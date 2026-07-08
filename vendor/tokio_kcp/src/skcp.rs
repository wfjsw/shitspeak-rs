use std::{
    io::{self, ErrorKind, Write},
    net::SocketAddr,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use futures_util::future;
use kcp::{Error as KcpError, Kcp, KcpResult, KcpStats};
use log::trace;

use crate::{udp_io::SharedUdpIo, utils::now_millis, KcpConfig};

/// Writer for sending packets to the underlying UdpSocket
struct UdpOutput {
    socket: SharedUdpIo,
    target_addr: SocketAddr,
}

impl UdpOutput {
    /// Create a new Writer for writing packets to UdpSocket
    pub fn new(socket: SharedUdpIo, target_addr: SocketAddr) -> UdpOutput {
        UdpOutput { socket, target_addr }
    }
}

impl Write for UdpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.socket.try_send_to(buf, self.target_addr) {
            Ok(n) => Ok(n),
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                trace!("[SEND] UDP send EAGAIN, packet.size: {} bytes, retry later", buf.len());
                Err(io::Error::from(ErrorKind::WouldBlock))
            }
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn is_would_block(err: &KcpError) -> bool {
    matches!(err, KcpError::IoError(io_err) if io_err.kind() == ErrorKind::WouldBlock)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use crate::udp_io::KcpUdpIo;

    use super::*;

    #[derive(Debug)]
    struct BlockingUdpIo {
        async_send_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl KcpUdpIo for BlockingUdpIo {
        async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::WouldBlock))
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::from(ErrorKind::WouldBlock))
        }

        async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
            self.async_send_calls.fetch_add(1, Ordering::SeqCst);
            Ok(buf.len())
        }

        fn try_send_to(&self, _buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::WouldBlock))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().expect("socket addr"))
        }
    }

    #[tokio::test]
    async fn would_block_send_is_reported_instead_of_dropped() {
        let async_send_calls = Arc::new(AtomicUsize::new(0));
        let socket: SharedUdpIo = Arc::new(BlockingUdpIo {
            async_send_calls: async_send_calls.clone(),
        });
        let target = "127.0.0.1:9".parse().expect("socket addr");
        let mut output = UdpOutput::new(socket, target);

        let err = output
            .write(b"kcp packet")
            .expect_err("write should report backpressure");
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(async_send_calls.load(Ordering::SeqCst), 0);
    }
}

#[derive(Debug)]
pub struct KcpSocket {
    kcp: Kcp<UdpOutput>,
    last_update: Instant,
    socket: SharedUdpIo,
    flush_write: bool,
    flush_ack_input: bool,
    sent_first: bool,
    pending_sender: Option<Waker>,
    pending_receiver: Option<Waker>,
    closed: bool,
    allow_recv_empty_packet: bool,
    pending_update: bool,
}

impl KcpSocket {
    pub fn new(
        c: &KcpConfig,
        conv: u32,
        socket: SharedUdpIo,
        target_addr: SocketAddr,
        stream: bool,
    ) -> KcpResult<KcpSocket> {
        let output = UdpOutput::new(socket.clone(), target_addr);
        let mut kcp = if stream {
            Kcp::new_stream(conv, output)
        } else {
            Kcp::new(conv, output)
        };
        c.apply_config(&mut kcp);

        // Ask server to allocate one
        if conv == 0 {
            kcp.input_conv();
        }

        kcp.update(now_millis())?;

        Ok(KcpSocket {
            kcp,
            last_update: Instant::now(),
            socket,
            flush_write: c.flush_write,
            flush_ack_input: c.flush_acks_input,
            sent_first: false,
            pending_sender: None,
            pending_receiver: None,
            closed: false,
            allow_recv_empty_packet: c.allow_recv_empty_packet,
            pending_update: true,
        })
    }

    /// Call every time you got data from transmission
    pub fn input(&mut self, buf: &[u8]) -> KcpResult<bool> {
        self.refresh_current();
        match self.kcp.input(buf) {
            Ok(..) => {}
            Err(KcpError::ConvInconsistent(expected, actual)) => {
                trace!("[INPUT] Conv expected={} actual={} ignored", expected, actual);
                return Ok(false);
            }
            Err(err) => return Err(err),
        }
        self.last_update = Instant::now();

        if self.flush_ack_input {
            match self.kcp.flush_ack() {
                Ok(()) => {}
                Err(err) if is_would_block(&err) => {
                    self.pending_update = true;
                    trace!("[INPUT] ACK flush backpressured; retry scheduled");
                }
                Err(err) => return Err(err),
            }
        } else {
            self.pending_update = true;
        }

        Ok(self.try_wake_pending_waker())
    }

    /// Call if you want to send some data
    pub fn poll_send(&mut self, cx: &mut Context<'_>, mut buf: &[u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Err(io::Error::from(ErrorKind::BrokenPipe).into()).into();
        }

        // If:
        //     1. Have sent the first packet (asking for conv)
        //     2. Too many pending packets
        if self.sent_first
            && (self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize
                || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize
                || self.kcp.waiting_conv())
        {
            trace!(
                "[SEND] waitsnd={} sndwnd={} rmtwnd={} excceeded or waiting conv={}",
                self.kcp.wait_snd(),
                self.kcp.snd_wnd(),
                self.kcp.rmt_wnd(),
                self.kcp.waiting_conv()
            );

            if let Some(waker) = self.pending_sender.replace(cx.waker().clone()) {
                if !cx.waker().will_wake(&waker) {
                    waker.wake();
                }
            }
            return Poll::Pending;
        }

        if !self.sent_first && self.kcp.waiting_conv() && buf.len() > self.kcp.mss() {
            buf = &buf[..self.kcp.mss()];
        }

        let n = self.kcp.send(buf)?;
        self.sent_first = true;
        self.pending_update = true;
        self.last_update = Instant::now();

        if self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize {
            if let Err(err) = self.flush() {
                if is_would_block(&err) {
                    return Ok(n).into();
                }
                return Err(err).into();
            }
        }

        if self.flush_write {
            if let Err(err) = self.flush() {
                if is_would_block(&err) {
                    return Ok(n).into();
                }
                return Err(err).into();
            }
        }

        Ok(n).into()
    }

    /// Call if you want to send some data
    #[allow(dead_code)]
    pub async fn send(&mut self, buf: &[u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    #[allow(dead_code)]
    pub fn try_recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        if self.closed {
            return Ok(0);
        }
        self.kcp.recv(buf)
    }

    pub fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Ok(0).into();
        }

        match self.kcp.recv(buf) {
            e @ (Err(KcpError::RecvQueueEmpty) | Err(KcpError::ExpectingFragment)) => {
                trace!(
                    "[RECV] rcvwnd={} peeksize={} r={:?}",
                    self.kcp.rcv_wnd(),
                    self.kcp.peeksize().unwrap_or(0),
                    e
                );
            }
            Err(err) => return Err(err).into(),
            Ok(n) => {
                if n == 0 && !self.allow_recv_empty_packet {
                    trace!(
                        "[RECV] rcvwnd={} peeksize={} r=Ok(0)",
                        self.kcp.rcv_wnd(),
                        self.kcp.peeksize().unwrap_or(0),
                    );
                } else {
                    self.last_update = Instant::now();
                    return Ok(n).into();
                }
            }
        }

        if let Some(waker) = self.pending_receiver.replace(cx.waker().clone()) {
            if !cx.waker().will_wake(&waker) {
                waker.wake();
            }
        }

        Poll::Pending
    }

    #[allow(dead_code)]
    pub async fn recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    pub fn flush(&mut self) -> KcpResult<()> {
        self.refresh_current();
        match self.kcp.flush() {
            Ok(()) => {
                self.pending_update = self.kcp.wait_snd() > 0 || self.kcp.waiting_conv();
                self.last_update = Instant::now();
                Ok(())
            }
            Err(err) => {
                if is_would_block(&err) {
                    self.pending_update = true;
                }
                Err(err)
            }
        }
    }

    fn refresh_current(&mut self) {
        self.kcp.set_current(now_millis());
    }

    fn try_wake_pending_waker(&mut self) -> bool {
        let mut waked = false;

        if self.pending_sender.is_some()
            && self.kcp.wait_snd() < self.kcp.snd_wnd() as usize
            && self.kcp.wait_snd() < self.kcp.rmt_wnd() as usize
            && !self.kcp.waiting_conv()
        {
            let waker = self.pending_sender.take().unwrap();
            waker.wake();

            waked = true;
        }

        if self.pending_receiver.is_some() {
            if let Ok(peek) = self.kcp.peeksize() {
                if self.allow_recv_empty_packet || peek > 0 {
                    let waker = self.pending_receiver.take().unwrap();
                    waker.wake();

                    waked = true;
                }
            }
        }

        waked
    }

    pub fn update(&mut self) -> KcpResult<Instant> {
        let now = now_millis();
        // An early wake may run before KCP's delayed flush time. Keep the
        // pending flag armed so the updater sleeps until the due tick instead
        // of parking with ACKs or writes still waiting inside KCP.
        let due_now = self.kcp.check(now) == 0;
        self.kcp.update(now)?;
        if due_now {
            self.pending_update = false;
        }
        let next = self.kcp.check(now);

        self.try_wake_pending_waker();

        Ok(Instant::now() + Duration::from_millis(next as u64))
    }

    pub fn needs_update(&self) -> bool {
        self.pending_update || self.kcp.wait_snd() > 0 || self.kcp.waiting_conv() || self.need_flush()
    }

    pub fn close(&mut self) {
        self.closed = true;
        if let Some(w) = self.pending_sender.take() {
            w.wake();
        }
        if let Some(w) = self.pending_receiver.take() {
            w.wake();
        }
    }

    pub fn udp_socket(&self) -> &SharedUdpIo {
        &self.socket
    }

    pub fn stats(&self) -> KcpStats {
        self.kcp.stats()
    }

    pub fn can_close(&self) -> bool {
        self.kcp.wait_snd() == 0
    }

    pub fn conv(&self) -> u32 {
        self.kcp.conv()
    }

    pub fn set_conv(&mut self, conv: u32) {
        self.kcp.set_conv(conv);
    }

    pub fn waiting_conv(&self) -> bool {
        self.kcp.waiting_conv()
    }

    pub fn peek_size(&self) -> KcpResult<usize> {
        self.kcp.peeksize()
    }

    pub fn last_update_time(&self) -> Instant {
        self.last_update
    }

    pub fn need_flush(&self) -> bool {
        (self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize)
            && !self.kcp.waiting_conv()
    }
}

#[cfg(test)]
mod test {

    use futures_util::task::noop_waker_ref;
    use kcp::Error as KcpError;
    use log::trace;
    use std::{
        convert::TryInto,
        io::{self, ErrorKind},
        net::SocketAddr,
        pin::Pin,
        sync::{Arc, Mutex as StdMutex},
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::{
        io::AsyncWrite,
        net::UdpSocket,
        sync::Mutex,
        time::{self, Instant},
    };

    use super::KcpSocket;
    use crate::{
        config::{KcpConfig, KcpNoDelayConfig},
        session::KcpSession,
        stream::KcpStream,
        udp_io::{KcpUdpIo, SharedUdpIo},
        utils::now_millis,
    };

    const TEST_CONV: u32 = 0xfeed_beef;
    const TEST_TARGET: &str = "127.0.0.1:9";
    const KCP_CMD_ACK: u8 = 82;

    #[derive(Debug, Default)]
    struct CapturingUdpIo {
        state: StdMutex<CapturingUdpState>,
    }

    #[derive(Debug, Default)]
    struct CapturingUdpState {
        sent: Vec<Vec<u8>>,
        fail_sends: usize,
    }

    impl CapturingUdpIo {
        fn with_fail_sends(fail_sends: usize) -> Self {
            Self {
                state: StdMutex::new(CapturingUdpState {
                    sent: Vec::new(),
                    fail_sends,
                }),
            }
        }

        fn take_sent(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.state.lock().expect("capture lock poisoned").sent)
        }

        fn set_fail_sends(&self, fail_sends: usize) {
            self.state.lock().expect("capture lock poisoned").fail_sends = fail_sends;
        }
    }

    #[async_trait::async_trait]
    impl KcpUdpIo for CapturingUdpIo {
        async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::WouldBlock))
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::from(ErrorKind::WouldBlock))
        }

        async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
            self.try_send_to(buf, target)
        }

        fn try_send_to(&self, buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
            let mut state = self.state.lock().expect("capture lock poisoned");
            if state.fail_sends > 0 {
                state.fail_sends -= 1;
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            state.sent.push(buf.to_vec());
            Ok(buf.len())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().expect("socket addr"))
        }
    }

    fn realtime_test_config() -> KcpConfig {
        let mut config = KcpConfig::default();
        config.nodelay = KcpNoDelayConfig {
            nodelay: true,
            interval: 10,
            resend: 0,
            nc: false,
        };
        config.flush_write = true;
        config
    }

    fn capturing_socket(config: &KcpConfig) -> (KcpSocket, Arc<CapturingUdpIo>) {
        let capture = Arc::new(CapturingUdpIo::default());
        let udp: SharedUdpIo = capture.clone();
        let target = TEST_TARGET.parse().expect("socket addr");
        (
            KcpSocket::new(config, TEST_CONV, udp, target, true).expect("kcp socket"),
            capture,
        )
    }

    fn capturing_socket_with_io(config: &KcpConfig, capture: Arc<CapturingUdpIo>) -> KcpSocket {
        let udp: SharedUdpIo = capture;
        let target = TEST_TARGET.parse().expect("socket addr");
        KcpSocket::new(config, TEST_CONV, udp, target, true).expect("kcp socket")
    }

    fn packet_ts(packet: &[u8]) -> u32 {
        u32::from_le_bytes(packet[8..12].try_into().expect("packet timestamp"))
    }

    fn ack_packet(ts: u32, sn: u32, una: u32) -> Vec<u8> {
        let mut packet = Vec::with_capacity(kcp::KCP_OVERHEAD);
        packet.extend_from_slice(&TEST_CONV.to_le_bytes());
        packet.push(KCP_CMD_ACK);
        packet.push(0);
        packet.extend_from_slice(&128u16.to_le_bytes());
        packet.extend_from_slice(&ts.to_le_bytes());
        packet.extend_from_slice(&sn.to_le_bytes());
        packet.extend_from_slice(&una.to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet
    }

    fn packet_cmd(packet: &[u8]) -> u8 {
        packet[4]
    }

    #[tokio::test]
    async fn stale_clock_immediate_flush_uses_current_timestamp_after_idle() {
        let config = realtime_test_config();
        let (mut sender, capture) = capturing_socket(&config);

        time::sleep(Duration::from_millis(60)).await;
        let before_send = now_millis();
        sender.send(b"fresh timestamp").await.unwrap();
        let after_send = now_millis();

        let packets = capture.take_sent();
        assert_eq!(packets.len(), 1);
        let ts = packet_ts(&packets[0]);
        assert!(
            ts >= before_send.saturating_sub(1),
            "packet timestamp {} predates send window {}..={}",
            ts,
            before_send,
            after_send
        );
        assert!(
            ts <= after_send.saturating_add(5),
            "packet timestamp {} exceeds send window {}..={}",
            ts,
            before_send,
            after_send
        );
    }

    #[tokio::test]
    async fn stale_clock_delayed_ack_input_prevents_min_rto_retransmit() {
        let config = realtime_test_config();
        let (mut sender, capture) = capturing_socket(&config);

        sender.send(b"first").await.unwrap();
        let first_packets = capture.take_sent();
        assert_eq!(first_packets.len(), 1);
        let first_ts = packet_ts(&first_packets[0]);

        time::sleep(Duration::from_millis(80)).await;
        sender.input(&ack_packet(first_ts, 0, 1)).unwrap();
        assert!(capture.take_sent().is_empty());

        sender.send(b"second").await.unwrap();
        let second_packets = capture.take_sent();
        assert_eq!(second_packets.len(), 1);

        time::sleep(Duration::from_millis(45)).await;
        sender.update().unwrap();
        assert!(
            capture.take_sent().is_empty(),
            "delayed ACK should raise RTO above the no-delay min-RTO window"
        );
    }

    #[tokio::test]
    async fn pending_update_survives_early_update_until_due_tick() {
        let config = KcpConfig::default();
        let (mut sender, sender_capture) = capturing_socket(&config);
        let (mut receiver, _) = capturing_socket(&config);

        sender.send(b"hello").await.unwrap();
        sender.flush().unwrap();

        let packets = sender_capture.take_sent();
        assert_eq!(packets.len(), 1);
        receiver.input(&packets[0]).unwrap();

        assert!(receiver.pending_update);
        let next = receiver.update().unwrap();
        assert!(receiver.pending_update);

        time::sleep_until(Instant::from_std(next)).await;
        receiver.update().unwrap();
        assert!(!receiver.pending_update);
    }

    #[tokio::test]
    async fn flush_acks_input_emits_ack_immediately() {
        let sender_config = realtime_test_config();
        let mut receiver_config = realtime_test_config();
        receiver_config.flush_acks_input = true;
        let (mut sender, sender_capture) = capturing_socket(&sender_config);
        let (mut receiver, receiver_capture) = capturing_socket(&receiver_config);

        sender.send(b"needs ack").await.unwrap();
        let packets = sender_capture.take_sent();
        assert_eq!(packets.len(), 1);

        receiver.input(&packets[0]).unwrap();

        let ack_packets = receiver_capture.take_sent();
        assert_eq!(ack_packets.len(), 1);
        assert_eq!(packet_cmd(&ack_packets[0]), KCP_CMD_ACK);
    }

    #[tokio::test]
    async fn poll_send_accepts_bytes_when_immediate_flush_is_backpressured() {
        let config = realtime_test_config();
        let capture = Arc::new(CapturingUdpIo::with_fail_sends(1));
        let mut socket = capturing_socket_with_io(&config, capture.clone());
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        match socket.poll_send(&mut cx, b"backpressured") {
            Poll::Ready(Ok(n)) => assert_eq!(n, b"backpressured".len()),
            other => panic!("expected accepted write, got {:?}", other),
        }
        assert!(socket.pending_update);
        assert!(capture.take_sent().is_empty());

        socket.flush().unwrap();

        let packets = capture.take_sent();
        assert_eq!(packets.len(), 1);
    }

    #[tokio::test]
    async fn stream_poll_flush_is_pending_until_backpressured_packet_retries() {
        let config = realtime_test_config();
        let capture = Arc::new(CapturingUdpIo::with_fail_sends(usize::MAX / 2));
        let socket = capturing_socket_with_io(&config, capture.clone());
        let session = KcpSession::new_shared(socket, Duration::from_secs(90), None);
        let mut stream = KcpStream::with_session(session);
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        match Pin::new(&mut stream).poll_write(&mut cx, b"retry me") {
            Poll::Ready(Ok(n)) => assert_eq!(n, b"retry me".len()),
            other => panic!("expected accepted stream write, got {:?}", other),
        }
        assert!(capture.take_sent().is_empty());

        match Pin::new(&mut stream).poll_flush(&mut cx) {
            Poll::Pending => {}
            other => panic!("expected backpressured flush to be pending, got {:?}", other),
        }
        assert!(capture.take_sent().is_empty());

        capture.set_fail_sends(0);
        for _ in 0..5 {
            match Pin::new(&mut stream).poll_flush(&mut cx) {
                Poll::Ready(Ok(())) => {
                    assert_eq!(capture.take_sent().len(), 1);
                    return;
                }
                Poll::Pending => tokio::task::yield_now().await,
                other => panic!("expected pending or successful retry, got {:?}", other),
            }
        }

        panic!("backpressured flush did not retry successfully");
    }

    #[tokio::test]
    async fn kcp_echo() {
        let _ = env_logger::try_init();

        static CONV: u32 = 0xdeadbeef;

        // s1 connects s2
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let s1_addr = s1.local_addr().unwrap();
        let s2_addr = s2.local_addr().unwrap();

        let s1 = Arc::new(s1);
        let s2 = Arc::new(s2);

        let config = KcpConfig::default();
        let kcp1 = KcpSocket::new(&config, 0, s1.clone(), s2_addr, true).unwrap();
        let kcp2 = KcpSocket::new(&config, CONV, s2.clone(), s1_addr, true).unwrap();

        let kcp1 = Arc::new(Mutex::new(kcp1));
        let kcp2 = Arc::new(Mutex::new(kcp2));

        let kcp1_task = {
            let kcp1 = kcp1.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp1.lock().await;
                    let next = kcp.update().expect("update");
                    trace!("kcp1 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            })
        };

        let kcp2_task = {
            let kcp2 = kcp2.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp2.lock().await;
                    let next = kcp.update().expect("update");
                    trace!("kcp2 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            })
        };

        const SEND_BUFFER: &[u8] = b"HELLO WORLD";

        {
            let n = kcp1.lock().await.send(SEND_BUFFER).await.unwrap();
            assert_eq!(n, SEND_BUFFER.len());
        }

        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            loop {
                let n = s2.recv(&mut buf).await.unwrap();

                let packet = &mut buf[..n];

                let conv = kcp::get_conv(packet);
                if conv == 0 {
                    kcp::set_conv(packet, CONV);
                }

                let mut kcp2 = kcp2.lock().await;
                kcp2.input(packet).unwrap();

                match kcp2.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        kcp2.send(received).await.unwrap();
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        });

        {
            let mut buf = [0u8; 1024];

            loop {
                let n = s1.recv(&mut buf).await.unwrap();

                let packet = &buf[..n];

                let mut kcp1 = kcp1.lock().await;
                kcp1.input(packet).unwrap();

                match kcp1.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        assert_eq!(received, SEND_BUFFER);
                        break;
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        }

        echo_task.abort();
        kcp1_task.abort();
        kcp2_task.abort();
    }
}
