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
                // send return EAGAIN
                // treated as packet loss/backpressure; KCP may retransmit.
                trace!("[SEND] UDP send EAGAIN, packet.size: {} bytes, dropped", buf.len());
                Ok(buf.len())
            }
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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
    async fn would_block_send_is_dropped_instead_of_deferred() {
        let async_send_calls = Arc::new(AtomicUsize::new(0));
        let socket: SharedUdpIo = Arc::new(BlockingUdpIo {
            async_send_calls: async_send_calls.clone(),
        });
        let target = "127.0.0.1:9".parse().expect("socket addr");
        let mut output = UdpOutput::new(socket, target);

        assert_eq!(output.write(b"kcp packet").expect("write"), 10);
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
            self.kcp.flush_ack()?;
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

        if self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize {
            self.kcp.flush()?;
        }

        self.last_update = Instant::now();

        if self.flush_write {
            self.kcp.flush()?;
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
        self.kcp.flush()?;
        self.pending_update = self.kcp.wait_snd() > 0 || self.kcp.waiting_conv();
        self.last_update = Instant::now();
        Ok(())
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
        self.pending_update
            || self.kcp.wait_snd() > 0
            || self.kcp.waiting_conv()
            || self.need_flush()
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

    use kcp::Error as KcpError;
    use log::trace;
    use std::sync::Arc;
    use tokio::{
        net::UdpSocket,
        sync::Mutex,
        time::{self, Instant},
    };

    use super::KcpSocket;
    use crate::config::KcpConfig;

    #[tokio::test]
    async fn pending_update_survives_early_update_until_due_tick() {
        static CONV: u32 = 0xfeedbeef;

        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let s1_addr = s1.local_addr().unwrap();
        let s2_addr = s2.local_addr().unwrap();

        let s1 = Arc::new(s1);
        let s2 = Arc::new(s2);

        let config = KcpConfig::default();
        let mut sender = KcpSocket::new(&config, CONV, s1.clone(), s2_addr, true).unwrap();
        let mut receiver = KcpSocket::new(&config, CONV, s2.clone(), s1_addr, true).unwrap();

        sender.send(b"hello").await.unwrap();
        sender.flush().unwrap();

        let mut packet = [0u8; 1500];
        let n = s2.recv(&mut packet).await.unwrap();
        receiver.input(&packet[..n]).unwrap();

        assert!(receiver.pending_update);
        let next = receiver.update().unwrap();
        assert!(receiver.pending_update);

        time::sleep_until(Instant::from_std(next)).await;
        receiver.update().unwrap();
        assert!(!receiver.pending_update);
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
