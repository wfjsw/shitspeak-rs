use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Debug},
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use byte_string::ByteStr;
use futures_util::task::AtomicWaker;
use kcp::{KcpResult, KcpStats};
use log::{error, trace};
use tokio::{
    sync::{mpsc, Mutex, Notify},
    time::{self, Instant},
};

use crate::{skcp::KcpSocket, udp_io::SharedUdpIo, KcpConfig};

pub struct KcpSession {
    socket: Mutex<KcpSocket>,
    closed: AtomicBool,
    session_expire: Duration,
    session_close_notifier: Option<(mpsc::Sender<SocketAddr>, SocketAddr)>,
    input_tx: mpsc::Sender<Vec<u8>>,
    notifier: Notify,
    socket_waker: AtomicWaker,
    stats: KcpStatsSnapshot,
}

#[derive(Debug, Default)]
struct KcpStatsSnapshot {
    sent_segments: AtomicU64,
    lost_segments: AtomicU64,
    srtt_ms: AtomicU32,
    rto_ms: AtomicU32,
    rtt_sample_count: AtomicU64,
}

impl KcpStatsSnapshot {
    fn update(&self, stats: &KcpStats) {
        self.sent_segments.store(stats.sent_segments(), Ordering::Relaxed);
        self.lost_segments.store(stats.lost_segments(), Ordering::Relaxed);
        self.srtt_ms.store(stats.srtt_ms().unwrap_or(0), Ordering::Relaxed);
        self.rto_ms.store(stats.rto_ms(), Ordering::Relaxed);
        self.rtt_sample_count.store(stats.rtt_sample_count(), Ordering::Relaxed);
    }

    fn sent_segments(&self) -> u64 {
        self.sent_segments.load(Ordering::Relaxed)
    }

    fn lost_segments(&self) -> u64 {
        self.lost_segments.load(Ordering::Relaxed)
    }

    fn srtt_ms(&self) -> Option<u32> {
        match self.srtt_ms.load(Ordering::Relaxed) {
            0 => None,
            srtt_ms => Some(srtt_ms),
        }
    }

    fn rto_ms(&self) -> u32 {
        self.rto_ms.load(Ordering::Relaxed)
    }

    fn rtt_sample_count(&self) -> u64 {
        self.rtt_sample_count.load(Ordering::Relaxed)
    }

    fn get(&self) -> KcpStats {
        KcpStats::with_rtt(
            self.sent_segments(),
            self.lost_segments(),
            self.srtt_ms(),
            self.rto_ms(),
            self.rtt_sample_count(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct KcpStatsHandle {
    session: Arc<KcpSession>,
}

impl KcpStatsHandle {
    pub(crate) fn new(session: Arc<KcpSession>) -> Self {
        Self { session }
    }

    pub fn stats(&self) -> KcpStats {
        self.session.snapshot_stats()
    }

    pub fn sent_segments(&self) -> u64 {
        self.session.sent_segments()
    }

    pub fn lost_segments(&self) -> u64 {
        self.session.lost_segments()
    }

    pub fn srtt_ms(&self) -> Option<u32> {
        self.session.srtt_ms()
    }

    pub fn rto_ms(&self) -> u32 {
        self.session.rto_ms()
    }

    pub fn rtt_sample_count(&self) -> u64 {
        self.session.rtt_sample_count()
    }
}

impl Drop for KcpSession {
    fn drop(&mut self) {
        trace!(
            "[SESSION] KcpSession is dropping, closed? {}",
            self.closed.load(Ordering::Acquire),
        );
    }
}

impl Debug for KcpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpSession")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("session_expired", &self.session_expire)
            .field("session_close_notifier", &self.session_close_notifier)
            .field("input_tx", &self.input_tx)
            .field("notifier", &self.notifier)
            .field("sent_segments", &self.sent_segments())
            .field("lost_segments", &self.lost_segments())
            .finish()
    }
}

impl KcpSession {
    fn new(
        socket: KcpSocket,
        session_expire: Duration,
        session_close_notifier: Option<(mpsc::Sender<SocketAddr>, SocketAddr)>,
        input_tx: mpsc::Sender<Vec<u8>>,
    ) -> KcpSession {
        let stats = KcpStatsSnapshot::default();
        stats.update(&socket.stats());
        KcpSession {
            socket: Mutex::new(socket),
            closed: AtomicBool::new(false),
            session_expire,
            session_close_notifier,
            input_tx,
            notifier: Notify::new(),
            socket_waker: AtomicWaker::new(),
            stats,
        }
    }

    pub fn new_shared(
        socket: KcpSocket,
        session_expire: Duration,
        session_close_notifier: Option<(mpsc::Sender<SocketAddr>, SocketAddr)>,
    ) -> Arc<KcpSession> {
        let is_client = session_close_notifier.is_none();

        let (input_tx, mut input_rx) = mpsc::channel(64);

        let udp_socket = socket.udp_socket().clone();

        let session = Arc::new(KcpSession::new(
            socket,
            session_expire,
            session_close_notifier,
            input_tx,
        ));

        let io_task_handle = {
            let session = session.clone();
            tokio::spawn(async move {
                let mut input_buffer = [0u8; 65536];

                loop {
                    tokio::select! {
                        // recv() then input()
                        // Drives the KCP machine forward
                        recv_result = udp_socket.recv(&mut input_buffer), if is_client => {
                            match recv_result {
                                Err(err) => {
                                    error!("[SESSION] UDP recv failed, error: {}", err);
                                }
                                Ok(n) => {
                                    let input_buffer = &input_buffer[..n];

                                    if input_buffer.len() < kcp::KCP_OVERHEAD {
                                        error!("packet too short, received {} bytes, but at least {} bytes",
                                               input_buffer.len(),
                                               kcp::KCP_OVERHEAD);
                                        continue;
                                    }

                                    let input_conv = kcp::get_conv(input_buffer);
                                    trace!("[SESSION] UDP recv {} bytes, conv: {}, going to input {:?}",
                                           n, input_conv, ByteStr::new(input_buffer));

                                    let mut socket = session.socket.lock().await;

                                    // Server may allocate another conv for this client.
                                    if !socket.waiting_conv() && socket.conv() != input_conv {
                                        trace!("[SESSION] UDP input conv: {} replaces session conv: {}", input_conv, socket.conv());
                                        socket.set_conv(input_conv);
                                    }

                                    match socket.input(input_buffer) {
                                        Ok(true) => {
                                            trace!("[SESSION] UDP input {} bytes and waked sender/receiver", n);
                                        }
                                        Ok(false) => {}
                                        Err(err) => {
                                            error!("[SESSION] UDP input {} bytes error: {}, input buffer {:?}",
                                                   n, err, ByteStr::new(input_buffer));
                                        }
                                    }
                                    session.update_stats(&socket);
                                    session.wake_socket_waiters();
                                    session.notify();
                                }
                            }
                        }

                        // bytes received from listener socket
                        input_opt = input_rx.recv() => {
                            match input_opt {
                                Some(input_buffer) => {
                                    let mut socket = session.socket.lock().await;
                                    match socket.input(&input_buffer) {
                                        Ok(waked) => {
                                            // trace!("[SESSION] UDP input {} bytes from channel {:?}",
                                            //        input_buffer.len(), ByteStr::new(&input_buffer));
                                            trace!("[SESSION] UDP input {} bytes from channel, waked? {} sender/receiver",
                                                   input_buffer.len(), waked);
                                        }
                                        Err(err) => {
                                            error!("[SESSION] UDP input {} bytes from channel failed, error: {}, input buffer {:?}",
                                                   input_buffer.len(), err, ByteStr::new(&input_buffer));
                                        }
                                    }
                                    session.update_stats(&socket);
                                    session.wake_socket_waiters();
                                    session.notify();
                                }
                                None => break,
                            }
                        }
                    }
                }
            })
        };

        // Per-session updater
        {
            let session = session.clone();
            tokio::spawn(async move {
                while !session.closed.load(Ordering::Relaxed) {
                    let next = {
                        let mut socket = session.socket.lock().await;
                        let mut next = None;

                        let is_closed = session.closed.load(Ordering::Acquire);
                        if is_closed && socket.can_close() {
                            trace!("[SESSION] KCP session closing");
                            break;
                        }

                        // server socket expires
                        if !is_client {
                            // If this is a server stream, close it automatically after a period of time
                            let last_update_time = socket.last_update_time();
                            let elapsed = last_update_time.elapsed();
                            next = Some(Instant::from_std(
                                last_update_time
                                    .checked_add(session.session_expire)
                                    .unwrap_or_else(std::time::Instant::now),
                            ));

                            if elapsed > session.session_expire {
                                if elapsed > session.session_expire * 2 {
                                    // Force close. Client may have already gone.
                                    trace!(
                                        "[SESSION] force close inactive session, conv: {}, last_update: {}s ago",
                                        socket.conv(),
                                        elapsed.as_secs()
                                    );
                                    break;
                                }

                                if !is_closed {
                                    trace!(
                                        "[SESSION] closing inactive session, conv: {}, last_update: {}s ago",
                                        socket.conv(),
                                        elapsed.as_secs()
                                    );
                                    session.closed.store(true, Ordering::Release);
                                }
                                next = Some(Instant::now() + session.session_expire);
                            }
                        }

                        // If window is full, flush it immediately
                        if socket.need_flush() {
                            let _ = socket.flush();
                        }

                        if socket.needs_update() {
                            next = Some(match socket.update() {
                                Ok(next_next) => Instant::from_std(next_next),
                                Err(err) => {
                                    error!("[SESSION] KCP update failed, error: {}", err);
                                    Instant::now() + Duration::from_millis(10)
                                }
                            });
                        }
                        session.update_stats(&socket);
                        session.wake_socket_waiters();
                        next
                    };

                    match next {
                        Some(next) => {
                            tokio::select! {
                                _ = time::sleep_until(next) => {},
                                _ = session.notifier.notified() => {},
                            }
                        }
                        None => {
                            session.notifier.notified().await;
                        }
                    }
                }

                {
                    // Close the socket.
                    // Wake all pending tasks and let all send/recv return EOF

                    let mut socket = session.socket.lock().await;
                    socket.close();
                    session.update_stats(&socket);
                    session.wake_socket_waiters();
                }

                if let Some((ref notifier, peer_addr)) = session.session_close_notifier {
                    let _ = notifier.send(peer_addr).await;
                }

                session.closed.store(true, Ordering::Release);
                io_task_handle.abort();

                trace!("[SESSION] KCP session closed");
            });
        }

        session
    }

    pub fn kcp_socket(&self) -> &Mutex<KcpSocket> {
        &self.socket
    }

    pub fn snapshot_stats(&self) -> KcpStats {
        self.stats.get()
    }

    pub async fn stats(&self) -> KcpStats {
        let socket = self.socket.lock().await;
        let stats = socket.stats();
        self.stats.update(&stats);
        stats
    }

    pub fn sent_segments(&self) -> u64 {
        self.stats.sent_segments()
    }

    pub fn lost_segments(&self) -> u64 {
        self.stats.lost_segments()
    }

    pub fn srtt_ms(&self) -> Option<u32> {
        self.stats.srtt_ms()
    }

    pub fn rto_ms(&self) -> u32 {
        self.stats.rto_ms()
    }

    pub fn rtt_sample_count(&self) -> u64 {
        self.stats.rtt_sample_count()
    }

    pub(crate) fn update_stats(&self, socket: &KcpSocket) {
        let stats = socket.stats();
        self.stats.update(&stats);
    }

    pub(crate) fn register_socket_waker(&self, waker: &std::task::Waker) {
        self.socket_waker.register(waker);
    }

    pub(crate) fn wake_socket_waiters(&self) {
        self.socket_waker.wake();
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify();
    }

    pub async fn input(&self, buf: &[u8]) -> Result<(), SessionClosedError> {
        self.input_tx.send(buf.to_owned()).await.map_err(|_| SessionClosedError)
    }

    pub async fn conv(&self) -> u32 {
        let socket = self.socket.lock().await;
        socket.conv()
    }

    pub fn notify(&self) {
        self.notifier.notify_one();
    }
}

pub struct SessionClosedError;

struct KcpSessionUniq(Arc<KcpSession>);

impl Drop for KcpSessionUniq {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Deref for KcpSessionUniq {
    type Target = KcpSession;

    fn deref(&self) -> &KcpSession {
        &self.0
    }
}

pub struct KcpSessionManager {
    sessions: HashMap<SocketAddr, KcpSessionUniq>,
    sessions_by_ip: HashMap<IpAddr, usize>,
}

impl KcpSessionManager {
    pub fn new() -> KcpSessionManager {
        KcpSessionManager {
            sessions: HashMap::new(),
            sessions_by_ip: HashMap::new(),
        }
    }

    #[inline]
    pub fn alloc_conv(&mut self) -> u32 {
        let mut conv = rand::random();
        while conv == 0 {
            conv = rand::random()
        }
        conv
    }

    pub fn close_peer(&mut self, peer_addr: SocketAddr) {
        if self.sessions.remove(&peer_addr).is_some() {
            self.decrement_ip(peer_addr.ip());
        }
    }

    pub fn get_peer(&self, peer_addr: SocketAddr) -> Option<Arc<KcpSession>> {
        self.sessions.get(&peer_addr).map(|session| session.0.clone())
    }

    fn increment_ip(&mut self, ip: IpAddr) {
        *self.sessions_by_ip.entry(ip).or_insert(0) += 1;
    }

    fn decrement_ip(&mut self, ip: IpAddr) {
        match self.sessions_by_ip.get_mut(&ip) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                self.sessions_by_ip.remove(&ip);
            }
            None => {}
        }
    }

    pub fn is_full(&self, max_sessions: usize) -> bool {
        self.sessions.len() >= max_sessions
    }

    pub fn ip_is_full(&self, ip: IpAddr, max_sessions_per_ip: usize) -> bool {
        self.sessions_by_ip.get(&ip).copied().unwrap_or(0) >= max_sessions_per_ip
    }

    pub async fn get_or_create(
        &mut self,
        config: &KcpConfig,
        conv: u32,
        sn: u32,
        udp: &SharedUdpIo,
        peer_addr: SocketAddr,
        session_close_notifier: &mpsc::Sender<SocketAddr>,
    ) -> KcpResult<(Arc<KcpSession>, bool)> {
        match self.sessions.entry(peer_addr) {
            Entry::Occupied(mut occ) => {
                let session = occ.get();

                if sn == 0 && session.conv().await != conv {
                    // This is the first packet received from this peer.
                    // Recreate a new session for this specific client.

                    let socket = KcpSocket::new(config, conv, udp.clone(), peer_addr, config.stream)?;
                    let session = KcpSession::new_shared(
                        socket,
                        config.session_expire,
                        Some((session_close_notifier.clone(), peer_addr)),
                    );

                    let old_session = occ.insert(KcpSessionUniq(session.clone()));
                    let old_conv = old_session.conv().await;
                    trace!(
                        "replaced session with conv: {} (old: {}), peer: {}",
                        conv,
                        old_conv,
                        peer_addr
                    );

                    Ok((session, true))
                } else {
                    Ok((session.0.clone(), false))
                }
            }
            Entry::Vacant(vac) => {
                let socket = KcpSocket::new(config, conv, udp.clone(), peer_addr, config.stream)?;
                let session = KcpSession::new_shared(
                    socket,
                    config.session_expire,
                    Some((session_close_notifier.clone(), peer_addr)),
                );
                trace!("created session for conv: {}, peer: {}", conv, peer_addr);
                vac.insert(KcpSessionUniq(session.clone()));
                self.increment_ip(peer_addr.ip());
                Ok((session, true))
            }
        }
    }
}
