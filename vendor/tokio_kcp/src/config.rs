use std::{io::Write, time::Duration};

use kcp::Kcp;

/// Kcp Delay Config
#[derive(Debug, Clone, Copy)]
pub struct KcpNoDelayConfig {
    /// Enable nodelay
    pub nodelay: bool,
    /// Internal update interval (ms)
    pub interval: i32,
    /// ACK number to enable fast resend
    pub resend: i32,
    /// Disable congetion control
    pub nc: bool,
}

impl Default for KcpNoDelayConfig {
    fn default() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: false,
            interval: 100,
            resend: 0,
            nc: false,
        }
    }
}

impl KcpNoDelayConfig {
    /// Get a fastest configuration
    ///
    /// 1. Enable NoDelay
    /// 2. Set ticking interval to be 10ms
    /// 3. Set fast resend to be 2
    /// 4. Disable congestion control
    pub const fn fastest() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: true,
            interval: 10,
            resend: 2,
            nc: true,
        }
    }

    /// Get a normal configuration
    ///
    /// 1. Disable NoDelay
    /// 2. Set ticking interval to be 40ms
    /// 3. Disable fast resend
    /// 4. Enable congestion control
    pub const fn normal() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: false,
            interval: 40,
            resend: 0,
            nc: false,
        }
    }
}

/// Kcp Config
#[derive(Debug, Clone, Copy)]
pub struct KcpConfig {
    /// Max Transmission Unit
    pub mtu: usize,
    /// nodelay
    pub nodelay: KcpNoDelayConfig,
    /// Send window size
    pub wnd_size: (u16, u16),
    /// Session expire duration, default is 90 seconds
    pub session_expire: Duration,
    /// Close sessions with outstanding send work after this much time without
    /// inbound KCP progress. Set to zero to disable.
    pub no_progress_timeout: Duration,
    /// Flush KCP state immediately after write
    pub flush_write: bool,
    /// Flush ACKs immediately after input
    pub flush_acks_input: bool,
    /// Stream mode
    pub stream: bool,
    /// Allow recv 0 byte packet. KCP Segments with 0 byte data are skipped by default.
    pub allow_recv_empty_packet: bool,
    max_sessions: usize,
    max_sessions_per_ip: usize,
}

impl Default for KcpConfig {
    fn default() -> KcpConfig {
        KcpConfig {
            mtu: 1400,
            nodelay: KcpNoDelayConfig::normal(),
            wnd_size: (256, 256),
            session_expire: Duration::from_secs(90),
            no_progress_timeout: Duration::from_millis(1500),
            flush_write: false,
            flush_acks_input: false,
            stream: false,
            allow_recv_empty_packet: false,
            max_sessions: 1024,
            max_sessions_per_ip: 64,
        }
    }
}

impl KcpConfig {
    /// Maximum live server-side KCP sessions accepted by a listener.
    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Return a copy of this config with a different listener session cap.
    pub fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions.max(1);
        self
    }

    /// Maximum live server-side KCP sessions accepted from one remote IP.
    pub fn max_sessions_per_ip(&self) -> usize {
        self.max_sessions_per_ip
    }

    /// Return a copy of this config with a different per-IP session cap.
    pub fn with_max_sessions_per_ip(mut self, max_sessions_per_ip: usize) -> Self {
        self.max_sessions_per_ip = max_sessions_per_ip.max(1);
        self
    }

    /// Applies config onto `Kcp`
    #[doc(hidden)]
    pub fn apply_config<W: Write>(&self, k: &mut Kcp<W>) {
        k.set_mtu(self.mtu).expect("invalid MTU");

        k.set_nodelay(
            self.nodelay.nodelay,
            self.nodelay.interval,
            self.nodelay.resend,
            self.nodelay.nc,
        );

        k.set_wndsize(self.wnd_size.0, self.wnd_size.1);
    }
}
