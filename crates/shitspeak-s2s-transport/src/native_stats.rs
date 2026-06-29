//! Native transport loss samplers.
//!
//! These samplers convert cumulative transport sent/declared-lost counters into
//! per-window loss samples for [`super::metrics::PeerMetrics`]. They
//! intentionally report only deltas; the first observation seeds the baseline
//! and does not affect routing.

use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NativeLossSample {
    sent_units: u64,
    lost_units: u64,
}

impl NativeLossSample {
    pub(crate) fn new(sent_units: u64, lost_units: u64) -> Self {
        Self {
            sent_units,
            lost_units,
        }
    }

    pub(crate) fn sent_units(&self) -> u64 {
        self.sent_units
    }

    pub(crate) fn lost_units(&self) -> u64 {
        self.lost_units
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RawNativeCounters {
    sent_units: u64,
    lost_units: u64,
}

impl RawNativeCounters {
    pub(crate) fn new(sent_units: u64, lost_units: u64) -> Self {
        Self {
            sent_units,
            lost_units,
        }
    }

    pub(crate) fn sent_units(&self) -> u64 {
        self.sent_units
    }

    pub(crate) fn lost_units(&self) -> u64 {
        self.lost_units
    }
}

pub(crate) trait NativeLossSampler: Send + 'static {
    fn sample(&mut self) -> Option<NativeLossSample>;
}

pub(crate) type BoxedNativeLossSampler = Box<dyn NativeLossSampler>;

pub(crate) fn delta_from_counters(
    previous: &mut Option<RawNativeCounters>,
    current: RawNativeCounters,
) -> Option<NativeLossSample> {
    let prior = previous.replace(current)?;
    let sent_delta = current.sent_units().saturating_sub(prior.sent_units());
    if sent_delta == 0 {
        return None;
    }
    let lost_delta = current.lost_units().saturating_sub(prior.lost_units());
    Some(NativeLossSample::new(sent_delta, lost_delta))
}

pub(crate) fn quic_sampler(conn: quinn::Connection) -> BoxedNativeLossSampler {
    Box::new(QuicNativeLossSampler::new(conn))
}

pub(crate) fn tcp_sampler(stream: &TcpStream) -> Option<BoxedNativeLossSampler> {
    tcp_platform::TcpNativeLossSampler::from_stream(stream)
        .map(|sampler| Box::new(sampler) as BoxedNativeLossSampler)
}

pub(crate) fn kcp_sampler(stream: &tokio_kcp::KcpStream) -> Option<BoxedNativeLossSampler> {
    Some(Box::new(KcpNativeLossSampler::new(stream.stats_handle())))
}

pub(crate) fn quic_path_counters(path: &quinn::PathStats) -> RawNativeCounters {
    RawNativeCounters::new(path.sent_packets, path.lost_packets)
}

#[derive(Debug)]
struct QuicNativeLossSampler {
    conn: quinn::Connection,
    previous: Option<RawNativeCounters>,
}

impl QuicNativeLossSampler {
    fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            previous: None,
        }
    }
}

impl NativeLossSampler for QuicNativeLossSampler {
    fn sample(&mut self) -> Option<NativeLossSample> {
        let stats = self.conn.stats();
        delta_from_counters(&mut self.previous, quic_path_counters(&stats.path))
    }
}

#[derive(Debug)]
struct KcpNativeLossSampler {
    handle: tokio_kcp::KcpStatsHandle,
    previous: Option<RawNativeCounters>,
}

impl KcpNativeLossSampler {
    fn new(handle: tokio_kcp::KcpStatsHandle) -> Self {
        Self {
            handle,
            previous: None,
        }
    }
}

impl NativeLossSampler for KcpNativeLossSampler {
    fn sample(&mut self) -> Option<NativeLossSample> {
        let stats = self.handle.stats();
        let current = RawNativeCounters::new(stats.sent_segments(), stats.lost_segments());
        delta_from_counters(&mut self.previous, current)
    }
}

#[cfg(target_os = "linux")]
mod tcp_platform {
    use std::mem;
    use std::os::fd::{AsRawFd, RawFd};

    use tokio::net::TcpStream;

    use super::{NativeLossSample, NativeLossSampler, RawNativeCounters, delta_from_counters};

    #[derive(Debug)]
    pub(super) struct TcpNativeLossSampler {
        fd: RawFd,
        previous: Option<RawNativeCounters>,
    }

    impl TcpNativeLossSampler {
        pub(super) fn from_stream(stream: &TcpStream) -> Option<Self> {
            Some(Self {
                fd: stream.as_raw_fd(),
                previous: None,
            })
        }
    }

    impl NativeLossSampler for TcpNativeLossSampler {
        fn sample(&mut self) -> Option<NativeLossSample> {
            let current = linux_tcp_counters(self.fd)?;
            delta_from_counters(&mut self.previous, current)
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct LinuxTcpInfo {
        tcpi_state: u8,
        tcpi_ca_state: u8,
        tcpi_retransmits: u8,
        tcpi_probes: u8,
        tcpi_backoff: u8,
        tcpi_options: u8,
        tcpi_snd_rcv_wscale: u8,
        tcpi_delivery_fastopen_bitfields: u8,
        tcpi_rto: u32,
        tcpi_ato: u32,
        tcpi_snd_mss: u32,
        tcpi_rcv_mss: u32,
        tcpi_unacked: u32,
        tcpi_sacked: u32,
        tcpi_lost: u32,
        tcpi_retrans: u32,
        tcpi_fackets: u32,
        tcpi_last_data_sent: u32,
        tcpi_last_ack_sent: u32,
        tcpi_last_data_recv: u32,
        tcpi_last_ack_recv: u32,
        tcpi_pmtu: u32,
        tcpi_rcv_ssthresh: u32,
        tcpi_rtt: u32,
        tcpi_rttvar: u32,
        tcpi_snd_ssthresh: u32,
        tcpi_snd_cwnd: u32,
        tcpi_advmss: u32,
        tcpi_reordering: u32,
        tcpi_rcv_rtt: u32,
        tcpi_rcv_space: u32,
        tcpi_total_retrans: u32,
        tcpi_pacing_rate: u64,
        tcpi_max_pacing_rate: u64,
        tcpi_bytes_acked: u64,
        tcpi_bytes_received: u64,
        tcpi_segs_out: u32,
        tcpi_segs_in: u32,
        tcpi_notsent_bytes: u32,
        tcpi_min_rtt: u32,
        tcpi_data_segs_in: u32,
        tcpi_data_segs_out: u32,
        tcpi_delivery_rate: u64,
        tcpi_busy_time: u64,
        tcpi_rwnd_limited: u64,
        tcpi_sndbuf_limited: u64,
        tcpi_delivered: u32,
        tcpi_delivered_ce: u32,
        tcpi_bytes_sent: u64,
        tcpi_bytes_retrans: u64,
        tcpi_dsack_dups: u32,
        tcpi_reord_seen: u32,
        tcpi_rcv_ooopack: u32,
        tcpi_snd_wnd: u32,
    }

    fn linux_tcp_counters(fd: RawFd) -> Option<RawNativeCounters> {
        let mut info = LinuxTcpInfo::default();
        let mut len = mem::size_of::<LinuxTcpInfo>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                &mut info as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        if info.tcpi_segs_out > 0 {
            return Some(RawNativeCounters::new(
                u64::from(info.tcpi_segs_out),
                u64::from(info.tcpi_total_retrans),
            ));
        }
        if info.tcpi_bytes_sent == 0 {
            return None;
        }
        Some(RawNativeCounters::new(
            info.tcpi_bytes_sent,
            info.tcpi_bytes_retrans,
        ))
    }
}

#[cfg(windows)]
mod tcp_platform {
    use std::mem;
    use std::os::windows::io::{AsRawSocket, RawSocket};
    use std::ptr;

    use tokio::net::TcpStream;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_TCP_INFO, SOCKET, SOCKET_ERROR, TCP_INFO_v0, TCP_INFO_v1, WSAIoctl,
    };

    use super::{NativeLossSample, NativeLossSampler, RawNativeCounters, delta_from_counters};

    #[derive(Debug)]
    pub(super) struct TcpNativeLossSampler {
        socket: RawSocket,
        previous: Option<RawNativeCounters>,
    }

    impl TcpNativeLossSampler {
        pub(super) fn from_stream(stream: &TcpStream) -> Option<Self> {
            Some(Self {
                socket: stream.as_raw_socket(),
                previous: None,
            })
        }
    }

    impl NativeLossSampler for TcpNativeLossSampler {
        fn sample(&mut self) -> Option<NativeLossSample> {
            let current = windows_tcp_counters(self.socket)?;
            delta_from_counters(&mut self.previous, current)
        }
    }

    fn windows_tcp_counters(socket: RawSocket) -> Option<RawNativeCounters> {
        let mut bytes_returned = 0u32;
        let mut version = 1u32;
        let mut info_v1 = TCP_INFO_v1::default();
        let rc = unsafe {
            WSAIoctl(
                socket as SOCKET,
                SIO_TCP_INFO,
                &version as *const _ as *const _,
                mem::size_of_val(&version) as u32,
                &mut info_v1 as *mut _ as *mut _,
                mem::size_of::<TCP_INFO_v1>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
                None,
            )
        };
        if rc != SOCKET_ERROR && info_v1.BytesOut > 0 {
            return Some(RawNativeCounters::new(
                info_v1.BytesOut,
                u64::from(info_v1.BytesRetrans),
            ));
        }

        bytes_returned = 0;
        version = 0;
        let mut info_v0 = TCP_INFO_v0::default();
        let rc = unsafe {
            WSAIoctl(
                socket as SOCKET,
                SIO_TCP_INFO,
                &version as *const _ as *const _,
                mem::size_of_val(&version) as u32,
                &mut info_v0 as *mut _ as *mut _,
                mem::size_of::<TCP_INFO_v0>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
                None,
            )
        };
        if rc == SOCKET_ERROR || info_v0.BytesOut == 0 {
            return None;
        }
        Some(RawNativeCounters::new(
            info_v0.BytesOut,
            u64::from(info_v0.BytesRetrans),
        ))
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod tcp_platform {
    use tokio::net::TcpStream;

    #[derive(Debug)]
    pub(super) struct TcpNativeLossSampler;

    impl TcpNativeLossSampler {
        pub(super) fn from_stream(_stream: &TcpStream) -> Option<Self> {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_delta_skips_baseline_then_reports_loss() {
        let mut previous = None;
        assert_eq!(
            delta_from_counters(&mut previous, RawNativeCounters::new(100, 4)),
            None
        );
        assert_eq!(
            delta_from_counters(&mut previous, RawNativeCounters::new(140, 7)),
            Some(NativeLossSample::new(40, 3))
        );
    }

    #[test]
    fn counter_delta_ignores_idle_samples() {
        let mut previous = Some(RawNativeCounters::new(100, 4));
        assert_eq!(
            delta_from_counters(&mut previous, RawNativeCounters::new(100, 5)),
            None
        );
        assert_eq!(previous, Some(RawNativeCounters::new(100, 5)));
    }

    #[test]
    fn quic_path_stats_convert_to_raw_counters() {
        let mut path = quinn::PathStats::default();
        path.sent_packets = 123;
        path.lost_packets = 7;
        assert_eq!(quic_path_counters(&path), RawNativeCounters::new(123, 7));
    }
}
