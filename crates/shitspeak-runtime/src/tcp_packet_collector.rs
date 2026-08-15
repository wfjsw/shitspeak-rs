use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const FLOW_CACHE_TTL: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const FLOW_CACHE_CAPACITY: usize = 16_384;

#[derive(Clone, Debug)]
pub(crate) struct TcpPacketMetadata {
    ja4t: String,
    ja4l: Option<String>,
}

impl TcpPacketMetadata {
    pub(crate) fn ja4t(&self) -> &str {
        &self.ja4t
    }

    pub(crate) fn ja4l(&self) -> Option<&str> {
        self.ja4l.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FlowKey {
    source: SocketAddr,
    destination: SocketAddr,
}

#[derive(Clone, Debug)]
struct SynMetadata {
    observed_at: Instant,
    syn_ack_at: Option<Instant>,
    first_application_data_at: Option<Instant>,
    observed_ttl: u8,
    window_size: u16,
    options: String,
    maximum_segment_size: Option<u16>,
    window_scale: Option<u8>,
}

pub(crate) struct TcpPacketCollector {
    flows: Arc<Mutex<HashMap<FlowKey, SynMetadata>>>,
    active_backend: Option<String>,
}

impl TcpPacketCollector {
    pub(crate) fn start(available_backends: &[String]) -> Arc<Self> {
        static COLLECTOR: OnceLock<Arc<TcpPacketCollector>> = OnceLock::new();
        COLLECTOR
            .get_or_init(|| Self::start_once(available_backends))
            .clone()
    }

    #[cfg(target_os = "linux")]
    fn start_once(available_backends: &[String]) -> Arc<Self> {
        linux::start(available_backends)
    }

    #[cfg(not(target_os = "linux"))]
    fn start_once(_available_backends: &[String]) -> Arc<Self> {
        Arc::new(Self {
            flows: Arc::new(Mutex::new(HashMap::new())),
            active_backend: None,
        })
    }

    pub(crate) fn active_backend(&self) -> Option<&str> {
        self.active_backend.as_deref()
    }

    pub(crate) fn lookup(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Option<TcpPacketMetadata> {
        let now = Instant::now();
        let metadata = self
            .flows
            .lock()
            .get(&FlowKey {
                source,
                destination,
            })?
            .clone();
        if now.duration_since(metadata.observed_at) > FLOW_CACHE_TTL {
            return None;
        }
        let ja4t = format!(
            "{}_{}_{}_{}",
            metadata.window_size,
            metadata.options,
            metadata.maximum_segment_size.unwrap_or_default(),
            metadata.window_scale.unwrap_or_default(),
        );
        let ja4l = metadata.syn_ack_at.and_then(|syn_ack_at| {
            metadata
                .first_application_data_at
                .map(|application_data_at| {
                    let tcp_latency = syn_ack_at.duration_since(metadata.observed_at).as_micros();
                    let application_latency =
                        application_data_at.duration_since(syn_ack_at).as_micros();
                    format!(
                        "{tcp_latency}_{}_{}",
                        metadata.observed_ttl, application_latency
                    )
                })
        });
        Some(TcpPacketMetadata { ja4t, ja4l })
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    const BPF_PROG_LOAD: u32 = 5;
    const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
    const BPF_LD_ABS_H: u8 = 0x28;
    const BPF_LD_ABS_B: u8 = 0x30;
    const BPF_ALU64_MOV_K: u8 = 0xb7;
    const BPF_JMP_JEQ_K: u8 = 0x15;
    const BPF_JMP_EXIT: u8 = 0x95;
    const SO_ATTACH_BPF: libc::c_int = 50;

    #[repr(C)]
    struct BpfInsn {
        code: u8,
        dst_src: u8,
        off: i16,
        imm: i32,
    }

    #[repr(C)]
    struct BpfProgLoadAttr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
    }

    pub(super) fn start(available_backends: &[String]) -> Arc<TcpPacketCollector> {
        let flows = Arc::new(Mutex::new(HashMap::new()));
        let Ok(packet_fd) = open_packet_socket() else {
            tracing::debug!("could not open AF_PACKET socket for TCP metadata capture");
            return Arc::new(TcpPacketCollector {
                flows,
                active_backend: None,
            });
        };
        // An OwnedFd makes every error path close the socket, including a
        // thread-spawn failure.
        let packet_fd = unsafe { OwnedFd::from_raw_fd(packet_fd) };
        let backend = if available_backends.iter().any(|backend| backend == "ebpf") {
            match attach_ebpf_socket_filter(packet_fd.as_raw_fd()) {
                Ok(()) => Some("ebpf".to_owned()),
                Err(error) => {
                    tracing::debug!(%error, "eBPF socket filter unavailable; falling back to AF_PACKET");
                    available_backends
                        .iter()
                        .any(|backend| backend == "af_packet")
                        .then(|| "af_packet".to_owned())
                }
            }
        } else {
            available_backends
                .iter()
                .any(|backend| backend == "af_packet")
                .then(|| "af_packet".to_owned())
        };
        let Some(backend) = backend else {
            return Arc::new(TcpPacketCollector {
                flows,
                active_backend: None,
            });
        };
        let flow_cache = Arc::clone(&flows);
        let thread = std::thread::Builder::new()
            .name("shitspeak-tcp-packet-capture".to_owned())
            .spawn(move || receive_packets(packet_fd, flow_cache));
        if let Err(error) = thread {
            tracing::warn!(%error, "could not start TCP packet capture thread");
            return Arc::new(TcpPacketCollector {
                flows,
                active_backend: None,
            });
        }
        Arc::new(TcpPacketCollector {
            flows,
            active_backend: Some(backend),
        })
    }

    fn open_packet_socket() -> std::io::Result<RawFd> {
        let protocol = u16::try_from(libc::ETH_P_ALL).unwrap_or_default().to_be() as libc::c_int;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        (fd >= 0)
            .then_some(fd)
            .ok_or_else(std::io::Error::last_os_error)
    }

    fn attach_ebpf_socket_filter(socket_fd: RawFd) -> std::io::Result<()> {
        // Keep non-TCP Ethernet frames in the kernel. VLAN-tagged packets
        // deliberately pass through so the userspace parser can handle their
        // variable header length; the overwhelmingly common untagged path is
        // filtered before it reaches the receiver thread.
        let instructions = [
            BpfInsn {
                code: BPF_LD_ABS_H,
                dst_src: 0,
                off: 0,
                imm: 12,
            },
            BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 6,
                imm: 0x0800,
            },
            BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 9,
                imm: 0x86dd,
            },
            BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 12,
                imm: 0x8100,
            },
            BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 11,
                imm: 0x88a8,
            },
            BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 10,
                imm: 0x9100,
            },
            BpfInsn {
                code: BPF_ALU64_MOV_K,
                dst_src: 0,
                off: 0,
                imm: 0,
            },
            BpfInsn {
                code: BPF_JMP_EXIT,
                dst_src: 0,
                off: 0,
                imm: 0,
            },
            BpfInsn {
                code: BPF_LD_ABS_B,
                dst_src: 0,
                off: 0,
                imm: 23,
            },
            BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 6,
                imm: libc::IPPROTO_TCP,
            },
            BpfInsn {
                code: BPF_ALU64_MOV_K,
                dst_src: 0,
                off: 0,
                imm: 0,
            },
            BpfInsn {
                code: BPF_JMP_EXIT,
                dst_src: 0,
                off: 0,
                imm: 0,
            },
            BpfInsn {
                code: BPF_LD_ABS_B,
                dst_src: 0,
                off: 0,
                imm: 20,
            },
            BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 2,
                imm: libc::IPPROTO_TCP,
            },
            BpfInsn {
                code: BPF_ALU64_MOV_K,
                dst_src: 0,
                off: 0,
                imm: 0,
            },
            BpfInsn {
                code: BPF_JMP_EXIT,
                dst_src: 0,
                off: 0,
                imm: 0,
            },
            BpfInsn {
                code: BPF_ALU64_MOV_K,
                dst_src: 0,
                off: 0,
                imm: -1,
            },
            BpfInsn {
                code: BPF_JMP_EXIT,
                dst_src: 0,
                off: 0,
                imm: 0,
            },
        ];
        let license = b"GPL\0";
        let attr = BpfProgLoadAttr {
            prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
            insn_cnt: instructions.len() as u32,
            insns: instructions.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            kern_version: 0,
            prog_flags: 0,
            prog_name: *b"ss_tcp_capture\0\0",
        };
        let program_fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_LOAD,
                &attr as *const BpfProgLoadAttr,
                mem::size_of::<BpfProgLoadAttr>(),
            ) as RawFd
        };
        if program_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = unsafe {
            libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                SO_ATTACH_BPF,
                &program_fd as *const RawFd as *const libc::c_void,
                mem::size_of::<RawFd>() as libc::socklen_t,
            )
        };
        unsafe { libc::close(program_fd) };
        (result == 0)
            .then_some(())
            .ok_or_else(std::io::Error::last_os_error)
    }

    fn receive_packets(packet_fd: OwnedFd, flows: Arc<Mutex<HashMap<FlowKey, SynMetadata>>>) {
        let mut buffer = [0u8; 65_536];
        loop {
            let len = unsafe {
                libc::recv(
                    packet_fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if len <= 0 {
                continue;
            }
            if let Some(packet) = parse_packet(&buffer[..len as usize]) {
                update_flows(&flows, packet, Instant::now());
            }
        }
    }

    struct TcpPacket {
        source: SocketAddr,
        destination: SocketAddr,
        ttl: u8,
        syn: bool,
        ack: bool,
        payload_len: usize,
        window_size: u16,
        options: String,
        maximum_segment_size: Option<u16>,
        window_scale: Option<u8>,
    }

    fn parse_packet(bytes: &[u8]) -> Option<TcpPacket> {
        let (ether_type, mut offset) = ethernet_payload(bytes)?;
        let (source_ip, destination_ip, ttl, tcp_offset) = match ether_type {
            0x0800 => parse_ipv4(bytes, offset)?,
            0x86dd => parse_ipv6(bytes, offset)?,
            _ => return None,
        };
        offset = tcp_offset;
        let tcp = bytes.get(offset..)?;
        let source_port = u16::from_be_bytes([*tcp.first()?, *tcp.get(1)?]);
        let destination_port = u16::from_be_bytes([*tcp.get(2)?, *tcp.get(3)?]);
        let header_len = usize::from(*tcp.get(12)? >> 4) * 4;
        if header_len < 20 || tcp.len() < header_len {
            return None;
        }
        let flags = *tcp.get(13)?;
        let (options, maximum_segment_size, window_scale) = parse_tcp_options(&tcp[20..header_len]);
        Some(TcpPacket {
            source: SocketAddr::new(source_ip, source_port),
            destination: SocketAddr::new(destination_ip, destination_port),
            ttl,
            syn: flags & 0x02 != 0,
            ack: flags & 0x10 != 0,
            payload_len: tcp.len() - header_len,
            window_size: u16::from_be_bytes([*tcp.get(14)?, *tcp.get(15)?]),
            options,
            maximum_segment_size,
            window_scale,
        })
    }

    fn ethernet_payload(bytes: &[u8]) -> Option<(u16, usize)> {
        let mut offset = 14;
        let mut ether_type = u16::from_be_bytes([*bytes.get(12)?, *bytes.get(13)?]);
        while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
            ether_type = u16::from_be_bytes([*bytes.get(offset + 2)?, *bytes.get(offset + 3)?]);
            offset += 4;
        }
        Some((ether_type, offset))
    }

    fn parse_ipv4(bytes: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, u8, usize)> {
        let header = bytes.get(offset..)?;
        let header_len = usize::from(*header.first()? & 0x0f) * 4;
        if header_len < 20
            || header.len() < header_len
            || *header.get(9)? != libc::IPPROTO_TCP as u8
        {
            return None;
        }
        let source = IpAddr::V4(Ipv4Addr::new(
            *header.get(12)?,
            *header.get(13)?,
            *header.get(14)?,
            *header.get(15)?,
        ));
        let destination = IpAddr::V4(Ipv4Addr::new(
            *header.get(16)?,
            *header.get(17)?,
            *header.get(18)?,
            *header.get(19)?,
        ));
        Some((source, destination, *header.get(8)?, offset + header_len))
    }

    fn parse_ipv6(bytes: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, u8, usize)> {
        let header = bytes.get(offset..offset + 40)?;
        if *header.get(6)? != libc::IPPROTO_TCP as u8 {
            return None;
        }
        let source = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(header.get(8..24)?).ok()?,
        ));
        let destination = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(header.get(24..40)?).ok()?,
        ));
        Some((source, destination, *header.get(7)?, offset + 40))
    }

    fn parse_tcp_options(options: &[u8]) -> (String, Option<u16>, Option<u8>) {
        let mut kinds = Vec::new();
        let mut maximum_segment_size = None;
        let mut window_scale = None;
        let mut offset = 0;
        while offset < options.len() {
            let kind = options[offset];
            if kind == 0 {
                break;
            }
            kinds.push(kind.to_string());
            if kind == 1 {
                offset += 1;
                continue;
            }
            let len = usize::from(*options.get(offset + 1).unwrap_or(&0));
            if len < 2 || offset + len > options.len() {
                break;
            }
            if kind == 2 && len == 4 {
                maximum_segment_size = Some(u16::from_be_bytes([
                    options[offset + 2],
                    options[offset + 3],
                ]));
            }
            if kind == 3 && len == 3 {
                window_scale = Some(options[offset + 2]);
            }
            offset += len;
        }
        (kinds.join("-"), maximum_segment_size, window_scale)
    }

    fn update_flows(flows: &Mutex<HashMap<FlowKey, SynMetadata>>, packet: TcpPacket, now: Instant) {
        let key = FlowKey {
            source: packet.source,
            destination: packet.destination,
        };
        let reverse = FlowKey {
            source: packet.destination,
            destination: packet.source,
        };
        let mut flows = flows.lock();
        if packet.syn && !packet.ack {
            if flows.len() >= FLOW_CACHE_CAPACITY {
                flows.retain(|_, metadata| {
                    now.duration_since(metadata.observed_at) <= FLOW_CACHE_TTL
                });
                if flows.len() >= FLOW_CACHE_CAPACITY
                    && let Some(key) = flows.keys().next().copied()
                {
                    flows.remove(&key);
                }
            }
            flows.insert(
                key,
                SynMetadata {
                    observed_at: now,
                    syn_ack_at: None,
                    first_application_data_at: None,
                    observed_ttl: packet.ttl,
                    window_size: packet.window_size,
                    options: packet.options,
                    maximum_segment_size: packet.maximum_segment_size,
                    window_scale: packet.window_scale,
                },
            );
        } else if packet.syn && packet.ack {
            if let Some(metadata) = flows.get_mut(&reverse) {
                metadata.syn_ack_at = Some(now);
            }
        } else if packet.payload_len > 0 {
            if let Some(metadata) = flows.get_mut(&key)
                && metadata.first_application_data_at.is_none()
            {
                metadata.first_application_data_at = Some(now);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_syn_options_and_produces_tcp_fingerprints() {
            let mut packet = vec![0; 14 + 20 + 32];
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            packet[14] = 0x45;
            packet[22] = 57;
            packet[23] = libc::IPPROTO_TCP as u8;
            packet[26..30].copy_from_slice(&[192, 0, 2, 1]);
            packet[30..34].copy_from_slice(&[198, 51, 100, 2]);
            let tcp = 34;
            packet[tcp..tcp + 2].copy_from_slice(&50000u16.to_be_bytes());
            packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
            packet[tcp + 12] = 8 << 4;
            packet[tcp + 13] = 0x02;
            packet[tcp + 14..tcp + 16].copy_from_slice(&64240u16.to_be_bytes());
            packet[tcp + 20..tcp + 32].copy_from_slice(&[
                2, 4, 0x05, 0xb4, // MSS 1460
                1,    // NOP
                3, 3, 8, // window scale
                4, 2, // SACK permitted
                0, 0, // end of option list and padding
            ]);

            let syn = parse_packet(&packet).expect("SYN must parse");
            assert!(syn.syn);
            assert_eq!(syn.options, "2-1-3-4");
            assert_eq!(syn.maximum_segment_size, Some(1460));
            assert_eq!(syn.window_scale, Some(8));

            let flows = Mutex::new(HashMap::new());
            let now = Instant::now();
            let source = syn.source;
            let destination = syn.destination;
            update_flows(&flows, syn, now);
            update_flows(
                &flows,
                TcpPacket {
                    source: destination,
                    destination: source,
                    ttl: 64,
                    syn: true,
                    ack: true,
                    payload_len: 0,
                    window_size: 0,
                    options: String::new(),
                    maximum_segment_size: None,
                    window_scale: None,
                },
                now + Duration::from_micros(125),
            );
            update_flows(
                &flows,
                TcpPacket {
                    source,
                    destination,
                    ttl: 57,
                    syn: false,
                    ack: true,
                    payload_len: 1,
                    window_size: 0,
                    options: String::new(),
                    maximum_segment_size: None,
                    window_scale: None,
                },
                now + Duration::from_micros(275),
            );

            let collector = TcpPacketCollector {
                flows: Arc::new(flows),
                active_backend: Some("af_packet".to_owned()),
            };
            let metadata = collector
                .lookup(source, destination)
                .expect("flow must remain cached");
            assert_eq!(metadata.ja4t(), "64240_2-1-3-4_1460_8");
            assert_eq!(metadata.ja4l(), Some("125_57_150"));
        }
    }
}
