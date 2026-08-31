use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use scc::HashCache;
use tokio::sync::Notify;

const FLOW_CACHE_TTL: Duration = Duration::from_secs(10);
const FLOW_METADATA_WAIT: Duration = Duration::from_secs(1);
const FLOW_CACHE_CAPACITY: usize = 16_384;

type FlowCache = HashCache<FlowKey, SynMetadata>;

fn new_flow_cache() -> FlowCache {
    HashCache::with_capacity(FLOW_CACHE_CAPACITY, FLOW_CACHE_CAPACITY)
}

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
    flows: Arc<FlowCache>,
    flow_updates: Arc<Notify>,
    active_backend: Option<String>,
    #[cfg(target_os = "linux")]
    packet_filter_controller: Option<Arc<linux::PacketFilterController>>,
}

impl TcpPacketCollector {
    pub(crate) fn start(
        available_backends: &[String],
        listener_ports: impl IntoIterator<Item = u16>,
    ) -> Arc<Self> {
        let listener_ports = listener_ports.into_iter().collect::<Vec<_>>();
        static COLLECTOR: OnceLock<Arc<TcpPacketCollector>> = OnceLock::new();
        let collector = COLLECTOR
            .get_or_init(|| Self::start_once(available_backends, &listener_ports))
            .clone();
        collector.register_listener_ports(listener_ports);
        collector
    }

    #[cfg(target_os = "linux")]
    fn start_once(available_backends: &[String], listener_ports: &[u16]) -> Arc<Self> {
        linux::start(available_backends, listener_ports)
    }

    #[cfg(not(target_os = "linux"))]
    fn start_once(_available_backends: &[String], _listener_ports: &[u16]) -> Arc<Self> {
        Arc::new(Self {
            flows: Arc::new(new_flow_cache()),
            flow_updates: Arc::new(Notify::new()),
            active_backend: None,
        })
    }

    pub(crate) fn register_listener_ports(&self, listener_ports: impl IntoIterator<Item = u16>) {
        #[cfg(target_os = "linux")]
        if let Some(controller) = &self.packet_filter_controller {
            controller.register_listener_ports(listener_ports);
        }

        #[cfg(not(target_os = "linux"))]
        let _ = listener_ports;
    }

    pub(crate) fn active_backend(&self) -> Option<&str> {
        self.active_backend.as_deref()
    }

    pub(crate) fn lookup(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Option<TcpPacketMetadata> {
        let source = shitspeak_auth::canonical_socket_addr(source);
        let destination = shitspeak_auth::canonical_socket_addr(destination);
        let now = Instant::now();
        let key = FlowKey {
            source,
            destination,
        };
        let metadata = self.flows.read_sync(&key, |_, metadata| metadata.clone())?;
        if now.duration_since(metadata.observed_at) > FLOW_CACHE_TTL {
            self.flows
                .remove_if_sync(&key, |current| current.observed_at == metadata.observed_at);
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

    /// Wait for the packet receiver to publish the flow observed by the
    /// completed TLS handshake. This closes the race between the asynchronous
    /// AF_PACKET receiver and the one-time authentication snapshot. A timeout
    /// still preserves best-effort behavior for dropped or unavailable
    /// captures.
    pub(crate) async fn lookup_after_capture(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Option<TcpPacketMetadata> {
        let deadline = tokio::time::Instant::now() + FLOW_METADATA_WAIT;
        loop {
            let notified = self.flow_updates.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let metadata = self.lookup(source, destination);
            if metadata
                .as_ref()
                .is_some_and(|metadata| metadata.ja4l().is_some())
            {
                return metadata;
            }
            if tokio::time::timeout_at(deadline, &mut notified)
                .await
                .is_err()
            {
                return self.lookup(source, destination);
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use parking_lot::Mutex;

    const BPF_PROG_LOAD: u32 = 5;
    const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
    const BPF_LD_ABS_H: u8 = 0x28;
    const BPF_LD_ABS_B: u8 = 0x30;
    const BPF_ALU64_MOV_K: u8 = 0xb7;
    const BPF_ALU64_MOV_X: u8 = 0xbf;
    const BPF_JMP_JEQ_K: u8 = 0x15;
    const BPF_JMP_EXIT: u8 = 0x95;
    const SO_ATTACH_BPF: libc::c_int = 50;
    const CAPTURE_SNAPSHOT_LEN: usize = 256;

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

    struct PacketFilterState {
        listener_ports: BTreeSet<u16>,
        narrowed: bool,
    }

    pub(super) struct PacketFilterController {
        packet_fd: Arc<OwnedFd>,
        state: Mutex<PacketFilterState>,
    }

    impl PacketFilterController {
        fn new(packet_fd: Arc<OwnedFd>, listener_ports: &[u16]) -> Self {
            Self {
                packet_fd,
                state: Mutex::new(PacketFilterState {
                    listener_ports: listener_ports.iter().copied().collect(),
                    narrowed: false,
                }),
            }
        }

        fn install_initial(&self) -> std::io::Result<()> {
            let mut state = self.state.lock();
            install_listener_filter(self.packet_fd.as_raw_fd(), &mut state)
        }

        pub(super) fn register_listener_ports(
            &self,
            listener_ports: impl IntoIterator<Item = u16>,
        ) {
            let mut state = self.state.lock();
            let mut changed = false;
            for port in listener_ports {
                changed |= state.listener_ports.insert(port);
            }
            if !changed && state.narrowed {
                return;
            }
            if let Err(error) = install_listener_filter(self.packet_fd.as_raw_fd(), &mut state) {
                tracing::warn!(%error, "could not update listener-port TCP packet filter");
            }
        }
    }

    fn install_listener_filter(
        socket_fd: RawFd,
        state: &mut PacketFilterState,
    ) -> std::io::Result<()> {
        let ports = state.listener_ports.iter().copied().collect::<Vec<_>>();
        match attach_ebpf_socket_filter(socket_fd, &ports) {
            Ok(()) => {
                state.narrowed = !ports.is_empty();
                Ok(())
            }
            Err(narrow_error) if !ports.is_empty() => {
                attach_ebpf_socket_filter(socket_fd, &[]).map_err(|broad_error| {
                    std::io::Error::other(format!(
                        "listener filter: {narrow_error}; broad fallback: {broad_error}"
                    ))
                })?;
                state.narrowed = false;
                tracing::warn!(%narrow_error, "listener-port eBPF filter unavailable; using broad TCP filter");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn start(
        available_backends: &[String],
        listener_ports: &[u16],
    ) -> Arc<TcpPacketCollector> {
        let flows = Arc::new(new_flow_cache());
        let flow_updates = Arc::new(Notify::new());
        let Ok(packet_fd) = open_packet_socket() else {
            tracing::debug!("could not open AF_PACKET socket for TCP metadata capture");
            return Arc::new(TcpPacketCollector {
                flows,
                flow_updates,
                active_backend: None,
                packet_filter_controller: None,
            });
        };
        // An OwnedFd makes every error path close the socket, including a
        // thread-spawn failure.
        let packet_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(packet_fd) });
        let mut packet_filter_controller = None;
        let backend = if available_backends.iter().any(|backend| backend == "ebpf") {
            let controller = Arc::new(PacketFilterController::new(
                Arc::clone(&packet_fd),
                listener_ports,
            ));
            match controller.install_initial() {
                Ok(()) => {
                    packet_filter_controller = Some(controller);
                    Some("ebpf".to_owned())
                }
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
                flow_updates,
                active_backend: None,
                packet_filter_controller: None,
            });
        };
        let flow_cache = Arc::clone(&flows);
        let updates = Arc::clone(&flow_updates);
        let thread = std::thread::Builder::new()
            .name("shitspeak-tcp-packet-capture".to_owned())
            .spawn(move || receive_packets(packet_fd, flow_cache, updates));
        if let Err(error) = thread {
            tracing::warn!(%error, "could not start TCP packet capture thread");
            return Arc::new(TcpPacketCollector {
                flows,
                flow_updates,
                active_backend: None,
                packet_filter_controller: None,
            });
        }
        Arc::new(TcpPacketCollector {
            flows,
            flow_updates,
            active_backend: Some(backend),
            packet_filter_controller,
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

    struct FilterBuilder {
        instructions: Vec<BpfInsn>,
        labels: HashMap<usize, usize>,
        jumps: Vec<(usize, usize)>,
        next_label: usize,
    }

    impl FilterBuilder {
        fn new() -> Self {
            Self {
                instructions: vec![socket_filter_context_prologue()],
                labels: HashMap::new(),
                jumps: Vec::new(),
                next_label: 0,
            }
        }

        fn new_label(&mut self) -> usize {
            let label = self.next_label;
            self.next_label += 1;
            label
        }

        fn mark(&mut self, label: usize) {
            self.labels.insert(label, self.instructions.len());
        }

        fn load_byte(&mut self, offset: usize) {
            self.instructions.push(BpfInsn {
                code: BPF_LD_ABS_B,
                dst_src: 0,
                off: 0,
                imm: offset as i32,
            });
        }

        fn load_half(&mut self, offset: usize) {
            self.instructions.push(BpfInsn {
                code: BPF_LD_ABS_H,
                dst_src: 0,
                off: 0,
                imm: offset as i32,
            });
        }

        fn jump_equal(&mut self, value: i32, label: usize) {
            let index = self.instructions.len();
            self.instructions.push(BpfInsn {
                code: BPF_JMP_JEQ_K,
                dst_src: 0,
                off: 0,
                imm: value,
            });
            self.jumps.push((index, label));
        }

        fn return_value(&mut self, value: i32) {
            self.instructions.push(BpfInsn {
                code: BPF_ALU64_MOV_K,
                dst_src: 0,
                off: 0,
                imm: value,
            });
            self.instructions.push(BpfInsn {
                code: BPF_JMP_EXIT,
                dst_src: 0,
                off: 0,
                imm: 0,
            });
        }

        fn finish(mut self) -> std::io::Result<Vec<BpfInsn>> {
            for (instruction, label) in self.jumps {
                let target = *self
                    .labels
                    .get(&label)
                    .ok_or_else(|| std::io::Error::other("unresolved eBPF filter label"))?;
                let relative = target as isize - instruction as isize - 1;
                self.instructions[instruction].off = i16::try_from(relative)
                    .map_err(|_| std::io::Error::other("eBPF listener filter is too large"))?;
            }
            Ok(self.instructions)
        }
    }

    fn build_socket_filter(listener_ports: &[u16]) -> std::io::Result<Vec<BpfInsn>> {
        let mut builder = FilterBuilder::new();
        let accept = builder.new_label();
        append_ethernet_dispatch(&mut builder, 12, 14, 0, listener_ports, accept);
        builder.mark(accept);
        builder.return_value(CAPTURE_SNAPSHOT_LEN as i32);
        builder.finish()
    }

    fn append_ethernet_dispatch(
        builder: &mut FilterBuilder,
        ether_type_offset: usize,
        ip_offset: usize,
        vlan_depth: usize,
        listener_ports: &[u16],
        accept: usize,
    ) {
        let ipv4 = builder.new_label();
        let ipv6 = builder.new_label();
        let vlan = builder.new_label();
        builder.load_half(ether_type_offset);
        builder.jump_equal(0x0800, ipv4);
        builder.jump_equal(0x86dd, ipv6);
        for ether_type in [0x8100, 0x88a8, 0x9100] {
            builder.jump_equal(ether_type, if vlan_depth < 2 { vlan } else { accept });
        }
        builder.return_value(0);

        builder.mark(ipv4);
        append_ipv4_filter(builder, ip_offset, listener_ports, accept);
        builder.mark(ipv6);
        append_ipv6_filter(builder, ip_offset, listener_ports, accept);

        if vlan_depth < 2 {
            builder.mark(vlan);
            append_ethernet_dispatch(
                builder,
                ether_type_offset + 4,
                ip_offset + 4,
                vlan_depth + 1,
                listener_ports,
                accept,
            );
        }
    }

    fn append_ipv4_filter(
        builder: &mut FilterBuilder,
        ip_offset: usize,
        listener_ports: &[u16],
        accept: usize,
    ) {
        let tcp = builder.new_label();
        builder.load_byte(ip_offset + 9);
        builder.jump_equal(libc::IPPROTO_TCP, tcp);
        builder.return_value(0);
        builder.mark(tcp);
        if listener_ports.is_empty() {
            builder.return_value(CAPTURE_SNAPSHOT_LEN as i32);
            return;
        }

        let fixed_header = builder.new_label();
        builder.load_byte(ip_offset);
        builder.jump_equal(0x45, fixed_header);
        builder.return_value(CAPTURE_SNAPSHOT_LEN as i32);
        builder.mark(fixed_header);
        append_port_filter(builder, ip_offset + 20, listener_ports, accept);
    }

    fn append_ipv6_filter(
        builder: &mut FilterBuilder,
        ip_offset: usize,
        listener_ports: &[u16],
        accept: usize,
    ) {
        let tcp = builder.new_label();
        builder.load_byte(ip_offset + 6);
        builder.jump_equal(libc::IPPROTO_TCP, tcp);
        builder.return_value(0);
        builder.mark(tcp);
        if listener_ports.is_empty() {
            builder.return_value(CAPTURE_SNAPSHOT_LEN as i32);
            return;
        }
        append_port_filter(builder, ip_offset + 40, listener_ports, accept);
    }

    fn append_port_filter(
        builder: &mut FilterBuilder,
        tcp_offset: usize,
        listener_ports: &[u16],
        accept: usize,
    ) {
        builder.load_half(tcp_offset);
        for port in listener_ports {
            builder.jump_equal(i32::from(*port), accept);
        }
        builder.load_half(tcp_offset + 2);
        for port in listener_ports {
            builder.jump_equal(i32::from(*port), accept);
        }
        builder.return_value(0);
    }

    fn attach_ebpf_socket_filter(socket_fd: RawFd, listener_ports: &[u16]) -> std::io::Result<()> {
        let instructions = build_socket_filter(listener_ports)?;
        let license = b"GPL\0";
        let attr = BpfProgLoadAttr {
            prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
            insn_cnt: u32::try_from(instructions.len())
                .map_err(|_| std::io::Error::other("eBPF listener filter is too large"))?,
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

    fn socket_filter_context_prologue() -> BpfInsn {
        // BPF_LD_ABS uses r6 as the saved socket-buffer context. The verifier
        // rejects the packet loads unless it is initialized from r1 first.
        BpfInsn {
            code: BPF_ALU64_MOV_X,
            dst_src: 0x16,
            off: 0,
            imm: 0,
        }
    }

    fn receive_packets(packet_fd: Arc<OwnedFd>, flows: Arc<FlowCache>, flow_updates: Arc<Notify>) {
        let mut buffer = [0u8; CAPTURE_SNAPSHOT_LEN];
        let mut receive_error_active = false;
        loop {
            let len = unsafe {
                libc::recv(
                    packet_fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if len < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if !receive_error_active {
                    tracing::warn!(%error, "TCP packet capture receive failed; retrying with backoff");
                }
                receive_error_active = true;
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            if len == 0 {
                if !receive_error_active {
                    tracing::warn!(
                        "TCP packet capture returned an empty packet; retrying with backoff"
                    );
                }
                receive_error_active = true;
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            receive_error_active = false;
            if let Some(packet) = parse_packet(&buffer[..len as usize]) {
                if update_flows(&flows, packet, Instant::now()) {
                    flow_updates.notify_waiters();
                }
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
        let (source_ip, destination_ip, ttl, tcp_offset, tcp_segment_len) = match ether_type {
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
        let syn = flags & 0x02 != 0;
        let (options, maximum_segment_size, window_scale) = if syn {
            parse_tcp_options(&tcp[20..header_len])
        } else {
            (String::new(), None, None)
        };
        Some(TcpPacket {
            source: SocketAddr::new(source_ip, source_port),
            destination: SocketAddr::new(destination_ip, destination_port),
            ttl,
            syn,
            ack: flags & 0x10 != 0,
            payload_len: tcp_segment_len.checked_sub(header_len)?,
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

    fn parse_ipv4(bytes: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, u8, usize, usize)> {
        let header = bytes.get(offset..)?;
        let header_len = usize::from(*header.first()? & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([*header.get(2)?, *header.get(3)?]));
        let fragment = u16::from_be_bytes([*header.get(6)?, *header.get(7)?]);
        if header_len < 20
            || header.len() < header_len
            || total_len < header_len
            || fragment & 0x3fff != 0
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
        Some((
            source,
            destination,
            *header.get(8)?,
            offset + header_len,
            total_len - header_len,
        ))
    }

    fn parse_ipv6(bytes: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, u8, usize, usize)> {
        let header = bytes.get(offset..offset + 40)?;
        if *header.get(6)? != libc::IPPROTO_TCP as u8 {
            return None;
        }
        let payload_len = usize::from(u16::from_be_bytes([*header.get(4)?, *header.get(5)?]));
        let source = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(header.get(8..24)?).ok()?,
        ));
        let destination = IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(header.get(24..40)?).ok()?,
        ));
        Some((
            source,
            destination,
            *header.get(7)?,
            offset + 40,
            payload_len,
        ))
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

    fn update_flows(flows: &FlowCache, packet: TcpPacket, now: Instant) -> bool {
        if !packet.syn && packet.payload_len == 0 {
            return false;
        }
        let key = FlowKey {
            source: packet.source,
            destination: packet.destination,
        };
        let reverse = FlowKey {
            source: packet.destination,
            destination: packet.source,
        };
        if packet.syn && !packet.ack {
            flows.entry_sync(key).put_entry(SynMetadata {
                observed_at: now,
                syn_ack_at: None,
                first_application_data_at: None,
                observed_ttl: packet.ttl,
                window_size: packet.window_size,
                options: packet.options,
                maximum_segment_size: packet.maximum_segment_size,
                window_scale: packet.window_scale,
            });
            true
        } else if packet.syn && packet.ack {
            let Some(mut entry) = flows.get_sync(&reverse) else {
                return false;
            };
            if now.duration_since(entry.get().observed_at) > FLOW_CACHE_TTL {
                let _ = entry.remove();
                return false;
            }
            let metadata = entry.get_mut();
            if metadata.syn_ack_at.is_some() {
                return false;
            }
            metadata.syn_ack_at = Some(now);
            true
        } else if packet.payload_len > 0 {
            let Some(mut entry) = flows.get_sync(&key) else {
                return false;
            };
            if now.duration_since(entry.get().observed_at) > FLOW_CACHE_TTL {
                let _ = entry.remove();
                return false;
            }
            let metadata = entry.get_mut();
            if metadata.first_application_data_at.is_some() {
                return false;
            }
            metadata.first_application_data_at = Some(now);
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ipv4_tcp_packet(source_port: u16, destination_port: u16, payload_len: usize) -> Vec<u8> {
            let captured_payload_len = payload_len.min(CAPTURE_SNAPSHOT_LEN - 54);
            let mut packet = vec![0; 14 + 20 + 20 + captured_payload_len];
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            packet[14] = 0x45;
            packet[16..18].copy_from_slice(&u16::try_from(40 + payload_len).unwrap().to_be_bytes());
            packet[22] = 57;
            packet[23] = libc::IPPROTO_TCP as u8;
            packet[26..30].copy_from_slice(&[192, 0, 2, 1]);
            packet[30..34].copy_from_slice(&[198, 51, 100, 2]);
            packet[34..36].copy_from_slice(&source_port.to_be_bytes());
            packet[36..38].copy_from_slice(&destination_port.to_be_bytes());
            packet[46] = 5 << 4;
            packet
        }

        fn vlan_packet(packet: &[u8], ether_type: u16) -> Vec<u8> {
            let mut tagged = vec![0; packet.len() + 4];
            tagged[..12].copy_from_slice(&packet[..12]);
            tagged[12..14].copy_from_slice(&ether_type.to_be_bytes());
            tagged[16..].copy_from_slice(&packet[12..]);
            tagged
        }

        fn ipv6_tcp_packet(source_port: u16, destination_port: u16) -> Vec<u8> {
            let mut packet = vec![0; 14 + 40 + 20];
            packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            packet[14] = 0x60;
            packet[18..20].copy_from_slice(&20u16.to_be_bytes());
            packet[20] = libc::IPPROTO_TCP as u8;
            packet[21] = 57;
            packet[22..38].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            packet[38..54].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            packet[54..56].copy_from_slice(&source_port.to_be_bytes());
            packet[56..58].copy_from_slice(&destination_port.to_be_bytes());
            packet[66] = 5 << 4;
            packet
        }

        fn run_socket_filter(instructions: &[BpfInsn], packet: &[u8]) -> u32 {
            let mut accumulator = 0i32;
            let mut instruction = 0usize;
            loop {
                let current = &instructions[instruction];
                match current.code {
                    BPF_ALU64_MOV_X => {}
                    BPF_ALU64_MOV_K => accumulator = current.imm,
                    BPF_LD_ABS_B => {
                        let Some(value) = packet.get(current.imm as usize) else {
                            return 0;
                        };
                        accumulator = i32::from(*value);
                    }
                    BPF_LD_ABS_H => {
                        let offset = current.imm as usize;
                        let Some(bytes) = packet.get(offset..offset + 2) else {
                            return 0;
                        };
                        accumulator = i32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                    }
                    BPF_JMP_JEQ_K => {
                        if accumulator == current.imm {
                            instruction =
                                (instruction as isize + isize::from(current.off) + 1) as usize;
                            continue;
                        }
                    }
                    BPF_JMP_EXIT => return accumulator as u32,
                    code => panic!("unsupported test eBPF instruction {code:#x}"),
                }
                instruction += 1;
            }
        }

        #[test]
        fn socket_filter_initializes_r6_with_the_socket_buffer_context() {
            let instruction = socket_filter_context_prologue();

            assert_eq!(instruction.code, BPF_ALU64_MOV_X);
            assert_eq!(instruction.dst_src, 0x16, "destination r6, source r1");
            assert_eq!(instruction.off, 0);
            assert_eq!(instruction.imm, 0);
        }

        #[test]
        fn socket_filter_limits_capture_to_listener_ports() {
            let instructions = build_socket_filter(&[443, 64738]).expect("build filter");

            assert_eq!(
                run_socket_filter(&instructions, &ipv4_tcp_packet(50000, 443, 0)),
                CAPTURE_SNAPSHOT_LEN as u32
            );
            assert_eq!(
                run_socket_filter(&instructions, &ipv4_tcp_packet(64738, 50000, 0)),
                CAPTURE_SNAPSHOT_LEN as u32
            );
            assert_eq!(
                run_socket_filter(&instructions, &ipv4_tcp_packet(50000, 8443, 0)),
                0
            );
            assert_eq!(
                run_socket_filter(&instructions, &ipv6_tcp_packet(50000, 443)),
                CAPTURE_SNAPSHOT_LEN as u32
            );
            assert_eq!(
                run_socket_filter(&instructions, &ipv6_tcp_packet(50000, 8443)),
                0
            );

            let mut udp = ipv4_tcp_packet(50000, 443, 0);
            udp[23] = libc::IPPROTO_UDP as u8;
            assert_eq!(run_socket_filter(&instructions, &udp), 0);
        }

        #[test]
        fn socket_filter_handles_common_vlan_depths() {
            let instructions = build_socket_filter(&[443]).expect("build filter");
            let untagged = ipv4_tcp_packet(50000, 443, 0);
            let single = vlan_packet(&untagged, 0x8100);
            let double = vlan_packet(&single, 0x88a8);

            assert_eq!(
                run_socket_filter(&instructions, &single),
                CAPTURE_SNAPSHOT_LEN as u32
            );
            assert_eq!(
                run_socket_filter(&instructions, &double),
                CAPTURE_SNAPSHOT_LEN as u32
            );

            let unrelated = vlan_packet(&ipv4_tcp_packet(50000, 8443, 0), 0x8100);
            assert_eq!(run_socket_filter(&instructions, &unrelated), 0);
        }

        #[test]
        fn broad_socket_filter_keeps_tcp_and_rejects_udp() {
            let instructions = build_socket_filter(&[]).expect("build filter");
            let tcp = ipv4_tcp_packet(50000, 8443, 0);
            assert_eq!(
                run_socket_filter(&instructions, &tcp),
                CAPTURE_SNAPSHOT_LEN as u32
            );

            let mut udp = tcp;
            udp[23] = libc::IPPROTO_UDP as u8;
            assert_eq!(run_socket_filter(&instructions, &udp), 0);
        }

        #[test]
        fn parses_syn_options_and_produces_tcp_fingerprints() {
            let mut packet = vec![0; 14 + 20 + 32];
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            packet[14] = 0x45;
            packet[16..18].copy_from_slice(&52u16.to_be_bytes());
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

            let flows = new_flow_cache();
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
                flow_updates: Arc::new(Notify::new()),
                active_backend: Some("af_packet".to_owned()),
                packet_filter_controller: None,
            };
            let mapped_source = SocketAddr::new(
                IpAddr::V6(match source.ip() {
                    IpAddr::V4(address) => address.to_ipv6_mapped(),
                    IpAddr::V6(_) => unreachable!("fixture uses IPv4"),
                }),
                source.port(),
            );
            let mapped_destination = SocketAddr::new(
                IpAddr::V6(match destination.ip() {
                    IpAddr::V4(address) => address.to_ipv6_mapped(),
                    IpAddr::V6(_) => unreachable!("fixture uses IPv4"),
                }),
                destination.port(),
            );
            let metadata = collector
                .lookup(mapped_source, mapped_destination)
                .expect("flow must remain cached");
            assert_eq!(metadata.ja4t(), "64240_2-1-3-4_1460_8");
            assert_eq!(metadata.ja4l(), Some("125_57_150"));
        }

        #[test]
        fn ethernet_padding_does_not_count_as_tcp_payload() {
            let mut packet = vec![0; 60];
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            packet[14] = 0x45;
            packet[16..18].copy_from_slice(&40u16.to_be_bytes());
            packet[22] = 57;
            packet[23] = libc::IPPROTO_TCP as u8;
            packet[26..30].copy_from_slice(&[192, 0, 2, 1]);
            packet[30..34].copy_from_slice(&[198, 51, 100, 2]);
            let tcp = 34;
            packet[tcp..tcp + 2].copy_from_slice(&50000u16.to_be_bytes());
            packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
            packet[tcp + 12] = 5 << 4;
            packet[tcp + 13] = 0x10;

            let ack = parse_packet(&packet).expect("ACK must parse");
            assert_eq!(ack.payload_len, 0);
            assert!(!update_flows(&new_flow_cache(), ack, Instant::now()));
        }

        #[test]
        fn truncated_capture_uses_declared_tcp_payload_length() {
            let packet = ipv4_tcp_packet(50000, 443, 1_000);
            let parsed = parse_packet(&packet).expect("truncated packet must parse");
            assert_eq!(parsed.payload_len, 1_000);
            assert!(parsed.options.is_empty());
        }

        #[test]
        fn fragmented_ipv4_packet_is_rejected() {
            let mut packet = ipv4_tcp_packet(50000, 443, 0);
            packet[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
            assert!(parse_packet(&packet).is_none());
        }

        #[test]
        fn retransmitted_syn_ack_keeps_the_first_observation() {
            let flows = new_flow_cache();
            let source: SocketAddr = "192.0.2.1:50000".parse().expect("source address");
            let destination: SocketAddr = "198.51.100.2:443".parse().expect("destination address");
            let now = Instant::now();
            assert!(update_flows(
                &flows,
                TcpPacket {
                    source,
                    destination,
                    ttl: 57,
                    syn: true,
                    ack: false,
                    payload_len: 0,
                    window_size: 64240,
                    options: "2-1-3-4".to_owned(),
                    maximum_segment_size: Some(1460),
                    window_scale: Some(8),
                },
                now,
            ));
            let first_syn_ack = now + Duration::from_micros(125);
            for (index, observed_at) in [first_syn_ack, now + Duration::from_micros(250)]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
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
                        observed_at,
                    ),
                    index == 0
                );
            }

            assert_eq!(
                flows
                    .read_sync(
                        &FlowKey {
                            source,
                            destination,
                        },
                        |_, metadata| metadata.syn_ack_at,
                    )
                    .flatten(),
                Some(first_syn_ack)
            );

            let first_data = now + Duration::from_micros(375);
            for (index, observed_at) in [first_data, now + Duration::from_micros(500)]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
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
                        observed_at,
                    ),
                    index == 0
                );
            }
        }

        #[tokio::test]
        async fn waits_for_flow_publication_before_snapshotting_metadata() {
            let flows = Arc::new(new_flow_cache());
            let flow_updates = Arc::new(Notify::new());
            let collector = Arc::new(TcpPacketCollector {
                flows: Arc::clone(&flows),
                flow_updates: Arc::clone(&flow_updates),
                active_backend: Some("ebpf".to_owned()),
                packet_filter_controller: None,
            });
            let source: SocketAddr = "192.0.2.1:50000".parse().expect("source address");
            let destination: SocketAddr = "198.51.100.2:443".parse().expect("destination address");

            let lookup = tokio::spawn({
                let collector = Arc::clone(&collector);
                async move { collector.lookup_after_capture(source, destination).await }
            });
            tokio::task::yield_now().await;

            let now = Instant::now();
            update_flows(
                &flows,
                TcpPacket {
                    source,
                    destination,
                    ttl: 57,
                    syn: true,
                    ack: false,
                    payload_len: 0,
                    window_size: 64240,
                    options: "2-1-3-4".to_owned(),
                    maximum_segment_size: Some(1460),
                    window_scale: Some(8),
                },
                now,
            );
            flow_updates.notify_waiters();
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
            flow_updates.notify_waiters();
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
            flow_updates.notify_waiters();

            let metadata = lookup
                .await
                .expect("lookup task must complete")
                .expect("published flow metadata");
            assert_eq!(metadata.ja4t(), "64240_2-1-3-4_1460_8");
            assert_eq!(metadata.ja4l(), Some("125_57_150"));
        }
    }
}
