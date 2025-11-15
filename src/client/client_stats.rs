
#[derive(Debug, Clone, Copy)]
pub struct ClientStats {
    udp_ping_avg: f32,
    udp_ping_var: f32,
    udp_packets: u32,
    udp_total_packets: u64,
    udp_volume: u64,
    tcp_ping_avg: f32,
    tcp_ping_var: f32,
    tcp_packets: u32,
    tcp_total_packets: u64,
    tcp_volume: u64,
}
