
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

impl Default for ClientStats {
    fn default() -> Self {
        ClientStats {
            udp_ping_avg: 0.0,
            udp_ping_var: 0.0,
            udp_packets: 0,
            udp_total_packets: 0,
            udp_volume: 0,
            tcp_ping_avg: 0.0,
            tcp_ping_var: 0.0,
            tcp_packets: 0,
            tcp_total_packets: 0,
            tcp_volume: 0,
        }
    }
}
