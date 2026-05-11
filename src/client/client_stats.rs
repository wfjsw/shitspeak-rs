use crate::messages::encoder::Ping;

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

impl ClientStats {
    pub fn update_from_ping_message(&mut self, ping_message: &Ping) {
        if let Some(udp_packets) = ping_message.udp_packets {
            self.udp_packets = udp_packets;
        }
        if let Some(tcp_packets) = ping_message.tcp_packets {
            self.tcp_packets = tcp_packets;
        }
        if let Some(udp_ping_avg) = ping_message.udp_ping_avg {
            self.udp_ping_avg = udp_ping_avg;
        }
        if let Some(udp_ping_var) = ping_message.udp_ping_var {
            self.udp_ping_var = udp_ping_var;
        }
        if let Some(tcp_ping_avg) = ping_message.tcp_ping_avg {
            self.tcp_ping_avg = tcp_ping_avg;
        }
        if let Some(tcp_ping_var) = ping_message.tcp_ping_var {
            self.tcp_ping_var = tcp_ping_var;
        }
    }

    pub fn udp_ping_avg(&self) -> f32 {
        self.udp_ping_avg
    }
    pub fn udp_ping_var(&self) -> f32 {
        self.udp_ping_var
    }
    pub fn udp_packets(&self) -> u32 {
        self.udp_packets
    }
    pub fn tcp_ping_avg(&self) -> f32 {
        self.tcp_ping_avg
    }
    pub fn tcp_ping_var(&self) -> f32 {
        self.tcp_ping_var
    }
    pub fn tcp_packets(&self) -> u32 {
        self.tcp_packets
    }
}
