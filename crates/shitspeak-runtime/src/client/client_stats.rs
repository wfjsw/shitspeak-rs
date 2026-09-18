use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use shitspeak_messages::messages::encoder::Ping;

const BANDWIDTH_WINDOW: Duration = Duration::from_secs(1);
const BANDWIDTH_MINIMUM_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
struct BandwidthSample {
    at: Instant,
    bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ClientStats {
    udp_ping_avg: f32,
    udp_ping_var: f32,
    udp_packets: u32,
    udp_volume: u64,
    tcp_ping_avg: f32,
    tcp_ping_var: f32,
    tcp_packets: u32,
    tcp_total_packets: u64,
    tcp_volume: u64,
    bandwidth_samples: VecDeque<BandwidthSample>,
}

impl Default for ClientStats {
    fn default() -> Self {
        ClientStats {
            udp_ping_avg: 0.0,
            udp_ping_var: 0.0,
            udp_packets: 0,
            udp_volume: 0,
            tcp_ping_avg: 0.0,
            tcp_ping_var: 0.0,
            tcp_packets: 0,
            tcp_total_packets: 0,
            tcp_volume: 0,
            bandwidth_samples: VecDeque::new(),
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

    pub fn record_udp_packet(&mut self, bytes: usize) {
        self.record_udp_packet_at(bytes, Instant::now());
    }

    fn record_udp_packet_at(&mut self, bytes: usize, at: Instant) {
        if bytes == 0 {
            return;
        }
        let bytes = bytes as u64;
        self.udp_volume = self.udp_volume.saturating_add(bytes);
        self.record_bandwidth_sample(bytes, at);
    }

    pub fn record_tcp_packets(&mut self, packets: usize, bytes: usize) {
        self.record_tcp_packets_at(packets, bytes, Instant::now());
    }

    fn record_tcp_packets_at(&mut self, packets: usize, bytes: usize, at: Instant) {
        if packets == 0 || bytes == 0 {
            return;
        }
        let bytes = bytes as u64;
        self.tcp_total_packets = self.tcp_total_packets.saturating_add(packets as u64);
        self.tcp_volume = self.tcp_volume.saturating_add(bytes);
        self.record_bandwidth_sample(bytes, at);
    }

    fn record_bandwidth_sample(&mut self, bytes: u64, at: Instant) {
        self.bandwidth_samples
            .push_back(BandwidthSample { at, bytes });
        self.prune_bandwidth_samples(at);
    }

    fn prune_bandwidth_samples(&mut self, now: Instant) {
        while self
            .bandwidth_samples
            .front()
            .is_some_and(|sample| now.duration_since(sample.at) > BANDWIDTH_WINDOW)
        {
            self.bandwidth_samples.pop_front();
        }
    }

    pub fn bandwidth_bytes_per_second(&mut self, now: Instant) -> u32 {
        self.prune_bandwidth_samples(now);
        let Some(first) = self.bandwidth_samples.front() else {
            return 0;
        };
        if now.duration_since(first.at) < BANDWIDTH_MINIMUM_INTERVAL {
            return 0;
        }
        let bytes: u64 = self
            .bandwidth_samples
            .iter()
            .map(|sample| sample.bytes)
            .sum();
        let elapsed = now.duration_since(first.at).as_secs_f64();
        ((bytes as f64 / elapsed).min(u32::MAX as f64)) as u32
    }

    pub fn total_volume(&self) -> u64 {
        self.udp_volume.saturating_add(self.tcp_volume)
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

#[cfg(test)]
mod tests {
    use super::ClientStats;
    use shitspeak_messages::messages::encoder::Ping;
    use std::time::{Duration, Instant};

    #[test]
    fn udp_ping_count_is_independent_of_server_observed_udp_traffic() {
        let mut stats = ClientStats::default();
        for _ in 0..8 {
            stats.record_udp_packet(512);
        }

        stats.update_from_ping_message(&Ping {
            udp_packets: Some(7),
            ..Ping::default()
        });

        assert_eq!(stats.udp_packets(), 7);
    }

    #[test]
    fn bandwidth_uses_recent_bytes_instead_of_lifetime_bytes() {
        let start = Instant::now();
        let mut stats = ClientStats::default();
        stats.record_tcp_packets_at(1, 1_000, start);
        stats.record_tcp_packets_at(1, 1_000, start + Duration::from_millis(500));

        assert_eq!(
            stats.bandwidth_bytes_per_second(start + Duration::from_millis(750)),
            4_000
        );
        assert_eq!(
            stats.bandwidth_bytes_per_second(start + Duration::from_secs(2)),
            0
        );
    }

    #[test]
    fn bandwidth_requires_a_quarter_second_of_samples() {
        let start = Instant::now();
        let mut stats = ClientStats::default();
        stats.record_udp_packet_at(1_000, start);

        assert_eq!(
            stats.bandwidth_bytes_per_second(start + Duration::from_millis(249)),
            0
        );
        assert_eq!(
            stats.bandwidth_bytes_per_second(start + Duration::from_millis(250)),
            4_000
        );
    }
}
