use chrono::{DateTime, Utc};

use crate::{client::crypt::CryptoMode, mumble_proto::Ping};

const DECRYPT_HISTORY_SIZE: usize = 0x100;

pub struct CryptState {
    key: Vec<u8>,
    encrypt_iv: Vec<u8>,
    decrypt_iv: Vec<u8>,

    last_good_time: DateTime<Utc>,

    good: u32,
    late: u32,
    lost: u32,
    resync: u32,
    remote_good: u32,
    remote_late: u32,
    remote_lost: u32,
    remote_resync: u32,

    decrypt_history: [u8; DECRYPT_HISTORY_SIZE],
    mode: Box<dyn CryptoMode>,
}

impl CryptState {
    pub fn update_from_ping_message(&mut self, ping_message: &Ping) {
        if let Some(good) = ping_message.good {
            self.remote_good = good;
        }

        if let Some(late) = ping_message.late {
            self.remote_late = late;
        }

        if let Some(lost) = ping_message.lost {
            self.remote_lost = lost;
        }

        if let Some(resync) = ping_message.resync {
            self.remote_resync = resync;
        }
    }

    pub fn create_ping_response(&self, ping_message: &Ping) -> Ping {
        Ping {
            good: Some(self.good),
            late: Some(self.late),
            lost: Some(self.lost),
            resync: Some(self.resync),
            timestamp: ping_message.timestamp,
            udp_packets: None,
            tcp_packets: None,
            udp_ping_avg: None,
            udp_ping_var: None,
            tcp_ping_avg: None,
            tcp_ping_var: None,
        }
    }
}
