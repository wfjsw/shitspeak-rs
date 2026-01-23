use aws_lc_rs::rand::SecureRandom;
use chrono::{DateTime, Utc};

use crate::{
    client::crypt::{errors::CryptError, CryptoMode, Ocb2},
    messages::encoder::Ping,
};

const DECRYPT_HISTORY_SIZE: usize = 0x100;

pub struct CryptState {
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
    pub fn supported_modes() -> &'static [&'static str] {
        &["OCB2-AES128"]
    }

    pub fn generate(mode: &str, rng: &dyn SecureRandom) -> Result<Self, CryptError> {
        let mode = match mode {
            "OCB2-AES128" => Box::new(Ocb2::new(rng)?) as Box<dyn CryptoMode>,
            _ => panic!("Unsupported crypto mode"),
        };

        let nonce_size = mode.nonce_size();
        let mut encrypt_iv = vec![0u8; nonce_size];
        let mut decrypt_iv = vec![0u8; nonce_size];
        rng.fill(&mut encrypt_iv)?;
        rng.fill(&mut decrypt_iv)?;

        Ok(CryptState {
            encrypt_iv,
            decrypt_iv,
            last_good_time: Utc::now(),
            good: 0,
            late: 0,
            lost: 0,
            resync: 0,
            remote_good: 0,
            remote_late: 0,
            remote_lost: 0,
            remote_resync: 0,
            decrypt_history: [0u8; DECRYPT_HISTORY_SIZE],
            mode,
        })
    }

    pub fn from_key(
        mode: &str,
        key: &[u8],
        encrypt_iv: &[u8],
        decrypt_iv: &[u8],
    ) -> Result<Self, CryptError> {
        let mode = match mode {
            "OCB2-AES128" => Box::new(Ocb2::from_key(
                key.try_into().map_err(|_| CryptError::InvalidKeySize)?,
            )?) as Box<dyn CryptoMode>,
            _ => panic!("Unsupported crypto mode"),
        };

        if encrypt_iv.len() != mode.nonce_size() || decrypt_iv.len() != mode.nonce_size() {
            return Err(CryptError::InvalidNonceSize);
        }

        Ok(CryptState {
            encrypt_iv: encrypt_iv.to_vec(),
            decrypt_iv: decrypt_iv.to_vec(),
            last_good_time: Utc::now(),
            good: 0,
            late: 0,
            lost: 0,
            resync: 0,
            remote_good: 0,
            remote_late: 0,
            remote_lost: 0,
            remote_resync: 0,
            decrypt_history: [0u8; DECRYPT_HISTORY_SIZE],
            mode,
        })
    }

    pub fn update_from_ping_message(&mut self, ping_message: &Ping) {
        self.remote_good = ping_message.good;
        self.remote_late = ping_message.late;
        self.remote_lost = ping_message.lost;
        self.remote_resync = ping_message.resync;
    }

    pub fn create_ping_response(&self, ping_message: &Ping) -> Ping {
        Ping {
            good: self.good,
            late: self.late,
            lost: self.lost,
            resync: self.resync,
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
