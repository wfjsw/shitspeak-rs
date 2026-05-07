use aws_lc_rs::rand::SecureRandom;
use bytes::BytesMut;
use chrono::{DateTime, Utc};

use crate::{
    client::crypt::{errors::CryptError, CryptoMode, Ocb2},
    messages::encoder::Ping,
};

const DECRYPT_HISTORY_SIZE: usize = 0x100;

pub struct CryptState {
    encrypt_iv: BytesMut,
    decrypt_iv: BytesMut,

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
            _ => return Err(CryptError::UnsupportedMode),
        };

        let nonce_size = mode.nonce_size();
        let mut encrypt_iv = vec![0u8; nonce_size];
        let mut decrypt_iv = vec![0u8; nonce_size];
        rng.fill(&mut encrypt_iv)?;
        rng.fill(&mut decrypt_iv)?;

        Ok(CryptState {
            encrypt_iv: BytesMut::from(encrypt_iv.as_slice()),
            decrypt_iv: BytesMut::from(decrypt_iv.as_slice()),
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
            _ => return Err(CryptError::UnsupportedMode),
        };

        if encrypt_iv.len() != mode.nonce_size() || decrypt_iv.len() != mode.nonce_size() {
            return Err(CryptError::InvalidNonceSize);
        }

        Ok(CryptState {
            encrypt_iv: BytesMut::from(encrypt_iv),
            decrypt_iv: BytesMut::from(decrypt_iv),
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

    pub fn overhead(&self) -> usize {
        1 + self.mode.overhead()
    }

    /// Return the encryption nonce (IV).
    pub fn encrypt_iv(&self) -> &[u8] {
        &self.encrypt_iv
    }

    /// Return the decryption nonce (IV).
    pub fn decrypt_iv(&self) -> &[u8] {
        &self.decrypt_iv
    }

    /// Overwrite the decrypt IV (used for client-requested resync).
    pub fn set_decrypt_iv(&mut self, iv: &[u8]) {
        self.decrypt_iv = BytesMut::from(iv);
        self.resync = self.resync.wrapping_add(1);
    }

    /// Return the key (if available from the crypto mode).
    pub fn key(&self) -> Option<&[u8]> {
        self.mode.key()
    }

    pub fn encrypt(&mut self, dest: &mut [u8], data: &[u8]) -> Result<(), CryptError> {
        // Increment the IV left-to-right (byte 0 first, carry to byte 1, ...).
        // This matches the Mumble C++ reference (`for i=0..15: if ++iv[i] break`)
        // and — crucially — matches the wire format which puts `encrypt_iv[0]`
        // in `dest[0]`. With a right-to-left increment, `dest[0]` would never
        // change between packets and the receiver would reject every packet
        // after the first as a duplicate IV.
        for byte in self.encrypt_iv.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }

        if dest.len() < data.len() + self.overhead() {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        // Wire layout: `[iv_byte (1), tag (3), ciphertext (N)]`. We hand the
        // OCB2 layer `&mut dest[1..]` so it places its tag at `dest[1..4]` and
        // its ciphertext at `dest[4..4+N]`, then we write the IV byte at
        // position 0. The decrypt path mirrors this by passing `&data[1..]`
        // to `mode.decrypt`, which reads the tag from positions 0..3 of that
        // slice (= wire positions 1..4).
        self.mode
            .encrypt(&mut dest[1..], data, &self.encrypt_iv)?;
        dest[0] = self.encrypt_iv[0];

        Ok(())
    }

    pub fn decrypt(&mut self, dest: &mut BytesMut, data: &[u8]) -> Result<(), CryptError> {
        if data.len() < self.overhead() {
            return Err(CryptError::DataTooShort);
        }
        
        let plain_len = data.len() - self.overhead();
        dest.resize(plain_len, 0);

        let incoming_iv_byte = data[0];
        let known_iv_byte = self.decrypt_iv[0];
        let mut restore = false;

        let iv_backup = self.decrypt_iv.to_vec();

        if known_iv_byte.wrapping_add(1) == incoming_iv_byte {
            // in order as expected
            if incoming_iv_byte > known_iv_byte {
                self.decrypt_iv[0] = incoming_iv_byte;
            } else if incoming_iv_byte < known_iv_byte {
                // wraparound
                self.decrypt_iv[0] = incoming_iv_byte;
                for byte in self.decrypt_iv.iter_mut().skip(1) {
                    *byte = byte.wrapping_add(1);
                    if *byte != 0 {
                        break;
                    }
                }
            } else {
                // unexpected identical IV byte — treat as unexpected/replay
                self.decrypt_iv.copy_from_slice(&iv_backup);
                return Err(CryptError::UnexpectedTag);
            }
        } else {
            // out of order or repeating

            let diff = incoming_iv_byte.wrapping_sub(known_iv_byte) as i8;
            if diff > -30 && diff < 0 {
                self.late = self.late.saturating_add(1);
                self.lost = self.lost.saturating_sub(1);
                self.decrypt_iv[0] = incoming_iv_byte;
                restore = true;
                if incoming_iv_byte < known_iv_byte {
                    // late packet, but no wraparound
                } else if incoming_iv_byte > known_iv_byte {
                    // Last was 0x02, here comes 0xff from last round
                    for byte in self.decrypt_iv.iter_mut().skip(1) {
                        let old_byte = *byte;
                        *byte = byte.wrapping_sub(1);
                        if old_byte != 0 {
                            break;
                        }
                    }
                } else {
                    self.decrypt_iv.copy_from_slice(&iv_backup);
                    return Err(CryptError::UnexpectedTag);
                }
            } else if diff > 0 {
                if incoming_iv_byte > known_iv_byte {
                    self.lost = self.lost.wrapping_add(incoming_iv_byte as u32 - known_iv_byte as u32 - 1);
                    self.decrypt_iv[0] = incoming_iv_byte;
                } else if incoming_iv_byte < known_iv_byte {
                    self.lost = self.lost.wrapping_add(256 - known_iv_byte as u32 + incoming_iv_byte as u32 - 1);
                    self.decrypt_iv[0] = incoming_iv_byte;
                    for byte in self.decrypt_iv.iter_mut().skip(1) {
                        *byte = byte.wrapping_add(1);
                        if *byte != 0 {
                            break;
                        }
                    }
                } else {
                    self.decrypt_iv.copy_from_slice(&iv_backup);
                    return Err(CryptError::UnexpectedTag);
                }
            } else {
                // diff == 0: duplicate/replay packet
                self.decrypt_iv.copy_from_slice(&iv_backup);
                return Err(CryptError::UnexpectedTag);
            }
        
            if self.decrypt_history[self.decrypt_iv[0] as usize] == self.decrypt_iv[1] {
                // restore the IV
                self.decrypt_iv.copy_from_slice(&iv_backup);

                return Err(CryptError::UnexpectedTag);
            }
        }

        let decrypt_result = self.mode.decrypt(dest, &data[1..], &self.decrypt_iv);

        if let Err(e) = decrypt_result {
            self.decrypt_iv.copy_from_slice(&iv_backup);
            return Err(e);
        }

        self.decrypt_history[self.decrypt_iv[0] as usize] = self.decrypt_iv[1];

        if restore {
            self.decrypt_iv.copy_from_slice(&iv_backup);
        }

        self.good = self.good.saturating_add(1);
        self.last_good_time = Utc::now();

        Ok(())
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
