use aws_lc_rs::rand::SecureRandom;
use bytes::BytesMut;
use chrono::{DateTime, Utc};

use shitspeak_messages::messages::encoder::Ping;

use crate::{CryptoMode, Ocb2, errors::CryptError};

const DECRYPT_HISTORY_SIZE: usize = 0x100;

pub struct CryptState {
    encrypt_iv: [u8; Ocb2::NONCE_SIZE],
    decrypt_iv: [u8; Ocb2::NONCE_SIZE],

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
    mode: Ocb2,
}

impl CryptState {
    pub fn supported_modes() -> &'static [&'static str] {
        &["OCB2-AES128"]
    }

    pub fn generate(mode: &str, rng: &dyn SecureRandom) -> Result<Self, CryptError> {
        let mode = match mode {
            "OCB2-AES128" => Ocb2::new(rng)?,
            _ => return Err(CryptError::UnsupportedMode),
        };

        let mut encrypt_iv = [0u8; Ocb2::NONCE_SIZE];
        let mut decrypt_iv = [0u8; Ocb2::NONCE_SIZE];
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
            "OCB2-AES128" => {
                Ocb2::from_key(key.try_into().map_err(|_| CryptError::InvalidKeySize)?)?
            }
            _ => return Err(CryptError::UnsupportedMode),
        };

        let encrypt_iv = encrypt_iv
            .try_into()
            .map_err(|_| CryptError::InvalidNonceSize)?;
        let decrypt_iv = decrypt_iv
            .try_into()
            .map_err(|_| CryptError::InvalidNonceSize)?;

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
        if iv.len() != Ocb2::NONCE_SIZE {
            return;
        }
        self.decrypt_iv.copy_from_slice(iv);
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
        self.mode.encrypt(&mut dest[1..], data, &self.encrypt_iv)?;
        dest[0] = self.encrypt_iv[0];

        Ok(())
    }

    /// Precompute the plaintext-derived component of the OCB2 authentication
    /// checksum, suitable for passing to `encrypt_with_precomputed_checksum`
    /// across a fan-out broadcast that shares the same plaintext. See
    /// `Ocb2::compute_plaintext_checksum` for layout details.
    pub fn compute_plaintext_checksum(plaintext: &[u8]) -> [u8; 16] {
        super::Ocb2::compute_plaintext_checksum(plaintext)
    }

    /// Variant of `encrypt` that takes a precomputed plaintext checksum.
    /// Output is byte-identical to `encrypt`. Skips the per-block plaintext
    /// XOR-fold inside the underlying mode (saves ~13% on a 256-recipient
    /// fan-out at 175 B plaintext). Identical IV management, identical
    /// destination layout — same correctness boundary.
    pub fn encrypt_with_precomputed_checksum(
        &mut self,
        dest: &mut [u8],
        data: &[u8],
        plaintext_checksum: &[u8; 16],
    ) -> Result<(), CryptError> {
        for byte in self.encrypt_iv.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }

        if dest.len() < data.len() + self.overhead() {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        self.mode.encrypt_with_plaintext_checksum(
            &mut dest[1..],
            data,
            &self.encrypt_iv,
            plaintext_checksum,
        )?;
        dest[0] = self.encrypt_iv[0];

        Ok(())
    }

    /// Encrypt a short ordered run of packets for the same recipient.
    ///
    /// This is intended for micro-batch experiments: the caller supplies each
    /// packet's destination, plaintext, and precomputed plaintext checksum,
    /// and this method advances the recipient IV exactly once per packet before
    /// handing the sequence to the crypto mode. Packet order is preserved.
    pub fn encrypt_sequence_with_precomputed_checksums(
        &mut self,
        dests: &mut [&mut [u8]],
        datas: &[&[u8]],
        plaintext_checksums: &[[u8; 16]],
    ) -> Result<(), CryptError> {
        if dests.len() != datas.len() || datas.len() != plaintext_checksums.len() {
            return Err(CryptError::DestinationBufferTooSmall);
        }
        let mode_overhead = self.mode.overhead();
        let wire_overhead = self.overhead();
        let mut nonces = Vec::with_capacity(datas.len());

        for (dest, data) in dests.iter_mut().zip(datas.iter()) {
            for byte in self.encrypt_iv.iter_mut() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }

            if dest.len() < data.len() + wire_overhead {
                return Err(CryptError::DestinationBufferTooSmall);
            }
            dest[0] = self.encrypt_iv[0];

            nonces.push(self.encrypt_iv);
        }

        let mut mode_dests = dests
            .iter_mut()
            .zip(datas.iter())
            .map(|(dest, data)| &mut dest[1..data.len() + 1 + mode_overhead])
            .collect::<Vec<_>>();

        self.mode.encrypt_sequence_with_plaintext_checksums(
            &mut mode_dests,
            datas,
            &nonces,
            plaintext_checksums,
        )
    }

    pub fn decrypt(&mut self, dest: &mut BytesMut, data: &[u8]) -> Result<(), CryptError> {
        if data.len() < self.overhead() {
            return Err(CryptError::DataTooShort);
        }

        let plain_len = data.len() - self.overhead();
        dest.resize(plain_len, 0);
        self.decrypt_into(&mut dest[..plain_len], data).map(|_| ())
    }

    pub fn decrypt_into(&mut self, dest: &mut [u8], data: &[u8]) -> Result<usize, CryptError> {
        if data.len() < self.overhead() {
            return Err(CryptError::DataTooShort);
        }

        let plain_len = data.len() - self.overhead();
        if dest.len() < plain_len {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        let incoming_iv_byte = data[0];
        let known_iv_byte = self.decrypt_iv[0];
        let mut restore = false;

        let iv_backup = self.decrypt_iv;

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
                self.decrypt_iv = iv_backup;
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
                    self.decrypt_iv = iv_backup;
                    return Err(CryptError::UnexpectedTag);
                }
            } else if diff > 0 {
                if incoming_iv_byte > known_iv_byte {
                    self.lost = self
                        .lost
                        .wrapping_add(incoming_iv_byte as u32 - known_iv_byte as u32 - 1);
                    self.decrypt_iv[0] = incoming_iv_byte;
                } else if incoming_iv_byte < known_iv_byte {
                    self.lost = self
                        .lost
                        .wrapping_add(256 - known_iv_byte as u32 + incoming_iv_byte as u32 - 1);
                    self.decrypt_iv[0] = incoming_iv_byte;
                    for byte in self.decrypt_iv.iter_mut().skip(1) {
                        *byte = byte.wrapping_add(1);
                        if *byte != 0 {
                            break;
                        }
                    }
                } else {
                    self.decrypt_iv = iv_backup;
                    return Err(CryptError::UnexpectedTag);
                }
            } else {
                // diff == 0: duplicate/replay packet
                self.decrypt_iv = iv_backup;
                return Err(CryptError::UnexpectedTag);
            }

            if self.decrypt_history[self.decrypt_iv[0] as usize] == self.decrypt_iv[1] {
                // restore the IV
                self.decrypt_iv = iv_backup;

                return Err(CryptError::UnexpectedTag);
            }
        }

        let decrypt_result =
            self.mode
                .decrypt(&mut dest[..plain_len], &data[1..], &self.decrypt_iv);

        if let Err(e) = decrypt_result {
            self.decrypt_iv = iv_backup;
            return Err(e);
        }

        self.decrypt_history[self.decrypt_iv[0] as usize] = self.decrypt_iv[1];

        if restore {
            self.decrypt_iv = iv_backup;
        }

        self.good = self.good.saturating_add(1);
        self.last_good_time = Utc::now();

        Ok(plain_len)
    }

    pub fn update_from_ping_message(&mut self, ping_message: &Ping) {
        self.remote_good = ping_message.good;
        self.remote_late = ping_message.late;
        self.remote_lost = ping_message.lost;
        self.remote_resync = ping_message.resync;
    }

    pub fn local_packet_stats(&self) -> (u32, u32, u32, u32) {
        (self.good, self.late, self.lost, self.resync)
    }

    pub fn remote_packet_stats(&self) -> (u32, u32, u32, u32) {
        (
            self.remote_good,
            self.remote_late,
            self.remote_lost,
            self.remote_resync,
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [0x42; 16];
    const IV_E: [u8; 16] = [0x01; 16];
    const IV_D: [u8; 16] = [0x02; 16];

    fn sender() -> CryptState {
        CryptState::from_key("OCB2-AES128", &KEY, &IV_E, &IV_D).unwrap()
    }

    fn receiver() -> CryptState {
        CryptState::from_key("OCB2-AES128", &KEY, &IV_D, &IV_E).unwrap()
    }

    #[test]
    fn sequence_encrypt_matches_per_packet_encrypt() {
        let datas = [1usize, 15, 16, 31, 170]
            .into_iter()
            .enumerate()
            .map(|(i, len)| vec![0xA0u8.wrapping_add(i as u8); len])
            .collect::<Vec<_>>();
        let checksums = datas
            .iter()
            .map(|data| CryptState::compute_plaintext_checksum(data))
            .collect::<Vec<_>>();

        let mut per_packet = sender();
        let expected = datas
            .iter()
            .zip(checksums.iter())
            .map(|(data, checksum)| {
                let mut out = vec![0u8; data.len() + per_packet.overhead()];
                per_packet
                    .encrypt_with_precomputed_checksum(&mut out, data, checksum)
                    .unwrap();
                out
            })
            .collect::<Vec<_>>();

        let mut sequence = sender();
        let mut actual = datas
            .iter()
            .map(|data| vec![0u8; data.len() + sequence.overhead()])
            .collect::<Vec<_>>();
        let mut dests = actual
            .iter_mut()
            .map(|out| out.as_mut_slice())
            .collect::<Vec<_>>();
        let data_refs = datas.iter().map(|data| data.as_slice()).collect::<Vec<_>>();

        sequence
            .encrypt_sequence_with_precomputed_checksums(&mut dests, &data_refs, &checksums)
            .unwrap();

        assert_eq!(actual, expected);

        let mut decrypt = receiver();
        for (encrypted, plain) in actual.iter().zip(datas.iter()) {
            let mut decrypted = BytesMut::new();
            decrypt.decrypt(&mut decrypted, encrypted).unwrap();
            assert_eq!(decrypted.as_ref(), plain.as_slice());
        }

        let mut decrypt_into = receiver();
        for (encrypted, plain) in actual.iter().zip(datas.iter()) {
            let mut decrypted = [0u8; 256];
            let len = decrypt_into
                .decrypt_into(&mut decrypted, encrypted)
                .unwrap();
            assert_eq!(&decrypted[..len], plain.as_slice());
        }
    }
}
