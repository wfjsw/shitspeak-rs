use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aws_lc_rs::rand::SecureRandom;
use bytes::BytesMut;
use chrono::{DateTime, Utc};

use shitspeak_messages::messages::encoder::Ping;

use crate::{CryptoMode, Ocb2, errors::CryptError};

const DECRYPT_HISTORY_SIZE: usize = 0x100;

/// A client's UDP crypto: an outbound [`CryptEncryptor`] and an inbound
/// [`CryptDecryptor`] sharing one key schedule.
///
/// The halves touch disjoint state, so a server can [`split`](Self::into_split)
/// them and let voice egress encrypt toward a client without contending with
/// that client's UDP ingress, which decrypts and keeps packet statistics.
pub struct CryptState {
    encryptor: CryptEncryptor,
    decryptor: CryptDecryptor,
}

/// The outbound half: the key schedule and the packets sent so far.
///
/// Every operation takes `&self`. The nonce for each packet is reserved with
/// one atomic add, and the AES-OCB work runs outside any lock, so concurrent
/// senders never wait for each other and never reuse a nonce.
pub struct CryptEncryptor {
    mode: Arc<Ocb2>,
    /// The nonce before the first packet, as a little-endian integer. Packet
    /// `n` (1-based) is sent with `base_iv + n`: Mumble increments the nonce
    /// byte 0 first, carrying into byte 1 and onward, which is exactly a
    /// little-endian increment. The wire carries byte 0.
    base_iv: u128,
    /// Packets sent, i.e. nonces reserved.
    sent: AtomicU64,
}

/// The inbound half: nonce tracking, replay history, and packet statistics.
pub struct CryptDecryptor {
    mode: Arc<Ocb2>,
    decrypt_iv: [u8; Ocb2::NONCE_SIZE],

    last_good_time: DateTime<Utc>,
    last_resync_request_time: DateTime<Utc>,

    good: u32,
    late: u32,
    lost: u32,
    resync: u32,
    remote_good: u32,
    remote_late: u32,
    remote_lost: u32,
    remote_resync: u32,

    decrypt_history: [u8; DECRYPT_HISTORY_SIZE],
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

        Ok(Self::assemble(mode, encrypt_iv, decrypt_iv))
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

        Ok(Self::assemble(mode, encrypt_iv, decrypt_iv))
    }

    fn assemble(
        mode: Ocb2,
        encrypt_iv: [u8; Ocb2::NONCE_SIZE],
        decrypt_iv: [u8; Ocb2::NONCE_SIZE],
    ) -> Self {
        let mode = Arc::new(mode);
        let now = Utc::now();
        CryptState {
            encryptor: CryptEncryptor {
                mode: mode.clone(),
                base_iv: u128::from_le_bytes(encrypt_iv),
                sent: AtomicU64::new(0),
            },
            decryptor: CryptDecryptor {
                mode,
                decrypt_iv,
                last_good_time: now,
                last_resync_request_time: now,
                good: 0,
                late: 0,
                lost: 0,
                resync: 0,
                remote_good: 0,
                remote_late: 0,
                remote_lost: 0,
                remote_resync: 0,
                decrypt_history: [0u8; DECRYPT_HISTORY_SIZE],
            },
        }
    }

    /// Separate the outbound and inbound halves so each can be guarded on
    /// its own.
    pub fn into_split(self) -> (CryptEncryptor, CryptDecryptor) {
        (self.encryptor, self.decryptor)
    }

    pub fn encryptor(&self) -> &CryptEncryptor {
        &self.encryptor
    }

    pub fn decryptor(&mut self) -> &mut CryptDecryptor {
        &mut self.decryptor
    }

    pub fn overhead(&self) -> usize {
        self.encryptor.overhead()
    }

    /// Return the encryption nonce (IV): the one the last packet used.
    pub fn encrypt_iv(&self) -> [u8; Ocb2::NONCE_SIZE] {
        self.encryptor.encrypt_iv()
    }

    /// Return the decryption nonce (IV).
    pub fn decrypt_iv(&self) -> &[u8] {
        self.decryptor.decrypt_iv()
    }

    /// Overwrite the decrypt IV (used for client-requested resync).
    pub fn set_decrypt_iv(&mut self, iv: &[u8]) {
        self.decryptor.set_decrypt_iv(iv);
    }

    /// Whether a nonce resync request is due: no good packet and no request
    /// for at least `interval`. Does not record a request.
    pub fn resync_request_due(&self, interval: std::time::Duration) -> bool {
        self.decryptor.resync_request_due(interval)
    }

    /// Record that a nonce resync request was actually handed to the client's
    /// transport. Call it only once the request is queued: a request that was
    /// never sent must not hold off the next one.
    pub fn record_resync_request(&mut self) {
        self.decryptor.record_resync_request();
    }

    /// Return the key (if available from the crypto mode).
    pub fn key(&self) -> Option<&[u8]> {
        self.encryptor.key()
    }

    pub fn encrypt(&mut self, dest: &mut [u8], data: &[u8]) -> Result<(), CryptError> {
        self.encryptor.encrypt(dest, data)
    }

    /// Precompute the plaintext-derived component of the OCB2 authentication
    /// checksum, suitable for passing to `encrypt_with_precomputed_checksum`
    /// across a fan-out broadcast that shares the same plaintext. See
    /// `Ocb2::compute_plaintext_checksum` for layout details.
    pub fn compute_plaintext_checksum(plaintext: &[u8]) -> [u8; 16] {
        super::Ocb2::compute_plaintext_checksum(plaintext)
    }

    /// See [`CryptEncryptor::encrypt_with_precomputed_checksum`].
    pub fn encrypt_with_precomputed_checksum(
        &mut self,
        dest: &mut [u8],
        data: &[u8],
        plaintext_checksum: &[u8; 16],
    ) -> Result<(), CryptError> {
        self.encryptor
            .encrypt_with_precomputed_checksum(dest, data, plaintext_checksum)
    }

    /// See [`CryptEncryptor::encrypt_sequence_with_precomputed_checksums`].
    pub fn encrypt_sequence_with_precomputed_checksums(
        &mut self,
        dests: &mut [&mut [u8]],
        datas: &[&[u8]],
        plaintext_checksums: &[[u8; 16]],
    ) -> Result<(), CryptError> {
        self.encryptor.encrypt_sequence_with_precomputed_checksums(
            dests,
            datas,
            plaintext_checksums,
        )
    }

    pub fn decrypt(&mut self, dest: &mut BytesMut, data: &[u8]) -> Result<(), CryptError> {
        self.decryptor.decrypt(dest, data)
    }

    pub fn decrypt_into(&mut self, dest: &mut [u8], data: &[u8]) -> Result<usize, CryptError> {
        self.decryptor.decrypt_into(dest, data)
    }

    pub fn update_from_ping_message(&mut self, ping_message: &Ping) {
        self.decryptor.update_from_ping_message(ping_message);
    }

    pub fn local_packet_stats(&self) -> (u32, u32, u32, u32) {
        self.decryptor.local_packet_stats()
    }

    pub fn remote_packet_stats(&self) -> (u32, u32, u32, u32) {
        self.decryptor.remote_packet_stats()
    }

    pub fn create_ping_response(&self, ping_message: &Ping) -> Ping {
        self.decryptor.create_ping_response(ping_message)
    }
}

impl CryptEncryptor {
    pub fn overhead(&self) -> usize {
        1 + self.mode.overhead()
    }

    /// Return the key (if available from the crypto mode).
    pub fn key(&self) -> Option<&[u8]> {
        self.mode.key()
    }

    /// Return the encryption nonce (IV): the one the last packet used, or the
    /// initial nonce before any packet was sent. A concurrent sender may
    /// advance it right after; a receiver resynchronised to an older value
    /// still accepts the later packets as a forward jump.
    pub fn encrypt_iv(&self) -> [u8; Ocb2::NONCE_SIZE] {
        self.nonce(self.sent.load(Ordering::Relaxed))
    }

    /// The nonce of packet `sent` (1-based; 0 is the initial nonce).
    fn nonce(&self, sent: u64) -> [u8; Ocb2::NONCE_SIZE] {
        self.base_iv.wrapping_add(u128::from(sent)).to_le_bytes()
    }

    /// Reserve `count` consecutive nonces and return the index of the first.
    fn reserve(&self, count: u64) -> u64 {
        self.sent.fetch_add(count, Ordering::Relaxed) + 1
    }

    pub fn encrypt(&self, dest: &mut [u8], data: &[u8]) -> Result<(), CryptError> {
        // A nonce is consumed even when the destination is too small, as the
        // reference increments before checking.
        let nonce = self.nonce(self.reserve(1));

        if dest.len() < data.len() + self.overhead() {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        // Wire layout: `[iv_byte (1), tag (3), ciphertext (N)]`. We hand the
        // OCB2 layer `&mut dest[1..]` so it places its tag at `dest[1..4]` and
        // its ciphertext at `dest[4..4+N]`, then we write the IV byte at
        // position 0. The decrypt path mirrors this by passing `&data[1..]`
        // to `mode.decrypt`, which reads the tag from positions 0..3 of that
        // slice (= wire positions 1..4).
        self.mode.encrypt(&mut dest[1..], data, &nonce)?;
        dest[0] = nonce[0];

        Ok(())
    }

    /// Variant of `encrypt` that takes a precomputed plaintext checksum.
    /// Output is byte-identical to `encrypt`. Skips the per-block plaintext
    /// XOR-fold inside the underlying mode (saves ~13% on a 256-recipient
    /// fan-out at 175 B plaintext). Identical IV management, identical
    /// destination layout — same correctness boundary.
    pub fn encrypt_with_precomputed_checksum(
        &self,
        dest: &mut [u8],
        data: &[u8],
        plaintext_checksum: &[u8; 16],
    ) -> Result<(), CryptError> {
        let nonce = self.nonce(self.reserve(1));

        if dest.len() < data.len() + self.overhead() {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        self.mode.encrypt_with_plaintext_checksum(
            &mut dest[1..],
            data,
            &nonce,
            plaintext_checksum,
        )?;
        dest[0] = nonce[0];

        Ok(())
    }

    /// Encrypt a short ordered run of packets for the same recipient.
    ///
    /// This is intended for micro-batch experiments: the caller supplies each
    /// packet's destination, plaintext, and precomputed plaintext checksum,
    /// and this method advances the recipient IV exactly once per packet before
    /// handing the sequence to the crypto mode. Packet order is preserved.
    pub fn encrypt_sequence_with_precomputed_checksums(
        &self,
        dests: &mut [&mut [u8]],
        datas: &[&[u8]],
        plaintext_checksums: &[[u8; 16]],
    ) -> Result<(), CryptError> {
        if dests.len() != datas.len() || datas.len() != plaintext_checksums.len() {
            return Err(CryptError::DestinationBufferTooSmall);
        }
        let mode_overhead = self.mode.overhead();
        let wire_overhead = self.overhead();
        if dests
            .iter()
            .zip(datas.iter())
            .any(|(dest, data)| dest.len() < data.len() + wire_overhead)
        {
            return Err(CryptError::DestinationBufferTooSmall);
        }
        let first = self.reserve(datas.len() as u64);
        let mut nonces = Vec::with_capacity(datas.len());

        for (index, dest) in dests.iter_mut().enumerate() {
            let nonce = self.nonce(first + index as u64);
            dest[0] = nonce[0];
            nonces.push(nonce);
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
}

impl CryptDecryptor {
    pub fn overhead(&self) -> usize {
        1 + self.mode.overhead()
    }

    /// Return the key (if available from the crypto mode).
    pub fn key(&self) -> Option<&[u8]> {
        self.mode.key()
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

    /// Whether a nonce resync request is due: no good packet and no request
    /// for at least `interval`. Does not record a request.
    pub fn resync_request_due(&self, interval: std::time::Duration) -> bool {
        let now = Utc::now();
        let since_last_good = (now - self.last_good_time).to_std().unwrap_or_default();
        let since_last_request = (now - self.last_resync_request_time)
            .to_std()
            .unwrap_or_default();
        since_last_good >= interval && since_last_request >= interval
    }

    /// Record that a nonce resync request was actually handed to the client's
    /// transport. Call it only once the request is queued: a request that was
    /// never sent must not hold off the next one.
    pub fn record_resync_request(&mut self) {
        self.last_resync_request_time = Utc::now();
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

    /// The Mumble reference nonce step: increment byte 0, carrying into
    /// byte 1 and onward.
    fn reference_increment(iv: &mut [u8; 16]) {
        for byte in iv.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// The reference wire packet: increment, OCB2-encrypt with the full
    /// nonce, prefix nonce byte 0.
    fn reference_packet(mode: &Ocb2, iv: &mut [u8; 16], data: &[u8]) -> Vec<u8> {
        reference_increment(iv);
        let mut out = vec![0u8; data.len() + 1 + mode.overhead()];
        mode.encrypt(&mut out[1..], data, iv).unwrap();
        out[0] = iv[0];
        out
    }

    #[test]
    fn encryptor_is_byte_identical_to_the_reference_across_nonce_carries() {
        let mut low_wrap = [0u8; 16];
        low_wrap[..8].copy_from_slice(&[0xFF; 8]);
        low_wrap[0] = 0xF0;
        let starts: [[u8; 16]; 4] = [
            IV_E,
            // Carries out of byte 0 into byte 1 and byte 2.
            [0xF8, 0xFF, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // Carries across the 64-bit boundary between byte 7 and byte 8.
            low_wrap,
            // Wraps the whole 128-bit nonce.
            [
                0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
            ],
        ];
        let reference_mode = Ocb2::from_key(KEY).unwrap();
        for start in starts {
            let state = CryptState::from_key("OCB2-AES128", &KEY, &start, &IV_D).unwrap();
            let (encryptor, _) = state.into_split();
            let mut iv = start;
            for packet in 0..40u8 {
                let data = vec![packet; 1 + packet as usize * 3];
                let expected = reference_packet(&reference_mode, &mut iv, &data);
                let mut actual = vec![0u8; data.len() + encryptor.overhead()];
                if packet % 2 == 0 {
                    encryptor.encrypt(&mut actual, &data).unwrap();
                } else {
                    let checksum = CryptState::compute_plaintext_checksum(&data);
                    encryptor
                        .encrypt_with_precomputed_checksum(&mut actual, &data, &checksum)
                        .unwrap();
                }
                assert_eq!(actual, expected, "start {start:02x?}, packet {packet}");
                assert_eq!(
                    encryptor.encrypt_iv(),
                    iv,
                    "start {start:02x?}, packet {packet}"
                );
            }
        }
    }

    #[test]
    fn split_halves_round_trip_and_report_the_last_used_nonce() {
        let (encryptor, _) = sender().into_split();
        assert_eq!(encryptor.encrypt_iv(), IV_E, "no packet sent yet");
        let (_, mut decryptor) = receiver().into_split();
        for len in [0usize, 1, 16, 33, 170] {
            let data = vec![0x5Au8; len];
            let mut wire = vec![0u8; len + encryptor.overhead()];
            encryptor.encrypt(&mut wire, &data).unwrap();
            let mut plain = BytesMut::new();
            decryptor.decrypt(&mut plain, &wire).unwrap();
            assert_eq!(plain.as_ref(), data.as_slice());
        }
        let mut expected = IV_E;
        for _ in 0..5 {
            reference_increment(&mut expected);
        }
        assert_eq!(encryptor.encrypt_iv(), expected);
        assert_eq!(decryptor.local_packet_stats().0, 5);
    }

    /// Concurrent senders each reserve their own nonce: none is used twice
    /// and none is skipped.
    #[test]
    fn concurrent_encrypts_use_every_nonce_exactly_once() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 500;
        let (encryptor, _) = sender().into_split();
        let mut nonce_bytes = std::thread::scope(|scope| {
            let workers = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        (0..PER_THREAD)
                            .map(|_| {
                                let mut wire = vec![0u8; 8 + encryptor.overhead()];
                                encryptor.encrypt(&mut wire, &[7u8; 8]).unwrap();
                                wire
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(nonce_bytes.len(), THREADS * PER_THREAD);
        let reference_mode = Ocb2::from_key(KEY).unwrap();
        let mut iv = IV_E;
        let mut expected = Vec::with_capacity(THREADS * PER_THREAD);
        for _ in 0..THREADS * PER_THREAD {
            expected.push(reference_packet(&reference_mode, &mut iv, &[7u8; 8]));
        }
        nonce_bytes.sort();
        expected.sort();
        assert_eq!(nonce_bytes, expected, "a nonce was reused or skipped");
        assert_eq!(encryptor.encrypt_iv(), iv);
    }
}
