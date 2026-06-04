use crate::client::crypt::errors::CryptError;

pub trait CryptoMode: Send + Sync {
    fn nonce_size(&self) -> usize;
    fn key_size(&self) -> usize;
    fn overhead(&self) -> usize;

    fn encrypt(&self, dest: &mut [u8], data: &[u8], nonce: &[u8]) -> Result<(), CryptError>;
    fn decrypt(&self, dest: &mut [u8], data: &[u8], nonce: &[u8]) -> Result<(), CryptError>;

    /// Variant of `encrypt` that takes a precomputed plaintext-derived
    /// checksum (see `CryptState::compute_plaintext_checksum`). Default
    /// implementation ignores the precomputation and falls through to
    /// `encrypt`; modes that benefit from fan-out reuse override this.
    fn encrypt_with_plaintext_checksum(
        &self,
        dest: &mut [u8],
        data: &[u8],
        nonce: &[u8],
        _plaintext_checksum: &[u8; 16],
    ) -> Result<(), CryptError> {
        self.encrypt(dest, data, nonce)
    }

    /// Encrypt a short sequence of independent OCB-style packets that share a
    /// key but use consecutive caller-supplied nonces. The default
    /// implementation preserves behavior by looping over
    /// `encrypt_with_plaintext_checksum`; modes can override this to batch
    /// backend work across packets.
    fn encrypt_sequence_with_plaintext_checksums(
        &self,
        dests: &mut [&mut [u8]],
        datas: &[&[u8]],
        nonces: &[[u8; 16]],
        plaintext_checksums: &[[u8; 16]],
    ) -> Result<(), CryptError> {
        if dests.len() != datas.len()
            || datas.len() != nonces.len()
            || nonces.len() != plaintext_checksums.len()
        {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        for (((dest, data), nonce), checksum) in dests
            .iter_mut()
            .zip(datas.iter())
            .zip(nonces.iter())
            .zip(plaintext_checksums.iter())
        {
            self.encrypt_with_plaintext_checksum(dest, data, nonce, checksum)?;
        }
        Ok(())
    }

    fn key(&self) -> Option<&[u8]>;
}
