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

    fn key(&self) -> Option<&[u8]>;
}
