use crate::client::crypt::errors::CryptError;

pub trait CryptoMode: Send + Sync {
    fn nonce_size(&self) -> usize;
    fn key_size(&self) -> usize;
    fn overhead(&self) -> usize;

    fn encrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptError>;
    fn decrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptError>;
}
