use crate::client::crypt::errors::CryptError;

pub trait CryptoMode: Send + Sync {
    fn nonce_size(&self) -> usize;
    fn key_size(&self) -> usize;
    fn overhead(&self) -> usize;

    fn encrypt(&self, dest: &mut [u8], data: &[u8], nonce: &[u8]) -> Result<(), CryptError>;
    fn decrypt(&self, dest: &mut [u8], data: &[u8], nonce: &[u8]) -> Result<(), CryptError>;

    fn key(&self) -> Option<&[u8]>;
}
