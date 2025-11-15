pub trait CryptoProvider : Send + Sync {
    fn nonce_size(&self) -> usize;
    fn key_size(&self) -> usize;
    fn overhead_size(&self) -> usize;

    fn set_key(&mut self, key: &mut [u8]);
    fn encrypt(&self, destination: &mut [u8], source: &[u8], nonce: &[u8]);
    fn decrypt(&self, destination: &mut [u8], source: &[u8], nonce: &[u8]) -> bool;
}
