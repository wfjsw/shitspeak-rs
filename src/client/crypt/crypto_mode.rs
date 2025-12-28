pub trait CryptoMode: Send + Sync {
    fn nonce_size(&self) -> usize;
    fn key_size(&self) -> usize;
    fn overhead(&self) -> usize;
}
