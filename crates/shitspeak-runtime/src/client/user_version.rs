#[derive(Debug)]
pub struct UserVersion {
    version: u32,
    client_name: String,
    os_name: String,
    os_version: String,
    crypto_mode: String,
}
