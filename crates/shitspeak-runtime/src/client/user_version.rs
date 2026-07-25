#[derive(Debug)]
pub struct UserVersion {
    version: u32,
    client_name: String,
    os_name: String,
    os_version: String,
    crypto_mode: String,
}

impl UserVersion {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    pub fn os_name(&self) -> &str {
        &self.os_name
    }

    pub fn os_version(&self) -> &str {
        &self.os_version
    }

    pub fn crypto_mode(&self) -> &str {
        &self.crypto_mode
    }
}
