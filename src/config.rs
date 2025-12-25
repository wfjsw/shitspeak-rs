use serde::Deserialize;
use config::{Config as ConfigCrate, Environment, File};

use crate::constants::MAX_NODE_ID;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub node_id: u16,
    pub listen: String,
    pub opus_threshold: u16,
    pub register_name: String,
    pub cert_path: String,
    pub key_path: String,
    pub send_version: bool,
    pub send_build_info: bool,
    pub send_os_info: bool,
    pub allowed_proxies: Vec<String>,
}

impl Config {
    pub fn load() -> Self {
        ConfigCrate::builder()
            .add_source(File::with_name("config"))
            .add_source(Environment::with_prefix("SHITSPEAK").separator("_"))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }
}
