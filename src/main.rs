mod client;
mod config;
mod server;
mod geoip;
mod voice_crypto;
mod messages;
mod types;
mod client_repository;
mod codec_info;
mod channels;
mod acl;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
