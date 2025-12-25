use crate::{config::Config, server::Server};

mod acl;
mod channels;
mod client;
mod client_repository;
mod codec_info;
mod config;
mod constants;
mod geoip;
mod messages;
mod server;
mod types;
mod voice_crypto;
mod client_certificate_verifier;
mod proxy_protocol;
mod protocol_version;

mod mumble_proto {
    include!(concat!(env!("OUT_DIR"), "/mumble_proto.rs"));
}

mod mumble_udp {
    include!(concat!(env!("OUT_DIR"), "/mumble_udp.rs"));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_appender = tracing_appender::rolling::daily("log", "server.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt().with_writer(non_blocking).init();

    let config = Config::load();
    let server = Server::new(config).await?;
    server.run().await?;
    Ok(())
}
