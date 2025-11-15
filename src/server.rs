use crate::{
    client::client::Client, client_repository::ClientRepository, codec_info::CodecInfo,
    config::Config, types::NodeIdentifier,
};

pub struct Server {
    config: Config,

    node_identifier: NodeIdentifier,
    tcp_listener: tokio::net::TcpListener,
    udp_socket: tokio::net::UdpSocket,

    clients: ClientRepository,

    codec_info: CodecInfo,
}

impl Server {
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {

    }
}
