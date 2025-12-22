use std::net::ToSocketAddrs;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use tokio_rustls::TlsAcceptor;

use crate::client_certificate_verifier::ClientCertificateVerifier;
use crate::{
    client_repository::ClientRepository, codec_info::CodecInfo,
    config::Config, types::NodeIdentifier,
};

pub struct Server {
    node_identifier: NodeIdentifier,

    tcp_listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    udp_socket: tokio::net::UdpSocket,

    clients: ClientRepository,

    codec_info: CodecInfo,
}

impl Server {
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let listen_address = config
            .listen
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| "Invalid listen address")?;

        let certificate = CertificateDer::pem_file_iter(config.cert_path)?.collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::from_pem_file(config.key_path)?;

        let tcp_listener = tokio::net::TcpListener::bind(&listen_address).await?;
        let udp_socket = tokio::net::UdpSocket::bind(&listen_address).await?;

        let client_cert_verifier = Arc::new(ClientCertificateVerifier::new());

        let tls_config = rustls::ServerConfig::builder_with_protocol_versions(
            &[&TLS12, &TLS13]
        )
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(certificate, private_key)?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        Ok(Server {
            node_identifier: config.node_id,
            tcp_listener,
            tls_acceptor,
            udp_socket,
            clients: ClientRepository::new(config.node_id),
            codec_info: CodecInfo::default(),
        })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub async fn reload(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // self.config = Config::load();
        Ok(())
    }
}
