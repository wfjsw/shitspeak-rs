use std::future::poll_fn;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;

use cidr::{AnyIpCidr, IpCidr};
use ppp::{HeaderResult, PartialResult};
use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use tokio::io::ReadBuf;
use tokio_rustls::TlsAcceptor;

use crate::client_certificate_verifier::ClientCertificateVerifier;
use crate::proxy_protocol::get_proxy_protocol_real_ip;
use crate::{
    client_repository::ClientRepository, codec_info::CodecInfo, config::Config,
    types::NodeIdentifier,
};

pub struct Server {
    node_identifier: NodeIdentifier,

    allowed_proxies: Vec<AnyIpCidr>,

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

        let allowed_proxies = config
            .allowed_proxies
            .iter()
            .map(|proxy| AnyIpCidr::from_str(proxy))
            .collect::<Result<Vec<_>, _>>()?;

        let certificate =
            CertificateDer::pem_file_iter(config.cert_path)?.collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::from_pem_file(config.key_path)?;

        let tcp_listener = tokio::net::TcpListener::bind(&listen_address).await?;
        let udp_socket = tokio::net::UdpSocket::bind(&listen_address).await?;

        let client_cert_verifier = Arc::new(ClientCertificateVerifier::new());

        let tls_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(certificate, private_key)?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        Ok(Server {
            node_identifier: config.node_id,
            allowed_proxies,
            tcp_listener,
            tls_acceptor,
            udp_socket,
            clients: ClientRepository::new(config.node_id),
            codec_info: CodecInfo::default(),
        })
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        println!("Server is running on {}", self.tcp_listener.local_addr()?);
        loop {
            let (tcp_stream, addr) = self.tcp_listener.accept().await?;
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = server.handle_incoming_connection(tcp_stream, addr).await {
                    eprintln!("Error handling connection: {}", e);
                }
            });
        }
        Ok(())
    }

    pub async fn handle_incoming_connection(
        &self,
        tcp_stream: tokio::net::TcpStream,
        addr: std::net::SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let real_ip = if self
            .allowed_proxies
            .iter()
            .any(|proxy| proxy.contains(&addr.ip()))
        {
            match get_proxy_protocol_real_ip(&tcp_stream).await? {
                Some(ip) => ip,
                None => addr.ip(),
            }
        } else {
            addr.ip()
        };

        // self.clients.allocate_client(
        //     real_ip,
        //     addr.ip(),
        //     None,
        //     addr,
        //     tcp_stream,
        //     UserVersion::default(),
        // );

        Ok(())
    }

    pub async fn reload(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // self.config = Config::load();
        Ok(())
    }
}
