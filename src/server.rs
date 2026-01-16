use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;

use cidr::AnyIpCidr;
use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer};
use rustls::version::{TLS12, TLS13};
use tokio_rustls::TlsAcceptor;

use crate::api::Authenticator;
use crate::client::AsyncMessageHandlerExt;
use crate::client_certificate_verifier::ClientCertificateVerifier;
use crate::errors::{
    HandleIncomingConnectionError, MessageHandlerError, MessageTypeNotForIncoming,
    ReadProtoMessageError,
};
use crate::messages::encoder::Version;
use crate::messages::WriteMessageExt;
use crate::proxy_protocol::get_proxy_protocol_real_ip;
use crate::{
    client_repository::ClientRepository, codec_info::CodecInfo, config::Config,
    types::NodeIdentifier,
};

pub struct Server {
    node_identifier: NodeIdentifier,

    // Config
    send_version: bool,
    send_build_info: bool,
    send_os_info: bool,
    allowed_proxies: Vec<AnyIpCidr>,

    tcp_listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    udp_socket: tokio::net::UdpSocket,

    clients: ClientRepository,

    codec_info: CodecInfo,

    authenticator: Box<dyn Authenticator>,
}

impl Server {
    pub async fn new<A: Authenticator>(config: Config, authenticator: A) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
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

        Ok(Arc::new(Box::new(Server {
            node_identifier: config.node_id,
            allowed_proxies,
            send_version: config.send_version,
            send_build_info: config.send_build_info,
            send_os_info: config.send_os_info,
            tcp_listener,
            tls_acceptor,
            udp_socket,
            clients: ClientRepository::new(config.node_id),
            codec_info: CodecInfo::default(),
            authenticator: Box::new(authenticator),
        })))
    }

    pub async fn run(self: &Arc<Box<Self>>) -> Result<(), Box<dyn std::error::Error>> {
        println!("Server is running on {}", self.tcp_listener.local_addr()?);
        loop {
            let (tcp_stream, remote_addr) = self.tcp_listener.accept().await?;
            let server = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(e) = server
                    .handle_incoming_connection(tcp_stream, remote_addr)
                    .await
                {
                    eprintln!("Error handling connection: {}", e);
                }
            });
        }
    }

    pub async fn handle_incoming_connection(
        self: &Arc<Box<Self>>,
        tcp_stream: tokio::net::TcpStream,
        remote_addr: std::net::SocketAddr,
    ) -> Result<(), HandleIncomingConnectionError> {
        let real_ip = if self
            .allowed_proxies
            .iter()
            .any(|proxy| proxy.contains(&remote_addr.ip()))
        {
            match get_proxy_protocol_real_ip(&tcp_stream).await? {
                Some(ip) => ip,
                None => remote_addr.ip(),
            }
        } else {
            remote_addr.ip()
        };

        let local_addr = tcp_stream.local_addr()?;
        let tls_acceptor = self.tls_acceptor.clone();
        let mut tls_stream = tls_acceptor.accept(tcp_stream).await?;

        // Send server version
        tls_stream
            .write_proto_message(
                &Version::for_server(self.send_version, self.send_build_info, self.send_os_info)
                    .into(),
            )
            .await?;

        let client = self
            .clients
            .allocate_local_client(real_ip, remote_addr, None, local_addr, tls_stream)
            .await;

        loop {
            // Handle incoming messages from the client
            match client.read_and_handle_message(self).await {
                Ok(_) => {}
                Err(_) => {}
            }
        }
    }

    pub async fn reload(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // self.config = Config::load();
        Ok(())
    }

    pub fn get_authenticator(&self) -> &dyn Authenticator {
        self.authenticator.as_ref()
    }
}
