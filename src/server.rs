use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;

use cidr::AnyIpCidr;
use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer};
use rustls::version::{TLS12, TLS13};
use tokio_rustls::TlsAcceptor;

use crate::api::Authenticator;
use crate::blob_store::{ChannelBlobStore, SessionBlobStore};
use crate::channel_repository::ChannelRepository;
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
    config: Config,

    allowed_proxies: Vec<AnyIpCidr>,

    tcp_listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    udp_socket: tokio::net::UdpSocket,

    pub clients: ClientRepository,
    pub channels: Arc<ChannelRepository>,
    pub channel_blobs: Arc<ChannelBlobStore>,
    pub session_blobs: Arc<SessionBlobStore>,

    pub codec_info: CodecInfo,

    pub authenticator: Box<dyn Authenticator>,
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
            CertificateDer::pem_file_iter(&config.cert_path)?.collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::from_pem_file(&config.key_path)?;

        let tcp_listener = tokio::net::TcpListener::bind(&listen_address).await?;
        let udp_socket = tokio::net::UdpSocket::bind(&listen_address).await?;

        let client_cert_verifier = Arc::new(ClientCertificateVerifier::new());

        let tls_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(certificate, private_key)?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // ── Channel repository & blob stores ─────────────────────────────
        let node_id = config.node_id;
        let (channels, channel_blobs, session_blobs) =
            match &config.blob_storage_dir {
                Some(dir) => {
                    let ch_repo = ChannelRepository::open(node_id, dir).await?;
                    let ch_blobs = Arc::new(ChannelBlobStore::open(dir).await?);
                    let s_blobs = Arc::new(SessionBlobStore::open(dir).await?);
                    (ch_repo, ch_blobs, s_blobs)
                }
                None => {
                    // In-memory mode: use a temp dir for blob stores so the
                    // code paths are uniform; blobs won't survive restarts.
                    let tmp = std::env::temp_dir().join("shitspeak-blobs");
                    let ch_repo = ChannelRepository::new_in_memory(node_id);
                    let ch_blobs = Arc::new(ChannelBlobStore::open(&tmp).await?);
                    let s_blobs = Arc::new(SessionBlobStore::open(&tmp).await?);
                    (ch_repo, ch_blobs, s_blobs)
                }
            };

        Ok(Arc::new(Box::new(Server {
            node_identifier: node_id,
            allowed_proxies,
            tcp_listener,
            tls_acceptor,
            udp_socket,
            clients: ClientRepository::new(node_id),
            channels,
            channel_blobs,
            session_blobs,
            codec_info: CodecInfo::default(),
            authenticator: Box::new(authenticator),
            config,
        })))
    }

    pub async fn run(self: &Arc<Box<Self>>) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Server is running on {}", self.tcp_listener.local_addr()?);
        loop {
            let (tcp_stream, remote_addr) = self.tcp_listener.accept().await?;
            let server = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(e) = server
                    .handle_incoming_connection(tcp_stream, remote_addr)
                    .await
                {
                    tracing::warn!("Error handling connection: {}", e);
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
                &Version::for_server(
                    self.config.send_version,
                    self.config.send_build_info,
                    self.config.send_os_info,
                )
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

    pub fn get_clients(&self) -> &ClientRepository {
        &self.clients
    }

    pub fn get_min_client_version(&self) -> u64 {
        self.config.min_client_version
    }

    pub fn get_max_users(&self) -> u64 {
        self.config.max_users
    }

    pub fn get_cert_required(&self) -> bool {
        self.config.cert_required
    }

    pub fn get_max_bandwidth(&self) -> u32 {
        self.config.max_bandwidth
    }

    pub fn get_welcome_text(&self) -> Option<&str> {
        self.config.welcome_text.as_deref()
    }

    pub fn get_allow_html(&self) -> bool {
        self.config.allow_html
    }

    pub fn get_max_text_message_length(&self) -> u32 {
        self.config.max_text_message_length
    }

    pub fn get_max_image_message_length(&self) -> u32 {
        self.config.max_image_message_length
    }
}
