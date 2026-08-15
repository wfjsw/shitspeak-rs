use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;

use crate::errors::HandleIncomingConnectionError;

use super::Server;

pub(super) const ALPN_MUMBLE: &[u8] = b"mumble";

pub type ServerExtensionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), HandleIncomingConnectionError>> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct AlpnConnectionInfo {
    real_ip: std::net::IpAddr,
    client_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    server_id: String,
    tls_ja3: Option<String>,
    tls_ja4: Option<String>,
    tls_ja4t: Option<String>,
    tls_ja4x: Option<String>,
    tls_ja4l: Option<String>,
    tls_sni: Option<String>,
    uses_proxy_protocol: bool,
}

impl AlpnConnectionInfo {
    pub(super) fn new(
        real_ip: std::net::IpAddr,
        client_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        server_id: String,
        tls_fingerprints: crate::tls_fingerprint::TlsFingerprints,
        uses_proxy_protocol: bool,
    ) -> Self {
        Self {
            real_ip,
            client_addr,
            local_addr,
            server_id,
            tls_ja3: tls_fingerprints.ja3,
            tls_ja4: tls_fingerprints.ja4,
            tls_ja4t: tls_fingerprints.ja4t,
            tls_ja4x: tls_fingerprints.ja4x,
            tls_ja4l: tls_fingerprints.ja4l,
            tls_sni: tls_fingerprints.sni,
            uses_proxy_protocol,
        }
    }

    pub fn real_ip(&self) -> std::net::IpAddr {
        self.real_ip
    }

    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn tls_ja4(&self) -> Option<&str> {
        self.tls_ja4.as_deref()
    }

    pub fn tls_ja3(&self) -> Option<&str> {
        self.tls_ja3.as_deref()
    }

    pub fn tls_ja4t(&self) -> Option<&str> {
        self.tls_ja4t.as_deref()
    }

    pub fn tls_ja4x(&self) -> Option<&str> {
        self.tls_ja4x.as_deref()
    }

    pub fn tls_ja4l(&self) -> Option<&str> {
        self.tls_ja4l.as_deref()
    }

    pub fn tls_sni(&self) -> Option<&str> {
        self.tls_sni.as_deref()
    }

    pub fn uses_proxy_protocol(&self) -> bool {
        self.uses_proxy_protocol
    }
}

pub trait ServerExtension: Send + Sync + 'static {
    fn c2s_alpn_protocols(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn spawn_tasks(
        &self,
        _server: Arc<Box<Server>>,
        _shutdown: tokio::sync::watch::Receiver<()>,
        _tasks: &mut JoinSet<()>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn handle_c2s_alpn_stream<'a>(
        &'a self,
        _server: Arc<Box<Server>>,
        _protocol: &'a [u8],
        _stream: TlsStream<TcpStream>,
        _info: AlpnConnectionInfo,
    ) -> Option<ServerExtensionFuture<'a>> {
        None
    }
}

#[derive(Clone, Default)]
pub struct ServerExtensions {
    extensions: Vec<Arc<dyn ServerExtension>>,
}

impl ServerExtensions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with<E>(mut self, extension: E) -> Self
    where
        E: ServerExtension,
    {
        self.push(extension);
        self
    }

    pub fn push<E>(&mut self, extension: E)
    where
        E: ServerExtension,
    {
        self.extensions.push(Arc::new(extension));
    }

    pub fn push_arc(&mut self, extension: Arc<dyn ServerExtension>) {
        self.extensions.push(extension);
    }

    pub(super) fn c2s_alpn_protocols(&self) -> Vec<Vec<u8>> {
        self.extensions
            .iter()
            .flat_map(|extension| extension.c2s_alpn_protocols())
            .collect()
    }

    pub(super) fn handles_c2s_alpn_protocol(&self, protocol: &[u8]) -> bool {
        self.extensions.iter().any(|extension| {
            extension
                .c2s_alpn_protocols()
                .iter()
                .any(|candidate| candidate.as_slice() == protocol)
        })
    }

    pub(super) fn spawn_tasks(
        &self,
        server: Arc<Box<Server>>,
        shutdown: tokio::sync::watch::Receiver<()>,
        tasks: &mut JoinSet<()>,
    ) -> std::io::Result<()> {
        for extension in &self.extensions {
            extension.spawn_tasks(Arc::clone(&server), shutdown.clone(), tasks)?;
        }
        Ok(())
    }

    pub(super) fn handle_c2s_alpn_stream<'a>(
        &'a self,
        server: Arc<Box<Server>>,
        protocol: &'a [u8],
        stream: TlsStream<TcpStream>,
        info: AlpnConnectionInfo,
    ) -> Option<ServerExtensionFuture<'a>> {
        self.extensions
            .iter()
            .find(|extension| {
                extension
                    .c2s_alpn_protocols()
                    .iter()
                    .any(|candidate| candidate.as_slice() == protocol)
            })
            .and_then(|extension| extension.handle_c2s_alpn_stream(server, protocol, stream, info))
    }
}
