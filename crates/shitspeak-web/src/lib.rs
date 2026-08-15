#[cfg(feature = "moq")]
pub mod moq;
pub mod peer;
pub mod protocol;
pub mod session;
pub mod signaling;
mod simd;
pub mod voice;

use std::sync::Arc;

use crate::session::WebTlsMetadata;
use shitspeak_runtime::errors::HandleIncomingConnectionError;
use shitspeak_runtime::server::{
    AlpnConnectionInfo, Server, ServerExtension, ServerExtensionFuture, ServerExtensions,
};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;

#[derive(Clone, Debug, Default)]
pub struct WebServerExtension;

impl ServerExtension for WebServerExtension {
    fn c2s_alpn_protocols(&self) -> Vec<Vec<u8>> {
        vec![signaling::ALPN_HTTP_1_1.to_vec()]
    }

    fn spawn_tasks(
        &self,
        server: Arc<Box<Server>>,
        shutdown: tokio::sync::watch::Receiver<()>,
        tasks: &mut JoinSet<()>,
    ) -> std::io::Result<()> {
        let startup_config = server.read_config().clone();
        let web_config = startup_config.web.clone();
        if web_config.enabled && web_config.listen.is_some() {
            let handle = signaling::SignalingServer::new(web_config.clone())
                .with_authenticator(server.authenticator_arc())
                .with_server(Arc::clone(&server))
                .spawn(shutdown.clone())?;
            tasks.spawn(async move {
                let _ = handle.await;
            });
        }

        #[cfg(feature = "moq")]
        if web_config.enabled && web_config.moq.enabled && web_config.moq.listen.is_some() {
            let handle = moq::MoqServer::new(web_config)
                .with_tls_fallback(
                    startup_config.cert_path.clone(),
                    startup_config.key_path.clone(),
                )
                .with_authenticator(server.authenticator_arc())
                .with_server(Arc::clone(&server))
                .spawn(shutdown)?;
            tasks.spawn(async move {
                let _ = handle.await;
            });
        }

        Ok(())
    }

    fn handle_c2s_alpn_stream<'a>(
        &'a self,
        server: Arc<Box<Server>>,
        protocol: &'a [u8],
        stream: TlsStream<TcpStream>,
        info: AlpnConnectionInfo,
    ) -> Option<ServerExtensionFuture<'a>> {
        if protocol != signaling::ALPN_HTTP_1_1 {
            return None;
        }

        Some(Box::pin(async move {
            let web = server.read_config().web.clone();
            signaling::SignalingServer::new(web)
                .with_authenticator(server.authenticator_arc())
                .with_server(Arc::clone(&server))
                .with_provisional_server_id(info.server_id().to_owned())
                .handle_stream_with_peer(
                    stream,
                    info.real_ip(),
                    info.client_addr(),
                    info.local_addr(),
                    WebTlsMetadata::new(
                        info.tls_ja3().map(ToOwned::to_owned),
                        info.tls_ja4().map(ToOwned::to_owned),
                        info.tls_ja4t().map(ToOwned::to_owned),
                        info.tls_ja4x().map(ToOwned::to_owned),
                        info.tls_ja4l().map(ToOwned::to_owned),
                        info.tls_sni().map(ToOwned::to_owned),
                    ),
                    info.uses_proxy_protocol(),
                )
                .await
                .map_err(HandleIncomingConnectionError::from)
        }))
    }
}

pub fn server_extensions() -> ServerExtensions {
    ServerExtensions::new().with(WebServerExtension)
}
