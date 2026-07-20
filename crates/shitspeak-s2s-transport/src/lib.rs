pub mod geoip {
    pub use shitspeak_core::{NodeGeo, valid_coordinates};
}

pub mod http_client {
    use std::time::Duration;

    use reqwest::Client;

    pub fn build_with_webpki_fallback(
        timeout: Duration,
        label: &str,
    ) -> Result<Client, reqwest::Error> {
        match Client::builder().timeout(timeout).build() {
            Ok(client) => Ok(client),
            Err(system_error) => {
                tracing::warn!(
                    "{label}: failed to build HTTP client with platform certificate verifier: \
                     {system_error}; falling back to bundled WebPKI roots"
                );
                Client::builder()
                    .timeout(timeout)
                    .tls_backend_preconfigured(webpki_rustls_config())
                    .build()
            }
        }
    }

    fn webpki_rustls_config() -> rustls::ClientConfig {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    }
}

pub mod debug_io {
    #[inline]
    pub fn record_named_sent(_kind: &'static str, _bytes: usize) {}

    #[inline]
    pub fn record_named_received(_kind: &'static str, _bytes: usize) {}
}

pub mod s2s_transport_proto {
    pub use shitspeak_proto::s2s_transport_proto::*;
}

pub mod s2s_overlay_proto {
    pub use shitspeak_proto::s2s_overlay_proto::*;
}

pub mod types {
    pub use shitspeak_core::{NodeIdentifier, default_server_id};
}

mod adaptive_queue;
mod compression;
mod config;
mod connection;
mod endpoint;
mod error;
mod frame;
mod identity;
mod local_ip;
mod manager;
mod metrics;
mod native_stats;
mod public_ip;
mod service_level;
mod stream_io;
mod tls;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

#[cfg(test)]
mod integration_tests;

pub use adaptive_queue::{AdaptiveQueueBudget, AdaptiveQueueReceiver, AdaptiveQueueSender};
pub use compression::SendOptions;
pub use config::{KcpTuning, TransportConfig, TransportRoutingPolicy, TransportTuning};
pub use connection::{AddressBackoffSnapshot, TransportPayloadPlan, TransportPayloadVariant};
pub use error::{ConfigError, SendError, TransportError};
pub use frame::{
    Frame, FrameType, build_frame, decode_frame, encode_frame, encode_frame_to_bytes,
    encoded_data_frame_len,
};
pub use identity::{
    OriginAuthenticationError, OriginSignature, OriginSignatureMetadata, node_id_from_cert_file,
};
pub use manager::PeerAddressSnapshot;
pub use manager::{AdaptiveInboundReceiver, ConnectionManager, Inbound, InboundMessage};
pub use metrics::{
    ExpiredOutboundDropSnapshot, ExpiredOutboundDropStage, InboundQueueStatusSnapshot, LinkMetrics,
    MetricsSnapshot, OutboundQueueStatusSnapshot, QueueStatusSnapshot, TransportIoDirection,
    TransportIoFrameSnapshot, TransportIoPressureResult, TransportIoSnapshot,
    TransportPipelineStageSnapshot, VoiceTransportBindingEventReason,
    VoiceTransportBindingEventSnapshot, VoiceTransportBindingSnapshot,
    VoiceTransportChallengerOutcome, VoiceTransportChallengerSnapshot,
};
pub use metrics::{
    apply_packet_loss_penalty, conversational_effective_delay_us, conversational_impairment,
    conversational_quality_score, transport_io_frame_snapshots, transport_io_snapshots,
    transport_pipeline_stage_snapshots,
};
pub use public_ip::discover_public_geo;
pub use service_level::{
    MessageClass, PeerAddress, RoutingMetric, SeedAddress, ServiceLevel, ServiceShape,
    TransportKind,
};
