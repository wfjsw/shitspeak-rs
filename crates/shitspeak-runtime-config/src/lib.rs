use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use config::{Config as ConfigCrate, Environment, File};
use serde::{Deserialize, Deserializer};
use shitspeak_core::{NodeGeo, NodeIdentifier, ProtocolVersion, constants::APP_PROTO_VER};
use shitspeak_s2s::application::ApplicationConfig;
use shitspeak_s2s::overlay::OverlayTuning;
use shitspeak_s2s::replications::ReplicationTuning;
use shitspeak_s2s_transport::{
    PeerAddress, SeedAddress, TransportConfig, TransportKind, TransportTuning,
};

pub use shitspeak_auth::{
    AuthenticatorBackend, AuthenticatorConfig, AuthenticatorConfigSource, ExecAuthenticatorConfig,
    ExecAuthenticatorMode, ExecLongRunningRequestMode, WasmAuthenticatorConfig,
};

const DEFAULT_LOCAL_NODE_ID: NodeIdentifier = 0;

#[derive(Deserialize, Debug, Clone)]
pub struct S2sConfig {
    /// S2S is explicit opt-in. Disabled configs do not need PKI/listen fields.
    #[serde(default)]
    pub enabled: bool,

    /// Whether private listen/advertise addresses are published into the
    /// overlay LSAs. Keep enabled for LAN/VPN/container clusters.
    #[serde(default = "default_true")]
    pub advertise_private_ips: bool,

    /// Local interface names whose unicast addresses should be added to
    /// automatic S2S advertisement. Empty by default so wildcard listeners do
    /// not publish every local interface.
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub local_interface_advertise: Vec<String>,

    #[serde(default)]
    pub ca_path: Option<PathBuf>,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,

    #[serde(default, deserialize_with = "deserialize_listen_addrs")]
    pub tcp_listen: Vec<SocketAddr>,
    #[serde(default, deserialize_with = "deserialize_listen_addrs")]
    pub kcp_listen: Vec<SocketAddr>,
    #[serde(default, deserialize_with = "deserialize_listen_addrs")]
    pub quic_listen: Vec<SocketAddr>,
    #[serde(default, deserialize_with = "deserialize_listen_addrs")]
    pub udp_listen: Vec<SocketAddr>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub tcp_advertise: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub kcp_advertise: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub quic_advertise: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub udp_advertise: Vec<String>,

    /// Optional plain HTTP listener for the S2S topology/status page.
    #[serde(default)]
    pub status_http_listen: Option<SocketAddr>,

    #[serde(default)]
    pub geo: S2sGeoConfig,

    #[serde(default)]
    pub persistence_dir: Option<PathBuf>,

    #[serde(default)]
    pub seed_addresses: Vec<S2sSeedAddressConfig>,

    /// L3 application-layer tunables (moderation + voice). Lives under
    /// `[s2s.application.*]` in TOML.
    #[serde(default)]
    pub application: ApplicationConfig,

    /// L1 transport-layer metrics smoothing + ping-cap tunables. Lives
    /// under `[s2s.transport.*]` in TOML.
    #[serde(default)]
    pub transport: TransportTuning,

    /// L2 overlay-layer tunables. Lives under `[s2s.overlay.*]` in TOML.
    #[serde(default)]
    pub overlay: OverlayTuning,

    /// L3 replications-layer tunables (Tempo + owner-mode). Lives under
    /// `[s2s.replications.*]` in TOML.
    #[serde(default)]
    pub replications: ReplicationTuning,
}

impl Default for S2sConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            advertise_private_ips: true,
            local_interface_advertise: Vec::new(),
            ca_path: None,
            cert_path: None,
            key_path: None,
            tcp_listen: Vec::new(),
            kcp_listen: Vec::new(),
            quic_listen: Vec::new(),
            udp_listen: Vec::new(),
            tcp_advertise: Vec::new(),
            kcp_advertise: Vec::new(),
            quic_advertise: Vec::new(),
            udp_advertise: Vec::new(),
            status_http_listen: None,
            geo: S2sGeoConfig::default(),
            persistence_dir: None,
            seed_addresses: Vec::new(),
            application: ApplicationConfig::default(),
            transport: TransportTuning::default(),
            overlay: OverlayTuning::default(),
            replications: ReplicationTuning::default(),
        }
    }
}

impl S2sConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn local_node_id(&self) -> Result<NodeIdentifier, String> {
        if !self.enabled {
            return Ok(DEFAULT_LOCAL_NODE_ID);
        }

        let Some(cert_path) = self.cert_path.as_deref() else {
            return Ok(DEFAULT_LOCAL_NODE_ID);
        };

        match shitspeak_s2s_transport::node_id_from_cert_file(cert_path) {
            Ok(node_id) => Ok(node_id),
            Err(shitspeak_s2s_transport::ConfigError::CertRead { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(DEFAULT_LOCAL_NODE_ID)
            }
            Err(e) => Err(format!(
                "failed to extract S2S node id from {}: {e}",
                cert_path.display()
            )),
        }
    }

    pub fn transport_config(&self) -> Result<Option<TransportConfig>, String> {
        self.transport_config_with_max_users_and_auto_advertise_host(100, None)
    }

    pub fn transport_config_with_max_users(
        &self,
        max_users: u64,
    ) -> Result<Option<TransportConfig>, String> {
        self.transport_config_with_max_users_and_auto_advertise_host(max_users, None)
    }

    pub fn transport_config_with_auto_advertise_host(
        &self,
        auto_advertise_host: Option<&str>,
    ) -> Result<Option<TransportConfig>, String> {
        self.transport_config_with_max_users_and_auto_advertise_host(100, auto_advertise_host)
    }

    pub fn transport_config_with_max_users_and_auto_advertise_host(
        &self,
        max_users: u64,
        auto_advertise_host: Option<&str>,
    ) -> Result<Option<TransportConfig>, String> {
        if !self.enabled {
            return Ok(None);
        }

        self.replications.validate()?;

        let ca_path = self
            .ca_path
            .clone()
            .ok_or_else(|| "s2s.enabled=true requires s2s.ca_path".to_string())?;
        let cert_path = self
            .cert_path
            .clone()
            .ok_or_else(|| "s2s.enabled=true requires s2s.cert_path".to_string())?;
        let key_path = self
            .key_path
            .clone()
            .ok_or_else(|| "s2s.enabled=true requires s2s.key_path".to_string())?;

        let mut cfg = TransportConfig::new(ca_path, cert_path, key_path)
            .with_advertise_private_ips(self.advertise_private_ips)
            .with_local_advertise_interfaces(self.local_interface_advertise.clone());
        cfg = cfg
            .with_tcp_listen_addrs(self.tcp_listen.iter().copied())
            .with_kcp_listen_addrs(self.kcp_listen.iter().copied())
            .with_quic_listen_addrs(self.quic_listen.iter().copied())
            .with_udp_listen_addrs(self.udp_listen.iter().copied());
        let tcp_advertise = resolve_s2s_advertise_overrides(
            "s2s.tcp_advertise",
            &self.tcp_advertise,
            auto_advertise_host,
            &self.tcp_listen,
        )?;
        let ResolvedAdvertiseAddrs {
            addrs,
            is_override,
            implicit_failures,
        } = tcp_advertise;
        for addr in addrs {
            cfg = if is_override {
                cfg.with_tcp_advertise_override(addr)
            } else {
                cfg.with_tcp_advertise(addr)
            };
        }
        for failure in implicit_failures {
            cfg = cfg.with_implicit_advertise_failure(failure);
        }
        let kcp_advertise = resolve_s2s_advertise_overrides(
            "s2s.kcp_advertise",
            &self.kcp_advertise,
            auto_advertise_host,
            &self.kcp_listen,
        )?;
        let ResolvedAdvertiseAddrs {
            addrs,
            is_override,
            implicit_failures,
        } = kcp_advertise;
        for addr in addrs {
            cfg = if is_override {
                cfg.with_kcp_advertise_override(addr)
            } else {
                cfg.with_kcp_advertise(addr)
            };
        }
        for failure in implicit_failures {
            cfg = cfg.with_implicit_advertise_failure(failure);
        }
        let quic_advertise = resolve_s2s_advertise_overrides(
            "s2s.quic_advertise",
            &self.quic_advertise,
            auto_advertise_host,
            &self.quic_listen,
        )?;
        let ResolvedAdvertiseAddrs {
            addrs,
            is_override,
            implicit_failures,
        } = quic_advertise;
        for addr in addrs {
            cfg = if is_override {
                cfg.with_quic_advertise_override(addr)
            } else {
                cfg.with_quic_advertise(addr)
            };
        }
        for failure in implicit_failures {
            cfg = cfg.with_implicit_advertise_failure(failure);
        }
        let udp_advertise = resolve_s2s_advertise_overrides(
            "s2s.udp_advertise",
            &self.udp_advertise,
            auto_advertise_host,
            &self.udp_listen,
        )?;
        let ResolvedAdvertiseAddrs {
            addrs,
            is_override,
            implicit_failures,
        } = udp_advertise;
        for addr in addrs {
            cfg = if is_override {
                cfg.with_udp_advertise_override(addr)
            } else {
                cfg.with_udp_advertise(addr)
            };
        }
        for failure in implicit_failures {
            cfg = cfg.with_implicit_advertise_failure(failure);
        }

        cfg = cfg.with_seed_targets(
            self.seed_addresses
                .iter()
                .map(S2sSeedAddressConfig::seed_address)
                .collect::<Result<Vec<_>, _>>()?,
        );
        let mut cfg = self
            .transport
            .try_apply(cfg)?
            .with_max_users(max_users.try_into().unwrap_or(usize::MAX));
        if let Some(dir) = self.persistence_dir.clone() {
            cfg = cfg.with_compression_adaptive_dictionary_cache_dir(dir);
        }
        Ok(Some(cfg))
    }

    pub fn overlay_config(&self) -> shitspeak_s2s::overlay::OverlayConfig {
        let mut cfg = shitspeak_s2s::overlay::OverlayConfig::new(Vec::new());
        if let Some(dir) = self.persistence_dir.clone() {
            cfg = cfg.with_persistence_dir(dir);
        }
        self.overlay
            .apply(cfg)
            .with_transport_routing_policy(self.transport.routing_policy())
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct S2sGeoConfig {
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

impl Default for S2sGeoConfig {
    fn default() -> Self {
        Self {
            latitude: None,
            longitude: None,
            city: None,
            region: None,
            country: None,
            source: None,
        }
    }
}

impl S2sGeoConfig {
    pub fn manual_geo(&self) -> Option<NodeGeo> {
        let latitude = self.latitude?;
        let longitude = self.longitude?;
        NodeGeo::new(
            latitude,
            longitude,
            self.city.clone(),
            self.region.clone(),
            self.country.clone(),
            self.source.clone().unwrap_or_else(|| "manual".to_owned()),
        )
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct S2sSeedAddressConfig {
    transport: S2sTransportKindConfig,
    addr: String,
}

impl S2sSeedAddressConfig {
    pub fn new(transport: S2sTransportKindConfig, addr: SocketAddr) -> Self {
        Self {
            transport,
            addr: addr.to_string(),
        }
    }

    pub fn transport(&self) -> S2sTransportKindConfig {
        self.transport
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn peer_address(&self) -> Result<PeerAddress, String> {
        let addr = resolve_s2s_addr("s2s seed address", &self.addr)?;
        Ok(PeerAddress::new(addr, self.transport.into()))
    }

    pub fn seed_address(&self) -> Result<SeedAddress, String> {
        validate_s2s_seed_addr("s2s seed address", &self.addr)?;
        Ok(SeedAddress::new(self.addr.clone(), self.transport.into()))
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AdvertiseOverrides {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ListenAddrs {
    One(SocketAddr),
    Many(Vec<SocketAddr>),
}

struct ResolvedAdvertiseAddrs {
    addrs: Vec<SocketAddr>,
    is_override: bool,
    implicit_failures: Vec<String>,
}

fn deserialize_listen_addrs<'de, D>(deserializer: D) -> Result<Vec<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = ListenAddrs::deserialize(deserializer)?;
    let mut addrs = Vec::new();
    match raw {
        ListenAddrs::One(addr) => push_unique_socket_addr(&mut addrs, addr),
        ListenAddrs::Many(values) => {
            for addr in values {
                push_unique_socket_addr(&mut addrs, addr);
            }
        }
    }
    Ok(addrs)
}

fn deserialize_advertise_overrides<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_list(deserializer)
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = AdvertiseOverrides::deserialize(deserializer)?;
    let values = match raw {
        AdvertiseOverrides::One(value) => vec![value],
        AdvertiseOverrides::Many(values) => values,
    };
    Ok(values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect())
}

fn resolve_s2s_advertise_overrides(
    label: &str,
    values: &[String],
    auto_advertise_host: Option<&str>,
    listen: &[SocketAddr],
) -> Result<ResolvedAdvertiseAddrs, String> {
    let mut resolved = Vec::new();
    if !values.is_empty() {
        for value in values {
            let addrs = resolve_s2s_advertise_addrs(label, value)?;
            let addrs = filter_advertise_addrs_for_listen(label, value, addrs, listen)?;
            push_unique_socket_addrs(&mut resolved, addrs);
        }
        return Ok(ResolvedAdvertiseAddrs {
            addrs: resolved,
            is_override: true,
            implicit_failures: Vec::new(),
        });
    }

    let Some(host) = auto_advertise_host
        .map(str::trim)
        .filter(|host| !host.is_empty())
    else {
        return Ok(ResolvedAdvertiseAddrs {
            addrs: Vec::new(),
            is_override: false,
            implicit_failures: Vec::new(),
        });
    };
    if listen.is_empty() {
        return Ok(ResolvedAdvertiseAddrs {
            addrs: Vec::new(),
            is_override: false,
            implicit_failures: Vec::new(),
        });
    };
    let mut implicit_failures = Vec::new();
    for listen_addr in listen {
        let value = format_host_port(host, listen_addr.port());
        match resolve_s2s_advertise_addrs(label, &value).and_then(|addrs| {
            filter_implicit_advertise_addrs(label, &value, addrs).and_then(|addrs| {
                filter_advertise_addrs_for_listen(
                    label,
                    &value,
                    addrs,
                    std::slice::from_ref(listen_addr),
                )
            })
        }) {
            Ok(addrs) => push_unique_socket_addrs(&mut resolved, addrs),
            Err(failure) => implicit_failures.push(failure),
        }
    }
    Ok(ResolvedAdvertiseAddrs {
        addrs: resolved,
        is_override: false,
        implicit_failures,
    })
}

fn filter_implicit_advertise_addrs(
    label: &str,
    value: &str,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, String> {
    let addrs = addrs
        .into_iter()
        .filter(|addr| is_routable_advertise_ip(addr.ip()))
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(format!(
            "{label} {value:?} did not resolve to any routable advertise addresses"
        ));
    }
    Ok(addrs)
}

fn filter_advertise_addrs_for_listen(
    label: &str,
    value: &str,
    addrs: Vec<SocketAddr>,
    listen: &[SocketAddr],
) -> Result<Vec<SocketAddr>, String> {
    if listen.is_empty() {
        return Ok(addrs);
    }
    let filtered = addrs
        .into_iter()
        .filter(|addr| listen_supports_advertise_family(listen, *addr))
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return Err(format!(
            "{label} {value:?} did not resolve to any addresses compatible with listen addresses {listen:?}"
        ));
    }
    Ok(filtered)
}

fn listen_supports_advertise_family(listen: &[SocketAddr], advertise: SocketAddr) -> bool {
    listen.iter().any(|listen_addr| {
        listen_addr.is_ipv4() == advertise.is_ipv4()
            || (advertise.is_ipv4() && listen_addr.is_ipv6() && listen_addr.ip().is_unspecified())
    })
}

fn push_unique_socket_addr(out: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if !out.contains(&addr) {
        out.push(addr);
    }
}

fn push_unique_socket_addrs(out: &mut Vec<SocketAddr>, addrs: Vec<SocketAddr>) {
    for addr in addrs {
        push_unique_socket_addr(out, addr);
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

fn resolve_s2s_advertise_addrs(label: &str, value: &str) -> Result<Vec<SocketAddr>, String> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            return Err(format!(
                "{label} {value:?} must not resolve to an unspecified address"
            ));
        }
        return Ok(vec![addr]);
    }

    let mut resolved = Vec::new();
    for addr in value
        .to_socket_addrs()
        .map_err(|e| format!("invalid {label} {value:?}: {e}"))?
    {
        if !is_routable_advertise_ip(addr.ip()) {
            continue;
        }
        if !resolved.contains(&addr) {
            resolved.push(addr);
        }
    }
    if resolved.is_empty() {
        return Err(format!(
            "{label} {value:?} did not resolve to any routable advertise addresses"
        ));
    }
    Ok(resolved)
}

fn resolve_s2s_addr(label: &str, value: &str) -> Result<SocketAddr, String> {
    let addr = value
        .to_socket_addrs()
        .map_err(|e| format!("invalid {label} {value:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("{label} {value:?} resolved to no addresses"))?;
    if addr.ip().is_unspecified() {
        return Err(format!(
            "{label} {value:?} must not resolve to an unspecified address"
        ));
    }
    Ok(addr)
}

fn validate_s2s_seed_addr(label: &str, value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("invalid {label} {value:?}: address is empty"));
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            return Err(format!(
                "{label} {value:?} must not resolve to an unspecified address"
            ));
        }
        return Ok(());
    }

    let Some((host, port)) = split_seed_host_port(value) else {
        return Err(format!(
            "invalid {label} {value:?}: expected host:port with numeric port"
        ));
    };
    if host.is_empty() {
        return Err(format!("invalid {label} {value:?}: host is empty"));
    }
    port.parse::<u16>()
        .map_err(|_| format!("invalid {label} {value:?}: port must be 0..65535"))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified() {
            return Err(format!(
                "{label} {value:?} must not resolve to an unspecified address"
            ));
        }
        return Err(format!(
            "invalid {label} {value:?}: IPv6 literal seed addresses must use [addr]:port"
        ));
    }
    Ok(())
}

fn split_seed_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        return Some((host, port));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    Some((host, port))
}

fn is_routable_advertise_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 198 && (18..=19).contains(&octets[1]))
        }
        std::net::IpAddr::V6(ip) => {
            let segments = ip.segments();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !((segments[0] & 0xffc0) == 0xfe80)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum S2sTransportKindConfig {
    Tcp,
    Kcp,
    Quic,
    Udp,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UdpPingUserCountScope {
    Cluster,
    Local,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthMode {
    Password,
    Sso,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerEntrypointConfig {
    pub server_id: String,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub udp_ping_status_server_id: Option<String>,
    #[serde(default)]
    pub sni: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebSsoConfig {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_sso_subject_claim")]
    pub subject_claim: String,
    #[serde(default = "default_sso_username_claim")]
    pub username_claim: String,
    #[serde(default = "default_sso_groups_claim")]
    pub groups_claim: String,
}

impl Default for WebSsoConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            jwks_url: None,
            audience: None,
            subject_claim: default_sso_subject_claim(),
            username_claim: default_sso_username_claim(),
            groups_claim: default_sso_groups_claim(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebAuthConfig {
    #[serde(default = "default_web_auth_modes")]
    pub modes: Vec<WebAuthMode>,
    #[serde(default = "default_true")]
    pub password_enabled: bool,
    #[serde(default)]
    pub sso: WebSsoConfig,
}

impl Default for WebAuthConfig {
    fn default() -> Self {
        Self {
            modes: default_web_auth_modes(),
            password_enabled: true,
            sso: WebSsoConfig::default(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebRtcIceServerConfig {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebRtcConfig {
    #[serde(default)]
    pub ice_servers: Vec<WebRtcIceServerConfig>,
    #[serde(default = "default_web_max_speaker_ssrcs")]
    pub max_speaker_ssrcs: u32,
    #[serde(default = "default_web_audio_bitrate")]
    pub audio_bitrate: u32,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebMoqConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default = "default_web_max_speaker_ssrcs")]
    pub max_speaker_tracks: u32,
    #[serde(default = "default_web_audio_bitrate")]
    pub audio_bitrate: u32,
}

impl Default for WebMoqConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: None,
            public_url: None,
            cert_path: None,
            key_path: None,
            max_speaker_tracks: default_web_max_speaker_ssrcs(),
            audio_bitrate: default_web_audio_bitrate(),
        }
    }
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            ice_servers: Vec::new(),
            max_speaker_ssrcs: default_web_max_speaker_ssrcs(),
            audio_bitrate: default_web_audio_bitrate(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default)]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub auth: WebAuthConfig,
    #[serde(default)]
    pub webrtc: WebRtcConfig,
    #[serde(default)]
    pub moq: WebMoqConfig,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: None,
            public_base_url: None,
            allowed_origins: Vec::new(),
            auth: WebAuthConfig::default(),
            webrtc: WebRtcConfig::default(),
            moq: WebMoqConfig::default(),
        }
    }
}

impl From<S2sTransportKindConfig> for TransportKind {
    fn from(value: S2sTransportKindConfig) -> Self {
        match value {
            S2sTransportKindConfig::Tcp => TransportKind::Tcp,
            S2sTransportKindConfig::Kcp => TransportKind::Kcp,
            S2sTransportKindConfig::Quic => TransportKind::Quic,
            S2sTransportKindConfig::Udp => TransportKind::Udp,
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AclConfig {
    /// When true, superusers ignore channel Enter ACLs. Default preserves the
    /// historical superuser behavior.
    #[serde(default = "default_true")]
    debug_acl_enter: bool,
    /// When true, a matching explicit Enter deny remains denied even when
    /// Write would otherwise imply Enter. Default preserves historical Write
    /// behavior.
    #[serde(default)]
    explicit_enter_deny_overrides_write: bool,
    /// When true, registered non-superuser ACL editors keep a personal
    /// Write|Traverse fallback if their edit would remove their own Write.
    #[serde(default = "default_true")]
    preserve_write_acl_on_edit: bool,
    /// When true, temporary channel creation adds a creator-specific ACL for
    /// any missing Write, Enter, and Speak permissions.
    #[serde(default = "default_true")]
    grant_temp_channel_creator_acl: bool,
    /// When true, ACL edits reevaluate Speak for clients currently in the
    /// changed channel subtree and update their suppress state.
    #[serde(default)]
    reevaluate_speak_on_acl_change: bool,
    /// When true, a moderator with the required Move permissions may move
    /// another user into a channel that user cannot Traverse.
    #[serde(default)]
    allow_move_without_traverse: bool,
    /// When true, a client retained in a non-Traverse channel also sees that
    /// channel's users plus directly linked channels and their users. It also
    /// reveals inaccessible directly linked channels and their users when the
    /// client's current channel is traversable.
    #[serde(default)]
    reveal_users_in_current_and_linked_channels_without_traverse: bool,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            debug_acl_enter: true,
            explicit_enter_deny_overrides_write: false,
            preserve_write_acl_on_edit: true,
            grant_temp_channel_creator_acl: true,
            reevaluate_speak_on_acl_change: false,
            allow_move_without_traverse: false,
            reveal_users_in_current_and_linked_channels_without_traverse: false,
        }
    }
}

impl AclConfig {
    pub fn new(debug_acl_enter: bool) -> Self {
        Self {
            debug_acl_enter,
            ..Self::default()
        }
    }

    pub fn with_explicit_enter_deny_overrides_write(
        debug_acl_enter: bool,
        explicit_enter_deny_overrides_write: bool,
    ) -> Self {
        Self {
            debug_acl_enter,
            explicit_enter_deny_overrides_write,
            ..Self::default()
        }
    }

    pub fn with_acl_behavior(
        debug_acl_enter: bool,
        explicit_enter_deny_overrides_write: bool,
        preserve_write_acl_on_edit: bool,
        grant_temp_channel_creator_acl: bool,
    ) -> Self {
        Self::with_acl_behavior_and_speak_reevaluation(
            debug_acl_enter,
            explicit_enter_deny_overrides_write,
            preserve_write_acl_on_edit,
            grant_temp_channel_creator_acl,
            false,
        )
    }

    pub fn with_acl_behavior_and_speak_reevaluation(
        debug_acl_enter: bool,
        explicit_enter_deny_overrides_write: bool,
        preserve_write_acl_on_edit: bool,
        grant_temp_channel_creator_acl: bool,
        reevaluate_speak_on_acl_change: bool,
    ) -> Self {
        Self {
            debug_acl_enter,
            explicit_enter_deny_overrides_write,
            preserve_write_acl_on_edit,
            grant_temp_channel_creator_acl,
            reevaluate_speak_on_acl_change,
            allow_move_without_traverse: false,
            reveal_users_in_current_and_linked_channels_without_traverse: false,
        }
    }

    pub fn with_allow_move_without_traverse(mut self, allow: bool) -> Self {
        self.allow_move_without_traverse = allow;
        self
    }

    pub fn with_reveal_users_in_current_and_linked_channels_without_traverse(
        mut self,
        reveal: bool,
    ) -> Self {
        self.reveal_users_in_current_and_linked_channels_without_traverse = reveal;
        self
    }

    pub fn debug_acl_enter(&self) -> bool {
        self.debug_acl_enter
    }

    pub fn explicit_enter_deny_overrides_write(&self) -> bool {
        self.explicit_enter_deny_overrides_write
    }

    pub fn preserve_write_acl_on_edit(&self) -> bool {
        self.preserve_write_acl_on_edit
    }

    pub fn grant_temp_channel_creator_acl(&self) -> bool {
        self.grant_temp_channel_creator_acl
    }

    pub fn reevaluate_speak_on_acl_change(&self) -> bool {
        self.reevaluate_speak_on_acl_change
    }

    pub fn allow_move_without_traverse(&self) -> bool {
        self.allow_move_without_traverse
    }

    pub fn reveal_users_in_current_and_linked_channels_without_traverse(&self) -> bool {
        self.reveal_users_in_current_and_linked_channels_without_traverse
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertificateHashProtection {
    #[default]
    Disabled,
    Irreversible,
    Reversible,
}

impl CertificateHashProtection {
    fn from_bool(enabled: bool) -> Self {
        if enabled {
            Self::Irreversible
        } else {
            Self::Disabled
        }
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "false" | "disabled" | "disable" | "off" | "none" => Some(Self::Disabled),
            "true" | "irreversible" => Some(Self::Irreversible),
            "reversible" => Some(Self::Reversible),
            _ => None,
        }
    }
}

impl std::fmt::Display for CertificateHashProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Disabled => "disabled",
            Self::Irreversible => "irreversible",
            Self::Reversible => "reversible",
        };
        f.write_str(value)
    }
}

impl<'de> Deserialize<'de> for CertificateHashProtection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawProtection {
            Bool(bool),
            String(String),
        }

        match RawProtection::deserialize(deserializer)? {
            RawProtection::Bool(enabled) => Ok(Self::from_bool(enabled)),
            RawProtection::String(value) => Self::parse(&value).ok_or_else(|| {
                serde::de::Error::custom(
                    "expected false, true, \"irreversible\", or \"reversible\"",
                )
            }),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivacyConfig {
    /// Controls remapping of other users' UserState.hash values before
    /// delivery to non-superuser clients. The viewer's own hash remains raw.
    #[serde(default)]
    protect_certificate_hashes: CertificateHashProtection,
    /// Shared cluster secret for certificate-hash remapping. Configure the
    /// same value on every node when protection is enabled.
    #[serde(default)]
    certificate_hash_secret: Option<String>,
    /// Environment-variable friendly form:
    /// SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET -> privacy.certificate.hash.secret.
    #[serde(default)]
    certificate: PrivacyCertificateConfig,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
struct PrivacyCertificateConfig {
    #[serde(default)]
    hash: PrivacyCertificateHashConfig,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
struct PrivacyCertificateHashConfig {
    #[serde(default)]
    secret: Option<String>,
}

impl PrivacyConfig {
    pub fn new(protect_certificate_hashes: bool, certificate_hash_secret: Option<String>) -> Self {
        Self::with_certificate_hash_protection(
            CertificateHashProtection::from_bool(protect_certificate_hashes),
            certificate_hash_secret,
        )
    }

    pub fn with_certificate_hash_protection(
        protect_certificate_hashes: CertificateHashProtection,
        certificate_hash_secret: Option<String>,
    ) -> Self {
        Self {
            protect_certificate_hashes,
            certificate_hash_secret,
            certificate: PrivacyCertificateConfig::default(),
        }
    }

    pub fn protect_certificate_hashes(&self) -> bool {
        self.protect_certificate_hashes.is_enabled()
    }

    pub fn certificate_hash_protection(&self) -> CertificateHashProtection {
        self.protect_certificate_hashes
    }

    pub fn certificate_hash_secret(&self) -> Option<&str> {
        self.certificate_hash_secret
            .as_deref()
            .or(self.certificate.hash.secret.as_deref())
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub listen: String,
    #[serde(default)]
    pub server_entrypoints: Vec<ServerEntrypointConfig>,
    pub register_name: String,

    // ── Public server registration ────────────────────────────────────────
    /// Password for authenticating with the public server registry.
    #[serde(default)]
    pub register_password: Option<String>,
    /// Public URL advertised in the registration payload.
    #[serde(default)]
    pub register_url: Option<String>,
    /// Hostname (or IP) that the registry should advertise for this server.
    /// If empty, the server's listen address is used.
    #[serde(default)]
    pub register_hostname: Option<String>,
    /// Geographic location string (e.g. "New York, USA") for the registry.
    #[serde(default)]
    pub register_location: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub send_version: bool,
    pub send_build_info: bool,
    pub send_os_info: bool,
    /// Server protocol version advertised to clients and used as the
    /// server-side feature gate for protocol-version-dependent behavior.
    /// Defaults to the compile-time `APP_PROTO_VER`; tests can override it
    /// per server without mutating global process state.
    #[serde(default = "default_server_protocol_version")]
    pub server_protocol_version: ProtocolVersion,
    pub allowed_proxies: Vec<String>,
    pub min_client_version: u64,
    pub max_users: u64,

    // ── Authentication backend ───────────────────────────────────────────
    /// Selects the built-in authenticator backend. Defaults to the demo
    /// authenticator.
    #[serde(default)]
    pub authenticator: AuthenticatorConfig,

    #[serde(default)]
    pub observability: ObservabilityConfig,

    #[serde(default)]
    pub geoip: GeoIpConfig,

    // ── Mumble standard server config ──────────────────────────────────────
    #[serde(default)]
    pub welcome_text: Option<String>,
    #[serde(default = "default_max_bandwidth")]
    pub max_bandwidth: u32,
    #[serde(default = "default_true")]
    pub allow_html: bool,
    #[serde(default = "default_max_text_message_length")]
    pub max_text_message_length: u32,
    #[serde(default = "default_max_image_message_length")]
    pub max_image_message_length: u32,
    #[serde(default = "default_root_channel_name")]
    pub root_channel_name: String,
    #[serde(default)]
    pub default_channel: u32,
    #[serde(default)]
    pub cert_required: bool,

    // ── Blob / persistence ─────────────────────────────────────────────────
    /// Directory used for WAL, snapshot, and blob storage.
    /// `None` = in-memory only (no persistence).
    #[serde(default)]
    pub blob_storage_dir: Option<PathBuf>,
    /// Total on-disk budget (bytes) for the session blob cache (user
    /// textures/comments) before *unreferenced* blobs are evicted
    /// least-recently-used first. Referenced blobs are never evicted.
    /// `0` disables eviction. Default: 256 MiB.
    #[serde(default = "default_session_blob_cache_budget_bytes")]
    pub session_blob_cache_budget_bytes: u64,
    /// Whether `user_channel_cache.db` records current/listening channel state
    /// for sessions hosted on remote S2S nodes. Default: `false`.
    #[serde(default)]
    pub user_channel_cache_record_remote_sessions: bool,
    /// Max channel log entries kept in memory for replay/S2S.
    #[serde(default = "default_channel_log_max_entries")]
    pub channel_log_max_entries: usize,
    /// Max client log entries kept in memory for replay/S2S.
    #[serde(default = "default_client_log_max_entries")]
    pub client_log_max_entries: usize,
    /// Snapshot cadence based on committed channel operations.
    #[serde(default = "default_channel_snapshot_every_ops")]
    pub channel_snapshot_every_ops: u64,
    /// Snapshot cadence based on elapsed seconds.
    #[serde(default = "default_channel_snapshot_every_secs")]
    pub channel_snapshot_every_secs: i64,
    /// Number of oldest WAL log lines to expire on each compaction pass.
    /// Compaction is best-effort and may keep more data to reduce churn.
    #[serde(default = "default_channel_wal_compaction_expire_count")]
    pub channel_wal_compaction_expire_count: usize,

    // ── UDP voice ──────────────────────────────────────────────────────────
    /// Whether to accept UDP voice packets.  When `false`, the UDP drain
    /// loop still runs (for ping/latency) but voice packets are silently
    /// dropped.  Default: `true`.
    #[serde(default = "default_true")]
    pub udp_voice_enabled: bool,
    /// Whether to respond to UDP ping packets with server information
    /// (version, user count, max users, bandwidth).  Default: `true`.
    #[serde(default = "default_true")]
    pub udp_ping_enabled: bool,
    /// Controls whether UDP pings display clusterwide users/max users or only
    /// this node's local users/max users. Default: `cluster`.
    #[serde(default = "default_udp_ping_user_count_scope")]
    pub udp_ping_user_count_scope: UdpPingUserCountScope,
    /// Minimum capacity of the bounded channel between the UDP drain task and
    /// the processing task. The effective capacity scales with `max_users`.
    /// Larger values tolerate processing bursts at the cost of memory.
    /// Default floor: 2048 (~2 MB of buffered packets).
    #[serde(default = "default_udp_channel_size")]
    pub udp_channel_size: usize,
    /// Realtime voice-path protections and retry budgets.
    #[serde(default)]
    pub voice: VoiceTuning,

    // ── Idle timeout ──────────────────────────────────────────────────────
    /// Seconds of inactivity (no ping) before a client is disconnected.
    /// Default: 30.
    #[serde(default = "default_idle_timeout")]
    pub client_idle_timeout_secs: u64,
    /// Milliseconds after TLS setup before a native client must finish Authenticate.
    /// Default: 30000.
    #[serde(default = "default_authenticate_timeout_ms")]
    pub authenticate_timeout_ms: u64,
    /// Maximum number of clients concurrently running UDP crypt setup,
    /// authenticator backend work, and post-authentication finalization. Zero
    /// disables the login queue and concurrency limit. Default: floor(3rd
    /// root(active CPU count)), minimum 1.
    #[serde(default = "default_auth_finalization_concurrency")]
    pub auth_finalization_concurrency: usize,
    /// Milliseconds before a pending two-phase channel delete is rolled back.
    /// Default: 5000.
    #[serde(default = "default_pending_delete_timeout_ms")]
    pub pending_delete_timeout_ms: u64,

    // ── Authentication abuse protections ──────────────────────────────────
    /// Leaky-bucket refill rate: authentication attempts allowed per source
    /// IP per second.  A burst of up to `auth_rate_limit_ip_burst` is allowed
    /// immediately (e.g. many users behind one NAT joining at once).  Zero
    /// disables the per-IP limit.  Default: 2.
    #[serde(default = "default_auth_rate_limit_per_ip_per_second")]
    pub auth_rate_limit_per_ip_per_second: f64,
    /// Burst of authentication attempts allowed per source IP.  Default: 10.
    #[serde(default = "default_auth_rate_limit_ip_burst")]
    pub auth_rate_limit_ip_burst: f64,
    /// Leaky-bucket refill rate: authentication attempts allowed per account
    /// (lowercased username) per second, slowing targeted credential
    /// stuffing.  Zero disables the per-account limit.  Default: 1.
    #[serde(default = "default_auth_rate_limit_per_account_per_second")]
    pub auth_rate_limit_per_account_per_second: f64,
    /// Burst of authentication attempts allowed per account.  Default: 10.
    #[serde(default = "default_auth_rate_limit_account_burst")]
    pub auth_rate_limit_account_burst: f64,

    // ── Access control ────────────────────────────────────────────────────
    /// Groups required to connect.  If empty, all authenticated users are
    /// allowed.  If non-empty, a user must belong to at least one of these
    /// groups to pass authentication.
    #[serde(default)]
    pub required_groups: HashSet<String>,

    /// When `true`, `ChannelState` messages include `is_enter_restricted`
    /// and `can_enter` fields computed from ACLs.  Default: `false`.
    #[serde(default)]
    pub send_permission_info: bool,

    /// When `true`, clients only receive user/session information for users
    /// whose current channel they can Traverse. Default: `false`.
    #[serde(default)]
    pub hide_users_without_traverse: bool,

    /// When `true`, clients only receive channels they can Traverse. Default:
    /// `false`.
    #[serde(default)]
    pub hide_channels_without_traverse: bool,

    /// When `true`, superusers see the hosting S2S node id appended to each
    /// user's display name in outgoing `UserState` messages. Default: `true`.
    #[serde(default = "default_true")]
    pub show_node_id_for_superusers: bool,

    // ── ACL behavior toggles ─────────────────────────────────────────────
    #[serde(default)]
    pub acl: AclConfig,

    // ── Privacy behavior toggles ───────────────────────────────────────
    #[serde(default)]
    pub privacy: PrivacyConfig,

    // ── S2S cluster bootstrap ───────────────────────────────────────────
    #[serde(default)]
    pub s2s: S2sConfig,

    // ── Browser WebRTC gateway ──────────────────────────────────────────
    #[serde(default)]
    pub web: WebConfig,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VoiceTuning {
    #[serde(default = "default_voice_max_udp_packet_age_ms")]
    max_udp_packet_age_ms: u64,
    #[serde(default = "default_voice_max_routing_queue_age_ms")]
    max_routing_queue_age_ms: u64,
    #[serde(default = "default_voice_udp_send_retry_budget_ms")]
    udp_send_retry_budget_ms: u64,
    #[serde(default)]
    dispatch: VoiceDispatchTuning,
}

impl Default for VoiceTuning {
    fn default() -> Self {
        Self {
            max_udp_packet_age_ms: default_voice_max_udp_packet_age_ms(),
            max_routing_queue_age_ms: default_voice_max_routing_queue_age_ms(),
            udp_send_retry_budget_ms: default_voice_udp_send_retry_budget_ms(),
            dispatch: VoiceDispatchTuning::default(),
        }
    }
}

impl VoiceTuning {
    pub fn max_udp_packet_age(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.max_udp_packet_age_ms)
    }

    pub fn max_routing_queue_age(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.max_routing_queue_age_ms)
    }

    pub fn udp_send_retry_budget(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.udp_send_retry_budget_ms)
    }

    pub fn dispatch(&self) -> &VoiceDispatchTuning {
        &self.dispatch
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum VoiceDispatchMode {
    #[default]
    StartupCalibrated,
    Sequential,
    Fixed,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VoiceDispatchTuning {
    #[serde(default)]
    mode: VoiceDispatchMode,
    #[serde(default = "default_voice_dispatch_fanout_threshold")]
    small_payload_rayon_threshold: usize,
    #[serde(default = "default_voice_dispatch_rayon_min_len")]
    small_payload_rayon_min_len: usize,
    #[serde(default = "default_voice_dispatch_fanout_threshold")]
    large_payload_rayon_threshold: usize,
    #[serde(default = "default_voice_dispatch_rayon_min_len")]
    large_payload_rayon_min_len: usize,
}

impl Default for VoiceDispatchTuning {
    fn default() -> Self {
        Self {
            mode: VoiceDispatchMode::StartupCalibrated,
            small_payload_rayon_threshold: default_voice_dispatch_fanout_threshold(),
            small_payload_rayon_min_len: default_voice_dispatch_rayon_min_len(),
            large_payload_rayon_threshold: default_voice_dispatch_fanout_threshold(),
            large_payload_rayon_min_len: default_voice_dispatch_rayon_min_len(),
        }
    }
}

impl VoiceDispatchTuning {
    pub fn mode(&self) -> VoiceDispatchMode {
        self.mode
    }

    pub fn small_payload_profile(&self) -> (usize, usize) {
        (
            self.small_payload_rayon_threshold,
            self.small_payload_rayon_min_len,
        )
    }

    pub fn large_payload_profile(&self) -> (usize, usize) {
        (
            self.large_payload_rayon_threshold,
            self.large_payload_rayon_min_len,
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.mode != VoiceDispatchMode::Fixed {
            return Ok(());
        }

        validate_voice_dispatch_profile("small_payload", self.small_payload_profile())?;
        validate_voice_dispatch_profile("large_payload", self.large_payload_profile())
    }
}

fn validate_voice_dispatch_profile(
    name: &str,
    (threshold, min_len): (usize, usize),
) -> Result<(), String> {
    if threshold == 0 {
        return Err(format!(
            "voice.dispatch.{name}_rayon_threshold must be at least 1"
        ));
    }
    if min_len == 0 {
        return Err(format!(
            "voice.dispatch.{name}_rayon_min_len must be at least 1"
        ));
    }
    if min_len > threshold {
        return Err(format!(
            "voice.dispatch.{name}_rayon_min_len must not exceed {name}_rayon_threshold"
        ));
    }
    Ok(())
}

impl AuthenticatorConfigSource for Config {
    fn authenticator_config(&self) -> &AuthenticatorConfig {
        &self.authenticator
    }

    fn authenticator_blob_storage_dir(&self) -> Option<&Path> {
        self.blob_storage_dir.as_deref()
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GeoIpConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_geoip_maxmind_database_path")]
    maxmind_database_path: Option<PathBuf>,
    #[serde(default = "default_geoip_cache_ttl_secs")]
    cache_ttl_secs: u64,
    #[serde(default = "default_geoip_cache_capacity")]
    cache_capacity: usize,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            maxmind_database_path: default_geoip_maxmind_database_path(),
            cache_ttl_secs: default_geoip_cache_ttl_secs(),
            cache_capacity: default_geoip_cache_capacity(),
        }
    }
}

impl GeoIpConfig {
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn maxmind_database_path(&self) -> Option<&PathBuf> {
        self.enabled()
            .then_some(self.maxmind_database_path.as_ref())
            .flatten()
    }

    pub fn cache_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.cache_ttl_secs.max(1))
    }

    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default = "default_metrics_path")]
    pub path: String,
    #[serde(default)]
    pub remote_write: RemoteWriteConfig,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: None,
            path: default_metrics_path(),
            remote_write: RemoteWriteConfig::default(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RemoteWriteConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default = "default_remote_write_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_remote_write_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_remote_write_retry_cache_capacity")]
    pub retry_cache_capacity: usize,
    #[serde(default = "default_remote_write_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_remote_write_retry_initial_interval_ms")]
    pub retry_initial_interval_ms: u64,
    #[serde(default = "default_remote_write_retry_max_interval_ms")]
    pub retry_max_interval_ms: u64,
}

impl Default for RemoteWriteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            labels: HashMap::new(),
            tenant_id: None,
            username: None,
            password: None,
            bearer_token: None,
            interval_ms: default_remote_write_interval_ms(),
            batch_size: default_remote_write_batch_size(),
            retry_cache_capacity: default_remote_write_retry_cache_capacity(),
            request_timeout_ms: default_remote_write_request_timeout_ms(),
            retry_initial_interval_ms: default_remote_write_retry_initial_interval_ms(),
            retry_max_interval_ms: default_remote_write_retry_max_interval_ms(),
        }
    }
}

fn default_max_bandwidth() -> u32 {
    72_000
}
fn default_true() -> bool {
    true
}

fn default_geoip_maxmind_database_path() -> Option<PathBuf> {
    Some(PathBuf::from("GeoLite2-City.mmdb"))
}

fn default_geoip_cache_ttl_secs() -> u64 {
    86_400
}

fn default_geoip_cache_capacity() -> usize {
    4096
}

fn default_metrics_path() -> String {
    "/metrics".to_owned()
}

fn default_remote_write_interval_ms() -> u64 {
    15_000
}

fn default_remote_write_batch_size() -> usize {
    4096
}

fn default_remote_write_retry_cache_capacity() -> usize {
    16_384
}

fn default_remote_write_request_timeout_ms() -> u64 {
    5_000
}

fn default_remote_write_retry_initial_interval_ms() -> u64 {
    1_000
}

fn default_remote_write_retry_max_interval_ms() -> u64 {
    30_000
}

fn default_server_protocol_version() -> ProtocolVersion {
    APP_PROTO_VER
}
fn default_max_text_message_length() -> u32 {
    5_000
}
fn default_max_image_message_length() -> u32 {
    131_072
}
fn default_root_channel_name() -> String {
    "Root".to_string()
}

fn default_session_blob_cache_budget_bytes() -> u64 {
    256 * 1024 * 1024
}
fn default_udp_channel_size() -> usize {
    2048
}
fn default_voice_max_udp_packet_age_ms() -> u64 {
    250
}
fn default_voice_max_routing_queue_age_ms() -> u64 {
    250
}
fn default_voice_udp_send_retry_budget_ms() -> u64 {
    2
}
fn default_voice_dispatch_fanout_threshold() -> usize {
    512
}
fn default_voice_dispatch_rayon_min_len() -> usize {
    256
}
fn default_udp_ping_user_count_scope() -> UdpPingUserCountScope {
    UdpPingUserCountScope::Cluster
}
fn default_idle_timeout() -> u64 {
    30
}
fn default_authenticate_timeout_ms() -> u64 {
    30_000
}
fn default_auth_finalization_concurrency() -> usize {
    let active_cpus = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    integer_third_root(active_cpus).max(1)
}
fn integer_third_root(value: usize) -> usize {
    if value <= 1 {
        return value;
    }
    let mut low = 1usize;
    let mut high = value.min(1usize << ((usize::BITS as usize + 2) / 3));
    let mut answer = 1usize;
    while low <= high {
        let mid = low + (high - low) / 2;
        if third_power_at_most(mid, value) {
            answer = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    answer
}
fn third_power_at_most(base: usize, value: usize) -> bool {
    debug_assert!(base > 0);
    base <= value / base / base
}
fn default_pending_delete_timeout_ms() -> u64 {
    5_000
}

fn default_auth_rate_limit_per_ip_per_second() -> f64 {
    2.0
}

fn default_auth_rate_limit_ip_burst() -> f64 {
    10.0
}

fn default_auth_rate_limit_per_account_per_second() -> f64 {
    1.0
}

fn default_auth_rate_limit_account_burst() -> f64 {
    10.0
}
fn default_channel_log_max_entries() -> usize {
    300
}
fn default_client_log_max_entries() -> usize {
    2_000
}
fn default_channel_snapshot_every_ops() -> u64 {
    10
}
fn default_channel_snapshot_every_secs() -> i64 {
    60
}
fn default_channel_wal_compaction_expire_count() -> usize {
    2_000
}
fn default_sso_subject_claim() -> String {
    "sub".to_string()
}
fn default_sso_username_claim() -> String {
    "preferred_username".to_string()
}
fn default_sso_groups_claim() -> String {
    "groups".to_string()
}
fn default_web_auth_modes() -> Vec<WebAuthMode> {
    vec![WebAuthMode::Password]
}
fn default_web_max_speaker_ssrcs() -> u32 {
    64
}
fn default_web_audio_bitrate() -> u32 {
    64_000
}

impl Config {
    pub fn load() -> Self {
        Self::build_config()
            .try_deserialize()
            .expect("Failed to load config.toml")
    }

    /// Reload config from disk. Returns `Ok(Some(new_config))` if the file
    /// was read successfully, `Ok(None)` if the file doesn't exist, or an
    /// error if deserialization fails.
    pub fn reload() -> Result<Option<Self>, config::ConfigError> {
        // Check if the file actually exists before trying to deserialize
        if !std::path::Path::new("config.toml").exists() {
            return Ok(None);
        }
        Self::build_config().try_deserialize().map(Some)
    }

    fn build_config() -> ConfigCrate {
        ConfigCrate::builder()
            .add_source(File::with_name("config"))
            // Preserve the original single-underscore nesting convention for
            // existing deployments, then layer the unambiguous form on top.
            .add_source(Environment::with_prefix("SHITSPEAK").separator("_"))
            .add_source(
                Environment::with_prefix("SHITSPEAK")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()
            .expect("Failed to build config sources")
    }

    pub fn local_node_id(&self) -> Result<NodeIdentifier, String> {
        self.s2s.local_node_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;
    use std::time::Duration;

    fn parse_s2s(raw: &str) -> Result<S2sConfig, ::config::ConfigError> {
        ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()?
            .try_deserialize()
    }

    fn parse_config(raw: &str) -> Result<Config, ::config::ConfigError> {
        ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()?
            .try_deserialize()
    }

    #[test]
    fn canonical_environment_keys_preserve_snake_case_leaves() {
        let base = r#"
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100
        "#;
        let environment = HashMap::from([
            ("SHITSPEAK_MAX_USERS".to_owned(), "250".to_owned()),
            (
                "SHITSPEAK_AUTHENTICATOR__BACKEND".to_owned(),
                "wasm".to_owned(),
            ),
            (
                "SHITSPEAK_AUTHENTICATOR__WASM__PATH".to_owned(),
                "auth/auth.wasm".to_owned(),
            ),
            (
                "SHITSPEAK_PRIVACY__CERTIFICATE_HASH_SECRET".to_owned(),
                "secret".to_owned(),
            ),
        ]);

        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(base, ::config::FileFormat::Toml))
            .add_source(
                ::config::Environment::with_prefix("SHITSPEAK")
                    .separator("_")
                    .source(Some(environment.clone())),
            )
            .add_source(
                ::config::Environment::with_prefix("SHITSPEAK")
                    .prefix_separator("_")
                    .separator("__")
                    .source(Some(environment)),
            )
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("environment overrides deserialize");

        assert_eq!(cfg.max_users, 250);
        assert_eq!(cfg.authenticator.backend(), AuthenticatorBackend::Wasm);
        assert_eq!(
            cfg.authenticator.wasm().path(),
            Some(&PathBuf::from("auth/auth.wasm"))
        );
        assert_eq!(cfg.privacy.certificate_hash_secret(), Some("secret"));
    }

    #[test]
    fn voice_dispatch_defaults_to_startup_calibration() {
        let dispatch: VoiceDispatchTuning = ::config::Config::builder()
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("voice dispatch config parses");

        assert_eq!(dispatch.mode(), VoiceDispatchMode::StartupCalibrated);
        assert_eq!(dispatch.small_payload_profile(), (512, 256));
        assert_eq!(dispatch.large_payload_profile(), (512, 256));
        assert!(dispatch.validate().is_ok());
    }

    #[test]
    fn fixed_voice_dispatch_parses_and_validates_profiles() {
        let dispatch: VoiceDispatchTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    mode = "fixed"
                    small_payload_rayon_threshold = 128
                    small_payload_rayon_min_len = 64
                    large_payload_rayon_threshold = 256
                    large_payload_rayon_min_len = 128
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("voice dispatch config parses");

        assert_eq!(dispatch.mode(), VoiceDispatchMode::Fixed);
        assert_eq!(dispatch.small_payload_profile(), (128, 64));
        assert_eq!(dispatch.large_payload_profile(), (256, 128));
        assert!(dispatch.validate().is_ok());
    }

    #[test]
    fn fixed_voice_dispatch_rejects_a_floor_above_its_threshold() {
        let dispatch: VoiceDispatchTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    mode = "fixed"
                    small_payload_rayon_threshold = 128
                    small_payload_rayon_min_len = 256
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("voice dispatch config parses");

        assert!(
            dispatch
                .validate()
                .expect_err("invalid fixed profile must be rejected")
                .contains("must not exceed")
        );
    }

    fn cert_with_cn(dir: &Path, cn: &str) -> PathBuf {
        let mut params =
            rcgen::CertificateParams::new(vec!["s2s-node.local".to_owned()]).expect("cert params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("self signed cert");
        let path = dir.join("s2s-cert.pem");
        std::fs::write(&path, cert.pem()).expect("write cert");
        path
    }

    #[test]
    fn integer_third_root_floors_without_overflow() {
        let cases = [
            (0, 0),
            (1, 1),
            (2, 1),
            (7, 1),
            (8, 2),
            (26, 2),
            (27, 3),
            (63, 3),
            (64, 4),
            (124, 4),
            (125, 5),
        ];
        for (value, expected) in cases {
            assert_eq!(integer_third_root(value), expected, "value={value}");
        }

        let max_root = integer_third_root(usize::MAX);
        assert!(third_power_at_most(max_root, usize::MAX));
        assert!(!third_power_at_most(max_root + 1, usize::MAX));
    }

    #[test]
    fn auth_finalization_concurrency_defaults_to_third_root_active_cpus() {
        let active_cpus = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        assert_eq!(
            default_auth_finalization_concurrency(),
            integer_third_root(active_cpus).max(1)
        );
    }

    #[test]
    fn auth_finalization_concurrency_preserves_explicit_zero() {
        let cfg = parse_config(
            r#"
                listen = "127.0.0.1:64738"
                register_name = "test"
                cert_path = "cert.pem"
                key_path = "key.pem"
                send_version = true
                send_build_info = true
                send_os_info = true
                allowed_proxies = []
                min_client_version = 0
                max_users = 100
                auth_finalization_concurrency = 0
            "#,
        )
        .expect("config deserialize");

        assert_eq!(cfg.auth_finalization_concurrency, 0);
    }

    /// Ensure the checked-in `config.toml` parses cleanly under the current
    /// schema, including the new `[s2s.transport]`, `[s2s.overlay]`, and
    /// `[s2s.replications]` sections.
    #[test]
    fn live_config_toml_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .join("config.toml");
        let raw = std::fs::read_to_string(&path).expect("config.toml missing");
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(&raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert_eq!(
            cfg.udp_ping_user_count_scope,
            UdpPingUserCountScope::Cluster
        );
        assert_eq!(cfg.blob_storage_dir, Some(PathBuf::from("data")));
        assert!(!cfg.user_channel_cache_record_remote_sessions);
        assert_eq!(cfg.client_idle_timeout_secs, 30);
        assert_eq!(cfg.authenticate_timeout_ms, 30_000);
        assert_eq!(cfg.pending_delete_timeout_ms, 5_000);
        // Spot-check a value from each new block.
        assert!(cfg.s2s.transport.latency_ewma_alpha > 0.0);
        assert!(cfg.s2s.overlay.lsdb_sync_max_response_lsas >= 1);
        assert!(
            cfg.s2s.replications.propose_ttl_ms >= cfg.s2s.replications.delivery_tick_interval_ms
        );
        assert!(!cfg.web.enabled);
        assert_eq!(cfg.web.auth.modes.len(), 2);
        assert_eq!(cfg.web.webrtc.max_speaker_ssrcs, 64);
        assert!(!cfg.web.moq.enabled);
        assert_eq!(cfg.web.moq.max_speaker_tracks, 64);
        assert!(!cfg.acl.debug_acl_enter());
        assert!(cfg.acl.explicit_enter_deny_overrides_write());
        assert!(!cfg.acl.preserve_write_acl_on_edit());
        assert!(cfg.acl.grant_temp_channel_creator_acl());
        assert!(cfg.acl.reevaluate_speak_on_acl_change());
        assert!(!cfg.acl.allow_move_without_traverse());
        assert!(
            !cfg.acl
                .reveal_users_in_current_and_linked_channels_without_traverse()
        );
        assert_eq!(cfg.root_channel_name, "Root");
        assert_eq!(cfg.authenticator.backend(), AuthenticatorBackend::Demo);
        assert!(cfg.geoip.enabled());
        assert_eq!(
            cfg.geoip.maxmind_database_path(),
            Some(&PathBuf::from("GeoLite2-City.mmdb"))
        );
        assert!(!cfg.observability.metrics.enabled);
        assert_eq!(cfg.observability.metrics.path, "/metrics");
        assert!(!cfg.observability.metrics.remote_write.enabled);
        assert!(cfg.show_node_id_for_superusers);
    }

    #[test]
    fn show_node_id_for_superusers_defaults_on_and_parses_false() {
        let base = r#"
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100
        "#;
        let default_cfg = parse_config(base).expect("config deserialize");
        assert!(default_cfg.show_node_id_for_superusers);

        let disabled_cfg = parse_config(&format!("{base}\nshow_node_id_for_superusers = false\n"))
            .expect("config deserialize");
        assert!(!disabled_cfg.show_node_id_for_superusers);
    }

    #[test]
    fn user_channel_cache_remote_sessions_default_off_and_parses_true() {
        let base = r#"
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100
        "#;

        let default_cfg = parse_config(base).expect("config deserialize");
        assert!(!default_cfg.user_channel_cache_record_remote_sessions);

        let enabled_cfg = parse_config(&format!(
            "{base}\nuser_channel_cache_record_remote_sessions = true\n"
        ))
        .expect("config deserialize");
        assert!(enabled_cfg.user_channel_cache_record_remote_sessions);
    }

    #[test]
    fn voice_tuning_defaults_and_overrides_parse() {
        let base = r#"
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100
        "#;
        let default_cfg = parse_config(base).expect("config deserialize");
        assert_eq!(
            default_cfg.voice.max_udp_packet_age(),
            Duration::from_millis(250)
        );
        assert_eq!(
            default_cfg.voice.max_routing_queue_age(),
            Duration::from_millis(250)
        );

        let override_cfg = parse_config(&format!(
            r#"{base}

            [voice]
            max_udp_packet_age_ms = 180
            max_routing_queue_age_ms = 190
        "#
        ))
        .expect("config deserialize");
        assert_eq!(
            override_cfg.voice.max_udp_packet_age(),
            Duration::from_millis(180)
        );
        assert_eq!(
            override_cfg.voice.max_routing_queue_age(),
            Duration::from_millis(190)
        );
    }

    #[test]
    fn full_config_parses_s2s_transport_kcp_tuning_path() {
        let raw = r#"
            listen = "127.0.0.1:0"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 10

            [s2s.transport.kcp]
            nodelay = true
            interval_ms = 10
            fast_resend = 2
            no_congestion = false
            flush_write = true
            flush_acks_input = true
        "#;
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        let kcp = cfg.s2s.transport.apply(TransportConfig::new(
            "ca.pem".into(),
            "cert.pem".into(),
            "key.pem".into(),
        ));
        let kcp = kcp.kcp_tuning();

        assert!(kcp.nodelay());
        assert_eq!(kcp.interval_ms(), 10);
        assert_eq!(kcp.fast_resend(), 2);
        assert!(!kcp.no_congestion());
        assert!(kcp.flush_write());
        assert!(kcp.flush_acks_input());
    }

    #[test]
    fn s2s_geo_manual_coordinates_parse_and_validate_bounds() {
        let cfg = parse_s2s(
            r#"
                [geo]
                latitude = 32.7767
                longitude = -96.7970
                city = " Dallas "
                region = "TX"
                country = "US"
                source = "operator"
            "#,
        )
        .expect("s2s geo config parses");

        let geo = cfg.geo.manual_geo().expect("manual geo");
        assert_eq!(geo.latitude(), 32.7767);
        assert_eq!(geo.longitude(), -96.7970);
        assert_eq!(geo.city(), Some("Dallas"));
        assert_eq!(geo.region(), Some("TX"));
        assert_eq!(geo.country(), Some("US"));
        assert_eq!(geo.source(), "operator");

        let invalid = parse_s2s(
            r#"
                [geo]
                latitude = 91.0
                longitude = -96.7970
            "#,
        )
        .expect("invalid coordinates still deserialize");
        assert!(invalid.geo.manual_geo().is_none());
    }

    #[test]
    fn global_geoip_config_parses_for_acl_shared_resolver() {
        let cfg: GeoIpConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                enabled = true
                maxmind_database_path = "GeoLite2-Country.mmdb"
                cache_ttl_secs = 60
                cache_capacity = 32
            "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("geoip config parses");

        assert!(cfg.enabled());
        assert_eq!(
            cfg.maxmind_database_path(),
            Some(&PathBuf::from("GeoLite2-Country.mmdb"))
        );
        assert_eq!(cfg.cache_ttl(), Duration::from_secs(60));
        assert_eq!(cfg.cache_capacity(), 32);
    }

    #[test]
    fn global_geoip_disabled_hides_database_path() {
        let cfg: GeoIpConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                enabled = false
                maxmind_database_path = "GeoLite2-Country.mmdb"
            "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("geoip config parses");

        assert!(!cfg.enabled());
        assert_eq!(cfg.maxmind_database_path(), None);
    }

    #[test]
    fn observability_metrics_config_parses() {
        let cfg: ObservabilityConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    [metrics]
                    enabled = true
                    listen = "127.0.0.1:9095"
                    path = "custom-metrics"

                    [metrics.remote_write]
                    enabled = true
                    url = "http://mimir.example/api/v1/push"
                    labels = { environment = "prod", cluster = "core" }
                    tenant_id = "tenant-a"
                    username = "user"
                    password = "secret"
                    interval_ms = 5000
                    batch_size = 128
                    retry_cache_capacity = 8
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("observability deserialize");

        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.metrics.listen, Some("127.0.0.1:9095".parse().unwrap()));
        assert_eq!(cfg.metrics.path, "custom-metrics");
        assert!(cfg.metrics.remote_write.enabled);
        assert_eq!(
            cfg.metrics.remote_write.url.as_deref(),
            Some("http://mimir.example/api/v1/push")
        );
        assert_eq!(
            cfg.metrics.remote_write.tenant_id.as_deref(),
            Some("tenant-a")
        );
        assert_eq!(
            cfg.metrics
                .remote_write
                .labels
                .get("environment")
                .map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            cfg.metrics
                .remote_write
                .labels
                .get("cluster")
                .map(String::as_str),
            Some("core")
        );
        assert_eq!(cfg.metrics.remote_write.batch_size, 128);
        assert_eq!(cfg.metrics.remote_write.retry_cache_capacity, 8);
    }

    #[test]
    fn root_channel_name_defaults_and_parses() {
        let default_cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    listen = "127.0.0.1:64738"
                    register_name = "test"
                    cert_path = "cert.pem"
                    key_path = "key.pem"
                    send_version = true
                    send_build_info = true
                    send_os_info = true
                    allowed_proxies = []
                    min_client_version = 0
                    max_users = 100
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert_eq!(default_cfg.root_channel_name, "Root");

        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    listen = "127.0.0.1:64738"
                    register_name = "test"
                    cert_path = "cert.pem"
                    key_path = "key.pem"
                    send_version = true
                    send_build_info = true
                    send_os_info = true
                    allowed_proxies = []
                    min_client_version = 0
                    max_users = 100
                    root_channel_name = "Lobby"
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert_eq!(cfg.root_channel_name, "Lobby");
    }

    #[test]
    fn authenticator_config_defaults_to_demo_backend() {
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    listen = "127.0.0.1:64738"
                    register_name = "test"
                    cert_path = "cert.pem"
                    key_path = "key.pem"
                    send_version = true
                    send_build_info = true
                    send_os_info = true
                    allowed_proxies = []
                    min_client_version = 0
                    max_users = 100
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.authenticator.backend(), AuthenticatorBackend::Demo);
        assert_eq!(cfg.authenticator.exec().command(), None);
        assert!(cfg.authenticator.exec().environment().is_empty());
        assert_eq!(cfg.authenticator.wasm().path(), None);
    }

    #[test]
    fn authenticator_config_parses_exec_backend() {
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    listen = "127.0.0.1:64738"
                    register_name = "test"
                    cert_path = "cert.pem"
                    key_path = "key.pem"
                    send_version = true
                    send_build_info = true
                    send_os_info = true
                    allowed_proxies = []
                    min_client_version = 0
                    max_users = 100

                    [authenticator]
                    backend = "exec"

                    [authenticator.exec]
                    mode = "exec_long_running"
                    long_running_request_mode = "async"
                    command = "auth-helper"
                    args = ["--mode", "server"]
                    environment = { AUTH_ENDPOINT = "https://auth.test", AUTH_MODE = "production" }
                    working_dir = "auth"
                    uid = 1001
                    gid = 1002
                    timeout_ms = 7500
                    max_response_bytes = 4096
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.authenticator.backend(), AuthenticatorBackend::Exec);
        assert_eq!(
            cfg.authenticator.exec().mode(),
            ExecAuthenticatorMode::LongRunning
        );
        assert_eq!(
            cfg.authenticator.exec().long_running_request_mode(),
            ExecLongRunningRequestMode::Async
        );
        assert_eq!(
            cfg.authenticator.exec().command().map(PathBuf::as_path),
            Some(Path::new("auth-helper"))
        );
        assert_eq!(cfg.authenticator.exec().args(), ["--mode", "server"]);
        assert_eq!(
            cfg.authenticator
                .exec()
                .environment()
                .get("AUTH_ENDPOINT")
                .map(String::as_str),
            Some("https://auth.test")
        );
        assert_eq!(
            cfg.authenticator
                .exec()
                .environment()
                .get("AUTH_MODE")
                .map(String::as_str),
            Some("production")
        );
        assert_eq!(
            cfg.authenticator.exec().working_dir().map(PathBuf::as_path),
            Some(Path::new("auth"))
        );
        assert_eq!(cfg.authenticator.exec().uid(), Some(1001));
        assert_eq!(cfg.authenticator.exec().gid(), Some(1002));
        assert_eq!(cfg.authenticator.exec().timeout_ms(), 7500);
        assert_eq!(cfg.authenticator.exec().max_response_bytes(), 4096);
    }

    #[test]
    fn authenticator_config_parses_wasm_backend() {
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    listen = "127.0.0.1:64738"
                    register_name = "test"
                    cert_path = "cert.pem"
                    key_path = "key.pem"
                    send_version = true
                    send_build_info = true
                    send_os_info = true
                    allowed_proxies = []
                    min_client_version = 0
                    max_users = 100

                    [authenticator]
                    backend = "wasm"

                    [authenticator.wasm]
                    path = "auth.wasm"
                    file_access_dir = ["auth-files", "shared-auth-files"]
                    working_dir = "auth-files"
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.authenticator.backend(), AuthenticatorBackend::Wasm);
        assert_eq!(
            cfg.authenticator.wasm().path().map(PathBuf::as_path),
            Some(Path::new("auth.wasm"))
        );
        assert_eq!(
            cfg.authenticator.wasm().file_access_dir(),
            [
                PathBuf::from("auth-files"),
                PathBuf::from("shared-auth-files")
            ]
        );
        assert_eq!(
            cfg.authenticator.wasm().working_dir().map(PathBuf::as_path),
            Some(Path::new("auth-files"))
        );
    }

    #[test]
    fn authenticator_exec_config_accepts_short_mode_aliases() {
        let cfg: AuthenticatorConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    backend = "exec"

                    [exec]
                    mode = "ephemeral"
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.backend(), AuthenticatorBackend::Exec);
        assert_eq!(cfg.exec().mode(), ExecAuthenticatorMode::Ephemeral);
    }

    #[test]
    fn authenticator_exec_config_defaults_to_ephemeral_mode() {
        let cfg: AuthenticatorConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    backend = "exec"
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.backend(), AuthenticatorBackend::Exec);
        assert_eq!(cfg.exec().mode(), ExecAuthenticatorMode::Ephemeral);
    }

    #[test]
    fn acl_config_defaults_and_parses_behavior_flags() {
        let default_cfg: AclConfig = ::config::Config::builder()
            .add_source(::config::File::from_str("", ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert!(default_cfg.debug_acl_enter());
        assert!(!default_cfg.explicit_enter_deny_overrides_write());
        assert!(default_cfg.preserve_write_acl_on_edit());
        assert!(default_cfg.grant_temp_channel_creator_acl());
        assert!(!default_cfg.reevaluate_speak_on_acl_change());
        assert!(!default_cfg.allow_move_without_traverse());
        assert!(!default_cfg.reveal_users_in_current_and_linked_channels_without_traverse());

        let cfg: AclConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    debug_acl_enter = false
                    explicit_enter_deny_overrides_write = true
                    preserve_write_acl_on_edit = false
                    grant_temp_channel_creator_acl = false
                    reevaluate_speak_on_acl_change = true
                    allow_move_without_traverse = true
                    reveal_users_in_current_and_linked_channels_without_traverse = true
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert!(!cfg.debug_acl_enter());
        assert!(cfg.explicit_enter_deny_overrides_write());
        assert!(!cfg.preserve_write_acl_on_edit());
        assert!(!cfg.grant_temp_channel_creator_acl());
        assert!(cfg.reevaluate_speak_on_acl_change());
        assert!(cfg.allow_move_without_traverse());
        assert!(cfg.reveal_users_in_current_and_linked_channels_without_traverse());

        let cfg = AclConfig::default()
            .with_allow_move_without_traverse(true)
            .with_reveal_users_in_current_and_linked_channels_without_traverse(true);
        assert!(cfg.allow_move_without_traverse());
        assert!(cfg.reveal_users_in_current_and_linked_channels_without_traverse());
    }

    #[test]
    fn privacy_config_defaults_and_parses_protection_modes_and_secret_forms() {
        let default_cfg: PrivacyConfig = ::config::Config::builder()
            .add_source(::config::File::from_str("", ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert!(!default_cfg.protect_certificate_hashes());
        assert_eq!(
            default_cfg.certificate_hash_protection(),
            CertificateHashProtection::Disabled
        );
        assert_eq!(default_cfg.certificate_hash_secret(), None);

        let flat_cfg: PrivacyConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    protect_certificate_hashes = true
                    certificate_hash_secret = "flat-secret"
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert!(flat_cfg.protect_certificate_hashes());
        assert_eq!(
            flat_cfg.certificate_hash_protection(),
            CertificateHashProtection::Irreversible
        );
        assert_eq!(flat_cfg.certificate_hash_secret(), Some("flat-secret"));

        let nested_cfg: PrivacyConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    protect_certificate_hashes = "reversible"

                    [certificate.hash]
                    secret = "nested-secret"
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert!(nested_cfg.protect_certificate_hashes());
        assert_eq!(
            nested_cfg.certificate_hash_protection(),
            CertificateHashProtection::Reversible
        );
        assert_eq!(nested_cfg.certificate_hash_secret(), Some("nested-secret"));

        let irreversible_cfg: PrivacyConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    protect_certificate_hashes = "irreversible"
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert_eq!(
            irreversible_cfg.certificate_hash_protection(),
            CertificateHashProtection::Irreversible
        );
    }

    #[test]
    fn udp_ping_user_count_scope_parses_local() {
        let raw = r#"
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100
            udp_ping_user_count_scope = "local"
        "#;
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert_eq!(cfg.udp_ping_user_count_scope, UdpPingUserCountScope::Local);
    }

    #[test]
    fn required_groups_parse_as_a_set() {
        let raw = r#"
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100
            required_groups = ["member", "admin", "member"]
        "#;
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.required_groups.len(), 2);
        assert!(cfg.required_groups.contains("member"));
        assert!(cfg.required_groups.contains("admin"));
    }

    #[test]
    fn server_entrypoints_parse_port_and_sni_scopes() {
        let raw = r#"
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100

            [[server_entrypoints]]
            server_id = "tenant-a"
            listen = "127.0.0.1:64748"
            udp_ping_status_server_id = "tenant-a-status"
            sni = ["tenant-a.example.test", "TENANT-A-ALT.example.test"]

            [[server_entrypoints]]
            server_id = "tenant-b"
            sni = ["tenant-b.example.test"]
        "#;
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.server_entrypoints.len(), 2);
        assert_eq!(cfg.server_entrypoints[0].server_id, "tenant-a");
        assert_eq!(
            cfg.server_entrypoints[0].listen.as_deref(),
            Some("127.0.0.1:64748")
        );
        assert_eq!(
            cfg.server_entrypoints[0]
                .udp_ping_status_server_id
                .as_deref(),
            Some("tenant-a-status")
        );
        assert_eq!(cfg.server_entrypoints[0].sni.len(), 2);
        assert_eq!(cfg.server_entrypoints[1].server_id, "tenant-b");
        assert!(cfg.server_entrypoints[1].listen.is_none());
        assert!(
            cfg.server_entrypoints[1]
                .udp_ping_status_server_id
                .is_none()
        );
    }

    #[test]
    fn s2s_is_disabled_by_default() {
        let cfg = S2sConfig::default();
        assert!(!cfg.is_enabled());
        assert!(cfg.transport_config().unwrap().is_none());
        assert_eq!(cfg.local_node_id().unwrap(), 0);
    }

    #[test]
    fn s2s_local_node_id_defaults_to_zero_without_cert_path() {
        let cfg = S2sConfig {
            enabled: true,
            ..Default::default()
        };

        assert_eq!(cfg.local_node_id().unwrap(), 0);
    }

    #[test]
    fn s2s_local_node_id_defaults_to_zero_when_cert_file_is_absent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cfg = S2sConfig {
            enabled: true,
            cert_path: Some(temp.path().join("missing-cert.pem")),
            ..Default::default()
        };

        assert_eq!(cfg.local_node_id().unwrap(), 0);
    }

    #[test]
    fn s2s_local_node_id_parses_numeric_cert_cn() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert_path = cert_with_cn(temp.path(), "42");
        let cfg = S2sConfig {
            enabled: true,
            cert_path: Some(cert_path),
            ..Default::default()
        };

        assert_eq!(cfg.local_node_id().unwrap(), 42);
    }

    #[test]
    fn web_config_defaults_to_password_auth() {
        let cfg = WebConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.auth.modes, vec![WebAuthMode::Password]);
        assert!(cfg.auth.password_enabled);
        assert_eq!(cfg.auth.sso.subject_claim, "sub");
        assert_eq!(cfg.webrtc.max_speaker_ssrcs, 64);
        assert!(!cfg.moq.enabled);
        assert_eq!(cfg.moq.max_speaker_tracks, 64);
    }

    #[test]
    fn web_config_parses_ice_and_sso() {
        let raw = r#"
            enabled = true
            listen = "127.0.0.1:64739"
            public_base_url = "https://voice.example.test"
            allowed_origins = ["https://voice.example.test"]

            [auth]
            modes = ["password", "sso"]
            password_enabled = true

            [auth.sso]
            issuer = "https://idp.example.test"
            jwks_url = "https://idp.example.test/jwks"
            audience = "shitspeak"
            subject_claim = "uid"
            username_claim = "name"
            groups_claim = "roles"

            [webrtc]
            max_speaker_ssrcs = 8
            audio_bitrate = 48000
            ice_servers = [
                { urls = ["turn:turn.example.test:3478"], username = "u", credential = "p" },
            ]

            [moq]
            enabled = true
            listen = "127.0.0.1:64740"
            public_url = "https://voice.example.test/web/moq"
            cert_path = "moq-cert.pem"
            key_path = "moq-key.pem"
            max_speaker_tracks = 6
            audio_bitrate = 32000
        "#;
        let cfg: WebConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert!(cfg.enabled);
        assert_eq!(
            cfg.auth.modes,
            vec![WebAuthMode::Password, WebAuthMode::Sso]
        );
        assert_eq!(cfg.auth.sso.subject_claim, "uid");
        assert_eq!(cfg.webrtc.max_speaker_ssrcs, 8);
        assert_eq!(cfg.webrtc.ice_servers[0].username.as_deref(), Some("u"));
        assert!(cfg.moq.enabled);
        assert_eq!(cfg.moq.listen.unwrap().to_string(), "127.0.0.1:64740");
        assert_eq!(
            cfg.moq.public_url.as_deref(),
            Some("https://voice.example.test/web/moq")
        );
        assert_eq!(
            cfg.moq.cert_path.as_deref(),
            Some(Path::new("moq-cert.pem"))
        );
        assert_eq!(cfg.moq.key_path.as_deref(), Some(Path::new("moq-key.pem")));
        assert_eq!(cfg.moq.max_speaker_tracks, 6);
        assert_eq!(cfg.moq.audio_bitrate, 32000);
    }

    #[test]
    fn s2s_enabled_flat_seed_addresses_parse() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dictionary_path = temp.path().join("s2s-transport.zdict");
        let dictionary = b"OverlayData ReplicationMessage StrictCatchupResp channel clients";
        std::fs::write(&dictionary_path, dictionary).expect("write compression dictionary");
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            advertise_private_ips = false
            tcp_listen = "0.0.0.0:64739"
            kcp_listen = "0.0.0.0:64740"
            quic_listen = "0.0.0.0:64741"
            udp_listen = "0.0.0.0:64742"
            tcp_advertise = ["127.0.0.1:64739", "127.0.0.2:64739"]
            kcp_advertise = ["127.0.0.1:64740"]
            quic_advertise = ["127.0.0.1:64741"]
            udp_advertise = ["127.0.0.1:64742"]
            status_http_listen = "0.0.0.0:64750"
            persistence_dir = "s2s-state"

            seed_addresses = [
                { transport = "tcp", addr = "10.0.0.2:64739" },
                { transport = "quic", addr = "localhost:64741" },
                { transport = "udp", addr = "10.0.0.4:64742" },
            ]

            [transport]
            ping_interval_secs = 7
            idle_ping_interval_secs = 19
            native_stats_interval_secs = 11
            stream_write_timeout_ms = 444
            quic_session_setup_timeout_ms = 5555
            quic_datagram_send_buffer_bytes = 32768
            quic_datagram_receive_buffer_bytes = 131072
            recent_probe_retry_cap_secs = 31
            stale_probe_retry_cap_secs = 601
            stale_probe_age_secs = 3601
            unconfirmed_address_retry_floor_secs = 301
            unconfirmed_address_retry_cap_secs = 1801
            unconfirmed_address_decay_failures = 7
            unselected_link_probe_interval_secs = 41
            max_outgoing_connections = 777
            udp_family_min_samples = 9
            udp_family_probe_loss_block_count = 6
            udp_family_block_loss_ppm = 210000
            udp_family_loss_excess_over_tcp_ppm = 45000
            large_rtt_threshold_ms = 130
            lossy_link_threshold_ppm = 17000
            bulk_payload_threshold_bytes = 49152
            bulk_backlog_threshold_bytes = 196608
            transport_switch_improvement_pct = 22
            transport_metric_stale_after_ms = 1555
            compression_enabled = false
            compression_min_bytes = 2048
            compression_min_savings_percent = 25
            compression_level = 3
            compression_adaptive_dictionary_enabled = true
            compression_dictionary_path = '__DICT__'

            [transport.kcp]
            nodelay = true
            interval_ms = 10
            fast_resend = 2
            no_congestion = false
            flush_write = true
            flush_acks_input = true
            failaway_with_alternative_ms = 123
            failaway_without_alternative_ms = 456
            no_progress_close_ms = 789

            [application.voice]
            transport_ttl_ms = 180
            repair_transport_ttl_ms = 300
        "#
        .replace("__DICT__", &dictionary_path.display().to_string());
        let cfg: S2sConfig = parse_s2s(&raw).expect("s2s config parses");
        assert!(cfg.is_enabled());
        assert!(!cfg.advertise_private_ips);
        assert_eq!(cfg.seed_addresses.len(), 3);
        assert_eq!(
            cfg.seed_addresses[0].transport(),
            S2sTransportKindConfig::Tcp
        );
        assert_eq!(
            cfg.seed_addresses[1].transport(),
            S2sTransportKindConfig::Quic
        );
        assert_eq!(
            cfg.seed_addresses[2].transport(),
            S2sTransportKindConfig::Udp
        );
        assert_eq!(cfg.seed_addresses[1].addr(), "localhost:64741");
        assert_eq!(
            cfg.status_http_listen,
            Some("0.0.0.0:64750".parse().unwrap())
        );

        let transport = cfg
            .transport_config_with_max_users(432)
            .expect("valid transport config")
            .expect("s2s enabled");
        assert_eq!(
            transport.tcp_listen_addrs(),
            &["0.0.0.0:64739".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            transport.kcp_listen_addrs(),
            &["0.0.0.0:64740".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            transport.quic_listen_addrs(),
            &["0.0.0.0:64741".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            transport.udp_listen_addrs(),
            &["0.0.0.0:64742".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(transport.seed_address_count(), 3);
        assert_eq!(transport.seed_targets().len(), 3);
        assert_eq!(transport.seed_targets()[1].addr(), "localhost:64741");
        assert_eq!(
            transport.tcp_advertise(),
            &[
                "127.0.0.1:64739".parse::<SocketAddr>().unwrap(),
                "127.0.0.2:64739".parse::<SocketAddr>().unwrap()
            ]
        );
        assert_eq!(
            transport.kcp_advertise(),
            &["127.0.0.1:64740".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            transport.quic_advertise(),
            &["127.0.0.1:64741".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            transport.udp_advertise(),
            &["127.0.0.1:64742".parse::<SocketAddr>().unwrap()]
        );
        assert!(!transport.advertise_private_ips());
        assert_eq!(transport.backoff_cap(), Duration::from_secs(31));
        assert_eq!(transport.stale_backoff_cap(), Duration::from_secs(601));
        assert_eq!(transport.stale_backoff_after(), Duration::from_secs(3601));
        assert_eq!(
            transport.unconfirmed_address_retry_floor(),
            Duration::from_secs(301)
        );
        assert_eq!(
            transport.unconfirmed_address_retry_cap(),
            Duration::from_secs(1801)
        );
        assert_eq!(transport.unconfirmed_address_decay_failures(), 7);
        assert_eq!(
            transport.unselected_link_probe_interval(),
            Duration::from_secs(41)
        );
        assert_eq!(transport.ping_interval(), Duration::from_secs(7));
        assert_eq!(transport.idle_ping_interval(), Duration::from_secs(19));
        assert_eq!(transport.native_stats_interval(), Duration::from_secs(11));
        assert_eq!(transport.stream_write_timeout(), Duration::from_millis(444));
        assert_eq!(
            transport.quic_session_setup_timeout(),
            Duration::from_millis(5_555)
        );
        assert_eq!(transport.quic_datagram_send_buffer_bytes(), 32_768);
        assert_eq!(transport.quic_datagram_receive_buffer_bytes(), 131_072);
        assert_eq!(transport.max_outgoing_connections(), 777);
        let routing_policy = transport.routing_policy();
        assert_eq!(routing_policy.udp_family_min_samples(), 9);
        assert_eq!(routing_policy.udp_family_probe_loss_block_count(), 6);
        assert_eq!(routing_policy.udp_family_block_loss_ppm(), 210_000);
        assert_eq!(routing_policy.udp_family_loss_excess_over_tcp_ppm(), 45_000);
        assert_eq!(routing_policy.large_rtt_threshold_ms(), 130);
        assert_eq!(routing_policy.lossy_link_threshold_ppm(), 17_000);
        assert_eq!(routing_policy.bulk_payload_threshold_bytes(), 49_152);
        assert_eq!(routing_policy.bulk_backlog_threshold_bytes(), 196_608);
        assert_eq!(routing_policy.transport_switch_improvement_pct(), 22);
        assert_eq!(
            routing_policy.transport_metric_stale_after(),
            Duration::from_millis(1555)
        );
        assert_eq!(transport.max_users(), 432);
        assert!(!transport.compression_enabled());
        assert_eq!(transport.compression_min_bytes(), 2048);
        assert_eq!(transport.compression_min_savings_percent(), 25);
        assert_eq!(transport.compression_level(), 3);
        assert!(transport.compression_adaptive_dictionary_enabled());
        let kcp = transport.kcp_tuning();
        assert!(kcp.nodelay());
        assert_eq!(kcp.interval_ms(), 10);
        assert_eq!(kcp.fast_resend(), 2);
        assert!(!kcp.no_congestion());
        assert!(kcp.flush_write());
        assert!(kcp.flush_acks_input());
        assert_eq!(kcp.failaway_with_alternative(), Duration::from_millis(123));
        assert_eq!(
            kcp.failaway_without_alternative(),
            Duration::from_millis(456)
        );
        assert_eq!(kcp.no_progress_close(), Duration::from_millis(789));
        assert_eq!(cfg.application.voice.transport_ttl_ms(), 180);
        assert_eq!(cfg.application.voice.repair_transport_ttl_ms, 300);
        assert_eq!(cfg.application.voice.repair_request_ttl_ms, 300);
        assert_eq!(
            transport.compression_dictionary_len(),
            Some(dictionary.len())
        );
        let overlay = cfg.overlay_config();
        assert!(overlay.persistence_dir().is_some());
        assert_eq!(overlay.transport_routing_policy(), routing_policy);
    }

    #[test]
    fn s2s_transport_loads_adaptive_dictionary_cache_from_persistence_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let persistence_dir = temp.path().join("s2s-state");
        let cache_dir = persistence_dir.join("transport");
        std::fs::create_dir_all(&cache_dir).expect("create adaptive dictionary cache dir");
        let dictionary =
            b"cached adaptive s2s transport zstd dictionary bytes from persistence dir";
        std::fs::write(cache_dir.join("adaptive-compression.zdict"), dictionary)
            .expect("write adaptive dictionary cache");
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "127.0.0.1:64739"
            persistence_dir = '__PERSISTENCE__'

            [transport]
            compression_enabled = true
            compression_adaptive_dictionary_enabled = true
        "#
        .replace("__PERSISTENCE__", &persistence_dir.display().to_string());
        let cfg: S2sConfig = parse_s2s(&raw).expect("s2s config parses");

        let transport = cfg
            .transport_config()
            .expect("valid transport config")
            .expect("s2s enabled");
        assert_eq!(
            transport.compression_cached_adaptive_dictionary_len(),
            Some(dictionary.len())
        );
    }

    #[test]
    fn s2s_overlay_route_transit_messages_parses() {
        let raw = r#"
            enabled = false

            [overlay]
            route_transit_messages = false
        "#;
        let cfg: S2sConfig = parse_s2s(raw).expect("s2s config parses");
        assert!(!cfg.overlay.route_transit_messages);
        assert!(!cfg.overlay_config().route_transit_messages());
    }

    #[test]
    fn s2s_enabled_requires_identity_paths() {
        let cfg = S2sConfig {
            enabled: true,
            ..Default::default()
        };
        let error = cfg.transport_config().unwrap_err();
        assert!(error.contains("ca_path"));
    }

    #[test]
    fn s2s_rejects_undersized_quic_datagram_buffers() {
        for key in [
            "quic_datagram_send_buffer_bytes",
            "quic_datagram_receive_buffer_bytes",
        ] {
            let raw = format!(
                r#"
                    enabled = true
                    ca_path = "s2s-ca.pem"
                    cert_path = "s2s-node.pem"
                    key_path = "s2s-node.key"

                    [transport]
                    {key} = 1199
                "#
            );
            let cfg: S2sConfig = parse_s2s(&raw).expect("s2s config parses");
            let error = cfg.transport_config().unwrap_err();

            assert!(error.contains(key), "error: {error}");
            assert!(error.contains("zero or at least 1200"), "error: {error}");
        }
    }

    #[test]
    fn s2s_rejects_invalid_seed_transport() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            seed_addresses = [
                { transport = "ws", addr = "10.0.0.2:64739" },
            ]
        "#;
        assert!(parse_s2s(raw).is_err());
    }

    #[test]
    fn s2s_listen_fields_accept_scalar_or_array_values() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = ["0.0.0.0:64739", "[::]:64739", "0.0.0.0:64739"]
            kcp_listen = "0.0.0.0:64740"
        "#;
        let cfg = parse_s2s(raw).expect("s2s config parses");
        let transport = cfg
            .transport_config()
            .expect("valid transport config")
            .expect("s2s enabled");

        assert_eq!(
            transport.tcp_listen_addrs(),
            &[
                "0.0.0.0:64739".parse::<SocketAddr>().unwrap(),
                "[::]:64739".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(
            transport.kcp_listen_addrs(),
            &["0.0.0.0:64740".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn s2s_rejects_invalid_seed_address() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            seed_addresses = [
                { transport = "tcp", addr = "not an address" },
            ]
        "#;
        let cfg = parse_s2s(raw).expect("seed address text deserializes");
        assert!(cfg.transport_config().is_err());
    }

    #[test]
    fn s2s_keeps_unresolved_seed_address_for_runtime_retry() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "127.0.0.1:64739"
            seed_addresses = [
                { transport = "tcp", addr = "missing-seed.invalid:64739" },
            ]
        "#;
        let cfg = parse_s2s(raw).expect("seed address text deserializes");
        let transport = cfg
            .transport_config()
            .expect("unresolved seed host does not block transport config")
            .expect("s2s enabled");
        assert_eq!(transport.seed_address_count(), 1);
        assert_eq!(
            transport.seed_targets()[0].addr(),
            "missing-seed.invalid:64739"
        );
    }

    #[test]
    fn s2s_rejects_unspecified_seed_address() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            seed_addresses = [
                { transport = "tcp", addr = "0.0.0.0:64739" },
            ]
        "#;
        let cfg = parse_s2s(raw).expect("seed address text deserializes");
        let err = cfg
            .transport_config()
            .expect_err("unspecified seed address is not dialable");
        assert!(err.contains("must not resolve to an unspecified address"));
    }

    #[test]
    fn s2s_rejects_unspecified_advertise_address() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_advertise = ["0.0.0.0:64739"]
        "#;
        let cfg = parse_s2s(raw).expect("advertise address text deserializes");
        let err = cfg
            .transport_config()
            .expect_err("unspecified advertise address is not dialable");
        assert!(err.contains("must not resolve to an unspecified address"));
    }

    #[test]
    fn s2s_rejects_advertise_address_with_incompatible_listen_family() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
            tcp_advertise = ["[fd00::1]:64739"]
        "#;
        let cfg = parse_s2s(raw).expect("advertise address text deserializes");
        let err = cfg
            .transport_config()
            .expect_err("IPv6 advertise is not reachable through an IPv4 listener");
        assert!(err.contains("compatible with listen addresses"));
    }

    #[test]
    fn s2s_rejects_hostname_advertise_without_routable_addresses() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_advertise = ["localhost:64739"]
        "#;
        let cfg = parse_s2s(raw).expect("advertise hostname text deserializes");
        let err = cfg
            .transport_config()
            .expect_err("hostname advertise must resolve to routable addresses");
        assert!(err.contains("did not resolve to any routable advertise addresses"));
    }

    #[test]
    fn s2s_dns_advertise_filter_allows_private_network_addresses() {
        assert!(is_routable_advertise_ip("10.182.157.4".parse().unwrap()));
        assert!(is_routable_advertise_ip("fd00::1".parse().unwrap()));
        assert!(!is_routable_advertise_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_routable_advertise_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn s2s_advertise_resolution_keeps_only_listener_ip_family() {
        let addrs = vec![
            "172.23.0.15:64740".parse::<SocketAddr>().unwrap(),
            "[fd31:8224:7cf6:5::f]:64740".parse::<SocketAddr>().unwrap(),
        ];
        let filtered = filter_advertise_addrs_for_listen(
            "s2s.kcp_advertise",
            "node-2:64740",
            addrs,
            &["0.0.0.0:64740".parse().unwrap()],
        )
        .expect("one resolved address matches the IPv4 listener");

        assert_eq!(
            filtered,
            vec!["172.23.0.15:64740".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn s2s_advertise_resolution_treats_unspecified_ipv6_listen_as_dual_stack() {
        let addrs = vec![
            "172.23.0.7:64739".parse::<SocketAddr>().unwrap(),
            "[fd31:8224:7cf6:5::7]:64739".parse::<SocketAddr>().unwrap(),
        ];
        let filtered = filter_advertise_addrs_for_listen(
            "s2s.tcp_advertise",
            "node-1:64739",
            addrs.clone(),
            &["[::]:64739".parse().unwrap()],
        )
        .expect("[::] listener can accept both resolved families in the verified Docker setup");

        assert_eq!(filtered, addrs);
    }

    #[test]
    fn s2s_blank_scalar_advertise_is_treated_as_no_override() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
            tcp_advertise = ""
        "#;
        let cfg = parse_s2s(raw).expect("blank legacy advertise string deserializes");
        let transport = cfg
            .transport_config()
            .expect("blank advertise is ignored")
            .expect("s2s enabled");
        assert!(transport.tcp_advertise().is_empty());
    }

    #[test]
    fn s2s_auto_advertise_host_is_used_when_no_override_is_set() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
        "#;
        let cfg = parse_s2s(raw).expect("s2s config parses");
        let transport = cfg
            .transport_config_with_auto_advertise_host(Some("8.8.8.8"))
            .expect("auto advertise host resolves")
            .expect("s2s enabled");
        assert_eq!(
            transport.tcp_advertise(),
            &["8.8.8.8:64739".parse::<SocketAddr>().unwrap()]
        );
        assert!(!transport.tcp_advertise_override());
    }

    #[test]
    fn s2s_auto_advertise_host_ignores_unroutable_hostname() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
        "#;
        let cfg = parse_s2s(raw).expect("s2s config parses");
        let transport = cfg
            .transport_config_with_auto_advertise_host(Some("localhost"))
            .expect("unroutable implicit advertise hostname is ignored")
            .expect("s2s enabled");

        assert!(transport.tcp_advertise().is_empty());
        assert!(!transport.tcp_advertise_override());
        assert_eq!(transport.implicit_advertise_failures().len(), 1);
        assert!(
            transport.implicit_advertise_failures()[0]
                .contains("did not resolve to any routable advertise addresses")
        );
    }

    #[test]
    fn s2s_auto_advertise_host_ignores_literal_loopback() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
        "#;
        let cfg = parse_s2s(raw).expect("s2s config parses");
        let transport = cfg
            .transport_config_with_auto_advertise_host(Some("127.0.0.1"))
            .expect("literal loopback implicit advertise host is ignored")
            .expect("s2s enabled");

        assert!(transport.tcp_advertise().is_empty());
        assert!(!transport.tcp_advertise_override());
        assert_eq!(transport.implicit_advertise_failures().len(), 1);
    }

    #[test]
    fn s2s_advertise_private_ips_defaults_to_true() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
        "#;
        let cfg = parse_s2s(raw).expect("s2s config parses");
        let transport = cfg
            .transport_config()
            .expect("valid transport config")
            .expect("s2s enabled");

        assert!(cfg.advertise_private_ips);
        assert!(transport.advertise_private_ips());
    }

    #[test]
    fn s2s_local_interface_advertise_parses_and_propagates() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            local_interface_advertise = ["tailscale0", "Tailscale", " "]
        "#;
        let cfg = parse_s2s(raw).expect("s2s config parses");
        assert_eq!(
            cfg.local_interface_advertise,
            vec!["tailscale0".to_string(), "Tailscale".to_string()]
        );

        let transport = cfg
            .transport_config()
            .expect("valid transport config")
            .expect("s2s enabled");
        assert_eq!(
            transport
                .local_advertise_interfaces()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["tailscale0", "Tailscale"]
        );
    }
}
