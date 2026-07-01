use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use bytes::Bytes;
use rand::RngExt;

use crate::config::{Config, ServerEntrypointConfig};

pub(super) type UdpPacket = (Bytes, std::net::SocketAddr, std::net::SocketAddr);

const DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS: usize = 128;
pub(super) const DYNAMIC_ENTRYPOINT_MIN_PORT: u16 = 49152;
pub(super) const DYNAMIC_ENTRYPOINT_MAX_PORT: u16 = 65535;

#[derive(Clone)]
pub(super) struct ServerTcpListener {
    pub(super) listener: Arc<tokio::net::TcpListener>,
}

pub(super) struct EntrypointBindings {
    pub(super) default_port: u16,
    pub(super) tcp_listeners: Vec<ServerTcpListener>,
    pub(super) udp_sockets: Vec<Arc<tokio::net::UdpSocket>>,
    pub(super) udp_socket_by_port: HashMap<u16, Arc<tokio::net::UdpSocket>>,
    pub(super) server_id_by_port: HashMap<u16, String>,
    pub(super) udp_ping_status_server_id_by_port: HashMap<u16, String>,
    pub(super) server_id_by_sni: HashMap<String, String>,
}

#[derive(Clone)]
pub(super) struct EntrypointRuntime {
    pub(super) udp_in: tokio::sync::mpsc::Sender<UdpPacket>,
    pub(super) udp_voice_enabled: bool,
    pub(super) udp_ping_enabled: bool,
    pub(super) shutdown: tokio::sync::watch::Receiver<()>,
}

fn first_socket_addr(address: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    address.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid listen address: {address}"),
        )
        .into()
    })
}

pub(super) async fn bind_entrypoint_socket_pair(
    address: SocketAddr,
) -> Result<(tokio::net::TcpListener, Arc<tokio::net::UdpSocket>), Box<dyn std::error::Error>> {
    if address.port() != 0 {
        return bind_entrypoint_socket_pair_once(address).await;
    }

    let mut last_bind_error = None;
    for attempt in 1..=DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS {
        let candidate = dynamic_entrypoint_bind_candidate(address, attempt);
        let udp_socket = match tokio::net::UdpSocket::bind(candidate).await {
            Ok(socket) => socket,
            Err(err) if dynamic_bind_error_is_retryable(&err) => {
                tracing::debug!(
                    attempt,
                    attempts = DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS,
                    %candidate,
                    error = ?err,
                    "entrypoint UDP candidate is unavailable; retrying entrypoint bind"
                );
                last_bind_error = Some(err);
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        let bound_address = udp_socket.local_addr()?;
        match tokio::net::TcpListener::bind(bound_address).await {
            Ok(tcp_listener) => return Ok((tcp_listener, Arc::new(udp_socket))),
            Err(err) if dynamic_bind_error_is_retryable(&err) => {
                tracing::debug!(
                    attempt,
                    attempts = DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS,
                    %bound_address,
                    error = ?err,
                    "ephemeral UDP port's TCP address is unavailable; retrying entrypoint bind"
                );
                last_bind_error = Some(err);
            }
            Err(err) => return Err(err.into()),
        }
    }

    let detail = last_bind_error
        .map(|err| err.to_string())
        .unwrap_or_else(|| "no retryable bind error was recorded".to_owned());
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!(
            "failed to bind a TCP/UDP entrypoint pair for {address} after {DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS} attempts: {detail}"
        ),
    )
    .into())
}

pub(super) fn dynamic_entrypoint_bind_candidate(address: SocketAddr, attempt: usize) -> SocketAddr {
    if attempt == 1 {
        return address;
    }
    SocketAddr::new(
        address.ip(),
        rand::rng().random_range(DYNAMIC_ENTRYPOINT_MIN_PORT..=DYNAMIC_ENTRYPOINT_MAX_PORT),
    )
}

pub(super) fn dynamic_bind_error_is_retryable(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
    )
}

async fn bind_entrypoint_socket_pair_once(
    address: SocketAddr,
) -> Result<(tokio::net::TcpListener, Arc<tokio::net::UdpSocket>), Box<dyn std::error::Error>> {
    let tcp_listener = tokio::net::TcpListener::bind(address).await?;
    let bound_address = tcp_listener.local_addr()?;
    let udp_socket = Arc::new(tokio::net::UdpSocket::bind(bound_address).await?);
    Ok((tcp_listener, udp_socket))
}

#[derive(Debug, Clone)]
pub(super) struct EntrypointListenSpec {
    pub(super) address: SocketAddr,
    pub(super) server_id: String,
    pub(super) udp_ping_status_server_id: String,
}

pub(super) fn normalize_sni_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

pub(super) async fn bind_entrypoints(
    config: &Config,
) -> Result<EntrypointBindings, Box<dyn std::error::Error>> {
    let mut tcp_listeners = Vec::new();
    let mut udp_sockets = Vec::new();
    let mut udp_socket_by_port = HashMap::new();
    let mut server_id_by_port = HashMap::new();
    let mut udp_ping_status_server_id_by_port = HashMap::new();

    let (server_id_by_sni, listen_specs) = entrypoint_config_routes(config)?;

    let listen_address = first_socket_addr(&config.listen)?;
    let (listener, udp_socket) = bind_entrypoint_socket_pair(listen_address).await?;
    let default_port = listener.local_addr()?.port();
    udp_socket_by_port.insert(default_port, Arc::clone(&udp_socket));
    udp_sockets.push(udp_socket);
    tcp_listeners.push(ServerTcpListener {
        listener: Arc::new(listener),
    });

    for spec in listen_specs {
        let EntrypointListenSpec {
            address,
            server_id,
            udp_ping_status_server_id,
        } = spec;
        let (listener, udp_socket) = bind_entrypoint_socket_pair(address).await?;
        let port = listener.local_addr()?.port();
        if port == default_port {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("server entrypoint for {server_id} reuses the default TCP/UDP port {port}"),
            )
            .into());
        }
        if let Some(existing) = server_id_by_port.insert(port, server_id.clone()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "multiple server entrypoints bind TCP/UDP port {port}: {existing} and {server_id}"
                ),
            )
            .into());
        }
        udp_ping_status_server_id_by_port.insert(port, udp_ping_status_server_id);
        udp_socket_by_port.insert(port, Arc::clone(&udp_socket));
        udp_sockets.push(udp_socket);
        tcp_listeners.push(ServerTcpListener {
            listener: Arc::new(listener),
        });
    }

    Ok(EntrypointBindings {
        default_port,
        tcp_listeners,
        udp_sockets,
        udp_socket_by_port,
        server_id_by_port,
        udp_ping_status_server_id_by_port,
        server_id_by_sni,
    })
}

pub(super) fn register_sni_entrypoints(
    server_id_by_sni: &mut HashMap<String, String>,
    entrypoint: &ServerEntrypointConfig,
    server_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for sni in &entrypoint.sni {
        let sni = normalize_sni_name(sni);
        if sni.is_empty() {
            continue;
        }
        if let Some(existing) = server_id_by_sni.insert(sni.clone(), server_id.to_owned()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SNI name {sni} is mapped to both {existing} and {server_id}"),
            )
            .into());
        }
    }
    Ok(())
}

pub(super) fn entrypoint_config_routes(
    config: &Config,
) -> Result<(HashMap<String, String>, Vec<EntrypointListenSpec>), Box<dyn std::error::Error>> {
    let mut server_id_by_sni = HashMap::new();
    let mut listen_specs = Vec::new();
    let mut fixed_port_owners: HashMap<u16, String> = HashMap::new();

    for entrypoint in &config.server_entrypoints {
        let server_id = entrypoint.server_id.trim();
        if server_id.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_entrypoints entries require non-empty server_id",
            )
            .into());
        }

        register_sni_entrypoints(&mut server_id_by_sni, entrypoint, server_id)?;

        let Some(listen) = entrypoint.listen.as_deref() else {
            continue;
        };
        let udp_ping_status_server_id = entrypoint
            .udp_ping_status_server_id
            .as_deref()
            .map(str::trim)
            .unwrap_or(server_id);
        if udp_ping_status_server_id.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("server entrypoint for {server_id} has empty udp_ping_status_server_id"),
            )
            .into());
        }
        let address = first_socket_addr(listen)?;
        if address.port() != 0 {
            if let Some(existing) = fixed_port_owners.insert(address.port(), server_id.to_owned()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "multiple server entrypoints bind TCP/UDP port {}: {} and {}",
                        address.port(),
                        existing,
                        server_id
                    ),
                )
                .into());
            }
        }
        listen_specs.push(EntrypointListenSpec {
            address,
            server_id: server_id.to_owned(),
            udp_ping_status_server_id: udp_ping_status_server_id.to_owned(),
        });
    }

    Ok((server_id_by_sni, listen_specs))
}
