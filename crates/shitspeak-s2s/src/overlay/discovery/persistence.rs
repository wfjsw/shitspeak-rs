//! JSON persistence for the runtime peer set.
//!
//! On every accepted LSA, the overlay debounces a write to
//! `<persistence_dir>/overlay/peers.json`. On startup, the file (if present)
//! is loaded and used as a second source of seed addresses (in addition to
//! `OverlayConfig::seed_peers`). Each entry lets the transport supervisor
//! dial the peer immediately while preserving a wall-clock `last_seen` and
//! per-address retry backoff so old peers are probed less aggressively than
//! freshly seen peers and restart does not reset failed-address timers.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{AddressBackoffSnapshot, PeerAddress, TransportKind};

use super::super::error::OverlayError;

const SCHEMA_VERSION: u32 = 1;
const SUBDIR: &str = "overlay";
const FILE_NAME: &str = "peers.json";

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PersistedPeers {
    pub version: u32,
    pub peers: Vec<PersistedPeer>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PersistedPeer {
    pub node_id: u16,
    pub addresses: Vec<PersistedAddress>,
    #[serde(default)]
    pub last_seen_unix_ms: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct PersistedAddress {
    /// SocketAddr text form (e.g., "127.0.0.1:9000" or "[::1]:9000").
    pub addr: String,
    pub transport: PersistedTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backoff: Option<PersistedAddressBackoff>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PersistedAddressBackoff {
    retry_delay_ms: u64,
    next_delay_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_after_unix_ms: Option<u64>,
    consecutive_failures: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PersistedTransport {
    Tcp,
    Kcp,
    Quic,
    Udp,
}

impl From<TransportKind> for PersistedTransport {
    fn from(v: TransportKind) -> Self {
        match v {
            TransportKind::Tcp => Self::Tcp,
            TransportKind::Kcp => Self::Kcp,
            TransportKind::Quic => Self::Quic,
            TransportKind::Udp => Self::Udp,
        }
    }
}

impl From<PersistedTransport> for TransportKind {
    fn from(v: PersistedTransport) -> Self {
        match v {
            PersistedTransport::Tcp => TransportKind::Tcp,
            PersistedTransport::Kcp => TransportKind::Kcp,
            PersistedTransport::Quic => TransportKind::Quic,
            PersistedTransport::Udp => TransportKind::Udp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistedPeerRecord {
    node_id: NodeIdentifier,
    addresses: Vec<PeerAddress>,
    address_backoffs: HashMap<PeerAddress, AddressBackoffSnapshot>,
    last_seen: Option<SystemTime>,
}

impl PersistedPeerRecord {
    #[cfg(test)]
    pub(crate) fn new(
        node_id: NodeIdentifier,
        addresses: Vec<PeerAddress>,
        last_seen: Option<SystemTime>,
    ) -> Self {
        Self {
            node_id,
            addresses,
            address_backoffs: HashMap::new(),
            last_seen,
        }
    }

    pub(crate) fn new_with_address_backoffs(
        node_id: NodeIdentifier,
        addresses: Vec<PeerAddress>,
        address_backoffs: HashMap<PeerAddress, AddressBackoffSnapshot>,
        last_seen: Option<SystemTime>,
    ) -> Self {
        Self {
            node_id,
            addresses,
            address_backoffs,
            last_seen,
        }
    }

    pub(crate) fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub(crate) fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }

    pub(crate) fn address_backoff(&self, addr: PeerAddress) -> Option<AddressBackoffSnapshot> {
        self.address_backoffs.get(&addr).copied()
    }

    pub(crate) fn last_seen(&self) -> Option<SystemTime> {
        self.last_seen
    }
}

/// Compute the on-disk path for the peers file given a persistence dir.
pub fn peers_file(persistence_dir: &Path) -> PathBuf {
    persistence_dir.join(SUBDIR).join(FILE_NAME)
}

/// Load the saved peers file. Returns an empty vec if the file is absent;
/// errors only on I/O or parse problems.
pub fn load(persistence_dir: &Path) -> Result<Vec<PersistedPeerRecord>, OverlayError> {
    let path = peers_file(persistence_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).map_err(|source| OverlayError::Persistence {
        path: path.clone(),
        source,
    })?;
    let parsed: PersistedPeers =
        serde_json::from_slice(&bytes).map_err(|source| OverlayError::PersistenceParse {
            path: path.clone(),
            source,
        })?;
    if parsed.version != SCHEMA_VERSION {
        // Forward-incompat. Treat as missing and let normal seed flow run.
        tracing::warn!(
            file = %path.display(),
            version = parsed.version,
            expected = SCHEMA_VERSION,
            "overlay peers file has unexpected schema version; ignoring"
        );
        return Ok(Vec::new());
    }
    let address_peer_counts = parsed_address_peer_counts(&parsed.peers);
    let mut out = Vec::with_capacity(parsed.peers.len());
    let mut dropped_addresses = 0usize;
    let mut dropped_ambiguous_addresses = 0usize;
    let mut dropped_peers = 0usize;
    for p in parsed.peers {
        let mut addrs = Vec::with_capacity(p.addresses.len());
        let mut backoffs = HashMap::new();
        for a in p.addresses {
            let Ok(sa) = a.addr.parse::<SocketAddr>() else {
                dropped_addresses += 1;
                continue;
            };
            let addr = PeerAddress::new(sa, a.transport.into());
            if !persisted_address_is_usable(addr) || addrs.contains(&addr) {
                dropped_addresses += 1;
                continue;
            }
            if address_peer_counts
                .get(&addr)
                .is_some_and(|count| *count > 1)
            {
                dropped_ambiguous_addresses += 1;
                continue;
            }
            if let Some(backoff) = a.backoff.map(address_backoff_from_persisted) {
                backoffs.insert(addr, backoff);
            }
            addrs.push(addr);
        }
        if addrs.is_empty() {
            dropped_peers += 1;
            continue;
        }
        out.push(PersistedPeerRecord::new_with_address_backoffs(
            p.node_id,
            addrs,
            backoffs,
            p.last_seen_unix_ms.map(system_time_from_unix_ms),
        ));
    }
    if dropped_addresses > 0 || dropped_ambiguous_addresses > 0 || dropped_peers > 0 {
        tracing::warn!(
            file = %path.display(),
            dropped_addresses,
            dropped_ambiguous_addresses,
            dropped_peers,
            "cleaned invalid addresses from persisted overlay peers"
        );
        if let Err(e) = save(persistence_dir, &out) {
            tracing::warn!(
                file = %path.display(),
                error = %e,
                "failed to rewrite cleaned persisted overlay peers"
            );
        }
    }
    Ok(out)
}

/// Atomically write the peers file: serialize to a temp file then rename.
pub fn save(persistence_dir: &Path, peers: &[PersistedPeerRecord]) -> Result<(), OverlayError> {
    let dir = persistence_dir.join(SUBDIR);
    fs::create_dir_all(&dir).map_err(|source| OverlayError::Persistence {
        path: dir.clone(),
        source,
    })?;
    let final_path = dir.join(FILE_NAME);
    let tmp_path = dir.join(format!("{FILE_NAME}.tmp"));
    let address_peer_counts = record_address_peer_counts(peers);

    let payload = PersistedPeers {
        version: SCHEMA_VERSION,
        peers: peers
            .iter()
            .filter_map(|peer| {
                let addresses: Vec<_> = peer
                    .addresses
                    .iter()
                    .filter(|addr| {
                        address_peer_counts
                            .get(addr)
                            .is_none_or(|count| *count <= 1)
                    })
                    .map(|a| PersistedAddress {
                        addr: a.addr().to_string(),
                        transport: a.transport().into(),
                        backoff: peer
                            .address_backoffs
                            .get(a)
                            .copied()
                            .map(persisted_address_backoff_from_snapshot),
                    })
                    .collect();
                (!addresses.is_empty()).then(|| PersistedPeer {
                    node_id: peer.node_id,
                    addresses,
                    last_seen_unix_ms: peer.last_seen.and_then(unix_ms_from_system_time),
                })
            })
            .collect(),
    };

    let bytes =
        serde_json::to_vec_pretty(&payload).map_err(|source| OverlayError::PersistenceParse {
            path: final_path.clone(),
            source,
        })?;

    {
        let mut f = fs::File::create(&tmp_path).map_err(|source| OverlayError::Persistence {
            path: tmp_path.clone(),
            source,
        })?;
        f.write_all(&bytes)
            .map_err(|source| OverlayError::Persistence {
                path: tmp_path.clone(),
                source,
            })?;
        f.sync_all().map_err(|source| OverlayError::Persistence {
            path: tmp_path.clone(),
            source,
        })?;
    }
    fs::rename(&tmp_path, &final_path).map_err(|source| OverlayError::Persistence {
        path: final_path.clone(),
        source,
    })?;
    Ok(())
}

fn system_time_from_unix_ms(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

fn unix_ms_from_system_time(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn millis_from_duration(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn persisted_address_backoff_from_snapshot(
    value: AddressBackoffSnapshot,
) -> PersistedAddressBackoff {
    PersistedAddressBackoff {
        retry_delay_ms: millis_from_duration(value.retry_delay()),
        next_delay_ms: millis_from_duration(value.next_delay()),
        retry_after_unix_ms: value.retry_after().and_then(unix_ms_from_system_time),
        consecutive_failures: value.consecutive_failures(),
    }
}

fn address_backoff_from_persisted(value: PersistedAddressBackoff) -> AddressBackoffSnapshot {
    AddressBackoffSnapshot::new(
        Duration::from_millis(value.retry_delay_ms),
        Duration::from_millis(value.next_delay_ms),
        value.retry_after_unix_ms.map(system_time_from_unix_ms),
        value.consecutive_failures,
    )
}

fn persisted_address_is_usable(addr: PeerAddress) -> bool {
    let socket = addr.addr();
    socket.port() != 0 && persisted_ip_is_usable(socket.ip())
}

fn persisted_ip_is_usable(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast()
}

fn parsed_address_peer_counts(peers: &[PersistedPeer]) -> HashMap<PeerAddress, usize> {
    let mut counts = HashMap::new();
    for peer in peers {
        let mut seen_for_peer = HashSet::new();
        for addr in &peer.addresses {
            let Ok(socket) = addr.addr.parse::<SocketAddr>() else {
                continue;
            };
            let peer_addr = PeerAddress::new(socket, addr.transport.into());
            if persisted_address_is_usable(peer_addr) && seen_for_peer.insert(peer_addr) {
                *counts.entry(peer_addr).or_insert(0) += 1;
            }
        }
    }
    counts
}

fn record_address_peer_counts(peers: &[PersistedPeerRecord]) -> HashMap<PeerAddress, usize> {
    let mut counts = HashMap::new();
    for peer in peers {
        let mut seen_for_peer = HashSet::new();
        for addr in &peer.addresses {
            if seen_for_peer.insert(*addr) {
                *counts.entry(*addr).or_insert(0) += 1;
            }
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip() {
        let dir = TempDir::new().unwrap();
        let seen = UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
        let peers = vec![
            PersistedPeerRecord::new(
                7u16,
                vec![PeerAddress::new(
                    "127.0.0.1:1234".parse().unwrap(),
                    TransportKind::Tcp,
                )],
                Some(seen),
            ),
            PersistedPeerRecord::new(
                42u16,
                vec![
                    PeerAddress::new("10.0.0.1:9000".parse().unwrap(), TransportKind::Quic),
                    PeerAddress::new("10.0.0.1:9001".parse().unwrap(), TransportKind::Udp),
                ],
                None,
            ),
        ];
        save(dir.path(), &peers).unwrap();
        let loaded = load(dir.path()).unwrap();
        // Order isn't guaranteed by the serializer, sort to compare.
        let mut expected = peers.clone();
        let mut actual = loaded.clone();
        expected.sort_by_key(|peer| peer.node_id());
        actual.sort_by_key(|peer| peer.node_id());
        assert_eq!(expected, actual);
    }

    #[test]
    fn roundtrip_preserves_address_backoff_state() {
        let dir = TempDir::new().unwrap();
        let addr = PeerAddress::new("10.0.0.7:64739".parse().unwrap(), TransportKind::Tcp);
        let retry_after = UNIX_EPOCH + Duration::from_millis(1_700_000_005_000);
        let backoff = AddressBackoffSnapshot::new(
            Duration::from_millis(750),
            Duration::from_secs(2),
            Some(retry_after),
            3,
        );
        let peers = vec![PersistedPeerRecord::new_with_address_backoffs(
            7,
            vec![addr],
            HashMap::from([(addr, backoff)]),
            Some(UNIX_EPOCH + Duration::from_millis(1_700_000_000_123)),
        )];

        save(dir.path(), &peers).unwrap();

        let written: PersistedPeers =
            serde_json::from_slice(&fs::read(peers_file(dir.path())).unwrap())
                .expect("persisted peers json");
        let persisted_backoff = written.peers[0].addresses[0]
            .backoff
            .expect("persisted address backoff");
        assert_eq!(persisted_backoff.retry_delay_ms, 750);
        assert_eq!(persisted_backoff.next_delay_ms, 2_000);
        assert_eq!(
            persisted_backoff.retry_after_unix_ms,
            Some(1_700_000_005_000)
        );
        assert_eq!(persisted_backoff.consecutive_failures, 3);

        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded, peers);
    }

    #[test]
    fn load_removes_invalid_addresses_from_disk() {
        let dir = TempDir::new().unwrap();
        let overlay_dir = dir.path().join(SUBDIR);
        fs::create_dir_all(&overlay_dir).unwrap();
        let path = overlay_dir.join(FILE_NAME);
        fs::write(
            &path,
            r#"{
  "version": 1,
  "peers": [
    {
      "node_id": 7,
      "addresses": [
        { "addr": "0.0.0.0:64739", "transport": "tcp" },
        { "addr": "224.0.0.1:64739", "transport": "tcp" },
        { "addr": "10.0.0.1:0", "transport": "tcp" },
        { "addr": "not an address", "transport": "tcp" },
        { "addr": "10.0.0.1:64739", "transport": "tcp" },
        { "addr": "10.0.0.1:64739", "transport": "tcp" }
      ],
      "last_seen_unix_ms": 1700000000123
    },
    {
      "node_id": 8,
      "addresses": [
        { "addr": "[::]:64739", "transport": "quic" }
      ]
    }
  ]
}"#,
        )
        .unwrap();

        let loaded = load(dir.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].node_id(), 7);
        assert_eq!(
            loaded[0].addresses(),
            &[PeerAddress::new(
                "10.0.0.1:64739".parse().unwrap(),
                TransportKind::Tcp
            )]
        );

        let cleaned: PersistedPeers =
            serde_json::from_slice(&fs::read(path).unwrap()).expect("cleaned peers json");
        assert_eq!(cleaned.peers.len(), 1);
        assert_eq!(cleaned.peers[0].node_id, 7);
        assert_eq!(cleaned.peers[0].addresses.len(), 1);
        assert_eq!(cleaned.peers[0].addresses[0].addr, "10.0.0.1:64739");
    }

    #[test]
    fn load_removes_addresses_shared_by_multiple_peer_ids() {
        let dir = TempDir::new().unwrap();
        let overlay_dir = dir.path().join(SUBDIR);
        fs::create_dir_all(&overlay_dir).unwrap();
        let path = overlay_dir.join(FILE_NAME);
        fs::write(
            &path,
            r#"{
  "version": 1,
  "peers": [
    {
      "node_id": 7,
      "addresses": [
        { "addr": "10.0.0.1:64739", "transport": "tcp" },
        { "addr": "10.0.0.7:64739", "transport": "tcp" }
      ]
    },
    {
      "node_id": 8,
      "addresses": [
        { "addr": "10.0.0.1:64739", "transport": "tcp" },
        { "addr": "10.0.0.8:64739", "transport": "tcp" }
      ]
    },
    {
      "node_id": 9,
      "addresses": [
        { "addr": "10.0.0.1:64739", "transport": "tcp" }
      ]
    }
  ]
}"#,
        )
        .unwrap();

        let loaded = load(dir.path()).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].node_id(), 7);
        assert_eq!(
            loaded[0].addresses(),
            &[PeerAddress::new(
                "10.0.0.7:64739".parse().unwrap(),
                TransportKind::Tcp
            )]
        );
        assert_eq!(loaded[1].node_id(), 8);
        assert_eq!(
            loaded[1].addresses(),
            &[PeerAddress::new(
                "10.0.0.8:64739".parse().unwrap(),
                TransportKind::Tcp
            )]
        );

        let cleaned: PersistedPeers =
            serde_json::from_slice(&fs::read(path).unwrap()).expect("cleaned peers json");
        assert_eq!(cleaned.peers.len(), 2);
        assert!(
            cleaned
                .peers
                .iter()
                .all(|peer| peer.addresses.iter().all(|a| a.addr != "10.0.0.1:64739"))
        );
    }

    #[test]
    fn save_skips_addresses_shared_by_multiple_peer_ids() {
        let dir = TempDir::new().unwrap();
        let shared = PeerAddress::new("10.0.0.1:64739".parse().unwrap(), TransportKind::Tcp);
        let peers = vec![
            PersistedPeerRecord::new(
                7,
                vec![
                    shared,
                    PeerAddress::new("10.0.0.7:64739".parse().unwrap(), TransportKind::Tcp),
                ],
                None,
            ),
            PersistedPeerRecord::new(
                8,
                vec![
                    shared,
                    PeerAddress::new("10.0.0.8:64739".parse().unwrap(), TransportKind::Tcp),
                ],
                None,
            ),
        ];

        save(dir.path(), &peers).unwrap();

        let written: PersistedPeers =
            serde_json::from_slice(&fs::read(peers_file(dir.path())).unwrap())
                .expect("persisted peers json");
        assert_eq!(written.peers.len(), 2);
        assert!(
            written
                .peers
                .iter()
                .all(|peer| peer.addresses.iter().all(|a| a.addr != "10.0.0.1:64739"))
        );
    }

    #[test]
    fn missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let loaded = load(dir.path()).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn future_schema_ignored_with_warning() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(SUBDIR);
        fs::create_dir_all(&path).unwrap();
        let bad = r#"{"version":99,"peers":[]}"#;
        fs::write(path.join(FILE_NAME), bad).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert!(loaded.is_empty());
    }
}
