//! JSON persistence for the runtime peer set.
//!
//! On every membership change, the overlay debounces a write to
//! `<persistence_dir>/overlay/peers.json`. On startup, the file (if present)
//! is loaded and used as a second source of seed addresses (in addition to
//! `OverlayConfig::seed_peers`). Each tuple `(node_id, [PeerAddress])` lets
//! the transport supervisor dial the peer immediately.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::s2s::transport::{PeerAddress, TransportKind};
use crate::types::NodeIdentifier;

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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct PersistedAddress {
    /// SocketAddr text form (e.g., "127.0.0.1:9000" or "[::1]:9000").
    pub addr: String,
    pub transport: PersistedTransport,
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

/// Compute the on-disk path for the peers file given a persistence dir.
pub fn peers_file(persistence_dir: &Path) -> PathBuf {
    persistence_dir.join(SUBDIR).join(FILE_NAME)
}

/// Load the saved peers file. Returns an empty vec if the file is absent;
/// errors only on I/O or parse problems.
pub fn load(persistence_dir: &Path) -> Result<Vec<(NodeIdentifier, Vec<PeerAddress>)>, OverlayError> {
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
    let mut out = Vec::with_capacity(parsed.peers.len());
    for p in parsed.peers {
        let mut addrs = Vec::with_capacity(p.addresses.len());
        for a in p.addresses {
            let Ok(sa) = a.addr.parse::<SocketAddr>() else { continue };
            addrs.push(PeerAddress::new(sa, a.transport.into()));
        }
        out.push((p.node_id, addrs));
    }
    Ok(out)
}

/// Atomically write the peers file: serialize to a temp file then rename.
pub fn save(
    persistence_dir: &Path,
    peers: &[(NodeIdentifier, Vec<PeerAddress>)],
) -> Result<(), OverlayError> {
    let dir = persistence_dir.join(SUBDIR);
    fs::create_dir_all(&dir).map_err(|source| OverlayError::Persistence {
        path: dir.clone(),
        source,
    })?;
    let final_path = dir.join(FILE_NAME);
    let tmp_path = dir.join(format!("{FILE_NAME}.tmp"));

    let payload = PersistedPeers {
        version: SCHEMA_VERSION,
        peers: peers
            .iter()
            .map(|(node, addrs)| PersistedPeer {
                node_id: *node,
                addresses: addrs
                    .iter()
                    .map(|a| PersistedAddress {
                        addr: a.addr().to_string(),
                        transport: a.transport().into(),
                    })
                    .collect(),
            })
            .collect(),
    };

    let bytes = serde_json::to_vec_pretty(&payload).map_err(|source| {
        OverlayError::PersistenceParse {
            path: final_path.clone(),
            source,
        }
    })?;

    {
        let mut f = fs::File::create(&tmp_path).map_err(|source| OverlayError::Persistence {
            path: tmp_path.clone(),
            source,
        })?;
        f.write_all(&bytes).map_err(|source| OverlayError::Persistence {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip() {
        let dir = TempDir::new().unwrap();
        let peers = vec![
            (
                7u16,
                vec![PeerAddress::new(
                    "127.0.0.1:1234".parse().unwrap(),
                    TransportKind::Tcp,
                )],
            ),
            (
                42u16,
                vec![
                    PeerAddress::new(
                        "10.0.0.1:9000".parse().unwrap(),
                        TransportKind::Quic,
                    ),
                    PeerAddress::new(
                        "10.0.0.1:9001".parse().unwrap(),
                        TransportKind::Udp,
                    ),
                ],
            ),
        ];
        save(dir.path(), &peers).unwrap();
        let loaded = load(dir.path()).unwrap();
        // Order isn't guaranteed by the serializer, sort to compare.
        let mut expected = peers.clone();
        let mut actual = loaded.clone();
        expected.sort_by_key(|(n, _)| *n);
        actual.sort_by_key(|(n, _)| *n);
        assert_eq!(expected, actual);
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
