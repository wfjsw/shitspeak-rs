//! `BanRepository` — versioned, SQLite-backed ban list store.
//!
//! Uses a single SQLite database file (`bans.db`) for both storage and
//! the operation log.  No separate WAL or snapshot files are needed.
//!
//! * `bans` table — current ban entries with indexed IP lookups.
//! * `ban_operations` table — append-only operation log for S2S replication.
//!
//! The public interface is unchanged from the previous in-memory implementation.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::broadcast;

// ─── Ban entry ───────────────────────────────────────────────────────────────

/// A single ban entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanEntry {
    /// IP address (IPv4 or IPv6).
    #[serde(with = "ip_addr_string")]
    pub address: IpAddr,
    /// CIDR prefix length (mask).  32 for single IPv4, 128 for single IPv6.
    pub mask: u8,
    /// Optional username of the banned user.
    pub name: Option<String>,
    /// SHA-1 hex of the banned user's certificate hash.
    pub hash: Option<String>,
    /// Reason for the ban.
    pub reason: Option<String>,
    /// Unix timestamp when the ban started.
    pub start: i64,
    /// Duration in seconds; 0 = permanent.
    pub duration: u64,
}

mod ip_addr_string {
    use super::*;
    use serde::de::Error;

    pub fn serialize<S>(value: &IpAddr, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IpAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

impl BanEntry {
    pub fn is_permanent(&self) -> bool {
        self.duration == 0
    }

    pub fn is_expired(&self, now: i64) -> bool {
        if self.duration == 0 {
            return false;
        }
        now >= self.start + self.duration as i64
    }
}

// ─── WAL types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanOperation {
    pub version: u64,
    pub node_id: u16,
    /// Unix timestamp (seconds since epoch) when the operation was created.
    pub timestamp: i64,
    #[serde(flatten)]
    pub op: BanOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BanOp {
    /// Replace the entire ban list with the given entries.
    SetBans { entries: Vec<BanEntry> },
    /// Add a single ban entry.
    AddBan { entry: BanEntry },
    /// Remove a ban entry by address and mask.
    RemoveBan { address: IpAddr, mask: u8 },
}

// ─── BanRepository ────────────────────────────────────────────────────────────

pub struct BanRepository {
    node_id: u16,
    /// SQLite connection wrapped in a Mutex (rusqlite Connection is not Sync).
    conn: Mutex<Connection>,
    version: AtomicU64,
    /// Optional storage directory (for logging / future use).
    #[allow(dead_code)]
    storage_dir: Option<PathBuf>,
    /// Broadcast channel for S2S subscribers.
    tx: broadcast::Sender<Arc<BanOperation>>,
}

impl BanRepository {
    // ── Construction ──────────────────────────────────────────────────────

    /// Create an in-memory repository (no persistence).
    pub fn new_in_memory(node_id: u16) -> Arc<Self> {
        let conn = Connection::open_in_memory().expect("in-memory SQLite should always open");
        let repo = Self::init_db(node_id, conn, None);
        Arc::new(repo)
    }

    /// Open (or create) a persisted repository in `storage_dir`.
    pub async fn open(node_id: u16, storage_dir: &Path) -> Result<Arc<Self>, io::Error> {
        tokio::fs::create_dir_all(storage_dir).await?;

        let db_path = storage_dir.join("bans.db");
        let conn = Connection::open(&db_path).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("failed to open bans.db: {e}"))
        })?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("failed to set WAL mode: {e}"))
            })?;

        let repo = Self::init_db(node_id, conn, Some(storage_dir.to_owned()));
        Ok(Arc::new(repo))
    }

    fn init_db(node_id: u16, conn: Connection, storage_dir: Option<PathBuf>) -> Self {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bans (
                address TEXT NOT NULL,
                mask INTEGER NOT NULL,
                name TEXT,
                hash TEXT,
                reason TEXT,
                start INTEGER NOT NULL,
                duration INTEGER NOT NULL,
                PRIMARY KEY (address, mask)
            );

            CREATE TABLE IF NOT EXISTS ban_operations (
                version INTEGER PRIMARY KEY,
                node_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                op_type TEXT NOT NULL,
                op_data TEXT NOT NULL
            );

            -- Index for efficient IP lookups
            CREATE INDEX IF NOT EXISTS idx_bans_address ON bans(address);",
        )
        .expect("table creation should succeed");

        // Determine current version from the operations table
        let max_version: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM ban_operations",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let (tx, _) = broadcast::channel(256);

        Self {
            node_id,
            conn: Mutex::new(conn),
            version: AtomicU64::new(max_version),
            storage_dir,
            tx,
        }
    }

    // ── Version ───────────────────────────────────────────────────────────

    pub fn current_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    pub fn local_node_id(&self) -> u16 {
        self.node_id
    }

    // ── Read API ──────────────────────────────────────────────────────────

    /// Return all non-expired ban entries.
    pub async fn get_active_bans(&self) -> Vec<BanEntry> {
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT address, mask, name, hash, reason, start, duration
                 FROM bans
                 WHERE duration = 0 OR (start + duration) > ?1",
            )
            .expect("query should be valid");

        let rows = stmt
            .query_map(params![now], |row| {
                let addr_str: String = row.get(0)?;
                Ok(BanEntry {
                    address: addr_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                    mask: row.get(1)?,
                    name: row.get(2)?,
                    hash: row.get(3)?,
                    reason: row.get(4)?,
                    start: row.get(5)?,
                    duration: row.get(6)?,
                })
            })
            .expect("query should succeed");

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Check whether an IP address is banned.
    pub async fn is_banned(&self, addr: IpAddr) -> bool {
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();

        // Get all non-expired bans and check CIDR matching in Rust.
        // For very large ban lists, we could push CIDR matching into SQL
        // with bit-shift arithmetic, but this is simpler and correct.
        let mut stmt = conn
            .prepare(
                "SELECT address, mask FROM bans
                 WHERE duration = 0 OR (start + duration) > ?1",
            )
            .expect("query should be valid");

        let result = stmt
            .query_map(params![now], |row| {
                let addr_str: String = row.get(0)?;
                let mask: u8 = row.get(1)?;
                Ok((addr_str, mask))
            })
            .expect("query should succeed");

        for row in result.flatten() {
            let (ban_addr_str, mask) = row;
            let ban_addr: IpAddr = match ban_addr_str.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            if ip_matches_cidr(ban_addr, mask, addr) {
                return true;
            }
        }
        false
    }

    // ── Mutation API ──────────────────────────────────────────────────────

    /// Replace the entire ban list.
    pub async fn set_bans(self: &Arc<Self>, entries: Vec<BanEntry>) -> Result<(), io::Error> {
        let op = {
            let conn = self.conn.lock();
            conn.execute("DELETE FROM bans", [])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let op = {
                let mut stmt = conn
                    .prepare(
                        "INSERT INTO bans (address, mask, name, hash, reason, start, duration)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    )
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                for entry in &entries {
                    stmt.execute(params![
                        entry.address.to_string(),
                        entry.mask,
                        entry.name,
                        entry.hash,
                        entry.reason,
                        entry.start,
                        entry.duration,
                    ])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
                self.make_op(BanOp::SetBans { entries })
            };
            op
        };
        // Lock released — safe to await
        self.commit(op).await?;
        Ok(())
    }

    /// Add a single ban entry.
    pub async fn add_ban(self: &Arc<Self>, entry: BanEntry) -> Result<(), io::Error> {
        let op = {
            let conn = self.conn.lock();
            conn.execute(
                "INSERT OR REPLACE INTO bans (address, mask, name, hash, reason, start, duration)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    entry.address.to_string(),
                    entry.mask,
                    entry.name,
                    entry.hash,
                    entry.reason,
                    entry.start,
                    entry.duration,
                ],
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            self.make_op(BanOp::AddBan { entry })
        };
        self.commit(op).await?;
        Ok(())
    }

    /// Remove a ban entry by address and mask.
    pub async fn remove_ban(self: &Arc<Self>, address: IpAddr, mask: u8) -> Result<(), io::Error> {
        let op = {
            let conn = self.conn.lock();
            conn.execute(
                "DELETE FROM bans WHERE address = ?1 AND mask = ?2",
                params![address.to_string(), mask],
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            self.make_op(BanOp::RemoveBan { address, mask })
        };
        self.commit(op).await?;
        Ok(())
    }

    // ── S2S / replication ─────────────────────────────────────────────────

    /// Subscribe to the stream of committed `BanOperation`s.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<BanOperation>> {
        self.tx.subscribe()
    }

    /// Return all log entries with `version > since_version`.
    pub async fn get_log_since(&self, since_version: u64) -> Vec<Arc<BanOperation>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT version, node_id, timestamp, op_type, op_data
                 FROM ban_operations
                 WHERE version > ?1
                 ORDER BY version ASC",
            )
            .expect("query should be valid");

        let rows = stmt
            .query_map(params![since_version], |row| {
                let version: u64 = row.get(0)?;
                let node_id: u16 = row.get(1)?;
                let timestamp: i64 = row.get(2)?;
                let op_type: String = row.get(3)?;
                let op_data: String = row.get(4)?;
                Ok((version, node_id, timestamp, op_type, op_data))
            })
            .expect("query should succeed");

        rows.filter_map(|r| r.ok())
            .filter_map(|(version, node_id, timestamp, _op_type, op_data)| {
                let op: BanOp = serde_json::from_str(&op_data).ok()?;
                Some(Arc::new(BanOperation {
                    version,
                    node_id,
                    timestamp,
                    op,
                }))
            })
            .collect()
    }

    /// Apply an operation that arrived from a remote node.
    pub async fn apply_remote_operation(&self, op: Arc<BanOperation>) {
        if op.version <= self.version.load(Ordering::Acquire) {
            return;
        }
        let conn = self.conn.lock();
        apply_op_to_db(&conn, &op.op).ok();
        // Record the operation in the log
        let op_data = serde_json::to_string(&op.op).expect("BanOp should be serializable");
        conn.execute(
            "INSERT OR IGNORE INTO ban_operations (version, node_id, timestamp, op_type, op_data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                op.version,
                op.node_id,
                op.timestamp,
                op_type_str(&op.op),
                op_data
            ],
        )
        .ok();
        self.version.fetch_max(op.version, Ordering::AcqRel);
    }

    pub async fn install_s2s_snapshot(&self, version: u64, entries: Vec<BanEntry>) {
        let conn = self.conn.lock();
        if let Err(e) = apply_op_to_db(&conn, &BanOp::SetBans { entries }) {
            tracing::warn!("ban snapshot install failed: {e}");
            return;
        }
        self.version.store(version, Ordering::Release);
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn make_op(&self, op: BanOp) -> BanOperation {
        BanOperation {
            version: 0, // assigned by commit()
            node_id: self.node_id,
            timestamp: chrono::Utc::now().timestamp(),
            op,
        }
    }

    /// Commit an operation: assign version, insert into ban_operations, broadcast.
    /// Acquires the connection lock internally.
    async fn commit(&self, op: BanOperation) -> Result<(), io::Error> {
        let op = {
            let conn = self.conn.lock();
            self.commit_locked(&conn, op)?
        };
        let _ = self.tx.send(op);
        Ok(())
    }

    /// Commit an operation synchronously. The caller must hold `conn` lock.
    fn commit_locked(
        &self,
        conn: &Connection,
        mut op: BanOperation,
    ) -> Result<Arc<BanOperation>, io::Error> {
        let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        op.version = version;

        let op_data = serde_json::to_string(&op.op).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("op serialisation error: {e}"),
            )
        })?;

        conn.execute(
            "INSERT INTO ban_operations (version, node_id, timestamp, op_type, op_data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                version,
                op.node_id,
                op.timestamp,
                op_type_str(&op.op),
                op_data
            ],
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let op = Arc::new(op);
        Ok(op)
    }
}

// ─── Free functions ──────────────────────────────────────────────────────────

/// Apply a `BanOp` to the database.
fn apply_op_to_db(conn: &Connection, op: &BanOp) -> Result<(), rusqlite::Error> {
    match op {
        BanOp::SetBans { entries } => {
            conn.execute("DELETE FROM bans", [])?;
            let mut stmt = conn.prepare(
                "INSERT INTO bans (address, mask, name, hash, reason, start, duration)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for entry in entries {
                stmt.execute(params![
                    entry.address.to_string(),
                    entry.mask,
                    entry.name,
                    entry.hash,
                    entry.reason,
                    entry.start,
                    entry.duration,
                ])?;
            }
        }
        BanOp::AddBan { entry } => {
            conn.execute(
                "INSERT OR REPLACE INTO bans (address, mask, name, hash, reason, start, duration)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    entry.address.to_string(),
                    entry.mask,
                    entry.name,
                    entry.hash,
                    entry.reason,
                    entry.start,
                    entry.duration,
                ],
            )?;
        }
        BanOp::RemoveBan { address, mask } => {
            conn.execute(
                "DELETE FROM bans WHERE address = ?1 AND mask = ?2",
                params![address.to_string(), mask],
            )?;
        }
    }
    Ok(())
}

/// Return a short string tag for the operation type (stored in the `op_type` column).
fn op_type_str(op: &BanOp) -> &'static str {
    match op {
        BanOp::SetBans { .. } => "set_bans",
        BanOp::AddBan { .. } => "add_ban",
        BanOp::RemoveBan { .. } => "remove_ban",
    }
}

/// Check whether a client IP matches a ban entry's CIDR range.
fn ip_matches_cidr(ban_addr: IpAddr, mask: u8, client_addr: IpAddr) -> bool {
    match (ban_addr, client_addr) {
        (IpAddr::V4(ban), IpAddr::V4(client)) => {
            if mask >= 32 {
                ban == client
            } else {
                let shift = 32 - mask;
                (u32::from(ban) >> shift) == (u32::from(client) >> shift)
            }
        }
        (IpAddr::V6(ban), IpAddr::V6(client)) => {
            if mask >= 128 {
                ban == client
            } else {
                let shift = 128 - mask;
                (u128::from(ban) >> shift) == (u128::from(client) >> shift)
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_operation_msgpack_round_trips() {
        let op = BanOperation {
            version: 7,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: BanEntry {
                    address: "203.0.113.17".parse().unwrap(),
                    mask: 32,
                    name: Some("replicated-ban".into()),
                    hash: None,
                    reason: Some("s2s integration test".into()),
                    start: 123,
                    duration: 0,
                },
            },
        };

        let encoded = rmp_serde::to_vec(&op).expect("encode ban op");
        let decoded: BanOperation = rmp_serde::from_slice(&encoded).expect("decode ban op");

        assert_eq!(decoded.version, op.version);
        assert_eq!(decoded.node_id, op.node_id);
        assert_eq!(decoded.timestamp, op.timestamp);
        match decoded.op {
            BanOp::AddBan { entry } => {
                assert_eq!(entry.address, IpAddr::from([203, 0, 113, 17]));
                assert_eq!(entry.reason.as_deref(), Some("s2s integration test"));
            }
            other => panic!("expected AddBan, got {other:?}"),
        }
    }
}
