//! `BanRepository` — versioned, SQLite-backed ban list store.
//!
//! Uses a single SQLite database file (`bans.db`) for both storage and
//! the operation log.  No separate WAL or snapshot files are needed.
//!
//! * `bans` table — current ban entries with indexed IP lookups.
//! * `ban_operations` table — append-only operation log for S2S replication.
//!
//! The public interface is unchanged from the previous in-memory implementation.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};
use rusqlite::{Connection, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::broadcast;

use shitspeak_core::StrictReplicationMetadata;

use crate::channel_repository::{StrictOperationApplyOutcome, StrictOperationId};

// ─── Ban entry ───────────────────────────────────────────────────────────────

fn sql_i64_from_u64(value: u64) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
}

fn sql_i64_from_u64_io(value: u64) -> Result<i64, io::Error> {
    sql_i64_from_u64(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

fn sqlite_io_error(error: rusqlite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

fn sql_u64_from_i64(value: i64) -> u64 {
    value.max(0) as u64
}

fn sql_text_from_u64(value: u64) -> String {
    value.to_string()
}

fn sql_u64_from_text(value: Option<String>) -> Option<u64> {
    value?.parse().ok()
}

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
    /// Whether the certificate hash is an active ban criterion.
    #[serde(default = "default_true")]
    pub ban_certificate: bool,
    /// Whether the IP address is an active ban criterion.
    #[serde(default = "default_true")]
    pub ban_ip: bool,
    /// Reason for the ban.
    pub reason: Option<String>,
    /// Unix timestamp when the ban started.
    pub start: i64,
    /// Duration in seconds; 0 = permanent.
    pub duration: u64,
}

fn default_true() -> bool {
    true
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

#[derive(Clone, Debug)]
pub struct BanLogEntry {
    op: Arc<BanOperation>,
    strict_metadata: Option<StrictReplicationMetadata>,
}

impl BanLogEntry {
    fn new(op: Arc<BanOperation>, strict_metadata: Option<StrictReplicationMetadata>) -> Self {
        Self {
            op,
            strict_metadata,
        }
    }

    pub fn op(&self) -> Arc<BanOperation> {
        self.op.clone()
    }

    pub fn strict_metadata(&self) -> Option<StrictReplicationMetadata> {
        self.strict_metadata
    }
}

/// An atomically captured strict-replication snapshot of the ban repository.
///
/// The state, version, freshness, and idempotency ledger are read from one
/// SQLite transaction. Consumers must serialize this bundle together rather
/// than independently querying its fields.
#[derive(Debug, Clone)]
pub struct BanStrictSnapshot {
    version: u64,
    entries: Vec<BanEntry>,
    freshness: i64,
    operation_ids: Vec<StrictOperationId>,
}

impl BanStrictSnapshot {
    /// Consume the snapshot into the values needed by an S2S snapshot frame.
    pub fn into_parts(self) -> (u64, Vec<BanEntry>, i64, Vec<StrictOperationId>) {
        (
            self.version,
            self.entries,
            self.freshness,
            self.operation_ids,
        )
    }
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

const IPV4_PREFIX_COUNT: u8 = 32;
const IPV6_PREFIX_COUNT: u8 = 128;

/// In-memory lookup tables used on the authentication path. Address width is
/// fixed, so checking every possible CIDR prefix is constant work regardless
/// of the number of configured bans.
#[derive(Default)]
struct BanLookupIndex {
    entries: HashMap<(IpAddr, u8), BanEntry>,
    ipv4_prefixes: HashMap<(u8, u32), i64>,
    ipv6_prefixes: HashMap<(u8, u128), i64>,
    identity_hashes: HashMap<String, i64>,
    asns: HashMap<u32, i64>,
    has_permanent_asn_ban: bool,
    latest_asn_expiry: i64,
}

impl BanLookupIndex {
    fn from_entries(entries: Vec<BanEntry>) -> Self {
        let mut index = Self::default();
        index.replace_entries(entries);
        index
    }

    fn apply_op(&mut self, op: &BanOp) {
        match op {
            BanOp::SetBans { entries } => self.replace_entries(entries.clone()),
            BanOp::AddBan { entry } => {
                self.entries
                    .insert((entry.address, entry.mask), entry.clone());
                self.rebuild();
            }
            BanOp::RemoveBan { address, mask } => {
                self.entries.remove(&(*address, *mask));
                self.rebuild();
            }
        }
    }

    fn replace_entries(&mut self, entries: Vec<BanEntry>) {
        self.entries = entries
            .into_iter()
            .map(|entry| ((entry.address, entry.mask), entry))
            .collect();
        self.rebuild();
    }

    fn rebuild(&mut self) {
        self.ipv4_prefixes.clear();
        self.ipv6_prefixes.clear();
        self.identity_hashes.clear();
        self.asns.clear();
        self.has_permanent_asn_ban = false;
        self.latest_asn_expiry = 0;

        for entry in self.entries.values() {
            let expiry = ban_expiry(entry);
            // A default-route CIDR would ban every address in its family. Keep
            // the entry for any independent identity criterion, but never
            // index it as an IP ban.
            if entry.ban_ip && entry.mask != 0 {
                match entry.address {
                    IpAddr::V4(address) => {
                        let mask = entry.mask.min(IPV4_PREFIX_COUNT);
                        extend_ban_expiry(
                            &mut self.ipv4_prefixes,
                            (mask, ipv4_prefix(address, mask)),
                            expiry,
                        );
                    }
                    IpAddr::V6(address) => {
                        let mask = entry.mask.min(IPV6_PREFIX_COUNT);
                        extend_ban_expiry(
                            &mut self.ipv6_prefixes,
                            (mask, ipv6_prefix(address, mask)),
                            expiry,
                        );
                    }
                }
            }
            if entry.ban_certificate {
                if let Some(hash) = entry.hash.as_deref() {
                    if let Some(asn) = asn_from_ban_hash(hash) {
                        extend_ban_expiry(&mut self.asns, asn, expiry);
                        if expiry == 0 {
                            self.has_permanent_asn_ban = true;
                        } else {
                            self.latest_asn_expiry = self.latest_asn_expiry.max(expiry);
                        }
                    } else {
                        extend_ban_expiry(
                            &mut self.identity_hashes,
                            hash.to_ascii_lowercase(),
                            expiry,
                        );
                    }
                }
            }
        }
    }

    fn is_ip_banned(&self, address: IpAddr, now: i64) -> bool {
        match address {
            IpAddr::V4(address) => (0..=IPV4_PREFIX_COUNT).any(|mask| {
                self.ipv4_prefixes
                    .get(&(mask, ipv4_prefix(address, mask)))
                    .is_some_and(|expiry| ban_is_active(*expiry, now))
            }),
            IpAddr::V6(address) => (0..=IPV6_PREFIX_COUNT).any(|mask| {
                self.ipv6_prefixes
                    .get(&(mask, ipv6_prefix(address, mask)))
                    .is_some_and(|expiry| ban_is_active(*expiry, now))
            }),
        }
    }

    fn is_identity_banned(
        &self,
        certificate_hash: Option<&str>,
        tls_ja4: Option<&str>,
        now: i64,
    ) -> bool {
        certificate_hash
            .into_iter()
            .chain(tls_ja4)
            .map(str::to_ascii_lowercase)
            .any(|identity| {
                self.identity_hashes
                    .get(&identity)
                    .is_some_and(|expiry| ban_is_active(*expiry, now))
            })
    }

    fn has_active_asn_bans(&self, now: i64) -> bool {
        self.has_permanent_asn_ban || now < self.latest_asn_expiry
    }

    fn is_asn_banned(&self, asn: u32, now: i64) -> bool {
        self.asns
            .get(&asn)
            .is_some_and(|expiry| ban_is_active(*expiry, now))
    }
}

fn asn_from_ban_hash(hash: &str) -> Option<u32> {
    let asn = hash.strip_prefix("AS")?;
    (!asn.is_empty() && asn.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| asn.parse().ok())
        .flatten()
}

fn ban_expiry(entry: &BanEntry) -> i64 {
    if entry.duration == 0 {
        0
    } else {
        entry
            .start
            .saturating_add(i64::try_from(entry.duration).unwrap_or(i64::MAX))
    }
}

fn ban_is_active(expiry: i64, now: i64) -> bool {
    expiry == 0 || now < expiry
}

fn extend_ban_expiry<K: std::cmp::Eq + std::hash::Hash>(
    index: &mut HashMap<K, i64>,
    key: K,
    expiry: i64,
) {
    index
        .entry(key)
        .and_modify(|existing| {
            if *existing == 0 || expiry == 0 {
                *existing = 0;
            } else {
                *existing = (*existing).max(expiry);
            }
        })
        .or_insert(expiry);
}

fn ipv4_prefix(address: std::net::Ipv4Addr, mask: u8) -> u32 {
    let mask = mask.min(IPV4_PREFIX_COUNT);
    if mask == 0 {
        0
    } else {
        u32::from(address) & (u32::MAX << (IPV4_PREFIX_COUNT - mask))
    }
}

fn ipv6_prefix(address: std::net::Ipv6Addr, mask: u8) -> u128 {
    let mask = mask.min(IPV6_PREFIX_COUNT);
    if mask == 0 {
        0
    } else {
        u128::from(address) & (u128::MAX << (IPV6_PREFIX_COUNT - mask))
    }
}

// ─── BanRepository ────────────────────────────────────────────────────────────

pub struct BanRepository {
    node_id: u16,
    /// SQLite connection wrapped in a Mutex (rusqlite Connection is not Sync).
    conn: Mutex<Connection>,
    /// Authentication-time ban lookups. Updated only after the corresponding
    /// SQLite mutation commits successfully.
    lookup_index: RwLock<BanLookupIndex>,
    version: AtomicU64,
    history_freshness: AtomicI64,
    /// Optional storage directory (for logging / future use).
    #[allow(dead_code)]
    storage_dir: Option<PathBuf>,
    /// A failed strict SQLite transaction leaves its durable terminal state
    /// uncertain. Keep v2 disabled until a fresh process reopens and verifies
    /// the repository rather than treating the configured path as healthy.
    strict_durability_poisoned: AtomicBool,
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
                ban_certificate INTEGER NOT NULL DEFAULT 1,
                ban_ip INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (address, mask)
            );

            CREATE TABLE IF NOT EXISTS ban_operations (
                version INTEGER PRIMARY KEY,
                node_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                op_type TEXT NOT NULL,
                op_data TEXT NOT NULL,
                strict_op_id_hi TEXT,
                strict_op_id_lo TEXT,
                strict_ts_final TEXT
            );

            CREATE TABLE IF NOT EXISTS ban_strict_op_ids (
                op_id_hi TEXT NOT NULL,
                op_id_lo TEXT NOT NULL,
                ts_final TEXT NOT NULL,
                PRIMARY KEY (op_id_hi, op_id_lo)
            );

            CREATE TABLE IF NOT EXISTS ban_snapshot_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version TEXT NOT NULL,
                freshness INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ban_repository_migrations (
                name TEXT PRIMARY KEY
            );

            -- Index for efficient IP lookups
            CREATE INDEX IF NOT EXISTS idx_bans_address ON bans(address);",
        )
        .expect("table creation should succeed");
        for migration in [
            "ALTER TABLE ban_operations ADD COLUMN strict_op_id_hi TEXT",
            "ALTER TABLE ban_operations ADD COLUMN strict_op_id_lo TEXT",
            "ALTER TABLE ban_operations ADD COLUMN strict_ts_final TEXT",
            "ALTER TABLE bans ADD COLUMN ban_certificate INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE bans ADD COLUMN ban_ip INTEGER NOT NULL DEFAULT 1",
        ] {
            let _ = conn.execute(migration, []);
        }
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             INSERT OR IGNORE INTO ban_strict_op_ids (op_id_hi, op_id_lo, ts_final)
             SELECT strict_op_id_hi, strict_op_id_lo, strict_ts_final
             FROM ban_operations
             WHERE strict_op_id_hi IS NOT NULL
               AND strict_op_id_lo IS NOT NULL
               AND strict_ts_final IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM ban_repository_migrations
                   WHERE name = 'strict_op_id_backfill_v1'
               );
             INSERT OR IGNORE INTO ban_repository_migrations (name)
             VALUES ('strict_op_id_backfill_v1');
             COMMIT;",
        )
        .expect("strict operation id backfill should succeed");

        // Determine current version from the operations table
        let max_version = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM ban_operations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(sql_u64_from_i64)
            .unwrap_or(0);
        let snapshot_version = conn
            .query_row(
                "SELECT version FROM ban_snapshot_state WHERE id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|version| sql_u64_from_text(Some(version)))
            .unwrap_or(0);
        let snapshot_freshness = conn
            .query_row(
                "SELECT freshness FROM ban_snapshot_state WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0);

        let (tx, _) = broadcast::channel(256);
        let lookup_index = BanLookupIndex::from_entries(
            active_bans_from_connection(&conn, chrono::Utc::now().timestamp()).unwrap_or_default(),
        );

        Self {
            node_id,
            conn: Mutex::new(conn),
            lookup_index: RwLock::new(lookup_index),
            version: AtomicU64::new(max_version.max(snapshot_version)),
            history_freshness: AtomicI64::new(snapshot_freshness),
            storage_dir,
            strict_durability_poisoned: AtomicBool::new(false),
            tx,
        }
    }

    // ── Version ───────────────────────────────────────────────────────────

    pub fn current_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    pub fn latest_timestamp(&self) -> i64 {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COALESCE(MAX(timestamp), 0) FROM ban_operations",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
        .max(self.history_freshness.load(Ordering::Acquire))
    }

    pub fn local_node_id(&self) -> u16 {
        self.node_id
    }

    /// Whether the strict-operation ledger is backed by a persistent SQLite
    /// database and therefore survives a repository restart.
    pub fn durable_storage_enabled(&self) -> bool {
        self.storage_dir.is_some() && !self.strict_durability_poisoned.load(Ordering::Acquire)
    }

    /// Whether this repository instance has observed a local strict-storage
    /// failure. Callers use this to distinguish a failed durable snapshot
    /// install from a semantically rejected peer snapshot.
    pub fn strict_durability_failure_observed(&self) -> bool {
        self.strict_durability_poisoned.load(Ordering::Acquire)
    }

    fn mark_strict_durability_failed(&self) {
        if self.storage_dir.is_some() {
            self.strict_durability_poisoned
                .store(true, Ordering::Release);
        }
    }

    /// Return strict operation ids retained by the durable idempotency ledger.
    /// These ids are intended to accompany an S2S ban snapshot.
    pub fn strict_operation_ids(&self) -> Result<Vec<StrictOperationId>, io::Error> {
        let conn = self.conn.lock();
        let result = strict_operation_ids_from_connection(&conn);
        if result.is_err() {
            self.mark_strict_durability_failed();
        }
        result
    }

    /// Atomically capture the data required for a strict-replication snapshot.
    ///
    /// This is deliberately a single repository operation: independently
    /// reading the version, ban entries, freshness, and operation-id ledger can
    /// expose state from different commits and make a later strict delivery look
    /// like a duplicate before its mutation is represented by the snapshot.
    pub fn strict_snapshot(&self) -> Result<BanStrictSnapshot, io::Error> {
        let result = (|| {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().map_err(sqlite_io_error)?;
            let version = durable_version_from_connection(&tx)?;
            let freshness = durable_freshness_from_connection(&tx)?;
            let entries = active_bans_from_connection(&tx, chrono::Utc::now().timestamp())?;
            let operation_ids = strict_operation_ids_from_connection(&tx)?;
            tx.commit().map_err(sqlite_io_error)?;

            Ok(BanStrictSnapshot {
                version,
                entries,
                freshness,
                operation_ids,
            })
        })();
        if result.is_err() {
            self.mark_strict_durability_failed();
        }
        result
    }

    /// Atomically capture the repository state for strict protocol v5.
    ///
    /// Applied-operation ownership moved to the S2S terminal journal in v5.
    /// The frozen legacy ledger is still captured atomically for pre-v5
    /// receivers, but v5 applications no longer add entries to it.
    pub fn strict_snapshot_v5(&self) -> Result<BanStrictSnapshot, io::Error> {
        let result = (|| {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().map_err(sqlite_io_error)?;
            let version = durable_version_from_connection(&tx)?;
            let freshness = durable_freshness_from_connection(&tx)?;
            let entries = active_bans_from_connection(&tx, chrono::Utc::now().timestamp())?;
            let operation_ids = strict_operation_ids_from_connection(&tx)?;
            tx.commit().map_err(sqlite_io_error)?;

            Ok(BanStrictSnapshot {
                version,
                entries,
                freshness,
                operation_ids,
            })
        })();
        if result.is_err() {
            self.mark_strict_durability_failed();
        }
        result
    }

    /// Merge strict operation ids received with an S2S ban snapshot. The
    /// transaction commits the ledger before this method returns.
    pub fn merge_strict_operation_ids(
        &self,
        operation_ids: &[StrictOperationId],
    ) -> Result<(), io::Error> {
        let result = (|| {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().map_err(sqlite_io_error)?;
            for operation_id in operation_ids {
                tx.execute(
                    "INSERT OR IGNORE INTO ban_strict_op_ids (op_id_hi, op_id_lo, ts_final)
                     VALUES (?1, ?2, ?3)",
                    params![
                        sql_text_from_u64(operation_id.op_id_hi()),
                        sql_text_from_u64(operation_id.op_id_lo()),
                        "0",
                    ],
                )
                .map_err(sqlite_io_error)?;
            }
            tx.commit().map_err(sqlite_io_error)
        })();
        if result.is_err() {
            self.mark_strict_durability_failed();
        }
        result
    }

    // ── Read API ──────────────────────────────────────────────────────────

    /// Return all non-expired ban entries.
    pub async fn get_active_bans(&self) -> Vec<BanEntry> {
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT address, mask, name, hash, ban_certificate, ban_ip, reason, start, duration
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
                    ban_certificate: row.get::<_, i64>(4)? != 0,
                    ban_ip: row.get::<_, i64>(5)? != 0,
                    reason: row.get(6)?,
                    start: row.get(7)?,
                    duration: sql_u64_from_i64(row.get::<_, i64>(8)?),
                })
            })
            .expect("query should succeed");

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Check whether an IP address is banned.
    pub async fn is_banned(&self, addr: IpAddr) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.lookup_index.read().is_ip_banned(addr, now)
    }

    /// Check certificate-hash and TLS JA4 ban criteria without scanning the
    /// ban list. ASN-style hashes are intentionally excluded here because
    /// they require an IP-to-ASN lookup by the runtime.
    pub fn is_identity_banned(
        &self,
        certificate_hash: Option<&str>,
        tls_ja4: Option<&str>,
    ) -> bool {
        self.lookup_index.read().is_identity_banned(
            certificate_hash,
            tls_ja4,
            chrono::Utc::now().timestamp(),
        )
    }

    /// Whether an active certificate-ban hash represents an ASN criterion.
    /// Callers use this to avoid a GeoIP lookup unless one is required.
    pub fn has_active_asn_bans(&self) -> bool {
        self.lookup_index
            .read()
            .has_active_asn_bans(chrono::Utc::now().timestamp())
    }

    /// Check an ASN resolved by the runtime against ASN-style certificate bans.
    pub fn is_asn_banned(&self, asn: u32) -> bool {
        self.lookup_index
            .read()
            .is_asn_banned(asn, chrono::Utc::now().timestamp())
    }

    // ── Mutation API ──────────────────────────────────────────────────────

    /// Replace the entire ban list.
    pub async fn set_bans(self: &Arc<Self>, entries: Vec<BanEntry>) -> Result<(), io::Error> {
        self.commit(self.make_op(BanOp::SetBans { entries })).await
    }

    /// Add a single ban entry.
    pub async fn add_ban(self: &Arc<Self>, entry: BanEntry) -> Result<(), io::Error> {
        self.commit(self.make_op(BanOp::AddBan { entry })).await
    }

    /// Remove a ban entry by address and mask.
    pub async fn remove_ban(self: &Arc<Self>, address: IpAddr, mask: u8) -> Result<(), io::Error> {
        self.commit(self.make_op(BanOp::RemoveBan { address, mask }))
            .await
    }

    // ── S2S / replication ─────────────────────────────────────────────────

    /// Subscribe to the stream of committed `BanOperation`s.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<BanOperation>> {
        self.tx.subscribe()
    }

    /// Return all log entries with `version > since_version`.
    pub async fn get_log_since(&self, since_version: u64) -> Vec<Arc<BanOperation>> {
        self.get_log_entries_since(since_version)
            .await
            .into_iter()
            .map(|entry| entry.op())
            .collect()
    }

    pub async fn get_log_entries_since(&self, since_version: u64) -> Vec<BanLogEntry> {
        let since_version = i64::try_from(since_version).unwrap_or(i64::MAX);
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT version, node_id, timestamp, op_type, op_data,
                        CAST(strict_op_id_hi AS TEXT),
                        CAST(strict_op_id_lo AS TEXT),
                        CAST(strict_ts_final AS TEXT)
                 FROM ban_operations
                 WHERE version > ?1
                 ORDER BY version ASC",
            )
            .expect("query should be valid");

        let rows = stmt
            .query_map(params![since_version], |row| {
                let version = sql_u64_from_i64(row.get::<_, i64>(0)?);
                let node_id: u16 = row.get(1)?;
                let timestamp: i64 = row.get(2)?;
                let op_type: String = row.get(3)?;
                let op_data: String = row.get(4)?;
                let strict_op_id_hi = row.get::<_, Option<String>>(5)?;
                let strict_op_id_lo = row.get::<_, Option<String>>(6)?;
                let strict_ts_final = row.get::<_, Option<String>>(7)?;
                Ok((
                    version,
                    node_id,
                    timestamp,
                    op_type,
                    op_data,
                    strict_op_id_hi,
                    strict_op_id_lo,
                    strict_ts_final,
                ))
            })
            .expect("query should succeed");

        rows.filter_map(|r| r.ok())
            .filter_map(
                |(
                    version,
                    node_id,
                    timestamp,
                    _op_type,
                    op_data,
                    strict_op_id_hi,
                    strict_op_id_lo,
                    strict_ts_final,
                )| {
                    let op: BanOp = serde_json::from_str(&op_data).ok()?;
                    let metadata = match (
                        sql_u64_from_text(strict_op_id_hi),
                        sql_u64_from_text(strict_op_id_lo),
                        sql_u64_from_text(strict_ts_final),
                    ) {
                        (Some(hi), Some(lo), Some(ts)) => {
                            Some(StrictReplicationMetadata::new(hi, lo, ts))
                        }
                        _ => None,
                    };
                    Some(BanLogEntry::new(
                        Arc::new(BanOperation {
                            version,
                            node_id,
                            timestamp,
                            op,
                        }),
                        metadata,
                    ))
                },
            )
            .collect()
    }

    /// Return strict-replication log entries after `since_version` when this
    /// repository still has a complete history for that cursor.
    ///
    /// `None` means an installed snapshot established a newer history floor,
    /// or durable log data cannot be read safely. Strict callers must request a
    /// snapshot in that case instead of treating a partial operation list as a
    /// complete history.
    pub async fn strict_log_entries_since(&self, since_version: u64) -> Option<Vec<BanLogEntry>> {
        let sql_since_version = i64::try_from(since_version).ok()?;
        let conn = self.conn.lock();
        let history_floor = match snapshot_version_from_connection(&conn) {
            Ok(version) => version,
            Err(_) => {
                self.mark_strict_durability_failed();
                return None;
            }
        };
        if since_version < history_floor {
            return None;
        }
        match strict_log_entries_since_from_connection(&conn, sql_since_version) {
            Ok(entries) => Some(entries),
            Err(_) => {
                self.mark_strict_durability_failed();
                None
            }
        }
    }

    /// Apply an operation that arrived from a remote node.
    pub async fn apply_remote_operation(&self, op: Arc<BanOperation>) {
        self.apply_remote_operation_with_metadata(op, None).await
    }

    pub async fn apply_remote_operation_with_metadata(
        &self,
        op: Arc<BanOperation>,
        strict_metadata: Option<StrictReplicationMetadata>,
    ) {
        if let Some(strict_metadata) = strict_metadata {
            if let Err(error) = self.apply_strict_operation_once(op, strict_metadata).await {
                tracing::warn!(error = %error, "strict ban operation apply failed");
            }
            return;
        }

        let Ok(sql_version) = sql_i64_from_u64(op.version) else {
            return;
        };
        let op_data = serde_json::to_string(&op.op).expect("BanOp should be serializable");
        let mut conn = self.conn.lock();
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(error) => {
                tracing::warn!(error = %error, "failed to begin remote ban operation transaction");
                return;
            }
        };
        let current_version = match durable_version_from_connection(&tx) {
            Ok(version) => version,
            Err(error) => {
                tracing::warn!(error = %error, "failed to read remote ban operation version");
                return;
            }
        };
        if op.version <= current_version {
            return;
        }
        if let Err(error) = apply_op_to_db(&tx, &op.op) {
            tracing::warn!(error = %error, "failed to apply remote ban operation");
            return;
        }
        if let Err(error) = tx.execute(
            "INSERT OR IGNORE INTO ban_operations
                (version, node_id, timestamp, op_type, op_data,
                 strict_op_id_hi, strict_op_id_lo, strict_ts_final)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                sql_version,
                op.node_id,
                op.timestamp,
                op_type_str(&op.op),
                op_data,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
            ],
        ) {
            tracing::warn!(error = %error, "failed to record remote ban operation");
            return;
        }
        if let Err(error) = tx.commit() {
            tracing::warn!(error = %error, "failed to commit remote ban operation");
            return;
        }
        self.version.fetch_max(op.version, Ordering::AcqRel);
        self.history_freshness
            .fetch_max(op.timestamp, Ordering::AcqRel);
        self.apply_lookup_index(&op.op);
    }

    /// Atomically apply a strict ban operation at most once. The op-id claim,
    /// ban mutation, and operation-log append commit in one SQLite
    /// transaction, so the result survives a repository restart.
    pub async fn apply_strict_operation_once(
        &self,
        op: Arc<BanOperation>,
        strict_metadata: StrictReplicationMetadata,
    ) -> Result<StrictOperationApplyOutcome, io::Error> {
        let result = self
            .apply_strict_operation_inner(op, strict_metadata, true)
            .await;
        if result.is_err() {
            self.mark_strict_durability_failed();
        }
        result
    }

    /// Apply a strict protocol v5 delivery with its WAL metadata.
    ///
    /// The S2S terminal journal owns idempotency in v5. This transaction still
    /// persists the operation id and final timestamp with the WAL row for
    /// history replay, but it neither claims nor grows `ban_strict_op_ids`.
    pub async fn apply_strict_operation_v5(
        &self,
        op: Arc<BanOperation>,
        strict_metadata: StrictReplicationMetadata,
    ) -> Result<StrictOperationApplyOutcome, io::Error> {
        let result = self
            .apply_strict_operation_inner(op, strict_metadata, false)
            .await;
        if result.is_err() {
            self.mark_strict_durability_failed();
        }
        result
    }

    async fn apply_strict_operation_inner(
        &self,
        op: Arc<BanOperation>,
        strict_metadata: StrictReplicationMetadata,
        claim_legacy_operation_id: bool,
    ) -> Result<StrictOperationApplyOutcome, io::Error> {
        let sql_version = sql_i64_from_u64_io(op.version)?;
        let op_data = serde_json::to_string(&op.op).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("op serialisation error: {error}"),
            )
        })?;
        let strict_op_id_hi = sql_text_from_u64(strict_metadata.op_id_hi());
        let strict_op_id_lo = sql_text_from_u64(strict_metadata.op_id_lo());
        let strict_ts_final = sql_text_from_u64(strict_metadata.ts_final());

        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        if claim_legacy_operation_id {
            let claimed = tx
                .execute(
                    "INSERT OR IGNORE INTO ban_strict_op_ids (op_id_hi, op_id_lo, ts_final)
                     VALUES (?1, ?2, ?3)",
                    params![&strict_op_id_hi, &strict_op_id_lo, &strict_ts_final],
                )
                .map_err(sqlite_io_error)?;
            if claimed == 0 {
                tx.commit().map_err(sqlite_io_error)?;
                return Ok(StrictOperationApplyOutcome::AlreadyApplied);
            }
        }

        let current_version = durable_version_from_connection(&tx)?;
        if op.version <= current_version {
            tx.rollback().map_err(sqlite_io_error)?;
            return Ok(StrictOperationApplyOutcome::VersionConflict);
        }

        apply_op_to_db(&tx, &op.op).map_err(sqlite_io_error)?;
        tx.execute(
            "INSERT INTO ban_operations
                (version, node_id, timestamp, op_type, op_data,
                 strict_op_id_hi, strict_op_id_lo, strict_ts_final)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                sql_version,
                op.node_id,
                op.timestamp,
                op_type_str(&op.op),
                op_data,
                strict_op_id_hi,
                strict_op_id_lo,
                strict_ts_final,
            ],
        )
        .map_err(sqlite_io_error)?;
        tx.commit().map_err(sqlite_io_error)?;

        self.version.fetch_max(op.version, Ordering::AcqRel);
        self.history_freshness
            .fetch_max(op.timestamp, Ordering::AcqRel);
        self.apply_lookup_index(&op.op);
        Ok(StrictOperationApplyOutcome::Applied)
    }

    pub async fn install_s2s_snapshot(&self, version: u64, entries: Vec<BanEntry>, freshness: i64) {
        if let Err(error) = self
            .install_s2s_snapshot_with_strict_operation_ids(version, entries, freshness, Vec::new())
            .await
        {
            tracing::warn!(error = %error, "ban snapshot install failed");
        }
    }

    /// Install an S2S ban snapshot and atomically merge strict operation ids
    /// represented by it into the durable SQLite ledger.
    ///
    /// A replacement must retain every local strict operation id. Otherwise a
    /// merged ledger could suppress replay of an operation whose ban state was
    /// erased by the replacement snapshot.
    pub async fn install_s2s_snapshot_with_strict_operation_ids(
        &self,
        version: u64,
        entries: Vec<BanEntry>,
        freshness: i64,
        strict_operation_ids: Vec<StrictOperationId>,
    ) -> Result<(), io::Error> {
        self.install_s2s_snapshot_inner(version, entries, freshness, Some(strict_operation_ids))
            .await
    }

    /// Install a strict protocol v5 snapshot without consulting or modifying
    /// the legacy repository-owned applied-operation ledger.
    pub async fn install_s2s_snapshot_v5(
        &self,
        version: u64,
        entries: Vec<BanEntry>,
        freshness: i64,
    ) -> Result<(), io::Error> {
        self.install_s2s_snapshot_inner(version, entries, freshness, None)
            .await
    }

    async fn install_s2s_snapshot_inner(
        &self,
        version: u64,
        entries: Vec<BanEntry>,
        freshness: i64,
        strict_operation_ids: Option<Vec<StrictOperationId>>,
    ) -> Result<(), io::Error> {
        let mut conn = self.conn.lock();
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(error) => {
                self.mark_strict_durability_failed();
                return Err(sqlite_io_error(error));
            }
        };
        let durable_version = match durable_version_from_connection(&tx) {
            Ok(version) => version,
            Err(error) => {
                self.mark_strict_durability_failed();
                return Err(error);
            }
        };
        if version < durable_version {
            // The caller is behind this repository. Treat the stale snapshot
            // as an idempotent no-op so catchup can complete without replacing
            // newer durable state.
            return Ok(());
        }
        if let Some(strict_operation_ids) = strict_operation_ids.as_ref() {
            let incoming_operation_ids: HashSet<_> = strict_operation_ids.iter().cloned().collect();
            let local_operation_ids = match strict_operation_ids_from_connection(&tx) {
                Ok(operation_ids) => operation_ids,
                Err(error) => {
                    self.mark_strict_durability_failed();
                    return Err(error);
                }
            };
            let missing_operation_ids = local_operation_ids
                .into_iter()
                .filter(|operation_id| !incoming_operation_ids.contains(operation_id))
                .count();
            if missing_operation_ids != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "strict snapshot operation-id ledger is missing {missing_operation_ids} locally applied operation(s)"
                    ),
                ));
            }
        }
        let set_bans = BanOp::SetBans { entries };
        if let Err(error) = apply_op_to_db(&tx, &set_bans) {
            self.mark_strict_durability_failed();
            return Err(sqlite_io_error(error));
        }
        if let Some(strict_operation_ids) = strict_operation_ids {
            for operation_id in strict_operation_ids {
                if let Err(error) = tx.execute(
                    "INSERT OR IGNORE INTO ban_strict_op_ids (op_id_hi, op_id_lo, ts_final)
                     VALUES (?1, ?2, ?3)",
                    params![
                        sql_text_from_u64(operation_id.op_id_hi()),
                        sql_text_from_u64(operation_id.op_id_lo()),
                        "0",
                    ],
                ) {
                    self.mark_strict_durability_failed();
                    return Err(sqlite_io_error(error));
                }
            }
        }
        if let Err(error) = tx.execute(
            "INSERT INTO ban_snapshot_state (id, version, freshness)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                version = excluded.version,
                freshness = excluded.freshness",
            params![sql_text_from_u64(version), freshness],
        ) {
            self.mark_strict_durability_failed();
            return Err(sqlite_io_error(error));
        }
        if let Err(error) = tx.commit() {
            self.mark_strict_durability_failed();
            return Err(sqlite_io_error(error));
        }

        self.version.store(version, Ordering::Release);
        self.history_freshness.store(freshness, Ordering::Release);
        self.apply_lookup_index(&set_bans);
        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn apply_lookup_index(&self, op: &BanOp) {
        self.lookup_index.write().apply_op(op);
    }

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
        let result = {
            let mut conn = self.conn.lock();
            self.commit_locked(&mut conn, op)
        };
        match result {
            Ok(op) => {
                let _ = self.tx.send(op);
                Ok(())
            }
            Err(error) => {
                self.mark_strict_durability_failed();
                Err(error)
            }
        }
    }

    /// Commit an operation synchronously. The caller must hold `conn` lock.
    fn commit_locked(
        &self,
        conn: &mut Connection,
        op: BanOperation,
    ) -> Result<Arc<BanOperation>, io::Error> {
        self.commit_locked_with_metadata(conn, op, None)
    }

    fn commit_locked_with_metadata(
        &self,
        conn: &mut Connection,
        mut op: BanOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
    ) -> Result<Arc<BanOperation>, io::Error> {
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        let version = durable_version_from_connection(&tx)?
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ban version overflow"))?;
        op.version = version;
        let sql_version = sql_i64_from_u64_io(version)?;

        let op_data = serde_json::to_string(&op.op).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("op serialisation error: {e}"),
            )
        })?;
        let (strict_op_id_hi, strict_op_id_lo, strict_ts_final) = strict_metadata
            .map(|metadata| {
                (
                    Some(sql_text_from_u64(metadata.op_id_hi())),
                    Some(sql_text_from_u64(metadata.op_id_lo())),
                    Some(sql_text_from_u64(metadata.ts_final())),
                )
            })
            .unwrap_or((None, None, None));

        apply_op_to_db(&tx, &op.op).map_err(sqlite_io_error)?;
        tx.execute(
            "INSERT INTO ban_operations
                (version, node_id, timestamp, op_type, op_data,
                 strict_op_id_hi, strict_op_id_lo, strict_ts_final)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                sql_version,
                op.node_id,
                op.timestamp,
                op_type_str(&op.op),
                op_data,
                strict_op_id_hi,
                strict_op_id_lo,
                strict_ts_final,
            ],
        )
        .map_err(sqlite_io_error)?;
        tx.commit().map_err(sqlite_io_error)?;

        let op = Arc::new(op);
        self.version.store(version, Ordering::Release);
        self.history_freshness
            .fetch_max(op.timestamp, Ordering::AcqRel);
        self.apply_lookup_index(&op.op);
        Ok(op)
    }
}

// ─── Free functions ──────────────────────────────────────────────────────────

fn snapshot_version_from_connection(conn: &Connection) -> Result<u64, io::Error> {
    match conn.query_row(
        "SELECT version FROM ban_snapshot_state WHERE id = 1",
        [],
        |row| row.get::<_, String>(0),
    ) {
        Ok(version) => version.parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid ban snapshot version: {error}"),
            )
        }),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(error) => Err(sqlite_io_error(error)),
    }
}

fn snapshot_freshness_from_connection(conn: &Connection) -> Result<i64, io::Error> {
    match conn.query_row(
        "SELECT freshness FROM ban_snapshot_state WHERE id = 1",
        [],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(freshness) => Ok(freshness),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(error) => Err(sqlite_io_error(error)),
    }
}

fn durable_version_from_connection(conn: &Connection) -> Result<u64, io::Error> {
    let operation_version = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM ban_operations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(sql_u64_from_i64)
        .map_err(sqlite_io_error)?;
    Ok(operation_version.max(snapshot_version_from_connection(conn)?))
}

fn durable_freshness_from_connection(conn: &Connection) -> Result<i64, io::Error> {
    let operation_freshness = conn
        .query_row(
            "SELECT COALESCE(MAX(timestamp), 0) FROM ban_operations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_io_error)?;
    Ok(operation_freshness.max(snapshot_freshness_from_connection(conn)?))
}

fn strict_operation_ids_from_connection(
    conn: &Connection,
) -> Result<Vec<StrictOperationId>, io::Error> {
    let raw_operation_ids = {
        let mut stmt = conn
            .prepare(
                "SELECT op_id_hi, op_id_lo
                 FROM ban_strict_op_ids
                 ORDER BY op_id_hi ASC, op_id_lo ASC",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_io_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_io_error)?
    };

    raw_operation_ids
        .into_iter()
        .map(|(op_id_hi, op_id_lo)| {
            let op_id_hi = op_id_hi.parse::<u64>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid strict operation high id: {error}"),
                )
            })?;
            let op_id_lo = op_id_lo.parse::<u64>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid strict operation low id: {error}"),
                )
            })?;
            Ok(StrictOperationId::new(op_id_hi, op_id_lo))
        })
        .collect()
}

fn active_bans_from_connection(conn: &Connection, now: i64) -> Result<Vec<BanEntry>, io::Error> {
    let raw_entries = {
        let mut stmt = conn
            .prepare(
                "SELECT address, mask, name, hash, ban_certificate, ban_ip, reason, start, duration
                 FROM bans
                 WHERE duration = 0 OR (start + duration) > ?1",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map(params![now], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, i64>(5)? != 0,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })
            .map_err(sqlite_io_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_io_error)?
    };

    raw_entries
        .into_iter()
        .map(
            |(address, mask, name, hash, ban_certificate, ban_ip, reason, start, duration)| {
                let address = address.parse().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid ban address in strict snapshot: {error}"),
                    )
                })?;
                let mask = u8::try_from(mask).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid ban mask in strict snapshot: {error}"),
                    )
                })?;
                let duration = u64::try_from(duration).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid ban duration in strict snapshot: {error}"),
                    )
                })?;
                Ok(BanEntry {
                    address,
                    mask,
                    name,
                    hash,
                    ban_certificate,
                    ban_ip,
                    reason,
                    start,
                    duration,
                })
            },
        )
        .collect()
}

fn strict_log_entries_since_from_connection(
    conn: &Connection,
    since_version: i64,
) -> Result<Vec<BanLogEntry>, io::Error> {
    let raw_entries = {
        let mut stmt = conn
            .prepare(
                "SELECT version, node_id, timestamp, op_data,
                        CAST(strict_op_id_hi AS TEXT),
                        CAST(strict_op_id_lo AS TEXT),
                        CAST(strict_ts_final AS TEXT)
                 FROM ban_operations
                 WHERE version > ?1
                 ORDER BY version ASC",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map(params![since_version], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u16>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(sqlite_io_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_io_error)?
    };

    raw_entries
        .into_iter()
        .map(
            |(
                version,
                node_id,
                timestamp,
                op_data,
                strict_op_id_hi,
                strict_op_id_lo,
                strict_ts_final,
            )| {
                let version = u64::try_from(version).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid strict ban operation version: {error}"),
                    )
                })?;
                let op = serde_json::from_str(&op_data).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid strict ban operation payload: {error}"),
                    )
                })?;
                let strict_metadata = match (strict_op_id_hi, strict_op_id_lo, strict_ts_final) {
                    (None, None, None) => None,
                    (Some(op_id_hi), Some(op_id_lo), Some(ts_final)) => {
                        let op_id_hi = op_id_hi.parse::<u64>().map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid strict operation high id: {error}"),
                            )
                        })?;
                        let op_id_lo = op_id_lo.parse::<u64>().map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid strict operation low id: {error}"),
                            )
                        })?;
                        let ts_final = ts_final.parse::<u64>().map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid strict operation final timestamp: {error}"),
                            )
                        })?;
                        Some(StrictReplicationMetadata::new(op_id_hi, op_id_lo, ts_final))
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "incomplete strict ban operation metadata",
                        ));
                    }
                };
                Ok(BanLogEntry::new(
                    Arc::new(BanOperation {
                        version,
                        node_id,
                        timestamp,
                        op,
                    }),
                    strict_metadata,
                ))
            },
        )
        .collect()
}

/// Apply a `BanOp` to the database.
fn apply_op_to_db(conn: &Connection, op: &BanOp) -> Result<(), rusqlite::Error> {
    match op {
        BanOp::SetBans { entries } => {
            conn.execute("DELETE FROM bans", [])?;
            let mut stmt = conn.prepare(
                "INSERT INTO bans (address, mask, name, hash, ban_certificate, ban_ip, reason, start, duration)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for entry in entries {
                stmt.execute(params![
                    entry.address.to_string(),
                    entry.mask,
                    entry.name,
                    entry.hash,
                    entry.ban_certificate as i64,
                    entry.ban_ip as i64,
                    entry.reason,
                    entry.start,
                    sql_i64_from_u64(entry.duration)?,
                ])?;
            }
        }
        BanOp::AddBan { entry } => {
            conn.execute(
                "INSERT OR REPLACE INTO bans (address, mask, name, hash, ban_certificate, ban_ip, reason, start, duration)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    entry.address.to_string(),
                    entry.mask,
                    entry.name,
                    entry.hash,
                    entry.ban_certificate as i64,
                    entry.ban_ip as i64,
                    entry.reason,
                    entry.start,
                    sql_i64_from_u64(entry.duration)?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_index_matches_ip_certificate_and_asn_bans() {
        let now = 1_000;
        let index = BanLookupIndex::from_entries(vec![
            BanEntry {
                address: "198.51.100.0".parse().unwrap(),
                mask: 24,
                name: None,
                hash: None,
                ban_certificate: false,
                ban_ip: true,
                reason: None,
                start: now,
                duration: 0,
            },
            BanEntry {
                address: "192.0.2.1".parse().unwrap(),
                mask: 32,
                name: None,
                hash: Some("AbCd".to_owned()),
                ban_certificate: true,
                ban_ip: false,
                reason: None,
                start: now,
                duration: 0,
            },
            BanEntry {
                address: "192.0.2.2".parse().unwrap(),
                mask: 32,
                name: None,
                hash: Some("AS13335".to_owned()),
                ban_certificate: true,
                ban_ip: false,
                reason: None,
                start: now,
                duration: 0,
            },
        ]);

        assert!(index.is_ip_banned("198.51.100.42".parse().unwrap(), now));
        assert!(!index.is_ip_banned("198.51.101.42".parse().unwrap(), now));
        assert!(index.is_identity_banned(Some("aBcD"), None, now));
        assert!(!index.is_identity_banned(Some("AS13335"), None, now));
        assert!(index.has_active_asn_bans(now));
        assert!(index.is_asn_banned(13335, now));
        assert!(!index.is_asn_banned(15169, now));
        assert_eq!(asn_from_ban_hash("AS13335"), Some(13335));
        assert_eq!(asn_from_ban_hash("as13335"), None);
    }

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
                    ban_certificate: true,
                    ban_ip: true,
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

    #[tokio::test]
    async fn ban_operation_log_preserves_strict_metadata() {
        let repo = BanRepository::new_in_memory(1);
        let metadata = StrictReplicationMetadata::new(u64::MAX - 2, u64::MAX - 1, u64::MAX);
        let op = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: BanEntry {
                    address: "203.0.113.18".parse().unwrap(),
                    mask: 32,
                    name: Some("strict-ban".into()),
                    hash: None,
                    ban_certificate: true,
                    ban_ip: true,
                    reason: Some("metadata test".into()),
                    start: 123,
                    duration: 0,
                },
            },
        });

        repo.apply_remote_operation_with_metadata(op, Some(metadata))
            .await;

        let entries = repo.get_log_entries_since(0).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op().version, 1);
        assert_eq!(entries[0].strict_metadata(), Some(metadata));
    }

    fn test_ban(address: &str, reason: &str) -> BanEntry {
        BanEntry {
            address: address.parse().unwrap(),
            mask: 32,
            name: Some("strict-ban".into()),
            hash: None,
            ban_certificate: true,
            ban_ip: true,
            reason: Some(reason.into()),
            start: 123,
            duration: 0,
        }
    }

    #[tokio::test]
    async fn ban_identity_criteria_can_be_disabled_independently() {
        let repo = BanRepository::new_in_memory(1);
        repo.add_ban(BanEntry {
            address: "203.0.113.19".parse().unwrap(),
            mask: 32,
            name: None,
            hash: Some("certificate".into()),
            ban_certificate: false,
            ban_ip: false,
            reason: None,
            start: chrono::Utc::now().timestamp(),
            duration: 0,
        })
        .await
        .unwrap();

        assert!(!repo.is_banned("203.0.113.19".parse().unwrap()).await);
        let entries = repo.get_active_bans().await;
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].ban_certificate);
        assert!(!entries[0].ban_ip);
    }

    #[tokio::test]
    async fn reloaded_lookup_index_preserves_disabled_ban_criteria() {
        let temp = tempfile::tempdir().unwrap();
        {
            let repo = BanRepository::open(1, temp.path()).await.unwrap();
            repo.add_ban(BanEntry {
                address: "198.51.100.42".parse().unwrap(),
                mask: 32,
                name: None,
                hash: Some("not-a-ban".into()),
                ban_certificate: false,
                ban_ip: false,
                reason: None,
                start: chrono::Utc::now().timestamp(),
                duration: 0,
            })
            .await
            .unwrap();
        }

        let repo = BanRepository::open(1, temp.path()).await.unwrap();
        assert!(!repo.is_banned("198.51.100.42".parse().unwrap()).await);
        assert!(!repo.is_identity_banned(Some("not-a-ban"), None));
    }

    #[tokio::test]
    async fn committed_ban_operations_refresh_the_lookup_index() {
        let repo = BanRepository::new_in_memory(1);
        let entry = BanEntry {
            address: "198.51.100.0".parse().unwrap(),
            mask: 24,
            name: None,
            hash: Some("AS13335".into()),
            ban_certificate: true,
            ban_ip: true,
            reason: None,
            start: chrono::Utc::now().timestamp(),
            duration: 0,
        };

        repo.add_ban(entry.clone()).await.unwrap();
        assert!(repo.is_banned("198.51.100.42".parse().unwrap()).await);
        assert!(repo.has_active_asn_bans());
        assert!(repo.is_asn_banned(13335));

        repo.remove_ban(entry.address, entry.mask).await.unwrap();
        assert!(!repo.is_banned("198.51.100.42".parse().unwrap()).await);
        assert!(!repo.has_active_asn_bans());
    }

    #[tokio::test]
    async fn default_route_ip_bans_are_ignored_but_normal_cidrs_are_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let start = chrono::Utc::now().timestamp();
        {
            let repo = BanRepository::open(1, temp.path()).await.unwrap();
            repo.add_ban(BanEntry {
                address: "::".parse().unwrap(),
                mask: 0,
                name: None,
                hash: None,
                ban_certificate: false,
                ban_ip: true,
                reason: None,
                start,
                duration: 0,
            })
            .await
            .unwrap();
            repo.add_ban(BanEntry {
                address: "0.0.0.0".parse().unwrap(),
                mask: 0,
                name: None,
                hash: None,
                ban_certificate: false,
                ban_ip: true,
                reason: None,
                start,
                duration: 0,
            })
            .await
            .unwrap();
            repo.add_ban(BanEntry {
                address: "2001:db8:1234:5678::".parse().unwrap(),
                mask: 64,
                name: None,
                hash: None,
                ban_certificate: false,
                ban_ip: true,
                reason: None,
                start,
                duration: 0,
            })
            .await
            .unwrap();
            repo.add_ban(BanEntry {
                address: "198.51.100.0".parse().unwrap(),
                mask: 24,
                name: None,
                hash: None,
                ban_certificate: false,
                ban_ip: true,
                reason: None,
                start,
                duration: 0,
            })
            .await
            .unwrap();
        }

        let repo = BanRepository::open(1, temp.path()).await.unwrap();

        assert!(
            repo.is_banned("2001:db8:1234:5678::99".parse().unwrap())
                .await
        );
        assert!(
            !repo
                .is_banned("2603:8081:1607:f280:20d6:d7fb:ad37:3e22".parse().unwrap())
                .await
        );
        assert!(repo.is_banned("198.51.100.42".parse().unwrap()).await);
        assert!(!repo.is_banned("203.0.113.42".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn durable_storage_capability_tracks_repository_backing() {
        assert!(!BanRepository::new_in_memory(1).durable_storage_enabled());

        let temp = tempfile::tempdir().unwrap();
        let persisted = BanRepository::open(1, temp.path()).await.unwrap();
        assert!(persisted.durable_storage_enabled());
    }

    #[tokio::test]
    async fn strict_sqlite_transaction_failure_latches_durable_capability_off() {
        let temp = tempfile::tempdir().unwrap();
        let repo = BanRepository::open(1, temp.path()).await.unwrap();
        assert!(repo.durable_storage_enabled());
        repo.conn
            .lock()
            .execute_batch("PRAGMA query_only = ON;")
            .unwrap();

        let result = repo
            .apply_strict_operation_once(
                Arc::new(BanOperation {
                    version: 1,
                    node_id: 1,
                    timestamp: 123,
                    op: BanOp::AddBan {
                        entry: test_ban("203.0.113.30", "read-only transaction"),
                    },
                }),
                StrictReplicationMetadata::new(91, 92, 93),
            )
            .await;

        assert!(result.is_err());
        assert!(
            !repo.durable_storage_enabled(),
            "a failed strict SQLite transaction must clamp v2 until restart"
        );
    }

    #[tokio::test]
    async fn strict_sqlite_snapshot_failure_latches_durable_capability_off() {
        let temp = tempfile::tempdir().unwrap();
        let repo = BanRepository::open(1, temp.path()).await.unwrap();
        assert!(repo.durable_storage_enabled());
        repo.conn
            .lock()
            .execute_batch("PRAGMA query_only = ON;")
            .unwrap();

        let result = repo
            .install_s2s_snapshot_with_strict_operation_ids(
                1,
                vec![test_ban("203.0.113.80", "snapshot")],
                123,
                Vec::new(),
            )
            .await;

        assert!(result.is_err());
        assert!(repo.strict_durability_failure_observed());
        assert!(
            !repo.durable_storage_enabled(),
            "a failed strict SQLite snapshot transaction must clamp v2 until restart"
        );
    }

    #[tokio::test]
    async fn strict_ban_op_id_survives_restart_and_prevents_replay() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = StrictReplicationMetadata::new(101, 202, 303);

        {
            let repo = BanRepository::open(1, temp.path()).await.unwrap();
            let first = Arc::new(BanOperation {
                version: 1,
                node_id: 1,
                timestamp: 123,
                op: BanOp::AddBan {
                    entry: test_ban("203.0.113.31", "first"),
                },
            });
            assert_eq!(
                repo.apply_strict_operation_once(first, metadata)
                    .await
                    .unwrap(),
                StrictOperationApplyOutcome::Applied
            );
        }

        let repo = BanRepository::open(1, temp.path()).await.unwrap();
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![StrictOperationId::new(101, 202)]
        );
        let duplicate = Arc::new(BanOperation {
            version: 2,
            node_id: 1,
            timestamp: 124,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.32", "replayed"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                duplicate,
                StrictReplicationMetadata::new(101, 202, 999),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::AlreadyApplied
        );
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.get_log_entries_since(0).await.len(), 1);
        let active_bans = repo.get_active_bans().await;
        assert_eq!(active_bans.len(), 1);
        assert_eq!(
            active_bans[0].address,
            "203.0.113.31".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn v5_strict_apply_does_not_grow_the_legacy_compatibility_ledger() {
        let temp = tempfile::tempdir().unwrap();
        {
            let repo = BanRepository::open(1, temp.path()).await.unwrap();
            repo.merge_strict_operation_ids(&[StrictOperationId::new(101, 202)])
                .unwrap();

            let operation = Arc::new(BanOperation {
                version: 1,
                node_id: 1,
                timestamp: 123,
                op: BanOp::AddBan {
                    entry: test_ban("203.0.113.33", "v5"),
                },
            });
            assert_eq!(
                repo.apply_strict_operation_v5(
                    operation,
                    StrictReplicationMetadata::new(301, 302, 303),
                )
                .await
                .unwrap(),
                StrictOperationApplyOutcome::Applied
            );
            assert_eq!(
                repo.strict_operation_ids().unwrap(),
                vec![StrictOperationId::new(101, 202)],
                "v5 delivery must not add repository-owned applied-operation rows"
            );
        }
        let repo = BanRepository::open(1, temp.path()).await.unwrap();
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![StrictOperationId::new(101, 202)],
            "the one-time legacy backfill must not import v5 WAL metadata"
        );

        let (version, entries, freshness, operation_ids) =
            repo.strict_snapshot_v5().unwrap().into_parts();
        assert_eq!(version, 1);
        assert_eq!(entries, vec![test_ban("203.0.113.33", "v5")]);
        assert_eq!(freshness, 123);
        assert_eq!(operation_ids, vec![StrictOperationId::new(101, 202)]);
    }

    #[tokio::test]
    async fn v5_snapshot_install_preserves_legacy_ledger_rows() {
        let repo = BanRepository::new_in_memory(1);
        let legacy_id = StrictOperationId::new(401, 402);
        repo.merge_strict_operation_ids(std::slice::from_ref(&legacy_id))
            .unwrap();

        repo.install_s2s_snapshot_v5(7, vec![test_ban("203.0.113.34", "v5-snapshot")], 456)
            .await
            .unwrap();

        assert_eq!(repo.current_version(), 7);
        assert_eq!(repo.strict_operation_ids().unwrap(), vec![legacy_id]);
        assert_eq!(
            repo.get_active_bans().await,
            vec![test_ban("203.0.113.34", "v5-snapshot")]
        );
    }

    #[tokio::test]
    async fn concurrent_strict_ban_operations_claim_one_op_id() {
        let repo = BanRepository::new_in_memory(1);
        let metadata = StrictReplicationMetadata::new(301, 302, 303);
        let op = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.35", "once"),
            },
        });

        let (first, second) = tokio::join!(
            repo.apply_strict_operation_once(Arc::clone(&op), metadata),
            repo.apply_strict_operation_once(op, metadata),
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == StrictOperationApplyOutcome::Applied)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == StrictOperationApplyOutcome::AlreadyApplied)
                .count(),
            1
        );
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.get_log_entries_since(0).await.len(), 1);
    }

    #[tokio::test]
    async fn strict_ban_version_conflict_does_not_claim_the_operation_id() {
        let repo = BanRepository::new_in_memory(1);
        let first = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.36", "first"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(first, StrictReplicationMetadata::new(401, 402, 1))
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let conflict = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 124,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.37", "conflict"),
            },
        });
        let conflicting_id = StrictReplicationMetadata::new(403, 404, 2);
        assert_eq!(
            repo.apply_strict_operation_once(Arc::clone(&conflict), conflicting_id)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::VersionConflict
        );
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![StrictOperationId::new(401, 402)]
        );

        let retry = Arc::new(BanOperation {
            version: 2,
            ..(*conflict).clone()
        });
        assert_eq!(
            repo.apply_strict_operation_once(retry, conflicting_id)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );
        assert_eq!(repo.current_version(), 2);
        assert_eq!(repo.get_active_bans().await.len(), 2);
    }

    #[tokio::test]
    async fn strict_snapshot_captures_state_version_freshness_and_ledger_together() {
        let repo = BanRepository::new_in_memory(1);
        let first_metadata = StrictReplicationMetadata::new(601, 602, 1);
        let first = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.51", "first"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(first, first_metadata)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let (version, entries, freshness, operation_ids) =
            repo.strict_snapshot().unwrap().into_parts();
        assert_eq!(version, 1);
        assert_eq!(freshness, 123);
        assert_eq!(entries, vec![test_ban("203.0.113.51", "first")]);
        assert_eq!(operation_ids, vec![StrictOperationId::new(601, 602)]);

        let second = Arc::new(BanOperation {
            version: 2,
            node_id: 1,
            timestamp: 124,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.52", "second"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(second, StrictReplicationMetadata::new(603, 604, 2))
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let (version, entries, freshness, operation_ids) =
            repo.strict_snapshot().unwrap().into_parts();
        assert_eq!(version, 2);
        assert_eq!(freshness, 124);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            operation_ids,
            vec![
                StrictOperationId::new(601, 602),
                StrictOperationId::new(603, 604),
            ]
        );
    }

    #[test]
    fn strict_snapshot_rejects_a_malformed_operation_id_ledger() {
        let repo = BanRepository::new_in_memory(1);
        {
            let conn = repo.conn.lock();
            conn.execute(
                "INSERT INTO ban_strict_op_ids (op_id_hi, op_id_lo, ts_final)
                 VALUES (?1, ?2, ?3)",
                params!["not-a-number", "2", "0"],
            )
            .unwrap();
        }

        let error = repo.strict_snapshot().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn ban_snapshot_merges_strict_operation_ids() {
        let temp = tempfile::tempdir().unwrap();
        let operation_id = StrictOperationId::new(501, 502);
        {
            let repo = BanRepository::open(1, temp.path()).await.unwrap();
            repo.install_s2s_snapshot_with_strict_operation_ids(
                7,
                vec![test_ban("203.0.113.41", "snapshot")],
                123,
                vec![operation_id.clone()],
            )
            .await
            .unwrap();
        }

        let repo = BanRepository::open(1, temp.path()).await.unwrap();
        assert_eq!(repo.current_version(), 7);
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![operation_id.clone()]
        );
        let (snapshot_version, snapshot_entries, snapshot_freshness, snapshot_operation_ids) =
            repo.strict_snapshot().unwrap().into_parts();
        assert_eq!(snapshot_version, 7);
        assert_eq!(snapshot_entries, vec![test_ban("203.0.113.41", "snapshot")]);
        assert_eq!(snapshot_freshness, 123);
        assert_eq!(
            snapshot_operation_ids,
            vec![StrictOperationId::new(501, 502)]
        );

        let unknown_id_at_snapshot_version = Arc::new(BanOperation {
            version: 7,
            node_id: 1,
            timestamp: 124,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.43", "conflict"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                unknown_id_at_snapshot_version,
                StrictReplicationMetadata::new(503, 504, 1),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::VersionConflict
        );
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![operation_id.clone()]
        );

        let duplicate = Arc::new(BanOperation {
            version: 8,
            node_id: 1,
            timestamp: 124,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.42", "replayed"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                duplicate,
                StrictReplicationMetadata::new(501, 502, 1),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::AlreadyApplied
        );
        let active_bans = repo.get_active_bans().await;
        assert_eq!(active_bans.len(), 1);
        assert_eq!(
            active_bans[0].address,
            "203.0.113.41".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn strict_snapshot_rejects_an_equal_version_replacement_missing_a_local_operation_id() {
        let temp = tempfile::tempdir().unwrap();
        let repo = BanRepository::open(1, temp.path()).await.unwrap();
        assert!(repo.durable_storage_enabled());
        let local_operation_id = StrictOperationId::new(801, 802);
        let local = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.81", "local"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                local,
                StrictReplicationMetadata::new(
                    local_operation_id.op_id_hi(),
                    local_operation_id.op_id_lo(),
                    1,
                ),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let error = repo
            .install_s2s_snapshot_with_strict_operation_ids(
                1,
                vec![test_ban("203.0.113.82", "replacement")],
                124,
                vec![StrictOperationId::new(803, 804)],
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(repo.current_version(), 1);
        assert_eq!(
            repo.get_active_bans().await,
            vec![test_ban("203.0.113.81", "local")]
        );
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![local_operation_id]
        );
        assert!(repo.durable_storage_enabled());
        assert!(!repo.strict_durability_failure_observed());
    }

    #[tokio::test]
    async fn strict_snapshot_rejects_a_newer_replacement_missing_a_local_operation_id() {
        let repo = BanRepository::new_in_memory(1);
        let local_operation_id = StrictOperationId::new(805, 806);
        let local = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 125,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.85", "local"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                local,
                StrictReplicationMetadata::new(
                    local_operation_id.op_id_hi(),
                    local_operation_id.op_id_lo(),
                    1,
                ),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );
        let before = repo.strict_snapshot().unwrap();

        let error = repo
            .install_s2s_snapshot_with_strict_operation_ids(
                2,
                vec![test_ban("203.0.113.86", "replacement")],
                126,
                vec![StrictOperationId::new(807, 808)],
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let after = repo.strict_snapshot().unwrap();
        assert_eq!(after.into_parts(), before.into_parts());
        assert_eq!(
            repo.get_active_bans().await,
            vec![test_ban("203.0.113.85", "local")]
        );
    }

    #[tokio::test]
    async fn strict_snapshot_accepts_a_newer_replacement_with_a_superset_ledger() {
        let repo = BanRepository::new_in_memory(1);
        let local_operation_id = StrictOperationId::new(811, 812);
        let local = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 127,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.87", "local"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                local,
                StrictReplicationMetadata::new(
                    local_operation_id.op_id_hi(),
                    local_operation_id.op_id_lo(),
                    1,
                ),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let incoming_operation_id = StrictOperationId::new(813, 814);
        repo.install_s2s_snapshot_with_strict_operation_ids(
            2,
            vec![test_ban("203.0.113.88", "replacement")],
            128,
            vec![local_operation_id.clone(), incoming_operation_id.clone()],
        )
        .await
        .unwrap();

        assert_eq!(repo.current_version(), 2);
        assert_eq!(
            repo.get_active_bans().await,
            vec![test_ban("203.0.113.88", "replacement")]
        );
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![local_operation_id, incoming_operation_id]
        );
    }

    #[tokio::test]
    async fn strict_log_requires_a_snapshot_below_the_installed_history_floor() {
        let repo = BanRepository::new_in_memory(1);
        repo.install_s2s_snapshot_with_strict_operation_ids(
            7,
            vec![test_ban("203.0.113.61", "snapshot")],
            123,
            vec![StrictOperationId::new(701, 702)],
        )
        .await
        .unwrap();

        assert!(repo.strict_log_entries_since(0).await.is_none());
        assert!(repo.strict_log_entries_since(6).await.is_none());
        assert!(repo.strict_log_entries_since(7).await.unwrap().is_empty());

        let increment = Arc::new(BanOperation {
            version: 8,
            node_id: 1,
            timestamp: 124,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.62", "increment"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                increment,
                StrictReplicationMetadata::new(703, 704, 2)
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        assert!(repo.strict_log_entries_since(0).await.is_none());
        let entries = repo.strict_log_entries_since(7).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op().version, 8);
    }

    #[tokio::test]
    async fn stale_snapshot_install_is_a_noop_against_newer_durable_state() {
        let repo = BanRepository::new_in_memory(1);
        let committed = Arc::new(BanOperation {
            version: 1,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: test_ban("203.0.113.71", "committed"),
            },
        });
        assert_eq!(
            repo.apply_strict_operation_once(
                committed,
                StrictReplicationMetadata::new(801, 802, 1)
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        repo.install_s2s_snapshot_with_strict_operation_ids(
            0,
            vec![test_ban("203.0.113.72", "stale")],
            1,
            vec![StrictOperationId::new(803, 804)],
        )
        .await
        .unwrap();
        assert_eq!(repo.current_version(), 1);
        assert_eq!(
            repo.get_active_bans().await,
            vec![test_ban("203.0.113.71", "committed")]
        );
        assert_eq!(
            repo.strict_operation_ids().unwrap(),
            vec![StrictOperationId::new(801, 802)]
        );
    }
}
