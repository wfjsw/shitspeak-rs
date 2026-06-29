use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::acl::ACLPermissions;
use crate::client::{Client, ClientTransportKind};
use crate::server::Server;

const CACHE_DB_FILE_NAME: &str = "user_channel_cache.db";
const LEGACY_CACHE_FILE_NAME: &str = "user_channel_cache.json";
const LAST_CHANNEL_TTL_DAYS: i64 = 30;
const LISTENING_CHANNEL_TTL_HOURS: i64 = 6;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachedUserChannels {
    pub last_channel_id: Option<u32>,
    pub listening_channel_ids: Vec<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoginChannelRestore {
    pub current_channel_id: u32,
    pub listening_channel_ids: Vec<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct UserChannelCacheEntry {
    #[serde(default)]
    last_channel_id: Option<u32>,
    #[serde(default)]
    last_channel_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    listening_channel_ids: Vec<u32>,
    #[serde(default)]
    listening_channel_expires_at: Option<DateTime<Utc>>,
}

pub struct UserChannelCache {
    conn: Mutex<Connection>,
}

impl UserChannelCache {
    pub async fn open(storage_dir: &Path) -> io::Result<Arc<Self>> {
        tokio::fs::create_dir_all(storage_dir).await?;
        let db_path = storage_dir.join(CACHE_DB_FILE_NAME);
        let mut conn = Connection::open(&db_path).map_err(|error| {
            sqlite_io_error(
                &format!("open user channel cache database {}", db_path.display()),
                error,
            )
        })?;
        configure_connection(&conn, true)
            .map_err(|error| sqlite_io_error("configure user channel cache database", error))?;
        init_schema(&conn)
            .map_err(|error| sqlite_io_error("initialize user channel cache database", error))?;
        import_legacy_json_cache(&mut conn, &storage_dir.join(LEGACY_CACHE_FILE_NAME)).await?;
        prune_expired_rows(&conn, Utc::now())
            .map_err(|error| sqlite_io_error("prune user channel cache database", error))?;

        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
        }))
    }

    pub fn new_in_memory() -> Arc<Self> {
        let conn = Connection::open_in_memory().expect("in-memory SQLite should always open");
        configure_connection(&conn, false).expect("in-memory SQLite should configure");
        init_schema(&conn).expect("in-memory SQLite schema should initialize");
        Arc::new(Self {
            conn: Mutex::new(conn),
        })
    }

    pub async fn get(&self, key: &str) -> Option<CachedUserChannels> {
        let now = Utc::now();
        let conn = self.conn.lock();
        match load_entry(&conn, key) {
            Ok(Some(entry)) => entry.cached_channels_at(now),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    cache_key = key,
                    error = %error,
                    "failed to read user channel cache"
                );
                None
            }
        }
    }

    pub async fn remember_last_channel(&self, key: &str, channel_id: u32) -> io::Result<()> {
        let now = Utc::now();
        let expires_at = now + Duration::days(LAST_CHANNEL_TTL_DAYS);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO user_channel_cache (
                cache_key,
                last_channel_id,
                last_channel_expires_at,
                listening_channel_expires_at,
                updated_at
            ) VALUES (?1, ?2, ?3, NULL, ?4)
            ON CONFLICT(cache_key) DO UPDATE SET
                last_channel_id = excluded.last_channel_id,
                last_channel_expires_at = excluded.last_channel_expires_at,
                updated_at = excluded.updated_at",
            params![
                key,
                i64::from(channel_id),
                expires_at.timestamp_millis(),
                now.timestamp_millis(),
            ],
        )
        .and_then(|_| prune_expired_rows(&conn, now))
        .map_err(|error| sqlite_io_error("store user last channel cache", error))
    }

    pub async fn remember_listening_channels<I>(&self, key: &str, channels: I) -> io::Result<()>
    where
        I: IntoIterator<Item = u32>,
    {
        let now = Utc::now();
        let channel_ids: Vec<u32> = channels
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let listening_expires_at = if channel_ids.is_empty() {
            None
        } else {
            Some(now + Duration::hours(LISTENING_CHANNEL_TTL_HOURS))
        };
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction()
            .map_err(|error| sqlite_io_error("begin user channel cache transaction", error))?;
        tx.execute(
            "INSERT INTO user_channel_cache (
                cache_key,
                last_channel_id,
                last_channel_expires_at,
                listening_channel_expires_at,
                updated_at
            ) VALUES (?1, NULL, NULL, ?2, ?3)
            ON CONFLICT(cache_key) DO UPDATE SET
                listening_channel_expires_at = excluded.listening_channel_expires_at,
                updated_at = excluded.updated_at",
            params![
                key,
                listening_expires_at.map(|expires_at| expires_at.timestamp_millis()),
                now.timestamp_millis(),
            ],
        )
        .and_then(|_| {
            tx.execute(
                "DELETE FROM user_channel_listening_channels WHERE cache_key = ?1",
                params![key],
            )
        })
        .map_err(|error| sqlite_io_error("store user listening channel cache", error))?;
        {
            let mut insert = tx
                .prepare(
                    "INSERT OR IGNORE INTO user_channel_listening_channels
                        (cache_key, channel_id)
                     VALUES (?1, ?2)",
                )
                .map_err(|error| sqlite_io_error("prepare user listening channel cache", error))?;
            for channel_id in &channel_ids {
                insert
                    .execute(params![key, i64::from(*channel_id)])
                    .map_err(|error| {
                        sqlite_io_error("store user listening channel cache", error)
                    })?;
            }
        }
        prune_expired_rows(&tx, now)
            .map_err(|error| sqlite_io_error("prune user channel cache database", error))?;
        tx.commit()
            .map_err(|error| sqlite_io_error("commit user channel cache transaction", error))
    }
}

fn sqlite_io_error(action: &str, error: rusqlite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{action}: {error}"))
}

fn configure_connection(conn: &Connection, persistent: bool) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    if persistent {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
    }
    Ok(())
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_channel_cache (
            cache_key TEXT PRIMARY KEY NOT NULL,
            last_channel_id INTEGER,
            last_channel_expires_at INTEGER,
            listening_channel_expires_at INTEGER,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_channel_listening_channels (
            cache_key TEXT NOT NULL,
            channel_id INTEGER NOT NULL,
            PRIMARY KEY (cache_key, channel_id),
            FOREIGN KEY (cache_key)
                REFERENCES user_channel_cache(cache_key)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_channel_cache_metadata (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_user_channel_cache_last_expires
            ON user_channel_cache(last_channel_expires_at);
        CREATE INDEX IF NOT EXISTS idx_user_channel_cache_listening_expires
            ON user_channel_cache(listening_channel_expires_at);",
    )
}

async fn import_legacy_json_cache(conn: &mut Connection, path: &Path) -> io::Result<()> {
    if legacy_import_was_attempted(conn)
        .map_err(|error| sqlite_io_error("read user channel cache migration marker", error))?
    {
        return Ok(());
    }

    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    let mut entries = match serde_json::from_slice::<HashMap<String, UserChannelCacheEntry>>(&bytes)
    {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "ignoring unreadable legacy user channel cache"
            );
            return Ok(());
        }
    };
    let now = Utc::now();
    prune_entries_at(&mut entries, now);

    let tx = conn
        .transaction()
        .map_err(|error| sqlite_io_error("begin user channel cache migration", error))?;
    for (key, entry) in entries {
        store_entry(&tx, &key, &entry, now)
            .map_err(|error| sqlite_io_error("import legacy user channel cache", error))?;
    }
    mark_legacy_import_attempted(&tx)
        .map_err(|error| sqlite_io_error("mark user channel cache migration", error))?;
    tx.commit()
        .map_err(|error| sqlite_io_error("commit user channel cache migration", error))?;
    tracing::info!(
        path = %path.display(),
        "imported legacy user channel cache into SQLite"
    );
    Ok(())
}

fn legacy_import_was_attempted(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT value FROM user_channel_cache_metadata WHERE key = 'legacy_json_imported'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map(|value| value.is_some())
}

fn mark_legacy_import_attempted(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO user_channel_cache_metadata (key, value)
         VALUES ('legacy_json_imported', '1')",
        [],
    )?;
    Ok(())
}

fn store_entry(
    conn: &Connection,
    key: &str,
    entry: &UserChannelCacheEntry,
    now: DateTime<Utc>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO user_channel_cache (
            cache_key,
            last_channel_id,
            last_channel_expires_at,
            listening_channel_expires_at,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key,
            entry.last_channel_id.map(i64::from),
            entry
                .last_channel_expires_at
                .map(|expires_at| expires_at.timestamp_millis()),
            entry
                .listening_channel_expires_at
                .map(|expires_at| expires_at.timestamp_millis()),
            now.timestamp_millis(),
        ],
    )?;
    conn.execute(
        "DELETE FROM user_channel_listening_channels WHERE cache_key = ?1",
        params![key],
    )?;
    let mut insert = conn.prepare(
        "INSERT OR IGNORE INTO user_channel_listening_channels (cache_key, channel_id)
         VALUES (?1, ?2)",
    )?;
    for channel_id in &entry.listening_channel_ids {
        insert.execute(params![key, i64::from(*channel_id)])?;
    }
    Ok(())
}

fn load_entry(conn: &Connection, key: &str) -> rusqlite::Result<Option<UserChannelCacheEntry>> {
    let row = conn
        .query_row(
            "SELECT last_channel_id, last_channel_expires_at, listening_channel_expires_at
             FROM user_channel_cache
             WHERE cache_key = ?1",
            params![key],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((last_channel_id, last_channel_expires_at, listening_channel_expires_at)) = row else {
        return Ok(None);
    };

    let mut stmt = conn.prepare(
        "SELECT channel_id
         FROM user_channel_listening_channels
         WHERE cache_key = ?1
         ORDER BY channel_id ASC",
    )?;
    let channels = stmt.query_map(params![key], |row| row.get::<_, i64>(0))?;
    let listening_channel_ids = channels
        .filter_map(Result::ok)
        .filter_map(sql_u32_from_i64)
        .collect();

    Ok(Some(UserChannelCacheEntry {
        last_channel_id: last_channel_id.and_then(sql_u32_from_i64),
        last_channel_expires_at: last_channel_expires_at.and_then(datetime_from_sql_millis),
        listening_channel_ids,
        listening_channel_expires_at: listening_channel_expires_at
            .and_then(datetime_from_sql_millis),
    }))
}

fn prune_expired_rows(conn: &Connection, now: DateTime<Utc>) -> rusqlite::Result<()> {
    let now = now.timestamp_millis();
    conn.execute(
        "UPDATE user_channel_cache
         SET last_channel_id = NULL,
             last_channel_expires_at = NULL
         WHERE last_channel_expires_at IS NULL
            OR last_channel_expires_at <= ?1",
        params![now],
    )?;
    conn.execute(
        "UPDATE user_channel_cache
         SET listening_channel_expires_at = NULL
         WHERE listening_channel_expires_at IS NULL
            OR listening_channel_expires_at <= ?1",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM user_channel_listening_channels
         WHERE cache_key IN (
            SELECT cache_key
            FROM user_channel_cache
            WHERE listening_channel_expires_at IS NULL
         )",
        [],
    )?;
    conn.execute(
        "DELETE FROM user_channel_cache
         WHERE last_channel_id IS NULL
           AND NOT EXISTS (
                SELECT 1
                FROM user_channel_listening_channels channels
                WHERE channels.cache_key = user_channel_cache.cache_key
           )",
        [],
    )?;
    Ok(())
}

fn sql_u32_from_i64(value: i64) -> Option<u32> {
    u32::try_from(value).ok()
}

fn datetime_from_sql_millis(value: i64) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp_millis(value)
}

impl UserChannelCacheEntry {
    fn cached_channels_at(&self, now: DateTime<Utc>) -> Option<CachedUserChannels> {
        let last_channel_id = match self.last_channel_expires_at {
            Some(expires_at) if expires_at > now => self.last_channel_id,
            _ => None,
        };
        let listening_channel_ids = match self.listening_channel_expires_at {
            Some(expires_at) if expires_at > now => self.listening_channel_ids.clone(),
            _ => Vec::new(),
        };

        if last_channel_id.is_none() && listening_channel_ids.is_empty() {
            None
        } else {
            Some(CachedUserChannels {
                last_channel_id,
                listening_channel_ids,
            })
        }
    }

    fn prune_at(&mut self, now: DateTime<Utc>) {
        if !matches!(self.last_channel_expires_at, Some(expires_at) if expires_at > now) {
            self.last_channel_id = None;
            self.last_channel_expires_at = None;
        }
        if !matches!(self.listening_channel_expires_at, Some(expires_at) if expires_at > now) {
            self.listening_channel_ids.clear();
            self.listening_channel_expires_at = None;
        }
    }

    fn has_cached_channels(&self) -> bool {
        self.last_channel_id.is_some() || !self.listening_channel_ids.is_empty()
    }
}

pub fn user_channel_cache_key(user_id: Option<u32>, username: Option<&str>) -> Option<String> {
    match user_id {
        Some(user_id) => Some(user_id.to_string()),
        None => username
            .filter(|username| !username.is_empty())
            .map(ToOwned::to_owned),
    }
}

pub async fn cache_key_for_client(client: &Client) -> Option<String> {
    let user_id = client.get_user_id();
    if user_id.is_some() {
        return user_channel_cache_key(user_id, None);
    }
    if client.transport_kind() == ClientTransportKind::Remote {
        return None;
    }

    let username = {
        let user_info = client.user_info_extended().await;
        user_info
            .get_credential()
            .as_ref()
            .map(|credential| credential.username.clone())
    };
    user_channel_cache_key(None, username.as_deref())
}

pub async fn resolve_login_channels(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    cache_key: Option<&str>,
) -> LoginChannelRestore {
    let cached_channels = match cache_key {
        Some(key) => server.get_user_channel_cache().get(key).await,
        None => None,
    };
    let server_id = client.server_id();
    let cached_last_channel_id = cached_channels
        .as_ref()
        .and_then(|channels| channels.last_channel_id);
    let current_channel_id =
        resolve_current_channel(server, client, &server_id, cached_last_channel_id).await;
    let listening_channel_ids = match cached_channels {
        Some(channels) => {
            resolve_listening_channels(server, client, &server_id, &channels.listening_channel_ids)
                .await
        }
        None => Vec::new(),
    };

    LoginChannelRestore {
        current_channel_id,
        listening_channel_ids,
    }
}

pub async fn resolve_forced_move_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    first_candidate_channel_id: u32,
) -> u32 {
    let server_id = client.server_id();
    let channel_candidates =
        forced_move_candidates(server, &server_id, first_candidate_channel_id).await;

    for channel_id in channel_candidates {
        if can_enter_channel(server, client, channel_id).await {
            return channel_id;
        }
    }

    let default_channel = existing_default_channel(server, &server_id).await;
    if default_channel != first_candidate_channel_id
        && can_enter_channel(server, client, default_channel).await
    {
        return default_channel;
    }

    if default_channel != 0 && can_enter_channel(server, client, 0).await {
        return 0;
    }

    default_channel
}

pub async fn move_local_client_to_forced_fallback(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    first_candidate_channel_id: u32,
    channel_version: u64,
) -> Option<u32> {
    let target_channel =
        resolve_forced_move_channel(server, client, first_candidate_channel_id).await;
    if target_channel == client.get_current_channel_id() {
        return None;
    }

    let repo = server.get_clients();
    client.set_current_channel_id(target_channel, repo, channel_version);
    Some(target_channel)
}

pub async fn move_local_clients_out_of_pending_delete(
    server: &Arc<Box<Server>>,
    server_id: &str,
    channel_id: u32,
    nonce: u64,
    fallback_channel_id: u32,
    channel_version: u64,
) -> usize {
    let subtree = server
        .get_channels()
        .pending_delete_subtree_set_in_server(server_id, channel_id, nonce)
        .await;
    if subtree.is_empty() {
        return 0;
    }

    let mut moved = 0;
    for client in server
        .get_clients()
        .get_local_clients_in_server(server_id)
        .await
    {
        if !subtree.contains(&client.get_current_channel_id()) {
            continue;
        }

        let channel_cache_key = cache_key_for_client(client.as_ref()).await;
        let target_channel = move_local_client_to_forced_fallback(
            server,
            &client,
            fallback_channel_id,
            channel_version,
        )
        .await;

        if let (Some(cache_key), Some(target_channel)) =
            (channel_cache_key.as_deref(), target_channel)
        {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_last_channel(cache_key, target_channel)
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key,
                    "failed to stage user last channel cache"
                );
            }
        }
        moved += 1;
    }

    moved
}

async fn resolve_current_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    server_id: &str,
    cached_channel_id: Option<u32>,
) -> u32 {
    if let Some(channel_id) = cached_channel_id {
        if let Some(channel_id) =
            usable_cached_current_channel(server, client, server_id, channel_id).await
        {
            return channel_id;
        }
    }

    existing_default_channel(server, server_id).await
}

async fn usable_cached_current_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    server_id: &str,
    channel_id: u32,
) -> Option<u32> {
    let channel_id = server
        .get_channels()
        .redirect_pending_delete_target_in_server(server_id, channel_id)
        .await;
    server
        .get_channels()
        .get_channel_in_server(server_id, channel_id)
        .await?;
    if can_enter_channel(server, client, channel_id).await {
        Some(channel_id)
    } else {
        None
    }
}

async fn forced_move_candidates(
    server: &Arc<Box<Server>>,
    server_id: &str,
    first_candidate_channel_id: u32,
) -> Vec<u32> {
    let mut candidates = Vec::new();
    let mut current = server
        .get_channels()
        .redirect_pending_delete_target_in_server(server_id, first_candidate_channel_id)
        .await;

    loop {
        if !candidates.contains(&current) {
            candidates.push(current);
        }
        let Some(channel) = server
            .get_channels()
            .get_channel_in_server(server_id, current)
            .await
        else {
            break;
        };
        let Some(parent_id) = channel.parent_id else {
            break;
        };
        current = parent_id;
    }

    candidates
}

async fn existing_default_channel(server: &Arc<Box<Server>>, server_id: &str) -> u32 {
    let default_channel = server.get_default_channel();
    let target_channel = if server
        .get_channels()
        .get_channel_in_server(server_id, default_channel)
        .await
        .is_some()
    {
        default_channel
    } else {
        0
    };

    server
        .get_channels()
        .redirect_pending_delete_target_in_server(server_id, target_channel)
        .await
}

async fn can_enter_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> bool {
    let permissions =
        crate::client::acl::compute_permissions_for_client(server, client, channel_id).await;
    permissions.contains(ACLPermissions::Traverse) && permissions.contains(ACLPermissions::Enter)
}

async fn resolve_listening_channels(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    server_id: &str,
    channel_ids: &[u32],
) -> Vec<u32> {
    let mut seen = BTreeSet::new();
    let mut restored = Vec::new();

    for channel_id in channel_ids {
        let channel_id = server
            .get_channels()
            .redirect_pending_delete_target_in_server(server_id, *channel_id)
            .await;
        if !seen.insert(channel_id) {
            continue;
        }
        if server
            .get_channels()
            .get_channel_in_server(server_id, channel_id)
            .await
            .is_none()
        {
            continue;
        }

        let permissions =
            crate::client::acl::compute_permissions_for_client(server, client, channel_id).await;
        if permissions.contains(ACLPermissions::Traverse)
            && permissions.contains(ACLPermissions::Listen)
        {
            restored.push(channel_id);
        }
    }

    restored
}

fn prune_entries_at(entries: &mut HashMap<String, UserChannelCacheEntry>, now: DateTime<Utc>) {
    entries.retain(|_, entry| {
        entry.prune_at(now);
        entry.has_cached_channels()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_prefers_user_id() {
        assert_eq!(
            user_channel_cache_key(Some(42), Some("alice")),
            Some("42".to_owned())
        );
        assert_eq!(
            user_channel_cache_key(None, Some("alice")),
            Some("alice".to_owned())
        );
        assert_eq!(user_channel_cache_key(None, None), None);
    }

    #[test]
    fn entry_respects_independent_ttls() {
        let now = Utc::now();
        let entry = UserChannelCacheEntry {
            last_channel_id: Some(7),
            last_channel_expires_at: Some(now + Duration::seconds(1)),
            listening_channel_ids: vec![3, 4],
            listening_channel_expires_at: Some(now - Duration::seconds(1)),
        };

        let cached = entry.cached_channels_at(now).expect("last channel valid");
        assert_eq!(cached.last_channel_id, Some(7));
        assert!(cached.listening_channel_ids.is_empty());
    }

    #[tokio::test]
    async fn cache_persists_to_sqlite_database() {
        let dir = tempfile::tempdir().unwrap();
        let cache = UserChannelCache::open(dir.path()).await.unwrap();

        cache.remember_last_channel("alice", 5).await.unwrap();
        cache
            .remember_listening_channels("alice", [9, 5, 9])
            .await
            .unwrap();

        let loaded = UserChannelCache::open(dir.path()).await.unwrap();
        let cached = loaded.get("alice").await.expect("cache entry");

        assert_eq!(cached.last_channel_id, Some(5));
        assert_eq!(cached.listening_channel_ids, vec![5, 9]);
        assert!(dir.path().join(CACHE_DB_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn legacy_json_cache_imports_to_sqlite_database_once() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let mut entries = HashMap::new();
        entries.insert(
            "alice".to_owned(),
            UserChannelCacheEntry {
                last_channel_id: Some(5),
                last_channel_expires_at: Some(now + Duration::days(1)),
                listening_channel_ids: vec![9, 5, 9],
                listening_channel_expires_at: Some(now + Duration::hours(1)),
            },
        );
        tokio::fs::write(
            dir.path().join(LEGACY_CACHE_FILE_NAME),
            serde_json::to_vec(&entries).unwrap(),
        )
        .await
        .unwrap();

        let loaded = UserChannelCache::open(dir.path()).await.unwrap();
        let cached = loaded.get("alice").await.expect("cache entry");

        assert_eq!(cached.last_channel_id, Some(5));
        assert_eq!(cached.listening_channel_ids, vec![5, 9]);

        loaded.remember_last_channel("alice", 11).await.unwrap();
        let reloaded = UserChannelCache::open(dir.path()).await.unwrap();
        let cached = reloaded.get("alice").await.expect("cache entry");

        assert_eq!(cached.last_channel_id, Some(11));
        assert_eq!(cached.listening_channel_ids, vec![5, 9]);
    }
}
