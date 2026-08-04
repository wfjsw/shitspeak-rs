use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::client::state_log::{ClientStateBroadcastPayload, ClientStateOperation};
use crate::client::{Client, ClientTransportKind};
use crate::server::Server;
use shitspeak_state::ACLPermissions;

const CACHE_DB_FILE_NAME: &str = "user_channel_cache.db";
const LEGACY_CACHE_FILE_NAME: &str = "user_channel_cache.json";
const LAST_CHANNEL_TTL_DAYS: i64 = 30;
const LISTENING_CHANNEL_TTL_HOURS: i64 = 6;
const PRUNE_INTERVAL: StdDuration = StdDuration::from_secs(60 * 60);
const PRUNE_RETRY_INTERVAL: StdDuration = StdDuration::from_secs(5 * 60);
const DB_COMMAND_QUEUE_CAPACITY: usize = 128;

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
    commands: mpsc::Sender<UserChannelCacheCommand>,
}

struct UserChannelCacheDb {
    conn: Connection,
    next_prune_at: Instant,
}

enum UserChannelCacheCommand {
    Get {
        key: String,
        response: oneshot::Sender<rusqlite::Result<Option<CachedUserChannels>>>,
    },
    RememberLastChannel {
        key: String,
        channel_id: u32,
        response: oneshot::Sender<io::Result<()>>,
    },
    RememberListeningChannels {
        key: String,
        channel_ids: Vec<u32>,
        response: oneshot::Sender<io::Result<()>>,
    },
    MigrateKey {
        from_key: String,
        to_key: String,
        response: oneshot::Sender<io::Result<()>>,
    },
    #[cfg(test)]
    Test {
        operation: Box<dyn FnOnce(&mut UserChannelCacheDb) + Send>,
    },
}

impl UserChannelCache {
    pub async fn open(storage_dir: &Path) -> io::Result<Arc<Self>> {
        tokio::fs::create_dir_all(storage_dir).await?;
        let db_path = storage_dir.join(CACHE_DB_FILE_NAME);
        let legacy_path = storage_dir.join(LEGACY_CACHE_FILE_NAME);
        let db = tokio::task::spawn_blocking(move || {
            let mut conn = Connection::open(&db_path).map_err(|error| {
                sqlite_io_error(
                    &format!("open user channel cache database {}", db_path.display()),
                    error,
                )
            })?;
            configure_connection(&conn, true)
                .map_err(|error| sqlite_io_error("configure user channel cache database", error))?;
            init_schema(&conn).map_err(|error| {
                sqlite_io_error("initialize user channel cache database", error)
            })?;
            import_legacy_json_cache(&mut conn, &legacy_path)?;
            prune_expired_rows(&conn, Utc::now())
                .map_err(|error| sqlite_io_error("prune user channel cache database", error))?;
            Ok::<_, io::Error>(UserChannelCacheDb::new(conn))
        })
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("initialize user channel cache worker: {error}"),
            )
        })??;

        Self::start_worker(move || db)
    }

    pub fn new_in_memory() -> Arc<Self> {
        Self::start_worker(|| {
            let conn = Connection::open_in_memory().expect("in-memory SQLite should always open");
            configure_connection(&conn, false).expect("in-memory SQLite should configure");
            init_schema(&conn).expect("in-memory SQLite schema should initialize");
            UserChannelCacheDb::new(conn)
        })
        .expect("user channel cache database worker should start")
    }

    pub async fn get(&self, key: &str) -> Option<CachedUserChannels> {
        let (response, receiver) = oneshot::channel();
        if self
            .commands
            .send(UserChannelCacheCommand::Get {
                key: key.to_owned(),
                response,
            })
            .await
            .is_err()
        {
            tracing::warn!(cache_key = key, "user channel cache worker stopped");
            return None;
        }

        match receiver.await {
            Ok(Ok(cached)) => cached,
            Ok(Err(error)) => {
                tracing::warn!(
                    cache_key = key,
                    error = %error,
                    "failed to read user channel cache"
                );
                None
            }
            Err(error) => {
                tracing::warn!(
                    cache_key = key,
                    error = %error,
                    "user channel cache worker dropped read response"
                );
                None
            }
        }
    }

    pub async fn remember_last_channel(&self, key: &str, channel_id: u32) -> io::Result<()> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(UserChannelCacheCommand::RememberLastChannel {
                key: key.to_owned(),
                channel_id,
                response,
            })
            .await
            .map_err(|_| cache_worker_stopped_error())?;
        receiver.await.map_err(|_| cache_worker_stopped_error())?
    }

    pub async fn remember_listening_channels<I>(&self, key: &str, channels: I) -> io::Result<()>
    where
        I: IntoIterator<Item = u32>,
    {
        let channel_ids = channels
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(UserChannelCacheCommand::RememberListeningChannels {
                key: key.to_owned(),
                channel_ids,
                response,
            })
            .await
            .map_err(|_| cache_worker_stopped_error())?;
        receiver.await.map_err(|_| cache_worker_stopped_error())?
    }

    /// Move a legacy cache entry to its stable identity key.
    ///
    /// If the stable key is already present, it wins and the legacy entry is
    /// removed. This prevents a stale numeric user id from overwriting an
    /// entry that was already stored for the authenticator-provided identity.
    pub async fn migrate_key(&self, from_key: &str, to_key: &str) -> io::Result<()> {
        if from_key == to_key {
            return Ok(());
        }

        let (response, receiver) = oneshot::channel();
        self.commands
            .send(UserChannelCacheCommand::MigrateKey {
                from_key: from_key.to_owned(),
                to_key: to_key.to_owned(),
                response,
            })
            .await
            .map_err(|_| cache_worker_stopped_error())?;
        receiver.await.map_err(|_| cache_worker_stopped_error())?
    }

    fn start_worker<F>(initialize: F) -> io::Result<Arc<Self>>
    where
        F: FnOnce() -> UserChannelCacheDb + Send + 'static,
    {
        let (commands, mut receiver) = mpsc::channel(DB_COMMAND_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("user-channel-cache-db".to_owned())
            .spawn(move || {
                let mut db = initialize();
                while let Some(command) = receiver.blocking_recv() {
                    match command {
                        UserChannelCacheCommand::Get { key, response } => {
                            let _ = response.send(db.get(&key));
                        }
                        UserChannelCacheCommand::RememberLastChannel {
                            key,
                            channel_id,
                            response,
                        } => {
                            let _ = response.send(db.remember_last_channel(&key, channel_id));
                        }
                        UserChannelCacheCommand::RememberListeningChannels {
                            key,
                            channel_ids,
                            response,
                        } => {
                            let _ =
                                response.send(db.remember_listening_channels(&key, channel_ids));
                        }
                        UserChannelCacheCommand::MigrateKey {
                            from_key,
                            to_key,
                            response,
                        } => {
                            let _ = response.send(db.migrate_key(&from_key, &to_key));
                        }
                        #[cfg(test)]
                        UserChannelCacheCommand::Test { operation } => operation(&mut db),
                    }
                }
            })?;
        Ok(Arc::new(Self { commands }))
    }

    #[cfg(test)]
    async fn with_db_for_test<T, F>(&self, operation: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&mut UserChannelCacheDb) -> T + Send + 'static,
    {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(UserChannelCacheCommand::Test {
                operation: Box::new(move |db| {
                    let _ = response.send(operation(db));
                }),
            })
            .await
            .expect("user channel cache worker should be running");
        receiver
            .await
            .expect("user channel cache test response should arrive")
    }
}

impl UserChannelCacheDb {
    fn new(conn: Connection) -> Self {
        Self {
            conn,
            next_prune_at: Instant::now() + PRUNE_INTERVAL,
        }
    }

    fn get(&self, key: &str) -> rusqlite::Result<Option<CachedUserChannels>> {
        Ok(load_entry(&self.conn, key)?.and_then(|entry| entry.cached_channels_at(Utc::now())))
    }

    fn remember_last_channel(&mut self, key: &str, channel_id: u32) -> io::Result<()> {
        let now = Utc::now();
        let expires_at = now + Duration::days(LAST_CHANNEL_TTL_DAYS);
        self.conn
            .execute(
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
            .map_err(|error| sqlite_io_error("store user last channel cache", error))?;
        self.prune_if_due_best_effort(now);
        Ok(())
    }

    fn remember_listening_channels(&mut self, key: &str, channel_ids: Vec<u32>) -> io::Result<()> {
        let now = Utc::now();
        let listening_expires_at = if channel_ids.is_empty() {
            None
        } else {
            Some(now + Duration::hours(LISTENING_CHANNEL_TTL_HOURS))
        };
        let tx = self
            .conn
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
        tx.commit()
            .map_err(|error| sqlite_io_error("commit user channel cache transaction", error))?;
        self.prune_if_due_best_effort(now);
        Ok(())
    }

    fn migrate_key(&mut self, from_key: &str, to_key: &str) -> io::Result<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|error| sqlite_io_error("begin user channel cache key migration", error))?;
        let source_exists = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM user_channel_cache WHERE cache_key = ?1)",
                params![from_key],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| sqlite_io_error("read user channel cache migration source", error))?;
        if !source_exists {
            return Ok(());
        }

        let destination_exists = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM user_channel_cache WHERE cache_key = ?1)",
                params![to_key],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| {
                sqlite_io_error("read user channel cache migration destination", error)
            })?;

        if !destination_exists {
            tx.execute(
                "INSERT INTO user_channel_cache (
                    cache_key,
                    last_channel_id,
                    last_channel_expires_at,
                    listening_channel_expires_at,
                    updated_at
                )
                SELECT ?2,
                    last_channel_id,
                    last_channel_expires_at,
                    listening_channel_expires_at,
                    updated_at
                FROM user_channel_cache
                WHERE cache_key = ?1",
                params![from_key, to_key],
            )
            .map_err(|error| sqlite_io_error("copy user channel cache migration entry", error))?;
            tx.execute(
                "INSERT INTO user_channel_listening_channels (cache_key, channel_id)
                 SELECT ?2, channel_id
                 FROM user_channel_listening_channels
                 WHERE cache_key = ?1",
                params![from_key, to_key],
            )
            .map_err(|error| {
                sqlite_io_error("copy user channel cache migration listeners", error)
            })?;
        }

        tx.execute(
            "DELETE FROM user_channel_cache WHERE cache_key = ?1",
            params![from_key],
        )
        .map_err(|error| sqlite_io_error("remove migrated user channel cache entry", error))?;
        tx.commit()
            .map_err(|error| sqlite_io_error("commit user channel cache key migration", error))
    }

    fn prune_is_due(&self) -> bool {
        Instant::now() >= self.next_prune_at
    }

    fn prune_if_due(&mut self, now: DateTime<Utc>) -> rusqlite::Result<()> {
        if !self.prune_is_due() {
            return Ok(());
        }

        let result = prune_expired_rows(&self.conn, now);
        self.schedule_next_prune(if result.is_ok() {
            PRUNE_INTERVAL
        } else {
            PRUNE_RETRY_INTERVAL
        });
        result
    }

    fn prune_if_due_best_effort(&mut self, now: DateTime<Utc>) {
        if let Err(error) = self.prune_if_due(now) {
            tracing::warn!(
                error = %error,
                "failed to prune user channel cache database; will retry later"
            );
        }
    }

    fn schedule_next_prune(&mut self, delay: StdDuration) {
        self.next_prune_at = Instant::now() + delay;
    }
}

fn sqlite_io_error(action: &str, error: rusqlite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{action}: {error}"))
}

fn cache_worker_stopped_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "user channel cache worker stopped",
    )
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

fn import_legacy_json_cache(conn: &mut Connection, path: &Path) -> io::Result<()> {
    if legacy_import_was_attempted(conn)
        .map_err(|error| sqlite_io_error("read user channel cache migration marker", error))?
    {
        return Ok(());
    }

    let bytes = match std::fs::read(path) {
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
         WHERE (last_channel_expires_at IS NOT NULL
                AND last_channel_expires_at <= ?1)
            OR (last_channel_expires_at IS NULL
                AND last_channel_id IS NOT NULL)",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM user_channel_listening_channels
         WHERE cache_key IN (
            SELECT cache_key
            FROM user_channel_cache
            WHERE listening_channel_expires_at IS NULL
               OR listening_channel_expires_at <= ?1
         )",
        params![now],
    )?;
    conn.execute(
        "UPDATE user_channel_cache
         SET listening_channel_expires_at = NULL
         WHERE listening_channel_expires_at IS NOT NULL
           AND listening_channel_expires_at <= ?1",
        params![now],
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

pub fn user_channel_cache_key(
    fqdn: Option<&str>,
    user_id: Option<u32>,
    username: Option<&str>,
) -> Option<String> {
    match fqdn.filter(|fqdn| !fqdn.is_empty()) {
        Some(fqdn) => Some(fqdn.to_owned()),
        None => match user_id {
            Some(user_id) => Some(user_id.to_string()),
            None => username
                .filter(|username| !username.is_empty())
                .map(ToOwned::to_owned),
        },
    }
}

pub async fn cache_key_for_client(server: &Server, client: &Client) -> Option<String> {
    let is_remote = client.transport_kind() == ClientTransportKind::Remote;
    if !records_client_transport(
        client.transport_kind(),
        server
            .read_config()
            .user_channel_cache_record_remote_sessions,
    ) {
        return None;
    }

    let fqdn = client.get_fqdn();
    let user_id = client.get_user_id();
    if let Some(cache_key) = user_channel_cache_key(fqdn.as_deref(), user_id, None) {
        return Some(cache_key);
    }
    if is_remote {
        return None;
    }

    let username = {
        let user_info = client.user_info_extended().await;
        user_info
            .get_credential()
            .as_ref()
            .map(|credential| credential.username.clone())
    };
    user_channel_cache_key(None, None, username.as_deref())
}

/// Listen to replicated client state after it has been materialized locally
/// and retain remote channel entries when configured to do so.
///
/// The client-state broadcast is the single passive stream shared by client
/// projections and S2S. It includes both normal remote operations and remote
/// snapshots, so observing it avoids coupling the cache to replication's
/// apply path.
pub(crate) fn spawn_remote_session_cache_observer(
    server: &Arc<Box<Server>>,
    mut shutdown: tokio::sync::watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let mut events = server.get_clients().subscribe();
    let server = Arc::downgrade(server);
    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                _ = shutdown.changed() => return,
                event = events.recv() => event,
            };
            match event {
                Ok(event) => {
                    let Some(server) = server.upgrade() else {
                        return;
                    };
                    record_remote_channel_entry(&server, &event).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        skipped,
                        "remote user channel cache observer lagged; skipped remote channel entries"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

async fn record_remote_channel_entry(
    server: &Arc<Box<Server>>,
    event: &ClientStateBroadcastPayload,
) {
    if event.entry.node_id == server.get_clients().local_node_id() {
        return;
    }

    let (server_id, session_id, client_instance_id, channel_id) = match &event.entry.op {
        ClientStateOperation::AddClient {
            server_id,
            session_id,
            client_instance_id,
            initial_state,
            ..
        } => match initial_state.current_channel_id {
            Some(channel_id) => (server_id, *session_id, *client_instance_id, channel_id),
            None => return,
        },
        ClientStateOperation::UpdateGlobalState {
            server_id,
            session_id,
            client_instance_id,
            delta,
            ..
        } => match delta.current_channel_id {
            Some(channel_id) => (server_id, *session_id, *client_instance_id, channel_id),
            None => return,
        },
        ClientStateOperation::RemoveClient { .. } | ClientStateOperation::ResetNode { .. } => {
            return;
        }
    };

    let Some(client) = server
        .get_clients()
        .get_client_in_server(server_id, session_id)
        .await
    else {
        return;
    };
    if client.transport_kind() != ClientTransportKind::Remote
        || client.client_instance_id() != client_instance_id
    {
        return;
    }

    let Some(cache_key) = cache_key_for_client(server.as_ref(), client.as_ref()).await else {
        return;
    };
    if let Err(error) = server
        .get_user_channel_cache()
        .remember_last_channel(&cache_key, channel_id)
        .await
    {
        tracing::warn!(
            error = %error,
            cache_key,
            session = u32::from(session_id),
            channel_id,
            "failed to record remote user channel cache entry"
        );
    }
}

fn records_client_transport(
    transport_kind: ClientTransportKind,
    record_remote_sessions: bool,
) -> bool {
    transport_kind != ClientTransportKind::Remote || record_remote_sessions
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

        let channel_cache_key = cache_key_for_client(server.as_ref(), client.as_ref()).await;
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
    fn cache_key_prefers_fqdn_then_user_id_then_username() {
        assert_eq!(
            user_channel_cache_key(Some("alice.example.test"), Some(42), Some("alice")),
            Some("alice.example.test".to_owned())
        );
        assert_eq!(
            user_channel_cache_key(Some(""), Some(42), Some("alice")),
            Some("42".to_owned())
        );
        assert_eq!(
            user_channel_cache_key(None, None, Some("alice")),
            Some("alice".to_owned())
        );
        assert_eq!(user_channel_cache_key(None, None, None), None);
    }

    #[test]
    fn remote_client_cache_recording_is_opt_in() {
        assert!(records_client_transport(
            ClientTransportKind::NativeMumble,
            false
        ));
        assert!(!records_client_transport(
            ClientTransportKind::Remote,
            false
        ));
        assert!(records_client_transport(ClientTransportKind::Remote, true));
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
    async fn cache_migrates_numeric_user_id_key_to_fqdn_key() {
        let cache = UserChannelCache::new_in_memory();
        cache.remember_last_channel("42", 5).await.unwrap();
        cache
            .remember_listening_channels("42", [7, 9])
            .await
            .unwrap();

        cache.migrate_key("42", "alice.example.test").await.unwrap();

        assert!(cache.get("42").await.is_none());
        assert_eq!(
            cache.get("alice.example.test").await,
            Some(CachedUserChannels {
                last_channel_id: Some(5),
                listening_channel_ids: vec![7, 9],
            })
        );
    }

    #[test]
    fn pruning_does_not_update_already_cleared_expirations() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, false).unwrap();
        init_schema(&conn).unwrap();
        conn.execute_batch(
            "CREATE TEMP TABLE update_audit (count INTEGER NOT NULL);
             INSERT INTO update_audit VALUES (0);
             CREATE TEMP TRIGGER audit_cache_updates
             AFTER UPDATE ON user_channel_cache
             BEGIN
                UPDATE update_audit SET count = count + 1;
             END;",
        )
        .unwrap();

        let now = Utc::now();
        conn.execute(
            "INSERT INTO user_channel_cache (
                cache_key,
                last_channel_id,
                last_channel_expires_at,
                listening_channel_expires_at,
                updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "alice",
                7_i64,
                (now - Duration::seconds(1)).timestamp_millis(),
                (now + Duration::hours(1)).timestamp_millis(),
                now.timestamp_millis(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_channel_listening_channels (cache_key, channel_id)
             VALUES ('alice', 9)",
            [],
        )
        .unwrap();

        prune_expired_rows(&conn, now).unwrap();
        prune_expired_rows(&conn, now).unwrap();

        let update_count: i64 = conn
            .query_row("SELECT count FROM update_audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(update_count, 1);
        let entry = load_entry(&conn, "alice").unwrap().expect("cache row");
        assert_eq!(entry.last_channel_id, None);
        assert_eq!(entry.listening_channel_ids, vec![9]);
    }

    #[test]
    fn pruning_removes_expired_and_missing_expiry_payloads() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn, false).unwrap();
        init_schema(&conn).unwrap();
        let now = Utc::now();

        conn.execute(
            "INSERT INTO user_channel_cache (
                cache_key,
                last_channel_id,
                last_channel_expires_at,
                listening_channel_expires_at,
                updated_at
             ) VALUES ('valid-last', 7, ?1, ?2, ?3),
                      ('missing-expiry', 8, NULL, NULL, ?3)",
            params![
                (now + Duration::hours(1)).timestamp_millis(),
                (now - Duration::seconds(1)).timestamp_millis(),
                now.timestamp_millis(),
            ],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO user_channel_listening_channels (cache_key, channel_id)
             VALUES ('valid-last', 9), ('missing-expiry', 10);",
        )
        .unwrap();

        prune_expired_rows(&conn, now).unwrap();

        let valid = load_entry(&conn, "valid-last")
            .unwrap()
            .expect("valid last channel");
        assert_eq!(valid.last_channel_id, Some(7));
        assert!(valid.listening_channel_ids.is_empty());
        assert!(load_entry(&conn, "missing-expiry").unwrap().is_none());
    }

    #[tokio::test]
    async fn writes_prune_expired_rows_only_when_interval_is_due() {
        let cache = UserChannelCache::new_in_memory();
        let now = Utc::now();
        cache
            .with_db_for_test(move |db| {
                db.conn
                    .execute(
                        "INSERT INTO user_channel_cache (
                        cache_key,
                        last_channel_id,
                        last_channel_expires_at,
                        listening_channel_expires_at,
                        updated_at
                     ) VALUES (?1, ?2, ?3, NULL, ?4)",
                        params![
                            "expired",
                            4_i64,
                            (now - Duration::seconds(1)).timestamp_millis(),
                            now.timestamp_millis(),
                        ],
                    )
                    .unwrap();
            })
            .await;

        assert!(cache.get("expired").await.is_none());
        cache.remember_last_channel("active", 5).await.unwrap();
        let expired_row_count = cache
            .with_db_for_test(|db| {
                let expired_row_count: i64 = db
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM user_channel_cache WHERE cache_key = 'expired'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                db.next_prune_at = Instant::now();
                expired_row_count
            })
            .await;
        assert_eq!(expired_row_count, 1);

        cache.remember_last_channel("active", 6).await.unwrap();
        let expired_row_count = cache
            .with_db_for_test(|db| {
                db.conn
                    .query_row(
                        "SELECT COUNT(*) FROM user_channel_cache WHERE cache_key = 'expired'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap()
            })
            .await;
        assert_eq!(expired_row_count, 0);
    }

    #[tokio::test]
    async fn prune_failure_does_not_fail_write_or_retry_immediately() {
        let cache = UserChannelCache::new_in_memory();
        let now = Utc::now();
        cache
            .with_db_for_test(move |db| {
                db.conn
                    .execute(
                        "INSERT INTO user_channel_cache (
                        cache_key,
                        last_channel_id,
                        last_channel_expires_at,
                        listening_channel_expires_at,
                        updated_at
                     ) VALUES ('expired', 4, ?1, NULL, ?2)",
                        params![
                            (now - Duration::seconds(1)).timestamp_millis(),
                            now.timestamp_millis(),
                        ],
                    )
                    .unwrap();
                db.conn
                    .execute_batch(
                        "CREATE TEMP TRIGGER fail_expired_prune
                     BEFORE UPDATE ON user_channel_cache
                     WHEN OLD.cache_key = 'expired'
                     BEGIN
                        SELECT RAISE(FAIL, 'forced prune failure');
                     END;",
                    )
                    .unwrap();
                db.next_prune_at = Instant::now();
            })
            .await;

        cache.remember_last_channel("active", 5).await.unwrap();

        let (next_prune_is_future, active) = cache
            .with_db_for_test(|db| {
                (
                    db.next_prune_at > Instant::now(),
                    load_entry(&db.conn, "active")
                        .unwrap()
                        .expect("foreground write should commit"),
                )
            })
            .await;
        assert!(next_prune_is_future);
        assert_eq!(active.last_channel_id, Some(5));
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn database_actor_handles_concurrent_requests() {
        let cache = UserChannelCache::new_in_memory();
        let mut writes = tokio::task::JoinSet::new();

        for channel_id in 1..=32 {
            let cache = Arc::clone(&cache);
            writes.spawn(async move {
                let key = format!("user-{channel_id}");
                cache.remember_last_channel(&key, channel_id).await
            });
        }

        while let Some(result) = writes.join_next().await {
            result
                .expect("cache writer task should not panic")
                .expect("cache write should succeed");
        }

        for channel_id in 1..=32 {
            let key = format!("user-{channel_id}");
            assert_eq!(
                cache
                    .get(&key)
                    .await
                    .and_then(|entry| entry.last_channel_id),
                Some(channel_id)
            );
        }
    }
}
