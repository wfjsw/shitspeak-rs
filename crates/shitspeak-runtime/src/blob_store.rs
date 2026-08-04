//! Blob storage implementations.
//!
//! Two stores are provided:
//!
//! * [`ChannelBlobStore`] — persistent, content-addressed storage for channel
//!   description blobs.  Disk is authoritative; blobs survive restarts.
//!   SHA-1 keyed, 2-char subdirectory sharding (same layout as git objects).
//!
//! * [`SessionBlobStore`] — persistent URL-keyed cache for user textures and
//!   comments.  Blobs are fetched from the URL supplied by the auth server,
//!   stored on disk indefinitely (no eviction), and keyed by SHA-1 of the
//!   content.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use bytes::Bytes;
use futures_util::StreamExt as _;
use tokio::fs;
use tokio::io::AsyncWriteExt as _;

use crate::http_client;

const SESSION_BLOB_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Compute the lowercase SHA-1 hex of `data`.
pub fn sha1_hex(data: &[u8]) -> String {
    hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
}

/// Derive the on-disk path for a blob key inside `root`.
///
/// Layout: `<root>/<2-char-prefix>/<remaining-38-chars>`
/// (same sharding as git objects to avoid large flat directories)
fn blob_path(root: &Path, key: &str) -> PathBuf {
    debug_assert!(
        key.len() == 40,
        "blob key must be a 40-char SHA-1 hex string"
    );
    let (prefix, rest) = key.split_at(2);
    root.join(prefix).join(rest)
}

// ─── ChannelBlobStore ─────────────────────────────────────────────────────────

/// Persistent primary storage for channel description blobs.
///
/// The store is content-addressed: the key is the lowercase SHA-1 hex of the
/// stored bytes.  Puts are idempotent — if the blob already exists the write
/// is skipped.
pub struct ChannelBlobStore {
    root: PathBuf,
}

impl ChannelBlobStore {
    /// Create (or open) a blob store rooted at `dir/blobs`.
    pub async fn open(dir: &Path) -> io::Result<Self> {
        let root = dir.join("blobs");
        fs::create_dir_all(&root).await?;
        Ok(Self { root })
    }

    /// Store `data` and return its SHA-1 key.  No-op if the blob already
    /// exists (idempotent).
    pub async fn put(&self, data: &[u8]) -> io::Result<String> {
        let key = sha1_hex(data);
        let path = blob_path(&self.root, &key);

        if self.exists(&key).await {
            return Ok(key);
        }

        // Atomic write: tmp → rename.
        let tmp = path.with_extension("tmp");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .await?;
            file.write_all(data).await?;
            file.sync_data().await?;
        }

        fs::rename(&tmp, &path).await?;

        Ok(key)
    }

    /// Read a blob by key, returning `None` if it does not exist.
    pub async fn get(&self, key: &str) -> io::Result<Option<Bytes>> {
        let path = blob_path(&self.root, key);
        match fs::read(&path).await {
            Ok(data) => Ok(Some(Bytes::from(data))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Delete a blob by key.  Silent if missing.
    pub async fn delete(&self, key: &str) -> io::Result<()> {
        let path = blob_path(&self.root, key);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Return `true` if the blob exists.
    pub async fn exists(&self, key: &str) -> bool {
        let path = blob_path(&self.root, key);
        fs::metadata(&path).await.is_ok()
    }

    /// Return every locally stored blob key.
    pub async fn keys(&self) -> io::Result<HashSet<String>> {
        let mut out = HashSet::new();
        let mut dirs = match fs::read_dir(&self.root).await {
            Ok(dirs) => dirs,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        while let Some(dir) = dirs.next_entry().await? {
            let file_type = dir.file_type().await?;
            if !file_type.is_dir() {
                continue;
            }
            let prefix = dir.file_name().to_string_lossy().to_string();
            if prefix.len() != 2 || !prefix.bytes().all(is_lower_hex) {
                continue;
            }
            let prefix = prefix.to_ascii_lowercase();
            let mut files = fs::read_dir(dir.path()).await?;
            while let Some(file) = files.next_entry().await? {
                if !file.file_type().await?.is_file() {
                    continue;
                }
                let suffix = file.file_name().to_string_lossy().to_string();
                if suffix.len() != 38 || !suffix.bytes().all(is_lower_hex) {
                    continue;
                }
                out.insert(format!("{prefix}{}", suffix.to_ascii_lowercase()));
            }
        }
        Ok(out)
    }
}

/// Persistent URL-keyed cache for user textures and comments.
///
/// Blobs are fetched from the URL supplied by the auth server on first use,
/// then stored on disk keyed by SHA-1 of their content.  The store survives
/// restarts (no wipe-on-start).
///
/// Eviction is *reference-aware*: blobs referenced by live client state are
/// pinned (via [`BlobPin`]) and are never evicted, so referenced content is
/// never lost and never causes a refetch. Only blobs with no live reference
/// are evicted, least-recently-used first, once the total cache size exceeds
/// the configured budget (`session_blob_cache_budget_bytes`; `0` disables
/// eviction). Eviction batches down to 75% of the budget to avoid churn at
/// the boundary. Reference checks are O(1) hash-map lookups.
///
/// During S2S, URL-backed blobs are fetched directly from their source URL.
/// URL-less blobs created by a connected user are fetched from a peer through
/// the S2S blob replication topic.
///
pub struct SessionBlobStore {
    root: PathBuf,
    http_client: reqwest::Client,
    index: std::sync::Mutex<SessionBlobIndex>,
    /// Reference counts for blobs pinned by live client state. O(1) check
    /// for the eviction path.
    references: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    /// Total on-disk budget before eviction of unreferenced blobs starts.
    /// `0` disables eviction.
    budget_bytes: u64,
}

/// RAII guard pinning a session blob (prevents eviction) while held.
/// Dropping the guard unpins the key. Holds a `Weak` reference so a store
/// dropped before the guard (shutdown) never panics on unpin.
pub struct BlobPin {
    store: std::sync::Weak<SessionBlobStore>,
    key: String,
}

impl BlobPin {
    pub(crate) fn new(store: &std::sync::Arc<SessionBlobStore>, key: &str) -> Self {
        store.pin(key);
        Self {
            store: std::sync::Arc::downgrade(store),
            key: key.to_owned(),
        }
    }
}

impl Drop for BlobPin {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            store.unpin(&self.key);
        }
    }
}

#[derive(Debug, Default)]
struct SessionBlobIndex {
    entries: std::collections::HashMap<String, SessionBlobIndexEntry>,
    total_bytes: u64,
}

#[derive(Debug)]
struct SessionBlobIndexEntry {
    size: u64,
    last_access: std::time::Instant,
}

impl SessionBlobIndex {
    /// Record a blob (or refresh its access time). Returns `true` if the
    /// entry is newly added.
    fn touch(&mut self, key: &str, size: u64) -> bool {
        let now = std::time::Instant::now();
        match self.entries.get_mut(key) {
            Some(entry) => {
                entry.size = size;
                entry.last_access = now;
                false
            }
            None => {
                self.total_bytes = self.total_bytes.saturating_add(size);
                self.entries.insert(
                    key.to_owned(),
                    SessionBlobIndexEntry {
                        size,
                        last_access: now,
                    },
                );
                true
            }
        }
    }

    /// Remove an entry from the index (file deletion handled by the caller).
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.size);
        }
    }
}

impl SessionBlobStore {
    /// Open (or create) a session blob store rooted at `dir/session_blobs`.
    /// The directory is created if it does not exist; existing blobs are left
    /// in place (no restart wipe) and indexed from their file mtimes.
    /// `budget_bytes` is the total on-disk budget before unreferenced blobs
    /// are evicted; `0` disables eviction.
    pub async fn open(dir: &Path, budget_bytes: u64) -> io::Result<Self> {
        let root = dir.join("session_blobs");
        fs::create_dir_all(&root).await?;
        let http_client = http_client::build_with_webpki_fallback(
            SESSION_BLOB_HTTP_TIMEOUT,
            "session blob store",
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        let index = scan_existing_session_blobs(&root).await;
        Ok(Self {
            root,
            http_client,
            index: std::sync::Mutex::new(index),
            references: std::sync::Mutex::new(std::collections::HashMap::new()),
            budget_bytes,
        })
    }

    /// Mark a blob as referenced by live client state. O(1). Referenced
    /// blobs are never evicted.
    pub fn pin(&self, key: &str) {
        let mut references = match self.references.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *references.entry(key.to_owned()).or_insert(0) += 1;
    }

    /// Release one reference on a blob. O(1).
    pub fn unpin(&self, key: &str) {
        let mut references = match self.references.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(count) = references.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                references.remove(key);
            }
        }
    }

    /// Whether a blob currently has any live reference. O(1).
    pub fn is_referenced(&self, key: &str) -> bool {
        let references = match self.references.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        references.get(key).copied().unwrap_or(0) > 0
    }

    /// Store `data` and return its SHA-1 key. No-op if the blob already exists.
    pub async fn put_content(&self, data: &[u8]) -> io::Result<String> {
        let key = sha1_hex(data);
        self.put(&key, data).await
    }

    /// Read a blob from the local cache by SHA-1 key.
    pub async fn get_cached(&self, key: &str) -> Option<Bytes> {
        let path = blob_path(&self.root, key);

        if let Ok(bytes) = fs::read(&path).await {
            let size = bytes.len() as u64;
            {
                let mut index = match self.index.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                index.touch(key, size);
            }
            return Some(Bytes::from(bytes));
        }

        None
    }

    /// Fetch a blob by SHA-1 key from the local cache.  On a cache miss,
    /// fetches from `source_url` (capped at [`crate::rate_limits::MAX_SESSION_BLOB_BYTES`])
    /// and caches the result.
    pub async fn get(&self, key: &str, source_url: &str) -> Option<Bytes> {
        if let Some(bytes) = self.get_cached(key).await {
            return Some(bytes);
        }

        let response = match self.http_client.get(source_url).send().await {
            Ok(resp) if resp.status().is_success() => resp,
            Ok(resp) => {
                tracing::warn!(
                    "SessionBlobStore fetch failed with status {} for {}",
                    resp.status(),
                    source_url
                );
                return None;
            }
            Err(err) => {
                tracing::warn!("SessionBlobStore fetch error for {}: {}", source_url, err);
                return None;
            }
        };

        let bytes = match read_body_bounded(response).await {
            Some(b) => b,
            None => {
                tracing::warn!(
                    "SessionBlobStore body for {} was empty, oversized, or unreadable",
                    source_url
                );
                return None;
            }
        };

        let fetched_key = sha1_hex(&bytes);
        if fetched_key != key {
            tracing::warn!(
                "SessionBlobStore hash mismatch for {}: expected {}, got {}",
                source_url,
                key,
                fetched_key
            );
            return None;
        }

        if self.put(key, &bytes).await.is_err() {
            return None;
        }

        Some(bytes)
    }

    /// Fetch a URL-backed blob, cache it, and return its SHA-1 key plus bytes.
    pub async fn fetch_and_cache(&self, source_url: &str) -> Option<(String, Bytes)> {
        let response = match self.http_client.get(source_url).send().await {
            Ok(resp) if resp.status().is_success() => resp,
            Ok(resp) => {
                tracing::warn!(
                    "SessionBlobStore fetch failed with status {} for {}",
                    resp.status(),
                    source_url
                );
                return None;
            }
            Err(err) => {
                tracing::warn!("SessionBlobStore fetch error for {}: {}", source_url, err);
                return None;
            }
        };

        let bytes = match read_body_bounded(response).await {
            Some(b) => b,
            None => {
                tracing::warn!(
                    "SessionBlobStore body for {} was empty, oversized, or unreadable",
                    source_url
                );
                return None;
            }
        };

        let key = sha1_hex(&bytes);
        if self.put(&key, &bytes).await.is_err() {
            return None;
        }

        Some((key, bytes))
    }

    /// Store `data` in the local disk cache under the given `key`.
    /// Returns the SHA-1 key on success.
    pub async fn put(&self, key: &str, data: &[u8]) -> io::Result<String> {
        let computed = sha1_hex(data);
        if computed != key {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob key does not match data hash",
            ));
        }
        if data.len() > crate::rate_limits::MAX_SESSION_BLOB_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "blob exceeds {} bytes",
                    crate::rate_limits::MAX_SESSION_BLOB_BYTES
                ),
            ));
        }

        let path = blob_path(&self.root, key);
        if fs::metadata(&path).await.is_ok() {
            {
                let mut index = match self.index.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                index.touch(key, data.len() as u64);
            }
            return Ok(key.to_owned());
        }

        let tmp = path.with_extension("tmp");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .await?;
            file.write_all(data).await?;
            file.sync_data().await?;
        }

        fs::rename(&tmp, &path).await?;

        {
            let mut index = match self.index.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            index.touch(key, data.len() as u64);
        }
        self.evict_if_over_budget().await;

        Ok(key.to_owned())
    }

    /// Check whether the local cache contains the blob for `key`.
    pub async fn exists(&self, key: &str) -> bool {
        let path = blob_path(&self.root, key);
        fs::metadata(path).await.is_ok()
    }

    /// Evict least-recently-used blobs with **no live reference** until the
    /// total cache size is at or below 75% of the budget (batching avoids
    /// churn at the boundary). Blobs pinned by live client state are never
    /// evicted; if every remaining blob is referenced, eviction stops even
    /// if the budget is still exceeded (referenced content must stay).
    ///
    /// The final unreferenced check and the file unlink happen under the
    /// references lock (with a synchronous unlink, no await in between) so a
    /// concurrent [`BlobPin`] cannot land between the check and the delete —
    /// otherwise a just-referenced, URL-less blob could be lost forever.
    /// Returns the number of blobs evicted.
    async fn evict_if_over_budget(&self) -> usize {
        let budget = self.budget_bytes;
        if budget == 0 {
            return 0;
        }
        let watermark = budget.saturating_mul(3) / 4;
        let mut evicted = 0;
        loop {
            let lru_key = {
                let index = match self.index.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let references = match self.references.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if index.total_bytes <= watermark {
                    return evicted;
                }
                index
                    .entries
                    .iter()
                    .filter(|(key, _)| references.get(*key).copied().unwrap_or(0) == 0)
                    .min_by_key(|(_, entry)| entry.last_access)
                    .map(|(key, _)| key.clone())
            };
            let Some(lru_key) = lru_key else {
                return evicted;
            };
            // Re-verify unreferenced and unlink atomically with respect to
            // pins. A synchronous unlink avoids awaiting while holding the
            // locks; the syscall is fast and lock ordering (index → refs) is
            // acyclic.
            let removed = {
                let mut index = match self.index.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let references = match self.references.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if references.get(&lru_key).copied().unwrap_or(0) > 0 {
                    // Pinned since selection; leave it alone.
                    false
                } else {
                    let path = blob_path(&self.root, &lru_key);
                    match std::fs::remove_file(&path) {
                        Ok(()) => {
                            index.remove(&lru_key);
                            true
                        }
                        Err(e) => {
                            tracing::warn!("SessionBlobStore eviction failed for {lru_key}: {e}");
                            // Drop the index entry so we do not retry forever.
                            index.remove(&lru_key);
                            true
                        }
                    }
                }
            };
            if removed {
                evicted += 1;
                tracing::debug!("SessionBlobStore evicted unreferenced LRU blob {lru_key}");
            }
        }
    }
}

/// Read a response body, rejecting it if it exceeds the session blob size
/// cap. The Content-Length header (when present) gives a cheap early
/// rejection; the streamed read enforces the cap regardless.
async fn read_body_bounded(response: reqwest::Response) -> Option<Bytes> {
    let limit = crate::rate_limits::MAX_SESSION_BLOB_BYTES;
    if let Some(content_length) = response.content_length() {
        if content_length > limit as u64 {
            return None;
        }
    }
    let mut stream = response.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if out.len().saturating_add(chunk.len()) > limit {
            return None;
        }
        out.extend_from_slice(&chunk);
    }
    Some(Bytes::from(out))
}

/// Rebuild the in-memory index from the on-disk shards, using each file's
/// mtime as a proxy for its last access time.
async fn scan_existing_session_blobs(root: &Path) -> SessionBlobIndex {
    let mut index = SessionBlobIndex::default();
    let mut dirs = match fs::read_dir(root).await {
        Ok(dirs) => dirs,
        Err(_) => return index,
    };
    while let Ok(Some(dir)) = dirs.next_entry().await {
        let Ok(file_type) = dir.file_type().await else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let prefix = dir.file_name().to_string_lossy().to_string();
        if prefix.len() != 2 || !prefix.bytes().all(is_lower_hex) {
            continue;
        }
        let prefix = prefix.to_ascii_lowercase();
        let mut files = match fs::read_dir(dir.path()).await {
            Ok(files) => files,
            Err(_) => continue,
        };
        while let Ok(Some(file)) = files.next_entry().await {
            let Ok(file_type) = file.file_type().await else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let suffix = file.file_name().to_string_lossy().to_string();
            if suffix.len() != 38 || !suffix.bytes().all(is_lower_hex) {
                continue;
            }
            let key = format!("{prefix}{}", suffix.to_ascii_lowercase());
            let Ok(metadata) = file.metadata().await else {
                continue;
            };
            let size = metadata.len();
            // Approximate last access from the file mtime: Instant::now()
            // minus the file's age.
            let last_access = metadata
                .modified()
                .ok()
                .and_then(|mtime| mtime.elapsed().ok())
                .map(|age| std::time::Instant::now() - age)
                .unwrap_or_else(std::time::Instant::now);
            index.total_bytes = index.total_bytes.saturating_add(size);
            index
                .entries
                .insert(key, SessionBlobIndexEntry { size, last_access });
        }
    }
    index
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shitspeak-session-blobs-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn pinned_blob_survives_eviction() {
        let dir = test_dir("pinned");
        // Tiny budget so eviction triggers on every put.
        let store = Arc::new(SessionBlobStore::open(&dir, 32).await.unwrap());

        let pinned_key = store.put_content(b"pinned-content").await.unwrap();
        store.pin(&pinned_key);
        assert!(store.is_referenced(&pinned_key));

        // Overwhelm the tiny budget with unreferenced blobs.
        for i in 0..20 {
            store
                .put_content(
                    &vec![b'x'; 128]
                        .into_iter()
                        .chain([i as u8])
                        .collect::<Vec<_>>(),
                )
                .await
                .unwrap();
        }

        // The referenced blob must still be readable (never evicted).
        assert!(
            store.get_cached(&pinned_key).await.is_some(),
            "referenced blob must survive eviction"
        );

        // Unpin, then force more eviction: it becomes evictable.
        store.unpin(&pinned_key);
        assert!(!store.is_referenced(&pinned_key));
        for _ in 0..20 {
            store.put_content(&vec![b'y'; 128]).await.unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn blob_pin_guard_releases_on_drop() {
        let dir = test_dir("guard");
        let store = Arc::new(SessionBlobStore::open(&dir, 1024).await.unwrap());
        let key = store.put_content(b"guarded").await.unwrap();

        let pin = BlobPin::new(&store, &key);
        assert!(store.is_referenced(&key));
        drop(pin);
        assert!(!store.is_referenced(&key));

        // A dropped store never panics when guards outlive it.
        let store = Arc::new(SessionBlobStore::open(&dir, 1024).await.unwrap());
        let key = store.put_content(b"late-unpin").await.unwrap();
        let pin = BlobPin::new(&store, &key);
        drop(store);
        drop(pin);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn eviction_disabled_with_zero_budget() {
        let dir = test_dir("noevict");
        let store = SessionBlobStore::open(&dir, 0).await.unwrap();
        let key = store.put_content(b"stays").await.unwrap();
        for _ in 0..10 {
            store.put_content(&vec![b'z'; 1024]).await.unwrap();
        }
        assert!(store.get_cached(&key).await.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
