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
/// then stored on disk indefinitely keyed by SHA-1 of their content.  The
/// store survives restarts (no wipe-on-start).  There is no eviction policy;
/// the operator manages disk space externally.
///
/// During S2S, both the blob hash and the source URL are propagated to peer
/// nodes.  A peer that lacks the blob fetches it directly from the same URL;
/// nodes never pull blobs from each other.
///
pub struct SessionBlobStore {
    root: PathBuf,
    http_client: reqwest::Client,
}

impl SessionBlobStore {
    /// Open (or create) a session blob store rooted at `dir/session_blobs`.
    /// The directory is created if it does not exist; existing blobs are left
    /// in place (no restart wipe).
    pub async fn open(dir: &Path) -> io::Result<Self> {
        let root = dir.join("session_blobs");
        fs::create_dir_all(&root).await?;
        let http_client = http_client::build_with_webpki_fallback(
            SESSION_BLOB_HTTP_TIMEOUT,
            "session blob store",
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self { root, http_client })
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
            return Some(Bytes::from(bytes));
        }

        None
    }

    /// Fetch a blob by SHA-1 key from the local cache.  On a cache miss,
    /// fetches from `source_url` and caches the result.
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

        let bytes = match response.bytes().await {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(
                    "SessionBlobStore read body error for {}: {}",
                    source_url,
                    err
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

        let bytes = match response.bytes().await {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(
                    "SessionBlobStore read body error for {}: {}",
                    source_url,
                    err
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

        let path = blob_path(&self.root, key);
        if fs::metadata(&path).await.is_ok() {
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

        Ok(key.to_owned())
    }

    /// Check whether the local cache contains the blob for `key`.
    pub async fn exists(&self, key: &str) -> bool {
        let path = blob_path(&self.root, key);
        fs::metadata(path).await.is_ok()
    }
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}
