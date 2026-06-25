use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::acl::ACLPermissions;
use crate::client::{Client, ClientTransportKind};
use crate::server::Server;

const CACHE_FILE_NAME: &str = "user_channel_cache.json";
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
    path: Option<PathBuf>,
    entries: Mutex<HashMap<String, UserChannelCacheEntry>>,
}

impl UserChannelCache {
    pub async fn open(storage_dir: &Path) -> io::Result<Arc<Self>> {
        tokio::fs::create_dir_all(storage_dir).await?;
        let path = storage_dir.join(CACHE_FILE_NAME);
        let entries = match tokio::fs::read(&path).await {
            Ok(bytes) => {
                match serde_json::from_slice::<HashMap<String, UserChannelCacheEntry>>(&bytes) {
                    Ok(mut entries) => {
                        prune_entries_at(&mut entries, Utc::now());
                        entries
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %error,
                            "ignoring unreadable user channel cache"
                        );
                        HashMap::new()
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };

        Ok(Arc::new(Self {
            path: Some(path),
            entries: Mutex::new(entries),
        }))
    }

    pub fn new_in_memory() -> Arc<Self> {
        Arc::new(Self {
            path: None,
            entries: Mutex::new(HashMap::new()),
        })
    }

    pub async fn get(&self, key: &str) -> Option<CachedUserChannels> {
        let entries = self.entries.lock().await;
        entries
            .get(key)
            .and_then(|entry| entry.cached_channels_at(Utc::now()))
    }

    pub async fn remember_last_channel(&self, key: &str, channel_id: u32) -> io::Result<()> {
        let now = Utc::now();
        let mut entries = self.entries.lock().await;
        let entry = entries.entry(key.to_owned()).or_default();
        entry.last_channel_id = Some(channel_id);
        entry.last_channel_expires_at = Some(now + Duration::days(LAST_CHANNEL_TTL_DAYS));
        prune_entries_at(&mut entries, now);
        self.save_locked(&entries).await
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
        let mut entries = self.entries.lock().await;
        let entry = entries.entry(key.to_owned()).or_default();
        entry.listening_channel_ids = channel_ids;
        entry.listening_channel_expires_at = if entry.listening_channel_ids.is_empty() {
            None
        } else {
            Some(now + Duration::hours(LISTENING_CHANNEL_TTL_HOURS))
        };
        prune_entries_at(&mut entries, now);
        self.save_locked(&entries).await
    }

    async fn save_locked(
        &self,
        entries: &HashMap<String, UserChannelCacheEntry>,
    ) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let tmp_path = path.with_file_name(format!(
            "{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(CACHE_FILE_NAME)
        ));
        let json = serde_json::to_vec_pretty(entries).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("serialize user channel cache: {error}"),
            )
        })?;

        {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)
                .await?;
            file.write_all(&json).await?;
            file.sync_data().await?;
        }
        tokio::fs::rename(&tmp_path, path).await
    }
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
    async fn cache_persists_to_snapshot_file() {
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
        assert!(dir.path().join(CACHE_FILE_NAME).exists());
    }
}
