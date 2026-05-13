use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use rand::{thread_rng, Rng};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::error::ReplicationError;
use super::proto::{
    self as repl_proto, BlobBody, BlobChunk, BlobChunkReq, BlobFind, BlobOffer,
    REPLICATION_SERVICE_TAG,
};
use super::topic::ErasedBlobRuntime;
use crate::blob_store::sha1_hex;
use crate::s2s::overlay::{MembershipEvent, OverlayNetwork};
use crate::s2s::transport::{MessageClass, ServiceLevel};
use crate::types::NodeIdentifier;

#[async_trait]
pub(crate) trait BlobNet: Send + Sync + 'static {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: BlobBody,
    ) -> Result<(), ReplicationError>;
    async fn send_broadcast(&self, topic: &str, body: BlobBody) -> Result<(), ReplicationError>;
    fn alive_members(&self) -> Vec<NodeIdentifier>;
    fn local_node_id(&self) -> NodeIdentifier;
}

pub(crate) struct OverlayBlobNet {
    pub overlay: OverlayNetwork,
}

#[async_trait]
impl BlobNet for OverlayBlobNet {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: BlobBody,
    ) -> Result<(), ReplicationError> {
        let msg = repl_proto::wrap_blob(topic, body);
        let bytes = repl_proto::encode(&msg)?;
        self.overlay
            .send_unicast(
                dst,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                MessageClass::Regular,
                bytes,
            )
            .await?;
        Ok(())
    }

    async fn send_broadcast(&self, topic: &str, body: BlobBody) -> Result<(), ReplicationError> {
        let msg = repl_proto::wrap_blob(topic, body);
        let bytes = repl_proto::encode(&msg)?;
        self.overlay
            .send_broadcast(
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                MessageClass::Regular,
                bytes,
            )
            .await?;
        Ok(())
    }

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.overlay.alive_members()
    }

    fn local_node_id(&self) -> NodeIdentifier {
        self.overlay.local_node_id()
    }
}

#[async_trait]
pub trait BlobReplicable: Send + Sync + 'static {
    async fn get_blob(&self, key: &str) -> Option<Bytes>;
    async fn put_blob(&self, key: &str, data: Bytes) -> Result<(), ReplicationError>;
    async fn delete_blob(&self, key: &str) -> Result<(), ReplicationError>;
    async fn stored_keys(&self) -> HashSet<String>;
    async fn referenced_keys(&self) -> HashSet<String>;
}

#[derive(Clone)]
pub struct BlobHandle<R: BlobReplicable> {
    pub(crate) runtime: Arc<BlobRuntime<R>>,
}

impl<R: BlobReplicable> BlobHandle<R> {
    pub async fn get(&self, key: &str) -> Option<Bytes> {
        self.runtime.get_or_fetch(key).await
    }
}

#[derive(Debug, Clone)]
struct BlobReplicationConfig {
    chunk_size: usize,
    request_timeout: Duration,
    offer_wait: Duration,
    retry_interval: Duration,
    max_parallel_peers: usize,
    decay_interval: Duration,
    unused_grace: Duration,
}

impl BlobReplicationConfig {
    fn from_replication(cfg: &super::ReplicationConfig) -> Self {
        Self {
            chunk_size: cfg.blob_chunk_size(),
            request_timeout: cfg.blob_request_timeout(),
            offer_wait: cfg.blob_offer_wait(),
            retry_interval: cfg.blob_retry_interval(),
            max_parallel_peers: cfg.blob_max_parallel_peers().max(1),
            decay_interval: cfg.blob_decay_interval(),
            unused_grace: cfg.blob_unused_grace(),
        }
    }
}

struct BlobFetch {
    key: String,
    request_id: u64,
    started_at: Instant,
    last_request_at: Instant,
    waiters: Vec<oneshot::Sender<Option<Bytes>>>,
    offers: BTreeMap<NodeIdentifier, BlobOffer>,
    chunks: BTreeMap<u32, Bytes>,
    requested: HashSet<u32>,
    requested_by_peer: HashMap<NodeIdentifier, HashSet<u32>>,
    total_size: Option<u64>,
    chunk_count: Option<u32>,
    chunk_size: Option<u32>,
}

impl BlobFetch {
    fn new(key: String, request_id: u64, waiter: oneshot::Sender<Option<Bytes>>) -> Self {
        let now = Instant::now();
        Self {
            key,
            request_id,
            started_at: now,
            last_request_at: now,
            waiters: vec![waiter],
            offers: BTreeMap::new(),
            chunks: BTreeMap::new(),
            requested: HashSet::new(),
            requested_by_peer: HashMap::new(),
            total_size: None,
            chunk_count: None,
            chunk_size: None,
        }
    }

    fn add_waiter(&mut self, waiter: oneshot::Sender<Option<Bytes>>) {
        self.waiters.push(waiter);
    }

    fn add_offer(&mut self, offer: BlobOffer) -> bool {
        if offer.chunk_count == 0 || offer.chunk_size == 0 {
            return false;
        }
        if self.chunk_count.is_none() {
            self.chunk_count = Some(offer.chunk_count);
            self.total_size = Some(offer.size);
            self.chunk_size = Some(offer.chunk_size);
        }
        if self.chunk_count != Some(offer.chunk_count)
            || self.total_size != Some(offer.size)
            || self.chunk_size != Some(offer.chunk_size)
        {
            return false;
        }
        self.offers.insert(offer.provider as NodeIdentifier, offer);
        true
    }

    fn is_complete(&self) -> bool {
        let Some(chunk_count) = self.chunk_count else {
            return false;
        };
        self.chunks.len() == chunk_count as usize
    }

    fn record_chunk(&mut self, chunk: BlobChunk) -> Option<Bytes> {
        if self.key != chunk.key || self.request_id != chunk.request_id {
            return None;
        }
        let Some(expected_count) = self.chunk_count else {
            return None;
        };
        if chunk.index >= expected_count || self.chunks.contains_key(&chunk.index) {
            return None;
        }
        if chunk.data.len() > chunk.chunk_size as usize {
            return None;
        }
        if self.total_size != Some(chunk.total_size) {
            return None;
        }

        self.chunks.insert(chunk.index, chunk.data);
        self.requested.remove(&chunk.index);
        for requested in self.requested_by_peer.values_mut() {
            requested.remove(&chunk.index);
        }

        if !self.is_complete() {
            return None;
        }

        let total_size = self.total_size? as usize;
        let mut out = BytesMut::with_capacity(total_size);
        for index in 0..expected_count {
            let chunk = self.chunks.get(&index)?;
            out.put_slice(chunk);
        }
        if out.len() == total_size {
            Some(out.freeze())
        } else {
            None
        }
    }

    fn stale_requested_indexes(&mut self, now: Instant, retry_after: Duration) -> Vec<u32> {
        if now.duration_since(self.last_request_at) < retry_after {
            return Vec::new();
        }
        let indexes: Vec<u32> = self.requested.iter().copied().collect();
        self.requested.clear();
        self.requested_by_peer.clear();
        indexes
    }

    fn next_requests(&mut self, max_parallel_peers: usize) -> Vec<ChunkRequestPlan> {
        let Some(chunk_count) = self.chunk_count else {
            return Vec::new();
        };
        let Some(chunk_size) = self.chunk_size else {
            return Vec::new();
        };
        let providers: Vec<NodeIdentifier> = self.offers.keys().copied().collect();
        if providers.is_empty() {
            return Vec::new();
        }

        let mut providers = providers;
        providers.truncate(providers.len().min(max_parallel_peers.max(1)));
        let providers = providers.as_slice();
        let mut out: BTreeMap<NodeIdentifier, Vec<u32>> = BTreeMap::new();
        let mut provider_index = 0usize;
        for index in 0..chunk_count {
            if self.chunks.contains_key(&index) || self.requested.contains(&index) {
                continue;
            }
            let provider = providers[provider_index % providers.len()];
            provider_index += 1;
            self.requested.insert(index);
            self.requested_by_peer
                .entry(provider)
                .or_default()
                .insert(index);
            out.entry(provider).or_default().push(index);
        }
        if !out.is_empty() {
            self.last_request_at = Instant::now();
        }
        out.into_iter()
            .map(|(provider, indexes)| ChunkRequestPlan {
                request_id: self.request_id,
                key: self.key.clone(),
                provider,
                indexes,
                chunk_size,
            })
            .collect()
    }
}

struct ChunkRequestPlan {
    request_id: u64,
    key: String,
    provider: NodeIdentifier,
    indexes: Vec<u32>,
    chunk_size: u32,
}

struct BlobRuntimeState {
    fetches_by_key: HashMap<String, u64>,
    fetches: HashMap<u64, BlobFetch>,
    unused_since: HashMap<String, Instant>,
}

impl BlobRuntimeState {
    fn new() -> Self {
        Self {
            fetches_by_key: HashMap::new(),
            fetches: HashMap::new(),
            unused_since: HashMap::new(),
        }
    }

    fn start_fetch(
        &mut self,
        key: String,
        request_id: u64,
        waiter: oneshot::Sender<Option<Bytes>>,
    ) -> bool {
        if let Some(existing) = self.fetches_by_key.get(&key).copied() {
            if let Some(fetch) = self.fetches.get_mut(&existing) {
                fetch.add_waiter(waiter);
                return false;
            }
        }
        self.fetches_by_key.insert(key.clone(), request_id);
        self.fetches
            .insert(request_id, BlobFetch::new(key, request_id, waiter));
        true
    }

    fn add_offer(
        &mut self,
        offer: BlobOffer,
        max_parallel_peers: usize,
        offer_wait: Duration,
    ) -> Vec<ChunkRequestPlan> {
        let Some(fetch) = self.fetches.get_mut(&offer.request_id) else {
            return Vec::new();
        };
        if fetch.key != offer.key || !fetch.add_offer(offer) {
            return Vec::new();
        }
        if fetch.requested.is_empty()
            && fetch.chunks.is_empty()
            && Instant::now().duration_since(fetch.started_at) < offer_wait
        {
            return Vec::new();
        }
        fetch.next_requests(max_parallel_peers)
    }

    fn record_chunk(&mut self, chunk: BlobChunk) -> Option<CompletedFetch> {
        let request_id = chunk.request_id;
        let fetch = self.fetches.get_mut(&request_id)?;
        let bytes = fetch.record_chunk(chunk)?;
        let fetch = self.fetches.remove(&request_id)?;
        self.fetches_by_key.remove(&fetch.key);
        Some(CompletedFetch {
            key: fetch.key,
            bytes,
            waiters: fetch.waiters,
        })
    }

    fn remove_fetch(&mut self, request_id: u64) -> Option<BlobFetch> {
        let fetch = self.fetches.remove(&request_id)?;
        self.fetches_by_key.remove(&fetch.key);
        Some(fetch)
    }
}

struct CompletedFetch {
    key: String,
    bytes: Bytes,
    waiters: Vec<oneshot::Sender<Option<Bytes>>>,
}

pub(crate) struct BlobRuntime<R: BlobReplicable> {
    repo: Arc<R>,
    self_id: NodeIdentifier,
    topic: String,
    net: Arc<dyn BlobNet>,
    state: Mutex<BlobRuntimeState>,
    request_counter: AtomicU64,
    shutdown: CancellationToken,
    cfg: BlobReplicationConfig,
}

impl<R: BlobReplicable> BlobRuntime<R> {
    pub(crate) fn new(
        repo: Arc<R>,
        self_id: NodeIdentifier,
        topic: String,
        net: Arc<dyn BlobNet>,
        shutdown: CancellationToken,
        cfg: Arc<super::ReplicationConfig>,
    ) -> Arc<Self> {
        let start = thread_rng().r#gen::<u64>().max(1);
        Arc::new(Self {
            repo,
            self_id,
            topic,
            net,
            state: Mutex::new(BlobRuntimeState::new()),
            request_counter: AtomicU64::new(start),
            shutdown,
            cfg: BlobReplicationConfig::from_replication(&cfg),
        })
    }

    pub(crate) fn start(self: &Arc<Self>) {
        spawn_decay_loop(self.clone());
    }

    async fn get_or_fetch(self: &Arc<Self>, key: &str) -> Option<Bytes> {
        let key = key.to_ascii_lowercase();
        if !is_valid_blob_key(&key) {
            return None;
        }
        if let Some(bytes) = self.repo.get_blob(&key).await {
            return Some(bytes);
        }

        let (tx, rx) = oneshot::channel();
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let should_start = self
            .state
            .lock()
            .start_fetch(key.clone(), request_id, tx);

        if should_start {
            if let Some(bytes) = self.repo.get_blob(&key).await {
                self.complete_fetch(request_id, Some(bytes)).await;
            } else {
                self.broadcast_find(request_id, &key).await;
                spawn_fetch_timeout(self.clone(), request_id);
            }
        }

        match rx.await {
            Ok(bytes) => bytes,
            Err(_) => None,
        }
    }

    async fn broadcast_find(&self, request_id: u64, key: &str) {
        if self
            .net
            .alive_members()
            .into_iter()
            .filter(|node| *node != self.self_id)
            .next()
            .is_none()
        {
            self.complete_fetch(request_id, None).await;
            return;
        }
        let body = BlobBody::Find(BlobFind {
            request_id,
            requester: self.self_id as u32,
            key: key.to_owned(),
            chunk_size: self.cfg.chunk_size as u32,
        });
        if let Err(e) = self.net.send_broadcast(&self.topic, body).await {
            trace!(error=%e, key, "blob find broadcast failed");
        }
    }

    async fn complete_fetch(&self, request_id: u64, bytes: Option<Bytes>) {
        let waiters = self
            .state
            .lock()
            .remove_fetch(request_id)
            .map(|fetch| fetch.waiters)
            .unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(bytes.clone());
        }
    }

    async fn handle_find(&self, from: NodeIdentifier, find: BlobFind) {
        if from == self.self_id
            || find.requester as NodeIdentifier != from
            || find.requester as NodeIdentifier == self.self_id
        {
            return;
        }
        if !is_valid_blob_key(&find.key) {
            return;
        }
        let Some(bytes) = self.repo.get_blob(&find.key).await else {
            return;
        };
        let chunk_size = normalized_chunk_size(find.chunk_size as usize, self.cfg.chunk_size);
        let chunk_count = chunk_count(bytes.len(), chunk_size);
        let offer = BlobOffer {
            request_id: find.request_id,
            provider: self.self_id as u32,
            key: find.key,
            size: bytes.len() as u64,
            chunk_count,
            chunk_size: chunk_size as u32,
        };
        let dst = find.requester as NodeIdentifier;
        if let Err(e) = self.net.send_unicast(dst, &self.topic, BlobBody::Offer(offer)).await {
            trace!(error=%e, %dst, "blob offer send failed");
        }
    }

    async fn handle_offer(&self, from: NodeIdentifier, offer: BlobOffer) {
        if from == self.self_id
            || offer.provider as NodeIdentifier != from
            || offer.provider as NodeIdentifier == self.self_id
            || offer.chunk_size as usize > self.cfg.chunk_size
        {
            return;
        }
        if !is_valid_blob_key(&offer.key) {
            return;
        }
        let requests = {
            let mut state = self.state.lock();
            state.add_offer(
                offer,
                self.cfg.max_parallel_peers,
                self.cfg.offer_wait,
            )
        };
        self.send_chunk_requests(requests).await;
    }

    async fn handle_chunk_req(&self, from: NodeIdentifier, req: BlobChunkReq) {
        if from == self.self_id
            || req.requester as NodeIdentifier != from
            || req.requester as NodeIdentifier == self.self_id
        {
            return;
        }
        if !is_valid_blob_key(&req.key) {
            return;
        }
        let Some(bytes) = self.repo.get_blob(&req.key).await else {
            return;
        };
        let chunk_size = normalized_chunk_size(req.chunk_size as usize, self.cfg.chunk_size);
        let dst = req.requester as NodeIdentifier;
        let total_size = bytes.len() as u64;
        for index in req.indexes {
            let Some(data) = slice_chunk(&bytes, index, chunk_size) else {
                continue;
            };
            let chunk = BlobChunk {
                request_id: req.request_id,
                provider: self.self_id as u32,
                key: req.key.clone(),
                index,
                chunk_size: chunk_size as u32,
                total_size,
                data,
            };
            if let Err(e) = self
                .net
                .send_unicast(dst, &self.topic, BlobBody::Chunk(chunk))
                .await
            {
                trace!(error=%e, %dst, "blob chunk send failed");
                break;
            }
        }
    }

    async fn handle_chunk(&self, from: NodeIdentifier, chunk: BlobChunk) {
        if from == self.self_id
            || chunk.provider as NodeIdentifier != from
            || chunk.provider as NodeIdentifier == self.self_id
            || chunk.chunk_size as usize > self.cfg.chunk_size
        {
            return;
        }
        let completed = {
            let mut state = self.state.lock();
            state.record_chunk(chunk)
        };
        if let Some(completed) = completed {
            let computed = sha1_hex(&completed.bytes);
            let result = if computed == completed.key {
                match self
                    .repo
                    .put_blob(&completed.key, completed.bytes.clone())
                    .await
                {
                    Ok(()) => Some(completed.bytes),
                    Err(e) => {
                        warn!(error=%e, key=%completed.key, "blob store write failed");
                        None
                    }
                }
            } else {
                warn!(
                    key=%completed.key,
                    computed=%computed,
                    "discarding downloaded blob with mismatched hash"
                );
                None
            };
            for waiter in completed.waiters {
                let _ = waiter.send(result.clone());
            }
        }
    }

    async fn send_chunk_requests(&self, requests: Vec<ChunkRequestPlan>) {
        for request in requests {
            if request.indexes.is_empty() {
                continue;
            }
            let body = BlobBody::ChunkReq(BlobChunkReq {
                request_id: request.request_id,
                requester: self.self_id as u32,
                key: request.key,
                indexes: request.indexes,
                chunk_size: request.chunk_size,
            });
            if let Err(e) = self
                .net
                .send_unicast(request.provider, &self.topic, body)
                .await
            {
                trace!(error=%e, dst=%request.provider, "blob chunk request send failed");
            }
        }
    }

    async fn expire_fetches(&self) {
        let now = Instant::now();
        let mut to_retry = Vec::new();
        let mut to_refind = Vec::new();
        let mut expired = Vec::new();
        {
            let mut state = self.state.lock();
            for fetch in state.fetches.values_mut() {
                if now.duration_since(fetch.started_at) >= self.cfg.request_timeout {
                    expired.push(fetch.request_id);
                    continue;
                }
                let stale = fetch.stale_requested_indexes(now, self.cfg.retry_interval);
                if !stale.is_empty() {
                    let requests = fetch.next_requests(self.cfg.max_parallel_peers);
                    to_retry.extend(requests);
                } else if !fetch.offers.is_empty()
                    && fetch.requested.is_empty()
                    && !fetch.is_complete()
                    && now.duration_since(fetch.started_at) >= self.cfg.offer_wait
                {
                    let requests = fetch.next_requests(self.cfg.max_parallel_peers);
                    to_retry.extend(requests);
                } else if now.duration_since(fetch.started_at) >= self.cfg.offer_wait
                    && fetch.offers.is_empty()
                    && now.duration_since(fetch.last_request_at) >= self.cfg.retry_interval
                {
                    fetch.last_request_at = now;
                    to_refind.push((fetch.request_id, fetch.key.clone()));
                }
            }
        }

        self.send_chunk_requests(to_retry).await;
        for (request_id, key) in to_refind {
            self.broadcast_find(request_id, &key).await;
        }
        for request_id in expired {
            self.complete_fetch(request_id, None).await;
        }
    }

    async fn decay_once(&self) {
        let referenced = self.repo.referenced_keys().await;
        let now = Instant::now();
        let mut to_delete = Vec::new();
        {
            let mut state = self.state.lock();
            state.unused_since.retain(|key, _| !referenced.contains(key));
            let mut local_known = referenced.clone();
            for fetch in state.fetches.values() {
                local_known.insert(fetch.key.clone());
            }
            for key in local_known {
                state.unused_since.remove(&key);
            }
        }

        let candidates = self.repo.stored_keys().await;
        {
            let mut state = self.state.lock();
            for key in candidates {
                if referenced.contains(&key) {
                    continue;
                }
                let since = state.unused_since.entry(key.clone()).or_insert(now);
                if now.duration_since(*since) >= self.cfg.unused_grace {
                    to_delete.push(key);
                }
            }
        }

        for key in to_delete {
            if let Err(e) = self.repo.delete_blob(&key).await {
                warn!(error=%e, key, "blob decay delete failed");
            } else {
                self.state.lock().unused_since.remove(&key);
                debug!(key, "decayed unused channel blob");
            }
        }
    }

}

#[async_trait]
impl<R: BlobReplicable> ErasedBlobRuntime for BlobRuntime<R> {
    async fn dispatch(&self, from: NodeIdentifier, body: BlobBody) {
        match body {
            BlobBody::Find(f) => self.handle_find(from, f).await,
            BlobBody::Offer(o) => self.handle_offer(from, o).await,
            BlobBody::ChunkReq(r) => self.handle_chunk_req(from, r).await,
            BlobBody::Chunk(c) => self.handle_chunk(from, c).await,
        }
    }

    fn on_membership(&self, _ev: &MembershipEvent) {}

    fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

fn spawn_fetch_timeout<R: BlobReplicable>(rt: Arc<BlobRuntime<R>>, request_id: u64) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(rt.cfg.retry_interval);
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => {
                    rt.complete_fetch(request_id, None).await;
                    return;
                }
                _ = tick.tick() => {
                    let exists = rt.state.lock().fetches.contains_key(&request_id);
                    if !exists {
                        return;
                    }
                    rt.expire_fetches().await;
                }
            }
        }
    });
}

fn spawn_decay_loop<R: BlobReplicable>(rt: Arc<BlobRuntime<R>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(rt.cfg.decay_interval);
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = tick.tick() => rt.decay_once().await,
            }
        }
    });
}

fn is_valid_blob_key(key: &str) -> bool {
    key.len() == 40
        && key
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn normalized_chunk_size(requested: usize, default: usize) -> usize {
    requested.clamp(1, default.max(1))
}

fn chunk_count(size: usize, chunk_size: usize) -> u32 {
    if size == 0 {
        return 1;
    }
    size.div_ceil(chunk_size).min(u32::MAX as usize) as u32
}

fn slice_chunk(bytes: &Bytes, index: u32, chunk_size: usize) -> Option<Bytes> {
    let start = index as usize * chunk_size;
    if start > bytes.len() {
        return None;
    }
    if bytes.is_empty() && index == 0 {
        return Some(Bytes::new());
    }
    let end = (start + chunk_size).min(bytes.len());
    if start >= end {
        return None;
    }
    Some(bytes.slice(start..end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_count_rounds_up_and_keeps_empty_addressable() {
        assert_eq!(chunk_count(0, 8), 1);
        assert_eq!(chunk_count(1, 8), 1);
        assert_eq!(chunk_count(8, 8), 1);
        assert_eq!(chunk_count(9, 8), 2);
    }

    #[test]
    fn blob_fetch_reassembles_out_of_order_chunks() {
        let (tx, _rx) = oneshot::channel();
        let mut fetch = BlobFetch::new("a".repeat(40), 77, tx);
        assert!(fetch.add_offer(BlobOffer {
            request_id: 77,
            provider: 2,
            key: "a".repeat(40),
            size: 6,
            chunk_count: 3,
            chunk_size: 2,
        }));

        assert!(fetch
            .record_chunk(BlobChunk {
                request_id: 77,
                provider: 2,
                key: "a".repeat(40),
                index: 2,
                chunk_size: 2,
                total_size: 6,
                data: Bytes::from_static(b"ef"),
            })
            .is_none());
        assert!(fetch
            .record_chunk(BlobChunk {
                request_id: 77,
                provider: 2,
                key: "a".repeat(40),
                index: 0,
                chunk_size: 2,
                total_size: 6,
                data: Bytes::from_static(b"ab"),
            })
            .is_none());
        let bytes = fetch
            .record_chunk(BlobChunk {
                request_id: 77,
                provider: 2,
                key: "a".repeat(40),
                index: 1,
                chunk_size: 2,
                total_size: 6,
                data: Bytes::from_static(b"cd"),
            })
            .unwrap();
        assert_eq!(&bytes[..], b"abcdef");
    }
}
