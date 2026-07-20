use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::channel_handler::{ChannelTreeShadow, SessionChannelShadow};
use crate::client::Client;
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::client::state_log::{ClientGlobalStateDelta, ClientStateLogEntry, ClientStateOperation};
use crate::messages::Message;
use crate::messages::encoder::{UserRemove, UserState};
use crate::server::Server;
use parking_lot::RwLock as ParkingRwLock;
use shitspeak_state::ACLPermissions;
use shitspeak_state::{ChannelOp, ChannelOperation};

const DELETE_FANOUT_CACHE_MAX_ENTRIES: usize = 128;
const SUPERUSER_NODE_DISPLAY_TRAIT_PREFIX: &str = " [n";
type PackedSessionId = u32;

#[derive(Debug)]
pub struct UserVisibilityState {
    known: HashMap<PackedSessionId, KnownUserVisibility>,
    sessions_by_channel: HashMap<u32, HashSet<PackedSessionId>>,
    sessions_by_listener_channel: HashMap<u32, HashSet<PackedSessionId>>,
    registration: Option<VisibilityRegistration>,
}

#[derive(Debug, Clone)]
struct KnownUserVisibility {
    channel_id: u32,
    listener_channels: HashSet<u32>,
}

impl Clone for UserVisibilityState {
    fn clone(&self) -> Self {
        Self {
            known: self.known.clone(),
            sessions_by_channel: self.sessions_by_channel.clone(),
            sessions_by_listener_channel: self.sessions_by_listener_channel.clone(),
            registration: None,
        }
    }
}

impl Default for UserVisibilityState {
    fn default() -> Self {
        Self {
            known: HashMap::new(),
            sessions_by_channel: HashMap::new(),
            sessions_by_listener_channel: HashMap::new(),
            registration: None,
        }
    }
}

impl Drop for UserVisibilityState {
    fn drop(&mut self) {
        self.registration.take();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct VisibilityViewerId(u64);

#[derive(Debug)]
struct VisibilityRegistration {
    index: Arc<VisibilityFanoutIndex>,
    viewer_id: VisibilityViewerId,
    server_id: String,
}

impl VisibilityRegistration {
    fn matches(&self, index: &Arc<VisibilityFanoutIndex>, server_id: &str) -> bool {
        Arc::ptr_eq(&self.index, index) && self.server_id == server_id
    }

    fn add_current_channel(&self, channel_id: u32) {
        self.index
            .add_current_channel(self.viewer_id, &self.server_id, channel_id);
    }

    fn remove_current_channel(&self, channel_id: u32) {
        self.index
            .remove_current_channel(self.viewer_id, &self.server_id, channel_id);
    }

    fn add_listener_channel(&self, channel_id: u32) {
        self.index
            .add_listener_channel(self.viewer_id, &self.server_id, channel_id);
    }

    fn remove_listener_channel(&self, channel_id: u32) {
        self.index
            .remove_listener_channel(self.viewer_id, &self.server_id, channel_id);
    }

    fn clear_refs(&self) {
        self.index.clear_viewer_refs(self.viewer_id);
    }
}

impl Drop for VisibilityRegistration {
    fn drop(&mut self) {
        self.index.unregister_viewer(self.viewer_id);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VisibilityChannelKey {
    server_id: String,
    channel_id: u32,
}

impl VisibilityChannelKey {
    fn new(server_id: &str, channel_id: u32) -> Self {
        Self {
            server_id: server_id.to_owned(),
            channel_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VisibilityDeleteCacheKey {
    server_id: String,
    version: u64,
}

impl VisibilityDeleteCacheKey {
    fn new(server_id: &str, version: u64) -> Self {
        Self {
            server_id: server_id.to_owned(),
            version,
        }
    }
}

#[derive(Debug, Default)]
struct VisibilityViewerRefs {
    current_channels: HashSet<u32>,
    listener_channels: HashSet<u32>,
}

#[derive(Debug, Clone, Default)]
struct VisibilityViewerDeleteFanout {
    current_channels: HashSet<u32>,
    listener_channels: HashSet<u32>,
}

#[derive(Debug, Clone, Default)]
struct VisibilityDeleteFanout {
    viewers: HashMap<VisibilityViewerId, VisibilityViewerDeleteFanout>,
}

impl VisibilityDeleteFanout {
    fn get(&self, viewer_id: VisibilityViewerId) -> Option<&VisibilityViewerDeleteFanout> {
        self.viewers.get(&viewer_id)
    }
}

#[derive(Debug)]
struct VisibilityFanoutInner {
    current_by_channel: HashMap<VisibilityChannelKey, HashSet<VisibilityViewerId>>,
    listeners_by_channel: HashMap<VisibilityChannelKey, HashSet<VisibilityViewerId>>,
    viewer_refs: HashMap<VisibilityViewerId, VisibilityViewerRefs>,
    delete_cache: HashMap<VisibilityDeleteCacheKey, Arc<VisibilityDeleteFanout>>,
    delete_cache_order: VecDeque<VisibilityDeleteCacheKey>,
    delete_cache_max_entries: usize,
}

impl VisibilityFanoutInner {
    fn new(delete_cache_max_entries: usize) -> Self {
        Self {
            current_by_channel: HashMap::new(),
            listeners_by_channel: HashMap::new(),
            viewer_refs: HashMap::new(),
            delete_cache: HashMap::new(),
            delete_cache_order: VecDeque::new(),
            delete_cache_max_entries: delete_cache_max_entries.max(1),
        }
    }
}

#[derive(Debug)]
pub(crate) struct VisibilityFanoutIndex {
    next_viewer_id: AtomicU64,
    inner: ParkingRwLock<VisibilityFanoutInner>,
}

impl Default for VisibilityFanoutIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl VisibilityFanoutIndex {
    pub(crate) fn new() -> Self {
        Self::with_delete_cache_max_entries(DELETE_FANOUT_CACHE_MAX_ENTRIES)
    }

    fn with_delete_cache_max_entries(delete_cache_max_entries: usize) -> Self {
        Self {
            next_viewer_id: AtomicU64::new(1),
            inner: ParkingRwLock::new(VisibilityFanoutInner::new(delete_cache_max_entries)),
        }
    }

    fn register_viewer(self: &Arc<Self>, server_id: String) -> VisibilityRegistration {
        let viewer_id = VisibilityViewerId(self.next_viewer_id.fetch_add(1, Ordering::Relaxed));
        self.inner.write().viewer_refs.entry(viewer_id).or_default();
        VisibilityRegistration {
            index: Arc::clone(self),
            viewer_id,
            server_id,
        }
    }

    fn unregister_viewer(&self, viewer_id: VisibilityViewerId) {
        let mut inner = self.inner.write();
        remove_viewer_refs_from_inner(&mut inner, viewer_id);
        inner.viewer_refs.remove(&viewer_id);
    }

    fn clear_viewer_refs(&self, viewer_id: VisibilityViewerId) {
        let mut inner = self.inner.write();
        remove_viewer_refs_from_inner(&mut inner, viewer_id);
        inner.viewer_refs.entry(viewer_id).or_default();
    }

    fn add_current_channel(&self, viewer_id: VisibilityViewerId, server_id: &str, channel_id: u32) {
        let mut inner = self.inner.write();
        inner
            .viewer_refs
            .entry(viewer_id)
            .or_default()
            .current_channels
            .insert(channel_id);
        inner
            .current_by_channel
            .entry(VisibilityChannelKey::new(server_id, channel_id))
            .or_default()
            .insert(viewer_id);
    }

    fn remove_current_channel(
        &self,
        viewer_id: VisibilityViewerId,
        server_id: &str,
        channel_id: u32,
    ) {
        let mut inner = self.inner.write();
        if let Some(refs) = inner.viewer_refs.get_mut(&viewer_id) {
            refs.current_channels.remove(&channel_id);
        }
        remove_viewer_from_channel_index(
            &mut inner.current_by_channel,
            &VisibilityChannelKey::new(server_id, channel_id),
            viewer_id,
        );
    }

    fn add_listener_channel(
        &self,
        viewer_id: VisibilityViewerId,
        server_id: &str,
        channel_id: u32,
    ) {
        let mut inner = self.inner.write();
        inner
            .viewer_refs
            .entry(viewer_id)
            .or_default()
            .listener_channels
            .insert(channel_id);
        inner
            .listeners_by_channel
            .entry(VisibilityChannelKey::new(server_id, channel_id))
            .or_default()
            .insert(viewer_id);
    }

    fn remove_listener_channel(
        &self,
        viewer_id: VisibilityViewerId,
        server_id: &str,
        channel_id: u32,
    ) {
        let mut inner = self.inner.write();
        if let Some(refs) = inner.viewer_refs.get_mut(&viewer_id) {
            refs.listener_channels.remove(&channel_id);
        }
        remove_viewer_from_channel_index(
            &mut inner.listeners_by_channel,
            &VisibilityChannelKey::new(server_id, channel_id),
            viewer_id,
        );
    }

    fn delete_fanout(
        &self,
        server_id: &str,
        version: u64,
        deleted_channel_ids: &[u32],
    ) -> Arc<VisibilityDeleteFanout> {
        let cache_key = VisibilityDeleteCacheKey::new(server_id, version);
        let mut inner = self.inner.write();
        if let Some(fanout) = inner.delete_cache.get(&cache_key) {
            return Arc::clone(fanout);
        }

        let mut fanout = VisibilityDeleteFanout::default();
        for channel_id in deleted_channel_ids {
            let channel_key = VisibilityChannelKey::new(server_id, *channel_id);
            if let Some(viewers) = inner.current_by_channel.get(&channel_key) {
                for viewer_id in viewers {
                    fanout
                        .viewers
                        .entry(*viewer_id)
                        .or_default()
                        .current_channels
                        .insert(*channel_id);
                }
            }
            if let Some(viewers) = inner.listeners_by_channel.get(&channel_key) {
                for viewer_id in viewers {
                    fanout
                        .viewers
                        .entry(*viewer_id)
                        .or_default()
                        .listener_channels
                        .insert(*channel_id);
                }
            }
        }

        let fanout = Arc::new(fanout);
        inner
            .delete_cache
            .insert(cache_key.clone(), Arc::clone(&fanout));
        inner.delete_cache_order.push_back(cache_key);
        while inner.delete_cache_order.len() > inner.delete_cache_max_entries {
            if let Some(evicted) = inner.delete_cache_order.pop_front() {
                inner.delete_cache.remove(&evicted);
            }
        }
        fanout
    }
}

fn remove_viewer_refs_from_inner(inner: &mut VisibilityFanoutInner, viewer_id: VisibilityViewerId) {
    let Some(refs) = inner.viewer_refs.get_mut(&viewer_id) else {
        return;
    };
    let current_channels = std::mem::take(&mut refs.current_channels);
    let listener_channels = std::mem::take(&mut refs.listener_channels);
    for channel_id in current_channels {
        remove_viewer_from_channel_index_by_id(
            &mut inner.current_by_channel,
            viewer_id,
            channel_id,
        );
    }
    for channel_id in listener_channels {
        remove_viewer_from_channel_index_by_id(
            &mut inner.listeners_by_channel,
            viewer_id,
            channel_id,
        );
    }
}

fn remove_viewer_from_channel_index_by_id(
    index: &mut HashMap<VisibilityChannelKey, HashSet<VisibilityViewerId>>,
    viewer_id: VisibilityViewerId,
    channel_id: u32,
) {
    index.retain(|key, viewers| {
        if key.channel_id == channel_id {
            viewers.remove(&viewer_id);
        }
        !viewers.is_empty()
    });
}

fn remove_viewer_from_channel_index(
    index: &mut HashMap<VisibilityChannelKey, HashSet<VisibilityViewerId>>,
    key: &VisibilityChannelKey,
    viewer_id: VisibilityViewerId,
) {
    let Some(viewers) = index.get_mut(key) else {
        return;
    };
    viewers.remove(&viewer_id);
    if viewers.is_empty() {
        index.remove(key);
    }
}

#[derive(Debug, Clone, Default)]
pub struct VisibilityRefreshScope {
    sessions: HashSet<PackedSessionId>,
    channels: HashSet<u32>,
    listener_channel_removals: HashMap<PackedSessionId, HashSet<u32>>,
    include_all_channels: bool,
    include_known_users: bool,
    include_user_state_names: bool,
}

impl VisibilityRefreshScope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_session(session: ClientSessionIdentifier) -> Self {
        let mut scope = Self::new();
        scope.include_session(session);
        scope
    }

    pub fn include_session(&mut self, session: ClientSessionIdentifier) {
        self.sessions.insert(u32::from(session));
    }

    pub fn include_sessions(
        &mut self,
        sessions: impl IntoIterator<Item = ClientSessionIdentifier>,
    ) {
        self.sessions.extend(sessions.into_iter().map(u32::from));
    }

    pub fn include_channel(&mut self, channel_id: u32) {
        self.channels.insert(channel_id);
    }

    pub fn include_channels(&mut self, channel_ids: impl IntoIterator<Item = u32>) {
        self.channels.extend(channel_ids);
    }

    fn include_listener_channel_removal(
        &mut self,
        session: ClientSessionIdentifier,
        channel_ids: impl IntoIterator<Item = u32>,
    ) {
        self.listener_channel_removals
            .entry(u32::from(session))
            .or_default()
            .extend(channel_ids);
    }

    pub fn include_all_channels(&mut self) {
        self.include_all_channels = true;
    }

    pub fn include_known_users(&mut self) {
        self.include_known_users = true;
    }

    pub fn include_user_state_names(&mut self) {
        self.include_user_state_names = true;
    }

    pub(crate) fn channel_ids(&self) -> &HashSet<u32> {
        &self.channels
    }

    pub(crate) fn includes_all_channels(&self) -> bool {
        self.include_all_channels
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
            && self.channels.is_empty()
            && self.listener_channel_removals.is_empty()
            && !self.include_all_channels
            && !self.include_known_users
            && !self.include_user_state_names
    }

    pub fn merge(&mut self, other: VisibilityRefreshScope) {
        self.sessions.extend(other.sessions);
        self.channels.extend(other.channels);
        for (session, channel_ids) in other.listener_channel_removals {
            self.listener_channel_removals
                .entry(session)
                .or_default()
                .extend(channel_ids);
        }
        self.include_all_channels |= other.include_all_channels;
        self.include_known_users |= other.include_known_users;
        self.include_user_state_names |= other.include_user_state_names;
    }
}

impl UserVisibilityState {
    fn ensure_registered_for_server(&mut self, server: &Arc<Box<Server>>, server_id: &str) -> bool {
        self.register_with_index(Arc::clone(server.visibility_fanout_index()), server_id)
    }

    fn register_with_index(&mut self, index: Arc<VisibilityFanoutIndex>, server_id: &str) -> bool {
        if self
            .registration
            .as_ref()
            .is_some_and(|registration| registration.matches(&index, server_id))
        {
            return false;
        }

        self.registration.take();
        let registration = index.register_viewer(server_id.to_owned());
        for channel_id in self.sessions_by_channel.keys().copied() {
            registration.add_current_channel(channel_id);
        }
        for channel_id in self.sessions_by_listener_channel.keys().copied() {
            registration.add_listener_channel(channel_id);
        }
        self.registration = Some(registration);
        true
    }

    fn registered_viewer_id(&self, server_id: &str) -> Option<VisibilityViewerId> {
        self.registration
            .as_ref()
            .filter(|registration| registration.server_id == server_id)
            .map(|registration| registration.viewer_id)
    }

    pub fn clear(&mut self) {
        if let Some(registration) = &self.registration {
            registration.clear_refs();
        }
        self.known.clear();
        self.sessions_by_channel.clear();
        self.sessions_by_listener_channel.clear();
    }

    pub fn known_channel(&self, session: ClientSessionIdentifier) -> Option<u32> {
        self.known
            .get(&u32::from(session))
            .map(|known| known.channel_id)
    }

    fn get(&self, session: ClientSessionIdentifier) -> Option<&KnownUserVisibility> {
        self.known.get(&u32::from(session))
    }

    fn insert(
        &mut self,
        session: ClientSessionIdentifier,
        channel_id: u32,
        listener_channels: HashSet<u32>,
    ) {
        self.remove(session);
        let packed_session = u32::from(session);
        let current_bucket_was_empty = self
            .sessions_by_channel
            .get(&channel_id)
            .is_none_or(HashSet::is_empty);
        self.sessions_by_channel
            .entry(channel_id)
            .or_default()
            .insert(packed_session);
        if current_bucket_was_empty {
            if let Some(registration) = &self.registration {
                registration.add_current_channel(channel_id);
            }
        }
        for listener_channel_id in &listener_channels {
            let listener_bucket_was_empty = self
                .sessions_by_listener_channel
                .get(listener_channel_id)
                .is_none_or(HashSet::is_empty);
            self.sessions_by_listener_channel
                .entry(*listener_channel_id)
                .or_default()
                .insert(packed_session);
            if listener_bucket_was_empty {
                if let Some(registration) = &self.registration {
                    registration.add_listener_channel(*listener_channel_id);
                }
            }
        }
        self.known.insert(
            packed_session,
            KnownUserVisibility {
                channel_id,
                listener_channels,
            },
        );
    }

    fn remove(&mut self, session: ClientSessionIdentifier) -> bool {
        let packed_session = u32::from(session);
        let Some(known) = self.known.remove(&packed_session) else {
            return false;
        };
        if remove_indexed_session(
            &mut self.sessions_by_channel,
            known.channel_id,
            packed_session,
        ) {
            if let Some(registration) = &self.registration {
                registration.remove_current_channel(known.channel_id);
            }
        }
        for listener_channel_id in known.listener_channels {
            if remove_indexed_session(
                &mut self.sessions_by_listener_channel,
                listener_channel_id,
                packed_session,
            ) {
                if let Some(registration) = &self.registration {
                    registration.remove_listener_channel(listener_channel_id);
                }
            }
        }
        true
    }

    fn known_sessions(&self) -> impl Iterator<Item = ClientSessionIdentifier> + '_ {
        self.known_session_ids().map(ClientSessionIdentifier::from)
    }

    fn known_session_ids(&self) -> impl Iterator<Item = PackedSessionId> + '_ {
        self.known.keys().copied()
    }

    fn known_session_ids_in_channels(
        &self,
        channel_ids: &HashSet<u32>,
    ) -> HashSet<PackedSessionId> {
        self.session_ids_in_indexed_channels(channel_ids)
    }

    fn referenced_channel_ids(&self) -> HashSet<u32> {
        let mut channel_ids = HashSet::new();
        channel_ids.extend(self.sessions_by_channel.keys().copied());
        channel_ids.extend(self.sessions_by_listener_channel.keys().copied());
        channel_ids
    }

    fn session_ids_in_indexed_channels(
        &self,
        channel_ids: &HashSet<u32>,
    ) -> HashSet<PackedSessionId> {
        let mut sessions = HashSet::new();
        for channel_id in channel_ids {
            if let Some(channel_sessions) = self.sessions_by_channel.get(channel_id) {
                sessions.extend(channel_sessions.iter().copied());
            }
            if let Some(listener_sessions) = self.sessions_by_listener_channel.get(channel_id) {
                sessions.extend(listener_sessions.iter().copied());
            }
        }
        sessions
    }

    fn sessions_in_current_channels(
        &self,
        channel_ids: &HashSet<u32>,
    ) -> HashSet<ClientSessionIdentifier> {
        self.session_ids_in_current_channels(channel_ids)
            .into_iter()
            .map(ClientSessionIdentifier::from)
            .collect()
    }

    fn session_ids_in_current_channels(
        &self,
        channel_ids: &HashSet<u32>,
    ) -> HashSet<PackedSessionId> {
        let mut sessions = HashSet::new();
        for channel_id in channel_ids {
            if let Some(channel_sessions) = self.sessions_by_channel.get(channel_id) {
                sessions.extend(channel_sessions.iter().copied());
            }
        }
        sessions
    }

    fn sessions_listening_to_channels(
        &self,
        channel_ids: &HashSet<u32>,
    ) -> HashSet<ClientSessionIdentifier> {
        self.session_ids_listening_to_channels(channel_ids)
            .into_iter()
            .map(ClientSessionIdentifier::from)
            .collect()
    }

    fn session_ids_listening_to_channels(
        &self,
        channel_ids: &HashSet<u32>,
    ) -> HashSet<PackedSessionId> {
        let mut sessions = HashSet::new();
        for channel_id in channel_ids {
            if let Some(listener_sessions) = self.sessions_by_listener_channel.get(channel_id) {
                sessions.extend(listener_sessions.iter().copied());
            }
        }
        sessions
    }

    fn remove_visible_listener_channels(
        &mut self,
        session: ClientSessionIdentifier,
        channel_ids: &HashSet<u32>,
    ) -> Vec<u32> {
        let packed_session = u32::from(session);
        let Some(known) = self.known.get_mut(&packed_session) else {
            return Vec::new();
        };
        let mut removed = known
            .listener_channels
            .intersection(channel_ids)
            .copied()
            .collect::<Vec<_>>();
        if removed.is_empty() {
            return Vec::new();
        }
        removed.sort_unstable();
        for channel_id in &removed {
            known.listener_channels.remove(channel_id);
            if remove_indexed_session(
                &mut self.sessions_by_listener_channel,
                *channel_id,
                packed_session,
            ) {
                if let Some(registration) = &self.registration {
                    registration.remove_listener_channel(*channel_id);
                }
            }
        }
        removed
    }
}

fn remove_indexed_session(
    index: &mut HashMap<u32, HashSet<PackedSessionId>>,
    channel_id: u32,
    session: PackedSessionId,
) -> bool {
    let Some(sessions) = index.get_mut(&channel_id) else {
        return false;
    };
    sessions.remove(&session);
    if sessions.is_empty() {
        index.remove(&channel_id);
        true
    } else {
        false
    }
}

pub async fn can_view_user(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    target: &Arc<Box<Client>>,
) -> bool {
    if !server.get_hide_users_without_traverse() {
        return true;
    }
    if viewer.get_session_id() == target.get_session_id() {
        return true;
    }
    if !target.is_authenticated() {
        return false;
    }
    let perms = crate::client::acl::compute_permissions_for_client(
        server,
        viewer,
        target.get_current_channel_id(),
    )
    .await;
    perms.contains(ACLPermissions::Traverse)
}

async fn can_project_user(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    target: &Arc<Box<Client>>,
) -> bool {
    // A viewer must always retain their own UserState. The matching channel
    // and its parent chain are retained separately by channel projection.
    if viewer.get_session_id() == target.get_session_id() {
        return true;
    }
    if !can_view_user(server, viewer, target).await {
        return false;
    }
    if !server.get_hide_channels_without_traverse() {
        return true;
    }
    crate::channel_handler::can_view_channel_with_ancestors(
        server,
        viewer,
        target.get_current_channel_id(),
    )
    .await
}

pub async fn get_visible_client_in_server(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    server_id: &str,
    session: ClientSessionIdentifier,
) -> Option<Arc<Box<Client>>> {
    let target = server
        .get_clients()
        .get_client_in_server(server_id, session)
        .await?;
    if can_project_user(server, viewer, &target).await {
        Some(target)
    } else {
        None
    }
}

pub async fn visible_listener_channels(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    channels: HashSet<u32>,
) -> HashSet<u32> {
    if !server.get_hide_users_without_traverse() {
        return channels;
    }

    let mut visible = HashSet::new();
    for channel_id in channels {
        let traversable = if server.get_hide_channels_without_traverse() {
            crate::channel_handler::can_view_channel_with_ancestors(server, viewer, channel_id)
                .await
        } else {
            crate::client::acl::compute_permissions_for_client(server, viewer, channel_id)
                .await
                .contains(ACLPermissions::Traverse)
        };

        if traversable {
            visible.insert(channel_id);
        }
    }
    visible
}

pub async fn build_visible_user_state(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    target: &Arc<Box<Client>>,
) -> UserState {
    let mut state = target.build_user_state_for_broadcast();
    if server.get_hide_users_without_traverse() {
        let listener_channels =
            visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;
        state.listening_channel_add = sorted_channels(&listener_channels);
        state.listening_channel_remove.clear();
    }
    project_user_state_fields_for_viewer(server, viewer, &mut state);
    state
}

pub fn user_state_projection_is_viewer_independent(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
) -> bool {
    (!viewer.is_superuser() || !server.get_show_node_id_for_superusers())
        && !server.get_hide_users_without_traverse()
        && server.get_certificate_hash_privacy().is_none()
}

pub async fn initialize(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
) {
    visibility.clear();
    channel_shadow.clear();
    let server_id = viewer.server_id();
    if server.get_hide_users_without_traverse() {
        visibility.ensure_registered_for_server(server, &server_id);
    }
    for target in server
        .get_clients()
        .get_all_clients_in_server(&server_id)
        .await
    {
        if !target.is_authenticated() {
            continue;
        }
        if !can_project_user(server, viewer, &target).await {
            continue;
        }
        let listener_channels =
            visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;
        let session = target.get_session_id();
        let channel_id = target.get_current_channel_id();
        visibility.insert(session, channel_id, listener_channels);
        channel_shadow.insert(session, channel_id);
    }
}

/// Reconcile a live session after either visibility flag changes in a config
/// reload. The transport loops own their shadows, so this builds one ordered
/// transition for each session instead of asking clients to reconnect.
///
/// Removal order is users/listeners, then channels. Additions use the reverse
/// order: channels first, then complete user states.
pub async fn visibility_config_reload_messages(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
) -> Vec<Message> {
    let server_id = viewer.server_id();
    let hide_users_without_traverse = server.get_hide_users_without_traverse();
    let hiding_users_before = visibility.registered_viewer_id(&server_id).is_some();
    // A channel-only toggle can change which users/listeners qualify because
    // user visibility is evaluated against the target's current channel.
    // Rebuild the user projection whenever filtering is active; config reloads
    // are infrequent, so this avoids leaving stale users online.
    let users_mode_changed = hide_users_without_traverse || hiding_users_before;

    let old_sessions = session_channel_shadow
        .iter()
        .map(|(session, _)| session)
        .collect::<HashSet<_>>();
    let old_channel_ids = channel_tree_shadow.channel_ids().clone();

    let channels = server.get_channels().get_all_in_server(&server_id).await;
    let mut visible_channel_ids = HashSet::with_capacity(channels.len());
    for channel in &channels {
        if crate::channel_handler::can_view_channel(server, viewer, channel.id).await {
            visible_channel_ids.insert(channel.id);
        }
    }
    visible_channel_ids.extend(crate::channel_handler::channel_and_ancestor_ids(
        &channels,
        viewer.get_current_channel_id(),
    ));
    crate::channel_handler::close_visible_channel_ancestors(&channels, &mut visible_channel_ids);

    let mut visible_targets = Vec::new();
    let mut new_sessions = HashSet::new();
    if users_mode_changed {
        for target in server
            .get_clients()
            .get_all_clients_in_server(&server_id)
            .await
        {
            if !target.is_authenticated()
                || !target.is_published()
                || !can_project_user(server, viewer, &target).await
            {
                continue;
            }
            new_sessions.insert(target.get_session_id());
            visible_targets.push(target);
        }
        visible_targets.sort_by_key(|target| u32::from(target.get_session_id()));
    }

    let mut messages = Vec::new();

    let removed_channel_id_set = old_channel_ids
        .difference(&visible_channel_ids)
        .copied()
        .collect::<HashSet<_>>();
    let added_channel_id_set = visible_channel_ids
        .difference(&old_channel_ids)
        .copied()
        .collect::<HashSet<_>>();
    let ordered_channels = crate::channel_handler::ordered_snapshot_channels(&channels);
    let mut link_updates_before_removals = Vec::new();
    let mut link_updates_after_additions = Vec::new();
    if !removed_channel_id_set.is_empty() || !added_channel_id_set.is_empty() {
        for channel in &ordered_channels {
            if !old_channel_ids.contains(&channel.id) || !visible_channel_ids.contains(&channel.id)
            {
                continue;
            }
            let links_removed = channel
                .links
                .iter()
                .any(|linked_id| removed_channel_id_set.contains(linked_id));
            let links_added = channel
                .links
                .iter()
                .any(|linked_id| added_channel_id_set.contains(linked_id));

            if links_removed {
                let mut state =
                    crate::channel_handler::build_channel_state_message(server, viewer, channel)
                        .await;
                state.links.retain(|linked_id| {
                    old_channel_ids.contains(linked_id)
                        && !removed_channel_id_set.contains(linked_id)
                });
                link_updates_before_removals.push(state.into());
            }
            if links_added {
                let mut state =
                    crate::channel_handler::build_channel_state_message(server, viewer, channel)
                        .await;
                state
                    .links
                    .retain(|linked_id| visible_channel_ids.contains(linked_id));
                link_updates_after_additions.push(state.into());
            }
        }
    }

    let old_listener_channels = if hiding_users_before {
        visible_targets
            .iter()
            .filter_map(|target| {
                visibility
                    .get(target.get_session_id())
                    .map(|known| (target.get_session_id(), known.listener_channels.clone()))
            })
            .collect::<HashMap<_, _>>()
    } else {
        HashMap::new()
    };
    let mut listener_channels_by_session = HashMap::new();
    if users_mode_changed {
        for target in &visible_targets {
            let session = target.get_session_id();
            let listener_channels =
                visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;
            let old = old_listener_channels
                .get(&session)
                .cloned()
                .unwrap_or_else(|| target.get_listening_channel_ids());
            let removed = sorted_difference(&old, &listener_channels);
            if !removed.is_empty() {
                messages.push(
                    UserState {
                        session: Some(session),
                        listening_channel_remove: removed,
                        ..Default::default()
                    }
                    .into(),
                );
            }
            listener_channels_by_session.insert(session, listener_channels);
        }
    }

    if users_mode_changed {
        let mut removed_sessions = old_sessions
            .difference(&new_sessions)
            .copied()
            .collect::<Vec<_>>();
        removed_sessions.sort_by_key(|session| u32::from(*session));
        messages.extend(removed_sessions.into_iter().map(hidden_user_remove));
    }

    messages.extend(link_updates_before_removals);

    let removed_channel_ids = crate::channel_handler::channel_removal_ids_descendant_first(
        &channels,
        &removed_channel_id_set,
    );
    for channel_id in &removed_channel_ids {
        channel_tree_shadow.remove(channel_id);
        messages.push(
            crate::messages::encoder::ChannelRemove {
                channel_id: *channel_id,
            }
            .into(),
        );
    }

    let final_visible_channel_ids = visible_channel_ids.clone();
    for channel in &ordered_channels {
        if !visible_channel_ids.contains(&channel.id) || old_channel_ids.contains(&channel.id) {
            continue;
        }
        let mut state =
            crate::channel_handler::build_channel_state_message(server, viewer, &channel).await;
        state
            .links
            .retain(|linked_id| final_visible_channel_ids.contains(linked_id));
        channel_tree_shadow.insert(channel.id);
        messages.push(state.into());
    }

    messages.extend(link_updates_after_additions);

    if users_mode_changed {
        visibility.clear();
        if !hide_users_without_traverse {
            // Stop indexing this viewer once user filtering is disabled.
            visibility.registration.take();
        } else {
            visibility.ensure_registered_for_server(server, &server_id);
        }
        session_channel_shadow.clear();

        for target in visible_targets {
            let session = target.get_session_id();
            let listener_channels = listener_channels_by_session
                .remove(&session)
                .unwrap_or_else(|| target.get_listening_channel_ids());
            if hide_users_without_traverse {
                visibility.insert(
                    session,
                    target.get_current_channel_id(),
                    listener_channels.clone(),
                );
            }
            session_channel_shadow.insert(session, target.get_current_channel_id());
            let mut state = build_visible_user_state(server, viewer, &target).await;
            state.listening_channel_remove.clear();
            messages.push(state.into());
        }
    }

    messages
}

pub async fn project_message(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    message: &Message,
) -> Vec<Message> {
    if server.get_hide_users_without_traverse() {
        visibility.ensure_registered_for_server(server, &viewer.server_id());
    }
    match message {
        Message::UserState(user_state) => {
            let Ok(user_state) = UserState::try_from(user_state.clone()) else {
                return if server.get_hide_users_without_traverse() {
                    Vec::new()
                } else {
                    vec![message.clone()]
                };
            };
            let Some(session) = user_state.session else {
                return if server.get_hide_users_without_traverse() {
                    Vec::new()
                } else {
                    vec![message.clone()]
                };
            };
            if server.get_hide_users_without_traverse() {
                project_user_state(server, viewer, visibility, &user_state, session).await
            } else {
                let mut projected = user_state;
                project_user_state_fields_for_viewer(server, viewer, &mut projected);
                vec![projected.into()]
            }
        }
        Message::UserRemove(user_remove) => {
            if !server.get_hide_users_without_traverse() {
                return vec![message.clone()];
            }
            let session = ClientSessionIdentifier::from(user_remove.session);
            if !visibility.remove(session) {
                return Vec::new();
            }
            let mut projected = UserRemove::from(user_remove.clone());
            projected.actor = visible_actor(
                server,
                viewer,
                projected.actor.map(ClientSessionIdentifier::from),
            )
            .await
            .map(u32::from);
            vec![projected.into()]
        }
        _ => vec![message.clone()],
    }
}

pub async fn project_message_with_shadow(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
) -> Vec<Message> {
    if let Message::UserRemove(user_remove) = message {
        channel_shadow.remove(&ClientSessionIdentifier::from(user_remove.session));
    }

    let projected = project_message(server, viewer, visibility, message).await;
    let mut out = Vec::new();
    for message in projected {
        out.extend(
            sync_projected_message_with_shadow(
                server,
                viewer,
                visibility,
                channel_shadow,
                server_id,
                message,
            )
            .await,
        );
    }
    out
}

pub async fn sync_projected_message_with_shadow(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: Message,
) -> Vec<Message> {
    let mut out = vec![message.clone()];
    let synthetic = crate::channel_handler::sync_shadow_for_client_message(
        server,
        server.get_channels(),
        channel_shadow,
        server_id,
        &message,
    )
    .await;
    for synthetic_message in synthetic {
        let projected_synthetic =
            project_message(server, viewer, visibility, &synthetic_message).await;
        for projected in projected_synthetic {
            let _ = crate::channel_handler::sync_shadow_for_client_message(
                server,
                server.get_channels(),
                channel_shadow,
                server_id,
                &projected,
            )
            .await;
            out.push(projected);
        }
    }
    out
}

pub async fn visibility_refresh_messages(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    mut scope: VisibilityRefreshScope,
) -> Vec<Message> {
    let hide_users_without_traverse = server.get_hide_users_without_traverse();
    let include_user_state_names = scope.include_user_state_names;
    if scope.is_empty() || (!hide_users_without_traverse && !include_user_state_names) {
        return Vec::new();
    }

    let server_id = viewer.server_id();
    if hide_users_without_traverse {
        visibility.ensure_registered_for_server(server, &server_id);
    }
    let mut sessions = std::mem::take(&mut scope.sessions);
    if scope.include_known_users {
        if hide_users_without_traverse {
            sessions.extend(visibility.known_session_ids());
        } else if include_user_state_names {
            sessions.extend(
                server
                    .get_clients()
                    .get_all_clients_in_server(&server_id)
                    .await
                    .into_iter()
                    .filter(|target| target.is_authenticated() && target.is_published())
                    .map(|target| u32::from(target.get_session_id())),
            );
        }
    }

    let mut channels = std::mem::take(&mut scope.channels);
    if scope.include_all_channels {
        channels.extend(
            server
                .get_channels()
                .get_all_in_server(&server_id)
                .await
                .into_iter()
                .map(|channel| channel.id),
        );
    }

    if !channels.is_empty() {
        if hide_users_without_traverse {
            sessions.extend(visibility.known_session_ids_in_channels(&channels));
        }
        sessions.extend(
            server
                .get_clients()
                .get_clients_in_channels_or_listeners_in_server(&server_id, &channels)
                .await
                .into_iter()
                .filter(|target| target.is_authenticated())
                .map(|target| u32::from(target.get_session_id())),
        );
    }

    let mut messages = Vec::new();
    if hide_users_without_traverse {
        for (session, channel_ids) in scope.listener_channel_removals {
            if sessions.contains(&session) {
                continue;
            }
            let session = ClientSessionIdentifier::from(session);
            let removed = visibility.remove_visible_listener_channels(session, &channel_ids);
            if removed.is_empty() {
                continue;
            }
            messages.push(
                UserState {
                    session: Some(session),
                    listening_channel_remove: removed,
                    ..Default::default()
                }
                .into(),
            );
        }
    }

    let mut sessions = sessions.into_iter().collect::<Vec<_>>();
    sessions.sort_unstable();
    sessions.dedup();

    for packed_session in sessions {
        let session = ClientSessionIdentifier::from(packed_session);
        match server
            .get_clients()
            .get_client_in_server(&server_id, session)
            .await
        {
            Some(target) if target.is_authenticated() => {
                if hide_users_without_traverse {
                    messages.extend(
                        refresh_target_visibility(
                            server,
                            viewer,
                            visibility,
                            &target,
                            include_user_state_names,
                        )
                        .await,
                    );
                } else if include_user_state_names
                    && let Some(message) =
                        user_state_name_refresh_for_viewer(server, viewer, &target)
                {
                    messages.push(message);
                }
            }
            _ if hide_users_without_traverse && visibility.remove(session) => {
                messages.push(hidden_user_remove(session));
            }
            _ => {}
        }
    }
    messages
}

pub async fn visibility_refresh_messages_with_shadow(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    scope: VisibilityRefreshScope,
) -> Vec<Message> {
    let refresh = visibility_refresh_messages(server, viewer, visibility, scope).await;
    let mut out = Vec::new();
    for message in refresh {
        out.extend(
            sync_projected_message_with_shadow(
                server,
                viewer,
                visibility,
                channel_shadow,
                server_id,
                message,
            )
            .await,
        );
    }
    out
}

pub async fn visibility_refresh_scope_for_client_log_entry(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    entry: &ClientStateLogEntry,
    old_viewer_channel_id: Option<u32>,
) -> VisibilityRefreshScope {
    visibility_refresh_scope_for_client_log_entry_with_home_move_impact(
        server,
        viewer,
        entry,
        old_viewer_channel_id,
        None,
    )
    .await
}

pub(crate) async fn visibility_refresh_scope_for_client_log_entry_with_home_move_impact(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    entry: &ClientStateLogEntry,
    old_viewer_channel_id: Option<u32>,
    home_move_impact: Option<&crate::channel_handler::HomeChannelMoveImpact>,
) -> VisibilityRefreshScope {
    let mut scope = VisibilityRefreshScope::new();
    match &entry.op {
        ClientStateOperation::UpdateGlobalState {
            session_id,
            client_instance_id,
            delta,
            ..
        } if *session_id == viewer.get_session_id()
            && (*client_instance_id == 0 || *client_instance_id == viewer.client_instance_id()) =>
        {
            scope.merge(
                visibility_refresh_scope_for_viewer_delta(
                    server,
                    viewer,
                    delta,
                    old_viewer_channel_id,
                    home_move_impact,
                )
                .await,
            );
        }
        ClientStateOperation::ResetNode { .. } => {
            scope.include_known_users();
        }
        _ => {}
    }
    scope
}

pub async fn visibility_refresh_scope_for_channel_operation(
    server: &Arc<Box<Server>>,
    op: &ChannelOperation,
) -> VisibilityRefreshScope {
    visibility_refresh_scope_for_channel_operation_inner(server, op, None).await
}

pub async fn visibility_refresh_scope_for_channel_operation_with_state(
    server: &Arc<Box<Server>>,
    op: &ChannelOperation,
    visibility: &mut UserVisibilityState,
) -> VisibilityRefreshScope {
    visibility_refresh_scope_for_channel_operation_inner(server, op, Some(visibility)).await
}

async fn visibility_refresh_scope_for_channel_operation_inner(
    server: &Arc<Box<Server>>,
    op: &ChannelOperation,
    visibility: Option<&mut UserVisibilityState>,
) -> VisibilityRefreshScope {
    let mut scope = VisibilityRefreshScope::new();
    let channels = server.get_channels();
    let mut visibility = visibility;
    match &op.op {
        ChannelOp::CreateChannel { channel } => {
            scope.include_channel(channel.id);
        }
        ChannelOp::UpdateChannel { id, patch } | ChannelOp::EditChannel { id, patch, .. } => {
            if patch.parent_id.is_some() {
                // Reparenting can change the viewer's home-channel hierarchy when
                // the viewer is in the moved subtree. Refresh the unrelated
                // channels whose ACL chains depend on that hierarchy as well as
                // the moved subtree itself. The repository owns this affected-set
                // calculation so visibility and ACL-cache invalidation stay aligned.
                let mut affected_channel_ids = if server.get_hide_users_without_traverse() {
                    channels
                        .acl_affected_channel_ids_for_op(&op.server_id, &op.op)
                        .await
                        .unwrap_or_else(|| HashSet::from([*id]))
                } else {
                    HashSet::from([*id])
                };
                let all_channels = channels.get_all_in_server(&op.server_id).await;
                crate::channel_handler::expand_channel_ids_to_descendant_closure(
                    &all_channels,
                    &mut affected_channel_ids,
                );
                scope.include_channels(affected_channel_ids);
            }
        }
        ChannelOp::SetAcls { channel_id, .. } => {
            scope.include_channels(
                channels
                    .subtree_ids_in_server(&op.server_id, *channel_id)
                    .await,
            );
        }
        ChannelOp::DeleteChannel { id, .. } => {
            if let Some(visibility) = visibility.as_deref_mut() {
                if let Some(deleted_channel_ids) = channels.delete_visibility_hint_for_operation(op)
                {
                    let registered_now =
                        visibility.ensure_registered_for_server(server, &op.server_id);
                    if registered_now {
                        let deleted_channel_ids = deleted_channel_ids.iter().copied().collect();
                        include_delete_visibility_refresh(
                            &mut scope,
                            visibility,
                            &deleted_channel_ids,
                        );
                    } else if let Some(viewer_id) = visibility.registered_viewer_id(&op.server_id) {
                        let fanout = server.visibility_fanout_index().delete_fanout(
                            &op.server_id,
                            op.version,
                            &deleted_channel_ids,
                        );
                        if let Some(viewer_fanout) = fanout.get(viewer_id) {
                            include_delete_visibility_refresh_for_channels(
                                &mut scope,
                                visibility,
                                &viewer_fanout.current_channels,
                                &viewer_fanout.listener_channels,
                            );
                        }
                    }
                } else {
                    let referenced_channel_ids = visibility.referenced_channel_ids();
                    let existing_channel_ids = channels
                        .existing_channel_ids_in_server(&op.server_id, &referenced_channel_ids);
                    let stale_channel_ids = referenced_channel_ids
                        .into_iter()
                        .filter(|channel_id| !existing_channel_ids.contains(channel_id))
                        .collect();
                    include_delete_visibility_refresh(&mut scope, visibility, &stale_channel_ids);
                }
            } else {
                scope.include_channel(*id);
                scope.include_known_users();
            }
        }
        ChannelOp::InstallSnapshot { channels, .. } => {
            scope.include_channels(channels.iter().map(|channel| channel.id));
            scope.include_all_channels();
            scope.include_known_users();
        }
        ChannelOp::MarkPendingDelete { .. }
        | ChannelOp::CancelPendingDelete { .. }
        | ChannelOp::AddLink { .. }
        | ChannelOp::RemoveLink { .. } => {}
    }
    scope
}

fn include_delete_visibility_refresh(
    scope: &mut VisibilityRefreshScope,
    visibility: &UserVisibilityState,
    deleted_channel_ids: &HashSet<u32>,
) {
    include_delete_visibility_refresh_for_channels(
        scope,
        visibility,
        deleted_channel_ids,
        deleted_channel_ids,
    );
}

fn include_delete_visibility_refresh_for_channels(
    scope: &mut VisibilityRefreshScope,
    visibility: &UserVisibilityState,
    current_channel_ids: &HashSet<u32>,
    listener_channel_ids: &HashSet<u32>,
) {
    let current_sessions = visibility.session_ids_in_current_channels(current_channel_ids);
    scope.sessions.extend(current_sessions.iter().copied());

    for channel_id in listener_channel_ids {
        if let Some(listener_sessions) = visibility.sessions_by_listener_channel.get(channel_id) {
            for packed_session in listener_sessions {
                if current_sessions.contains(packed_session) {
                    continue;
                }
                scope
                    .listener_channel_removals
                    .entry(*packed_session)
                    .or_default()
                    .insert(*channel_id);
            }
        }
    }
}

async fn visibility_refresh_scope_for_viewer_delta(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    delta: &ClientGlobalStateDelta,
    old_viewer_channel_id: Option<u32>,
    home_move_impact: Option<&crate::channel_handler::HomeChannelMoveImpact>,
) -> VisibilityRefreshScope {
    let mut scope = VisibilityRefreshScope::new();
    if delta.user_id.is_some()
        || delta.groups.is_some()
        || delta.is_superuser.is_some()
        || delta.tokens.is_some()
    {
        scope.include_all_channels();
        scope.include_known_users();
        if delta.is_superuser.is_some() && server.get_show_node_id_for_superusers() {
            scope.include_user_state_names();
        }
    } else if let Some(new_channel_id) = delta.current_channel_id {
        // The viewer's old channel may no longer be retained after a move,
        // while the new channel and its parents must be introduced before
        // the self UserState points at them.
        scope.include_channel(new_channel_id);
        if let Some(old_channel_id) = old_viewer_channel_id {
            scope.include_channel(old_channel_id);
        }
        let impact = match home_move_impact {
            Some(impact) => impact,
            None => {
                // Non-connection callers may not already have the shared move
                // analysis. Preserve their behavior without making the common
                // connection path take a second channel snapshot.
                let calculated = crate::channel_handler::HomeChannelMoveImpact::calculate(
                    server,
                    viewer,
                    old_viewer_channel_id,
                    new_channel_id,
                )
                .await;
                scope.include_channels(calculated.visibility_channel_ids().iter().copied());
                return scope;
            }
        };
        scope.include_channels(impact.visibility_channel_ids().iter().copied());
    }
    scope
}

async fn project_user_state(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    raw: &UserState,
    session: ClientSessionIdentifier,
) -> Vec<Message> {
    let server_id = viewer.server_id();
    let Some(target) = server
        .get_clients()
        .get_client_in_server(&server_id, session)
        .await
    else {
        if visibility.remove(session) {
            return vec![hidden_user_remove(session)];
        }
        return Vec::new();
    };

    let visible = can_project_user(server, viewer, &target).await;
    let known_before = visibility.get(session).cloned();
    if !visible {
        if visibility.remove(session) {
            return vec![hidden_user_remove(session)];
        }
        return Vec::new();
    }

    let current_channel = target.get_current_channel_id();
    let new_listeners =
        visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;

    if known_before.is_none() {
        visibility.insert(session, current_channel, new_listeners.clone());
        let mut state = target.build_user_state_for_broadcast();
        state.listening_channel_add = sorted_channels(&new_listeners);
        state.listening_channel_remove.clear();
        project_user_state_fields_for_viewer(server, viewer, &mut state);
        return vec![state.into()];
    }

    let old = known_before.expect("checked is_some");
    visibility.insert(session, current_channel, new_listeners.clone());
    let mut projected = raw.clone();
    projected.actor = visible_actor(server, viewer, raw.actor).await;
    projected.listening_channel_add = sorted_difference(&new_listeners, &old.listener_channels);
    projected.listening_channel_remove = sorted_difference(&old.listener_channels, &new_listeners);
    project_user_state_fields_for_viewer(server, viewer, &mut projected);

    if user_state_delta_empty(&projected) {
        Vec::new()
    } else {
        vec![projected.into()]
    }
}

async fn refresh_target_visibility(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    target: &Arc<Box<Client>>,
    include_user_state_name: bool,
) -> Vec<Message> {
    let session = target.get_session_id();
    let known_before = visibility.get(session).cloned();
    let visible = can_project_user(server, viewer, target).await;

    if !visible {
        if visibility.remove(session) {
            return vec![hidden_user_remove(session)];
        }
        return Vec::new();
    }

    let current_channel = target.get_current_channel_id();
    let new_listeners =
        visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;

    match known_before {
        None => {
            visibility.insert(session, current_channel, new_listeners.clone());
            let mut state = target.build_user_state_for_broadcast();
            state.listening_channel_add = sorted_channels(&new_listeners);
            state.listening_channel_remove.clear();
            project_user_state_fields_for_viewer(server, viewer, &mut state);
            vec![state.into()]
        }
        Some(old) => {
            visibility.insert(session, current_channel, new_listeners.clone());
            let mut state = UserState {
                session: Some(session),
                channel_id: (old.channel_id != current_channel).then_some(current_channel),
                ..Default::default()
            };
            state.listening_channel_add = sorted_difference(&new_listeners, &old.listener_channels);
            state.listening_channel_remove =
                sorted_difference(&old.listener_channels, &new_listeners);
            if include_user_state_name {
                state.name = target.display_name_opt();
            }
            project_user_state_fields_for_viewer(server, viewer, &mut state);
            if user_state_delta_empty(&state) {
                Vec::new()
            } else {
                vec![state.into()]
            }
        }
    }
}

fn user_state_name_refresh_for_viewer(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    target: &Arc<Box<Client>>,
) -> Option<Message> {
    let mut state = UserState {
        session: Some(target.get_session_id()),
        name: target.display_name_opt(),
        ..Default::default()
    };
    project_user_state_fields_for_viewer(server, viewer, &mut state);
    (!user_state_delta_empty(&state)).then(|| state.into())
}

async fn visible_actor(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    actor: Option<ClientSessionIdentifier>,
) -> Option<ClientSessionIdentifier> {
    let actor = actor?;
    let server_id = viewer.server_id();
    let target = server
        .get_clients()
        .get_client_in_server(&server_id, actor)
        .await?;
    can_project_user(server, viewer, &target)
        .await
        .then_some(actor)
}

fn protect_user_state_hash_for_viewer(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    state: &mut UserState,
) {
    let Some((protection, secret)) = server.get_certificate_hash_privacy() else {
        return;
    };
    crate::privacy::protect_user_state_certificate_hash(
        state,
        viewer.is_superuser(),
        viewer.get_session_id(),
        protection,
        Some(secret.as_str()),
    );
}

fn project_user_state_fields_for_viewer(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    state: &mut UserState,
) {
    protect_user_state_hash_for_viewer(server, viewer, state);
    apply_superuser_node_display_trait(server, viewer, state);
}

fn apply_superuser_node_display_trait(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    state: &mut UserState,
) {
    if !server.get_show_node_id_for_superusers() || !viewer.is_superuser() {
        return;
    }
    let Some(session) = state.session else {
        return;
    };
    let Some(name) = state.name.as_mut() else {
        return;
    };
    append_node_display_trait(name, session.get_node_id());
}

fn append_node_display_trait(name: &mut String, node_id: u16) {
    let suffix = format!("{SUPERUSER_NODE_DISPLAY_TRAIT_PREFIX}{node_id}]");
    if !name.ends_with(&suffix) {
        name.push_str(&suffix);
    }
}

fn hidden_user_remove(session: ClientSessionIdentifier) -> Message {
    UserRemove {
        session: u32::from(session),
        actor: None,
        reason: None,
        ban: Some(false),
    }
    .into()
}

fn sorted_channels(channels: &HashSet<u32>) -> Vec<u32> {
    let mut out = channels.iter().copied().collect::<Vec<_>>();
    out.sort_unstable();
    out
}

fn sorted_difference(left: &HashSet<u32>, right: &HashSet<u32>) -> Vec<u32> {
    let mut out = left.difference(right).copied().collect::<Vec<_>>();
    out.sort_unstable();
    out
}

fn user_state_delta_empty(state: &UserState) -> bool {
    state.actor.is_none()
        && state.name.is_none()
        && state.user_id.is_none()
        && state.channel_id.is_none()
        && state.mute.is_none()
        && state.deaf.is_none()
        && state.suppress.is_none()
        && state.self_mute.is_none()
        && state.self_deaf.is_none()
        && state.texture.is_none()
        && state.plugin_context.is_none()
        && state.plugin_identity.is_none()
        && state.comment.is_none()
        && state.hash.is_none()
        && state.comment_hash.is_none()
        && state.texture_hash.is_none()
        && state.priority_speaker.is_none()
        && state.recording.is_none()
        && state.temporary_access_tokens.is_empty()
        && state.listening_channel_add.is_empty()
        && state.listening_channel_remove.is_empty()
        && state.listening_volume_adjustment.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: u32) -> ClientSessionIdentifier {
        ClientSessionIdentifier::new(1, id).expect("valid session")
    }

    fn channels(ids: &[u32]) -> HashSet<u32> {
        ids.iter().copied().collect()
    }

    #[test]
    fn node_display_trait_appends_node_id() {
        let mut name = "alice".to_owned();

        append_node_display_trait(&mut name, 42);

        assert_eq!(name, "alice [n42]");
    }

    #[test]
    fn node_display_trait_does_not_duplicate_matching_suffix() {
        let mut name = "alice [n42]".to_owned();

        append_node_display_trait(&mut name, 42);

        assert_eq!(name, "alice [n42]");
    }

    #[test]
    fn user_state_name_refresh_keeps_scope_non_empty() {
        let mut scope = VisibilityRefreshScope::new();

        scope.include_user_state_names();

        assert!(!scope.is_empty());
    }

    #[test]
    fn indexes_current_and_listener_channels_on_insert() {
        let mut visibility = UserVisibilityState::default();
        visibility.insert(session(10), 42, channels(&[7, 8]));

        assert_eq!(
            visibility.sessions_in_current_channels(&channels(&[42])),
            HashSet::from([session(10)])
        );
        assert_eq!(
            visibility.sessions_listening_to_channels(&channels(&[7])),
            HashSet::from([session(10)])
        );
    }

    #[test]
    fn indexes_remove_old_entries_on_insert_overwrite() {
        let mut visibility = UserVisibilityState::default();
        visibility.insert(session(10), 42, channels(&[7]));
        visibility.insert(session(10), 99, channels(&[8]));

        assert!(
            visibility
                .sessions_in_current_channels(&channels(&[42]))
                .is_empty()
        );
        assert!(
            visibility
                .sessions_listening_to_channels(&channels(&[7]))
                .is_empty()
        );
        assert_eq!(
            visibility.sessions_in_current_channels(&channels(&[99])),
            HashSet::from([session(10)])
        );
        assert_eq!(
            visibility.sessions_listening_to_channels(&channels(&[8])),
            HashSet::from([session(10)])
        );
    }

    #[test]
    fn indexes_remove_entries_on_remove_and_clear() {
        let mut visibility = UserVisibilityState::default();
        visibility.insert(session(10), 42, channels(&[7]));
        visibility.insert(session(11), 43, channels(&[8]));

        assert!(visibility.remove(session(10)));
        assert!(
            visibility
                .sessions_in_current_channels(&channels(&[42]))
                .is_empty()
        );
        assert!(
            visibility
                .sessions_listening_to_channels(&channels(&[7]))
                .is_empty()
        );

        visibility.clear();
        assert!(visibility.known_sessions().collect::<Vec<_>>().is_empty());
        assert!(
            visibility
                .sessions_in_current_channels(&channels(&[43]))
                .is_empty()
        );
        assert!(
            visibility
                .sessions_listening_to_channels(&channels(&[8]))
                .is_empty()
        );
    }

    #[test]
    fn listener_cleanup_updates_known_state_and_indexes() {
        let mut visibility = UserVisibilityState::default();
        visibility.insert(session(10), 42, channels(&[7, 8, 9]));

        let removed = visibility.remove_visible_listener_channels(session(10), &channels(&[7, 9]));

        assert_eq!(removed, vec![7, 9]);
        assert_eq!(
            visibility.get(session(10)).unwrap().listener_channels,
            channels(&[8])
        );
        assert!(
            visibility
                .sessions_listening_to_channels(&channels(&[7, 9]))
                .is_empty()
        );
        assert_eq!(
            visibility.sessions_listening_to_channels(&channels(&[8])),
            HashSet::from([session(10)])
        );
    }

    #[test]
    fn delete_scope_records_exact_listener_channel_removals() {
        let mut visibility = UserVisibilityState::default();
        visibility.insert(session(10), 42, channels(&[7, 99]));
        visibility.insert(session(11), 7, channels(&[8]));
        visibility.insert(session(12), 43, channels(&[8]));

        let mut scope = VisibilityRefreshScope::new();
        include_delete_visibility_refresh(&mut scope, &visibility, &channels(&[7, 8]));

        assert_eq!(scope.sessions, HashSet::from([u32::from(session(11))]));
        assert_eq!(
            scope
                .listener_channel_removals
                .get(&u32::from(session(10)))
                .cloned(),
            Some(channels(&[7]))
        );
        assert_eq!(
            scope
                .listener_channel_removals
                .get(&u32::from(session(12)))
                .cloned(),
            Some(channels(&[8]))
        );
        assert!(
            !scope
                .listener_channel_removals
                .contains_key(&u32::from(session(11)))
        );
    }

    #[test]
    fn delete_scope_with_empty_deleted_set_skips_valid_listener_channels() {
        let mut visibility = UserVisibilityState::default();
        visibility.insert(session(10), 42, channels(&[7]));

        let mut scope = VisibilityRefreshScope::new();
        include_delete_visibility_refresh(&mut scope, &visibility, &HashSet::new());

        assert!(scope.is_empty());
    }

    #[test]
    fn fanout_index_returns_only_affected_viewers_with_exact_channels() {
        let index = Arc::new(VisibilityFanoutIndex::with_delete_cache_max_entries(8));
        let mut affected = UserVisibilityState::default();
        let mut unaffected = UserVisibilityState::default();
        affected.register_with_index(Arc::clone(&index), "server-a");
        unaffected.register_with_index(Arc::clone(&index), "server-a");
        affected.insert(session(10), 42, channels(&[7, 99]));
        unaffected.insert(session(20), 100, channels(&[8]));

        let affected_id = affected.registered_viewer_id("server-a").unwrap();
        let unaffected_id = unaffected.registered_viewer_id("server-a").unwrap();
        let fanout = index.delete_fanout("server-a", 1, &[7, 42, 88]);
        let affected_fanout = fanout.get(affected_id).expect("affected viewer");

        assert_eq!(affected_fanout.current_channels, channels(&[42]));
        assert_eq!(affected_fanout.listener_channels, channels(&[7]));
        assert!(fanout.get(unaffected_id).is_none());
    }

    #[test]
    fn fanout_index_tracks_bucket_transitions() {
        let index = Arc::new(VisibilityFanoutIndex::with_delete_cache_max_entries(8));
        let mut visibility = UserVisibilityState::default();
        visibility.register_with_index(Arc::clone(&index), "server-a");
        let viewer_id = visibility.registered_viewer_id("server-a").unwrap();
        visibility.insert(session(10), 42, channels(&[7]));
        visibility.insert(session(11), 42, channels(&[7]));

        assert!(
            index
                .delete_fanout("server-a", 1, &[42, 7])
                .get(viewer_id)
                .is_some()
        );

        assert!(visibility.remove(session(10)));
        assert!(
            index
                .delete_fanout("server-a", 2, &[42, 7])
                .get(viewer_id)
                .is_some()
        );

        assert!(visibility.remove(session(11)));
        assert!(
            index
                .delete_fanout("server-a", 3, &[42, 7])
                .get(viewer_id)
                .is_none()
        );
    }

    #[test]
    fn fanout_index_unregisters_on_drop() {
        let index = Arc::new(VisibilityFanoutIndex::with_delete_cache_max_entries(8));
        let viewer_id = {
            let mut visibility = UserVisibilityState::default();
            visibility.register_with_index(Arc::clone(&index), "server-a");
            visibility.insert(session(10), 42, channels(&[7]));
            visibility.registered_viewer_id("server-a").unwrap()
        };

        assert!(
            index
                .delete_fanout("server-a", 1, &[42, 7])
                .get(viewer_id)
                .is_none()
        );
    }

    #[test]
    fn registered_clear_removes_global_refs_but_keeps_registration() {
        let index = Arc::new(VisibilityFanoutIndex::with_delete_cache_max_entries(8));
        let mut visibility = UserVisibilityState::default();
        visibility.register_with_index(Arc::clone(&index), "server-a");
        visibility.insert(session(10), 42, channels(&[7]));
        let viewer_id = visibility.registered_viewer_id("server-a").unwrap();

        visibility.clear();
        assert!(
            index
                .delete_fanout("server-a", 1, &[42, 7])
                .get(viewer_id)
                .is_none()
        );

        visibility.insert(session(11), 43, channels(&[8]));
        let fanout = index.delete_fanout("server-a", 2, &[43, 8]);
        let viewer_fanout = fanout.get(viewer_id).expect("viewer remains registered");
        assert_eq!(viewer_fanout.current_channels, channels(&[43]));
        assert_eq!(viewer_fanout.listener_channels, channels(&[8]));
    }

    #[test]
    fn listener_cleanup_updates_global_fanout_index() {
        let index = Arc::new(VisibilityFanoutIndex::with_delete_cache_max_entries(8));
        let mut visibility = UserVisibilityState::default();
        visibility.register_with_index(Arc::clone(&index), "server-a");
        visibility.insert(session(10), 42, channels(&[7, 8]));
        let viewer_id = visibility.registered_viewer_id("server-a").unwrap();

        assert_eq!(
            visibility.remove_visible_listener_channels(session(10), &channels(&[7])),
            vec![7]
        );

        assert!(
            index
                .delete_fanout("server-a", 1, &[7])
                .get(viewer_id)
                .is_none()
        );
        assert!(
            index
                .delete_fanout("server-a", 2, &[8])
                .get(viewer_id)
                .is_some()
        );
    }

    #[test]
    fn cloned_visibility_state_is_unregistered_until_reindexed() {
        let index = Arc::new(VisibilityFanoutIndex::with_delete_cache_max_entries(8));
        let mut visibility = UserVisibilityState::default();
        visibility.register_with_index(Arc::clone(&index), "server-a");
        visibility.insert(session(10), 42, channels(&[7]));

        let mut cloned = visibility.clone();
        assert!(cloned.registered_viewer_id("server-a").is_none());

        cloned.register_with_index(Arc::clone(&index), "server-a");
        let cloned_id = cloned.registered_viewer_id("server-a").unwrap();
        let fanout = index.delete_fanout("server-a", 1, &[42, 7]);
        let cloned_fanout = fanout.get(cloned_id).expect("clone reindexed");
        assert_eq!(cloned_fanout.current_channels, channels(&[42]));
        assert_eq!(cloned_fanout.listener_channels, channels(&[7]));
    }

    #[test]
    fn delete_fanout_cache_is_bounded() {
        let index = Arc::new(VisibilityFanoutIndex::with_delete_cache_max_entries(2));

        let _ = index.delete_fanout("server-a", 1, &[42]);
        let _ = index.delete_fanout("server-a", 2, &[42]);
        let _ = index.delete_fanout("server-a", 3, &[42]);

        let inner = index.inner.read();
        assert_eq!(inner.delete_cache.len(), 2);
        assert!(
            !inner
                .delete_cache
                .contains_key(&VisibilityDeleteCacheKey::new("server-a", 1))
        );
        assert!(
            inner
                .delete_cache
                .contains_key(&VisibilityDeleteCacheKey::new("server-a", 2))
        );
        assert!(
            inner
                .delete_cache
                .contains_key(&VisibilityDeleteCacheKey::new("server-a", 3))
        );
    }
}
