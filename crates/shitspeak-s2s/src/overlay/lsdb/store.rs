//! Link-state database in-memory store + on-disk LSA floor.
//!
//! The LSDB is keyed by `origin: NodeIdentifier` and holds at most one
//! `LsaEntry` per origin. An incoming LSA is admitted iff its
//! `(boot_epoch, seq)` is strictly greater than the current `(boot_epoch,
//! seq)` for that origin in BOTH the LSDB and the on-disk floor.
//!
//! ## Floor (zombie defense)
//!
//! The floor is a single monotonic `(boot_epoch, seq)` per origin we have
//! ever seen. Every LSA admission advances it; persistence is debounced
//! via a [`Notify`]. The floor protects against the "stale LSA from a
//! partitioned peer revives a graceful-leaver" scenario AND the analogous
//! "we restart with empty LSDB and a stale LSA slips through" scenario.
//!
//! ## Lifecycle
//!
//! * Non-tombstone entries age out at `now - ts_local_received >=
//!   lsa_max_age` and emit `MembershipEvent::Failed(origin)`.
//! * Tombstone entries age out at `tombstone_in_memory_age` to free
//!   memory; the `Left` event was already emitted on first sight, so age-
//!   out is silent. The floor entry persists.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tracing::{Level, debug, trace, warn};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{PeerAddress, TransportKind};

use super::super::proto::{address_from_pb, address_to_pb, kind_to_u32, u32_to_kind};
use shitspeak_proto::s2s_overlay_proto as pb;

/// Replication service kinds advertised by one overlay member.
///
/// Missing fields on the wire default to enabled to keep rolling upgrades
/// compatible with existing full S2S nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicationServices {
    strict: bool,
    content: bool,
    owner: bool,
}

impl ReplicationServices {
    pub const ALL: Self = Self {
        strict: true,
        content: true,
        owner: true,
    };

    pub const NONE: Self = Self {
        strict: false,
        content: false,
        owner: false,
    };

    pub const STRICT_AND_CONTENT: Self = Self {
        strict: true,
        content: true,
        owner: false,
    };

    pub fn new(strict: bool, content: bool, owner: bool) -> Self {
        Self {
            strict,
            content,
            owner,
        }
    }

    pub fn strict(self) -> bool {
        self.strict
    }

    pub fn content(self) -> bool {
        self.content
    }

    pub fn owner(self) -> bool {
        self.owner
    }
}

impl Default for ReplicationServices {
    fn default() -> Self {
        Self::ALL
    }
}

/// Versioned-tree protocol support advertised by one overlay member.
///
/// Unlike the older application-service flags, an absent capability field
/// means unsupported. Sending a tree frame through an older relay would
/// otherwise make it silently treat the frame as an empty-destination
/// overlay message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DistributionCapabilities {
    protocol_version: u32,
    profile_ids: Vec<u32>,
}

impl DistributionCapabilities {
    /// Version 2 carries hop-rebased, peer-clock-aware distribution
    /// deadlines. Version 1 remains readable for rolling-upgrade fallback.
    pub const PROTOCOL_VERSION: u32 = 2;
    pub const V1_PROTOCOL_VERSION: u32 = 1;

    pub const UNSUPPORTED: Self = Self {
        protocol_version: 0,
        profile_ids: Vec::new(),
    };

    pub const V1_EMPTY: Self = Self {
        protocol_version: Self::V1_PROTOCOL_VERSION,
        profile_ids: Vec::new(),
    };

    pub fn v1(profile_ids: impl IntoIterator<Item = u32>) -> Self {
        let mut profile_ids: Vec<_> = profile_ids.into_iter().filter(|id| *id != 0).collect();
        profile_ids.sort_unstable();
        profile_ids.dedup();
        Self {
            protocol_version: Self::V1_PROTOCOL_VERSION,
            profile_ids,
        }
    }

    pub fn v2(profile_ids: impl IntoIterator<Item = u32>) -> Self {
        let mut profile_ids: Vec<_> = profile_ids.into_iter().filter(|id| *id != 0).collect();
        profile_ids.sort_unstable();
        profile_ids.dedup();
        Self {
            protocol_version: Self::PROTOCOL_VERSION,
            profile_ids,
        }
    }

    pub fn from_wire(protocol_version: u32, profile_ids: impl IntoIterator<Item = u32>) -> Self {
        if protocol_version == 0 {
            return Self::UNSUPPORTED;
        }
        let mut profile_ids: Vec<_> = profile_ids.into_iter().filter(|id| *id != 0).collect();
        profile_ids.sort_unstable();
        profile_ids.dedup();
        Self {
            protocol_version,
            profile_ids,
        }
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn profile_ids(&self) -> &[u32] {
        &self.profile_ids
    }

    pub fn supports(&self, required_protocol_version: u32, profile_id: u32) -> bool {
        self.protocol_version >= required_protocol_version
            && profile_id != 0
            && self.profile_ids.binary_search(&profile_id).is_ok()
    }
}

/// Application service kinds advertised by one overlay member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationServices {
    voice: bool,
    distribution: DistributionCapabilities,
}

impl ApplicationServices {
    pub const ALL: Self = Self {
        voice: true,
        distribution: DistributionCapabilities::V1_EMPTY,
    };

    pub const NONE: Self = Self {
        voice: false,
        distribution: DistributionCapabilities::V1_EMPTY,
    };

    pub fn new(voice: bool) -> Self {
        if voice { Self::ALL } else { Self::NONE }
    }

    pub fn with_distribution_capabilities(
        voice: bool,
        distribution: DistributionCapabilities,
    ) -> Self {
        Self {
            voice,
            distribution,
        }
    }

    pub fn all() -> Self {
        Self::ALL
    }

    pub fn none() -> Self {
        Self::NONE
    }

    pub fn voice(&self) -> bool {
        self.voice
    }

    pub fn distribution(&self) -> &DistributionCapabilities {
        &self.distribution
    }
}

impl Default for ApplicationServices {
    fn default() -> Self {
        Self::all()
    }
}

/// One LSA's domain-side representation.
#[derive(Clone, Debug)]
pub struct LsaEntry {
    pub origin: NodeIdentifier,
    pub boot_epoch: u64,
    pub seq: u64,
    pub ts_local_received: Instant,
    pub tombstone: bool,
    pub addresses: Vec<PeerAddress>,
    pub links: Vec<LinkAdvertised>,
    pub max_users: u64,
    pub transit_disabled: bool,
    pub replication_services: ReplicationServices,
    pub application_services: ApplicationServices,
}

#[derive(Clone, Debug)]
pub struct LinkAdvertised {
    pub neighbor: NodeIdentifier,
    pub rtt_us: u64,
    pub jitter_us: u64,
    pub throughput_bps: u64,
    pub observed_recv_bps: u64,
    pub observed_sent_bps: u64,
    pub throughput_confidence_ppm: u32,
    pub transports_mask: u32,
    /// Legacy route-cost value: the conservative effective loss.
    pub loss_ppm: u32,
    pub probe_loss_ppm: u32,
    pub native_loss_ppm: u32,
    pub data_health_ppm: u32,
    pub loss_sample_count: u64,
    pub transport_metrics: Vec<LinkTransportAdvertised>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkTransportAdvertised {
    transport: TransportKind,
    rtt_us: u64,
    jitter_us: u64,
    loss_ppm: u32,
    loss_sample_count: u64,
}

impl LinkTransportAdvertised {
    pub fn new(
        transport: TransportKind,
        rtt_us: u64,
        jitter_us: u64,
        loss_ppm: u32,
        loss_sample_count: u64,
    ) -> Self {
        Self {
            transport,
            rtt_us,
            jitter_us,
            loss_ppm,
            loss_sample_count,
        }
    }

    pub fn transport(self) -> TransportKind {
        self.transport
    }

    pub fn rtt_us(self) -> u64 {
        self.rtt_us
    }

    pub fn jitter_us(self) -> u64 {
        self.jitter_us
    }

    pub fn loss_ppm(self) -> u32 {
        self.loss_ppm
    }

    pub fn loss_sample_count(self) -> u64 {
        self.loss_sample_count
    }
}

const MAX_LINK_DELTAS_IN_LOG: usize = 16;

fn describe_lsa_entry_delta(previous: Option<&LsaEntry>, current: &LsaEntry) -> String {
    let Some(previous) = previous else {
        return "new_origin".to_string();
    };

    let mut changes = Vec::new();
    push_scalar_change(
        &mut changes,
        "tombstone",
        previous.tombstone,
        current.tombstone,
    );
    push_scalar_change(
        &mut changes,
        "max_users",
        previous.max_users,
        current.max_users,
    );
    push_scalar_change(
        &mut changes,
        "transit_disabled",
        previous.transit_disabled,
        current.transit_disabled,
    );
    push_scalar_change(
        &mut changes,
        "strict_replication",
        previous.replication_services.strict(),
        current.replication_services.strict(),
    );
    push_scalar_change(
        &mut changes,
        "content_replication",
        previous.replication_services.content(),
        current.replication_services.content(),
    );
    push_scalar_change(
        &mut changes,
        "owner_replication",
        previous.replication_services.owner(),
        current.replication_services.owner(),
    );
    push_scalar_change(
        &mut changes,
        "voice_service",
        previous.application_services.voice(),
        current.application_services.voice(),
    );
    push_scalar_change(
        &mut changes,
        "distribution_protocol_version",
        previous
            .application_services
            .distribution()
            .protocol_version(),
        current
            .application_services
            .distribution()
            .protocol_version(),
    );
    if previous.application_services.distribution().profile_ids()
        != current.application_services.distribution().profile_ids()
    {
        changes.push(format!(
            "distribution_profiles {:?}->{:?}",
            previous.application_services.distribution().profile_ids(),
            current.application_services.distribution().profile_ids(),
        ));
    }
    describe_address_delta(&mut changes, &previous.addresses, &current.addresses);
    describe_link_delta(&mut changes, &previous.links, &current.links);

    if changes.is_empty() {
        "content_unchanged".to_string()
    } else {
        changes.join("; ")
    }
}

fn push_scalar_change<T>(changes: &mut Vec<String>, field: &str, previous: T, current: T)
where
    T: Copy + Eq + Display,
{
    if previous != current {
        changes.push(format!("{field} {previous}->{current}"));
    }
}

fn describe_address_delta(
    changes: &mut Vec<String>,
    previous: &[PeerAddress],
    current: &[PeerAddress],
) {
    if previous == current {
        return;
    }

    let previous_set = previous.iter().copied().collect::<HashSet<_>>();
    let current_set = current.iter().copied().collect::<HashSet<_>>();

    let added = current
        .iter()
        .filter(|addr| !previous_set.contains(*addr))
        .copied()
        .collect::<Vec<_>>();
    let removed = previous
        .iter()
        .filter(|addr| !current_set.contains(*addr))
        .copied()
        .collect::<Vec<_>>();

    if added.is_empty() && removed.is_empty() {
        changes.push(format!(
            "address_order {:?}->{:?}",
            previous.iter().map(PeerAddress::addr).collect::<Vec<_>>(),
            current.iter().map(PeerAddress::addr).collect::<Vec<_>>()
        ));
    } else {
        changes.push(format!("addresses +{added:?} -{removed:?}"));
    }
}

fn describe_link_delta(
    changes: &mut Vec<String>,
    previous: &[LinkAdvertised],
    current: &[LinkAdvertised],
) {
    let previous_by_neighbor = link_map(previous);
    let current_by_neighbor = link_map(current);

    let added = current_by_neighbor
        .keys()
        .filter(|neighbor| !previous_by_neighbor.contains_key(*neighbor))
        .copied()
        .collect::<Vec<_>>();
    let removed = previous_by_neighbor
        .keys()
        .filter(|neighbor| !current_by_neighbor.contains_key(*neighbor))
        .copied()
        .collect::<Vec<_>>();

    if !added.is_empty() || !removed.is_empty() {
        changes.push(format!("links +{added:?} -{removed:?}"));
    }

    let previous_order = previous
        .iter()
        .map(|link| link.neighbor)
        .collect::<Vec<_>>();
    let current_order = current.iter().map(|link| link.neighbor).collect::<Vec<_>>();
    if added.is_empty()
        && removed.is_empty()
        && previous_order != current_order
        && previous_by_neighbor.len() == current_by_neighbor.len()
    {
        changes.push(format!("link_order {previous_order:?}->{current_order:?}"));
    }

    let mut logged_metric_deltas = 0usize;
    let mut omitted_metric_deltas = 0usize;
    for (neighbor, previous_link) in &previous_by_neighbor {
        let Some(current_link) = current_by_neighbor.get(neighbor) else {
            continue;
        };
        let Some(delta) = describe_single_link_delta(*neighbor, previous_link, current_link) else {
            continue;
        };
        if logged_metric_deltas < MAX_LINK_DELTAS_IN_LOG {
            changes.push(delta);
            logged_metric_deltas += 1;
        } else {
            omitted_metric_deltas += 1;
        }
    }
    if omitted_metric_deltas > 0 {
        changes.push(format!(
            "{omitted_metric_deltas} additional link metric changes omitted"
        ));
    }
}

fn link_map(links: &[LinkAdvertised]) -> BTreeMap<NodeIdentifier, &LinkAdvertised> {
    let mut out = BTreeMap::new();
    for link in links {
        out.insert(link.neighbor, link);
    }
    out
}

fn describe_single_link_delta(
    neighbor: NodeIdentifier,
    previous: &LinkAdvertised,
    current: &LinkAdvertised,
) -> Option<String> {
    let mut fields = Vec::new();
    push_scalar_change(&mut fields, "rtt_us", previous.rtt_us, current.rtt_us);
    push_scalar_change(
        &mut fields,
        "jitter_us",
        previous.jitter_us,
        current.jitter_us,
    );
    push_scalar_change(
        &mut fields,
        "throughput_bps",
        previous.throughput_bps,
        current.throughput_bps,
    );
    push_scalar_change(
        &mut fields,
        "observed_recv_bps",
        previous.observed_recv_bps,
        current.observed_recv_bps,
    );
    push_scalar_change(
        &mut fields,
        "observed_sent_bps",
        previous.observed_sent_bps,
        current.observed_sent_bps,
    );
    push_scalar_change(
        &mut fields,
        "throughput_confidence_ppm",
        previous.throughput_confidence_ppm,
        current.throughput_confidence_ppm,
    );
    if previous.transports_mask != current.transports_mask {
        fields.push(format!(
            "transports_mask {:#x}->{:#x}",
            previous.transports_mask, current.transports_mask
        ));
    }
    push_scalar_change(&mut fields, "loss_ppm", previous.loss_ppm, current.loss_ppm);
    push_scalar_change(
        &mut fields,
        "probe_loss_ppm",
        previous.probe_loss_ppm,
        current.probe_loss_ppm,
    );
    push_scalar_change(
        &mut fields,
        "native_loss_ppm",
        previous.native_loss_ppm,
        current.native_loss_ppm,
    );
    push_scalar_change(
        &mut fields,
        "data_health_ppm",
        previous.data_health_ppm,
        current.data_health_ppm,
    );
    push_scalar_change(
        &mut fields,
        "loss_sample_count",
        previous.loss_sample_count,
        current.loss_sample_count,
    );
    if previous.transport_metrics != current.transport_metrics {
        fields.push(format!(
            "transport_metrics {:?}->{:?}",
            previous.transport_metrics, current.transport_metrics
        ));
    }

    if fields.is_empty() {
        None
    } else {
        Some(format!("link[{neighbor}] {}", fields.join(", ")))
    }
}

impl LsaEntry {
    /// Build from a wire LSA. Returns `None` if `origin` is not a valid
    /// `NodeIdentifier` (overflows u16).
    pub fn from_pb(pb: &pb::LinkStateAdvert) -> Option<Self> {
        let origin = NodeIdentifier::try_from(pb.origin).ok()?;
        let addresses = pb.addresses.iter().filter_map(address_from_pb).collect();
        let links = pb
            .links
            .iter()
            .filter_map(|l| {
                let neighbor = NodeIdentifier::try_from(l.neighbor).ok()?;
                let observed_recv_bps = l.observed_recv_bps;
                let observed_sent_bps = if l.observed_sent_bps > 0 {
                    l.observed_sent_bps
                } else {
                    l.throughput_bps
                };
                let throughput_confidence_ppm = if l.throughput_confidence_ppm > 0 {
                    l.throughput_confidence_ppm.min(1_000_000)
                } else if l.throughput_bps > 0 {
                    1_000_000
                } else {
                    0
                };
                Some(LinkAdvertised {
                    neighbor,
                    rtt_us: l.rtt_us,
                    jitter_us: l.jitter_us,
                    throughput_bps: l
                        .throughput_bps
                        .max(observed_recv_bps.max(observed_sent_bps)),
                    observed_recv_bps,
                    observed_sent_bps,
                    throughput_confidence_ppm,
                    transports_mask: l.transports_mask,
                    loss_ppm: l.loss_ppm,
                    probe_loss_ppm: l.probe_loss_ppm,
                    native_loss_ppm: l.native_loss_ppm,
                    data_health_ppm: l.data_health_ppm,
                    loss_sample_count: l.loss_sample_count,
                    transport_metrics: l
                        .transport_metrics
                        .iter()
                        .filter_map(|metric| {
                            Some(LinkTransportAdvertised::new(
                                u32_to_kind(metric.transport)?,
                                metric.rtt_us,
                                metric.jitter_us,
                                metric.loss_ppm,
                                metric.loss_sample_count,
                            ))
                        })
                        .collect(),
                })
            })
            .collect();
        Some(LsaEntry {
            origin,
            boot_epoch: pb.boot_epoch,
            seq: pb.seq,
            ts_local_received: Instant::now(),
            tombstone: pb.tombstone,
            addresses,
            links,
            max_users: pb.max_users,
            transit_disabled: pb.transit_disabled,
            replication_services: ReplicationServices::new(
                !pb.strict_replication_disabled,
                !pb.content_replication_disabled,
                !pb.owner_replication_disabled,
            ),
            application_services: ApplicationServices::with_distribution_capabilities(
                !pb.voice_service_disabled,
                DistributionCapabilities::from_wire(
                    pb.distribution_protocol_version,
                    pb.distribution_profile_ids.iter().copied(),
                ),
            ),
        })
    }

    pub fn to_pb(&self) -> pb::LinkStateAdvert {
        use super::super::proto::node_to_wire;
        pb::LinkStateAdvert {
            origin: node_to_wire(self.origin),
            boot_epoch: self.boot_epoch,
            seq: self.seq,
            ts_emit_us: 0,
            tombstone: self.tombstone,
            addresses: self.addresses.iter().map(address_to_pb).collect(),
            links: self
                .links
                .iter()
                .map(|l| pb::LinkAdvert {
                    neighbor: node_to_wire(l.neighbor),
                    rtt_us: l.rtt_us,
                    jitter_us: l.jitter_us,
                    throughput_bps: l.observed_recv_bps.max(l.observed_sent_bps),
                    observed_recv_bps: l.observed_recv_bps,
                    observed_sent_bps: l.observed_sent_bps,
                    throughput_confidence_ppm: l.throughput_confidence_ppm.min(1_000_000),
                    transports_mask: l.transports_mask,
                    loss_ppm: l.loss_ppm,
                    probe_loss_ppm: l.probe_loss_ppm,
                    native_loss_ppm: l.native_loss_ppm,
                    data_health_ppm: l.data_health_ppm,
                    loss_sample_count: l.loss_sample_count,
                    transport_metrics: l
                        .transport_metrics
                        .iter()
                        .map(|metric| pb::LinkTransportMetric {
                            transport: kind_to_u32(metric.transport()),
                            rtt_us: metric.rtt_us(),
                            jitter_us: metric.jitter_us(),
                            loss_ppm: metric.loss_ppm(),
                            loss_sample_count: metric.loss_sample_count(),
                        })
                        .collect(),
                })
                .collect(),
            max_users: self.max_users,
            transit_disabled: self.transit_disabled,
            strict_replication_disabled: !self.replication_services.strict(),
            content_replication_disabled: !self.replication_services.content(),
            owner_replication_disabled: !self.replication_services.owner(),
            voice_service_disabled: !self.application_services.voice(),
            distribution_protocol_version: self
                .application_services
                .distribution()
                .protocol_version(),
            distribution_profile_ids: self
                .application_services
                .distribution()
                .profile_ids()
                .to_vec(),
        }
    }
}

/// Strictly-greater comparison on `(boot_epoch, seq)`.
#[inline]
pub fn is_strictly_newer(new_be: u64, new_seq: u64, cur_be: u64, cur_seq: u64) -> bool {
    new_be > cur_be || (new_be == cur_be && new_seq > cur_seq)
}

/// Outcome of an admission attempt. Used by the flood path to decide
/// whether to forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// New origin or strictly newer (boot_epoch, seq); store updated.
    Accepted,
    /// Same/older `(boot_epoch, seq)` — already known.
    Stale,
    /// Same boot_epoch, same or older seq, BUT old entry was tombstone-
    /// gone-from-memory yet floor knew this seq. Caller drops silently.
    BelowFloor,
}

#[derive(Debug, Clone, Copy)]
pub struct OriginVersion {
    pub boot_epoch: u64,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum DiffOutcome {
    /// Newer than what the requester says they have; send them ours.
    SendOurs,
    /// They have something newer or equal; skip.
    Skip,
}

/// On-disk floor entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FloorEntryDisk {
    origin: u32,
    boot_epoch: u64,
    seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FloorFileV1 {
    version: u32,
    floor: Vec<FloorEntryDisk>,
}

/// Monotonic per-origin floor: highest `(boot_epoch, seq)` we have ever
/// seen. Persisted to disk debounced.
pub struct LsaFloor {
    inner: RwLock<HashMap<NodeIdentifier, OriginVersion>>,
    local_node_id: NodeIdentifier,
    persistence_dir: Option<PathBuf>,
    persist_signal: Notify,
}

impl LsaFloor {
    pub fn new(local_node_id: NodeIdentifier, persistence_dir: Option<PathBuf>) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            local_node_id,
            persistence_dir,
            persist_signal: Notify::new(),
        }
    }

    /// Load from `lsa_floor.json` under `persistence_dir/overlay/`. Missing
    /// file is not an error.
    pub fn load(&self) {
        let Some(dir) = &self.persistence_dir else {
            return;
        };
        let path = floor_path(dir);
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<FloorFileV1>(&bytes) {
                Ok(v1) if v1.version == 1 => {
                    let mut g = self.inner.write();
                    for e in v1.floor {
                        if e.origin <= u16::MAX as u32
                            && e.origin as NodeIdentifier != self.local_node_id
                        {
                            g.insert(
                                e.origin as NodeIdentifier,
                                OriginVersion {
                                    boot_epoch: e.boot_epoch,
                                    seq: e.seq,
                                },
                            );
                        }
                    }
                    debug!(?path, count = g.len(), "lsa floor loaded");
                }
                Ok(_) => warn!(?path, "lsa floor: unrecognized version, ignoring"),
                Err(e) => warn!(?path, error=%e, "lsa floor parse error; starting fresh"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(?path, error=%e, "lsa floor read error; starting fresh"),
        }
    }

    pub fn get(&self, origin: NodeIdentifier) -> Option<OriginVersion> {
        if origin == self.local_node_id {
            return None;
        }
        self.inner.read().get(&origin).copied()
    }

    /// Advance the floor for `origin` to `(boot_epoch, seq)` if strictly
    /// greater. Returns true if changed.
    pub fn advance(&self, origin: NodeIdentifier, boot_epoch: u64, seq: u64) -> bool {
        if origin == self.local_node_id {
            return false;
        }
        let mut g = self.inner.write();
        let entry = g.entry(origin).or_insert(OriginVersion {
            boot_epoch: 0,
            seq: 0,
        });
        if is_strictly_newer(boot_epoch, seq, entry.boot_epoch, entry.seq) {
            entry.boot_epoch = boot_epoch;
            entry.seq = seq;
            self.persist_signal.notify_one();
            true
        } else {
            false
        }
    }

    /// Snapshot every entry for the persister.
    fn snapshot(&self) -> Vec<FloorEntryDisk> {
        self.inner
            .read()
            .iter()
            .filter(|(origin, _)| **origin != self.local_node_id)
            .map(|(origin, v)| FloorEntryDisk {
                origin: *origin as u32,
                boot_epoch: v.boot_epoch,
                seq: v.seq,
            })
            .collect()
    }

    fn write_now(&self) {
        let Some(dir) = &self.persistence_dir else {
            return;
        };
        let path = floor_path(dir);
        let snapshot = self.snapshot();
        let body = FloorFileV1 {
            version: 1,
            floor: snapshot,
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(?parent, error=%e, "lsa floor: cannot create dir");
                return;
            }
        }
        match serde_json::to_vec_pretty(&body) {
            Ok(bytes) => {
                let tmp = path.with_extension("json.tmp");
                if let Err(e) = std::fs::write(&tmp, &bytes) {
                    warn!(?tmp, error=%e, "lsa floor: write tmp failed");
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    warn!(?path, error=%e, "lsa floor: rename failed");
                }
            }
            Err(e) => warn!(error=%e, "lsa floor: serialize failed"),
        }
    }

    /// Subscribe to "floor changed" notifications.
    pub fn signal(&self) -> &Notify {
        &self.persist_signal
    }
}

fn floor_path(dir: &Path) -> PathBuf {
    dir.join("overlay").join("lsa_floor.json")
}

/// In-memory link-state database. Owned by `OverlayInner`.
pub struct LinkStateDb {
    inner: RwLock<HashMap<NodeIdentifier, LsaEntry>>,
    floor: Arc<LsaFloor>,
    change_signal: Notify,
    dirty_origins: RwLock<HashSet<NodeIdentifier>>,
}

fn distribution_epoch_hash_value(hash: &mut u64, value: u64) {
    *hash ^= value;
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

impl LinkStateDb {
    pub fn new(floor: Arc<LsaFloor>) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            floor,
            change_signal: Notify::new(),
            dirty_origins: RwLock::new(HashSet::new()),
        }
    }

    pub fn floor(&self) -> &Arc<LsaFloor> {
        &self.floor
    }

    /// Wakes routing recomputer + membership diff watcher.
    pub fn change_signal(&self) -> &Notify {
        &self.change_signal
    }

    /// Try to admit one incoming LSA. Order of checks:
    ///   1. If we have a current LSDB entry, accept iff strictly newer
    ///      than it; otherwise return `Stale`.
    ///   2. If we have no LSDB entry, fall back to the on-disk floor —
    ///      accept iff strictly newer than the floor; otherwise return
    ///      `BelowFloor` (zombie defense after age-out / our restart).
    ///   3. Admission advances the floor in place.
    pub fn admit(&self, lsa: LsaEntry) -> AdmissionResult {
        let origin = lsa.origin;
        let boot_epoch = lsa.boot_epoch;
        let seq = lsa.seq;
        let tombstone = lsa.tombstone;
        let debug_delta = tracing::enabled!(Level::TRACE);
        let mut previous_for_log = None;
        let mut delta_for_log = None;
        {
            let mut g = self.inner.write();
            if debug_delta {
                previous_for_log = g.get(&origin).cloned();
            }
            match g.get(&origin) {
                Some(prev) => {
                    if !is_strictly_newer(lsa.boot_epoch, lsa.seq, prev.boot_epoch, prev.seq) {
                        return AdmissionResult::Stale;
                    }
                }
                None => {
                    // No live entry — defer to the floor.
                    if let Some(fv) = self.floor.get(origin) {
                        if !is_strictly_newer(lsa.boot_epoch, lsa.seq, fv.boot_epoch, fv.seq) {
                            return AdmissionResult::BelowFloor;
                        }
                    }
                }
            }
            if debug_delta {
                delta_for_log = Some(describe_lsa_entry_delta(previous_for_log.as_ref(), &lsa));
            }
            // Advance floor under the write lock so any subsequent admit
            // sees the updated value.
            self.floor.advance(origin, lsa.boot_epoch, lsa.seq);
            g.insert(origin, lsa);
        }
        if let Some(delta) = delta_for_log {
            trace!(
                origin,
                previous_boot_epoch = previous_for_log.as_ref().map(|entry| entry.boot_epoch),
                previous_seq = previous_for_log.as_ref().map(|entry| entry.seq),
                boot_epoch,
                seq,
                tombstone,
                changes = %delta,
                "lsdb accepted lsa"
            );
        }
        self.mark_dirty(origin);
        self.change_signal.notify_waiters();
        AdmissionResult::Accepted
    }

    fn mark_dirty(&self, origin: NodeIdentifier) {
        self.dirty_origins.write().insert(origin);
    }

    pub(crate) fn drain_dirty_origins(&self) -> HashSet<NodeIdentifier> {
        std::mem::take(&mut *self.dirty_origins.write())
    }

    pub fn get(&self, origin: NodeIdentifier) -> Option<LsaEntry> {
        self.inner.read().get(&origin).cloned()
    }

    pub fn snapshot(&self) -> Vec<LsaEntry> {
        let mut out: Vec<LsaEntry> = self.inner.read().values().cloned().collect();
        out.sort_by_key(|e| e.origin);
        out
    }

    /// Stable structural epoch for profiled distribution trees.
    ///
    /// This represents only the active topology and eligibility state that
    /// can change a tree: member identity, transit and service eligibility,
    /// distribution capability, and directed neighbor transport masks.
    /// It intentionally omits LSA sequence numbers and sampled link metrics
    /// so metric changes can remain subject to distribution hysteresis.
    pub fn distribution_epoch(&self) -> u64 {
        let entries = self.inner.read();
        let mut active: Vec<_> = entries.values().filter(|entry| !entry.tombstone).collect();
        active.sort_by_key(|entry| entry.origin);
        let active_origins: HashSet<_> = active.iter().map(|entry| entry.origin).collect();

        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        distribution_epoch_hash_value(&mut hash, active.len() as u64);
        for entry in active {
            distribution_epoch_hash_value(&mut hash, u64::from(entry.origin));
            distribution_epoch_hash_value(&mut hash, entry.boot_epoch);
            distribution_epoch_hash_value(&mut hash, u64::from(entry.transit_disabled));
            distribution_epoch_hash_value(
                &mut hash,
                u64::from(entry.replication_services.strict()),
            );
            distribution_epoch_hash_value(
                &mut hash,
                u64::from(entry.replication_services.content()),
            );
            distribution_epoch_hash_value(&mut hash, u64::from(entry.replication_services.owner()));
            distribution_epoch_hash_value(&mut hash, u64::from(entry.application_services.voice()));

            let distribution = entry.application_services.distribution();
            distribution_epoch_hash_value(&mut hash, u64::from(distribution.protocol_version()));
            distribution_epoch_hash_value(&mut hash, distribution.profile_ids().len() as u64);
            for profile_id in distribution.profile_ids() {
                distribution_epoch_hash_value(&mut hash, u64::from(*profile_id));
            }

            let mut links: Vec<_> = entry
                .links
                .iter()
                .filter(|link| active_origins.contains(&link.neighbor))
                .collect();
            links.sort_by_key(|link| (link.neighbor, link.transports_mask));
            distribution_epoch_hash_value(&mut hash, links.len() as u64);
            for link in links {
                distribution_epoch_hash_value(&mut hash, u64::from(link.neighbor));
                distribution_epoch_hash_value(&mut hash, u64::from(link.transports_mask));
            }
        }
        hash.max(1)
    }

    pub(crate) fn with_entries<R>(
        &self,
        f: impl FnOnce(&HashMap<NodeIdentifier, LsaEntry>) -> R,
    ) -> R {
        let entries = self.inner.read();
        f(&entries)
    }

    pub(crate) fn alive_max_users(&self) -> u64 {
        self.inner
            .read()
            .values()
            .filter(|entry| !entry.tombstone)
            .map(|entry| entry.max_users)
            .sum()
    }

    pub(crate) fn edge_rtt_snapshot(&self) -> Vec<Duration> {
        self.inner
            .read()
            .values()
            .filter(|entry| !entry.tombstone)
            .flat_map(|entry| entry.links.iter())
            .filter_map(|link| {
                if link.rtt_us == 0 {
                    None
                } else {
                    Some(Duration::from_micros(link.rtt_us))
                }
            })
            .collect()
    }

    /// Compact `(origin, boot_epoch, seq)` digest.
    pub fn digest(&self) -> Vec<(NodeIdentifier, u64, u64)> {
        self.inner
            .read()
            .values()
            .map(|e| (e.origin, e.boot_epoch, e.seq))
            .collect()
    }

    /// Compute LSAs to send to a peer whose digest we just received.
    /// Returns LSAs strictly newer than what the peer has.
    pub fn diff_for(&self, peer_digest: &HashMap<NodeIdentifier, OriginVersion>) -> Vec<LsaEntry> {
        let g = self.inner.read();
        g.values()
            .filter(|e| match peer_digest.get(&e.origin) {
                Some(v) => is_strictly_newer(e.boot_epoch, e.seq, v.boot_epoch, v.seq),
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Sweep entries for age-out. Returns (failed, tombstone_swept).
    /// `failed` = origins whose non-tombstone LSA timed out.
    /// `tombstone_swept` = origins whose tombstone aged out of memory.
    pub fn sweep(
        &self,
        lsa_max_age: Duration,
        tombstone_in_memory_age: Duration,
    ) -> (Vec<NodeIdentifier>, Vec<NodeIdentifier>) {
        let now = Instant::now();
        let mut failed = Vec::new();
        let mut tombstone_swept = Vec::new();
        {
            let mut g = self.inner.write();
            g.retain(|origin, e| {
                let age = now.saturating_duration_since(e.ts_local_received);
                if e.tombstone {
                    if age >= tombstone_in_memory_age {
                        tombstone_swept.push(*origin);
                        return false;
                    }
                } else if age >= lsa_max_age {
                    failed.push(*origin);
                    return false;
                }
                true
            });
        }
        if !failed.is_empty() || !tombstone_swept.is_empty() {
            {
                let mut dirty = self.dirty_origins.write();
                dirty.extend(failed.iter().copied());
                dirty.extend(tombstone_swept.iter().copied());
            }
            self.change_signal.notify_waiters();
        }
        (failed, tombstone_swept)
    }

    /// Set of origins with an active (non-tombstone) LSA. Used for
    /// `alive_members()` and membership diffs.
    pub fn active_origins(&self) -> Vec<NodeIdentifier> {
        let mut out: Vec<_> = self
            .inner
            .read()
            .values()
            .filter(|e| !e.tombstone)
            .map(|e| e.origin)
            .collect();
        out.sort();
        out
    }

    fn active_origins_by_replication_kind(
        &self,
        enabled: impl Fn(ReplicationServices) -> bool,
    ) -> Vec<NodeIdentifier> {
        let mut out: Vec<_> = self
            .inner
            .read()
            .values()
            .filter(|e| !e.tombstone && enabled(e.replication_services))
            .map(|e| e.origin)
            .collect();
        out.sort();
        out
    }

    fn active_origins_by_application_kind(
        &self,
        enabled: impl Fn(&ApplicationServices) -> bool,
    ) -> Vec<NodeIdentifier> {
        let mut out: Vec<_> = self
            .inner
            .read()
            .values()
            .filter(|e| !e.tombstone && enabled(&e.application_services))
            .map(|e| e.origin)
            .collect();
        out.sort();
        out
    }

    /// Set of active origins that advertise strict replication service.
    pub fn strict_replication_origins(&self) -> Vec<NodeIdentifier> {
        self.active_origins_by_replication_kind(ReplicationServices::strict)
    }

    /// Set of active origins that advertise content/blob replication service.
    pub fn content_replication_origins(&self) -> Vec<NodeIdentifier> {
        self.active_origins_by_replication_kind(ReplicationServices::content)
    }

    /// Set of active origins that advertise owner-scoped replication service.
    pub fn owner_replication_origins(&self) -> Vec<NodeIdentifier> {
        self.active_origins_by_replication_kind(ReplicationServices::owner)
    }

    /// Set of active origins that advertise application voice service.
    pub fn voice_origins(&self) -> Vec<NodeIdentifier> {
        self.active_origins_by_application_kind(ApplicationServices::voice)
    }

    /// Capability snapshot for one active overlay member.
    pub fn distribution_capabilities(
        &self,
        node: NodeIdentifier,
    ) -> Option<DistributionCapabilities> {
        self.inner
            .read()
            .get(&node)
            .filter(|entry| !entry.tombstone)
            .map(|entry| entry.application_services.distribution().clone())
    }

    /// Whether one active member supports the requested generic distribution
    /// protocol version and profile. Older LSAs decode as unsupported.
    pub fn supports_distribution_profile(
        &self,
        node: NodeIdentifier,
        required_protocol_version: u32,
        profile_id: u32,
    ) -> bool {
        self.distribution_capabilities(node)
            .is_some_and(|capabilities| {
                capabilities.supports(required_protocol_version, profile_id)
            })
    }
}

/// Background task: write the floor to disk once per `interval` whenever
/// changes have been signalled. Cancellable via `shutdown`.
pub fn spawn_floor_persister(
    floor: Arc<LsaFloor>,
    interval: Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    floor.write_now();
                    return;
                }
                _ = floor.signal().notified() => {}
            }
            tokio::select! {
                _ = shutdown.cancelled() => {
                    floor.write_now();
                    return;
                }
                _ = tokio::time::sleep(interval) => {}
            }
            floor.write_now();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(origin: NodeIdentifier, boot: u64, seq: u64, tombstone: bool) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: boot,
            seq,
            ts_local_received: Instant::now(),
            tombstone,
            addresses: vec![],
            links: vec![],
            max_users: 0,
            transit_disabled: false,
            replication_services: ReplicationServices::ALL,
            application_services: ApplicationServices::ALL,
        }
    }

    fn test_link(neighbor: NodeIdentifier, rtt_us: u64) -> LinkAdvertised {
        LinkAdvertised {
            neighbor,
            rtt_us,
            jitter_us: 0,
            throughput_bps: 0,
            observed_recv_bps: 0,
            observed_sent_bps: 0,
            throughput_confidence_ppm: 0,
            transports_mask: 0,
            loss_ppm: 0,
            probe_loss_ppm: 0,
            native_loss_ppm: 0,
            data_health_ppm: 0,
            loss_sample_count: 0,
            transport_metrics: Vec::new(),
        }
    }

    #[test]
    fn distribution_epoch_ignores_lsa_sequence_and_link_metric_changes() {
        let db = LinkStateDb::new(Arc::new(LsaFloor::new(0, None)));
        let mut source = entry(1, 100, 1, false);
        source.links = vec![test_link(2, 1_000), test_link(3, 2_000)];
        source.links[0].transports_mask = 0b01;
        source.links[1].transports_mask = 0b10;
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        assert_eq!(db.admit(entry(2, 100, 1, false)), AdmissionResult::Accepted);
        assert_eq!(db.admit(entry(3, 100, 1, false)), AdmissionResult::Accepted);
        let before = db.distribution_epoch();

        source.seq = 2;
        source.max_users = 500;
        source.links.reverse();
        for link in &mut source.links {
            link.rtt_us = 99_000;
            link.jitter_us = 9_000;
            link.throughput_bps = 1_000_000;
            link.observed_recv_bps = 900_000;
            link.observed_sent_bps = 800_000;
            link.throughput_confidence_ppm = 750_000;
            link.loss_ppm = 200_000;
            link.probe_loss_ppm = 100_000;
            link.native_loss_ppm = 150_000;
            link.data_health_ppm = 50_000;
            link.loss_sample_count = 100;
            link.transport_metrics = vec![LinkTransportAdvertised::new(
                TransportKind::Udp,
                99_000,
                9_000,
                200_000,
                100,
            )];
        }
        assert_eq!(db.admit(source), AdmissionResult::Accepted);

        assert_eq!(db.distribution_epoch(), before);
    }

    #[test]
    fn distribution_epoch_changes_for_transit_service_capability_and_link_state() {
        let db = LinkStateDb::new(Arc::new(LsaFloor::new(0, None)));
        let mut source = entry(1, 100, 1, false);
        source.links = vec![test_link(2, 1_000)];
        source.links[0].transports_mask = 0b01;
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        assert_eq!(db.admit(entry(2, 100, 1, false)), AdmissionResult::Accepted);
        let initial = db.distribution_epoch();

        source.seq = 2;
        source.boot_epoch = 101;
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        let identity_changed = db.distribution_epoch();
        assert_ne!(identity_changed, initial);

        source.seq = 3;
        source.transit_disabled = true;
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        let transit_changed = db.distribution_epoch();
        assert_ne!(transit_changed, identity_changed);

        source.seq = 4;
        source.replication_services = ReplicationServices::NONE;
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        let replication_service_changed = db.distribution_epoch();
        assert_ne!(replication_service_changed, transit_changed);

        source.seq = 5;
        source.application_services = ApplicationServices::new(false);
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        let service_changed = db.distribution_epoch();
        assert_ne!(service_changed, replication_service_changed);

        source.seq = 6;
        source.application_services = ApplicationServices::with_distribution_capabilities(
            false,
            DistributionCapabilities::v2([1, 7]),
        );
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        let capability_changed = db.distribution_epoch();
        assert_ne!(capability_changed, service_changed);

        source.seq = 7;
        source.application_services = ApplicationServices::with_distribution_capabilities(
            false,
            DistributionCapabilities::v2([1, 8]),
        );
        assert_eq!(db.admit(source.clone()), AdmissionResult::Accepted);
        let profiles_changed = db.distribution_epoch();
        assert_ne!(profiles_changed, capability_changed);

        source.seq = 8;
        source.links[0].transports_mask = 0b10;
        assert_eq!(db.admit(source), AdmissionResult::Accepted);
        assert_ne!(db.distribution_epoch(), profiles_changed);
    }

    #[test]
    fn admit_first_lsa() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        assert_eq!(db.admit(entry(1, 100, 1, false)), AdmissionResult::Accepted);
        assert!(db.get(1).is_some());
    }

    #[test]
    fn lsa_roundtrips_max_users() {
        let mut lsa = entry(1, 100, 1, false);
        lsa.max_users = 250;
        lsa.transit_disabled = true;
        lsa.replication_services = ReplicationServices::STRICT_AND_CONTENT;
        lsa.application_services = ApplicationServices::NONE;
        lsa.links = vec![LinkAdvertised {
            neighbor: 2,
            rtt_us: 1_000,
            jitter_us: 100,
            throughput_bps: 10_000,
            observed_recv_bps: 4_000,
            observed_sent_bps: 10_000,
            throughput_confidence_ppm: 750_000,
            transports_mask: 1,
            loss_ppm: 25_000,
            probe_loss_ppm: 10_000,
            native_loss_ppm: 40_000,
            data_health_ppm: 5_000,
            loss_sample_count: 123,
            transport_metrics: vec![LinkTransportAdvertised::new(
                TransportKind::Udp,
                1_250,
                150,
                30_000,
                64,
            )],
        }];
        let pb = lsa.to_pb();
        assert_eq!(pb.max_users, 250);
        assert!(pb.transit_disabled);
        assert!(!pb.strict_replication_disabled);
        assert!(!pb.content_replication_disabled);
        assert!(pb.owner_replication_disabled);
        assert!(pb.voice_service_disabled);
        let wire_link = pb.links.first().unwrap();
        assert_eq!(wire_link.loss_ppm, 25_000);
        assert_eq!(wire_link.probe_loss_ppm, 10_000);
        assert_eq!(wire_link.native_loss_ppm, 40_000);
        assert_eq!(wire_link.data_health_ppm, 5_000);
        assert_eq!(wire_link.loss_sample_count, 123);
        assert_eq!(wire_link.throughput_bps, 10_000);
        assert_eq!(wire_link.observed_recv_bps, 4_000);
        assert_eq!(wire_link.observed_sent_bps, 10_000);
        assert_eq!(wire_link.throughput_confidence_ppm, 750_000);
        assert_eq!(wire_link.transport_metrics.len(), 1);
        assert_eq!(
            wire_link.transport_metrics[0],
            pb::LinkTransportMetric {
                transport: kind_to_u32(TransportKind::Udp),
                rtt_us: 1_250,
                jitter_us: 150,
                loss_ppm: 30_000,
                loss_sample_count: 64,
            }
        );
        let roundtrip = LsaEntry::from_pb(&pb).unwrap();
        assert_eq!(roundtrip.max_users, 250);
        assert!(roundtrip.transit_disabled);
        assert_eq!(
            roundtrip.replication_services,
            ReplicationServices::STRICT_AND_CONTENT
        );
        assert_eq!(roundtrip.application_services, ApplicationServices::NONE);
        let link = roundtrip.links.first().unwrap();
        assert_eq!(link.loss_ppm, 25_000);
        assert_eq!(link.probe_loss_ppm, 10_000);
        assert_eq!(link.native_loss_ppm, 40_000);
        assert_eq!(link.data_health_ppm, 5_000);
        assert_eq!(link.loss_sample_count, 123);
        assert_eq!(link.throughput_bps, 10_000);
        assert_eq!(link.observed_recv_bps, 4_000);
        assert_eq!(link.observed_sent_bps, 10_000);
        assert_eq!(link.throughput_confidence_ppm, 750_000);
        assert_eq!(
            link.transport_metrics,
            vec![LinkTransportAdvertised::new(
                TransportKind::Udp,
                1_250,
                150,
                30_000,
                64,
            )]
        );
    }

    #[test]
    fn distribution_capabilities_roundtrip_and_gate_member_support() {
        let mut lsa = entry(1, 100, 1, false);
        lsa.application_services = ApplicationServices::with_distribution_capabilities(
            true,
            DistributionCapabilities::v2([9, 3, 9]),
        );

        let pb = lsa.to_pb();
        assert_eq!(
            pb.distribution_protocol_version,
            DistributionCapabilities::PROTOCOL_VERSION
        );
        assert_eq!(pb.distribution_profile_ids, vec![3, 9]);

        let roundtrip = LsaEntry::from_pb(&pb).unwrap();
        assert!(roundtrip.application_services.distribution().supports(2, 3));
        assert!(roundtrip.application_services.distribution().supports(2, 9));
        assert!(!roundtrip.application_services.distribution().supports(2, 8));

        let db = LinkStateDb::new(Arc::new(LsaFloor::new(0, None)));
        assert_eq!(db.admit(roundtrip), AdmissionResult::Accepted);
        assert!(db.supports_distribution_profile(1, 2, 3));
        assert!(!db.supports_distribution_profile(1, 2, 8));
    }

    #[test]
    fn v1_distribution_capability_is_ineligible_for_v2_trees() {
        let capability = DistributionCapabilities::v1([3]);
        assert!(capability.supports(1, 3));
        assert!(!capability.supports(DistributionCapabilities::PROTOCOL_VERSION, 3));
    }

    #[test]
    fn missing_distribution_fields_are_unsupported() {
        let pb = pb::LinkStateAdvert {
            origin: 1,
            boot_epoch: 100,
            seq: 1,
            ..Default::default()
        };
        let lsa = LsaEntry::from_pb(&pb).unwrap();
        assert_eq!(
            lsa.application_services.distribution().protocol_version(),
            0
        );
        assert!(!lsa.application_services.distribution().supports(1, 1));
    }

    #[test]
    fn link_breakdown_fields_default_when_absent_on_wire() {
        let pb = pb::LinkStateAdvert {
            origin: 1,
            boot_epoch: 100,
            seq: 1,
            links: vec![pb::LinkAdvert {
                neighbor: 2,
                rtt_us: 1_000,
                loss_ppm: 25_000,
                ..Default::default()
            }],
            ..Default::default()
        };

        let lsa = LsaEntry::from_pb(&pb).unwrap();
        let link = lsa.links.first().unwrap();
        assert_eq!(link.loss_ppm, 25_000);
        assert_eq!(link.probe_loss_ppm, 0);
        assert_eq!(link.native_loss_ppm, 0);
        assert_eq!(link.data_health_ppm, 0);
        assert_eq!(link.loss_sample_count, 0);
        assert_eq!(link.observed_recv_bps, 0);
        assert_eq!(link.observed_sent_bps, 0);
        assert_eq!(link.throughput_confidence_ppm, 0);
    }

    #[test]
    fn link_state_db_sums_alive_max_users() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        let mut first = entry(1, 100, 1, false);
        first.max_users = 100;
        let mut second = entry(2, 100, 1, false);
        second.max_users = 200;
        let mut left = entry(3, 100, 1, true);
        left.max_users = 300;
        db.admit(first);
        db.admit(second);
        db.admit(left);
        assert_eq!(db.alive_max_users(), 300);
    }

    #[test]
    fn edge_rtt_snapshot_skips_zero_and_tombstoned_links() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        let mut alive = entry(1, 100, 1, false);
        alive.links = vec![test_link(2, 1_500), test_link(3, 0)];
        let mut left = entry(4, 100, 1, true);
        left.links = vec![test_link(5, 9_000)];
        db.admit(alive);
        db.admit(left);

        assert_eq!(db.edge_rtt_snapshot(), vec![Duration::from_micros(1_500)]);
    }

    #[test]
    fn replication_origins_filter_by_enabled_service() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        let strict_only = entry(1, 100, 1, false);
        let mut content_only = entry(2, 100, 1, false);
        content_only.replication_services = ReplicationServices::new(false, true, false);
        let mut owner_only = entry(3, 100, 1, false);
        owner_only.replication_services = ReplicationServices::new(false, false, true);
        let mut none = entry(4, 100, 1, false);
        none.replication_services = ReplicationServices::NONE;
        let mut left = entry(5, 100, 1, true);
        left.replication_services = ReplicationServices::ALL;

        db.admit(strict_only);
        db.admit(content_only);
        db.admit(owner_only);
        db.admit(none);
        db.admit(left);

        assert_eq!(db.strict_replication_origins(), vec![1]);
        assert_eq!(db.content_replication_origins(), vec![1, 2]);
        assert_eq!(db.owner_replication_origins(), vec![1, 3]);
    }

    #[test]
    fn voice_origins_filter_by_enabled_service() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        let voice = entry(1, 100, 1, false);
        let mut forwarder = entry(2, 100, 1, false);
        forwarder.application_services = ApplicationServices::NONE;
        let mut left = entry(3, 100, 1, true);
        left.application_services = ApplicationServices::ALL;

        db.admit(voice);
        db.admit(forwarder);
        db.admit(left);

        assert_eq!(db.voice_origins(), vec![1]);
    }

    #[test]
    fn reject_stale_seq() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        db.admit(entry(1, 100, 5, false));
        assert_eq!(db.admit(entry(1, 100, 3, false)), AdmissionResult::Stale);
    }

    #[test]
    fn higher_boot_epoch_supersedes() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        db.admit(entry(1, 100, 10, false));
        assert_eq!(db.admit(entry(1, 200, 0, false)), AdmissionResult::Accepted);
        let got = db.get(1).unwrap();
        assert_eq!(got.boot_epoch, 200);
        assert_eq!(got.seq, 0);
    }

    #[test]
    fn floor_blocks_zombie_after_age_out() {
        let floor = Arc::new(LsaFloor::new(0, None));
        // Floor has been advanced (e.g., by a tombstone admitted earlier).
        floor.advance(1, 100, 50);
        let db = LinkStateDb::new(floor);
        // LSDB is empty (entry aged out of memory).
        // Inject a stale LSA at same boot_epoch and lower seq.
        assert_eq!(
            db.admit(entry(1, 100, 49, false)),
            AdmissionResult::BelowFloor
        );
        assert!(db.get(1).is_none());
    }

    #[test]
    fn floor_admits_legitimate_restart() {
        let floor = Arc::new(LsaFloor::new(0, None));
        floor.advance(1, 100, 50);
        let db = LinkStateDb::new(floor);
        // Higher boot_epoch always wins.
        assert_eq!(db.admit(entry(1, 200, 0, false)), AdmissionResult::Accepted);
    }

    #[test]
    fn admit_advances_floor() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor.clone());
        db.admit(entry(1, 100, 5, false));
        let v = floor.get(1).unwrap();
        assert_eq!(v.boot_epoch, 100);
        assert_eq!(v.seq, 5);
    }

    #[test]
    fn local_origin_is_not_written_to_floor() {
        let floor = Arc::new(LsaFloor::new(1, None));
        let db = LinkStateDb::new(floor.clone());
        db.admit(entry(1, 100, 5, false));
        assert!(floor.get(1).is_none());

        // A later local LSA with the same boot epoch is judged against the
        // live LSDB entry, not against a persisted zombie-defense floor.
        assert_eq!(db.admit(entry(1, 100, 6, false)), AdmissionResult::Accepted);
    }

    #[test]
    fn dirty_origins_track_admit_and_sweep_once() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        db.admit(entry(1, 100, 5, false));
        db.admit(entry(2, 100, 1, false));
        assert_eq!(db.drain_dirty_origins(), HashSet::from([1, 2]));
        assert!(db.drain_dirty_origins().is_empty());

        {
            let mut g = db.inner.write();
            let e = g.get_mut(&1).unwrap();
            e.ts_local_received = Instant::now() - Duration::from_secs(60);
        }
        let (failed, _) = db.sweep(Duration::from_secs(30), Duration::from_secs(120));
        assert_eq!(failed, vec![1u16]);
        assert_eq!(db.drain_dirty_origins(), HashSet::from([1]));
    }

    #[test]
    fn sweep_ages_out_non_tombstone() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        db.admit(entry(1, 100, 5, false));
        // Shift ts_local_received back.
        {
            let mut g = db.inner.write();
            let e = g.get_mut(&1).unwrap();
            e.ts_local_received = Instant::now() - Duration::from_secs(60);
        }
        let (failed, _) = db.sweep(Duration::from_secs(30), Duration::from_secs(120));
        assert_eq!(failed, vec![1u16]);
    }

    #[test]
    fn floor_disk_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let f1 = LsaFloor::new(0, Some(dir.path().to_path_buf()));
        f1.advance(7, 1234, 9);
        f1.advance(8, 5678, 1);
        f1.write_now();
        let f2 = LsaFloor::new(0, Some(dir.path().to_path_buf()));
        f2.load();
        assert_eq!(f2.get(7).unwrap().boot_epoch, 1234);
        assert_eq!(f2.get(7).unwrap().seq, 9);
        assert_eq!(f2.get(8).unwrap().boot_epoch, 5678);
    }

    #[test]
    fn floor_disk_omits_and_ignores_local_origin() {
        let dir = tempfile::TempDir::new().unwrap();
        let f1 = LsaFloor::new(7, Some(dir.path().to_path_buf()));
        assert!(!f1.advance(7, 1234, 9));
        f1.advance(8, 5678, 1);
        f1.write_now();

        let raw = std::fs::read_to_string(floor_path(dir.path())).unwrap();
        assert!(!raw.contains("\"origin\": 7"));

        let f2 = LsaFloor::new(8, Some(dir.path().to_path_buf()));
        f2.load();
        assert!(f2.get(8).is_none());
    }
}
