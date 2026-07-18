//! Per-service-level shortest-path computation over the LSDB graph.
//!
//! For each `ServiceLevel`, we run a single-source Dijkstra from the
//! local node. The default cost functions and the per-edge admission
//! filter depend on the level:
//!
//! * `Reliable`: `rtt_us + cfg.reliable_throughput_penalty_us_kbps /
//!   max(throughput_kbps, 1)`. Edges whose `transports_mask` does not
//!   intersect `cfg.reliable_transports_mask` are dropped.
//! * `ReliableLowLatency`: `rtt_us + cfg.rll_jitter_weight * jitter_us`.
//!   Filtered against `cfg.rll_transports_mask`.
//! * `BestEffort`: `rtt_us`. Filtered against
//!   `cfg.best_effort_transports_mask`.
//!
//! Upper layers may request a different `RoutingMetric`; voice uses the
//! E-model-inspired conversational metric. Edges only count if BOTH
//! endpoints have non-tombstone LSAs. This matches LSDB-derived
//! membership: a peer is in the graph iff its LSA is current.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{
    ServiceLevel, TransportKind, apply_packet_loss_penalty, conversational_effective_delay_us,
    conversational_impairment,
};

use super::super::config::{OverlayConfig, transport_bit};
use super::super::lsdb::{LinkAdvertised, LinkStateDb, LinkTransportAdvertised, LsaEntry};
use super::RoutingMetric;

pub(crate) const MIN_ROUTE_LOSS_EXCLUSION_SAMPLES: u64 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEntry {
    pub next_hop: NodeIdentifier,
    pub cost: u64,
    pub latency_us: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RoutingGraph {
    active: HashSet<NodeIdentifier>,
    transit_disabled: HashSet<NodeIdentifier>,
    /// `links[origin]` = what `origin` observes about each of its neighbors.
    /// Each entry represents one directed edge: origin → link.neighbor, scored
    /// by origin's own measurements (RTT probes it sent, jitter/loss it
    /// received). The reverse edge B→A is stored separately under B's entry.
    links: HashMap<NodeIdentifier, Vec<LinkAdvertised>>,
}

impl RoutingGraph {
    pub(crate) fn from_lsdb(lsdb: &LinkStateDb) -> Self {
        lsdb.with_entries(|entries| Self::from_entries(entries.values()))
    }

    pub(crate) fn from_lsdb_filtered<F>(lsdb: &LinkStateDb, include_node: F) -> Self
    where
        F: Fn(NodeIdentifier) -> bool,
    {
        lsdb.with_entries(|entries| Self::from_entries_filtered(entries.values(), include_node))
    }

    fn from_entries<'a>(entries: impl IntoIterator<Item = &'a LsaEntry>) -> Self {
        Self::from_entries_filtered(entries, |_| true)
    }

    fn from_entries_filtered<'a, F>(
        entries: impl IntoIterator<Item = &'a LsaEntry>,
        include_node: F,
    ) -> Self
    where
        F: Fn(NodeIdentifier) -> bool,
    {
        let mut active = HashSet::new();
        let mut transit_disabled = HashSet::new();
        let mut links = HashMap::new();

        for entry in entries {
            if entry.tombstone || !include_node(entry.origin) {
                continue;
            }
            active.insert(entry.origin);
            if entry.transit_disabled {
                transit_disabled.insert(entry.origin);
            }
            links.insert(
                entry.origin,
                entry
                    .links
                    .iter()
                    .filter(|link| include_node(link.neighbor))
                    .cloned()
                    .collect(),
            );
        }

        Self {
            active,
            transit_disabled,
            links,
        }
    }

    pub(crate) fn active_len(&self) -> usize {
        self.active.len()
    }

    pub(crate) fn is_active(&self, node: NodeIdentifier) -> bool {
        self.active.contains(&node)
    }

    pub(crate) fn active_nodes(&self) -> impl Iterator<Item = NodeIdentifier> + '_ {
        self.active.iter().copied()
    }

    pub(crate) fn links_by_origin(
        &self,
    ) -> impl Iterator<Item = (NodeIdentifier, &[LinkAdvertised])> + '_ {
        self.links
            .iter()
            .map(|(origin, links)| (*origin, links.as_slice()))
    }

    pub(crate) fn transit_disabled(&self, node: NodeIdentifier) -> bool {
        self.transit_disabled.contains(&node)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PathCost {
    pub(crate) primary: u64,
    pub(crate) latency_us: u64,
    pub(crate) hops: u32,
}

impl PathCost {
    pub(crate) const ZERO: Self = Self {
        primary: 0,
        latency_us: 0,
        hops: 0,
    };

    pub(crate) fn add(self, edge: EdgeCost) -> Self {
        Self {
            primary: self.primary.saturating_add(edge.primary),
            latency_us: self.latency_us.saturating_add(edge.latency_us),
            hops: self.hops.saturating_add(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EdgeCost {
    pub(crate) primary: u64,
    pub(crate) latency_us: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ShortestPathTree {
    pub(crate) dist: HashMap<NodeIdentifier, PathCost>,
    pub(crate) prev: HashMap<NodeIdentifier, NodeIdentifier>,
}

/// Compute the shortest-path table from `self_id` for `level`.
/// Returns a map `dst -> RouteEntry`. The local node itself is not
/// included.
pub fn compute(
    lsdb: &LinkStateDb,
    self_id: NodeIdentifier,
    level: ServiceLevel,
    cfg: &OverlayConfig,
) -> HashMap<NodeIdentifier, RouteEntry> {
    compute_with_metric(
        lsdb,
        self_id,
        level,
        RoutingMetric::default_for_level(level),
        cfg,
    )
}

/// Compute the shortest-path table with an explicit route-selection metric.
pub fn compute_with_metric(
    lsdb: &LinkStateDb,
    self_id: NodeIdentifier,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> HashMap<NodeIdentifier, RouteEntry> {
    let graph = RoutingGraph::from_lsdb(lsdb);
    compute_on_graph(&graph, self_id, level, metric, cfg)
}

pub(crate) fn compute_on_graph(
    graph: &RoutingGraph,
    self_id: NodeIdentifier,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> HashMap<NodeIdentifier, RouteEntry> {
    let tree = shortest_path_tree(graph, self_id, level, metric, cfg);
    route_table_from_tree(&tree, self_id)
}

pub(crate) fn adjacency_for(
    graph: &RoutingGraph,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> HashMap<NodeIdentifier, Vec<(NodeIdentifier, EdgeCost)>> {
    let mask = match level {
        ServiceLevel::Reliable => cfg.reliable_transports_mask(),
        ServiceLevel::ReliableLowLatency => cfg.rll_transports_mask(),
        ServiceLevel::BestEffort => cfg.best_effort_transports_mask(),
    };

    let mut adj: HashMap<NodeIdentifier, Vec<(NodeIdentifier, EdgeCost)>> = HashMap::new();
    for (origin, links) in graph.links_by_origin() {
        let mut edges = Vec::new();
        for link in links {
            let metric_inputs = edge_metric_inputs(link, level, metric, cfg);
            if !graph.is_active(link.neighbor)
                || link.transports_mask & mask == 0
                || has_confident_excessive_loss(
                    metric_inputs.loss_ppm,
                    metric_inputs.loss_sample_count,
                    cfg.max_route_packet_loss_ppm(),
                )
            {
                continue;
            }
            let cost = compute_cost(link, metric, cfg, metric_inputs);
            edges.push((link.neighbor, cost));
        }
        adj.insert(origin, edges);
    }
    adj
}

pub(crate) fn shortest_path_tree(
    graph: &RoutingGraph,
    self_id: NodeIdentifier,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> ShortestPathTree {
    let adj = adjacency_for(graph, level, metric, cfg);

    // Dijkstra from self_id.
    let mut dist: HashMap<NodeIdentifier, PathCost> = HashMap::new();
    let mut prev: HashMap<NodeIdentifier, NodeIdentifier> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(PathCost, NodeIdentifier)>> = BinaryHeap::new();
    dist.insert(self_id, PathCost::ZERO);
    heap.push(Reverse((PathCost::ZERO, self_id)));

    while let Some(Reverse((d, u))) = heap.pop() {
        if dist.get(&u).is_some_and(|known| d > *known) {
            continue;
        }
        if u != self_id && graph.transit_disabled.contains(&u) {
            continue;
        }
        let Some(neighbors) = adj.get(&u) else {
            continue;
        };
        for (v, w) in neighbors {
            let nd = d.add(*w);
            if dist.get(v).map_or(true, |known| nd < *known) {
                dist.insert(*v, nd);
                prev.insert(*v, u);
                heap.push(Reverse((nd, *v)));
            }
        }
    }

    ShortestPathTree { dist, prev }
}

pub(crate) fn route_table_from_tree(
    tree: &ShortestPathTree,
    self_id: NodeIdentifier,
) -> HashMap<NodeIdentifier, RouteEntry> {
    // Walk back to find the next hop for every destination.
    let mut out = HashMap::new();
    for (dst, cost) in &tree.dist {
        let dst = *dst;
        if dst == self_id {
            continue;
        }
        // Trace back to the immediate successor of `self_id`.
        let mut cur = dst;
        loop {
            match tree.prev.get(&cur) {
                Some(p) if *p == self_id => {
                    out.insert(
                        dst,
                        RouteEntry {
                            next_hop: cur,
                            cost: cost.primary,
                            latency_us: cost.latency_us,
                        },
                    );
                    break;
                }
                Some(p) => cur = *p,
                None => break,
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct EdgeMetricInputs {
    rtt_us: u64,
    jitter_us: u64,
    loss_ppm: u32,
    loss_sample_count: u64,
}

fn edge_metric_inputs(
    link: &LinkAdvertised,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> EdgeMetricInputs {
    match metric {
        RoutingMetric::ReliableCost => {
            if let Some(tcp) = transport_metric(link, TransportKind::Tcp) {
                return edge_metric_inputs_from_transport(link, tcp);
            }
        }
        RoutingMetric::ReliableLowLatencyCost => {
            if let Some(candidate) = best_viable_reliable_udp_metric(link, metric, cfg) {
                return edge_metric_inputs_from_transport(link, candidate);
            }
        }
        RoutingMetric::BestEffortCost => {
            if level == ServiceLevel::BestEffort {
                if let Some(udp) = transport_metric(link, TransportKind::Udp) {
                    return edge_metric_inputs_from_transport(link, udp);
                }
            }
        }
        RoutingMetric::ConversationalQuality => {
            if level == ServiceLevel::BestEffort {
                if let Some(udp) = transport_metric(link, TransportKind::Udp) {
                    return edge_metric_inputs_from_transport(link, udp);
                }
            } else if let Some(candidate) = best_viable_reliable_udp_metric(link, metric, cfg) {
                return edge_metric_inputs_from_transport(link, candidate);
            }
        }
    }
    EdgeMetricInputs {
        rtt_us: link.rtt_us,
        jitter_us: link.jitter_us,
        loss_ppm: link.loss_ppm,
        loss_sample_count: link.loss_sample_count,
    }
}

fn transport_metric(
    link: &LinkAdvertised,
    transport: TransportKind,
) -> Option<&LinkTransportAdvertised> {
    link.transport_metrics
        .iter()
        .find(|metric| metric.transport() == transport)
}

fn edge_metric_inputs_from_transport(
    link: &LinkAdvertised,
    metric: &LinkTransportAdvertised,
) -> EdgeMetricInputs {
    EdgeMetricInputs {
        rtt_us: if metric.rtt_us() > 0 {
            metric.rtt_us()
        } else {
            link.rtt_us
        },
        jitter_us: metric.jitter_us(),
        loss_ppm: metric.loss_ppm(),
        loss_sample_count: metric.loss_sample_count(),
    }
}

fn best_viable_reliable_udp_metric<'a>(
    link: &'a LinkAdvertised,
    routing_metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> Option<&'a LinkTransportAdvertised> {
    link.transport_metrics
        .iter()
        .filter(|metric| matches!(metric.transport(), TransportKind::Kcp | TransportKind::Quic))
        .filter(|metric| link.transports_mask & transport_bit(metric.transport()) != 0)
        .filter(|metric| reliable_udp_metric_is_viable(link, metric, cfg))
        .min_by_key(|metric| transport_metric_cost(link, metric, routing_metric, cfg))
}

fn reliable_udp_metric_is_viable(
    link: &LinkAdvertised,
    metric: &LinkTransportAdvertised,
    cfg: &OverlayConfig,
) -> bool {
    let policy = cfg.transport_routing_policy();
    if metric.loss_sample_count() < policy.udp_family_min_samples() {
        return false;
    }
    if metric.loss_ppm() >= policy.udp_family_block_loss_ppm() {
        return false;
    }

    let tcp_loss = transport_metric(link, TransportKind::Tcp)
        .filter(|tcp| tcp.loss_sample_count() >= policy.udp_family_min_samples())
        .map(|tcp| tcp.loss_ppm())
        .or_else(|| {
            (link.loss_sample_count >= policy.udp_family_min_samples()).then_some(link.loss_ppm)
        });
    !tcp_loss.is_some_and(|tcp_loss| {
        metric.loss_ppm() >= tcp_loss.saturating_add(policy.udp_family_loss_excess_over_tcp_ppm())
    })
}

fn transport_metric_cost(
    link: &LinkAdvertised,
    metric: &LinkTransportAdvertised,
    routing_metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> u64 {
    let inputs = edge_metric_inputs_from_transport(link, metric);
    compute_cost(link, routing_metric, cfg, inputs).primary
}

fn has_confident_excessive_loss(loss_ppm: u32, loss_sample_count: u64, max_loss_ppm: u32) -> bool {
    route_loss_is_confident(loss_sample_count) && loss_ppm >= max_loss_ppm
}

fn compute_cost(
    link: &LinkAdvertised,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
    metric_inputs: EdgeMetricInputs,
) -> EdgeCost {
    let route_throughput_bps =
        confidence_weighted_throughput_bps(link.observed_sent_bps, link.throughput_confidence_ppm);
    let primary = match metric {
        RoutingMetric::ReliableCost => compute_reliable_cost(
            metric_inputs.rtt_us,
            route_throughput_bps,
            metric_inputs.loss_ppm,
            cfg,
        ),
        RoutingMetric::ReliableLowLatencyCost => compute_reliable_low_latency_cost(
            metric_inputs.rtt_us,
            metric_inputs.jitter_us,
            metric_inputs.loss_ppm,
            cfg,
        ),
        RoutingMetric::BestEffortCost => {
            apply_packet_loss_penalty(metric_inputs.rtt_us.max(1) as f64, metric_inputs.loss_ppm)
                .ceil() as u64
        }
        RoutingMetric::ConversationalQuality => (conversational_impairment(
            metric_inputs.rtt_us as f64,
            metric_inputs.jitter_us as f64,
            route_throughput_bps as f64,
            metric_inputs.loss_ppm,
        ) * 10_000.0)
            .ceil()
            .max(1.0) as u64,
    };
    let latency_us = match metric {
        RoutingMetric::ReliableCost
        | RoutingMetric::ReliableLowLatencyCost
        | RoutingMetric::BestEffortCost => metric_inputs.rtt_us.max(1),
        RoutingMetric::ConversationalQuality => conversational_effective_delay_us(
            metric_inputs.rtt_us as f64,
            metric_inputs.jitter_us as f64,
        )
        .max(1),
    };
    EdgeCost {
        primary: primary.max(1),
        latency_us,
    }
}

fn confidence_weighted_throughput_bps(observed_sent_bps: u64, confidence_ppm: u32) -> u64 {
    if observed_sent_bps == 0 {
        return 0;
    }
    let confidence = u64::from(confidence_ppm.min(1_000_000));
    observed_sent_bps
        .saturating_mul(confidence)
        .saturating_div(1_000_000)
}

fn route_loss_is_confident(loss_sample_count: u64) -> bool {
    loss_sample_count >= MIN_ROUTE_LOSS_EXCLUSION_SAMPLES
}

fn compute_reliable_low_latency_cost(
    rtt_us: u64,
    jitter_us: u64,
    loss_ppm: u32,
    cfg: &OverlayConfig,
) -> u64 {
    let weighted_jitter = (cfg.rll_jitter_weight() * jitter_us as f64) as u64;
    apply_packet_loss_penalty((rtt_us + weighted_jitter).max(1) as f64, loss_ppm).ceil() as u64
}

fn compute_reliable_cost(
    rtt_us: u64,
    throughput_bps: u64,
    loss_ppm: u32,
    cfg: &OverlayConfig,
) -> u64 {
    let throughput_kbps = (throughput_bps as f64 / 1024.0).max(1.0);
    let penalty = (cfg.reliable_throughput_penalty_us_kbps() / throughput_kbps) as u64;
    apply_packet_loss_penalty((rtt_us + penalty).max(1) as f64, loss_ppm).ceil() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use super::super::super::config::transport_bit;
    use super::super::super::lsdb::{
        ApplicationServices, LinkTransportAdvertised, LsaEntry, LsaFloor, ReplicationServices,
    };
    use shitspeak_s2s_transport::{TransportKind, TransportRoutingPolicy};

    fn cfg() -> OverlayConfig {
        OverlayConfig::new(vec![])
    }

    fn entry(
        origin: NodeIdentifier,
        boot: u64,
        seq: u64,
        links: Vec<(NodeIdentifier, u64, u64, u64)>,
    ) -> LsaEntry {
        entry_with_loss(
            origin,
            boot,
            seq,
            links
                .into_iter()
                .map(|(n, rtt, jitter, tput)| (n, rtt, jitter, tput, 0))
                .collect(),
        )
    }

    fn entry_with_loss(
        origin: NodeIdentifier,
        boot: u64,
        seq: u64,
        links: Vec<(NodeIdentifier, u64, u64, u64, u32)>,
    ) -> LsaEntry {
        entry_with_loss_samples(origin, boot, seq, links, 0)
    }

    fn entry_with_loss_samples(
        origin: NodeIdentifier,
        boot: u64,
        seq: u64,
        links: Vec<(NodeIdentifier, u64, u64, u64, u32)>,
        loss_sample_count: u64,
    ) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: boot,
            seq,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(|(n, rtt, jitter, tput, loss_ppm)| LinkAdvertised {
                    neighbor: n,
                    rtt_us: rtt,
                    jitter_us: jitter,
                    throughput_bps: tput,
                    observed_recv_bps: tput,
                    observed_sent_bps: tput,
                    throughput_confidence_ppm: 1_000_000,
                    transports_mask: super::super::super::config::transport_bit(
                        shitspeak_s2s_transport::TransportKind::Tcp,
                    ),
                    loss_ppm,
                    probe_loss_ppm: loss_ppm,
                    native_loss_ppm: 0,
                    data_health_ppm: 0,
                    loss_sample_count,
                    transport_metrics: Vec::new(),
                })
                .collect(),
            max_users: 0,
            transit_disabled: false,
            replication_services: ReplicationServices::ALL,
            application_services: ApplicationServices::ALL,
            strict_replication_protocol_version: 0,
            strict_replication_transit_protocol_version: 0,
            upper_layer_capabilities: None,
        }
    }

    fn entry_with_loss_breakdown(
        origin: NodeIdentifier,
        boot: u64,
        seq: u64,
        links: Vec<(NodeIdentifier, u64, u64, u64, u32, u32, u32, u32, u64)>,
    ) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: boot,
            seq,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(
                    |(
                        n,
                        rtt,
                        jitter,
                        tput,
                        loss_ppm,
                        probe_loss_ppm,
                        native_loss_ppm,
                        data_health_ppm,
                        loss_sample_count,
                    )| LinkAdvertised {
                        neighbor: n,
                        rtt_us: rtt,
                        jitter_us: jitter,
                        throughput_bps: tput,
                        observed_recv_bps: tput,
                        observed_sent_bps: tput,
                        throughput_confidence_ppm: 1_000_000,
                        transports_mask: super::super::super::config::transport_bit(
                            shitspeak_s2s_transport::TransportKind::Tcp,
                        ),
                        loss_ppm,
                        probe_loss_ppm,
                        native_loss_ppm,
                        data_health_ppm,
                        loss_sample_count,
                        transport_metrics: Vec::new(),
                    },
                )
                .collect(),
            max_users: 0,
            transit_disabled: false,
            replication_services: ReplicationServices::ALL,
            application_services: ApplicationServices::ALL,
            strict_replication_protocol_version: 0,
            strict_replication_transit_protocol_version: 0,
            upper_layer_capabilities: None,
        }
    }

    fn build_db(lsas: Vec<LsaEntry>) -> LinkStateDb {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        for l in lsas {
            db.admit(l);
        }
        db
    }

    fn entry_with_udp_metrics(
        origin: NodeIdentifier,
        links: Vec<(NodeIdentifier, u64, u32, Option<(u64, u64, u32, u64)>)>,
    ) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: 100,
            seq: 1,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(
                    |(neighbor, rtt_us, aggregate_loss_ppm, udp)| LinkAdvertised {
                        neighbor,
                        rtt_us,
                        jitter_us: 0,
                        throughput_bps: 1_000_000,
                        observed_recv_bps: 1_000_000,
                        observed_sent_bps: 1_000_000,
                        throughput_confidence_ppm: 1_000_000,
                        transports_mask: transport_bit(TransportKind::Tcp)
                            | transport_bit(TransportKind::Udp),
                        loss_ppm: aggregate_loss_ppm,
                        probe_loss_ppm: aggregate_loss_ppm,
                        native_loss_ppm: 0,
                        data_health_ppm: 0,
                        loss_sample_count: MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
                        transport_metrics: udp
                            .map(|(udp_rtt, udp_jitter, udp_loss, samples)| {
                                vec![LinkTransportAdvertised::new(
                                    TransportKind::Udp,
                                    udp_rtt,
                                    udp_jitter,
                                    udp_loss,
                                    samples,
                                )]
                            })
                            .unwrap_or_default(),
                    },
                )
                .collect(),
            max_users: 0,
            transit_disabled: false,
            replication_services: ReplicationServices::ALL,
            application_services: ApplicationServices::ALL,
            strict_replication_protocol_version: 0,
            strict_replication_transit_protocol_version: 0,
            upper_layer_capabilities: None,
        }
    }

    fn entry_with_transport_metrics(
        origin: NodeIdentifier,
        links: Vec<(NodeIdentifier, u64, u32, u32, Vec<LinkTransportAdvertised>)>,
    ) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: 100,
            seq: 1,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(
                    |(neighbor, rtt_us, loss_ppm, transports_mask, transport_metrics)| {
                        LinkAdvertised {
                            neighbor,
                            rtt_us,
                            jitter_us: 0,
                            throughput_bps: 1_000_000,
                            observed_recv_bps: 1_000_000,
                            observed_sent_bps: 1_000_000,
                            throughput_confidence_ppm: 1_000_000,
                            transports_mask,
                            loss_ppm,
                            probe_loss_ppm: loss_ppm,
                            native_loss_ppm: 0,
                            data_health_ppm: 0,
                            loss_sample_count: MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
                            transport_metrics,
                        }
                    },
                )
                .collect(),
            max_users: 0,
            transit_disabled: false,
            replication_services: ReplicationServices::ALL,
            application_services: ApplicationServices::ALL,
            strict_replication_protocol_version: 0,
            strict_replication_transit_protocol_version: 0,
            upper_layer_capabilities: None,
        }
    }

    #[test]
    fn line_topology_routes() {
        // 1 -> 2 -> 3
        let db = build_db(vec![
            entry(1, 100, 1, vec![(2, 5_000, 100, 1_000_000)]),
            entry(
                2,
                100,
                1,
                vec![(1, 5_000, 100, 1_000_000), (3, 4_000, 100, 1_000_000)],
            ),
            entry(3, 100, 1, vec![(2, 4_000, 100, 1_000_000)]),
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert_eq!(table[&2].next_hop, 2);
        assert_eq!(table[&3].next_hop, 2); // via 2
        assert!(table[&3].cost > table[&2].cost);
    }

    #[test]
    fn picks_lower_cost_path() {
        // 1—2 (rtt=10ms), 1—3 (rtt=2ms), 3—2 (rtt=2ms).
        // Direct 1->2 costs 10ms; via 3: 2+2=4ms. So next_hop(2) = 3.
        let db = build_db(vec![
            entry(
                1,
                100,
                1,
                vec![(2, 10_000, 0, 1_000_000), (3, 2_000, 0, 1_000_000)],
            ),
            entry(
                2,
                100,
                1,
                vec![(1, 10_000, 0, 1_000_000), (3, 2_000, 0, 1_000_000)],
            ),
            entry(
                3,
                100,
                1,
                vec![(1, 2_000, 0, 1_000_000), (2, 2_000, 0, 1_000_000)],
            ),
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert_eq!(table[&2].next_hop, 3);
        assert_eq!(table[&3].next_hop, 3);
    }

    #[test]
    fn conversational_metric_avoids_lossy_low_latency_path() {
        // Default best-effort still picks the lower per-service RTT path
        // through node 3. Conversational routing prefers the direct path
        // because the low-RTT transit edges advertise heavy loss.
        let db = build_db(vec![
            entry_with_loss_samples(
                1,
                100,
                1,
                vec![
                    (2, 10_000, 0, 1_000_000, 0),
                    (3, 2_000, 0, 1_000_000, 250_000),
                ],
                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
            ),
            entry_with_loss_samples(
                2,
                100,
                1,
                vec![
                    (1, 10_000, 0, 1_000_000, 0),
                    (3, 2_000, 0, 1_000_000, 250_000),
                ],
                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
            ),
            entry_with_loss_samples(
                3,
                100,
                1,
                vec![
                    (1, 2_000, 0, 1_000_000, 250_000),
                    (2, 2_000, 0, 1_000_000, 250_000),
                ],
                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
            ),
        ]);

        let default = compute(&db, 1, ServiceLevel::BestEffort, &cfg());
        assert_eq!(default[&2].next_hop, 3);

        let conversational = compute_with_metric(
            &db,
            1,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            &cfg(),
        );
        assert_eq!(conversational[&2].next_hop, 2);
    }

    #[test]
    fn conversational_metric_uses_udp_specific_loss_without_penalizing_reliable_cost() {
        let db = build_db(vec![
            entry_with_udp_metrics(
                1,
                vec![
                    (
                        2,
                        5_000,
                        0,
                        Some((5_000, 0, 300_000, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES)),
                    ),
                    (
                        3,
                        12_000,
                        0,
                        Some((12_000, 0, 0, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES)),
                    ),
                ],
            ),
            entry_with_udp_metrics(
                2,
                vec![
                    (
                        1,
                        5_000,
                        0,
                        Some((5_000, 0, 300_000, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES)),
                    ),
                    (
                        3,
                        1_000,
                        0,
                        Some((1_000, 0, 0, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES)),
                    ),
                ],
            ),
            entry_with_udp_metrics(
                3,
                vec![
                    (
                        1,
                        12_000,
                        0,
                        Some((12_000, 0, 0, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES)),
                    ),
                    (
                        2,
                        1_000,
                        0,
                        Some((1_000, 0, 0, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES)),
                    ),
                ],
            ),
        ]);

        let reliable = compute_with_metric(
            &db,
            1,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &cfg(),
        );
        assert_eq!(reliable[&2].next_hop, 2);

        let conversational = compute_with_metric(
            &db,
            1,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            &cfg(),
        );
        assert_eq!(conversational[&2].next_hop, 3);
    }

    #[test]
    fn reliable_cost_uses_tcp_specific_advertised_metrics() {
        let tcp_quic = transport_bit(TransportKind::Tcp) | transport_bit(TransportKind::Quic);
        let tcp = transport_bit(TransportKind::Tcp);
        let db = build_db(vec![
            entry_with_transport_metrics(
                1,
                vec![
                    (
                        2,
                        5_000,
                        0,
                        tcp_quic,
                        vec![
                            LinkTransportAdvertised::new(
                                TransportKind::Tcp,
                                100_000,
                                0,
                                0,
                                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
                            ),
                            LinkTransportAdvertised::new(
                                TransportKind::Quic,
                                1_000,
                                0,
                                0,
                                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
                            ),
                        ],
                    ),
                    (3, 30_000, 0, tcp, Vec::new()),
                ],
            ),
            entry_with_transport_metrics(2, Vec::new()),
            entry_with_transport_metrics(3, vec![(2, 30_000, 0, tcp, Vec::new())]),
        ]);

        let table = compute_with_metric(
            &db,
            1,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &cfg(),
        );

        assert_eq!(table[&2].next_hop, 3);
    }

    #[test]
    fn reliable_low_latency_uses_kcp_metrics_only_after_viability_floor() {
        let tcp_kcp = transport_bit(TransportKind::Tcp) | transport_bit(TransportKind::Kcp);
        let tcp = transport_bit(TransportKind::Tcp);
        let below_floor = TransportRoutingPolicy::default()
            .udp_family_min_samples()
            .saturating_sub(1);
        let db = build_db(vec![
            entry_with_transport_metrics(
                1,
                vec![
                    (
                        2,
                        200_000,
                        0,
                        tcp_kcp,
                        vec![LinkTransportAdvertised::new(
                            TransportKind::Kcp,
                            20_000,
                            0,
                            0,
                            below_floor,
                        )],
                    ),
                    (3, 90_000, 0, tcp, Vec::new()),
                ],
            ),
            entry_with_transport_metrics(2, Vec::new()),
            entry_with_transport_metrics(3, vec![(2, 90_000, 0, tcp, Vec::new())]),
        ]);

        let table = compute_with_metric(
            &db,
            1,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ReliableLowLatencyCost,
            &cfg(),
        );
        assert_eq!(table[&2].next_hop, 3);

        let db = build_db(vec![
            entry_with_transport_metrics(
                1,
                vec![
                    (
                        2,
                        200_000,
                        0,
                        tcp_kcp,
                        vec![LinkTransportAdvertised::new(
                            TransportKind::Kcp,
                            20_000,
                            0,
                            0,
                            TransportRoutingPolicy::default().udp_family_min_samples(),
                        )],
                    ),
                    (3, 90_000, 0, tcp, Vec::new()),
                ],
            ),
            entry_with_transport_metrics(2, Vec::new()),
            entry_with_transport_metrics(3, vec![(2, 90_000, 0, tcp, Vec::new())]),
        ]);

        let table = compute_with_metric(
            &db,
            1,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ReliableLowLatencyCost,
            &cfg(),
        );
        assert_eq!(table[&2].next_hop, 2);
    }

    #[test]
    fn best_effort_cost_uses_raw_udp_metrics() {
        let tcp_udp = transport_bit(TransportKind::Tcp) | transport_bit(TransportKind::Udp);
        let tcp = transport_bit(TransportKind::Tcp);
        let db = build_db(vec![
            entry_with_transport_metrics(
                1,
                vec![
                    (
                        2,
                        100_000,
                        0,
                        tcp_udp,
                        vec![LinkTransportAdvertised::new(
                            TransportKind::Udp,
                            5_000,
                            0,
                            0,
                            1,
                        )],
                    ),
                    (3, 30_000, 0, tcp, Vec::new()),
                ],
            ),
            entry_with_transport_metrics(2, Vec::new()),
            entry_with_transport_metrics(3, vec![(2, 30_000, 0, tcp, Vec::new())]),
        ]);

        let table = compute_with_metric(
            &db,
            1,
            ServiceLevel::BestEffort,
            RoutingMetric::BestEffortCost,
            &cfg(),
        );

        assert_eq!(table[&2].next_hop, 2);
    }

    #[test]
    fn default_metrics_penalize_packet_loss() {
        // Direct 1->2 is lower RTT but 40% loss. The two-hop path via 3 has
        // higher raw RTT and no loss, so the packet-loss penalty should win.
        let db = build_db(vec![
            entry_with_loss_samples(
                1,
                100,
                1,
                vec![
                    (2, 10_000, 0, 1_000_000, 400_000),
                    (3, 12_000, 0, 1_000_000, 0),
                ],
                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
            ),
            entry_with_loss_samples(
                2,
                100,
                1,
                vec![
                    (1, 10_000, 0, 1_000_000, 400_000),
                    (3, 1_000, 0, 1_000_000, 0),
                ],
                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
            ),
            entry_with_loss_samples(
                3,
                100,
                1,
                vec![(1, 12_000, 0, 1_000_000, 0), (2, 1_000, 0, 1_000_000, 0)],
                MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
            ),
        ]);

        let table = compute(&db, 1, ServiceLevel::BestEffort, &cfg());
        assert_eq!(table[&2].next_hop, 3);
    }

    #[test]
    fn clean_probe_high_native_loss_deprefers_direct_link() {
        // The advertised legacy loss is already the effective conservative
        // value, even though the probe breakdown is clean.
        let db = build_db(vec![
            entry_with_loss_breakdown(
                1,
                100,
                1,
                vec![
                    (2, 10_000, 0, 1_000_000, 250_000, 0, 500_000, 0, 64),
                    (3, 12_000, 0, 1_000_000, 0, 0, 0, 0, 64),
                ],
            ),
            entry_with_loss_breakdown(
                2,
                100,
                1,
                vec![
                    (1, 10_000, 0, 1_000_000, 250_000, 0, 500_000, 0, 64),
                    (3, 1_000, 0, 1_000_000, 0, 0, 0, 0, 64),
                ],
            ),
            entry_with_loss_breakdown(
                3,
                100,
                1,
                vec![
                    (1, 12_000, 0, 1_000_000, 0, 0, 0, 0, 64),
                    (2, 1_000, 0, 1_000_000, 0, 0, 0, 0, 64),
                ],
            ),
        ]);

        let table = compute(&db, 1, ServiceLevel::BestEffort, &cfg());
        assert_eq!(table[&2].next_hop, 3);
    }

    #[test]
    fn low_confidence_excessive_packet_loss_remains_route_eligible() {
        let db = build_db(vec![
            entry_with_loss(1, 100, 1, vec![(2, 1_000, 0, 1_000_000, 600_000)]),
            entry_with_loss(2, 100, 1, vec![(1, 1_000, 0, 1_000_000, 600_000)]),
        ]);

        let table = compute(&db, 1, ServiceLevel::BestEffort, &cfg());
        assert_eq!(table[&2].next_hop, 2);
        assert!(table[&2].cost > 1_000);
    }

    #[test]
    fn low_confidence_excessive_packet_loss_still_deprefers_direct_path() {
        let db = build_db(vec![
            entry_with_loss(
                1,
                100,
                1,
                vec![
                    (2, 10_000, 0, 1_000_000, 1_000_000),
                    (3, 12_000, 0, 1_000_000, 0),
                ],
            ),
            entry_with_loss(2, 100, 1, vec![(1, 10_000, 0, 1_000_000, 1_000_000)]),
            entry_with_loss(
                3,
                100,
                1,
                vec![(1, 12_000, 0, 1_000_000, 0), (2, 1_000, 0, 1_000_000, 0)],
            ),
        ]);

        let table = compute(&db, 1, ServiceLevel::BestEffort, &cfg());
        assert_eq!(table[&2].next_hop, 3);
    }

    #[test]
    fn high_confidence_excessive_packet_loss_makes_link_unavailable() {
        let db = build_db(vec![
            entry_with_loss_breakdown(
                1,
                100,
                1,
                vec![(
                    2,
                    1_000,
                    0,
                    1_000_000,
                    600_000,
                    600_000,
                    0,
                    0,
                    MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
                )],
            ),
            entry_with_loss_breakdown(
                2,
                100,
                1,
                vec![(
                    1,
                    1_000,
                    0,
                    1_000_000,
                    600_000,
                    600_000,
                    0,
                    0,
                    MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
                )],
            ),
        ]);

        let table = compute(&db, 1, ServiceLevel::BestEffort, &cfg());
        assert!(!table.contains_key(&2));
    }

    #[test]
    fn non_transit_origin_can_be_destination_but_not_intermediate() {
        let mut node2 = entry(
            2,
            100,
            1,
            vec![(1, 5_000, 0, 1_000_000), (3, 5_000, 0, 1_000_000)],
        );
        node2.transit_disabled = true;
        let db = build_db(vec![
            entry(1, 100, 1, vec![(2, 5_000, 0, 1_000_000)]),
            node2,
            entry(3, 100, 1, vec![(2, 5_000, 0, 1_000_000)]),
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert_eq!(table[&2].next_hop, 2);
        assert!(!table.contains_key(&3));
    }

    #[test]
    fn tombstone_origin_drops_from_graph() {
        let mut e2_dead = entry(2, 100, 5, vec![]);
        e2_dead.tombstone = true;
        let db = build_db(vec![
            entry(1, 100, 1, vec![(2, 5_000, 0, 1_000_000)]),
            e2_dead,
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert!(!table.contains_key(&2));
    }

    #[test]
    fn directed_edge_uses_originator_metrics_only() {
        // Node 1→2: forward (node 1's view) has 10ms RTT and 100 Kbps.
        // Node 2→1: reverse (node 2's view) has 10ms RTT and 1 Mbps.
        // Edge 1→2 cost must reflect 100 Kbps (node 1's measurement), not 1 Mbps.
        let db = build_db(vec![
            entry(1, 100, 1, vec![(2, 10_000, 0, 100_000)]), // 1's view of 1→2
            entry(2, 100, 1, vec![(1, 10_000, 0, 1_000_000)]), // 2's view of 2→1
        ]);
        let table_low = compute(&db, 1, ServiceLevel::Reliable, &cfg());

        // Compare: both sides say 100 Kbps — symmetric baseline.
        let db_sym = build_db(vec![
            entry(1, 100, 1, vec![(2, 10_000, 0, 100_000)]),
            entry(2, 100, 1, vec![(1, 10_000, 0, 100_000)]),
        ]);
        let table_sym = compute(&db_sym, 1, ServiceLevel::Reliable, &cfg());

        // The directed edge 1→2 uses node 1's metrics only: 100 Kbps in both
        // cases, so costs must match.
        assert_eq!(table_low[&2].cost, table_sym[&2].cost);
    }

    #[test]
    fn directed_graph_independent_path_costs() {
        // Asymmetric topology: 1→3 (node 1's view of 3) is expensive (2ms RTT
        // + 8ms jitter), but 3→1 (node 3's view of 1) is cheap. Routing from
        // node 1 to node 2 must use the 1-side directed costs.
        //
        //   1 —(1→2: 10ms, jitter=0)—> 2
        //   1 —(1→3: 2ms, jitter=8ms)—> 3
        //   3 —(3→2: 2ms, jitter=0)—>  2
        //
        // RLL cost of path 1→3→2: (2ms + 4*8ms=34ms) + (2ms) = 36ms > direct 10ms.
        // So routing from 1 to 2 should prefer direct 1→2.
        let db = build_db(vec![
            entry(
                1,
                100,
                1,
                vec![(2, 10_000, 0, 1_000_000), (3, 2_000, 8_000, 1_000_000)],
            ),
            entry(
                2,
                100,
                1,
                vec![(1, 10_000, 0, 1_000_000), (3, 2_000, 0, 1_000_000)],
            ),
            entry(
                3,
                100,
                1,
                vec![(1, 2_000, 0, 1_000_000), (2, 2_000, 0, 1_000_000)],
            ),
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        // Direct path is cheaper (10ms) than via 3 (2ms + 32ms jitter penalty + 2ms).
        assert_eq!(table[&2].next_hop, 2);
    }

    #[test]
    fn empty_graph_returns_empty_table() {
        let floor = Arc::new(LsaFloor::new(0, None));
        let db = LinkStateDb::new(floor);
        let table = compute(&db, 1, ServiceLevel::Reliable, &cfg());
        assert!(table.is_empty());
    }
}
