//! Debounced routing recompute task.
//!
//! Waits on the LSDB `change_signal`. On wake, sleeps for
//! `cfg.routing_recompute_debounce()` so a flood burst coalesces into
//! one recompute pass, then runs Dijkstra for each `ServiceLevel` and
//! atomically swaps the new tables into an `ArcSwap<RoutingTables>`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{ConnectionManager, ServiceLevel};

use super::super::config::OverlayConfig;
use super::super::duplicate::DuplicateDetector;
use super::super::lsdb::LinkStateDb;
use super::RoutingTables;
use super::dijkstra;
use super::dynamic::DynamicSpf;

const VOICE_ALTERNATE_PRECOMPUTE_DEBOUNCE: Duration = Duration::from_secs(2);

pub fn spawn_recomputer(
    lsdb: Arc<LinkStateDb>,
    self_id: NodeIdentifier,
    tables: Arc<ArcSwap<RoutingTables>>,
    transport: ConnectionManager,
    duplicate_detector: Arc<DuplicateDetector>,
    cfg: OverlayConfig,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut dynamic = None;
        lsdb.drain_dirty_origins();

        loop {
            loop {
                let Some(computation) = compute_routing_offloaded(
                    lsdb.clone(),
                    self_id,
                    duplicate_detector.clone(),
                    cfg.clone(),
                    dynamic.take(),
                    &shutdown,
                )
                .await
                else {
                    return;
                };
                let RoutingComputation {
                    lsdb_revision,
                    dynamic: next_dynamic,
                    tables: new,
                    bridge_targets,
                } = computation;
                let dynamic_spf = next_dynamic.is_some();
                dynamic = next_dynamic;

                if shutdown.is_cancelled() {
                    return;
                }
                let published = lsdb.if_revision(lsdb_revision, || {
                    transport.set_required_outgoing_nodes(bridge_targets);
                    trace!(
                        dynamic_spf,
                        reliable = new.for_level(ServiceLevel::Reliable).len(),
                        rll = new.for_level(ServiceLevel::ReliableLowLatency).len(),
                        best_effort = new.for_level(ServiceLevel::BestEffort).len(),
                        "routing recomputed"
                    );
                    publish_routing_tables(
                        &tables,
                        new,
                        self_id,
                        cfg.routing_recompute_debounce(),
                        &shutdown,
                    );
                });
                if published {
                    break;
                }
                trace!(lsdb_revision, "discarded stale routing computation");
            }

            let notified = lsdb.change_signal().notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if lsdb.drain_dirty_origins().is_empty() {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = &mut notified => {}
                }
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(cfg.routing_recompute_debounce()) => {}
            }
            lsdb.drain_dirty_origins();
        }
    });
}

struct RoutingComputation {
    lsdb_revision: u64,
    dynamic: Option<DynamicSpf>,
    tables: RoutingTables,
    bridge_targets: HashSet<NodeIdentifier>,
}

fn spawn_routing_computation<F, T>(compute: F) -> tokio::task::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(compute)
}

async fn compute_routing_offloaded(
    lsdb: Arc<LinkStateDb>,
    self_id: NodeIdentifier,
    duplicate_detector: Arc<DuplicateDetector>,
    cfg: OverlayConfig,
    dynamic: Option<DynamicSpf>,
    shutdown: &CancellationToken,
) -> Option<RoutingComputation> {
    let computation = spawn_routing_computation(move || {
        compute_routing(&lsdb, self_id, &duplicate_detector, &cfg, dynamic, || {})
    });
    tokio::select! {
        _ = shutdown.cancelled() => None,
        result = computation => match result {
            Ok(computation) => Some(computation),
            Err(error) => {
                warn!(%error, "routing computation task failed");
                None
            }
        }
    }
}

fn compute_routing<F>(
    lsdb: &LinkStateDb,
    self_id: NodeIdentifier,
    duplicate_detector: &DuplicateDetector,
    cfg: &OverlayConfig,
    dynamic: Option<DynamicSpf>,
    after_snapshot: F,
) -> RoutingComputation
where
    F: FnOnce(),
{
    let (lsdb_revision, entries) = lsdb.routing_snapshot();
    after_snapshot();
    let graph = dijkstra::RoutingGraph::from_entries_filtered(entries.iter(), |node| {
        !duplicate_detector.is_quarantined(node)
    });

    if cfg.routing_dynamic_spf_enabled() {
        let (dynamic, tables) = match dynamic {
            Some(mut dynamic) => {
                let tables = dynamic.update_graph(graph, cfg);
                (dynamic, tables)
            }
            None => {
                let dynamic = DynamicSpf::from_graph(graph, self_id, cfg);
                let tables = dynamic.routing_tables(cfg);
                (dynamic, tables)
            }
        };
        let bridge_targets = component_bridge_targets(dynamic.graph(), self_id);
        RoutingComputation {
            lsdb_revision,
            dynamic: Some(dynamic),
            tables,
            bridge_targets,
        }
    } else {
        let bridge_targets = component_bridge_targets(&graph, self_id);
        let tables = RoutingTables::from_graph(&graph, self_id, cfg);
        RoutingComputation {
            lsdb_revision,
            dynamic: None,
            tables,
            bridge_targets,
        }
    }
}

fn publish_routing_tables(
    tables: &Arc<ArcSwap<RoutingTables>>,
    new: RoutingTables,
    self_id: NodeIdentifier,
    alternate_debounce: std::time::Duration,
    shutdown: &CancellationToken,
) {
    let snapshot = Arc::new(new);
    let generation = snapshot.generation();
    tables.store(snapshot.clone());
    let alternate_debounce = alternate_debounce.max(VOICE_ALTERNATE_PRECOMPUTE_DEBOUNCE);

    let tables = tables.clone();
    let shutdown = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(alternate_debounce) => {}
        }
        if tables.load().generation() != generation {
            return;
        }

        let compute_snapshot = snapshot.clone();
        let Ok(alternates) =
            tokio::task::spawn_blocking(move || compute_snapshot.compute_voice_alternates(self_id))
                .await
        else {
            return;
        };

        if !shutdown.is_cancelled() && tables.load().generation() == generation {
            snapshot.install_voice_alternates(alternates);
        }
    });
}

fn component_bridge_targets(
    graph_view: &dijkstra::RoutingGraph,
    self_id: NodeIdentifier,
) -> HashSet<NodeIdentifier> {
    if graph_view.active_len() <= 1 || !graph_view.is_active(self_id) {
        return HashSet::new();
    }

    let mut graph: HashMap<NodeIdentifier, Vec<NodeIdentifier>> = HashMap::new();
    for node in graph_view.active_nodes() {
        graph.entry(node).or_default();
    }
    for (origin, links) in graph_view.links_by_origin() {
        for link in links {
            if !graph_view.is_active(link.neighbor) {
                continue;
            }
            graph.entry(origin).or_default().push(link.neighbor);
            graph.entry(link.neighbor).or_default().push(origin);
        }
    }

    let mut seen = HashSet::new();
    let mut components: Vec<Vec<NodeIdentifier>> = Vec::new();
    for start in graph_view.active_nodes() {
        if !seen.insert(start) {
            continue;
        }
        let mut component = Vec::new();
        let mut queue = VecDeque::from([start]);
        while let Some(node) = queue.pop_front() {
            component.push(node);
            if let Some(neighbors) = graph.get(&node) {
                for neighbor in neighbors {
                    if seen.insert(*neighbor) {
                        queue.push_back(*neighbor);
                    }
                }
            }
        }
        component.sort_unstable();
        components.push(component);
    }

    let local_component = components
        .iter()
        .position(|component| component.binary_search(&self_id).is_ok());
    let mut targets = HashSet::new();
    for (idx, component) in components.iter().enumerate() {
        if Some(idx) == local_component {
            continue;
        }
        if let Some(representative) = component.first() {
            targets.insert(*representative);
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::super::config::transport_bit;
    use super::super::super::lsdb::{
        ApplicationServices, LinkAdvertised, LsaEntry, LsaFloor, ReplicationServices,
    };
    use shitspeak_s2s_transport::TransportKind;
    use std::sync::Barrier;

    fn entry(origin: NodeIdentifier, links: Vec<NodeIdentifier>) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: 1,
            seq: 1,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(|neighbor| LinkAdvertised {
                    neighbor,
                    rtt_us: 1_000,
                    jitter_us: 0,
                    throughput_bps: 1_000_000,
                    observed_recv_bps: 1_000_000,
                    observed_sent_bps: 1_000_000,
                    throughput_confidence_ppm: 1_000_000,
                    transports_mask: transport_bit(TransportKind::Tcp),
                    loss_ppm: 0,
                    probe_loss_ppm: 0,
                    native_loss_ppm: 0,
                    data_health_ppm: 0,
                    loss_sample_count: 0,
                    datagram_loss_ppm: 0,
                    datagram_loss_sample_count: 0,
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

    fn build_db(entries: Vec<LsaEntry>) -> LinkStateDb {
        let db = LinkStateDb::new(Arc::new(LsaFloor::new(0, None)));
        for entry in entries {
            db.admit(entry);
        }
        db
    }

    fn voice_tables() -> RoutingTables {
        let mut tables = RoutingTables::empty();
        let edge = dijkstra::EdgeCost {
            primary: 1,
            latency_us: 100,
        };
        tables.insert_table_with_adjacency(
            super::super::RoutingMetric::ConversationalQuality,
            ServiceLevel::BestEffort,
            HashMap::from([(
                10,
                dijkstra::RouteEntry {
                    next_hop: 2,
                    cost: 2,
                    latency_us: 200,
                },
            )]),
            HashMap::from([
                (1, vec![(2, edge), (3, edge)]),
                (2, vec![(10, edge)]),
                (3, vec![(10, edge)]),
                (10, vec![]),
            ]),
        );
        tables
    }

    #[tokio::test(flavor = "current_thread")]
    async fn routing_computation_does_not_block_the_async_worker() {
        let release = Arc::new(Barrier::new(2));
        let compute_release = release.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        let computation = spawn_routing_computation(move || {
            let _ = started_tx.send(());
            compute_release.wait();
        });
        started_rx.await.expect("blocking computation started");

        let heartbeat = tokio::spawn(async {
            tokio::task::yield_now().await;
            1
        });
        assert_eq!(heartbeat.await.expect("heartbeat task completed"), 1);

        release.wait();
        computation.await.expect("blocking computation completed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lsa_admitted_during_computation_makes_result_stale_and_is_recomputed() {
        let lsdb = Arc::new(build_db(vec![entry(1, vec![])]));
        lsdb.drain_dirty_origins();
        let duplicate_detector = Arc::new(DuplicateDetector::new(1, Duration::from_secs(1)));
        let cfg = OverlayConfig::new(vec![]);
        let release = Arc::new(Barrier::new(2));
        let compute_release = release.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        let compute_lsdb = lsdb.clone();
        let compute_duplicates = duplicate_detector.clone();
        let compute_cfg = cfg.clone();
        let computation = spawn_routing_computation(move || {
            compute_routing(
                &compute_lsdb,
                1,
                &compute_duplicates,
                &compute_cfg,
                None,
                || {
                    let _ = started_tx.send(());
                    compute_release.wait();
                },
            )
        });
        started_rx.await.expect("routing snapshot captured");

        let mut local = entry(1, vec![2]);
        local.seq = 2;
        lsdb.admit(local);
        lsdb.admit(entry(2, vec![1]));
        release.wait();
        let stale = computation.await.expect("stale computation completed");

        let published = Arc::new(ArcSwap::from_pointee(RoutingTables::empty()));
        assert!(!lsdb.if_revision(stale.lsdb_revision, || {
            published.store(Arc::new(stale.tables.clone()));
        }));
        assert!(
            published
                .load()
                .for_level(ServiceLevel::Reliable)
                .is_empty()
        );

        let current = compute_routing(&lsdb, 1, &duplicate_detector, &cfg, stale.dynamic, || {});
        assert!(lsdb.if_revision(current.lsdb_revision, || {}));
        assert!(
            current
                .tables
                .for_level(ServiceLevel::Reliable)
                .contains_key(&2)
        );
    }

    #[test]
    fn component_bridge_targets_pick_foreign_component_representatives() {
        let db = build_db(vec![
            entry(1, vec![2]),
            entry(2, vec![1]),
            entry(3, vec![4]),
            entry(4, vec![3]),
            entry(5, vec![]),
        ]);

        let graph = dijkstra::RoutingGraph::from_lsdb(&db);
        let targets = component_bridge_targets(&graph, 1);
        assert_eq!(targets, HashSet::from([3, 5]));
    }

    #[test]
    fn component_bridge_targets_empty_when_graph_connected() {
        let db = build_db(vec![
            entry(1, vec![2]),
            entry(2, vec![1, 3]),
            entry(3, vec![2]),
        ]);

        let graph = dijkstra::RoutingGraph::from_lsdb(&db);
        assert!(component_bridge_targets(&graph, 1).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn deferred_voice_alternates_skip_stale_generations() {
        let published = Arc::new(ArcSwap::from_pointee(RoutingTables::empty()));
        let shutdown = CancellationToken::new();

        let stale = voice_tables();
        let stale_observer = stale.clone();
        publish_routing_tables(&published, stale, 1, Duration::ZERO, &shutdown);

        let current = voice_tables();
        let current_observer = current.clone();
        publish_routing_tables(&published, current, 1, Duration::ZERO, &shutdown);

        tokio::task::yield_now().await;
        tokio::time::advance(VOICE_ALTERNATE_PRECOMPUTE_DEBOUNCE).await;
        for _ in 0..1000 {
            if current_observer.has_precomputed_voice_alternate(10, 2) {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(stale_observer.voice_alternate_searches(), 0);
        assert!(!stale_observer.has_precomputed_voice_alternate(10, 2));
        assert!(current_observer.voice_alternate_searches() > 0);
        assert!(current_observer.has_precomputed_voice_alternate(10, 2));
        shutdown.cancel();
    }
}
