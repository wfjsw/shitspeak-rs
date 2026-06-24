//! Dynamic shortest-path maintenance for LSDB changes.
//!
//! This keeps the same routing-table surface as the full Dijkstra path, but
//! repairs only the affected shortest-path tree portions for ordinary LSA
//! changes. Full rebuild remains the startup/config/large-dirty-set fallback.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::s2s::transport::ServiceLevel;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::lsdb::LinkStateDb;
use super::dijkstra::{self, EdgeCost, PathCost, RouteEntry, RoutingGraph, ShortestPathTree};
use super::{RoutingMetric, RoutingTableKey, RoutingTables};

const DYNAMIC_DIRTY_FALLBACK_ORIGINS: usize = 128;

pub(crate) struct DynamicSpf {
    self_id: NodeIdentifier,
    graph: RoutingGraph,
    tables: HashMap<RoutingTableKey, DynamicTable>,
}

impl DynamicSpf {
    pub(crate) fn rebuild(
        lsdb: &LinkStateDb,
        self_id: NodeIdentifier,
        cfg: &OverlayConfig,
    ) -> Self {
        Self::from_graph(RoutingGraph::from_lsdb(lsdb), self_id, cfg)
    }

    pub(crate) fn update(
        &mut self,
        lsdb: &LinkStateDb,
        dirty_origins: HashSet<NodeIdentifier>,
        cfg: &OverlayConfig,
    ) -> RoutingTables {
        if dirty_origins.is_empty() {
            return self.routing_tables();
        }

        let next_graph = RoutingGraph::from_lsdb(lsdb);
        if dirty_origins.len() > DYNAMIC_DIRTY_FALLBACK_ORIGINS {
            *self = Self::from_graph(next_graph, self.self_id, cfg);
            return self.routing_tables();
        }

        for table in self.tables.values_mut() {
            table.update(&self.graph, &next_graph, &dirty_origins, self.self_id, cfg);
        }
        self.graph = next_graph;
        self.routing_tables()
    }

    pub(crate) fn graph(&self) -> &RoutingGraph {
        &self.graph
    }

    pub(crate) fn routing_tables(&self) -> RoutingTables {
        let mut out = RoutingTables::empty();
        for (key, table) in &self.tables {
            out.insert_table(key.metric, key.level, table.routes.clone());
        }
        out
    }

    fn from_graph(graph: RoutingGraph, self_id: NodeIdentifier, cfg: &OverlayConfig) -> Self {
        let mut tables = HashMap::new();
        for metric in RoutingMetric::ALL {
            for level in ServiceLevel::ALL {
                tables.insert(
                    RoutingTableKey::new(metric, level),
                    DynamicTable::rebuild(&graph, self_id, level, metric, cfg),
                );
            }
        }
        Self {
            self_id,
            graph,
            tables,
        }
    }
}

struct DynamicTable {
    level: ServiceLevel,
    metric: RoutingMetric,
    dist: HashMap<NodeIdentifier, PathCost>,
    prev: HashMap<NodeIdentifier, NodeIdentifier>,
    routes: HashMap<NodeIdentifier, RouteEntry>,
}

impl DynamicTable {
    fn rebuild(
        graph: &RoutingGraph,
        self_id: NodeIdentifier,
        level: ServiceLevel,
        metric: RoutingMetric,
        cfg: &OverlayConfig,
    ) -> Self {
        let tree = dijkstra::shortest_path_tree(graph, self_id, level, metric, cfg);
        let routes = dijkstra::route_table_from_tree(&tree, self_id);
        Self {
            level,
            metric,
            dist: tree.dist,
            prev: tree.prev,
            routes,
        }
    }

    fn update(
        &mut self,
        old_graph: &RoutingGraph,
        new_graph: &RoutingGraph,
        dirty_origins: &HashSet<NodeIdentifier>,
        self_id: NodeIdentifier,
        cfg: &OverlayConfig,
    ) {
        let old_adj = dijkstra::adjacency_for(old_graph, self.level, self.metric, cfg);
        let new_adj = dijkstra::adjacency_for(new_graph, self.level, self.metric, cfg);
        let children = self.children();
        let mut invalid_roots = HashSet::new();
        let mut candidate_edges = Vec::new();
        let mut needs_frontier_repair = false;

        for origin in dirty_origins {
            let old_active = old_graph.is_active(*origin);
            let new_active = new_graph.is_active(*origin);
            if old_active && !new_active {
                invalid_roots.insert(*origin);
                continue;
            }
            if !old_active && new_active {
                needs_frontier_repair = true;
            }

            let old_transit_disabled = old_graph.transit_disabled(*origin);
            let new_transit_disabled = new_graph.transit_disabled(*origin);
            if old_transit_disabled != new_transit_disabled {
                if new_transit_disabled && *origin != self_id {
                    if let Some(child_nodes) = children.get(origin) {
                        invalid_roots.extend(child_nodes.iter().copied());
                    }
                } else {
                    needs_frontier_repair = true;
                }
            }

            let old_edges = edge_map(old_adj.get(origin));
            let new_edges = edge_map(new_adj.get(origin));

            for (neighbor, old_cost) in &old_edges {
                match new_edges.get(neighbor) {
                    Some(new_cost) if *new_cost <= *old_cost => {}
                    _ => {
                        if self
                            .prev
                            .get(neighbor)
                            .is_some_and(|parent| parent == origin)
                        {
                            invalid_roots.insert(*neighbor);
                        }
                    }
                }
            }
            for (neighbor, new_cost) in &new_edges {
                match old_edges.get(neighbor) {
                    Some(old_cost) if *new_cost >= *old_cost => {}
                    _ => candidate_edges.push((*origin, *neighbor, *new_cost)),
                }
            }
        }

        let invalidated = self.invalidate_subtrees(&invalid_roots, self_id);
        let mut heap = BinaryHeap::new();
        if !invalidated.is_empty() || needs_frontier_repair {
            self.seed_reachable_frontier(new_graph, &new_adj, self_id, &mut heap);
        } else {
            for (origin, neighbor, cost) in candidate_edges {
                self.relax_edge(new_graph, origin, neighbor, cost, self_id, &mut heap);
            }
        }
        self.run_relaxation(new_graph, &new_adj, self_id, &mut heap);
        self.refresh_routes(self_id);
    }

    fn children(&self) -> HashMap<NodeIdentifier, Vec<NodeIdentifier>> {
        let mut children: HashMap<NodeIdentifier, Vec<NodeIdentifier>> = HashMap::new();
        for (node, parent) in &self.prev {
            children.entry(*parent).or_default().push(*node);
        }
        children
    }

    fn invalidate_subtrees(
        &mut self,
        roots: &HashSet<NodeIdentifier>,
        self_id: NodeIdentifier,
    ) -> HashSet<NodeIdentifier> {
        if roots.is_empty() {
            return HashSet::new();
        }
        let children = self.children();
        let mut removed = HashSet::new();
        let mut stack: Vec<_> = roots.iter().copied().collect();
        while let Some(node) = stack.pop() {
            if !removed.insert(node) {
                continue;
            }
            if let Some(child_nodes) = children.get(&node) {
                stack.extend(child_nodes.iter().copied());
            }
        }

        if removed.contains(&self_id) {
            self.dist.clear();
            self.prev.clear();
            self.dist.insert(self_id, PathCost::ZERO);
            return removed;
        }

        for node in &removed {
            self.dist.remove(node);
            self.prev.remove(node);
        }
        self.prev
            .retain(|node, parent| !removed.contains(node) && !removed.contains(parent));
        removed
    }

    fn seed_reachable_frontier(
        &mut self,
        graph: &RoutingGraph,
        adj: &HashMap<NodeIdentifier, Vec<(NodeIdentifier, EdgeCost)>>,
        self_id: NodeIdentifier,
        heap: &mut BinaryHeap<Reverse<(PathCost, NodeIdentifier)>>,
    ) {
        let origins: Vec<_> = self.dist.keys().copied().collect();
        for origin in origins {
            let Some(edges) = adj.get(&origin) else {
                continue;
            };
            for (neighbor, cost) in edges {
                self.relax_edge(graph, origin, *neighbor, *cost, self_id, heap);
            }
        }
    }

    fn relax_edge(
        &mut self,
        graph: &RoutingGraph,
        origin: NodeIdentifier,
        neighbor: NodeIdentifier,
        cost: EdgeCost,
        self_id: NodeIdentifier,
        heap: &mut BinaryHeap<Reverse<(PathCost, NodeIdentifier)>>,
    ) {
        if !can_expand(graph, origin, self_id) {
            return;
        }
        let Some(origin_cost) = self.dist.get(&origin).copied() else {
            return;
        };
        let next_cost = origin_cost.add(cost);
        if self
            .dist
            .get(&neighbor)
            .map_or(true, |known| next_cost < *known)
        {
            self.dist.insert(neighbor, next_cost);
            self.prev.insert(neighbor, origin);
            heap.push(Reverse((next_cost, neighbor)));
        }
    }

    fn run_relaxation(
        &mut self,
        graph: &RoutingGraph,
        adj: &HashMap<NodeIdentifier, Vec<(NodeIdentifier, EdgeCost)>>,
        self_id: NodeIdentifier,
        heap: &mut BinaryHeap<Reverse<(PathCost, NodeIdentifier)>>,
    ) {
        while let Some(Reverse((cost, node))) = heap.pop() {
            if self.dist.get(&node).is_some_and(|known| cost > *known) {
                continue;
            }
            if !can_expand(graph, node, self_id) {
                continue;
            }
            let Some(edges) = adj.get(&node) else {
                continue;
            };
            for (neighbor, edge_cost) in edges {
                self.relax_edge(graph, node, *neighbor, *edge_cost, self_id, heap);
            }
        }
    }

    fn refresh_routes(&mut self, self_id: NodeIdentifier) {
        let tree = ShortestPathTree {
            dist: self.dist.clone(),
            prev: self.prev.clone(),
        };
        self.routes = dijkstra::route_table_from_tree(&tree, self_id);
    }
}

fn edge_map(edges: Option<&Vec<(NodeIdentifier, EdgeCost)>>) -> HashMap<NodeIdentifier, EdgeCost> {
    edges
        .into_iter()
        .flat_map(|edges| edges.iter().copied())
        .collect()
}

fn can_expand(graph: &RoutingGraph, node: NodeIdentifier, self_id: NodeIdentifier) -> bool {
    node == self_id || (graph.is_active(node) && !graph.transit_disabled(node))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;
    use crate::s2s::overlay::config::transport_bit;
    use crate::s2s::overlay::lsdb::{LinkAdvertised, LsaEntry, LsaFloor, ReplicationServices};
    use crate::s2s::transport::TransportKind;

    fn cfg() -> OverlayConfig {
        OverlayConfig::new(vec![])
    }

    fn link(neighbor: NodeIdentifier, rtt_us: u64) -> LinkAdvertised {
        LinkAdvertised {
            neighbor,
            rtt_us,
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
        }
    }

    fn entry(origin: NodeIdentifier, links: Vec<LinkAdvertised>) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: 1,
            seq: 1,
            ts_local_received: Instant::now(),
            tombstone: false,
            addresses: vec![],
            links,
            max_users: 0,
            transit_disabled: false,
            replication_services: ReplicationServices::ALL,
        }
    }

    fn build_db(entries: Vec<LsaEntry>) -> LinkStateDb {
        let db = LinkStateDb::new(Arc::new(LsaFloor::new(0, None)));
        for entry in entries {
            db.admit(entry);
        }
        db.drain_dirty_origins();
        db
    }

    fn assert_dynamic_matches_full(
        engine: &mut DynamicSpf,
        db: &LinkStateDb,
        dirty: HashSet<NodeIdentifier>,
    ) {
        let cfg = cfg();
        let dynamic = engine.update(db, dirty, &cfg);
        let graph = RoutingGraph::from_lsdb(db);
        for metric in RoutingMetric::ALL {
            for level in ServiceLevel::ALL {
                let full = dijkstra::compute_on_graph(&graph, 1, level, metric, &cfg);
                assert_eq!(dynamic.for_metric_level(metric, level), &full);
            }
        }
    }

    #[test]
    fn dynamic_spf_matches_full_for_edge_add_decrease_increase_remove_and_tombstone() {
        let cfg = cfg();
        let db = build_db(vec![
            entry(1, vec![link(2, 10)]),
            entry(2, vec![link(1, 10)]),
        ]);
        let mut engine = DynamicSpf::rebuild(&db, 1, &cfg);

        let mut node2 = entry(2, vec![link(1, 10), link(3, 10)]);
        node2.seq = 2;
        db.admit(node2);
        db.admit(entry(3, vec![link(2, 10)]));
        assert_dynamic_matches_full(&mut engine, &db, db.drain_dirty_origins());

        let mut node1 = entry(1, vec![link(2, 10), link(3, 5)]);
        node1.seq = 2;
        db.admit(node1);
        assert_dynamic_matches_full(&mut engine, &db, db.drain_dirty_origins());

        let mut node1 = entry(1, vec![link(2, 50), link(3, 5)]);
        node1.seq = 3;
        db.admit(node1);
        assert_dynamic_matches_full(&mut engine, &db, db.drain_dirty_origins());

        let mut node1 = entry(1, vec![link(2, 50)]);
        node1.seq = 4;
        db.admit(node1);
        assert_dynamic_matches_full(&mut engine, &db, db.drain_dirty_origins());

        let mut tombstone = entry(3, vec![]);
        tombstone.seq = 2;
        tombstone.tombstone = true;
        db.admit(tombstone);
        assert_dynamic_matches_full(&mut engine, &db, db.drain_dirty_origins());
    }

    #[test]
    fn dynamic_spf_matches_full_for_transit_disabled_change() {
        let cfg = cfg();
        let mut node2 = entry(2, vec![link(1, 10), link(3, 10)]);
        let db = build_db(vec![
            entry(1, vec![link(2, 10)]),
            node2.clone(),
            entry(3, vec![link(2, 10)]),
        ]);
        let mut engine = DynamicSpf::rebuild(&db, 1, &cfg);

        node2.seq = 2;
        node2.transit_disabled = true;
        db.admit(node2);
        assert_dynamic_matches_full(&mut engine, &db, db.drain_dirty_origins());
    }
}
