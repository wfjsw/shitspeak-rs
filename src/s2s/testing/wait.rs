//! Predicate-driven sleep loops used by integration tests.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::cluster::Cluster;

/// Wait for `predicate` to hold or `deadline` to elapse. Returns whether
/// the predicate held in time.
pub async fn wait_until<F: FnMut() -> bool>(deadline: Duration, mut predicate: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// As `wait_until` but with a custom poll interval.
pub async fn wait_until_with<F: FnMut() -> bool>(
    deadline: Duration,
    poll: Duration,
    mut predicate: F,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(poll).await;
    }
    false
}

/// Wait until every (a, b) pair from `from` × `to` (where a ≠ b) has
/// `from.alive_members().contains(&b)`.
pub async fn wait_for_full_alive_mesh(cluster: &Cluster, deadline: Duration) -> bool {
    let ids: HashSet<u16> = cluster.ids().into_iter().collect();
    wait_until(deadline, || {
        for n in &cluster.nodes {
            let alive: HashSet<u16> = n.overlay.alive_members().into_iter().collect();
            for &other in &ids {
                if other == n.id {
                    continue;
                }
                if !alive.contains(&other) {
                    return false;
                }
            }
        }
        true
    })
    .await
}

/// Wait until every node has a `Reliable` route to every other.
pub async fn wait_for_full_routing(cluster: &Cluster, deadline: Duration) -> bool {
    let ids: Vec<u16> = cluster.ids();
    wait_until(deadline, || {
        for n in &cluster.nodes {
            for &other in &ids {
                if other == n.id {
                    continue;
                }
                if n.overlay
                    .route_to(other, crate::s2s::transport::ServiceLevel::Reliable)
                    .is_none()
                {
                    return false;
                }
            }
        }
        true
    })
    .await
}
