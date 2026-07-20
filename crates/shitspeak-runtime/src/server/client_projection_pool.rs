use std::sync::{Arc, Weak};

use futures_util::FutureExt as _;
use tokio::sync::{broadcast, watch};

use crate::client::state_log::ClientStateBroadcastPayload;
use shitspeak_state::ChannelOperation;

use super::Server;
use super::client_projection::{ClientProjectionEvent, ClientProjectionState};
use super::sharded_subscriber::{
    PoolBuildError, PoolHealth, Registration, RegistrationError, ShardedSubscriberPool,
};

const CLIENT_PROJECTION_SHARDS: usize = 8;
const CLIENT_PROJECTION_EVENT_CAPACITY: usize = 2048;

pub(crate) struct ClientProjectionPool {
    pool: ShardedSubscriberPool<ClientProjectionEvent, ClientProjectionState>,
    _event_tx: broadcast::Sender<ClientProjectionEvent>,
    router_health_rx: watch::Receiver<bool>,
}

impl ClientProjectionPool {
    pub(crate) fn spawn(
        server: Weak<Box<Server>>,
        client_rx: broadcast::Receiver<Arc<ClientStateBroadcastPayload>>,
        channel_rx: broadcast::Receiver<Arc<ChannelOperation>>,
        visibility_reload_rx: broadcast::Receiver<()>,
    ) -> Result<Self, PoolBuildError> {
        let (event_tx, _) = broadcast::channel(CLIENT_PROJECTION_EVENT_CAPACITY);
        let pool = ShardedSubscriberPool::new(&event_tx, CLIENT_PROJECTION_SHARDS)?;
        let (router_health_tx, router_health_rx) = watch::channel(true);
        let router_event_tx = event_tx.clone();
        let health_server = server.clone();
        tokio::spawn(async move {
            let result = std::panic::AssertUnwindSafe(run_projection_router(
                server,
                router_event_tx,
                client_rx,
                channel_rx,
                visibility_reload_rx,
            ))
            .catch_unwind()
            .await;
            if let Err(payload) = result {
                tracing::error!(
                    panic = %panic_message(payload),
                    "client projection router panicked"
                );
            } else if let Some(server) = health_server.upgrade() {
                tracing::error!(
                    node = server.node_identifier,
                    "client projection router stopped"
                );
            }
            let _ = router_health_tx.send(false);
        });
        Ok(Self {
            pool,
            _event_tx: event_tx,
            router_health_rx,
        })
    }

    pub(crate) async fn register(
        &self,
        state: ClientProjectionState,
    ) -> Result<ClientProjectionRegistration, RegistrationError> {
        if !*self.router_health_rx.borrow() {
            return Err(RegistrationError::ShardStopped);
        }
        let key = state.client_instance_id();
        let registration = self.pool.register(&key, state).await?;
        let shard_index = registration.shard_index();
        Ok(ClientProjectionRegistration {
            _registration: registration,
            shard_index,
            health_rx: self.pool.health(),
            router_health_rx: self.router_health_rx.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn shard_count(&self) -> usize {
        self.pool.shard_count()
    }
}

pub(crate) struct ClientProjectionRegistration {
    _registration: Registration<ClientProjectionState>,
    shard_index: usize,
    health_rx: watch::Receiver<PoolHealth>,
    router_health_rx: watch::Receiver<bool>,
}

impl ClientProjectionRegistration {
    /// Completes only when this client's projection shard stops or fails.
    pub(crate) async fn failed(&mut self) {
        loop {
            if !shard_is_healthy(&self.health_rx.borrow(), self.shard_index) {
                return;
            }
            if !*self.router_health_rx.borrow() {
                return;
            }
            tokio::select! {
                result = self.health_rx.changed() => {
                    if result.is_err() {
                        return;
                    }
                }
                result = self.router_health_rx.changed() => {
                    if result.is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn shard_index(&self) -> usize {
        self._registration.shard_index()
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "projection router panicked".to_owned()
    }
}

fn shard_is_healthy(health: &PoolHealth, shard_index: usize) -> bool {
    use super::sharded_subscriber::ShardStatus;
    matches!(
        health.shard_status(shard_index),
        Some(ShardStatus::Starting | ShardStatus::Running)
    )
}

async fn run_projection_router(
    _server: Weak<Box<Server>>,
    event_tx: broadcast::Sender<ClientProjectionEvent>,
    mut client_rx: broadcast::Receiver<Arc<ClientStateBroadcastPayload>>,
    mut channel_rx: broadcast::Receiver<Arc<ChannelOperation>>,
    mut visibility_reload_rx: broadcast::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = channel_rx.recv() => {
                match result {
                    Ok(operation) => {
                        let _ = event_tx.send(ClientProjectionEvent::Channel(operation));
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "client projection router lagged on channel log");
                        let _ = event_tx.send(ClientProjectionEvent::ChannelLagged(skipped));
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            result = client_rx.recv() => {
                if !drain_ready_channels(&event_tx, &mut channel_rx) {
                    return;
                }
                match result {
                    Ok(payload) => {
                        let _ = event_tx.send(ClientProjectionEvent::Client(payload));
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "client projection router lagged on client log");
                        let _ = event_tx.send(ClientProjectionEvent::ClientLagged(skipped));
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            result = visibility_reload_rx.recv() => {
                match result {
                    Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = event_tx.send(ClientProjectionEvent::VisibilityReload);
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

fn drain_ready_channels(
    event_tx: &broadcast::Sender<ClientProjectionEvent>,
    channel_rx: &mut broadcast::Receiver<Arc<ChannelOperation>>,
) -> bool {
    // Drain the complete ready prefix that existed when the client event won
    // the fair select. New channel publications wait for the next turn, so a
    // continuous producer cannot trap the router in this loop.
    let ready = channel_rx.len();
    for _ in 0..ready {
        match channel_rx.try_recv() {
            Ok(operation) => {
                let _ = event_tx.send(ClientProjectionEvent::Channel(operation));
            }
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                tracing::warn!(
                    skipped,
                    "client projection router lagged while draining channel log"
                );
                let _ = event_tx.send(ClientProjectionEvent::ChannelLagged(skipped));
                break;
            }
            Err(broadcast::error::TryRecvError::Closed) => {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use shitspeak_state::ChannelOp;

    fn channel_operation(version: u64) -> Arc<ChannelOperation> {
        Arc::new(ChannelOperation {
            server_id: "test".to_owned(),
            version,
            node_id: 1,
            timestamp: 0,
            emits_client_message: true,
            op: ChannelOp::DeleteChannel {
                id: version as u32,
                nonce: 1,
            },
        })
    }

    #[test]
    fn ready_channel_drain_is_not_capped_before_a_client_event() {
        let (channel_tx, mut channel_rx) = broadcast::channel(128);
        let (event_tx, mut event_rx) = broadcast::channel(128);
        for version in 1..=65 {
            channel_tx
                .send(channel_operation(version))
                .expect("channel receiver is open");
        }

        assert!(drain_ready_channels(&event_tx, &mut channel_rx));
        for expected in 1..=65 {
            let ClientProjectionEvent::Channel(operation) = event_rx
                .try_recv()
                .expect("the full ready prefix must be forwarded")
            else {
                panic!("expected a channel event");
            };
            assert_eq!(operation.version, expected);
        }
        assert!(matches!(
            event_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn essential_router_source_closure_marks_router_unhealthy() {
        let (client_tx, client_rx) = broadcast::channel(8);
        let (_channel_tx, channel_rx) = broadcast::channel(8);
        let (_visibility_tx, visibility_rx) = broadcast::channel(8);
        let pool = ClientProjectionPool::spawn(
            Weak::<Box<Server>>::new(),
            client_rx,
            channel_rx,
            visibility_rx,
        )
        .expect("pool starts");
        let mut health = pool.router_health_rx.clone();

        drop(client_tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), health.changed())
            .await
            .expect("router health changes")
            .expect("health sender remains open");
        assert!(!*health.borrow());
    }
}
