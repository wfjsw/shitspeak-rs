use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use crate::api::{Authenticator, ReloadableAuthenticator};
use crate::client::Client;
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::config::Config;
use crate::errors::MessageHandlerError;
use crate::messages::encoder::TextMessage;
use crate::messages::{Message, WriteMessageExt};

const AUTH_FINALIZATION_QUEUE_NOTICE_INTERVAL: Duration = Duration::from_secs(5);

pub(super) struct AuthFinalizationQueue {
    authenticator: Arc<ReloadableAuthenticator>,
    semaphore: Arc<tokio::sync::Semaphore>,
    next_ticket: AtomicU64,
    waiters: Mutex<VecDeque<AuthFinalizationWaiter>>,
    waiters_changed: tokio::sync::Notify,
    #[cfg(test)]
    test_gate: Mutex<Option<AuthFinalizationTestGate>>,
}

#[derive(Clone)]
struct AuthFinalizationWaiter {
    ticket: u64,
}

pub(super) enum AuthFinalizationAdmission {
    Immediate(tokio::sync::OwnedSemaphorePermit),
    Queued(u64),
}

#[cfg(test)]
struct AuthFinalizationTestGate {
    target_acquire: usize,
    acquired_count: std::sync::atomic::AtomicUsize,
    entered_tx: tokio::sync::watch::Sender<usize>,
    release_rx: tokio::sync::watch::Receiver<bool>,
}

#[cfg(test)]
pub(crate) struct AuthFinalizationTestGateHandle {
    entered_rx: tokio::sync::watch::Receiver<usize>,
    release_tx: tokio::sync::watch::Sender<bool>,
}

#[cfg(test)]
impl AuthFinalizationTestGateHandle {
    pub async fn wait_entered(&mut self, deadline: Duration) -> Option<usize> {
        tokio::time::timeout(deadline, async {
            loop {
                let value = *self.entered_rx.borrow();
                if value != 0 {
                    return value;
                }
                if self.entered_rx.changed().await.is_err() {
                    return 0;
                }
            }
        })
        .await
        .ok()
        .filter(|value| *value != 0)
    }

    pub fn release(&self) {
        let _ = self.release_tx.send(true);
    }
}

pub struct AuthFinalizationPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    queue: Arc<AuthFinalizationQueue>,
    ticket: u64,
}

impl AuthFinalizationQueue {
    pub(super) fn new(limit: usize, authenticator: ReloadableAuthenticator) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
            semaphore: Arc::new(tokio::sync::Semaphore::new(limit.max(1))),
            next_ticket: AtomicU64::new(1),
            waiters: Mutex::new(VecDeque::new()),
            waiters_changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            test_gate: Mutex::new(None),
        }
    }

    pub(super) fn authenticator(&self) -> &dyn Authenticator {
        self.authenticator.as_ref()
    }

    pub(super) fn authenticator_arc(&self) -> Arc<dyn Authenticator> {
        let authenticator: Arc<dyn Authenticator> = self.authenticator.clone();
        authenticator
    }

    pub(super) fn prepare_authenticator_reload(
        &self,
        config: &Config,
    ) -> Result<Option<Arc<dyn Authenticator>>, crate::api::AuthenticatorBackendError> {
        self.authenticator.prepare_reload(config)
    }

    pub(super) fn apply_prepared_authenticator_reload(&self, next: Option<Arc<dyn Authenticator>>) {
        self.authenticator.apply_prepared_reload(next);
    }

    pub(super) async fn acquire(
        self: &Arc<Self>,
        client: &Arc<Box<Client>>,
    ) -> Result<AuthFinalizationPermit, MessageHandlerError> {
        let ticket = match self.reserve_or_queue() {
            AuthFinalizationAdmission::Immediate(permit) => {
                self.wait_for_test_gate_if_needed().await;
                return Ok(AuthFinalizationPermit {
                    _permit: permit,
                    queue: Arc::clone(self),
                    ticket: 0,
                });
            }
            AuthFinalizationAdmission::Queued(ticket) => ticket,
        };

        let waiter = AuthFinalizationTicket {
            queue: Arc::clone(self),
            ticket,
        };
        let mut last_announced_position = None;
        self.send_queue_notice(client, ticket, &mut last_announced_position)
            .await?;
        let permit = self
            .acquire_queued_permit(client, ticket, &mut last_announced_position)
            .await?;

        drop(waiter);
        self.wait_for_test_gate_if_needed().await;
        Ok(AuthFinalizationPermit {
            _permit: permit,
            queue: Arc::clone(self),
            ticket,
        })
    }

    pub(super) fn reserve_or_queue(self: &Arc<Self>) -> AuthFinalizationAdmission {
        let mut waiters = self.waiters.lock();
        if waiters.is_empty()
            && let Ok(permit) = Arc::clone(&self.semaphore).try_acquire_owned()
        {
            return AuthFinalizationAdmission::Immediate(permit);
        }

        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        waiters.push_back(AuthFinalizationWaiter { ticket });
        AuthFinalizationAdmission::Queued(ticket)
    }

    async fn acquire_queued_permit(
        self: &Arc<Self>,
        client: &Arc<Box<Client>>,
        ticket: u64,
        last_announced_position: &mut Option<usize>,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, MessageHandlerError> {
        let mut notice_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + AUTH_FINALIZATION_QUEUE_NOTICE_INTERVAL,
            AUTH_FINALIZATION_QUEUE_NOTICE_INTERVAL,
        );
        notice_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let waiters_changed = self.waiters_changed.notified();
            tokio::pin!(waiters_changed);

            if !self.is_front(ticket) {
                tokio::select! {
                    _ = &mut waiters_changed => {}
                    _ = notice_interval.tick() => {
                        self.send_queue_notice(client, ticket, last_announced_position).await?;
                    }
                }
                continue;
            }

            let permit = Arc::clone(&self.semaphore).acquire_owned();
            tokio::pin!(permit);
            loop {
                tokio::select! {
                    permit = &mut permit => {
                        return Ok(permit.expect("auth finalization semaphore should not be closed"));
                    }
                    _ = notice_interval.tick() => {
                        self.send_queue_notice(client, ticket, last_announced_position).await?;
                    }
                }
            }
        }
    }

    async fn send_queue_notice(
        &self,
        client: &Arc<Box<Client>>,
        ticket: u64,
        last_announced_position: &mut Option<usize>,
    ) -> Result<(), MessageHandlerError> {
        if let Some(position) = self.position(ticket)
            && should_send_auth_finalization_queue_notice(last_announced_position, position)
        {
            let message = auth_finalization_queue_message(client.get_session_id(), position);
            client.write_proto_message(&message).await?;
        }
        Ok(())
    }

    fn remove_waiter(&self, ticket: u64) {
        if ticket != 0 {
            let removed = {
                let mut waiters = self.waiters.lock();
                let before = waiters.len();
                waiters.retain(|waiter| waiter.ticket != ticket);
                waiters.len() != before
            };
            if removed {
                self.waiters_changed.notify_waiters();
            }
        }
    }

    fn is_front(&self, ticket: u64) -> bool {
        let waiters = self.waiters.lock();
        waiters
            .front()
            .is_some_and(|waiter| waiter.ticket == ticket)
    }

    pub(super) fn position(&self, ticket: u64) -> Option<usize> {
        let waiters = self.waiters.lock();
        waiters
            .iter()
            .position(|waiter| waiter.ticket == ticket)
            .map(|index| index + 1)
    }

    #[cfg(test)]
    pub(super) fn install_test_gate(
        &self,
        target_acquire: usize,
    ) -> AuthFinalizationTestGateHandle {
        let (entered_tx, entered_rx) = tokio::sync::watch::channel(0);
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        *self.test_gate.lock() = Some(AuthFinalizationTestGate {
            target_acquire,
            acquired_count: std::sync::atomic::AtomicUsize::new(0),
            entered_tx,
            release_rx,
        });
        AuthFinalizationTestGateHandle {
            entered_rx,
            release_tx,
        }
    }

    async fn wait_for_test_gate_if_needed(&self) {
        #[cfg(test)]
        {
            let release_rx = {
                let guard = self.test_gate.lock();
                let Some(gate) = guard.as_ref() else {
                    return;
                };
                let acquire_index = gate.acquired_count.fetch_add(1, Ordering::Relaxed) + 1;
                if acquire_index != gate.target_acquire {
                    return;
                }
                let _ = gate.entered_tx.send(acquire_index);
                gate.release_rx.clone()
            };
            let mut release_rx = release_rx;
            while !*release_rx.borrow() {
                if release_rx.changed().await.is_err() {
                    break;
                }
            }
        }
    }
}

struct AuthFinalizationTicket {
    queue: Arc<AuthFinalizationQueue>,
    ticket: u64,
}

impl Drop for AuthFinalizationTicket {
    fn drop(&mut self) {
        self.queue.remove_waiter(self.ticket);
    }
}

impl Drop for AuthFinalizationPermit {
    fn drop(&mut self) {
        self.queue.remove_waiter(self.ticket);
    }
}

impl AuthFinalizationPermit {
    pub(crate) fn authenticator(&self) -> &dyn Authenticator {
        self.queue.authenticator()
    }
}

fn auth_finalization_queue_message(
    session_id: ClientSessionIdentifier,
    position: usize,
) -> Message {
    let users_ahead = position.saturating_sub(1);

    Message::TextMessage(
        TextMessage {
            actor: None,
            session: vec![u32::from(session_id)],
            channel_id: Vec::new(),
            tree_id: Vec::new(),
            message: format!(
                "You're in the login queue. There are {users_ahead} users ahead of you."
            ),
        }
        .into(),
    )
}

pub(super) fn should_send_auth_finalization_queue_notice(
    last_announced_position: &mut Option<usize>,
    position: usize,
) -> bool {
    if *last_announced_position == Some(position) {
        return false;
    }

    *last_announced_position = Some(position);
    true
}
