//! Per-destination ordering for reliable overlay payloads.

use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use tokio::sync::{Mutex, MutexGuard};

use crate::s2s::transport::{MessageClass, ServiceLevel};
use crate::types::NodeIdentifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct InboundKey {
    src: NodeIdentifier,
    dst: NodeIdentifier,
}

#[derive(Debug, Default)]
struct InboundState {
    next_seq: u64,
    buffered: BTreeMap<u64, OrderedDelivery>,
}

#[derive(Debug)]
pub(crate) struct OverlayOrdering {
    outbound_send: Mutex<()>,
    outbound_next: Mutex<HashMap<NodeIdentifier, u64>>,
    inbound: Mutex<HashMap<InboundKey, InboundState>>,
}

impl OverlayOrdering {
    pub(crate) fn new() -> Self {
        Self {
            outbound_send: Mutex::new(()),
            outbound_next: Mutex::new(HashMap::new()),
            inbound: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn outbound_send_guard(&self) -> MutexGuard<'_, ()> {
        self.outbound_send.lock().await
    }

    pub(crate) async fn next_outbound_seq(&self, dst: NodeIdentifier) -> u64 {
        let mut outbound = self.outbound_next.lock().await;
        let seq = outbound.entry(dst).or_insert(0);
        let current = *seq;
        *seq = seq.saturating_add(1);
        current
    }

    pub(crate) async fn release_failed_outbound_seq(&self, dst: NodeIdentifier, seq: u64) {
        let mut outbound = self.outbound_next.lock().await;
        if let Some(next) = outbound.get_mut(&dst) {
            if *next == seq.saturating_add(1) {
                *next = seq;
            }
        }
    }

    pub(crate) async fn reset_peer(&self, peer: NodeIdentifier) {
        self.outbound_next.lock().await.remove(&peer);
        self.inbound
            .lock()
            .await
            .retain(|key, _| key.src != peer && key.dst != peer);
    }

    pub(crate) async fn accept_inbound(
        &self,
        dst: NodeIdentifier,
        seq: u64,
        delivery: OrderedDelivery,
    ) -> Vec<OrderedDelivery> {
        let key = InboundKey {
            src: delivery.src(),
            dst,
        };
        let mut inbound = self.inbound.lock().await;
        let state = inbound.entry(key).or_default();

        if seq < state.next_seq {
            return Vec::new();
        }

        if seq > state.next_seq {
            state.buffered.entry(seq).or_insert(delivery);
            return Vec::new();
        }

        let mut ready = vec![delivery];
        state.next_seq = state.next_seq.saturating_add(1);
        while let Some(delivery) = state.buffered.remove(&state.next_seq) {
            ready.push(delivery);
            state.next_seq = state.next_seq.saturating_add(1);
        }

        ready
    }
}

impl Default for OverlayOrdering {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OrderedDelivery {
    src: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
}

impl OrderedDelivery {
    pub(crate) fn new(
        src: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Self {
        Self {
            src,
            tag,
            level,
            class,
            body,
        }
    }

    pub(crate) fn src(&self) -> NodeIdentifier {
        self.src
    }

    pub(crate) fn tag(&self) -> u32 {
        self.tag
    }

    pub(crate) fn level(&self) -> ServiceLevel {
        self.level
    }

    pub(crate) fn class(&self) -> MessageClass {
        self.class
    }

    pub(crate) fn body(&self) -> Bytes {
        self.body.clone()
    }
}

pub(crate) fn requires_ordering(level: ServiceLevel) -> bool {
    matches!(
        level,
        ServiceLevel::Reliable | ServiceLevel::ReliableLowLatency
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery(src: NodeIdentifier, body: &'static [u8]) -> OrderedDelivery {
        OrderedDelivery::new(
            src,
            7,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            Bytes::from_static(body),
        )
    }

    #[tokio::test]
    async fn buffers_until_missing_sequence_arrives() {
        let ordering = OverlayOrdering::new();

        assert!(ordering
            .accept_inbound(2, 1, delivery(1, b"second"))
            .await
            .is_empty());

        let ready = ordering.accept_inbound(2, 0, delivery(1, b"first")).await;
        assert_eq!(ready.len(), 2);
        assert_eq!(&ready[0].body()[..], b"first");
        assert_eq!(&ready[1].body()[..], b"second");
    }

    #[tokio::test]
    async fn outbound_sequence_can_be_released_after_failed_send() {
        let ordering = OverlayOrdering::new();

        let first = ordering.next_outbound_seq(2).await;
        ordering.release_failed_outbound_seq(2, first).await;
        let retry = ordering.next_outbound_seq(2).await;

        assert_eq!(first, retry);
    }

    #[tokio::test]
    async fn reset_peer_clears_outbound_and_inbound_sequence_state() {
        let ordering = OverlayOrdering::new();

        assert_eq!(ordering.next_outbound_seq(2).await, 0);
        assert_eq!(ordering.next_outbound_seq(2).await, 1);
        assert!(ordering
            .accept_inbound(1, 1, delivery(2, b"second"))
            .await
            .is_empty());

        ordering.reset_peer(2).await;

        assert_eq!(ordering.next_outbound_seq(2).await, 0);
        let ready = ordering
            .accept_inbound(1, 0, delivery(2, b"first-after-reset"))
            .await;
        assert_eq!(ready.len(), 1);
        assert_eq!(&ready[0].body()[..], b"first-after-reset");
    }
}
