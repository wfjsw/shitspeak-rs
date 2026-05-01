use bytes::Bytes;
use tokio::sync::mpsc;

use crate::s2s::core::overlay::{Overlay, OverlayError, OverlayFrame};
use crate::s2s::core::transport::StreamClass;
use crate::s2s::core::NodeId;

#[derive(Clone)]
pub struct VoiceStreamAdapter {
    overlay: Overlay,
}

impl VoiceStreamAdapter {
    pub fn new(overlay: Overlay) -> Self {
        Self { overlay }
    }

    pub async fn send_voice_multicast(
        &self,
        recipients: &[NodeId],
        payload: Bytes,
    ) -> Result<(), OverlayError> {
        let _ = self
            .overlay
            .send_multicast(recipients, StreamClass::LowLatencyDatagram, payload)
            .await?;
        Ok(())
    }

    pub async fn send_voice_broadcast(&self, payload: Bytes) -> Result<(), OverlayError> {
        let _ = self
            .overlay
            .send_broadcast(StreamClass::LowLatencyDatagram, payload)
            .await?;
        Ok(())
    }

    pub async fn send_voice_unicast(
        &self,
        dst: NodeId,
        payload: Bytes,
    ) -> Result<(), OverlayError> {
        let _ = self
            .overlay
            .send_unreliable(dst, StreamClass::LowLatencyDatagram, payload)
            .await?;
        Ok(())
    }

    pub async fn send_voice_direct(
        &self,
        dst: NodeId,
        payload: Bytes,
    ) -> Result<(), OverlayError> {
        let _ = self
            .overlay
            .send_direct(dst, StreamClass::LowLatencyDatagram, payload)
            .await?;
        Ok(())
    }

    pub async fn subscribe_voice_inbound(&self) -> mpsc::Receiver<OverlayFrame> {
        self.overlay
            .subscribe_inbound(StreamClass::LowLatencyDatagram)
            .await
    }
}
