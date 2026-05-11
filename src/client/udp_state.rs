use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::{client::voice_target::VoiceTarget, voice_crypto::CryptoProvider};

pub struct UdpState {
    udp_enabled: bool,

    last_resync: DateTime<Utc>,
    crypto_provider: Box<dyn CryptoProvider>,
    celt_versions: Vec<i32>,
    opus: bool,

    voice_targets: HashMap<u32, VoiceTarget>,
}

impl UdpState {
    pub fn new(crypto_provider: Box<dyn CryptoProvider>) -> Self {
        UdpState {
            udp_enabled: false,
            last_resync: Utc::now(),
            crypto_provider,
            celt_versions: Vec::new(),
            opus: true,
            voice_targets: HashMap::new(),
        }
    }

    pub fn voice_target_mut(&mut self, id: u32) -> &mut VoiceTarget {
        self.voice_targets
            .entry(id)
            .or_insert_with(VoiceTarget::new)
    }

    pub fn voice_target(&self, id: u32) -> Option<&VoiceTarget> {
        self.voice_targets.get(&id)
    }
}
