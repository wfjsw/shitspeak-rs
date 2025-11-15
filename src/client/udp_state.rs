use std::collections::{HashMap};

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
