pub struct CodecInfo {
    alpha_codec: i32,
    beta_codec: i32,
    prefer_alpha_codec: bool,
    opus: bool,
}

impl Default for CodecInfo {

    fn default() -> Self {
        CodecInfo {
            alpha_codec: 0,
            beta_codec: 0,
            prefer_alpha_codec: false,
            opus: false,
        }
    }
}

impl CodecInfo {
    pub fn alpha_codec(&self) -> i32 { self.alpha_codec }
    pub fn beta_codec(&self) -> i32 { self.beta_codec }
    pub fn prefer_alpha_codec(&self) -> bool { self.prefer_alpha_codec }
    pub fn opus(&self) -> bool { self.opus }
    /// Re-evaluate codec selection based on client capabilities.
    /// Returns `true` if the codec selection changed.
    pub fn recheck(
        &mut self,
        alpha_count: usize,
        beta_count: usize,
        prefer_alpha_count: usize,
        opus_count: usize,
        total_clients: usize,
    ) -> bool {
        if total_clients == 0 {
            return false;
        }

        let old_alpha = self.alpha_codec;
        let old_beta = self.beta_codec;
        let old_prefer = self.prefer_alpha_codec;
        let old_opus = self.opus;

        // Prefer Opus if any client supports it
        self.opus = opus_count > 0;

        // CELT codec selection (only relevant if no Opus)
        if !self.opus {
            self.alpha_codec = if alpha_count > 0 { -2147483637i32 } else { 0 };
            self.beta_codec = if beta_count > 0 { -2147483637i32 } else { 0 };
            self.prefer_alpha_codec = prefer_alpha_count >= beta_count;
        } else {
            self.alpha_codec = 0;
            self.beta_codec = 0;
            self.prefer_alpha_codec = false;
        }

        self.alpha_codec != old_alpha
            || self.beta_codec != old_beta
            || self.prefer_alpha_codec != old_prefer
            || self.opus != old_opus
    }
}
