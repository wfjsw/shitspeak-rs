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
