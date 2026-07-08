use std::{sync::OnceLock, time::Instant};

#[inline]
pub fn now_millis() -> u32 {
    static START: OnceLock<Instant> = OnceLock::new();

    START.get_or_init(Instant::now).elapsed().as_millis() as u32
}
