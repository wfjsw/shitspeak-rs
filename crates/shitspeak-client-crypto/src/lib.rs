#![allow(warnings)]

mod aes_backend;
mod crypt_state;
mod crypto_mode;
mod errors;
mod gf128;
mod ocb2;
#[cfg(test)]
mod profile_test;

pub use aes_backend::probe as probe_aes_backend;
pub use crypt_state::CryptState;
pub use crypto_mode::CryptoMode;
pub use errors::CryptError;
pub use gf128::probe as probe_gf128_backend;
pub use ocb2::Ocb2;
