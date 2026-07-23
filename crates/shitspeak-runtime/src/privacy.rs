use shitspeak_messages::messages::encoder::UserState;

const CERTIFICATE_HASH_REMAP_CONTEXT: &[u8] = b"shitspeak-rs/privacy/certificate-hash/v1";
const CERTIFICATE_HASH_AES_KEY_CONTEXT: &[u8] = b"shitspeak-rs/privacy/certificate-hash/aes-key/v1";
const CERTIFICATE_HASH_AES_ROUND_CONTEXT: &[u8; 5] = b"schp1";
const CERTIFICATE_HASH_BYTES: usize = 20;
const CERTIFICATE_HASH_FEISTEL_HALF_BYTES: usize = CERTIFICATE_HASH_BYTES / 2;
const CERTIFICATE_HASH_FEISTEL_ROUNDS: u8 = 8;

pub fn remapped_certificate_hash_hex(secret: &str, certificate_hash_hex: &str) -> Option<String> {
    let certificate_hash = hex::decode(certificate_hash_hex).ok()?;
    if certificate_hash.len() != CERTIFICATE_HASH_BYTES {
        return None;
    }

    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret.as_bytes());
    let mut input =
        Vec::with_capacity(CERTIFICATE_HASH_REMAP_CONTEXT.len() + certificate_hash.len());
    input.extend_from_slice(CERTIFICATE_HASH_REMAP_CONTEXT);
    input.extend_from_slice(&certificate_hash);
    let tag = aws_lc_rs::hmac::sign(&key, &input);
    Some(hex::encode(&tag.as_ref()[..CERTIFICATE_HASH_BYTES]))
}

pub fn protected_certificate_hash_hex(
    protection: shitspeak_runtime_config::CertificateHashProtection,
    secret: &str,
    certificate_hash_hex: &str,
) -> Option<String> {
    match protection {
        shitspeak_runtime_config::CertificateHashProtection::Disabled => {
            Some(certificate_hash_hex.to_owned())
        }
        shitspeak_runtime_config::CertificateHashProtection::Irreversible => {
            remapped_certificate_hash_hex(secret, certificate_hash_hex)
        }
        shitspeak_runtime_config::CertificateHashProtection::Reversible => {
            reversible_certificate_hash_hex(secret, certificate_hash_hex)
        }
    }
}

fn reversible_certificate_hash_hex(secret: &str, certificate_hash_hex: &str) -> Option<String> {
    apply_reversible_certificate_hash_permutation(secret, certificate_hash_hex, false)
}

fn apply_reversible_certificate_hash_permutation(
    secret: &str,
    certificate_hash_hex: &str,
    reverse: bool,
) -> Option<String> {
    let certificate_hash = hex::decode(certificate_hash_hex).ok()?;
    let mut state: [u8; CERTIFICATE_HASH_BYTES] = certificate_hash.as_slice().try_into().ok()?;
    let key = derive_certificate_hash_aes_key(secret);
    let unbound_key = aws_lc_rs::cipher::UnboundCipherKey::new(&aws_lc_rs::cipher::AES_256, &key)
        .expect("AES-256 key length is fixed");
    let cipher =
        aws_lc_rs::cipher::EncryptingKey::ecb(unbound_key).expect("AES-256 ECB key is valid");

    let round_iter: Box<dyn Iterator<Item = u8>> = if reverse {
        Box::new((0..CERTIFICATE_HASH_FEISTEL_ROUNDS).rev())
    } else {
        Box::new(0..CERTIFICATE_HASH_FEISTEL_ROUNDS)
    };

    for round in round_iter {
        let mut left = [0u8; CERTIFICATE_HASH_FEISTEL_HALF_BYTES];
        let mut right = [0u8; CERTIFICATE_HASH_FEISTEL_HALF_BYTES];
        left.copy_from_slice(&state[..CERTIFICATE_HASH_FEISTEL_HALF_BYTES]);
        right.copy_from_slice(&state[CERTIFICATE_HASH_FEISTEL_HALF_BYTES..]);

        if reverse {
            let round_output = certificate_hash_aes_round_output(&cipher, round, &left);
            for i in 0..CERTIFICATE_HASH_FEISTEL_HALF_BYTES {
                state[i] = right[i] ^ round_output[i];
                state[CERTIFICATE_HASH_FEISTEL_HALF_BYTES + i] = left[i];
            }
        } else {
            let round_output = certificate_hash_aes_round_output(&cipher, round, &right);
            for i in 0..CERTIFICATE_HASH_FEISTEL_HALF_BYTES {
                state[i] = right[i];
                state[CERTIFICATE_HASH_FEISTEL_HALF_BYTES + i] = left[i] ^ round_output[i];
            }
        }
    }

    Some(hex::encode(state))
}

fn derive_certificate_hash_aes_key(secret: &str) -> [u8; 32] {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret.as_bytes());
    let tag = aws_lc_rs::hmac::sign(&key, CERTIFICATE_HASH_AES_KEY_CONTEXT);
    tag.as_ref()
        .try_into()
        .expect("HMAC-SHA256 output length is fixed")
}

fn certificate_hash_aes_round_output(
    cipher: &aws_lc_rs::cipher::EncryptingKey,
    round: u8,
    half: &[u8; CERTIFICATE_HASH_FEISTEL_HALF_BYTES],
) -> [u8; CERTIFICATE_HASH_FEISTEL_HALF_BYTES] {
    let mut block = [0u8; 16];
    block[..CERTIFICATE_HASH_AES_ROUND_CONTEXT.len()]
        .copy_from_slice(CERTIFICATE_HASH_AES_ROUND_CONTEXT);
    block[CERTIFICATE_HASH_AES_ROUND_CONTEXT.len()] = round;
    block[CERTIFICATE_HASH_AES_ROUND_CONTEXT.len() + 1..].copy_from_slice(half);
    cipher
        .encrypt(&mut block)
        .expect("AES-256 ECB encrypts one complete block");

    let mut out = [0u8; CERTIFICATE_HASH_FEISTEL_HALF_BYTES];
    out.copy_from_slice(&block[..CERTIFICATE_HASH_FEISTEL_HALF_BYTES]);
    out
}

pub fn protect_user_state_certificate_hash(
    state: &mut UserState,
    viewer_is_superuser: bool,
    viewer_session: crate::client::client_session_identifier::ClientSessionIdentifier,
    protection: shitspeak_runtime_config::CertificateHashProtection,
    secret: Option<&str>,
) {
    if !should_protect_user_state_certificate_hash(
        state,
        viewer_is_superuser,
        viewer_session,
        protection,
    ) {
        return;
    }

    let Some(secret) = secret.filter(|secret| !secret.is_empty()) else {
        return;
    };
    let Some(hash) = state.hash.as_deref() else {
        return;
    };
    if let Some(remapped) = protected_certificate_hash_hex(protection, secret, hash) {
        state.hash = Some(remapped);
    }
}

pub(crate) fn should_protect_user_state_certificate_hash(
    state: &UserState,
    viewer_is_superuser: bool,
    viewer_session: crate::client::client_session_identifier::ClientSessionIdentifier,
    protection: shitspeak_runtime_config::CertificateHashProtection,
) -> bool {
    protection.is_enabled()
        && !viewer_is_superuser
        && state.session != Some(viewer_session)
        && state.hash.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::client_session_identifier::ClientSessionIdentifier;
    use shitspeak_runtime_config::CertificateHashProtection;

    #[test]
    fn remap_is_stable_and_not_the_source_hash() {
        let source = "00112233445566778899aabbccddeeff00112233";

        let first = remapped_certificate_hash_hex("cluster-secret", source).unwrap();
        let second = remapped_certificate_hash_hex("cluster-secret", source).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), source.len());
        assert_ne!(first, source);
    }

    #[test]
    fn reversible_remap_is_stable_and_reversible_with_secret() {
        let source = "00112233445566778899aabbccddeeff00112233";

        let first = protected_certificate_hash_hex(
            CertificateHashProtection::Reversible,
            "cluster-secret",
            source,
        )
        .unwrap();
        let second = protected_certificate_hash_hex(
            CertificateHashProtection::Reversible,
            "cluster-secret",
            source,
        )
        .unwrap();
        let restored =
            apply_reversible_certificate_hash_permutation("cluster-secret", &first, true).unwrap();
        let wrong_secret =
            apply_reversible_certificate_hash_permutation("other-secret", &first, true).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), source.len());
        assert_ne!(first, source);
        assert_eq!(restored, source);
        assert_ne!(wrong_secret, source);
    }

    #[test]
    fn user_state_self_hash_is_not_remapped() {
        let viewer = ClientSessionIdentifier::from(7u32);
        let source = "00112233445566778899aabbccddeeff00112233";
        let mut state = UserState {
            session: Some(viewer),
            hash: Some(source.to_owned()),
            ..UserState::default()
        };

        protect_user_state_certificate_hash(
            &mut state,
            false,
            viewer,
            CertificateHashProtection::Irreversible,
            Some("cluster-secret"),
        );

        assert_eq!(state.hash.as_deref(), Some(source));
    }
}
