use shitspeak_messages::messages::encoder::UserState;

const CERTIFICATE_HASH_REMAP_CONTEXT: &[u8] = b"shitspeak-rs/privacy/certificate-hash/v2";
const CERTIFICATE_HASH_AES_KEY_CONTEXT: &[u8] =
    b"shitspeak-rs/privacy/certificate-hash/aes-key/v1";
const CERTIFICATE_HASH_AES_ROUND_CONTEXT: &[u8; 5] = b"schp1";
const CERTIFICATE_HASH_BYTES: usize = 20;
const CERTIFICATE_HASH_FEISTEL_HALF_BYTES: usize = CERTIFICATE_HASH_BYTES / 2;
const CERTIFICATE_HASH_FEISTEL_ROUNDS: u8 = 8;

const IDENTITY_KIND_EMPTY: u8 = 0;
const IDENTITY_KIND_FQDN: u8 = 1;
const IDENTITY_KIND_USER_ID: u8 = 2;

/// Identity of one side of a certificate-hash projection, used as salt
/// material.
///
/// The identity is the party's FQDN when one is available, its user id when
/// there is no FQDN, and nothing at all when neither is available.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivacyIdentity {
    kind: PrivacyIdentityKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PrivacyIdentityKind {
    Empty,
    Fqdn(String),
    UserId(u32),
}

impl PrivacyIdentity {
    /// Builds the identity from an optional FQDN and optional user id,
    /// preferring the FQDN. An empty FQDN counts as missing.
    pub fn new(fqdn: Option<&str>, user_id: Option<u32>) -> Self {
        let kind = match fqdn.filter(|fqdn| !fqdn.is_empty()) {
            Some(fqdn) => PrivacyIdentityKind::Fqdn(fqdn.to_owned()),
            None => match user_id {
                Some(user_id) => PrivacyIdentityKind::UserId(user_id),
                None => PrivacyIdentityKind::Empty,
            },
        };
        Self { kind }
    }

    fn append_encoded(&self, out: &mut Vec<u8>) {
        match &self.kind {
            PrivacyIdentityKind::Empty => out.push(IDENTITY_KIND_EMPTY),
            PrivacyIdentityKind::Fqdn(fqdn) => {
                out.push(IDENTITY_KIND_FQDN);
                append_length_prefixed(out, fqdn.as_bytes());
            }
            PrivacyIdentityKind::UserId(user_id) => {
                out.push(IDENTITY_KIND_USER_ID);
                out.extend_from_slice(&user_id.to_be_bytes());
            }
        }
    }
}

/// Per-recipient salt for the irreversible certificate-hash projection.
///
/// The salt binds a projected hash to both the referenced user and the
/// receiving side, so every recipient observes a different hash for the same
/// person and nobody can correlate their own view with someone else's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateHashSalt {
    referenced_identity: PrivacyIdentity,
    receiver_certificate_hash: Vec<u8>,
    receiver_identity: PrivacyIdentity,
}

impl CertificateHashSalt {
    /// Builds a salt from the referenced user's identity, the receiving side's
    /// certificate hash, and the receiving side's identity.
    pub fn new(
        referenced_identity: PrivacyIdentity,
        receiver_certificate_hash: &[u8],
        receiver_identity: PrivacyIdentity,
    ) -> Self {
        Self {
            referenced_identity,
            receiver_certificate_hash: receiver_certificate_hash.to_owned(),
            receiver_identity,
        }
    }

    /// Unambiguous encoding of the three salt components, in the order
    /// referenced identity, receiver certificate hash, receiver identity.
    ///
    /// Every component is self-delimiting, so no two distinct salts share an
    /// encoding and the components cannot run together across a boundary.
    fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.referenced_identity.append_encoded(&mut out);
        append_length_prefixed(&mut out, &self.receiver_certificate_hash);
        self.receiver_identity.append_encoded(&mut out);
        out
    }
}

fn append_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Derives the privacy-preserving form of `certificate_hash_hex` for one
/// recipient.
///
/// `secret` is the HMAC key; `salt` and the source hash are concatenated into
/// the signed message, so the secret stays key material and the salt stays
/// data.
pub fn remapped_certificate_hash_hex(
    secret: &str,
    certificate_hash_hex: &str,
    salt: &CertificateHashSalt,
) -> Option<String> {
    let certificate_hash = hex::decode(certificate_hash_hex).ok()?;
    if certificate_hash.len() != CERTIFICATE_HASH_BYTES {
        return None;
    }

    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret.as_bytes());
    let salt_bytes = salt.encoded();
    let mut input = Vec::with_capacity(
        CERTIFICATE_HASH_REMAP_CONTEXT.len() + salt_bytes.len() + certificate_hash.len(),
    );
    input.extend_from_slice(CERTIFICATE_HASH_REMAP_CONTEXT);
    input.extend_from_slice(&salt_bytes);
    input.extend_from_slice(&certificate_hash);
    let tag = aws_lc_rs::hmac::sign(&key, &input);
    Some(hex::encode(&tag.as_ref()[..CERTIFICATE_HASH_BYTES]))
}

/// Projects `certificate_hash_hex` under `protection`.
///
/// `Disabled` passes the source hash through untouched. `Irreversible` derives
/// a distinct value per recipient from `salt`. `Reversible` deliberately
/// ignores `salt`: it stays a pure secret-keyed permutation of the source hash
/// of the same length, so the original remains recoverable from the secret
/// alone regardless of who is looking.
pub fn protected_certificate_hash_hex(
    protection: shitspeak_runtime_config::CertificateHashProtection,
    secret: &str,
    certificate_hash_hex: &str,
    salt: &CertificateHashSalt,
) -> Option<String> {
    match protection {
        shitspeak_runtime_config::CertificateHashProtection::Disabled => {
            Some(certificate_hash_hex.to_owned())
        }
        shitspeak_runtime_config::CertificateHashProtection::Irreversible => {
            remapped_certificate_hash_hex(secret, certificate_hash_hex, salt)
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

/// Derives the Feistel round key from the secret alone. The reversible
/// permutation must stay decryptable with the secret only, so no salt takes
/// part in the key schedule.
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
    protect_superusers: bool,
    salt: &CertificateHashSalt,
) {
    if !should_protect_user_state_certificate_hash(
        state,
        viewer_is_superuser,
        viewer_session,
        protection,
        protect_superusers,
    ) {
        return;
    }

    let Some(secret) = secret.filter(|secret| !secret.is_empty()) else {
        return;
    };
    let Some(hash) = state.hash.as_deref() else {
        return;
    };
    if let Some(remapped) = protected_certificate_hash_hex(protection, secret, hash, salt) {
        state.hash = Some(remapped);
    }
}

pub(crate) fn should_protect_user_state_certificate_hash(
    state: &UserState,
    viewer_is_superuser: bool,
    viewer_session: crate::client::client_session_identifier::ClientSessionIdentifier,
    protection: shitspeak_runtime_config::CertificateHashProtection,
    protect_superusers: bool,
) -> bool {
    protection.is_enabled()
        && (!viewer_is_superuser || protect_superusers)
        && state.session != Some(viewer_session)
        && state.hash.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::client_session_identifier::ClientSessionIdentifier;
    use shitspeak_runtime_config::CertificateHashProtection;

    const SOURCE: &str = "00112233445566778899aabbccddeeff00112233";

    fn identity(fqdn: Option<&str>, user_id: Option<u32>) -> PrivacyIdentity {
        PrivacyIdentity::new(fqdn, user_id)
    }

    fn salt(
        referenced: PrivacyIdentity,
        receiver_certificate_hash: &[u8],
        receiver: PrivacyIdentity,
    ) -> CertificateHashSalt {
        CertificateHashSalt::new(referenced, receiver_certificate_hash, receiver)
    }

    fn alice_view_of_user_two() -> CertificateHashSalt {
        salt(identity(None, Some(2)), &[0xaa; 20], identity(None, Some(1)))
    }

    fn carol_view_of_user_two() -> CertificateHashSalt {
        salt(identity(None, Some(2)), &[0xcc; 20], identity(None, Some(3)))
    }

    #[test]
    fn remap_is_stable_and_not_the_source_hash() {
        let salt = alice_view_of_user_two();

        let first = remapped_certificate_hash_hex("cluster-secret", SOURCE, &salt).unwrap();
        let second = remapped_certificate_hash_hex("cluster-secret", SOURCE, &salt).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), SOURCE.len());
        assert_ne!(first, SOURCE);
    }

    /// The headline property: the same person yields a different hash for
    /// every receiving side.
    #[test]
    fn remap_differs_for_every_receiving_side() {
        let for_alice =
            remapped_certificate_hash_hex("cluster-secret", SOURCE, &alice_view_of_user_two())
                .unwrap();
        let for_carol =
            remapped_certificate_hash_hex("cluster-secret", SOURCE, &carol_view_of_user_two())
                .unwrap();

        assert_ne!(for_alice, for_carol);
    }

    #[test]
    fn remap_differs_with_referenced_identity() {
        let receiver_certificate_hash = [0xab; 20];
        let receiver = identity(None, Some(1));
        let for_user_two = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(
                identity(None, Some(2)),
                &receiver_certificate_hash,
                receiver.clone(),
            ),
        )
        .unwrap();
        let for_user_three = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(
                identity(None, Some(3)),
                &receiver_certificate_hash,
                receiver.clone(),
            ),
        )
        .unwrap();
        let for_fqdn = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(
                identity(Some("target.example"), Some(2)),
                &receiver_certificate_hash,
                receiver,
            ),
        )
        .unwrap();

        assert_ne!(for_user_two, for_user_three);
        assert_ne!(for_user_two, for_fqdn);
        assert_ne!(for_user_three, for_fqdn);
    }

    #[test]
    fn remap_differs_with_receiver_identity() {
        let receiver_certificate_hash = [0xab; 20];
        let referenced = identity(None, Some(2));
        let for_user_one = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(
                referenced.clone(),
                &receiver_certificate_hash,
                identity(None, Some(1)),
            ),
        )
        .unwrap();
        let for_user_three = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(
                referenced.clone(),
                &receiver_certificate_hash,
                identity(None, Some(3)),
            ),
        )
        .unwrap();
        let for_fqdn = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(
                referenced,
                &receiver_certificate_hash,
                identity(Some("viewer.example"), Some(1)),
            ),
        )
        .unwrap();

        assert_ne!(for_user_one, for_user_three);
        assert_ne!(for_user_one, for_fqdn);
        assert_ne!(for_user_three, for_fqdn);
    }

    #[test]
    fn remap_differs_with_receiver_certificate_hash() {
        let referenced = identity(None, Some(2));
        let receiver = identity(None, Some(1));
        let for_one_cert = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(referenced.clone(), &[0xaa; 20], receiver.clone()),
        )
        .unwrap();
        let for_other_cert = remapped_certificate_hash_hex(
            "cluster-secret",
            SOURCE,
            &salt(referenced, &[0xbb; 20], receiver),
        )
        .unwrap();

        assert_ne!(for_one_cert, for_other_cert);
    }

    /// An FQDN that looks like a user id, a real user id, and no identity at
    /// all must never produce the same identity.
    #[test]
    fn identity_forms_do_not_collide() {
        let variants = [
            identity(Some("7"), None),
            identity(None, Some(7)),
            identity(None, None),
            identity(Some("a"), None),
            identity(Some("a\0b"), None),
        ];
        for (i, left) in variants.iter().enumerate() {
            for right in &variants[i + 1..] {
                assert_ne!(
                    left, right,
                    "identity forms {left:?} and {right:?} must not collide"
                );
            }
        }

        // An empty FQDN is treated as missing, so it falls through to the user
        // id or to the empty identity.
        assert_eq!(identity(Some(""), None), identity(None, None));
        assert_eq!(identity(Some(""), Some(7)), identity(None, Some(7)));
    }

    /// Salt encodings must be injective: distinct salts must not share an
    /// encoding, including across component boundaries.
    #[test]
    fn salt_encoding_is_unambiguous() {
        let cases = [
            salt(identity(Some("ab"), None), &[1, 2], identity(None, Some(3))),
            salt(identity(Some("a"), None), &[1], identity(Some("b"), Some(3))),
            salt(
                identity(None, Some(0x0000_0102)),
                &[3],
                identity(None, None),
            ),
            salt(identity(None, None), &[], identity(None, None)),
        ];
        for (i, left) in cases.iter().enumerate() {
            for right in &cases[i + 1..] {
                assert_ne!(
                    left.encoded(),
                    right.encoded(),
                    "salts {left:?} and {right:?} must not share an encoding"
                );
            }
        }
    }

    #[test]
    fn reversible_remap_is_stable_and_reversible_with_secret() {
        let first = protected_certificate_hash_hex(
            CertificateHashProtection::Reversible,
            "cluster-secret",
            SOURCE,
            &alice_view_of_user_two(),
        )
        .unwrap();
        let second = protected_certificate_hash_hex(
            CertificateHashProtection::Reversible,
            "cluster-secret",
            SOURCE,
            &alice_view_of_user_two(),
        )
        .unwrap();
        let restored =
            apply_reversible_certificate_hash_permutation("cluster-secret", &first, true).unwrap();
        let wrong_secret =
            apply_reversible_certificate_hash_permutation("other-secret", &first, true).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), SOURCE.len());
        assert_ne!(first, SOURCE);
        assert_eq!(restored, SOURCE);
        assert_ne!(wrong_secret, SOURCE);
    }

    /// The reversible projection must ignore the salt entirely so that it
    /// stays decryptable to the same source hash with the secret alone.
    #[test]
    fn reversible_remap_ignores_the_salt() {
        let for_alice = protected_certificate_hash_hex(
            CertificateHashProtection::Reversible,
            "cluster-secret",
            SOURCE,
            &alice_view_of_user_two(),
        )
        .unwrap();
        let for_carol = protected_certificate_hash_hex(
            CertificateHashProtection::Reversible,
            "cluster-secret",
            SOURCE,
            &carol_view_of_user_two(),
        )
        .unwrap();

        assert_eq!(for_alice, for_carol);
        assert_eq!(
            apply_reversible_certificate_hash_permutation("cluster-secret", &for_carol, true)
                .unwrap(),
            SOURCE
        );
    }

    #[test]
    fn user_state_self_hash_is_not_remapped() {
        let viewer = ClientSessionIdentifier::from(7u32);
        let mut state = UserState {
            session: Some(viewer),
            hash: Some(SOURCE.to_owned()),
            ..UserState::default()
        };

        protect_user_state_certificate_hash(
            &mut state,
            false,
            viewer,
            CertificateHashProtection::Irreversible,
            Some("cluster-secret"),
            false,
            &alice_view_of_user_two(),
        );

        assert_eq!(state.hash.as_deref(), Some(SOURCE));
    }

    /// `protect_certificate_hashes_for_superusers` must be honoured: a
    /// superuser viewer is protected once the flag is set.
    #[test]
    fn user_state_superuser_hash_is_protected_only_when_configured() {
        let viewer = ClientSessionIdentifier::from(7u32);

        let mut permissive = UserState {
            session: Some(ClientSessionIdentifier::from(8u32)),
            hash: Some(SOURCE.to_owned()),
            ..UserState::default()
        };
        protect_user_state_certificate_hash(
            &mut permissive,
            true,
            viewer,
            CertificateHashProtection::Irreversible,
            Some("cluster-secret"),
            false,
            &alice_view_of_user_two(),
        );
        assert_eq!(permissive.hash.as_deref(), Some(SOURCE));

        let mut strict = UserState {
            session: Some(ClientSessionIdentifier::from(8u32)),
            hash: Some(SOURCE.to_owned()),
            ..UserState::default()
        };
        protect_user_state_certificate_hash(
            &mut strict,
            true,
            viewer,
            CertificateHashProtection::Irreversible,
            Some("cluster-secret"),
            true,
            &alice_view_of_user_two(),
        );
        assert_ne!(strict.hash.as_deref(), Some(SOURCE));
    }
}