//! Localization of server-generated text.
//!
//! Messages live in `translations/server/<language>.json`, one monolingual
//! JSON file per language, maintained through Weblate. The files are compiled
//! into the binary; [`Localizer`] serves them and can additionally apply live
//! translations downloaded from Weblate while the server runs (see
//! [`sync`]). Channel names are translated separately, by
//! [`channel_names`].

mod catalog;
pub mod channel_names;
pub(crate) mod sync;
pub(crate) mod weblate;
#[cfg(test)]
pub(crate) mod weblate_mock;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use shitspeak_messages::messages::encoder::{DenyType, RejectType};

pub use shitspeak_core::Language;

pub(crate) use catalog::{Catalog, RejectedEntry};
use catalog::{CatalogSet, format_message, validate_translation};

include!(concat!(env!("OUT_DIR"), "/localization_catalog.rs"));

macro_rules! text_keys {
    ($($variant:ident),* $(,)?) => {
        /// Server-generated messages that are not tied to a protocol enum.
        /// Each variant is the key `text.<Variant>` in the catalogs.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum TextKey {
            $($variant),*
        }

        impl TextKey {
            pub const ALL: &'static [TextKey] = &[$(TextKey::$variant),*];

            pub fn key(self) -> &'static str {
                match self {
                    $(TextKey::$variant => concat!("text.", stringify!($variant))),*
                }
            }
        }
    };
}

text_keys! {
    MissingRequiredGroup,
    NoRootTraverse,
    CryptSetupFailed,
    WriteAclRequired,
    CannotDeleteRootChannel,
    ChannelNameRequired,
    CannotRenameRootChannel,
    ChannelDoesNotExist,
    ChannelNameTooLong,
    ChannelDescriptionTooLong,
    ChannelNameConflict,
    TemporaryChannelCannotHaveChildren,
    TemporaryChannelRateLimited,
    ChannelCreateFailed,
    AclGroupUpdatesUnsupported,
    CommentStoreFailed,
    TextureStoreFailed,
    ChannelOperationTimedOut,
    ChannelOperationFailed,
    BanListUpdateSubmitted,
    BanListUpdateAdmitted,
    BanListUpdateRejected,
    ChannelSettingsUpdateSubmitted,
    ChannelSettingsUpdateCommitted,
    ChannelSettingsUpdateUnableToCommit,
    LoginQueuePosition,
    HideMe,
    ShowMe,
    PasswordAuthenticationDisabled,
}

/// Catalog key of the default `Reject` reason for `reject_type`.
pub fn reject_key(reject_type: RejectType) -> &'static str {
    match reject_type {
        RejectType::None => "reject.None",
        RejectType::WrongVersion => "reject.WrongVersion",
        RejectType::InvalidUsername => "reject.InvalidUsername",
        RejectType::WrongUserPw => "reject.WrongUserPw",
        RejectType::WrongServerPw => "reject.WrongServerPw",
        RejectType::UsernameInUse => "reject.UsernameInUse",
        RejectType::ServerFull => "reject.ServerFull",
        RejectType::NoCertificate => "reject.NoCertificate",
        RejectType::AuthenticatorFail => "reject.AuthenticatorFail",
        RejectType::NoNewConnections => "reject.NoNewConnections",
    }
}

/// Catalog key of the default `PermissionDenied` reason for `deny_type`.
pub fn deny_key(deny_type: DenyType) -> &'static str {
    match deny_type {
        DenyType::Text => "deny.Text",
        DenyType::Permission => "deny.Permission",
        DenyType::SuperUser => "deny.SuperUser",
        DenyType::ChannelName => "deny.ChannelName",
        DenyType::TextTooLong => "deny.TextTooLong",
        DenyType::H9k => "deny.H9k",
        DenyType::TemporaryChannel => "deny.TemporaryChannel",
        DenyType::MissingCertificate => "deny.MissingCertificate",
        DenyType::UserName => "deny.UserName",
        DenyType::ChannelFull => "deny.ChannelFull",
        DenyType::NestingLimit => "deny.NestingLimit",
        DenyType::ChannelCountLimit => "deny.ChannelCountLimit",
        DenyType::ChannelListenerLimit => "deny.ChannelListenerLimit",
        DenyType::UserListenerLimit => "deny.UserListenerLimit",
    }
}

#[cfg(test)]
const ALL_REJECT_TYPES: &[RejectType] = &[
    RejectType::None,
    RejectType::WrongVersion,
    RejectType::InvalidUsername,
    RejectType::WrongUserPw,
    RejectType::WrongServerPw,
    RejectType::UsernameInUse,
    RejectType::ServerFull,
    RejectType::NoCertificate,
    RejectType::AuthenticatorFail,
    RejectType::NoNewConnections,
];

#[cfg(test)]
const ALL_DENY_TYPES: &[DenyType] = &[
    DenyType::Text,
    DenyType::Permission,
    DenyType::SuperUser,
    DenyType::ChannelName,
    DenyType::TextTooLong,
    DenyType::H9k,
    DenyType::TemporaryChannel,
    DenyType::MissingCertificate,
    DenyType::UserName,
    DenyType::ChannelFull,
    DenyType::NestingLimit,
    DenyType::ChannelCountLimit,
    DenyType::ChannelListenerLimit,
    DenyType::UserListenerLimit,
];

/// Every key the server looks up. The source catalog must define all of them.
#[cfg(test)]
pub(crate) fn all_keys() -> impl Iterator<Item = &'static str> {
    TextKey::ALL
        .iter()
        .map(|key| key.key())
        .chain(ALL_REJECT_TYPES.iter().map(|reject| reject_key(*reject)))
        .chain(ALL_DENY_TYPES.iter().map(|deny| deny_key(*deny)))
}

/// The bundled catalogs, parsed and validated once per process.
struct Bundled {
    catalogs: CatalogSet,
    rejected: Vec<RejectedEntry>,
}

fn bundled() -> &'static Bundled {
    static BUNDLED: OnceLock<Bundled> = OnceLock::new();
    BUNDLED.get_or_init(|| {
        let mut source = None;
        let mut translations = Vec::new();
        for (code, json) in BUNDLED_CATALOGS {
            let catalog = Catalog::from_json(json)
                .unwrap_or_else(|error| panic!("bundled catalog {code}.json: {error}"));
            let language = Language::parse(code)
                .unwrap_or_else(|| panic!("bundled catalog {code}.json: invalid language code"));
            if language == Language::ENGLISH {
                source = Some(catalog);
            } else {
                translations.push((language, catalog));
            }
        }
        // The build script guarantees `en.json` exists; key coverage is
        // enforced by the tests below.
        let source = source.expect("bundled source catalog en.json");
        let mut rejected = Vec::new();
        let translations = translations
            .into_iter()
            .map(|(language, catalog)| {
                let (accepted, mut dropped) = validate_translation(&source, &language, catalog);
                rejected.append(&mut dropped);
                (language, accepted)
            })
            .collect();
        Bundled {
            catalogs: CatalogSet::new(Language::ENGLISH, source, translations),
            rejected,
        }
    })
}

/// English source text for `key`, independent of any live updates. Used for
/// logs and `Display` implementations, which are not shown to users.
pub(crate) fn source_text(key: &str) -> &'static str {
    bundled().catalogs.source().get(key).unwrap_or("")
}

/// Serves localized server text: the bundled catalogs, optionally overlaid
/// with live translations from Weblate.
pub struct Localizer {
    current: ArcSwap<CatalogSet>,
}

impl Default for Localizer {
    fn default() -> Self {
        Self::bundled()
    }
}

impl Localizer {
    /// A localizer serving only the catalogs compiled into the binary.
    pub fn bundled() -> Self {
        let bundled = bundled();
        for rejected in &bundled.rejected {
            tracing::warn!(entry = %rejected, "ignoring invalid bundled translation");
        }
        Self {
            current: ArcSwap::from_pointee(bundled.catalogs.clone()),
        }
    }

    /// Languages that currently have a catalog, source language first.
    pub fn languages(&self) -> Vec<Language> {
        self.current.load().languages().to_vec()
    }

    fn lookup(&self, language: &Language, key: &str) -> String {
        self.current
            .load()
            .lookup(language, key)
            .unwrap_or(key)
            .to_owned()
    }

    pub fn text(&self, language: &Language, key: TextKey) -> Cow<'static, str> {
        Cow::Owned(self.lookup(language, key.key()))
    }

    /// Text with `{name}` placeholders substituted from `arguments`.
    pub fn format(
        &self,
        language: &Language,
        key: TextKey,
        arguments: &[(&str, &str)],
    ) -> Cow<'static, str> {
        Cow::Owned(format_message(&self.lookup(language, key.key()), arguments))
    }

    pub fn channel_does_not_exist(&self, language: &Language, channel_id: u32) -> Cow<'static, str> {
        self.format(
            language,
            TextKey::ChannelDoesNotExist,
            &[("channel_id", &channel_id.to_string())],
        )
    }

    pub fn reject_reason(&self, language: &Language, reject_type: RejectType) -> Cow<'static, str> {
        Cow::Owned(self.lookup(language, reject_key(reject_type)))
    }

    pub fn permission_denied_reason(
        &self,
        language: &Language,
        deny_type: DenyType,
    ) -> Cow<'static, str> {
        Cow::Owned(self.lookup(language, deny_key(deny_type)))
    }

    /// Replace the live layer with `live` translations. Entries are validated
    /// against the bundled source catalog; rejected entries are returned and
    /// the rest of their language still applies. Keys that `live` does not
    /// provide keep their bundled text.
    pub(crate) fn apply_live(&self, live: HashMap<Language, Catalog>) -> Vec<RejectedEntry> {
        let bundled = &bundled().catalogs;
        let mut rejected = Vec::new();
        let validated: HashMap<Language, Catalog> = live
            .into_iter()
            .map(|(language, catalog)| {
                let (accepted, mut dropped) =
                    validate_translation(bundled.source(), &language, catalog);
                rejected.append(&mut dropped);
                (language, accepted)
            })
            .collect();
        self.current
            .store(Arc::new(bundled.overlaid_with(&validated)));
        rejected
    }
}

fn shared_bundled_localizer() -> Arc<Localizer> {
    static SHARED: OnceLock<Arc<Localizer>> = OnceLock::new();
    SHARED
        .get_or_init(|| Arc::new(Localizer::bundled()))
        .clone()
}

/// A client's language together with the translations it is served from.
///
/// Clients start with English and the bundled catalogs; the server replaces
/// the locale when it resolves the client's language, binding the client to
/// the server's live catalogs.
#[derive(Clone)]
pub struct ClientLocale {
    language: Language,
    localizer: Arc<Localizer>,
    channel_names: Arc<channel_names::ChannelNameTranslations>,
}

impl Default for ClientLocale {
    fn default() -> Self {
        Self {
            language: Language::default(),
            localizer: shared_bundled_localizer(),
            channel_names: Arc::new(channel_names::ChannelNameTranslations::new()),
        }
    }
}

impl std::fmt::Debug for ClientLocale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientLocale")
            .field("language", &self.language)
            .finish_non_exhaustive()
    }
}

impl ClientLocale {
    pub fn new(
        language: Language,
        localizer: Arc<Localizer>,
        channel_names: Arc<channel_names::ChannelNameTranslations>,
    ) -> Self {
        Self {
            language,
            localizer,
            channel_names,
        }
    }

    pub fn with_language(&self, language: Language) -> Self {
        Self {
            language,
            ..self.clone()
        }
    }

    pub fn language(&self) -> &Language {
        &self.language
    }

    pub fn localizer(&self) -> &Localizer {
        &self.localizer
    }

    pub fn channel_names(&self) -> &channel_names::ChannelNameTranslations {
        &self.channel_names
    }

    pub fn text(&self, key: TextKey) -> Cow<'static, str> {
        self.localizer.text(&self.language, key)
    }

    pub fn format(&self, key: TextKey, arguments: &[(&str, &str)]) -> Cow<'static, str> {
        self.localizer.format(&self.language, key, arguments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn language(tag: &str) -> Language {
        Language::parse(tag).unwrap()
    }

    #[test]
    fn source_catalog_defines_every_key_the_server_uses() {
        let source = bundled().catalogs.source();
        let missing: Vec<&str> = all_keys().filter(|key| source.get(key).is_none()).collect();
        assert!(missing.is_empty(), "en.json is missing keys: {missing:?}");
    }

    #[test]
    fn source_catalog_has_no_unused_keys() {
        let used: std::collections::HashSet<&str> = all_keys().collect();
        let unused: Vec<&str> = bundled()
            .catalogs
            .source()
            .entries()
            .map(|(key, _)| key)
            .filter(|key| !used.contains(key))
            .collect();
        assert!(unused.is_empty(), "en.json has unused keys: {unused:?}");
    }

    #[test]
    fn every_bundled_translation_is_valid() {
        assert!(
            bundled().rejected.is_empty(),
            "invalid bundled translations: {:?}",
            bundled()
                .rejected
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn bundled_languages_include_the_historical_catalogs() {
        let languages: Vec<String> = Localizer::bundled()
            .languages()
            .iter()
            .map(Language::tag)
            .collect();
        for expected in ["en", "es", "fr", "de", "zh-Hans"] {
            assert!(
                languages.iter().any(|language| language == expected),
                "missing {expected} in {languages:?}"
            );
        }
        assert_eq!(languages[0], "en", "source language comes first");
    }

    #[test]
    fn lookups_negotiate_regional_tags_onto_bundled_catalogs() {
        let localizer = Localizer::bundled();
        assert_eq!(
            localizer.reject_reason(&language("es-MX"), RejectType::WrongUserPw),
            "Usuario o contraseña incorrectos"
        );
        assert_eq!(
            localizer.channel_does_not_exist(&language("zh-CN"), 7),
            source_text_in(&localizer, "zh-Hans", TextKey::ChannelDoesNotExist)
                .replace("{channel_id}", "7")
        );
        assert_eq!(
            localizer.reject_reason(&language("kl"), RejectType::WrongUserPw),
            "Incorrect username or password"
        );
    }

    fn source_text_in(localizer: &Localizer, tag: &str, key: TextKey) -> String {
        localizer.text(&language(tag), key).into_owned()
    }

    #[test]
    fn live_translations_override_and_extend_bundled_catalogs() {
        let localizer = Localizer::bundled();
        let mut live = HashMap::new();
        live.insert(
            language("es"),
            Catalog::from_entries(HashMap::from([(
                "reject.WrongUserPw".to_owned(),
                "Credenciales incorrectas".to_owned(),
            )])),
        );
        live.insert(
            language("ja"),
            Catalog::from_entries(HashMap::from([
                ("reject.ServerFull".to_owned(), "サーバーは満員です".to_owned()),
                (
                    "text.ChannelDoesNotExist".to_owned(),
                    "チャンネル {id} は存在しません".to_owned(),
                ),
            ])),
        );

        let rejected = localizer.apply_live(live);

        assert_eq!(
            rejected,
            vec![RejectedEntry::PlaceholderMismatch {
                language: "ja".to_owned(),
                key: "text.ChannelDoesNotExist".to_owned(),
            }]
        );
        assert_eq!(
            localizer.reject_reason(&language("es"), RejectType::WrongUserPw),
            "Credenciales incorrectas"
        );
        assert_eq!(
            localizer.reject_reason(&language("es"), RejectType::ServerFull),
            Localizer::bundled().reject_reason(&language("es"), RejectType::ServerFull),
            "keys the live layer does not provide keep their bundled text"
        );
        assert_eq!(
            localizer.reject_reason(&language("ja-JP"), RejectType::ServerFull),
            "サーバーは満員です"
        );
        assert_eq!(
            localizer.channel_does_not_exist(&language("ja"), 3),
            "Channel 3 does not exist",
            "a rejected entry falls back to the source text"
        );

        localizer.apply_live(HashMap::new());
        assert_eq!(
            localizer.reject_reason(&language("es"), RejectType::WrongUserPw),
            "Usuario o contraseña incorrectos",
            "an empty live layer restores the bundled catalogs"
        );
    }
}
