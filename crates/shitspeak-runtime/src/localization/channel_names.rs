//! Channel-name translation.
//!
//! Channel names are user content in no particular language, so the raw name
//! itself is the translation key. The server keeps a Weblate component in sync
//! with the channel tree (pushing names it has not seen as new source
//! strings), downloads the translations, and rewrites the `name` of every
//! outgoing `ChannelState` for the client's language. A name without a
//! translation is shown as entered.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use shitspeak_core::Language;
use shitspeak_messages::messages::Message;
use shitspeak_runtime_config::{ChannelNameTranslationConfig, WeblateComponentConfig};

use super::sync::{
    TranslationCache, WeblateSyncJob, origin_of, poll_until_shutdown, refresh_translations,
};
use super::weblate::WeblateClient;
use crate::server::Server;

/// Names pushed to Weblate per poll. Bounds the burst after a large import;
/// the remainder is pushed on the following polls.
const MAX_NAMES_PUSHED_PER_POLL: usize = 200;

/// Translations of raw channel names for one language: raw → translated.
pub type ChannelNameMap = HashMap<String, String>;

#[derive(Debug, Default, Clone)]
struct ChannelNameCatalog {
    languages: Vec<Language>,
    names: HashMap<Language, Arc<ChannelNameMap>>,
}

impl ChannelNameCatalog {
    fn new(names: HashMap<Language, ChannelNameMap>) -> Self {
        let mut languages: Vec<Language> = names.keys().cloned().collect();
        languages.sort_by_key(Language::tag);
        Self {
            languages,
            names: names
                .into_iter()
                .map(|(language, map)| (language, Arc::new(map)))
                .collect(),
        }
    }

    fn for_language(&self, language: &Language) -> Option<Arc<ChannelNameMap>> {
        let matched = language.negotiate(&self.languages)?;
        self.names.get(matched).cloned()
    }
}

/// What changed between two channel-name catalogs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ChannelNameDiff {
    /// Raw names whose translation changed in at least one language.
    names: HashSet<String>,
    /// Languages with at least one changed translation.
    languages: HashSet<Language>,
    /// A language was added or removed, which can change the negotiation
    /// result of any client.
    language_set_changed: bool,
}

impl ChannelNameDiff {
    pub(crate) fn is_empty(&self) -> bool {
        self.names.is_empty() && !self.language_set_changed
    }

}

fn diff(old: &ChannelNameCatalog, new: &ChannelNameCatalog) -> ChannelNameDiff {
    let mut changed = ChannelNameDiff {
        language_set_changed: old.languages != new.languages,
        ..Default::default()
    };
    let empty = ChannelNameMap::new();
    let languages: HashSet<&Language> = old.names.keys().chain(new.names.keys()).collect();
    for language in languages {
        let before = old.names.get(language).map_or(&empty, |map| map.as_ref());
        let after = new.names.get(language).map_or(&empty, |map| map.as_ref());
        let mut language_changed = false;
        for raw in before.keys().chain(after.keys()) {
            if before.get(raw) != after.get(raw) {
                changed.names.insert(raw.clone());
                language_changed = true;
            }
        }
        if language_changed {
            changed.languages.insert(language.clone());
        }
    }
    changed
}

/// Live channel-name translations shared by every connection of a server.
#[derive(Debug, Default)]
pub struct ChannelNameTranslations {
    current: ArcSwap<ChannelNameCatalog>,
}

impl ChannelNameTranslations {
    pub fn new() -> Self {
        Self::default()
    }

    /// Translations for the catalog language that best matches `language`.
    pub fn for_language(&self, language: &Language) -> Option<Arc<ChannelNameMap>> {
        self.current.load().for_language(language)
    }

    /// `raw` translated for `language`, or `None` when there is no
    /// translation.
    pub fn translate(&self, language: &Language, raw: &str) -> Option<String> {
        self.for_language(language)?.get(raw).cloned()
    }

    /// Replace every translation and report what changed.
    pub(crate) fn replace(&self, names: HashMap<Language, ChannelNameMap>) -> ChannelNameDiff {
        let new = ChannelNameCatalog::new(names);
        let old = self.current.swap(Arc::new(new));
        diff(&old, &self.current.load())
    }

    /// Whether a client with `language` may see different names after
    /// `diff` was applied.
    pub(crate) fn affects(&self, diff: &ChannelNameDiff, language: &Language) -> bool {
        if diff.language_set_changed {
            return true;
        }
        let current = self.current.load();
        language
            .negotiate(&current.languages)
            .is_some_and(|matched| diff.languages.contains(matched))
    }
}

/// Rewrite channel names in `messages` for a client. Returns `None` when no
/// message needed a change, so callers can send the originals without
/// copying.
pub fn localize_channel_names(
    names: &ChannelNameMap,
    messages: &[Message],
) -> Option<Vec<Message>> {
    let needs_rewrite = |message: &Message| {
        matches!(
            message,
            Message::ChannelState(state)
                if state.name.as_ref().is_some_and(|name| names.contains_key(name))
        )
    };
    if !messages.iter().any(needs_rewrite) {
        return None;
    }
    Some(
        messages
            .iter()
            .map(|message| {
                let mut message = message.clone();
                localize_channel_name(names, &mut message);
                message
            })
            .collect(),
    )
}

/// Rewrite the channel name of a single message in place.
pub fn localize_channel_name(names: &ChannelNameMap, message: &mut Message) {
    if let Message::ChannelState(state) = message
        && let Some(name) = state.name.as_mut()
        && let Some(translated) = names.get(name.as_str())
    {
        name.clone_from(translated);
    }
}

/// Why connections must re-send channel names, delivered to every client
/// projection in order with channel operations.
#[derive(Debug)]
pub(crate) enum ChannelNameRefresh {
    /// Translations changed; clients whose language is affected re-send the
    /// listed channels.
    Translations(ChannelNamesChanged),
    /// One client's language changed (e.g. on reauthentication); it re-sends
    /// every channel it can see.
    ClientLanguage(crate::client::ClientInstanceId),
}

/// A channel-name translation change, with the channels it affects on this
/// node.
#[derive(Debug)]
pub(crate) struct ChannelNamesChanged {
    diff: ChannelNameDiff,
    /// `server_id` → `(channel_id, raw name)` of channels whose name has a
    /// changed translation.
    channels: HashMap<String, Vec<(u32, String)>>,
}

impl ChannelNamesChanged {
    pub(crate) fn diff(&self) -> &ChannelNameDiff {
        &self.diff
    }

    pub(crate) fn channels_in_server(&self, server_id: &str) -> &[(u32, String)] {
        self.channels
            .get(server_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

/// Parse `(weblate language code → entries)` into channel-name maps, dropping
/// the source language and codes that are not language tags.
fn channel_name_maps(cache: &TranslationCache) -> HashMap<Language, ChannelNameMap> {
    let mut maps = HashMap::new();
    for (code, language) in cache.languages() {
        if language.is_source() {
            continue;
        }
        let Some(tag) = Language::parse(code) else {
            tracing::warn!(code, "ignoring Weblate channel-name language with an invalid code");
            continue;
        };
        let map: ChannelNameMap = language
            .entries()
            .filter(|(raw, translated)| !translated.trim().is_empty() && raw != translated)
            .map(|(raw, translated)| (raw.to_owned(), translated.to_owned()))
            .collect();
        maps.insert(tag, map);
    }
    maps
}

/// Apply `cache` to the server's translations and notify connections about
/// channels whose displayed name may have changed.
pub(crate) async fn apply_channel_name_cache(server: &Server, cache: &TranslationCache) {
    let diff = server
        .channel_name_translations()
        .replace(channel_name_maps(cache));
    if diff.is_empty() {
        return;
    }
    let mut channels: HashMap<String, Vec<(u32, String)>> = HashMap::new();
    for (server_id, channel) in server.get_channels().get_all_scoped().await {
        if diff.names.contains(&channel.name) || diff.language_set_changed {
            channels
                .entry(server_id)
                .or_default()
                .push((channel.id, channel.name.clone()));
        }
    }
    tracing::info!(
        names = diff.names.len(),
        languages = diff.languages.len(),
        channels = channels.values().map(Vec::len).sum::<usize>(),
        "channel-name translations changed"
    );
    server.publish_channel_name_refresh(ChannelNameRefresh::Translations(ChannelNamesChanged {
        diff,
        channels,
    }));
}

/// Every distinct raw channel name on this node, root names included.
async fn raw_channel_names(server: &Server) -> HashSet<String> {
    server
        .get_channels()
        .get_all_scoped()
        .await
        .into_iter()
        .map(|(_, channel)| channel.name.clone())
        .filter(|name| !name.trim().is_empty())
        .collect()
}

/// Add channel names that Weblate does not know yet as source strings.
async fn push_new_names(
    server: &Server,
    client: &WeblateClient,
    cache: &mut TranslationCache,
) -> Result<(), super::weblate::WeblateError> {
    let Some(source_code) = cache.source_code().map(str::to_owned) else {
        tracing::warn!(
            "channel-name Weblate component reports no source language; not pushing names"
        );
        return Ok(());
    };
    let mut missing: Vec<String> = raw_channel_names(server)
        .await
        .into_iter()
        .filter(|name| !cache.has_source_key(name))
        .collect();
    missing.sort();
    let total = missing.len();
    for name in missing.into_iter().take(MAX_NAMES_PUSHED_PER_POLL) {
        client.add_source_string(&source_code, &name, &name).await?;
        cache.insert_source_key(&name);
    }
    if total > 0 {
        tracing::info!(
            pushed = total.min(MAX_NAMES_PUSHED_PER_POLL),
            remaining = total.saturating_sub(MAX_NAMES_PUSHED_PER_POLL),
            "pushed new channel names to Weblate"
        );
    }
    Ok(())
}

fn active_config(server: &Server) -> Option<ChannelNameTranslationConfig> {
    server
        .read_config()
        .channel_name_translation
        .clone()
        .filter(ChannelNameTranslationConfig::enabled)
}

fn load_cache_for(config: &ChannelNameTranslationConfig) -> Option<TranslationCache> {
    let cache = TranslationCache::load(config.cache_path()?)?;
    (cache.origin() == origin_of(config.weblate())).then_some(cache)
}

/// Apply the on-disk cache so translations are available before the first
/// successful poll.
pub(crate) async fn load_channel_name_cache(server: &Server) {
    if let Some(cache) = active_config(server).as_ref().and_then(load_cache_for) {
        apply_channel_name_cache(server, &cache).await;
    }
}

struct ChannelNameSync;

#[async_trait]
impl WeblateSyncJob for ChannelNameSync {
    fn target(&self, server: &Server) -> Option<(WeblateComponentConfig, Duration)> {
        active_config(server).map(|config| (config.weblate().clone(), config.poll_interval()))
    }

    fn initial_cache(&self, server: &Server) -> Option<TranslationCache> {
        active_config(server).as_ref().and_then(load_cache_for)
    }

    async fn poll(
        &mut self,
        server: &Arc<Box<Server>>,
        client: &WeblateClient,
        cache: &mut TranslationCache,
    ) {
        let Some(config) = active_config(server) else {
            return;
        };
        let changed = match refresh_translations(client, cache).await {
            Ok(changed) => changed,
            Err(error) => {
                tracing::warn!(%error, "channel-name translation refresh failed");
                return;
            }
        };
        let before_push = cache.clone();
        if config.push_names()
            && let Err(error) = push_new_names(server, client, cache).await
        {
            tracing::warn!(%error, "pushing channel names to Weblate failed");
        }
        if changed {
            apply_channel_name_cache(server, cache).await;
        }
        if (changed || *cache != before_push)
            && let Some(path) = config.cache_path()
            && let Err(error) = cache.save(path)
        {
            tracing::warn!(
                path = %path.display(),
                %error,
                "saving channel-name translation cache failed"
            );
        }
    }

    async fn disabled(&mut self, server: &Arc<Box<Server>>) {
        // Show raw names again.
        apply_channel_name_cache(server, &TranslationCache::default()).await;
    }
}

/// Keep channel-name translations in sync with Weblate until shutdown. Config
/// reloads take effect on the next poll.
pub(crate) fn spawn_channel_name_sync(
    server: Weak<Box<Server>>,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(poll_until_shutdown(server, shutdown, ChannelNameSync))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shitspeak_messages::messages::encoder::ChannelState;

    fn language(tag: &str) -> Language {
        Language::parse(tag).unwrap()
    }

    fn names(entries: &[(&str, &[(&str, &str)])]) -> HashMap<Language, ChannelNameMap> {
        entries
            .iter()
            .map(|(tag, pairs)| {
                (
                    language(tag),
                    pairs
                        .iter()
                        .map(|(raw, translated)| ((*raw).to_owned(), (*translated).to_owned()))
                        .collect(),
                )
            })
            .collect()
    }

    fn channel_state(id: u32, name: Option<&str>) -> Message {
        ChannelState {
            channel_id: Some(id),
            name: name.map(str::to_owned),
            ..Default::default()
        }
        .into()
    }

    fn name_of(message: &Message) -> Option<&str> {
        match message {
            Message::ChannelState(state) => state.name.as_deref(),
            _ => None,
        }
    }

    #[test]
    fn translations_negotiate_regional_client_languages() {
        let translations = ChannelNameTranslations::new();
        translations.replace(names(&[("zh-Hans", &[("Lobby", "大厅")]), ("es", &[("Lobby", "Vestíbulo")])]));

        assert_eq!(translations.translate(&language("zh-CN"), "Lobby").as_deref(), Some("大厅"));
        assert_eq!(translations.translate(&language("es-MX"), "Lobby").as_deref(), Some("Vestíbulo"));
        assert_eq!(translations.translate(&language("de"), "Lobby"), None);
        assert_eq!(translations.translate(&language("es"), "Music"), None);
    }

    #[test]
    fn diff_reports_changed_names_and_languages() {
        let translations = ChannelNameTranslations::new();
        let first = translations.replace(names(&[("es", &[("Lobby", "Vestíbulo"), ("Music", "Música")])]));
        assert!(first.language_set_changed);

        let second = translations.replace(names(&[("es", &[("Lobby", "Sala"), ("Music", "Música")])]));
        assert!(!second.language_set_changed);
        assert_eq!(second.names, HashSet::from(["Lobby".to_owned()]));
        assert_eq!(second.languages, HashSet::from([language("es")]));
        assert!(translations.affects(&second, &language("es-MX")));
        assert!(!translations.affects(&second, &language("de")));

        let unchanged = translations.replace(names(&[("es", &[("Lobby", "Sala"), ("Music", "Música")])]));
        assert!(unchanged.is_empty());
    }

    #[test]
    fn localization_rewrites_only_translated_channel_names() {
        let map: ChannelNameMap = HashMap::from([("Lobby".to_owned(), "Vestíbulo".to_owned())]);
        let messages = vec![
            channel_state(1, Some("Lobby")),
            channel_state(2, Some("Music")),
            channel_state(3, None),
        ];

        let localized = localize_channel_names(&map, &messages).expect("a name was translated");

        assert_eq!(name_of(&localized[0]), Some("Vestíbulo"));
        assert_eq!(name_of(&localized[1]), Some("Music"));
        assert_eq!(name_of(&localized[2]), None);
        assert!(
            localize_channel_names(&map, &messages[1..]).is_none(),
            "batches without translated names are not copied"
        );
    }
}
