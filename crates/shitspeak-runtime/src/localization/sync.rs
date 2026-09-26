//! Polling Weblate for translations while the server runs.
//!
//! Both Weblate integrations — the server's own message catalog and channel
//! names — share the same loop: list the component's languages, download the
//! ones whose fingerprint changed, apply the result, and persist it so the
//! next start does not depend on Weblate being reachable.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shitspeak_core::Language;
use shitspeak_runtime_config::{TranslationSyncConfig, WeblateComponentConfig};

use super::Catalog;
use super::weblate::{WeblateClient, WeblateError};
use crate::server::Server;

/// How often a disabled integration re-reads the config to notice that it
/// was enabled by a reload.
const DISABLED_RECHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Downloaded translations of one Weblate component.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TranslationCache {
    /// Identifies the component the cache was downloaded from, so a cache
    /// file is not applied after the config points somewhere else.
    #[serde(default)]
    origin: String,
    #[serde(default)]
    languages: BTreeMap<String, CachedLanguage>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedLanguage {
    fingerprint: String,
    #[serde(default)]
    is_source: bool,
    #[serde(default)]
    entries: BTreeMap<String, String>,
}

impl CachedLanguage {
    pub(crate) fn is_source(&self) -> bool {
        self.is_source
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

pub(crate) fn origin_of(component: &WeblateComponentConfig) -> String {
    format!(
        "{}|{}|{}",
        component.url().trim_end_matches('/'),
        component.project(),
        component.component()
    )
}

impl TranslationCache {
    pub(crate) fn for_component(component: &WeblateComponentConfig) -> Self {
        Self {
            origin: origin_of(component),
            languages: BTreeMap::new(),
        }
    }

    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    /// `(Weblate language code, translations)` for every language.
    pub(crate) fn languages(&self) -> impl Iterator<Item = (&str, &CachedLanguage)> {
        self.languages
            .iter()
            .map(|(code, language)| (code.as_str(), language))
    }

    pub(crate) fn source_code(&self) -> Option<&str> {
        self.languages
            .iter()
            .find(|(_, language)| language.is_source)
            .map(|(code, _)| code.as_str())
    }

    pub(crate) fn has_source_key(&self, key: &str) -> bool {
        self.languages
            .values()
            .any(|language| language.is_source && language.entries.contains_key(key))
    }

    /// Record a key that was just added to the source language, so it is
    /// not pushed again before the next download of the source language.
    pub(crate) fn insert_source_key(&mut self, key: &str) {
        if let Some(source) = self.languages.values_mut().find(|language| language.is_source) {
            source.entries.insert(key.to_owned(), key.to_owned());
        }
    }

    /// Read a cache file. A missing or unreadable file yields `None`; the
    /// caller then starts from Weblate alone.
    pub(crate) fn load(path: &Path) -> Option<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "reading translation cache failed");
                return None;
            }
        };
        match serde_json::from_slice(&bytes) {
            Ok(cache) => Some(cache),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "ignoring corrupt translation cache");
                None
            }
        }
    }

    /// Write the cache atomically: a crash never leaves a truncated file.
    pub(crate) fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&temporary, path)
    }
}

/// Bring `cache` up to date with the component. Only languages whose
/// fingerprint changed are downloaded. Returns whether any translation
/// changed. On error `cache` is left untouched.
pub(crate) async fn refresh_translations(
    client: &WeblateClient,
    cache: &mut TranslationCache,
) -> Result<bool, WeblateError> {
    let summaries = client.translations().await?;
    let mut languages = BTreeMap::new();
    let mut changed = false;
    for summary in summaries {
        let code = summary.language_code().to_owned();
        let fingerprint = summary.fingerprint();
        if let Some(existing) = cache.languages.get(&code)
            && existing.fingerprint == fingerprint
            && existing.is_source == summary.is_source()
        {
            languages.insert(code, existing.clone());
            continue;
        }
        let entries = client.translated_units(&code).await?.into_iter().collect();
        let language = CachedLanguage {
            fingerprint,
            is_source: summary.is_source(),
            entries,
        };
        changed |= cache
            .languages
            .get(&code)
            .is_none_or(|existing| existing.entries != language.entries);
        languages.insert(code, language);
    }
    changed |= languages.len() != cache.languages.len();
    cache.languages = languages;
    Ok(changed)
}

/// One Weblate integration driven by [`poll_until_shutdown`].
#[async_trait]
pub(crate) trait WeblateSyncJob: Send + 'static {
    /// The component to poll and the poll interval, or `None` when the
    /// integration is disabled.
    fn target(&self, server: &Server) -> Option<(WeblateComponentConfig, Duration)>;

    /// The cache to start from (normally the one loaded at startup).
    fn initial_cache(&self, server: &Server) -> Option<TranslationCache>;

    /// Refresh `cache` from Weblate and apply it.
    async fn poll(&mut self, server: &Arc<Box<Server>>, client: &WeblateClient, cache: &mut TranslationCache);

    /// The integration was disabled by a config reload: stop serving live
    /// translations.
    async fn disabled(&mut self, server: &Arc<Box<Server>>);
}

/// Run `job` until shutdown, following config reloads.
pub(crate) async fn poll_until_shutdown<J: WeblateSyncJob>(
    server: Weak<Box<Server>>,
    mut shutdown: tokio::sync::watch::Receiver<()>,
    mut job: J,
) {
    let mut connection: Option<(WeblateComponentConfig, WeblateClient)> = None;
    let mut cache = TranslationCache::default();
    loop {
        let delay = {
            let Some(server) = server.upgrade() else {
                return;
            };
            match job.target(&server) {
                Some((component, interval)) => {
                    if connection.as_ref().map(|(current, _)| current) != Some(&component) {
                        connection = match WeblateClient::new(&component) {
                            Ok(client) => Some((component.clone(), client)),
                            Err(error) => {
                                tracing::warn!(%error, "cannot reach Weblate with the configured URL");
                                None
                            }
                        };
                        let origin = origin_of(&component);
                        cache = job
                            .initial_cache(&server)
                            .filter(|cache| cache.origin() == origin)
                            .unwrap_or_else(|| TranslationCache::for_component(&component));
                    }
                    if let Some((_, client)) = &connection {
                        job.poll(&server, client, &mut cache).await;
                    }
                    interval
                }
                None => {
                    if connection.take().is_some() {
                        cache = TranslationCache::default();
                        job.disabled(&server).await;
                    }
                    DISABLED_RECHECK_INTERVAL
                }
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// Parse a cache into catalogs keyed by language, skipping language codes
/// that are not language tags.
fn catalogs_from_cache(cache: &TranslationCache) -> HashMap<Language, Catalog> {
    let mut catalogs = HashMap::new();
    for (code, language) in cache.languages() {
        let Some(tag) = Language::parse(code) else {
            tracing::warn!(code, "ignoring Weblate language with an invalid code");
            continue;
        };
        let entries = language
            .entries()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        catalogs.insert(tag, Catalog::from_entries(entries));
    }
    catalogs
}

/// Apply live server-message translations from `cache`.
pub(crate) fn apply_translation_cache(server: &Server, cache: &TranslationCache) {
    let rejected = server.localizer().apply_live(catalogs_from_cache(cache));
    for entry in rejected {
        tracing::warn!(%entry, "ignoring invalid live translation");
    }
}

fn active_translation_sync(server: &Server) -> Option<TranslationSyncConfig> {
    server
        .read_config()
        .translation_sync
        .clone()
        .filter(TranslationSyncConfig::enabled)
}

fn load_cache_for(config: &TranslationSyncConfig) -> Option<TranslationCache> {
    let cache = TranslationCache::load(config.cache_path()?)?;
    (cache.origin() == origin_of(config.weblate())).then_some(cache)
}

/// Apply the on-disk cache of live server-message translations, if any.
pub(crate) fn load_translation_cache(server: &Server) {
    if let Some(cache) = active_translation_sync(server).as_ref().and_then(load_cache_for) {
        apply_translation_cache(server, &cache);
    }
}

struct ServerTextSync;

#[async_trait]
impl WeblateSyncJob for ServerTextSync {
    fn target(&self, server: &Server) -> Option<(WeblateComponentConfig, Duration)> {
        active_translation_sync(server).map(|config| (config.weblate().clone(), config.poll_interval()))
    }

    fn initial_cache(&self, server: &Server) -> Option<TranslationCache> {
        active_translation_sync(server).as_ref().and_then(load_cache_for)
    }

    async fn poll(&mut self, server: &Arc<Box<Server>>, client: &WeblateClient, cache: &mut TranslationCache) {
        match refresh_translations(client, cache).await {
            Ok(true) => {
                tracing::info!(
                    languages = cache.languages.len(),
                    "server translations updated from Weblate"
                );
                apply_translation_cache(server, cache);
                if let Some(path) = active_translation_sync(server)
                    .as_ref()
                    .and_then(TranslationSyncConfig::cache_path)
                    && let Err(error) = cache.save(path)
                {
                    tracing::warn!(path = %path.display(), %error, "saving translation cache failed");
                }
            }
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "server translation refresh failed"),
        }
    }

    async fn disabled(&mut self, server: &Arc<Box<Server>>) {
        server.localizer().apply_live(HashMap::new());
    }
}

/// Keep the server's message catalog in sync with Weblate until shutdown.
pub(crate) fn spawn_translation_sync(
    server: Weak<Box<Server>>,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(poll_until_shutdown(server, shutdown, ServerTextSync))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localization::weblate_mock::MockWeblate;

    fn client(mock: &MockWeblate) -> WeblateClient {
        WeblateClient::new(&WeblateComponentConfig::new(mock.url(), "proj", "comp", None)).unwrap()
    }

    #[tokio::test]
    async fn refresh_downloads_only_changed_languages() {
        let mock = MockWeblate::start().await;
        mock.set_translation("en", true, &[("a", "A")]);
        mock.set_translation("es", false, &[("a", "A-es")]);
        let client = client(&mock);
        let mut cache = TranslationCache::default();

        assert!(refresh_translations(&client, &mut cache).await.unwrap());
        let after_first = mock.request_count();

        assert!(!refresh_translations(&client, &mut cache).await.unwrap());
        assert_eq!(
            mock.request_count() - after_first,
            1,
            "an unchanged component costs a single listing request"
        );

        mock.translate("es", "a", "A-es-2");
        assert!(refresh_translations(&client, &mut cache).await.unwrap());
        let es = cache.languages.get("es").unwrap();
        assert_eq!(es.entries.get("a").map(String::as_str), Some("A-es-2"));

        mock.remove_language("es");
        assert!(refresh_translations(&client, &mut cache).await.unwrap());
        assert!(!cache.languages.contains_key("es"));
    }

    #[tokio::test]
    async fn failed_refresh_keeps_the_previous_cache() {
        let mock = MockWeblate::start().await;
        mock.set_translation("es", false, &[("a", "A-es")]);
        let client = client(&mock);
        let mut cache = TranslationCache::default();
        refresh_translations(&client, &mut cache).await.unwrap();
        let before = cache.clone();

        mock.set_unavailable(true);
        assert!(refresh_translations(&client, &mut cache).await.is_err());
        assert_eq!(cache, before);
    }

    #[test]
    fn cache_round_trips_through_disk() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("cache.json");
        let mut cache = TranslationCache::for_component(&WeblateComponentConfig::new(
            "https://weblate.example/",
            "p",
            "c",
            None,
        ));
        cache.languages.insert(
            "es".to_owned(),
            CachedLanguage {
                fingerprint: "f".to_owned(),
                is_source: false,
                entries: BTreeMap::from([("a".to_owned(), "A-es".to_owned())]),
            },
        );

        cache.save(&path).unwrap();

        assert_eq!(TranslationCache::load(&path), Some(cache));
        assert_eq!(TranslationCache::load(&directory.path().join("missing.json")), None);
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(TranslationCache::load(&path), None);
    }
}
