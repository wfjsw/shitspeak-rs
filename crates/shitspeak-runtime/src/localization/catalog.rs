//! Message catalogs: parsing, validation and per-language lookup.
//!
//! A catalog maps flat, dotted message keys (`reject.WrongUserPw`) to message
//! text. On disk and in Weblate a catalog is a nested JSON object
//! (`{"reject": {"WrongUserPw": "…"}}`); both spellings produce the same keys.
//!
//! The English catalog is the source: it defines which keys exist and which
//! `{placeholder}`s each message takes. Every other catalog is validated
//! against it entry by entry, so a bad translation only costs that one string
//! (it falls back to English) instead of the whole language.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use shitspeak_core::Language;

/// One language's messages, keyed by flat dotted key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Catalog {
    entries: HashMap<String, String>,
}

impl Catalog {
    pub(crate) fn from_entries(entries: HashMap<String, String>) -> Self {
        Self { entries }
    }

    /// Parse a catalog file. Nested objects are flattened into dotted keys;
    /// non-string leaves are rejected because Weblate never produces them.
    pub(crate) fn from_json(json: &str) -> Result<Self, CatalogError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|error| CatalogError::Json(error.to_string()))?;
        let serde_json::Value::Object(object) = value else {
            return Err(CatalogError::NotAnObject);
        };
        let mut entries = HashMap::new();
        flatten_into(&mut entries, String::new(), object)?;
        Ok(Self { entries })
    }

    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Overlay `other` on top of this catalog; entries in `other` win.
    fn overlaid_with(&self, other: &Catalog) -> Catalog {
        let mut entries = self.entries.clone();
        entries.extend(
            other
                .entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        Catalog { entries }
    }
}

fn flatten_into(
    entries: &mut HashMap<String, String>,
    prefix: String,
    object: serde_json::Map<String, serde_json::Value>,
) -> Result<(), CatalogError> {
    for (key, value) in object {
        let key = if prefix.is_empty() {
            key
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            serde_json::Value::String(text) => {
                entries.insert(key, text);
            }
            serde_json::Value::Object(nested) => flatten_into(entries, key, nested)?,
            _ => return Err(CatalogError::NonStringValue(key)),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CatalogError {
    Json(String),
    NotAnObject,
    NonStringValue(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid JSON: {error}"),
            Self::NotAnObject => f.write_str("catalog must be a JSON object"),
            Self::NonStringValue(key) => write!(f, "value of {key:?} is not a string"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// The `{name}` placeholders in a message, as a set.
pub(crate) fn placeholders(message: &str) -> BTreeSet<&str> {
    let mut found = BTreeSet::new();
    let mut rest = message;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        let name = &after[..close];
        if !name.is_empty()
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            found.insert(name);
            rest = &after[close + 1..];
        } else {
            rest = after;
        }
    }
    found
}

/// Why a translated entry was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RejectedEntry {
    /// The key does not exist in the source catalog.
    UnknownKey { language: String, key: String },
    /// The translation's placeholders differ from the source message's.
    PlaceholderMismatch { language: String, key: String },
}

impl fmt::Display for RejectedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey { language, key } => {
                write!(f, "{language}: unknown message key {key:?}")
            }
            Self::PlaceholderMismatch { language, key } => write!(
                f,
                "{language}: placeholders of {key:?} do not match the source message"
            ),
        }
    }
}

/// Keep only the entries of `translation` that the source knows and whose
/// placeholders match; empty strings mean "untranslated" and are dropped
/// silently.
pub(crate) fn validate_translation(
    source: &Catalog,
    language: &Language,
    translation: Catalog,
) -> (Catalog, Vec<RejectedEntry>) {
    let mut rejected = Vec::new();
    let mut accepted = HashMap::with_capacity(translation.entries.len());
    for (key, text) in translation.entries {
        if text.trim().is_empty() {
            continue;
        }
        let Some(source_text) = source.get(&key) else {
            rejected.push(RejectedEntry::UnknownKey {
                language: language.tag(),
                key,
            });
            continue;
        };
        if placeholders(source_text) != placeholders(&text) {
            rejected.push(RejectedEntry::PlaceholderMismatch {
                language: language.tag(),
                key,
            });
            continue;
        }
        accepted.insert(key, text);
    }
    (Catalog::from_entries(accepted), rejected)
}

/// An immutable set of catalogs that answers lookups for any language.
#[derive(Debug, Clone)]
pub(crate) struct CatalogSet {
    source_language: Language,
    source: Catalog,
    translations: HashMap<Language, Catalog>,
    /// Negotiation candidates: the source language plus every translation.
    languages: Vec<Language>,
}

impl CatalogSet {
    /// Build a set from a complete source catalog and already validated
    /// translations.
    pub(crate) fn new(
        source_language: Language,
        source: Catalog,
        translations: HashMap<Language, Catalog>,
    ) -> Self {
        let mut languages = Vec::with_capacity(translations.len() + 1);
        languages.push(source_language.clone());
        let mut translated: Vec<Language> = translations
            .keys()
            .filter(|language| **language != source_language)
            .cloned()
            .collect();
        translated.sort_by_key(Language::tag);
        languages.extend(translated);
        Self {
            source_language,
            source,
            translations,
            languages,
        }
    }

    pub(crate) fn source(&self) -> &Catalog {
        &self.source
    }

    pub(crate) fn languages(&self) -> &[Language] {
        &self.languages
    }

    /// Return a new set where each catalog in `overlay` is layered on top of
    /// this set's catalog for the same language. Entries that the overlay
    /// does not provide keep their current text.
    pub(crate) fn overlaid_with(&self, overlay: &HashMap<Language, Catalog>) -> Self {
        let mut source = self.source.clone();
        let mut translations = self.translations.clone();
        for (language, catalog) in overlay {
            if *language == self.source_language {
                source = source.overlaid_with(catalog);
                continue;
            }
            let merged = match translations.get(language) {
                Some(existing) => existing.overlaid_with(catalog),
                None => catalog.clone(),
            };
            translations.insert(language.clone(), merged);
        }
        Self::new(self.source_language.clone(), source, translations)
    }

    /// The message for `key` in the catalog that best matches `language`,
    /// falling back to the source catalog for untranslated keys.
    pub(crate) fn lookup(&self, language: &Language, key: &str) -> Option<&str> {
        let translated = language
            .negotiate(&self.languages)
            .filter(|matched| **matched != self.source_language)
            .and_then(|matched| self.translations.get(matched))
            .and_then(|catalog| catalog.get(key));
        translated.or_else(|| self.source.get(key))
    }
}

/// Substitute `{name}` placeholders. Unknown placeholders are left as-is so a
/// missing argument is visible instead of silently producing broken text.
/// Substitution is a single pass, so argument values that themselves contain
/// `{…}` are never expanded.
pub(crate) fn format_message(template: &str, arguments: &[(&str, &str)]) -> String {
    let mut formatted = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        formatted.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let value = after.find('}').and_then(|close| {
            let name = &after[..close];
            arguments
                .iter()
                .find(|(argument, _)| *argument == name)
                .map(|(_, value)| (*value, close))
        });
        match value {
            Some((value, close)) => {
                formatted.push_str(value);
                rest = &after[close + 1..];
            }
            None => {
                formatted.push('{');
                rest = after;
            }
        }
    }
    formatted.push_str(rest);
    formatted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn language(tag: &str) -> Language {
        Language::parse(tag).unwrap()
    }

    fn catalog(entries: &[(&str, &str)]) -> Catalog {
        Catalog::from_entries(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        )
    }

    #[test]
    fn nested_json_flattens_into_dotted_keys() {
        let parsed = Catalog::from_json(
            r#"{"reject": {"WrongUserPw": "Wrong"}, "text": {"a": {"b": "deep"}}}"#,
        )
        .unwrap();
        assert_eq!(parsed.get("reject.WrongUserPw"), Some("Wrong"));
        assert_eq!(parsed.get("text.a.b"), Some("deep"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn non_string_leaves_are_rejected() {
        assert_eq!(
            Catalog::from_json(r#"{"reject": {"WrongUserPw": 3}}"#),
            Err(CatalogError::NonStringValue("reject.WrongUserPw".to_owned()))
        );
        assert_eq!(
            Catalog::from_json("[]"),
            Err(CatalogError::NotAnObject)
        );
    }

    #[test]
    fn placeholders_ignore_braces_that_are_not_identifiers() {
        assert_eq!(
            placeholders("Channel {channel_id} of {server} {not valid} {}"),
            BTreeSet::from(["channel_id", "server"])
        );
    }

    #[test]
    fn validation_drops_unknown_keys_placeholder_mismatches_and_empty_strings() {
        let source = catalog(&[
            ("text.ChannelDoesNotExist", "Channel {channel_id} does not exist"),
            ("text.Plain", "Plain"),
            ("text.Empty", "Empty"),
        ]);
        let (accepted, rejected) = validate_translation(
            &source,
            &language("es"),
            catalog(&[
                ("text.ChannelDoesNotExist", "El canal {canal} no existe"),
                ("text.Plain", "Simple"),
                ("text.Empty", "  "),
                ("text.Removed", "Eliminado"),
            ]),
        );
        assert_eq!(accepted, catalog(&[("text.Plain", "Simple")]));
        assert_eq!(rejected.len(), 2);
        assert!(rejected.contains(&RejectedEntry::PlaceholderMismatch {
            language: "es".to_owned(),
            key: "text.ChannelDoesNotExist".to_owned(),
        }));
        assert!(rejected.contains(&RejectedEntry::UnknownKey {
            language: "es".to_owned(),
            key: "text.Removed".to_owned(),
        }));
    }

    #[test]
    fn lookup_negotiates_and_falls_back_to_the_source_per_key() {
        let set = CatalogSet::new(
            Language::ENGLISH,
            catalog(&[("a", "A"), ("b", "B")]),
            HashMap::from([(language("es"), catalog(&[("a", "A-es")]))]),
        );
        assert_eq!(set.lookup(&language("es-MX"), "a"), Some("A-es"));
        assert_eq!(set.lookup(&language("es-MX"), "b"), Some("B"));
        assert_eq!(set.lookup(&language("kl"), "a"), Some("A"));
        assert_eq!(set.lookup(&language("es"), "missing"), None);
    }

    #[test]
    fn overlays_replace_individual_entries_and_add_languages() {
        let base = CatalogSet::new(
            Language::ENGLISH,
            catalog(&[("a", "A"), ("b", "B")]),
            HashMap::from([(language("es"), catalog(&[("a", "A-es"), ("b", "B-es")]))]),
        );
        let overlaid = base.overlaid_with(&HashMap::from([
            (language("es"), catalog(&[("a", "A-es-live")])),
            (language("ja"), catalog(&[("a", "A-ja")])),
            (Language::ENGLISH, catalog(&[("b", "B-live")])),
        ]));
        assert_eq!(overlaid.lookup(&language("es"), "a"), Some("A-es-live"));
        assert_eq!(overlaid.lookup(&language("es"), "b"), Some("B-es"));
        assert_eq!(overlaid.lookup(&language("ja"), "a"), Some("A-ja"));
        assert_eq!(overlaid.lookup(&language("ja"), "b"), Some("B-live"));
        assert_eq!(overlaid.lookup(&Language::ENGLISH, "b"), Some("B-live"));
        assert_eq!(base.lookup(&language("ja"), "a"), Some("A"));
    }

    #[test]
    fn formatting_substitutes_named_placeholders() {
        assert_eq!(
            format_message("Channel {channel_id} of {channel_id}", &[("channel_id", "7")]),
            "Channel 7 of 7"
        );
        assert_eq!(format_message("Keep {other}", &[]), "Keep {other}");
        assert_eq!(
            format_message("{a} {b}", &[("a", "{b}"), ("b", "x")]),
            "{b} x",
            "values are not expanded again"
        );
    }
}
