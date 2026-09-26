use std::fmt;

use fluent_langneg::{NegotiationStrategy, negotiate_languages};
use icu_locid::{LanguageIdentifier, langid};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

/// A user's language preference, as a canonical BCP-47 language tag.
///
/// The value records what was *requested* (`es-MX`, `zh-Hans-CN`, `en-GB`, …),
/// not which catalog serves it. Translation catalogs are data that can appear
/// at runtime (bundled files, a live Weblate project, channel-name
/// translations), so each consumer matches the preference against the
/// languages it currently has with [`Language::negotiate`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Language(LanguageIdentifier);

impl Language {
    /// The source language of the bundled server catalog.
    pub const ENGLISH: Language = Language(langid!("en"));

    /// Parse a language tag. Both BCP-47 (`pt-BR`) and the underscore form
    /// used by Weblate and gettext file names (`pt_BR`, `zh_Hans`) are
    /// accepted. Returns `None` for text that is not a language tag.
    pub fn parse(tag: &str) -> Option<Self> {
        let tag = tag.trim().replace('_', "-");
        if tag.is_empty() {
            return None;
        }
        let identifier: LanguageIdentifier = tag.parse().ok()?;
        // `und` parses successfully but expresses no preference at all.
        (!identifier.language.is_empty()).then_some(Self(identifier))
    }

    pub fn identifier(&self) -> &LanguageIdentifier {
        &self.0
    }

    /// Canonical BCP-47 spelling of this language tag.
    pub fn tag(&self) -> String {
        self.0.to_string()
    }

    /// Pick the best entry of `available` for this preference, or `None` when
    /// nothing is close enough. Regional and script variants resolve onto the
    /// base language (`es-MX` → `es`, `zh-CN` → `zh-Hans`) and vice versa.
    pub fn negotiate<'a>(&self, available: &'a [Language]) -> Option<&'a Language> {
        if available.is_empty() {
            return None;
        }
        let identifiers: Vec<&LanguageIdentifier> =
            available.iter().map(Language::identifier).collect();
        let matched = negotiate_languages(
            std::slice::from_ref(&self.0),
            &identifiers,
            None,
            NegotiationStrategy::Filtering,
        )
        .first()
        .copied()?;
        available
            .iter()
            .find(|language| language.identifier() == *matched)
    }
}

impl Default for Language {
    fn default() -> Self {
        Self::ENGLISH
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Serialize for Language {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.tag())
    }
}

/// Deserialization rejects text that is not a language tag instead of falling
/// back to English: a misspelled configuration value must surface rather than
/// silently change the server's language. Whether a catalog exists for the tag
/// is deliberately not checked here, because catalogs can arrive at runtime.
impl<'de> Deserialize<'de> for Language {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tag = String::deserialize(deserializer)?;
        Language::parse(&tag).ok_or_else(|| {
            de::Error::custom(format!(
                "invalid language tag {tag:?}; expected a BCP-47 tag such as \"en\", \"es-MX\" or \"zh-Hans\""
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Language;

    fn languages(tags: &[&str]) -> Vec<Language> {
        tags.iter().map(|tag| Language::parse(tag).unwrap()).collect()
    }

    #[test]
    fn negotiates_regional_and_script_variants_onto_available_languages() {
        let available = languages(&["en", "es", "fr", "de", "zh-Hans"]);
        for (requested, expected) in [
            ("en", "en"),
            ("en-US", "en"),
            ("en-GB", "en"),
            ("es", "es"),
            ("es-MX", "es"),
            ("es-419", "es"),
            ("fr-CA", "fr"),
            ("de-DE", "de"),
            ("zh", "zh-Hans"),
            ("zh-Hans", "zh-Hans"),
            ("zh-CN", "zh-Hans"),
        ] {
            let requested = Language::parse(requested).unwrap();
            assert_eq!(
                requested.negotiate(&available).map(Language::tag).as_deref(),
                Some(expected),
                "tag {requested}"
            );
        }
    }

    #[test]
    fn negotiation_reports_no_match_for_unavailable_languages() {
        let available = languages(&["en", "es"]);
        assert_eq!(Language::parse("kl").unwrap().negotiate(&available), None);
        assert_eq!(Language::ENGLISH.negotiate(&[]), None);
    }

    #[test]
    fn parsing_accepts_weblate_underscore_codes_and_normalizes_case() {
        assert_eq!(Language::parse("pt_BR").unwrap().tag(), "pt-BR");
        assert_eq!(Language::parse("zh_Hans").unwrap().tag(), "zh-Hans");
        assert_eq!(Language::parse("  ES-mx  ").unwrap().tag(), "es-MX");
    }

    #[test]
    fn parsing_rejects_text_that_is_not_a_language_tag() {
        assert_eq!(Language::parse("not a tag!"), None);
        assert_eq!(Language::parse(""), None);
        assert_eq!(Language::parse("und"), None);
    }

    #[test]
    fn serde_round_trips_through_the_canonical_tag() {
        for tag in ["en", "es-MX", "zh-Hans", "kl"] {
            let language = Language::parse(tag).unwrap();
            let encoded = serde_json::to_string(&language).unwrap();
            assert_eq!(encoded, format!("\"{tag}\""));
            assert_eq!(serde_json::from_str::<Language>(&encoded).unwrap(), language);
        }
    }

    #[test]
    fn deserialization_rejects_invalid_tags() {
        let error = serde_json::from_str::<Language>("\"not a tag!\"").unwrap_err();
        assert!(
            error.to_string().contains("invalid language tag"),
            "unexpected error: {error}"
        );
    }
}
