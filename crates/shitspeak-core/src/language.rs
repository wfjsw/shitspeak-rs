use fluent_langneg::{NegotiationStrategy, negotiate_languages};
use icu_locid::{LanguageIdentifier, langid};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

/// Language selection for server-generated text.
///
/// Each variant corresponds to one translation catalog. Incoming language
/// requests are arbitrary BCP-47 tags (`es-MX`, `zh-Hans-CN`, `en-GB`, …); they
/// are matched against the catalogs by language negotiation rather than by a
/// hand-maintained table of accepted spellings, so adding a catalog only means
/// adding a variant and its tag in [`Language::TAGGED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    English,
    Spanish,
    French,
    German,
    ChineseSimplified,
}

impl Language {
    /// Every supported catalog paired with the BCP-47 tag it is written in.
    /// This is the single place a new translation catalog is registered.
    const TAGGED: &'static [(Language, LanguageIdentifier)] = &[
        (Language::English, langid!("en")),
        (Language::Spanish, langid!("es")),
        (Language::French, langid!("fr")),
        (Language::German, langid!("de")),
        (Language::ChineseSimplified, langid!("zh-Hans")),
    ];

    pub fn all() -> impl Iterator<Item = Language> {
        Self::TAGGED.iter().map(|(language, _)| *language)
    }

    /// Resolve a requested language tag to the best matching catalog, falling
    /// back to [`Language::English`] when the tag is unparsable or matches no
    /// catalog. Use [`Self::negotiate`] when an unmatched tag must be an error.
    pub fn from_code(code: &str) -> Self {
        Self::negotiate(code).unwrap_or_default()
    }

    /// Resolve a requested language tag to the best matching catalog, or `None`
    /// when the tag is not a valid language tag or matches no catalog.
    pub fn negotiate(code: &str) -> Option<Self> {
        let requested: LanguageIdentifier = code.trim().parse().ok()?;
        let available: Vec<&LanguageIdentifier> = Self::TAGGED.iter().map(|(_, tag)| tag).collect();
        let matched = negotiate_languages(
            std::slice::from_ref(&requested),
            &available,
            None,
            NegotiationStrategy::Filtering,
        )
        .first()
        .copied()?;
        Self::TAGGED
            .iter()
            .find_map(|(language, tag)| (tag == *matched).then_some(*language))
    }

    /// Short canonical code for this language, as used on the wire and in
    /// configuration files.
    pub fn code(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Spanish => "es",
            Self::French => "fr",
            Self::German => "de",
            Self::ChineseSimplified => "zh",
        }
    }
}

impl Serialize for Language {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}

/// Deserialization negotiates the tag like [`Language::negotiate`], but reports
/// an error instead of falling back to English: a misspelled configuration
/// value must surface rather than silently change the server's language.
impl<'de> Deserialize<'de> for Language {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let code = String::deserialize(deserializer)?;
        Language::negotiate(&code).ok_or_else(|| {
            let supported = Language::all()
                .map(|language| language.code())
                .collect::<Vec<_>>()
                .join(", ");
            de::Error::custom(format!(
                "unsupported language tag {code:?}; supported languages: {supported}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Language;

    #[test]
    fn negotiates_regional_and_script_variants_onto_catalogs() {
        for (code, expected) in [
            ("en", Language::English),
            ("en-US", Language::English),
            ("en-GB", Language::English),
            ("es", Language::Spanish),
            ("es-MX", Language::Spanish),
            ("es-419", Language::Spanish),
            ("fr-CA", Language::French),
            ("de-DE", Language::German),
            ("zh", Language::ChineseSimplified),
            ("zh-Hans", Language::ChineseSimplified),
            ("zh-CN", Language::ChineseSimplified),
        ] {
            assert_eq!(Language::negotiate(code), Some(expected), "tag {code}");
        }
    }

    #[test]
    fn negotiation_is_whitespace_and_case_insensitive() {
        assert_eq!(Language::negotiate("  ES-mx  "), Some(Language::Spanish));
    }

    #[test]
    fn from_code_falls_back_to_english_but_negotiate_reports_no_match() {
        // `from_code` stays lenient for authenticator payloads.
        assert_eq!(Language::from_code("kl"), Language::English);
        assert_eq!(Language::from_code("not a tag!"), Language::English);
        assert_eq!(Language::negotiate("kl"), None);
        assert_eq!(Language::negotiate("not a tag!"), None);
    }

    #[test]
    fn serde_round_trips_through_the_canonical_code() {
        for language in Language::all() {
            let encoded = serde_json::to_string(&language).unwrap();
            assert_eq!(encoded, format!("\"{}\"", language.code()));
            assert_eq!(
                serde_json::from_str::<Language>(&encoded).unwrap(),
                language
            );
        }
    }

    #[test]
    fn deserialization_rejects_unsupported_tags() {
        let error = serde_json::from_str::<Language>("\"kl\"").unwrap_err();
        assert!(
            error.to_string().contains("unsupported language tag"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn every_registered_catalog_negotiates_back_to_itself() {
        assert_eq!(Language::all().count(), 5);
        for language in Language::all() {
            assert_eq!(Language::negotiate(language.code()), Some(language));
        }
    }
}
