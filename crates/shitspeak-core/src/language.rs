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
    pub fn from_code(code: &str) -> Self {
        match code.trim().to_ascii_lowercase().as_str() {
            "es" | "es-es" | "es-mx" => Self::Spanish,
            "fr" | "fr-fr" | "fr-ca" => Self::French,
            "de" | "de-de" => Self::German,
            "zh" | "zh-cn" | "zh-hans" => Self::ChineseSimplified,
            _ => Self::English,
        }
    }

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
