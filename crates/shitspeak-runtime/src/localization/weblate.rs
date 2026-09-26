//! Minimal client for the parts of the Weblate REST API the server uses.
//!
//! Translations are read through the units API rather than the file download
//! endpoint: file downloads return the file as last committed to the VCS,
//! while units reflect every saved translation immediately, which is what
//! live updates need.

use std::fmt;
use std::time::Duration;

use reqwest::{Method, StatusCode, Url};
use serde::Deserialize;
use shitspeak_runtime_config::WeblateComponentConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Weblate caps page sizes; larger requests are clamped server-side.
const UNITS_PAGE_SIZE: &str = "1000";
/// Guards against a misbehaving server returning an endless `next` chain.
const MAX_PAGES: usize = 10_000;

#[derive(Debug)]
pub(crate) enum WeblateError {
    InvalidUrl(String),
    Http(reqwest::Error),
    Status { status: StatusCode, body: String },
    Decode(String),
    TooManyPages,
}

impl fmt::Display for WeblateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(error) => write!(f, "invalid Weblate URL: {error}"),
            Self::Http(error) => write!(f, "Weblate request failed: {error}"),
            Self::Status { status, body } => {
                write!(f, "Weblate returned {status}: {}", truncate(body, 300))
            }
            Self::Decode(error) => write!(f, "unexpected Weblate response: {error}"),
            Self::TooManyPages => f.write_str("Weblate pagination did not terminate"),
        }
    }
}

impl std::error::Error for WeblateError {}

fn truncate(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// One language of a component, as listed by
/// `GET /api/components/{project}/{component}/translations/`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct TranslationSummary {
    language_code: String,
    #[serde(default)]
    is_source: bool,
    #[serde(default)]
    last_change: Option<String>,
    #[serde(default)]
    translated: u64,
    #[serde(default)]
    total: u64,
}

impl TranslationSummary {
    pub(crate) fn language_code(&self) -> &str {
        &self.language_code
    }

    pub(crate) fn is_source(&self) -> bool {
        self.is_source
    }

    /// Changes whenever the translation's content may have changed. Used to
    /// skip downloading languages that did not change since the last poll.
    pub(crate) fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}",
            self.last_change.as_deref().unwrap_or_default(),
            self.translated,
            self.total
        )
    }
}

#[derive(Debug, Deserialize)]
struct Page<T> {
    #[serde(default)]
    next: Option<String>,
    results: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct Unit {
    #[serde(default)]
    context: String,
    #[serde(default)]
    source: Vec<String>,
    #[serde(default)]
    target: Vec<String>,
    #[serde(default)]
    translated: bool,
}

impl Unit {
    /// The monolingual key. Weblate reports it as the unit context; nested
    /// JSON keys are joined with `.` and may carry a leading separator
    /// depending on the translate-toolkit version.
    fn key(&self) -> Option<String> {
        let key = if self.context.is_empty() {
            self.source.first()?.as_str()
        } else {
            self.context.strip_prefix('.').unwrap_or(&self.context)
        };
        (!key.is_empty()).then(|| key.to_owned())
    }
}

#[derive(Clone)]
pub(crate) struct WeblateClient {
    http: reqwest::Client,
    api: Url,
    token: Option<String>,
    project: String,
    component: String,
}

impl WeblateClient {
    pub(crate) fn new(config: &WeblateComponentConfig) -> Result<Self, WeblateError> {
        let mut base = config.url().trim_end_matches('/').to_owned();
        base.push_str("/api/");
        let api = Url::parse(&base).map_err(|error| WeblateError::InvalidUrl(error.to_string()))?;
        let http = crate::http_client::build_with_webpki_fallback(REQUEST_TIMEOUT, "weblate")
            .map_err(WeblateError::Http)?;
        Ok(Self {
            http,
            api,
            token: config.token().map(str::to_owned),
            project: config.project().to_owned(),
            component: config.component().to_owned(),
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, WeblateError> {
        let mut url = self.api.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| WeblateError::InvalidUrl(self.api.to_string()))?;
            path.pop_if_empty();
            path.extend(segments);
            // Weblate routes end with a slash.
            path.push("");
        }
        Ok(url)
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<Vec<u8>, WeblateError> {
        let mut request = self
            .http
            .request(method, url)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(token) = &self.token {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Token {token}"));
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.map_err(WeblateError::Http)?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(WeblateError::Http)?;
        if !status.is_success() {
            return Err(WeblateError::Status {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(bytes.to_vec())
    }

    async fn get_all_pages<T: for<'de> Deserialize<'de>>(
        &self,
        first: Url,
    ) -> Result<Vec<T>, WeblateError> {
        let mut results = Vec::new();
        let mut next = Some(first);
        for _ in 0..MAX_PAGES {
            let Some(url) = next.take() else {
                return Ok(results);
            };
            let bytes = self.send(Method::GET, url, None).await?;
            let page: Page<T> = serde_json::from_slice(&bytes)
                .map_err(|error| WeblateError::Decode(error.to_string()))?;
            results.extend(page.results);
            next = page
                .next
                .map(|next| {
                    Url::parse(&next).map_err(|error| WeblateError::InvalidUrl(error.to_string()))
                })
                .transpose()?;
        }
        Err(WeblateError::TooManyPages)
    }

    /// Every language of the component, including the source language.
    pub(crate) async fn translations(&self) -> Result<Vec<TranslationSummary>, WeblateError> {
        let url = self.endpoint(&["components", &self.project, &self.component, "translations"])?;
        self.get_all_pages(url).await
    }

    fn units_url(&self, language_code: &str, query: Option<&str>) -> Result<Url, WeblateError> {
        let mut url = self.endpoint(&[
            "translations",
            &self.project,
            &self.component,
            language_code,
            "units",
        ])?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("page_size", UNITS_PAGE_SIZE);
            if let Some(query) = query {
                pairs.append_pair("q", query);
            }
        }
        Ok(url)
    }

    /// `(key, translation)` for every unit of `language_code` that is
    /// translated or approved. Strings that need editing are left out so a
    /// draft never reaches users.
    pub(crate) async fn translated_units(
        &self,
        language_code: &str,
    ) -> Result<Vec<(String, String)>, WeblateError> {
        let url = self.units_url(language_code, Some("state:>=translated"))?;
        let units: Vec<Unit> = self.get_all_pages(url).await?;
        Ok(units
            .into_iter()
            .filter(|unit| unit.translated)
            .filter_map(|unit| {
                let target = unit.target.first()?.clone();
                Some((unit.key()?, target))
            })
            .collect())
    }

    /// Add a source string to a monolingual component. A key that already
    /// exists counts as success, since another node may have added it first.
    pub(crate) async fn add_source_string(
        &self,
        source_language_code: &str,
        key: &str,
        value: &str,
    ) -> Result<(), WeblateError> {
        let url = self.endpoint(&[
            "translations",
            &self.project,
            &self.component,
            source_language_code,
            "units",
        ])?;
        let body = serde_json::json!({ "key": key, "value": [value] });
        match self.send(Method::POST, url, Some(body)).await {
            Ok(_) => Ok(()),
            Err(WeblateError::Status { status, body })
                if status == StatusCode::BAD_REQUEST && body.contains("already") =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localization::weblate_mock::MockWeblate;
    use std::collections::HashSet;

    fn client(mock: &MockWeblate, token: Option<&str>) -> WeblateClient {
        WeblateClient::new(&WeblateComponentConfig::new(
            mock.url(),
            "proj",
            "comp",
            token.map(str::to_owned),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn lists_translations_across_pages() {
        let mock = MockWeblate::start().await;
        mock.set_translation("en", true, &[]);
        mock.set_translation("es", false, &[("a", "A-es")]);
        mock.set_page_size(1);

        let translations = client(&mock, None).translations().await.unwrap();

        let codes: Vec<_> = translations
            .iter()
            .map(|summary| (summary.language_code().to_owned(), summary.is_source()))
            .collect();
        assert_eq!(codes, vec![("en".to_owned(), true), ("es".to_owned(), false)]);
    }

    #[tokio::test]
    async fn reads_only_translated_units_and_sends_the_token() {
        let mock = MockWeblate::start().await;
        mock.set_translation("en", true, &[("a", "A"), ("b", "B")]);
        mock.set_translation("es", false, &[("a", "A-es")]);
        mock.set_draft("es", "b", "B-es-draft");

        let units = client(&mock, Some("wlu_secret"))
            .translated_units("es")
            .await
            .unwrap();

        assert_eq!(units, vec![("a".to_owned(), "A-es".to_owned())]);
        assert!(
            mock.authorizations()
                .iter()
                .all(|header| header.as_deref() == Some("Token wlu_secret"))
        );
    }

    #[tokio::test]
    async fn adding_an_existing_source_string_is_not_an_error() {
        let mock = MockWeblate::start().await;
        mock.set_translation("x_key", true, &[("Lobby", "Lobby")]);
        let client = client(&mock, Some("wlu_secret"));

        client.add_source_string("x_key", "Lobby", "Lobby").await.unwrap();
        client.add_source_string("x_key", "Music", "Music").await.unwrap();

        assert_eq!(mock.added_keys(), vec!["Music".to_owned()]);
        let keys: HashSet<String> = client
            .translated_units("x_key")
            .await
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(keys, HashSet::from(["Lobby".to_owned(), "Music".to_owned()]));
    }

    #[tokio::test]
    async fn http_errors_surface_with_status() {
        let mock = MockWeblate::start().await;
        let error = client(&mock, None).translated_units("missing").await.unwrap_err();
        assert!(
            matches!(error, WeblateError::Status { status, .. } if status == StatusCode::NOT_FOUND),
            "unexpected error: {error}"
        );
    }
}
