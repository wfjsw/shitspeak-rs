//! In-process fake of the Weblate REST endpoints used by the server, served
//! over real HTTP so tests exercise the actual client.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use parking_lot::Mutex;
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
struct MockUnit {
    target: String,
    translated: bool,
}

#[derive(Debug, Clone, Default)]
struct MockTranslation {
    is_source: bool,
    revision: u64,
    units: BTreeMap<String, MockUnit>,
}

#[derive(Default)]
struct MockState {
    translations: BTreeMap<String, MockTranslation>,
    revision: u64,
    page_size: Option<usize>,
    authorizations: Vec<Option<String>>,
    added_keys: Vec<String>,
    unavailable: bool,
    requests: usize,
}

impl MockState {
    fn bump(&mut self, language_code: &str) {
        self.revision += 1;
        let revision = self.revision;
        if let Some(translation) = self.translations.get_mut(language_code) {
            translation.revision = revision;
        }
    }
}

#[derive(Clone)]
pub(crate) struct MockWeblate {
    url: String,
    state: Arc<Mutex<MockState>>,
}

impl MockWeblate {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(MockState::default()));
        let server_state = state.clone();
        let base = url.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = server_state.clone();
                let base = base.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, &base, &state).await;
                });
            }
        });
        Self { url, state }
    }

    pub(crate) fn url(&self) -> String {
        self.url.clone()
    }

    /// Replace a language with fully translated `entries`.
    pub(crate) fn set_translation(&self, language_code: &str, is_source: bool, entries: &[(&str, &str)]) {
        let mut state = self.state.lock();
        state.translations.insert(
            language_code.to_owned(),
            MockTranslation {
                is_source,
                revision: 0,
                units: entries
                    .iter()
                    .map(|(key, target)| {
                        (
                            (*key).to_owned(),
                            MockUnit {
                                target: (*target).to_owned(),
                                translated: true,
                            },
                        )
                    })
                    .collect(),
            },
        );
        state.bump(language_code);
    }

    /// Set one translated string, creating the language if needed.
    pub(crate) fn translate(&self, language_code: &str, key: &str, target: &str) {
        let mut state = self.state.lock();
        state
            .translations
            .entry(language_code.to_owned())
            .or_default()
            .units
            .insert(
                key.to_owned(),
                MockUnit {
                    target: target.to_owned(),
                    translated: true,
                },
            );
        state.bump(language_code);
    }

    /// Store a string that still needs editing; it must not be served.
    pub(crate) fn set_draft(&self, language_code: &str, key: &str, target: &str) {
        let mut state = self.state.lock();
        state
            .translations
            .entry(language_code.to_owned())
            .or_default()
            .units
            .insert(
                key.to_owned(),
                MockUnit {
                    target: target.to_owned(),
                    translated: false,
                },
            );
        state.bump(language_code);
    }

    pub(crate) fn remove_language(&self, language_code: &str) {
        let mut state = self.state.lock();
        state.translations.remove(language_code);
        state.revision += 1;
    }

    pub(crate) fn set_page_size(&self, page_size: usize) {
        self.state.lock().page_size = Some(page_size);
    }

    pub(crate) fn set_unavailable(&self, unavailable: bool) {
        self.state.lock().unavailable = unavailable;
    }

    pub(crate) fn authorizations(&self) -> Vec<Option<String>> {
        self.state.lock().authorizations.clone()
    }

    pub(crate) fn added_keys(&self) -> Vec<String> {
        self.state.lock().added_keys.clone()
    }

    pub(crate) fn source_keys(&self) -> Vec<String> {
        let state = self.state.lock();
        state
            .translations
            .values()
            .find(|translation| translation.is_source)
            .map(|translation| translation.units.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn request_count(&self) -> usize {
        self.state.lock().requests
    }
}

struct Request {
    method: String,
    target: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let target = request_line.next().unwrap_or_default().to_owned();
    let mut content_length = 0;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        }
    }
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(Some(Request {
        method,
        target,
        authorization,
        body,
    }))
}

async fn serve(mut stream: TcpStream, base: &str, state: &Mutex<MockState>) -> std::io::Result<()> {
    while let Some(request) = read_request(&mut stream).await? {
        let (status, body) = respond(base, state, request);
        let reason = match status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "Service Unavailable",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
    }
    Ok(())
}

fn respond(base: &str, state: &Mutex<MockState>, request: Request) -> (u16, String) {
    let mut state = state.lock();
    state.requests += 1;
    state.authorizations.push(request.authorization.clone());
    if state.unavailable {
        return (503, "{}".to_owned());
    }
    let url = Url::parse(&format!("{base}{}", request.target)).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let segments: Vec<String> = url
        .path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).map(str::to_owned).collect())
        .unwrap_or_default();
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
    let page: usize = query.get("page").and_then(|page| page.parse().ok()).unwrap_or(1);
    let page_size = state.page_size.unwrap_or(usize::MAX);

    match (request.method.as_str(), segments.as_slice()) {
        ("GET", ["api", "components", _, _, "translations"]) => {
            let results: Vec<serde_json::Value> = state
                .translations
                .iter()
                .map(|(code, translation)| {
                    serde_json::json!({
                        "language_code": code,
                        "is_source": translation.is_source,
                        "last_change": format!("rev-{}", translation.revision),
                        "translated": translation.units.values().filter(|unit| unit.translated).count(),
                        "total": translation.units.len(),
                    })
                })
                .collect();
            (200, paginate(&url, results, page, page_size))
        }
        ("GET", ["api", "translations", _, _, language_code, "units"]) => {
            let Some(translation) = state.translations.get(*language_code) else {
                return (404, r#"{"detail":"Not found."}"#.to_owned());
            };
            let translated_only = query
                .get("q")
                .is_some_and(|query| query.contains("state:>=translated"));
            let results: Vec<serde_json::Value> = translation
                .units
                .iter()
                .filter(|(_, unit)| !translated_only || unit.translated)
                .map(|(key, unit)| {
                    serde_json::json!({
                        "context": key,
                        "source": [key],
                        "target": [unit.target],
                        "translated": unit.translated,
                    })
                })
                .collect();
            (200, paginate(&url, results, page, page_size))
        }
        ("POST", ["api", "translations", _, _, language_code, "units"]) => {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let key = body["key"].as_str().unwrap_or_default().to_owned();
            let value = body["value"][0].as_str().unwrap_or_default().to_owned();
            let language_code = (*language_code).to_owned();
            let Some(translation) = state.translations.get_mut(&language_code) else {
                return (404, r#"{"detail":"Not found."}"#.to_owned());
            };
            if translation.units.contains_key(&key) {
                return (
                    400,
                    r#"{"key":["This string seems to already exist."]}"#.to_owned(),
                );
            }
            translation.units.insert(
                key.clone(),
                MockUnit {
                    target: value,
                    translated: true,
                },
            );
            state.added_keys.push(key);
            state.bump(&language_code);
            (200, "{}".to_owned())
        }
        _ => (404, r#"{"detail":"Not found."}"#.to_owned()),
    }
}

fn paginate(url: &Url, results: Vec<serde_json::Value>, page: usize, page_size: usize) -> String {
    let start = (page - 1).saturating_mul(page_size).min(results.len());
    let end = start.saturating_add(page_size).min(results.len());
    let next = (end < results.len()).then(|| {
        let mut next = url.clone();
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .into_owned()
            .filter(|(name, _)| name != "page")
            .collect();
        next.query_pairs_mut()
            .clear()
            .extend_pairs(pairs)
            .append_pair("page", &(page + 1).to_string());
        next.to_string()
    });
    serde_json::json!({
        "count": results.len(),
        "next": next,
        "results": results[start..end],
    })
    .to_string()
}
