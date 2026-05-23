use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::runtime::Handle;
use wasmtime::{Caller, Engine as WasmEngine, Extern, Instance, Linker, Memory, Module, Store};

use crate::localization::Language;
use crate::protocol_version::ProtocolVersion;

use super::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    ExternalAuthClaims, RegisteredUser,
};

const MAX_WASM_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_WASM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum WasmAuthenticatorError {
    #[error("failed to read WASM authenticator `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to compile WASM authenticator `{path}`: {error}")]
    Compile { path: PathBuf, error: String },
    #[error("WASM authenticator is missing required export `{0}`")]
    MissingExport(&'static str),
    #[error("WASM authenticator execution failed: {0}")]
    Execution(String),
    #[error("WASM authenticator memory access failed: {0}")]
    Memory(String),
    #[error("WASM authenticator returned invalid payload: {0}")]
    InvalidPayload(String),
    #[error("WASM authenticator JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct DemoAuthenticator;

#[async_trait]
impl Authenticator for DemoAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        _password: Option<&str>,
        _auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let groups = if username == "admin" {
            vec!["admin".to_owned()]
        } else {
            Vec::new()
        };
        Ok(AuthenticateResult {
            user_id: None,
            display_name: Some(username.to_owned()),
            groups,
            virtual_server_id: None,
            language: Language::default(),
            texture_url: None,
            comment_url: None,
        })
    }
}

pub struct ReloadableAuthenticator {
    inner: RwLock<Arc<dyn Authenticator>>,
    reloads_from_wasm_config: bool,
}

impl ReloadableAuthenticator {
    pub fn fixed<A: Authenticator>(authenticator: A) -> Self {
        let inner: Arc<dyn Authenticator> = Arc::new(authenticator);
        Self {
            inner: RwLock::new(inner),
            reloads_from_wasm_config: false,
        }
    }

    pub fn from_wasm_path(path: Option<&Path>) -> Result<Self, WasmAuthenticatorError> {
        Ok(Self {
            inner: RwLock::new(load_authenticator_from_wasm_path(path)?),
            reloads_from_wasm_config: true,
        })
    }

    pub fn prepare_wasm_reload(
        &self,
        path: Option<&Path>,
    ) -> Result<Option<Arc<dyn Authenticator>>, WasmAuthenticatorError> {
        if !self.reloads_from_wasm_config {
            return Ok(None);
        }
        load_authenticator_from_wasm_path(path).map(Some)
    }

    pub fn apply_prepared_reload(&self, next: Option<Arc<dyn Authenticator>>) {
        if let Some(next) = next {
            *self.inner.write().expect("Authenticator RwLock poisoned") = next;
        }
    }

    fn load_inner(&self) -> Arc<dyn Authenticator> {
        self.inner
            .read()
            .expect("Authenticator RwLock poisoned")
            .clone()
    }
}

#[async_trait]
impl Authenticator for ReloadableAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        self.load_inner()
            .authenticate(username, password, auxiliary_data)
            .await
    }

    async fn authenticate_external(
        &self,
        claims: &ExternalAuthClaims,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        self.load_inner()
            .authenticate_external(claims, auxiliary_data)
            .await
    }

    async fn language(
        &self,
        username: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Language {
        self.load_inner().language(username, auxiliary_data).await
    }

    async fn get_user_texture(&self, user_id: u32) -> Option<bytes::Bytes> {
        self.load_inner().get_user_texture(user_id).await
    }

    async fn get_user_comment(&self, user_id: u32) -> Option<String> {
        self.load_inner().get_user_comment(user_id).await
    }

    async fn set_user_texture(&self, user_id: u32, data: bytes::Bytes) -> Result<(), ()> {
        self.load_inner().set_user_texture(user_id, data).await
    }

    async fn set_user_comment(&self, user_id: u32, comment: String) -> Result<(), ()> {
        self.load_inner().set_user_comment(user_id, comment).await
    }

    async fn get_registered_users(&self, name_filter: &str) -> Vec<RegisteredUser> {
        self.load_inner().get_registered_users(name_filter).await
    }

    async fn unregister_user(&self, user_id: u32) -> Result<(), ()> {
        self.load_inner().unregister_user(user_id).await
    }
}

fn load_authenticator_from_wasm_path(
    path: Option<&Path>,
) -> Result<Arc<dyn Authenticator>, WasmAuthenticatorError> {
    match path.filter(|path| !path.as_os_str().is_empty()) {
        Some(path) => Ok(Arc::new(WasmAuthenticator::from_file(path)?)),
        None => Ok(Arc::new(DemoAuthenticator)),
    }
}

pub struct WasmAuthenticator {
    module: Arc<CompiledWasmAuthenticator>,
    http_client: reqwest::Client,
    source_path: PathBuf,
}

impl WasmAuthenticator {
    pub fn from_file(path: &Path) -> Result<Self, WasmAuthenticatorError> {
        let bytes = std::fs::read(path).map_err(|source| WasmAuthenticatorError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let engine = WasmEngine::default();
        let module =
            Module::new(&engine, &bytes).map_err(|source| WasmAuthenticatorError::Compile {
                path: path.to_path_buf(),
                error: source.to_string(),
            })?;

        tracing::info!(path = %path.display(), "loaded WASM authenticator");
        Ok(Self {
            module: Arc::new(CompiledWasmAuthenticator { engine, module }),
            http_client: reqwest::Client::new(),
            source_path: path.to_path_buf(),
        })
    }

    async fn invoke_required<Request, Response>(
        &self,
        export_name: &'static str,
        request: Request,
    ) -> Result<Response, WasmAuthenticatorError>
    where
        Request: Serialize + Send + 'static,
        Response: for<'de> Deserialize<'de> + Send + 'static,
    {
        let Some(bytes) = self.invoke_json(export_name, request).await? else {
            return Err(WasmAuthenticatorError::MissingExport(export_name));
        };
        serde_json::from_slice(&bytes).map_err(WasmAuthenticatorError::Json)
    }

    async fn invoke_optional<Request, Response>(
        &self,
        export_name: &'static str,
        request: Request,
    ) -> Result<Option<Response>, WasmAuthenticatorError>
    where
        Request: Serialize + Send + 'static,
        Response: for<'de> Deserialize<'de> + Send + 'static,
    {
        let Some(bytes) = self.invoke_json(export_name, request).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(WasmAuthenticatorError::Json)
    }

    async fn invoke_json<Request>(
        &self,
        export_name: &'static str,
        request: Request,
    ) -> Result<Option<Vec<u8>>, WasmAuthenticatorError>
    where
        Request: Serialize + Send + 'static,
    {
        let request_json = serde_json::to_vec(&request)?;
        let module = Arc::clone(&self.module);
        let http_client = self.http_client.clone();
        let runtime = Handle::current();
        let source_path = self.source_path.clone();

        tokio::task::spawn_blocking(move || {
            module.invoke_json_export(export_name, &request_json, http_client, runtime)
        })
        .await
        .map_err(|error| {
            WasmAuthenticatorError::Execution(format!(
                "WASM authenticator `{}` task failed: {error}",
                source_path.display()
            ))
        })?
    }
}

#[async_trait]
impl Authenticator for WasmAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let request = WasmAuthenticateRequest {
            username: username.to_owned(),
            password: password.map(ToOwned::to_owned),
            auxiliary_data: WasmAuthenticateAuxiliaryData::from(auxiliary_data),
        };
        match self
            .invoke_required::<_, WasmAuthenticateResponse>("authenticate", request)
            .await
        {
            Ok(response) => response.into_authenticate_result(),
            Err(error) => {
                tracing::warn!(error = %error, "WASM authenticator failed");
                Err(AuthenticationRejection::RetryLater)
            }
        }
    }

    async fn authenticate_external(
        &self,
        claims: &ExternalAuthClaims,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let request = WasmExternalAuthenticateRequest {
            claims: WasmExternalAuthClaims::from(claims),
            auxiliary_data: WasmAuthenticateAuxiliaryData::from(auxiliary_data),
        };
        match self
            .invoke_optional::<_, WasmAuthenticateResponse>("authenticate_external", request)
            .await
        {
            Ok(Some(response)) => response.into_authenticate_result(),
            Ok(None) => Ok(AuthenticateResult {
                user_id: Some(claims.subject),
                display_name: claims
                    .display_name
                    .clone()
                    .or_else(|| Some(claims.username.clone())),
                groups: claims.groups.clone(),
                virtual_server_id: None,
                language: Language::default(),
                texture_url: None,
                comment_url: None,
            }),
            Err(error) => {
                tracing::warn!(error = %error, "WASM external authenticator failed");
                Err(AuthenticationRejection::RetryLater)
            }
        }
    }

    async fn language(
        &self,
        username: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Language {
        let request = WasmLanguageRequest {
            username: username.map(ToOwned::to_owned),
            auxiliary_data: WasmAuthenticateAuxiliaryData::from(auxiliary_data),
        };
        match self
            .invoke_optional::<_, WasmLanguageResponse>("language", request)
            .await
        {
            Ok(Some(response)) => Language::from_code(&response.language),
            Ok(None) => Language::default(),
            Err(error) => {
                tracing::warn!(error = %error, "WASM authenticator language lookup failed");
                Language::default()
            }
        }
    }
}

struct CompiledWasmAuthenticator {
    engine: WasmEngine,
    module: Module,
}

impl CompiledWasmAuthenticator {
    fn invoke_json_export(
        &self,
        export_name: &'static str,
        request_json: &[u8],
        http_client: reqwest::Client,
        runtime: Handle,
    ) -> Result<Option<Vec<u8>>, WasmAuthenticatorError> {
        if request_json.len() > MAX_WASM_REQUEST_BYTES {
            return Err(WasmAuthenticatorError::InvalidPayload(format!(
                "request exceeds {MAX_WASM_REQUEST_BYTES} bytes"
            )));
        }

        let mut store = Store::new(
            &self.engine,
            HostState {
                http_client,
                runtime,
            },
        );
        let linker = build_linker(&self.engine)?;
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(wasm_execution_error)?;
        let Some(func) = instance.get_func(&mut store, export_name) else {
            return Ok(None);
        };
        let func = func
            .typed::<(i32, i32), i64>(&store)
            .map_err(wasm_execution_error)?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| WasmAuthenticatorError::MissingExport("alloc"))?;
        let dealloc = optional_dealloc(&mut store, &instance)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(WasmAuthenticatorError::MissingExport("memory"))?;

        let request_len = checked_i32_len(request_json.len())?;
        let request_ptr = alloc
            .call(&mut store, request_len)
            .map_err(wasm_execution_error)?;
        if request_ptr < 0 {
            return Err(WasmAuthenticatorError::InvalidPayload(
                "alloc returned a negative pointer".to_owned(),
            ));
        }
        memory
            .write(&mut store, request_ptr as usize, request_json)
            .map_err(|error| WasmAuthenticatorError::Memory(error.to_string()))?;

        let packed = func
            .call(&mut store, (request_ptr, request_len))
            .map_err(wasm_execution_error)?;
        let (response_ptr, response_len) = unpack_ptr_len(packed)?;
        if response_len as usize > MAX_WASM_RESPONSE_BYTES {
            return Err(WasmAuthenticatorError::InvalidPayload(format!(
                "response exceeds {MAX_WASM_RESPONSE_BYTES} bytes"
            )));
        }
        let mut response = vec![0u8; response_len as usize];
        memory
            .read(&store, response_ptr as usize, &mut response)
            .map_err(|error| WasmAuthenticatorError::Memory(error.to_string()))?;

        if let Some(dealloc) = dealloc {
            if request_ptr as u32 != response_ptr || request_len as u32 != response_len {
                let _ = dealloc.call(&mut store, (request_ptr, request_len));
            }
            let _ = dealloc.call(&mut store, (response_ptr as i32, response_len as i32));
        }

        Ok(Some(response))
    }
}

fn build_linker(engine: &WasmEngine) -> Result<Linker<HostState>, WasmAuthenticatorError> {
    let mut linker = Linker::new(engine);
    linker
        .func_wrap("env", "fetch", host_fetch)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "fetch", host_fetch)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "log", host_log)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "log", host_log)
        .map_err(wasm_execution_error)?;
    Ok(linker)
}

fn optional_dealloc(
    store: &mut Store<HostState>,
    instance: &Instance,
) -> Result<Option<wasmtime::TypedFunc<(i32, i32), ()>>, WasmAuthenticatorError> {
    let Some(func) = instance.get_func(&mut *store, "dealloc") else {
        return Ok(None);
    };
    func.typed::<(i32, i32), ()>(&mut *store)
        .map(Some)
        .map_err(wasm_execution_error)
}

fn host_fetch(
    mut caller: Caller<'_, HostState>,
    request_ptr: i32,
    request_len: i32,
    response_ptr: i32,
    response_capacity: i32,
) -> i32 {
    let response = match read_guest_bytes(&mut caller, request_ptr, request_len) {
        Ok(bytes) => match serde_json::from_slice::<FetchRequest>(&bytes) {
            Ok(request) => execute_fetch(caller.data(), request),
            Err(error) => FetchResponse::error(format!("invalid fetch request JSON: {error}")),
        },
        Err(error) => FetchResponse::error(error),
    };

    match serde_json::to_vec(&response) {
        Ok(bytes) => write_guest_bytes(&mut caller, response_ptr, response_capacity, &bytes),
        Err(error) => {
            let fallback =
                format!(r#"{{"ok":false,"error":"failed to encode response: {error}"}}"#);
            write_guest_bytes(
                &mut caller,
                response_ptr,
                response_capacity,
                fallback.as_bytes(),
            )
        }
    }
}

fn host_log(mut caller: Caller<'_, HostState>, level: i32, ptr: i32, len: i32) {
    let message = read_guest_bytes(&mut caller, ptr, len)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| "<invalid guest log message>".to_owned());
    match level {
        1 => tracing::error!(target: "wasm_auth", "{message}"),
        2 => tracing::warn!(target: "wasm_auth", "{message}"),
        4 => tracing::debug!(target: "wasm_auth", "{message}"),
        5 => tracing::trace!(target: "wasm_auth", "{message}"),
        _ => tracing::info!(target: "wasm_auth", "{message}"),
    }
}

fn read_guest_bytes(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, String> {
    if ptr < 0 || len < 0 {
        return Err("guest pointer and length must be non-negative".to_owned());
    }
    let len = len as usize;
    if len > MAX_WASM_RESPONSE_BYTES {
        return Err(format!(
            "guest buffer length exceeds {MAX_WASM_RESPONSE_BYTES} bytes"
        ));
    }
    let memory = guest_memory(caller)?;
    let mut bytes = vec![0u8; len];
    memory
        .read(&*caller, ptr as usize, &mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn write_guest_bytes(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    capacity: i32,
    bytes: &[u8],
) -> i32 {
    if ptr < 0 || capacity < 0 {
        return -1;
    }
    let Ok(required_len) = checked_i32_len(bytes.len()) else {
        return i32::MIN;
    };
    if bytes.len() > capacity as usize {
        return -required_len;
    }
    let Ok(memory) = guest_memory(caller) else {
        return -1;
    };
    match memory.write(caller, ptr as usize, bytes) {
        Ok(()) => required_len,
        Err(_) => -1,
    }
}

fn guest_memory(caller: &mut Caller<'_, HostState>) -> Result<Memory, String> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| "guest does not export memory".to_owned())
}

fn execute_fetch(state: &HostState, request: FetchRequest) -> FetchResponse {
    let url = match Url::parse(&request.url) {
        Ok(url) => url,
        Err(error) => return FetchResponse::error(format!("invalid URL: {error}")),
    };
    if url.scheme() != "https" {
        return FetchResponse::error("fetch only allows https URLs".to_owned());
    }
    let method = request
        .method
        .as_deref()
        .unwrap_or("GET")
        .parse::<Method>()
        .unwrap_or(Method::GET);
    let mut builder = state.http_client.request(method, url);
    for (name, value) in request.headers {
        builder = builder.header(name, value);
    }
    if let Some(timeout_ms) = request.timeout_ms {
        builder = builder.timeout(Duration::from_millis(timeout_ms).min(MAX_FETCH_TIMEOUT));
    }
    if let Some(body) = request.body {
        builder = builder.body(body.into_bytes());
    }

    state.runtime.block_on(async move {
        match builder.send().await {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();
                let status_text = status.canonical_reason().unwrap_or("").to_owned();
                let ok = status.is_success();
                let mut headers = HashMap::new();
                for (name, value) in response.headers() {
                    if let Ok(value) = value.to_str() {
                        headers.insert(name.as_str().to_owned(), value.to_owned());
                    }
                }
                match response.bytes().await {
                    Ok(body) => FetchResponse {
                        ok,
                        status: status_code,
                        status_text,
                        headers,
                        body: Some(String::from_utf8_lossy(&body).into_owned()),
                        error: None,
                    },
                    Err(error) => FetchResponse::error(format!("failed to read response: {error}")),
                }
            }
            Err(error) => FetchResponse::error(error.to_string()),
        }
    })
}

fn checked_i32_len(len: usize) -> Result<i32, WasmAuthenticatorError> {
    i32::try_from(len)
        .map_err(|_| WasmAuthenticatorError::InvalidPayload("buffer too large".to_owned()))
}

fn unpack_ptr_len(packed: i64) -> Result<(u32, u32), WasmAuthenticatorError> {
    if packed < 0 {
        return Err(WasmAuthenticatorError::InvalidPayload(format!(
            "guest returned negative pointer/length value {packed}"
        )));
    }
    let packed = packed as u64;
    Ok(((packed >> 32) as u32, (packed & 0xffff_ffff) as u32))
}

fn wasm_execution_error(error: impl std::fmt::Display) -> WasmAuthenticatorError {
    WasmAuthenticatorError::Execution(error.to_string())
}

struct HostState {
    http_client: reqwest::Client,
    runtime: Handle,
}

#[derive(Serialize)]
struct WasmAuthenticateRequest {
    username: String,
    password: Option<String>,
    auxiliary_data: WasmAuthenticateAuxiliaryData,
}

#[derive(Serialize)]
struct WasmExternalAuthenticateRequest {
    claims: WasmExternalAuthClaims,
    auxiliary_data: WasmAuthenticateAuxiliaryData,
}

#[derive(Serialize)]
struct WasmLanguageRequest {
    username: Option<String>,
    auxiliary_data: WasmAuthenticateAuxiliaryData,
}

#[derive(Serialize)]
struct WasmAuthenticateAuxiliaryData {
    certificate_hash_base64: Option<String>,
    session_id: u32,
    ip_address: IpAddr,
    version: Option<ProtocolVersion>,
    client_name: Option<String>,
    os_name: Option<String>,
    os_version: Option<String>,
}

impl From<&AuthenticateAuxiliaryData> for WasmAuthenticateAuxiliaryData {
    fn from(value: &AuthenticateAuxiliaryData) -> Self {
        Self {
            certificate_hash_base64: value
                .certificate_hash
                .as_ref()
                .map(|hash| BASE64_STANDARD.encode(hash)),
            session_id: value.session_id,
            ip_address: value.ip_address,
            version: value.version,
            client_name: value.client_name.clone(),
            os_name: value.os_name.clone(),
            os_version: value.os_version.clone(),
        }
    }
}

#[derive(Serialize)]
struct WasmExternalAuthClaims {
    subject: u32,
    username: String,
    display_name: Option<String>,
    groups: Vec<String>,
}

impl From<&ExternalAuthClaims> for WasmExternalAuthClaims {
    fn from(value: &ExternalAuthClaims) -> Self {
        Self {
            subject: value.subject,
            username: value.username.clone(),
            display_name: value.display_name.clone(),
            groups: value.groups.clone(),
        }
    }
}

#[derive(Deserialize)]
struct WasmAuthenticateResponse {
    #[serde(default = "default_true")]
    accepted: bool,
    #[serde(default)]
    rejection: Option<String>,
    #[serde(default)]
    user_id: Option<u32>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    virtual_server_id: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    texture_url: Option<String>,
    #[serde(default)]
    comment_url: Option<String>,
}

impl WasmAuthenticateResponse {
    fn into_authenticate_result(self) -> Result<AuthenticateResult, AuthenticationRejection> {
        if !self.accepted {
            return Err(match self.rejection.as_deref() {
                Some("no_such_user") | Some("invalid_username") => {
                    AuthenticationRejection::NoSuchUser
                }
                Some("wrong_password") => AuthenticationRejection::WrongPassword,
                _ => AuthenticationRejection::RetryLater,
            });
        }
        Ok(AuthenticateResult {
            user_id: self.user_id,
            display_name: self.display_name,
            groups: self.groups,
            virtual_server_id: self.virtual_server_id,
            language: self
                .language
                .as_deref()
                .map(Language::from_code)
                .unwrap_or_default(),
            texture_url: self.texture_url,
            comment_url: self.comment_url,
        })
    }
}

#[derive(Deserialize)]
struct WasmLanguageResponse {
    language: String,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct FetchRequest {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    /// Plain-text (UTF-8) request body.
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Serialize)]
struct FetchResponse {
    ok: bool,
    /// HTTP status code; 0 when no HTTP response was received (network error).
    status: u16,
    status_text: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    error: Option<String>,
}

impl FetchResponse {
    fn error(error: String) -> Self {
        Self {
            ok: false,
            status: 0,
            status_text: String::new(),
            headers: HashMap::new(),
            body: None,
            error: Some(error),
        }
    }
}
