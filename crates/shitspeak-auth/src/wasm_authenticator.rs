use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time;
use wasmtime::{
    Caller, Config as WasmConfig, Engine as WasmEngine, Extern, ExternType, Instance, Linker,
    Memory, Module, Store, TypedFunc,
};

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};

use crate::Language;
use crate::config::{
    AuthenticatorBackend, AuthenticatorConfigSource, ExecAuthenticatorMode,
    default_wasm_authenticator_max_instances,
};
use crate::http_client;

use super::ExecAuthenticator;
use super::authenticator_json::{
    AuthenticatorJsonAuthenticateRequest, AuthenticatorJsonAuthenticateResponse,
    AuthenticatorJsonExternalAuthenticateRequest, authenticate_result_from_external_claims,
};
use super::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    ExternalAuthClaims, RegisteredUser,
};

const MAX_WASM_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_WASM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WASM_AUTH_CACHE_KEY_BYTES: usize = 1024;
const MAX_WASM_AUTH_CACHE_VALUE_BYTES: usize = 64 * 1024;
const MAX_WASM_AUTH_CACHE_ENTRIES: usize = 1024;
const MAX_WASM_AUTH_STATE_KEY_BYTES: usize = 1024;
const MAX_WASM_AUTH_STATE_VALUE_BYTES: usize = MAX_WASM_RESPONSE_BYTES;
const MAX_WASM_AUTH_FILE_PATH_BYTES: usize = 1024;
const MAX_WASM_AUTH_OPEN_STREAMS: usize = 64;
const WASM_AUTH_STATE_SUBDIR: &str = "wasm_authenticator";
const MAX_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
const FILE_OPEN_READ: i32 = 0x01;
const FILE_OPEN_WRITE: i32 = 0x02;
const FILE_OPEN_CREATE: i32 = 0x04;
const FILE_OPEN_TRUNCATE: i32 = 0x08;
const FILE_OPEN_APPEND: i32 = 0x10;
static WASM_AUTH_STATE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    #[error("failed to build WASM authenticator HTTP client: {source}")]
    HttpClient { source: reqwest::Error },
    #[error("invalid WASM authenticator file access config: {0}")]
    FileAccessConfig(String),
    #[error("WASM authenticator JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum AuthenticatorBackendError {
    #[error(transparent)]
    Wasm(#[from] WasmAuthenticatorError),
    #[error(transparent)]
    Exec(#[from] super::ExecAuthenticatorError),
    #[error("authenticator.backend = \"wasm\" requires authenticator.wasm.path")]
    MissingWasmPath,
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
            is_superuser: username == "admin",
            virtual_server_id: None,
            language: Language::default(),
            max_bandwidth: None,
            texture_url: None,
            comment_url: None,
        })
    }
}

pub struct ReloadableAuthenticator {
    inner: RwLock<Arc<dyn Authenticator>>,
    reloads_from_config: bool,
}

impl ReloadableAuthenticator {
    pub fn fixed<A: Authenticator>(authenticator: A) -> Self {
        let inner: Arc<dyn Authenticator> = Arc::new(authenticator);
        Self {
            inner: RwLock::new(inner),
            reloads_from_config: false,
        }
    }

    pub fn from_config(
        config: &(impl AuthenticatorConfigSource + ?Sized),
    ) -> Result<Self, AuthenticatorBackendError> {
        Ok(Self {
            inner: RwLock::new(load_authenticator_from_config(config)?),
            reloads_from_config: true,
        })
    }

    pub fn prepare_reload(
        &self,
        config: &(impl AuthenticatorConfigSource + ?Sized),
    ) -> Result<Option<Arc<dyn Authenticator>>, AuthenticatorBackendError> {
        if !self.reloads_from_config {
            return Ok(None);
        }
        load_authenticator_from_config(config).map(Some)
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

fn load_authenticator_from_config(
    config: &(impl AuthenticatorConfigSource + ?Sized),
) -> Result<Arc<dyn Authenticator>, AuthenticatorBackendError> {
    let authenticator = config.authenticator_config();
    let wasm = authenticator.wasm();
    match authenticator.backend() {
        AuthenticatorBackend::Demo => Ok(Arc::new(DemoAuthenticator)),
        AuthenticatorBackend::Wasm => {
            let Some(path) = wasm.path().map(PathBuf::as_path) else {
                return Err(AuthenticatorBackendError::MissingWasmPath);
            };
            load_wasm_authenticator(
                path,
                config.authenticator_blob_storage_dir(),
                wasm.max_instances(),
                wasm.file_access_dir(),
                wasm.working_dir().map(PathBuf::as_path),
            )
            .map_err(AuthenticatorBackendError::Wasm)
        }
        AuthenticatorBackend::Exec => match authenticator.exec().mode() {
            ExecAuthenticatorMode::Ephemeral => Ok(Arc::new(ExecAuthenticator::ephemeral(
                authenticator.exec().clone(),
            )?)),
            ExecAuthenticatorMode::LongRunning => Ok(Arc::new(ExecAuthenticator::long_running(
                authenticator.exec().clone(),
            )?)),
        },
    }
}

fn load_wasm_authenticator(
    path: &Path,
    storage_dir: Option<&Path>,
    max_instances: usize,
    file_access_dirs: &[PathBuf],
    working_dir: Option<&Path>,
) -> Result<Arc<dyn Authenticator>, WasmAuthenticatorError> {
    Ok(Arc::new(WasmAuthenticator::from_file_with_max_instances(
        path,
        storage_dir,
        max_instances,
        file_access_dirs,
        working_dir,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthenticatorConfig, ExecAuthenticatorConfig, WasmAuthenticatorConfig};

    #[test]
    fn demo_backend_ignores_wasm_path() {
        let config = AuthenticatorConfig::new(AuthenticatorBackend::Demo)
            .with_wasm(WasmAuthenticatorConfig::new("auth.wasm"));

        assert!(load_authenticator_from_config(&config).is_ok());
    }

    #[test]
    fn wasm_config_defaults_to_active_cpu_count() {
        let active_cpus = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        assert_eq!(
            WasmAuthenticatorConfig::default().max_instances(),
            active_cpus
        );
        assert_eq!(
            WasmAuthenticatorConfig::new("auth.wasm").max_instances(),
            active_cpus
        );
        assert_eq!(
            WasmAuthenticatorConfig::new("auth.wasm")
                .with_max_instances(0)
                .max_instances(),
            1
        );
    }

    #[test]
    fn explicit_wasm_backend_requires_wasm_path() {
        let config = AuthenticatorConfig::new(AuthenticatorBackend::Wasm);

        let error = match load_authenticator_from_config(&config) {
            Ok(_) => panic!("missing WASM path was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, AuthenticatorBackendError::MissingWasmPath));
    }

    #[test]
    fn explicit_wasm_backend_uses_nested_wasm_path() {
        let config = AuthenticatorConfig::new(AuthenticatorBackend::Wasm)
            .with_wasm(WasmAuthenticatorConfig::new("missing-auth.wasm"));

        let error = match load_authenticator_from_config(&config) {
            Ok(_) => panic!("missing WASM file was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            AuthenticatorBackendError::Wasm(WasmAuthenticatorError::Read { path, .. })
                if path == PathBuf::from("missing-auth.wasm")
        ));
    }

    #[test]
    fn exec_backend_requires_command() {
        let config = AuthenticatorConfig::new(AuthenticatorBackend::Exec)
            .with_exec(ExecAuthenticatorConfig::default());

        let error = match load_authenticator_from_config(&config) {
            Ok(_) => panic!("missing exec command was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            AuthenticatorBackendError::Exec(crate::ExecAuthenticatorError::MissingCommand)
        ));
    }
}

pub struct WasmAuthenticator {
    module: Arc<CompiledWasmAuthenticator>,
}

impl WasmAuthenticator {
    pub fn from_file(
        path: &Path,
        storage_dir: Option<&Path>,
        file_access_dirs: &[PathBuf],
        working_dir: Option<&Path>,
    ) -> Result<Self, WasmAuthenticatorError> {
        Self::from_file_with_max_instances(
            path,
            storage_dir,
            default_wasm_authenticator_max_instances(),
            file_access_dirs,
            working_dir,
        )
    }

    pub fn from_file_with_max_instances(
        path: &Path,
        storage_dir: Option<&Path>,
        max_instances: usize,
        file_access_dirs: &[PathBuf],
        working_dir: Option<&Path>,
    ) -> Result<Self, WasmAuthenticatorError> {
        let bytes = std::fs::read(path).map_err(|source| WasmAuthenticatorError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config = WasmConfig::new();
        let engine =
            WasmEngine::new(&config).map_err(|source| WasmAuthenticatorError::Compile {
                path: path.to_path_buf(),
                error: source.to_string(),
            })?;
        let module =
            Module::new(&engine, &bytes).map_err(|source| WasmAuthenticatorError::Compile {
                path: path.to_path_buf(),
                error: source.to_string(),
            })?;

        tracing::info!(path = %path.display(), "loaded WASM authenticator");
        let http_client =
            http_client::build_with_webpki_fallback(MAX_FETCH_TIMEOUT, "WASM authenticator fetch")
                .map_err(|source| WasmAuthenticatorError::HttpClient { source })?;
        let exports = WasmAuthenticatorExports::from_module(&module);
        let linker = build_linker(&engine)?;
        Ok(Self {
            module: Arc::new(CompiledWasmAuthenticator {
                engine,
                module,
                linker,
                exports,
                http_client,
                cache: Arc::new(WasmAuthCache::default()),
                state: Arc::new(WasmAuthState::new(
                    storage_dir,
                    file_access_dirs,
                    working_dir,
                )?),
                instance_pool: Mutex::new(WasmAuthenticatorInstancePool::default()),
                instance_slots: Arc::new(Semaphore::new(max_instances.max(1))),
                instance_creation: Mutex::new(()),
            }),
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
        if self
            .module
            .optional_func_export_available(export_name)
            .is_some_and(|available| !available)
        {
            return Ok(None);
        }
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

        module.invoke_json_export(export_name, &request_json).await
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
        let request = AuthenticatorJsonAuthenticateRequest::new(
            username.to_owned(),
            password.map(ToOwned::to_owned),
            auxiliary_data,
        );
        match self
            .invoke_required::<_, AuthenticatorJsonAuthenticateResponse>("authenticate", request)
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
        let request = AuthenticatorJsonExternalAuthenticateRequest::new(claims, auxiliary_data);
        match self
            .invoke_optional::<_, AuthenticatorJsonAuthenticateResponse>(
                "authenticate_external",
                request,
            )
            .await
        {
            Ok(Some(response)) => response.into_authenticate_result(),
            Ok(None) => Ok(authenticate_result_from_external_claims(claims)),
            Err(error) => {
                tracing::warn!(error = %error, "WASM external authenticator failed");
                Err(AuthenticationRejection::RetryLater)
            }
        }
    }
}

struct CompiledWasmAuthenticator {
    engine: WasmEngine,
    module: Module,
    linker: Linker<HostState>,
    exports: WasmAuthenticatorExports,
    http_client: reqwest::Client,
    cache: Arc<WasmAuthCache>,
    state: Arc<WasmAuthState>,
    instance_pool: Mutex<WasmAuthenticatorInstancePool>,
    instance_slots: Arc<Semaphore>,
    instance_creation: Mutex<()>,
}

#[derive(Clone, Copy, Debug)]
struct WasmAuthenticatorExports {
    authenticate_external: bool,
}

impl WasmAuthenticatorExports {
    fn from_module(module: &Module) -> Self {
        Self {
            authenticate_external: module_has_func_export(module, "authenticate_external"),
        }
    }

    fn optional_func_export_available(&self, export_name: &str) -> Option<bool> {
        match export_name {
            "authenticate_external" => Some(self.authenticate_external),
            _ => None,
        }
    }
}

impl CompiledWasmAuthenticator {
    fn optional_func_export_available(&self, export_name: &str) -> Option<bool> {
        self.exports.optional_func_export_available(export_name)
    }

    async fn invoke_json_export(
        &self,
        export_name: &'static str,
        request_json: &[u8],
    ) -> Result<Option<Vec<u8>>, WasmAuthenticatorError> {
        if request_json.len() > MAX_WASM_REQUEST_BYTES {
            return Err(WasmAuthenticatorError::InvalidPayload(format!(
                "request exceeds {MAX_WASM_REQUEST_BYTES} bytes"
            )));
        }

        let mut checkout = self.checkout_instance().await?;
        let Some(func) = checkout
            .instance
            .instance
            .get_func(&mut checkout.instance.store, export_name)
        else {
            self.release_instance(checkout).await;
            return Ok(None);
        };
        let func = func
            .typed::<(i32, i32), i64>(&checkout.instance.store)
            .map_err(wasm_execution_error)?;

        let request_len = checked_i32_len(request_json.len())?;
        let request_ptr = checkout
            .instance
            .alloc
            .call_async(&mut checkout.instance.store, request_len)
            .await
            .map_err(wasm_execution_error)?;
        if request_ptr < 0 {
            return Err(WasmAuthenticatorError::InvalidPayload(
                "alloc returned a negative pointer".to_owned(),
            ));
        }
        checkout
            .instance
            .memory
            .write(
                &mut checkout.instance.store,
                request_ptr as usize,
                request_json,
            )
            .map_err(|error| WasmAuthenticatorError::Memory(error.to_string()))?;

        let packed = func
            .call_async(&mut checkout.instance.store, (request_ptr, request_len))
            .await
            .map_err(wasm_execution_error)?;
        let (response_ptr, response_len) = unpack_ptr_len(packed)?;
        if response_len as usize > MAX_WASM_RESPONSE_BYTES {
            return Err(WasmAuthenticatorError::InvalidPayload(format!(
                "response exceeds {MAX_WASM_RESPONSE_BYTES} bytes"
            )));
        }
        let mut response = vec![0u8; response_len as usize];
        checkout
            .instance
            .memory
            .read(
                &checkout.instance.store,
                response_ptr as usize,
                &mut response,
            )
            .map_err(|error| WasmAuthenticatorError::Memory(error.to_string()))?;

        if let Some(dealloc) = checkout.instance.dealloc.as_ref() {
            if request_ptr as u32 != response_ptr || request_len as u32 != response_len {
                let _ = dealloc
                    .call_async(&mut checkout.instance.store, (request_ptr, request_len))
                    .await;
            }
            let _ = dealloc
                .call_async(
                    &mut checkout.instance.store,
                    (response_ptr as i32, response_len as i32),
                )
                .await;
        }

        self.release_instance(checkout).await;
        Ok(Some(response))
    }

    async fn checkout_instance(&self) -> Result<WasmAuthenticatorCheckout, WasmAuthenticatorError> {
        let permit = Arc::clone(&self.instance_slots)
            .acquire_owned()
            .await
            .map_err(|_| {
                WasmAuthenticatorError::Execution(
                    "WASM authenticator instance limiter closed".to_owned(),
                )
            })?;

        if let Some(instance) = self.instance_pool.lock().await.instances.pop() {
            return Ok(WasmAuthenticatorCheckout { instance, permit });
        }

        let _creation = self.instance_creation.lock().await;
        if let Some(instance) = self.instance_pool.lock().await.instances.pop() {
            return Ok(WasmAuthenticatorCheckout { instance, permit });
        }

        let mut store = Store::new(
            &self.engine,
            HostState {
                http_client: self.http_client.clone(),
                cache: Arc::clone(&self.cache),
                state: Arc::clone(&self.state),
                streams: HostStreams::default(),
            },
        );
        let instance = self
            .linker
            .instantiate_async(&mut store, &self.module)
            .await
            .map_err(wasm_execution_error)?;
        let instance = WasmAuthenticatorInstance::new(store, instance)?;
        Ok(WasmAuthenticatorCheckout { instance, permit })
    }

    async fn release_instance(&self, checkout: WasmAuthenticatorCheckout) {
        let WasmAuthenticatorCheckout {
            mut instance,
            permit,
        } = checkout;
        instance.store.data_mut().streams.clear();
        self.instance_pool.lock().await.instances.push(instance);
        drop(permit);
    }
}

#[derive(Default)]
struct WasmAuthenticatorInstancePool {
    instances: Vec<WasmAuthenticatorInstance>,
}

struct WasmAuthenticatorCheckout {
    instance: WasmAuthenticatorInstance,
    permit: OwnedSemaphorePermit,
}

struct WasmAuthenticatorInstance {
    store: Store<HostState>,
    instance: Instance,
    alloc: TypedFunc<i32, i32>,
    dealloc: Option<TypedFunc<(i32, i32), ()>>,
    memory: Memory,
}

impl WasmAuthenticatorInstance {
    fn new(
        mut store: Store<HostState>,
        instance: Instance,
    ) -> Result<Self, WasmAuthenticatorError> {
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| WasmAuthenticatorError::MissingExport("alloc"))?;
        let dealloc = optional_dealloc(&mut store, &instance)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(WasmAuthenticatorError::MissingExport("memory"))?;
        Ok(Self {
            store,
            instance,
            alloc,
            dealloc,
            memory,
        })
    }
}

fn module_has_func_export(module: &Module, export_name: &str) -> bool {
    matches!(module.get_export(export_name), Some(ExternType::Func(_)))
}

fn build_linker(engine: &WasmEngine) -> Result<Linker<HostState>, WasmAuthenticatorError> {
    let mut linker = Linker::new(engine);
    linker
        .func_wrap_async("env", "fetch", |caller, params| {
            Box::new(host_fetch(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "fetch", |caller, params| {
            Box::new(host_fetch(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("env", "tcp_open", |caller, params| {
            Box::new(host_tcp_open(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "tcp_open", |caller, params| {
            Box::new(host_tcp_open(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("env", "udp_open", |caller, params| {
            Box::new(host_udp_open(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "udp_open", |caller, params| {
            Box::new(host_udp_open(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("env", "file_open", |caller, params| {
            Box::new(host_file_open(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "file_open", |caller, params| {
            Box::new(host_file_open(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("env", "stream_read", |caller, params| {
            Box::new(host_stream_read(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "stream_read", |caller, params| {
            Box::new(host_stream_read(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("env", "stream_write", |caller, params| {
            Box::new(host_stream_write(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "stream_write", |caller, params| {
            Box::new(host_stream_write(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("env", "stream_seek", |caller, params| {
            Box::new(host_stream_seek(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "stream_seek", |caller, params| {
            Box::new(host_stream_seek(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "stream_close", host_stream_close)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "stream_close", host_stream_close)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("env", "file_delete", |caller, params| {
            Box::new(host_file_delete(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap_async("shitspeak", "file_delete", |caller, params| {
            Box::new(host_file_delete(caller, params))
        })
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "log", host_log)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "log", host_log)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "cache_get", host_cache_get)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "cache_get", host_cache_get)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "cache_put", host_cache_put)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "cache_put", host_cache_put)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "cache_delete", host_cache_delete)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "cache_delete", host_cache_delete)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "cache_clear", host_cache_clear)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "cache_clear", host_cache_clear)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "state_get", host_state_get)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "state_get", host_state_get)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "state_put", host_state_put)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "state_put", host_state_put)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "state_delete", host_state_delete)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "state_delete", host_state_delete)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("env", "state_clear", host_state_clear)
        .map_err(wasm_execution_error)?;
    linker
        .func_wrap("shitspeak", "state_clear", host_state_clear)
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

async fn host_fetch(
    mut caller: Caller<'_, HostState>,
    (request_ptr, request_len, response_ptr, response_capacity): (i32, i32, i32, i32),
) -> i32 {
    let response = match read_guest_bytes(&mut caller, request_ptr, request_len) {
        Ok(bytes) => match serde_json::from_slice::<FetchRequest>(&bytes) {
            Ok(request) => execute_fetch(caller.data(), request).await,
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

async fn host_tcp_open(
    mut caller: Caller<'_, HostState>,
    (addr_ptr, addr_len, timeout_ms): (i32, i32, i32),
) -> i32 {
    let addr = match read_socket_addr(&mut caller, addr_ptr, addr_len) {
        Ok(addr) => addr,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth TCP address");
            return -1;
        }
    };
    let stream = match with_timeout(timeout_ms, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::warn!(target: "wasm_auth", %addr, error = %error, "WASM auth TCP open failed");
            return -1;
        }
        Err(error) => {
            tracing::warn!(target: "wasm_auth", %addr, error = %error, "WASM auth TCP open timed out");
            return -1;
        }
    };
    caller.data_mut().streams.insert(HostStream::Tcp(stream))
}

async fn host_udp_open(mut caller: Caller<'_, HostState>, (addr_ptr, addr_len): (i32, i32)) -> i32 {
    let addr = match read_socket_addr(&mut caller, addr_ptr, addr_len) {
        Ok(addr) => addr,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth UDP address");
            return -1;
        }
    };
    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", %addr, error = %error, "WASM auth UDP bind failed");
            return -1;
        }
    };
    if let Err(error) = socket.connect(addr).await {
        tracing::warn!(target: "wasm_auth", %addr, error = %error, "WASM auth UDP connect failed");
        return -1;
    }
    caller.data_mut().streams.insert(HostStream::Udp(socket))
}

async fn host_file_open(
    mut caller: Caller<'_, HostState>,
    (path_ptr, path_len, flags): (i32, i32, i32),
) -> i32 {
    let path = match read_guest_string(
        &mut caller,
        path_ptr,
        path_len,
        MAX_WASM_AUTH_FILE_PATH_BYTES,
    ) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth file path");
            return -1;
        }
    };
    let file = match caller.data().state.open_file(&path, flags).await {
        Ok(Some(file)) => file,
        Ok(None) => return 0,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", path, error = %error, "WASM auth file open failed");
            return -1;
        }
    };
    caller.data_mut().streams.insert(HostStream::File(file))
}

async fn host_stream_read(
    mut caller: Caller<'_, HostState>,
    (handle, response_ptr, response_capacity, timeout_ms): (i32, i32, i32, i32),
) -> i32 {
    if response_ptr < 0 || response_capacity < 0 {
        return -1;
    }
    let Ok(capacity) = usize::try_from(response_capacity) else {
        return -1;
    };
    if capacity > MAX_WASM_RESPONSE_BYTES {
        return -1;
    }
    let mut buf = vec![0u8; capacity];
    let result = match caller.data_mut().streams.get_mut(handle) {
        Some(HostStream::Tcp(stream)) => with_timeout(timeout_ms, stream.read(&mut buf)).await,
        Some(HostStream::Udp(socket)) => with_timeout(timeout_ms, socket.recv(&mut buf)).await,
        Some(HostStream::File(file)) => with_timeout(timeout_ms, file.read(&mut buf)).await,
        None => return -1,
    };
    let n = match result {
        Ok(Ok(n)) => n,
        Ok(Err(error)) => {
            tracing::warn!(target: "wasm_auth", handle, error = %error, "WASM auth stream read failed");
            return -1;
        }
        Err(_) => return 0,
    };
    write_guest_bytes(&mut caller, response_ptr, response_capacity, &buf[..n])
}

async fn host_stream_write(
    mut caller: Caller<'_, HostState>,
    (handle, request_ptr, request_len, timeout_ms): (i32, i32, i32, i32),
) -> i32 {
    let bytes = match read_guest_bytes(&mut caller, request_ptr, request_len) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth stream write buffer");
            return -1;
        }
    };
    let result = match caller.data_mut().streams.get_mut(handle) {
        Some(HostStream::Tcp(stream)) => with_timeout(timeout_ms, stream.write(&bytes)).await,
        Some(HostStream::Udp(socket)) => with_timeout(timeout_ms, socket.send(&bytes)).await,
        Some(HostStream::File(file)) => with_timeout(timeout_ms, file.write(&bytes)).await,
        None => return -1,
    };
    match result {
        Ok(Ok(n)) => checked_i32_plain(n),
        Ok(Err(error)) => {
            tracing::warn!(target: "wasm_auth", handle, error = %error, "WASM auth stream write failed");
            -1
        }
        Err(_) => -1,
    }
}

async fn host_stream_seek(
    mut caller: Caller<'_, HostState>,
    (handle, position): (i32, i64),
) -> i32 {
    if position < 0 {
        return -1;
    }
    let Some(HostStream::File(file)) = caller.data_mut().streams.get_mut(handle) else {
        return -1;
    };
    match file.seek(io::SeekFrom::Start(position as u64)).await {
        Ok(_) => 1,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", handle, error = %error, "WASM auth file seek failed");
            -1
        }
    }
}

fn host_stream_close(mut caller: Caller<'_, HostState>, handle: i32) -> i32 {
    if caller.data_mut().streams.remove(handle).is_some() {
        1
    } else {
        0
    }
}

async fn host_file_delete(
    mut caller: Caller<'_, HostState>,
    (path_ptr, path_len): (i32, i32),
) -> i32 {
    let path = match read_guest_string(
        &mut caller,
        path_ptr,
        path_len,
        MAX_WASM_AUTH_FILE_PATH_BYTES,
    ) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth file delete path");
            return -1;
        }
    };
    match caller.data().state.file_delete(&path).await {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", path, error = %error, "WASM auth file delete failed");
            -1
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

fn host_cache_get(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    response_ptr: i32,
    response_capacity: i32,
) -> i32 {
    let key = match read_cache_key(&mut caller, key_ptr, key_len) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth cache get");
            return -1;
        }
    };
    let Some(value) = caller.data().cache.get(&key) else {
        return 0;
    };
    write_guest_bytes(&mut caller, response_ptr, response_capacity, &value)
}

fn host_cache_put(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> i32 {
    let key = match read_cache_key(&mut caller, key_ptr, key_len) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth cache put key");
            return -1;
        }
    };
    if value_len <= 0 || value_len as usize > MAX_WASM_AUTH_CACHE_VALUE_BYTES {
        tracing::warn!(
            target: "wasm_auth",
            value_len,
            "invalid WASM auth cache put value length"
        );
        return -1;
    }
    let value = match read_guest_bytes(&mut caller, value_ptr, value_len) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth cache put value");
            return -1;
        }
    };
    caller.data().cache.put(key, value);
    1
}

fn host_cache_delete(mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32) -> i32 {
    let key = match read_cache_key(&mut caller, key_ptr, key_len) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth cache delete");
            return -1;
        }
    };
    if caller.data().cache.delete(&key) {
        1
    } else {
        0
    }
}

fn host_cache_clear(caller: Caller<'_, HostState>) -> i32 {
    caller.data().cache.clear();
    1
}

fn host_state_get(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    response_ptr: i32,
    response_capacity: i32,
) -> i32 {
    let key = match read_state_key(&mut caller, key_ptr, key_len) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth state get");
            return -1;
        }
    };
    let value = match caller.data().state.get(&key) {
        Ok(Some(value)) => value,
        Ok(None) => return 0,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error = %error, "WASM auth state get failed");
            return -1;
        }
    };
    write_guest_bytes(&mut caller, response_ptr, response_capacity, &value)
}

fn host_state_put(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> i32 {
    let key = match read_state_key(&mut caller, key_ptr, key_len) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth state put key");
            return -1;
        }
    };
    if value_len <= 0 || value_len as usize > MAX_WASM_AUTH_STATE_VALUE_BYTES {
        tracing::warn!(
            target: "wasm_auth",
            value_len,
            "invalid WASM auth state put value length"
        );
        return -1;
    }
    let value = match read_guest_bytes(&mut caller, value_ptr, value_len) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth state put value");
            return -1;
        }
    };
    match caller.data().state.put(&key, &value) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error = %error, "WASM auth state put failed");
            -1
        }
    }
}

fn host_state_delete(mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32) -> i32 {
    let key = match read_state_key(&mut caller, key_ptr, key_len) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error, "invalid WASM auth state delete");
            return -1;
        }
    };
    match caller.data().state.delete(&key) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error = %error, "WASM auth state delete failed");
            -1
        }
    }
}

fn host_state_clear(caller: Caller<'_, HostState>) -> i32 {
    match caller.data().state.clear() {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(error) => {
            tracing::warn!(target: "wasm_auth", error = %error, "WASM auth state clear failed");
            -1
        }
    }
}

fn read_cache_key(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, String> {
    if len < 0 || len as usize > MAX_WASM_AUTH_CACHE_KEY_BYTES {
        return Err(format!(
            "cache key length must be between 0 and {MAX_WASM_AUTH_CACHE_KEY_BYTES} bytes"
        ));
    }
    read_guest_bytes(caller, ptr, len)
}

fn read_state_key(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, String> {
    if len <= 0 || len as usize > MAX_WASM_AUTH_STATE_KEY_BYTES {
        return Err(format!(
            "state key length must be between 1 and {MAX_WASM_AUTH_STATE_KEY_BYTES} bytes"
        ));
    }
    read_guest_bytes(caller, ptr, len)
}

fn read_socket_addr(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<SocketAddr, String> {
    let addr = read_guest_string(caller, ptr, len, MAX_WASM_AUTH_FILE_PATH_BYTES)?;
    addr.parse::<SocketAddr>()
        .map_err(|error| format!("socket address must be host:port: {error}"))
}

fn read_guest_string(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
    max_len: usize,
) -> Result<String, String> {
    if len < 0 || len as usize > max_len {
        return Err(format!(
            "guest string length must be between 0 and {max_len} bytes"
        ));
    }
    String::from_utf8(read_guest_bytes(caller, ptr, len)?)
        .map_err(|error| format!("guest string must be UTF-8: {error}"))
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

async fn execute_fetch(state: &HostState, request: FetchRequest) -> FetchResponse {
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
}

fn checked_i32_len(len: usize) -> Result<i32, WasmAuthenticatorError> {
    i32::try_from(len)
        .map_err(|_| WasmAuthenticatorError::InvalidPayload("buffer too large".to_owned()))
}

fn checked_i32_plain(len: usize) -> i32 {
    i32::try_from(len).unwrap_or(i32::MAX)
}

async fn with_timeout<T>(
    timeout_ms: i32,
    future: impl std::future::Future<Output = T>,
) -> Result<T, time::error::Elapsed> {
    time::timeout(timeout_duration(timeout_ms), future).await
}

fn timeout_duration(timeout_ms: i32) -> Duration {
    if timeout_ms <= 0 {
        return MAX_SOCKET_TIMEOUT;
    }
    Duration::from_millis(timeout_ms as u64).min(MAX_SOCKET_TIMEOUT)
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
    cache: Arc<WasmAuthCache>,
    state: Arc<WasmAuthState>,
    streams: HostStreams,
}

#[derive(Default)]
struct HostStreams {
    next_handle: i32,
    streams: HashMap<i32, HostStream>,
}

impl HostStreams {
    fn insert(&mut self, stream: HostStream) -> i32 {
        if self.streams.len() >= MAX_WASM_AUTH_OPEN_STREAMS {
            return -1;
        }
        let handle = self.next_available_handle();
        if handle <= 0 {
            return -1;
        }
        self.streams.insert(handle, stream);
        handle
    }

    fn next_available_handle(&mut self) -> i32 {
        for _ in 0..i32::MAX {
            self.next_handle = self.next_handle.saturating_add(1);
            if self.next_handle <= 0 {
                self.next_handle = 1;
            }
            if !self.streams.contains_key(&self.next_handle) {
                return self.next_handle;
            }
        }
        -1
    }

    fn get_mut(&mut self, handle: i32) -> Option<&mut HostStream> {
        self.streams.get_mut(&handle)
    }

    fn remove(&mut self, handle: i32) -> Option<HostStream> {
        self.streams.remove(&handle)
    }

    fn clear(&mut self) {
        self.next_handle = 0;
        self.streams.clear();
    }
}

enum HostStream {
    Tcp(TcpStream),
    Udp(UdpSocket),
    File(File),
}

#[derive(Default)]
struct WasmAuthCache {
    inner: RwLock<WasmAuthCacheInner>,
}

impl WasmAuthCache {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner
            .read()
            .expect("WASM auth cache RwLock poisoned")
            .entries
            .get(key)
            .cloned()
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) {
        let mut inner = self.inner.write().expect("WASM auth cache RwLock poisoned");
        if inner.entries.contains_key(&key) {
            inner.entries.insert(key, value);
            return;
        }
        while inner.entries.len() >= MAX_WASM_AUTH_CACHE_ENTRIES {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.entries.remove(&oldest);
        }
        inner.order.push_back(key.clone());
        inner.entries.insert(key, value);
    }

    fn delete(&self, key: &[u8]) -> bool {
        let mut inner = self.inner.write().expect("WASM auth cache RwLock poisoned");
        let removed = inner.entries.remove(key).is_some();
        if removed {
            inner.order.retain(|candidate| candidate.as_slice() != key);
        }
        removed
    }

    fn clear(&self) {
        let mut inner = self.inner.write().expect("WASM auth cache RwLock poisoned");
        inner.entries.clear();
        inner.order.clear();
    }
}

#[derive(Default)]
struct WasmAuthCacheInner {
    entries: HashMap<Vec<u8>, Vec<u8>>,
    order: VecDeque<Vec<u8>>,
}

struct WasmAuthState {
    root: Option<PathBuf>,
    file_roots: Vec<PathBuf>,
    working_dir: PathBuf,
}

impl WasmAuthState {
    fn new(
        storage_dir: Option<&Path>,
        file_access_dirs: &[PathBuf],
        working_dir: Option<&Path>,
    ) -> Result<Self, WasmAuthenticatorError> {
        let process_dir = std::env::current_dir().map_err(|error| {
            WasmAuthenticatorError::FileAccessConfig(format!(
                "failed to resolve process current directory: {error}"
            ))
        })?;
        let working_dir = working_dir
            .map(|dir| normalize_host_path(&process_dir, dir))
            .transpose()
            .map_err(WasmAuthenticatorError::FileAccessConfig)?
            .unwrap_or_else(|| process_dir.clone());
        let file_roots = file_access_dirs
            .iter()
            .map(|dir| normalize_host_path(&process_dir, dir))
            .collect::<Result<Vec<_>, _>>()
            .map_err(WasmAuthenticatorError::FileAccessConfig)?;

        Ok(Self {
            root: storage_dir.map(|dir| dir.join(WASM_AUTH_STATE_SUBDIR)),
            file_roots,
            working_dir,
        })
    }

    fn get(&self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let Some(path) = self.path_for_key(key) else {
            return Ok(None);
        };
        match fs::read(&path) {
            Ok(value) if value.len() <= MAX_WASM_AUTH_STATE_VALUE_BYTES => Ok(Some(value)),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persistent state value exceeds host limit",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> io::Result<bool> {
        let Some(path) = self.path_for_key(key) else {
            return Ok(false);
        };
        let Some(parent) = path.parent() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "persistent state path has no parent",
            ));
        };
        fs::create_dir_all(parent)?;
        let tmp_seq = WASM_AUTH_STATE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp-{tmp_seq}"));
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(value)?;
            file.sync_data()?;
        }
        replace_file(&tmp, &path)?;
        Ok(true)
    }

    fn delete(&self, key: &[u8]) -> io::Result<bool> {
        let Some(path) = self.path_for_key(key) else {
            return Ok(false);
        };
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn clear(&self) -> io::Result<bool> {
        let Some(root) = self.root.as_ref() else {
            return Ok(false);
        };
        match fs::remove_dir_all(root) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    }

    fn path_for_key(&self, key: &[u8]) -> Option<PathBuf> {
        let root = self.root.as_ref()?;
        let key = sha1_hex(key);
        let (prefix, suffix) = key.split_at(2);
        Some(root.join(prefix).join(suffix))
    }

    async fn open_file(&self, path: &str, flags: i32) -> io::Result<Option<File>> {
        let Some(path) = self.path_for_file(path)? else {
            return Ok(None);
        };
        if let Some(parent) = path.parent() {
            if flags & FILE_OPEN_CREATE != 0 {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(flags & FILE_OPEN_READ != 0)
            .write(flags & FILE_OPEN_WRITE != 0)
            .create(flags & FILE_OPEN_CREATE != 0)
            .truncate(flags & FILE_OPEN_TRUNCATE != 0)
            .append(flags & FILE_OPEN_APPEND != 0);
        options.open(path).await.map(Some)
    }

    async fn file_delete(&self, path: &str) -> io::Result<bool> {
        let Some(path) = self.path_for_file(path)? else {
            return Ok(false);
        };
        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn path_for_file(&self, path: &str) -> io::Result<Option<PathBuf>> {
        if self.file_roots.is_empty() {
            return Ok(None);
        }
        if path.as_bytes().len() > MAX_WASM_AUTH_FILE_PATH_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file path exceeds host limit",
            ));
        }
        let path = Path::new(path);
        let resolved = if path.is_absolute() {
            normalize_guest_path(path)?
        } else {
            normalize_guest_path(&self.working_dir.join(path))?
        };
        if self
            .file_roots
            .iter()
            .any(|root| resolved.starts_with(root))
        {
            Ok(Some(resolved))
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file path is outside authenticator.wasm.file_access_dir",
            ));
        }
    }
}

fn normalize_host_path(base: &Path, path: &Path) -> Result<PathBuf, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    normalize_path_components(&path, true)
        .map_err(|error| format!("invalid path `{}`: {error}", path.display()))
}

fn normalize_guest_path(path: &Path) -> io::Result<PathBuf> {
    normalize_path_components(path, true)
}

fn normalize_path_components(path: &Path, allow_parent: bool) -> io::Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::ParentDir => {
                if allow_parent {
                    if !normalized.pop() {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "file path cannot traverse above root",
                        ));
                    }
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "file path cannot contain traversal",
                    ));
                }
            }
        }
    }
    Ok(normalized)
}

fn replace_file(src: &Path, dst: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        match fs::remove_file(dst) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::rename(src, dst)
}

fn sha1_hex(data: &[u8]) -> String {
    hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
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
