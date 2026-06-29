use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatorBackend {
    #[default]
    Demo,
    Wasm,
    Exec,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecAuthenticatorMode {
    #[default]
    #[serde(
        rename = "exec_ephemeral",
        alias = "ephemeral",
        alias = "executable_ephemeral"
    )]
    Ephemeral,
    #[serde(
        rename = "exec_long_running",
        alias = "long_running",
        alias = "executable_long_running"
    )]
    LongRunning,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecLongRunningRequestMode {
    #[default]
    Serialized,
    Async,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExecAuthenticatorConfig {
    #[serde(default)]
    mode: ExecAuthenticatorMode,
    #[serde(default)]
    long_running_request_mode: ExecLongRunningRequestMode,
    #[serde(default)]
    command: Option<PathBuf>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    working_dir: Option<PathBuf>,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    gid: Option<u32>,
    #[serde(default = "default_exec_authenticator_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_exec_authenticator_max_response_bytes")]
    max_response_bytes: usize,
}

impl Default for ExecAuthenticatorConfig {
    fn default() -> Self {
        Self {
            mode: ExecAuthenticatorMode::default(),
            long_running_request_mode: ExecLongRunningRequestMode::default(),
            command: None,
            args: Vec::new(),
            working_dir: None,
            uid: None,
            gid: None,
            timeout_ms: default_exec_authenticator_timeout_ms(),
            max_response_bytes: default_exec_authenticator_max_response_bytes(),
        }
    }
}

impl ExecAuthenticatorConfig {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: Some(command.into()),
            ..Self::default()
        }
    }

    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_mode(mut self, mode: ExecAuthenticatorMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_long_running_request_mode(mut self, mode: ExecLongRunningRequestMode) -> Self {
        self.long_running_request_mode = mode;
        self
    }

    pub fn with_working_dir(mut self, working_dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(working_dir.into());
        self
    }

    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn with_gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn command(&self) -> Option<&PathBuf> {
        self.command.as_ref()
    }

    pub fn mode(&self) -> ExecAuthenticatorMode {
        self.mode
    }

    pub fn long_running_request_mode(&self) -> ExecLongRunningRequestMode {
        self.long_running_request_mode
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn working_dir(&self) -> Option<&PathBuf> {
        self.working_dir.as_ref()
    }

    pub fn uid(&self) -> Option<u32> {
        self.uid
    }

    pub fn gid(&self) -> Option<u32> {
        self.gid
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WasmAuthenticatorConfig {
    /// Optional WASM authenticator module loaded by the binary at startup and
    /// on hot reload.
    #[serde(default)]
    path: Option<PathBuf>,
    /// Maximum number of WASM instances that may be checked out concurrently.
    #[serde(default = "default_wasm_authenticator_max_instances")]
    max_instances: usize,
    /// Optional directories that bound WASM authenticator file stream access.
    /// When empty, file stream imports are unavailable.
    #[serde(default)]
    file_access_dir: Vec<PathBuf>,
    /// Optional working directory used to resolve relative WASM authenticator
    /// file stream paths. Access is still bounded by `file_access_dir`.
    #[serde(default)]
    working_dir: Option<PathBuf>,
}

impl Default for WasmAuthenticatorConfig {
    fn default() -> Self {
        Self {
            path: None,
            max_instances: default_wasm_authenticator_max_instances(),
            file_access_dir: Vec::new(),
            working_dir: None,
        }
    }
}

impl WasmAuthenticatorConfig {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
            ..Self::default()
        }
    }

    pub fn with_max_instances(mut self, max_instances: usize) -> Self {
        self.max_instances = max_instances.max(1);
        self
    }

    pub fn with_file_access_dir(
        mut self,
        dirs: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Self {
        self.file_access_dir = dirs.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_working_dir(mut self, working_dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(working_dir.into());
        self
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    pub fn max_instances(&self) -> usize {
        self.max_instances.max(1)
    }

    pub fn file_access_dir(&self) -> &[PathBuf] {
        &self.file_access_dir
    }

    pub fn working_dir(&self) -> Option<&PathBuf> {
        self.working_dir.as_ref()
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthenticatorConfig {
    #[serde(default)]
    backend: AuthenticatorBackend,
    #[serde(default)]
    wasm: WasmAuthenticatorConfig,
    #[serde(default)]
    exec: ExecAuthenticatorConfig,
}

impl AuthenticatorConfig {
    pub fn new(backend: AuthenticatorBackend) -> Self {
        Self {
            backend,
            ..Self::default()
        }
    }

    pub fn with_exec(mut self, exec: ExecAuthenticatorConfig) -> Self {
        self.exec = exec;
        self
    }

    pub fn with_wasm(mut self, wasm: WasmAuthenticatorConfig) -> Self {
        self.wasm = wasm;
        self
    }

    pub fn backend(&self) -> AuthenticatorBackend {
        self.backend
    }

    pub fn wasm(&self) -> &WasmAuthenticatorConfig {
        &self.wasm
    }

    pub fn exec(&self) -> &ExecAuthenticatorConfig {
        &self.exec
    }
}

pub trait AuthenticatorConfigSource {
    fn authenticator_config(&self) -> &AuthenticatorConfig;

    fn authenticator_blob_storage_dir(&self) -> Option<&Path> {
        None
    }
}

impl AuthenticatorConfigSource for AuthenticatorConfig {
    fn authenticator_config(&self) -> &AuthenticatorConfig {
        self
    }
}

fn default_exec_authenticator_timeout_ms() -> u64 {
    30_000
}

fn default_exec_authenticator_max_response_bytes() -> usize {
    16 * 1024 * 1024
}

pub(crate) fn default_wasm_authenticator_max_instances() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1)
}
