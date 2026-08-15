use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader,
};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, oneshot};
use tokio::time;

use crate::config::{ExecAuthenticatorConfig, ExecLongRunningRequestMode};

use super::authenticator_json::{
    AuthenticatorJsonAuthenticateResponse, ExecAuthenticatorJsonRequest,
};
use super::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    ExternalAuthClaims,
};

const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ExecAuthenticatorError {
    #[error("exec authenticator command is not configured")]
    MissingCommand,
    #[error("exec authenticator command `{path}` cannot be empty")]
    EmptyCommand { path: PathBuf },
    #[error("exec authenticator command `{path}` must be an absolute path")]
    RelativeCommand { path: PathBuf },
    #[error("exec authenticator setuid/setgid is unsupported on this platform")]
    UnsupportedPermissionDrop,
    #[error("failed to spawn exec authenticator `{path}`: {source}")]
    Spawn {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("exec authenticator `{path}` did not provide stdin")]
    MissingStdin { path: PathBuf },
    #[error("exec authenticator `{path}` did not provide stdout")]
    MissingStdout { path: PathBuf },
    #[error("failed to serialize exec authenticator request: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to write exec authenticator request to `{path}`: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read exec authenticator response from `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("exec authenticator `{path}` timed out after {timeout:?}")]
    Timeout { path: PathBuf, timeout: Duration },
    #[error("exec authenticator `{path}` exceeded response limit of {limit} bytes")]
    ResponseTooLarge { path: PathBuf, limit: usize },
    #[error("exec authenticator `{path}` exited without a response")]
    EmptyResponse { path: PathBuf },
    #[error("exec authenticator `{path}` exited with status {status}")]
    Exit { path: PathBuf, status: String },
    #[error("exec authenticator `{path}` returned invalid JSON: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("exec authenticator `{path}` response is missing request_id")]
    MissingRequestId { path: PathBuf },
    #[error("exec authenticator `{path}` response request_id {actual:?} did not match {expected}")]
    UnexpectedRequestId {
        path: PathBuf,
        expected: u64,
        actual: Option<u64>,
    },
    #[error("exec authenticator `{path}` protocol error: {message}")]
    Protocol { path: PathBuf, message: String },
    #[error("long-running exec authenticator `{path}` reader stopped")]
    ReaderStopped { path: PathBuf },
}

#[derive(Clone)]
pub struct ExecAuthenticator {
    inner: Arc<ExecAuthenticatorInner>,
}

impl ExecAuthenticator {
    pub fn ephemeral(config: ExecAuthenticatorConfig) -> Result<Self, ExecAuthenticatorError> {
        Ok(Self {
            inner: Arc::new(ExecAuthenticatorInner::new(
                ExecAuthenticatorMode::Ephemeral,
                config,
            )?),
        })
    }

    pub fn long_running(config: ExecAuthenticatorConfig) -> Result<Self, ExecAuthenticatorError> {
        let request_mode = config.long_running_request_mode();
        Ok(Self {
            inner: Arc::new(ExecAuthenticatorInner::new(
                ExecAuthenticatorMode::LongRunning(Box::new(LongRunningExecAuthenticatorMode {
                    process: Mutex::new(LongRunningProcessState::default()),
                    request_mode,
                    next_request_id: AtomicU64::new(1),
                })),
                config,
            )?),
        })
    }

    pub fn command_path(&self) -> &Path {
        self.inner.command_path()
    }

    async fn invoke<Response>(
        &self,
        request: ExecAuthenticatorJsonRequest,
    ) -> Result<Response, ExecAuthenticatorError>
    where
        Response: DeserializeOwned + Send + 'static,
    {
        self.inner.invoke(request).await
    }
}

#[async_trait]
impl Authenticator for ExecAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let request =
            ExecAuthenticatorJsonRequest::authenticate(username, password, auxiliary_data);
        match self
            .invoke::<AuthenticatorJsonAuthenticateResponse>(request)
            .await
        {
            Ok(response) => response.into_authenticate_result(),
            Err(error) => {
                tracing::warn!(error = %error, "exec authenticator failed");
                Err(AuthenticationRejection::RetryLater)
            }
        }
    }

    async fn authenticate_external(
        &self,
        claims: &ExternalAuthClaims,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let request = ExecAuthenticatorJsonRequest::authenticate_external(claims, auxiliary_data);
        match self
            .invoke::<AuthenticatorJsonAuthenticateResponse>(request)
            .await
        {
            Ok(response) => response.into_authenticate_result(),
            Err(error) => {
                tracing::warn!(error = %error, "exec external authenticator failed");
                Err(AuthenticationRejection::RetryLater)
            }
        }
    }
}

struct ExecAuthenticatorInner {
    mode: ExecAuthenticatorMode,
    command: PathBuf,
    args: Vec<String>,
    environment: HashMap<String, String>,
    working_dir: Option<PathBuf>,
    uid: Option<u32>,
    gid: Option<u32>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl ExecAuthenticatorInner {
    fn new(
        mode: ExecAuthenticatorMode,
        config: ExecAuthenticatorConfig,
    ) -> Result<Self, ExecAuthenticatorError> {
        validate_permission_drop(config.uid(), config.gid())?;
        let command = config
            .command()
            .cloned()
            .ok_or(ExecAuthenticatorError::MissingCommand)?;
        if command.as_os_str().is_empty() {
            return Err(ExecAuthenticatorError::EmptyCommand { path: command });
        }
        // Resolving the helper through the parent's PATH lets a local
        // attacker who can influence PATH substitute an arbitrary binary.
        // Require an absolute path.
        if !command.is_absolute() {
            return Err(ExecAuthenticatorError::RelativeCommand { path: command });
        }
        let timeout = match config.timeout_ms() {
            0 => DEFAULT_TIMEOUT,
            timeout_ms => Duration::from_millis(timeout_ms),
        };
        let max_response_bytes = match config.max_response_bytes() {
            0 => DEFAULT_MAX_RESPONSE_BYTES,
            max_response_bytes => max_response_bytes,
        };
        Ok(Self {
            mode,
            command,
            args: config.args().to_vec(),
            environment: config.environment().clone(),
            working_dir: config.working_dir().cloned(),
            uid: config.uid(),
            gid: config.gid(),
            timeout,
            max_response_bytes,
        })
    }

    fn command_path(&self) -> &Path {
        &self.command
    }

    async fn invoke<Response>(
        &self,
        request: ExecAuthenticatorJsonRequest,
    ) -> Result<Response, ExecAuthenticatorError>
    where
        Response: DeserializeOwned + Send + 'static,
    {
        let response_json = match &self.mode {
            ExecAuthenticatorMode::Ephemeral => {
                let request_json = line_json(&request)?;
                self.invoke_ephemeral(request_json).await?
            }
            ExecAuthenticatorMode::LongRunning(mode) => {
                self.invoke_long_running(
                    &mode.process,
                    mode.request_mode,
                    &mode.next_request_id,
                    request,
                )
                .await?
            }
        };
        serde_json::from_slice(&response_json).map_err(|source| ExecAuthenticatorError::Json {
            path: self.command.clone(),
            source,
        })
    }

    async fn invoke_ephemeral(
        &self,
        request_json: Vec<u8>,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        let mut child = self.spawn_child(false)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ExecAuthenticatorError::MissingStdin {
                path: self.command.clone(),
            })?;
        stdin
            .write_all(&request_json)
            .await
            .map_err(|source| ExecAuthenticatorError::Write {
                path: self.command.clone(),
                source,
            })?;
        stdin
            .shutdown()
            .await
            .map_err(|source| ExecAuthenticatorError::Write {
                path: self.command.clone(),
                source,
            })?;
        drop(stdin);

        let mut stdout =
            child
                .stdout
                .take()
                .ok_or_else(|| ExecAuthenticatorError::MissingStdout {
                    path: self.command.clone(),
                })?;
        let response = self
            .with_timeout(self.read_response_to_end(&mut stdout), self.timeout)
            .await??;
        let status = self
            .with_timeout(child.wait(), self.timeout)
            .await?
            .map_err(|source| ExecAuthenticatorError::Read {
                path: self.command.clone(),
                source,
            })?;
        if !status.success() {
            return Err(ExecAuthenticatorError::Exit {
                path: self.command.clone(),
                status: status.to_string(),
            });
        }
        Ok(response)
    }

    async fn invoke_long_running(
        &self,
        process: &Mutex<LongRunningProcessState>,
        request_mode: ExecLongRunningRequestMode,
        next_request_id: &AtomicU64,
        request: ExecAuthenticatorJsonRequest,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        match request_mode {
            ExecLongRunningRequestMode::Serialized => {
                let request_id = next_request_id.fetch_add(1, Ordering::Relaxed);
                let request_json = line_json(&request.with_request_id(request_id))?;
                self.invoke_long_running_serialized(process, request_id, request_json)
                    .await
            }
            ExecLongRunningRequestMode::Async => {
                let request_id = next_request_id.fetch_add(1, Ordering::Relaxed);
                let request_json = line_json(&request.with_request_id(request_id))?;
                self.invoke_long_running_async(process, request_id, request_json)
                    .await
            }
        }
    }

    async fn invoke_long_running_serialized(
        &self,
        process: &Mutex<LongRunningProcessState>,
        request_id: u64,
        request_json: Vec<u8>,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        let mut state = process.lock().await;
        if state.serialized.is_none() {
            state.serialized = Some(self.spawn_long_running_serialized()?);
        }
        let active = state
            .serialized
            .as_mut()
            .expect("long-running serialized process was just spawned");
        match self
            .send_and_read_correlated_line(active, request_id, &request_json)
            .await
        {
            Ok(response) => Ok(response),
            Err(error) => {
                self.drop_serialized_process(&mut state, &error);
                Err(error)
            }
        }
    }

    async fn invoke_long_running_async(
        &self,
        process: &Mutex<LongRunningProcessState>,
        request_id: u64,
        request_json: Vec<u8>,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        let (response_rx, pending) = {
            let mut state = process.lock().await;
            if state.async_process.is_none() {
                state.async_process = Some(self.spawn_long_running_async()?);
            }
            let Some(active) = state.async_process.as_mut() else {
                return Err(ExecAuthenticatorError::Protocol {
                    path: self.command.clone(),
                    message: "async long-running process was not available after spawn".to_owned(),
                });
            };
            let (response_tx, response_rx) = oneshot::channel();
            if let Err(error) =
                register_pending_response(&active.responses, &self.command, request_id, response_tx)
            {
                self.drop_async_process(&mut state, &error);
                return Err(error);
            }

            let write_result = self
                .with_timeout(
                    async {
                        active.stdin.write_all(&request_json).await?;
                        active.stdin.flush().await
                    },
                    self.timeout,
                )
                .await;
            let write_error = match write_result {
                Ok(Ok(())) => None,
                Ok(Err(source)) => Some(ExecAuthenticatorError::Write {
                    path: self.command.clone(),
                    source,
                }),
                Err(error) => Some(error),
            };
            if let Some(error) = write_error {
                active
                    .responses
                    .lock()
                    .expect("long-running exec response state poisoned")
                    .pending
                    .remove(&request_id);
                self.drop_async_process(&mut state, &error);
                return Err(error);
            }
            (response_rx, Arc::clone(&active.responses))
        };

        match time::timeout(self.timeout, response_rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => Err(ExecAuthenticatorError::ReaderStopped {
                path: self.command.clone(),
            }),
            Err(_) => {
                pending
                    .lock()
                    .expect("long-running exec response state poisoned")
                    .pending
                    .remove(&request_id);
                Err(ExecAuthenticatorError::Timeout {
                    path: self.command.clone(),
                    timeout: self.timeout,
                })
            }
        }
    }

    async fn send_and_read_correlated_line(
        &self,
        process: &mut SerializedLongRunningExecAuthenticatorProcess,
        request_id: u64,
        request_json: &[u8],
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        self.with_timeout(
            async {
                process.stdin.write_all(request_json).await?;
                process.stdin.flush().await
            },
            self.timeout,
        )
        .await?
        .map_err(|source| ExecAuthenticatorError::Write {
            path: self.command.clone(),
            source,
        })?;

        let response = self
            .with_timeout(self.read_response_line(&mut process.stdout), self.timeout)
            .await??;
        self.unwrap_correlated_response(request_id, response, false)
    }

    async fn read_response_to_end(
        &self,
        stdout: &mut ChildStdout,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        let mut response = Vec::new();
        let limit = self.max_response_bytes.saturating_add(1);
        stdout
            .take(limit as u64)
            .read_to_end(&mut response)
            .await
            .map_err(|source| ExecAuthenticatorError::Read {
                path: self.command.clone(),
                source,
            })?;
        trim_line_end(&mut response);
        self.check_response(&response)?;
        Ok(response)
    }

    async fn read_response_line(
        &self,
        stdout: &mut BufReader<ChildStdout>,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        read_response_line_from(&self.command, self.max_response_bytes, stdout).await
    }

    fn unwrap_correlated_response(
        &self,
        expected_request_id: u64,
        response: Vec<u8>,
        require_request_id: bool,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        let request_id = serde_json::from_slice::<CorrelatedResponse>(&response)
            .map_err(|source| ExecAuthenticatorError::Json {
                path: self.command.clone(),
                source,
            })?
            .request_id;
        if require_request_id && request_id.is_none() {
            return Err(ExecAuthenticatorError::MissingRequestId {
                path: self.command.clone(),
            });
        }
        if let Some(actual) = request_id
            && actual != expected_request_id
        {
            return Err(ExecAuthenticatorError::UnexpectedRequestId {
                path: self.command.clone(),
                expected: expected_request_id,
                actual: Some(actual),
            });
        }
        Ok(response)
    }

    fn check_response(&self, response: &[u8]) -> Result<(), ExecAuthenticatorError> {
        if response.is_empty() {
            return Err(ExecAuthenticatorError::EmptyResponse {
                path: self.command.clone(),
            });
        }
        if response.len() > self.max_response_bytes {
            return Err(ExecAuthenticatorError::ResponseTooLarge {
                path: self.command.clone(),
                limit: self.max_response_bytes,
            });
        }
        Ok(())
    }

    fn spawn_child(&self, _long_running: bool) -> Result<Child, ExecAuthenticatorError> {
        let mut command = Command::new(&self.command);
        // The helper is operator-supplied and trusted (the operator chooses
        // which process to run and which environment to configure), so the
        // parent environment is inherited as-is; `.envs` merges the
        // explicitly configured variables on top.
        command
            .args(&self.args)
            .envs(&self.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(working_dir) = &self.working_dir {
            command.current_dir(working_dir);
        }
        apply_permission_drop(&mut command, self.uid, self.gid)?;
        apply_background_priority(&mut command);
        let mut child = command
            .spawn()
            .map_err(|source| ExecAuthenticatorError::Spawn {
                path: self.command.clone(),
                source,
            })?;
        self.spawn_stderr_reader(&mut child);
        Ok(child)
    }

    /// Read the helper's stderr in a background task, sanitizing each line
    /// (control characters stripped, length capped) so a misbehaving helper
    /// cannot inject ANSI/control sequences into the host logs or flood them.
    fn spawn_stderr_reader(&self, child: &mut Child) {
        let Some(stderr) = child.stderr.take() else {
            return;
        };
        let command = self.command.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let sanitized = sanitize_stderr_line(line.trim_end_matches(['\r', '\n']));
                        tracing::debug!(
                            command = %command.display(),
                            stderr = %sanitized,
                            "exec authenticator stderr"
                        );
                    }
                }
            }
        });
    }

    fn spawn_long_running_serialized(
        &self,
    ) -> Result<SerializedLongRunningExecAuthenticatorProcess, ExecAuthenticatorError> {
        let mut child = self.spawn_child(true)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ExecAuthenticatorError::MissingStdin {
                path: self.command.clone(),
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecAuthenticatorError::MissingStdout {
                path: self.command.clone(),
            })?;
        Ok(SerializedLongRunningExecAuthenticatorProcess {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn spawn_long_running_async(
        &self,
    ) -> Result<AsyncLongRunningExecAuthenticatorProcess, ExecAuthenticatorError> {
        let mut child = self.spawn_child(true)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ExecAuthenticatorError::MissingStdin {
                path: self.command.clone(),
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecAuthenticatorError::MissingStdout {
                path: self.command.clone(),
            })?;
        let responses = Arc::new(std::sync::Mutex::new(
            AsyncLongRunningResponseState::default(),
        ));
        tokio::spawn(read_long_running_async_responses(
            self.command.clone(),
            self.max_response_bytes,
            BufReader::new(stdout),
            Arc::clone(&responses),
        ));
        Ok(AsyncLongRunningExecAuthenticatorProcess {
            child,
            stdin,
            responses,
        })
    }

    fn drop_serialized_process(
        &self,
        state: &mut LongRunningProcessState,
        error: &ExecAuthenticatorError,
    ) {
        let failed_path = self.command.clone();
        drop(state.serialized.take());
        tracing::warn!(
            error = %error,
            path = %failed_path.display(),
            "serialized long-running exec authenticator failed; it will be respawned for the next request"
        );
    }

    fn drop_async_process(
        &self,
        state: &mut LongRunningProcessState,
        error: &ExecAuthenticatorError,
    ) {
        let failed_path = self.command.clone();
        drop(state.async_process.take());
        tracing::warn!(
            error = %error,
            path = %failed_path.display(),
            "async long-running exec authenticator failed; it will be respawned for the next request"
        );
    }

    async fn with_timeout<F, T>(
        &self,
        future: F,
        timeout: Duration,
    ) -> Result<T, ExecAuthenticatorError>
    where
        F: std::future::Future<Output = T>,
    {
        time::timeout(timeout, future)
            .await
            .map_err(|_| ExecAuthenticatorError::Timeout {
                path: self.command.clone(),
                timeout,
            })
    }
}

/// Sanitize one stderr line for logging: strip control characters (except
/// tab) and cap the length so a helper cannot inject ANSI/escape sequences
/// into the host logs or flood them with oversized lines.
fn sanitize_stderr_line(line: &str) -> String {
    const MAX_LINE_CHARS: usize = 512;
    let mut out = String::with_capacity(line.len().min(MAX_LINE_CHARS));
    for ch in line.chars().take(MAX_LINE_CHARS) {
        if ch.is_control() && ch != '\t' {
            out.push('\u{FFFD}');
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(windows)]
fn apply_background_priority(command: &mut Command) {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::BELOW_NORMAL_PRIORITY_CLASS;

    command
        .as_std_mut()
        .creation_flags(BELOW_NORMAL_PRIORITY_CLASS);
}

#[cfg(not(windows))]
fn apply_background_priority(_command: &mut Command) {
    // On Unix, process niceness is inherited from the low-priority auth
    // runtime thread which spawns the helper.
}

enum ExecAuthenticatorMode {
    Ephemeral,
    LongRunning(Box<LongRunningExecAuthenticatorMode>),
}

struct LongRunningExecAuthenticatorMode {
    process: Mutex<LongRunningProcessState>,
    request_mode: ExecLongRunningRequestMode,
    next_request_id: AtomicU64,
}

#[derive(Default)]
struct LongRunningProcessState {
    serialized: Option<SerializedLongRunningExecAuthenticatorProcess>,
    async_process: Option<AsyncLongRunningExecAuthenticatorProcess>,
}

struct SerializedLongRunningExecAuthenticatorProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

type PendingLongRunningResponseSender = oneshot::Sender<Result<Vec<u8>, ExecAuthenticatorError>>;

#[derive(Default)]
struct AsyncLongRunningResponseState {
    pending: HashMap<u64, PendingLongRunningResponseSender>,
    reader_stopped: bool,
}

type SharedAsyncLongRunningResponseState = Arc<std::sync::Mutex<AsyncLongRunningResponseState>>;

struct AsyncLongRunningExecAuthenticatorProcess {
    child: Child,
    stdin: ChildStdin,
    responses: SharedAsyncLongRunningResponseState,
}

impl Drop for SerializedLongRunningExecAuthenticatorProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl Drop for AsyncLongRunningExecAuthenticatorProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn line_json(request: &ExecAuthenticatorJsonRequest) -> Result<Vec<u8>, ExecAuthenticatorError> {
    let mut request_json =
        serde_json::to_vec(request).map_err(ExecAuthenticatorError::Serialize)?;
    request_json.push(b'\n');
    Ok(request_json)
}

#[derive(Deserialize)]
struct CorrelatedResponse {
    #[serde(default)]
    request_id: Option<u64>,
}

async fn read_long_running_async_responses(
    path: PathBuf,
    max_response_bytes: usize,
    mut stdout: BufReader<ChildStdout>,
    responses: SharedAsyncLongRunningResponseState,
) {
    loop {
        let response = match read_response_line_from(&path, max_response_bytes, &mut stdout).await {
            Ok(response) => response,
            Err(error) => {
                fail_pending_responses(&responses, &path, error);
                return;
            }
        };
        let (request_id, response) = match unwrap_required_async_response(&path, response) {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(error = %error, path = %path.display(), "invalid async exec authenticator response");
                fail_pending_responses(&responses, &path, error);
                return;
            }
        };
        let sender = responses
            .lock()
            .expect("long-running exec response state poisoned")
            .pending
            .remove(&request_id);
        let Some(sender) = sender else {
            tracing::warn!(
                path = %path.display(),
                request_id,
                "async exec authenticator returned response for unknown request_id"
            );
            continue;
        };
        let _ = sender.send(Ok(response));
    }
}

async fn read_response_line_from<Reader>(
    path: &Path,
    max_response_bytes: usize,
    stdout: &mut Reader,
) -> Result<Vec<u8>, ExecAuthenticatorError>
where
    Reader: AsyncBufRead + Unpin,
{
    let mut response = Vec::new();
    loop {
        let buffer = stdout
            .fill_buf()
            .await
            .map_err(|source| ExecAuthenticatorError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if buffer.is_empty() {
            break;
        }

        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let bytes_to_copy = newline.map_or(buffer.len(), |index| index + 1);
        if bytes_to_copy > max_response_bytes - response.len() {
            return Err(ExecAuthenticatorError::ResponseTooLarge {
                path: path.to_path_buf(),
                limit: max_response_bytes,
            });
        }

        response.extend_from_slice(&buffer[..bytes_to_copy]);
        stdout.consume(bytes_to_copy);
        if newline.is_some() {
            break;
        }
    }
    trim_line_end(&mut response);
    if response.is_empty() {
        return Err(ExecAuthenticatorError::EmptyResponse {
            path: path.to_path_buf(),
        });
    }
    Ok(response)
}

fn unwrap_required_async_response(
    path: &Path,
    response: Vec<u8>,
) -> Result<(u64, Vec<u8>), ExecAuthenticatorError> {
    let request_id = serde_json::from_slice::<CorrelatedResponse>(&response)
        .map_err(|source| ExecAuthenticatorError::Json {
            path: path.to_path_buf(),
            source,
        })?
        .request_id
        .ok_or_else(|| ExecAuthenticatorError::MissingRequestId {
            path: path.to_path_buf(),
        })?;
    Ok((request_id, response))
}

fn fail_pending_responses(
    responses: &SharedAsyncLongRunningResponseState,
    path: &Path,
    cause: ExecAuthenticatorError,
) {
    let pending = {
        let mut responses = responses
            .lock()
            .expect("long-running exec response state poisoned");
        responses.reader_stopped = true;
        std::mem::take(&mut responses.pending)
    };
    let message = cause.to_string();
    for sender in pending.into_values() {
        let _ = sender.send(Err(ExecAuthenticatorError::Protocol {
            path: path.to_path_buf(),
            message: message.clone(),
        }));
    }
}

fn register_pending_response(
    responses: &SharedAsyncLongRunningResponseState,
    path: &Path,
    request_id: u64,
    sender: PendingLongRunningResponseSender,
) -> Result<(), ExecAuthenticatorError> {
    let mut responses = responses
        .lock()
        .expect("long-running exec response state poisoned");
    if responses.reader_stopped {
        return Err(ExecAuthenticatorError::ReaderStopped {
            path: path.to_path_buf(),
        });
    }
    match responses.pending.entry(request_id) {
        std::collections::hash_map::Entry::Occupied(_) => {
            return Err(ExecAuthenticatorError::Protocol {
                path: path.to_path_buf(),
                message: format!("duplicate long-running request id {request_id}"),
            });
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(sender);
        }
    }
    Ok(())
}

fn trim_line_end(response: &mut Vec<u8>) {
    if response.last() == Some(&b'\n') {
        response.pop();
        if response.last() == Some(&b'\r') {
            response.pop();
        }
    }
}

fn validate_permission_drop(
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), ExecAuthenticatorError> {
    #[cfg(unix)]
    {
        let _ = (uid, gid);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if uid.is_some() || gid.is_some() {
            return Err(ExecAuthenticatorError::UnsupportedPermissionDrop);
        }
        Ok(())
    }
}

fn apply_permission_drop(
    command: &mut Command,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), ExecAuthenticatorError> {
    #[cfg(unix)]
    {
        if let Some(gid) = gid {
            command.gid(gid);
        }
        if let Some(uid) = uid {
            command.uid(uid);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = command;
        validate_permission_drop(uid, gid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExecLongRunningRequestMode;
    use bytes::Bytes;
    use shitspeak_core::ProtocolVersion;
    use std::net::IpAddr;

    /// Resolve a bare executable name through the test process PATH so tests
    /// pass absolute command paths (relative commands are rejected).
    fn resolve_in_path(name: &str) -> PathBuf {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                #[cfg(windows)]
                {
                    candidates.push(dir.join(name));
                    candidates.push(dir.join(format!("{name}.exe")));
                }
                #[cfg(not(windows))]
                candidates.push(dir.join(name));
            }
        }
        candidates
            .iter()
            .find(|path| path.is_file())
            .cloned()
            .unwrap_or_else(|| panic!("{name} not found in PATH"))
    }

    #[test]
    fn relative_command_is_rejected() {
        let error = match ExecAuthenticator::ephemeral(ExecAuthenticatorConfig::new(
            "relative-helper.sh",
        )) {
            Ok(_) => panic!("relative command must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ExecAuthenticatorError::RelativeCommand { .. }
        ));
    }

    #[test]
    fn sanitize_stderr_line_strips_control_characters_and_caps_length() {
        // ANSI escape sequences and other control characters are neutralized.
        assert_eq!(
            sanitize_stderr_line("hello\x1b[31mworld"),
            "hello\u{FFFD}[31mworld"
        );
        // Tab is preserved; newline (already trimmed by the reader) is not
        // part of the input here.
        assert_eq!(sanitize_stderr_line("a\tb"), "a\tb");
        // Length is capped.
        let long = "x".repeat(10_000);
        assert!(sanitize_stderr_line(&long).chars().count() <= 512);
    }

    fn auxiliary_data() -> AuthenticateAuxiliaryData {
        AuthenticateAuxiliaryData {
            certificate_hash: Some(Bytes::from_static(b"cert")),
            session_id: 42,
            ip_address: IpAddr::from([127, 0, 0, 1]),
            tls_ja3: Some("ja3".to_owned()),
            tls_ja4: Some("ja4".to_owned()),
            tls_ja4t: None,
            tls_ja4x: Some("ja4x".to_owned()),
            tls_ja4l: None,
            tls_sni: Some("example.test".to_owned()),
            proxy_server_address: Some("192.0.2.5:443".parse().unwrap()),
            packet_capture_backends: vec!["af_packet".to_owned()],
            packet_capture_backend: Some("af_packet".to_owned()),
            uses_proxy_protocol: false,
            version: Some(ProtocolVersion::new(1, 2, 3)),
            client_name: Some("client".to_owned()),
            os_name: Some("os".to_owned()),
            os_version: Some("version".to_owned()),
            auth_session_id: None,
        }
    }

    #[tokio::test]
    async fn response_line_reader_preserves_limit_and_buffered_following_line() {
        let path = Path::new("test-authenticator");
        let mut stdout = BufReader::new(&b"first\nsecond\n"[..]);

        let first = read_response_line_from(path, 6, &mut stdout)
            .await
            .expect("first response line");
        let second = read_response_line_from(path, 7, &mut stdout)
            .await
            .expect("second response line");

        assert_eq!(first, b"first");
        assert_eq!(second, b"second");

        let mut oversized = BufReader::new(&b"first\n"[..]);
        assert!(matches!(
            read_response_line_from(path, 5, &mut oversized).await,
            Err(ExecAuthenticatorError::ResponseTooLarge { limit: 5, .. })
        ));
    }

    #[test]
    fn correlated_response_keeps_original_json_bytes() {
        let response =
            br#"{ "accepted": true, "request_id": 42, "display_name": "alice" }"#.to_vec();
        let expected = response.clone();

        let (request_id, response) =
            unwrap_required_async_response(Path::new("test-authenticator"), response)
                .expect("correlated response");

        assert_eq!(request_id, 42);
        assert_eq!(response, expected);
        serde_json::from_slice::<AuthenticatorJsonAuthenticateResponse>(&response)
            .expect("typed response ignores request_id");
    }

    #[tokio::test]
    async fn ephemeral_exec_authenticator_reads_json_response() {
        let authenticator =
            platform_echo_authenticator(false, ExecLongRunningRequestMode::Serialized);
        let result = authenticator
            .authenticate("alice", Some("secret"), &auxiliary_data())
            .await
            .expect("authentication result");

        assert_eq!(result.display_name.as_deref(), Some("alice"));
        assert_eq!(result.groups, vec!["exec"]);
    }

    #[tokio::test]
    async fn ephemeral_exec_authenticator_passes_configured_environment() {
        let result = platform_environment_authenticator()
            .authenticate("alice", None, &auxiliary_data())
            .await
            .expect("authentication result");

        assert_eq!(result.display_name.as_deref(), Some("configured-value"));
    }

    #[tokio::test]
    async fn serialized_long_running_exec_authenticator_accepts_legacy_json_response() {
        let authenticator =
            platform_echo_authenticator(true, ExecLongRunningRequestMode::Serialized);
        for username in ["alice", "bob"] {
            let result = authenticator
                .authenticate(username, None, &auxiliary_data())
                .await
                .expect("authentication result");

            assert_eq!(result.display_name.as_deref(), Some(username));
            assert_eq!(result.groups, vec!["exec"]);
        }
    }

    #[tokio::test]
    async fn async_long_running_exec_authenticator_correlates_out_of_order_responses() {
        let authenticator = platform_out_of_order_async_authenticator();
        let alice_auxiliary = auxiliary_data();
        let bob_auxiliary = auxiliary_data();
        let (alice, bob) = tokio::join!(
            authenticator.authenticate("alice", None, &alice_auxiliary),
            authenticator.authenticate("bob", None, &bob_auxiliary),
        );

        let alice = alice.expect("alice authentication result");
        let bob = bob.expect("bob authentication result");
        assert_eq!(alice.display_name.as_deref(), Some("alice"));
        assert_eq!(bob.display_name.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn async_long_running_write_timeout_drops_process_and_pending_request() {
        let authenticator = platform_stalled_async_authenticator();
        let username = "x".repeat(16 * 1024 * 1024);
        let request =
            ExecAuthenticatorJsonRequest::authenticate(&username, None, &auxiliary_data());

        let error = match authenticator
            .invoke::<AuthenticatorJsonAuthenticateResponse>(request)
            .await
        {
            Ok(_) => panic!("stalled authenticator unexpectedly responded"),
            Err(error) => error,
        };

        assert!(matches!(error, ExecAuthenticatorError::Timeout { .. }));
        let ExecAuthenticatorMode::LongRunning(mode) = &authenticator.inner.mode else {
            panic!("test authenticator was not long-running");
        };
        let state = mode.process.lock().await;
        assert!(state.async_process.is_none());
    }

    #[tokio::test]
    async fn stopped_async_reader_rejects_new_pending_requests_after_drain() {
        let responses = Arc::new(std::sync::Mutex::new(
            AsyncLongRunningResponseState::default(),
        ));
        let path = Path::new("test-authenticator");
        let (first_tx, first_rx) = oneshot::channel();
        register_pending_response(&responses, path, 1, first_tx)
            .expect("initial pending response registration");

        fail_pending_responses(
            &responses,
            path,
            ExecAuthenticatorError::EmptyResponse {
                path: path.to_path_buf(),
            },
        );

        assert!(matches!(
            first_rx.await.expect("reader failure response"),
            Err(ExecAuthenticatorError::Protocol { .. })
        ));
        let (late_tx, _late_rx) = oneshot::channel();
        assert!(matches!(
            register_pending_response(&responses, path, 2, late_tx),
            Err(ExecAuthenticatorError::ReaderStopped { .. })
        ));
        assert!(
            responses
                .lock()
                .expect("long-running exec response state poisoned")
                .pending
                .is_empty()
        );
    }

    #[cfg(windows)]
    fn platform_environment_authenticator() -> ExecAuthenticator {
        let script = r#"
$ErrorActionPreference = 'Stop'
$null = [Console]::In.ReadLine()
'{"accepted":true,"display_name":"' + $env:SHITSPEAK_EXEC_AUTH_TEST + '"}'
"#;
        ExecAuthenticator::ephemeral(
            ExecAuthenticatorConfig::new(resolve_in_path("powershell"))
                .with_args(["-NoProfile", "-NonInteractive", "-Command", script])
                .with_environment([("SHITSPEAK_EXEC_AUTH_TEST", "configured-value")])
                .with_timeout_ms(5_000),
        )
        .unwrap()
    }

    #[cfg(not(windows))]
    fn platform_environment_authenticator() -> ExecAuthenticator {
        let script = r#"
IFS= read -r line
printf '{"accepted":true,"display_name":"%s"}\n' "$SHITSPEAK_EXEC_AUTH_TEST"
"#;
        ExecAuthenticator::ephemeral(
            ExecAuthenticatorConfig::new(resolve_in_path("sh"))
                .with_args(["-c", script])
                .with_environment([("SHITSPEAK_EXEC_AUTH_TEST", "configured-value")])
                .with_timeout_ms(5_000),
        )
        .unwrap()
    }

    #[cfg(windows)]
    fn platform_echo_authenticator(
        long_running: bool,
        request_mode: ExecLongRunningRequestMode,
    ) -> ExecAuthenticator {
        let script = if long_running {
            r#"
$ErrorActionPreference = 'Stop'
while (($line = [Console]::In.ReadLine()) -ne $null) {
    $request = $line | ConvertFrom-Json
    '{"accepted":true,"display_name":"' + $request.username + '","groups":["exec"]}'
}
"#
        } else {
            r#"
$ErrorActionPreference = 'Stop'
$line = [Console]::In.ReadLine()
$request = $line | ConvertFrom-Json
'{"accepted":true,"display_name":"' + $request.username + '","groups":["exec"]}'
"#
        };
        let config = ExecAuthenticatorConfig::new(resolve_in_path("powershell"))
            .with_args(["-NoProfile", "-NonInteractive", "-Command", script])
            .with_long_running_request_mode(request_mode)
            .with_timeout_ms(5_000);
        if long_running {
            ExecAuthenticator::long_running(config).unwrap()
        } else {
            ExecAuthenticator::ephemeral(config).unwrap()
        }
    }

    #[cfg(windows)]
    fn platform_out_of_order_async_authenticator() -> ExecAuthenticator {
        let script = r#"
$ErrorActionPreference = 'Stop'
$first = [Console]::In.ReadLine() | ConvertFrom-Json
$second = [Console]::In.ReadLine() | ConvertFrom-Json
'{"request_id":' + $second.request_id + ',"accepted":true,"display_name":"' + $second.username + '","groups":["exec"]}'
'{"request_id":' + $first.request_id + ',"accepted":true,"display_name":"' + $first.username + '","groups":["exec"]}'
while (($line = [Console]::In.ReadLine()) -ne $null) {
    $request = $line | ConvertFrom-Json
    '{"request_id":' + $request.request_id + ',"accepted":true,"display_name":"' + $request.username + '","groups":["exec"]}'
}
"#;
        ExecAuthenticator::long_running(
            ExecAuthenticatorConfig::new(resolve_in_path("powershell"))
                .with_args(["-NoProfile", "-NonInteractive", "-Command", script])
                .with_long_running_request_mode(ExecLongRunningRequestMode::Async)
                .with_timeout_ms(5_000),
        )
        .unwrap()
    }

    #[cfg(windows)]
    fn platform_stalled_async_authenticator() -> ExecAuthenticator {
        ExecAuthenticator::long_running(
            ExecAuthenticatorConfig::new(resolve_in_path("powershell"))
                .with_args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 30",
                ])
                .with_long_running_request_mode(ExecLongRunningRequestMode::Async)
                .with_timeout_ms(100),
        )
        .unwrap()
    }

    #[cfg(not(windows))]
    fn platform_echo_authenticator(
        long_running: bool,
        request_mode: ExecLongRunningRequestMode,
    ) -> ExecAuthenticator {
        let script = if long_running {
            r#"
while IFS= read -r line; do
    username=$(printf '%s' "$line" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')
    printf '{"accepted":true,"display_name":"%s","groups":["exec"]}\n' "$username"
done
"#
        } else {
            r#"
IFS= read -r line
username=$(printf '%s' "$line" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')
printf '{"accepted":true,"display_name":"%s","groups":["exec"]}\n' "$username"
"#
        };
        let config = ExecAuthenticatorConfig::new(resolve_in_path("sh"))
            .with_args(["-c", script])
            .with_long_running_request_mode(request_mode)
            .with_timeout_ms(5_000);
        if long_running {
            ExecAuthenticator::long_running(config).unwrap()
        } else {
            ExecAuthenticator::ephemeral(config).unwrap()
        }
    }

    #[cfg(not(windows))]
    fn platform_out_of_order_async_authenticator() -> ExecAuthenticator {
        let script = r#"
read -r first
read -r second
first_id=$(printf '%s' "$first" | sed -n 's/.*"request_id":\([0-9][0-9]*\).*/\1/p')
first_username=$(printf '%s' "$first" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')
second_id=$(printf '%s' "$second" | sed -n 's/.*"request_id":\([0-9][0-9]*\).*/\1/p')
second_username=$(printf '%s' "$second" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')
printf '{"request_id":%s,"accepted":true,"display_name":"%s","groups":["exec"]}\n' "$second_id" "$second_username"
printf '{"request_id":%s,"accepted":true,"display_name":"%s","groups":["exec"]}\n' "$first_id" "$first_username"
while IFS= read -r line; do
    request_id=$(printf '%s' "$line" | sed -n 's/.*"request_id":\([0-9][0-9]*\).*/\1/p')
    username=$(printf '%s' "$line" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')
    printf '{"request_id":%s,"accepted":true,"display_name":"%s","groups":["exec"]}\n' "$request_id" "$username"
done
"#;
        ExecAuthenticator::long_running(
            ExecAuthenticatorConfig::new(resolve_in_path("sh"))
                .with_args(["-c", script])
                .with_long_running_request_mode(ExecLongRunningRequestMode::Async)
                .with_timeout_ms(5_000),
        )
        .unwrap()
    }

    #[cfg(not(windows))]
    fn platform_stalled_async_authenticator() -> ExecAuthenticator {
        ExecAuthenticator::long_running(
            ExecAuthenticatorConfig::new(resolve_in_path("sh"))
                .with_args(["-c", "exec sleep 30"])
                .with_long_running_request_mode(ExecLongRunningRequestMode::Async)
                .with_timeout_ms(100),
        )
        .unwrap()
    }

    #[cfg(not(unix))]
    #[test]
    fn permission_drop_is_rejected_on_non_unix() {
        let error = match ExecAuthenticator::ephemeral(
            ExecAuthenticatorConfig::new(resolve_in_path("cmd")).with_uid(1),
        ) {
            Ok(_) => panic!("non-Unix setuid was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ExecAuthenticatorError::UnsupportedPermissionDrop
        ));
    }
}
