use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time;

use crate::config::ExecAuthenticatorConfig;

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
        Ok(Self {
            inner: Arc::new(ExecAuthenticatorInner::new(
                ExecAuthenticatorMode::LongRunning {
                    process: Mutex::new(None),
                },
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
        let mut request_json =
            serde_json::to_vec(&request).map_err(ExecAuthenticatorError::Serialize)?;
        request_json.push(b'\n');
        let response_json = match &self.mode {
            ExecAuthenticatorMode::Ephemeral => self.invoke_ephemeral(request_json).await?,
            ExecAuthenticatorMode::LongRunning { process } => {
                self.invoke_long_running(process, request_json).await?
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
        process: &Mutex<Option<LongRunningExecAuthenticatorProcess>>,
        request_json: Vec<u8>,
    ) -> Result<Vec<u8>, ExecAuthenticatorError> {
        let mut process = process.lock().await;
        if process.is_none() {
            *process = Some(self.spawn_long_running()?);
        }
        let active = process
            .as_mut()
            .expect("long-running process was just spawned");
        match self.send_and_read_line(active, &request_json).await {
            Ok(response) => Ok(response),
            Err(error) => {
                let failed_path = self.command.clone();
                drop(process.take());
                tracing::warn!(
                    error = %error,
                    path = %failed_path.display(),
                    "long-running exec authenticator failed; it will be respawned for the next request"
                );
                Err(error)
            }
        }
    }

    async fn send_and_read_line(
        &self,
        process: &mut LongRunningExecAuthenticatorProcess,
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

        self.with_timeout(self.read_response_line(&mut process.stdout), self.timeout)
            .await?
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
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let bytes_read =
                stdout
                    .read(&mut byte)
                    .await
                    .map_err(|source| ExecAuthenticatorError::Read {
                        path: self.command.clone(),
                        source,
                    })?;
            if bytes_read == 0 {
                break;
            }
            response.push(byte[0]);
            if response.len() > self.max_response_bytes {
                return Err(ExecAuthenticatorError::ResponseTooLarge {
                    path: self.command.clone(),
                    limit: self.max_response_bytes,
                });
            }
            if byte[0] == b'\n' {
                break;
            }
        }
        trim_line_end(&mut response);
        self.check_response(&response)?;
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
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        if let Some(working_dir) = &self.working_dir {
            command.current_dir(working_dir);
        }
        apply_permission_drop(&mut command, self.uid, self.gid)?;
        command
            .spawn()
            .map_err(|source| ExecAuthenticatorError::Spawn {
                path: self.command.clone(),
                source,
            })
    }

    fn spawn_long_running(
        &self,
    ) -> Result<LongRunningExecAuthenticatorProcess, ExecAuthenticatorError> {
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
        Ok(LongRunningExecAuthenticatorProcess {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
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

enum ExecAuthenticatorMode {
    Ephemeral,
    LongRunning {
        process: Mutex<Option<LongRunningExecAuthenticatorProcess>>,
    },
}

struct LongRunningExecAuthenticatorProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Drop for LongRunningExecAuthenticatorProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
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
    use bytes::Bytes;
    use shitspeak_core::ProtocolVersion;
    use std::net::IpAddr;

    fn auxiliary_data() -> AuthenticateAuxiliaryData {
        AuthenticateAuxiliaryData {
            certificate_hash: Some(Bytes::from_static(b"cert")),
            session_id: 42,
            ip_address: IpAddr::from([127, 0, 0, 1]),
            tls_ja4: Some("ja4".to_owned()),
            uses_proxy_protocol: false,
            version: Some(ProtocolVersion::new(1, 2, 3)),
            client_name: Some("client".to_owned()),
            os_name: Some("os".to_owned()),
            os_version: Some("version".to_owned()),
        }
    }

    #[tokio::test]
    async fn ephemeral_exec_authenticator_reads_json_response() {
        let authenticator = platform_echo_authenticator(false);
        let result = authenticator
            .authenticate("alice", Some("secret"), &auxiliary_data())
            .await
            .expect("authentication result");

        assert_eq!(result.display_name.as_deref(), Some("alice"));
        assert_eq!(result.groups, vec!["exec"]);
    }

    #[tokio::test]
    async fn long_running_exec_authenticator_reads_json_response() {
        let authenticator = platform_echo_authenticator(true);
        for username in ["alice", "bob"] {
            let result = authenticator
                .authenticate(username, None, &auxiliary_data())
                .await
                .expect("authentication result");

            assert_eq!(result.display_name.as_deref(), Some(username));
            assert_eq!(result.groups, vec!["exec"]);
        }
    }

    #[cfg(windows)]
    fn platform_echo_authenticator(long_running: bool) -> ExecAuthenticator {
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
        let config = ExecAuthenticatorConfig::new("powershell")
            .with_args(["-NoProfile", "-NonInteractive", "-Command", script])
            .with_timeout_ms(5_000);
        if long_running {
            ExecAuthenticator::long_running(config).unwrap()
        } else {
            ExecAuthenticator::ephemeral(config).unwrap()
        }
    }

    #[cfg(not(windows))]
    fn platform_echo_authenticator(long_running: bool) -> ExecAuthenticator {
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
        let config = ExecAuthenticatorConfig::new("sh")
            .with_args(["-c", script])
            .with_timeout_ms(5_000);
        if long_running {
            ExecAuthenticator::long_running(config).unwrap()
        } else {
            ExecAuthenticator::ephemeral(config).unwrap()
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn permission_drop_is_rejected_on_non_unix() {
        let error =
            match ExecAuthenticator::ephemeral(ExecAuthenticatorConfig::new("cmd").with_uid(1)) {
                Ok(_) => panic!("non-Unix setuid was accepted"),
                Err(error) => error,
            };
        assert!(matches!(
            error,
            ExecAuthenticatorError::UnsupportedPermissionDrop
        ));
    }
}
