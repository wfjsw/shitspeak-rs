# Authentication

[Docs index](README.md)

ShitSpeak supports three authentication backends:

- `demo`: built-in development authenticator.
- `exec`: external process using JSON over stdin/stdout.
- `wasm`: Wasmtime module using a pointer/length ABI plus host imports.

For any exposed deployment, replace the demo backend.

## Selecting A Backend

```toml
[authenticator]
backend = "demo"
```

Valid values are `demo`, `exec`, and `wasm`.

## Demo Backend

The demo backend is useful for local testing. It is not a production access-control system.

```toml
[authenticator]
backend = "demo"
```

## Exec Authenticator

Exec authenticators receive JSON lines on stdin and write JSON responses on stdout. They can run once per request or as a long-running helper.

```toml
[authenticator]
backend = "exec"

[authenticator.exec]
mode = "exec_long_running" # exec_ephemeral, exec_long_running
command = "auth-helper"
args = []
working_dir = "auth"
timeout_ms = 30000
max_response_bytes = 16777216
# uid = 1001
# gid = 1001
```

Unix `uid` and `gid` dropping is optional. If the systemd unit is hardened, extra capabilities may be required for child-process user/group changes. See [Deployment](deployment.md).

## WASM Authenticator

WASM authenticators run under Wasmtime without WASI. The host links only the imports documented below.

```toml
[authenticator]
backend = "wasm"

[authenticator.wasm]
path = "auth.wasm"
file_access_dir = ["auth-files"]
working_dir = "auth-files"
```

`file_access_dir` bounds the raw file stream imports. When it is empty, file stream imports are unavailable. Relative guest file paths resolve under `working_dir` if configured.

When the configured `.wasm` file changes, reload compiles the new module before activating it. If compilation or loading fails, the previous authenticator remains active.

Example authenticators:

- [Rust WASM authenticator example](../examples/wasm-auth-rust/README.md)
- [AssemblyScript WASM authenticator example](../examples/wasm-auth-assemblyscript/README.md)

Build the Rust example:

```powershell
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/wasm-auth-rust/Cargo.toml --target wasm32-unknown-unknown --release
```

Build the AssemblyScript example:

```powershell
cd examples/wasm-auth-assemblyscript
npm install
npm run build
```

## Authenticator Responses

Successful authentication can provide identity, display name, groups, virtual server routing, language, and per-client bandwidth:

```json
{
  "accepted": true,
  "user_id": 42,
  "display_name": "Alice",
  "groups": ["admin"],
  "virtual_server_id": null,
  "language": "en",
  "max_bandwidth": null,
  "texture_url": null,
  "comment_url": null
}
```

`max_bandwidth`, when present, overrides the configured `max_bandwidth` value advertised to that authenticated client.

For rejection, return `accepted: false` and a `rejection` value such as `no_such_user`, `invalid_username`, `wrong_password`, or `retry_later`.

## Required Groups

`required_groups` can enforce a coarse deployment-level group gate after authentication:

```toml
required_groups = ["admin", "member"]
```

If the list is empty, all authenticated users are allowed. If it is non-empty, a user must belong to at least one listed group.

## WASM Authenticator Contract

The module must export:

```text
memory
alloc(len: i32) -> i32
authenticate(ptr: i32, len: i32) -> i64
```

`authenticate` receives a UTF-8 JSON request in guest memory and returns `(ptr << 32) | len`, where `ptr` and `len` describe a UTF-8 JSON response. An optional `dealloc(ptr: i32, len: i32)` export is called for request and response buffers when present.

Optional exports:

```text
language(ptr: i32, len: i32) -> i64
authenticate_external(ptr: i32, len: i32) -> i64
```

### Authenticate Request

```json
{
  "username": "alice",
  "password": "optional password",
  "auxiliary_data": {
    "certificate_hash_base64": null,
    "session_id": 1,
    "ip_address": "127.0.0.1",
    "tls_ja4": "t13x0306h2_8daaf6152771_02713d6af862",
    "uses_proxy_protocol": false,
    "version": { "major": 1, "minor": 5, "patch": 0 },
    "client_name": "Mumble",
    "os_name": "Windows",
    "os_version": "10"
  }
}
```

### HTTPS Fetch Import

The host provides `fetch` under both `env.fetch` and `shitspeak.fetch`:

```text
fetch(request_ptr: i32, request_len: i32, response_ptr: i32, response_capacity: i32) -> i32
```

The request is JSON:

```json
{
  "url": "https://auth.example.test/check",
  "method": "POST",
  "headers": { "content-type": "application/json" },
  "body": "{\"user\":\"alice\"}",
  "timeout_ms": 5000
}
```

The response buffer receives JSON containing `ok`, `status`, `status_text`, `headers`, `body`, and `error`. The return value is the response byte length. If the supplied response buffer is too small, the return value is the negative required length. Only `https://` URLs are allowed.

Although the guest imports this as a normal core-WASM function, the host implementation is async. A call to `fetch` may yield the Wasmtime invocation while the HTTP request is in flight, then resume the guest with the same return-value contract.

### Host Cache And State Imports

The host provides these imports under both `env` and `shitspeak`:

```text
cache_get(key_ptr: i32, key_len: i32, response_ptr: i32, response_capacity: i32) -> i32
cache_put(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32
cache_delete(key_ptr: i32, key_len: i32) -> i32
cache_clear() -> i32

state_get(key_ptr: i32, key_len: i32, response_ptr: i32, response_capacity: i32) -> i32
state_put(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32
state_delete(key_ptr: i32, key_len: i32) -> i32
state_clear() -> i32
```

`cache_*` is per-loaded-authenticator, in-memory, and lost on reload. Keys are up to 1024 bytes and values are 1 byte to 64 KiB.

`state_*` is durable key/value storage for the authenticator. It is available only when `blob_storage_dir` is configured; data is stored under a host-owned `wasm_authenticator` subdirectory. Keys are up to 1024 bytes and values are 1 byte to 16 MiB. When no persistence directory is configured, state operations return `0`.

For `*_get`, `0` means missing or unavailable, a positive value is the number of bytes written, a negative value is the required response size, and `-1` means error. For `*_put`, `*_delete`, and `*_clear`, `1` means changed or success, `0` means unavailable or absent, and `-1` means error.

### Raw Stream Imports

The host provides raw TCP, UDP, and file stream imports under both `env` and `shitspeak`:

```text
tcp_open(addr_ptr: i32, addr_len: i32, timeout_ms: i32) -> i32
udp_open(addr_ptr: i32, addr_len: i32) -> i32
file_open(path_ptr: i32, path_len: i32, flags: i32) -> i32
stream_read(handle: i32, response_ptr: i32, response_capacity: i32, timeout_ms: i32) -> i32
stream_write(handle: i32, request_ptr: i32, request_len: i32, timeout_ms: i32) -> i32
stream_seek(handle: i32, position: i64) -> i32
stream_close(handle: i32) -> i32
file_delete(path_ptr: i32, path_len: i32) -> i32
```

Socket addresses are UTF-8 `SocketAddr` strings such as `127.0.0.1:8080` or `[::1]:8080`. TCP and UDP payloads are raw bytes. `stream_read` returns bytes directly into the guest buffer; `stream_write` writes guest bytes as-is. Positive return values are handle IDs or byte counts, `0` means unavailable, EOF, timeout, or no deletion, a negative byte count means the read buffer was too small, and `-1` means error.

File streams are available only when `authenticator.wasm.file_access_dir` lists one or more directories. Guest paths are real filesystem paths: absolute paths are used directly, and relative paths resolve under `authenticator.wasm.working_dir` or the server process working directory when it is omitted. After resolution and path normalization, the target must be inside one of the configured access directories. `file_open` flags are `1` read, `2` write, `4` create, `8` truncate, and `16` append; combine them with bitwise OR.
