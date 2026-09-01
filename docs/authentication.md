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
long_running_request_mode = "serialized" # serialized, async
command = "auth-helper"
args = []
environment = { AUTH_ENDPOINT = "https://auth.example", AUTH_MODE = "production" }
working_dir = "auth"
timeout_ms = 30000
max_response_bytes = 16777216
# uid = 1001
# gid = 1001
```

`environment` adds or overrides variables in the helper process environment. Other variables are inherited from the server process, and configured values are passed literally without expansion.

Unix `uid` and `gid` dropping is optional. If the systemd unit is hardened, extra capabilities may be required for child-process user/group changes. See [Deployment](deployment.md).

For `exec_long_running`, the server sends a `request_id` with each request. `long_running_request_mode = "serialized"` keeps one request in flight at a time and accepts legacy responses without `request_id`; if a response includes `request_id`, it must match. `long_running_request_mode = "async"` allows multiple in-flight requests and requires every response to include the matching `request_id`.

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

The server keeps a reusable pool of WASM instances instead of creating one per authentication call. Authenticator calls run on a bounded background-priority runtime so CPU-heavy login work does not occupy the Tokio workers serving ping and voice traffic. On Linux those workers use nice `+10`; on Windows they use the lowest thread-priority class. Positive `auth_finalization_concurrency` values control authenticator concurrency through the login queue; setting the value to `0` bypasses the queue and imposes no admission limit. WASM instance creation itself remains serialized even though the pool may grow as needed.

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
  "auth_session_id": "auth-session-7f3c",
  "user_id": 42,
  "fqdn": "alice.auth.example",
  "display_name": "Alice",
  "groups": ["admin"],
  "virtual_server_id": null,
  "language": "en",
  "max_bandwidth": null,
  "texture_url": null,
  "comment_url": null,
  "authenticated_until": "2026-07-22T20:30:00Z",
  "authentication_expiry_action": "reauth"
}
```

`max_bandwidth`, when present, overrides the configured `max_bandwidth` value advertised to that authenticated client.

`fqdn` is an optional authenticator-assigned, globally unique user identifier. It is replicated between cluster nodes but is not sent in Mumble `UserState` messages.

`auth_session_id` is an optional opaque identifier supplied by the authenticator. The server retains it for the connection and includes it as `auxiliary_data.auth_session_id` in later authentication requests for that connection, including expiry-triggered reauthentication.

`authenticated_until` is an optional RFC 3339 timestamp. The deadline and action are connection-local state and are not persisted. Once the deadline has passed, the server applies `authentication_expiry_action` on an idle-reaper pass. The action defaults to `kick` when omitted:

- `reauth` authenticates the user again with the original credential. The current `auth_session_id`, when one exists, is included in the request. The existing authenticated state remains in effect while the request is pending. A failed reauthentication disconnects the user; a successful response refreshes the user's identity, groups, local authentication metadata, and expiry settings. If the response selects a different virtual server, the user is disconnected.
- `kick` disconnects the user.
- `deregister` removes the connection's registered-user identity, reevaluates its ACL access, and disconnects it if it can no longer traverse the root channel. Other session state is retained.

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
    "tls_ja3": "771,4865-4866,10-11,23,0",
    "tls_ja4": "t13x0306h2_8daaf6152771_02713d6af862",
    "tls_ja4t": null,
    "tls_ja4x": null,
    "tls_ja4l": null,
    "tls_sni": "voice.example.test",
    "proxy_server_address": "192.0.2.5:443",
    "packet_capture_backends": ["ebpf", "af_packet"],
    "packet_capture_backend": "ebpf",
    "uses_proxy_protocol": false,
    "version": { "major": 1, "minor": 5, "patch": 0 },
    "client_name": "Mumble",
    "os_name": "Windows",
    "os_version": "10"
  }
}
```

`tls_ja3` and `tls_ja4` describe the TLS ClientHello; `tls_ja4x` describes the
presented client certificate. `tls_sni` is the client-provided server name.
`tls_ja3` is the canonical ordered JA3 field string, deliberately un-hashed so
authenticators do not need legacy MD5 to compare or inspect it.
When PROXY protocol is accepted, `proxy_server_address` identifies the trusted
transport peer that supplied it. `packet_capture_backends` is probed once at
server startup and ranks the Linux packet-observation options available to the
process: `ebpf` requires `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, and
`CAP_NET_RAW`; the `af_packet` fallback requires `CAP_NET_RAW`.
`packet_capture_backend` is the backend actually started, and is `null` if
capture setup failed.
`tls_ja4t` and `tls_ja4l` are `null` unless the listener has a TCP packet
metadata source that can observe the initial SYN packet; a regular accepted TCP
socket does not expose the required window, option-order, TTL, or SYN timing
data. They are also `null` for PROXY-protocol clients because the observed TCP
peer is the proxy, not the logical client.

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
