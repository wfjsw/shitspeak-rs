import { JSON } from "json-as";

@external("shitspeak", "fetch")
declare function hostFetch(requestPtr: i32, requestLen: i32, responsePtr: i32, responseCapacity: i32): i32;

@external("shitspeak", "log")
declare function hostLog(level: i32, ptr: i32, len: i32): void;

// ── Allocator ─────────────────────────────────────────────────────────────────
// The host calls alloc/dealloc to manage shared memory regions used for
// passing JSON request bytes in and reading JSON response bytes out.

const liveBuffers = new Array<ArrayBuffer>();

export function alloc(len: i32): i32 {
  const buffer = new ArrayBuffer(len > 0 ? len : 1);
  liveBuffers.push(buffer);
  return changetype<i32>(buffer);
}

export function dealloc(ptr: i32, _len: i32): void {
  for (let i = 0; i < liveBuffers.length; i++) {
    if (changetype<i32>(liveBuffers[i]) === ptr) {
      liveBuffers.splice(i, 1);
      return;
    }
  }
}

// ── Wire types ────────────────────────────────────────────────────────────────

@json
class AuthenticateRequest {
  username: string = "";
  password: string | null = null;
}

@json
class AuthenticateResponse {
  accepted: bool = true;
  @omitnull()
  rejection: string | null = null;
  // Nullable integer: use JSON.Box so the field serialises as a JSON number
  // when set, or is omitted entirely when null.
  @omitnull()
  user_id: JSON.Box<i32> | null = null;
  @omitnull()
  display_name: string | null = null;
  groups: string[] = [];
  is_superuser: bool = false;
  @omitnull()
  virtual_server_id: string | null = null;
  language: string = "en";
  @omitnull()
  max_bandwidth: JSON.Box<i32> | null = null;
  @omitnull()
  texture_url: string | null = null;
  @omitnull()
  comment_url: string | null = null;
}

@json
class FetchRequest {
  url: string = "";
  method: string = "GET";
  headers: Map<string, string> = new Map<string, string>();
  body: string | null = null;
  timeout_ms: i32 = 5000;
}

@json
class FetchResponse {
  ok: bool = false;
  // 0 when no HTTP response was received (network error).
  status: i32 = 0;
  status_text: string = "";
  headers: Map<string, string> = new Map<string, string>();
  @omitnull()
  body: string | null = null;
}

// ── Exports ───────────────────────────────────────────────────────────────────

export function authenticate(ptr: i32, len: i32): u64 {
  const request = JSON.parse<AuthenticateRequest>(readString(ptr, len));

  if (request.username == "admin") {
    if (request.password == "secret") {
      const resp = new AuthenticateResponse();
      resp.user_id = new JSON.Box<i32>(1);
      resp.display_name = "Admin";
      resp.groups = ["admin"];
      resp.is_superuser = true;
      return writeResponse(resp);
    }
    return writeResponse(mkReject("wrong_password"));
  }

  if (request.username == "guest") {
    const resp = new AuthenticateResponse();
    resp.display_name = "guest";
    setLanguage(resp, request.username);
    return writeResponse(resp);
  }

  if (request.username.startsWith("fetch:")) {
    return authenticateWithFetch(request.username.slice(6));
  }

  return writeResponse(mkReject("no_such_user"));
}

// ── Fetch-backed authentication ───────────────────────────────────────────────

function authenticateWithFetch(username: string): u64 {
  const fetchReq = new FetchRequest();
  fetchReq.url =
    "https://auth.example.test/mumble/check?user=" + encodeComponent(username);

  const fetchResp = doFetch(fetchReq);
  if (fetchResp == null) {
    log(2, "authenticateWithFetch: request failed");
    return writeResponse(mkReject("retry_later"));
  }

  if (!fetchResp.ok || fetchResp.status != 200) {
    return writeResponse(mkReject("retry_later"));
  }

  const resp = new AuthenticateResponse();
  resp.display_name = username;
  setLanguage(resp, username);
  return writeResponse(resp);
}

function doFetch(request: FetchRequest): FetchResponse | null {
  const reqJson = JSON.stringify(request);
  const reqBuffer = String.UTF8.encode(reqJson, false);
  const reqPtr = alloc(reqBuffer.byteLength);
  memory.copy(reqPtr, changetype<usize>(reqBuffer), reqBuffer.byteLength);

  const initCapacity = 8192;
  let respPtr = alloc(initCapacity);
  let written = hostFetch(reqPtr, reqBuffer.byteLength, respPtr, initCapacity);

  if (written < 0) {
    dealloc(respPtr, initCapacity);
    const required = -written;
    respPtr = alloc(required);
    written = hostFetch(reqPtr, reqBuffer.byteLength, respPtr, required);
    if (written < 0) {
      dealloc(respPtr, required);
      dealloc(reqPtr, reqBuffer.byteLength);
      return null;
    }
  }
  dealloc(reqPtr, reqBuffer.byteLength);

  const respJson = readString(respPtr, written);
  dealloc(respPtr, written);

  return JSON.parse<FetchResponse>(respJson);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function mkReject(reason: string): AuthenticateResponse {
  const resp = new AuthenticateResponse();
  resp.accepted = false;
  resp.rejection = reason;
  return resp;
}

function setLanguage(resp: AuthenticateResponse, username: string): void {
  if (username.endsWith(".es")) {
    resp.language = "es";
  }
}

function writeResponse(resp: AuthenticateResponse): u64 {
  return writeString(JSON.stringify(resp));
}

function writeString(value: string): u64 {
  const buffer = String.UTF8.encode(value, false);
  const ptr = alloc(buffer.byteLength);
  memory.copy(ptr, changetype<usize>(buffer), buffer.byteLength);
  return (u64(ptr) << 32) | u64(buffer.byteLength);
}

function readString(ptr: i32, len: i32): string {
  return String.UTF8.decodeUnsafe(ptr, len, true);
}

function log(level: i32, message: string): void {
  const buffer = String.UTF8.encode(message, false);
  hostLog(level, changetype<i32>(buffer), buffer.byteLength);
}

// Percent-encodes characters that are not URL-safe (RFC 3986 unreserved set).
function encodeComponent(value: string): string {
  let result = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (
      (code >= 0x41 && code <= 0x5a) || // A-Z
      (code >= 0x61 && code <= 0x7a) || // a-z
      (code >= 0x30 && code <= 0x39) || // 0-9
      code == 0x2d || code == 0x5f || code == 0x2e || code == 0x7e // - _ . ~
    ) {
      result += value.charAt(i);
    } else {
      result += "%" + (code < 0x10 ? "0" : "") + code.toString(16).toUpperCase();
    }
  }
  return result;
}
