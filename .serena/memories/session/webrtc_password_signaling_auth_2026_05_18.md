# WebRTC Password Signaling Auth Step (2026-05-18)

Implemented password-auth bootstrap over the WebSocket signaling channel.

Files changed in this step:
- `src/server.rs`
  - Changed `Server.authenticator` from `Box<dyn Authenticator>` to `Arc<dyn Authenticator>` so the signaling server can share the same authenticator instance as native Mumble handlers.
  - Separate web listener and ALPN `http/1.1` shared-port route now pass `.with_authenticator(Arc::clone(&self.authenticator))` into `SignalingServer`.
  - ALPN route now calls `handle_stream_with_peer(tls_stream, real_ip, remote_addr, local_addr)` so auth auxiliary data can use the real client IP.
- `src/web/signaling.rs`
  - Added `SignalingServer::with_authenticator` and `handle_stream_with_peer`.
  - Added `SignalingContext` and `SignalingSession` for per-WebSocket auth state.
  - Extended signaling JSON to parse `{ "type": "authenticate", "auth": ... }` using existing `web::protocol::AuthRequest`.
  - Password auth calls the real `Authenticator::authenticate(username, Some(password), auxiliary)`.
  - Successful password auth emits typed `ServerEvent::Authenticated { session, display_name }`.
  - Failed password auth emits `ServerEvent::AuthenticationRejected { reason }`.
  - SSO still returns `authentication_rejected` with `sso authentication is not implemented yet`.
  - SDP offers and ICE candidates are now rejected with typed error events until authentication succeeds when web auth is enabled.
  - Existing WebRTC bridge still returns not-implemented after authentication/auth-disabled path.
- `web/sdk/shitspeak.js`
  - `authenticatePassword` and `authenticateSso` now send over the signaling WebSocket, not the RTC data channel.
  - Added `openSignaling`, `createAndSendOffer`, and `connectWithPassword`.
  - `connectWithPassword` opens WebSocket signaling, waits for `authenticated`, then creates/sends the WebRTC offer. If `authentication_rejected` or signaling `error` arrives first it rejects.
  - Non-SDP signaling messages are routed through the normal SDK server-event emitter.
- `web/sdk/shitspeak.d.ts`
  - Added typings for `openSignaling`, `createAndSendOffer`, and `connectWithPassword`.
- `web/demo/main.js`
  - Demo now uses `connectWithPassword(username, password)` and no longer waits for the RTC data channel to authenticate.

Tests added/updated:
- `websocket_password_authenticates_through_authenticator`
- `websocket_password_auth_reports_rejection`
- `websocket_offer_requires_authentication_when_auth_is_enabled`
- Existing offer-not-implemented test explicitly disables auth to keep testing the post-auth/auth-disabled placeholder bridge path.

Validation:
- `cargo test web:: --lib` passed: 15 passed.
- `cargo test --lib` passed: 298 passed, 4 ignored.

Important limitation left:
- This does not yet allocate a normal `Client` in `ClientRepository`; the repository still has `allocate_local_client(..., connection: TlsStream<TcpStream>)`, so web sessions cannot become first-class internal clients until client transport is refactored away from concrete TLS streams.
- WebRTC SDP/ICE/media bridge still not implemented.

Recommended next step:
- Refactor client transport so `Client` can be backed by either native TLS or a web gateway transport, then make an authenticated WebSocket allocate/publish a normal local client and replay initial state as typed SDK events.
