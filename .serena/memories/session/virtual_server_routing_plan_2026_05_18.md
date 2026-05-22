# Virtual server routing decisions (2026-05-18)

User wants virtual servers through SNI, different TCP/UDP ports, and authenticator-based override.

Decisions:
- Virtual server IDs are strings.
- Channels are separated per virtual server logically, but all virtual-server channel records live in one shared ChannelRepository for easier implementation; channel identity must include the virtual server ID.
- Authenticator, user accounts/sessions, bans, most global config, and UDP infrastructure are shared.
- Live presence, user broadcasts, channel operations, text/voice routing, and channel subscriptions must be scoped to the client's final virtual server because channel IDs are only meaningful inside that virtual server's channel tree.
- Authentication has highest routing priority: `AuthenticateResult` should include `virtual_server_id: Option<String>`.
- If authenticator returns `Some(id)`, that ID is the final virtual server even if it is not present in config.
- Config only declares port/SNI entrypoints for virtual servers; it does not bound the set of auth-selectable virtual server IDs.
- An auth-forced unknown ID materializes/uses the corresponding virtual server channel tree and places the user there.
- If authenticator returns `None`, final route falls back to port, then SNI, then default virtual server.
- Port-based virtual servers should bind matching UDP ports.
- Public registration is related only to the default virtual server; non-default virtual servers are not independently registered.
- SNI should use rustls `ClientHello::server_name()` for cert selection and `ServerConnection::server_name()` after handshake for routing metadata.
