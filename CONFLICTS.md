# Design Conflicts & Divergences

This document records where `shitspeak-rs` intentionally diverges from the
reference implementations — the official [Mumble](https://github.com/mumble-voip/mumble)
server (`Murmur`, written in C++) and the Go-based [hall](https://github.com/volatiletech/hall)
server.

---

## 1. User Registration & Authentication

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| Local DB registration | Stripped | SQLite-backed | Pluggable `Authenticator` trait |

**Decision:** `shitspeak-rs` keeps a pluggable `Authenticator` trait with
default no-op methods.  External backends (LDAP, HTTP, database) implement the
trait.  This is **not a conflict** — it's a superset of both approaches.

---

## 2. Multiple Sessions Per User ID

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| Duplicate login | Ghost-kicks old session | Ghost-kicks old session | **Allows multiple simultaneous sessions** |

**Decision:** `shitspeak-rs` allows multiple simultaneous sessions per user ID.
The `ClientSessionIdentifier` (64-bit composite: `node_id << 20 | local_session_id`)
remains the unique per-session key.  No ghost-kick is performed on duplicate
login.  This is a deliberate divergence from both hall and mumble.

---

## 3. User Textures & Comments (Blobs)

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| User textures | Stripped | Fully supported | Fully supported |
| Blob storage | N/A | In-process | `ChannelBlobStore` + `SessionBlobStore` |

**Decision:** `shitspeak-rs` implements blobs via two content-addressed stores:
- `ChannelBlobStore` — persistent, local-primary, S2S-propagated (channel descriptions)
- `SessionBlobStore` — persistent URL-keyed cache (user textures/comments)

This **partially aligns with mumble** — the blob concept is the same, but the
storage backend differs (mumble stores blobs in-process; shitspeak-rs uses
disk-backed SHA-1 content-addressed stores with HTTP fetch for session blobs).

---

## 4. Channel Storage

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| Channel storage | SQLite | SQLite | In-memory HashMap + WAL + snapshot |

**Decision:** `shitspeak-rs` uses `ChannelRepository` — an in-memory
`HashMap<u32, Channel>` with an append-only JSON-lines WAL and periodic JSON
snapshots.  This is **not a conflict with mumble** — it's a different storage
backend that achieves the same durability guarantees without an external
database dependency.

---

## 5. Temporary Channels

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| Temporary channels | Stripped | Supported (bit-31 ID) | Supported (bit-31 ID) |

**Decision:** `shitspeak-rs` implements temporary channels per the mumble spec.
Channel IDs with bit-31 set are treated as temporary.  This **aligns with
mumble**.

---

## 6. ACL Group Expressions

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| Group directives | Partial | Full expression engine | Full expression engine |

**Decision:** `shitspeak-rs` has a complete group expression engine in
`src/client/group.rs` supporting: `all`, `none`, `auth`, `in`, `out`, `sub`,
`~sub`, `!sub`, `#sub`, `$cert`, `%cidr`, `%asn`, `%country`, and token
variants (`#@`, `#$`).  This **aligns with mumble**.

---

## 7. `broadcastListenerVolumeAdjustments`

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| Volume adjustment broadcast | N/A | Configurable | Configurable (`Config::broadcast_listener_volume_adjustments`) |

**Decision:** Per the mumble spec, when `broadcast_listener_volume_adjustments`
is `true`, volume adjustments are included in `UserState` broadcasts to all
v1.4.0+ clients.  When `false`, they are sent only to the owning session.
This is configured via `Config::broadcast_listener_volume_adjustments: bool`
(default: `true`).

---

## 8. UDP Voice Transport

| Aspect | hall | mumble (Murmur) | shitspeak-rs |
|--------|------|-----------------|-------------|
| UDP sendmmsg | N/A | Uses `sendmmsg` | Uses standard `tokio::net::UdpSocket` |

**Decision:** `shitspeak-rs` skips `sendmmsg` batching for UDP.  Standard
`tokio::net::UdpSocket` with per-packet `send_to` is used.  TCP control
channel messages are batched via `write_proto_message_batch()` to reduce
syscall overhead.

---

## 9. Excluded Features

The following mumble features are explicitly **out of scope** for `shitspeak-rs`:

- **Server registration** (public server list)
- **Zeroconf / Bonjour** service discovery
- **`PluginDataTransmission`** message handling
- **Ice / audio backends** (server-side audio mixing)

---

## 10. Cryptographic Backend

| Aspect | mumble (Murmur) | shitspeak-rs |
|--------|-----------------|-------------|
| Crypto library | OpenSSL | `aws-lc-rs` |

**Decision:** `shitspeak-rs` uses `aws-lc-rs` for all cryptographic operations
(OCB2-AES128 for voice, SHA-1 for content hashing via `SHA1_FOR_LEGACY_USE_ONLY`).
This is a non-functional difference — the wire protocol is identical.

---

*Last updated: 2026-04-21*
