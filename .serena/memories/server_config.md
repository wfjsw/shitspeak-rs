# Server & Connection Handling

## Server (src/server.rs)
- `Server` struct — main server
- `replay_client_log_gap` — replay missed client state log entries
- `replay_channel_log_gap` — replay missed channel log entries
- `recv_optional` — helper for optional message reception

## Config (src/config.rs)
- `Config` struct — loaded from config.toml
- Default functions: `default_max_bandwidth`, `default_true`, `default_max_text_message_length`, `default_max_image_message_length`, `default_udp_channel_size`, `default_idle_timeout`

## TLS (src/client_certificate_verifier.rs)
- `ClientCertificateVerifier` — implements rustls `ClientCertVerifier`
- Custom certificate verification logic

## PROXY Protocol (src/proxy_protocol.rs)
- `get_proxy_protocol_real_ip` — extract real client IP from PROXY protocol header
- `convert_v1_addresses_to_ipaddr` — parse v1 header addresses
- `convert_v2_addresses_to_ipaddr` — parse v2 header addresses
- `GetProxyProtocolRealIpError` enum

## GeoIP (src/geoip.rs)
- `Config` struct — GeoIP database path configuration
- Uses maxminddb with mmap

## Protocol Version (src/protocol_version.rs)
- `ProtocolVersion` newtype over u32/u64
- Conversions: From<u32>, From<u64>, ToString

## Codec Info (src/codec_info.rs)
- `CodecInfo` struct — codec negotiation data
- Implements Default

## Constants (src/constants.rs)
- `MAX_NODE_ID` = 4095, `MAX_LOCAL_SESSION_ID` = 1,048,575
- `MTU` = 1500
- Build metadata: `APP_NAME_FROM_ENV`, `APP_VERSION_FROM_ENV`, `APP_PROTO_VER`, `BUILD_DATE`, `COMMIT_HASH`, `COMMIT_DATE`
- Functions: `app_name()`, `app_version()`, `release()`
