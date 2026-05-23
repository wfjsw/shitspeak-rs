# KCP listener receiving DTLS-looking packets (2026-05-23)

Observed log:
`tokio_kcp::session ... UDP input 59 bytes error: invalid segment data size ... input buffer b"\x17\xfe\xfd..."`

The byte prefix `17 fe fd` is a DTLS 1.2 record header (`0x17` application data, `0xfefd` DTLS 1.2). This means non-KCP DTLS traffic reached the S2S KCP UDP listener, commonly port `64740` in the docker-compose-16node example. `tokio_kcp` 0.9.8 accepts any UDP packet at least KCP-overhead-sized and treats the first four bytes as a KCP conversation id, so DTLS noise can produce scary `invalid segment data size` errors from the dependency before app-level TLS/KCP handling sees it.

Checked the generated compose example: S2S config advertises KCP on `64740/udp` and DTLS UDP on `64742/udp`; no generated `udp` peer address in node-10 persisted state used port 64740. The generated `[web]` block is disabled, but its sample `listen/public_base_url` use `64740`, which would be a confusing conflict if someone enables web without changing ports.

Operational things to check: ensure S2S UDP/DTLS clients and `udp_advertise` use `64742`, not `64740`; clear stale `nodes/*/s2s-state` when switching environments; avoid enabling web/MoQ on S2S KCP/QUIC ports; optionally filter `tokio_kcp::session` logs if unavoidable internet DTLS noise is hitting the KCP port.