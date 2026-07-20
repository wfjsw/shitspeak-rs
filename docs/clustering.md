# Clustering

[Docs index](README.md)

ShitSpeak includes an experimental server-to-server subsystem for multi-node operation. It includes transport sessions, overlay routing, replication, status pages, and content-addressed channel blob transfer.

## Components

- Transport: TCP, KCP, QUIC, and UDP peer connections with metrics and optional compression.
- Overlay: neighbor liveness, link-state database, routing, ordered messaging, and transit controls.
- Replications: strict and owner-mode replication paths for shared state.
- Application layer: voice, text, plugin data, moderation, and user statistics propagation.
- Status and metrics: local topology status page and Prometheus exposition.

## Minimal Shape

Enable S2S and provide identity, listen addresses, advertised addresses, seeds, and state storage:

```toml
[s2s]
enabled = true
ca_path = "s2s-ca.pem"
cert_path = "s2s-cert.pem"
key_path = "s2s-key.pem"
persistence_dir = "s2s-state"

tcp_listen = "0.0.0.0:64739"
kcp_listen = "0.0.0.0:64740"
quic_listen = "0.0.0.0:64740"
udp_listen = "0.0.0.0:64740"

tcp_advertise = "node-1.example.com:64739"
kcp_advertise = "node-1.example.com:64740"
quic_advertise = "node-1.example.com:64740"
udp_advertise = "node-1.example.com:64740"

status_http_listen = "0.0.0.0:64750"

seed_addresses = [
  { transport = "tcp", addr = "node-2.example.com:64739" },
  { transport = "quic", addr = "node-3.example.com:64741" },
]
```

KCP, QUIC, and packet-encrypted UDP can share one local UDP port. The server
binds one UDP socket and demultiplexes protocol frames in userspace using
`0x81` for KCP, `0x82` for QUIC, and `0x80` for UDP. Upgrade participating
nodes together because legacy unprefixed UDP-family traffic is rejected.

Every clustered node needs a unique S2S leaf certificate whose Common Name is the numeric node id. When S2S is disabled or no S2S certificate is configured, the local node id defaults to `0`.

Generate local S2S test certificates:

```powershell
cargo run --example gen-s2s-certs
```

## Address Advertisement

By default, S2S may advertise private RFC1918 IPv4 and IPv6 unique-local addresses. This keeps LAN, VPN, and container clusters working:

```toml
[s2s]
advertise_private_ips = true
```

Set `advertise_private_ips = false` when public deployments should not publish private addresses.

Wildcard listeners can advertise selected local interface addresses:

```toml
[s2s]
local_interface_advertise = ["tailscale0", "Tailscale"]
```

Interface names are matched case-insensitively. On Windows, adapter name, friendly name, and description are checked.

## QUIC Protocol Versions And Delivery Lanes

QUIC advertises ALPN protocols in the order `s2s/2`, `s2s/1`. Two upgraded
peers therefore use `s2s/2`; a connection to a peer that only supports
`s2s/1` retains the legacy single reliable stream, including its existing
BestEffort behavior.

An `s2s/2` session maps traffic as follows:

| Requested service level and class | QUIC delivery lane |
|---|---|
| `BestEffort`, any message class | QUIC DATAGRAM |
| Non-BestEffort `Control` | Persistent Control stream |
| Non-BestEffort `HighPriority` | Persistent HighPriority stream |
| Non-BestEffort `Regular` | Persistent Regular stream |

BestEffort takes precedence over the message class. The class is still carried
in the DATAGRAM frame and selects the inbound Control, HighPriority, or Regular
queue. Each reliable lane preserves FIFO order independently, but there is no
ordering guarantee between lanes. The three reliable streams have equal QUIC
priority; only the Control lane carries session liveness frames.

A QUIC DATAGRAM contains one transport frame and has no stream length prefix.
It is unreliable: QUIC does not retransmit it, it can be lost or reordered,
and a successful send only means that it was queued locally. ShitSpeak does not
fragment an oversized QUIC DATAGRAM or automatically move it to a reliable
lane. Application sequencing and repair remain responsible where needed.
Under pressure, the application DATAGRAM queue evicts older traffic in favor
of the newest traffic.

DATAGRAM payloads may use configured stateless L1 compression when the send
permits compression, but never use an adaptive dictionary. Each reliable lane
has independent adaptive-compression state. DATAGRAM and stream frames still
share the connection's congestion controller and path capacity; separate lanes
do not reserve bandwidth. Quinn sends already-queued DATAGRAM frames before
stream frames, so keep the DATAGRAM buffers shallow enough for the workload.

Protocol selection happens only during connection establishment. Existing
`s2s/1` sessions remain v1 until they reconnect, and failure while establishing
an already-negotiated v2 session does not downgrade that connection to v1.
Normal routing and reconnection handle the failure. For rolling upgrades,
deploy a dual-stack release first and retain `s2s/1` for at least one complete
rollback window. Remove v1 only after both active-v1 and newly-negotiated-v1
metrics remain zero for that entire window.

## Transport Compression

S2S transport supports selective payload compression:

```toml
[s2s.transport]
quic_session_setup_timeout_ms = 10000
quic_datagram_send_buffer_bytes = 65536
quic_datagram_receive_buffer_bytes = 262144
compression_enabled = true
compression_min_bytes = 1024
compression_min_savings_percent = 10
compression_level = 1
compression_adaptive_dictionary_enabled = true
```

The QUIC session setup timeout bounds establishment of the required class
lanes. QUIC DATAGRAM send and receive buffers default to 64 KiB and 256 KiB,
respectively; enabled buffers must be at least 1200 bytes.

Setting a DATAGRAM buffer to zero disables that local direction, but does not
disable the `s2s/2` ALPN offer or request an `s2s/1` downgrade. A zero receive
buffer means the endpoint cannot advertise the DATAGRAM support required by
v2. A zero send buffer also prevents the complete v2 mapping, so negotiated v2
setup fails when either local direction is disabled. Keep
both buffers nonzero for operational v2 sessions. A peer that supports only
`s2s/1` can still negotiate the legacy protocol normally.

When `s2s.persistence_dir` is configured, the latest learned adaptive compression dictionary is cached below that directory and renegotiated with peers after restart.

## Status Page And Metrics

`s2s.status_http_listen` exposes a local HTTP status page. It also serves Prometheus metrics on `/metrics` and `/s2s/metrics`.

The separate `[observability.metrics]` server can expose the same topology metrics on a dedicated endpoint. See [Observability](observability.md).

## Local 16-Node Demo

The Docker Compose demo under `examples/docker-compose-16node` creates a local 16-node cluster with generated per-node config and S2S certificates.

Build the Linux musl binary first:

```powershell
cross build --target=x86_64-unknown-linux-musl
```

Generate or refresh the demo:

```powershell
pwsh examples/docker-compose-16node/generate-compose-16node.ps1 -Force
```

Start it:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml up -d --build
```

Node `N` publishes Mumble TCP and UDP on `localhost:20000 + N` and its status page on `localhost:21000 + N`. Node 1 is reachable at `localhost:20001`, and its status page is `http://localhost:21001`.

More details are in the [16-node demo README](../examples/docker-compose-16node/README.md).
