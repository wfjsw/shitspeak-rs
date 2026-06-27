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
quic_listen = "0.0.0.0:64741"
udp_listen = "0.0.0.0:64742"

tcp_advertise = "node-1.example.com:64739"
kcp_advertise = "node-1.example.com:64740"
quic_advertise = "node-1.example.com:64741"
udp_advertise = "node-1.example.com:64742"

status_http_listen = "0.0.0.0:64750"

seed_addresses = [
  { transport = "tcp", addr = "node-2.example.com:64739" },
  { transport = "quic", addr = "node-3.example.com:64741" },
]
```

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

## Transport Compression

S2S transport supports selective payload compression:

```toml
[s2s.transport]
compression_enabled = true
compression_min_bytes = 1024
compression_min_savings_percent = 10
compression_level = 1
compression_adaptive_dictionary_enabled = true
```

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
