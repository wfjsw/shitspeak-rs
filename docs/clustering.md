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

## BestEffort Datagram Preference

For every `BestEffort` route, raw UDP and the DATAGRAM delivery path on an
eligible `s2s/2` QUIC session form one preferred datagram tier when the
complete frame fits. The requested routing metric chooses between eligible raw
UDP and QUIC DATAGRAM paths, giving them equal tier priority. Eligible datagram
paths stay ahead of TCP, KCP, and QUIC reliable streams. Reliable fallback is
used only when datagrams are unavailable, do not fit the frame, or have
degraded or blocked health. Probing and viable datagram paths remain eligible;
lack of samples alone does not force reliable fallback. Within that fallback,
current queue pressure and the requested routing metric choose between QUIC
streams and TCP.

QUIC DATAGRAM is a delivery path on the existing QUIC session, not a separate
physical `TransportKind`; it shares that connection's network path, congestion
controller, and capacity. For BestEffort, QUIC stream delivery remains an
explicit reliable fallback alongside TCP and KCP. An item is sent on a reliable
lane only after routing selects that delivery path; DATAGRAM enqueue failure
does not silently convert it to a reliable lane.

Selection telemetry preserves this logical distinction:
`shitspeak_s2s_delivery_path_selections_total{path="quic_datagram"}` and
`{path="quic_stream"}` report the two QUIC delivery paths separately. Physical
QUIC RTT, loss, and health remain shared under `TransportKind::Quic`; the path
label describes delivery semantics, not a separate network link.

BestEffort datagram health also runs as a shadow-only hysteretic observer, and
its `suspect` state does not affect selection. Raw UDP uses weighted effective
loss. QUIC DATAGRAM instead uses peer/path-local app-queue rejection and writer
failure. Quinn buffer pressure, too-large events, and ingress validation remain
separate diagnostic counters. No DATAGRAM ACK, on-time delivery, or end-to-end
packet-loss signal exists. Aggregate QUIC stream RTT/loss does not drive this
local score, and the observer does not affect routing or KCP behavior.

QUIC DATAGRAM uses fixed one-second evidence windows with bounded 64-window
replay. It requires two or three distinct completed bad windows (three by
default) before entering `suspect`, and new completed healthy windows spanning
10--30 seconds before recovery. Re-reading one window cannot advance either
gate. Stale evidence returns the observer to `probing` without clearing the
recovery latch; replacing the session starts a tokenized evidence generation,
and late outcomes from the replaced session are ignored. Status keeps the last
scored generation separate from newer diagnostic-only generations. JSON and
bounded `shitspeak_s2s_datagram_path_*` Prometheus gauges expose state, reason,
score, confidence, window counters, pending temporal progress, transitions,
and freshness.

UDP-family health and viability gates still apply. Unhealthy or unusable
datagram candidates are excluded, and the QUIC DATAGRAM path is excluded from
the tier when the encoded frame does not fit its current maximum DATAGRAM
size. Normal stream fallback applies when no eligible datagram candidate
remains. For every BestEffort route, KCP's measured cost is increased by
`best_effort_kcp_cost_penalty_pct` (25% by default), while unmeasured KCP is
ordered after QUIC and TCP. KCP remains available when its adjusted metric
wins or it is the only fallback. `Reliable` traffic is unaffected. After KCP
fails away or closes for no forward progress, expiring high-priority
conversational voice requires fresh KCP acknowledgement/RTT progress before
admitting it again. An eligible datagram path may replace a reliable incumbent
immediately. Voice min-hold and challenger confirmation continue to govern
other path changes.

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

## Voice Repair Allocation

Voice repair uses one conserved global currency: each encoded original byte
mints one quarter-byte of repair credit only after the aggregate primary send is
accepted. A failed primary send mints nothing. Proactive copies, NACK responses,
tail attempts, and their retries all pay their encoded payload size from that
ledger. The proactive/reactive entitlements, protected reactive reserve, and
borrowing rules partition this credit; none of them creates a second mint.

Proactive first copies receive a small deterministic destination-fair phase.
Shared overflow then ranks candidates by marginal utility per byte, combining
measured alternate loss and on-time probability, terminator value, a
first-hop/transport diversity proxy, deadline urgency, diminishing returns for
another copy, and fairness aging. Copy demand remains under the existing
UDP-only loss/jitter policy; scoring does not generate QUIC-DATAGRAM copies and
only allocates the conserved budget among candidates that policy generated.
Continuously waiting overflow gains 3.125% priority per allocator round, capped
at 1.5 times after 16 rounds, without minting credit. The batch uses pre-send
route-quality and deadline snapshots plus deterministic tie-breaking, so
destination iteration order does not decide who receives credit. Diversity and
on-time arrival remain estimates: a different first hop does not prove
downstream independence, and no repair delivery ACK is available to this
allocator.

Reactive permits are scheduled per encoded frame. Each destination is ordered
by earliest deadline, while deterministic byte-deficit round robin shares
service across destinations and a per-destination epoch cap defers excess retry
traffic. Temporary credit exhaustion parks rather than sheds live work, and
only a delivered permit advances fairness/retry accounting. NACKs carry the
requester's remaining actionable-gap time as a relative duration; the responder
bounds it locally and applies it to permit waiting and send attempts. This
requires no synchronized clock, but it also cannot subtract request-path transit
time and therefore does not guarantee receiver-side on-time delivery.
Aggregate scheduler metrics expose queued items/bytes, active destinations,
oldest wait, maximum starvation rounds, and bounded grant/wait/defer/expiry/
cancellation/shutdown events without per-request label cardinality.

NACK ranges and tail suffixes advance one frame at a time. The current frame
from every ready key enters the shared allocator before transport concurrency
is applied, then a successful frame requeues the next sequence behind other
ready work. Deferred retries and temporarily unaffordable large frames are
skipped while eligible fresh or smaller same-destination work is considered.
Actual transport sends remain bounded and same-destination repair sends remain
serialized.

Tail repair uses protected reactive credit, primary sender admission, and a
separate sender pressure lane. It remains proactive-marked at the receiver,
because no later frame exists to open a reorder gap for a lost terminator. Tail
is consequently not yet a fully isolated reactive receiver path.

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
