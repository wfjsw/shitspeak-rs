# Docker Compose 16-node demo

This folder generates and runs a local Docker Compose network shaped like the UTD 16-node deployment bundle. Every node runs the same server image, gets its own S2S ECDSA certificate/key pair with a numeric Common Name node id, and seeds to the next two nodes in the ring.

The demo uses the already-built Linux musl binary so Docker does not need to rebuild the Rust dependency graph.

## Generate

Build the Linux binary from the repository root first:

```powershell
cross build --target=x86_64-unknown-linux-musl
```

Generate or refresh the Compose material:

```powershell
pwsh examples/docker-compose-16node/generate-compose-16node.ps1 -Force
```

The generator writes:

1. `compose.yaml`
2. `image/Dockerfile` and `image/shitspeak-rs`
3. shared client TLS and S2S CA files under `shared/`
4. per-node `config.toml`, `s2s-cert.pem`, `s2s-key.pem`, `data/`, and `s2s-state/` under `nodes/node-01` through `nodes/node-16`
5. `manifest.json` with host port assignments

When re-run with `-Force`, generated config and certificate material is replaced, but existing per-node `data/` and `s2s-state/` directories are kept.

## Run

Start the local cluster:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml up -d --build
```

Check containers and logs:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml ps
docker compose -f examples/docker-compose-16node/compose.yaml logs -f node-01
```

Stop the demo containers and network:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml down
```

Runtime state is bind-mounted into each per-node folder. For example, node 1 stores server data in `nodes/node-01/data` and S2S state in `nodes/node-01/s2s-state`.

## Transport IO Survey

For debug builds, `survey-transports.ps1` runs the 16-node stack once per S2S
transport and records a steady-state packet/byte breakdown from the topology
debug counters plus container `eth0` and `/proc/net/snmp` counters:

```powershell
cd examples/docker-compose-16node
.\survey-transports.ps1 -Transport all -CleanState
```

Results are written under `.transport-survey/results-*`. The script temporarily
rewrites generated node configs to isolate each transport, stops compose between
runs, and restores the configs when it exits.

## Serialized pre-release netem gate

`pre-release-netem-scenario.json` defines a deterministic 15-minute release
scenario. Nodes 1-8 and 9-16 form two local regions. The long-haul profiles span
409-1288 ms one-way delay and 450-750 ms jitter, including a deterministic
Gilbert-Elliott burst-loss interval. Rules match both TCP request and reply
directions and each KCP, QUIC, and UDP destination port. The timeline serializes
per-transport endpoint loss, a four-node minority partition that preserves the
12-node quorum, node restart, and recovery.

Regenerate the demo after pulling changes so the image includes `tc` and every
node receives `NET_ADMIN`, then build and run the gate:

```powershell
cross build --target=x86_64-unknown-linux-musl `
  --target-dir target/pre-release-workload --features pre-release-workload
pwsh examples/docker-compose-16node/generate-compose-16node.ps1 `
  -PreReleaseWorkload -Force
pwsh examples/docker-compose-16node/run-pre-release-netem.ps1 -Build
```

The runner starts the cluster, waits for all health endpoints, applies timeline
events one at a time, samples every 15 seconds, clears netem on exit, and runs
strict acceptance checks. A failed check returns a nonzero exit code.

The workload driver is mandatory because the production status endpoint cannot
inject an encrypted semantic `DistributionAck` loss or export strict ordered
histories. The runner invokes it concurrently with `-ArtifactDirectory`,
`-ScenarioPath`, and `-DurationSeconds` parameters. It must generate concurrent
strict proposals and generic tree traffic, restart a node during an in-flight
proposal, drop a selected distribution ACK through test-support fault control,
and run mirrored tree and legacy performance phases. A schema-v2 control file
holds the run ID, phase, scoring window, and ACK-fault arm state, so restarted
processes cannot infer a phase from local uptime. Tree sends continue unscored
through restart windows. The exact fail-closed evidence
contract is in `workload-summary.schema.json`. `logs_by_node` and
`deliveries_by_node` contain ordered operation IDs and delivered packet IDs, not
version counters. Metric-only LSA counts are emission events, not per-neighbor
flood packet counts.

The two CPU fields are source-container mean CPU percentages over mirrored
phases with equal sample counts. Logical-send counts must remain within the
configured tolerance. The operation fields are cluster-aggregate physical
encode/send deltas from `shitspeak_s2s_debug_packet_io_packets_total` for
`overlay.data.tag.251`, normalized by scored logical sends during acceptance.

Result bundles are written below `.pre-release-netem/results-*`. They contain
the scenario, topology snapshots, selected public Prometheus metrics, `tc`
state, aggregate container stats, workload output, container/workload logs, and
an acceptance report. They intentionally exclude node configs, container
environment, certificates, and keys.

Useful lower-level commands:

```powershell
# Apply or inspect one rule set on an already-running stack.
pwsh examples/docker-compose-16node/netem-controller.ps1 -Action Apply -RuleSet baseline
pwsh examples/docker-compose-16node/netem-controller.ps1 -Action Show
pwsh examples/docker-compose-16node/netem-controller.ps1 -Action Clear

# Re-evaluate an existing artifact bundle after adjusting acceptance thresholds.
pwsh examples/docker-compose-16node/test-pre-release-netem.ps1 `
  -ArtifactDirectory examples/docker-compose-16node/.pre-release-netem/results-YYYYMMDD-HHMMSS
```

`-NoStart` reuses a running stack, `-KeepNetem` preserves the final qdisc state,
and `-SkipAcceptance` is intended only for controller/collector development.

## Ports

Each container listens on the same internal ports as the UTD bundle:

1. `64738/tcp` and `64738/udp`: Mumble client listener
2. `64739/tcp`: S2S TCP listener
3. `64740/udp`: S2S KCP listener
4. `64741/udp`: S2S QUIC listener
5. `64742/udp`: S2S UDP listener
6. `64750/tcp`: S2S status HTTP page

Host port assignments are deterministic:

1. node `N` client TCP and UDP: `20000 + N`
2. node `N` S2S status HTTP: `21000 + N`

For example, connect a Mumble client to node 1 at `localhost:20001`, and open node 1's S2S status page at `http://localhost:21001`.

The generated certificates are for local development only.
