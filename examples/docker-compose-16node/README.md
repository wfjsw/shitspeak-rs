# Docker Compose 16-node demo

This folder generates and runs a local Docker Compose network shaped like the UTD 16-node deployment bundle. Every node runs the same server image, has a unique `node_id`, gets its own S2S ECDSA certificate/key pair, and seeds to the next two nodes in the ring.

The demo uses the already-built Linux musl binary so Docker does not need to rebuild the Rust dependency graph.

## Generate

Build the Linux binary from the repository root first:

```powershell
cross build --target=x86_64-unknown-linux-musl
```

Generate or refresh the Compose material:

```powershell
pwsh deploy/docker-compose-16node/generate-compose-16node.ps1 -Force
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
docker compose -f deploy/docker-compose-16node/compose.yaml up -d --build
```

Check containers and logs:

```powershell
docker compose -f deploy/docker-compose-16node/compose.yaml ps
docker compose -f deploy/docker-compose-16node/compose.yaml logs -f node-01
```

Stop the demo containers and network:

```powershell
docker compose -f deploy/docker-compose-16node/compose.yaml down
```

Runtime state is bind-mounted into each per-node folder. For example, node 1 stores server data in `nodes/node-01/data` and S2S state in `nodes/node-01/s2s-state`.

## Ports

Each container listens on the same internal ports as the UTD bundle:

1. `64738/tcp` and `64738/udp`: Mumble client listener
2. `64739/tcp`: S2S TCP listener
3. `64740/udp`: S2S KCP listener
4. `64741/tcp`: S2S QUIC listener
5. `64742/udp`: S2S UDP listener
6. `64750/tcp`: S2S status HTTP page

Host port assignments are deterministic:

1. node `N` client TCP and UDP: `20000 + N`
2. node `N` S2S status HTTP: `21000 + N`

For example, connect a Mumble client to node 1 at `localhost:20001`, and open node 1's S2S status page at `http://localhost:21001`.

The generated certificates are for local development only.
