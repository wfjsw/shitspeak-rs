# Deployment

[Docs index](README.md)

Before exposing ShitSpeak publicly, replace local test material and review authentication, TLS, persistence, registration, and network settings.

## Production Checklist

- Replace generated test certificates.
- Protect TLS private keys, S2S keys, authenticator modules, exec helper scripts, and persistent data.
- Use `authenticator.backend = "wasm"` or `authenticator.backend = "exec"` with production policy.
- Back up `blob_storage_dir` and `s2s.persistence_dir`.
- Configure `allowed_proxies` only for trusted PROXY protocol senders.
- Review public registration settings before enabling registry publication.
- Set the same certificate-hash privacy secret on every cluster node when privacy protection is enabled.
- Review browser gateway origins and certificates when `[web]` or `[web.moq]` is enabled.

## Docker

A root `Dockerfile` is included. The local 16-node example under `examples/docker-compose-16node` builds a cluster from a prebuilt Linux musl binary.

Build the Linux musl binary:

```powershell
cross build --target=x86_64-unknown-linux-musl --release
```

Generate or refresh the 16-node Compose material:

```powershell
pwsh examples/docker-compose-16node/generate-compose-16node.ps1 -Force
```

Start the cluster:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml up -d --build
```

Useful commands:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml ps
docker compose -f examples/docker-compose-16node/compose.yaml logs -f node-01
docker compose -f examples/docker-compose-16node/compose.yaml down -v
```

## systemd

The example unit is under `packaging/systemd/shitspeak-rs.service`. Its README includes install commands and notes about hardening and state layout:

- [systemd unit notes](../packaging/systemd/README.md)

Example install flow:

```sh
sudo install -Dm755 target/release/shitspeak-rs /usr/local/bin/shitspeak-rs
sudo install -d -m 0750 -o root -g root /etc/shitspeak-rs
sudo install -m 0600 -o root -g root config.toml /etc/shitspeak-rs/config.toml
sudo install -Dm644 packaging/systemd/shitspeak-rs.service /etc/systemd/system/shitspeak-rs.service
sudo systemctl daemon-reload
sudo systemctl enable --now shitspeak-rs
```

If `authenticator.exec.uid` or `authenticator.exec.gid` is configured, the hardened unit may need a drop-in that grants `CAP_SETUID` and `CAP_SETGID` for the child-process drop.

## Public Registration

Configure all required registration fields to publish to the public Mumble server list:

```toml
register_name = "My ShitSpeak Server"
register_password = "registry-password"
register_url = "mumble://voice.example.com:64738"
register_hostname = "voice.example.com"
register_location = "New York, USA"
```

Keep `udp_ping_enabled = true` for normal listing behavior.

## Certificates

Local helpers:

```powershell
cargo run --example gen-test-certs
cargo run --example gen-s2s-certs
```

These helpers are for development and test deployments. Use real operational certificate material in production.
