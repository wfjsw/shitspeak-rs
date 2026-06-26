# systemd unit

This unit expects:

- binary: `/usr/local/bin/shitspeak-rs`
- config directory: `/etc/shitspeak-rs`
- config file: `/etc/shitspeak-rs/config.toml`
- runtime user/group: `root`, with systemd sandboxing and an empty capability set

Example install:

```sh
sudo install -Dm755 target/release/shitspeak-rs /usr/local/bin/shitspeak-rs
sudo install -d -m 0750 -o root -g root /etc/shitspeak-rs
sudo install -m 0600 -o root -g root config.toml /etc/shitspeak-rs/config.toml
sudo install -Dm644 packaging/systemd/shitspeak-rs.service /etc/systemd/system/shitspeak-rs.service
sudo systemctl daemon-reload
sudo systemctl enable --now shitspeak-rs
```

The unit intentionally runs as uid 0 for compatibility with existing state
ownership, but it removes Linux capabilities with `CapabilityBoundingSet=` and
uses filesystem and kernel hardening. `/root` is hidden from the service except
for a read-only bind mount of `/root/winterco` and a read-write bind mount of
`/root/winterco/state`. Existing state can be reused directly:

```sh
sudo mkdir -p /root/winterco/state
```

Keep certs, keys, WASM authenticators, and exec authenticator scripts under
`/etc/shitspeak-rs` or `/root/winterco`, and put writable application state under
`/root/winterco/state`.

If `authenticator.exec.uid` or `authenticator.exec.gid` is configured, add a
drop-in that grants only the permissions needed for that child-process drop:

```ini
[Service]
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
RestrictSUIDSGID=false
```
