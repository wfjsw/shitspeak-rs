# systemd unit

This unit expects:

- binary: `/usr/local/bin/shitspeak-rs`
- config directory: `/etc/shitspeak-rs`
- config file: `/etc/shitspeak-rs/config.toml`
- runtime user/group: `root`, with systemd sandboxing and an empty capability set

Install the binary, configuration, and unit at those paths through the local
package-management process, then reload systemd and enable the service.

`ProtectSystem=strict` makes the configuration directory read-only. Configure
all writable application state below the directory created by
`StateDirectory=shitspeak-rs`.

The unit intentionally runs as uid 0 for compatibility with existing state
ownership, but it removes Linux capabilities with `CapabilityBoundingSet=` and
uses filesystem and kernel hardening. Keep certificates, keys, WASM
authenticators, and exec authenticator scripts in the configuration directory;
keep writable application state only in the service state directory.

If `authenticator.exec.uid` or `authenticator.exec.gid` is configured, add a
drop-in that grants only the permissions needed for that child-process drop:

```ini
[Service]
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
RestrictSUIDSGID=false
```
