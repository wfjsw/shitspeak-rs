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

## systemd

The example unit is under `packaging/systemd/shitspeak-rs.service`. Its README
describes hardening and state layout:

- [systemd unit notes](../packaging/systemd/README.md)

Follow the unit notes for installation and hardening guidance. If
`authenticator.exec.uid` or `authenticator.exec.gid` is configured, the
hardened unit may need a drop-in that grants `CAP_SETUID` and `CAP_SETGID` for
the child-process drop.

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

Use certificate material appropriate for the server's configured public
identity and store its private keys securely.
