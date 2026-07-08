# Observability

[Docs index](README.md)

ShitSpeak exposes operational signals through structured logs, optional Loki shipping, S2S status pages, Prometheus text metrics, remote write, and Grafana provisioning examples.

## Local Logging

Use `RUST_LOG` while developing:

```powershell
$env:RUST_LOG = "debug"
cargo run
```

## Loki Logging

Enable `[logging.loki]` in `config.toml` or set equivalent `SHITSPEAK_LOGGING_LOKI_*` environment variables:

```toml
[logging.loki]
enabled = true
url = "http://localhost:3100"
filter = "shitspeak_rs=debug"
labels = { environment = "dev" }
```

If `filter` is omitted, Loki shipping defaults to `shitspeak_rs=<level>`, so dependency logs are not sent unless the directive is widened. Failed pushes are retried from a bounded in-memory cache. Loki streams automatically include a `node_id` label with the resolved S2S node id.

Useful tuning:

```toml
batch_size = 128
flush_interval_ms = 1000
queue_capacity = 4096
retry_cache_capacity = 4096
retry_initial_interval_ms = 1000
retry_max_interval_ms = 30000
```

## S2S Status Page

When clustering config includes:

```toml
[s2s]
status_http_listen = "0.0.0.0:64750"
```

the node exposes a local status page with topology, route, link, S2S queue,
packet IO, and compression views.

The same listener serves Prometheus metrics on `/metrics` and `/s2s/metrics`,
including `shitspeak_s2s_queue_status` for incoming and outgoing queue depth,
capacity, high watermark, samples, and full samples. S2S transport queue depth,
capacity, and high watermark are reported as bytes because those queues are
adaptive byte-budgeted queues.

## Metrics Server

The dedicated observability metrics endpoint is configured separately:

```toml
[observability.metrics]
enabled = true
listen = "0.0.0.0:64751"
path = "/metrics"
```

`/health` returns a simple health response.

The endpoint also emits `shitspeak_build_info`, a gauge with value `1` and
labels for the local node, app name, app version, commit hash, commit date, and
build date. Use it to compare deployed binary versions across scraped nodes.

## Remote Write

Remote write can send the metrics samples to Prometheus-compatible receivers such as Grafana Mimir:

```toml
[observability.metrics.remote_write]
enabled = true
url = "http://localhost:9009/api/v1/push"
labels = { environment = "local" }
interval_ms = 15000
batch_size = 4096
```

Authentication options:

```toml
tenant_id = "tenant"
username = "user"
password = "secret"
# bearer_token = "token"
```

If `bearer_token` is set, it takes precedence over basic auth.

## Grafana Artifacts

Grafana and Prometheus examples live under `deploy/grafana`:

- `dashboards/shitspeak-s2s-topology.json`
- `provisioning/dashboards/shitspeak-s2s.yaml`
- `provisioning/datasources/mimir.yaml`
- `prometheus/prometheus.yml`

The topology globe uses the `volkovlabs-echarts-panel` Grafana plugin, also published as Business Charts. See the [Grafana provisioning notes](../deploy/grafana/README.md).
