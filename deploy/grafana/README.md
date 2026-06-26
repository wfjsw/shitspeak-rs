# ShitSpeak S2S Grafana Artifacts

This directory contains provisionable Grafana and Prometheus examples for the
S2S topology metrics.

- `dashboards/shitspeak-s2s-topology.json`: Grafana dashboard with node/link
  tables, direct metrics, route views, packet IO, and a geomap.
- `provisioning/dashboards/shitspeak-s2s.yaml`: Grafana dashboard provider.
- `provisioning/datasources/mimir.yaml`: configurable Prometheus/Mimir
  datasource.
- `prometheus/prometheus.yml`: example scrape plus remote_write config.

The dashboard's topology map uses the `vaduga-mapgl-panel` Grafana plugin.
Install that plugin before provisioning the dashboard.
The `map_projection` dashboard variable records the desired flat/globe mode,
but current `vaduga-mapgl-panel` geo rendering does not consume that option.

The dashboard uses a Grafana datasource variable named `datasource`, defaulting
to the provisioned UID `mimir`. Override the example datasource provisioning
with Grafana environment variable expansion when needed:

- `SHITSPEAK_GRAFANA_DATASOURCE_UID`: datasource UID, default `mimir`.
- `SHITSPEAK_GRAFANA_DATASOURCE_URL`: datasource URL, default
  `http://mimir:9009/prometheus`.

Each ShitSpeak node publishes only its own S2S observability contribution:
its node row, source-owned links and routes, local direct metrics, and local
debug packet IO. Scrape or remote-write every node independently, and the
dashboard combines the topology in Grafana/Mimir with PromQL grouped by the
stable logical labels such as `node`, `source`, `target`, `peer`, and
`transport`.
