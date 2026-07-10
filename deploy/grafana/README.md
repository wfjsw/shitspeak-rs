# ShitSpeak S2S Grafana Artifacts

This directory contains provisionable Grafana and Prometheus examples for the
S2S topology metrics.

- `dashboards/shitspeak-s2s-topology.json`: Grafana dashboard with node/link
  tables, build versions, direct metrics, route views, S2S queue status,
  transport and replication internals, S2S voice metrics, native voice
  internals, packet IO, and a node globe.
- `provisioning/dashboards/shitspeak-s2s.yaml`: Grafana dashboard provider.
- `provisioning/datasources/mimir.yaml`: configurable Prometheus/Mimir
  datasource.
- `prometheus/prometheus.yml`: example scrape plus remote_write config.
- `prometheus/shitspeak-alerts.yml`: example alert rules for S2S queue
  pressure, slow local voice routing, and stale realtime voice drops.

The dashboard's topology globe uses the `volkovlabs-echarts-panel` Grafana
plugin, also published as Business Charts. Install that plugin before
provisioning the dashboard.

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
