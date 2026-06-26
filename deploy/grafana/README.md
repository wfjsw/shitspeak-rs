# ShitSpeak S2S Grafana Artifacts

This directory contains provisionable Grafana and Prometheus examples for the
S2S topology metrics.

- `dashboards/shitspeak-s2s-topology.json`: Grafana dashboard with node/link
  tables, direct metrics, route views, packet IO, and a geomap.
- `provisioning/dashboards/shitspeak-s2s.yaml`: Grafana dashboard provider.
- `provisioning/datasources/mimir.yaml`: example Mimir datasource.
- `prometheus/prometheus.yml`: example scrape plus remote_write config.

The dashboard expects the Prometheus/Mimir datasource UID `mimir`. Update the
datasource UID or the dashboard `datasource.uid` values if your environment
uses a different name.

Each ShitSpeak node publishes only its own S2S observability contribution:
its node row, source-owned links and routes, local direct metrics, and local
debug packet IO. Scrape or remote-write every node independently, and the
dashboard combines the topology in Grafana/Mimir with PromQL grouped by the
stable logical labels such as `node`, `source`, `target`, `peer`, and
`transport`.
