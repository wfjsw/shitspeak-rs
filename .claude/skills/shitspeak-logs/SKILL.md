---
name: shitspeak-logs
description: Use when investigating ShitSpeak production or deployment behavior through Grafana/Loki logs, including requests to inspect recent errors, correlate node behavior, query LogQL, discover Loki labels, or compare logs with the repo's observability and deployment configuration. Requires the project-local shitspeak_grafana MCP server to be configured and authenticated.
---

# ShitSpeak Logs

Use the `shitspeak_grafana` MCP server for live Grafana/Loki access. Keep queries read-only and prefer narrow time ranges. The server is of UTC timestamp, but by default, user will provide local timestamp information. You need to convert it on your own.

Default Loki selector:

```logql
{service_name="shitspeak-rs", source="tracing_subscriber"}
```

## Workflow

1. Confirm the user has given a time window, environment/deployment, node, request id, user/session id, or symptom. If not, start with the smallest recent window that could answer the question.
2. Discover Loki datasource and label shape through Grafana when the datasource UID is unknown, but keep log searches scoped to the default selector unless the user explicitly asks to widen it.
3. Add more labels to the default selector only when they are known and useful, such as `job`, `instance`, `nodename`, `environment`, `target`, `peer`, `transport`, and `node`.
4. Start with the default selector, then narrow with text filters such as `|= "error"` or case-insensitive regex filters.
5. Summarize findings with concrete timestamps, labels, and representative log lines. Avoid dumping large log blocks unless the user asks.

## Repo Context

- App Loki shipping is documented in `docs/observability.md`.
- Example Loki app config lives under `[logging.loki]` in `config.toml`.
- Deployment examples under `deploy/winterco/**/config/config.toml` use `service_name = "shitspeak-rs"` and environment-specific labels.
- Grafana dashboard artifacts under `deploy/grafana` mostly cover Prometheus/Mimir S2S topology metrics; use them for metric correlation, not as proof that Loki labels exist.

## Guardrails

- Do not write to Grafana; the MCP server is configured with `--disable-write`.
- Do not expose service account tokens, Grafana URLs that the user treats as private, or sensitive log payloads in broad summaries.
- If the MCP server is unavailable, explain whether the issue is missing `GRAFANA_URL`, missing `GRAFANA_SERVICE_ACCOUNT_TOKEN`, network reachability to Grafana, or token permissions.
