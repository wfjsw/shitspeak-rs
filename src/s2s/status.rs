use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::s2s::overlay::{MemberStatus, OverlayNetwork, RoutingMetric};
use crate::s2s::transport::{ConnectionManager, TransportKind};
use crate::s2s::transport::{MessageClass, ServiceLevel, ServiceShape};
use crate::types::NodeIdentifier;

const MAX_REQUEST_BYTES: usize = 8192;

#[derive(Debug, Serialize)]
struct TopologySnapshot {
    local_node: NodeIdentifier,
    generated_at_unix_ms: u128,
    nodes: Vec<TopologyNode>,
    links: Vec<TopologyLink>,
    routes: Vec<TopologyRoute>,
    local_metrics: Vec<TransportMetric>,
}

#[derive(Debug, Serialize)]
struct TopologyNode {
    node_id: NodeIdentifier,
    status: &'static str,
    boot_epoch: u64,
    max_users: u64,
    addresses: Vec<TopologyAddress>,
    transit_enabled: bool,
    lsa_seq: Option<u64>,
    lsa_age_ms: Option<u128>,
}

#[derive(Debug, Serialize)]
struct TopologyAddress {
    transport: &'static str,
    addr: String,
}

#[derive(Debug, Serialize)]
struct TopologyLink {
    source: NodeIdentifier,
    target: NodeIdentifier,
    status: &'static str,
    rtt_us: u64,
    jitter_us: u64,
    throughput_bps: u64,
    loss_ppm: u32,
    transports: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct TopologyRoute {
    dst: NodeIdentifier,
    metric: &'static str,
    level: &'static str,
    next_hop: NodeIdentifier,
    cost: u64,
}

#[derive(Debug, Serialize)]
struct TransportMetric {
    peer: NodeIdentifier,
    transport: &'static str,
    rtt_us: f64,
    jitter_us: f64,
    recv_bps: f64,
    sent_bps: f64,
    wire_recv_bps: f64,
    wire_sent_bps: f64,
    probe_goodput_bps: f64,
    estimated_throughput_bps: f64,
    samples: u64,
    probe_samples: u64,
    service_metrics: Vec<TransportServiceMetric>,
    last_update_age_ms: Option<u128>,
}

#[derive(Debug, Serialize)]
struct TransportServiceMetric {
    service: &'static str,
    level: &'static str,
    class: &'static str,
    payload_bytes: usize,
    supported: bool,
    probe_goodput_bps: f64,
    probe_samples: u64,
}

pub fn spawn_status_server(
    listen: SocketAddr,
    overlay: OverlayNetwork,
    transport: ConnectionManager,
    mut shutdown: watch::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    let listener = std::net::TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;

    Ok(tokio::spawn(async move {
        tracing::info!(%listen, "S2S topology HTTP server listening");
        loop {
            let (stream, peer) = tokio::select! {
                result = listener.accept() => match result {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%listen, %error, "S2S topology HTTP accept failed");
                        continue;
                    }
                },
                _ = shutdown.changed() => break,
            };

            let overlay = overlay.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, overlay, transport).await {
                    tracing::trace!(%peer, %error, "S2S topology HTTP connection failed");
                }
            });
        }
    }))
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    overlay: OverlayNetwork,
    transport: ConnectionManager,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&scratch[..n]);
        if buf.len() > MAX_REQUEST_BYTES {
            return write_response(
                &mut stream,
                "413 Payload Too Large",
                "text/plain; charset=utf-8",
                b"request too large",
            )
            .await;
        }
        if find_header_end(&buf).is_some() {
            break;
        }
    }

    let first_line = std::str::from_utf8(&buf)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let raw_path = parts.next().unwrap_or_default();
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    match (method, path) {
        ("GET", "/") | ("GET", "/topology") | ("GET", "/s2s/topology") => {
            write_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                STATUS_HTML.as_bytes(),
            )
            .await
        }
        ("GET", "/topology.json") | ("GET", "/s2s/topology.json") => {
            let snapshot = build_topology_snapshot(&overlay, &transport);
            let body = serde_json::to_vec_pretty(&snapshot)
                .map_err(|error| io::Error::other(error.to_string()))?;
            write_response(&mut stream, "200 OK", "application/json", &body).await
        }
        ("GET", "/health") | ("GET", "/s2s/health") => {
            write_response(
                &mut stream,
                "200 OK",
                "application/json",
                br#"{"status":"ok"}"#,
            )
            .await
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                "application/json",
                br#"{"error":"not found"}"#,
            )
            .await
        }
    }
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

fn build_topology_snapshot(
    overlay: &OverlayNetwork,
    transport: &ConnectionManager,
) -> TopologySnapshot {
    let now = Instant::now();
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let lsas = overlay.link_state_snapshot();
    let routing = overlay.routing_snapshot();
    let metrics = transport.metrics_snapshot();

    let mut lsa_by_origin = BTreeMap::new();
    for lsa in &lsas {
        lsa_by_origin.insert(lsa.origin, lsa);
    }

    let mut nodes = overlay
        .members()
        .into_iter()
        .map(|member| {
            let lsa = lsa_by_origin.get(&member.node_id()).copied();
            TopologyNode {
                node_id: member.node_id(),
                status: member_status_name(member.status()),
                boot_epoch: member.boot_epoch(),
                max_users: member.max_users(),
                addresses: member
                    .addresses()
                    .iter()
                    .map(|addr| TopologyAddress {
                        transport: transport_kind_name(addr.transport()),
                        addr: addr.addr().to_string(),
                    })
                    .collect(),
                transit_enabled: match lsa {
                    Some(entry) => !entry.transit_disabled,
                    None => true,
                },
                lsa_seq: lsa.map(|entry| entry.seq),
                lsa_age_ms: lsa
                    .map(|entry| now.duration_since(entry.ts_local_received).as_millis()),
            }
        })
        .collect::<Vec<_>>();
    nodes.sort_by_key(|node| node.node_id);

    let alive: std::collections::BTreeSet<NodeIdentifier> = nodes
        .iter()
        .filter(|node| node.status == "alive")
        .map(|node| node.node_id)
        .collect();

    let mut links = Vec::new();
    for lsa in &lsas {
        for link in &lsa.links {
            links.push(TopologyLink {
                source: lsa.origin,
                target: link.neighbor,
                status: if !lsa.tombstone
                    && alive.contains(&lsa.origin)
                    && alive.contains(&link.neighbor)
                {
                    "active"
                } else {
                    "stale"
                },
                rtt_us: link.rtt_us,
                jitter_us: link.jitter_us,
                throughput_bps: link.throughput_bps,
                loss_ppm: link.loss_ppm,
                transports: transport_names_from_mask(link.transports_mask),
            });
        }
    }
    links.sort_by_key(|link| (link.source, link.target));

    let mut routes = Vec::new();
    append_routes(
        &mut routes,
        "per_service",
        "reliable",
        routing
            .for_metric_level(RoutingMetric::PerServiceCost, ServiceLevel::Reliable)
            .iter(),
    );
    append_routes(
        &mut routes,
        "per_service",
        "reliable_low_latency",
        routing
            .for_metric_level(
                RoutingMetric::PerServiceCost,
                ServiceLevel::ReliableLowLatency,
            )
            .iter(),
    );
    append_routes(
        &mut routes,
        "per_service",
        "best_effort",
        routing
            .for_metric_level(RoutingMetric::PerServiceCost, ServiceLevel::BestEffort)
            .iter(),
    );
    append_routes(
        &mut routes,
        "conversational",
        "reliable",
        routing
            .for_metric_level(RoutingMetric::ConversationalQuality, ServiceLevel::Reliable)
            .iter(),
    );
    append_routes(
        &mut routes,
        "conversational",
        "reliable_low_latency",
        routing
            .for_metric_level(
                RoutingMetric::ConversationalQuality,
                ServiceLevel::ReliableLowLatency,
            )
            .iter(),
    );
    append_routes(
        &mut routes,
        "conversational",
        "best_effort",
        routing
            .for_metric_level(
                RoutingMetric::ConversationalQuality,
                ServiceLevel::BestEffort,
            )
            .iter(),
    );
    routes.sort_by_key(|route| (route.metric, route.level, route.dst));

    let mut local_metrics = Vec::new();
    let transport_cfg = transport.inner.cfg();
    for (peer, per_transport) in metrics.per_node() {
        for (kind, metric) in per_transport {
            let service_metrics = ServiceShape::ALL
                .into_iter()
                .map(|shape| {
                    let probe = metric.service_probe(shape);
                    TransportServiceMetric {
                        service: shape.name(),
                        level: service_level_name(shape.service_level()),
                        class: message_class_name(shape.message_class()),
                        payload_bytes: transport_cfg.service_probe_payload_size(shape),
                        supported: transport_cfg.service_probe_supported(*kind, shape),
                        probe_goodput_bps: probe.goodput_bps(),
                        probe_samples: probe.samples(),
                    }
                })
                .collect();
            local_metrics.push(TransportMetric {
                peer: *peer,
                transport: transport_kind_name(*kind),
                rtt_us: metric.rtt_us(),
                jitter_us: metric.jitter_us(),
                recv_bps: metric.recv_bps(),
                sent_bps: metric.sent_bps(),
                wire_recv_bps: metric.wire_recv_bps(),
                wire_sent_bps: metric.wire_sent_bps(),
                probe_goodput_bps: metric.max_probe_goodput_bps(),
                estimated_throughput_bps: metric.estimated_throughput_bps(),
                samples: metric.samples(),
                probe_samples: metric.probe_samples(),
                service_metrics,
                last_update_age_ms: metric
                    .last_update()
                    .map(|ts| now.duration_since(ts).as_millis()),
            });
        }
    }
    local_metrics.sort_by_key(|metric| (metric.peer, metric.transport));

    TopologySnapshot {
        local_node: overlay.local_node_id(),
        generated_at_unix_ms,
        nodes,
        links,
        routes,
        local_metrics,
    }
}

fn append_routes<'a>(
    out: &mut Vec<TopologyRoute>,
    metric: &'static str,
    level: &'static str,
    iter: impl Iterator<Item = (&'a NodeIdentifier, &'a crate::s2s::overlay::RouteEntry)>,
) {
    out.extend(iter.map(|(dst, route)| TopologyRoute {
        dst: *dst,
        metric,
        level,
        next_hop: route.next_hop,
        cost: route.cost,
    }));
}

fn member_status_name(status: MemberStatus) -> &'static str {
    match status {
        MemberStatus::Alive => "alive",
        MemberStatus::Failed => "failed",
        MemberStatus::Left => "left",
    }
}

fn transport_kind_name(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Tcp => "tcp",
        TransportKind::Kcp => "kcp",
        TransportKind::Quic => "quic",
        TransportKind::Udp => "udp",
    }
}

fn service_level_name(level: ServiceLevel) -> &'static str {
    match level {
        ServiceLevel::ReliableLowLatency => "reliable_low_latency",
        ServiceLevel::Reliable => "reliable",
        ServiceLevel::BestEffort => "best_effort",
    }
}

fn message_class_name(class: MessageClass) -> &'static str {
    match class {
        MessageClass::HighPriority => "high_priority",
        MessageClass::Regular => "regular",
    }
}

fn transport_names_from_mask(mask: u32) -> Vec<&'static str> {
    [
        TransportKind::Tcp,
        TransportKind::Kcp,
        TransportKind::Quic,
        TransportKind::Udp,
    ]
    .into_iter()
    .filter(|kind| mask & crate::s2s::overlay::config::transport_bit(*kind) != 0)
    .map(transport_kind_name)
    .collect()
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

const STATUS_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>S2S Topology</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/10.0.2/dist/dist/vis-network.min.css" integrity="sha512-GSpw80rwo8kTr/5IPf9mhy5Ze8smoCCJ9fDJceVf6UAA5EUk9mOa/h/rug+PcDyCkdkR1mA+Gb3ot2GyHimFkw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<style>
:root { color-scheme: light; --bg: #f7f8fb; --ink: #18202b; --muted: #677285; --line: #d9dee8; --panel: #ffffff; --accent: #0f8b8d; --warn: #c77700; --bad: #b42318; --good: #237b4b; }
* { box-sizing: border-box; }
body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); }
header { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; padding: 16px 20px; border-bottom: 1px solid var(--line); background: var(--panel); }
h1 { margin: 0; font-size: 20px; font-weight: 650; }
.meta { color: var(--muted); font-size: 13px; }
main { display: grid; grid-template-columns: minmax(420px, 1.35fr) minmax(320px, .9fr); gap: 16px; padding: 16px; }
section { min-width: 0; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
.panel h2 { margin: 0; padding: 12px 14px; font-size: 14px; border-bottom: 1px solid var(--line); }
#graph { width: 100%; height: min(62vh, 640px); min-height: 420px; background: #fbfcfe; }
.vis-network { outline: none; }
.vis-tooltip { position: absolute; visibility: hidden; padding: 8px 10px; max-width: 360px; color: var(--ink); background: #fff; border: 1px solid var(--line); border-radius: 6px; box-shadow: 0 8px 24px rgba(24, 32, 43, .12); font-size: 12px; line-height: 1.4; white-space: normal; }
.tables { display: grid; gap: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; background: #fafbfc; }
.pill { display: inline-block; min-width: 54px; padding: 2px 6px; border-radius: 999px; text-align: center; color: #fff; font-size: 11px; }
.alive, .active { background: var(--good); }
.left, .stale { background: var(--warn); }
.failed { background: var(--bad); }
.transport { color: var(--muted); }
@media (max-width: 920px) { main { grid-template-columns: 1fr; } #graph { height: 460px; } }
</style>
</head>
<body>
<header>
  <h1>S2S topology</h1>
  <div class="meta" id="meta">loading</div>
</header>
<main>
  <section class="panel">
    <h2>Network</h2>
    <div id="graph" role="img" aria-label="S2S network topology"></div>
  </section>
  <section class="tables">
    <div class="panel"><h2>Nodes</h2><table><thead><tr><th>Node</th><th>Status</th><th>LSA</th><th>Addresses</th></tr></thead><tbody id="nodes"></tbody></table></div>
    <div class="panel"><h2>Direct Metrics</h2><table><thead><tr><th>Peer</th><th>Transport</th><th>RTT</th><th>Jitter</th><th>Payload Traffic</th><th>Wire Traffic</th><th>Voice</th><th>Control</th><th>Bulk</th></tr></thead><tbody id="metrics"></tbody></table></div>
    <div class="panel"><h2>Routes</h2><table><thead><tr><th>Metric</th><th>Level</th><th>Dst</th><th>Next hop</th><th>Cost</th></tr></thead><tbody id="routes"></tbody></table></div>
  </section>
</main>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/10.0.2/dist/vis-network.min.js" integrity="sha512-5qYRU42HLweh0Ehlsu9bVWc13gwZviSNGsnfx+PqGRQRM4NltzGzb8dO3WY20CTsbkTBzhyKlso9cfYz2A5lOQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script>
const graph = document.getElementById('graph');
const meta = document.getElementById('meta');
const nodesTbody = document.getElementById('nodes');
const metricsTbody = document.getElementById('metrics');
const routesTbody = document.getElementById('routes');
let network;
let graphNodes;
let graphEdges;
let currentLocalNode = null;
let graphTopologyKey = '';
function fmtUs(v) { return v ? (v / 1000).toFixed(1) + ' ms' : '-'; }
function fmtBps(v) { if (!v) return '-'; const u = ['B/s','KB/s','MB/s','GB/s']; let i = 0; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return v.toFixed(i ? 1 : 0) + ' ' + u[i]; }
function fmtLoss(v) { return v ? (v / 10000).toFixed(2) + '%' : '0%'; }
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function fmtPair(a, b) { const v = Math.max(a || 0, b || 0); return fmtBps(v); }
function serviceProbeCell(metric, service) {
    const item = (metric.service_metrics || []).find(s => s.service === service);
    if (!item || !item.supported) return 'n/a';
    const value = fmtBps(item.probe_goodput_bps);
    return `${value}<br><span class="transport">${item.payload_bytes} B</span>`;
}
function tooltipHtml(lines) {
  const el = document.createElement('div');
  el.innerHTML = lines.join('<br>');
  return el;
}
function topologyKeyFor(data) {
  const nodes = data.nodes.map(n => String(n.node_id)).sort().join(',');
  const edges = data.links
    .map(l => `${l.source}->${l.target}:${(l.transports || []).join('/')}`)
    .sort()
    .join(',');
  return `${nodes}|${edges}`;
}
function graphPhysicsOptions() {
  return {
    enabled: true,
    solver: 'repulsion',
    stabilization: { enabled: true, iterations: 220, fit: true },
    repulsion: {
      nodeDistance: 285,
      centralGravity: 0.004,
      springLength: 260,
      springConstant: 0.025,
      damping: 0.09
    },
    minVelocity: 0.6
  };
}
function settleGraph() {
  network.setOptions({ physics: graphPhysicsOptions() });
  network.stabilize(220);
}
function nodeColor(n) {
  if (n.node_id === currentLocalNode) return { background: '#18202b', border: '#18202b', highlight: { background: '#263244', border: '#18202b' } };
  if (n.status === 'alive') return { background: '#237b4b', border: '#185b38', highlight: { background: '#2f9360', border: '#185b38' } };
  if (n.status === 'failed') return { background: '#b42318', border: '#851b12', highlight: { background: '#c8372b', border: '#851b12' } };
  return { background: '#c77700', border: '#965a00', highlight: { background: '#dc8a12', border: '#965a00' } };
}
function linkColor(status) {
  return status === 'active'
    ? { color: '#0f8b8d', highlight: '#0b6e70', hover: '#0b6e70' }
    : { color: '#c77700', highlight: '#965a00', hover: '#965a00' };
}
function edgeWidth(throughput) {
  if (!throughput) return 1.5;
  return Math.max(1.5, Math.min(7, 1.5 + Math.log2(throughput / 1024 + 1) * 0.45));
}
function syncDataSet(ds, items) {
  const nextIds = new Set(items.map(item => String(item.id)));
  const stale = ds.getIds().filter(id => !nextIds.has(String(id)));
  if (stale.length) ds.remove(stale);
  if (items.length) ds.update(items);
}
function ensureNetwork() {
  if (network) return true;
  if (!window.vis || !vis.Network || !vis.DataSet) {
    meta.textContent = 'vis-network failed to load';
    return false;
  }
  graphNodes = new vis.DataSet();
  graphEdges = new vis.DataSet();
  network = new vis.Network(graph, { nodes: graphNodes, edges: graphEdges }, {
    autoResize: true,
    layout: { improvedLayout: true },
    interaction: { hover: true, tooltipDelay: 120, dragNodes: true, dragView: true, zoomView: true, navigationButtons: false, keyboard: true },
    physics: graphPhysicsOptions(),
    nodes: {
      shape: 'dot', size: 22, borderWidth: 2,
      font: { color: '#18202b', size: 13, face: 'ui-sans-serif, system-ui, sans-serif', vadjust: -33 }
    },
    edges: {
      smooth: { enabled: true, type: 'continuous', roundness: 0.2 },
      arrows: { to: { enabled: true, scaleFactor: 0.55 } },
      font: { color: '#4f5b6e', size: 10, strokeWidth: 3, strokeColor: '#fbfcfe' },
      color: { inherit: false },
      selectionWidth: 1.5,
      hoverWidth: 1.5
    }
  });
  network.on('stabilizationIterationsDone', () => network.setOptions({ physics: false }));
  network.on('dragStart', () => network.setOptions({ physics: false }));
  return true;
}
function renderGraph(data) {
  currentLocalNode = data.local_node;
  if (!ensureNetwork()) return;
  const topologyKey = topologyKeyFor(data);
  const topologyChanged = topologyKey !== graphTopologyKey;
  const nodes = data.nodes.map(n => ({
    id: String(n.node_id),
    label: String(n.node_id),
    title: tooltipHtml([
      `<strong>node ${esc(n.node_id)}</strong>`,
      `Status: ${esc(n.status)}`,
      `Transit: ${n.transit_enabled ? 'enabled' : 'disabled'}`,
      `Boot epoch: ${esc(n.boot_epoch)}`,
      `LSA seq: ${esc(n.lsa_seq ?? '-')}`,
      `LSA age: ${esc(n.lsa_age_ms ?? '-')} ms`,
      ...n.addresses.map(a => `${esc(a.transport)} ${esc(a.addr)}`)
    ]),
    color: nodeColor(n),
    borderWidth: n.node_id === data.local_node ? 4 : 2,
    font: { color: n.node_id === data.local_node ? '#18202b' : '#263244' }
  }));
  const edges = data.links.map((link, i) => {
    const transports = link.transports && link.transports.length ? link.transports.join('/') : 'unknown';
    return {
      id: `${link.source}->${link.target}:${transports}:${i}`,
      from: String(link.source),
      to: String(link.target),
      label: fmtUs(link.rtt_us),
      title: tooltipHtml([
        `<strong>${esc(link.source)} -> ${esc(link.target)}</strong>`,
        `Status: ${esc(link.status)}`,
        `Transports: ${esc(transports)}`,
        `RTT: ${fmtUs(link.rtt_us)}`,
        `Jitter: ${fmtUs(link.jitter_us)}`,
        `Loss: ${fmtLoss(link.loss_ppm)}`,
        `Throughput: ${fmtBps(link.throughput_bps)}`
      ]),
      color: linkColor(link.status),
      width: edgeWidth(link.throughput_bps),
      dashes: link.status !== 'active'
    };
  });
  syncDataSet(graphNodes, nodes);
  syncDataSet(graphEdges, edges);
  if (topologyChanged) {
    graphTopologyKey = topologyKey;
    settleGraph();
  }
}
function renderTables(data) {
  nodesTbody.innerHTML = data.nodes.map(n => `<tr><td>${n.node_id}</td><td><span class="pill ${n.status}">${n.status}</span></td><td>seq ${n.lsa_seq ?? '-'}<br>${n.lsa_age_ms ?? '-'} ms</td><td>${n.addresses.map(a => `<span class="transport">${esc(a.transport)}</span> ${esc(a.addr)}`).join('<br>')}</td></tr>`).join('');
    metricsTbody.innerHTML = data.local_metrics.map(m => `<tr><td>${m.peer}</td><td>${esc(m.transport)}</td><td>${fmtUs(m.rtt_us)}</td><td>${fmtUs(m.jitter_us)}</td><td>${fmtPair(m.recv_bps, m.sent_bps)}</td><td>${fmtPair(m.wire_recv_bps, m.wire_sent_bps)}</td><td>${serviceProbeCell(m, 'voice')}</td><td>${serviceProbeCell(m, 'control')}</td><td>${serviceProbeCell(m, 'bulk')}</td></tr>`).join('');
  routesTbody.innerHTML = data.routes.map(r => `<tr><td>${esc(r.metric)}</td><td>${esc(r.level)}</td><td>${r.dst}</td><td>${r.next_hop}</td><td>${r.cost}</td></tr>`).join('');
}
async function refresh() {
  try {
    const res = await fetch('/topology.json', { cache: 'no-store' });
    const data = await res.json();
    meta.textContent = `node ${data.local_node} - ${data.nodes.length} known nodes - ${new Date(Number(data.generated_at_unix_ms)).toLocaleTimeString()}`;
    renderGraph(data); renderTables(data);
  } catch (e) {
    meta.textContent = `refresh failed: ${e}`;
  }
}
addEventListener('resize', () => { if (network) network.fit({ animation: false }); });
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_http_header_end() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nx"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\n\n"), None);
    }

    #[test]
    fn transport_mask_names_are_stable() {
        let mask = crate::s2s::overlay::config::transport_bit(TransportKind::Tcp)
            | crate::s2s::overlay::config::transport_bit(TransportKind::Udp);
        assert_eq!(transport_names_from_mask(mask), vec!["tcp", "udp"]);
    }

    #[test]
    fn status_page_uses_sri_protected_cdn_vis_network_assets() {
        assert!(STATUS_HTML.contains("https://cdnjs.cloudflare.com/ajax/libs/vis-network/10.0.2/dist/dist/vis-network.min.css"));
        assert!(STATUS_HTML.contains(
            "https://cdnjs.cloudflare.com/ajax/libs/vis-network/10.0.2/dist/vis-network.min.js"
        ));
        assert!(STATUS_HTML.contains("sha512-GSpw80rwo8kTr/5IPf9mhy5Ze8smoCCJ9fDJceVf6UAA5EUk9mOa/h/rug+PcDyCkdkR1mA+Gb3ot2GyHimFkw=="));
        assert!(STATUS_HTML.contains("sha512-5qYRU42HLweh0Ehlsu9bVWc13gwZviSNGsnfx+PqGRQRM4NltzGzb8dO3WY20CTsbkTBzhyKlso9cfYz2A5lOQ=="));
        assert!(STATUS_HTML.contains("referrerpolicy=\"no-referrer\""));
        assert!(STATUS_HTML.contains("new vis.Network"));
        assert!(STATUS_HTML.contains("dragNodes: true"));
        assert!(STATUS_HTML.contains("solver: 'repulsion'"));
        assert!(STATUS_HTML.contains("tooltipHtml(["));
        assert!(STATUS_HTML.contains("network.setOptions({ physics: false })"));
    }
}
