use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::overlay::{MemberStatus, OverlayNetwork, RoutingMetric};
use shitspeak_core::NodeGeo;

use crate::geo::SharedNodeGeo;
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{ConnectionManager, MetricsSnapshot, TransportKind};
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

const MAX_REQUEST_BYTES: usize = 8192;

#[derive(Debug, Serialize)]
pub(crate) struct TopologySnapshot {
    local_node: NodeIdentifier,
    generated_at_unix_ms: u128,
    nodes: Vec<TopologyNode>,
    links: Vec<TopologyLink>,
    routes: Vec<TopologyRoute>,
    duplicate_nodes: Vec<TopologyDuplicateNode>,
    local_metrics: Vec<TransportMetric>,
    outbound_queues: Vec<OutboundQueueMetric>,
    inbound_queues: Vec<InboundQueueMetric>,
    expired_outbound_drops: Vec<ExpiredOutboundDropMetric>,
    transport_health_exclusions: Vec<TransportHealthExclusionMetric>,
    datagram_path_health: Vec<DatagramPathHealthMetric>,
    delivery_path_selections: Vec<DeliveryPathSelectionMetric>,
    voice_transport_bindings: Vec<VoiceTransportBindingMetric>,
    voice_transport_binding_events: Vec<VoiceTransportBindingEventMetric>,
    voice_transport_challengers: Vec<VoiceTransportChallengerMetric>,
    quic_lanes: Vec<QuicLaneMetric>,
    quic_datagram_drops: Vec<QuicDatagramDropMetric>,
    quic_protocol_events: Vec<QuicProtocolEventMetric>,
    quic_protocol_errors: Vec<QuicProtocolErrorMetric>,
    quic_sessions: Vec<QuicSessionMetric>,
    debug_packet_io: Vec<crate::debug_io::PacketIoSnapshot>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeliveryPathSelectionMetric {
    path: &'static str,
    selections: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct QuicSessionMetric {
    peer: NodeIdentifier,
    remote_addr: Option<String>,
    dialer: bool,
    negotiated_protocol: &'static str,
    three_lane_ready: bool,
    max_datagram_size: Option<usize>,
    datagram_send_buffer_bytes: usize,
    datagram_receive_buffer_bytes: usize,
    datagrams_queued: u64,
    datagrams_received: u64,
    datagrams_dropped: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct QuicLaneMetric {
    peer: Option<NodeIdentifier>,
    direction: &'static str,
    lane: &'static str,
    frames: u64,
    bytes: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct QuicDatagramDropMetric {
    reason: &'static str,
    drops: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct QuicProtocolEventMetric {
    stage: &'static str,
    version: &'static str,
    result: &'static str,
    events: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct QuicProtocolErrorMetric {
    reason: &'static str,
    errors: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct VoiceTransportBindingMetric {
    peer: NodeIdentifier,
    transport: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct VoiceTransportBindingEventMetric {
    peer: NodeIdentifier,
    from_transport: &'static str,
    to_transport: &'static str,
    reason: &'static str,
    events: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct VoiceTransportChallengerMetric {
    peer: NodeIdentifier,
    incumbent: &'static str,
    challenger: &'static str,
    outcome: &'static str,
    events: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct TopologyNode {
    node_id: NodeIdentifier,
    status: &'static str,
    boot_epoch: u64,
    max_users: u64,
    addresses: Vec<TopologyAddress>,
    geo: Option<NodeGeo>,
    transit_enabled: bool,
    lsa_seq: Option<u64>,
    lsa_age_ms: Option<u128>,
    strict_replication_protocol_version: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TopologyAddress {
    transport: &'static str,
    addr: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct TopologyLink {
    source: NodeIdentifier,
    target: NodeIdentifier,
    status: &'static str,
    rtt_us: u64,
    jitter_us: u64,
    throughput_bps: u64,
    observed_recv_bps: u64,
    observed_sent_bps: u64,
    throughput_confidence_ppm: u32,
    loss_ppm: u32,
    probe_loss_ppm: u32,
    native_loss_ppm: u32,
    data_health_ppm: u32,
    loss_sample_count: u64,
    transports: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TopologyRoute {
    dst: NodeIdentifier,
    metric: &'static str,
    level: &'static str,
    next_hop: NodeIdentifier,
    transport: &'static str,
    service_fit: &'static str,
    cost: u64,
    transport_cost: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TopologyDuplicateNode {
    node: NodeIdentifier,
    observed_epochs: usize,
    conflict: bool,
    quarantined: bool,
    reason: &'static str,
    quarantine_age_ms: u128,
    quarantine_remaining_ms: u128,
    conflicts_total: u64,
    dropped_messages_total: Vec<TopologyDuplicateDrop>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TopologyDuplicateDrop {
    kind: &'static str,
    count: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct TransportMetric {
    peer: NodeIdentifier,
    transport: &'static str,
    rtt_us: f64,
    jitter_us: f64,
    recv_bps: f64,
    sent_bps: f64,
    wire_recv_bps: f64,
    wire_sent_bps: f64,
    compression_recv_ratio: Option<f64>,
    compression_sent_ratio: Option<f64>,
    compression_total_ratio: Option<f64>,
    packet_loss_ppm: u32,
    probe_loss_ppm: u32,
    probe_loss_ewma_ppm: u32,
    native_loss_ppm: u32,
    native_loss_ewma_ppm: u32,
    data_health_ppm: u32,
    loss_sample_count: u64,
    probe_packets: u64,
    lost_probe_packets: u64,
    unmatched_probe_pongs: u64,
    native_loss_samples: u64,
    native_lost_samples: u64,
    data_health_samples: u64,
    data_health_failures: u64,
    estimated_throughput_bps: f64,
    samples: u64,
    last_update_age_ms: Option<u128>,
    kcp_runtime: Option<KcpRuntimeMetric>,
}

#[derive(Debug, Serialize)]
pub(crate) struct KcpRuntimeMetric {
    closed: bool,
    pending_sender: bool,
    waiting_conv: bool,
    wait_snd: u64,
    snd_wnd: u64,
    rmt_wnd: u64,
    input_queue_drops: u64,
    no_progress_closes: u64,
    last_input_age_ms: Option<u64>,
    outstanding_no_progress_age_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OutboundQueueMetric {
    peer: NodeIdentifier,
    transport: &'static str,
    depth: usize,
    high_watermark: usize,
    capacity: usize,
    samples: u64,
    full_samples: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct InboundQueueMetric {
    class: &'static str,
    depth: usize,
    high_watermark: usize,
    capacity: usize,
    samples: u64,
    full_samples: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExpiredOutboundDropMetric {
    peer: NodeIdentifier,
    stage: &'static str,
    transport: &'static str,
    class: &'static str,
    frames: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct TransportHealthExclusionMetric {
    peer: NodeIdentifier,
    transport: &'static str,
    reason: &'static str,
    exclusions: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct DatagramPathHealthMetric {
    peer: NodeIdentifier,
    path: &'static str,
    state: &'static str,
    reason: &'static str,
    effective_loss_ppm: Option<u32>,
    path_health_score_ppm: Option<u32>,
    loss_samples: u64,
    sample_confidence_ppm: u32,
    enqueue_accepted: u64,
    enqueue_rejected: u64,
    too_large: u64,
    pressure: u64,
    outcome_successes: u64,
    outcome_failures: u64,
    ingress_validated: u64,
    ingress_rejected: u64,
    ingress_read_failures: u64,
    consecutive_bad_windows: u32,
    recovery_healthy_age_ms: u128,
    recovery_required: bool,
    transitions: u64,
    state_age_ms: u128,
    scored_generation: Option<u64>,
    diagnostic_generation: Option<u64>,
    observation_age_ms: u128,
    diagnostic_observation_age_ms: Option<u128>,
}

pub fn spawn_status_server(
    listen: SocketAddr,
    overlay: OverlayNetwork,
    transport: ConnectionManager,
    local_geo: SharedNodeGeo,
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
            let local_geo = local_geo.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, overlay, transport, local_geo).await {
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
    local_geo: SharedNodeGeo,
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
            let snapshot = build_topology_snapshot(&overlay, &transport, local_geo.get());
            let body = serde_json::to_vec_pretty(&snapshot)
                .map_err(|error| io::Error::other(error.to_string()))?;
            write_response(&mut stream, "200 OK", "application/json", &body).await
        }
        ("GET", "/metrics") | ("GET", "/s2s/metrics") => {
            let body = render_prometheus_metrics(&overlay, &transport, local_geo.get());
            write_response(
                &mut stream,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                body.as_bytes(),
            )
            .await
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

pub(crate) fn build_topology_snapshot(
    overlay: &OverlayNetwork,
    transport: &ConnectionManager,
    local_geo: Option<NodeGeo>,
) -> TopologySnapshot {
    let now = Instant::now();
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let lsas = overlay.link_state_snapshot();
    let routing = overlay.routing_snapshot();
    let mut duplicate_nodes = overlay
        .duplicate_node_snapshot()
        .into_iter()
        .map(|node| TopologyDuplicateNode {
            node: node.node_id(),
            observed_epochs: node.observed_epochs(),
            conflict: node.observed_epochs() > 1,
            quarantined: node.quarantined(),
            reason: node.reason(),
            quarantine_age_ms: node.age_ms(),
            quarantine_remaining_ms: node.remaining_ms(),
            conflicts_total: node.conflicts_total(),
            dropped_messages_total: node
                .dropped_messages_total()
                .iter()
                .map(|drop| TopologyDuplicateDrop {
                    kind: drop.kind(),
                    count: drop.count(),
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    duplicate_nodes.sort_by_key(|node| node.node);
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
                geo: (member.node_id() == overlay.local_node_id())
                    .then(|| local_geo.clone())
                    .flatten(),
                transit_enabled: match lsa {
                    Some(entry) => !entry.transit_disabled,
                    None => true,
                },
                lsa_seq: lsa.map(|entry| entry.seq),
                lsa_age_ms: lsa
                    .map(|entry| now.duration_since(entry.ts_local_received).as_millis()),
                strict_replication_protocol_version: lsa
                    .map(|entry| entry.strict_replication_protocol_version()),
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
        if overlay.is_node_quarantined(lsa.origin) {
            continue;
        }
        for link in &lsa.links {
            if overlay.is_node_quarantined(link.neighbor) {
                continue;
            }
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
                observed_recv_bps: link.observed_recv_bps,
                observed_sent_bps: link.observed_sent_bps,
                throughput_confidence_ppm: link.throughput_confidence_ppm,
                loss_ppm: link.loss_ppm,
                probe_loss_ppm: link.probe_loss_ppm,
                native_loss_ppm: link.native_loss_ppm,
                data_health_ppm: link.data_health_ppm,
                loss_sample_count: link.loss_sample_count,
                transports: transport_names_from_mask(link.transports_mask),
            });
        }
    }
    links.sort_by_key(|link| (link.source, link.target));

    let mut routes = Vec::new();
    for metric in RoutingMetric::ALL {
        for level in ServiceLevel::ALL {
            append_routes(
                &mut routes,
                transport,
                &metrics,
                metric,
                metric.name(),
                level,
                service_level_name(level),
                routing.for_metric_level(metric, level).iter(),
            );
        }
    }
    routes.sort_by_key(|route| {
        (
            route.metric,
            route.level,
            route.dst,
            route.next_hop,
            route.transport,
        )
    });

    let mut local_metrics = Vec::new();
    for (peer, per_transport) in metrics.per_node() {
        for (kind, metric) in per_transport {
            local_metrics.push(TransportMetric {
                peer: *peer,
                transport: transport_kind_name(*kind),
                rtt_us: metric.rtt_us(),
                jitter_us: metric.jitter_us(),
                recv_bps: metric.recv_bps(),
                sent_bps: metric.sent_bps(),
                wire_recv_bps: metric.wire_recv_bps(),
                wire_sent_bps: metric.wire_sent_bps(),
                compression_recv_ratio: metric.l1_compression_recv_ratio(),
                compression_sent_ratio: metric.l1_compression_sent_ratio(),
                compression_total_ratio: metric.l1_compression_total_ratio(),
                packet_loss_ppm: metric.packet_loss_ppm(),
                probe_loss_ppm: metric.probe_loss_ppm(),
                probe_loss_ewma_ppm: metric.probe_loss_ewma_ppm(),
                native_loss_ppm: metric.native_loss_ppm(),
                native_loss_ewma_ppm: metric.native_loss_ewma_ppm(),
                data_health_ppm: metric.data_health_ppm(),
                loss_sample_count: metric.loss_sample_count(),
                probe_packets: metric.probe_packets(),
                lost_probe_packets: metric.lost_probe_packets(),
                unmatched_probe_pongs: metric.unmatched_probe_pongs(),
                native_loss_samples: metric.native_loss_samples(),
                native_lost_samples: metric.native_lost_samples(),
                data_health_samples: metric.data_health_samples(),
                data_health_failures: metric.data_health_failures(),
                estimated_throughput_bps: metric.estimated_throughput_bps(),
                samples: metric.samples(),
                last_update_age_ms: metric
                    .last_update()
                    .map(|ts| now.duration_since(ts).as_millis()),
                kcp_runtime: metric.kcp_runtime().map(|runtime| KcpRuntimeMetric {
                    closed: runtime.closed(),
                    pending_sender: runtime.pending_sender(),
                    waiting_conv: runtime.waiting_conv(),
                    wait_snd: runtime.wait_snd(),
                    snd_wnd: runtime.snd_wnd(),
                    rmt_wnd: runtime.rmt_wnd(),
                    input_queue_drops: runtime.input_queue_drops(),
                    no_progress_closes: runtime.no_progress_closes(),
                    last_input_age_ms: runtime.last_input_age_ms(),
                    outstanding_no_progress_age_ms: runtime.outstanding_no_progress_age_ms(),
                }),
            });
        }
    }
    local_metrics.sort_by_key(|metric| (metric.peer, metric.transport));

    let mut outbound_queues = metrics
        .outbound_queues()
        .iter()
        .map(|queue| {
            let status = queue.status();
            OutboundQueueMetric {
                peer: queue.peer(),
                transport: outbound_queue_transport_name(queue.transport()),
                depth: status.depth(),
                high_watermark: status.high_depth(),
                capacity: status.capacity(),
                samples: status.samples(),
                full_samples: status.full_samples(),
            }
        })
        .collect::<Vec<_>>();
    outbound_queues.sort_by_key(|queue| (queue.peer, queue.transport));

    let mut inbound_queues = metrics
        .inbound_queues()
        .iter()
        .map(|queue| {
            let status = queue.status();
            InboundQueueMetric {
                class: message_class_name(queue.class()),
                depth: status.depth(),
                high_watermark: status.high_depth(),
                capacity: status.capacity(),
                samples: status.samples(),
                full_samples: status.full_samples(),
            }
        })
        .collect::<Vec<_>>();
    inbound_queues.sort_by_key(|queue| queue.class);

    let mut expired_outbound_drops = metrics
        .expired_outbound_drops()
        .iter()
        .map(|entry| ExpiredOutboundDropMetric {
            peer: entry.peer(),
            stage: entry.stage().name(),
            transport: outbound_queue_transport_name(entry.transport()),
            class: message_class_name(entry.class()),
            frames: entry.frames(),
        })
        .collect::<Vec<_>>();
    expired_outbound_drops
        .sort_by_key(|entry| (entry.peer, entry.stage, entry.transport, entry.class));

    let mut transport_health_exclusions = metrics
        .transport_health_exclusions()
        .iter()
        .map(|entry| TransportHealthExclusionMetric {
            peer: entry.peer(),
            transport: transport_kind_name(entry.transport()),
            reason: entry.reason().name(),
            exclusions: entry.exclusions(),
        })
        .collect::<Vec<_>>();
    transport_health_exclusions.sort_by_key(|entry| (entry.peer, entry.transport, entry.reason));

    let mut datagram_path_health = metrics
        .datagram_path_health()
        .iter()
        .map(|entry| DatagramPathHealthMetric {
            peer: entry.peer(),
            path: entry.path().name(),
            state: entry.state().name(),
            reason: entry.reason().name(),
            effective_loss_ppm: entry.effective_loss_ppm(),
            path_health_score_ppm: entry.path_health_score_ppm(),
            loss_samples: entry.loss_samples(),
            sample_confidence_ppm: entry.sample_confidence_ppm(),
            enqueue_accepted: entry.enqueue_accepted(),
            enqueue_rejected: entry.enqueue_rejected(),
            too_large: entry.too_large(),
            pressure: entry.pressure(),
            outcome_successes: entry.outcome_successes(),
            outcome_failures: entry.outcome_failures(),
            ingress_validated: entry.ingress_validated(),
            ingress_rejected: entry.ingress_rejected(),
            ingress_read_failures: entry.ingress_read_failures(),
            consecutive_bad_windows: entry.consecutive_bad_windows(),
            recovery_healthy_age_ms: entry.recovery_healthy_age().as_millis(),
            recovery_required: entry.recovery_required(),
            transitions: entry.transitions(),
            state_age_ms: entry.state_age().as_millis(),
            scored_generation: entry.scored_generation(),
            diagnostic_generation: entry.diagnostic_generation(),
            observation_age_ms: entry.observation_age().as_millis(),
            diagnostic_observation_age_ms: entry
                .diagnostic_observation_age()
                .map(|age| age.as_millis()),
        })
        .collect::<Vec<_>>();
    datagram_path_health.sort_by_key(|entry| (entry.peer, entry.path));

    let mut voice_transport_bindings = metrics
        .voice_transport_bindings()
        .iter()
        .map(|entry| VoiceTransportBindingMetric {
            peer: entry.peer(),
            transport: transport_kind_name(entry.transport()),
        })
        .collect::<Vec<_>>();
    voice_transport_bindings.sort_by_key(|entry| (entry.peer, entry.transport));

    let mut voice_transport_binding_events = metrics
        .voice_transport_binding_events()
        .iter()
        .map(|entry| VoiceTransportBindingEventMetric {
            peer: entry.peer(),
            from_transport: entry
                .from_transport()
                .map(transport_kind_name)
                .unwrap_or("none"),
            to_transport: entry
                .to_transport()
                .map(transport_kind_name)
                .unwrap_or("none"),
            reason: entry.reason().name(),
            events: entry.events(),
        })
        .collect::<Vec<_>>();
    voice_transport_binding_events.sort_by_key(|entry| {
        (
            entry.peer,
            entry.from_transport,
            entry.to_transport,
            entry.reason,
        )
    });

    let mut voice_transport_challengers = metrics
        .voice_transport_challengers()
        .iter()
        .map(|entry| VoiceTransportChallengerMetric {
            peer: entry.peer(),
            incumbent: transport_kind_name(entry.incumbent()),
            challenger: transport_kind_name(entry.challenger()),
            outcome: entry.outcome().name(),
            events: entry.events(),
        })
        .collect::<Vec<_>>();
    voice_transport_challengers
        .sort_by_key(|entry| (entry.peer, entry.incumbent, entry.challenger, entry.outcome));

    let delivery_path_selections = shitspeak_s2s_transport::delivery_path_selection_snapshots()
        .into_iter()
        .map(|entry| DeliveryPathSelectionMetric {
            path: entry.path().name(),
            selections: entry.selections(),
        })
        .collect();
    let quic_lanes = shitspeak_s2s_transport::quic_lane_snapshots()
        .into_iter()
        .map(|entry| QuicLaneMetric {
            peer: entry.peer(),
            direction: entry.direction().name(),
            lane: entry.lane().name(),
            frames: entry.frames(),
            bytes: entry.bytes(),
        })
        .collect();
    let quic_datagram_drops = shitspeak_s2s_transport::quic_datagram_drop_snapshots()
        .into_iter()
        .map(|entry| QuicDatagramDropMetric {
            reason: entry.reason().name(),
            drops: entry.drops(),
        })
        .collect();
    let quic_protocol_events = shitspeak_s2s_transport::quic_protocol_event_snapshots()
        .into_iter()
        .map(|entry| QuicProtocolEventMetric {
            stage: entry.stage().name(),
            version: entry.version().name(),
            result: entry.result().name(),
            events: entry.events(),
        })
        .collect();
    let quic_protocol_errors = shitspeak_s2s_transport::quic_protocol_error_snapshots()
        .into_iter()
        .map(|entry| QuicProtocolErrorMetric {
            reason: entry.reason().name(),
            errors: entry.errors(),
        })
        .collect();
    let quic_sessions = transport
        .quic_session_status()
        .into_iter()
        .map(|entry| QuicSessionMetric {
            peer: entry.peer(),
            remote_addr: entry.remote_addr().map(|addr| addr.to_string()),
            dialer: entry.is_dialer(),
            negotiated_protocol: entry.protocol().name(),
            three_lane_ready: entry.three_lane_ready(),
            max_datagram_size: entry.max_datagram_size(),
            datagram_send_buffer_bytes: entry.datagram_send_buffer_bytes(),
            datagram_receive_buffer_bytes: entry.datagram_receive_buffer_bytes(),
            datagrams_queued: entry.datagrams_queued(),
            datagrams_received: entry.datagrams_received(),
            datagrams_dropped: entry.datagrams_dropped(),
        })
        .collect();

    TopologySnapshot {
        local_node: overlay.local_node_id(),
        generated_at_unix_ms,
        nodes,
        links,
        routes,
        duplicate_nodes,
        local_metrics,
        outbound_queues,
        inbound_queues,
        expired_outbound_drops,
        transport_health_exclusions,
        datagram_path_health,
        delivery_path_selections,
        voice_transport_bindings,
        voice_transport_binding_events,
        voice_transport_challengers,
        quic_lanes,
        quic_datagram_drops,
        quic_protocol_events,
        quic_protocol_errors,
        quic_sessions,
        debug_packet_io: crate::debug_io::snapshot(),
    }
}

pub fn render_prometheus_metrics(
    overlay: &OverlayNetwork,
    transport: &ConnectionManager,
    local_geo: Option<NodeGeo>,
) -> String {
    let snapshot = build_topology_snapshot(overlay, transport, local_geo);
    crate::overlay::distribution_metrics::set_peer_clock_offsets(&overlay.peer_clock_offsets());
    let mut out = String::new();
    let mut writer = PrometheusWriter::new(&mut out);
    writer.render(&snapshot);
    out
}

pub fn prometheus_samples(
    overlay: &OverlayNetwork,
    transport: &ConnectionManager,
    local_geo: Option<NodeGeo>,
) -> Vec<PrometheusSample> {
    let snapshot = build_topology_snapshot(overlay, transport, local_geo);
    crate::overlay::distribution_metrics::set_peer_clock_offsets(&overlay.peer_clock_offsets());
    samples_from_snapshot(&snapshot)
}

#[derive(Clone, Debug, PartialEq)]
pub struct PrometheusSample {
    name: String,
    labels: Vec<(String, String)>,
    value: f64,
}

impl PrometheusSample {
    pub fn new(name: impl Into<String>, labels: Vec<(String, String)>, value: f64) -> Self {
        Self {
            name: name.into(),
            labels,
            value,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn labels(&self) -> &[(String, String)] {
        &self.labels
    }

    pub fn value(&self) -> f64 {
        self.value
    }
}

struct PrometheusWriter<'a> {
    out: &'a mut String,
}

impl<'a> PrometheusWriter<'a> {
    fn new(out: &'a mut String) -> Self {
        Self { out }
    }

    fn render(&mut self, snapshot: &TopologySnapshot) {
        self.header("shitspeak_s2s_node_info", "S2S node metadata.", "gauge");
        self.header(
            "shitspeak_s2s_node_strict_replication_protocol_version",
            "S2S node advertised strict replication protocol version.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_node_status",
            "S2S node status by state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_node_geo_latitude",
            "S2S node latitude in degrees.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_node_geo_longitude",
            "S2S node longitude in degrees.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_rtt_us",
            "S2S advertised link RTT.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_jitter_us",
            "S2S advertised link jitter.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_throughput_bps",
            "S2S advertised link throughput.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_observed_recv_bps",
            "S2S advertised observed receive throughput.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_observed_sent_bps",
            "S2S advertised observed send throughput.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_loss_ppm",
            "S2S advertised effective link loss.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_loss_breakdown_ppm",
            "S2S advertised link loss by source.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_health_ppm",
            "S2S advertised link health failure rates.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_loss_samples",
            "S2S advertised link loss sample count.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_throughput_confidence_ppm",
            "S2S advertised link throughput confidence.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_link_status",
            "S2S advertised link status by state.",
            "gauge",
        );
        self.header("shitspeak_s2s_route_cost", "S2S route cost.", "gauge");
        self.header(
            "shitspeak_s2s_route_transport_cost",
            "S2S route transport cost.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_route_service_fit",
            "S2S route service-fit state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_duplicate_node_conflict",
            "S2S duplicate node-id conflict state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_node_quarantined",
            "S2S duplicate node quarantine state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_duplicate_node_observed_epochs",
            "S2S live/recent boot epochs observed for a node ID.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_duplicate_node_quarantine_age_ms",
            "S2S duplicate node quarantine age in milliseconds.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_duplicate_node_quarantine_remaining_ms",
            "S2S duplicate node quarantine remaining time in milliseconds.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_duplicate_node_conflicts_total",
            "S2S duplicate node-id conflicts observed.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_duplicate_node_dropped_messages_total",
            "S2S messages dropped due to duplicate node-id quarantine.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_direct_metric_rtt_us",
            "Local direct peer RTT.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_direct_metric_jitter_us",
            "Local direct peer jitter.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_direct_metric_traffic_bps",
            "Local direct peer traffic by direction.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_direct_metric_loss_ppm",
            "Local direct peer loss by kind.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_direct_metric_unmatched_probe_pongs",
            "Local direct peer probe pongs that did not match pending pings.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_direct_metric_compression_ratio",
            "Local direct peer compression ratio.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_direct_metric_last_update_age_ms",
            "Local direct peer metric update age.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_kcp_runtime_state",
            "Local KCP runtime boolean state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_kcp_runtime_window",
            "Local KCP pending and window state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_kcp_input_queue_drops_total",
            "Local KCP input queue drops.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_kcp_no_progress_closes_total",
            "Local KCP sessions closed for no progress.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_kcp_last_input_age_ms",
            "Local KCP last input age.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_kcp_outstanding_no_progress_age_ms",
            "Local KCP outstanding send no-progress age.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_transport_health_exclusions_total",
            "Local transport sender exclusions due to health checks.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_datagram_path_health",
            "Current shadow health state for each local BestEffort datagram delivery path.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_effective_loss_ppm",
            "Current weighted effective-loss score observed for a datagram delivery path.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_health_score_ppm",
            "Current local admission and writer-outcome failure score for a datagram delivery path.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_loss_samples",
            "Current effective-loss sample count for a datagram delivery path.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_sample_confidence_ppm",
            "Confidence of the current datagram delivery-path health window.",
            "gauge",
        );
        for (name, help) in [
            (
                "enqueue_accepted",
                "App-queue admissions in the current completed window.",
            ),
            (
                "enqueue_rejected",
                "App-queue rejections in the current completed window.",
            ),
            (
                "too_large",
                "Too-large or no-fit observations in the current completed window.",
            ),
            (
                "pressure",
                "App or Quinn queue-pressure observations in the current completed window.",
            ),
            (
                "outcome_successes",
                "Quinn DATAGRAM writer acceptances in the current completed window.",
            ),
            (
                "outcome_failures",
                "Quinn DATAGRAM writer failures in the current completed window.",
            ),
            (
                "ingress_validated",
                "Validated QUIC DATAGRAM ingress frames in the current completed window.",
            ),
            (
                "ingress_rejected",
                "Rejected QUIC DATAGRAM ingress frames in the current completed window.",
            ),
            (
                "ingress_read_failures",
                "QUIC DATAGRAM ingress read failures in the current completed window.",
            ),
        ] {
            self.header(
                &format!("shitspeak_s2s_datagram_path_{name}"),
                help,
                "gauge",
            );
        }
        self.header(
            "shitspeak_s2s_datagram_path_consecutive_bad_windows",
            "Consecutive completed bad windows pending shadow suspect entry.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_recovery_healthy_age_ms",
            "Span of distinct completed healthy windows pending shadow recovery.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_recovery_required",
            "Whether the datagram path must complete temporal recovery before becoming healthy.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_health_transitions",
            "Shadow datagram health state transitions in the current observation lifetime.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_health_state_age_ms",
            "Age of the current shadow datagram health state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_health_observation_age_ms",
            "Age of the most recent scored shadow datagram health observation.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_scored_generation",
            "Generation of the most recent scored QUIC DATAGRAM evidence window.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_diagnostic_generation",
            "Generation of the most recent diagnostic QUIC DATAGRAM evidence window.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_datagram_path_diagnostic_observation_age_ms",
            "Age of the most recent diagnostic QUIC DATAGRAM evidence window.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_delivery_path_selections_total",
            "Local successful S2S dispatch selections by logical delivery path.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_transport_binding",
            "Current sticky voice transport binding by local node and peer.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_transport_binding_events_total",
            "Sticky voice transport binding transitions by local node, peer, and reason.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_transport_challenger_total",
            "Sticky voice transport challenger outcomes by local node and peer.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_tree_edge_binding",
            "Current sticky voice tree-edge binding mode by source and peer.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_tree_edge_binding_events_total",
            "Sticky voice tree-edge binding transitions by source, peer, and reason.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_overlap_reserved_bytes",
            "Reserved overlap-copy bytes by first hop.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_overlap_capacity_bytes",
            "Rate-scaled overlap-copy capacity by first hop.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_overlap_copies_sent_total",
            "Voice overlap copies accepted by first hop.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_overlap_copies_shed_total",
            "Voice overlap copies shed before or during send.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_overlap_primary_fallback_sends_total",
            "Primary voice sends recovered through the overlap path.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_queue_status",
            "Local S2S queue status by direction, peer, transport, and class.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_outbound_queue_status",
            "Local S2S outbound queue status.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_inbound_queue_status",
            "Local S2S inbound queue status.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_expired_outbound_frames_total",
            "S2S outbound frames dropped because their send deadline expired.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_quic_lane_frames_total",
            "QUIC v2 frames by peer, direction, and physical delivery lane.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_quic_lane_bytes_total",
            "QUIC v2 payload bytes by peer, direction, and physical delivery lane.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_quic_datagram_drops_total",
            "QUIC DATAGRAM drops by bounded reason.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_quic_protocol_events_total",
            "QUIC S2S protocol negotiation and setup results.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_quic_protocol_errors_total",
            "QUIC S2S protocol errors by bounded reason.",
            "counter",
        );
        // CPU_ATTRIBUTION_PROMQL s2s_transport_pipeline:
        // topk(20, sum by (transport, stage) (
        //   rate(shitspeak_s2s_transport_pipeline_stage_duration_us_total{source="12"}[5m])
        // ) / 1e6)
        // Search with: rg "CPU_ATTRIBUTION_PROMQL s2s_transport_pipeline"
        self.header(
            "shitspeak_s2s_transport_pipeline_stage_events_total",
            "S2S transport pipeline stage observations by transport and stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_transport_pipeline_stage_duration_us_total",
            "S2S transport pipeline stage wall-clock duration in microseconds by transport and stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_transport_pipeline_stage_duration_us_bucket_total",
            "Bucketed S2S transport pipeline stage wall-clock duration in microseconds by transport and stage.",
            "counter",
        );
        // CHOPPY_VOICE_PROMQL node_to_node:
        // Source node egress to each peer:
        // sum by (source, peer, transport, direction) (
        //   rate(shitspeak_s2s_transport_io_bytes_total{
        //     source="12", direction="egress"
        //   }[1m])
        // )
        // Peer ingress from source node 12:
        // sum by (source, peer, transport, direction) (
        //   rate(shitspeak_s2s_transport_io_bytes_total{
        //     peer="12", direction="ingress"
        //   }[1m])
        // )
        // Pressure on node 12 vs sibling China nodes:
        // sum by (source, peer, transport, direction, result) (
        //   rate(shitspeak_s2s_transport_io_pressure_total{
        //     source=~"1|11|12|13|14"
        //   }[5m])
        // )
        // Search with: rg "CHOPPY_VOICE_PROMQL node_to_node"
        self.header(
            "shitspeak_s2s_transport_io_batches_total",
            "S2S transport IO batches by local node, peer, transport, and direction.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_transport_io_frames_total",
            "S2S transport IO frames by local node, peer, transport, direction, and class.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_transport_io_bytes_total",
            "S2S transport IO bytes by local node, peer, transport, and direction.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_transport_io_batch_size_bucket_total",
            "S2S transport IO batch size buckets by local node, peer, transport, and direction.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_transport_io_pressure_total",
            "S2S transport IO pressure events by local node, peer, transport, direction, and result.",
            "counter",
        );
        // CHOPPY_VOICE_PROMQL source_node_egress:
        // Source node app-level S2S voice egress:
        // sum by (source, mode, result) (
        //   rate(shitspeak_s2s_voice_send_events_total{source="12"}[1m])
        // )
        // Compare against receiver-side S2S reorder outcomes:
        // sum by (source, origin_node, from_immediate, result) (
        //   rate(shitspeak_s2s_voice_receive_events_total{
        //     source="12", origin_node="12", result=~"gap_buffered|gap_filled|deadline_flush|buffer_drop"
        //   }[1m])
        // )
        // Search with: rg "CHOPPY_VOICE_PROMQL source_node_egress"
        self.header(
            "shitspeak_s2s_voice_send_events_total",
            "S2S voice application send events by local node, mode, destination-count bucket, bytes bucket, and result.",
            "counter",
        );
        // CHOPPY_VOICE_PROMQL receiver_node_ingress:
        // Receiver reorder outcomes for voice originated by node 12:
        // sum by (source, origin_node, from_immediate, result) (
        //   rate(shitspeak_s2s_voice_receive_events_total{source="13", origin_node="12"}[1m])
        // )
        // Receiver repair behavior for the same incident window:
        // sum by (source, peer, result) (
        //   rate(shitspeak_s2s_voice_repair_events_total{source="13"}[1m])
        // )
        // Compare with receiver native UDP egress pressure:
        // sum by (node, result) (
        //   rate(shitspeak_voice_udp_send_events_total{node="13"}[1m])
        // )
        // Search with: rg "CHOPPY_VOICE_PROMQL receiver_node_ingress"
        self.header(
            "shitspeak_s2s_voice_receive_events_total",
            "S2S voice application receive and reorder events by local node, origin node, immediate peer, and result.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_repair_events_total",
            "S2S voice repair events by local node, peer, and result.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_repair_cache_occupancy",
            "Current number of original S2S voice frames retained for repair.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_repair_cache_capacity",
            "Maximum number of original S2S voice frames retained for repair.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_repair_cache_evictions_total",
            "Original S2S voice frames evicted because the repair cache reached capacity.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_reorder_pending",
            "Current S2S voice reorder pending frame count by local node.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reorder_pending_bucket_total",
            "Sampled S2S voice reorder pending frame count buckets by local node.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_ingress_admission_drops_total",
            "S2S voice ingress work rejected by byte-budget lane.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_ingress_queue_capacity_bytes",
            "Current S2S voice ingress byte-budget capacity by lane.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_ingress_queue_used_bytes",
            "S2S voice ingress byte-budget capacity reserved by lane.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reorder_speaker_states",
            "Current S2S voice reorder speaker states.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reorder_speaker_cap",
            "Current S2S voice reorder speaker-state admission cap.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_deadline_wakes_total",
            "S2S voice reorder deadline wake requests by bounded result.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_proactive_queue_capacity_bytes",
            "Current S2S voice proactive repair byte-budget capacity.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_proactive_queue_used_bytes",
            "S2S voice proactive repair byte-budget capacity reserved.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_proactive_credit_balance_bytes",
            "Current S2S voice proactive repair byte-credit balance.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_proactive_credit_cap_bytes",
            "Current S2S voice proactive repair byte-credit burst cap.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_proactive_events_total",
            "S2S voice proactive repair outcomes by bounded kind and result.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_repair_credit_bytes_total",
            "S2S voice repair credit bytes by bounded lifecycle stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_repair_allocator_class_bytes_total",
            "S2S voice repair allocation bytes by bounded proactive or reactive class and stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_repair_allocator_destination_bytes_total",
            "S2S voice repair allocation bytes by bounded cluster peer and allocation stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_repair_allocator_state_bytes",
            "Current S2S voice hierarchical repair allocator byte state.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_repair_allocator_active_destinations",
            "Current destinations participating in S2S voice fair repair allocation.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reactive_scheduler_events_total",
            "S2S voice reactive repair scheduler outcomes by bounded event.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_voice_reactive_scheduler_queued_items",
            "Current S2S voice reactive repair items waiting for scheduling.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reactive_scheduler_queued_encoded_bytes",
            "Current encoded bytes in S2S voice reactive repair items waiting for scheduling.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reactive_scheduler_active_destinations",
            "Current destinations represented in the S2S voice reactive repair queue.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reactive_scheduler_oldest_wait_microseconds",
            "Age in microseconds of the oldest queued S2S voice reactive repair item.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_voice_reactive_scheduler_max_starvation_rounds",
            "Current maximum scheduler starvation rounds across queued S2S voice reactive destinations.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_debug_packet_io_bytes_total",
            "Debug S2S packet IO bytes by packet kind and direction.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_debug_packet_io_packets_total",
            "Debug S2S packet IO packets by packet kind and direction.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_debug_packet_io_avg_bps",
            "Debug S2S packet IO average bytes per second by packet kind and direction.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_replication_catchup_requests_total",
            "Logical S2S replication catchup requests sent by mode, initiating reason, and phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_replication_catchup_responses_total",
            "Logical S2S replication catchup responses built by mode, initiating reason, and phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_replication_catchup_response_ops_total",
            "Logical S2S replication catchup records encoded by mode, initiating reason, and phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_replication_catchup_response_bytes_total",
            "Logical S2S replication catchup response bytes encoded by mode, initiating reason, and phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_replication_catchup_suppressed_total",
            "S2S replication catchup work suppressed by mode, initiating reason, and phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_replication_catchup_active",
            "S2S replication catchup responses currently active.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_session_starts_total",
            "Strict replication catchup sessions started by bounded initiating reason.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_session_completions_total",
            "Strict replication catchup sessions completed by bounded initiating reason and outcome.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_sessions_active",
            "Current strict replication catchup sessions by bounded initiating reason.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_session_events_total",
            "Strict replication catchup session coalescing, refresh, restart, and final-ack events.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_send_attempts_total",
            "Physical strict replication catchup send attempts by reason, phase, lane, and outcome, including retries and redundant copies.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_send_bytes_total",
            "Exact encoded bytes in physical strict replication catchup send attempts by reason, phase, lane, and outcome.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_duplicate_pages_total",
            "Strict replication catchup duplicate pages by suppression or cached-replay outcome.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_snapshot_receive_events_total",
            "Strict replication snapshot receiver progress, stale-page, and bounded restart-reason events.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_snapshot_responder_events_total",
            "Non-exclusive strict replication snapshot responder decisions, lifecycle transitions, and send anomalies.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_backpressure_events_total",
            "Strict replication catchup backpressure, retry, and exhausted-retry events by reason and phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_backoff_delay_ms_total",
            "Accumulated strict replication catchup backoff delay in milliseconds by reason and phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_bulk_in_flight_bytes",
            "Current strict replication catchup bulk bytes reserved in flight.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_catchup_throttled_total",
            "Strict replication catchup work throttled by bounded resource reason.",
            "counter",
        );
        // CPU_ATTRIBUTION_PROMQL s2s_replication_pipeline:
        // topk(20, sum by (kind, stage) (
        //   rate(shitspeak_s2s_replication_pipeline_stage_duration_us_total{node="12"}[5m])
        // ) / 1e6)
        // Replace node="12" with the scraper's node-id label if needed.
        // Search with: rg "CPU_ATTRIBUTION_PROMQL s2s_replication_pipeline"
        self.header(
            "shitspeak_s2s_replication_pipeline_stage_events_total",
            "S2S replication pipeline stage observations by replication kind and stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_replication_pipeline_stage_duration_us_total",
            "Total S2S replication pipeline stage wall-clock duration in microseconds by replication kind and stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_replication_pipeline_stage_duration_us_bucket_total",
            "Bucketed S2S replication pipeline stage wall-clock duration in microseconds by replication kind and stage.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_client_replication_worker_queue_depth",
            "S2S client replication worker queue depth.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_client_replication_worker_queue_wait_us_total",
            "Total time spent waiting in the S2S client replication worker queue.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_client_replication_worker_queue_wait_samples_total",
            "S2S client replication worker queue wait samples.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_client_replication_worker_queue_wait_us_bucket_total",
            "S2S client replication worker queue wait buckets.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_cluster_protocol_version",
            "Minimum strict replication protocol version advertised by alive S2S peers.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_terminal_resolution_ready",
            "Whether the negotiated strict protocol may emit terminal resolutions.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_unsupported_active_peers",
            "Alive S2S peers below the strict terminal-resolution protocol version.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_terminal_decisions_total",
            "Strict terminal decisions by bounded outcome.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_fence_rejections_total",
            "Late or conflicting strict frames rejected by a terminal-resolution fence.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_admission_peer_states",
            "Strict topic-peer admission records by bounded convergence state; self is implicit and excluded.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_admission_highest_barrier",
            "Highest logical strict timestamp currently fencing a pending peer admission across active strict topics.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_admission_awaiting_proofs",
            "Strict peer admissions awaiting history, clock, or both reciprocal proofs across active strict topics.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_clock_demand",
            "Current strict clock-tick demand by bounded cause: active-topic counts for local work and peer counts for missing evidence.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_unacknowledged_head_peers",
            "Current routed peer incarnations that have not acknowledged local strict head evidence.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_probe_events_total",
            "Strict clock and history probe lifecycle events by bounded reason and outcome.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_admission_events_total",
            "Strict peer admission state-machine transitions and proof observations by bounded event.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_history_election_events_total",
            "Strict history-election state-machine transitions and observations by bounded event.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_head_events_total",
            "Strict head-evidence observations, acknowledgement outcomes, and clock-tick attempts by bounded event.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_phase_topics",
            "Current strict recovery topics by bounded coordinator phase.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_progress_age_ms",
            "Maximum milliseconds since authenticated progress among strict recovery topics in each phase.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_donor_sessions_active",
            "Active protocol-v8 donor sessions by bounded transfer kind.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_attempts_total",
            "Strict foreign-lineage recovery attempts started.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_coalesced_triggers_total",
            "Strict recovery triggers coalesced into an active attempt by bounded event.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_retransmits_total",
            "Strict recovery wire identities retransmitted by bounded coordinator phase.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_donor_switches_total",
            "Strict recovery donor switches by bounded reason.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_certificate_failures_total",
            "Strict recovery certificate failures by bounded reason.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_stale_events_total",
            "Attempt-correlated strict recovery callbacks ignored by bounded event class.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_completion_duration_ms_total",
            "Accumulated duration in milliseconds of completed strict recovery attempts.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_strict_replication_recovery_completion_duration_count",
            "Number of completed strict recovery attempts included in the duration total.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_distribution_events_total",
            "Distribution-tree control, forwarding, deadline, and fallback events.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_distribution_pending_acks",
            "Pending acknowledgements before a distribution tree activates.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_distribution_tree_edges",
            "Tree edges in this node's local distribution snapshots; not cluster-unique edges.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_overlay_attachment_inline_bytes_total",
            "Bytes of optional overlay attachments received inline.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_overlay_attachment_sidecar_chunks_emitted_total",
            "Disposable overlay attachment chunks generated for sidecar delivery.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_overlay_attachment_sidecar_chunks_dropped_total",
            "Invalid disposable overlay attachment chunks discarded at their destination.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_overlay_attachment_reassemblies_total",
            "Complete disposable overlay attachments reassembled from sidecar chunks.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_overlay_attachment_cacheless_branch_drops_total",
            "Realtime tree branches dropped without cached or inline tree hints.",
            "counter",
        );
        self.header(
            "shitspeak_s2s_distribution_peer_clock_offset_us",
            "Direct peer wall-clock offset in microseconds, positive when the peer is ahead.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_distribution_peer_clock_uncertainty_us",
            "Direct peer clock estimate uncertainty in microseconds.",
            "gauge",
        );
        self.header(
            "shitspeak_s2s_distribution_peer_clock_estimate_age_seconds",
            "Age of the selected fresh direct-peer clock estimate in seconds.",
            "gauge",
        );

        for sample in samples_from_snapshot(snapshot) {
            self.sample(sample);
        }
    }

    fn header(&mut self, name: &str, help: &str, kind: &str) {
        self.out.push_str("# HELP ");
        self.out.push_str(name);
        self.out.push(' ');
        self.out.push_str(help);
        self.out.push('\n');
        self.out.push_str("# TYPE ");
        self.out.push_str(name);
        self.out.push(' ');
        self.out.push_str(kind);
        self.out.push('\n');
    }

    fn sample(&mut self, sample: PrometheusSample) {
        self.out.push_str(&sample.name);
        if !sample.labels.is_empty() {
            self.out.push('{');
            for (index, (key, value)) in sample.labels.iter().enumerate() {
                if index > 0 {
                    self.out.push(',');
                }
                self.out.push_str(key);
                self.out.push_str("=\"");
                escape_label_value(self.out, value);
                self.out.push('"');
            }
            self.out.push('}');
        }
        self.out.push(' ');
        self.out.push_str(&format_prometheus_value(sample.value));
        self.out.push('\n');
    }
}

fn samples_from_snapshot(snapshot: &TopologySnapshot) -> Vec<PrometheusSample> {
    let mut out = Vec::new();
    out.extend(crate::replications::metrics::prometheus_samples());
    out.extend(crate::application::voice::metrics::prometheus_samples());
    out.extend(crate::overlay::distribution_metrics::prometheus_samples(
        snapshot.local_node,
    ));
    out.extend(crate::overlay::attachment_metrics::prometheus_samples());
    let local_node = snapshot.local_node.to_string();
    for node in snapshot
        .nodes
        .iter()
        .filter(|node| node.node_id == snapshot.local_node)
    {
        let node_id = node.node_id.to_string();
        out.push(sample(
            "shitspeak_s2s_node_info",
            vec![
                ("node", node_id.as_str()),
                ("transit_enabled", bool_label(node.transit_enabled)),
                (
                    "geo_source",
                    node.geo.as_ref().map(NodeGeo::source).unwrap_or(""),
                ),
            ],
            1.0,
        ));
        out.push(sample(
            "shitspeak_s2s_node_strict_replication_protocol_version",
            vec![("node", node_id.as_str())],
            node.strict_replication_protocol_version.unwrap_or(0) as f64,
        ));
        for state in ["alive", "failed", "left"] {
            out.push(sample(
                "shitspeak_s2s_node_status",
                vec![("node", node_id.as_str()), ("status", state)],
                if node.status == state { 1.0 } else { 0.0 },
            ));
        }
        if let Some(geo) = &node.geo {
            out.push(sample(
                "shitspeak_s2s_node_geo_latitude",
                vec![
                    ("node", node_id.as_str()),
                    ("city", geo.city().unwrap_or("")),
                    ("region", geo.region().unwrap_or("")),
                    ("country", geo.country().unwrap_or("")),
                    ("source", geo.source()),
                ],
                geo.latitude(),
            ));
            out.push(sample(
                "shitspeak_s2s_node_geo_longitude",
                vec![
                    ("node", node_id.as_str()),
                    ("city", geo.city().unwrap_or("")),
                    ("region", geo.region().unwrap_or("")),
                    ("country", geo.country().unwrap_or("")),
                    ("source", geo.source()),
                ],
                geo.longitude(),
            ));
        }
    }

    for link in snapshot
        .links
        .iter()
        .filter(|link| link.source == snapshot.local_node)
    {
        let source = link.source.to_string();
        let target = link.target.to_string();
        let transport = if link.transports.is_empty() {
            "unknown".to_owned()
        } else {
            link.transports.join(",")
        };
        let base = vec![
            ("source", source.as_str()),
            ("target", target.as_str()),
            ("transport", transport.as_str()),
        ];
        out.push(sample_with_base(
            "shitspeak_s2s_link_rtt_us",
            &base,
            link.rtt_us as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_link_jitter_us",
            &base,
            link.jitter_us as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_link_throughput_bps",
            &base,
            link.throughput_bps as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_link_observed_recv_bps",
            &base,
            link.observed_recv_bps as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_link_observed_sent_bps",
            &base,
            link.observed_sent_bps as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_link_loss_ppm",
            &base,
            link.loss_ppm as f64,
        ));
        for (metric, value) in [
            ("effective", link.loss_ppm),
            ("probe", link.probe_loss_ppm),
            ("native", link.native_loss_ppm),
        ] {
            let mut labels = base.clone();
            labels.push(("metric", metric));
            out.push(sample(
                "shitspeak_s2s_link_loss_breakdown_ppm",
                labels,
                value as f64,
            ));
        }
        {
            let mut labels = base.clone();
            labels.push(("metric", "data_health"));
            out.push(sample(
                "shitspeak_s2s_link_health_ppm",
                labels,
                link.data_health_ppm as f64,
            ));
        }
        out.push(sample_with_base(
            "shitspeak_s2s_link_loss_samples",
            &base,
            link.loss_sample_count as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_link_throughput_confidence_ppm",
            &base,
            link.throughput_confidence_ppm as f64,
        ));
        for status in ["active", "stale"] {
            let mut labels = base.clone();
            labels.push(("status", status));
            out.push(sample(
                "shitspeak_s2s_link_status",
                labels,
                if link.status == status { 1.0 } else { 0.0 },
            ));
        }
    }

    for route in &snapshot.routes {
        let source = local_node.clone();
        let target = route.dst.to_string();
        let next_hop = route.next_hop.to_string();
        let base = vec![
            ("source", source.as_str()),
            ("target", target.as_str()),
            ("dst", target.as_str()),
            ("next_hop", next_hop.as_str()),
            ("metric", route.metric),
            ("level", route.level),
            ("transport", route.transport),
        ];
        out.push(sample_with_base(
            "shitspeak_s2s_route_cost",
            &base,
            route.cost as f64,
        ));
        if let Some(cost) = route.transport_cost {
            out.push(sample_with_base(
                "shitspeak_s2s_route_transport_cost",
                &base,
                cost as f64,
            ));
        }
        for fit in ["chosen", "candidate", "ineligible"] {
            let mut labels = base.clone();
            labels.push(("service_fit", fit));
            out.push(sample(
                "shitspeak_s2s_route_service_fit",
                labels,
                if route.service_fit == fit { 1.0 } else { 0.0 },
            ));
        }
    }

    for duplicate in &snapshot.duplicate_nodes {
        let source = local_node.clone();
        let node = duplicate.node.to_string();
        let base = vec![("source", source.as_str()), ("node", node.as_str())];
        out.push(sample_with_base(
            "shitspeak_s2s_duplicate_node_conflict",
            &base,
            if duplicate.conflict { 1.0 } else { 0.0 },
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_duplicate_node_observed_epochs",
            &base,
            duplicate.observed_epochs as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_duplicate_node_quarantine_age_ms",
            &base,
            duplicate.quarantine_age_ms as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_duplicate_node_quarantine_remaining_ms",
            &base,
            duplicate.quarantine_remaining_ms as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_duplicate_node_conflicts_total",
            &base,
            duplicate.conflicts_total as f64,
        ));
        {
            let mut labels = base.clone();
            labels.push(("reason", duplicate.reason));
            out.push(sample(
                "shitspeak_s2s_node_quarantined",
                labels,
                if duplicate.quarantined { 1.0 } else { 0.0 },
            ));
        }
        for drop in &duplicate.dropped_messages_total {
            let mut labels = base.clone();
            labels.push(("kind", drop.kind));
            out.push(sample(
                "shitspeak_s2s_duplicate_node_dropped_messages_total",
                labels,
                drop.count as f64,
            ));
        }
    }

    for metric in &snapshot.local_metrics {
        let source = local_node.clone();
        let peer = metric.peer.to_string();
        let base = vec![
            ("source", source.as_str()),
            ("peer", peer.as_str()),
            ("transport", metric.transport),
        ];
        out.push(sample_with_base(
            "shitspeak_s2s_direct_metric_rtt_us",
            &base,
            metric.rtt_us,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_direct_metric_jitter_us",
            &base,
            metric.jitter_us,
        ));
        for (direction, value) in [
            ("recv", metric.recv_bps),
            ("sent", metric.sent_bps),
            ("wire_recv", metric.wire_recv_bps),
            ("wire_sent", metric.wire_sent_bps),
        ] {
            let mut labels = base.clone();
            labels.push(("direction", direction));
            out.push(sample(
                "shitspeak_s2s_direct_metric_traffic_bps",
                labels,
                value,
            ));
        }
        for (kind, value) in [
            ("effective", metric.packet_loss_ppm),
            ("probe", metric.probe_loss_ppm),
            ("probe_ewma", metric.probe_loss_ewma_ppm),
            ("native", metric.native_loss_ppm),
            ("native_ewma", metric.native_loss_ewma_ppm),
            ("data_health", metric.data_health_ppm),
        ] {
            let mut labels = base.clone();
            labels.push(("kind", kind));
            out.push(sample(
                "shitspeak_s2s_direct_metric_loss_ppm",
                labels,
                value as f64,
            ));
        }
        out.push(sample_with_base(
            "shitspeak_s2s_direct_metric_unmatched_probe_pongs",
            &base,
            metric.unmatched_probe_pongs as f64,
        ));
        for (direction, value) in [
            ("recv", metric.compression_recv_ratio),
            ("sent", metric.compression_sent_ratio),
            ("total", metric.compression_total_ratio),
        ] {
            if let Some(value) = value {
                let mut labels = base.clone();
                labels.push(("direction", direction));
                out.push(sample(
                    "shitspeak_s2s_direct_metric_compression_ratio",
                    labels,
                    value,
                ));
            }
        }
        if let Some(age) = metric.last_update_age_ms {
            out.push(sample_with_base(
                "shitspeak_s2s_direct_metric_last_update_age_ms",
                &base,
                age as f64,
            ));
        }
        if let Some(runtime) = &metric.kcp_runtime {
            for (state, active) in [
                ("closed", runtime.closed),
                ("pending_sender", runtime.pending_sender),
                ("waiting_conv", runtime.waiting_conv),
            ] {
                let mut labels = base.clone();
                labels.push(("state", state));
                out.push(sample(
                    "shitspeak_s2s_kcp_runtime_state",
                    labels,
                    if active { 1.0 } else { 0.0 },
                ));
            }
            for (metric_name, value) in [
                ("wait_snd", runtime.wait_snd),
                ("snd_wnd", runtime.snd_wnd),
                ("rmt_wnd", runtime.rmt_wnd),
            ] {
                let mut labels = base.clone();
                labels.push(("metric", metric_name));
                out.push(sample(
                    "shitspeak_s2s_kcp_runtime_window",
                    labels,
                    value as f64,
                ));
            }
            out.push(sample_with_base(
                "shitspeak_s2s_kcp_input_queue_drops_total",
                &base,
                runtime.input_queue_drops as f64,
            ));
            out.push(sample_with_base(
                "shitspeak_s2s_kcp_no_progress_closes_total",
                &base,
                runtime.no_progress_closes as f64,
            ));
            if let Some(age) = runtime.last_input_age_ms {
                out.push(sample_with_base(
                    "shitspeak_s2s_kcp_last_input_age_ms",
                    &base,
                    age as f64,
                ));
            }
            if let Some(age) = runtime.outstanding_no_progress_age_ms {
                out.push(sample_with_base(
                    "shitspeak_s2s_kcp_outstanding_no_progress_age_ms",
                    &base,
                    age as f64,
                ));
            }
        }
    }

    for entry in &snapshot.transport_health_exclusions {
        let source = local_node.clone();
        let peer = entry.peer.to_string();
        out.push(sample(
            "shitspeak_s2s_transport_health_exclusions_total",
            vec![
                ("source", source.as_str()),
                ("peer", peer.as_str()),
                ("transport", entry.transport),
                ("reason", entry.reason),
            ],
            entry.exclusions as f64,
        ));
    }

    for entry in &snapshot.datagram_path_health {
        let source = local_node.clone();
        let peer = entry.peer.to_string();
        let labels = vec![
            ("source", source.as_str()),
            ("peer", peer.as_str()),
            ("path", entry.path),
            ("state", entry.state),
            ("reason", entry.reason),
        ];
        out.push(sample(
            "shitspeak_s2s_datagram_path_health",
            labels.clone(),
            1.0,
        ));
        if let Some(loss_ppm) = entry.effective_loss_ppm {
            out.push(sample(
                "shitspeak_s2s_datagram_path_effective_loss_ppm",
                labels.clone(),
                loss_ppm as f64,
            ));
        }
        if let Some(score_ppm) = entry.path_health_score_ppm {
            out.push(sample(
                "shitspeak_s2s_datagram_path_health_score_ppm",
                labels.clone(),
                score_ppm as f64,
            ));
        }
        out.push(sample(
            "shitspeak_s2s_datagram_path_loss_samples",
            labels.clone(),
            entry.loss_samples as f64,
        ));
        out.push(sample(
            "shitspeak_s2s_datagram_path_sample_confidence_ppm",
            labels.clone(),
            entry.sample_confidence_ppm as f64,
        ));
        for (name, value) in [
            ("enqueue_accepted", entry.enqueue_accepted),
            ("enqueue_rejected", entry.enqueue_rejected),
            ("too_large", entry.too_large),
            ("pressure", entry.pressure),
            ("outcome_successes", entry.outcome_successes),
            ("outcome_failures", entry.outcome_failures),
            ("ingress_validated", entry.ingress_validated),
            ("ingress_rejected", entry.ingress_rejected),
            ("ingress_read_failures", entry.ingress_read_failures),
        ] {
            out.push(sample(
                &format!("shitspeak_s2s_datagram_path_{name}"),
                labels.clone(),
                value as f64,
            ));
        }
        out.push(sample(
            "shitspeak_s2s_datagram_path_consecutive_bad_windows",
            labels.clone(),
            entry.consecutive_bad_windows as f64,
        ));
        out.push(sample(
            "shitspeak_s2s_datagram_path_recovery_healthy_age_ms",
            labels.clone(),
            entry.recovery_healthy_age_ms as f64,
        ));
        out.push(sample(
            "shitspeak_s2s_datagram_path_recovery_required",
            labels.clone(),
            if entry.recovery_required { 1.0 } else { 0.0 },
        ));
        out.push(sample(
            "shitspeak_s2s_datagram_path_health_transitions",
            labels.clone(),
            entry.transitions as f64,
        ));
        out.push(sample(
            "shitspeak_s2s_datagram_path_health_state_age_ms",
            labels.clone(),
            entry.state_age_ms as f64,
        ));
        if let Some(generation) = entry.scored_generation {
            out.push(sample(
                "shitspeak_s2s_datagram_path_scored_generation",
                labels.clone(),
                generation as f64,
            ));
        }
        if let Some(generation) = entry.diagnostic_generation {
            out.push(sample(
                "shitspeak_s2s_datagram_path_diagnostic_generation",
                labels.clone(),
                generation as f64,
            ));
        }
        out.push(sample(
            "shitspeak_s2s_datagram_path_health_observation_age_ms",
            labels.clone(),
            entry.observation_age_ms as f64,
        ));
        if let Some(age_ms) = entry.diagnostic_observation_age_ms {
            out.push(sample(
                "shitspeak_s2s_datagram_path_diagnostic_observation_age_ms",
                labels,
                age_ms as f64,
            ));
        }
    }

    for entry in &snapshot.voice_transport_bindings {
        let source = local_node.clone();
        let peer = entry.peer.to_string();
        out.push(sample(
            "shitspeak_s2s_voice_transport_binding",
            vec![
                ("source", source.as_str()),
                ("peer", peer.as_str()),
                ("transport", entry.transport),
            ],
            1.0,
        ));
    }

    for entry in &snapshot.voice_transport_binding_events {
        let source = local_node.clone();
        let peer = entry.peer.to_string();
        out.push(sample(
            "shitspeak_s2s_voice_transport_binding_events_total",
            vec![
                ("source", source.as_str()),
                ("peer", peer.as_str()),
                ("from_transport", entry.from_transport),
                ("to_transport", entry.to_transport),
                ("reason", entry.reason),
            ],
            entry.events as f64,
        ));
    }

    for entry in &snapshot.voice_transport_challengers {
        let source = local_node.clone();
        let peer = entry.peer.to_string();
        out.push(sample(
            "shitspeak_s2s_voice_transport_challenger_total",
            vec![
                ("source", source.as_str()),
                ("peer", peer.as_str()),
                ("incumbent", entry.incumbent),
                ("challenger", entry.challenger),
                ("outcome", entry.outcome),
            ],
            entry.events as f64,
        ));
    }

    for queue in &snapshot.outbound_queues {
        let source = local_node.clone();
        let peer = queue.peer.to_string();
        let unified_base = vec![
            ("source", source.as_str()),
            ("direction", "outgoing"),
            ("peer", peer.as_str()),
            ("transport", queue.transport),
            ("class", ""),
        ];
        add_queue_status_samples(
            &mut out,
            "shitspeak_s2s_queue_status",
            &unified_base,
            queue.depth,
            queue.high_watermark,
            queue.capacity,
            queue.samples,
            queue.full_samples,
        );

        let base = vec![
            ("source", source.as_str()),
            ("peer", peer.as_str()),
            ("transport", queue.transport),
        ];
        add_queue_status_samples(
            &mut out,
            "shitspeak_s2s_outbound_queue_status",
            &base,
            queue.depth,
            queue.high_watermark,
            queue.capacity,
            queue.samples,
            queue.full_samples,
        );
    }

    for queue in &snapshot.inbound_queues {
        let source = local_node.clone();
        let unified_base = vec![
            ("source", source.as_str()),
            ("direction", "incoming"),
            ("peer", ""),
            ("transport", ""),
            ("class", queue.class),
        ];
        add_queue_status_samples(
            &mut out,
            "shitspeak_s2s_queue_status",
            &unified_base,
            queue.depth,
            queue.high_watermark,
            queue.capacity,
            queue.samples,
            queue.full_samples,
        );

        let base = vec![("source", source.as_str()), ("class", queue.class)];
        add_queue_status_samples(
            &mut out,
            "shitspeak_s2s_inbound_queue_status",
            &base,
            queue.depth,
            queue.high_watermark,
            queue.capacity,
            queue.samples,
            queue.full_samples,
        );
    }

    for entry in &snapshot.expired_outbound_drops {
        let source = local_node.clone();
        let peer = entry.peer.to_string();
        out.push(sample(
            "shitspeak_s2s_expired_outbound_frames_total",
            vec![
                ("source", source.as_str()),
                ("peer", peer.as_str()),
                ("stage", entry.stage),
                ("transport", entry.transport),
                ("class", entry.class),
            ],
            entry.frames as f64,
        ));
    }

    for entry in &snapshot.delivery_path_selections {
        out.push(sample(
            "shitspeak_s2s_delivery_path_selections_total",
            vec![("source", local_node.as_str()), ("path", entry.path)],
            entry.selections as f64,
        ));
    }

    for entry in &snapshot.quic_lanes {
        let source = local_node.clone();
        let peer = entry
            .peer
            .map(|peer| peer.to_string())
            .unwrap_or_else(|| "overflow".to_owned());
        let labels = vec![
            ("source", source.as_str()),
            ("peer", peer.as_str()),
            ("direction", entry.direction),
            ("lane", entry.lane),
        ];
        out.push(sample_with_base(
            "shitspeak_s2s_quic_lane_frames_total",
            &labels,
            entry.frames as f64,
        ));
        out.push(sample_with_base(
            "shitspeak_s2s_quic_lane_bytes_total",
            &labels,
            entry.bytes as f64,
        ));
    }
    for entry in &snapshot.quic_datagram_drops {
        out.push(sample(
            "shitspeak_s2s_quic_datagram_drops_total",
            vec![("source", local_node.as_str()), ("reason", entry.reason)],
            entry.drops as f64,
        ));
    }
    for entry in &snapshot.quic_protocol_events {
        out.push(sample(
            "shitspeak_s2s_quic_protocol_events_total",
            vec![
                ("source", local_node.as_str()),
                ("stage", entry.stage),
                ("version", entry.version),
                ("result", entry.result),
            ],
            entry.events as f64,
        ));
    }
    for entry in &snapshot.quic_protocol_errors {
        out.push(sample(
            "shitspeak_s2s_quic_protocol_errors_total",
            vec![("source", local_node.as_str()), ("reason", entry.reason)],
            entry.errors as f64,
        ));
    }

    for stage in shitspeak_s2s_transport::transport_pipeline_stage_snapshots() {
        add_transport_pipeline_stage_samples(&mut out, &local_node, stage);
    }
    for io in shitspeak_s2s_transport::transport_io_snapshots() {
        add_transport_io_samples(&mut out, &local_node, io);
    }
    for frames in shitspeak_s2s_transport::transport_io_frame_snapshots() {
        add_transport_io_frame_samples(&mut out, &local_node, frames);
    }

    for packet in &snapshot.debug_packet_io {
        add_debug_packet_samples(&mut out, packet);
    }

    out
}

fn add_queue_status_samples(
    out: &mut Vec<PrometheusSample>,
    name: &str,
    base: &[(&str, &str)],
    depth: usize,
    high_watermark: usize,
    capacity: usize,
    samples: u64,
    full_samples: u64,
) {
    for (metric, value) in [
        ("depth", depth as f64),
        ("high_watermark", high_watermark as f64),
        ("capacity", capacity as f64),
        ("samples", samples as f64),
        ("full_samples", full_samples as f64),
    ] {
        let mut labels = base.to_vec();
        labels.push(("metric", metric));
        out.push(sample(name, labels, value));
    }
}

fn add_transport_pipeline_stage_samples(
    out: &mut Vec<PrometheusSample>,
    local_node: &str,
    stage: shitspeak_s2s_transport::TransportPipelineStageSnapshot,
) {
    let transport = transport_kind_name(stage.transport());
    let stage_name = stage.stage().name();
    let labels = vec![
        ("source", local_node),
        ("transport", transport),
        ("stage", stage_name),
    ];
    out.push(sample(
        "shitspeak_s2s_transport_pipeline_stage_events_total",
        labels.clone(),
        stage.events() as f64,
    ));
    out.push(sample(
        "shitspeak_s2s_transport_pipeline_stage_duration_us_total",
        labels.clone(),
        stage.duration_us() as f64,
    ));
    for (bucket, count) in stage.buckets() {
        let mut bucket_labels = labels.clone();
        bucket_labels.push(("bucket", bucket));
        out.push(sample(
            "shitspeak_s2s_transport_pipeline_stage_duration_us_bucket_total",
            bucket_labels,
            count as f64,
        ));
    }
}

fn add_transport_io_samples(
    out: &mut Vec<PrometheusSample>,
    local_node: &str,
    io: shitspeak_s2s_transport::TransportIoSnapshot,
) {
    let peer = io.peer().to_string();
    let transport = transport_kind_name(io.transport());
    let direction = io.direction().name();
    let labels = vec![
        ("source", local_node),
        ("peer", peer.as_str()),
        ("transport", transport),
        ("direction", direction),
    ];
    out.push(sample(
        "shitspeak_s2s_transport_io_batches_total",
        labels.clone(),
        io.batches() as f64,
    ));
    out.push(sample(
        "shitspeak_s2s_transport_io_bytes_total",
        labels.clone(),
        io.bytes() as f64,
    ));
    for (bucket, count) in io.batch_size_buckets() {
        let mut bucket_labels = labels.clone();
        bucket_labels.push(("bucket", bucket));
        out.push(sample(
            "shitspeak_s2s_transport_io_batch_size_bucket_total",
            bucket_labels,
            count as f64,
        ));
    }
    for (result, count) in io.pressure() {
        let mut pressure_labels = labels.clone();
        pressure_labels.push(("result", result.name()));
        out.push(sample(
            "shitspeak_s2s_transport_io_pressure_total",
            pressure_labels,
            count as f64,
        ));
    }
}

fn add_transport_io_frame_samples(
    out: &mut Vec<PrometheusSample>,
    local_node: &str,
    frames: shitspeak_s2s_transport::TransportIoFrameSnapshot,
) {
    let peer = frames.peer().to_string();
    out.push(sample(
        "shitspeak_s2s_transport_io_frames_total",
        vec![
            ("source", local_node),
            ("peer", peer.as_str()),
            ("transport", transport_kind_name(frames.transport())),
            ("direction", frames.direction().name()),
            ("class", message_class_name(frames.class())),
        ],
        frames.frames() as f64,
    ));
}

fn add_debug_packet_samples(
    out: &mut Vec<PrometheusSample>,
    packet: &crate::debug_io::PacketIoSnapshot,
) {
    #[derive(serde::Deserialize)]
    struct PacketView {
        source: u16,
        destination: u16,
        kind: String,
        sent_bytes: u64,
        recv_bytes: u64,
        sent_count: u64,
        send_attempt_count: u64,
        recv_count: u64,
        avg_sent_bps: f64,
        avg_recv_bps: f64,
    }

    let Ok(view) = serde_json::to_value(packet).and_then(serde_json::from_value::<PacketView>)
    else {
        return;
    };
    let source = view.source.to_string();
    let destination = view.destination.to_string();
    out.push(sample(
        "shitspeak_s2s_debug_packet_io_send_attempts_total",
        vec![
            ("source", source.as_str()),
            ("destination", destination.as_str()),
            ("packet_kind", view.kind.as_str()),
        ],
        view.send_attempt_count as f64,
    ));
    for (direction, bytes, count, avg_bps) in [
        ("sent", view.sent_bytes, view.sent_count, view.avg_sent_bps),
        ("recv", view.recv_bytes, view.recv_count, view.avg_recv_bps),
    ] {
        out.push(sample(
            "shitspeak_s2s_debug_packet_io_bytes_total",
            vec![
                ("source", source.as_str()),
                ("destination", destination.as_str()),
                ("packet_kind", view.kind.as_str()),
                ("direction", direction),
            ],
            bytes as f64,
        ));
        out.push(sample(
            "shitspeak_s2s_debug_packet_io_packets_total",
            vec![
                ("source", source.as_str()),
                ("destination", destination.as_str()),
                ("packet_kind", view.kind.as_str()),
                ("direction", direction),
            ],
            count as f64,
        ));
        out.push(sample(
            "shitspeak_s2s_debug_packet_io_avg_bps",
            vec![
                ("source", source.as_str()),
                ("destination", destination.as_str()),
                ("packet_kind", view.kind.as_str()),
                ("direction", direction),
            ],
            avg_bps,
        ));
    }
}

fn sample(name: &str, labels: Vec<(&str, &str)>, value: f64) -> PrometheusSample {
    PrometheusSample::new(
        name,
        labels
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
        value,
    )
}

fn sample_with_base(name: &str, labels: &[(&str, &str)], value: f64) -> PrometheusSample {
    sample(name, labels.to_vec(), value)
}

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn format_prometheus_value(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value == f64::INFINITY {
        "+Inf".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-Inf".to_owned()
    } else {
        value.to_string()
    }
}

fn escape_label_value(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
}

fn append_routes<'a>(
    out: &mut Vec<TopologyRoute>,
    transport: &ConnectionManager,
    metrics: &MetricsSnapshot,
    metric_kind: RoutingMetric,
    metric_name: &'static str,
    level: ServiceLevel,
    level_name: &'static str,
    iter: impl Iterator<Item = (&'a NodeIdentifier, &'a crate::overlay::RouteEntry)>,
) {
    for (dst, route) in iter {
        let kinds = route_transport_rows(transport, metrics, route.next_hop);
        let chosen = choose_route_transport(transport, route.next_hop, level, metric_kind);
        for kind in kinds {
            let transport_cost = metrics
                .for_node(route.next_hop)
                .and_then(|per_transport| per_transport.get(&kind))
                .and_then(|link| link.routing_cost(level, metric_kind))
                .map(|cost| cost.ceil().max(1.0) as u64);
            out.push(TopologyRoute {
                dst: *dst,
                metric: metric_name,
                level: level_name,
                next_hop: route.next_hop,
                transport: transport_kind_name(kind),
                service_fit: route_transport_fit(kind, chosen, level),
                cost: route.cost,
                transport_cost,
            });
        }
    }
}

fn route_transport_rows(
    transport: &ConnectionManager,
    metrics: &MetricsSnapshot,
    next_hop: NodeIdentifier,
) -> Vec<TransportKind> {
    let mut kinds = transport.live_transport_kinds(next_hop);
    if kinds.is_empty() {
        kinds.extend(
            metrics
                .for_node(next_hop)
                .into_iter()
                .flat_map(|per_transport| per_transport.keys().copied()),
        );
    }
    kinds.sort_by_key(|kind| transport_kind_name(*kind));
    kinds.dedup();
    kinds
}

fn choose_route_transport(
    transport: &ConnectionManager,
    next_hop: NodeIdentifier,
    level: ServiceLevel,
    metric: RoutingMetric,
) -> Option<TransportKind> {
    transport
        .ranked_live_transports_for(next_hop, level, metric)
        .into_iter()
        .next()
}

fn route_transport_fit(
    kind: TransportKind,
    chosen: Option<TransportKind>,
    level: ServiceLevel,
) -> &'static str {
    if !kind.is_acceptable_for(level) {
        "ineligible"
    } else if Some(kind) == chosen {
        "chosen"
    } else {
        "candidate"
    }
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

fn outbound_queue_transport_name(kind: Option<TransportKind>) -> &'static str {
    kind.map(transport_kind_name).unwrap_or("routed")
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
        MessageClass::Control => "control",
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
    .filter(|kind| mask & crate::overlay::config::transport_bit(*kind) != 0)
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
.wide-panel { grid-column: 1 / -1; }
#graph { width: 100%; height: min(62vh, 640px); min-height: 420px; background: #fbfcfe; }
.vis-network { outline: none; }
.vis-tooltip { position: absolute; visibility: hidden; padding: 8px 10px; max-width: 360px; color: var(--ink); background: #fff; border: 1px solid var(--line); border-radius: 6px; box-shadow: 0 8px 24px rgba(24, 32, 43, .12); font-size: 12px; line-height: 1.4; white-space: normal; }
.tables { display: grid; gap: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; background: #fafbfc; }
.pill { display: inline-block; min-width: 54px; padding: 2px 6px; border-radius: 999px; text-align: center; color: #fff; font-size: 11px; }
.chosen { background: var(--good); }
.candidate { background: var(--accent); }
.ineligible { background: var(--muted); }
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
    <div class="panel"><h2>Packet IO</h2><table><thead><tr><th>Path</th><th>Kind</th><th>Total</th><th>Sent</th><th>Recv</th><th>Count</th><th>Avg</th></tr></thead><tbody id="packet-io"></tbody></table></div>
    <div class="panel"><h2>S2S Queues</h2><table><thead><tr><th>Direction</th><th>Target</th><th>Depth</th><th>High</th><th>Capacity</th><th>Full</th></tr></thead><tbody id="queues"></tbody></table></div>
    <div class="panel"><h2>Direct Metrics</h2><table><thead><tr><th>Peer</th><th>Transport</th><th>RTT</th><th>Jitter</th><th>Loss</th><th>Payload Traffic</th><th>Wire Traffic</th><th>Compression</th></tr></thead><tbody id="metrics"></tbody></table></div>
  </section>
  <section class="panel wide-panel">
    <h2>Routes</h2>
    <table><thead><tr><th>Metric</th><th>Level</th><th>Dst</th><th>Next hop</th><th>Transport</th><th>Service fit</th><th>Route cost</th><th>Transport cost</th></tr></thead><tbody id="routes"></tbody></table>
  </section>
</main>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/10.0.2/dist/vis-network.min.js" integrity="sha512-5qYRU42HLweh0Ehlsu9bVWc13gwZviSNGsnfx+PqGRQRM4NltzGzb8dO3WY20CTsbkTBzhyKlso9cfYz2A5lOQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script>
const graph = document.getElementById('graph');
const meta = document.getElementById('meta');
const nodesTbody = document.getElementById('nodes');
const packetIoTbody = document.getElementById('packet-io');
const queuesTbody = document.getElementById('queues');
const metricsTbody = document.getElementById('metrics');
const routesTbody = document.getElementById('routes');
let network;
let graphNodes;
let graphEdges;
let currentLocalNode = null;
let graphTopologyKey = '';
function fmtUs(v) { return v ? (v / 1000).toFixed(1) + ' ms' : '-'; }
function fmtBytes(v) { if (!v) return '-'; const u = ['B','KB','MB','GB']; let i = 0; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return v.toFixed(i ? 1 : 0) + ' ' + u[i]; }
function fmtBps(v) { if (!v) return '-'; const u = ['B/s','KB/s','MB/s','GB/s']; let i = 0; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return v.toFixed(i ? 1 : 0) + ' ' + u[i]; }
function fmtLoss(v) { return v ? (v / 10000).toFixed(2) + '%' : '0%'; }
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function fmtPair(a, b) { return `recv ${fmtBps(a)}<br><span class="transport">sent ${fmtBps(b)}</span>`; }
function fmtCompressionRatio(v) {
    if (v === null || v === undefined || !Number.isFinite(Number(v)) || v <= 0) return '-';
    const factor = 1 / v;
    const savings = (1 - v) * 100;
    return `${factor.toFixed(factor >= 10 ? 1 : 2)}x / ${savings.toFixed(1)}%`;
}
function compressionCell(item) {
    if (item.compression_total_ratio === null || item.compression_total_ratio === undefined) return '-';
    return `${fmtCompressionRatio(item.compression_total_ratio)}<br><span class="transport">sent ${fmtCompressionRatio(item.compression_sent_ratio)} &middot; recv ${fmtCompressionRatio(item.compression_recv_ratio)}</span>`;
}
function lossBreakdown(item) {
    return `eff ${fmtLoss(item.loss_ppm ?? item.packet_loss_ppm)}<br><span class="transport">probe ${fmtLoss(item.probe_loss_ppm)} &middot; native ${fmtLoss(item.native_loss_ppm)} &middot; data ${fmtLoss(item.data_health_ppm)}</span>`;
}
function queueRows(data) {
  const outbound = (data.outbound_queues || []).map(q => ({
    direction: 'outgoing',
    target: `${q.peer} / ${esc(q.transport)}`,
    depth: q.depth,
    high: q.high_watermark,
    capacity: q.capacity,
    full: `${q.full_samples}/${q.samples}`
  }));
  const inbound = (data.inbound_queues || []).map(q => ({
    direction: 'incoming',
    target: esc(q.class),
    depth: q.depth,
    high: q.high_watermark,
    capacity: q.capacity,
    full: `${q.full_samples}/${q.samples}`
  }));
  return inbound.concat(outbound);
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
      `Strict replication protocol: v${esc(n.strict_replication_protocol_version ?? 0)}`,
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
        `Probe/native/data: ${fmtLoss(link.probe_loss_ppm)} / ${fmtLoss(link.native_loss_ppm)} / ${fmtLoss(link.data_health_ppm)}`,
        `Loss samples: ${esc(link.loss_sample_count)}`,
        `Throughput: ${fmtBps(link.throughput_bps)}`,
        `Observed recv/sent: ${fmtBps(link.observed_recv_bps)} / ${fmtBps(link.observed_sent_bps)}`,
        `Throughput confidence: ${fmtLoss(link.throughput_confidence_ppm)}`
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
  nodesTbody.innerHTML = data.nodes.map(n => `<tr><td>${n.node_id}</td><td><span class="pill ${n.status}">${n.status}</span></td><td>seq ${n.lsa_seq ?? '-'}<br>${n.lsa_age_ms ?? '-'} ms<br>strict v${n.strict_replication_protocol_version ?? 0}</td><td>${n.addresses.map(a => `<span class="transport">${esc(a.transport)}</span> ${esc(a.addr)}`).join('<br>')}</td></tr>`).join('');
  const packetRows = data.debug_packet_io || [];
  packetIoTbody.innerHTML = packetRows.length
    ? packetRows.map(p => `<tr><td>${p.source} -> ${p.destination}</td><td>${esc(p.kind)}</td><td>${fmtBytes(p.total_bytes)}</td><td>${fmtBytes(p.sent_bytes)}<br><span class="transport">${p.sent_count}</span></td><td>${fmtBytes(p.recv_bytes)}<br><span class="transport">${p.recv_count}</span></td><td>${p.total_count}</td><td>${fmtBps(p.avg_total_bps)}</td></tr>`).join('')
    : `<tr><td colspan="7" class="transport">-</td></tr>`;
  const queues = queueRows(data);
  queuesTbody.innerHTML = queues.length
    ? queues.map(q => `<tr><td>${esc(q.direction)}</td><td>${q.target}</td><td>${q.depth}</td><td>${q.high}</td><td>${q.capacity}</td><td>${q.full}</td></tr>`).join('')
    : `<tr><td colspan="6" class="transport">-</td></tr>`;
  metricsTbody.innerHTML = data.local_metrics.map(m => `<tr><td>${m.peer}</td><td>${esc(m.transport)}</td><td>${fmtUs(m.rtt_us)}</td><td>${fmtUs(m.jitter_us)}</td><td>${lossBreakdown(m)}<br><span class="transport">probe ${m.lost_probe_packets}/${m.probe_packets} &middot; unmatched ${m.unmatched_probe_pongs} &middot; native ${m.native_lost_samples}/${m.native_loss_samples} &middot; data ${m.data_health_failures}/${m.data_health_samples}</span></td><td>${fmtPair(m.recv_bps, m.sent_bps)}</td><td>${fmtPair(m.wire_recv_bps, m.wire_sent_bps)}</td><td>${compressionCell(m)}</td></tr>`).join('');
  routesTbody.innerHTML = data.routes.map(r => `<tr><td>${esc(r.metric)}</td><td>${esc(r.level)}</td><td>${r.dst}</td><td>${r.next_hop}</td><td>${esc(r.transport)}</td><td><span class="pill ${esc(r.service_fit)}">${esc(r.service_fit)}</span></td><td>${r.cost}</td><td>${r.transport_cost ?? '-'}</td></tr>`).join('');
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
    use shitspeak_core::NodeGeo;

    #[test]
    fn finds_http_header_end() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nx"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\n\n"), None);
    }

    #[test]
    fn transport_mask_names_are_stable() {
        let mask = crate::overlay::config::transport_bit(TransportKind::Tcp)
            | crate::overlay::config::transport_bit(TransportKind::Udp);
        assert_eq!(transport_names_from_mask(mask), vec!["tcp", "udp"]);
    }

    #[test]
    fn prometheus_exposition_escapes_labels_and_renders_topology_samples() {
        let snapshot = TopologySnapshot {
            local_node: 1,
            generated_at_unix_ms: 123,
            nodes: vec![
                TopologyNode {
                    node_id: 1,
                    status: "alive",
                    boot_epoch: 7,
                    max_users: 100,
                    addresses: Vec::new(),
                    geo: NodeGeo::new(
                        32.7767,
                        -96.7970,
                        Some("Dallas \"North\"\nWest\\".to_owned()),
                        Some("TX".to_owned()),
                        Some("US".to_owned()),
                        "manual",
                    ),
                    transit_enabled: true,
                    lsa_seq: Some(9),
                    lsa_age_ms: Some(10),
                    strict_replication_protocol_version: Some(2),
                },
                TopologyNode {
                    node_id: 2,
                    status: "alive",
                    boot_epoch: 8,
                    max_users: 100,
                    addresses: Vec::new(),
                    geo: NodeGeo::new(
                        29.7604,
                        -95.3698,
                        Some("Houston".to_owned()),
                        Some("TX".to_owned()),
                        Some("US".to_owned()),
                        "cloudflare",
                    ),
                    transit_enabled: true,
                    lsa_seq: Some(10),
                    lsa_age_ms: Some(20),
                    strict_replication_protocol_version: Some(0),
                },
            ],
            links: vec![
                TopologyLink {
                    source: 1,
                    target: 2,
                    status: "active",
                    rtt_us: 1_500,
                    jitter_us: 250,
                    throughput_bps: 50_000,
                    observed_recv_bps: 40_000,
                    observed_sent_bps: 45_000,
                    throughput_confidence_ppm: 750_000,
                    loss_ppm: 25_000,
                    probe_loss_ppm: 10_000,
                    native_loss_ppm: 40_000,
                    data_health_ppm: 5_000,
                    loss_sample_count: 12,
                    transports: vec!["tcp", "quic"],
                },
                TopologyLink {
                    source: 2,
                    target: 1,
                    status: "active",
                    rtt_us: 2_500,
                    jitter_us: 350,
                    throughput_bps: 60_000,
                    observed_recv_bps: 50_000,
                    observed_sent_bps: 55_000,
                    throughput_confidence_ppm: 650_000,
                    loss_ppm: 35_000,
                    probe_loss_ppm: 20_000,
                    native_loss_ppm: 50_000,
                    data_health_ppm: 6_000,
                    loss_sample_count: 13,
                    transports: vec!["tcp"],
                },
            ],
            routes: vec![TopologyRoute {
                dst: 3,
                metric: "conversational",
                level: "reliable",
                next_hop: 2,
                transport: "quic",
                service_fit: "chosen",
                cost: 42,
                transport_cost: Some(21),
            }],
            duplicate_nodes: vec![TopologyDuplicateNode {
                node: 4,
                observed_epochs: 2,
                conflict: true,
                quarantined: true,
                reason: "duplicate_boot_epoch",
                quarantine_age_ms: 50,
                quarantine_remaining_ms: 950,
                conflicts_total: 1,
                dropped_messages_total: vec![TopologyDuplicateDrop {
                    kind: "OverlayData",
                    count: 3,
                }],
            }],
            local_metrics: vec![TransportMetric {
                peer: 2,
                transport: "quic",
                rtt_us: 1_500.0,
                jitter_us: 250.0,
                recv_bps: 1_000.0,
                sent_bps: 2_000.0,
                wire_recv_bps: 1_100.0,
                wire_sent_bps: 2_100.0,
                compression_recv_ratio: Some(0.5),
                compression_sent_ratio: Some(0.75),
                compression_total_ratio: Some(0.6),
                packet_loss_ppm: 25_000,
                probe_loss_ppm: 10_000,
                probe_loss_ewma_ppm: 11_000,
                native_loss_ppm: 40_000,
                native_loss_ewma_ppm: 41_000,
                data_health_ppm: 5_000,
                loss_sample_count: 12,
                probe_packets: 100,
                lost_probe_packets: 1,
                unmatched_probe_pongs: 4,
                native_loss_samples: 50,
                native_lost_samples: 2,
                data_health_samples: 40,
                data_health_failures: 3,
                estimated_throughput_bps: 50_000.0,
                samples: 9,
                last_update_age_ms: Some(1234),
                kcp_runtime: None,
            }],
            outbound_queues: vec![OutboundQueueMetric {
                peer: 2,
                transport: "quic",
                depth: 3,
                high_watermark: 7,
                capacity: 8,
                samples: 11,
                full_samples: 2,
            }],
            inbound_queues: vec![InboundQueueMetric {
                class: "regular",
                depth: 4,
                high_watermark: 9,
                capacity: 10,
                samples: 12,
                full_samples: 3,
            }],
            expired_outbound_drops: vec![ExpiredOutboundDropMetric {
                peer: 2,
                stage: "transport_write",
                transport: "quic",
                class: "high_priority",
                frames: 5,
            }],
            transport_health_exclusions: vec![TransportHealthExclusionMetric {
                peer: 2,
                transport: "kcp",
                reason: "kcp_failaway",
                exclusions: 7,
            }],
            datagram_path_health: vec![DatagramPathHealthMetric {
                peer: 2,
                path: "quic_datagram",
                state: "suspect",
                reason: "measured_loss",
                effective_loss_ppm: Some(6_000),
                path_health_score_ppm: Some(125_000),
                loss_samples: 64,
                sample_confidence_ppm: 1_000_000,
                enqueue_accepted: 60,
                enqueue_rejected: 4,
                too_large: 2,
                pressure: 3,
                outcome_successes: 61,
                outcome_failures: 3,
                ingress_validated: 12,
                ingress_rejected: 1,
                ingress_read_failures: 0,
                consecutive_bad_windows: 3,
                recovery_healthy_age_ms: 0,
                recovery_required: true,
                transitions: 3,
                state_age_ms: 1_250,
                scored_generation: Some(7),
                diagnostic_generation: Some(8),
                observation_age_ms: 25,
                diagnostic_observation_age_ms: Some(10),
            }],
            delivery_path_selections: vec![DeliveryPathSelectionMetric {
                path: "quic_datagram",
                selections: 13,
            }],
            voice_transport_bindings: vec![VoiceTransportBindingMetric {
                peer: 2,
                transport: "quic",
            }],
            voice_transport_binding_events: vec![VoiceTransportBindingEventMetric {
                peer: 2,
                from_transport: "kcp",
                to_transport: "quic",
                reason: "confirmed_challenger",
                events: 3,
            }],
            voice_transport_challengers: vec![VoiceTransportChallengerMetric {
                peer: 2,
                incumbent: "kcp",
                challenger: "quic",
                outcome: "confirmed",
                events: 2,
            }],
            quic_lanes: vec![QuicLaneMetric {
                peer: Some(2),
                direction: "egress",
                lane: "datagram",
                frames: 11,
                bytes: 1_234,
            }],
            quic_datagram_drops: vec![QuicDatagramDropMetric {
                reason: "too_large",
                drops: 3,
            }],
            quic_protocol_events: vec![QuicProtocolEventMetric {
                stage: "setup",
                version: "s2s2",
                result: "success",
                events: 4,
            }],
            quic_protocol_errors: vec![QuicProtocolErrorMetric {
                reason: "class_mismatch",
                errors: 2,
            }],
            quic_sessions: vec![QuicSessionMetric {
                peer: 2,
                remote_addr: Some("127.0.0.1:64741".to_owned()),
                dialer: true,
                negotiated_protocol: "s2s/2",
                three_lane_ready: true,
                max_datagram_size: Some(1200),
                datagram_send_buffer_bytes: 65_536,
                datagram_receive_buffer_bytes: 262_144,
                datagrams_queued: 7,
                datagrams_received: 6,
                datagrams_dropped: 1,
            }],
            debug_packet_io: Vec::new(),
        };

        let mut rendered = String::new();
        PrometheusWriter::new(&mut rendered).render(&snapshot);

        let topology_json = serde_json::to_value(&snapshot).expect("topology JSON serializes");
        assert_eq!(
            topology_json["nodes"][0]["strict_replication_protocol_version"],
            2
        );
        assert_eq!(
            topology_json["nodes"][1]["strict_replication_protocol_version"],
            0
        );
        assert_eq!(topology_json["quic_lanes"][0]["lane"], "datagram");
        assert_eq!(
            topology_json["delivery_path_selections"][0]["path"],
            "quic_datagram"
        );
        assert_eq!(topology_json["datagram_path_health"][0]["state"], "suspect");
        assert_eq!(
            topology_json["datagram_path_health"][0]["observation_age_ms"],
            25
        );
        assert_eq!(
            topology_json["datagram_path_health"][0]["path_health_score_ppm"],
            125_000
        );
        assert_eq!(
            topology_json["datagram_path_health"][0]["sample_confidence_ppm"],
            1_000_000
        );
        assert_eq!(topology_json["datagram_path_health"][0]["pressure"], 3);
        assert_eq!(
            topology_json["datagram_path_health"][0]["scored_generation"],
            7
        );
        assert_eq!(
            topology_json["datagram_path_health"][0]["diagnostic_generation"],
            8
        );
        assert_eq!(
            topology_json["datagram_path_health"][0]["diagnostic_observation_age_ms"],
            10
        );
        assert_eq!(
            topology_json["datagram_path_health"][0]["recovery_required"],
            true
        );
        assert_eq!(
            topology_json["quic_sessions"][0]["negotiated_protocol"],
            "s2s/2"
        );
        assert_eq!(topology_json["quic_sessions"][0]["datagrams_queued"], 7);
        assert_eq!(
            topology_json["quic_datagram_drops"][0]["reason"],
            "too_large"
        );

        assert!(rendered.contains("# TYPE shitspeak_s2s_node_info gauge\n"));
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_node_strict_replication_protocol_version gauge\n")
        );
        assert!(
            rendered
                .contains("shitspeak_s2s_node_strict_replication_protocol_version{node=\"1\"} 2")
        );
        assert!(
            !rendered
                .contains("shitspeak_s2s_node_strict_replication_protocol_version{node=\"2\"}")
        );
        assert!(rendered.contains(
            "shitspeak_s2s_node_geo_latitude{node=\"1\",city=\"Dallas \\\"North\\\"\\nWest\\\\\",region=\"TX\",country=\"US\",source=\"manual\"} 32.7767"
        ));
        assert!(!rendered.contains("shitspeak_s2s_node_info{node=\"2\""));
        assert!(!rendered.contains("shitspeak_s2s_node_geo_latitude{node=\"2\",city=\"Houston\""));
        assert!(rendered.contains(
            "shitspeak_s2s_link_loss_breakdown_ppm{source=\"1\",target=\"2\",transport=\"tcp,quic\",metric=\"probe\"} 10000"
        ));
        assert!(!rendered.contains(
            "shitspeak_s2s_link_loss_breakdown_ppm{source=\"2\",target=\"1\",transport=\"tcp\",metric=\"probe\"}"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_link_health_ppm{source=\"1\",target=\"2\",transport=\"tcp,quic\",metric=\"data_health\"} 5000"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_direct_metric_unmatched_probe_pongs{source=\"1\",peer=\"2\",transport=\"quic\"} 4"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_route_service_fit{source=\"1\",target=\"3\",dst=\"3\",next_hop=\"2\",metric=\"conversational\",level=\"reliable\",transport=\"quic\",service_fit=\"chosen\"} 1"
        ));
        assert!(
            rendered.contains("shitspeak_s2s_duplicate_node_conflict{source=\"1\",node=\"4\"} 1")
        );
        assert!(rendered.contains(
            "shitspeak_s2s_node_quarantined{source=\"1\",node=\"4\",reason=\"duplicate_boot_epoch\"} 1"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_duplicate_node_dropped_messages_total{source=\"1\",node=\"4\",kind=\"OverlayData\"} 3"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_direct_metric_traffic_bps{source=\"1\",peer=\"2\",transport=\"quic\",direction=\"sent\"} 2000"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_outbound_queue_status{source=\"1\",peer=\"2\",transport=\"quic\",metric=\"high_watermark\"} 7"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_inbound_queue_status{source=\"1\",class=\"regular\",metric=\"full_samples\"} 3"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_queue_status{source=\"1\",direction=\"outgoing\",peer=\"2\",transport=\"quic\",class=\"\",metric=\"depth\"} 3"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_queue_status{source=\"1\",direction=\"incoming\",peer=\"\",transport=\"\",class=\"regular\",metric=\"high_watermark\"} 9"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_expired_outbound_frames_total{source=\"1\",peer=\"2\",stage=\"transport_write\",transport=\"quic\",class=\"high_priority\"} 5"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_transport_health_exclusions_total{source=\"1\",peer=\"2\",transport=\"kcp\",reason=\"kcp_failaway\"} 7"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_health{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 1"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_effective_loss_ppm{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 6000"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_health_observation_age_ms{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 25"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_scored_generation{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 7"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_diagnostic_generation{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 8"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_health_score_ppm{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 125000"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_pressure{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 3"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_datagram_path_recovery_required{source=\"1\",peer=\"2\",path=\"quic_datagram\",state=\"suspect\",reason=\"measured_loss\"} 1"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_delivery_path_selections_total{source=\"1\",path=\"quic_datagram\"} 13"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_voice_transport_binding{source=\"1\",peer=\"2\",transport=\"quic\"} 1"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_voice_transport_binding_events_total{source=\"1\",peer=\"2\",from_transport=\"kcp\",to_transport=\"quic\",reason=\"confirmed_challenger\"} 3"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_voice_transport_challenger_total{source=\"1\",peer=\"2\",incumbent=\"kcp\",challenger=\"quic\",outcome=\"confirmed\"} 2"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_quic_lane_frames_total{source=\"1\",peer=\"2\",direction=\"egress\",lane=\"datagram\"} 11"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_quic_lane_bytes_total{source=\"1\",peer=\"2\",direction=\"egress\",lane=\"datagram\"} 1234"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_quic_datagram_drops_total{source=\"1\",reason=\"too_large\"} 3"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_quic_protocol_events_total{source=\"1\",stage=\"setup\",version=\"s2s2\",result=\"success\"} 4"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_quic_protocol_errors_total{source=\"1\",reason=\"class_mismatch\"} 2"
        ));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_transport_binding gauge\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_delivery_path_selections_total counter\n"));
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_voice_transport_binding_events_total counter\n")
        );
        assert!(
            rendered.contains("# TYPE shitspeak_s2s_voice_transport_challenger_total counter\n")
        );
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_tree_edge_binding gauge\n"));
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_voice_tree_edge_binding_events_total counter\n")
        );
        assert!(rendered.contains("# TYPE shitspeak_s2s_transport_io_batches_total counter\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_transport_io_frames_total counter\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_send_events_total counter\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_receive_events_total counter\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_repair_events_total counter\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_repair_cache_occupancy gauge\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_repair_cache_capacity gauge\n"));
        assert!(
            rendered.contains("# TYPE shitspeak_s2s_voice_repair_cache_evictions_total counter\n")
        );
        assert!(
            rendered.contains("# TYPE shitspeak_s2s_voice_repair_credit_bytes_total counter\n")
        );
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_voice_repair_allocator_class_bytes_total counter\n"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_voice_repair_allocator_destination_bytes_total counter\n"
        ));
        assert!(
            rendered.contains("# TYPE shitspeak_s2s_voice_repair_allocator_state_bytes gauge\n")
        );
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_voice_reactive_scheduler_events_total counter\n")
        );
        assert!(
            rendered.contains("# TYPE shitspeak_s2s_voice_reactive_scheduler_queued_items gauge\n")
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_voice_reactive_scheduler_queued_encoded_bytes gauge\n"
        ));
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_voice_reactive_scheduler_active_destinations gauge\n"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_voice_reactive_scheduler_oldest_wait_microseconds gauge\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_voice_reactive_scheduler_max_starvation_rounds gauge\n"
        ));
        assert!(
            rendered.contains("# TYPE shitspeak_s2s_voice_ingress_admission_drops_total counter\n")
        );
        assert!(
            rendered.contains("# TYPE shitspeak_s2s_voice_ingress_queue_capacity_bytes gauge\n")
        );
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_reorder_speaker_states gauge\n"));
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_cluster_protocol_version gauge\n"
            )
        );
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_terminal_resolution_ready gauge\n"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_terminal_decisions_total counter\n"
        ));
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_strict_replication_admission_peer_states gauge\n")
        );
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_admission_highest_barrier gauge\n"
            )
        );
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_admission_awaiting_proofs gauge\n"
            )
        );
        assert!(rendered.contains("# TYPE shitspeak_s2s_strict_replication_clock_demand gauge\n"));
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_unacknowledged_head_peers gauge\n"
            )
        );
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_strict_replication_probe_events_total counter\n")
        );
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_admission_events_total counter\n"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_history_election_events_total counter\n"
        ));
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_strict_replication_head_events_total counter\n")
        );
        assert!(
            rendered
                .contains("# TYPE shitspeak_s2s_strict_replication_recovery_phase_topics gauge\n")
        );
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_recovery_progress_age_ms gauge\n"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_donor_sessions_active gauge\n"
        ));
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_recovery_attempts_total counter\n"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_coalesced_triggers_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_retransmits_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_donor_switches_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_certificate_failures_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_stale_events_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_completion_duration_ms_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_recovery_completion_duration_count counter\n"
        ));
        assert!(
            rendered.contains(
                "shitspeak_s2s_strict_replication_recovery_phase_topics{phase=\"healthy\"}"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_session_starts_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_session_completions_total counter\n"
        ));
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_catchup_sessions_active gauge\n"
            )
        );
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_session_events_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_send_attempts_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_send_bytes_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_duplicate_pages_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_snapshot_receive_events_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_snapshot_responder_events_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_backpressure_events_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_backoff_delay_ms_total counter\n"
        ));
        assert!(rendered.contains(
            "# TYPE shitspeak_s2s_strict_replication_catchup_bulk_in_flight_bytes gauge\n"
        ));
        assert!(
            rendered.contains(
                "# TYPE shitspeak_s2s_strict_replication_catchup_throttled_total counter\n"
            )
        );
        assert!(rendered.contains(
            "shitspeak_s2s_replication_catchup_requests_total{mode=\"strict\",reason=\"legacy_v2\",phase=\"metadata\"}"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_strict_replication_catchup_sessions_active{reason=\"delivery_watermark\"}"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_strict_replication_catchup_duplicate_pages_total{outcome=\"cached_replay\"}"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_strict_replication_snapshot_receive_events_total{event=\"stale_foreign_transfer\"}"
        ));
        assert!(rendered.contains(
            "shitspeak_s2s_strict_replication_snapshot_responder_events_total{event=\"completion_acknowledged\"}"
        ));
        assert!(
            rendered.contains("shitspeak_s2s_strict_replication_clock_demand{reason=\"head_ack\"}")
        );
        assert!(rendered.contains(
            "shitspeak_s2s_strict_replication_head_events_total{event=\"evidence_terminal_digest_mismatch\"}"
        ));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_deadline_wakes_total counter\n"));
        assert!(rendered.contains("# TYPE shitspeak_s2s_voice_proactive_events_total counter\n"));
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
        assert!(STATUS_HTML.contains("Packet IO"));
        assert!(STATUS_HTML.contains("debug_packet_io"));
        assert!(STATUS_HTML.contains("S2S Queues"));
        assert!(STATUS_HTML.contains("outbound_queues"));
        assert!(STATUS_HTML.contains("inbound_queues"));
        assert!(STATUS_HTML.contains("Compression"));
        assert!(STATUS_HTML.contains("compression_total_ratio"));
        assert!(STATUS_HTML.contains("network.setOptions({ physics: false })"));
        assert!(STATUS_HTML.contains("Service fit"));
        assert!(STATUS_HTML.contains("wide-panel"));
        assert!(STATUS_HTML.contains("transport_cost"));
    }
}
