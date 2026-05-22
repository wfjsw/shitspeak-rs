# Voice Allocation/Copy Review (2026-05-17)

Traced voice path:
- TCP UDPTunnel: message reader reads payload into BytesMut and freezes to Bytes, handler decodes Audio, then Client::push_voice_routing sends owned Audio through per-client routing mpsc.
- UDP: Server::spawn_udp_drain receives datagrams, Server::spawn_udp_process decrypts and decodes IncomingUdpPacket, then pushes owned Audio through the same routing mpsc.
- Routing: spawn_voice_routing_task calls route_voice(&Audio); route_voice resolves targets and flush_voice_batch encodes once per (PacketFormat, AudioContext) in EncodeCache, then per-recipient encrypts and batches UDP datagrams or enqueues shared Bytes for TCP tunnel.

Implemented low-risk copy reduction:
- src/server.rs::spawn_udp_drain now uses BytesMut::with_capacity(MTU) and tokio::net::UdpSocket::recv_buf_from.
- The received buffer is handed to the UDP processing channel with buf.split().freeze(), replacing the prior Bytes::copy_from_slice(&buf[..len]) copy from a reusable Vec.
- Ping decode now reads from &buf before the buffer is split/frozen.

Arena/reference conclusion:
- Passing references through mpsc is not a good fit for the drain->process or routing channels because packets outlive the receive loop iteration/task frame. Borrowed packet refs would require scoped tasks or self-referential queue ownership and would complicate backpressure/drop semantics.
- An MTU-sized arena/ring could be useful only if it owns slots across channel boundaries with ref-counted guards, but that is essentially a bespoke Bytes pool. It risks slot exhaustion under the existing bounded UDP queue and adds complexity versus BytesMut/Bytes ownership.
- The current best tradeoff is owned Bytes/BytesMut: receive directly into MTU-sized BytesMut, freeze once for cross-task ownership, decode Audio with Bytes-backed frame slices, then share encoded Bytes across TCP fallback recipients. Further gains should focus on buffer reuse/pooling for per-recipient encrypted UDP outputs if benchmarking shows allocator pressure.

Validation:
- cargo fmt
- cargo check (passes; Windows incremental compilation finalization warning: Access is denied)
- cargo test voice_udp -- --nocapture --test-threads=1 (5 passed; same Windows incremental warning)

Dirty worktree note: many existing .serena memories and project.yml changes were already present; do not treat them as part of this implementation except this memory file if persisted by Serena.