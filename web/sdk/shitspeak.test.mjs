import assert from "node:assert/strict";
import { ShitSpeakClient } from "./shitspeak.js";

const originals = {
  WebSocket: globalThis.WebSocket,
  RTCPeerConnection: globalThis.RTCPeerConnection,
  MediaStream: globalThis.MediaStream,
};

class FakeWebSocket extends EventTarget {
  static OPEN = 1;
  static instances = [];

  constructor(url) {
    super();
    this.url = url;
    this.readyState = FakeWebSocket.OPEN;
    this.sent = [];
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => this.dispatchEvent(new Event("open")));
  }

  send(payload) {
    this.sent.push(JSON.parse(payload));
  }

  close() {
    this.readyState = 3;
    this.dispatchEvent(new Event("close"));
  }

  serverEvent(event) {
    this.dispatchEvent(
      new MessageEvent("message", {
        data: JSON.stringify(event),
      }),
    );
  }
}

class FakeDataChannel extends EventTarget {
  constructor(label, init) {
    super();
    this.label = label;
    this.ordered = init?.ordered ?? false;
    this.readyState = "connecting";
    this.sent = [];
  }

  send(payload) {
    this.sent.push(JSON.parse(payload));
  }

  close() {
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }

  open() {
    this.readyState = "open";
    this.dispatchEvent(new Event("open"));
  }

  serverEvent(event) {
    this.dispatchEvent(
      new MessageEvent("message", {
        data: JSON.stringify(event),
      }),
    );
  }
}

class FakeRTCPeerConnection extends EventTarget {
  static instances = [];

  constructor(config) {
    super();
    this.config = config;
    this.transceivers = [];
    this.dataChannels = [];
    this.localDescriptions = [];
    this.remoteDescriptions = [];
    this.iceCandidates = [];
    this.iceConnectionState = "new";
    FakeRTCPeerConnection.instances.push(this);
  }

  createDataChannel(label, init) {
    const channel = new FakeDataChannel(label, init);
    this.dataChannels.push(channel);
    return channel;
  }

  addTransceiver(trackOrKind, init) {
    const transceiver = { trackOrKind, init };
    this.transceivers.push(transceiver);
    return transceiver;
  }

  async createOffer() {
    return { type: "offer", sdp: "v=0\r\n" };
  }

  async setLocalDescription(description) {
    this.localDescriptions.push(description);
    this.localDescription = description;
  }

  async setRemoteDescription(description) {
    this.remoteDescriptions.push(description);
    this.remoteDescription = description;
  }

  async addIceCandidate(candidate) {
    this.iceCandidates.push(candidate);
  }

  close() {
    this.closed = true;
  }

  emitCandidate(candidate) {
    const event = new Event("icecandidate");
    event.candidate = candidate;
    this.dispatchEvent(event);
  }

  emitTrack(track) {
    const event = new Event("track");
    event.track = track;
    event.streams = [];
    this.dispatchEvent(event);
  }
}

class FakeMediaStream {
  constructor() {
    this.tracks = [];
  }

  addTrack(track) {
    this.tracks.push(track);
  }

  getTracks() {
    return this.tracks;
  }
}

function installFakes() {
  FakeWebSocket.instances = [];
  FakeRTCPeerConnection.instances = [];
  globalThis.WebSocket = FakeWebSocket;
  globalThis.RTCPeerConnection = FakeRTCPeerConnection;
  globalThis.MediaStream = FakeMediaStream;
}

function restoreGlobals() {
  for (const [name, value] of Object.entries(originals)) {
    if (value === undefined) {
      delete globalThis[name];
    } else {
      globalThis[name] = value;
    }
  }
}

async function openWithGatewayConfig(client, event = {
  type: "gateway_config",
  max_speaker_slots: 5,
  audio_bitrate: 64_000,
}) {
  const opened = client.openSignaling();
  await new Promise((resolve) => setTimeout(resolve, 0));
  const socket = FakeWebSocket.instances.at(-1);
  socket.serverEvent(event);
  await opened;
  return socket;
}

async function testGatewayConfigCapsSpeakerSlotsAndOffer() {
  installFakes();
  const client = new ShitSpeakClient({
    signalingUrl: "ws://gateway.test/web/signaling",
    maxSpeakerSlots: 12,
  });
  const socket = await openWithGatewayConfig(client, {
    type: "gateway_config",
    max_speaker_slots: 3,
    audio_bitrate: 32_000,
  });

  assert.equal(client.maxSpeakerSlots, 3);
  assert.equal(client.gatewayConfig.audio_bitrate, 32_000);

  await client.createAndSendOffer();
  const peer = FakeRTCPeerConnection.instances.at(-1);
  assert.equal(peer.config.bundlePolicy, "max-bundle");
  assert.equal(peer.transceivers.length, 3);
  assert.deepEqual(
    peer.transceivers.map((entry) => entry.init.direction),
    ["recvonly", "recvonly", "recvonly"],
  );
  assert.equal(peer.dataChannels[0].label, "shitspeak-control");
  assert.equal(peer.dataChannels[0].ordered, true);
  assert.deepEqual(socket.sent.at(-1), {
    type: "offer",
    sdp: "v=0\r\n",
    speaker_slots: 3,
  });
}

async function testCommandsFallbackThenUseControlChannel() {
  installFakes();
  const client = new ShitSpeakClient({ signalingUrl: "ws://gateway.test/web/signaling" });
  const socket = await openWithGatewayConfig(client);
  await client.ensurePeer();

  client.joinChannel(7);
  assert.deepEqual(socket.sent.at(-1), {
    type: "join_channel",
    channel_id: 7,
  });

  client.control.open();
  client.setMute(true);
  assert.deepEqual(client.control.sent.at(-1), {
    type: "set_mute",
    muted: true,
  });
  assert.notDeepEqual(socket.sent.at(-1), {
    type: "set_mute",
    muted: true,
  });
}

async function testPushToTalkTargetEncodingAndEpochs() {
  installFakes();
  const client = new ShitSpeakClient({ signalingUrl: "ws://gateway.test/web/signaling" });
  await openWithGatewayConfig(client);
  await client.ensurePeer();
  client.control.open();

  assert.equal(client.setPushToTalk(true, 4), 1);
  assert.deepEqual(client.control.sent.at(-1), {
    type: "voice_control",
    ptt: true,
    target: { slot: 4 },
    epoch: 1,
  });

  assert.equal(client.setPushToTalk(false, "server_loopback"), 2);
  assert.deepEqual(client.control.sent.at(-1), {
    type: "voice_control",
    ptt: false,
    target: "server_loopback",
    epoch: 2,
  });
}

async function testStateCacheAndMetadataEvents() {
  installFakes();
  const client = new ShitSpeakClient({ signalingUrl: "ws://gateway.test/web/signaling" });
  await openWithGatewayConfig(client);
  await client.ensurePeer();

  const seen = [];
  client.addEventListener("event", (event) => seen.push(event.detail.type));
  client.handleServerEvent({
    type: "user_state",
    session: 2,
    name: "Alice",
    channel_id: 0,
  });
  client.handleServerEvent({
    type: "user_state",
    session: 2,
    self_mute: true,
  });
  assert.deepEqual(client.users.get(2), {
    type: "user_state",
    session: 2,
    name: "Alice",
    channel_id: 0,
    self_mute: true,
  });

  client.handleServerEvent({
    type: "channel_state",
    channel_id: 1,
    name: "Lobby",
    links: [2],
  });
  client.handleServerEvent({
    type: "channel_state",
    channel_id: 1,
    links_add: [3],
    links_remove: [2],
  });
  assert.deepEqual(client.channels.get(1).links, [3]);

  client.handleServerEvent({
    type: "speaker_assigned",
    ssrc: 123,
    speaker_session: 2,
    track_id: "speaker-slot-0",
    epoch: 9,
  });
  assert.equal(client.speakers.get(123).speaker_session, 2);

  client.handleServerEvent({
    type: "voice_segment_end",
    ssrc: 123,
    speaker_session: 2,
    context: "normal",
    channel_id: 1,
    rtp_timestamp: 42,
    epoch: 9,
  });
  assert.equal(client.speakers.has(123), false);
  assert.deepEqual(seen.slice(0, 2), ["user_state", "user_state"]);
}

async function testSignalAndTrackHandling() {
  installFakes();
  const client = new ShitSpeakClient({ signalingUrl: "ws://gateway.test/web/signaling" });
  await openWithGatewayConfig(client);
  await client.ensurePeer();
  const peer = FakeRTCPeerConnection.instances.at(-1);

  await client.handleSignal(
    new MessageEvent("message", {
      data: JSON.stringify({ type: "answer", sdp: "v=0\r\nanswer" }),
    }),
  );
  assert.deepEqual(peer.remoteDescriptions.at(-1), {
    type: "answer",
    sdp: "v=0\r\nanswer",
  });

  await client.handleSignal(
    new MessageEvent("message", {
      data: JSON.stringify({ type: "ice_candidate", candidate: { candidate: "candidate:1" } }),
    }),
  );
  assert.deepEqual(peer.iceCandidates.at(-1), { candidate: "candidate:1" });

  const tracks = [];
  client.addEventListener("track", (event) => tracks.push(event.detail));
  peer.emitTrack("remote-audio");
  assert.deepEqual(client.remoteStream.tracks, ["remote-audio"]);
  assert.equal(tracks[0].track, "remote-audio");
  assert.equal(tracks[0].stream, client.remoteStream);
}

const tests = [
  testGatewayConfigCapsSpeakerSlotsAndOffer,
  testCommandsFallbackThenUseControlChannel,
  testPushToTalkTargetEncodingAndEpochs,
  testStateCacheAndMetadataEvents,
  testSignalAndTrackHandling,
];

try {
  for (const test of tests) {
    await test();
    console.log(`ok ${test.name}`);
  }
} finally {
  restoreGlobals();
}
