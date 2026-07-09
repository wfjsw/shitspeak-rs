import assert from "node:assert/strict";
import { ShitSpeakClient } from "./shitspeak.js";

const originals = {
  WebSocket: globalThis.WebSocket,
  RTCPeerConnection: globalThis.RTCPeerConnection,
  MediaStream: globalThis.MediaStream,
  WebTransport: globalThis.WebTransport,
  AudioEncoder: globalThis.AudioEncoder,
  AudioDecoder: globalThis.AudioDecoder,
  EncodedAudioChunk: globalThis.EncodedAudioChunk,
  AudioContext: globalThis.AudioContext,
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
  constructor(tracks = []) {
    this.tracks = [...tracks];
  }

  addTrack(track) {
    this.tracks.push(track);
  }

  getTracks() {
    return this.tracks;
  }

  getAudioTracks() {
    return this.tracks.filter((track) => track.kind === "audio");
  }
}

class FakeMoqAdapter extends EventTarget {
  constructor(options) {
    super();
    this.options = options;
    this.sent = [];
    this.connected = false;
  }

  async connect() {
    this.connected = true;
    this.dispatchEvent(new CustomEvent("status", { detail: "connected" }));
  }

  sendCommand(command) {
    this.sent.push(command);
    if (command.type === "authenticate") {
      queueMicrotask(() => {
        this.dispatchEvent(
          new CustomEvent("event", {
            detail: { type: "authenticated", session: 9, display_name: "MoQ User" },
          }),
        );
      });
    }
  }

  async useMicrophone() {
    return new FakeMediaStream();
  }

  serverEvent(event) {
    this.dispatchEvent(new CustomEvent("event", { detail: event }));
  }
}

class FakeMoqTrack {
  constructor(name) {
    this.name = name;
    this.frames = [];
    this.readFrames = [];
    this.readResolvers = [];
    this.closed = false;
  }

  writeFrame(frame) {
    this.frames.push(frame);
  }

  writeString(value) {
    this.writeFrame(new TextEncoder().encode(value));
  }

  async readFrame() {
    if (this.readFrames.length > 0) {
      return this.readFrames.shift();
    }
    if (this.closed) {
      return undefined;
    }
    return new Promise((resolve) => this.readResolvers.push(resolve));
  }

  pushFrame(frame) {
    const resolve = this.readResolvers.shift();
    if (resolve) {
      resolve(frame);
      return;
    }
    this.readFrames.push(frame);
  }

  close() {
    this.closed = true;
    while (this.readResolvers.length > 0) {
      this.readResolvers.shift()(undefined);
    }
  }
}

class FakeEncodedAudioChunk {
  constructor(init) {
    this.type = init.type;
    this.timestamp = init.timestamp;
    this.data = init.data;
  }
}

class FakeAudioData {
  constructor({ numberOfFrames = 960, sampleRate = 48_000, numberOfChannels = 1 } = {}) {
    this.numberOfFrames = numberOfFrames;
    this.sampleRate = sampleRate;
    this.numberOfChannels = numberOfChannels;
    this.closed = false;
  }

  copyTo(destination) {
    destination.fill(0);
  }

  close() {
    this.closed = true;
  }
}

class FakeAudioDecoder {
  constructor({ output, error }) {
    this.output = output;
    this.error = error;
    this.closed = false;
  }

  configure(config) {
    this.config = config;
  }

  decode(_chunk) {
    queueMicrotask(() => {
      if (!this.closed) {
        this.output(new FakeAudioData());
      }
    });
  }

  close() {
    this.closed = true;
  }
}

class FakeAudioContext {
  static instances = [];

  constructor(config) {
    this.config = config;
    this.currentTime = 0;
    this.state = "running";
    this.scheduledStarts = [];
    FakeAudioContext.instances.push(this);
  }

  createMediaStreamDestination() {
    return {
      stream: new FakeMediaStream([{ kind: "audio", id: "moq-output" }]),
    };
  }

  createBuffer(_channels, frames, sampleRate) {
    return {
      duration: frames / sampleRate,
      getChannelData: () => new Float32Array(frames),
    };
  }

  createBufferSource() {
    return {
      buffer: null,
      connect: () => {},
      start: (time) => this.scheduledStarts.push(time),
    };
  }

  async resume() {}

  async close() {}
}

class FakeMoqBroadcast {
  constructor() {
    this.requests = [];
    this.subscribed = [];
  }

  subscribe(name, priority) {
    const track = new FakeMoqTrack(name);
    this.subscribed.push({ name, priority, track });
    return track;
  }

  request(name, priority = 0) {
    const track = new FakeMoqTrack(name);
    this.requests.push({ track, priority });
  }

  async requested() {
    return this.requests.shift();
  }

  close() {
    this.closed = true;
  }
}

class FakeMoqConnection {
  constructor(url) {
    this.url = url;
    this.published = [];
    this.consumed = [];
    this.closed = new Promise(() => {});
  }

  publish(path, broadcast) {
    this.published.push({ path, broadcast });
    broadcast.request("control/up");
    broadcast.request("audio/up/mic");
  }

  consume(path) {
    this.consumed.push(path);
    this.downstream = new FakeMoqBroadcast();
    return this.downstream;
  }

  close() {
    this.closeCalled = true;
  }
}

function fakeMoqModules(connections) {
  const Moq = {
    Broadcast: FakeMoqBroadcast,
    Path: {
      from: (...parts) => parts.join("/").replace(/^\/+|\/+$/g, ""),
    },
    Connection: {
      connect: async (url) => {
        const connection = new FakeMoqConnection(url);
        connections.push(connection);
        return connection;
      },
    },
    Varint: {
      encode: (value) => {
        if (value <= 0x3f) return Uint8Array.of(value);
        if (value <= 0x3fff) {
          const out = new Uint8Array(2);
          new DataView(out.buffer).setUint16(0, value | 0x4000);
          return out;
        }
        const out = new Uint8Array(4);
        new DataView(out.buffer).setUint32(0, value | 0x80000000);
        return out;
      },
      decode: (frame) => {
        const size = 1 << ((frame[0] & 0xc0) >> 6);
        const view = new DataView(frame.buffer, frame.byteOffset, size);
        let value;
        if (size === 1) value = frame[0] & 0x3f;
        else if (size === 2) value = view.getUint16(0) & 0x3fff;
        else value = view.getUint32(0) & 0x3fffffff;
        return [value, frame.subarray(size)];
      },
    },
  };
  const Hang = {
    Catalog: {
      fetch: async () => ({
        audio: {
          renditions: {
            "audio/down/slot/0": {
              codec: "opus",
              container: { kind: "legacy" },
              sampleRate: 48000,
              numberOfChannels: 1,
            },
          },
        },
      }),
    },
    Container: {
      Legacy: {
        Format: class {
          decode(frame) {
            const [timestamp, payload] = Moq.Varint.decode(frame);
            return [{ data: payload, timestamp, keyframe: false }];
          }
        },
      },
    },
  };
  return { Moq, Hang };
}

function installFakes() {
  FakeWebSocket.instances = [];
  FakeRTCPeerConnection.instances = [];
  FakeAudioContext.instances = [];
  globalThis.WebSocket = FakeWebSocket;
  globalThis.RTCPeerConnection = FakeRTCPeerConnection;
  globalThis.MediaStream = FakeMediaStream;
  globalThis.WebTransport = class FakeWebTransport {};
}

function installAudioFakes() {
  globalThis.AudioDecoder = FakeAudioDecoder;
  globalThis.EncodedAudioChunk = FakeEncodedAudioChunk;
  globalThis.AudioContext = FakeAudioContext;
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

async function testMoqTransportDoesNotCreatePeerConnection() {
  installFakes();
  let adapter = null;
  const client = new ShitSpeakClient({
    signalingUrl: "ws://gateway.test/web/signaling",
    transport: "moq",
    moqUrl: "https://gateway.test/web/moq",
    moqAdapterFactory: (options) => {
      adapter = new FakeMoqAdapter(options);
      return adapter;
    },
  });

  await client.connectWithPassword("user", "secret", { microphone: true });

  assert.equal(client.selectedTransport, "moq");
  assert.equal(client.moqStatus, "connected");
  assert.equal(adapter.connected, true);
  assert.equal(FakeRTCPeerConnection.instances.length, 0);
  assert.deepEqual(adapter.sent[0], {
    type: "authenticate",
    auth: { password: { username: "user", password: "secret" } },
  });
  assert.equal(client.localStream instanceof FakeMediaStream, true);
}

async function testAutoSelectsMoqWhenGatewayAdvertisesOnlyMoq() {
  installFakes();
  let adapter = null;
  const client = new ShitSpeakClient({
    signalingUrl: "ws://gateway.test/web/signaling",
    moqAdapterFactory: (options) => {
      adapter = new FakeMoqAdapter(options);
      return adapter;
    },
  });
  const connecting = client.connectWithPassword("user", "secret");
  await new Promise((resolve) => setTimeout(resolve, 0));
  const socket = FakeWebSocket.instances.at(-1);
  socket.serverEvent({
    type: "gateway_config",
    max_speaker_slots: 8,
    audio_bitrate: 64_000,
    transports: ["moq"],
    moq: {
      url: "https://gateway.test/web/moq",
      max_speaker_tracks: 8,
      audio_bitrate: 64_000,
    },
  });
  await connecting;

  assert.equal(client.selectedTransport, "moq");
  assert.equal(adapter.options.url, "https://gateway.test/web/moq");
  assert.equal(FakeRTCPeerConnection.instances.length, 0);
}

async function testDefaultMoqAdapterPublishesControlAndAudioTracks() {
  installFakes();
  const connections = [];
  const modules = fakeMoqModules(connections);
  const client = new ShitSpeakClient({
    signalingUrl: "ws://gateway.test/web/signaling",
    transport: "moq",
    moqUrl: "https://gateway.test/web/moq",
    maxSpeakerSlots: 2,
    moqLiteModule: modules.Moq,
    moqHangModule: modules.Hang,
  });

  await client.connect();
  client.sendCommand({ type: "join_channel", channel_id: 4 });
  adapterServerEvent(client, { type: "voice_control_ack", epoch: client.setPushToTalk(true) });
  client.setPushToTalk(false);

  const connection = connections[0];
  assert.equal(connection.published[0].path, "web/moq");
  assert.deepEqual(
    connection.downstream.subscribed.map((entry) => entry.name),
    ["control/down", "catalog.json", "audio/down/slot/0", "audio/down/slot/1"],
  );

  const controlUp = client.moq.controlUp;
  const audioUp = client.moq.audioUp;
  assert.deepEqual(JSON.parse(new TextDecoder().decode(controlUp.frames[0])), {
    type: "join_channel",
    channel_id: 4,
  });
  assert.equal(audioUp.frames.at(-1)[0], 0x53);
  assert.equal(audioUp.frames.at(-1)[1], 0x53);
  assert.equal(audioUp.frames.at(-1)[2], 0x4d);
  assert.equal(audioUp.frames.at(-1)[3], 0x41);
  assert.equal(audioUp.frames.at(-1)[5] & 0x01, 0x01);
}

async function testMoqPlaybackUsesIndependentSlotClocks() {
  installFakes();
  installAudioFakes();
  const connections = [];
  const modules = fakeMoqModules(connections);
  const client = new ShitSpeakClient({
    signalingUrl: "ws://gateway.test/web/signaling",
    transport: "moq",
    moqUrl: "https://gateway.test/web/moq",
    maxSpeakerSlots: 2,
    moqLiteModule: modules.Moq,
    moqHangModule: modules.Hang,
  });

  await client.connect();
  moqDownTrack(connections[0], "audio/down/slot/0").pushFrame(makeHangAudioFrame(modules, 0));
  moqDownTrack(connections[0], "audio/down/slot/1").pushFrame(makeHangAudioFrame(modules, 0));

  await waitFor(() => FakeAudioContext.instances[0]?.scheduledStarts.length === 2);
  assert.deepEqual(FakeAudioContext.instances[0].scheduledStarts, [0.08, 0.08]);
  client.close();
}

async function testMoqPlaybackKeepsFramesContiguousAfterSmallJitter() {
  installFakes();
  installAudioFakes();
  const connections = [];
  const modules = fakeMoqModules(connections);
  const client = new ShitSpeakClient({
    signalingUrl: "ws://gateway.test/web/signaling",
    transport: "moq",
    moqUrl: "https://gateway.test/web/moq",
    maxSpeakerSlots: 1,
    moqLiteModule: modules.Moq,
    moqHangModule: modules.Hang,
  });

  await client.connect();
  const slot = moqDownTrack(connections[0], "audio/down/slot/0");
  slot.pushFrame(makeHangAudioFrame(modules, 0));
  await waitFor(() => FakeAudioContext.instances[0]?.scheduledStarts.length === 1);
  const context = FakeAudioContext.instances[0];
  context.currentTime = 0.021;

  slot.pushFrame(makeHangAudioFrame(modules, 960));

  await waitFor(() => context.scheduledStarts.length === 2);
  assert.deepEqual(context.scheduledStarts, [0.08, 0.1]);
  client.close();
}

function adapterServerEvent(client, event) {
  if (typeof client.moq?.handleServerEvent === "function") {
    client.moq.handleServerEvent(event);
    return;
  }
  client.moq.dispatchEvent(new CustomEvent("event", { detail: event }));
}

function moqDownTrack(connection, name) {
  return connection.downstream.subscribed.find((entry) => entry.name === name).track;
}

function makeHangAudioFrame(modules, timestamp, payloadText = "opus") {
  const timestampBytes = modules.Moq.Varint.encode(timestamp);
  const payload = new TextEncoder().encode(payloadText);
  const frame = new Uint8Array(timestampBytes.byteLength + payload.byteLength);
  frame.set(timestampBytes, 0);
  frame.set(payload, timestampBytes.byteLength);
  return frame;
}

async function waitFor(predicate) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  assert.fail("condition was not met");
}

const tests = [
  testGatewayConfigCapsSpeakerSlotsAndOffer,
  testCommandsFallbackThenUseControlChannel,
  testPushToTalkTargetEncodingAndEpochs,
  testStateCacheAndMetadataEvents,
  testSignalAndTrackHandling,
  testMoqTransportDoesNotCreatePeerConnection,
  testAutoSelectsMoqWhenGatewayAdvertisesOnlyMoq,
  testDefaultMoqAdapterPublishesControlAndAudioTracks,
  testMoqPlaybackUsesIndependentSlotClocks,
  testMoqPlaybackKeepsFramesContiguousAfterSmallJitter,
];

try {
  for (const test of tests) {
    await test();
    console.log(`ok ${test.name}`);
  }
} finally {
  restoreGlobals();
}
