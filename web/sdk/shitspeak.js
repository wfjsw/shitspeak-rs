const DEFAULT_CONTROL_LABEL = "shitspeak-control";
const MOQ_BROADCAST_PATH = "web/moq";
const MOQ_CATALOG_TRACK = "catalog.json";
const MOQ_CONTROL_UP_TRACK = "control/up";
const MOQ_CONTROL_DOWN_TRACK = "control/down";
const MOQ_AUDIO_UP_MIC_TRACK = "audio/up/mic";
const MOQ_AUDIO_DOWN_SLOT_PREFIX = "audio/down/slot/";
const MOQ_AUDIO_MAGIC = new Uint8Array([0x53, 0x53, 0x4d, 0x41]); // SSMA
const MOQ_AUDIO_VERSION = 1;
const MOQ_AUDIO_TERMINATOR = 0x01;
const OPUS_SAMPLE_RATE = 48_000;
const OPUS_CHANNELS = 1;
const OPUS_RTP_TICKS_PER_20MS = 960;
const MOQ_PLAYBACK_LEAD_SECONDS = 0.08;
const MOQ_PLAYBACK_UNDERRUN_GRACE_SECONDS = 0.005;
const MOQ_PLAYBACK_MAX_LEAD_SECONDS = 0.5;
const DEFAULT_MOQ_AUDIO_BITRATE = 64_000;
const DEFAULT_MOQ_LITE_MODULE_URL = "https://esm.sh/@moq/lite@0.2.3?bundle";
const DEFAULT_MOQ_HANG_MODULE_URL = "https://esm.sh/@moq/hang@0.2.5?bundle";

export class ShitSpeakClient extends EventTarget {
  constructor(options) {
    super();
    this.signalingUrl = options.signalingUrl;
    this.transport = normalizeTransport(options.transport ?? "auto");
    this.selectedTransport = null;
    this.moqUrl = options.moqUrl ?? null;
    this.moqAdapterFactory = options.moqAdapterFactory ?? null;
    this.moqLiteModule = options.moqLiteModule ?? null;
    this.moqHangModule = options.moqHangModule ?? null;
    this.moqLiteModuleUrl = options.moqLiteModuleUrl ?? DEFAULT_MOQ_LITE_MODULE_URL;
    this.moqHangModuleUrl = options.moqHangModuleUrl ?? DEFAULT_MOQ_HANG_MODULE_URL;
    this.iceServers = options.iceServers ?? [];
    this.controlLabel = options.controlLabel ?? DEFAULT_CONTROL_LABEL;
    this.peer = null;
    this.control = null;
    this.socket = null;
    this.moq = null;
    this.moqStatus = "idle";
    this.localStream = null;
    this.localAudioTransceivers = [];
    this.speakerTransceivers = [];
    this.requestedMaxSpeakerSlots = options.maxSpeakerSlots;
    this.maxSpeakerSlots = options.maxSpeakerSlots ?? 64;
    this.remoteStream = null;
    this.connected = false;
    this.epoch = 0;
    this.speakers = new Map();
    this.users = new Map();
    this.channels = new Map();
    this.serverSync = null;
    this.serverConfig = null;
    this.gatewayConfig = null;
    this.codecVersion = null;
  }

  async connect() {
    if (this.transport === "moq" && this.moqUrl) {
      this.selectedTransport = "moq";
      await this.connectMoq();
      return;
    }
    await this.openSignaling();
    this.selectTransport();
    if (this.selectedTransport === "moq") {
      this.closeSignaling();
      await this.connectMoq();
      return;
    }
    await this.createAndSendOffer();
  }

  async connectWithPassword(username, password, options = {}) {
    if (this.transport === "moq" && this.moqUrl) {
      this.selectedTransport = "moq";
      await this.connectMoqWithPassword(username, password, options);
      return;
    }
    await this.openSignaling();
    this.selectTransport();
    if (this.selectedTransport === "moq") {
      this.closeSignaling();
      await this.connectMoqWithPassword(username, password, options);
      return;
    }
    const authenticated = waitForAuthentication(this);
    this.authenticatePassword(username, password);
    await authenticated;
    await this.ensurePeer();
    if (options.microphone) {
      await this.useMicrophone(options.microphone === true ? { audio: true } : options.microphone);
    }
    await this.createAndSendOffer();
  }

  async openSignaling() {
    if (this.socket?.readyState === WebSocket.OPEN && this.gatewayConfig != null) {
      return;
    }
    const gatewayConfig = waitForEvent(this, "gateway_config");
    this.socket = new WebSocket(this.signalingUrl);
    this.socket.addEventListener("message", (event) => this.handleSignal(event));
    await once(this.socket, "open");
    await gatewayConfig;
  }

  async createAndSendOffer() {
    if (this.selectedTransport === "moq") {
      throw new Error("createAndSendOffer() is only available for WebRTC transport");
    }
    this.selectedTransport ??= "webrtc";
    await this.ensurePeer();
    const offer = await this.peer.createOffer();
    await this.peer.setLocalDescription(offer);
    this.sendSignal({ type: "offer", sdp: offer.sdp, speaker_slots: this.maxSpeakerSlots });
    this.connected = true;
  }

  async useMicrophone(constraints = { audio: true }) {
    if (this.selectedTransport === "moq") {
      await this.ensureMoq();
      if (typeof this.moq.useMicrophone === "function") {
        this.localStream = await this.moq.useMicrophone(constraints);
        return this.localStream;
      }
      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
      this.setMoqStatus("capture_ready");
      return this.localStream;
    }
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error("openSignaling() must be called before useMicrophone()");
    }
    await this.ensurePeer();
    this.localStream?.getTracks().forEach((track) => track.stop());
    this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
    for (const track of this.localStream.getAudioTracks()) {
      const transceiver = this.peer.addTransceiver(track, {
        direction: "sendonly",
        streams: [this.localStream],
      });
      this.localAudioTransceivers.push(transceiver);
    }
    if (this.connected) {
      await this.createAndSendOffer();
    }
    return this.localStream;
  }

  authenticatePassword(username, password) {
    this.sendCommand({
      type: "authenticate",
      auth: { password: { username, password } },
    });
  }

  authenticateSso(token) {
    this.sendCommand({
      type: "authenticate",
      auth: { sso: { token } },
    });
  }

  setPushToTalk(enabled, target = "normal") {
    this.epoch += 1;
    this.sendCommand({
      type: "voice_control",
      ptt: enabled,
      target: encodeVoiceTarget(target),
      epoch: this.epoch,
    });
    return this.epoch;
  }

  joinChannel(channelId) {
    this.sendCommand({ type: "join_channel", channel_id: channelId });
  }

  sendText(text) {
    this.sendCommand({ type: "send_text", text });
  }

  setMute(muted) {
    this.sendCommand({ type: "set_mute", muted });
  }

  setDeaf(deafened) {
    this.sendCommand({ type: "set_deaf", deafened });
  }

  close() {
    this.localStream?.getTracks().forEach((track) => track.stop());
    this.control?.close();
    this.closeSignaling();
    this.moq?.close?.();
    this.moq = null;
    this.peer?.close();
  }

  closeSignaling() {
    this.socket?.close();
    this.socket = null;
  }

  bindPeerEvents() {
    this.peer.addEventListener("icecandidate", (event) => {
      if (event.candidate) {
        this.sendSignal({ type: "ice_candidate", candidate: event.candidate.toJSON() });
      }
    });
    this.peer.addEventListener("iceconnectionstatechange", () => {
      this.emit("iceconnectionstatechange", { state: this.peer.iceConnectionState });
    });
    this.peer.addEventListener("track", (event) => {
      this.remoteStream.addTrack(event.track);
      this.emit("track", {
        track: event.track,
        streams: event.streams,
        stream: this.remoteStream,
      });
    });
  }

  bindControlEvents() {
    this.control.addEventListener("open", () => this.emit("controlopen", {}));
    this.control.addEventListener("close", () => this.emit("controlclose", {}));
    this.control.addEventListener("message", (event) => this.handleControlMessage(event.data));
  }

  async handleSignal(event) {
    const message = JSON.parse(event.data);
    if (message.type === "answer") {
      if (!this.peer) return;
      await this.peer.setRemoteDescription({ type: "answer", sdp: message.sdp });
    } else if (message.type === "ice_candidate") {
      if (!this.peer) return;
      await this.peer.addIceCandidate(message.candidate);
    } else if (message.type === "error") {
      this.emit("error", { message: message.message });
    } else {
      this.handleServerEvent(message);
    }
  }

  handleControlMessage(data) {
    const event = JSON.parse(data);
    this.handleServerEvent(event);
  }

  handleServerEvent(event) {
    if (event.type === "speaker_assigned") {
      this.speakers.set(event.ssrc, event);
    } else if (event.type === "voice_segment_end") {
      this.speakers.delete(event.ssrc);
    } else if (event.type === "user_state") {
      this.applyUserState(event);
    } else if (event.type === "user_remove") {
      this.users.delete(event.session);
    } else if (event.type === "channel_state") {
      this.applyChannelState(event);
    } else if (event.type === "channel_remove") {
      this.channels.delete(event.channel_id);
    } else if (event.type === "server_sync") {
      this.serverSync = event;
    } else if (event.type === "server_config") {
      this.serverConfig = event;
    } else if (event.type === "gateway_config") {
      this.applyGatewayConfig(event);
      this.gatewayConfig = event;
    } else if (event.type === "codec_version") {
      this.codecVersion = event;
    }
    this.emit(event.type, event);
    this.emit("event", event);
  }

  applyUserState(event) {
    if (event.session == null) {
      return;
    }
    const previous = this.users.get(event.session) ?? {};
    this.users.set(event.session, mergePatch(previous, event));
  }

  applyChannelState(event) {
    if (event.channel_id == null) {
      return;
    }
    const previous = this.channels.get(event.channel_id) ?? {};
    const next = mergePatch(previous, event);
    if (event.links_add?.length) {
      next.links = unique([...(previous.links ?? []), ...event.links_add]);
    }
    if (event.links_remove?.length) {
      const remove = new Set(event.links_remove);
      next.links = (next.links ?? []).filter((id) => !remove.has(id));
    }
    this.channels.set(event.channel_id, next);
  }

  sendSignal(message) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error("signaling socket is not open");
    }
    this.socket.send(JSON.stringify(message));
  }

  sendCommand(command) {
    if (this.selectedTransport === "moq") {
      if (!this.moq || typeof this.moq.sendCommand !== "function") {
        throw new Error("MoQ transport is not connected");
      }
      this.moq.sendCommand(command);
      return;
    }
    if (this.control?.readyState === "open") {
      this.control.send(JSON.stringify(command));
      return;
    }
    this.sendSignal(command);
  }

  emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  addSpeakerReceivers() {
    for (let index = 0; index < this.maxSpeakerSlots; index += 1) {
      this.speakerTransceivers.push(
        this.peer.addTransceiver("audio", { direction: "recvonly" }),
      );
    }
  }

  async ensurePeer() {
    if (this.peer) {
      return;
    }
    this.selectedTransport ??= "webrtc";
    if (this.gatewayConfig == null) {
      this.applyGatewayConfig({ max_speaker_slots: this.maxSpeakerSlots ?? 64 });
    }
    this.peer = new RTCPeerConnection({
      iceServers: this.iceServers,
      bundlePolicy: "max-bundle",
    });
    this.control = this.peer.createDataChannel(this.controlLabel, { ordered: true });
    this.remoteStream = new MediaStream();
    this.addSpeakerReceivers();
    this.bindPeerEvents();
    this.bindControlEvents();
  }

  applyGatewayConfig(event) {
    if (this.peer) {
      return;
    }
    const serverMax = normalizeSpeakerSlots(event.max_speaker_slots, 64);
    const requested = this.requestedMaxSpeakerSlots == null
      ? serverMax
      : Math.min(normalizeSpeakerSlots(this.requestedMaxSpeakerSlots, serverMax), serverMax);
    this.maxSpeakerSlots = requested;
    if (!this.moqUrl && event.moq?.url) {
      this.moqUrl = event.moq.url;
    }
  }

  selectTransport() {
    if (this.transport === "webrtc") {
      this.setSelectedTransport("webrtc");
      return this.selectedTransport;
    }
    if (this.transport === "moq") {
      this.setSelectedTransport("moq");
      return this.selectedTransport;
    }
    const transports = new Set((this.gatewayConfig?.transports ?? []).map(normalizeTransportName));
    const moqAvailable = transports.has("moq") && (this.moqUrl || this.gatewayConfig?.moq);
    const webrtcAvailable = transports.size === 0 || transports.has("webrtc");
    if (moqAvailable && !webrtcAvailable) {
      this.setSelectedTransport("moq");
    } else {
      this.setSelectedTransport("webrtc");
    }
    return this.selectedTransport;
  }

  setSelectedTransport(transport) {
    if (this.selectedTransport === transport) {
      return;
    }
    this.selectedTransport = transport;
    this.emit("transportchange", { transport });
  }

  async connectMoqWithPassword(username, password, options = {}) {
    await this.connectMoq();
    const authenticated = waitForAuthentication(this);
    this.sendCommand({
      type: "authenticate",
      auth: { password: { username, password } },
    });
    await authenticated;
    if (options.microphone) {
      await this.useMicrophone(options.microphone === true ? { audio: true } : options.microphone);
    }
  }

  async connectMoq() {
    this.setSelectedTransport("moq");
    await this.ensureMoq();
    this.setMoqStatus("connecting");
    await this.moq.connect?.();
    this.connected = true;
    this.setMoqStatus("connected");
  }

  async ensureMoq() {
    if (this.moq) {
      return;
    }
    const url = this.resolveMoqUrl();
    const factory = this.moqAdapterFactory ?? defaultMoqAdapterFactory;
    this.moq = factory({
      client: this,
      url,
      maxSpeakerSlots: this.gatewayConfig?.moq?.max_speaker_tracks ?? this.maxSpeakerSlots,
      audioBitrate: this.gatewayConfig?.moq?.audio_bitrate ?? this.gatewayConfig?.audio_bitrate,
      moqLiteModule: this.moqLiteModule,
      moqHangModule: this.moqHangModule,
      moqLiteModuleUrl: this.moqLiteModuleUrl,
      moqHangModuleUrl: this.moqHangModuleUrl,
    });
    this.bindMoqEvents(this.moq);
  }

  bindMoqEvents(adapter) {
    adapter.addEventListener?.("event", (event) => this.handleServerEvent(event.detail));
    adapter.addEventListener?.("message", (event) => {
      const data = typeof event.data === "string" ? event.data : event.detail;
      if (data) {
        this.handleServerEvent(typeof data === "string" ? JSON.parse(data) : data);
      }
    });
    adapter.addEventListener?.("status", (event) => {
      const status = typeof event.detail === "string" ? event.detail : event.detail?.status;
      if (status) {
        this.setMoqStatus(status);
      }
    });
    adapter.addEventListener?.("track", (event) => this.emit("track", event.detail));
    adapter.addEventListener?.("error", (event) => {
      this.emit("error", event.detail ?? { message: event.message ?? "MoQ transport error" });
    });
  }

  resolveMoqUrl() {
    const configured = this.moqUrl ?? this.gatewayConfig?.moq?.url;
    if (configured) {
      return configured;
    }
    if (!this.signalingUrl) {
      throw new Error("MoQ transport requires moqUrl or gateway_config.moq.url");
    }
    const url = new URL(this.signalingUrl);
    url.protocol = url.protocol === "wss:" ? "https:" : "http:";
    url.pathname = "/web/moq";
    url.search = "";
    url.hash = "";
    return url.toString();
  }

  setMoqStatus(status) {
    if (this.moqStatus === status) {
      return;
    }
    this.moqStatus = status;
    this.emit("moqstatus", { status });
  }
}

class BrowserMoqAdapter extends EventTarget {
  constructor({
    url,
    maxSpeakerSlots = 1,
    audioBitrate = DEFAULT_MOQ_AUDIO_BITRATE,
    moqLiteModule = null,
    moqHangModule = null,
    moqLiteModuleUrl = DEFAULT_MOQ_LITE_MODULE_URL,
    moqHangModuleUrl = DEFAULT_MOQ_HANG_MODULE_URL,
  }) {
    super();
    this.url = url;
    this.maxSpeakerSlots = normalizeSpeakerSlots(maxSpeakerSlots, 1);
    this.audioBitrate = audioBitrate ?? DEFAULT_MOQ_AUDIO_BITRATE;
    this.moqLiteModule = moqLiteModule;
    this.moqHangModule = moqHangModule;
    this.moqLiteModuleUrl = moqLiteModuleUrl;
    this.moqHangModuleUrl = moqHangModuleUrl;
    this.Moq = null;
    this.Hang = null;
    this.connection = null;
    this.upBroadcast = null;
    this.downBroadcast = null;
    this.controlUp = null;
    this.audioUp = null;
    this.commandQueue = [];
    this.micFrameQueue = [];
    this.pendingTerminator = false;
    this.closed = false;
    this.catalog = null;
    this.speakers = new Map();
    this.playbacks = new Map();
    this.audioContext = null;
    this.audioDestination = null;
    this.outputStream = null;
    this.outputTrackEmitted = false;
    this.localStream = null;
    this.micReader = null;
    this.micTask = null;
    this.micToken = null;
    this.audioEncoder = null;
    this.audioEncoderConfigured = false;
    this.micBaseMediaTimestamp = null;
    this.lastMicTimestamp = 0;
    this.voiceActive = false;
    this.pendingVoiceControl = null;
    this.sentMicMedia = false;
    this.legacyFormat = null;
    this.controlUpReady = new Promise((resolve, reject) => {
      this.resolveControlUp = resolve;
      this.rejectControlUp = reject;
    });
    this.audioUpReady = new Promise((resolve, reject) => {
      this.resolveAudioUp = resolve;
      this.rejectAudioUp = reject;
    });
  }

  async connect() {
    if (this.connection) {
      return;
    }
    if (typeof WebTransport !== "function") {
      throw new Error("MoQ transport requires WebTransport or a custom moqAdapterFactory");
    }
    try {
      this.setStatus("loading");
      await this.loadModules();
      this.setStatus("connecting");
      const path = this.Moq.Path.from(MOQ_BROADCAST_PATH);
      this.connection = await this.Moq.Connection.connect(new URL(this.url), {
        websocket: { enabled: false },
      });
      this.connection.closed?.then(
        () => {
          if (!this.closed) {
            this.setStatus("closed");
          }
        },
        (error) => this.fail(error),
      );

      this.upBroadcast = new this.Moq.Broadcast();
      this.connection.publish(path, this.upBroadcast);
      this.acceptPublishedTracks();

      this.downBroadcast = this.connection.consume(path);
      const controlDown = this.downBroadcast.subscribe(MOQ_CONTROL_DOWN_TRACK, 0);
      const catalog = this.downBroadcast.subscribe(MOQ_CATALOG_TRACK, 10);
      this.readControlEvents(controlDown);
      this.readCatalog(catalog);
      this.subscribeSpeakerTracks(this.downBroadcast);

      await Promise.all([this.controlUpReady, this.audioUpReady]);
      this.setStatus("connected");
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }

  async loadModules() {
    const globalModules = globalThis.ShitSpeakMoqModules ?? {};
    this.Moq = this.moqLiteModule ?? globalModules.Moq ?? globalModules.moqLite;
    this.Hang = this.moqHangModule ?? globalModules.Hang ?? globalModules.moqHang;
    if (!this.Moq) {
      this.Moq = await import(this.moqLiteModuleUrl);
    }
    if (!this.Hang) {
      this.Hang = await import(this.moqHangModuleUrl);
    }
    if (!this.Moq?.Connection?.connect || !this.Moq?.Broadcast || !this.Moq?.Path) {
      throw new Error("@moq/lite module is missing Connection, Broadcast, or Path exports");
    }
  }

  acceptPublishedTracks() {
    void (async () => {
      for (;;) {
        const request = await this.upBroadcast.requested();
        if (!request) {
          break;
        }
        const track = request.track;
        if (track.name === MOQ_CONTROL_UP_TRACK) {
          this.controlUp = track;
          this.resolveControlUp(track);
          this.flushCommands();
        } else if (track.name === MOQ_AUDIO_UP_MIC_TRACK) {
          this.audioUp = track;
          this.resolveAudioUp(track);
          this.flushMicFrames();
        } else {
          track.close?.(new Error(`unsupported MoQ upload track: ${track.name}`));
        }
      }
    })().catch((error) => this.fail(error));
  }

  readControlEvents(track) {
    void (async () => {
      for (;;) {
        const text = await readTrackString(track);
        if (text == null) {
          break;
        }
        const event = JSON.parse(text);
        this.handleServerEvent(event);
      }
    })().catch((error) => this.fail(error));
  }

  readCatalog(track) {
    void (async () => {
      let catalog = null;
      if (this.Hang?.Catalog?.fetch) {
        catalog = await this.Hang.Catalog.fetch(track);
      } else {
        const frame = await track.readFrame();
        catalog = frame ? JSON.parse(new TextDecoder().decode(frame)) : null;
      }
      if (catalog) {
        this.catalog = catalog;
        this.dispatchEvent(new CustomEvent("catalog", { detail: catalog }));
      }
    })().catch((error) => this.fail(error));
  }

  subscribeSpeakerTracks(broadcast) {
    for (let slot = 0; slot < this.maxSpeakerSlots; slot += 1) {
      const trackId = audioDownSlot(slot);
      const track = broadcast.subscribe(trackId, 20 + slot);
      const playback = new MoqSpeakerSlotPlayback(this, slot, trackId, track);
      this.playbacks.set(trackId, playback);
      playback.start();
    }
  }

  handleServerEvent(event) {
    if (event.type === "speaker_assigned") {
      this.speakers.set(event.ssrc, event.track_id);
    } else if (event.type === "voice_segment_end") {
      const trackId = this.speakers.get(event.ssrc);
      this.speakers.delete(event.ssrc);
      if (trackId) {
        this.playbacks.get(trackId)?.resetDecoder();
      }
    } else if (event.type === "voice_control_ack") {
      this.applyVoiceControlAck(event.epoch);
    }
    this.dispatchEvent(new CustomEvent("event", { detail: event }));
  }

  sendCommand(command) {
    if (!this.controlUp) {
      this.commandQueue.push(command);
      return;
    }
    this.writeCommand(command);
  }

  writeCommand(command) {
    this.controlUp.writeString(JSON.stringify(command));
    if (command?.type === "voice_control") {
      this.pendingVoiceControl = {
        epoch: command.epoch,
        ptt: command.ptt,
      };
      if (command.ptt === false) {
        const shouldTerminate = this.voiceActive || this.sentMicMedia;
        this.voiceActive = false;
        if (shouldTerminate) {
          this.sendMicTerminator();
        }
      }
    }
  }

  applyVoiceControlAck(epoch) {
    if (!this.pendingVoiceControl || this.pendingVoiceControl.epoch !== epoch) {
      return;
    }
    this.voiceActive = this.pendingVoiceControl.ptt;
    this.pendingVoiceControl = null;
  }

  flushCommands() {
    while (this.controlUp && this.commandQueue.length > 0) {
      this.writeCommand(this.commandQueue.shift());
    }
  }

  async useMicrophone(constraints = { audio: true }) {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("MoQ microphone capture requires navigator.mediaDevices.getUserMedia");
    }
    const stream = await navigator.mediaDevices.getUserMedia(moqMicrophoneConstraints(constraints));
    await this.startMicrophone(stream);
    this.localStream = stream;
    this.setStatus("capture_ready");
    return stream;
  }

  async startMicrophone(stream) {
    if (typeof MediaStreamTrackProcessor !== "function") {
      throw new Error("MoQ microphone capture requires MediaStreamTrackProcessor");
    }
    if (typeof AudioEncoder !== "function") {
      throw new Error("MoQ microphone capture requires WebCodecs AudioEncoder");
    }
    const [track] = stream.getAudioTracks();
    if (!track) {
      throw new Error("MoQ microphone capture requires an audio track");
    }
    await this.audioUpReady;
    this.stopMicrophone();

    const processor = new MediaStreamTrackProcessor({ track });
    const reader = processor.readable.getReader();
    const token = { cancelled: false };
    this.micReader = reader;
    this.micToken = token;
    this.audioEncoderConfigured = false;
    this.micBaseMediaTimestamp = null;
    this.audioEncoder = new AudioEncoder({
      output: (chunk) => this.handleEncodedMicrophoneChunk(chunk),
      error: (error) => this.fail(error),
    });
    this.micTask = this.readMicrophone(reader, token);
  }

  async readMicrophone(reader, token) {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done || token.cancelled) {
          break;
        }
        try {
          if (!this.audioEncoderConfigured) {
            await this.configureAudioEncoder(value);
          }
          this.audioEncoder.encode(value);
        } finally {
          value.close();
        }
      }
    } catch (error) {
      if (!token.cancelled) {
        this.fail(error);
      }
    }
  }

  async configureAudioEncoder(audioData) {
    const config = {
      codec: "opus",
      sampleRate: audioData.sampleRate || OPUS_SAMPLE_RATE,
      numberOfChannels: Math.min(audioData.numberOfChannels || OPUS_CHANNELS, OPUS_CHANNELS),
      bitrate: this.audioBitrate,
    };
    if (typeof AudioEncoder.isConfigSupported === "function") {
      const supported = await AudioEncoder.isConfigSupported(config);
      if (!supported.supported) {
        throw new Error("WebCodecs AudioEncoder does not support Opus microphone capture");
      }
      this.audioEncoder.configure(supported.config ?? config);
    } else {
      this.audioEncoder.configure(config);
    }
    this.audioEncoderConfigured = true;
  }

  handleEncodedMicrophoneChunk(chunk) {
    if (!this.voiceActive) {
      return;
    }
    const payload = new Uint8Array(chunk.byteLength);
    chunk.copyTo(payload);
    const timestamp = this.microphoneRtpTimestamp(chunk.timestamp);
    this.lastMicTimestamp = timestamp;
    this.sentMicMedia = true;
    this.writeMicFrame(encodeHangLegacyFrame(payload, timestamp, this.Moq));
  }

  microphoneRtpTimestamp(mediaTimestamp) {
    const timestamp = Number.isFinite(mediaTimestamp) ? mediaTimestamp : performance.now() * 1000;
    this.micBaseMediaTimestamp ??= timestamp;
    const elapsedMicros = Math.max(0, timestamp - this.micBaseMediaTimestamp);
    return Math.floor((elapsedMicros * OPUS_SAMPLE_RATE) / 1_000_000) >>> 0;
  }

  writeMicFrame(frame) {
    if (!this.audioUp) {
      this.micFrameQueue.push(frame);
      if (this.micFrameQueue.length > 128) {
        this.micFrameQueue.shift();
      }
      return;
    }
    this.audioUp.writeFrame(frame);
  }

  flushMicFrames() {
    while (this.audioUp && this.micFrameQueue.length > 0) {
      this.audioUp.writeFrame(this.micFrameQueue.shift());
    }
    if (this.pendingTerminator) {
      this.pendingTerminator = false;
      this.sendMicTerminator();
    }
  }

  sendMicTerminator() {
    const timestamp = (this.lastMicTimestamp + OPUS_RTP_TICKS_PER_20MS) >>> 0;
    this.lastMicTimestamp = timestamp;
    const frame = encodeShitSpeakMoqAudioFrame(timestamp, new Uint8Array(), true);
    if (!this.audioUp) {
      this.pendingTerminator = true;
      return;
    }
    this.audioUp.writeFrame(frame);
    this.sentMicMedia = false;
  }

  stopMicrophone() {
    this.micToken && (this.micToken.cancelled = true);
    const cancel = this.micReader?.cancel?.();
    cancel?.catch?.(() => {});
    try {
      this.audioEncoder?.close?.();
    } catch {
      // Ignore close races from WebCodecs.
    }
    this.micReader = null;
    this.micToken = null;
    this.audioEncoder = null;
    this.audioEncoderConfigured = false;
    this.micTask = null;
  }

  decodeHangFrames(frame) {
    if (!this.legacyFormat && this.Hang?.Container?.Legacy?.Format) {
      this.legacyFormat = new this.Hang.Container.Legacy.Format();
    }
    if (this.legacyFormat) {
      return this.legacyFormat.decode(frame);
    }
    const decoded = decodeHangLegacyFrame(frame, this.Moq);
    return [{ data: decoded.payload, timestamp: decoded.timestamp, keyframe: false }];
  }

  async ensureAudioOutput() {
    const AudioContextCtor = globalThis.AudioContext ?? globalThis.webkitAudioContext;
    if (!AudioContextCtor) {
      throw new Error("MoQ audio playback requires WebAudio");
    }
    this.audioContext ??= new AudioContextCtor({ sampleRate: OPUS_SAMPLE_RATE });
    this.audioDestination ??= this.audioContext.createMediaStreamDestination();
    this.outputStream ??= this.audioDestination.stream;
    if (!this.outputTrackEmitted) {
      this.outputTrackEmitted = true;
      this.dispatchEvent(new CustomEvent("track", {
        detail: {
          transport: "moq",
          track: this.outputStream.getAudioTracks()[0],
          stream: this.outputStream,
          streams: [this.outputStream],
        },
      }));
    }
    if (this.audioContext.state === "suspended") {
      await this.audioContext.resume().catch(() => {});
    }
  }

  setStatus(status) {
    this.dispatchEvent(new CustomEvent("status", { detail: status }));
  }

  fail(error) {
    if (this.closed) {
      return;
    }
    const message = error?.message ?? String(error);
    this.setStatus("error");
    this.dispatchEvent(new CustomEvent("error", { detail: { message, error } }));
  }

  close() {
    this.closed = true;
    this.stopMicrophone();
    this.setStatus("closed");
    this.localStream?.getTracks?.().forEach((track) => track.stop?.());
    for (const playback of this.playbacks.values()) {
      playback.close();
    }
    this.playbacks.clear();
    this.upBroadcast?.close?.();
    this.downBroadcast?.close?.();
    this.connection?.close?.();
    const closeAudio = this.audioContext?.close?.();
    closeAudio?.catch?.(() => {});
    const error = new Error("MoQ transport closed");
    this.rejectControlUp?.(error);
    this.rejectAudioUp?.(error);
  }
}

class MoqSpeakerSlotPlayback {
  constructor(adapter, slot, trackId, track) {
    this.adapter = adapter;
    this.slot = slot;
    this.trackId = trackId;
    this.track = track;
    this.decoder = null;
    this.closed = false;
    this.playbackTime = 0;
  }

  start() {
    void this.run().catch((error) => this.adapter.fail(error));
  }

  async run() {
    for (;;) {
      const frame = await this.track.readFrame();
      if (frame == null || this.closed) {
        break;
      }
      if (isShitSpeakMoqAudioFrame(frame)) {
        const decoded = decodeShitSpeakMoqAudioFrame(frame);
        if (decoded.terminator) {
          this.resetDecoder();
        } else {
          this.decodeOpus(decoded.payload, decoded.timestamp);
        }
        continue;
      }
      for (const decoded of this.adapter.decodeHangFrames(frame)) {
        this.decodeOpus(decoded.data, decoded.timestamp);
      }
    }
  }

  decodeOpus(payload, timestamp) {
    if (!payload?.byteLength) {
      return;
    }
    if (typeof AudioDecoder !== "function" || typeof EncodedAudioChunk !== "function") {
      throw new Error("MoQ speaker playback requires WebCodecs AudioDecoder");
    }
    if (!this.decoder) {
      this.decoder = new AudioDecoder({
        output: (audioData) => void this.playAudioData(audioData),
        error: (error) => this.adapter.fail(error),
      });
      this.decoder.configure({
        codec: "opus",
        sampleRate: OPUS_SAMPLE_RATE,
        numberOfChannels: OPUS_CHANNELS,
      });
    }
    this.decoder.decode(new EncodedAudioChunk({
      type: "key",
      timestamp: Number(timestamp) || 0,
      data: payload,
    }));
  }

  async playAudioData(audioData) {
    let shouldClose = true;
    try {
      await this.adapter.ensureAudioOutput();
      if (!this.adapter.audioContext || !this.adapter.audioDestination) {
        audioData.close();
        shouldClose = false;
        return;
      }
      const buffer = audioDataToAudioBuffer(this.adapter.audioContext, audioData);
      const source = this.adapter.audioContext.createBufferSource();
      source.buffer = buffer;
      source.connect(this.adapter.audioDestination);
      source.start(this.nextStartTime(buffer.duration));
    } finally {
      if (shouldClose) {
        audioData.close();
      }
    }
  }

  nextStartTime(duration) {
    const now = this.adapter.audioContext.currentTime;
    const minStart = now + MOQ_PLAYBACK_UNDERRUN_GRACE_SECONDS;
    const maxStart = now + MOQ_PLAYBACK_MAX_LEAD_SECONDS;
    if (this.playbackTime <= 0 || this.playbackTime < minStart || this.playbackTime > maxStart) {
      this.playbackTime = now + MOQ_PLAYBACK_LEAD_SECONDS;
    }
    const start = this.playbackTime;
    this.playbackTime = start + duration;
    return start;
  }

  resetDecoder() {
    try {
      this.decoder?.close?.();
    } catch {
      // Ignore close races from WebCodecs.
    }
    this.decoder = null;
  }

  close() {
    this.closed = true;
    this.track.close?.();
    this.resetDecoder();
  }
}

function mergePatch(previous, patch) {
  const next = { ...previous };
  for (const [key, value] of Object.entries(patch)) {
    if (value !== undefined) {
      next[key] = value;
    }
  }
  return next;
}

function unique(values) {
  return [...new Set(values)];
}

function encodeVoiceTarget(target) {
  if (target === "normal" || target == null) {
    return "normal";
  }
  if (target === "server_loopback") {
    return "server_loopback";
  }
  if (typeof target === "number") {
    return { slot: target };
  }
  if (typeof target === "object" && "slot" in target) {
    return { slot: target.slot };
  }
  return target;
}

function audioDownSlot(slot) {
  return `${MOQ_AUDIO_DOWN_SLOT_PREFIX}${slot}`;
}

function moqMicrophoneConstraints(constraints) {
  if (constraints === true) {
    return {
      audio: {
        channelCount: OPUS_CHANNELS,
        sampleRate: OPUS_SAMPLE_RATE,
        echoCancellation: true,
        noiseSuppression: true,
      },
    };
  }
  if (constraints?.audio === true) {
    return {
      ...constraints,
      audio: {
        channelCount: OPUS_CHANNELS,
        sampleRate: OPUS_SAMPLE_RATE,
        echoCancellation: true,
        noiseSuppression: true,
      },
    };
  }
  if (typeof constraints?.audio === "object") {
    return {
      ...constraints,
      audio: {
        channelCount: OPUS_CHANNELS,
        sampleRate: OPUS_SAMPLE_RATE,
        echoCancellation: true,
        noiseSuppression: true,
        ...constraints.audio,
      },
    };
  }
  return constraints;
}

async function readTrackString(track) {
  if (typeof track.readString === "function") {
    return track.readString();
  }
  const frame = await track.readFrame();
  return frame ? new TextDecoder().decode(frame) : undefined;
}

function encodeHangLegacyFrame(payload, timestamp, Moq) {
  const timestampBytes = Moq?.Varint?.encode
    ? Moq.Varint.encode(timestamp)
    : encodeQuicVarint(timestamp);
  const out = new Uint8Array(timestampBytes.byteLength + payload.byteLength);
  out.set(timestampBytes, 0);
  out.set(payload, timestampBytes.byteLength);
  return out;
}

function decodeHangLegacyFrame(frame, Moq) {
  const decoded = Moq?.Varint?.decode
    ? Moq.Varint.decode(frame)
    : decodeQuicVarint(frame);
  return { timestamp: decoded[0], payload: decoded[1] };
}

function encodeShitSpeakMoqAudioFrame(timestamp, payload, terminator) {
  const out = new Uint8Array(14 + payload.byteLength);
  out.set(MOQ_AUDIO_MAGIC, 0);
  out[4] = MOQ_AUDIO_VERSION;
  out[5] = terminator ? MOQ_AUDIO_TERMINATOR : 0;
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setBigUint64(6, BigInt(timestamp));
  out.set(payload, 14);
  return out;
}

function isShitSpeakMoqAudioFrame(frame) {
  return frame?.byteLength >= 14
    && frame[0] === MOQ_AUDIO_MAGIC[0]
    && frame[1] === MOQ_AUDIO_MAGIC[1]
    && frame[2] === MOQ_AUDIO_MAGIC[2]
    && frame[3] === MOQ_AUDIO_MAGIC[3];
}

function decodeShitSpeakMoqAudioFrame(frame) {
  if (!isShitSpeakMoqAudioFrame(frame)) {
    throw new Error("invalid ShitSpeak MoQ audio frame");
  }
  if (frame[4] !== MOQ_AUDIO_VERSION) {
    throw new Error(`unsupported ShitSpeak MoQ audio frame version ${frame[4]}`);
  }
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  return {
    timestamp: Number(view.getBigUint64(6)),
    terminator: (frame[5] & MOQ_AUDIO_TERMINATOR) !== 0,
    payload: frame.subarray(14),
  };
}

function encodeQuicVarint(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(`invalid varint value: ${value}`);
  }
  if (value <= 0x3f) {
    return Uint8Array.of(value);
  }
  if (value <= 0x3fff) {
    const out = new Uint8Array(2);
    const view = new DataView(out.buffer);
    view.setUint16(0, value | 0x4000);
    return out;
  }
  if (value <= 0x3fffffff) {
    const out = new Uint8Array(4);
    const view = new DataView(out.buffer);
    view.setUint32(0, value | 0x80000000);
    return out;
  }
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(value) | 0xc000000000000000n);
  return out;
}

function decodeQuicVarint(buffer) {
  if (!buffer?.byteLength) {
    throw new Error("empty varint buffer");
  }
  const size = 1 << ((buffer[0] & 0xc0) >> 6);
  if (buffer.byteLength < size) {
    throw new Error("truncated varint buffer");
  }
  const view = new DataView(buffer.buffer, buffer.byteOffset, size);
  let value = 0;
  if (size === 1) {
    value = buffer[0] & 0x3f;
  } else if (size === 2) {
    value = view.getUint16(0) & 0x3fff;
  } else if (size === 4) {
    value = view.getUint32(0) & 0x3fffffff;
  } else {
    value = Number(view.getBigUint64(0) & 0x3fffffffffffffffn);
  }
  return [value, buffer.subarray(size)];
}

function audioDataToAudioBuffer(context, audioData) {
  const channels = audioData.numberOfChannels || OPUS_CHANNELS;
  const frames = audioData.numberOfFrames;
  const sampleRate = audioData.sampleRate || OPUS_SAMPLE_RATE;
  const buffer = context.createBuffer(channels, frames, sampleRate);
  for (let channel = 0; channel < channels; channel += 1) {
    audioData.copyTo(buffer.getChannelData(channel), {
      planeIndex: channel,
      format: "f32-planar",
    });
  }
  return buffer;
}

function normalizeSpeakerSlots(value, fallback) {
  if (value == null) {
    return fallback;
  }
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.max(1, Math.floor(numeric));
}

function normalizeTransport(value) {
  const normalized = normalizeTransportName(value);
  if (normalized === "auto" || normalized === "webrtc" || normalized === "moq") {
    return normalized;
  }
  throw new Error(`unsupported transport: ${value}`);
}

function normalizeTransportName(value) {
  if (value === "web_rtc" || value === "rtc") {
    return "webrtc";
  }
  return String(value ?? "").toLowerCase();
}

function defaultMoqAdapterFactory(options) {
  return new BrowserMoqAdapter(options);
}

function once(target, type) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      target.removeEventListener(type, onEvent);
      target.removeEventListener("error", onError);
    };
    const onEvent = (event) => {
      cleanup();
      resolve(event);
    };
    const onError = (event) => {
      cleanup();
      reject(event);
    };
    target.addEventListener(type, onEvent, { once: true });
    target.addEventListener("error", onError, { once: true });
  });
}

function waitForEvent(target, type) {
  return new Promise((resolve) => {
    const onEvent = (event) => {
      target.removeEventListener(type, onEvent);
      resolve(event);
    };
    target.addEventListener(type, onEvent, { once: true });
  });
}

function waitForAuthentication(client) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      client.removeEventListener("authenticated", onAuthenticated);
      client.removeEventListener("authentication_rejected", onRejected);
      client.removeEventListener("error", onError);
    };
    const onAuthenticated = (event) => {
      cleanup();
      resolve(event);
    };
    const onRejected = (event) => {
      cleanup();
      reject(new Error(event.detail?.reason ?? "authentication rejected"));
    };
    const onError = (event) => {
      cleanup();
      reject(new Error(event.detail?.message ?? "signaling error"));
    };
    client.addEventListener("authenticated", onAuthenticated, { once: true });
    client.addEventListener("authentication_rejected", onRejected, { once: true });
    client.addEventListener("error", onError, { once: true });
  });
}
