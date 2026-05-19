const DEFAULT_CONTROL_LABEL = "shitspeak-control";

export class ShitSpeakClient extends EventTarget {
  constructor(options) {
    super();
    this.signalingUrl = options.signalingUrl;
    this.iceServers = options.iceServers ?? [];
    this.controlLabel = options.controlLabel ?? DEFAULT_CONTROL_LABEL;
    this.peer = null;
    this.control = null;
    this.socket = null;
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
    await this.openSignaling();
    await this.createAndSendOffer();
  }

  async connectWithPassword(username, password, options = {}) {
    await this.openSignaling();
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
    const gatewayConfig = waitForEvent(this, "gateway_config");
    this.socket = new WebSocket(this.signalingUrl);
    this.socket.addEventListener("message", (event) => this.handleSignal(event));
    await once(this.socket, "open");
    await gatewayConfig;
  }

  async createAndSendOffer() {
    await this.ensurePeer();
    const offer = await this.peer.createOffer();
    await this.peer.setLocalDescription(offer);
    this.sendSignal({ type: "offer", sdp: offer.sdp, speaker_slots: this.maxSpeakerSlots });
    this.connected = true;
  }

  async useMicrophone(constraints = { audio: true }) {
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
    this.sendSignal({
      type: "authenticate",
      auth: { password: { username, password } },
    });
  }

  authenticateSso(token) {
    this.sendSignal({
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
    this.socket?.close();
    this.peer?.close();
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
      await this.peer.setRemoteDescription({ type: "answer", sdp: message.sdp });
    } else if (message.type === "ice_candidate") {
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
