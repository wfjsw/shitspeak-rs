export interface ShitSpeakClientOptions {
  signalingUrl: string;
  transport?: "auto" | "webrtc" | "moq";
  moqUrl?: string;
  moqAdapterFactory?: (options: MoqAdapterOptions) => MoqAdapter;
  moqLiteModule?: unknown;
  moqHangModule?: unknown;
  moqLiteModuleUrl?: string;
  moqHangModuleUrl?: string;
  iceServers?: RTCIceServer[];
  controlLabel?: string;
  maxSpeakerSlots?: number;
}

export type VoiceTargetInput = "normal" | "server_loopback" | number | { slot: number };
export type ShitSpeakTransport = "auto" | "webrtc" | "moq";
export type SelectedShitSpeakTransport = "webrtc" | "moq";

export interface MoqAdapterOptions {
  client: ShitSpeakClient;
  url: string;
  maxSpeakerSlots: number;
  audioBitrate?: number;
  moqLiteModule?: unknown;
  moqHangModule?: unknown;
  moqLiteModuleUrl?: string;
  moqHangModuleUrl?: string;
}

export interface MoqAdapter extends EventTarget {
  connect?(): Promise<void>;
  sendCommand(command: unknown): void;
  useMicrophone?(constraints?: MediaStreamConstraints): Promise<MediaStream>;
  startMicrophone?(stream: MediaStream): Promise<void>;
  close?(): void;
}

export interface SpeakerAssignedEvent {
  type: "speaker_assigned";
  ssrc: number;
  speaker_session: number;
  track_id: string;
  epoch: number;
}

export interface GatewayConfigEvent {
  type: "gateway_config";
  max_speaker_slots: number;
  audio_bitrate: number;
  transports?: Array<"web_rtc" | "moq">;
  moq?: {
    url?: string;
    max_speaker_tracks: number;
    audio_bitrate: number;
  };
}

export interface VoiceSegmentEvent {
  type: "voice_segment_start" | "voice_segment_end";
  ssrc: number;
  speaker_session: number;
  context: string;
  channel_id: number;
  rtp_timestamp: number;
  epoch: number;
}

export interface UserStateEvent {
  type: "user_state";
  session?: number;
  actor?: number;
  name?: string;
  user_id?: number;
  channel_id?: number;
  mute?: boolean;
  deaf?: boolean;
  suppress?: boolean;
  self_mute?: boolean;
  self_deaf?: boolean;
  texture?: string;
  plugin_context?: string;
  plugin_identity?: string;
  comment?: string;
  hash?: string;
  comment_hash?: string;
  texture_hash?: string;
  priority_speaker?: boolean;
  recording?: boolean;
  listening_channel_add?: number[];
  listening_channel_remove?: number[];
  listening_volume_adjustment?: Array<{
    listening_channel: number;
    volume_adjustment: number;
  }>;
}

export interface UserRemoveEvent {
  type: "user_remove";
  session: number;
  actor?: number;
  reason?: string;
  ban?: boolean;
}

export interface ChannelStateEvent {
  type: "channel_state";
  channel_id?: number;
  parent?: number;
  name?: string;
  links?: number[];
  description?: string;
  links_add?: number[];
  links_remove?: number[];
  temporary?: boolean;
  position?: number;
  description_hash?: string;
  max_users?: number;
  is_enter_restricted?: boolean;
  can_enter?: boolean;
}

export interface ServerSyncEvent {
  type: "server_sync";
  session?: number;
  max_bandwidth?: number;
  welcome_text?: string;
  permissions?: number;
}

export interface ServerConfigEvent {
  type: "server_config";
  max_bandwidth?: number;
  welcome_text?: string;
  allow_html?: boolean;
  message_length?: number;
  image_message_length?: number;
  max_users?: number;
  recording_allowed?: boolean;
}

export type ShitSpeakServerEvent =
  | GatewayConfigEvent
  | SpeakerAssignedEvent
  | VoiceSegmentEvent
  | UserStateEvent
  | UserRemoveEvent
  | ChannelStateEvent
  | { type: "channel_remove"; channel_id: number }
  | ServerSyncEvent
  | ServerConfigEvent
  | { type: "permission_denied"; deny_type?: string; session?: number; channel_id?: number; reason?: string; name?: string; permission?: number }
  | { type: "codec_version"; alpha: number; beta: number; prefer_alpha: boolean; opus?: boolean }
  | { type: "authenticated"; session: number; display_name?: string }
  | { type: "authentication_rejected"; reason: string }
  | { type: "voice_control_ack"; epoch: number }
  | { type: "text_message"; sender_session: number; target_sessions?: number[]; channel_ids?: number[]; tree_ids?: number[]; text: string }
  | { type: "error"; message: string };

export class ShitSpeakClient extends EventTarget {
  readonly speakers: Map<number, SpeakerAssignedEvent>;
  readonly users: Map<number, UserStateEvent>;
  readonly channels: Map<number, ChannelStateEvent>;
  readonly localStream: MediaStream | null;
  readonly remoteStream: MediaStream | null;
  readonly maxSpeakerSlots: number;
  readonly selectedTransport: SelectedShitSpeakTransport | null;
  readonly moqStatus: string;
  readonly gatewayConfig: GatewayConfigEvent | null;
  readonly serverSync: ServerSyncEvent | null;
  readonly serverConfig: ServerConfigEvent | null;
  readonly codecVersion: { type: "codec_version"; alpha: number; beta: number; prefer_alpha: boolean; opus?: boolean } | null;
  constructor(options: ShitSpeakClientOptions);
  connect(): Promise<void>;
  openSignaling(): Promise<void>;
  createAndSendOffer(): Promise<void>;
  connectWithPassword(username: string, password: string, options?: { microphone?: boolean | MediaStreamConstraints }): Promise<void>;
  useMicrophone(constraints?: MediaStreamConstraints): Promise<MediaStream>;
  authenticatePassword(username: string, password: string): void;
  authenticateSso(token: string): void;
  setPushToTalk(enabled: boolean, target?: VoiceTargetInput): number;
  joinChannel(channelId: number): void;
  sendText(text: string): void;
  setMute(muted: boolean): void;
  setDeaf(deafened: boolean): void;
  close(): void;
}
