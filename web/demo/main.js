import { ShitSpeakClient } from "../sdk/shitspeak.js";

const log = document.querySelector("#log");
const connectButton = document.querySelector("#connect");
const micButton = document.querySelector("#mic");
const pttButton = document.querySelector("#ptt");
const signalingUrl = document.querySelector("#signalingUrl");
const speakerSlots = document.querySelector("#speakerSlots");
const username = document.querySelector("#username");
const password = document.querySelector("#password");
const channels = document.querySelector("#channels");
const users = document.querySelector("#users");

let client = null;
let ptt = false;

connectButton.addEventListener("click", async () => {
  client?.close();
  const requestedSlots = Number(speakerSlots.value);
  client = new ShitSpeakClient({
    signalingUrl: signalingUrl.value,
    ...(requestedSlots > 0 ? { maxSpeakerSlots: requestedSlots } : {}),
  });
  bindClient(client);

  append("connecting");
  await client.connectWithPassword(username.value, password.value, { microphone: true });
  append("connected signaling");
  micButton.disabled = false;
  pttButton.disabled = false;
});

micButton.addEventListener("click", async () => {
  await client.useMicrophone();
  append("microphone attached");
});

pttButton.addEventListener("mousedown", () => {
  ptt = true;
  client.setPushToTalk(true);
  pttButton.classList.add("active");
});

pttButton.addEventListener("mouseup", () => {
  ptt = false;
  client.setPushToTalk(false);
  pttButton.classList.remove("active");
});

function bindClient(nextClient) {
  nextClient.addEventListener("controlopen", () => {
    append("control channel open");
    micButton.disabled = false;
    pttButton.disabled = false;
  });
  nextClient.addEventListener("iceconnectionstatechange", (event) => {
    append(`ice: ${event.detail.state}`);
  });
  nextClient.addEventListener("event", (event) => {
    append(JSON.stringify(event.detail));
    renderState(nextClient);
  });
  nextClient.addEventListener("track", (event) => {
    const audio = new Audio();
    audio.srcObject = event.detail.stream;
    audio.autoplay = true;
    audio.play().catch((error) => append(`audio play failed: ${error.message}`));
  });
  nextClient.addEventListener("error", (event) => {
    append(`error: ${event.detail.message ?? "unknown"}`);
  });
}

function renderState(nextClient) {
  channels.replaceChildren(
    ...[...nextClient.channels.values()]
      .sort((a, b) => (a.channel_id ?? 0) - (b.channel_id ?? 0))
      .map((channel) => listItem(`#${channel.channel_id ?? "?"} ${channel.name ?? "(unnamed)"}`)),
  );
  users.replaceChildren(
    ...[...nextClient.users.values()]
      .sort((a, b) => (a.session ?? 0) - (b.session ?? 0))
      .map((user) => {
        const channel = user.channel_id == null ? "" : ` @ #${user.channel_id}`;
        return listItem(`${user.name ?? `session ${user.session}`}${channel}`);
      }),
  );
}

function listItem(text) {
  const item = document.createElement("li");
  item.textContent = text;
  return item;
}

function append(message) {
  const prefix = ptt ? "[talking]" : "[idle]";
  log.textContent += `${prefix} ${message}\n`;
  log.scrollTop = log.scrollHeight;
}
