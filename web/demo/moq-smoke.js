import { ShitSpeakClient } from "../sdk/shitspeak.js";

const log = document.querySelector("#log");
const moqUrl = document.querySelector("#moqUrl");
const signalingUrl = document.querySelector("#signalingUrl");
const username = document.querySelector("#username");
const password = document.querySelector("#password");
const capabilitiesButton = document.querySelector("#capabilities");
const connectButton = document.querySelector("#connect");
const micButton = document.querySelector("#mic");
const pttButton = document.querySelector("#ptt");

let client = null;
let ptt = false;

capabilitiesButton.addEventListener("click", () => {
  const checks = {
    WebTransport: typeof WebTransport === "function",
    AudioEncoder: typeof AudioEncoder === "function",
    AudioDecoder: typeof AudioDecoder === "function",
    EncodedAudioChunk: typeof EncodedAudioChunk === "function",
    AudioContext: typeof AudioContext === "function" || typeof webkitAudioContext === "function",
    getUserMedia: typeof navigator.mediaDevices?.getUserMedia === "function",
  };
  append(`capabilities ${JSON.stringify(checks)}`);
});

connectButton.addEventListener("click", async () => {
  client?.close();
  client = new ShitSpeakClient({
    signalingUrl: signalingUrl.value,
    transport: "moq",
    moqUrl: moqUrl.value,
  });
  bindClient(client);

  append("connecting moq");
  try {
    await client.connectWithPassword(username.value, password.value);
    append("authenticated");
    micButton.disabled = false;
    pttButton.disabled = false;
  } catch (error) {
    append(`connect failed: ${error.message}`);
    throw error;
  }
});

micButton.addEventListener("click", async () => {
  try {
    await client.useMicrophone();
    append("microphone attached");
  } catch (error) {
    append(`microphone failed: ${error.message}`);
  }
});

pttButton.addEventListener("mousedown", () => setPtt(true));
pttButton.addEventListener("mouseup", () => setPtt(false));
pttButton.addEventListener("mouseleave", () => {
  if (ptt) {
    setPtt(false);
  }
});

function bindClient(nextClient) {
  nextClient.addEventListener("transportchange", (event) => {
    append(`transport ${event.detail.transport}`);
  });
  nextClient.addEventListener("moqstatus", (event) => {
    append(`moq ${event.detail.status}`);
  });
  nextClient.addEventListener("event", (event) => {
    append(JSON.stringify(event.detail));
  });
  nextClient.addEventListener("catalog", (event) => {
    append(`catalog ${JSON.stringify(event.detail)}`);
  });
  nextClient.addEventListener("track", (event) => {
    const audio = new Audio();
    audio.srcObject = event.detail.stream;
    audio.autoplay = true;
    audio.play().catch((error) => append(`audio play failed: ${error.message}`));
    append("audio output track attached");
  });
  nextClient.addEventListener("error", (event) => {
    append(`error: ${event.detail?.message ?? "unknown"}`);
  });
}

function setPtt(enabled) {
  if (!client) {
    return;
  }
  ptt = enabled;
  const epoch = client.setPushToTalk(enabled);
  pttButton.classList.toggle("active", enabled);
  append(`ptt ${enabled ? "on" : "off"} epoch ${epoch}`);
}

function append(message) {
  const prefix = ptt ? "[talking]" : "[idle]";
  log.textContent += `${prefix} ${message}\n`;
  log.scrollTop = log.scrollHeight;
}
