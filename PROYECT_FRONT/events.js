import { login, register, logout } from "./Auth.js";


const logOutput = document.getElementById("log-output");
const statusBadge = document.getElementById("status-badge");

function setStatus(text, type = "idle") {
    statusBadge.textContent = text;
    statusBadge.classList.remove("badge-ok", "badge-error");
    if (type === "ok") statusBadge.classList.add("badge-ok");
    if (type === "error") statusBadge.classList.add("badge-error");
}

function appendLog(label, data, isError = false) {
    const time = new Date().toLocaleTimeString();
    const prefix = isError ? "[ERROR]" : "[OK]";
    const json = (data !== undefined)
        ? JSON.stringify(data, null, 2)
        : "(sin payload)";

    const block =
        time + " " + prefix + " " + label + "\n" +
        json + "\n" +
        "----------------------------------------\n";

    logOutput.textContent = block + logOutput.textContent;
}


// REGISTER
document.getElementById("btn-register").addEventListener("click", async () => {
    const user = document.getElementById("reg-username").value.trim();
    const email = document.getElementById("reg-email").value.trim();
    const password = document.getElementById("reg-password").value;

    setStatus("register...");
    try {
        const status = await register(email,user, password);

        appendLog("register(user,email,password)", status, false);
        setStatus("register ok", "ok");
    } catch (err) {
        appendLog("register(user,email,password)", { message: String(err) }, true);
        setStatus("register error", "error");
    }
});

// LOGIN
document.getElementById("btn-login").addEventListener("click", async () => {
    const user = document.getElementById("login-username").value.trim();
    const email = document.getElementById("login-email").value.trim() || null;
    const password = document.getElementById("login-password").value;

    setStatus("login...");
    try {
        // email es opcional, si es null podrias decidir no pasarlo
        const status = await login(email,user, password);

        appendLog("login(user,email?,password)", status, false);
        setStatus("login ok", "ok");
    } catch (err) {
        appendLog("login(user,email?,password)", { message: String(err) }, true);
        setStatus("login error", "error");
    }
});

// UNLOGIN
document.getElementById("btn-unlogin").addEventListener("click", async () => {
    setStatus("unlogin...");
    try {
        const status = await logout();

        appendLog("unlogin()", status, false);
        setStatus("unlogin ok", "ok");
    } catch (err) {
        appendLog("unlogin()", { message: String(err) }, true);
        setStatus("unlogin error", "error");
    }
});

// helpers locales en events.js

async function filesInputToPacketFiles(fileInput) {
  const files = Array.from(fileInput.files || []);
  const out = [];

  for (const file of files) {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }

    out.push({
      id: crypto.randomUUID(),
      file_name: file.name,
      mime: file.type || "application/octet-stream",
      data_b64: btoa(binary)
    });
  }

  return out;
}

import { sendStateful,sendStateless } from "./Auth.js";

// ==============================
// SEND STATELESS
// ==============================
document.getElementById("btn-stateless").addEventListener("click", async () => {
  const url = document.getElementById("stateless-url").value.trim();
  const packetText = document.getElementById("stateless-packet").value;
  const filesInput = document.getElementById("stateless-files");

  let data;
  try {
    data = packetText ? JSON.parse(packetText) : {};
  } catch {
    setStatus("JSON invalido", "error");
    return;
  }

  setStatus("sendStateless...");
  try {
    const files = await filesInputToPacketFiles(filesInput);
    const resp = await sendStateless(url, data, files);

    appendLog("sendStateless(url,data,files)", resp, false);
    setStatus("sendStateless ok", "ok");
  } catch (err) {
    appendLog(
      "sendStateless(url,data,files)",
      { message: String(err) },
      true
    );
    setStatus("sendStateless error", "error");
  }
});

// ==============================
// SEND STATEFUL
// ==============================
document.getElementById("btn-stateful").addEventListener("click", async () => {
  const url = document.getElementById("stateful-url").value.trim();
  const packetText = document.getElementById("stateful-packet").value;
  const filesInput = document.getElementById("stateful-files");

  let data;
  try {
    data = packetText ? JSON.parse(packetText) : {};
  } catch {
    setStatus("JSON invalido", "error");
    return;
  }

  setStatus("sendStateful...");
  try {
    const files = await filesInputToPacketFiles(filesInput);
    const resp = await sendStateful(url, data, files);

    appendLog("sendStateful(url,data,files)", resp, false);
    setStatus("sendStateful ok", "ok");
  } catch (err) {
    appendLog(
      "sendStateful(url,data,files)",
      { message: String(err) },
      true
    );
    setStatus("sendStateful error", "error");
  }
});


// Limpiar log
document.getElementById("btn-clear-log").addEventListener("click", () => {
    logOutput.textContent = "";
    setStatus("idle");
});