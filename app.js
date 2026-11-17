import { hexDigest, openGrant, pack, readKey, sealGrant, vault } from "./vault.js";
import { access, describeDevice, devicePublicKey, isOwner, requestIdentity } from "./access.js";

const find = selector => document.querySelector(selector);
const login = find("#login");
const home = find("#home");
const admin = find("#admin");
const adminButton = find("#show-admin");
const resources = find("#resources");
const form = find("#sign-in");
const status = find("#status");
const requestButton = find("#request-access");
const requestStatus = find("#request-status");
const registerForm = find("#register");
const adminStatus = find("#admin-status");
const requestList = find("#request-list");
const notifyButton = find("#enable-notifications");
const validUsername = /^[a-z0-9][a-z0-9_.@+-]{0,63}$/;

let activeSession;
let requestState;
let knownRequests;
let adminRefresh = 0;
let statusRefresh = 0;

function show(session) {
  activeSession = session;
  login.hidden = Boolean(session);
  home.hidden = !session;
  adminButton.hidden = !isOwner(session);
  admin.hidden = true;
  resources.hidden = false;
  knownRequests = undefined;
  if (isOwner(session)) void refreshAdmin();
  else if (!session) void refreshRequest();
}

async function workerReady() {
  if (navigator.serviceWorker.controller) return;
  await new Promise(resolve => {
    const listener = () => {
      if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.removeEventListener("controllerchange", listener);
        resolve();
      }
    };
    navigator.serviceWorker.addEventListener("controllerchange", listener);
    listener();
  });
}

const registration = navigator.serviceWorker.register("/sw.js", { type: "module", updateViaCache: "none" });
registration.catch(() => { status.textContent = "This browser could not start the portal. Reload and try again."; });

function showRequest(state) {
  requestState = state;
  requestButton.hidden = Boolean(state);
  registerForm.hidden = state !== "approved";
  requestStatus.textContent = {
    pending: "Request sent. Check this page for a decision.",
    approved: "Your request was approved. Create your account below.",
    denied: "Your access request was declined.",
    registered: "Your account is ready. You can sign in above.",
  }[state] || "";
}

async function refreshRequest() {
  const sequence = ++statusRefresh;
  const identity = await vault("get", "request");
  if (!identity) return;
  try {
    const current = await access("status", identity);
    if (sequence === statusRefresh && !activeSession) showRequest(current.state);
  } catch (error) {
    if (error.status !== 404 && sequence === statusRefresh && !activeSession && requestState) {
      requestStatus.textContent = "The request inbox is temporarily unavailable. Your request is still saved.";
    }
  }
}

requestButton.addEventListener("click", async () => {
  status.textContent = "";
  requestStatus.textContent = "Sending your request…";
  requestButton.disabled = true;
  ++statusRefresh;
  try {
    const key = await devicePublicKey();
    const identity = await requestIdentity();
    await access("request", { ...identity, key, device: describeDevice() });
    showRequest("pending");
    await refreshRequest();
  } catch (error) {
    requestStatus.textContent = error.message || "The request could not be sent.";
  } finally {
    requestButton.disabled = false;
  }
});

async function signIn(name, password, grant) {
  const device = await vault("get", "device");
  const raw = await openGrant(device, grant, name, password);
  const key = await readKey(raw.slice(0, 32));
  const session = { key, username: name, expires: Date.now() + 8 * 60 * 60_000 };
  if (name === "aaron" && raw.byteLength === 64) {
    session.admin = { archiveKey: raw.slice(0, 32), token: pack(raw.slice(32)) };
  }
  await registration;
  await workerReady();
  await vault("put", "session", session);
  form.reset();
  show(session);
}

async function findGrant(name) {
  const saved = await fetch(`/grants/${await hexDigest(name)}.json`, { cache: "no-store" });
  if (saved.ok) return saved.json();
  if (name === "aaron") throw new Error();
  const identity = await vault("get", "request");
  if (identity) {
    const result = await access("status", identity);
    if (result.state === "registered" && result.username === name) return result.account_grant;
  }
  throw new Error();
}

form.addEventListener("submit", async event => {
  event.preventDefault();
  const values = new FormData(form);
  const name = values.get("username").trim().toLowerCase();
  const password = values.get("password");
  const submit = form.querySelector('[type="submit"]');
  submit.disabled = true;
  status.textContent = "";
  try {
    if (!validUsername.test(name) || !password) throw new Error();
    await signIn(name, password, await findGrant(name));
  } catch {
    status.textContent = "Sign-in failed. Check your username and password and try again.";
  } finally {
    submit.disabled = false;
  }
});

registerForm.addEventListener("submit", async event => {
  event.preventDefault();
  const values = new FormData(registerForm);
  const name = values.get("username").trim().toLowerCase();
  const password = values.get("password");
  const submit = registerForm.querySelector('[type="submit"]');
  submit.disabled = true;
  try {
    if (!validUsername.test(name) || name === "aaron") throw new Error("Choose a different username.");
    if (password.length < 12) throw new Error("Choose a password with at least 12 characters.");
    const identity = await vault("get", "request");
    const current = await access("status", identity);
    if (current.state !== "approved") throw new Error("This request is no longer available for registration.");
    const device = await vault("get", "device");
    const raw = await openGrant(device, current.approval, identity.id, identity.id);
    const grant = await sealGrant(await devicePublicKey(), raw, name, password);
    await access("register", { ...identity, username: name, grant });
    registerForm.reset();
    showRequest("registered");
    await signIn(name, password, grant);
  } catch (error) {
    requestStatus.textContent = error.message || "Registration could not be completed.";
  } finally {
    submit.disabled = false;
  }
});

const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
function renderRequests(requests) {
  requestList.replaceChildren();
  for (const request of requests) {
    const row = document.createElement("article");
    row.className = "request-row";
    const detail = document.createElement("div");
    const label = document.createElement("strong");
    label.textContent = request.device;
    const time = document.createElement("time");
    time.dateTime = request.created_at;
    time.textContent = date.format(new Date(request.created_at));
    detail.append(label, time);

    const controls = document.createElement("div");
    controls.className = "top-actions";
    for (const [label, approve] of [["Yes", true], ["No", false]]) {
      const button = document.createElement("button");
      button.className = "quiet";
      button.type = "button";
      button.textContent = label;
      button.setAttribute("aria-label", `${label}, ${approve ? "approve" : "decline"} request from ${request.device}`);
      button.addEventListener("click", () => decide(request, approve, controls));
      controls.append(button);
    }
    row.append(detail, controls);
    requestList.append(row);
  }
}

async function decide(request, approve, controls) {
  const session = activeSession;
  if (!isOwner(session)) return;
  for (const button of controls.children) button.disabled = true;
  try {
    const grant = approve ? await sealGrant(request.browser_key, session.admin.archiveKey, request.id, request.id) : null;
    if (activeSession !== session || !isOwner(session)) return;
    await access("decide", { owner: session.admin.token, id: request.id, approve, grant });
    await refreshAdmin();
  } catch (error) {
    adminStatus.textContent = error.message || "The decision could not be saved.";
  } finally {
    for (const button of controls.children) button.disabled = false;
  }
}

async function refreshAdmin() {
  const session = activeSession;
  if (!isOwner(session)) return;
  const sequence = ++adminRefresh;
  try {
    const { requests } = await access("list", { owner: session.admin.token });
    if (activeSession !== session || sequence !== adminRefresh || !isOwner(session)) return;
    adminButton.textContent = requests.length ? `Admin (${requests.length})` : "Admin";
    const newer = knownRequests && requests.filter(request => !knownRequests.has(request.id));
    if (newer?.length && globalThis.Notification?.permission === "granted") {
      const ready = await registration;
      void ready.showNotification("New access request", {
        body: newer.length === 1 ? newer[0].device : `${newer.length} requests are waiting for your decision.`,
        tag: "ibdps-access",
      }).catch(() => {});
    }
    knownRequests = new Set(requests.map(request => request.id));
    if (!admin.hidden) {
      adminStatus.textContent = requests.length ? `${requests.length} waiting for a decision` : "No access requests.";
      renderRequests(requests);
    }
  } catch {
    if (activeSession === session && !admin.hidden) adminStatus.textContent = "The request inbox is temporarily unavailable.";
  }
}

adminButton.addEventListener("click", () => {
  if (!isOwner(activeSession)) return;
  admin.hidden = false;
  resources.hidden = true;
  notifyButton.hidden = !globalThis.Notification || Notification.permission !== "default";
  admin.querySelector("h1").focus();
  void refreshAdmin();
});

notifyButton.addEventListener("click", async () => {
  const permission = await Notification.requestPermission();
  notifyButton.hidden = permission !== "default";
});

find("#close-admin").addEventListener("click", () => {
  admin.hidden = true;
  resources.hidden = false;
  adminButton.focus();
});

find("#sign-out").addEventListener("click", async () => {
  await vault("delete", "session");
  show(null);
});

setInterval(() => {
  if (activeSession?.expires <= Date.now()) {
    void vault("delete", "session").then(() => show(null));
  } else if (isOwner(activeSession)) {
    void refreshAdmin();
  } else if (!activeSession && requestState === "pending") {
    void refreshRequest();
  }
}, 20_000);

const currentSession = await vault("get", "session").catch(() => null);
if (currentSession?.expires > Date.now()) {
  await registration;
  await workerReady();
  show(currentSession);
} else {
  show(null);
}
