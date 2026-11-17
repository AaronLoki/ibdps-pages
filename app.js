import { hexDigest, pack, unlock, vault } from "./vault.js";

const login = document.querySelector("#login");
const home = document.querySelector("#home");
const form = document.querySelector("#sign-in");
const status = document.querySelector("#status");
const username = document.querySelector("#username");
const requestButton = document.querySelector("#request-access");
const setup = document.querySelector("#setup");
const setupCode = document.querySelector("#setup-code");
const validUsername = /^[a-z0-9][a-z0-9_.@+-]{0,63}$/;

function show(signedIn) {
  login.hidden = signedIn;
  home.hidden = !signedIn;
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

const currentSession = await vault("get", "session").catch(() => null);
if (currentSession?.expires > Date.now()) {
  await registration;
  await workerReady();
  show(true);
}

requestButton.addEventListener("click", async () => {
  status.textContent = "";
  requestButton.disabled = true;
  try {
    let device = await vault("get", "device");
    if (!device) {
      device = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      await vault("put", "device", device);
    }
    const publicKey = await crypto.subtle.exportKey("raw", device.publicKey);
    setupCode.value = pack(publicKey);
    setup.hidden = false;
    setupCode.select();
  } catch {
    status.textContent = "Access setup is unavailable. Try a regular browser window.";
  } finally {
    requestButton.disabled = false;
  }
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  const loginName = username.value.trim().toLowerCase();
  const password = new FormData(form).get("password");
  const submit = form.querySelector('[type="submit"]');
  submit.disabled = true;
  status.textContent = "";
  try {
    if (!validUsername.test(loginName) || typeof password !== "string" || !password) throw new Error();
    const device = await vault("get", "device");
    if (!device) throw new Error();
    const grant = await fetch(`/grants/${await hexDigest(loginName)}.json`, { cache: "no-store" });
    if (!grant.ok) throw new Error();
    const key = await unlock(device, await grant.json(), loginName, password);
    await registration;
    await workerReady();
    await vault("put", "session", { key, expires: Date.now() + 8 * 60 * 60_000 });
    form.reset();
    setup.hidden = true;
    show(true);
  } catch {
    status.textContent = "Sign-in failed. Check your username and password and try again.";
  } finally {
    submit.disabled = false;
  }
});

document.querySelector("#sign-out").addEventListener("click", async () => {
  await vault("delete", "session");
  show(false);
});
