import { pack, vault } from "./vault.js";

const OWNER = "aaron";
const endpoint = "https://jlasqtrtugmpoodottpb.supabase.co/functions/v1/ibdps-access";
const BROWSER_CURVE = { name: "ECDH", namedCurve: "P-256" };
const BROWSER_NAMES = [
  [/\bEdg(?:e|A|iOS)?\//, "Edge"],
  [/\bOPR\//, "Opera"],
  [/\bFirefox\/|\bFxiOS\//, "Firefox"],
  [/\bChrome\/|\bCriOS\//, "Chrome"],
  [/\bSafari\//, "Safari"],
];
const PLATFORMS = [
  [/iPad|iPhone|iPod/, "iOS"],
  [/Android/, "Android"],
  [/Windows/, "Windows"],
  [/Mac OS|Macintosh/, "macOS"],
  [/CrOS/, "ChromeOS"],
  [/Linux/, "Linux"],
];

export function isOwner(session, now = Date.now()) {
  return session?.username === OWNER && Boolean(session.admin?.token) && session.expires > now;
}

async function getOrCreate(name, create) {
  const saved = await vault("get", name);
  if (saved) return saved;
  const newValue = await create();
  try {
    await vault("add", name, newValue);
    return newValue;
  } catch (error) {
    if (error?.name !== "ConstraintError") throw error;
    return vault("get", name);
  }
}

export async function devicePublicKey() {
  const device = await getOrCreate("device",
    () => crypto.subtle.generateKey(BROWSER_CURVE, false, ["deriveBits"]));
  return pack(await crypto.subtle.exportKey("raw", device.publicKey));
}

export function describeDevice(browser = navigator) {
  const agent = browser.userAgent || "";
  const platform = PLATFORMS.find(([pattern]) => pattern.test(agent))?.[1] || "Unknown OS";
  const browserName = BROWSER_NAMES.find(([pattern]) => pattern.test(agent))?.[1] || "Unknown browser";
  const touchMac = /Macintosh/.test(agent) && browser.maxTouchPoints > 1;
  let type = "Computer";
  if (touchMac || /iPad|Tablet/.test(agent) || (/Android/.test(agent) && !/Mobile/.test(agent))) {
    type = "Tablet";
  } else if (browser.userAgentData?.mobile || /Mobile|iPhone|iPod/.test(agent)) {
    type = "Phone";
  }
  return `${type} · ${touchMac ? "iPadOS" : platform} · ${browserName}`;
}

export async function access(action, fields) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, ...fields }),
    cache: "no-store",
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || "The request inbox is temporarily unavailable.");
    error.status = response.status;
    throw error;
  }
  return result;
}

export function requestIdentity() {
  return getOrCreate("request", () => ({
    id: crypto.randomUUID(), token: pack(crypto.getRandomValues(new Uint8Array(32))),
  }));
}
