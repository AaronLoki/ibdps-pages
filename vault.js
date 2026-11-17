const bytes = new TextEncoder();

function openVault() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("ibdps-vault", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("keys");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function vault(operation, id, value) {
  const db = await openVault();
  const readOnly = operation === "get";
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction("keys", readOnly ? "readonly" : "readwrite");
      const store = tx.objectStore("keys");
      const request = operation === "put" || operation === "add"
        ? store[operation](value, id)
        : store[operation](id);
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export async function hexDigest(text) {
  const hash = await crypto.subtle.digest("SHA-256", bytes.encode(text));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
}

export function unpack(value) {
  return Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), char => char.charCodeAt(0));
}

export function pack(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function decode(key, encrypted, label) {
  return crypto.subtle.decrypt({
    name: "AES-GCM",
    iv: encrypted.slice(0, 12),
    additionalData: bytes.encode(label),
  }, key, encrypted.slice(12));
}

const curve = { name: "ECDH", namedCurve: "P-256" };

async function wrappingKey(privateKey, peerCode, salt, usage) {
  const peer = await crypto.subtle.importKey("raw", unpack(peerCode), curve, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256);
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({
    name: "HKDF",
    hash: "SHA-256",
    salt: bytes.encode(salt),
    info: bytes.encode("ibdps-language-access-v1"),
  }, material, { name: "AES-GCM", length: 256 }, false, [usage]);
}

export async function openGrant(device, grant, label, salt) {
  const key = await wrappingKey(device.privateKey, grant.peer, salt, "decrypt");
  return decode(key, unpack(grant.data), label);
}

export async function sealGrant(recipient, raw, label, salt) {
  const sender = await crypto.subtle.generateKey(curve, false, ["deriveBits"]);
  const key = await wrappingKey(sender.privateKey, recipient, salt, "encrypt");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await crypto.subtle.encrypt({
    name: "AES-GCM", iv, additionalData: bytes.encode(label),
  }, key, raw));
  const result = new Uint8Array(iv.length + data.length);
  result.set(iv);
  result.set(data, iv.length);
  return { peer: pack(await crypto.subtle.exportKey("raw", sender.publicKey)), data: pack(result) };
}

export function readKey(raw) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
}
