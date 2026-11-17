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
      const request = operation === "put" ? store.put(value, id) : store[operation](id);
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

export async function unlock(device, grant, username, password) {
  const curve = { name: "ECDH", namedCurve: "P-256" };
  const peer = await crypto.subtle.importKey("raw", unpack(grant.peer), curve, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, device.privateKey, 256);
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const wrappingKey = await crypto.subtle.deriveKey({
    name: "HKDF",
    hash: "SHA-256",
    salt: bytes.encode(password),
    info: bytes.encode("ibdps-language-access-v1"),
  }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const courseKey = await decode(wrappingKey, unpack(grant.data), username);
  return crypto.subtle.importKey("raw", courseKey, "AES-GCM", false, ["decrypt"]);
}
