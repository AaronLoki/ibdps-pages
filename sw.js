import { decode, hexDigest, vault } from "./vault.js";

const mime = {
  html: "text/html; charset=utf-8", pdf: "text/html; charset=utf-8",
  css: "text/css", js: "text/javascript", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
  gif: "image/gif", svg: "image/svg+xml", webp: "image/webp", avif: "image/avif", ico: "image/x-icon",
  woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf", otf: "font/otf", eot: "application/vnd.ms-fontobject",
  mp3: "audio/mpeg", m4a: "audio/mp4", wav: "audio/wav", ogg: "audio/ogg", aac: "audio/aac", vtt: "text/vtt",
};

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", event => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  if (url.origin === self.location.origin && (url.pathname === "/languageseven" || url.pathname.startsWith("/languageseven/"))) {
    event.respondWith(openResource(event.request, url).catch(() => new Response("Resource unavailable", { status: 404 })));
  }
});

self.addEventListener("notificationclick", event => {
  if (event.notification.tag !== "ibdps-access") return;
  event.notification.close();
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const portal = windows.find(window => new URL(window.url).pathname === "/");
    if (portal) await portal.focus();
    else await self.clients.openWindow("/");
  })());
});

async function openResource(request, url) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response(null, { status: 405, headers: { Allow: "GET, HEAD" } });
  }
  const session = await vault("get", "session");
  if (!session || session.expires <= Date.now()) {
    return request.mode === "navigate"
      ? Response.redirect(new URL("/", url), 302)
      : new Response(null, { status: 401 });
  }
  if (url.pathname === "/languageseven") return Response.redirect(new URL("/languageseven/", url), 302);
  let path = decodeURIComponent(url.pathname);
  if (path.endsWith("/")) path += "index.html";
  const format = path.split(".").at(-1).toLowerCase();
  const type = mime[format];
  if (!type) return new Response(null, { status: 404 });
  const saved = await fetch(`/encrypted/${await hexDigest(path)}.bin`);
  if (!saved.ok) return new Response(null, { status: 404 });
  const plain = await decode(session.key, new Uint8Array(await saved.arrayBuffer()), path);
  const headers = new Headers({
    "Cache-Control": "private, no-store",
    "Content-Type": type,
    "Content-Disposition": "inline",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": `default-src 'none'; script-src ${url.origin}/archive.js; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; media-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'`,
  });
  const range = request.headers.get("range");
  if (type.startsWith("audio/") && range) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(range);
    const size = plain.byteLength;
    let start = 0;
    let end = size - 1;
    if (match?.[1]) {
      start = Number(match[1]);
      if (match[2]) end = Math.min(end, Number(match[2]));
    } else if (match?.[2]) {
      start = Math.max(0, size - Number(match[2]));
    } else {
      start = size;
    }
    if (start > end) {
      headers.set("Content-Range", `bytes */${size}`);
      return new Response(null, { status: 416, headers });
    }
    headers.set("Accept-Ranges", "bytes");
    headers.set("Content-Range", `bytes ${start}-${end}/${size}`);
    headers.set("Content-Length", String(end - start + 1));
    return new Response(request.method === "HEAD" ? null : plain.slice(start, end + 1), { status: 206, headers });
  }
  headers.set("Content-Length", String(plain.byteLength));
  return new Response(request.method === "HEAD" ? null : plain, { headers });
}
