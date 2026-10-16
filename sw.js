// Mailbord offline — service worker
// App shell: served from cache, refreshed in the background.
// data/index.bin + data/keys.json: network first (short timeout), cache as fallback.
// data/m/* and data/a/*: content-addressed, so cache first and never refetched.
const SHELL = 'mb-shell-v1';
const DATA = 'mb-data-v1';
const FONTS = 'mb-fonts-v1';
const SHELL_FILES = ['./', 'index.html', 'app.js', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png',
  'vendor/pdf.min.js', 'vendor/pdf.worker.min.js'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(SHELL).then(c => c.addAll(SHELL_FILES)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keep = [SHELL, DATA, FONTS];
    for (const k of await caches.keys()) if (!keep.includes(k)) await caches.delete(k);
    await self.clients.claim();
  })());
});

const timeout = (ms) => new Promise((_, bad) => setTimeout(() => bad(new Error('timeout')), ms));

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  if (url.host === 'fonts.googleapis.com' || url.host === 'fonts.gstatic.com') {
    e.respondWith(caches.open(FONTS).then(async c => (await c.match(req)) || fetch(req).then(r => { c.put(req, r.clone()); return r; })));
    return;
  }
  if (url.origin !== self.location.origin) return;
  const path = url.pathname;

  if (/\/data\/(m|a)\//.test(path)) {
    e.respondWith(caches.open(DATA).then(async c => {
      const hit = await c.match(req, { ignoreSearch: true });
      if (hit) return hit;
      const r = await fetch(req);
      if (r.ok) c.put(req, r.clone());
      return r;
    }));
    return;
  }
  if (/\/data\/(index\.bin|keys\.json)$/.test(path)) {
    e.respondWith(caches.open(DATA).then(async c => {
      try {
        const r = await Promise.race([fetch(req, { cache: 'no-store' }), timeout(6000)]);
        if (r.ok) { await c.put(req.url.split('?')[0], r.clone()); return r; }
        throw new Error('status ' + r.status);
      } catch (err) {
        const hit = await c.match(req.url.split('?')[0]);
        if (hit) { const h = new Headers(hit.headers); h.set('x-from-cache', '1'); return new Response(await hit.arrayBuffer(), { status: 200, headers: h }); }
        throw err;
      }
    }));
    return;
  }
  // app shell: cache first, refresh in background
  e.respondWith(caches.open(SHELL).then(async c => {
    const hit = await c.match(req, { ignoreSearch: true });
    const net = fetch(req).then(r => { if (r.ok) c.put(req, r.clone()); return r; }).catch(() => null);
    return hit || (await net) || c.match('index.html');
  }));
});
