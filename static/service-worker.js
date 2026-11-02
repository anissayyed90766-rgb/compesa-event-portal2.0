// Bump this version whenever app.js/style.css/index.html change, so visitors
// get the update instead of being stuck on an old cached copy forever.
const CACHE = 'compesa-v3';
const CORE_ASSETS = ['/', '/static/style.css', '/static/app.js'];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE_ASSETS)).catch(() => {}));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Network-first: always try the live server first so a bugfix or redeploy is
// visible immediately. Only fall back to the cached copy when the network
// request fails (e.g. the visitor is offline).
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request)
      .then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
