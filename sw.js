// installability + push notifications; nothing is cached (all live data)
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()))
// GET-only pass-through: intercepting POSTs breaks their bodies (this killed
// terminal input and PIN login once the SW took control of the page)
self.addEventListener('fetch', e => { if (e.request.method !== 'GET') return })

self.addEventListener('push', e => {
  let p = {}
  try { p = e.data.json() } catch {}
  e.waitUntil(self.registration.showNotification(p.title || 'Solo Remote', {
    body: p.body || '',
    tag: p.tag,
    icon: new URL('/icons/icon-192.png', self.registration.scope).href,
    badge: new URL('/icons/badge-96.png', self.registration.scope).href,
    data: { procId: p.procId },
  }))
})

self.addEventListener('notificationclick', e => {
  e.notification.close()
  const target = '/' + (e.notification.data?.procId ? '#agent-' + e.notification.data.procId : '')
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) if ('focus' in c) { c.navigate(target); return c.focus() }
    return clients.openWindow(target)
  }))
})
