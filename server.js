// Zero-dependency server. It stores only opaque ciphertext and relays WebRTC
// signaling messages; it never receives encryption keys or file plaintext.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const MAX_BLOB = 50 * 1024 * 1024;
const MAX_TTL = 24 * 3600 * 1000;
const ROOM_TTL = 10 * 60 * 1000;

const vault = new Map(); // id -> {data, expires, downloads, maxDownloads}
const rooms = new Map(); // code -> {peers: Map(peerId -> res), queue: Map, expires}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };

function send(res, code, body, headers = {}) {
  res.writeHead(code, { 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}
const json = (res, code, obj) => send(res, code, JSON.stringify(obj), { 'Content-Type': 'application/json' });

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Mock public registries. The client sends only a SHA-256 hash of the identifier,
// so the raw email/handle never leaves the browser; results are deterministic.
const SOURCES = [
  { id: 'breach-db', name: 'MockBreach Database', type: 'Data breach', severity: 30, detail: 'Credentials found in a leaked dataset (hashed passwords + email).', fix: 'Change the password everywhere it was reused, enable a password manager and 2FA.' },
  { id: 'broker', name: 'PeopleFinderMock (data broker)', type: 'Data broker', severity: 22, detail: 'Profile listing name, city and age range.', fix: 'Submit an opt-out request at the broker\'s "Do not sell/Remove my info" page and confirm via email.' },
  { id: 'social', name: 'SocialGraph public profile', type: 'Social media', severity: 14, detail: 'Public profile indexable by search engines.', fix: 'Set the profile to private and disable "Allow search engines to link to your profile".' },
  { id: 'paste', name: 'PasteDump archive', type: 'Paste site', severity: 25, detail: 'Identifier appears in a public text paste.', fix: 'Request removal via the paste site abuse form and rotate any exposed secrets.' },
  { id: 'whois', name: 'WHOIS registry', type: 'Domain registry', severity: 12, detail: 'Contact details visible in domain registration.', fix: 'Enable WHOIS privacy/proxy service with your registrar.' },
  { id: 'code', name: 'CodeHub commit history', type: 'Code hosting', severity: 10, detail: 'Email present in public commit metadata.', fix: 'Use the no-reply commit address and rewrite history for sensitive repos.' },
  { id: 'forum', name: 'OldForum archive', type: 'Forum', severity: 8, detail: 'Legacy forum account with public post history.', fix: 'Delete the account or request GDPR/CCPA erasure from the forum admin.' },
];

function osint(hash) {
  const bytes = Buffer.from(hash, 'hex');
  return SOURCES.filter((_, i) => bytes[i] % 100 < 45).map(s => ({ ...s }));
}

function cleanup() {
  const now = Date.now();
  for (const [k, v] of vault) if (v.expires < now) vault.delete(k);
  for (const [k, r] of rooms) if (r.expires < now) {
    for (const res of r.peers.values()) res.end();
    rooms.delete(k);
  }
}
setInterval(cleanup, 15000).unref();

async function api(req, res, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api', ...]
  const [, a, b, c] = parts;

  if (a === 'osint' && req.method === 'GET') {
    const h = url.searchParams.get('h') || '';
    if (!/^[0-9a-f]{64}$/.test(h)) return json(res, 400, { error: 'Invalid identifier hash' });
    await new Promise(r => setTimeout(r, 600)); // simulate registry latency
    return json(res, 200, { findings: osint(h) });
  }

  if (a === 'vault') {
    if (req.method === 'POST' && !b) {
      const ttl = Math.min(Math.max(parseInt(url.searchParams.get('ttl')) || 3600000, 60000), MAX_TTL);
      const maxDownloads = Math.min(parseInt(url.searchParams.get('max')) || 0, 1000);
      let data;
      try { data = await readBody(req, MAX_BLOB); } catch { return json(res, 413, { error: 'File too large (50 MB max)' }); }
      if (!data.length) return json(res, 400, { error: 'Empty upload' });
      const id = crypto.randomBytes(12).toString('base64url');
      vault.set(id, { data, expires: Date.now() + ttl, downloads: 0, maxDownloads });
      return json(res, 200, { id, expires: Date.now() + ttl });
    }
    const item = b && vault.get(b);
    if (b && req.method === 'GET') {
      if (!item || item.expires < Date.now()) { vault.delete(b); return json(res, 410, { error: 'This link has expired or does not exist.' }); }
      item.downloads++;
      const body = item.data;
      if (item.maxDownloads && item.downloads >= item.maxDownloads) vault.delete(b);
      return send(res, 200, body, { 'Content-Type': 'application/octet-stream', 'X-Expires': String(item.expires) });
    }
    if (b && req.method === 'DELETE') { vault.delete(b); return json(res, 200, { ok: true }); }
  }

  if (a === 'rooms') {
    if (req.method === 'POST' && !b) {
      let code;
      do { code = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); } while (rooms.has(code));
      rooms.set(code, { peers: new Map(), queue: new Map(), expires: Date.now() + ROOM_TTL });
      return json(res, 200, { code });
    }
    const room = b && rooms.get(b);
    if (!room) return json(res, 404, { error: 'Room not found or expired' });
    if (c === 'events' && req.method === 'GET') {
      const peer = url.searchParams.get('peer');
      if (!peer) return json(res, 400, { error: 'peer required' });
      if (!room.peers.has(peer) && room.peers.size >= 2) return json(res, 409, { error: 'Room is full' });
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
      room.peers.set(peer, res);
      const send_ = (ev, d) => res.write(`event: ${ev}\ndata: ${JSON.stringify(d)}\n\n`);
      send_('hello', { peers: [...room.peers.keys()].filter(p => p !== peer) });
      for (const [other, r] of room.peers) if (other !== peer) r.write(`event: peer\ndata: ${JSON.stringify({ peer })}\n\n`);
      const hb = setInterval(() => res.write(': hb\n\n'), 20000);
      req.on('close', () => {
        clearInterval(hb);
        if (room.peers.get(peer) === res) room.peers.delete(peer);
        for (const r of room.peers.values()) r.write(`event: left\ndata: ${JSON.stringify({ peer })}\n\n`);
      });
      return;
    }
    if (c === 'signal' && req.method === 'POST') {
      let msg;
      try { msg = JSON.parse((await readBody(req, 65536)).toString()); } catch { return json(res, 400, { error: 'Bad JSON' }); }
      const target = room.peers.get(msg.to);
      if (!target) return json(res, 404, { error: 'Peer not connected' });
      target.write(`event: signal\ndata: ${JSON.stringify({ from: msg.from, data: msg.data })}\n\n`);
      return json(res, 200, { ok: true });
    }
  }
  json(res, 404, { error: 'Not found' });
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    let p = url.pathname === '/' ? '/index.html' : url.pathname;
    const file = path.normalize(path.join(PUBLIC, p));
    if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, 'Forbidden');
    fs.readFile(file, (err, data) => {
      if (err) return send(res, 404, 'Not found');
      send(res, 200, data, {
        'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
        'Referrer-Policy': 'no-referrer', // never leak URL hash/keys
      });
    });
  } catch (e) { json(res, 500, { error: 'Server error' }); }
}).listen(PORT, () => console.log(`Privacy suite on http://localhost:${PORT}`));
