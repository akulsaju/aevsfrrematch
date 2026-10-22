// Shared API handler used by both the local server and the Vercel function.
// The server only ever stores opaque ciphertext and relays WebRTC signaling messages.
const crypto = require('crypto');
const store = require('./store');
const { scan } = require('../registries');
const { scanUsername } = require('../footprint');

const PART_MAX = 600 * 1024;
const MAX_PARTS = 40;
const MAX_TTL = 24 * 3600;
const ROOM_TTL = 3600;

const send = (res, code, body, headers = {}) => { res.writeHead(code, { 'Cache-Control': 'no-store', ...headers }); res.end(body); };
const json = (res, code, obj) => send(res, code, JSON.stringify(obj), { 'Content-Type': 'application/json' });

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
const readJson = async (req, limit = 65536) => { try { return JSON.parse((await readBody(req, limit)).toString() || '{}'); } catch { return null; } };
const rand = n => crypto.randomBytes(n).toString('base64url');
const isId = s => /^[A-Za-z0-9_-]{6,64}$/.test(s || '');

async function vault(req, res, url, parts) {
  const [, , id, sub, idx] = parts; // api vault <id> <sub> <idx>
  const q = url.searchParams;

  if (id === 'init' && req.method === 'POST') {
    const ttl = Math.min(Math.max(parseInt(q.get('ttl')) || 3600, 60), MAX_TTL);
    const max = Math.min(Math.max(parseInt(q.get('max')) || 0, 0), 1000);
    const n = parseInt(q.get('parts'));
    if (!(n >= 1 && n <= MAX_PARTS)) return json(res, 413, { error: `File too large (max about ${Math.floor(MAX_PARTS * PART_MAX / 1048576)} MB)` });
    const vid = rand(12), up = rand(16), expires = Date.now() + ttl * 1000;
    await store.set('vm:' + vid, JSON.stringify({ parts: n, max, expires, up, ready: false }), ttl);
    return json(res, 200, { id: vid, up, expires, partSize: PART_MAX });
  }
  if (!isId(id)) return json(res, 400, { error: 'Bad id' });
  const meta = JSON.parse((await store.get('vm:' + id)) || 'null');
  if (!meta) return json(res, 410, { error: 'This link has expired or does not exist.' });
  const ttlLeft = Math.max(1, Math.ceil((meta.expires - Date.now()) / 1000));

  if (sub === 'part' && req.method === 'PUT') {
    if (q.get('up') !== meta.up) return json(res, 403, { error: 'Bad upload token' });
    const i = parseInt(idx);
    if (!(i >= 0 && i < meta.parts)) return json(res, 400, { error: 'Bad part index' });
    let body;
    try { body = await readBody(req, PART_MAX); } catch { return json(res, 413, { error: 'Part too large' }); }
    if (!body.length) return json(res, 400, { error: 'Empty part' });
    await store.set(`vp:${id}:${i}`, body.toString('base64'), ttlLeft);
    return json(res, 200, { ok: true });
  }
  if (sub === 'finish' && req.method === 'POST') {
    if (q.get('up') !== meta.up) return json(res, 403, { error: 'Bad upload token' });
    for (let i = 0; i < meta.parts; i++) if (!(await store.get(`vp:${id}:${i}`))) return json(res, 400, { error: 'Upload incomplete (part ' + i + ' missing)' });
    meta.ready = true;
    await store.set('vm:' + id, JSON.stringify(meta), ttlLeft);
    return json(res, 200, { ok: true });
  }
  if (sub === 'meta' && req.method === 'GET') {
    if (!meta.ready) return json(res, 410, { error: 'This link has expired or does not exist.' });
    const n = await store.incr('vd:' + id, ttlLeft);
    if (meta.max && n > meta.max) return json(res, 410, { error: 'This link has expired, was already used, or never existed.' });
    const token = rand(12);
    await store.set(`vt:${id}:${token}`, '1', 900);
    if (meta.max && n === meta.max) // last allowed download: ciphertext disappears shortly after
      for (let i = 0; i < meta.parts; i++) await store.expire(`vp:${id}:${i}`, 900);
    return json(res, 200, { parts: meta.parts, token, expires: meta.expires });
  }
  if (sub === 'part' && req.method === 'GET') {
    if (!(await store.get(`vt:${id}:${q.get('t')}`))) return json(res, 410, { error: 'Download session expired. Reopen the link.' });
    const b64 = await store.get(`vp:${id}:${parseInt(idx)}`);
    if (!b64) return json(res, 410, { error: 'This link has expired or does not exist.' });
    return send(res, 200, Buffer.from(b64, 'base64'), { 'Content-Type': 'application/octet-stream' });
  }
  if (!sub && req.method === 'DELETE') {
    if (q.get('up') !== meta.up) return json(res, 403, { error: 'Bad upload token' });
    await store.del('vm:' + id, ...Array.from({ length: meta.parts }, (_, i) => `vp:${id}:${i}`));
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: 'Not found' });
}

async function rooms(req, res, url, parts) {
  const [, , code, sub] = parts;
  if (!code && req.method === 'POST') {
    let c;
    do { c = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); } while (await store.get('room:' + c));
    await store.set('room:' + c, '1', ROOM_TTL);
    return json(res, 200, { code: c });
  }
  if (!/^\d{6}$/.test(code || '') || !(await store.get('room:' + code))) return json(res, 404, { error: 'Room not found or expired' });
  const peersOf = async () => (await store.lrange('rp:' + code, 0)) || [];
  const push = (peer, msg) => store.rpush(`ri:${code}:${peer}`, JSON.stringify(msg), ROOM_TTL);

  if (sub === 'join' && req.method === 'POST') {
    const b = await readJson(req); if (!b || !isId(b.peer)) return json(res, 400, { error: 'Bad request' });
    const peers = await peersOf();
    if (!peers.includes(b.peer)) {
      if (peers.length >= 2) return json(res, 409, { error: 'Room is full' });
      await store.rpush('rp:' + code, b.peer, ROOM_TTL);
      for (const p of peers) await push(p, { t: 'peer', peer: b.peer });
    }
    return json(res, 200, { peers: peers.filter(p => p !== b.peer) });
  }
  if (sub === 'poll' && req.method === 'GET') {
    const peer = url.searchParams.get('peer'), after = Math.max(0, parseInt(url.searchParams.get('after')) || 0);
    if (!isId(peer)) return json(res, 400, { error: 'Bad request' });
    const msgs = (await store.lrange(`ri:${code}:${peer}`, after)).map(s => JSON.parse(s));
    return json(res, 200, { msgs, next: after + msgs.length });
  }
  if (sub === 'signal' && req.method === 'POST') {
    const b = await readJson(req); if (!b || !isId(b.from) || !isId(b.to)) return json(res, 400, { error: 'Bad request' });
    const peers = await peersOf();
    if (!peers.includes(b.from) || !peers.includes(b.to)) return json(res, 404, { error: 'Peer not connected' });
    await push(b.to, { t: 'signal', from: b.from, data: b.data });
    return json(res, 200, { ok: true });
  }
  if (sub === 'leave' && req.method === 'POST') {
    const b = await readJson(req); if (!b || !isId(b.peer)) return json(res, 400, { error: 'Bad request' });
    const peers = await peersOf();
    await store.del('rp:' + code);
    for (const p of peers.filter(p => p !== b.peer)) { await store.rpush('rp:' + code, p, ROOM_TTL); await push(p, { t: 'left', peer: b.peer }); }
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: 'Not found' });
}

async function handleApi(req, res, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api', area, ...]
  try {
    const area = parts[1];
    if (area === 'osint' && req.method === 'POST') {
      const body = await readJson(req, 2048); if (!body) return json(res, 400, { error: 'Bad request' });
      try { return json(res, 200, await scan(body.q)); } catch (e) { return json(res, e.status || 502, { error: e.message }); }
    }
    if (area === 'footprint' && req.method === 'POST') {
      const body = await readJson(req, 2048); if (!body) return json(res, 400, { error: 'Bad request' });
      const u = String(body.q || '').trim().replace(/^@/, '').toLowerCase();
      if (!/^[a-z0-9][a-z0-9_.-]{0,38}$/.test(u)) return json(res, 400, { error: 'Enter a valid username (letters, digits, . _ -).' });
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store' });
      const line = o => res.writableEnded || res.write(JSON.stringify(o) + '\n');
      const out = await scanUsername(u, (done, total, hit) => line({ done, total, hit: hit && { name: hit.name, url: hit.url.replaceAll('{}', u) } }));
      line({ final: true, total: out.total, manual: out.manual, unknown: out.results.filter(r => r.status === 'unknown').length });
      return res.end();
    }
    if (area === 'vault' || area === 'rooms') {
      if (process.env.VERCEL && !store.persistent) return json(res, 503, { error: 'Server storage is not configured. Add REDIS_URL (or an Upstash Redis integration) to the Vercel project and redeploy.' });
      return area === 'vault' ? await vault(req, res, url, parts) : await rooms(req, res, url, parts);
    }
    if (area === 'health') return json(res, 200, { ok: true, persistentStore: store.persistent });
    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    if (!res.headersSent) return json(res, 500, { error: 'Server error' });
    res.end();
  }
}

module.exports = { handleApi };
