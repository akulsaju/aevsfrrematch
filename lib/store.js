// Key/value store. Uses Redis when configured (REDIS_URL over TCP, or Upstash REST), which works on
// serverless; otherwise an in-memory Map for local development.
const REDIS_URL = process.env.REDIS_URL;
const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const persistent = !!(REDIS_URL || (URL_ && TOKEN));

let client = null; // reused across warm serverless invocations
async function tcp() {
  if (client && client.isOpen) return client;
  const { createClient } = require('redis');
  client = createClient({ url: REDIS_URL, socket: { connectTimeout: 8000, reconnectStrategy: false } });
  client.on('error', () => { });
  await client.connect();
  return client;
}

async function cmd(...args) {
  if (REDIS_URL) return (await tcp()).sendCommand(args.map(String));
  const r = await fetch(URL_, { method: 'POST', headers: { Authorization: 'Bearer ' + TOKEN }, body: JSON.stringify(args.map(String)) });
  const d = await r.json();
  if (!r.ok || d.error) throw new Error('store: ' + (d.error || r.status));
  return d.result;
}

const mem = new Map(); // key -> {v, exp}
const live = k => { const e = mem.get(k); if (e && e.exp < Date.now()) { mem.delete(k); return null; } return e || null; };
const exp = s => Date.now() + s * 1000;

const store = persistent ? {
  persistent,
  set: (k, v, ttl) => cmd('SET', k, v, 'EX', ttl),
  get: k => cmd('GET', k),
  del: (...k) => k.length ? cmd('DEL', ...k) : 0,
  expire: (k, ttl) => cmd('EXPIRE', k, ttl),
  incr: async (k, ttl) => { const n = await cmd('INCR', k); if (n === 1) await cmd('EXPIRE', k, ttl); return n; },
  rpush: async (k, v, ttl) => { const n = await cmd('RPUSH', k, v); await cmd('EXPIRE', k, ttl); return n; },
  lrange: (k, start) => cmd('LRANGE', k, start, -1),
} : {
  persistent,
  async set(k, v, ttl) { mem.set(k, { v, exp: exp(ttl) }); },
  async get(k) { const e = live(k); return e ? e.v : null; },
  async del(...k) { k.forEach(x => mem.delete(x)); },
  async expire(k, ttl) { const e = live(k); if (e) e.exp = Math.min(e.exp, exp(ttl)); },
  async incr(k, ttl) { const e = live(k); const n = (e ? e.v : 0) + 1; mem.set(k, { v: n, exp: e ? e.exp : exp(ttl) }); return n; },
  async rpush(k, v, ttl) { const e = live(k) || { v: [], exp: exp(ttl) }; e.v.push(v); mem.set(k, e); return e.v.length; },
  async lrange(k, start) { const e = live(k); return e ? e.v.slice(start) : []; },
};

if (!persistent) setInterval(() => { for (const k of mem.keys()) live(k); }, 30000).unref();

module.exports = store;
