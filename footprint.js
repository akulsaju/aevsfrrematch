// Username footprint checker: runs profile-URL checks against many sites (definitions derived from the
// MIT-licensed Sherlock project, validated by tools/validate-sites.js).
const fs = require('fs');
const path = require('path');

const SITES_FILES = ['sites.json', 'sites-wmn.json'].map(f => path.join(__dirname, f));
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

function loadSites() {
  const out = [];
  for (const f of SITES_FILES) { try { out.push(...JSON.parse(fs.readFileSync(f, 'utf8'))); } catch { } }
  return out;
}

const fill = (s, u) => String(s).replaceAll('{}', u);

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', trade: '™', copy: '©', reg: '®', hellip: '…', mdash: '—', ndash: '–', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', middot: '·', bull: '•', raquo: '»', laquo: '«' };
function clean(s, max) {
  const t = String(s || '')
    .replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => {
      if (e[0] === '#') { const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(n); } catch { return ''; } }
      return ENT[e.toLowerCase()] ?? m;
    })
    .replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max - 1) + '…' : t;
}
// Public page metadata (title / description) shown to the user as "what was found".
function pageInfo(html) {
  const head = String(html).slice(0, 200000);
  const tag = n => {
    const a = head.match(new RegExp(`<meta[^>]+(?:property|name)=["']${n}["'][^>]*?content=["']([^"']*)["']`, 'i'));
    const b = head.match(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]*?(?:property|name)=["']${n}["']`, 'i'));
    return (a || b || [])[1] || '';
  };
  const t = head.match(/<title[^>]*>([^<]*)<\/title>/i);
  const title = clean(tag('og:title') || (t && t[1]) || '', 120);
  const description = clean(tag('og:description') || tag('description') || tag('twitter:description'), 280);
  const info = {};
  if (title) info.title = title;
  if (description) info.description = description;
  return info;
}

// Returns 'found' | 'missing' | 'unknown'. When found, `info` receives the page title/description.
async function checkSite(site, username, timeout = 8000, info = {}) {
  if (site.regex && !new RegExp(site.regex).test(username)) return 'missing';
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const url = fill(site.probe || site.url, username);
    const r = await fetch(url, {
      method: site.method || (site.type === 'status_code' || site.type === 'response_url' ? 'GET' : 'GET'),
      headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9', ...(site.headers || {}) },
      redirect: site.type === 'response_url' || (site.type === 'wmn' && (site.ec >= 300 || site.mc >= 300)) ? 'manual' : 'follow', signal: ctl.signal,
    });
    if (site.type === 'wmn') {
      const body = (await r.text()).slice(0, 400000);
      const missing = r.status === site.mc || (site.ms && body.includes(site.ms));
      if (r.status === site.ec && (!site.es || body.includes(site.es)) && !(site.ms && body.includes(site.ms))) { Object.assign(info, pageInfo(body)); return 'found'; }
      return missing ? 'missing' : 'unknown';
    }
    if (site.type === 'status_code') {
      if (r.status >= 200 && r.status < 300) { try { Object.assign(info, pageInfo((await r.text()).slice(0, 200000))); } catch { } return 'found'; }
      if (r.status === 404 || r.status === 410 || r.status === 400) return 'missing';
      return 'unknown'; // 403/429/5xx: blocked or rate-limited, cannot tell
    }
    if (site.type === 'response_url') {
      if (r.status >= 200 && r.status < 300) { try { Object.assign(info, pageInfo((await r.text()).slice(0, 200000))); } catch { } return 'found'; }
      return r.status >= 300 && r.status < 400 ? 'missing' : 'unknown';
    }
    if (r.status === 429 || r.status >= 500) return 'unknown';
    const body = (await r.text()).slice(0, 400000);
    if (site.type === 'has') { if (!body.includes(site.has)) return 'missing'; Object.assign(info, pageInfo(body)); return 'found'; }
    const msgs = [].concat(site.msg);
    if (msgs.some(m => body.includes(m))) return 'missing';
    if (r.status >= 200 && r.status < 300) { Object.assign(info, pageInfo(body)); return 'found'; }
    return 'missing';
  } catch { return 'unknown'; }
  finally { clearTimeout(t); }
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}

const MANUAL = [
  ['Instagram', 'https://www.instagram.com/{}/'], ['Facebook', 'https://www.facebook.com/{}'], ['Reddit', 'https://www.reddit.com/user/{}'],
  ['Threads', 'https://www.threads.net/@{}'], ['LinkedIn', 'https://www.linkedin.com/in/{}'], ['Spotify', 'https://open.spotify.com/user/{}'],
].map(([name, url]) => ({ name, url }));

async function scanUsername(username, onProgress) {
  const sites = loadSites();
  let done = 0;
  const deadline = Date.now() + (parseInt(process.env.SCAN_DEADLINE_MS) || 48000);
  const res = await pool(sites, 60, async s => {
    const left = deadline - Date.now();
    const info = {};
    const status = left < 1500 ? 'unknown' : await checkSite(s, username, Math.min(7000, left), info);
    onProgress && onProgress(++done, sites.length, status === 'found' ? { ...s, info } : null);
    return { site: s, status };
  });
  return { total: sites.length, results: res, manual: MANUAL.map(m => ({ name: m.name, url: fill(m.url, username) })) };
}

module.exports = { checkSite, scanUsername, loadSites, pool };
