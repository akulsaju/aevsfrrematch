// Username footprint checker: runs profile-URL checks against many sites (definitions derived from the
// MIT-licensed Sherlock project, validated by tools/validate-sites.js).
const fs = require('fs');
const path = require('path');

const SITES_FILE = path.join(__dirname, 'sites.json');
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

function loadSites() {
  try { return JSON.parse(fs.readFileSync(SITES_FILE, 'utf8')); } catch { return []; }
}

const fill = (s, u) => String(s).replaceAll('{}', u);

// Returns 'found' | 'missing' | 'unknown'
async function checkSite(site, username, timeout = 8000) {
  if (site.regex && !new RegExp(site.regex).test(username)) return 'missing';
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const url = fill(site.probe || site.url, username);
    const r = await fetch(url, {
      method: site.method || (site.type === 'status_code' || site.type === 'response_url' ? 'GET' : 'GET'),
      headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9', ...(site.headers || {}) },
      redirect: site.type === 'response_url' ? 'manual' : 'follow', signal: ctl.signal,
    });
    if (site.type === 'status_code') {
      if (r.status >= 200 && r.status < 300) return 'found';
      if (r.status === 404 || r.status === 410 || r.status === 400) return 'missing';
      return 'unknown'; // 403/429/5xx: blocked or rate-limited, cannot tell
    }
    if (site.type === 'response_url') return r.status >= 200 && r.status < 300 ? 'found' : (r.status >= 300 && r.status < 400 ? 'missing' : 'unknown');
    if (r.status === 429 || r.status >= 500) return 'unknown';
    const body = (await r.text()).slice(0, 400000);
    if (site.type === 'has') return body.includes(site.has) ? 'found' : 'missing';
    const msgs = [].concat(site.msg);
    if (msgs.some(m => body.includes(m))) return 'missing';
    return r.status >= 200 && r.status < 300 ? 'found' : 'missing';
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
    const status = left < 1500 ? 'unknown' : await checkSite(s, username, Math.min(7000, left));
    onProgress && onProgress(++done, sites.length, status === 'found' ? s : null);
    return { site: s, status };
  });
  return { total: sites.length, results: res, manual: MANUAL.map(m => ({ name: m.name, url: fill(m.url, username) })) };
}

module.exports = { checkSite, scanUsername, loadSites, pool };
