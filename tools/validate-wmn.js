// Usage: node tools/validate-wmn.js <path-to-wmn-data.json>
// Source: WhatsMyName project (CC BY-SA 4.0), https://github.com/WebBreacher/WhatsMyName
// Keeps only sites where a known user is found AND a random user is reported missing,
// skipping sites already covered by sites.json, POST-based checks, bot-protected and adult sites.
const fs = require('fs');
const path = require('path');
const { checkSite, pool } = require('../footprint');

const src = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const existing = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'sites.json'), 'utf8'));
const host = u => { try { return new URL(u.replace('{}', 'x').replace('{account}', 'x')).hostname.replace(/^www\./, ''); } catch { return ''; } };
const have = new Set(existing.map(s => host(s.url)));
const random = 'zq' + Math.random().toString(36).slice(2, 12) + 'xk';

const cands = [];
for (const w of src.sites) {
  if (w.valid === false || w.post_body || w.cat === 'xx' || (w.protection && w.protection.length)) continue;
  if (!w.uri_check || !w.uri_check.includes('{account}') || !w.known || !w.known.length) continue;
  if (!w.e_code || !w.m_code || w.e_code === w.m_code) continue;
  const h = host(w.uri_check); if (!h || have.has(h)) continue;
  have.add(h);
  const s = { name: w.name, url: w.uri_check.replaceAll('{account}', '{}'), home: new URL(w.uri_check.replace('{account}', 'x')).origin + '/', type: 'wmn', ec: w.e_code, mc: w.m_code, claimed: w.known[0] };
  if (w.e_string) s.es = w.e_string;
  if (w.m_string) s.ms = w.m_string;
  if (w.headers) s.headers = w.headers;
  cands.push(s);
}

(async () => {
  console.log('candidates', cands.length);
  const out = await pool(cands, 25, async s => {
    const a = await checkSite(s, s.claimed, 12000), b = await checkSite(s, random, 12000);
    return { s, a, b, ok: a === 'found' && b === 'missing' };
  });
  const good = out.filter(o => o.ok).map(o => o.s).sort((x, y) => x.name.localeCompare(y.name));
  fs.writeFileSync(path.join(__dirname, '..', 'sites-wmn.json'), JSON.stringify(good.map(({ claimed, ...r }) => r), null, 1));
  console.log('validated', good.length);
  console.log('rejected:', out.filter(o => !o.ok).map(o => `${o.s.name}[${o.a}/${o.b}]`).join(' '));
})();
