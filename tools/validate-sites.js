// Usage: node tools/validate-sites.js <path-to-sherlock-data.json>
// Keeps only sites where a known user is found AND a random user is reported missing.
const fs = require('fs');
const path = require('path');
const { checkSite, pool } = require('../footprint');

const src = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const random = 'zq' + Math.random().toString(36).slice(2, 12) + 'xk';

function convert(name, d) {
  if (!['status_code', 'message', 'response_url'].includes(d.errorType)) return null;
  if (d.request_method && d.request_method !== 'GET') return null;
  if (d.request_payload) return null;
  const s = { name, url: d.url, home: d.urlMain, type: d.errorType, claimed: d.username_claimed };
  if (d.urlProbe) s.probe = d.urlProbe;
  if (d.regexCheck) s.regex = d.regexCheck;
  if (d.headers) s.headers = d.headers;
  if (d.errorType === 'message') { if (!d.errorMsg) return null; s.msg = d.errorMsg; }
  return s;
}

(async () => {
  const cands = Object.entries(src).filter(([k]) => k[0] !== '$').map(([k, v]) => convert(k, v)).filter(Boolean);
  const custom = JSON.parse(fs.readFileSync(path.join(__dirname, 'custom-sites.json'), 'utf8'));
  const names = new Set(custom.map(c => c.name.toLowerCase()));
  cands.splice(0, cands.length, ...cands.filter(c => !names.has(c.name.toLowerCase())), ...custom);
  console.log('candidates', cands.length);
  const out = await pool(cands, 20, async s => {
    const a = await checkSite(s, s.claimed, 12000), b = await checkSite(s, random, 12000);
    return { s, a, b, ok: a === 'found' && b === 'missing' };
  });
  const good = out.filter(o => o.ok).map(o => o.s).sort((x, y) => x.name.localeCompare(y.name));
  fs.writeFileSync(path.join(__dirname, '..', 'sites.json'), JSON.stringify(good.map(({ claimed, ...r }) => r), null, 1));
  console.log('validated', good.length);
  console.log('rejected:', out.filter(o => !o.ok).map(o => `${o.s.name}[${o.a}/${o.b}]`).join(' '));
})();
