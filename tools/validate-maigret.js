// Builds sites-maigret.json from Maigret's database (MIT, https://github.com/soxoj/maigret).
// Usage: node tools/validate-maigret.js <maigret data.json> [out.json]
// A site is kept only if its known-claimed username is "found" AND a random one is "missing", using the same
// rules the live scanner applies (checkSite, type "mg"), so every kept site demonstrably distinguishes the two.
const fs = require('fs');
const path = require('path');
const { checkSite, pool } = require('../footprint');

const src = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const OUT = process.argv[3] || path.join(__dirname, '..', 'sites-maigret.json');
const existing = new Set();
for (const f of ['sites.json', 'sites-wmn.json']) {
  try { for (const s of JSON.parse(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'))) { try { existing.add(new URL(s.home || s.url.replace('{}', 'x')).hostname.replace(/^www\./, '')); } catch { } } } catch { }
}
const SKIP_TAGS = new Set(['porn', 'adult', 'erotic', 'dating-adult']);
const host = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return null; } };

const cands = [];
const seenHost = new Set(existing);
for (const [name, raw] of Object.entries(src.sites)) {
  const eng = raw.engine && src.engines[raw.engine] ? src.engines[raw.engine].site : {};
  const s = { ...eng, ...raw };
  if (s.disabled || !s.usernameClaimed || !s.usernameUnclaimed || !s.url || !s.checkType) continue;
  if ((s.tags || []).some(t => SKIP_TAGS.has(t)) || s.protection || s.requestMethod === 'POST' || s.requestPayload) continue;
  const fillUrl = t => String(t).replaceAll('{urlMain}', s.urlMain || '').replaceAll('{urlSubpath}', s.urlSubpath || '').replaceAll('{username}', '{}');
  const url = fillUrl(s.url);
  if (!/^https?:\/\//.test(url) || !url.includes('{}')) continue;
  const h = host(s.urlMain || url);
  if (!h || seenHost.has(h)) continue;
  seenHost.add(h);
  const o = { name, url, home: s.urlMain || url.replace('{}', ''), type: 'mg', ck: s.checkType, claimed: s.usernameClaimed, unclaimed: s.usernameUnclaimed };
  if (s.urlProbe) o.probe = fillUrl(s.urlProbe);
  if (s.presenseStrs && s.presenseStrs.length) o.pr = s.presenseStrs;
  if (s.absenceStrs && s.absenceStrs.length) o.ab = s.absenceStrs;
  if (s.ignore403) o.ig403 = true;
  if (s.regexCheck) o.regex = s.regexCheck;
  if (s.headers) o.headers = s.headers;
  if (o.ck === 'message' && !o.pr && !o.ab) continue;
  cands.push(o);
}
console.log('candidates', cands.length);

(async () => {
  let n = 0;
  const tick = () => { if (++n % 250 === 0) console.log('progress', n); };
  const p1 = await pool(cands, 80, async s => { const r = await checkSite(s, s.claimed, 10000); tick(); return r; });
  const stage = cands.filter((_, i) => p1[i] === 'found');
  console.log('claimed found', stage.length);
  n = 0;
  const p2 = await pool(stage, 80, async s => {
    const bad = s.regex && !new RegExp(s.regex).test(s.unclaimed);
    let r = 'missing';
    if (!bad) {
      r = await checkSite({ ...s, regex: undefined }, s.unclaimed, 10000);
      if (r === 'unknown') r = await checkSite({ ...s, regex: undefined }, s.unclaimed, 10000);
    }
    tick(); return r;
  });
  const keep = stage.filter((_, i) => p2[i] === 'missing').map(({ unclaimed, ...s }) => s);
  fs.writeFileSync(OUT, JSON.stringify(keep));
  console.log('validated', keep.length, 'wrote', OUT, Math.round(fs.statSync(OUT).size / 1024) + ' KB');
})();
