'use strict';
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
const fmt = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const msg = (el, text, cls = 'info') => { el.innerHTML = ''; if (!text) return; const d = document.createElement('div'); d.className = 'msg ' + cls; d.textContent = text; el.append(d); };
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const setFile = (input, file) => { const dt = new DataTransfer(); dt.items.add(file); input.files = dt.files; input.dispatchEvent(new Event('change')); };

/* ---------- Navigation ---------- */
function show(tab) {
  document.querySelectorAll('section').forEach(s => s.classList.toggle('active', s.id === tab));
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
}
$('nav').onclick = e => { const b = e.target.closest('button[data-tab]'); b && show(b.dataset.tab); };

/* ---------- 1. OSINT audit ---------- */
let lastReport = null;
async function footprintScan(username) {
  $('aprog').hidden = false; $('aprogText').textContent = 'Checking profiles…';
  const r = await fetch('/api/footprint', { method: 'POST', body: JSON.stringify({ q: username }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'Footprint scan failed');
  const reader = r.body.getReader(), td = new TextDecoder(); let buf = '', hits = [], fin = null, last = { done: 0, total: 0 };
  for (;;) {
    const { value, done } = await reader.read(); if (done) break;
    buf += td.decode(value, { stream: true });
    let i; while ((i = buf.indexOf('\n')) >= 0) {
      const l = buf.slice(0, i); buf = buf.slice(i + 1); if (!l) continue;
      const m = JSON.parse(l);
      if (m.final) fin = m;
      else {
        last = m; if (m.hit) hits.push(m.hit);
        $('abar').style.width = (m.done / m.total * 100) + '%';
        $('aprogText').textContent = `Checked ${m.done}/${m.total} sites · ${hits.length} profile(s) found`;
      }
    }
  }
  if (!fin) throw new Error('Footprint scan was interrupted (network drop). Retry.');
  hits.sort((a, b) => a.name.localeCompare(b.name));
  return { hits, total: fin.total, checked: fin.total - fin.unknown, unknown: fin.unknown, manual: fin.manual };
}
function footprintFinding(hits, checked) {
  const n = hits.length, sev = Math.min(35, Math.round(4 + n * 1.5));
  return {
    id: 'footprint', name: `Username found on ${n} more platform${n === 1 ? '' : 's'}`, type: 'Social footprint', severity: sev,
    level: sev >= 25 ? 'Critical' : sev >= 15 ? 'High' : sev >= 10 ? 'Medium' : 'Low',
    detail: `A profile page exists for this username on ${n} of ${checked} reachable sites. A reused username lets anyone link your accounts together.`,
    exposed: ['Username', 'Public profile pages', 'Cross-platform identity link'], risk: 'Account correlation, doxxing and targeted social engineering',
    effort: 'High', time: `${Math.max(10, n * 5)} min`, firstSeen: 'unknown', source: 'Profile URL checks', url: null,
    items: hits.map(h => ({ name: h.name, date: '', data: h.url, url: h.url })),
    steps: ['Open each profile below and confirm whether it is yours.', 'Delete accounts you no longer use (search "<site> delete account").', 'For accounts you keep, set them to private and remove bio, photo, location and links.', 'Use a different username per context so profiles cannot be correlated.', 'Impersonation? Use the platform\'s report form.'],
  };
}
$('scan').onclick = async () => {
  const q = $('q').value.trim().toLowerCase();
  if (!q) return msg($('auditMsg'), 'Enter an email or handle first.', 'err');
  $('scan').disabled = true; $('result').hidden = true;
  msg($('auditMsg'), 'Querying live public registries…');
  $('abar').style.width = '0'; $('aprog').hidden = true;
  try {
    const isEmail = q.includes('@');
    const username = q.replace(/^@/, '');
    const fpPromise = isEmail ? null : footprintScan(username);
    const r = await fetch('/api/osint', { method: 'POST', body: JSON.stringify({ q }) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || 'Registry error');
    let findings = data.findings, sources = data.sources, fp = null;
    if (fpPromise) {
      fp = await fpPromise;
      // Dedicated provider findings already cover these platforms in more detail.
      const covered = new Set(findings.map(f => f.source));
      const extra = fp.hits.filter(h => !covered.has(h.name));
      if (extra.length) findings = [...findings, footprintFinding(extra, fp.checked)];
      sources = [...sources, { name: `Profile URL checks (${fp.total} sites)`, ok: fp.checked > 0, hits: fp.hits.length, error: 'no site responded' }];
    }
    renderAudit(q, findings, sources, fp);
    const down = sources.filter(s => !s.ok);
    msg($('auditMsg'), down.length ? `Partial results: ${down.map(s => `${s.name} (${s.error})`).join(', ')} unavailable. Score may be understated; retry later.` : '', 'err');
  } catch (e) {
    msg($('auditMsg'), 'Scan failed: ' + (e.message === 'Failed to fetch' ? 'network unreachable. Check your connection and retry.' : e.message), 'err');
  } finally { $('scan').disabled = false; }
};
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const maskId = q => q.includes('@') ? q.replace(/^(.).*(@.*)$/, '$1***$2') : q.replace(/^(@?.).*(.)$/, '$1***$2');
const LEVEL_COLOR = { Critical: '#f85149', High: '#d29922', Medium: '#2f81f7', Low: '#8b949e' };
const EFFORT_RANK = { Low: 0, Medium: 1, High: 2 };
let lastData = null;

function buildReport(q, findings, sources) {
  const score = Math.max(0, 100 - findings.reduce((s, f) => s + f.severity, 0));
  const byLevel = {}; findings.forEach(f => byLevel[f.level] = (byLevel[f.level] || 0) + 1);
  const exposed = [...new Set(findings.flatMap(f => f.exposed))];
  // Highest points recovered per effort goes first.
  const plan = [...findings].sort((a, b) => (b.severity / (EFFORT_RANK[b.effort] + 1)) - (a.severity / (EFFORT_RANK[a.effort] + 1)));
  const potential = Math.min(100, score + findings.reduce((s, f) => s + f.severity, 0));
  return {
    generatedAt: new Date().toISOString(), subject: maskId(q), score, potentialScore: potential, sourcesChecked: sources,
    rating: score >= 75 ? 'Low exposure' : score >= 45 ? 'Moderate exposure' : 'High exposure',
    summary: { totalFindings: findings.length, byLevel, dataTypesExposed: exposed },
    findings: [...findings].sort((a, b) => b.severity - a.severity),
    actionPlan: plan.map((f, i) => ({ priority: i + 1, source: f.name, effort: f.effort, estimatedTime: f.time, pointsRecovered: f.severity, steps: f.steps })),
    general: ['Use unique passwords and a password manager.', 'Enable 2FA everywhere, preferring hardware keys or authenticator apps.', 'Use email aliases for sign-ups.', 'Re-run this audit every 3 months.'],
    note: 'Results come from live public sources (XposedOrNot, Gravatar, GitHub, RDAP, GitLab, Hacker News, Keybase, DEV). Absence of a finding does not prove absence of exposure.'
  };
}
function reportHtml(r) {
  const rows = r.findings.map(f => `<h3>${esc(f.name)} <span style="color:${LEVEL_COLOR[f.level]}">[${esc(f.level)}]</span></h3>
<p><b>Category:</b> ${esc(f.type)} · <b>First seen:</b> ${esc(f.firstSeen)} · <b>Impact:</b> −${f.severity} pts · <b>Ref:</b> ${esc(f.reference)}</p>
<p>${esc(f.detail)}</p><p><b>Source:</b> ${esc(f.source)} · <a href="${esc(f.url)}">${esc(f.url)}</a></p><p><b>Data exposed:</b> ${f.exposed.map(esc).join(', ')}</p>${f.items ? `<ul>${f.items.map(i => `<li>${esc(i.name)} ${esc(i.date || '')} - ${esc(i.data)}</li>`).join('')}</ul>` : ''}<p><b>Risk:</b> ${esc(f.risk)}</p>
<p><b>Removal (effort ${esc(f.effort)}, ~${esc(f.time)}):</b></p><ol>${f.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>`).join('');
  const plan = r.actionPlan.map(p => `<tr><td>${p.priority}</td><td>${esc(p.source)}</td><td>${esc(p.effort)}</td><td>${esc(p.estimatedTime)}</td><td>+${p.pointsRecovered}</td></tr>`).join('');
  return `<!doctype html><meta charset="utf-8"><title>Privacy report</title><style>body{font:15px/1.5 system-ui;max-width:800px;margin:30px auto;padding:0 16px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px;text-align:left}</style>
<h1>Digital Privacy Report</h1><p>Subject: <b>${esc(r.subject)}</b> · Generated ${esc(r.generatedAt)}</p>
<h2>Score: ${r.score}/100 (${esc(r.rating)})</h2><p>Potential after remediation: <b>${r.potentialScore}/100</b>. ${r.summary.totalFindings} finding(s): ${Object.entries(r.summary.byLevel).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'}.</p>
<p><b>Data types exposed:</b> ${r.summary.dataTypesExposed.map(esc).join(', ') || 'none'}</p>
<h2>Findings</h2>${rows || '<p>No exposure found.</p>'}<h2>Prioritised action plan</h2><table><tr><th>#</th><th>Source</th><th>Effort</th><th>Time</th><th>Score gain</th></tr>${plan}</table>
<h2>General recommendations</h2><ul>${r.general.map(g => `<li>${esc(g)}</li>`).join('')}</ul><p><i>${esc(r.note)}</i></p>`;
}
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

function renderAudit(q, findings, sources = [], fp = null) {
  const r = buildReport(q, findings, sources); lastData = r;
  if (fp) r.manualChecks = fp.manual;
  const color = r.score >= 75 ? '#3fb950' : r.score >= 45 ? '#d29922' : '#f85149';
  $('result').hidden = false;
  $('arc').style.stroke = color; $('arc').setAttribute('stroke-dasharray', `${r.score} 100`);
  $('score').textContent = r.score; $('score').style.color = color;
  $('grade').textContent = `${r.rating} · potential ${r.potentialScore}/100`;
  const sum = $('summary'); sum.innerHTML = '';
  sum.append(el('div', null, `${r.summary.totalFindings} finding(s) for ${r.subject}`));
  const chips = el('div', 'row');
  Object.entries(r.summary.byLevel).forEach(([k, v]) => { const c = el('span', 'chip', `${v} ${k}`); c.style.borderColor = LEVEL_COLOR[k]; chips.append(c); });
  sum.append(chips);
  if (r.summary.dataTypesExposed.length) sum.append(el('small', 'muted', 'Exposed data: ' + r.summary.dataTypesExposed.join(', ')));

  const box = $('findings'); box.innerHTML = '';
  if (!r.findings.length) box.textContent = 'No public exposure found. 🎉';
  r.findings.forEach(f => {
    const d = el('details', 'finding'); d.style.borderLeftColor = LEVEL_COLOR[f.level]; d.open = f.level === 'Critical';
    const sm = el('summary'); sm.append(el('strong', null, f.name), el('small', null, ` · ${f.level} · −${f.severity} pts`));
    const meta = el('small', 'muted', `${f.type} · source ${f.source} · first seen ${f.firstSeen}`);
    const ol = el('ol'); f.steps.forEach(s => ol.append(el('li', null, s)));
    d.append(sm, meta, el('div', null, f.detail), el('div', null, 'Data exposed: ' + f.exposed.join(', ')), el('div', null, 'Risk: ' + f.risk));
    if (f.url && /^https:\/\//.test(f.url)) { const a = el('a', null, 'View source ↗'); a.href = f.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; d.append(a); }
    if (f.items) { const ul = el('ul'); f.items.forEach(i => { const li = el('li'); if (i.url && /^https?:\/\//.test(i.url)) { const a = el('a', null, i.name); a.href = i.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; li.append(a); } else li.textContent = `${i.name}${i.date ? ' (' + i.date + ')' : ''} — ${i.data}`; ul.append(li); }); d.append(el('div', 'muted', f.id === 'footprint' ? 'Profiles found:' : 'Breaches:'), ul); }
    d.append(el('div', 'fix', `Removal steps (effort ${f.effort}, ~${f.time}):`), ol);
    box.append(d);
  });
  const st = $('sources'); st.innerHTML = '';
  sources.forEach(s => st.append(el('span', 'chip', (s.ok ? '✓ ' : '✗ ') + s.name + (s.ok ? ` (${s.hits})` : ''))));
  const mc = $('manual'); mc.innerHTML = '';
  if (fp && fp.manual.length) {
    mc.append(el('div', 'muted', `Cannot be checked automatically (login wall) - open to verify manually. ${fp.unknown} of ${fp.total} sites were unreachable/blocked.`));
    const row = el('div', 'row'); fp.manual.forEach(m => { const a = el('a', 'chip', m.name + ' ↗'); a.href = m.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; row.append(a); }); mc.append(row);
  }
  const plan = $('plan'); plan.innerHTML = '';
  r.actionPlan.forEach(p => plan.append(el('li', null, `${p.source}: ${p.effort} effort, ~${p.estimatedTime}, +${p.pointsRecovered} pts`)));
  $('planWrap').hidden = !r.actionPlan.length;
  lastReport = new File([JSON.stringify(r, null, 2)], 'privacy-report.json', { type: 'application/json' });
}
const download = (name, type, text) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); };
$('dlHtml').onclick = () => lastData && download('privacy-report.html', 'text/html', reportHtml(lastData));
$('dlJson').onclick = () => lastData && download('privacy-report.json', 'application/json', JSON.stringify(lastData, null, 2));
$('printRpt').onclick = () => { if (!lastData) return; const w = window.open('', '_blank'); if (!w) return msg($('auditMsg'), 'Pop-up blocked; use Download HTML instead.', 'err'); w.document.write(reportHtml(lastData)); w.document.close(); w.print(); };
$('saveReport').onclick = () => { setFile($('vfile'), lastReport); show('vault'); };

/* ---------- 2. Zero-knowledge vault ---------- */
const CHUNK = 256 * 1024;
const u32 = n => new Uint8Array([n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255]);
const rd32 = (a, o) => ((a[o] << 24) | (a[o + 1] << 16) | (a[o + 2] << 8) | a[o + 3]) >>> 0;
const aad = (i, t) => { const a = new Uint8Array(8); a.set(u32(i)); a.set(u32(t), 4); return a; };

async function encryptFile(file, key, onProgress) {
  const meta = enc.encode(JSON.stringify({ name: file.name, type: file.type, size: file.size }));
  const total = 1 + Math.ceil(file.size / CHUNK);
  const parts = [enc.encode('ZKV1'), u32(total)];
  for (let i = 0; i < total; i++) {
    const plain = i === 0 ? meta : new Uint8Array(await file.slice((i - 1) * CHUNK, i * CHUNK).arrayBuffer());
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(i, total) }, key, plain));
    parts.push(u32(ct.length), iv, ct);
    onProgress((i + 1) / total);
  }
  return new Blob(parts);
}
async function decryptBuffer(buf, key, onProgress) {
  const a = new Uint8Array(buf);
  if (a.length < 8 || dec.decode(a.slice(0, 4)) !== 'ZKV1') throw new Error('Not a valid encrypted file.');
  const total = rd32(a, 4); let o = 8; const out = []; let meta;
  for (let i = 0; i < total; i++) {
    if (o + 16 > a.length) throw new Error('File is truncated or corrupted.');
    const len = rd32(a, o), iv = a.slice(o + 4, o + 16), ct = a.slice(o + 16, o + 16 + len);
    if (ct.length !== len) throw new Error('File is truncated or corrupted.');
    o += 16 + len;
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(i, total) }, key, ct));
    if (i === 0) meta = JSON.parse(dec.decode(pt)); else out.push(pt);
    onProgress((i + 1) / total);
  }
  return { meta, blob: new Blob(out, { type: meta.type || 'application/octet-stream' }) };
}
const api = (x, fallback) => {
  let d = {}; try { d = JSON.parse(dec.decode(x.response)); } catch { }
  if (x.status === 410) throw new Error(d.error || 'This link has expired, was already used, or never existed.');
  if (x.status !== 200) throw new Error(d.error || fallback + ' (' + x.status + ')');
  return d;
};
const xhr = (method, url, body, onProgress) => new Promise((res, rej) => {
  const x = new XMLHttpRequest(); x.open(method, url); x.responseType = 'arraybuffer';
  const prog = e => e.lengthComputable && onProgress(e.loaded / e.total);
  x.upload.onprogress = prog; x.onprogress = prog;
  x.onload = () => res(x); x.onerror = () => rej(new Error('Network error. Check your connection and retry.'));
  x.ontimeout = () => rej(new Error('Request timed out.'));
  x.send(body);
});

$('encup').onclick = async () => {
  const f = $('vfile').files[0];
  if (!f) return msg($('vout'), 'Choose a file first.', 'err');
  if (f.size > 19 * 1024 * 1024) return msg($('vout'), 'File too large (max ~19 MB). Use P2P transfer for bigger files.', 'err');
  $('encup').disabled = true; msg($('vout'), '');
  try {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    $('vstatus').textContent = 'Encrypting locally…';
    const blob = await encryptFile(f, key, p => $('vbar').style.width = p * 50 + '%');
    $('vstatus').textContent = 'Uploading ciphertext…';
    const PART = 512 * 1024, n = Math.max(1, Math.ceil(blob.size / PART));
    const r = await api(await xhr('POST', `/api/vault/init?ttl=${$('ttl').value}&max=${$('maxdl').value}&parts=${n}`, null, () => { }), 'Upload failed');
    try {
      for (let i = 0; i < n; i++) {
        await api(await xhr('PUT', `/api/vault/${r.id}/part/${i}?up=${r.up}`, blob.slice(i * PART, (i + 1) * PART), () => { }), 'Upload failed');
        $('vbar').style.width = 50 + (i + 1) / n * 50 + '%';
      }
      await api(await xhr('POST', `/api/vault/${r.id}/finish?up=${r.up}`, null, () => { }), 'Upload failed');
    } catch (e) { xhr('DELETE', `/api/vault/${r.id}?up=${r.up}`, null, () => { }).catch(() => { }); throw e; }
    const raw = b64u(await crypto.subtle.exportKey('raw', key));
    const link = `${location.origin}/?v=${r.id}#key=${raw}`;
    $('vstatus').textContent = 'Done. The server holds only ciphertext.';
    const o = $('vout'); o.innerHTML = '';
    const l = document.createElement('div'); l.className = 'link'; l.textContent = link;
    const row = document.createElement('div'); row.className = 'row';
    const cp = document.createElement('button'); cp.className = 'primary'; cp.textContent = 'Copy link';
    cp.onclick = () => navigator.clipboard.writeText(link).then(() => cp.textContent = 'Copied ✓');
    const p2p = document.createElement('button'); p2p.className = 'ghost'; p2p.textContent = 'Send original via P2P instead';
    p2p.onclick = () => { setFile($('pfile'), f); show('p2p'); };
    const ex = document.createElement('small'); ex.className = 'muted'; ex.textContent = 'Expires ' + new Date(r.expires).toLocaleString();
    row.append(cp, p2p, ex); o.append(l, row);
  } catch (e) { msg($('vout'), e.message, 'err'); $('vstatus').textContent = ''; }
  finally { $('encup').disabled = false; }
};

// Download side
const params = new URLSearchParams(location.search), vid = params.get('v');
let manualKeyNeeded = false;
function getKeyString() {
  const m = /key=([A-Za-z0-9_-]+)/.exec(location.hash);
  return (manualKeyNeeded && $('manualKey').value.trim()) || (m && m[1]) || '';
}
if (vid) {
  show('vault'); $('dlCard').hidden = false; $('upCard').hidden = true;
  $('dlInfo').textContent = 'You were sent an end-to-end encrypted file. Decryption happens in your browser.';
  if (!getKeyString()) { $('manualKey').hidden = false; manualKeyNeeded = true; msg($('dmsg'), 'This link has no decryption key (#key=…). Paste it below.', 'err'); }
}
$('decBtn').onclick = async () => {
  $('decBtn').disabled = true; $('dbar').style.width = '0'; msg($('dmsg'), 'Downloading…');
  try {
    const ks = getKeyString();
    let key;
    try {
      const raw = unb64u(ks); if (raw.length !== 32) throw 0;
      key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    } catch { $('manualKey').hidden = false; manualKeyNeeded = true; throw new Error('Decryption key is missing or malformed.'); }
    const info = await api(await xhr('GET', `/api/vault/${encodeURIComponent(vid)}/meta`, null, () => { }), 'Server error');
    const bufs = [];
    for (let i = 0; i < info.parts; i++) {
      const x = await xhr('GET', `/api/vault/${encodeURIComponent(vid)}/part/${i}?t=${info.token}`, null, () => { });
      if (x.status !== 200) api(x, 'Server error');
      bufs.push(x.response);
      $('dbar').style.width = (i + 1) / info.parts * 50 + '%';
    }
    msg($('dmsg'), 'Decrypting…');
    let res;
    try { res = await decryptBuffer(await new Blob(bufs).arrayBuffer(), key, p => $('dbar').style.width = 50 + p * 50 + '%'); }
    catch (e) {
      if (e.name === 'OperationError') { $('manualKey').hidden = false; manualKeyNeeded = true; throw new Error('Invalid decryption key. The file could not be decrypted (wrong key or tampered data).'); }
      throw e;
    }
    const a = document.createElement('a'); a.href = URL.createObjectURL(res.blob); a.download = res.meta.name || 'file'; a.click();
    msg($('dmsg'), `Decrypted "${res.meta.name}" (${fmt(res.meta.size)}) ✓`, 'ok');
  } catch (e) { msg($('dmsg'), e.message, 'err'); }
  finally { $('decBtn').disabled = false; }
};

/* ---------- 3. P2P transfer over WebRTC ---------- */
const ICE = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
const MAX_BUF = 1 << 20, P_CHUNK = 16 * 1024;
let peerId = crypto.randomUUID(), room = null, es = null, pc = null, dc = null, remote = null, incoming = null, pendingIce = [];

function pstate(text, cls) { const s = $('pstate'); s.className = 'msg ' + (cls === 'bad' ? 'err' : cls === 'on' ? 'ok' : 'info'); s.innerHTML = `<span class="dot ${cls || ''}"></span>`; s.append(text); }
const signal = data => fetch(`/api/rooms/${room}/signal`, { method: 'POST', body: JSON.stringify({ from: peerId, to: remote, data }) }).catch(() => pstate('Signaling server unreachable.', 'bad'));

function teardown(keepRoom) {
  dc && dc.close(); pc && pc.close(); dc = pc = remote = null; pendingIce = [];
  if (!keepRoom) {
    if (room) navigator.sendBeacon(`/api/rooms/${room}/leave`, JSON.stringify({ peer: peerId }));
    pollGen++; es = null; room = null; $('xfer').hidden = true;
  }
  $('psend').disabled = true;
}
addEventListener('pagehide', () => { if (room) navigator.sendBeacon(`/api/rooms/${room}/leave`, JSON.stringify({ peer: peerId })); });
function newPeer() {
  pc = new RTCPeerConnection(ICE);
  pc.onicecandidate = e => e.candidate && signal({ ice: e.candidate });
  pc.oniceconnectionstatechange = () => {
    const s = pc && pc.iceConnectionState;
    if (s === 'disconnected') pstate('Connection unstable… waiting to recover', 'bad');
    if (s === 'failed') { pstate('Connection failed (network drop or NAT). Click Join/Create room to retry.', 'bad'); if (incoming) { incoming.row.status.textContent = 'Aborted: connection lost'; incoming = null; } $('psend').disabled = true; }
    if (s === 'connected' || s === 'completed') pstate('Connected peer-to-peer (direct, encrypted by DTLS)', 'on');
  };
  pc.ondatachannel = e => setupChannel(e.channel);
}
function setupChannel(ch) {
  dc = ch; ch.binaryType = 'arraybuffer'; ch.bufferedAmountLowThreshold = MAX_BUF / 2;
  ch.onopen = () => { $('xfer').hidden = false; $('psend').disabled = false; pstate('Connected peer-to-peer (direct, encrypted by DTLS)', 'on'); };
  ch.onclose = () => { $('psend').disabled = true; pstate('Peer disconnected.', 'bad'); if (incoming) { incoming.row.status.textContent = 'Aborted: peer disconnected'; incoming = null; } };
  ch.onerror = () => pstate('Data channel error.', 'bad');
  ch.onmessage = onData;
}
function addRow(label) {
  const d = document.createElement('div'); d.className = 'finding';
  const t = document.createElement('div'); t.textContent = label;
  const bar = document.createElement('div'); bar.className = 'bar'; const fill = document.createElement('div'); bar.append(fill);
  const status = document.createElement('small'); status.className = 'muted';
  d.append(t, bar, status); $('pxfers').prepend(d);
  return { fill, status };
}
function onData(e) {
  if (typeof e.data === 'string') {
    const m = JSON.parse(e.data);
    if (m.t === 'meta') incoming = { m, got: 0, parts: [], row: addRow('⬇ ' + m.name + ' (' + fmt(m.size) + ')') };
    else if (m.t === 'end' && incoming) {
      const { m: meta, got, parts, row } = incoming; incoming = null;
      if (got !== meta.size) { row.status.textContent = 'Corrupted: size mismatch'; return; }
      const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(parts, { type: meta.type })); a.download = meta.name; a.click();
      row.fill.style.width = '100%'; row.status.textContent = 'Received ✓';
    }
  } else if (incoming) {
    incoming.parts.push(e.data); incoming.got += e.data.byteLength;
    incoming.row.fill.style.width = (incoming.got / (incoming.m.size || 1) * 100) + '%';
    incoming.row.status.textContent = fmt(incoming.got) + ' / ' + fmt(incoming.m.size);
  }
}
$('psend').onclick = async () => {
  const f = $('pfile').files[0];
  if (!f || !dc || dc.readyState !== 'open') return pstate('Pick a file and connect first.', 'bad');
  const row = addRow('⬆ ' + f.name + ' (' + fmt(f.size) + ')'); $('psend').disabled = true;
  try {
    dc.send(JSON.stringify({ t: 'meta', name: f.name, size: f.size, type: f.type }));
    for (let off = 0; off < f.size; off += P_CHUNK) {
      if (!dc || dc.readyState !== 'open') throw new Error('connection lost');
      if (dc.bufferedAmount > MAX_BUF) await new Promise(r => { dc.onbufferedamountlow = () => { dc.onbufferedamountlow = null; r(); }; });
      dc.send(await f.slice(off, off + P_CHUNK).arrayBuffer());
      row.fill.style.width = Math.min(100, (off + P_CHUNK) / f.size * 100) + '%';
      row.status.textContent = fmt(Math.min(off + P_CHUNK, f.size)) + ' / ' + fmt(f.size);
    }
    dc.send(JSON.stringify({ t: 'end' })); row.status.textContent = 'Sent ✓';
  } catch (e) { row.status.textContent = 'Failed: ' + e.message; }
  finally { $('psend').disabled = !(dc && dc.readyState === 'open'); }
};
$('leave').onclick = () => { teardown(false); $('hostOut').innerHTML = ''; pstate('Disconnected'); };

let pollGen = 0;
async function startOffer(peer) { // existing peer initiates when a newcomer arrives
  remote = peer; newPeer(); setupChannel(pc.createDataChannel('file'));
  await pc.setLocalDescription(await pc.createOffer()); signal({ sdp: pc.localDescription });
}
async function onSignal(from, data) {
  try {
    if (data.sdp) {
      if (data.sdp.type === 'offer') { remote = from; newPeer(); }
      await pc.setRemoteDescription(data.sdp);
      for (const c of pendingIce.splice(0)) await pc.addIceCandidate(c);
      if (data.sdp.type === 'offer') { await pc.setLocalDescription(await pc.createAnswer()); signal({ sdp: pc.localDescription }); }
    } else if (data.ice) {
      if (pc && pc.remoteDescription) await pc.addIceCandidate(data.ice); else pendingIce.push(data.ice);
    }
  } catch { pstate('Handshake failed. Disconnect and retry.', 'bad'); }
}
async function connectRoom(code) {
  teardown(false); room = code; peerId = crypto.randomUUID();
  const gen = ++pollGen;
  let j;
  try {
    const r = await fetch(`/api/rooms/${code}/join`, { method: 'POST', body: JSON.stringify({ peer: peerId }) });
    j = await r.json();
    if (!r.ok) { pstate(j.error || 'Could not join room.', 'bad'); room = null; return; }
  } catch { pstate('Could not reach the server.', 'bad'); room = null; return; }
  pstate(j.peers.length ? 'Peer found, negotiating…' : 'Waiting for peer… share the code');
  let after = 0, fails = 0;
  while (gen === pollGen) {
    try {
      const r = await fetch(`/api/rooms/${code}/poll?peer=${peerId}&after=${after}`);
      if (gen !== pollGen) return;
      if (r.status === 404) { pstate('Room closed or expired.', 'bad'); teardown(false); return; }
      const d = await r.json(); fails = 0; after = d.next;
      for (const m of d.msgs) {
        if (m.t === 'peer') await startOffer(m.peer);
        else if (m.t === 'signal') await onSignal(m.from, m.data);
        else if (m.t === 'left') { pstate('Peer left the room.', 'bad'); $('psend').disabled = true; }
      }
    } catch {
      if (++fails >= 5) { pstate('Signaling server unreachable. Check your connection and retry.', 'bad'); teardown(false); return; }
    }
    await new Promise(r => setTimeout(r, 800));
  }
}
$('host').onclick = async () => {
  try {
    const { code } = await (await fetch('/api/rooms', { method: 'POST' })).json();
    const url = `${location.origin}/?room=${code}`;
    const o = $('hostOut'); o.innerHTML = `<div class="code">${code}</div><div id="qr"></div><small class="muted">Room expires in 10 minutes</small>`;
    try { const q = qrcode(0, 'M'); q.addData(url); q.make(); $('qr').innerHTML = q.createSvgTag({ cellSize: 4, margin: 0, scalable: true }); } catch { }
    connectRoom(code);
  } catch { pstate('Could not create room (server unreachable).', 'bad'); }
};
$('join').onclick = () => {
  const c = $('joinCode').value.trim();
  if (!/^\d{6}$/.test(c)) return pstate('Enter a valid 6-digit code.', 'bad');
  connectRoom(c);
};
$('scanQr').onclick = async () => {
  if (!('BarcodeDetector' in window)) return pstate('QR scanning is unsupported in this browser; type the code instead.', 'bad');
  try {
    const v = $('cam'); v.srcObject = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    v.hidden = false; await v.play();
    const det = new BarcodeDetector({ formats: ['qr_code'] });
    const loop = async () => {
      if (v.hidden) return;
      const r = await det.detect(v).catch(() => []);
      const m = r[0] && /room=(\d{6})/.exec(r[0].rawValue);
      if (m) { v.srcObject.getTracks().forEach(t => t.stop()); v.hidden = true; $('joinCode').value = m[1]; connectRoom(m[1]); } else setTimeout(loop, 250);
    };
    loop();
  } catch { pstate('Camera unavailable or permission denied.', 'bad'); }
};
const roomParam = params.get('room');
if (/^\d{6}$/.test(roomParam || '')) { show('p2p'); $('joinCode').value = roomParam; connectRoom(roomParam); }
window.addEventListener('beforeunload', () => es && es.close());
