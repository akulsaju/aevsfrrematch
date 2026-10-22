// Live OSINT providers. Every one queries a real, public, keyless source.
// Each returns an array of findings (empty = nothing found) or throws if the source is unreachable.
const crypto = require('crypto');

const UA = 'PrivacyShield/1.0 (+personal exposure self-audit)';
const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'aol.com', 'gmx.com', 'mail.com', 'yandex.com', 'zoho.com']);

async function getJson(url, { okStatuses = [200], notFound = [404], plain = false, timeout = 9000 } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { headers: plain ? {} : { 'User-Agent': UA, Accept: 'application/json' }, signal: ctl.signal });
    if (notFound.includes(r.status)) return null;
    if (!okStatuses.includes(r.status)) throw new Error('HTTP ' + r.status);
    return await r.json();
  } catch (e) {
    throw new Error(e.name === 'AbortError' ? 'timed out' : e.message);
  } finally { clearTimeout(t); }
}

const level = s => (s >= 25 ? 'Critical' : s >= 15 ? 'High' : s >= 10 ? 'Medium' : 'Low');
function finding(id, name, type, severity, o) {
  return { id, name, type, severity, level: level(severity), effort: 'Low', time: '5-10 min', ...o };
}

/* ---------- email providers ---------- */
async function xposedOrNot(email) {
  const d = await getJson('https://api.xposedornot.com/v1/breach-analytics?email=' + encodeURIComponent(email));
  const out = [];
  const list = (d && d.ExposedBreaches && d.ExposedBreaches.breaches_details) || [];
  if (list.length) {
    const exposed = [...new Set(list.flatMap(b => (b.xposed_data || '').split(';')).map(s => s.trim()).filter(Boolean))];
    const sorted = [...list].sort((a, b) => (b.xposed_records || 0) - (a.xposed_records || 0));
    const pwRisk = list.some(b => /plaintext|easytocrack/i.test(b.password_risk || ''));
    const sev = Math.min(40, 10 + list.length * 3 + (pwRisk ? 10 : 0));
    out.push(finding('breaches', `Data breaches (${list.length})`, 'Data breach', sev, {
      detail: `This email appears in ${list.length} known breach(es): ${sorted.slice(0, 8).map(b => `${b.breach}${b.xposed_date ? ' (' + b.xposed_date + ')' : ''}`).join(', ')}${list.length > 8 ? ', …' : ''}.${pwRisk ? ' Some breaches leaked passwords in plaintext or easily cracked form.' : ''}`,
      exposed, risk: 'Credential stuffing, account takeover and targeted phishing',
      effort: 'Medium', time: '30-60 min',
      firstSeen: sorted.map(b => (b.added || '').slice(0, 10)).filter(Boolean).sort()[0] || 'unknown',
      source: 'XposedOrNot', url: 'https://xposedornot.com/',
      items: sorted.slice(0, 25).map(b => ({ name: b.breach, date: b.xposed_date, records: b.xposed_records, data: (b.xposed_data || '').replace(/;/g, ', '), domain: b.domain })),
      steps: ['Review each breach below and log in to those services.', 'Change the password on each one, and anywhere you reused it.', 'Use a password manager to generate unique passwords.', 'Enable app-based or hardware 2FA, starting with email and banking.', 'Treat emails that mention these services as potential phishing.'],
    }));
  }
  const p = d && d.PastesSummary;
  if (p && Number(p.cnt) > 0) {
    out.push(finding('pastes', `Public pastes (${p.cnt})`, 'Paste site', 25, {
      detail: `This email appears in ${p.cnt} public paste(s)${p.domain ? ' on ' + p.domain : ''}.`,
      exposed: ['Email address', 'Possibly credentials'], risk: 'Leaked secrets and permanent public copies',
      effort: 'High', time: '1-3 hours', firstSeen: p.tmpstmp ? new Date(Number(p.tmpstmp) * 1000).toISOString().slice(0, 10) : 'unknown',
      source: 'XposedOrNot', url: 'https://xposedornot.com/',
      steps: ['Locate the paste and identify any passwords or tokens in it.', 'Rotate every exposed credential immediately.', 'File a removal request through the paste site\'s abuse form.', 'Request search-engine de-indexing.'],
    }));
  }
  return out;
}

async function gravatar(email) {
  const hash = crypto.createHash('md5').update(email).digest('hex');
  const d = await getJson(`https://www.gravatar.com/${hash}.json`, { plain: true, timeout: 20000 });
  const e = d && d.entry && d.entry[0];
  if (!e) return [];
  const exposed = ['Email-linked avatar'];
  if (e.displayName || (e.name && e.name.formatted)) exposed.push('Name');
  if (e.currentLocation) exposed.push('Location');
  if (e.accounts && e.accounts.length) exposed.push('Linked accounts: ' + e.accounts.map(a => a.shortname).join(', '));
  if (e.urls && e.urls.length) exposed.push('Websites');
  return [finding('gravatar', 'Gravatar public profile', 'Social media', 12, {
    detail: `A public Gravatar profile is linked to this email${e.displayName ? ' (display name "' + e.displayName + '")' : ''}. Anyone who knows your email can look it up.`,
    exposed, risk: 'Links your email to your identity and other accounts', firstSeen: 'unknown', source: 'Gravatar', url: e.profileUrl || `https://gravatar.com/${hash}`,
    steps: ['Sign in at gravatar.com with this email.', 'Open My Profile and remove name, location, links and verified accounts.', 'Set avatar rating and profile visibility to hide details, or delete the Gravatar account.'],
  })];
}

async function githubCommits(email) {
  const d = await getJson(`https://api.github.com/search/commits?q=${encodeURIComponent('author-email:' + email)}&per_page=1`, { okStatuses: [200], notFound: [404, 422] });
  const c = d && d.items && d.items[0];
  if (!c || (c.commit.author.email || '').toLowerCase() !== email) return []; // search is fuzzy; require an exact match
  return [finding('github-commits', 'Email in public GitHub commits', 'Code hosting', 10, {
    detail: `Commits authored with this email are publicly searchable${c.author ? ' and tied to the account @' + c.author.login : ''}. Example: ${c.repository.full_name}.`,
    exposed: ['Commit author email', 'Real name', 'Commit timestamps / timezone'], risk: 'Email harvesting and identity correlation',
    effort: 'Medium', time: '10-30 min', firstSeen: (c.commit.author.date || '').slice(0, 10) || 'unknown', source: 'GitHub Search API', url: c.html_url,
    steps: ['In GitHub Settings > Emails enable "Keep my email addresses private".', 'Set git config user.email to your ID+username@users.noreply.github.com address.', 'For sensitive repos, rewrite history with git filter-repo and force-push.', 'Ask collaborators to re-clone forks.'],
  })];
}

async function whoisDomain(email) {
  const domain = email.split('@')[1];
  if (!domain || FREE_MAIL.has(domain)) return [];
  const d = await getJson('https://rdap.org/domain/' + encodeURIComponent(domain));
  if (!d) return [];
  const exposed = [];
  const walk = ents => (ents || []).forEach(en => {
    const vc = en.vcardArray && en.vcardArray[1];
    if (vc && (en.roles || []).some(r => /registrant|administrative|technical/.test(r))) {
      for (const [k, , , v] of vc) {
        const val = Array.isArray(v) ? v.join(' ') : String(v || '');
        if (/redact|privacy|proxy|withheld|not disclosed|data protected/i.test(val) || !val.trim()) continue;
        if (['fn', 'org'].includes(k)) exposed.push('Registrant ' + (k === 'fn' ? 'name' : 'organisation'));
        if (k === 'email') exposed.push('Contact email');
        if (k === 'tel') exposed.push('Phone number');
        if (k === 'adr') exposed.push('Postal address');
      }
    }
    walk(en.entities);
  });
  walk(d.entities);
  const uniq = [...new Set(exposed)];
  if (!uniq.length) return [];
  const created = (d.events || []).find(e => e.eventAction === 'registration');
  return [finding('rdap', `Domain registration (${domain})`, 'Domain registry', 14, {
    detail: `The public RDAP/WHOIS record for ${domain} lists personal or organisation contact details.`,
    exposed: uniq, risk: 'Stalking, spam and social engineering from public domain records', firstSeen: created ? created.eventDate.slice(0, 10) : 'unknown',
    source: 'RDAP (rdap.org)', url: 'https://rdap.org/domain/' + domain,
    steps: ['Log in to your domain registrar.', 'Enable WHOIS privacy / proxy protection.', 'Replace contact details with a role-based address.', 'Re-check the RDAP record after 24 hours.'],
  })];
}

/* ---------- handle providers ---------- */
function profile(id, name, severity, url, exposed, detail, steps, first) {
  return finding(id, name, 'Public profile', severity, { detail, exposed, risk: 'Public profile can be correlated with your other accounts', firstSeen: first || 'unknown', source: name, url, steps });
}
const iso = s => (s ? String(s).slice(0, 10) : 'unknown');

async function githubUser(h) {
  const d = await getJson('https://api.github.com/users/' + encodeURIComponent(h));
  if (!d) return [];
  const exposed = ['Username', 'Avatar'];
  ['name', 'company', 'location', 'email', 'blog', 'bio', 'twitter_username'].forEach(k => d[k] && exposed.push(k.replace('_', ' ')));
  return [profile('github', 'GitHub', 10 + (d.email ? 5 : 0), d.html_url, exposed, `Public GitHub profile with ${d.public_repos} repos and ${d.followers} followers.`,
    ['Open Settings > Public profile and clear name, bio, company, location and links.', 'Untick "Public email" and enable "Keep my email private".', 'Review public repos/gists for personal data, or make them private.'], iso(d.created_at))];
}
async function gitlabUser(h) {
  const d = await getJson('https://gitlab.com/api/v4/users?username=' + encodeURIComponent(h));
  const u = Array.isArray(d) && d[0];
  if (!u) return [];
  return [profile('gitlab', 'GitLab', 8, u.web_url, ['Username', 'Avatar', 'Projects'], 'Public GitLab profile found.',
    ['Open Preferences > Profile.', 'Enable "Private profile".', 'Review public projects and snippets.'])];
}
async function hackerNews(h) {
  const d = await getJson('https://hacker-news.firebaseio.com/v0/user/' + encodeURIComponent(h) + '.json');
  if (!d) return [];
  return [profile('hn', 'Hacker News', 8, 'https://news.ycombinator.com/user?id=' + h, ['Username', 'About text', 'Comment & submission history'],
    `Public Hacker News account with ${d.karma} karma and ${(d.submitted || []).length} public items.`,
    ['Edit your "about" field to remove personal details.', 'Email hn@ycombinator.com to request deletion or anonymisation of old comments.'], d.created ? new Date(d.created * 1000).toISOString().slice(0, 10) : 'unknown')];
}
async function keybase(h) {
  const d = await getJson('https://keybase.io/_/api/1.0/user/lookup.json?usernames=' + encodeURIComponent(h));
  const u = d && d.them && d.them[0];
  if (!u) return [];
  const proofs = Object.keys((u.proofs_summary && u.proofs_summary.by_presentation_group) || {});
  return [profile('keybase', 'Keybase', 12, 'https://keybase.io/' + h, ['Username', 'Public keys', ...(u.profile && u.profile.full_name ? ['Full name'] : []), ...(proofs.length ? ['Linked accounts: ' + proofs.join(', ')] : [])],
    'Public Keybase identity with cryptographic proofs linking your accounts.', ['Revoke identity proofs you no longer want public in the Keybase app.', 'Clear full name, bio and location in Profile settings.', 'Or delete the account.'], d.them[0].basics ? new Date(u.basics.ctime * 1000).toISOString().slice(0, 10) : 'unknown')];
}
async function devTo(h) {
  const d = await getJson('https://dev.to/api/users/by_username?url=' + encodeURIComponent(h));
  if (!d || !d.username) return [];
  const exposed = ['Username', 'Name'];
  ['twitter_username', 'github_username', 'location', 'summary', 'website_url'].forEach(k => d[k] && exposed.push(k.replace('_', ' ')));
  return [profile('devto', 'DEV Community', 8, 'https://dev.to/' + d.username, exposed, 'Public DEV profile found.', ['Open Settings > Profile and remove location, links and summary.', 'Unpublish or delete old posts that reveal personal info.'], iso(d.joined_at))];
}

const EMAIL_PROVIDERS = [['XposedOrNot breach database', xposedOrNot], ['Gravatar', gravatar], ['GitHub commit search', githubCommits], ['RDAP domain registry', whoisDomain]];
const HANDLE_PROVIDERS = [['GitHub', githubUser], ['GitLab', gitlabUser], ['Hacker News', hackerNews], ['Keybase', keybase], ['DEV Community', devTo]];

async function scan(raw) {
  const q = String(raw || '').trim().toLowerCase();
  let providers, type, arg = q;
  if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(q) && q.length <= 254) { providers = EMAIL_PROVIDERS; type = 'email'; }
  else if (/^@?[a-z0-9][a-z0-9_.-]{0,38}$/.test(q)) { providers = HANDLE_PROVIDERS; type = 'handle'; arg = q.replace(/^@/, ''); }
  else { const e = new Error('Enter a valid email address or handle (letters, digits, . _ -).'); e.status = 400; throw e; }
  const settled = await Promise.allSettled(providers.map(([, fn]) => fn(arg)));
  const sources = providers.map(([name], i) => settled[i].status === 'fulfilled'
    ? { name, ok: true, hits: settled[i].value.length } : { name, ok: false, error: settled[i].reason.message });
  const findings = settled.flatMap(s => (s.status === 'fulfilled' ? s.value : []));
  return { type, findings, sources };
}

module.exports = { scan };
