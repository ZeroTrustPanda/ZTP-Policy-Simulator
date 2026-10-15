'use strict';
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const { exec } = require('child_process');

const { ZClient, loadSnapshot, refreshKeys, ZIA, probe, catalog, lookupUser, urlLookup, URL_LOOKUP_MAX, zpaWorks, zpaScimGroupName, zpaScimAttrName, zidIndex, zpaScimMembership } = require('./src/zscaler');
const changes = require('./src/changes');
const bulk = require('./src/bulk');
const recommend = require('./src/recommend');
const { simulate, rationalize } = require('./src/engine');
const M = require('./src/matchers');
const VERSION = require('./package.json').version;

const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = process.env.HOST || '127.0.0.1'; // loopback only; credentials live in memory only
const SESSION_TTL = 60 * 60 * 1000;
const sessions = new Map(); // id -> {client, snap, demo, job, last}

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

setInterval(() => { const now = Date.now(); for (const [k, v] of sessions) if (now - v.last > SESSION_TTL && !(v.bulk && ['lookup', 'simulate', 'queued'].includes(v.bulk.phase))) sessions.delete(k); }, 60000).unref();

function getSession(req, res) {
  const id = (req.body && req.body.sessionId) || req.query.sessionId;
  const s = sessions.get(id);
  if (!s) { res.status(440).json({ error: 'Session expired or not connected. Click Connect again.' }); return null; }
  s.last = Date.now();
  return s;
}
const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => {
  console.error('[error]', e.message);
  res.status(e.status === 401 ? 401 : 500).json({ error: e.message, code: e.code });
});

function counts(snap) {
  const c = {};
  if (!snap) return c;
  for (const [k, v] of Object.entries(snap.data)) c[k] = Array.isArray(v) ? v.length : v ? 1 : 0;
  return c;
}
function snapInfo(s) {
  return s.snap ? { loadedAt: s.snap.loadedAt, counts: counts(s.snap), errors: s.snap.errors, locations: (s.snap.data.locations || []).map((l) => l.name).filter(Boolean) } : null;
}

app.get('/api/version', (req, res) => res.json({ version: VERSION }));

// Step 1: authenticate and probe what the API client can reach. Does NOT load policy.
app.post('/api/connect', wrap(async (req, res) => {
  const b = req.body || {};
  const id = crypto.randomBytes(16).toString('hex');
  if (b.demo) {
    const snap = { loadedAt: Date.now(), data: require('./src/demo-snapshot.json'), errors: {} };
    sessions.set(id, { demo: true, snap, last: Date.now() });
    return res.json({ sessionId: id, demo: true, probe: { ZIA: { ok: true }, ZCC: { ok: true }, ZPA: { ok: true } }, snapshot: snapInfo(sessions.get(id)) });
  }
  const client = new ZClient({ vanityDomain: b.vanityDomain, clientId: b.clientId, clientSecret: b.clientSecret, zpaCustomerId: (b.zpaCustomerId || '').trim() || undefined, cloud: b.cloud, apiBase: b.apiBase || undefined });
  await client.auth();
  const pr = await probe(client);
  sessions.set(id, { client, snap: null, last: Date.now() });
  console.log(`[connect] ${client.tokenHost} -> ${client.apiHost}  ${Object.entries(pr).map(([k, v]) => `${k}:${v.ok ? 'ok' : v.status || 'err'}`).join(' ')}`);
  res.json({ sessionId: id, tokenHost: client.tokenHost, apiHost: client.apiHost, probe: pr, zpa: zpaInfo(client), catalog: catalog(client).map((e) => ({ key: e.key, label: e.label, group: e.group })) });
}));

const zpaInfo = (client) => ({ customerId: client.cfg.zpaCustomerId || null, source: client.cfg.zpaCustomerId ? client.cfg.zpaIdSource || 'entered' : null });

// ZPA uses the same OneAPI client. Only its customer ID is extra, and only when the token doesn't carry it.
app.post('/api/zpa/customer', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (s.demo || !s.client) return res.json({ ok: true, demo: true });
  const id = String((req.body && req.body.customerId) || '').trim();
  if (!/^\d{6,22}$/.test(id)) return res.status(400).json({ error: 'The ZPA customer ID is a long number (Administration → API Keys in the ZPA Admin Portal).' });
  const r = await zpaWorks(s.client, id);
  if (!r.ok) return res.status(r.status === 401 || r.status === 403 ? 403 : 400).json({ error: `ZPA didn't accept customer ID ${id} with this API client (${r.status || 'error'}). ${r.status === 401 || r.status === 403 ? 'Check the ID, and that the API client has a ZPA role in ZIdentity.' : r.error || ''}`.trim() });
  s.client.cfg.zpaCustomerId = id; s.client.cfg.zpaIdSource = 'entered';
  res.json({ ok: true, zpa: zpaInfo(s.client) });
}));

// Step 2: load policies (background job; poll /api/load-status).
app.post('/api/load', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (s.demo) return res.json({ started: false, done: true, snapshot: snapInfo(s) });
  if (s.job && !s.job.done) return res.json({ started: false, running: true });
  const groups = Array.isArray(req.body.groups) && req.body.groups.length ? req.body.groups : ['zia', 'zcc', 'zpa'];
  if (groups.includes('zpa') && !s.client.cfg.zpaCustomerId) return res.status(400).json({ error: 'Enter the ZPA customer ID to load ZPA policies, or untick ZPA.', needsZpaId: true });
  const job = { started: Date.now(), done: false, items: {} };
  s.job = job;
  loadSnapshot(s.client, { groups, job })
    .then((snap) => { s.snap = snap; job.done = true; job.finished = Date.now(); })
    .catch((e) => { job.done = true; job.error = e.message; });
  res.json({ started: true });
}));

app.post('/api/load-status', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const j = s.job;
  res.json({ job: j ? { done: j.done, error: j.error, items: j.items, started: j.started, finished: j.finished } : null, snapshot: j && j.done ? snapInfo(s) : s.snap ? snapInfo(s) : null });
});

app.post('/api/diagnostics', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  res.json({ tokenHost: s.client && s.client.tokenHost, apiHost: s.client && s.client.apiHost, log: s.client ? s.client.log.slice(-200) : [], snapshotErrors: s.snap ? s.snap.errors : {} });
});

// Save the loaded policy snapshot (rules only — no credentials or tokens) for offline use / troubleshooting.
app.post('/api/snapshot/save', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.snap) return res.status(409).json({ error: 'Load policies first.' });
  const fs = require('fs'), os = require('os');
  const dir = path.join(os.homedir(), 'ZTP-Policy-Simulator', 'snapshots');
  fs.mkdirSync(dir, { recursive: true });
  const tenant = (s.client && s.client.tokenHost.split('.')[0]) || 'demo';
  const file = path.join(dir, `${tenant}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  fs.writeFileSync(file, JSON.stringify({ tool: 'ztp-policy-simulator', version: VERSION, tenant, loadedAt: s.snap.loadedAt, errors: s.snap.errors, data: s.snap.data }, null, 1));
  res.json({ file });
});

// Open a saved snapshot (offline simulation, no tenant connection).
app.post('/api/snapshot/open', wrap(async (req, res) => {
  const j = req.body && req.body.snapshot;
  if (!j || typeof j.data !== 'object') return res.status(400).json({ error: 'Not a simulator snapshot file.' });
  const id = crypto.randomBytes(16).toString('hex');
  const snap = { loadedAt: j.loadedAt || Date.now(), data: j.data, errors: j.errors || {} };
  sessions.set(id, { demo: true, snap, last: Date.now() });
  res.json({ sessionId: id, demo: true, offline: true, tenant: j.tenant, snapshot: snapInfo(sessions.get(id)) });
}));

app.post('/api/disconnect', (req, res) => { sessions.delete(req.body && req.body.sessionId); res.json({ ok: true }); });

async function buildContext(s, b) {
  const t = M.parseTarget(b.target || '');
  const ctx = {
    target: t, port: b.port ? +b.port : t && t.port ? t.port : null, protocol: (b.protocol || 'tcp').toLowerCase(),
    fileType: (b.fileType || '').replace(/^\./, '').toUpperCase() || null, operation: b.operation || null,
    method: (b.method || '').toUpperCase() || null,
    networkService: b.networkService || null, application: b.application || null, dnsProtocol: b.dnsProtocol || null,
    user: b.user || null, groups: b.groups || [], department: b.department || null,
    location: b.location || null, locationGroups: b.locationGroups || [], sourceIp: b.sourceIp || null, destCountry: b.destCountry || null,
    resolvedIps: [], categories: [], notes: [],
    useZpa: b.useZpa !== false, cloudApp: b.cloudApp || null,
  };
  if (b.ip) {
    if (!t) ctx.target = M.parseTarget(b.ip);
    else if (!t.isIp) ctx.resolvedIps.push(b.ip);
  }
  const tg = ctx.target;
  if (tg && !tg.isIp && !tg.isWildcard && !b.ip) {
    try { ctx.resolvedIps = (await dns.resolve4(tg.host)).slice(0, 8); } catch { ctx.notes.push(`DNS resolution of ${tg.host} failed locally; IP-based rules may show as unknown.`); }
  }
  if (b.categories && b.categories.length) { ctx.categories = b.categories; ctx.categorySource = b.noLookup ? 'precomputed' : 'entered'; }
  else if (tg && !b.noLookup && !s.demo && s.client) {
    // Zscaler classification for the destination: hostnames and single IPs (not CIDRs/ranges). Cached per session.
    const key = bulk.lookupKey(tg.raw || tg.host);
    if (key) {
      s.catCache = s.catCache || new Map();
      try {
        if (!s.catCache.has(key) || s.catCache.get(key).error) {
          const out = await urlLookup(s.client, [key]);
          const o = out.find((x) => String(x.url || '').toLowerCase() === key.toLowerCase()) || out[0];
          s.catCache.set(key, o ? bulk.fromLookup(o) : { categories: [], security: [], error: 'not returned' });
        }
        const c = s.catCache.get(key);
        ctx.categories = [...c.categories, ...c.security];
        ctx.securityCategories = c.security;
        if (c.application && !ctx.cloudApp) ctx.cloudApp = c.application;
        ctx.categorySource = 'Zscaler lookup';
        if (tg.isWildcard) ctx.notes.push(`Wildcard query: categories taken from probe host ${key}.`);
        if (c.error) ctx.notes.push(`Zscaler returned no category for ${key}.`);
      } catch (e) { ctx.notes.push(`Category lookup failed: ${e.message}`); }
    } else if (tg.isIp) ctx.notes.push('Category lookup skipped: CIDRs and ranges have no single classification — enter one IP to look it up.');
  }
  // Accept pasted text like "288261371856945305 = jane@acme.org": use the email in it.
  if (b.user) { const em = String(b.user).match(/[^\s=<>"',;()]+@[^\s=<>"',;()]+\.[a-z]{2,}/i); ctx.userEmail = em ? em[0].toLowerCase() : null; if (em && em[0] !== String(b.user).trim()) { ctx.user = em[0]; b = Object.assign({}, b, { user: em[0] }); } }
  if (s.demo && s.snap && s.snap.data) {
    const dd = s.snap.data;
    ctx.zpaScimNames = Object.fromEntries(Object.values(dd.zpaScimGroups || {}).flat().map((g) => [String(g.id), g.name]));
    const q = String(b.user || '').toLowerCase();
    const u = q && (dd.demoUsers || []).find((x) => [x.email, x.name].some((v) => String(v).toLowerCase() === q));
    if (u && !(b.groups && b.groups.length)) {
      ctx.groups = u.groups; ctx.department = ctx.department || u.department; ctx.userResolved = Object.assign({ source: 'sample directory' }, u);
      ctx.notes.push(`User ${u.email} found in the sample directory: ${u.groups.join(', ')}.`);
    }
  }
  if (b.user && !s.demo && s.client && !(b.groups && b.groups.length)) {
    s.userCache = s.userCache || new Map();
    try {
      const k = String(b.user).toLowerCase();
      if (!s.userCache.has(k) || (b.zidId && !s.userCache.get(k))) s.userCache.set(k, await lookupUser(s.client, b.user, { zidId: b.zidId, name: b.userName }));
      const u = s.userCache.get(k);
      if (u) {
        ctx.groups = u.groups; ctx.department = ctx.department || u.department; ctx.userResolved = u;
        ctx.notes.push(`User ${u.email || u.name} found in ${u.source}: ${u.groups.length} group${u.groups.length === 1 ? '' : 's'}${u.groups.length ? ' (' + u.groups.slice(0, 8).join(', ') + (u.groups.length > 8 ? ', …' : '') + ')' : ''}.`);
        if (u.ziaError) ctx.notes.push(`ZIA's user list refused this API client (${/HTTP (\d+)/.exec(u.ziaError) ? /HTTP (\d+)/.exec(u.ziaError)[1] : 'error'}), so groups came from ZIdentity.`);
      } else ctx.notes.push(`User "${b.user}" not found in ZIA or ZIdentity${s.client._zidDiag ? ` (${s.client._zidDiag})` : ''}.`);
    } catch (e) { ctx.notes.push(`User lookup failed: ${e.message}`); }
  }
  // ZPA's own record of the user: SCIM group membership per SCIM-enabled IdP (what ZPA evaluates SCIM_GROUP against).
  const dz = s.snap && s.snap.data;
  if (b.user && dz && dz.zpaAccessRules && !s.demo && s.client && s.client.cfg.zpaCustomerId && b.useZpa !== false) {
    const idps = (dz.zpaIdps || []).filter((i) => i.scimEnabled || i.enableScimBasedPolicy);
    if (idps.length) {
      s.scimMember = s.scimMember || new Map();
      const names = [...new Set([ctx.userEmail, b.user, ctx.userResolved && ctx.userResolved.loginName].filter(Boolean).map((x) => String(x)))];
      let res = null;
      for (const n of names) {
        const k = n.toLowerCase();
        if (!s.scimMember.has(k)) s.scimMember.set(k, await zpaScimMembership(s.client, idps, n));
        const r = s.scimMember.get(k);
        if (r.some((x) => x.groups && x.groups.length)) { res = r; break; }
        res = res || r;
      }
      ctx.zpaScimMember = Object.fromEntries((res || []).filter((x) => x.groups && x.groups.length).map((x) => [x.idpId, x.groups.map((g) => g.id)])); // empty = unknown, not 'in no groups'
      for (const x of res || []) for (const g of x.groups || []) { s.scimNames = s.scimNames || new Map(); s.scimNames.set(g.id, g.name); }
      const found = (res || []).filter((x) => x.groups && x.groups.length);
      if (found.length) ctx.notes.push(`ZPA SCIM: ${found.map((x) => `${x.idp}: ${x.groups.length} group${x.groups.length === 1 ? '' : 's'} (${x.groups.slice(0, 6).map((g) => g.name).join(', ')}${x.groups.length > 6 ? ', …' : ''})`).join('; ')}.`);
      else ctx.notes.push(`ZPA SCIM: no group membership found for ${names[0]}${(res || []).filter((x) => x.note).map((x) => ` (${x.idp}: ${/not\.found|No scim user/i.test(x.note) ? 'not provisioned' : x.note.slice(0, 80)})`).join('')}.`);
    }
  }
  // ZPA access rules reference SCIM groups by ID: resolve the names once per session so a user's groups can be matched.
  const d = s.snap && s.snap.data;
  if (d && d.zpaAccessRules && !s.demo && s.client && s.client.cfg.zpaCustomerId && b.useZpa !== false) {
    s.scimNames = s.scimNames || new Map();
    const ids = new Set();
    for (const r of [...(d.zpaAccessRules || []), ...(d.zpaForwardingRules || [])]) for (const c of r.conditions || []) for (const o of c.operands || [])
      if (o.objectType === 'SCIM_GROUP' && !o.name) for (const v of (o.values || (o.rhs != null ? [o.rhs] : []))) if (!s.scimNames.has(String(v))) ids.add(String(v));
    for (const id of [...ids].slice(0, 150)) { try { s.scimNames.set(id, await zpaScimGroupName(s.client, id)); } catch { s.scimNames.set(id, null); } }
    ctx.zpaScimNames = Object.fromEntries(s.scimNames);
  }
  // SCIM attribute conditions (lhs = attribute ID, rhs = value): resolve attribute names so email/userName ones can be checked.
  if (d && d.zpaAccessRules && !s.demo && s.client && s.client.cfg.zpaCustomerId && b.useZpa !== false) {
    s.scimAttrs = s.scimAttrs || new Map();
    const want = new Map();
    const idps = (d.zpaIdps || []).map((i) => String(i.id));
    for (const r of [...(d.zpaAccessRules || []), ...(d.zpaForwardingRules || [])]) for (const c of r.conditions || []) for (const o of c.operands || [])
      if (o.objectType === 'SCIM' && o.lhs != null && !s.scimAttrs.has(String(o.lhs))) want.set(String(o.lhs), o.idpId || o.idp_id || null);
    for (const [attr, idp] of [...want].slice(0, 50)) {
      let name = null;
      for (const i of idp ? [String(idp)] : idps.slice(0, 5)) { try { name = await zpaScimAttrName(s.client, i, attr); if (name) break; } catch {} }
      s.scimAttrs.set(attr, name);
    }
    ctx.zpaScimAttrs = Object.fromEntries(s.scimAttrs);
  }
  return ctx;
}

app.post('/api/simulate', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.snap) return res.status(409).json({ error: 'Policies are not loaded yet. Click "Load policies" first.' });
  const b = req.body;
  if (!b.target && !b.ip && !b.port && !b.networkService && !b.application && !b.fileType) return res.status(400).json({ error: 'Enter at least a destination, port, network service, application or file type.' });
  // Who: picks[] holds up to two identities (user or group). One → simulate as it; two → compare side by side.
  const asPick = async (pk) => {
    const b2 = Object.assign({}, b, { picks: undefined });
    if (pk.kind === 'group') Object.assign(b2, { user: '', groups: [String(pk.name)] });
    else Object.assign(b2, { user: String(pk.email || pk.name || ''), groups: [], zidId: pk.zidId || null, userName: pk.name });
    const ctx = await buildContext(s, b2);
    if (pk.kind === 'group') ctx.notes.unshift(`Simulated as a member of group "${pk.name}"${pk.source ? ` (${pk.source})` : ''} only, with no user-specific attributes.`);
    return ctx;
  };
  const picks = Array.isArray(b.picks) ? b.picks.slice(0, 2) : [];
  if (picks.length === 1) {
    const out = simulate(s.snap, await asPick(picks[0]), b.manual || {});
    out.snapshot = { loadedAt: s.snap.loadedAt, errors: s.snap.errors, counts: counts(s.snap) };
    out.pick = picks[0];
    return res.json(out);
  }
  if (picks.length === 2) {
    const runs = [];
    for (const pk of picks) {
      const ctx = await asPick(pk);
      const out = simulate(s.snap, ctx, b.manual || {});
      runs.push(Object.assign({ pick: pk }, out));
    }
    return res.json({ compare: runs, snapshot: { loadedAt: s.snap.loadedAt, errors: s.snap.errors, counts: counts(s.snap) } });
  }
  const ctx = await buildContext(s, b);
  const out = simulate(s.snap, ctx, b.manual || {});
  out.snapshot = { loadedAt: s.snap.loadedAt, errors: s.snap.errors, counts: counts(s.snap) };
  res.json(out);
}));

// ---------- bulk ----------
app.post('/api/bulk/start', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.snap) return res.status(409).json({ error: 'Policies are not loaded yet. Click "Load policies" first.' });
  if (s.bulk && ['lookup', 'simulate', 'queued'].includes(s.bulk.phase)) return res.status(409).json({ error: 'A bulk test is already running. Cancel it or wait for it to finish.' });
  const b = req.body || {};
  const parsed = bulk.parseCsv(b.csv || '');
  if (!parsed.entries.length) return res.status(400).json({ error: 'No destinations found. Put one IP, CIDR, range or host per line, or use a header row with an "ip" column.', skipped: parsed.skipped.slice(0, 20) });
  const ex = bulk.expand(parsed.entries);
  if (ex.error) return res.status(400).json({ error: ex.error });
  if (!ex.rows.length) return res.status(400).json({ error: 'Nothing valid to test.', skipped: [...parsed.skipped, ...ex.skipped].slice(0, 20) });
  const opts = { lookup: b.lookup !== false && !!s.client, defaultPort: b.defaultPort || '', defaultProtocol: b.defaultProtocol || 'tcp', expected: recommend.normExpected(b.expected), useZpa: b.useZpa !== false };
  const skipped = [...parsed.skipped, ...ex.skipped];
  const job = {
    id: crypto.randomBytes(6).toString('hex'), phase: 'queued', total: ex.rows.length, done: 0, results: [], started: Date.now(), name: String(b.fileName || 'bulk').replace(/\.[^.]+$/, ''),
    parse: { entries: parsed.entries.length, rows: ex.rows.length, header: parsed.header, skipped: skipped.length, skippedSample: skipped.slice(0, 20), lookup: opts.lookup, lookupOffReason: opts.lookup ? null : s.client ? 'turned off' : 'not connected to a tenant (sample or offline snapshot)' },
    touch: () => { s.last = Date.now(); }, expectation: opts.expected,
  };
  s.bulk = job;
  bulk.runJob(s, job, ex.rows, opts, { buildContext, simulate, urlLookup, URL_LOOKUP_MAX });
  console.log(`[bulk] ${job.total} rows (lookup ${opts.lookup ? 'on' : 'off'})`);
  res.json(bulk.status(job));
}));

// Category lookup for up to 100 destinations, plus the policy rules that reference each category.
app.post('/api/lookup', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const raw = Array.isArray(req.body.entries) ? req.body.entries : String(req.body.entries || '').split(/[\s,;]+/);
  const entries = [...new Set(raw.map((x) => String(x).trim()).filter(Boolean))];
  if (!entries.length) return res.status(400).json({ error: 'Enter a URL, host or IP to look up.' });
  if (entries.length > URL_LOOKUP_MAX) return res.status(400).json({ error: `Up to ${URL_LOOKUP_MAX} entries at a time. Use Bulk test for more.` });
  if (!s.client) return res.status(409).json({ error: 'Category lookup needs a live tenant connection (not sample policies or an offline snapshot).' });
  s.catCache = s.catCache || new Map();
  const keys = entries.map((e) => ({ entry: e, key: bulk.lookupKey(e) }));
  const need = [...new Set(keys.map((k) => k.key).filter((k) => k && !(s.catCache.has(k) && !s.catCache.get(k).error)))];
  if (need.length) {
    const out = await urlLookup(s.client, need);
    const by = new Map(out.map((o) => [String(o.url || '').toLowerCase(), o]));
    for (const k of need) { const o = by.get(k.toLowerCase()); s.catCache.set(k, o ? bulk.fromLookup(o) : { categories: [], security: [], error: 'not returned by lookup' }); }
  }
  const data = (s.snap && s.snap.data) || {};
  res.json({
    results: keys.map(({ entry, key }) => {
      if (!key) return { entry, error: 'CIDRs and ranges have no single category. Enter individual IPs.' };
      const c = s.catCache.get(key) || {};
      const cats = [...(c.categories || []), ...(c.security || [])];
      return { entry, key, categories: c.categories || [], security: c.security || [], application: c.application || '', error: c.error || null,
        kinds: Object.fromEntries(cats.map((x) => [x, recommend.categoryKind(x)])),
        rules: Object.fromEntries(cats.map((x) => [x, recommend.rulesForCategory(data, x)])) };
    }),
    policyLoaded: !!s.snap,
  });
}));

app.post('/api/bulk/status', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  res.json({ job: bulk.status(s.bulk) });
});

app.post('/api/bulk/cancel', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (s.bulk) s.bulk.cancelled = true;
  res.json({ ok: true });
});

app.get('/api/bulk/result', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const j = s.bulk;
  if (!j) return res.status(404).json({ error: 'No bulk test in this session.' });
  const filters = { flagged: (r) => r.error || r.action !== 'ALLOW' || r.couldBlock, mismatch: (r) => r.meets === 'no' };
  const only = filters[req.query.list || req.query.only] || null;
  if (req.query.list) {
    // Plain list of destinations (one per line), ready to paste into an IP destination group or custom URL category.
    const rows = j.results.filter(only || (() => true)).filter((r) => !req.query.area || r.area === req.query.area);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${j.name.replace(/[^\w.-]+/g, '_')}-${req.query.area ? req.query.area.replace(/\W+/g, '-').toLowerCase() + '-' : ''}destinations.txt"`);
    return res.send([...new Set(rows.map((r) => r.target))].join('\r\n') + '\r\n');
  }
  const stamp = new Date(j.started).toISOString().slice(0, 16).replace(/[:T]/g, '-');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${j.name.replace(/[^\w.-]+/g, '_')}-results${only ? '-' + (req.query.only || 'filtered') : ''}-${stamp}.csv"`);
  res.send('\uFEFF' + bulk.toCsv(j.results, only));
});

// ---------- policy changes ----------
// Write mode is off by default and per session. Sample / offline sessions apply changes to the in-memory policy only.
const apiFor = (s) => (s.demo ? (s.mockApi = s.mockApi || changes.mockApi(s.snap.data)) : changes.realApi(s.client));
const tenantOf = (s) => (s.demo ? 'sample policy (in memory)' : s.client.tokenHost.split('.')[0]);
function previewBody(b) {
  if (Array.isArray(b)) return b.length > 8 ? [...b.slice(0, 8).map(previewBody), `… ${(b.length - 8).toLocaleString()} more`] : b.map(previewBody);
  if (b && typeof b === 'object') return Object.fromEntries(Object.entries(b).map(([k, v]) => [k, previewBody(v)]));
  return b;
}
function auditWrite(s, entry) {
  try {
    const fs = require('fs'), os = require('os');
    const dir = path.join(os.homedir(), 'ZTP-Policy-Simulator', 'changes');
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(dir, `${tenantOf(s).replace(/\W+/g, '_')}.jsonl`), JSON.stringify(Object.assign({ tenant: tenantOf(s) }, entry)) + '\n');
  } catch (e) { console.error('[audit]', e.message); }
}
async function afterChange(s, keys) {
  if (!s.demo && s.client && keys && keys.length) await refreshKeys(s.client, s.snap, keys);
}

app.post('/api/changes/mode', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (req.body.enable !== undefined) s.writeEnabled = !!req.body.enable;
  res.json({ writeEnabled: !!s.writeEnabled, mock: !!s.demo, tenant: s.snap ? tenantOf(s) : null });
});

app.post('/api/changes/context', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.snap) return res.status(409).json({ error: 'Load policies first.' });
  const d = s.snap.data, arr = (x) => (Array.isArray(x) ? x : []);
  const ids = (l) => arr(l).map((c) => String((c && c.id) || c));
  const rules = (k) => arr(d[k]).filter((r) => !r.defaultRule).sort((a, b) => a.order - b.order)
    .map((r) => ({ id: r.id, name: r.name, order: r.order, action: r.action, state: r.state, cats: [...ids(r.urlCategories), ...ids(r.destIpCategories), ...ids(r.resCategories)], groups: ids(r.destIpGroups) }));
  res.json({
    tenant: tenantOf(s), mock: !!s.demo, writeEnabled: !!s.writeEnabled, errors: s.snap.errors,
    categories: arr(d.customUrlCategories).map((c) => ({ id: c.id, name: c.configuredName || c.id, count: arr(c.urls).length + arr(c.ipRanges).length })),
    groups: arr(d.ipDestinationGroups).map((g) => ({ id: g.id, name: g.name, type: g.type || 'DSTN_IP', count: arr(g.addresses).length })),
    rules: { url: rules('urlFilteringRules'), firewall: rules('firewallRules'), dns: rules('dnsRules') },
    locations: arr(d.locations).map((l) => ({ id: l.id, name: l.name })),
    limits: { groupMax: changes.GROUP_MAX, nameMax: changes.NAME_MAX },
  });
});

// Directory search for rule criteria (groups, departments, users).
// Identity search for the "Compare as" pickers: users and groups from ZIdentity, ZIA and ZPA SCIM, labelled by source.
app.post('/api/identities', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const q = String((req.body && req.body.q) || '').trim();
  if (q.length < 2) return res.json({ results: [] });
  const ql = q.toLowerCase(), out = [], failed = [];
  const hit = (v) => String(v || '').toLowerCase().includes(ql); // every source is filtered here, whatever the API returned
  const add = (x) => { if (!out.some((y) => y.kind === x.kind && lc2(y.name) === lc2(x.name) && lc2(y.email) === lc2(x.email))) out.push(x); else { const y = out.find((y2) => y2.kind === x.kind && lc2(y2.name) === lc2(x.name) && lc2(y2.email) === lc2(x.email)); if (!y.source.includes(x.source)) y.source += ' · ' + x.source; if (x.zidId && !y.zidId) y.zidId = x.zidId; } };
  const d = (s.snap && s.snap.data) || {};
  if (s.demo || !s.client) {
    for (const u of d.demoUsers || []) if ((u.name + ' ' + u.email).toLowerCase().includes(ql)) add({ kind: 'user', name: u.name, email: u.email, source: 'sample' });
    const groups = new Set([...Object.values(d.zpaScimGroups || {}).flat().map((g) => g.name), ...(d.demoUsers || []).flatMap((u) => u.groups)]);
    for (const k of ['urlFilteringRules', 'firewallRules', 'dnsRules', 'sslRules', 'webDlpRules']) for (const r of d[k] || []) for (const g of r.groups || []) groups.add(g.name);
    for (const g of groups) if (String(g).toLowerCase().includes(ql)) add({ kind: 'group', name: g, source: 'sample' });
    return res.json({ results: out.slice(0, 30) });
  }
  const c = s.client, recs = (x) => (Array.isArray(x) ? x : (x && (x.records || x.list)) || []);
  const tries = [
    ['ZIdentity', async () => {
      const idx = await zidIndex(c);
      for (const u of idx.users) if ([u.displayName, u.loginName, u.primaryEmail].some(hit)) add({ kind: 'user', name: u.displayName || u.loginName, email: u.primaryEmail || u.loginName, source: 'ZIdentity', zidId: u.id });
      for (const g of idx.groups) if (hit(g.name || g.displayName)) add({ kind: 'group', name: g.name || g.displayName, source: 'ZIdentity' });
    }],
    ['ZIA users', async () => { for (const u of recs(await c.get(`${ZIA}/users`, { search: q, pageSize: '50' }))) if (hit(u.name) || hit(u.email)) add({ kind: 'user', name: u.name, email: u.email, source: 'ZIA' }); }],
    ['ZIA groups', async () => { for (const g of recs(await c.get(`${ZIA}/groups`, { search: q, pageSize: '50' }))) if (hit(g.name)) add({ kind: 'group', name: g.name, source: 'ZIA' }); }],
  ];
  if (c.cfg.zpaCustomerId) {
    const idps = (d.zpaIdps || []).filter((i) => i.scimEnabled || i.enableScimBasedPolicy).slice(0, 4);
    for (const idp of idps) tries.push([`ZPA SCIM (${idp.name})`, async () => {
      const r = await c.get(`/zpa/userconfig/v1/customers/${c.cfg.zpaCustomerId}/scimgroup/idpId/${encodeURIComponent(idp.id)}`, { search: q, pagesize: '20' });
      for (const g of recs(r)) if (hit(g.name)) add({ kind: 'group', name: g.name, source: `ZPA SCIM · ${idp.name}` });
    }]);
  }
  await Promise.all(tries.map(([name, fn]) => fn().catch((e) => failed.push(`${name}: ${e.status || e.message}`))));
  const pre = (x) => ([x.name, x.email].some((v) => lc2(v).startsWith(ql)) ? 0 : 1);
  out.sort((a, b2) => (a.kind === b2.kind ? 0 : a.kind === 'user' ? -1 : 1) || pre(a) - pre(b2) || lc2(a.name).localeCompare(lc2(b2.name)));
  res.json({ results: out.filter((x) => x.name).slice(0, 30), failed });
}));
const lc2 = (v) => String(v || '').toLowerCase();

app.post('/api/directory', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const type = ['groups', 'departments', 'users'].includes(req.body.type) ? req.body.type : 'groups';
  const q = String(req.body.q || '').trim();
  let list = [];
  if (s.demo || !s.client) {
    const seen = new Map();
    for (const k of ['urlFilteringRules', 'firewallRules', 'dnsRules', 'sslRules', 'webDlpRules']) for (const r of (s.snap && s.snap.data[k]) || []) for (const x of r[type] || []) if (x && x.name) seen.set(String(x.id), { id: x.id, name: x.name });
    list = [...seen.values()];
  } else {
    let ziaErr = null;
    try {
      const out = await s.client.get(`${ZIA}/${type}`, Object.assign({ pageSize: '50' }, q ? { search: q } : {}));
      list = (Array.isArray(out) ? out : []).map((x) => ({ id: x.id, name: x.name || x.email, email: x.email }));
    } catch (e) { ziaErr = e; }
    if (ziaErr && type !== 'departments') {
      // ZIA refused (e.g. 403): show ZIdentity matches, but ZIA rules need ZIA IDs, so they are listed for reference only.
      const recs = (x) => (Array.isArray(x) ? x : (x && x.records) || []);
      try {
        const r = await s.client.get(`/ziam/admin/api/v1/${type}`, Object.assign({ limit: '50' }, q ? { [type === 'users' ? 'displayName[like]' : 'name[like]']: q } : {}));
        list = recs(r).map((x) => ({ id: null, name: x.name || x.displayName || x.loginName, email: x.primaryEmail, note: 'ZIdentity (not usable in a ZIA rule until it syncs to ZIA)' }));
      } catch { throw ziaErr; }
    }
  }
  if (q) list = list.filter((x) => (x.name + ' ' + (x.email || '')).toLowerCase().includes(q.toLowerCase()));
  res.json({ results: list.slice(0, 50) });
}));

// Resolve a bulk selection (filter and/or ticked rows) into destinations.
app.post('/api/bulk/select', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const j = s.bulk; if (!j) return res.status(404).json({ error: 'No bulk test in this session.' });
  const f = req.body.filter || {}, ticked = new Set((req.body.rows || []).map(String));
  const rows = j.results.filter((r) => !r.error && (ticked.size ? ticked.has(String(r.row)) : true)
    && (!f.results || !f.results.length || f.results.includes(r.result))
    && (!f.mismatch || r.meets === 'no')
    && (!f.category || (r.category || '').split('; ').includes(f.category))
    && (!f.area || r.area === f.area));
  const blocked = rows.filter((r) => r.action !== 'ALLOW' && r.action !== 'BYPASS');
  const deciders = {};
  for (const r of blocked) { const k = `${r.module}|${r.rule}`; deciders[k] = (deciders[k] || 0) + 1; }
  res.json({ count: rows.length, targets: [...new Set(rows.map((r) => r.target))], blocked: blocked.length, allowed: rows.filter((r) => r.action === 'ALLOW').length,
    bypassed: rows.filter((r) => r.action === 'BYPASS').length, deciders: Object.entries(deciders).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, n]) => ({ module: k.split('|')[0], rule: k.split('|')[1], count: n })) });
});

app.post('/api/changes/plan', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.snap) return res.status(409).json({ error: 'Load policies first.' });
  const spec = req.body.spec || {};
  const p = spec.kind === 'zpa' ? changes.planZpa(spec, s.snap.data) : changes.plan(spec, s.snap.data);
  s.plans = s.plans || new Map(); s.plans.set(p.id, p);
  res.json(Object.assign({}, p, { entries: undefined, steps: p.steps.map((st) => ({ title: st.title, method: st.method, path: (st.api === 'zpa' ? `/zpa/mgmtconfig/v1/admin/customers/${(s.client && s.client.cfg.zpaCustomerId) || '{customerId}'}` : '/zia/api/v1') + st.path, body: previewBody(st.body) })), tenant: tenantOf(s), mock: !!s.demo, writeEnabled: !!s.writeEnabled }));
});

// ZPA context for the "private application" change: segments, groups, server groups, access rules, IdPs, SAML attributes.
app.post('/api/zpa/context', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const d = (s.snap && s.snap.data) || {}, arr = (x) => (Array.isArray(x) ? x : []);
  if (!d.zpaApps && !d.zpaAccessRules) return res.status(409).json({ error: 'ZPA policy is not loaded. Tick Private Access (ZPA) in Load policies and reload.' });
  res.json({
    segments: arr(d.zpaApps).map((a) => ({ id: a.id, name: a.name, count: arr(a.domainNames).length, segmentGroupId: a.segmentGroupId, bypassType: a.bypassType })),
    segmentGroups: arr(d.zpaSegmentGroups).map((g) => ({ id: g.id, name: g.name })),
    serverGroups: arr(d.zpaServerGroups).map((g) => ({ id: g.id, name: g.name })),
    rules: arr(d.zpaAccessRules).map((r) => ({ id: r.id, name: r.name, order: r.ruleOrder != null ? +r.ruleOrder : r.order, action: r.action })).sort((a, b) => a.order - b.order),
    idps: arr(d.zpaIdps).map((i) => ({ id: i.id, name: i.name, scim: !!(i.scimEnabled || i.enableScimBasedPolicy) })),
    saml: arr(d.zpaSamlAttributes).map((a) => ({ id: a.id, name: a.name, idpId: a.idpId })),
    policySet: !!(d.zpaAccessPolicySet && (d.zpaAccessPolicySet.id || (Array.isArray(d.zpaAccessPolicySet) && d.zpaAccessPolicySet.length))),
    errors: Object.fromEntries(Object.entries(s.snap.errors || {}).filter(([k]) => k.startsWith('zpa'))),
  });
});

app.post('/api/zpa/scim', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const idp = String(req.body.idpId || ''), q = String(req.body.q || '').trim().toLowerCase();
  let list = [];
  if (s.demo || !s.client) list = ((s.snap.data.zpaScimGroups || {})[idp] || []);
  else {
    const out = await s.client.get(`/zpa/userconfig/v1/customers/${s.client.cfg.zpaCustomerId}/scimgroup/idpId/${encodeURIComponent(idp)}`, Object.assign({ pagesize: '100' }, q ? { search: q } : {}));
    list = (Array.isArray(out) ? out : (out && out.list) || []).map((g) => ({ id: g.id, name: g.name }));
  }
  if (q) list = list.filter((g) => String(g.name).toLowerCase().includes(q));
  res.json({ results: list.slice(0, 50) });
}));

app.post('/api/changes/apply', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const p = s.plans && s.plans.get(req.body.planId);
  if (!p) return res.status(404).json({ error: 'That preview has expired. Preview the change again.' });
  if (p.errors.length) return res.status(400).json({ error: p.errors.join(' ') });
  if (!s.writeEnabled) return res.status(403).json({ error: 'Policy changes are switched off for this session. Turn on "Allow policy changes" first.' });
  if (req.body.confirm !== true) return res.status(400).json({ error: 'Confirmation required.' });
  const api = apiFor(s);
  const entry = await changes.apply(p, api);
  s.plans.delete(p.id);
  await afterChange(s, p.refreshKeys);
  let status = null; try { status = (await api.request('GET', '/status')).status; } catch {}
  s.changeLog = s.changeLog || []; s.changeLog.unshift(entry);
  auditWrite(s, { type: 'apply', id: entry.id, at: entry.at, intent: entry.intent, summary: entry.summary, done: entry.done.map((d) => ({ title: d.title, method: d.method, path: d.path })), failed: entry.failed });
  console.log(`[change] ${tenantOf(s)}: ${entry.done.length}/${p.steps.length} steps${entry.failed ? ' FAILED: ' + entry.failed.error : ''}`);
  res.json({ entry: logView(entry), activation: status, mock: !!s.demo });
}));

const logView = (e) => ({ id: e.id, at: e.at, intent: e.intent, summary: e.summary, done: e.done.map((d) => ({ title: d.title, method: d.method, path: d.path })), failed: e.failed, undone: e.undone, undoResults: e.undoResults });

app.post('/api/changes/log', (req, res) => {
  const s = getSession(req, res); if (!s) return;
  res.json({ entries: (s.changeLog || []).map(logView) });
});

app.post('/api/changes/undo', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.writeEnabled) return res.status(403).json({ error: 'Turn on "Allow policy changes" to undo.' });
  const e = (s.changeLog || []).find((x) => x.id === req.body.id);
  if (!e) return res.status(404).json({ error: 'Change not found.' });
  if (e.undone) return res.status(409).json({ error: 'Already undone.' });
  const api = apiFor(s);
  const results = await changes.undo(e, api);
  await afterChange(s, e.refreshKeys);
  auditWrite(s, { type: 'undo', id: e.id, at: Date.now(), results });
  let status = null; try { status = (await api.request('GET', '/status')).status; } catch {}
  res.json({ entry: logView(e), activation: status });
}));

app.post('/api/changes/status', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  const out = await apiFor(s).request('GET', '/status');
  res.json({ status: out && out.status, mock: !!s.demo });
}));

app.post('/api/changes/activate', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.writeEnabled) return res.status(403).json({ error: 'Turn on "Allow policy changes" to activate.' });
  const out = await apiFor(s).request('POST', '/status/activate');
  auditWrite(s, { type: 'activate', at: Date.now(), result: out && out.status });
  res.json({ status: out && out.status, mock: !!s.demo });
}));

app.listen(PORT, HOST, () => {
  const url = `http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`;
  console.log(`ZeroTrustPanda ZS Policy Simulator v${VERSION} running at ${url}`);
  if (!process.argv.includes('--no-open') && !process.env.NO_OPEN) {
    const cmd = process.platform === 'win32' ? `start "" ${url}` : process.platform === 'darwin' ? `open ${url}` : `xdg-open ${url}`;
    exec(cmd, () => {});
  }
}).on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error(`Port ${PORT} is already in use — close the other copy of the simulator, or start with PORT=8788.`);
  else console.error(e.message);
  process.exitCode = 1;
});

module.exports = app;
