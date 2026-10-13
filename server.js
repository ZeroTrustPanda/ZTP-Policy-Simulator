'use strict';
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const { exec } = require('child_process');

const { ZClient, loadSnapshot, probe, catalog, lookupUser, urlLookup } = require('./src/zscaler');
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

setInterval(() => { const now = Date.now(); for (const [k, v] of sessions) if (now - v.last > SESSION_TTL) sessions.delete(k); }, 60000).unref();

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
  res.json({ sessionId: id, tokenHost: client.tokenHost, apiHost: client.apiHost, probe: pr, catalog: catalog(client).map((e) => ({ key: e.key, label: e.label, group: e.group })) });
}));

// Step 2: load policies (background job; poll /api/load-status).
app.post('/api/load', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (s.demo) return res.json({ started: false, done: true, snapshot: snapInfo(s) });
  if (s.job && !s.job.done) return res.json({ started: false, running: true });
  const groups = Array.isArray(req.body.groups) && req.body.groups.length ? req.body.groups : ['zia', 'zcc', 'zpa'];
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
  };
  if (b.ip) {
    if (!t) ctx.target = M.parseTarget(b.ip);
    else if (!t.isIp) ctx.resolvedIps.push(b.ip);
  }
  const tg = ctx.target;
  if (tg && !tg.isIp && !tg.isWildcard && !b.ip) {
    try { ctx.resolvedIps = (await dns.resolve4(tg.host)).slice(0, 8); } catch { ctx.notes.push(`DNS resolution of ${tg.host} failed locally; IP-based rules may show as unknown.`); }
  }
  if (b.categories && b.categories.length) ctx.categories = b.categories;
  else if (tg && !s.demo && s.client && !tg.isIp) {
    try {
      const probeHost = tg.isWildcard ? 'www.' + tg.host.replace(/^\*\.?/, '') : tg.host;
      const out = await urlLookup(s.client, [probeHost]);
      if (out[0]) ctx.categories = [...(out[0].urlClassifications || []), ...(out[0].urlClassificationsWithSecurityAlert || [])];
      if (tg.isWildcard) ctx.notes.push(`Wildcard query: categories taken from probe host ${probeHost}.`);
    } catch (e) { ctx.notes.push(`URL category lookup failed: ${e.message}`); }
  }
  if (b.user && !s.demo && s.client && !(b.groups && b.groups.length)) {
    try {
      const u = await lookupUser(s.client, b.user);
      if (u) { ctx.groups = u.groups; ctx.department = ctx.department || u.department; ctx.userResolved = u; }
      else ctx.notes.push(`User "${b.user}" not found in ZIA; group/department rules will show as unknown unless you enter them.`);
    } catch (e) { ctx.notes.push(`User lookup failed: ${e.message}`); }
  }
  return ctx;
}

app.post('/api/simulate', wrap(async (req, res) => {
  const s = getSession(req, res); if (!s) return;
  if (!s.snap) return res.status(409).json({ error: 'Policies are not loaded yet. Click "Load policies" first.' });
  const b = req.body;
  if (!b.target && !b.ip && !b.port && !b.networkService && !b.application && !b.fileType) return res.status(400).json({ error: 'Enter at least a destination, port, network service, application or file type.' });
  const ctx = await buildContext(s, b);
  const out = simulate(s.snap, ctx, b.manual || {});
  out.snapshot = { loadedAt: s.snap.loadedAt, errors: s.snap.errors, counts: counts(s.snap) };
  res.json(out);
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
