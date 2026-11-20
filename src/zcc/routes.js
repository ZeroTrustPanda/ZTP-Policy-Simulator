'use strict';
// From ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission;
// ported to CommonJS and mounted at /zcc inside the Zscaler Policy Troubleshooting Toolkit.
// The JSON API (routes below) is the original one; only the HTTP server around it changed.

const { expandUpload } = require('./parser');
const { createDataset, deleteDataset, getDataset, listDatasets } = require('./store');
const { readLocalLogs, localLogDirs } = require('./local');
const { matchSegment } = require('./zpa');

const MAX_UPLOAD = 1024 * 1024 * 1024;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(data);
}

async function readBody(req, limit = MAX_UPLOAD) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw new HttpError(413, 'Upload too large');
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

async function readJson(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body) && req._body) return req.body; // already parsed by express.json
  const buf = await readBody(req, 1024 * 1024);
  if (!buf.length) return {};
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw new HttpError(400, 'Invalid JSON body');
  }
}

function need(id) {
  const d = getDataset(id);
  if (!d) throw new HttpError(404, 'Dataset not found');
  if (!d.ready) throw new HttpError(409, 'Dataset not finalized');
  return d;
}

function filterParams(sp) {
  const num = (k) => (sp.get(k) ? Number(sp.get(k)) : undefined);
  return {
    q: sp.get('q') || undefined,
    regex: sp.get('regex') === '1' || undefined,
    levels: sp.get('levels') || undefined,
    comps: sp.get('comps') || undefined,
    svc: ['zpa', 'zia'].includes(sp.get('svc')) ? sp.get('svc') : sp.get('zpa') === '1' ? 'zpa' : undefined,
    hideNoise: sp.get('hideNoise') === '1' || undefined,
    from: num('from'),
    to: num('to'),
    tag: /^\d+$/.test(sp.get('tag') || '') ? sp.get('tag') : undefined,
  };
}

function entryOut(tl, i, full = false) {
  const msg = tl.msg(i);
  const nl = msg.indexOf('\n');
  return {
    i,
    ts: tl.ts[i],
    time: tl.time(i),
    tz: tl.tzText(i),
    lvl: tl.level(i),
    comp: tl.comp(i),
    pid: tl.pid[i] || null,
    tid: tl.tid[i] || null,
    file: tl.files[tl.file[i]].name,
    line: tl.line[i],
    zpa: tl.isZpa(i),
    zia: tl.isZia(i),
    multi: nl !== -1,
    // Preview: the first non-empty line (some entries start with a bare newline).
    msg: full ? msg : (nl === -1 ? msg : msg.split('\n').find((l) => l.trim()) || '').slice(0, 2000),
  };
}

// Route table: [method, regex, handler(match, req, url, res)]
const routes = [
  ['GET', /^\/api\/datasets$/, () => listDatasets()],
  ['GET', /^\/api\/local$/, () => ({ dirs: localLogDirs() })],
  [
    'POST',
    /^\/api\/datasets$/,
    async (_m, req) => {
      const body = await readJson(req);
      const d = createDataset(String(body.name || 'Upload').slice(0, 200), 'upload');
      return d.meta();
    },
  ],
  [
    'POST',
    /^\/api\/datasets\/local$/,
    async (_m, req) => {
      const body = await readJson(req);
      const { dirs, files, skipped } = await readLocalLogs({ includeUpm: !!body.includeUpm, sinceDays: Number(body.sinceDays) || 0 });
      if (!files.length) throw new HttpError(404, `No ZCC logs found in ${dirs.join(', ') || '(no known directories for this OS)'}. Set ZCC_LOG_DIRS to point at your log folder.`);
      const d = createDataset(`This machine (${new Date().toLocaleString()})`, 'local');
      d.addFiles(files);
      for (const s of skipped) d.warnings.push(`Skipped ${s}`);
      d.finalize();
      return d.summary();
    },
  ],
  [
    'POST',
    /^\/api\/datasets\/([\w-]+)\/files$/,
    async (m, req, url) => {
      const d = getDataset(m[1]);
      if (!d) throw new HttpError(404, 'Dataset not found');
      if (d.ready) throw new HttpError(409, 'Dataset already finalized');
      const name = decodeURIComponent(req.headers['x-filename'] || 'upload.log');
      const bytes = new Uint8Array(await readBody(req));
      const files = expandUpload(name, bytes, { includeUpm: url.searchParams.get('includeUpm') === '1' });
      d.addFiles(files);
      return { name, extracted: files.map((f) => f.name) };
    },
  ],
  [
    'POST',
    /^\/api\/datasets\/([\w-]+)\/finalize$/,
    (m) => {
      const d = getDataset(m[1]);
      if (!d) throw new HttpError(404, 'Dataset not found');
      if (!d.pending.length && !d.ready) throw new HttpError(400, 'No log files were found in the upload');
      if (!d.ready) d.finalize();
      return d.summary();
    },
  ],
  [
    'DELETE',
    /^\/api\/datasets\/([\w-]+)$/,
    (m) => {
      if (!deleteDataset(m[1])) throw new HttpError(404, 'Dataset not found');
      return { ok: true };
    },
  ],
  ['GET', /^\/api\/datasets\/([\w-]+)\/summary$/, (m) => need(m[1]).summary()],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/entries$/,
    (m, _req, url) => {
      const d = need(m[1]);
      const sp = url.searchParams;
      const idx = d.filter(filterParams(sp));
      const offset = Math.max(0, Number(sp.get('offset')) || 0);
      const limit = Math.min(2000, Math.max(1, Number(sp.get('limit')) || 200));
      const out = [];
      for (let k = offset; k < Math.min(idx.length, offset + limit); k++) out.push(entryOut(d.tl, idx[k]));
      return { total: idx.length, offset, entries: out };
    },
  ],
  [
    // Position of an entry within a filtered list (or the nearest following one).
    'GET',
    /^\/api\/datasets\/([\w-]+)\/locate$/,
    (m, _req, url) => {
      const d = need(m[1]);
      const target = Number(url.searchParams.get('i'));
      const idx = d.filter(filterParams(url.searchParams));
      let lo = 0;
      let hi = idx.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (idx[mid] < target) lo = mid + 1;
        else hi = mid;
      }
      return { position: Math.min(lo, Math.max(0, idx.length - 1)), exact: idx[lo] === target, total: idx.length };
    },
  ],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/entries\/(\d+)$/,
    (m) => {
      const d = need(m[1]);
      const i = Number(m[2]);
      if (!(i < d.tl.length)) throw new HttpError(404, 'Entry not found');
      return entryOut(d.tl, i, true);
    },
  ],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/zpa\/overview$/,
    (m) => {
      const z = need(m[1]).zpa;
      return { info: z.info, sessions: z.sessions, events: z.events, states: z.states.map(({ key, ...s }) => s), dnsChecks: z.dnsChecks };
    },
  ],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/zpa\/segments$/,
    (m) => {
      const z = need(m[1]).zpa;
      return { segments: z.segments, history: z.segmentHistory, batches: z.segmentBatches };
    },
  ],
  [
    // Which received segment domain would a destination match?
    'GET',
    /^\/api\/datasets\/([\w-]+)\/zpa\/match$/,
    (m, _req, url) => {
      const z = need(m[1]).zpa;
      const sp = url.searchParams;
      const host = (sp.get('host') || '').trim();
      if (!host) throw new HttpError(400, 'host is required');
      const port = sp.get('port') ? Number(sp.get('port')) : null;
      const proto = sp.get('proto') === 'udp' ? 17 : sp.get('proto') === 'icmp' ? 1 : 6;
      const match = matchSegment(z.segments, host, port, proto);
      const seen = z.mtunnels.filter((x) => x.app.toLowerCase() === host.toLowerCase()).length;
      return { host, port, proto, match, segment: match ? z.segments.find((s) => s.domain === match.domain) : null, mtunnelsSeen: seen };
    },
  ],
  ['GET', /^\/api\/datasets\/([\w-]+)\/zpa\/apps$/, (m) => need(m[1]).apps],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/zpa\/mtunnels$/,
    (m, _req, url) => {
      const z = need(m[1]).zpa;
      const sp = url.searchParams;
      const app = sp.get('app');
      const seg = sp.get('segment');
      const status = sp.get('status');
      let list = z.mtunnels;
      if (app !== null) list = list.filter((x) => x.app === app);
      if (seg !== null) list = list.filter((x) => x.segment === seg);
      if (status) list = list.filter((x) => x.status === status);
      const limit = Math.min(5000, Number(sp.get('limit')) || 1000);
      return { total: list.length, mtunnels: list.slice(-limit).reverse() };
    },
  ],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/errors$/,
    (m) => {
      const d = need(m[1]);
      return { zpn: d.zpa.zpnErrors, zia: d.zia.errors, groups: d.triage };
    },
  ],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/zia\/overview$/,
    (m) => {
      const d = need(m[1]);
      const z = d.zia;
      return {
        info: z.info,
        stateChanges: z.stateChanges,
        events: z.events,
        health: z.health,
        healthChecks: z.healthChecks.slice(-2000),
        apiLookups: z.apiLookups.slice(-2000),
        states: d.zpa.states.map(({ key, ...s }) => s),
      };
    },
  ],
  ['GET', /^\/api\/datasets\/([\w-]+)\/zia\/hosts$/, (m) => need(m[1]).hosts],
  [
    'GET',
    /^\/api\/datasets\/([\w-]+)\/zia\/flows$/,
    (m, _req, url) => {
      const z = need(m[1]).zia;
      const sp = url.searchParams;
      const host = sp.get('host');
      const status = sp.get('status');
      let list = z.flows;
      if (host !== null) list = list.filter((f) => (f.host || f.dst || '(unknown)') === host);
      if (status) list = list.filter((f) => f.status === status);
      const limit = Math.min(5000, Number(sp.get('limit')) || 1000);
      return { total: list.length, flows: list.slice(-limit).reverse() };
    },
  ],
];


// Express-style handler for everything under the mount point (/zcc). Only /api/* is handled here; the
// static UI is served by express.static from public/zcc.
async function handler(req, res, next) {
  const url = new URL(req.url, 'http://localhost');
  if (!url.pathname.startsWith('/api/')) return next();
  try {
    for (const [method, rx, h] of routes) {
      if (req.method !== method) continue;
      const m = rx.exec(url.pathname);
      if (!m) continue;
      const out = await h(m, req, url, res);
      return send(res, 200, out);
    }
    throw new HttpError(404, 'Unknown API route');
  } catch (err) {
    const status = err.status || 500;
    if (status === 500) console.error('[zcc]', err.message);
    if (!res.headersSent) send(res, status, { error: err.message });
  }
}

module.exports = { handler, routes };
