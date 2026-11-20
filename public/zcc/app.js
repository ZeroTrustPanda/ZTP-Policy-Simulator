// ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission.
// Toolkit changes: API under /zcc, toolkit theme, and "Simulate policy" buttons that hand a destination to the Policy Simulator.
// ZCC Log Explorer frontend. No build step: plain ES modules + the JSON API in server/.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmtN = (n) => (n == null ? '—' : Number(n).toLocaleString());
const fmtBytes = (n) => {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let k = 0;
  while (n >= 1024 && k < u.length - 1) {
    n /= 1024;
    k++;
  }
  return `${k ? n.toFixed(n < 10 ? 1 : 0) : n} ${u[k]}`;
};
const pct = (a, b) => (b ? `${Math.round((a / b) * 100)}%` : '—');

const store = {
  get(k) {
    try {
      return localStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set(k, v) {
    try {
      localStorage.setItem(k, v);
    } catch {
      /* storage unavailable */
    }
  },
};

const state = {
  datasets: [],
  ds: null, // active dataset id
  summary: null,
  cache: {}, // per-dataset API results
  tl: null, // timeline state, created per dataset
};

// ---------------------------------------------------------------- API

// Toolkit: the explorer's API is mounted at /zcc/api.
const API_BASE = '/zcc';
// Toolkit: when shown inside the toolkit, destinations can be sent to the Policy Simulator.
const EMBEDDED = window.parent !== window;
const simBtn = (target, port, protocol = 'tcp') =>
  EMBEDDED && target ? `<button type="button" class="btn small sim" data-sim="${esc(JSON.stringify({ target, port: port || null, protocol }))}" title="Run this destination through the Policy Simulator">▶ Simulate policy</button>` : '';
document.addEventListener('click', (ev) => {
  const b = ev.target.closest('[data-sim]');
  if (!b) return;
  ev.preventDefault();
  ev.stopPropagation();
  try {
    window.parent.postMessage({ type: 'ztp-simulate', source: 'ZCC Log Explorer', ...JSON.parse(b.dataset.sim) }, location.origin);
  } catch {}
});

async function api(path, opts = {}) {
  const res = await fetch(path.startsWith('/api/') ? API_BASE + path : path, opts);
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok) throw new Error(body?.error || `${res.status} ${res.statusText}`);
  return body;
}
async function dsApi(path) {
  try {
    return await api(`/api/datasets/${state.ds}${path}`);
  } catch (err) {
    // The server keeps datasets in memory; after a restart the old id is gone.
    if (err.message === 'Dataset not found') {
      toast('That dataset is no longer on the server (restarted?). Switching…');
      state.ds = null;
      state.summary = null;
      refreshDatasets();
    }
    throw err;
  }
}
async function cached(key, path) {
  const c = (state.cache[state.ds] ||= {});
  if (!c[key]) c[key] = dsApi(path).catch((e) => {
    delete c[key];
    throw e;
  });
  return c[key];
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 2600);
}

// ---------------------------------------------------------------- time
// Timestamps arrive as epoch ms and are shown in the viewer's own time zone.

const VIEWER_TZ = Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time';
function tzAbbr(ts) {
  const part = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' })
    .formatToParts(new Date(ts ?? Date.now()))
    .find((x) => x.type === 'timeZoneName');
  return part?.value || VIEWER_TZ;
}
function fmtTs(ts, { date = true, ms = true } = {}) {
  if (ts == null) return '—';
  const d = new Date(ts);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  const t = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}${ms ? '.' + p(d.getMilliseconds(), 3) : ''}`;
  return date ? `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${t}` : t;
}
function fmtDur(ms) {
  if (ms == null) return '—';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = s / 60;
  if (m < 60) return `${Math.floor(m)}m ${Math.round(s % 60)}s`;
  const h = m / 60;
  if (h < 48) return `${Math.floor(h)}h ${Math.round(m % 60)}m`;
  return `${Math.floor(h / 24)}d ${Math.round(h % 24)}h`;
}

// ---------------------------------------------------------------- shared UI bits

const STATUS_PILL = {
  established: ['ok', 'no close logged'],
  closed: ['ok', 'closed'],
  failed: ['error', 'failed'],
  pending: ['warn', 'no response'],
  unknown: ['info', 'unknown'],
};
const pill = (cls, text) => `<span class="pill ${cls}">${esc(text)}</span>`;
const mtPill = (s) => pill(...(STATUS_PILL[s] || ['info', s]));

function ratioBar(ok, failed) {
  const total = ok + failed;
  if (!total) return '';
  return `<span class="ratio" title="${ok} ok, ${failed} failed"><span style="width:${(ok / total) * 100}%;background:var(--series-ok)"></span><span style="width:${(failed / total) * 100}%;background:var(--critical)"></span></span>`;
}

/**
 * Sortable table. columns: {key, label, num?, render?(row), sortVal?(row), cls?}
 * detail(row) → HTML or Promise<HTML> shown in an expandable row.
 */
function table(container, { columns, rows, sortKey, sortDir = 'desc', onClick, detail, empty = 'Nothing to show', rowKey = (r, i) => i }) {
  let key = sortKey;
  let dir = sortDir;
  let open = null;
  const wrap = document.createElement('div');
  wrap.className = 'table-wrap';
  container.replaceChildren(wrap);

  function sorted() {
    if (!key) return rows;
    const col = columns.find((c) => c.key === key);
    const val = col.sortVal || ((r) => r[key]);
    return [...rows].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = x == null ? 1 : y == null ? -1 : typeof x === 'number' ? x - y : String(x).localeCompare(String(y));
      return dir === 'asc' ? c : -c;
    });
  }
  function draw() {
    const list = sorted();
    const head = columns
      .map((c) => `<th class="sortable ${c.num ? 'num' : ''}" data-k="${c.key}" scope="col">${esc(c.label)}${key === c.key ? ` <span class="arrow">${dir === 'asc' ? '▲' : '▼'}</span>` : ''}</th>`)
      .join('');
    const body = list.length
      ? list
          .map((r, i) => {
            const k = rowKey(r, i);
            const tds = columns.map((c) => `<td class="${c.num ? 'num' : ''} ${c.cls || ''}">${c.render ? c.render(r) : esc(r[c.key])}</td>`).join('');
            const sel = open === k;
            return `<tr class="${onClick || detail ? 'clickable' : ''} ${sel ? 'selected' : ''}" data-k="${esc(k)}">${tds}</tr>${sel && detail ? `<tr class="detail-row"><td colspan="${columns.length}"><div class="detail-slot muted">Loading…</div></td></tr>` : ''}`;
          })
          .join('')
      : `<tr><td colspan="${columns.length}" class="muted">${esc(empty)}</td></tr>`;
    wrap.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
    if (open != null && detail) {
      const row = list.find((r, i) => String(rowKey(r, i)) === String(open));
      const slot = $('.detail-slot', wrap);
      if (row && slot)
        Promise.resolve(detail(row, slot)).then((html) => {
          if (typeof html === 'string') {
            slot.classList.remove('muted');
            slot.innerHTML = html;
          }
        });
    }
  }
  wrap.addEventListener('click', (ev) => {
    const th = ev.target.closest('th[data-k]');
    if (th) {
      if (key === th.dataset.k) dir = dir === 'asc' ? 'desc' : 'asc';
      else {
        key = th.dataset.k;
        dir = columns.find((c) => c.key === key).num ? 'desc' : 'asc';
      }
      draw();
      return;
    }
    if (ev.target.closest('.detail-row, a, button')) return;
    const tr = ev.target.closest('tr[data-k]');
    if (!tr) return;
    const list = sorted();
    const idx = list.findIndex((r, i) => String(rowKey(r, i)) === tr.dataset.k);
    const row = list[idx];
    if (detail) {
      open = String(open) === tr.dataset.k ? null : tr.dataset.k;
      draw();
    } else if (onClick) onClick(row);
  });
  draw();
  return {
    update(newRows) {
      rows = newRows;
      draw();
    },
  };
}

function mtunnelTable(container, mts) {
  return table(container, {
    rows: mts,
    rowKey: (r) => r.id,
    sortKey: 'ts',
    empty: 'No mTunnels',
    columns: [
      { key: 'ts', label: 'Time', render: (r) => `<span class="mono">${esc(fmtTs(r.ts))}</span>`, cls: 'mono' },
      { key: 'app', label: 'App', cls: 'wrap' },
      { key: 'port', label: 'Proto / port', render: (r) => `${esc(r.proto)}/${esc(r.port)}`, sortVal: (r) => r.port },
      { key: 'status', label: 'Result', render: (r) => mtPill(r.status) },
      { key: 'reason', label: 'Reason', render: (r) => (r.reason ? `<code>${esc(r.reason)}</code>` : '<span class="muted">—</span>'), cls: 'wrap' },
      { key: 'setupMs', label: 'Setup', num: true, render: (r) => (r.setupMs != null ? fmtDur(r.setupMs) : '—') },
      { key: 'tag', label: 'Tag', num: true },
      { key: 'link', label: '', render: (r) => `<a href="#/timeline?tag=${r.tag}&i=${r.i}">logs →</a>` },
    ],
  });
}

// ---------------------------------------------------------------- charts

/** Stacked bars of mTunnel outcomes per time bucket, with a hover tooltip. */
function outcomeChart(container, hist, { okLabel = 'Completed / open', failLabel = 'Failed', empty = 'No mTunnels in these logs.', what = 'mTunnel outcomes' } = {}) {
  if (!hist) {
    container.innerHTML = `<p class="muted">${esc(empty)}</p>`;
    return;
  }
  const n = hist.ok.length;
  const totals = hist.ok.map((v, k) => v + hist.failed[k]);
  const max = niceMax(Math.max(1, ...totals));
  const W = Math.max(container.clientWidth || 600, 280);
  const H = 180;
  const m = { l: 34, r: 8, t: 6, b: 22 };
  const iw = W - m.l - m.r;
  const ih = H - m.t - m.b;
  const bw = iw / n;
  const gap = bw > 6 ? 2 : bw > 3 ? 1 : 0;
  const y = (v) => m.t + ih - (v / max) * ih;
  let bars = '';
  for (let k = 0; k < n; k++) {
    // Few buckets would otherwise produce slab-like bars; cap the width and center it.
    const w = Math.max(1, Math.min(bw - gap, 40));
    const x = m.l + k * bw + (bw - w) / 2;
    const ok = hist.ok[k];
    const fl = hist.failed[k];
    if (ok) bars += barPath(x, y(ok), w, m.t + ih - y(ok), !fl, 'var(--series-ok)');
    if (fl) {
      const base = y(ok) - (ok ? 2 : 0);
      bars += barPath(x, y(ok + fl) - (ok ? 2 : 0), w, base - (y(ok + fl) - (ok ? 2 : 0)), true, 'var(--critical)');
    }
  }
  const ticks = [0, max / 2, max];
  const grid = ticks.map((t) => `<line x1="${m.l}" x2="${W - m.r}" y1="${y(t)}" y2="${y(t)}"/>`).join('');
  const ylab = ticks.map((t) => `<text x="${m.l - 6}" y="${y(t) + 4}" text-anchor="end">${fmtN(t)}</text>`).join('');
  const xticks = [];
  const every = Math.max(1, Math.round(n / Math.max(2, Math.floor(iw / 110))));
  for (let k = 0; k < n; k += every) {
    const ts = hist.start + k * hist.bucket;
    const label = hist.bucket >= 86400e3 ? fmtTs(ts, { ms: false }).slice(5, 10) : fmtTs(ts, { ms: false }).slice(5, 16);
    xticks.push(`<text x="${m.l + k * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${esc(label)}</text>`);
  }
  container.innerHTML = `
    <div class="legend"><span><span class="sw" style="background:var(--series-ok)"></span>${esc(okLabel)}</span><span><span class="sw" style="background:var(--critical)"></span>${esc(failLabel)}</span></div>
    <div class="chart"><svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="${esc(what)} over time">
      <g class="grid">${grid}</g>${bars}
      <line class="baseline" x1="${m.l}" x2="${W - m.r}" y1="${m.t + ih}" y2="${m.t + ih}"/>
      <g class="axis">${ylab}${xticks.join('')}</g>
      <rect class="hit" x="${m.l}" y="${m.t}" width="${iw}" height="${ih}" fill="transparent"/>
    </svg><div class="tooltip" hidden></div></div>`;
  const svg = $('svg', container);
  const tip = $('.tooltip', container);
  svg.addEventListener('mousemove', (ev) => {
    const r = svg.getBoundingClientRect();
    const sx = ((ev.clientX - r.left) / r.width) * W;
    const k = Math.floor((sx - m.l) / bw);
    if (k < 0 || k >= n) return (tip.hidden = true);
    const ts = hist.start + k * hist.bucket;
    tip.hidden = false;
    tip.innerHTML = `<div class="tt-title">${esc(fmtTs(ts, { ms: false }))} – ${esc(fmtTs(ts + hist.bucket, { date: false, ms: false }))}</div>
      <div>${esc(okLabel)}: <b>${fmtN(hist.ok[k])}</b></div><div>${esc(failLabel)}: <b>${fmtN(hist.failed[k])}</b></div>`;
    const px = ((m.l + k * bw + bw / 2) / W) * r.width;
    tip.style.left = `${Math.min(px + 12, r.width - tip.offsetWidth - 4)}px`;
    tip.style.top = '24px';
  });
  svg.addEventListener('mouseleave', () => (tip.hidden = true));
}
function barPath(x, y, w, h, roundTop, fill) {
  if (h <= 0) return '';
  const r = roundTop ? Math.min(4, w / 2, h) : 0;
  return `<path fill="${fill}" d="M${x},${y + h}V${y + r}${r ? `Q${x},${y} ${x + r},${y}` : ''}H${x + w - r}${r ? `Q${x + w},${y} ${x + w},${y + r}` : ''}V${y + h}Z"/>`;
}
function niceMax(v) {
  const p = 10 ** Math.floor(Math.log10(v));
  for (const s of [1, 2, 2.5, 5, 10]) if (s * p >= v) return s * p;
  return v;
}

/** Tunnel state over the log time range: one band for ZPA, one for ZIA. */
const STATE_CLASS = (s) => (s.zpn === 'TUNNEL_FORWARDING' && s.auth === 'AUTHENTICATED' ? 'good' : /CONNECTING|AUTHENTICATING|PENDING/.test(s.zpn) ? 'warning' : 'critical');
// ZIA turned off by the user/admin is a choice, not an outage, so it gets a neutral color.
const ZIA_CLASS = (z) => (z === 'TUNNEL_FORWARDING' || z === 'ON' ? 'good' : /CONNECTING/.test(z || '') ? 'warning' : /OFF|DISABLED|NONE/.test(z || '') ? 'off' : 'critical');
const STATE_COLOR = { good: 'var(--good)', warning: 'var(--warning)', critical: 'var(--critical)', off: 'var(--off)' };
const pillFor = (cls) => ({ good: 'ok', warning: 'warn', critical: 'error', off: 'info' })[cls];
function stateStrip(container, states, range, bands = ['zpa', 'zia']) {
  if (!states.length || !range) {
    container.innerHTML = '<p class="muted">No tunnel status lines (ZApp Status) found.</p>';
    return;
  }
  const W = Math.max(container.clientWidth || 600, 280);
  const BAND = 22;
  const GAP = 6;
  const m = { l: 40, r: 4, t: 4 };
  const H = m.t + bands.length * (BAND + GAP) + 18;
  const span = Math.max(1, range.to - range.from);
  const x = (ts) => m.l + ((ts - range.from) / span) * (W - m.l - m.r);
  const def = {
    zpa: { label: 'ZPA', key: (s) => `${s.zpn}|${s.auth}`, cls: STATE_CLASS },
    zia: { label: 'ZIA', key: (s) => s.zia, cls: (s) => ZIA_CLASS(s.zia) },
  };
  let rects = '';
  const segsBy = {};
  bands.forEach((b, row) => {
    const y = m.t + row * (BAND + GAP);
    // Merge consecutive states that look the same for this band.
    const segs = [];
    for (const s of states) {
      const k = def[b].key(s);
      if (segs.length && segs[segs.length - 1].k === k) continue;
      segs.push({ ...s, k, cls: def[b].cls(s) });
    }
    segs.forEach((s, j) => (s.end = segs[j + 1]?.ts ?? range.to));
    segsBy[b] = segs;
    rects += `<text x="0" y="${y + BAND / 2 + 4}" class="band-label">${def[b].label}</text>`;
    rects += `<rect x="${m.l}" y="${y}" width="${W - m.l - m.r}" height="${BAND}" rx="4" fill="var(--surface-2)"/>`;
    for (const s of segs) {
      const x0 = x(s.ts);
      rects += `<rect x="${x0}" y="${y}" width="${Math.max(1.5, x(s.end) - x0 - 1)}" height="${BAND}" fill="${STATE_COLOR[s.cls]}"/>`;
    }
  });
  const labels = [range.from, (range.from + range.to) / 2, range.to]
    .map((t, k) => `<text x="${x(t)}" y="${H - 4}" text-anchor="${['start', 'middle', 'end'][k]}">${esc(fmtTs(t, { ms: false }))}</text>`)
    .join('');
  container.innerHTML = `
    <div class="legend">
      <span><span class="sw" style="background:var(--good)"></span>Forwarding</span>
      <span><span class="sw" style="background:var(--warning)"></span>Connecting</span>
      <span><span class="sw" style="background:var(--critical)"></span>Down / error</span>
      <span><span class="sw" style="background:var(--off)"></span>Turned off</span>
      <span><span class="sw" style="background:var(--surface-2);border:1px solid var(--border-strong)"></span>No data</span>
    </div>
    <div class="chart"><svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="Tunnel state over time">${rects}<g class="axis">${labels}</g></svg><div class="tooltip" hidden></div></div>`;
  const svg = $('svg', container);
  const tip = $('.tooltip', container);
  svg.addEventListener('mousemove', (ev) => {
    const r = svg.getBoundingClientRect();
    const sx = ((ev.clientX - r.left) / r.width) * W;
    const sy = ((ev.clientY - r.top) / r.height) * H;
    const row = Math.floor((sy - m.t) / (BAND + GAP));
    const b = bands[row];
    if (!b || sx < m.l) return (tip.hidden = true);
    const ts = range.from + ((sx - m.l) / (W - m.l - m.r)) * span;
    const s = [...segsBy[b]].reverse().find((z) => z.ts <= ts);
    tip.hidden = false;
    if (!s) tip.innerHTML = '<div class="tt-title">No tunnel status yet</div>';
    else {
      const when = `<div>${esc(fmtTs(s.ts, { ms: false }))} → ${esc(fmtTs(s.end, { ms: false }))} (${fmtDur(s.end - s.ts)})</div>`;
      tip.innerHTML =
        b === 'zpa'
          ? `<div class="tt-title">ZPA ${esc(s.zpn)} · ${esc(s.auth)}</div>${when}<div>Broker ${esc(s.broker || '—')} · ${esc(s.protocol || '')} · network ${esc(s.network)}</div>`
          : `<div class="tt-title">ZIA ${esc(s.zia)}</div>${when}<div>network ${esc(s.network)}</div>`;
    }
    tip.style.left = `${Math.max(0, Math.min(ev.clientX - r.left + 12, r.width - tip.offsetWidth - 4))}px`;
    tip.style.top = `${m.t + (row + 1) * (BAND + GAP) + 4}px`;
  });
  svg.addEventListener('mouseleave', () => (tip.hidden = true));
}

// ---------------------------------------------------------------- views

function emptyState(el) {
  el.className = '';
  el.innerHTML = `<div class="empty">
    <h2>No logs loaded</h2>
    <p>Load an exported Client Connector log bundle, or read the logs from this machine.</p>
    <p><button class="btn primary" id="emptyLoad">Load logs</button></p>
  </div>`;
  $('#emptyLoad').onclick = openLoadDialog;
}

const views = {
  async overview(el) {
    const s = state.summary;
    const z = s.zpa;
    const st = z.info.lastState;
    const stCls = st ? pillFor(STATE_CLASS(st)) : 'info';
    const zi = s.zia;
    const ziaState = zi.lastState || zi.state;
    el.innerHTML = `
      ${s.warnings.length ? `<div class="card" style="border-color:var(--warning)"><h2>Warnings</h2><ul class="small">${s.warnings.slice(0, 8).map((w) => `<li>${esc(w)}</li>`).join('')}</ul></div>` : ''}
      <div class="grid tiles">
        <div class="card tile"><div class="label">ZPA tunnel (last seen)</div><div class="value sm">${st ? pill(stCls, st.zpn) : '—'}</div><div class="sub">${st ? `${esc(st.auth)} · ${esc(st.protocol)} · ${esc(st.network)}` : 'no status lines'}</div></div>
        <div class="card tile"><div class="label">Client Connector</div><div class="value sm">${esc(z.info.versions.join(', ') || '—')}</div><div class="sub">forwarding profile: ${esc(z.info.forwardingProfile || '—')}</div></div>
        <div class="card tile"><div class="label">Broker</div><div class="value sm mono">${esc(st?.broker || '—')}</div><div class="sub">public IP ${esc(z.info.publicIps.join(', ') || '—')}</div></div>
        <div class="card tile"><div class="label">mTunnels</div><div class="value">${fmtN(z.mtunnels)}</div><div class="sub">${fmtN(z.mtStatus.failed)} failed (${pct(z.mtStatus.failed, z.mtunnels)})</div></div>
        <div class="card tile"><div class="label">App segment domains</div><div class="value">${fmtN(z.segments)}</div><div class="sub">${z.segmentDownloads} download(s), ${z.segmentUpdates} update(s)</div></div>
        <div class="card tile"><div class="label">Applications accessed</div><div class="value">${fmtN(z.apps)}</div><div class="sub">${fmtN(z.dnsChecks)} DNS checks via broker</div></div>
      </div>
      <div class="grid tiles">
        <div class="card tile"><div class="label">ZIA tunnel (last seen)</div><div class="value sm">${ziaState ? pill(pillFor(ZIA_CLASS(ziaState)), ziaState) : '—'}</div><div class="sub">transport ${esc(zi.transport || '—')} · ${esc(zi.forwarding || '—')}</div></div>
        <div class="card tile"><div class="label">ZIA gateways offered</div><div class="value">${fmtN(zi.gateways)}</div><div class="sub">from PAC</div></div>
        <div class="card tile"><div class="label">Web connections</div><div class="value">${fmtN(zi.flows)}</div><div class="sub">${fmtN(zi.flowStatus.failed || 0)} failed (${pct(zi.flowStatus.failed || 0, zi.flows)}) · ${fmtN(zi.hosts)} hosts</div></div>
        <div class="card tile"><div class="label">Via Z-Tunnel 2.0 / gateway / direct</div><div class="value sm">${fmtN(zi.paths.zt2 || 0)} / ${fmtN(zi.paths.gateway || 0)} / ${fmtN(zi.paths.direct || 0)}</div><div class="sub">${fmtN(zi.paths.unknown || 0)} undetermined</div></div>
        <div class="card tile"><div class="label">ZIA health checks</div><div class="value sm">${zi.health ? `${fmtN(zi.health.ok)} ok · ${fmtN(zi.health.failed)} failed` : '—'}</div><div class="sub">${zi.health?.lastFail ? `last failure ${esc(fmtTs(zi.health.lastFail, { ms: false }))}` : 'no failures'}</div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>ZPA mTunnel outcomes over time</h2><div id="ovChart"></div></div>
        <div class="card"><h2>ZIA web connections over time</h2><div id="ovZiaChart"></div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>Top ZPA error codes</h2><div id="ovErrors"></div></div>
        <div class="card"><h2>Log bundle</h2>
          <dl class="kv">
            <dt>Time range</dt><dd>${s.range ? `${esc(fmtTs(s.range.from, { ms: false }))} → ${esc(fmtTs(s.range.to, { ms: false }))} <span class="muted">(${fmtDur(s.range.to - s.range.from)}, ${esc(VIEWER_TZ)})</span>` : '—'}</dd>
            <dt>Lines</dt><dd>${fmtN(s.entries)} <span class="muted">· ${fmtN(s.levels.ERR)} ERR · ${fmtN(s.levels.WAR)} WAR</span></dd>
            <dt>Tunnel ID</dt><dd class="mono">${esc(z.info.tunnelIds.join(', ') || '—')}</dd>
            <dt>Parsed in</dt><dd>${fmtN(s.buildMs)} ms</dd>
          </dl>
          <div id="ovFiles" style="margin-top:10px"></div>
        </div>
      </div>`;
    outcomeChart($('#ovChart', el), z.histogram);
    outcomeChart($('#ovZiaChart', el), zi.histogram, { okLabel: 'Completed / open', failLabel: 'Failed', empty: 'No ZIA web connections in these logs.', what: 'ZIA connections' });
    table($('#ovErrors', el), {
      rows: z.topErrors,
      sortKey: 'count',
      empty: 'No ZPA error codes in these logs',
      onClick: (r) => go(`#/timeline?q=${encodeURIComponent(r.code)}`),
      columns: [
        { key: 'code', label: 'Code', render: (r) => `<code>${esc(r.code)}</code><div class="small muted">${esc(r.title)}</div>`, cls: 'wrap' },
        { key: 'category', label: 'Kind', render: (r) => (r.category === 'normal' ? pill('ok', 'normal close') : pill(r.category === 'unknown' ? 'info' : 'error', r.category)) },
        { key: 'count', label: 'Count', num: true, render: (r) => fmtN(r.count) },
        { key: 'last', label: 'Last seen', render: (r) => `<span class="mono small">${esc(fmtTs(r.last, { ms: false }))}</span>` },
      ],
    });
    table($('#ovFiles', el), {
      rows: s.fileList,
      sortKey: 'first',
      sortDir: 'asc',
      columns: [
        { key: 'name', label: 'File', cls: 'mono wrap' },
        { key: 'component', label: 'Component' },
        { key: 'entries', label: 'Entries', num: true, render: (r) => fmtN(r.entries) },
        { key: 'first', label: 'From', render: (r) => `<span class="small mono">${esc(fmtTs(r.first, { ms: false }))}</span>` },
      ],
    });
  },

  timeline: renderTimeline,

  async sessions(el) {
    const ov = await cached('overview', '/zpa/overview');
    const st = ov.info.lastState;
    el.innerHTML = `
      <div class="card"><h2>Tunnel state</h2><div id="strip"></div></div>
      <div class="grid two">
        <div class="card"><h2>Current status (last seen)</h2>
          ${st ? `<dl class="kv">
            <dt>ZPA tunnel</dt><dd>${pill(pillFor(STATE_CLASS(st)), st.zpn)}</dd>
            <dt>Authentication</dt><dd>${pill(st.auth === 'AUTHENTICATED' ? 'ok' : 'error', st.auth)}</dd>
            <dt>Broker IP</dt><dd class="mono">${esc(st.broker || '—')}</dd>
            <dt>Transport</dt><dd>${esc(st.protocol || '—')} · ${esc(st.tunnelType)}</dd>
            <dt>Network</dt><dd>${esc(st.network)}</dd>
            <dt>ZIA tunnel</dt><dd>${esc(st.zia)}</dd>
            <dt>Tunnel ID</dt><dd class="mono">${esc(ov.info.tunnelIds.join(', ') || '—')}</dd>
            <dt>Public IP</dt><dd class="mono">${esc(ov.info.publicIps.join(', ') || '—')}</dd>
          </dl>` : '<p class="muted">No ZApp Status lines found.</p>'}
        </div>
        <div class="card"><h2>Broker sessions</h2><div id="sessTable"></div>
          <p class="small muted">One session per <code>zpn_client_authenticate_ack</code>. mTunnel counts are attributed to the session that was active when they were requested.</p></div>
      </div>
      <div class="card"><h2>Lifecycle events</h2>
        <div class="toolbar" id="evChips"></div>
        <ul class="events" id="events"></ul>
      </div>
      <div class="card"><h2>DNS checks sent to broker</h2><div id="dns"></div></div>`;
    stateStrip($('#strip', el), ov.states, state.summary.range);
    table($('#sessTable', el), {
      rows: ov.sessions,
      sortKey: 'start',
      empty: 'No authentication to a broker found in these logs',
      onClick: (r) => go(`#/timeline?i=${r.i}`),
      columns: [
        { key: 'start', label: 'Started', render: (r) => `<span class="mono small">${esc(fmtTs(r.start, { ms: false }))}</span>` },
        { key: 'broker', label: 'Broker', cls: 'mono wrap' },
        { key: 'dur', label: 'Duration', num: true, sortVal: (r) => (r.end ?? state.summary.range.to) - r.start, render: (r) => (r.end ? fmtDur(r.end - r.start) : `${fmtDur(state.summary.range.to - r.start)}+`) },
        { key: 'mtunnels', label: 'mTunnels', num: true },
        { key: 'failed', label: 'Failed', num: true },
      ],
    });
    const types = [...new Set(ov.events.map((e) => e.type))];
    const active = new Set(types.filter((t) => t !== 'posture' && t !== 'trusted-net'));
    const chips = $('#evChips', el);
    const drawEvents = () => {
      chips.innerHTML = types.map((t) => `<button class="chip" aria-pressed="${active.has(t)}" data-t="${esc(t)}">${esc(t)} <span class="muted">${ov.events.filter((e) => e.type === t).length}</span></button>`).join('');
      const list = ov.events.filter((e) => active.has(e.type));
      $('#events', el).innerHTML = list.length
        ? list
            .slice(-800)
            .reverse()
            .map((e) => `<li data-i="${e.i}"><span class="t">${esc(fmtTs(e.ts))}</span><span>${pill(e.severity === 'ok' ? 'ok' : e.severity === 'warn' ? 'warn' : e.severity === 'error' ? 'error' : 'info', e.type)}</span><span>${esc(e.detail)}${e.reason ? ` <span class="muted small">(${esc(e.reason)})</span>` : ''}</span></li>`)
            .join('')
        : '<li class="muted">No events of the selected types.</li>';
    };
    chips.addEventListener('click', (ev) => {
      const b = ev.target.closest('.chip');
      if (!b) return;
      active.has(b.dataset.t) ? active.delete(b.dataset.t) : active.add(b.dataset.t);
      drawEvents();
    });
    $('#events', el).addEventListener('click', (ev) => {
      const li = ev.target.closest('li[data-i]');
      if (li) go(`#/timeline?i=${li.dataset.i}`);
    });
    drawEvents();
    table($('#dns', el), {
      rows: ov.dnsChecks,
      sortKey: 'ts',
      empty: 'No zpn_dns_client_check messages',
      onClick: (r) => go(`#/timeline?i=${r.i}`),
      columns: [
        { key: 'ts', label: 'Time', render: (r) => `<span class="mono small">${esc(fmtTs(r.ts))}</span>` },
        { key: 'name', label: 'Name', cls: 'mono wrap' },
        { key: 'type', label: 'Type' },
        { key: 'result', label: 'Result', render: (r) => (r.result === 'FOUND' ? pill('ok', 'found') : r.result === 'NO_RECORDS' ? pill('warn', 'no records') : pill('error', r.result)) },
        { key: 'latencyMs', label: 'Latency', num: true, render: (r) => fmtDur(r.latencyMs) },
      ],
    });
  },

  async segments(el) {
    const data = await cached('segments', '/zpa/segments');
    const kinds = { fqdn: 'FQDN', wildcard: 'Wildcard', ip: 'IP', cidr: 'Subnet' };
    el.innerHTML = `
      <div class="card"><h2>Which segment would a destination use?</h2>
        <form class="match-box" id="matchForm">
          <input type="text" id="mHost" placeholder="host.example.com or 10.1.2.3" required style="min-width:240px;flex:1" />
          <input type="number" id="mPort" placeholder="port" min="1" max="65535" style="width:100px" />
          <select id="mProto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select>
          <button class="btn primary">Check</button>
        </form>
        <div class="match-result" id="mResult"></div>
      </div>
      <div class="card">
        <div class="page-head"><h2 style="margin:0">Segment domains received (${data.segments.length})</h2>
          <span class="small muted">Each ZPA application segment is delivered to the client as one entry per domain/IP/subnet.</span></div>
        <div class="toolbar">
          <input type="search" class="grow" id="segQ" placeholder="Filter domains…" />
          ${Object.entries(kinds).map(([k, v]) => `<button class="chip" aria-pressed="true" data-kind="${k}">${v} <span class="muted">${data.segments.filter((s) => s.kind === k).length}</span></button>`).join('')}
          <label class="check small"><input type="checkbox" id="segUsed" /> Only with traffic</label>
        </div>
        <div id="segTable"></div>
      </div>
      <div class="card"><h2>Downloads &amp; updates</h2><div id="batches"></div></div>`;

    const kindOn = new Set(Object.keys(kinds));
    const filtered = () => {
      const q = $('#segQ', el).value.trim().toLowerCase();
      const used = $('#segUsed', el).checked;
      return data.segments.filter((s) => kindOn.has(s.kind) && (!q || s.domain.toLowerCase().includes(q)) && (!used || s.mtunnels));
    };
    const t = table($('#segTable', el), {
      rows: filtered(),
      rowKey: (r) => r.domain,
      sortKey: 'domain',
      sortDir: 'asc',
      empty: 'No segment domains match',
      columns: [
        { key: 'domain', label: 'Domain / IP', cls: 'mono wrap' },
        { key: 'kind', label: 'Type', render: (r) => kinds[r.kind] },
        { key: 'tcpText', label: 'TCP ports', cls: 'mono wrap' },
        { key: 'udpText', label: 'UDP ports', cls: 'mono wrap' },
        { key: 'icmp', label: 'ICMP' },
        { key: 'bypassType', label: 'Bypass', render: (r) => (r.bypass ? pill('warn', r.bypassType || 'yes') : `<span class="muted">${esc(r.bypassType || 'never')}</span>`) },
        { key: 'doubleEncrypt', label: 'Dbl enc', render: (r) => (r.doubleEncrypt ? pill('info', 'on') : '<span class="muted">off</span>') },
        { key: 'mtunnels', label: 'mTunnels', num: true },
        { key: 'failed', label: 'Failed', num: true, render: (r) => (r.failed ? `<span class="lv-ERR">${r.failed}</span>` : '0') },
        { key: 'updates', label: 'Changes', num: true, render: (r) => (r.updates > 1 ? pill('warn', `${r.updates - 1}`) : '<span class="muted">—</span>') },
      ],
      detail: async (r, slot) => {
        const hist = data.history[r.domain] || [];
        const mt = await dsApi(`/zpa/mtunnels?segment=${encodeURIComponent(r.domain)}&limit=300`);
        slot.classList.remove('muted');
        slot.innerHTML = `
          <div class="grid two">
            <div><strong>History</strong><ul class="events">${hist
              .map((h) => `<li data-i="${h.i}"><span class="t">${esc(fmtTs(h.ts))}</span><span>${pill(h.change === 'added' ? 'ok' : h.change === 'deleted' || h.change === 'removed' ? 'error' : 'warn', h.change.split(':')[0])}</span><span class="small">${esc(h.change.includes(':') ? h.change.split(': ').slice(1).join(': ') : h.reason || `TCP ${h.tcp || '—'} · UDP ${h.udp || '—'}`)}</span></li>`)
              .join('')}</ul></div>
            <div><strong>Bypass on re-auth:</strong> ${r.bypassOnReauth ? 'yes' : 'no'}<br/><strong>First seen:</strong> ${esc(fmtTs(r.firstSeen))}</div>
          </div>
          <div style="margin-top:10px"><strong>mTunnels matched to this domain</strong> <span class="muted small">(${mt.total}${mt.total > 300 ? ', latest 300' : ''})</span></div>
          <div class="mt" style="margin-top:6px"></div>`;
        mtunnelTable($('.mt', slot), mt.mtunnels);
        $$('li[data-i]', slot).forEach((li) => (li.onclick = () => go(`#/timeline?i=${li.dataset.i}`)));
      },
    });
    $('#segQ', el).addEventListener('input', () => t.update(filtered()));
    $('#segUsed', el).addEventListener('change', () => t.update(filtered()));
    el.addEventListener('click', (ev) => {
      const c = ev.target.closest('.chip[data-kind]');
      if (!c) return;
      const on = c.getAttribute('aria-pressed') !== 'true';
      c.setAttribute('aria-pressed', on);
      on ? kindOn.add(c.dataset.kind) : kindOn.delete(c.dataset.kind);
      t.update(filtered());
    });
    $('#matchForm', el).addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const host = $('#mHost', el).value.trim();
      const port = $('#mPort', el).value;
      const proto = $('#mProto', el).value;
      const out = $('#mResult', el);
      try {
        const r = await dsApi(`/zpa/match?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}&proto=${proto}`);
        if (!r.match) {
          out.innerHTML = `${pill('error', 'no match')} <code>${esc(host)}</code> is not covered by any segment domain this client received, so ZCC will not send it to ZPA. ${simBtn(host, port ? Number(port) : null, proto === 'udp' ? 'udp' : 'tcp')}`;
        } else {
          const s = r.segment;
          out.innerHTML = `${r.match.portOk ? pill('ok', 'matches') : pill('warn', 'domain matches, port not included')}
            <code>${esc(host)}${port ? ':' + esc(port) : ''}</code> → <code>${esc(r.match.domain)}</code>
            <span class="muted">(${kinds[s.kind]}; TCP ${esc(s.tcpText || '—')}; UDP ${esc(s.udpText || '—')})</span>.
            ${r.mtunnelsSeen ? `${r.mtunnelsSeen} mTunnel(s) to this exact name in the logs. <a href="#/apps?app=${encodeURIComponent(host)}">View →</a>` : 'No mTunnels to this exact name in the logs.'}
            <div class="small muted" style="margin-top:4px">Client-side approximation (most specific domain wins). Access is still decided by broker policy. ${simBtn(host, port ? Number(port) : null, proto === 'udp' ? 'udp' : 'tcp')}</div>`;
        }
      } catch (err) {
        out.textContent = err.message;
      }
    });
    table($('#batches', el), {
      rows: data.batches,
      sortKey: 'ts',
      empty: 'No zpn_client_app messages (logs may start after the tunnel came up)',
      onClick: (r) => go(`#/timeline?i=${r.i}`),
      columns: [
        { key: 'ts', label: 'Time', render: (r) => `<span class="mono small">${esc(fmtTs(r.ts))}</span>` },
        { key: 'complete', label: 'Kind', render: (r) => (r.complete ? pill('ok', 'full download') : pill('info', 'incremental update')) },
        { key: 'count', label: 'Domains', num: true },
        { key: 'domains', label: 'Details', cls: 'small wrap', render: (r) => esc(r.domains.slice(0, 12).join(', ') + (r.domains.length > 12 ? ` … +${r.domains.length - 12}` : '')) + (r.removed.length ? `<div class="lv-ERR">removed: ${esc(r.removed.join(', '))}</div>` : '') },
      ],
    });
  },

  async apps(el, params) {
    const apps = await cached('apps', '/zpa/apps');
    el.innerHTML = `
      <div class="page-head"><h1>Applications</h1><span class="small muted">Grouped by the name or IP in <code>zpn_mtunnel_request</code>. Click a row to see its connections.</span></div>
      <div class="toolbar">
        <input type="search" class="grow" id="appQ" placeholder="Filter applications…" value="${esc(params.get('app') || '')}" />
        <label class="check small"><input type="checkbox" id="appFail" /> Only with failures</label>
      </div>
      <div id="appTable"></div>`;
    const filtered = () => {
      const q = $('#appQ', el).value.trim().toLowerCase();
      const f = $('#appFail', el).checked;
      return apps.filter((a) => (!q || a.app.toLowerCase().includes(q)) && (!f || a.failed));
    };
    const t = table($('#appTable', el), {
      rows: filtered(),
      rowKey: (r) => r.app,
      sortKey: 'total',
      empty: 'No mTunnels found',
      columns: [
        { key: 'app', label: 'Application', cls: 'mono wrap' },
        { key: 'segment', label: 'Matched segment', render: (r) => (r.segment ? `<code>${esc(r.segment)}</code>` : pill('warn', 'none')) + (r.portMismatch ? ` ${pill('warn', 'port outside segment')}` : ''), cls: 'wrap' },
        { key: 'ports', label: 'Ports', cls: 'small wrap', render: (r) => esc(r.ports.slice(0, 6).join(', ') + (r.ports.length > 6 ? '…' : '')) },
        { key: 'total', label: 'mTunnels', num: true },
        { key: 'failed', label: 'Failed', num: true, render: (r) => `<span class="bar-cell" style="justify-content:flex-end">${r.failed ? `<span class="lv-ERR">${r.failed}</span>` : '0'} ${ratioBar(r.total - r.failed, r.failed)}</span>` },
        { key: 'topReason', label: 'Top failure', render: (r) => (r.topReason ? `<code class="small">${esc(r.topReason)}</code>` : '<span class="muted">—</span>'), cls: 'wrap' },
        { key: 'setupP50', label: 'Setup p50', num: true, render: (r) => fmtDur(r.setupP50) },
        { key: 'setupP95', label: 'p95', num: true, render: (r) => fmtDur(r.setupP95) },
        { key: 'last', label: 'Last seen', render: (r) => `<span class="mono small">${esc(fmtTs(r.last, { ms: false }))}</span>` },
      ],
      detail: async (r, slot) => {
        const mt = await dsApi(`/zpa/mtunnels?app=${encodeURIComponent(r.app)}&limit=500`);
        const reasons = Object.entries(r.reasons).sort((a, b) => b[1] - a[1]);
        slot.classList.remove('muted');
        slot.innerHTML = `
          ${reasons.length ? `<div class="toolbar">${reasons.map(([k, v]) => `<span class="pill error">${esc(k)} × ${v}</span>`).join('')}
            <a class="small" href="#/timeline?q=${encodeURIComponent(r.app)}&hideNoise=1">all log lines for this app →</a> ${simBtn(r.app, parseInt(String(r.ports[0] || '').split('/').pop(), 10) || null, /^(udp|17)\//i.test(String(r.ports[0] || '')) ? 'udp' : 'tcp')}</div>` : `<div class="toolbar"><a class="small" href="#/timeline?q=${encodeURIComponent(r.app)}&hideNoise=1">all log lines for this app →</a> ${simBtn(r.app, parseInt(String(r.ports[0] || '').split('/').pop(), 10) || null, /^(udp|17)\//i.test(String(r.ports[0] || '')) ? 'udp' : 'tcp')}</div>`}
          <div class="mt"></div>`;
        mtunnelTable($('.mt', slot), mt.mtunnels);
      },
    });
    $('#appQ', el).addEventListener('input', () => t.update(filtered()));
    $('#appFail', el).addEventListener('change', () => t.update(filtered()));
  },

  async zia(el) {
    const ov = await cached('ziaOverview', '/zia/overview');
    const st = state.summary.zia;
    const last = ov.states.length ? ov.states[ov.states.length - 1] : null;
    const zState = last?.zia || ov.info.state;
    const prof = ov.info.profile;
    el.innerHTML = `
      <div class="card"><h2>Tunnel state</h2><div id="strip"></div></div>
      <div class="grid two">
        <div class="card"><h2>ZIA status (last seen)</h2>
          <dl class="kv">
            <dt>ZIA tunnel</dt><dd>${zState ? pill(pillFor(ZIA_CLASS(zState)), zState) : '—'}</dd>
            <dt>Forwarding action</dt><dd>${esc(prof?.action || '—')}</dd>
            <dt>Primary transport</dt><dd>${esc(prof?.settings?.primaryTransport || '—')}${prof?.settings?.allowTLSFallback ? ' <span class="muted">(TLS fallback allowed)</span>' : ''}</dd>
            <dt>Network</dt><dd>${esc(last?.network || '—')}</dd>
            <dt>Health checks</dt><dd>${Object.entries(ov.health)
              .map(([svc, h]) => `${esc(svc)}: ${fmtN(h.ok)} ok, ${h.failed ? `<span class="lv-ERR">${fmtN(h.failed)} failed</span>` : '0 failed'}`)
              .join('<br/>') || '—'}</dd>
            <dt>Web connections</dt><dd>${fmtN(st.flows)} <a href="#/web">view →</a></dd>
          </dl>
        </div>
        <div class="card"><h2>Gateways (from PAC)</h2><div id="gw"></div>
          <p class="small muted">PAC request type 1 and 2 lists as delivered to the client. "Connections" counts web connections that used that gateway IP.</p></div>
      </div>
      <div class="card"><h2>Forwarding profile</h2><div id="prof"></div></div>
      <div class="card"><h2>ZIA lifecycle events</h2>
        <div class="toolbar" id="evChips"></div>
        <ul class="events" id="events"></ul>
      </div>
      <div class="card"><h2>Tunnel API lookups</h2>
        <p class="small muted" style="margin:0 0 8px">Other components (mostly ZDX) ask ZSATunnel how a URL would be routed via <code>/getTunnelBypass</code>. <code>requestType</code> and <code>bypassReason</code> are shown raw because their meanings aren't documented.</p>
        <div id="api"></div></div>`;
    stateStrip($('#strip', el), ov.states, state.summary.range);
    table($('#gw', el), {
      rows: ov.info.gateways,
      sortKey: 'flows',
      empty: 'No PAC proxy list (refreshSMEIpFromPac) in these logs',
      onClick: (r) => go(`#/timeline?i=${r.i}`),
      columns: [
        { key: 'ip', label: 'Gateway IP', cls: 'mono' },
        { key: 'port', label: 'Port', num: true },
        { key: 'sni', label: 'SNI suffix', cls: 'mono' },
        { key: 'pacType', label: 'PAC list', num: true },
        { key: 'flows', label: 'Connections', num: true },
      ],
    });
    $('#prof', el).innerHTML = prof
      ? `<dl class="kv">${Object.entries(prof.settings)
          .map(([k, v]) => `<dt class="mono small">${esc(k)}</dt><dd>${esc(String(v))}</dd>`)
          .join('')}</dl><p class="small"><a href="#/timeline?i=${prof.i}">full profile in logs →</a></p>`
      : '<p class="muted">No "Updating forwarding profile" line found.</p>';
    const types = [...new Set(ov.events.map((e) => e.type))];
    const active = new Set(types);
    const chips = $('#evChips', el);
    const drawEvents = () => {
      chips.innerHTML = types.map((t) => `<button class="chip" aria-pressed="${active.has(t)}" data-t="${esc(t)}">${esc(t)} <span class="muted">${ov.events.filter((e) => e.type === t).length}</span></button>`).join('');
      const list = ov.events.filter((e) => active.has(e.type));
      $('#events', el).innerHTML = list.length
        ? list
            .slice(-800)
            .reverse()
            .map((e) => `<li data-i="${e.i}"><span class="t">${esc(fmtTs(e.ts))}</span><span>${pill(e.severity === 'ok' ? 'ok' : e.severity === 'warn' ? 'warn' : e.severity === 'error' ? 'error' : 'info', e.type)}</span><span>${esc(e.detail)}</span></li>`)
            .join('')
        : '<li class="muted">No events of the selected types.</li>';
    };
    chips.addEventListener('click', (ev) => {
      const b = ev.target.closest('.chip');
      if (!b) return;
      active.has(b.dataset.t) ? active.delete(b.dataset.t) : active.add(b.dataset.t);
      drawEvents();
    });
    $('#events', el).addEventListener('click', (ev) => {
      const li = ev.target.closest('li[data-i]');
      if (li) go(`#/timeline?i=${li.dataset.i}`);
    });
    drawEvents();
    table($('#api', el), {
      rows: ov.apiLookups,
      sortKey: 'ts',
      empty: 'No "Tunnel api request" lines',
      onClick: (r) => go(`#/timeline?i=${r.i}`),
      columns: [
        { key: 'ts', label: 'Time', render: (r) => `<span class="mono small">${esc(fmtTs(r.ts))}</span>` },
        { key: 'host', label: 'Host', cls: 'mono wrap' },
        { key: 'port', label: 'Port', num: true },
        { key: 'destinationIp', label: 'Resolved IP', cls: 'mono' },
        { key: 'gateway', label: 'Gateway', cls: 'mono', render: (r) => esc(r.gateway || '—') },
        { key: 'requestType', label: 'requestType', num: true },
        { key: 'bypassReason', label: 'bypassReason', num: true, render: (r) => (r.bypassReason == null ? '—' : r.bypassReason) },
        { key: 'ziaOff', label: '', render: (r) => (r.ziaOff ? pill('info', 'ZIA off → bypass') : '') },
      ],
    });
  },

  async web(el, params) {
    const hosts = await cached('ziaHosts', '/zia/hosts');
    const PATH = { zt2: ['ok', 'Z-Tunnel 2.0'], gateway: ['info', 'gateway'], direct: ['warn', 'direct'], unknown: ['info', 'undetermined'] };
    const pathPill = (p) => pill(...(PATH[p] || ['info', p]));
    el.innerHTML = `
      <div class="page-head"><h1>Web traffic</h1><span class="small muted">Connections intercepted by ZSATunnel (tun adapter or local proxy), grouped by SNI / CONNECT host. ZPA app traffic is excluded.</span></div>
      <div class="toolbar">
        <input type="search" class="grow" id="webQ" placeholder="Filter hosts…" value="${esc(params.get('host') || '')}" />
        <select id="webPath" aria-label="Path"><option value="">All paths</option><option value="zt2">Z-Tunnel 2.0</option><option value="gateway">Gateway (CONNECT)</option><option value="direct">Direct</option><option value="unknown">Undetermined</option></select>
        <label class="check small"><input type="checkbox" id="webFail" /> Only with failures</label>
        <label class="check small"><input type="checkbox" id="webZdx" /> Hide ZDX probes</label>
      </div>
      <div id="webTable"></div>
      <p class="small muted">Path: <b>Z-Tunnel 2.0</b> = handed to the packet tunnel; <b>gateway</b> = HTTP CONNECT to the ZIA gateway (Z-Tunnel 1.0 / PAC proxy); <b>direct</b> = PAC returned DIRECT. "No response" means the client sent data and the connection closed with 0 bytes received.</p>`;
    const filtered = () => {
      const q = $('#webQ', el).value.trim().toLowerCase();
      const p = $('#webPath', el).value;
      const f = $('#webFail', el).checked;
      const z = $('#webZdx', el).checked;
      return hosts.filter((h) => (!q || h.host.toLowerCase().includes(q) || h.ips.some((ip) => ip.includes(q))) && (!p || h.paths[p]) && (!f || h.failed) && (!z || h.zdx < h.total));
    };
    const t = table($('#webTable', el), {
      rows: filtered(),
      rowKey: (r) => r.host,
      sortKey: 'total',
      empty: 'No ZIA web connections found',
      columns: [
        { key: 'host', label: 'Host', cls: 'mono wrap', render: (r) => esc(r.host) + (r.zdx ? ` ${pill('info', r.zdx === r.total ? 'ZDX' : `ZDX ×${r.zdx}`)}` : '') },
        { key: 'mainPath', label: 'Path', render: (r) => Object.keys(r.paths).map(pathPill).join(' ') },
        { key: 'ports', label: 'Ports', cls: 'small', render: (r) => esc(r.ports.join(', ')) },
        { key: 'total', label: 'Conns', num: true },
        { key: 'failed', label: 'Failed', num: true, render: (r) => `<span class="bar-cell" style="justify-content:flex-end">${r.failed ? `<span class="lv-ERR">${r.failed}</span>` : '0'} ${ratioBar(r.total - r.failed, r.failed)}</span>` },
        { key: 'topReason', label: 'Top failure', cls: 'small wrap', render: (r) => (r.topReason ? esc(r.topReason) : '<span class="muted">—</span>') },
        { key: 'bytesDown', label: 'Down', num: true, render: (r) => fmtBytes(r.bytesDown) },
        { key: 'bytesUp', label: 'Up', num: true, render: (r) => fmtBytes(r.bytesUp) },
        { key: 'last', label: 'Last seen', render: (r) => `<span class="mono small">${esc(fmtTs(r.last, { ms: false }))}</span>` },
      ],
      detail: async (r, slot) => {
        const data = await dsApi(`/zia/flows?host=${encodeURIComponent(r.host)}&limit=500`);
        slot.classList.remove('muted');
        slot.innerHTML = `<div class="toolbar small">${r.ips.length ? `IPs: <code>${esc(r.ips.join(', '))}</code>` : ''} ${r.gateways.length ? `· gateways: <code>${esc(r.gateways.join(', '))}</code>` : ''}
          <a href="#/timeline?q=${encodeURIComponent(r.host)}&hideNoise=1">all log lines for this host →</a> ${simBtn(r.host, r.ports[0] || 443)}</div><div class="fl"></div>`;
        table($('.fl', slot), {
          rows: data.flows,
          rowKey: (f) => `${f.cid}-${f.i}`,
          sortKey: 'ts',
          columns: [
            { key: 'ts', label: 'Time', render: (f) => `<span class="mono small">${esc(fmtTs(f.ts))}</span>` },
            { key: 'kind', label: 'Source', render: (f) => (f.kind === 'tun' ? 'tun adapter' : `local proxy${f.method ? ` (${esc(f.method)})` : ''}`) },
            { key: 'dst', label: 'Destination', cls: 'mono small', render: (f) => esc(`${f.dst || f.host || '—'}${f.port ? ':' + f.port : ''}`) },
            { key: 'path', label: 'Path', render: (f) => pathPill(f.path) + (f.gateway && f.path !== 'direct' ? ` <span class="mono small muted">${esc(f.gateway)}</span>` : '') },
            { key: 'status', label: 'Result', render: (f) => (f.status === 'ok' ? pill('ok', 'ok') : f.status === 'failed' ? pill('error', 'failed') : f.status === 'empty' ? pill('info', 'no data') : pill('warn', 'no close logged')) },
            { key: 'reason', label: 'Reason', cls: 'small wrap', render: (f) => esc(f.reason || (f.httpStatus ? `HTTP ${f.httpStatus}` : '')) + (f.zdx ? ` ${pill('info', 'ZDX probe')}` : '') },
            { key: 'bytesDown', label: 'Down', num: true, render: (f) => fmtBytes(f.bytesDown) },
            { key: 'bytesUp', label: 'Up', num: true, render: (f) => fmtBytes(f.bytesUp) },
            { key: 'dur', label: 'Duration', num: true, sortVal: (f) => (f.endTs ? f.endTs - f.ts : null), render: (f) => (f.endTs ? fmtDur(f.endTs - f.ts) : '—') },
            { key: 'cid', label: '', render: (f) => `<a href="#/timeline?tag=${f.cid}&i=${f.i}">logs →</a>` },
          ],
        });
      },
    });
    for (const id of ['#webQ', '#webPath', '#webFail', '#webZdx']) $(id, el).addEventListener(id === '#webQ' ? 'input' : 'change', () => t.update(filtered()));
  },

  async errors(el) {
    const data = await cached('errors', '/errors');
    el.innerHTML = `
      <div class="page-head"><h1>Error triage</h1><span class="small muted">ZPA error codes from broker messages, ZIA connection failures, then every ERR/WAR log line grouped by pattern.</span></div>
      <div class="grid err-grid" id="codes"></div>
      <div class="card"><h2>ZIA connection failures</h2><div id="ziaErr"></div></div>
      <div class="card">
        <h2>Log error patterns</h2>
        <div class="toolbar">
          <input type="search" class="grow" id="errQ" placeholder="Filter patterns…" />
          <button class="chip" aria-pressed="true" data-l="ERR">ERR</button>
          <button class="chip" aria-pressed="false" data-l="WAR">WAR</button>
          <select id="errSvc" aria-label="Service"><option value="">All services</option><option value="zpa">ZPA-related</option><option value="zia">ZIA-related</option></select>
        </div>
        <div id="groups"></div>
      </div>`;
    $('#codes', el).innerHTML = data.zpn.length
      ? data.zpn
          .map(
            (c) => `<div class="card err-card cat-${esc(c.category)}">
          <div style="display:flex;justify-content:space-between;gap:8px;align-items:start">
            <div><div class="code">${esc(c.code)}</div><div class="small">${esc(c.title)}</div></div>
            <div class="count">${fmtN(c.count)}</div>
          </div>
          ${c.hint ? `<p>${esc(c.hint)}</p>` : ''}
          <div class="small muted" style="margin-top:6px">${esc(c.types.join(', '))} · ${esc(fmtTs(c.first, { ms: false }))} → ${esc(fmtTs(c.last, { date: false, ms: false }))}</div>
          <div style="margin-top:8px;display:flex;gap:6px"><a class="btn sm" href="#/timeline?q=${encodeURIComponent(c.code)}">Show lines</a><a class="btn sm" href="#/timeline?i=${c.sample}">First occurrence</a></div>
        </div>`,
          )
          .join('')
      : '<div class="card muted">No ZPA error codes found.</div>';
    table($('#ziaErr', el), {
      rows: data.zia,
      sortKey: 'count',
      empty: 'No failed ZIA web connections',
      onClick: (r) => go(`#/timeline?i=${r.sample}`),
      columns: [
        { key: 'reason', label: 'Reason', cls: 'wrap' },
        { key: 'count', label: 'Count', num: true },
        { key: 'hostCount', label: 'Hosts', num: true, render: (r) => `<span title="${esc(r.hosts.join(', '))}">${r.hostCount}</span>` },
        { key: 'hosts', label: 'Examples', cls: 'mono small wrap', render: (r) => esc(r.hosts.slice(0, 4).join(', ')) },
        { key: 'last', label: 'Last', render: (r) => `<span class="mono small">${esc(fmtTs(r.last, { ms: false }))}</span>` },
      ],
    });
    const lv = new Set(['ERR']);
    const filtered = () => {
      const q = $('#errQ', el).value.trim().toLowerCase();
      const svc = $('#errSvc', el).value;
      return data.groups.filter((g) => lv.has(g.lvl) && (!svc || g[svc]) && (!q || g.sig.toLowerCase().includes(q) || g.sampleMsg.toLowerCase().includes(q)));
    };
    const t = table($('#groups', el), {
      rows: filtered(),
      sortKey: 'count',
      empty: 'No matching patterns',
      onClick: (r) => go(`#/timeline?i=${r.sample}`),
      columns: [
        { key: 'lvl', label: 'Lvl', render: (r) => `<span class="lv-${r.lvl}" style="font-weight:600">${r.lvl}</span>` },
        { key: 'comp', label: 'Component' },
        { key: 'sig', label: 'Pattern', cls: 'mono wrap', render: (r) => esc(r.sig) },
        { key: 'count', label: 'Count', num: true, render: (r) => fmtN(r.count) },
        { key: 'first', label: 'First', render: (r) => `<span class="mono small">${esc(fmtTs(r.first, { ms: false }))}</span>` },
        { key: 'last', label: 'Last', render: (r) => `<span class="mono small">${esc(fmtTs(r.last, { ms: false }))}</span>` },
      ],
    });
    $('#errQ', el).addEventListener('input', () => t.update(filtered()));
    $('#errSvc', el).addEventListener('change', () => t.update(filtered()));
    el.addEventListener('click', (ev) => {
      const c = ev.target.closest('.chip[data-l]');
      if (!c) return;
      const on = c.getAttribute('aria-pressed') !== 'true';
      c.setAttribute('aria-pressed', on);
      on ? lv.add(c.dataset.l) : lv.delete(c.dataset.l);
      t.update(filtered());
    });
  },
};

// ---------------------------------------------------------------- timeline

const ROW = 22;
const PAGE = 400;
const ALL_LEVELS = ['ERR', 'WAR', 'INF', 'DBG'];

function defaultFilters() {
  return { q: '', regex: false, levels: new Set(ALL_LEVELS), comps: null, svc: '', hideNoise: true, tag: '' };
}

function tlQuery(f) {
  const p = new URLSearchParams();
  if (f.q) p.set('q', f.q);
  if (f.regex) p.set('regex', '1');
  if (f.levels.size < ALL_LEVELS.length) p.set('levels', [...f.levels].join(',') || 'NONE');
  if (f.comps) p.set('comps', [...f.comps].join(',') || 'NONE');
  if (f.svc) p.set('svc', f.svc);
  if (f.hideNoise) p.set('hideNoise', '1');
  if (f.tag) p.set('tag', f.tag);
  return p.toString();
}

async function renderTimeline(el, params) {
  const tl = (state.tl ||= { f: defaultFilters(), selected: null, scrollTop: 0 });
  // Deep links (#/timeline?q=..&tag=..&i=..) replace the current filters.
  const jumpTo = params.has('i') ? Number(params.get('i')) : null;
  if ([...params.keys()].some((k) => k !== 'i') || jumpTo != null) {
    tl.f = defaultFilters();
    if (params.has('q')) tl.f.q = params.get('q');
    if (params.has('tag')) tl.f.tag = params.get('tag');
    if (params.has('svc')) tl.f.svc = params.get('svc');
    // When jumping to a specific line, show everything so it can't be filtered out.
    tl.f.hideNoise = params.has('hideNoise') || (jumpTo == null && !params.has('tag'));
    history.replaceState(null, '', '#/timeline');
  }
  const f = tl.f;
  const comps = Object.keys(state.summary.components);
  el.className = 'fill';
  el.innerHTML = `
    <div class="tl-filters">
      <div class="search">
        <input type="search" id="tlQ" placeholder="Search messages… (e.g. boston01, BRK_MT, tag_id)" value="${esc(f.q)}" aria-label="Search" />
        <button class="chip" id="tlRx" aria-pressed="${f.regex}" title="Treat search as a regular expression">.*</button>
      </div>
      ${ALL_LEVELS.map((l) => `<button class="chip lv-chip" data-l="${l}" aria-pressed="${f.levels.has(l)}"><span class="lv-${l}">${l}</span></button>`).join('')}
      <select id="tlComp" aria-label="Component"><option value="">All components</option>${comps.map((c) => `<option ${f.comps?.has(c) && f.comps.size === 1 ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>
      <input type="text" id="tlTag" placeholder="tag / conn ID" value="${esc(f.tag)}" style="width:110px" aria-label="ZPA tag_id or connection ID" title="A ZPA mTunnel tag_id or a ZSATunnel connection ID (ID=…)" />
      <select id="tlSvc" aria-label="Service"><option value="">All services</option><option value="zpa" ${f.svc === 'zpa' ? 'selected' : ''}>ZPA</option><option value="zia" ${f.svc === 'zia' ? 'selected' : ''}>ZIA</option></select>
      <label class="check small" title="Hides heartbeat lines: fohh_status, socket read/write counters, XPC chatter, ZApp Status"><input type="checkbox" id="tlNoise" ${f.hideNoise ? 'checked' : ''}/> Hide noise</label>
      <button class="btn sm ghost" id="tlReset">Reset</button>
    </div>
    <div class="tl-meta"><span id="tlCount">…</span><span class="spacer"></span><span class="muted">↑/↓ to move · Enter for context</span></div>
    <div class="tl-body">
      <div class="tl-scroll" id="tlScroll" tabindex="0"><div class="tl-spacer" id="tlSpacer"></div></div>
      <div class="tl-detail" id="tlDetail" hidden></div>
    </div>`;

  const scroll = $('#tlScroll', el);
  const spacer = $('#tlSpacer', el);
  let total = 0;
  let gen = 0;
  let pages = new Map();
  let raf = 0;

  const hl = (text) => {
    const s = esc(text);
    if (!f.q) return s;
    try {
      const rx = new RegExp(f.regex ? f.q : f.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      // Highlight on escaped text only when the needle has no escapable characters.
      if (/[&<>"']/.test(f.q)) return s;
      return s.replace(rx, (m) => (m ? `<mark>${m}</mark>` : m));
    } catch {
      return s;
    }
  };

  async function loadPage(p) {
    if (pages.has(p)) return;
    pages.set(p, null);
    const g = gen;
    try {
      const r = await dsApi(`/entries?${tlQuery(f)}&offset=${p * PAGE}&limit=${PAGE}`);
      if (g !== gen) return;
      pages.set(p, r.entries);
      schedule();
    } catch (err) {
      if (g === gen) pages.delete(p);
      toast(err.message);
    }
  }
  function rowAt(k) {
    const pg = pages.get(Math.floor(k / PAGE));
    return pg ? pg[k % PAGE] : undefined;
  }
  function draw() {
    raf = 0;
    const top = scroll.scrollTop;
    const first = Math.max(0, Math.floor(top / ROW) - 8);
    const last = Math.min(total - 1, Math.ceil((top + scroll.clientHeight) / ROW) + 8);
    let html = '';
    for (let k = first; k <= last; k++) {
      const e = rowAt(k);
      if (!e) {
        loadPage(Math.floor(k / PAGE));
        html += `<div class="tl-row loading" style="top:${k * ROW}px"><span class="t"></span><span class="m">…</span></div>`;
        continue;
      }
      html += `<div class="tl-row ${tl.selected === e.i ? 'sel' : ''}" data-k="${k}" data-i="${e.i}" style="top:${k * ROW}px"><span class="t" title="Log text: ${esc(e.time)}">${esc(fmtTs(e.ts))}</span><span class="lv lv-${e.lvl}">${e.lvl}</span><span class="c">${esc(e.comp)}</span><span class="m">${hl(e.msg)}${e.multi ? ' <span class="more">⏎</span>' : ''}</span></div>`;
    }
    spacer.innerHTML = html;
  }
  const schedule = () => (raf ||= requestAnimationFrame(draw));

  async function reload({ keepScroll = false, jump = null } = {}) {
    gen++;
    pages = new Map();
    $('#tlCount', el).textContent = 'Filtering…';
    try {
      let pos = null;
      if (jump != null) {
        const loc = await dsApi(`/locate?${tlQuery(f)}&i=${jump}`);
        total = loc.total;
        pos = loc.position;
      } else {
        const r = await dsApi(`/entries?${tlQuery(f)}&offset=0&limit=${PAGE}`);
        total = r.total;
        pages.set(0, r.entries);
      }
      spacer.style.height = `${total * ROW}px`;
      $('#tlCount', el).textContent = `${fmtN(total)} of ${fmtN(state.summary.entries)} lines`;
      if (pos != null) {
        scroll.scrollTop = Math.max(0, pos * ROW - scroll.clientHeight / 3);
        select(jump);
      } else if (!keepScroll) scroll.scrollTop = 0;
      else scroll.scrollTop = tl.scrollTop;
      draw();
    } catch (err) {
      $('#tlCount', el).textContent = err.message;
      total = 0;
      spacer.style.height = '0px';
      spacer.innerHTML = '';
    }
  }

  async function select(i) {
    tl.selected = i;
    schedule();
    const box = $('#tlDetail', el);
    box.hidden = false;
    let e;
    try {
      e = await dsApi(`/entries/${i}`);
    } catch (err) {
      box.innerHTML = `<div class="tl-detail-body">${esc(err.message)}</div>`;
      return;
    }
    if (tl.selected !== i) return;
    const tag = /tag_id"?:\s*(\d+)|TAG-ID=(\d+)|tag_id:\s*(\d+)/.exec(e.msg);
    const tagId = tag && (tag[1] || tag[2] || tag[3]);
    const conn = /^(?:===> )?ID=(\d+),|TcpConnection run for ID: (\d+)\)/.exec(e.msg);
    const connId = conn && (conn[1] || conn[2]);
    const json = extractJson(e.msg);
    box.innerHTML = `
      <div class="tl-detail-head">
        <span class="lv-${e.lvl}" style="font-weight:600">${e.lvl}</span>
        <span class="mono">${esc(fmtTs(e.ts))} ${esc(tzAbbr(e.ts))}</span>
        <span class="muted mono" title="Timestamp as written in the log file">log: ${esc(e.time)}${e.tz ? `(${esc(e.tz)})` : ''}</span>
        <span class="muted">${esc(e.file)}:${e.line}</span>
        <span class="muted">pid ${e.pid ?? '—'} · tid ${e.tid ?? '—'}</span>
        <span class="spacer"></span>
        ${tagId ? `<button class="btn sm" data-act="tag" data-tag="${tagId}">Follow tag ${tagId}</button>` : ''}
        ${connId && !tagId ? `<button class="btn sm" data-act="tag" data-tag="${connId}">Follow connection ${connId}</button>` : ''}
        <button class="btn sm" data-act="ctx">Show in context</button>
        <button class="btn sm" data-act="copy">Copy</button>
        <button class="btn sm ghost" data-act="close" aria-label="Close details">✕</button>
      </div>
      <div class="tl-detail-body"><pre class="msg">${esc(e.msg)}</pre>${json ? `<pre class="json">${prettyJson(json)}</pre>` : ''}</div>`;
    box.onclick = async (ev) => {
      const act = ev.target.closest('[data-act]')?.dataset.act;
      if (act === 'close') {
        box.hidden = true;
        tl.selected = null;
        schedule();
      } else if (act === 'copy') {
        try {
          await navigator.clipboard.writeText(`${e.time}(${e.tz}) ${e.lvl} ${e.msg}`);
          toast('Copied');
        } catch {
          toast('Clipboard unavailable');
        }
      } else if (act === 'ctx') {
        tl.f = defaultFilters();
        tl.f.hideNoise = false;
        Object.assign(f, tl.f);
        syncControls();
        reload({ jump: i });
      } else if (act === 'tag') {
        f.tag = ev.target.dataset.tag;
        f.q = '';
        f.hideNoise = false;
        syncControls();
        reload({ jump: i });
      }
    };
  }

  function syncControls() {
    $('#tlQ', el).value = f.q;
    $('#tlTag', el).value = f.tag;
    $('#tlRx', el).setAttribute('aria-pressed', f.regex);
    $('#tlSvc', el).value = f.svc;
    $('#tlNoise', el).checked = f.hideNoise;
    $('#tlComp', el).value = f.comps && f.comps.size === 1 ? [...f.comps][0] : '';
    $$('.lv-chip', el).forEach((c) => c.setAttribute('aria-pressed', f.levels.has(c.dataset.l)));
  }

  let debounce;
  $('#tlQ', el).addEventListener('input', (ev) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      f.q = ev.target.value;
      reload();
    }, 250);
  });
  $('#tlTag', el).addEventListener('change', (ev) => {
    f.tag = ev.target.value.replace(/\D/g, '');
    reload();
  });
  $('#tlRx', el).onclick = (ev) => {
    f.regex = !f.regex;
    ev.currentTarget.setAttribute('aria-pressed', f.regex);
    if (f.q) reload();
  };
  $$('.lv-chip', el).forEach(
    (c) =>
      (c.onclick = () => {
        const l = c.dataset.l;
        f.levels.has(l) ? f.levels.delete(l) : f.levels.add(l);
        c.setAttribute('aria-pressed', f.levels.has(l));
        reload();
      }),
  );
  $('#tlComp', el).onchange = (ev) => {
    f.comps = ev.target.value ? new Set([ev.target.value]) : null;
    reload();
  };
  $('#tlSvc', el).onchange = (ev) => {
    f.svc = ev.target.value;
    reload();
  };
  $('#tlNoise', el).onchange = (ev) => {
    f.hideNoise = ev.target.checked;
    reload();
  };
  $('#tlReset', el).onclick = () => {
    tl.f = defaultFilters();
    Object.assign(f, tl.f);
    syncControls();
    reload();
  };
  scroll.addEventListener('scroll', () => {
    tl.scrollTop = scroll.scrollTop;
    schedule();
  });
  spacer.addEventListener('click', (ev) => {
    const row = ev.target.closest('.tl-row[data-i]');
    if (row) {
      select(Number(row.dataset.i));
      scroll.focus({ preventScroll: true });
    }
  });
  scroll.addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp' && ev.key !== 'Enter') return;
    const cur = $('.tl-row.sel', spacer);
    if (ev.key === 'Enter') {
      if (tl.selected != null) $('#tlDetail [data-act="ctx"]', el)?.click();
      return;
    }
    ev.preventDefault();
    let k = cur ? Number(cur.dataset.k) : Math.floor(scroll.scrollTop / ROW);
    k = Math.max(0, Math.min(total - 1, k + (ev.key === 'ArrowDown' ? 1 : -1)));
    const e = rowAt(k);
    if (!e) return;
    if (k * ROW < scroll.scrollTop) scroll.scrollTop = k * ROW;
    else if ((k + 1) * ROW > scroll.scrollTop + scroll.clientHeight) scroll.scrollTop = (k + 1) * ROW - scroll.clientHeight;
    select(e.i);
  });
  new ResizeObserver(schedule).observe(scroll);

  await reload({ keepScroll: jumpTo == null, jump: jumpTo });
  if (jumpTo == null && tl.selected != null) select(tl.selected);
}

function extractJson(msg) {
  const k = msg.indexOf('{', Math.max(0, msg.indexOf('Data:')));
  if (k < 0 || !/Data:/.test(msg)) return null;
  try {
    return JSON.parse(msg.slice(k));
  } catch {
    return null;
  }
}
function prettyJson(obj) {
  return esc(JSON.stringify(obj, null, 2)).replace(
    /(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(-?\d+(?:\.\d+)?)\b/g,
    (m, str, colon, num) => (str ? (colon ? `<span class="j-key">${str}</span>${colon}` : `<span class="j-str">${str}</span>`) : `<span class="j-num">${num}</span>`),
  );
}

// ---------------------------------------------------------------- routing

function go(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

let routing = 0;
async function route() {
  const token = ++routing;
  const [path, qs] = location.hash.replace(/^#\/?/, '').split('?');
  const name = views[path] ? path : 'overview';
  const params = new URLSearchParams(qs || '');
  $$('#tabs a').forEach((a) => a.classList.toggle('active', a.dataset.view === name));
  const el = $('#view');
  el.className = '';
  if (!state.ds || !state.summary) return emptyState(el);
  el.innerHTML = '<p class="muted">Loading…</p>';
  try {
    await views[name](el, params);
  } catch (err) {
    if (token === routing) el.innerHTML = `<div class="empty"><h2>Something went wrong</h2><p>${esc(err.message)}</p></div>`;
  }
}

// ---------------------------------------------------------------- datasets

async function refreshDatasets(selectId) {
  state.datasets = await api('/api/datasets');
  const sel = $('#dsSelect');
  const ready = state.datasets.filter((d) => d.ready);
  sel.innerHTML = ready.length
    ? ready.map((d) => `<option value="${d.id}">${esc(d.name)} · ${fmtN(d.entries)} lines</option>`).join('')
    : '<option value="">No logs loaded</option>';
  sel.disabled = !ready.length;
  const want = selectId || state.ds || store.get('zcc.ds');
  const pick = ready.find((d) => d.id === want) || ready[ready.length - 1];
  await activate(pick?.id || null);
}

async function activate(id) {
  if (id === state.ds && state.summary) return route();
  state.ds = id;
  state.summary = null;
  state.tl = null;
  if (id) {
    store.set('zcc.ds', id);
    $('#dsSelect').value = id;
    try {
      state.summary = await api(`/api/datasets/${id}/summary`);
    } catch (err) {
      toast(err.message);
      state.ds = null;
    }
  }
  route();
}

// ---------------------------------------------------------------- loading logs

function openLoadDialog() {
  $('#loadStatus').textContent = '';
  $('#loadStatus').classList.remove('error');
  $('#loadDialog').showModal();
}
function setStatus(msg, error = false) {
  const s = $('#loadStatus');
  s.textContent = msg;
  s.classList.toggle('error', error);
}

async function uploadFiles(files) {
  if (!files.length) return;
  const includeUpm = $('#includeUpm').checked;
  const name = files.length === 1 ? files[0].name : `${files.length} files (${files[0].name}…)`;
  try {
    const ds = await api('/api/datasets', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name }) });
    let k = 0;
    for (const file of files) {
      k++;
      setStatus(`Uploading ${k}/${files.length}: ${file.name} (${(file.size / 1e6).toFixed(1)} MB)…`);
      await api(`/api/datasets/${ds.id}/files${includeUpm ? '?includeUpm=1' : ''}`, {
        method: 'POST',
        headers: { 'x-filename': encodeURIComponent(file.name), 'content-type': 'application/octet-stream' },
        body: file,
      });
    }
    setStatus('Parsing and analyzing…');
    const summary = await api(`/api/datasets/${ds.id}/finalize`, { method: 'POST' });
    $('#loadDialog').close();
    toast(`Loaded ${fmtN(summary.entries)} lines from ${summary.fileList.length} file(s)`);
    await refreshDatasets(ds.id);
  } catch (err) {
    setStatus(err.message, true);
  }
}

async function loadLocal() {
  setStatus('Reading local Client Connector logs…');
  $('#localBtn').disabled = true;
  try {
    const summary = await api('/api/datasets/local', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ includeUpm: $('#includeUpm').checked, sinceDays: Number($('#sinceDays').value) }),
    });
    $('#loadDialog').close();
    toast(`Loaded ${fmtN(summary.entries)} lines from ${summary.fileList.length} file(s)`);
    await refreshDatasets(summary.id);
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    $('#localBtn').disabled = false;
  }
}

function initLoader() {
  const drop = $('#dropZone');
  const input = $('#fileInput');
  drop.onclick = () => input.click();
  drop.onkeydown = (e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), input.click());
  input.onchange = () => {
    uploadFiles([...input.files]);
    input.value = '';
  };
  drop.addEventListener('dragover', (e) => {
    e.preventDefault();
    drop.classList.add('over');
  });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    uploadFiles([...e.dataTransfer.files]);
  });
  // Allow dropping files anywhere on the page.
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => {
    if (e.target.closest?.('#dropZone')) return;
    e.preventDefault();
    if (e.dataTransfer?.files?.length) {
      openLoadDialog();
      uploadFiles([...e.dataTransfer.files]);
    }
  });
  $('#localBtn').onclick = loadLocal;
  $('#loadBtn').onclick = openLoadDialog;
  api('/api/local')
    .then((r) => ($('#localDirs').textContent = r.dirs.length ? r.dirs.join(', ') : 'No default log folder for this OS; set ZCC_LOG_DIRS'))
    .catch(() => {});
}

function initTheme() {
  const saved = store.get('zcc.theme');
  if (saved) document.documentElement.dataset.theme = saved;
  $('#themeBtn').onclick = () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    const next = dark ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    store.set('zcc.theme', next);
    route(); // redraw charts with new colors
  };
}

initTheme();
initLoader();
$('#dsSelect').onchange = (e) => activate(e.target.value);
window.addEventListener('hashchange', route);
let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const v = location.hash.replace(/^#\/?/, '').split('?')[0];
    if (['overview', 'sessions', 'zia', ''].includes(v)) route();
  }, 200);
});
refreshDatasets().catch((err) => {
  $('#view').innerHTML = `<div class="empty"><h2>Cannot reach the server</h2><p>${esc(err.message)}</p></div>`;
});
