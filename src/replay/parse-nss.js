'use strict';
// NSS web logs: JSON lines, JSON array batches (Cloud NSS), or TSV with a configurable field list.
// JSON objects may be bare or wrapped as {"sourcetype":"zscalernss-web","event":{...}}.
const { linesOf } = require('./lines');
const { record } = require('./normalize');

const FIELD = { time: 'time', epochtime: 'epochtime', login: 'user', elogin: 'user', dept: 'dept', location: 'location', url: 'url', eurl: 'url', host: 'host', urlcat: 'urlcat', action: 'action', ruletype: 'ruleType', rulelabel: 'blockedBy', urlfilterrulelabel: 'urlRule', cltip: 'clientIp' };
const HEX = new Set(['elogin', 'eurl']);
const dehex = (s) => { try { return /^([0-9a-f]{2})+$/i.test(s) ? Buffer.from(s, 'hex').toString('utf8') : s; } catch { return s; } };

function fromNss(obj) {
  const ev = obj && typeof obj.event === 'object' && obj.event ? obj.event : obj;
  const f = {};
  for (const [k, v] of Object.entries(ev || {})) { const t = FIELD[k]; if (t && f[t] == null) f[t] = HEX.has(k) ? dehex(String(v)) : v; }
  return record(f);
}

// Default TSV field list = Research's synthetic custom format; override with opts.fields (NSS variable names).
const DEFAULT_TSV_FIELDS = ['time', 'login', 'dept', 'location', 'url', 'urlcat', 'action', 'reason', 'rulelabel', 'urlfilterrulelabel', 'cltip'];
// Accepts a feed format string like "%s{time}\t%s{login}..." too.
function fieldsFrom(spec) {
  if (Array.isArray(spec)) return spec;
  const m = [...String(spec).matchAll(/%[0-9]*[sdx]\{(\w+)\}/g)].map((x) => x[1]);
  return m.length ? m : String(spec).split(/[\t,]/).map((s) => s.trim()).filter(Boolean);
}

async function* parseNssTsv(src, opts = {}, stats = {}) {
  const fields = fieldsFrom(opts.fields || DEFAULT_TSV_FIELDS);
  stats.rows = 0; stats.skipped = 0;
  for await (const line of linesOf(src)) {
    if (!line.trim()) continue;
    const cells = line.split('\t');
    const o = {}; fields.forEach((f, i) => { o[f] = cells[i] == null ? '' : decodeURIComponentSafe(cells[i]); });
    const r = fromNss(o);
    if (!r.host) { stats.skipped++; continue; }
    stats.rows++; yield r;
  }
}
function decodeURIComponentSafe(s) { try { return /%[0-9a-f]{2}/i.test(s) ? decodeURIComponent(s) : s; } catch { return s; } }

// JSON lines and JSON arrays (one array per line/batch, or a pretty-printed array spanning many lines).
async function* parseNssJson(src, stats = {}) {
  stats.rows = 0; stats.skipped = 0;
  let buf = '', depth = 0, inStr = false, esc = false;
  const emit = function* (text) {
    let v; try { v = JSON.parse(text); } catch { stats.skipped++; return; }
    for (const o of Array.isArray(v) ? v : [v]) { const r = fromNss(o); if (r.host) { stats.rows++; yield r; } else stats.skipped++; }
  };
  // Scan characters, emitting each top-level object; array brackets at depth 0 are ignored so huge arrays stream.
  for await (const line of linesOf(src)) {
    for (const ch of line + '\n') {
      if (depth === 0) { if (ch === '{') { depth = 1; buf = '{'; } continue; }
      buf += ch;
      if (inStr) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') inStr = false; continue; }
      if (ch === '"') inStr = true; else if (ch === '{') depth++;
      else if (ch === '}' && --depth === 0) { yield* emit(buf); buf = ''; }
    }
  }
  if (depth) stats.skipped++;
}

module.exports = { parseNssJson, parseNssTsv, fromNss, fieldsFrom, DEFAULT_TSV_FIELDS };
