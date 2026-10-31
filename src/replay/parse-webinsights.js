'use strict';
// Web Insights Logs CSV export. One row per transaction. Columns vary with the admin's column picker, so
// columns are matched by header name (case/space/punctuation-insensitive). Preamble lines before the header are skipped.
const { csvRows } = require('./lines');
const { record } = require('./normalize');

const key = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const HEADERS = {
  time: ['loggedtime', 'time', 'datetime', 'timestamp', 'eventtime'],
  user: ['user', 'login', 'username'],
  dept: ['department', 'dept'],
  location: ['location'],
  url: ['url', 'fullurl'],
  host: ['host', 'hostname', 'serverhostname'],
  urlcat: ['urlcategory', 'category'],
  action: ['policyaction', 'action'],
  ruleType: ['blockedpolicytype'],
  blockedBy: ['blockedpolicyname'],
  urlRule: ['urlfilteringpolicyname'],
  clientIp: ['clientip', 'clientinternalip'],
  weight: ['transactions', 'count', 'numberoftransactions', 'weight'],
};
const LOOKUP = new Map(Object.entries(HEADERS).flatMap(([f, list]) => list.map((h) => [h, f])));
const REQUIRED_ANY = ['url', 'host'];

function mapHeader(cells) {
  const map = cells.map((c) => LOOKUP.get(key(c)) || null);
  return REQUIRED_ANY.some((f) => map.includes(f)) && map.filter(Boolean).length >= 2 ? map : null;
}

// Yields normalized records. stats (optional object) receives { rows, skipped, header, unknownColumns }.
async function* parseWebInsights(src, stats = {}) {
  let map = null; stats.rows = 0; stats.skipped = 0;
  for await (const cells of csvRows(src)) {
    if (!map) {
      map = mapHeader(cells);
      if (map) { stats.header = cells; stats.unknownColumns = cells.filter((_, i) => !map[i]); }
      continue; // preamble or header line
    }
    const f = {};
    map.forEach((k, i) => { if (k && f[k] == null) f[k] = cells[i]; });
    const r = record(f);
    if (!r.host) { stats.skipped++; continue; }
    stats.rows++;
    yield r;
  }
  if (!map) throw new Error('Web Insights CSV: no header row with a URL or Host column found');
}

module.exports = { parseWebInsights, mapHeader, HEADERS };
