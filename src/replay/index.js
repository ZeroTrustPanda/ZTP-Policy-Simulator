'use strict';
// Impact replay (see docs/impact-replay-plan.md). Phases 1-2 done: log parsing + aggregation, offline proposed policy.
// simulateDiff (phase 3) is still a fail-safe stub.
const { parseWebInsights } = require('./parse-webinsights');
const { parseNssJson, parseNssTsv, fieldsFrom } = require('./parse-nss');
const { proposedPolicy } = require('./proposed');
const { record } = require('./normalize');

const NOT_IMPLEMENTED = Object.freeze({ ok: false, status: 'not_implemented' });
const RECORD_FIELDS = ['time', 'user', 'dept', 'location', 'url', 'host', 'urlcat', 'action', 'ruleType', 'blockedBy', 'urlRule', 'clientIp', 'weight'];

// Records with identical evaluation inputs are evaluated once; weight sums, and per-day counts are kept for the trend.
const KEY_FIELDS = ['user', 'dept', 'location', 'host', 'url', 'urlcat', 'action', 'blockedBy'];
const aggregateKey = (r) => KEY_FIELDS.map((k) => (r[k] == null ? '' : String(r[k]).toLowerCase())).join('|');

async function aggregate(records) {
  const groups = new Map();
  const add = (r) => {
    const k = aggregateKey(r);
    const w = Number.isFinite(r.weight) && r.weight > 0 ? r.weight : 1;
    const day = r.time ? String(r.time).slice(0, 10) : 'unknown';
    let g = groups.get(k);
    if (!g) { g = Object.assign({}, r, { weight: 0, days: {} }); delete g.time; delete g.timeRaw; groups.set(k, g); }
    g.weight += w; g.days[day] = (g.days[day] || 0) + w;
  };
  if (records && typeof records[Symbol.asyncIterator] === 'function') { for await (const r of records) add(r); }
  else for (const r of records || []) add(r);
  return [...groups.values()];
}

// format: 'webinsights' | 'nss-json' | 'nss-tsv' | 'auto' (sniffed from the first non-empty line of a string).
function sniff(text) {
  const l = String(text).replace(/^\uFEFF/, '').split(/\r?\n/).find((x) => x.trim()) || '';
  if (/^\s*[[{]/.test(l)) return 'nss-json';
  if (l.includes('\t') && !l.includes(',')) return 'nss-tsv';
  return 'webinsights';
}
function parseLogs(src, { format = 'auto', fields } = {}, stats = {}) {
  const f = format === 'auto' ? (typeof src === 'string' ? sniff(src) : null) : format;
  if (f === 'webinsights') return parseWebInsights(src, stats);
  if (f === 'nss-json') return parseNssJson(src, stats);
  if (f === 'nss-tsv') return parseNssTsv(src, { fields }, stats);
  throw new Error(`unknown or unsniffable log format: ${format}`);
}

function simulateDiff(/* currentSnap, proposedSnap, records, opts */) { return NOT_IMPLEMENTED; }

module.exports = { RECORD_FIELDS, aggregateKey, aggregate, parseLogs, sniff, parseWebInsights, parseNssJson, parseNssTsv, fieldsFrom, proposedPolicy, record, simulateDiff, NOT_IMPLEMENTED };
