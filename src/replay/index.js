'use strict';
// Impact replay (WORK IN PROGRESS, see docs/impact-replay-plan.md).
// Answers "if I apply this change, which logged transactions would change outcome?"
// This is a fail-safe skeleton: nothing is wired into server.js yet, and every
// unimplemented step returns { ok: false, status: 'not_implemented' } instead of guessing.

const NOT_IMPLEMENTED = Object.freeze({ ok: false, status: 'not_implemented' });

// Fields a normalized log record will carry once the parsers exist (names pending Research confirmation).
const RECORD_FIELDS = ['time', 'user', 'department', 'location', 'url', 'host', 'urlCategory', 'action', 'ruleName', 'protocol', 'port', 'fileType', 'blockedBy', 'weight'];
// blockedBy: NSS rulelabel (only set for block rules) or Web Insights 'Blocked Policy Name' -> 'already blocked by' column;

// Aggregation key: records with identical evaluation inputs are evaluated once and weighted.
function aggregateKey(r) {
  return [r.user, r.department, r.location, r.host, r.urlCategory, r.protocol, r.port, r.fileType].map((v) => (v == null ? '' : String(v).toLowerCase())).join('|');
}

function aggregate(records) {
  const groups = new Map();
  for (const r of records || []) {
    const k = aggregateKey(r);
    const g = groups.get(k);
    const w = Number.isFinite(r.weight) && r.weight > 0 ? r.weight : 1;
    if (g) g.weight += w; else groups.set(k, Object.assign({}, r, { weight: w }));
  }
  return [...groups.values()];
}

function parseWebInsightsCsv(/* text */) { return NOT_IMPLEMENTED; }
function parseNssWebLog(/* text */) { return NOT_IMPLEMENTED; }
function simulateDiff(/* currentSnap, proposedSnap, records, opts */) { return NOT_IMPLEMENTED; }

module.exports = { RECORD_FIELDS, aggregateKey, aggregate, parseWebInsightsCsv, parseNssWebLog, simulateDiff, NOT_IMPLEMENTED };
