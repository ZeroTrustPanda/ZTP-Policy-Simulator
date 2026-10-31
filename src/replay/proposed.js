'use strict';
// Phase 2: build a proposed policy by applying a change-wizard spec to a deep clone of the snapshot, offline.
// The live snapshot is never mutated and no real API is called (changes.mockApi on the clone only).
const C = require('../changes');

const clone = (x) => (typeof structuredClone === 'function' ? structuredClone(x) : JSON.parse(JSON.stringify(x)));

async function proposedPolicy(snap, spec) {
  const live = snap && snap.data ? snap.data : snap;
  if (!live || typeof live !== 'object') throw new TypeError('snapshot required');
  const data = clone(live);
  const p = C.plan(spec, data);
  if (p.errors && p.errors.length) return { ok: false, errors: p.errors, warnings: p.warnings || [], plan: p };
  const entry = await C.apply(p, C.mockApi(data));
  if (entry.failed) return { ok: false, errors: [entry.failed.error || 'apply failed'], warnings: p.warnings || [], plan: p };
  delete data.__status;
  return { ok: true, data, plan: p, warnings: p.warnings || [], summary: p.summary };
}

module.exports = { proposedPolicy, clone };
