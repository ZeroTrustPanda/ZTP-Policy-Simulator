'use strict';
const test = require('node:test');
const assert = require('node:assert');
const R = require('../src/replay');

// Synthetic data only: example.com hosts and RFC 5737 addresses.
test('aggregate merges identical evaluation inputs and sums weight', () => {
  const recs = [
    { user: 'alice@example.com', host: 'www.example.com', urlCategory: 'NEWS', weight: 3 },
    { user: 'ALICE@example.com', host: 'www.example.com', urlCategory: 'news' },
    { user: 'bob@example.com', host: '192.0.2.10', urlCategory: 'OTHER' },
  ];
  const out = R.aggregate(recs);
  assert.strictEqual(out.length, 2);
  assert.strictEqual(out.find((r) => r.user === 'alice@example.com').weight, 4);
});

test('unimplemented steps fail safe', () => {
  for (const f of [R.parseWebInsightsCsv, R.parseNssWebLog, R.simulateDiff]) assert.deepStrictEqual(f(''), { ok: false, status: 'not_implemented' });
});
