'use strict';
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const { simulate } = require('../src/engine');
const changes = require('../src/changes');

const rules = [
  { id: 1, name: 'Allow Gambling for VIPs', order: 1, rank: 7, state: 'ENABLED', action: 'ALLOW', urlCategories: ['GAMBLING'] },
  { id: 2, name: 'Corp: Block Gambling', order: 2, rank: 2, state: 'ENABLED', action: 'BLOCK', urlCategories: ['GAMBLING'] },
  { id: 3, name: 'Default', order: -1, rank: 7, state: 'ENABLED', action: 'ALLOW' },
];
const run = (adv) => simulate({ data: { urlFilteringRules: rules, advancedSettings: adv } }, { target: M.parseTarget('bet.example'), port: 443, protocol: 'tcp', groups: [], categories: ['GAMBLING'], resolvedIps: [], notes: [] }, {});

test('admin ranking off: rule order decides, rank ignored', () => {
  const r = run({ enableAdminRankAccess: false });
  assert.equal(r.summary.primary.rule, 'Allow Gambling for VIPs');
  assert.equal(r.context.adminRanking, false);
  assert.equal(r.summary.rank, undefined);
});

test('admin ranking on: rank first, then order; the shadowed lower-rank rule is reported', () => {
  const r = run({ enableAdminRankAccess: true });
  assert.equal(r.summary.primary.rule, 'Corp: Block Gambling');
  assert.equal(r.summary.primary.action, 'BLOCK');
  assert.equal(r.summary.rank.rank, 2);
  assert.deepEqual(r.summary.rank.effects.map((e) => [e.name, e.status]), [['Allow Gambling for VIPs', 'match']]);
  assert.ok(r.context.notes.some((n) => /Admin ranking is on/.test(n)));
});

test('policy change: a new rule placed above a ranked rule takes that rank', () => {
  const data = { advancedSettings: { enableAdminRankAccess: true }, urlFilteringRules: rules, customUrlCategories: [] };
  const p = changes.plan({ intent: 'ALLOW', entries: ['bet.example'], category: { mode: 'new', name: 'Bet Allow' }, rules: { url: { enabled: true, mode: 'new', name: 'Allow bet', placeAbove: 2 } } }, data);
  assert.deepEqual(p.errors, []);
  const step = p.steps.find((st) => st.body && st.body.name === 'Allow bet');
  assert.equal(step.body.rank, 2); assert.equal(step.body.order, 2);
  assert.ok(p.warnings.some((w) => /admin rank 2/.test(w)));
  const off = changes.plan({ intent: 'ALLOW', entries: ['bet.example'], category: { mode: 'new', name: 'Bet Allow' }, rules: { url: { enabled: true, mode: 'new', name: 'Allow bet', placeAbove: 2 } } }, Object.assign({}, data, { advancedSettings: { enableAdminRankAccess: false } }));
  assert.equal(off.steps.find((st) => st.body && st.body.name === 'Allow bet').body.rank, 7);
});
