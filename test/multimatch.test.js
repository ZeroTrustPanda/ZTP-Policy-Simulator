'use strict';
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const { simulate } = require('../src/engine');

const data = {
  urlFilteringRules: [
    { id: 1, name: 'Block Gambling', order: 1, state: 'ENABLED', action: 'BLOCK', urlCategories: ['GAMBLING'] },
    { id: 2, name: 'Caution Gambling for HR', order: 2, state: 'ENABLED', action: 'CAUTION', urlCategories: ['GAMBLING'], groups: [{ id: 7, name: 'HR' }] },
    { id: 3, name: 'Block Gambling again', order: 3, state: 'ENABLED', action: 'BLOCK', urlCategories: ['GAMBLING'] },
    { id: 4, name: 'Block Social', order: 4, state: 'ENABLED', action: 'BLOCK', urlCategories: ['SOCIAL_NETWORKING'] },
    { id: 5, name: 'Allow Everything Else', order: 5, state: 'ENABLED', action: 'ALLOW', urlCategories: ['ANY'] },
    { id: 6, name: 'Default', order: -1, state: 'ENABLED', action: 'ALLOW' },
  ],
};
const run = (over) => { const t = M.parseTarget('bet.example'); return simulate({ data }, Object.assign({ target: t, port: 443, protocol: 'tcp', groups: [], categories: ['GAMBLING'], resolvedIps: [], notes: [] }, over), {}); };

test('multi-match: later rules that also match are listed, catch-alls counted, different actions flagged', () => {
  const r = run({ user: 'pat', groups: ['HR'] });
  const u = r.modules.find((m) => m.module === 'URL Filtering');
  assert.equal(u.decidingRule.name, 'Block Gambling');
  assert.deepEqual(u.alsoMatched.map((e) => e.name), ['Caution Gambling for HR', 'Block Gambling again']);
  assert.equal(u.alsoMatched[0].differs, true); assert.equal(u.alsoMatched[1].differs, false);
  assert.equal(u.alsoMatchedCatchAll, 2); // "Allow Everything Else" (ANY) and the default rule
  const mm = r.summary.multiMatch.find((x) => x.module === 'URL Filtering');
  assert.equal(mm.decides, true); assert.equal(mm.rule, 'Block Gambling');
});

test('multi-match: rules that only might match (unknown) are not listed', () => {
  const r = run({});
  const u = r.modules.find((m) => m.module === 'URL Filtering');
  assert.deepEqual(u.alsoMatched.map((e) => e.name), ['Block Gambling again']); // HR rule is unknown without a user
});
