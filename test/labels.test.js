'use strict';
// Customer report: firewall rules carrying labels ("Blocks", "Any - Any") all came out "unknown", so a TCP/53 bulk run
// showed every IP as ALLOWED with no deciding rule. Labels are tags only; they never decide whether traffic matches.
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const { simulate } = require('../src/engine');
const bulk = require('../src/bulk');
const snap = require('./fixtures-labels.json');
const run = (ip, cats, port = 53) => simulate(snap, { target: M.parseTarget(ip), port, protocol: 'tcp', groups: [], categories: cats, categorySource: 'Zscaler lookup', resolvedIps: [], notes: [] }, {});
const fw = (r) => r.modules.find((m) => m.module === 'Firewall');

test('rule labels are not conditions', () => {
  const r = run('1.54.187.242', ['MISCELLANEOUS_OR_UNKNOWN']);
  for (const e of fw(r).rules) assert.ok(!e.criteria.some((c) => /label/i.test(c.field)), `${e.name} has a label criterion`);
});

test('IP in the SIRT list on TCP/53 is blocked by "SIRT Block"', () => {
  const r = run('1.54.187.242', ['MISCELLANEOUS_OR_UNKNOWN']);
  assert.equal(fw(r).decidingRule.name, 'SIRT Block');
  assert.equal(r.summary.overall, 'BLOCKED');
  assert.equal(r.summary.primary.rule, 'SIRT Block');
});

test('other IPs on TCP/53 are allowed by "Recommended Firewall Rule"', () => {
  const r = run('8.8.8.8', ['WEB_SEARCH']);
  assert.equal(fw(r).decidingRule.name, 'Recommended Firewall Rule');
  assert.equal(r.summary.overall, 'ALLOWED');
  assert.equal(r.summary.primary.rule, 'Recommended Firewall Rule');
});

test('nothing else matches: the tenant default rule (Block/Drop) decides, not a hard-coded Allow', () => {
  const r = run('8.8.8.8', ['WEB_SEARCH'], 3389);
  assert.equal(fw(r).decidingRule.name, 'Default Firewall Filtering Rule');
  assert.equal(r.summary.overall, 'BLOCKED');
});

test('bulk CSV shows the deciding rule and spells out the conditions', () => {
  const r = run('8.8.8.8', ['WEB_SEARCH']);
  const row = bulk.resultRow(0, { line: 1, input: '8.8.8.8', target: '8.8.8.8', port: 53, protocol: 'tcp' }, r, { categories: ['WEB_SEARCH'], source: 'Zscaler lookup' }, '', snap.data);
  assert.match(bulk.toCsv([row]), /Recommended Firewall Rule/);
  assert.match(String(row.conditions), /Geolocation Block List/);
});

test('a destination IP group missing from the snapshot is unknown, not "any destination"', () => {
  const s = JSON.parse(JSON.stringify(snap));
  s.data.firewallRules.splice(1, 0, { id: 150, name: 'VOIP group allow', order: 2, rank: 0, state: 'ENABLED', action: 'ALLOW', destIpGroups: [{ id: 77, name: 'VOIP Applications' }] });
  const r = simulate(s, { target: M.parseTarget('1.54.187.242'), port: 53, protocol: 'tcp', groups: [], categories: ['MISCELLANEOUS_OR_UNKNOWN'], categorySource: 'Zscaler lookup', resolvedIps: [], notes: [] }, {});
  const e = fw(r).rules.find((x) => x.name === 'VOIP group allow');
  assert.equal(e.criteria.find((c) => c.field === 'destination').status, 'unknown');
  assert.equal(fw(r).decidingRule.name, 'SIRT Block');
});
