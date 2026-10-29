'use strict';
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const { simulate, isTimeout } = require('../src/engine');

// A tenant like the customer's: the predefined "Office 365 One Click Rule" (only criterion: app service group OFFICE365)
// sits above the tenant's own rules. The API never returns the group's members.
const data = {
  firewallRules: [
    { id: 1, name: 'Office 365 One Click Rule', order: 1, rank: 7, state: 'ENABLED', action: 'ALLOW', predefined: true, appServiceGroups: [{ id: 1, name: 'OFFICE365' }] },
    { id: 2, name: 'UCaaS One Click Rule', order: 2, rank: 7, state: 'ENABLED', action: 'ALLOW', predefined: true, appServiceGroups: [{ id: 2, name: 'ZOOM' }, { id: 3, name: 'WEBEX' }] },
    { id: 3, name: 'Block hosting providers', order: 3, rank: 7, state: 'ENABLED', action: 'BLOCK_DROP', destIpCategories: ['WEB_HOSTING'] },
    { id: 9, name: 'Default Firewall Filtering Rule', order: -1, rank: 7, state: 'ENABLED', action: 'ALLOW', defaultRule: true },
  ],
  zccAppServices: [{ id: 11, appName: 'M365', appDataBlob: [{ proto: 'TCP', port: '443,80', ipaddr: '52.108.0.0/14,20.190.128.0/18' }] }],
};
const run = (target, cats = [], extra = {}) => simulate({ data, errors: extra.errors || {} }, Object.assign({ target: M.parseTarget(target), port: 443, protocol: 'tcp', groups: [], categories: cats, resolvedIps: [], notes: [] }, extra.ctx || {}), {});
const fw = (r) => r.modules.find((m) => m.module === 'Firewall');

test('Office 365 One Click no longer matches every IP (namecheap-style hosting IP)', () => {
  const r = run('198.54.117.200', ['WEB_HOSTING']);
  assert.equal(fw(r).rules.find((e) => e.name === 'Office 365 One Click Rule').status, 'nomatch');
  assert.equal(fw(r).decidingRule.name, 'Block hosting providers');
});

test('Office 365 One Click still matches Microsoft 365 IPs and hostnames', () => {
  assert.equal(fw(run('52.108.10.10')).decidingRule.name, 'Office 365 One Click Rule');
  assert.equal(fw(run('outlook.office365.com')).decidingRule.name, 'Office 365 One Click Rule');
  assert.equal(fw(run('www.namecheap.com', ['WEB_HOSTING'])).decidingRule.name, 'Block hosting providers');
});

test('app service groups without known ranges are "unknown", never a match', () => {
  const r = run('203.0.113.50', ['WEB_HOSTING']);
  const u = fw(r).rules.find((e) => e.name === 'UCaaS One Click Rule');
  assert.equal(u.status, 'unknown');
  assert.equal(fw(run('zoom.us')).decidingRule.name, 'UCaaS One Click Rule');
});

test('a rule criterion the simulator does not evaluate makes the rule unknown, not a catch-all', () => {
  const d2 = { firewallRules: [{ id: 5, name: 'Mystery', order: 1, state: 'ENABLED', action: 'BLOCK_DROP', someNewCriterion: [{ id: 1, name: 'X' }] }] };
  const r = simulate({ data: d2 }, { target: M.parseTarget('8.8.8.8'), port: 443, protocol: 'tcp', groups: [], categories: [], resolvedIps: [], notes: [] }, {});
  const e = fw(r).rules[0];
  assert.equal(e.status, 'unknown');
  assert.match(e.criteria.find((c) => c.field === 'someNewCriterion').detail, /not evaluated/);
});

test('a policy set that failed to load (timeout) is reported, not treated as "no rule matched"', () => {
  assert.equal(isTimeout(new Error('Request timeout')), true);
  assert.equal(isTimeout('HTTP 504 GET /zia/api/v1/firewallFilteringRules'), true);
  const r = run('8.8.8.8', [], { errors: { firewallRules: 'ETIMEDOUT: Request timeout (api.zsapi.net)' } });
  assert.equal(fw(r).verdict, 'NOT_EVALUATED');
  assert.equal(r.summary.incomplete[0].module, 'Firewall');
  assert.equal(r.summary.incomplete[0].timeout, true);
});

test('lookup failures reach the result', () => {
  const r = run('8.8.8.8', [], { ctx: { lookupErrors: [{ module: 'Zscaler category lookup', error: 'Request timeout', timeout: true }] } });
  assert.equal(r.summary.incomplete.some((x) => x.module === 'Zscaler category lookup' && x.timeout), true);
});

test('repeated simulations are independent (no state carried between runs)', () => {
  const a = run('52.108.10.10');
  const b = run('198.54.117.200', ['WEB_HOSTING']);
  const c = run('52.108.10.10');
  assert.equal(fw(a).decidingRule.name, fw(c).decidingRule.name);
  assert.notEqual(fw(b).decidingRule.name, 'Office 365 One Click Rule');
});
