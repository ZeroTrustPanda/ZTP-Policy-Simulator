'use strict';
const test = require('node:test');
const assert = require('node:assert');
const C = require('../src/changes');
const { simulate } = require('../src/engine');
const M = require('../src/matchers');

const fresh = () => JSON.parse(JSON.stringify(require('../src/demo-snapshot.json')));
const ctx = (target, extra = {}) => Object.assign({ target: M.parseTarget(target), port: 443, protocol: 'tcp', categories: [], resolvedIps: [], groups: [], notes: [] }, extra);
const verdict = (data, target, extra) => simulate({ data }, ctx(target, extra), {}).summary.primary;

test('block: new category + URL, firewall and DNS rules + ATP denylist, then undo restores everything', async () => {
  const data = fresh();
  const before = JSON.stringify({ c: data.customUrlCategories, g: data.ipDestinationGroups, u: data.urlFilteringRules, f: data.firewallRules, d: data.dnsRules, a: data.atpMaliciousUrls });
  assert.equal(verdict(data, '45.9.9.9').action, 'ALLOW');
  const firstUrl = data.urlFilteringRules.filter((r) => !r.defaultRule).sort((a, b) => a.order - b.order)[0];
  const p = C.plan({
    intent: 'BLOCK', entries: ['45.9.9.9', '45.9.9.10', '45.9.9.11', 'evil.example.net'],
    category: { mode: 'new', name: 'SOC IOC Block List' }, ipGroup: { mode: 'new', name: 'SOC IOC Block List' },
    rules: { url: { enabled: true, mode: 'new', name: 'SOC-IOC-Block', placeAbove: 'TOP' }, firewall: { enabled: true, mode: 'new', name: 'SOC-IOC-Block-FW', placeAbove: 'BOTTOM' }, dns: { enabled: true, mode: 'new', name: 'SOC-IOC-Block-DNS', placeAbove: 'TOP' } },
    atp: { enabled: true }, criteria: { groups: [{ id: 77, name: 'Guests' }] },
  }, data);
  assert.deepEqual(p.errors, []);
  assert.ok(p.steps.some((s) => s.method === 'POST' && s.path === '/urlCategories'));
  const urlRule = p.steps.find((s) => s.path === '/urlFilteringRules').body;
  assert.equal(urlRule.order, 1); assert.deepEqual(urlRule.protocols, ['ANY_RULE']); assert.equal(urlRule.rank, 7);
  assert.deepEqual(urlRule.groups, [{ id: 77, name: 'Guests' }]);
  const dnsRule = p.steps.find((s) => s.path === '/firewallDnsRules').body;
  assert.ok(dnsRule.resCategories && dnsRule.destIpCategories, 'DNS uses resolved and requested category');
  const api = C.mockApi(data);
  const entry = await C.apply(p, api);
  assert.equal(entry.failed, null, entry.failed && entry.failed.error);
  assert.equal((await api.request('GET', '/status')).status, 'PENDING');
  assert.equal(firstUrl.order, 2, 'existing rules shift down when inserting at the top');
  // Group-scoped rule: a guest is blocked, everyone else still allowed by URL policy; firewall rule blocks all.
  const cat = data.customUrlCategories.find((c) => c.configuredName === 'SOC IOC Block List');
  assert.deepEqual(cat.ipRanges, ['45.9.9.10/31']); assert.ok(cat.urls.includes('45.9.9.9') && cat.urls.includes('evil.example.net'));
  assert.equal(verdict(data, '45.9.9.9', { groups: ['Guests'] }).action, 'BLOCK');
  assert.ok(data.atpMaliciousUrls.blacklistUrls.includes('45.9.9.9'));
  await C.undo(entry, api);
  assert.equal(entry.undone, true, JSON.stringify(entry.undoResults));
  assert.equal(JSON.stringify({ c: data.customUrlCategories, g: data.ipDestinationGroups, u: data.urlFilteringRules, f: data.firewallRules, d: data.dnsRules, a: data.atpMaliciousUrls }), before);
});

test('allow: blocked by a URL category rule → allow rule placed above it wins', async () => {
  const data = fresh();
  assert.equal(verdict(data, '45.2.0.4', { categories: ['GAMBLING'] }).action, 'BLOCK');
  const blocker = data.urlFilteringRules.find((r) => r.name === 'Block Gambling and Adult');
  const p = C.plan({ intent: 'ALLOW', entries: ['45.2.0.4'], category: { mode: 'new', name: 'Allowed Exceptions' },
    rules: { url: { enabled: true, mode: 'new', name: 'Allow-Exceptions', placeAbove: blocker.id } } }, data);
  assert.deepEqual(p.errors, []);
  const order = blocker.order;
  await C.apply(p, C.mockApi(data));
  assert.equal(data.urlFilteringRules.find((r) => r.name === 'Allow-Exceptions').order, order);
  assert.equal(verdict(data, '45.2.0.4', { categories: ['GAMBLING'] }).action, 'ALLOW');
});

test('existing category and group: only new entries are added; reusing a rule adds overflow groups to it', async () => {
  const data = fresh();
  data.ipDestinationGroups.push({ id: 5551, name: 'IOC Group', type: 'DSTN_IP', addresses: Array.from({ length: 7999 }, (_, i) => `11.0.${i >> 8}.${i & 255}`) });
  data.firewallRules.push({ id: 6661, name: 'Block IOC', order: 3, action: 'BLOCK_DROP', destIpGroups: [{ id: 5551, name: 'IOC Group' }] });
  const entries = ['11.0.0.0', ...Array.from({ length: 300 }, (_, i) => `12.0.${i >> 8}.${(i * 2) & 255}`)]; // first one already present
  const p = C.plan({ intent: 'BLOCK', entries, collapse: false, ipGroup: { mode: 'existing', id: 5551 },
    rules: { firewall: { enabled: true, mode: 'reuse', ruleId: 6661 } } }, data);
  assert.deepEqual(p.errors, []);
  assert.equal(p.steps[0].body.addresses.length, 8000, 'fills existing group to 8,000');
  assert.equal(p.steps[1].method, 'POST'); assert.equal(p.steps[1].body.name, 'IOC Group 2');
  assert.equal(p.steps[2].path, '/firewallFilteringRules/6661');
  const entry = await C.apply(p, C.mockApi(data));
  assert.equal(entry.failed, null);
  const rule = data.firewallRules.find((r) => r.id === 6661);
  assert.equal(rule.destIpGroups.length, 2);
});

test('validation: duplicate names, long names and empty input are refused before anything is sent', () => {
  const data = fresh();
  const existing = data.urlFilteringRules[0].name;
  const p = C.plan({ intent: 'BLOCK', entries: ['1.2.3.4'], category: { mode: 'new', name: 'X' }, rules: { url: { enabled: true, mode: 'new', name: existing } } }, data);
  assert.ok(p.errors.some((e) => /already exists/.test(e)));
  const p2 = C.plan({ intent: 'BLOCK', entries: ['1.2.3.4'], category: { mode: 'new', name: 'X' }, rules: { url: { enabled: true, mode: 'new', name: 'A'.repeat(40) } } }, data);
  assert.ok(p2.errors.some((e) => /31/.test(e)));
  const p3 = C.plan({ intent: 'BLOCK', entries: ['nope'], rules: {} }, data);
  assert.ok(p3.errors.length >= 2);
});

test('a failure mid-plan stops, and undo reverts only what was applied', async () => {
  const data = fresh();
  const api = C.mockApi(data);
  const real = api.request;
  api.request = async (m, p, b) => { if (p === '/firewallFilteringRules' && m === 'POST') throw new Error('HTTP 400: rank not allowed'); return real(m, p, b); };
  const p = C.plan({ intent: 'BLOCK', entries: ['46.1.1.1'], ipGroup: { mode: 'new', name: 'G1' }, rules: { firewall: { enabled: true, mode: 'new', name: 'FW1', placeAbove: 'TOP' } } }, data);
  const entry = await C.apply(p, api);
  assert.ok(entry.failed && /rank/.test(entry.failed.error));
  assert.equal(entry.done.length, 1);
  assert.ok(data.ipDestinationGroups.some((g) => g.name === 'G1'));
  api.request = real;
  await C.undo(entry, api);
  assert.ok(!data.ipDestinationGroups.some((g) => g.name === 'G1'));
});

test('activation status flips to pending after a change and back after activate', async () => {
  const data = fresh(); const api = C.mockApi(data);
  assert.equal((await api.request('GET', '/status')).status, 'ACTIVE');
  await C.apply(C.plan({ intent: 'BLOCK', entries: ['47.1.1.1'], atp: { enabled: true } }, data), api);
  assert.equal((await api.request('GET', '/status')).status, 'PENDING');
  await api.request('POST', '/status/activate');
  assert.equal((await api.request('GET', '/status')).status, 'ACTIVE');
});

test('warns when a catch-all rule with the opposite action sits above the new rule', () => {
  const data = fresh();
  const allowAll = data.urlFilteringRules.find((r) => r.name === 'Allow Everything Else');
  const p = C.plan({ intent: 'BLOCK', entries: ['48.1.1.1'], category: { mode: 'new', name: 'Z' }, rules: { url: { enabled: true, mode: 'new', name: 'Z-Block', placeAbove: 'BOTTOM' } } }, data);
  assert.ok(p.warnings.some((w) => w.includes(allowAll.name)));
  const p2 = C.plan({ intent: 'BLOCK', entries: ['48.1.1.1'], category: { mode: 'new', name: 'Z' }, rules: { url: { enabled: true, mode: 'new', name: 'Z-Block', placeAbove: allowAll.id } } }, data);
  assert.ok(!p2.warnings.some((w) => w.includes('never apply')));
});
