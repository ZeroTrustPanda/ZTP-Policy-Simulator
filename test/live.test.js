'use strict';
const test = require('node:test');
const assert = require('node:assert');
const live = require('../src/live');

test('device details: whitelisted fields only — one-time passwords never leave the server', () => {
  const raw = { id: '190286315', type: 4, state: 2, machineHostname: 'F99LXTG6YY', os_version: 'Version 15.6.1', unique_id: 'U-1', agent_version: '4.5.2.73',
    last_seen_time: '1759852321', devicePolicyName: 'ZTunnel2.0', tunnelVersion: '20:1', ziaEnabled: 'true', zpaEnabled: 'false', zdxEnabled: 'true',
    ziaHealth: 'Active', zpaHealth: 'Not  Applicable', zdxHealth: 'Active', deviceOtpArray: ['cx6t2c5scf', 'fnkkbwbypk'], hardwareFingerprint: 'abc' };
  const d = Object.assign(live.deviceSummary(raw), { health: live.deviceHealth(raw) });
  assert.equal(d.os, 'macOS'); assert.equal(d.profile, 'ZTunnel2.0'); assert.equal(d.udid, 'U-1'); assert.equal(d.zccVersion, '4.5.2.73');
  assert.equal(d.health.zpa.enabled, false); assert.equal(d.health.zpa.health, null); assert.equal(d.health.zia.health, 'Active');
  assert.equal(d.lastSeen, 1759852321000);
  const json = JSON.stringify(d);
  assert.ok(!/cx6t2c5scf|fnkkbwbypk|Otp|hardwareFingerprint/i.test(json), 'no OTPs or fingerprints');
  const w = live.deviceWarnings(Object.assign({}, d, { lastSeen: Date.now() }));
  assert.ok(w.some((x) => x.svc === 'ZPA' && /turned off/.test(x.text)));
  assert.ok(!w.some((x) => x.svc === 'ZIA'));
});

test('device lookup asks ZCC for the user and returns the newest first', async () => {
  const calls = [];
  const client = { get: async (p, q) => { calls.push([p, q]); return [{ udid: 'A', machineHostname: 'old', type: 3, last_seen_time: '1700000000', policyName: 'P1' }, { udid: 'B', machineHostname: 'new', type: 3, last_seen_time: '1750000000', policyName: 'P2' }]; } };
  const list = await live.listDevices(client, 'jane@acme.org');
  assert.deepEqual(calls[0], ['/zcc/papi/public/v1/getDevices', { username: 'jane@acme.org', pageSize: '50' }]);
  assert.deepEqual(list.map((d) => d.hostname), ['new', 'old']);
});

const DATA = () => ({
  zpaApps: [{ id: 'S1', name: 'PACS', serverGroups: [{ id: 'G1' }] }, { id: 'S2', name: 'Lonely', serverGroups: [] }, { id: 'S3', name: 'BA app', serverGroups: [{ id: 'G2' }], clientlessApps: [{ certificateId: 'C1' }] }],
  zpaServerGroups: [{ id: 'G1', name: 'SG1', appConnectorGroups: [{ id: 'A1', name: 'ACG1' }] }, { id: 'G2', name: 'SG2', appConnectorGroups: [{ id: 'A2', name: 'ACG2' }] }],
  zpaConnectorGroups: [{ id: 'A1', name: 'ACG1', enabled: true }, { id: 'A2', name: 'ACG2', enabled: true }],
  zpaConnectors: [
    { name: 'c1', appConnectorGroupId: 'A1', controlChannelStatus: 'ZPN_STATUS_AUTHENTICATED', lastBrokerConnectTime: '1704838712512094' },
    { name: 'c2', appConnectorGroupId: 'A1', controlChannelStatus: 'ZPN_STATUS_DISCONNECTED' },
    { name: 'c3', appConnectorGroupId: 'A2', controlChannelStatus: 'ZPN_STATUS_DISCONNECTED' }],
  zpaBaCerts: [{ id: 'C1', name: 'ba.acme.org', validToInEpochSec: String(Math.floor(Date.now() / 1000) + 5 * 86400) }],
  zpaEnrollmentCerts: [{ id: 'E1', name: 'Connector', validToInEpochSec: String(Math.floor(Date.now() / 1000) - 86400) }],
});

test('ZPA path health: degraded, down, no server group, Browser Access certificate', () => {
  const d = DATA();
  const a = live.zpaPathHealth(d, 'S1');
  assert.equal(a.status, 'degraded'); assert.equal(a.groups[0].up, 1); assert.equal(a.groups[0].total, 2);
  assert.ok(a.groups[0].connectors[0].lastConnect < Date.now() && a.groups[0].connectors[0].lastConnect > 1.7e12, 'microseconds converted');
  assert.equal(live.zpaPathHealth(d, 'S2').status, 'no-server-group');
  const c = live.zpaPathHealth(d, 'S3');
  assert.equal(c.status, 'down'); assert.equal(c.certs[0].name, 'ba.acme.org'); assert.ok(c.certs[0].days <= 5);
  d.zpaConnectors[1].controlChannelStatus = 'ZPN_STATUS_AUTHENTICATED';
  assert.equal(live.zpaPathHealth(d, 'S1').status, 'ok');
  const t = live.zpaTenantHealth(DATA());
  assert.ok(t.certs.some((x) => x.name === 'Connector' && x.days < 0));
  assert.deepEqual(t.downGroups.map((g) => g.name), ['ACG2']);
});

test('ZIA audit log: start, poll, download CSV with title lines, filter', async () => {
  const calls = [];
  let polls = 0;
  const csv = 'Audit Log Report\nGenerated,2026-10-19\n\n"Time","Admin","Action","Category","Sub-Category","Resource","Result"\n"2026-10-19 10:00:00","a@acme.org","UPDATE","Firewall Filtering","Firewall Rule","Block Telnet, legacy","SUCCESS"\n"2026-10-19 11:00:00","b@acme.org","CREATE","URL Filtering","URL Filtering Rule","Block Gambling","SUCCESS"\n';
  const client = { request: async (m, p, o = {}) => {
    calls.push([m, p, o.body ? Object.keys(o.body).join(',') : '', o.headers && o.headers.Accept]);
    if (m === 'GET' && p.endsWith('/auditlogEntryReport')) return { status: ++polls < 2 ? 'EXECUTING' : 'COMPLETE' };
    if (p.endsWith('/download')) return csv;
    return null;
  } };
  const r = await live.auditLog(client, { hours: 24, sleep: async () => {} });
  assert.deepEqual(calls[0].slice(0, 3), ['POST', '/zia/api/v1/auditlogEntryReport', 'startTime,endTime']);
  assert.match(calls[calls.length - 1][3], /text\/csv/);
  assert.deepEqual(r.columns.slice(0, 3), ['Time', 'Admin', 'Action']);
  assert.equal(r.entries.length, 2); assert.equal(r.entries[0].Resource, 'Block Telnet, legacy');
  assert.equal(live.filterAudit(r.entries, 'firewall telnet').length, 1);
  assert.equal(live.filterAudit(r.entries, '').length, 2);
});

test('ZIA audit log: an early 404 "No Report to download" keeps polling', async () => {
  let polls = 0;
  const client = { request: async (m, p) => {
    if (m === 'GET' && p.endsWith('/auditlogEntryReport')) { if (++polls < 3) throw Object.assign(new Error('HTTP 404 No Report to download'), { status: 404 }); return { status: 'COMPLETE' }; }
    if (p.endsWith('/download')) return '"Time","Admin","Action","Category","Sub-Category","Resource","Result"\n"2026-10-19 10:00:00","a","UPDATE","Firewall Filtering","Firewall Rule","X","SUCCESS"\n';
    return null;
  } };
  const r = await live.auditLog(client, { hours: 1, sleep: async () => {} });
  assert.equal(r.entries.length, 1);
});

test('simulation scopes Client Connector profiles to the looked-up device', () => {
  const { simulate } = require('../src/engine'); const M = require('../src/matchers');
  const data = require('../src/demo-snapshot.json');
  const dev = Object.assign({}, data.demoDevices['sam.kim@hospital.example'][0]);
  const r = simulate({ data }, { target: M.parseTarget('pacs.hospital.example'), port: 104, protocol: 'tcp', categories: [], resolvedIps: [], groups: [], notes: [], useZpa: true, device: Object.assign(dev, { lastSeen: Date.now() }) }, {});
  const fw = r.modules.find((m) => m.module.startsWith('Forwarding'));
  assert.deepEqual(fw.profiles.filter((p) => p.applies === 'yes').map((p) => p.name), ['Corp Windows']);
  assert.ok(r.summary.deviceWarnings.some((w) => w.svc === 'ZPA'));
  const zpa = r.modules.find((m) => m.module === 'ZPA Access Policy');
  assert.equal(zpa.pathHealth.status, 'ok');
});
