'use strict';
// ZCC Log Explorer tests (from github.com/alexbnn/zcc-log-explorer), ported to CommonJS.
// Tests use synthetic lines shaped like real ZSATunnel output (no customer data).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { zip } = require('./helpers/pcap-builder');
// Same shape as fflate's zipSync({name: bytes}) used by the original tests
const zipSync = (o) => zip(Object.entries(o).map(([name, data]) => ({ name, data: Buffer.from(data) })));
const strToU8 = (s) => Buffer.from(s);
const { buildTimeline, classifyFile, expandUpload } = require('../src/zcc/parser');
const { analyzeZpa, matchSegment, summarizeApps, formatRanges } = require('../src/zcc/zpa');

const H = (t, lvl, msg) => `2026-10-14 ${t}(-0400)[100:200] ${lvl} ${msg}`;
const app = (domain, ports, hasNext, extra = '') =>
  H('10:00:01.000100', 'INF', `ZPN:0: Control Message Response Data: {"zpn_client_app":{"app_domain":"${domain}","bypass":0,"bypass_on_reauth":0,"bypass_type":"NEVER","deleted":0,"double_encrypt":0,"has_next":${hasNext},"icmp_access_type":"NONE","tcp_port_ranges":${ports},"udp_port_ranges":[]${extra}}}`);

const TUNNEL = [
  'Redirected stderr',
  H('10:00:00.000001', 'DBG', 'ZApp Status: getCurrentNetworkType:TRUSTED getSmeProxyState: OFF getZpnProxyState:CONNECTING getZpnAuthState:AUTHENTICATED broker:1.1.1.1 protocol:TLS type:User Tunnel'),
  H('10:00:00.500000', 'INF', 'ZPN:0: Control Message Response Data: {"zpn_client_authenticate_ack":{"broker_type":1,"current_broker":"broker1.example.net","pub_ip":"203.0.113.9","tunnel_id":"T1"}}'),
  app('.corp.example', '[1,65535]', 1),
  app('10.0.0.0/8', '[443,443]', 1),
  app('db.corp.example', '[5432,5432]', 0),
  H('10:00:01.000200', 'INF', 'ZPN:0: Control Message Response Data: {"zpn_client_app_complete":{}}'),
  H('10:00:02.000000', 'DBG', 'ZApp Status: getCurrentNetworkType:TRUSTED getSmeProxyState: OFF getZpnProxyState:TUNNEL_FORWARDING getZpnAuthState:AUTHENTICATED broker:1.1.1.1 protocol:TLS type:User Tunnel'),
  // OK mtunnel, closed by connector
  H('10:00:03.000000', 'DBG', 'Writing Mtunnel request: Size: 1 Data: { "zpn_mtunnel_request": { "app_name": "web.corp.example", "app_type": "name", "double_encrypt": 0, "ip_protocol": 6, "o_dip": "100.64.1.1", "o_sport": 5000, "server_port": 443, "tag_id": 1 } }'),
  H('10:00:03.050000', 'INF', 'ZPN:0: Control Message Response Data: {"zpn_mtunnel_request_ack":{"err_code":1,"mtunnel_id":"T1,a","tag_id":1}}'),
  H('10:00:09.000000', 'INF', 'ZPN:0: Control Message Response Data: {"zpn_mtunnel_end":{"drop_data":1,"err_code":4001,"error":"BRK_MT_CLOSED_FROM_ASSISTANT","tag_id":1}}'),
  // Policy failure
  H('10:00:04.000000', 'DBG', 'Writing Mtunnel request: Size: 1 Data: { "zpn_mtunnel_request": { "app_name": "db.corp.example", "app_type": "name", "double_encrypt": 0, "ip_protocol": 6, "o_dip": "100.64.1.2", "o_sport": 5001, "server_port": 5432, "tag_id": 2 } }'),
  H('10:00:04.020000', 'INF', 'ZPN:0: Control Message Response Data: {"zpn_mtunnel_request_ack":{"err_code":5011,"error":"BRK_MT_SETUP_FAIL_NO_POLICY_FOUND","tag_id":2}}'),
  // Legacy request shape, unreachable
  H('10:00:05.000000', 'DBG', 'Writing Mtunnel request: Size: 1 Data: { "zpn_mtunnel_request": { "app_name": "10.1.2.3", "app_type": "ip", "o_dip": "10.1.2.3", "tag_id": 3, "tcp_server_port": 443 } }'),
  H('10:00:05.100000', 'INF', 'ZPN:0: Control Message Response Data: {"zpn_mtunnel_end":{"drop_data":1,"err_code":4002,"error":"APP_NOT_REACHABLE","tag_id":3}}'),
  // Incremental update changes ports on one domain
  app('db.corp.example', '[5432,5433]', 0),
  H('10:00:07.000000', 'DBG', 'Ignored response of XPC request: XPC Request {\n    zpn = 4;\n}'),
].join('\n');

function load() {
  return buildTimeline([{ name: 'ZSATunnel_2026-10-14-14-00-00.000000.log', text: TUNNEL }]);
}

test('classifies ZCC file names', () => {
  assert.equal(classifyFile('ZSATunnel_2026-10-14-18-20-30.382951.log'), 'Tunnel');
  assert.equal(classifyFile('ZSAService_2026-10-12-19-46-43.506185.log'), 'Service');
  assert.equal(classifyFile('ZSAUpm_ZWebload_2026-10-14-12-25-53.592328.log'), 'UPM/ZWebload');
});

test('parses headers, offsets, preamble and multi-line entries', () => {
  const tl = load();
  assert.equal(tl.msg(0), 'Redirected stderr');
  assert.equal(tl.tzText(0), '-0400'); // preamble inherits the first real line's offset
  assert.equal(tl.time(1), '2026-10-14 10:00:00.000001');
  // ZCC writes the UTC clock with a local-offset label, so the clock is read as UTC.
  assert.equal(tl.ts[1], Date.UTC(2026, 9, 14, 10, 0, 0) + 0.001);
  const multi = [...Array(tl.length).keys()].find((i) => tl.msg(i).startsWith('Ignored response'));
  assert.ok(tl.isMulti(multi));
  assert.ok(tl.msg(multi).endsWith('}'));
  assert.ok(tl.isNoise(multi));
});

test('builds app segments from full download plus incremental updates', () => {
  const z = analyzeZpa(load());
  assert.deepEqual(z.segments.map((s) => s.domain), ['.corp.example', '10.0.0.0/8', 'db.corp.example']);
  const db = z.segments.find((s) => s.domain === 'db.corp.example');
  assert.equal(db.tcpText, '5432-5433');
  assert.equal(z.segmentBatches.filter((b) => b.complete).length, 1);
  assert.equal(z.segmentBatches.filter((b) => !b.complete).length, 1);
  assert.match(z.segmentHistory['db.corp.example'][1].change, /^changed: TCP 5432 → 5432-5433/);
});

test('tracks mtunnel outcomes, including the legacy request format', () => {
  const z = analyzeZpa(load());
  const byTag = Object.fromEntries(z.mtunnels.map((m) => [m.tag, m]));
  assert.equal(byTag[1].status, 'closed');
  assert.equal(byTag[1].segment, '.corp.example');
  assert.equal(byTag[2].status, 'failed');
  assert.equal(byTag[2].reason, 'BRK_MT_SETUP_FAIL_NO_POLICY_FOUND');
  assert.equal(byTag[2].segment, 'db.corp.example'); // exact FQDN beats wildcard
  assert.equal(byTag[3].status, 'failed');
  assert.equal(byTag[3].proto, 'TCP');
  assert.equal(byTag[3].port, 443);
  assert.equal(byTag[3].segment, '10.0.0.0/8');
  const apps = summarizeApps(z);
  assert.equal(apps.find((a) => a.app === 'db.corp.example').topReason, 'BRK_MT_SETUP_FAIL_NO_POLICY_FOUND');
  assert.equal(z.zpnErrors.find((e) => e.code === 'APP_NOT_REACHABLE').category, 'connector');
});

test('records sessions and state transitions', () => {
  const z = analyzeZpa(load());
  assert.equal(z.sessions.length, 1);
  assert.equal(z.sessions[0].broker, 'broker1.example.net');
  assert.equal(z.states.length, 2);
  assert.equal(z.info.lastState.zpn, 'TUNNEL_FORWARDING');
});

test('segment matching respects specificity and ports', () => {
  const segs = analyzeZpa(load()).segments;
  assert.deepEqual(matchSegment(segs, 'db.corp.example', 5432, 6), { domain: 'db.corp.example', portOk: true });
  assert.deepEqual(matchSegment(segs, 'x.corp.example', 22, 6), { domain: '.corp.example', portOk: true });
  assert.deepEqual(matchSegment(segs, '10.9.9.9', 22, 6), { domain: '10.0.0.0/8', portOk: false });
  assert.equal(matchSegment(segs, 'example.org', 443, 6), null);
  assert.equal(formatRanges([1, 65535]), 'all');
});

test('expands nested zip bundles and skips UPM by default', () => {
  const inner = zipSync({ 'ZSATunnel_2026-10-14-14-00-00.000000.log': strToU8(TUNNEL) });
  const outer = zipSync({
    'logs/ZSATunnel_2026-10-14-14-00-00.000000.log.zip': inner,
    'logs/ZSAUpm_ZWebload_2026-10-14-12-25-53.592328.log': strToU8('x'),
    '__MACOSX/._junk': strToU8('x'),
  });
  const files = expandUpload('bundle.zip', outer);
  assert.deepEqual(files.map((f) => f.name), ['ZSATunnel_2026-10-14-14-00-00.000000.log']);
  assert.equal(expandUpload('bundle.zip', outer, { includeUpm: true }).length, 2);
});
