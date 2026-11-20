'use strict';
// ZCC Log Explorer tests (from github.com/alexbnn/zcc-log-explorer), ported to CommonJS.
// Synthetic ZSATunnel lines shaped like real ZIA output (no customer data).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildTimeline } = require('../src/zcc/parser');
const { analyzeZia, summarizeHosts } = require('../src/zcc/zia');

const H = (t, lvl, msg) => `2026-10-14 ${t}(-0400)[100:200] ${lvl} ${msg}`;
const LINES = [
  H('10:00:00.000000', 'INF', 'Changing ZIA state from: OFF to CONNECTING'),
  H('10:00:00.100000', 'DBG', 'refreshSMEIpFromPac: Proxy List (pacRequestType= 1): {IP: [198.51.100.1] Port: [443] SNISuffix: [example.net]}, {IP: [198.51.100.2] Port: [443] SNISuffix: [example.net]}, '),
  H('10:00:00.200000', 'INF', 'Changing ZIA state from: CONNECTING to ON'),
  H('10:00:00.200100', 'INF', 'TET:ZIA_T2: established'),
  H('10:00:00.300000', 'INF', 'Updating forwarding profile to: (TUNNEL) {"primaryTransport":"DTLS","allowTLSFallback":1,"other":2}'),
  // Z-Tunnel 2.0 flow, ok
  H('10:00:01.000000', 'INF', '===> ID=11, TUN-Proxy: connection to 203.0.113.5 sock-fd=1, src_port=5000, dst_port=443, localAddr: 100.64.0.1:9000'),
  H('10:00:01.000100', 'DBG', 'ID=11, HTTPS, SNI-Host=example.org'),
  H('10:00:01.000200', 'DBG', 'ID=11, PAC Parse Action: Proxy: 198.51.100.1'),
  H('10:00:01.000300', 'DBG', 'ID=11, Forwarding connection for 203.0.113.5:443 to packet modifier'),
  H('10:00:02.000000', 'ERR', 'Unexpected exception (TcpConnection run for ID: 11): Application exception: Both client and server sockets are closed!'),
  H('10:00:02.000100', 'INF', '===> ID=11, ~ZTCPServerConnection state=closed ServerConnections=1 clt_bytes=1000, srv_bytes=5000!'),
  // Gateway CONNECT flow with a 403
  H('10:00:03.000000', 'INF', '===> ID=12, LCL-Proxy: connection from 127.0.0.1:5001 sock-fd=2 localAddr: 127.0.0.1:9000'),
  H('10:00:03.000100', 'INF', 'ID=12, HTTP Request Version: HTTP/1.1 Host=blocked.example:443 Method=CONNECT Uri=blocked.example:443'),
  H('10:00:03.000200', 'INF', 'ID=12, Tunnel to SME for host=blocked.example:443, SME IP=198.51.100.1:443'),
  H('10:00:03.100000', 'DBG', 'ID=12, SME response: Version: HTTP/1.1 Status: 407 Reason: Unauthorized'),
  H('10:00:03.200000', 'DBG', 'ID=12, SME response: Version: HTTP/1.1 Status: 403 Reason: Forbidden'),
  H('10:00:03.300000', 'INF', '===> ID=12, ~ZTCPServerConnection state=closed ServerConnections=1 clt_bytes=200, srv_bytes=100!'),
  // ZDX probe handed to ZPA: excluded
  H('10:00:04.000000', 'INF', '===> ID=13, LCL-Proxy: connection from 127.0.0.1:5002 sock-fd=3 localAddr: 127.0.0.1:9000'),
  H('10:00:04.000100', 'DBG', 'ID=13, Offloading ZDX request to Zpn!!'),
  H('10:00:04.000200', 'INF', '===> ID=13, ~ZTCPServerConnection state=closed ServerConnections=0 clt_bytes=528, srv_bytes=0!'),
  // Direct flow with no response
  H('10:00:05.000000', 'INF', '===> ID=14, TUN-Proxy: connection to 203.0.113.9 sock-fd=4, src_port=5003, dst_port=443, localAddr: 100.64.0.1:9000'),
  H('10:00:05.000100', 'DBG', 'ID=14, readFromClient: Host Address: slow.example:443'),
  H('10:00:05.000200', 'DBG', 'ID=14, PAC Parse Action: Direct'),
  H('10:00:09.000000', 'INF', '===> ID=14, ~ZTCPServerConnection state=closed ServerConnections=1 clt_bytes=300, srv_bytes=0!'),
  H('10:00:10.000000', 'INF', 'checkTunTcpEchoServerUpImpl: Connecting to 100.64.0.6:80 for ZIA health check (address family = IPv4)'),
  H('10:00:10.100000', 'ERR', 'Error connecting to tcp echo server. Select Error: 36, sel_res=0'),
  H('10:00:11.000000', 'INF', 'Changing ZIA state from: ON to OFF'),
].join('\n');

const tl = buildTimeline([{ name: 'ZSATunnel_2026-10-14-14-00-00.000000.log', text: LINES }]);
const z = analyzeZia(tl);

test('tracks ZIA state, gateways, tunnel events and profile', () => {
  assert.deepEqual(z.stateChanges.map((s) => s.to), ['CONNECTING', 'ON', 'OFF']);
  assert.equal(z.info.state, 'OFF');
  assert.deepEqual(z.info.gateways.map((g) => g.ip), ['198.51.100.1', '198.51.100.2']);
  assert.deepEqual(z.info.profile.settings, { primaryTransport: 'DTLS', allowTLSFallback: 1 });
  assert.ok(z.events.some((e) => e.detail === 'Z-Tunnel 2.0 established'));
  assert.deepEqual(z.health.ZIA, { ok: 0, failed: 1, lastOk: null, lastFail: z.healthChecks[0].ts });
});

test('classifies connections by path and outcome', () => {
  const by = Object.fromEntries(z.flows.map((f) => [f.cid, f]));
  assert.equal(by[13], undefined, 'ZDX probe offloaded to ZPA is excluded');
  assert.equal(by[11].host, 'example.org');
  assert.equal(by[11].path, 'zt2');
  assert.equal(by[11].status, 'ok'); // the "Both ... sockets are closed" exception is a normal close
  assert.equal(by[12].path, 'gateway');
  assert.equal(by[12].status, 'failed');
  assert.equal(by[12].reason, 'HTTP 403 Forbidden from gateway');
  assert.equal(by[12].host, 'blocked.example');
  assert.equal(by[14].path, 'direct');
  assert.equal(by[14].reason, 'no response (0 bytes received)');
  const hosts = summarizeHosts(z);
  assert.equal(hosts.find((h) => h.host === 'example.org').bytesDown, 5000);
  assert.equal(z.info.gateways.find((g) => g.ip === '198.51.100.1').flows, 2);
});
