'use strict';
// The toolkit's offline tools through the real HTTP server: ZCC Log Explorer (mounted at /zcc), packet capture and PAC.
const test = require('node:test');
const assert = require('node:assert');
const P = require('./helpers/pcap-builder');

process.env.PORT = '0'; process.env.NO_OPEN = '1'; process.env.NO_UPDATE_CHECK = '1'; process.env.HOST = '127.0.0.1';
const app = require('../server');
const base = () => `http://127.0.0.1:${app.server.address().port}`;
const ready = new Promise((r) => (app.server.listening ? r() : app.server.once('listening', r)));
test.after(() => { app.server.close(); require('../src/pac').stopWorker(); });

test('toolkit: ZCC Log Explorer API is mounted at /zcc and its UI is served', async () => {
  await ready;
  const j = (r) => r.json();
  const ds = await fetch(base() + '/zcc/api/datasets', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'bundle.zip' }) }).then(j);
  assert.match(ds.id, /^[0-9a-f]{8}$/);
  const H = (t, l, m) => `2026-10-14 ${t}(-0400)[100:200] ${l} ${m}`;
  const log = [H('10:00:00.000001', 'INF', 'Changing ZIA state from: CONNECTING to TUNNEL_FORWARDING'), H('10:00:01.000001', 'ERR', 'something failed')].join('\n');
  const bundle = P.zip([{ name: 'logs/ZSATunnel_2026-10-14-14-00-00.000000.log', data: Buffer.from(log) }]);
  const up = await fetch(`${base()}/zcc/api/datasets/${ds.id}/files`, { method: 'POST', headers: { 'x-filename': 'bundle.zip' }, body: bundle }).then(j);
  assert.deepEqual(up.extracted, ['ZSATunnel_2026-10-14-14-00-00.000000.log']);
  const sum = await fetch(`${base()}/zcc/api/datasets/${ds.id}/finalize`, { method: 'POST' }).then(j);
  assert.equal(sum.entries, 2);
  const ent = await fetch(`${base()}/zcc/api/datasets/${ds.id}/entries?levels=ERR`).then(j);
  assert.equal(ent.total, 1);
  const html = await fetch(base() + '/zcc/').then((r) => r.text());
  assert.match(html, /toolkit\.css/);
  assert.equal((await fetch(base() + '/zcc/api/nope')).status, 404);
  const home = await fetch(base() + '/').then((r) => r.text());
  for (const t of ['Policy Simulator', 'ZCC Log Explorer', 'Packet Capture Analyzer', 'PAC Analyzer']) assert.ok(home.includes(`<div class="hc-title">${t}</div>`), t);
});

test('toolkit: packet capture and PAC endpoints need no session', async () => {
  await ready;
  const cap = P.pcap(P.conv('192.168.1.5', 50000, '203.0.113.9', 3389, { synack: false }));
  const r = await fetch(base() + '/api/pcap/analyze', { method: 'POST', headers: { 'content-type': 'application/octet-stream', 'x-filename': encodeURIComponent('my capture.pcap') }, body: cap }).then((x) => x.json());
  assert.equal(r.file.name, 'my capture.pcap');
  assert.equal(r.flows[0].status, 'no-answer');
  const bad = await fetch(base() + '/api/pcap/analyze', { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: 'nope, not a capture file at all' });
  assert.equal(bad.status, 400);
  const pac = 'function FindProxyForURL(url, host) { if (dnsDomainIs(host, ".corp.example")) return "DIRECT"; return "PROXY ${GATEWAY}:80"; }';
  const a = await fetch(base() + '/api/pac/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: pac }) }).then((x) => x.json());
  assert.ok(a.behaviour.findings.some((f) => /Private addresses/.test(f.title)));
  const t = await fetch(base() + '/api/pac/test', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: pac, urls: ['https://a.corp.example/path?q=1', 'https://example.net:8443/x', 'http://plain.example/p'], realDns: false }) }).then((x) => x.json());
  assert.deepEqual(t.results.map((x) => [x.url, x.verdict, x.line]), [['https://a.corp.example/', 'DIRECT', 1], ['https://example.net:8443/', 'ZSCALER', 1], ['http://plain.example/p', 'ZSCALER', 1]]);
  const tenant = await fetch(base() + '/api/pac/tenant?sessionId=none').then((x) => x.json());
  assert.deepEqual(tenant, { pacs: [] });
  assert.equal((await fetch(base() + '/api/pac/fetch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'file:///etc/passwd' }) })).status, 400);
});
