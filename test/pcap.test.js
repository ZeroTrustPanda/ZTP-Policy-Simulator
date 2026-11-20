'use strict';
// Packet capture analyzer: formats, conversations, DNS, TLS (incl. Zscaler-issued certificates), findings, robustness.
const test = require('node:test');
const assert = require('node:assert');
const P = require('./helpers/pcap-builder');
const { analyze, formatOf } = require('../src/pcap');

const C = '192.168.1.20';
function scenario() {
  const pk = [];
  // DNS: answered, NXDOMAIN, unanswered
  pk.push(P.udpPkt(C, 53001, '192.168.1.1', 53, P.dns({ id: 1, name: 'app.example.com' }), 1700000000));
  pk.push(P.udpPkt('192.168.1.1', 53, C, 53001, P.dns({ id: 1, response: true, name: 'app.example.com', answers: ['93.184.216.34'] }), 1700000000.02));
  pk.push(P.udpPkt(C, 53002, '192.168.1.1', 53, P.dns({ id: 2, name: 'missing.corp.example' }), 1700000000.03));
  pk.push(P.udpPkt('192.168.1.1', 53, C, 53002, P.dns({ id: 2, response: true, rcode: 3, name: 'missing.corp.example' }), 1700000000.05));
  pk.push(P.udpPkt(C, 53003, '192.168.1.1', 53, P.dns({ id: 3, name: 'silent.example.net' }), 1700000000.06));
  // TLS to app.example.com inspected by Zscaler, and the client rejects the certificate (pinning)
  pk.push(...P.conv(C, 50001, '93.184.216.34', 443, { clientData: [P.clientHello('app.example.com'), P.alert(48)], serverData: [P.serverFlight('Zscaler Intermediate Root CA (zscalerthree.net)', 'Zscaler Inc.', 'app.example.com')], t: 1700000001 }));
  // Client Connector tunnel to a ZIA Service Edge
  pk.push(...P.conv(C, 50002, '165.225.10.20', 443, { clientData: [P.clientHello('gateway.zscalerthree.net')], serverData: [P.serverFlight('DigiCert', 'DigiCert Inc', 'gateway.zscalerthree.net')], t: 1700000002 }));
  // SYN never answered (dropped), and one refused
  pk.push(...P.conv(C, 50003, '203.0.113.50', 3389, { synack: false, t: 1700000003 }));
  pk.push(...P.conv(C, 50004, '203.0.113.51', 22, { rstFromServer: true, t: 1700000004 }));
  // Plain HTTP and QUIC
  pk.push(...P.conv(C, 50005, '198.51.100.7', 80, { clientData: [Buffer.from('GET /x HTTP/1.1\r\nHost: plain.example.org\r\nUser-Agent: t\r\n\r\n')], serverData: [Buffer.from('HTTP/1.1 403 Forbidden\r\nServer: Zscaler/6.2\r\n\r\n')], t: 1700000005 }));
  const quic = Buffer.alloc(40, 0); quic[0] = 0xc3; quic.writeUInt32BE(1, 1);
  pk.push(P.udpPkt(C, 50006, '142.250.1.1', 443, quic, 1700000006), P.udpPkt(C, 50006, '142.250.1.1', 443, quic, 1700000006.5));
  // ZPA synthetic IP
  pk.push(...P.conv(C, 50007, '100.64.0.5', 104, { clientData: [Buffer.from('hello')], serverData: [Buffer.from('ok')], t: 1700000007 }));
  return pk;
}

test('pcap: conversations, DNS, TLS, Zscaler path and findings', () => {
  const r = analyze(P.pcap(scenario()));
  assert.equal(r.file.files[0].format, 'pcap');
  const f = (sport, server) => r.flows.find((x) => x.sport === sport && (!server || x.server === server));
  const tls = f(443, '93.184.216.34');
  assert.equal(tls.name, 'app.example.com');
  assert.equal(tls.tls.sni, 'app.example.com');
  assert.deepEqual(tls.tls.alpn, ['h2', 'http/1.1']);
  assert.equal(tls.tls.zscalerCert, true, 'certificate issued by Zscaler = SSL inspected');
  assert.equal(tls.status, 'tls-alert');
  assert.equal(tls.via, 'ZIA', 'a Zscaler-issued certificate proves it went through ZIA'); assert.match(tls.role, /SSL-inspected/);
  assert.ok(tls.rtt > 0);
  const gw = f(443, '165.225.10.20');
  assert.equal(gw.via, 'ZIA'); assert.match(gw.role, /Service Edge/);
  assert.equal(f(3389).status, 'no-answer');
  assert.equal(f(22).status, 'refused');
  const http = f(80); assert.equal(http.name, 'plain.example.org'); assert.equal(http.http.response.status, 403); assert.equal(http.http.response.zscaler, true);
  assert.equal(r.flows.find((x) => x.app === 'QUIC').proto, 'udp');
  assert.equal(f(104).via, 'ZPA');
  // DNS
  const d = (n) => r.dns.find((x) => x.name === n);
  assert.equal(d('app.example.com').status, 'ok'); assert.equal(d('app.example.com').answers[0].data, '93.184.216.34');
  assert.equal(d('missing.corp.example').rcode, 'NXDOMAIN');
  assert.equal(d('silent.example.net').status, 'no-response');
  // Findings: pinning first, with something to simulate
  const titles = r.findings.map((x) => x.title).join('\n');
  assert.match(r.findings[0].title, /rejected the server certificate \(unknown_ca\)/);
  assert.match(r.findings[0].detail, /Do Not Inspect/);
  assert.deepEqual(r.findings[0].simulate, { target: 'app.example.com', port: 443, protocol: 'tcp' });
  assert.match(titles, /203\.0\.113\.50:3389 didn't answer/);
  assert.match(titles, /refused the connection/);
  assert.match(titles, /DNS: missing\.corp\.example → NXDOMAIN/);
  assert.match(titles, /DNS: silent\.example\.net → no response/);
  assert.match(titles, /QUIC/);
  assert.match(titles, /SSL-inspected by Zscaler/);
  assert.equal(r.summary.viaZia, 3); assert.equal(r.summary.viaZpa, 1); assert.equal(http.via, 'ZIA'); assert.equal(r.summary.inspected, 1);
});

test('pcap: pcapng, nanosecond and big-endian pcap, VLAN tags, Linux cooked capture, zip bundles', () => {
  const pk = scenario();
  for (const buf of [P.pcapng(pk), P.pcap(pk, { ns: true }), P.pcap(pk, { bigEndian: true })]) {
    const r = analyze(buf);
    assert.equal(r.flows.find((x) => x.sport === 443 && x.name === 'app.example.com').tls.zscalerCert, true);
    assert.equal(r.dns.length, 3);
    assert.ok(Math.abs(r.file.first - 1700000000) < 1, `timestamps (${r.file.first})`);
  }
  const vlan = P.pcap([{ data: P.eth(P.ipv4(C, '1.1.1.1', 17, P.udp(5000, 53, P.dns({ name: 'v.example' }))), { vlan: 20 }) }]);
  assert.equal(analyze(vlan).dns[0].name, 'v.example');
  // Linux cooked (SLL): 16-byte header with the ethertype at the end
  const sllHdr = Buffer.alloc(16); sllHdr.writeUInt16BE(0x0800, 14);
  const sll = P.pcap([{ data: Buffer.concat([sllHdr, P.ipv4(C, '1.1.1.1', 17, P.udp(5000, 53, P.dns({ name: 's.example' })))]) }], { link: 113 });
  assert.equal(analyze(sll).dns[0].name, 's.example');
  // Raw IP (e.g. captured on the Zscaler tunnel adapter)
  const raw = P.pcap([{ data: P.ipv4(C, '1.1.1.1', 17, P.udp(5000, 53, P.dns({ name: 'r.example' }))) }], { link: 101 });
  assert.equal(analyze(raw).dns[0].name, 'r.example');
  // A ZCC-style bundle: zip with a capture inside, plus files that aren't captures
  const z = P.zip([{ name: 'logs/ZSATunnel.log', data: Buffer.from('not a capture') }, { name: 'capture/ZCC_capture.pcapng', data: P.pcapng(pk) }]);
  assert.equal(formatOf(z), 'zip');
  const rz = analyze(z);
  assert.deepEqual(rz.file.files.map((x) => x.name), ['capture/ZCC_capture.pcapng']);
  assert.equal(rz.dns.length, 3);
});

test('pcap: rejects non-captures and survives damaged files', () => {
  assert.throws(() => analyze(Buffer.from('hello world, definitely not a capture file')), /Not a packet capture/);
  assert.throws(() => analyze(P.zip([{ name: 'readme.txt', data: Buffer.from('x') }])), /no \.pcap/);
  const good = P.pcap(scenario());
  // truncated at every 7th byte: never throws, never loops
  for (let n = 24; n < good.length; n += 7) analyze(good.subarray(0, n));
  // random corruption of packet bytes (fixed seed)
  let seed = 42; const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  for (let k = 0; k < 300; k++) {
    const b = Buffer.from(good);
    for (let j = 0; j < 20; j++) b[24 + Math.floor(rnd() * (b.length - 24))] = Math.floor(rnd() * 256);
    analyze(b);
    const ng = P.pcapng(scenario()); for (let j = 0; j < 20; j++) ng[28 + Math.floor(rnd() * (ng.length - 28))] = Math.floor(rnd() * 256);
    try { analyze(ng); } catch (e) { assert.match(e.message, /pcapng|capture/); }
  }
});

test('pcap: retransmissions and direct-vs-Zscaler finding', () => {
  const pk = P.conv(C, 51000, '93.184.216.40', 443, { clientData: [P.clientHello('slow.example.com')], serverData: [P.serverFlight('R3', "Let's Encrypt", 'slow.example.com')] });
  const last = pk[pk.length - 1];
  for (let i = 0; i < 30; i++) pk.push({ t: 1700000100 + i, data: last.data }); // same segment over and over
  pk.push(...P.conv(C, 51001, '165.225.1.1', 443, { clientData: [P.clientHello('gateway.zscaler.net')], t: 1700000200 }));
  const r = analyze(P.pcap(pk));
  const slow = r.flows.find((x) => x.name === 'slow.example.com');
  assert.equal(slow.retrans, 30);
  assert.equal(slow.tls.zscalerCert, false);
  assert.ok(r.findings.some((x) => /retransmitted/.test(x.title)));
  assert.ok(r.findings.some((x) => /went direct while others used Zscaler/.test(x.title)));
});
