'use strict';
// Builds small synthetic packet captures for the analyzer tests (no real traffic, no customer data).
const zlib = require('zlib');

const ipb = (s) => Buffer.from(s.split('.').map(Number));
function csum(buf) { let s = 0; for (let i = 0; i + 1 < buf.length; i += 2) s += buf.readUInt16BE(i); if (buf.length % 2) s += buf[buf.length - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16); return ~s & 0xffff; }
function ipv4(src, dst, proto, payload) {
  const h = Buffer.alloc(20); h[0] = 0x45; h.writeUInt16BE(20 + payload.length, 2); h[8] = 64; h[9] = proto; ipb(src).copy(h, 12); ipb(dst).copy(h, 16); h.writeUInt16BE(csum(h), 10);
  return Buffer.concat([h, payload]);
}
function tcp(sp, dp, { seq = 1, ack = 0, flags = 'A', win = 65535, data = Buffer.alloc(0) } = {}) {
  const h = Buffer.alloc(20); h.writeUInt16BE(sp, 0); h.writeUInt16BE(dp, 2); h.writeUInt32BE(seq >>> 0, 4); h.writeUInt32BE(ack >>> 0, 8); h[12] = 5 << 4;
  let f = 0; for (const c of flags) f |= { F: 1, S: 2, R: 4, P: 8, A: 16 }[c] || 0; h[13] = f; h.writeUInt16BE(win, 14);
  return Buffer.concat([h, data]);
}
function udp(sp, dp, data) { const h = Buffer.alloc(8); h.writeUInt16BE(sp, 0); h.writeUInt16BE(dp, 2); h.writeUInt16BE(8 + data.length, 4); return Buffer.concat([h, data]); }
function eth(ipPacket, { vlan } = {}) {
  const mac = Buffer.from('020000000001020000000002', 'hex');
  const tag = vlan ? Buffer.from([0x81, 0x00, 0, vlan, 0x08, 0x00]) : Buffer.from([0x08, 0x00]);
  return Buffer.concat([mac, tag, ipPacket]);
}
function dnsName(n) { return Buffer.concat([...n.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]); }
function dns({ id = 1, response = false, rcode = 0, name, type = 1, answers = [] }) {
  const h = Buffer.alloc(12); h.writeUInt16BE(id, 0); h.writeUInt16BE((response ? 0x8180 : 0x0100) | rcode, 2); h.writeUInt16BE(1, 4); h.writeUInt16BE(answers.length, 6);
  const q = Buffer.concat([dnsName(name), Buffer.from([0, type, 0, 1])]);
  const an = answers.map((ip) => { const r = Buffer.alloc(16); r.writeUInt16BE(0xc00c, 0); r.writeUInt16BE(1, 2); r.writeUInt16BE(1, 4); r.writeUInt32BE(300, 6); r.writeUInt16BE(4, 10); ipb(ip).copy(r, 12); return r; });
  return Buffer.concat([h, q, ...an]);
}
// DER helpers for a tiny certificate (issuer / subject only matter)
const der = (tag, body) => { const l = body.length; const len = l < 128 ? Buffer.from([l]) : l < 256 ? Buffer.from([0x81, l]) : Buffer.from([0x82, l >> 8, l & 255]); return Buffer.concat([Buffer.from([tag]), len, body]); };
const name = (cn, o) => der(0x30, Buffer.concat([
  der(0x31, der(0x30, Buffer.concat([der(0x06, Buffer.from('55040a', 'hex')), der(0x0c, Buffer.from(o))]))),
  der(0x31, der(0x30, Buffer.concat([der(0x06, Buffer.from('550403', 'hex')), der(0x0c, Buffer.from(cn))]))),
]));
function cert(issuerCN, issuerO, subjectCN) {
  const tbs = der(0x30, Buffer.concat([der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([1])), der(0x30, der(0x06, Buffer.from('2a864886f70d01010b', 'hex'))),
    name(issuerCN, issuerO), der(0x30, Buffer.alloc(0)), name(subjectCN, 'Example')]));
  return der(0x30, Buffer.concat([tbs, der(0x30, Buffer.alloc(0)), der(0x03, Buffer.from([0]))]));
}
const u24 = (n) => Buffer.from([n >> 16, (n >> 8) & 255, n & 255]);
const hs = (type, body) => Buffer.concat([Buffer.from([type]), u24(body.length), body]);
const rec = (ct, body) => Buffer.concat([Buffer.from([ct, 3, 3, body.length >> 8, body.length & 255]), body]);
function clientHello(sni, { alpn = ['h2', 'http/1.1'] } = {}) {
  const s = Buffer.from(sni);
  const sniExt = Buffer.concat([Buffer.from([0, 0]), u16(s.length + 5), u16(s.length + 3), Buffer.from([0]), u16(s.length), s]);
  const al = Buffer.concat(alpn.map((a) => Buffer.concat([Buffer.from([a.length]), Buffer.from(a)])));
  const alpnExt = Buffer.concat([Buffer.from([0, 16]), u16(al.length + 2), u16(al.length), al]);
  const ver = Buffer.concat([Buffer.from([0, 43]), u16(5), Buffer.from([4, 3, 4, 3, 3])]);
  const exts = Buffer.concat([sniExt, alpnExt, ver]);
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, 7), Buffer.from([0]), u16(2), Buffer.from([0x13, 0x01]), Buffer.from([1, 0]), u16(exts.length), exts]);
  return rec(22, hs(1, body));
}
function u16(n) { return Buffer.from([n >> 8, n & 255]); }
function serverFlight(issuerCN, issuerO, subjectCN) {
  const sh = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, 9), Buffer.from([0]), Buffer.from([0xc0, 0x2f]), Buffer.from([0]), u16(0)]);
  const c = cert(issuerCN, issuerO, subjectCN);
  const certMsg = Buffer.concat([u24(c.length + 3), u24(c.length), c]);
  return rec(22, Buffer.concat([hs(2, sh), hs(11, certMsg), hs(14, Buffer.alloc(0))]));
}
const alert = (desc) => rec(21, Buffer.from([2, desc]));

// Writers
function pcap(packets, { link = 1, ns = false, bigEndian = false } = {}) {
  const w32 = (b, v, o) => (bigEndian ? b.writeUInt32BE(v >>> 0, o) : b.writeUInt32LE(v >>> 0, o));
  const w16 = (b, v, o) => (bigEndian ? b.writeUInt16BE(v, o) : b.writeUInt16LE(v, o));
  const h = Buffer.alloc(24); w32(h, ns ? 0xa1b23c4d : 0xa1b2c3d4, 0); w16(h, 2, 4); w16(h, 4, 6); w32(h, 262144, 16); w32(h, link, 20);
  const parts = [h];
  packets.forEach((p, i) => { const r = Buffer.alloc(16); const t = p.t != null ? p.t : 1700000000 + i * 0.01; w32(r, Math.floor(t), 0); w32(r, Math.round((t % 1) * (ns ? 1e9 : 1e6)), 4); w32(r, p.data.length, 8); w32(r, p.orig || p.data.length, 12); parts.push(r, p.data); });
  return Buffer.concat(parts);
}
function pcapng(packets, { link = 1 } = {}) {
  const block = (type, body) => { const pad = (4 - (body.length % 4)) % 4; const len = 12 + body.length + pad; const b = Buffer.alloc(len); b.writeUInt32LE(type, 0); b.writeUInt32LE(len, 4); body.copy(b, 8); b.writeUInt32LE(len, len - 4); return b; };
  const shb = Buffer.alloc(16); shb.writeUInt32LE(0x1a2b3c4d, 0); shb.writeUInt16LE(1, 4); shb.writeBigInt64LE(-1n, 8);
  const idb = Buffer.alloc(8); idb.writeUInt16LE(link, 0); idb.writeUInt32LE(262144, 4);
  const out = [block(0x0a0d0d0a, shb), block(1, idb)];
  packets.forEach((p, i) => {
    const us = BigInt(Math.round((p.t != null ? p.t : 1700000000 + i * 0.01) * 1e6));
    const pad = (4 - (p.data.length % 4)) % 4; const b = Buffer.alloc(20 + p.data.length + pad);
    b.writeUInt32LE(0, 0); b.writeUInt32LE(Number(us >> 32n), 4); b.writeUInt32LE(Number(us & 0xffffffffn), 8); b.writeUInt32LE(p.data.length, 12); b.writeUInt32LE(p.data.length, 16); p.data.copy(b, 20);
    out.push(block(6, b));
  });
  return Buffer.concat(out);
}
function zip(files) {
  const locals = [], centrals = []; let off = 0;
  for (const f of files) {
    const nm = Buffer.from(f.name), data = zlib.deflateRawSync(f.data);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(nm.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, nm, data); centrals.push(ch, nm); off += 30 + nm.length + data.length;
  }
  const cd = Buffer.concat(centrals); const e = Buffer.alloc(22); e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(files.length, 8); e.writeUInt16LE(files.length, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, e]);
}

// A TCP conversation helper: handshake, client data, server data, optional extra packets
function conv(c, cp, s, sp, { clientData = [], serverData = [], synack = true, rstFromServer = false, t = 1700000000 } = {}) {
  const P = []; let cs = 1000, ss = 5000; let tt = t;
  const add = (from, seg) => P.push({ t: (tt += 0.01), data: eth(ipv4(from === 'c' ? c : s, from === 'c' ? s : c, 6, seg)) });
  add('c', tcp(cp, sp, { seq: cs, flags: 'S' }));
  if (rstFromServer) { add('s', tcp(sp, cp, { seq: 0, ack: cs + 1, flags: 'RA' })); return P; }
  if (!synack) return P;
  add('s', tcp(sp, cp, { seq: ss, ack: cs + 1, flags: 'SA' })); cs++; ss++;
  add('c', tcp(cp, sp, { seq: cs, ack: ss, flags: 'A' }));
  for (let i = 0; i < Math.max(clientData.length, serverData.length); i++) {
    if (clientData[i]) { add('c', tcp(cp, sp, { seq: cs, ack: ss, flags: 'PA', data: clientData[i] })); cs += clientData[i].length; }
    if (serverData[i]) { add('s', tcp(sp, cp, { seq: ss, ack: cs, flags: 'PA', data: serverData[i] })); ss += serverData[i].length; }
  }
  return P;
}
const udpPkt = (src, sp, dst, dp, data, t) => ({ t, data: eth(ipv4(src, dst, 17, udp(sp, dp, data))) });

module.exports = { ipv4, tcp, udp, eth, dns, clientHello, serverFlight, alert, pcap, pcapng, zip, conv, udpPkt, rec };
