'use strict';
// Packet capture analyzer: reads .pcap / .pcapng (or a .zip such as a Client Connector log bundle that contains them)
// entirely in memory, rebuilds conversations and reports what matters for Zscaler troubleshooting:
// DNS answers and failures, TCP connects/resets/retransmits, TLS server names, alerts and whether a certificate was
// issued by Zscaler (SSL inspection), HTTP requests, QUIC, and which traffic went through Zscaler (ZIA/ZPA) or direct.
// Every length is bounds-checked: capture files are untrusted input.
const { readZip } = require('./zip');

const LIMITS = { packets: 3000000, flows: 200000, streamBytes: 65536, zipTotal: 600 * 1024 * 1024, perFlowSegs: 4000 };

// ---------- container formats ----------
function* pcapPackets(buf) {
  const m = buf.readUInt32LE(0);
  let le, ns;
  if (m === 0xa1b2c3d4) { le = true; ns = false; } else if (m === 0xd4c3b2a1) { le = false; ns = false; } else if (m === 0xa1b23c4d) { le = true; ns = true; } else if (m === 0x4d3cb2a1) { le = false; ns = true; } else throw new Error('not a pcap file');
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const link = u32(20) & 0x0fffffff;
  let o = 24;
  while (o + 16 <= buf.length) {
    const sec = u32(o), frac = u32(o + 4), incl = u32(o + 8), orig = u32(o + 12);
    o += 16;
    if (incl > buf.length - o || incl > 262144 * 4) break; // truncated / corrupt file
    yield { ts: sec + frac / (ns ? 1e9 : 1e6), link, data: buf.subarray(o, o + incl), orig };
    o += incl;
  }
}
function* pcapngPackets(buf) {
  let o = 0, le = true;
  let ifaces = [];
  const u16 = (p) => (le ? buf.readUInt16LE(p) : buf.readUInt16BE(p));
  const u32 = (p) => (le ? buf.readUInt32LE(p) : buf.readUInt32BE(p));
  while (o + 12 <= buf.length) {
    let type = buf.readUInt32LE(o);
    if (type === 0x0a0d0d0a) { // Section Header: byte order decides the rest of the section
      const bom = buf.readUInt32LE(o + 8);
      le = bom === 0x1a2b3c4d; if (!le && buf.readUInt32BE(o + 8) !== 0x1a2b3c4d) throw new Error('bad pcapng byte-order magic');
      ifaces = [];
    } else type = u32(o);
    const len = u32(o + 4);
    if (len < 12 || len % 4 || o + len > buf.length) break;
    const b = o + 8;
    if (type === 1) { // Interface Description
      const iface = { link: u16(b), snap: u32(b + 4), res: 1e-6 };
      let p = b + 8;
      while (p + 4 <= o + len - 4) { const code = u16(p), olen = u16(p + 2); if (code === 0) break; if (code === 9 && olen >= 1) { const v = buf[p + 4]; iface.res = v & 0x80 ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v); } p += 4 + olen + ((4 - (olen % 4)) % 4); }
      ifaces.push(iface);
    } else if (type === 6 || type === 2) { // Enhanced / obsolete Packet Block
      const id = type === 6 ? u32(b) : u16(b);
      const hi = u32(b + 4), lo = u32(b + 8), cap = u32(b + 12), orig = u32(b + 16);
      const iface = ifaces[id] || { link: 1, res: 1e-6 };
      if (cap <= len - 32) yield { ts: (hi * 4294967296 + lo) * iface.res, link: iface.link, data: buf.subarray(b + 20, b + 20 + cap), orig };
    } else if (type === 3) { // Simple Packet Block (interface 0, no timestamp)
      const iface = ifaces[0] || { link: 1, snap: 0 };
      const orig = u32(b); const cap = Math.min(orig, len - 16, iface.snap || Infinity);
      yield { ts: 0, link: iface.link, data: buf.subarray(b + 4, b + 4 + cap), orig };
    }
    o += len;
  }
}
// Capture files inside a zip (e.g. a Client Connector bundle), size-capped.
function zipCaptures(buf) {
  return readZip(buf, { want: (name) => /\.(pcapng|pcap|cap)$/i.test(name) && !/(^|\/)__MACOSX\//.test(name), maxTotal: LIMITS.zipTotal }).filter((f) => f.data);
}
function formatOf(buf) {
  if (buf.length < 24) return null;
  const m = buf.readUInt32LE(0);
  if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(m)) return 'pcap';
  if (m === 0x0a0d0d0a) return 'pcapng';
  if (m === 0x04034b50) return 'zip';
  return null;
}

// ---------- link / network / transport decoding ----------
const ip4 = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
function ip6(b, o) {
  const g = []; for (let i = 0; i < 8; i++) g.push(b.readUInt16BE(o + i * 2).toString(16));
  let best = [-1, 0], cur = [-1, 0];
  g.forEach((x, i) => { if (x === '0') { if (cur[0] < 0) cur = [i, 0]; cur[1]++; if (cur[1] > best[1]) best = cur.slice(); } else cur = [-1, 0]; });
  if (best[1] < 2) return g.join(':');
  return `${g.slice(0, best[0]).join(':')}::${g.slice(best[0] + best[1]).join(':')}`;
}
// returns { family, src, dst, proto, l4: Buffer, ipLen, frag } or null
function decodeL3(link, d) {
  let o = 0, et = null;
  switch (link) {
    case 1: { // Ethernet (+ VLAN tags)
      if (d.length < 14) return null;
      et = d.readUInt16BE(12); o = 14;
      while ((et === 0x8100 || et === 0x88a8 || et === 0x9100) && o + 4 <= d.length) { et = d.readUInt16BE(o + 2); o += 4; }
      if (et === 0x8864 && o + 8 <= d.length) { const pp = d.readUInt16BE(o + 6); o += 8; et = pp === 0x0021 ? 0x0800 : pp === 0x0057 ? 0x86dd : null; } // PPPoE
      break;
    }
    case 0: case 108: { // BSD loopback: 4-byte address family (host order for 0, network order for 108)
      if (d.length < 4) return null;
      const fam = link === 108 ? d.readUInt32BE(0) : (d.readUInt32LE(0) < 256 ? d.readUInt32LE(0) : d.readUInt32BE(0));
      et = fam === 2 ? 0x0800 : [24, 28, 30, 10, 23].includes(fam) ? 0x86dd : null; o = 4; break;
    }
    case 113: if (d.length < 16) return null; et = d.readUInt16BE(14); o = 16; break; // Linux cooked
    case 276: if (d.length < 20) return null; et = d.readUInt16BE(0); o = 20; break; // Linux cooked v2
    case 101: case 12: case 14: case 228: case 229: { // raw IP
      if (!d.length) return null; const v = d[0] >> 4; et = v === 4 ? 0x0800 : v === 6 ? 0x86dd : null; o = 0; break;
    }
    default: return null;
  }
  if (et === 0x0800) {
    if (o + 20 > d.length || d[o] >> 4 !== 4) return null;
    const ihl = (d[o] & 15) * 4, tot = d.readUInt16BE(o + 2), proto = d[o + 9], fo = d.readUInt16BE(o + 6);
    if (ihl < 20) return null;
    const end = Math.min(d.length, o + (tot || d.length - o));
    return { family: 4, src: ip4(d, o + 12), dst: ip4(d, o + 16), proto, l4: d.subarray(Math.min(o + ihl, end), end), ipLen: tot, frag: (fo & 0x1fff) !== 0, moreFrags: !!(fo & 0x2000) };
  }
  if (et === 0x86dd) {
    if (o + 40 > d.length || d[o] >> 4 !== 6) return null;
    let nh = d[o + 6], p = o + 40; const plen = d.readUInt16BE(o + 4); const end = Math.min(d.length, o + 40 + plen); let frag = false;
    for (let guard = 0; guard < 8 && [0, 43, 60, 44, 51].includes(nh) && p + 8 <= end; guard++) {
      const next = d[p];
      if (nh === 44) { frag = (d.readUInt16BE(p + 2) & 0xfff8) !== 0; p += 8; } else if (nh === 51) p += (d[p + 1] + 2) * 4; else p += (d[p + 1] + 1) * 8;
      nh = next;
    }
    return { family: 6, src: ip6(d, o + 8), dst: ip6(d, o + 24), proto: nh, l4: d.subarray(Math.min(p, end), end), ipLen: plen + 40, frag };
  }
  return null;
}

// ---------- application parsers ----------
function dnsName(b, o, depth = 0) {
  const labels = []; let jumped = false, next = o, guard = 0;
  while (o < b.length && guard++ < 128) {
    const l = b[o];
    if (l === 0) { o++; break; }
    if ((l & 0xc0) === 0xc0) { if (o + 1 >= b.length || depth > 10) return null; if (!jumped) next = o + 2; jumped = true; o = ((l & 0x3f) << 8) | b[o + 1]; depth++; continue; }
    if (o + 1 + l > b.length) return null;
    labels.push(b.toString('latin1', o + 1, o + 1 + l)); o += 1 + l;
  }
  return { name: labels.join('.').toLowerCase(), end: jumped ? next : o };
}
const RCODE = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];
const QTYPE = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 64: 'SVCB' };
function parseDns(b) {
  if (b.length < 12) return null;
  const id = b.readUInt16BE(0), flags = b.readUInt16BE(2), qd = b.readUInt16BE(4), an = b.readUInt16BE(6);
  if (qd > 10 || an > 200) return null;
  let o = 12; const qs = [], ans = [];
  for (let i = 0; i < qd; i++) { const n = dnsName(b, o); if (!n || n.end + 4 > b.length) return null; qs.push({ name: n.name, type: QTYPE[b.readUInt16BE(n.end)] || b.readUInt16BE(n.end) }); o = n.end + 4; }
  for (let i = 0; i < an; i++) {
    const n = dnsName(b, o); if (!n || n.end + 10 > b.length) break;
    const t = b.readUInt16BE(n.end), ttl = b.readUInt32BE(n.end + 4), rl = b.readUInt16BE(n.end + 8), r = n.end + 10;
    if (r + rl > b.length) break;
    let data = null;
    if (t === 1 && rl === 4) data = ip4(b, r); else if (t === 28 && rl === 16) data = ip6(b, r); else if (t === 5) { const c = dnsName(b, r); data = c && c.name; }
    ans.push({ name: n.name, type: QTYPE[t] || t, ttl, data }); o = r + rl;
  }
  return { id, response: !!(flags & 0x8000), rcode: RCODE[flags & 15] || String(flags & 15), questions: qs, answers: ans };
}
// TLS records from the start of one direction of a TCP stream
const ALERT = { 0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure', 42: 'bad_certificate', 43: 'unsupported_certificate', 44: 'certificate_revoked', 45: 'certificate_expired', 46: 'certificate_unknown', 47: 'illegal_parameter', 48: 'unknown_ca', 49: 'access_denied', 50: 'decode_error', 51: 'decrypt_error', 70: 'protocol_version', 71: 'insufficient_security', 80: 'internal_error', 86: 'inappropriate_fallback', 90: 'user_canceled', 109: 'missing_extension', 112: 'unrecognized_name', 116: 'certificate_required', 120: 'no_application_protocol' };
const TLSV = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
function parseTls(stream, side) {
  const r = { records: 0 }; let o = 0; const hs = [];
  while (o + 5 <= stream.length && r.records < 64) {
    const ct = stream[o], ver = stream.readUInt16BE(o + 1), len = stream.readUInt16BE(o + 3);
    if (![20, 21, 22, 23].includes(ct) || (ver >> 8) !== 3) break;
    r.records++; r.recordVersion = r.recordVersion || ver;
    const body = stream.subarray(o + 5, Math.min(stream.length, o + 5 + len));
    if (ct === 22) hs.push(body);
    else if (ct === 21 && body.length >= 2 && len === 2) (r.alerts = r.alerts || []).push({ level: body[0] === 2 ? 'fatal' : 'warning', desc: ALERT[body[1]] || `alert ${body[1]}`, from: side });
    else if (ct === 23) { r.appData = true; break; }
    else if (ct === 20) r.ccs = true;
    if (o + 5 + len > stream.length) break;
    o += 5 + len;
  }
  const h = Buffer.concat(hs);
  let p = 0;
  while (p + 4 <= h.length) {
    const t = h[p], l = h.readUIntBE(p + 1, 3), m = h.subarray(p + 4, Math.min(h.length, p + 4 + l));
    if (t === 1) Object.assign(r, clientHello(m));
    else if (t === 2) Object.assign(r, serverHello(m));
    else if (t === 11) { const c = certificateMsg(m); if (c) r.cert = c; }
    if (p + 4 + l > h.length || l === 0 && t !== 14) break;
    p += 4 + l;
  }
  return r;
}
function exts(m, o, f) {
  if (o + 2 > m.length) return; const end = Math.min(m.length, o + 2 + m.readUInt16BE(o)); o += 2;
  while (o + 4 <= end) { const t = m.readUInt16BE(o), l = m.readUInt16BE(o + 2); f(t, m.subarray(o + 4, Math.min(end, o + 4 + l))); o += 4 + l; }
}
function clientHello(m) {
  const r = { hello: 'client' }; if (m.length < 38) return r;
  r.clientVersion = m.readUInt16BE(0);
  let o = 34; o += 1 + m[o]; if (o + 2 > m.length) return r; o += 2 + m.readUInt16BE(o); if (o + 1 > m.length) return r; o += 1 + m[o];
  exts(m, o, (t, e) => {
    if (t === 0 && e.length >= 5) { const l = e.readUInt16BE(3); if (e[2] === 0 && 5 + l <= e.length) r.sni = e.toString('latin1', 5, 5 + l).toLowerCase(); }
    else if (t === 16 && e.length >= 3) { const a = []; let p = 2; while (p < e.length) { const l = e[p]; a.push(e.toString('latin1', p + 1, p + 1 + l)); p += 1 + l; } r.alpn = a; }
    else if (t === 43 && e.length >= 3) { const v = []; for (let p = 1; p + 1 < e.length; p += 2) v.push(e.readUInt16BE(p)); r.offered = v.filter((x) => TLSV[x]).map((x) => TLSV[x]); }
    else if (t === 0xfe0d) r.ech = true; // Encrypted Client Hello: real server name hidden
  });
  return r;
}
function serverHello(m) {
  const r = { serverHello: true }; if (m.length < 38) return r;
  let v = m.readUInt16BE(0); let o = 34; o += 1 + m[o]; if (o + 3 > m.length) return r; o += 3;
  exts(m, o, (t, e) => { if (t === 43 && e.length >= 2) v = e.readUInt16BE(0); });
  r.version = TLSV[v] || `0x${v.toString(16)}`;
  return r;
}
// X.509: issuer and subject (CN / O) of the first certificate. TLS 1.2 and earlier only (1.3 encrypts it).
function der(b, o) {
  if (o + 2 > b.length) return null;
  const tag = b[o]; let len = b[o + 1], hl = 2;
  if (len & 0x80) { const n = len & 0x7f; if (n > 4 || o + 2 + n > b.length) return null; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[o + 2 + i]; hl = 2 + n; }
  if (o + hl + len > b.length) return null;
  return { tag, start: o + hl, end: o + hl + len };
}
function derName(b, n) {
  const out = {}; let p = n.start;
  while (p < n.end) {
    const set = der(b, p); if (!set) break; let q = set.start;
    while (q < set.end) {
      const seq = der(b, q); if (!seq) break;
      const oid = der(b, seq.start), val = oid && der(b, oid.end);
      if (oid && val) { const o = b.subarray(oid.start, oid.end).toString('hex'); const v = b.toString(val.tag === 0x1e ? 'utf16le' : 'utf8', val.start, val.end); if (o === '550403') out.CN = v; else if (o === '55040a') out.O = v; }
      q = seq.end;
    }
    p = set.end;
  }
  return out;
}
function certificateMsg(m) {
  try {
    if (m.length < 6) return null;
    let o = 3; // total certificates length
    if (m.length > 3 && m[0] === 0 && m.readUIntBE(0, 3) + 3 !== m.length && m.length > 4) o = 1 + m[0] + 3; // TLS 1.3 layout (request context)
    const clen = m.readUIntBE(o, 3); const c = m.subarray(o + 3, Math.min(m.length, o + 3 + clen));
    const cert = der(c, 0); const tbs = cert && der(c, cert.start); if (!tbs) return null;
    let p = tbs.start; const f = [];
    while (p < tbs.end && f.length < 6) { const e = der(c, p); if (!e) break; f.push(e); p = e.end; }
    const off = f[0] && f[0].tag === 0xa0 ? 1 : 0; // optional [0] version
    const issuer = f[2 + off] && derName(c, f[2 + off]), subject = f[4 + off] && derName(c, f[4 + off]);
    return issuer ? { issuer, subject } : null;
  } catch { return null; }
}
function parseHttp(stream, side) {
  const head = stream.toString('latin1', 0, Math.min(stream.length, 8192));
  const end = head.indexOf('\r\n\r\n'); const lines = (end > 0 ? head.slice(0, end) : head).split('\r\n');
  const hdr = (n) => { const l = lines.find((x) => x.toLowerCase().startsWith(n + ':')); return l ? l.slice(n.length + 1).trim() : null; };
  if (side === 'client') {
    const m = lines[0].match(/^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) (\S+) HTTP\/1\.[01]$/);
    return m ? { method: m[1], target: m[2], host: (hdr('host') || '').toLowerCase() || null, userAgent: hdr('user-agent') } : null;
  }
  const m = lines[0].match(/^HTTP\/1\.[01] (\d{3})(?: (.*))?$/);
  return m ? { status: +m[1], reason: m[2] || '', server: hdr('server'), location: hdr('location'), zscaler: /zscaler/i.test(head) } : null;
}

// ---------- Zscaler awareness ----------
const ZS_DOMAINS = /(^|\.)(zscaler(one|two|three|beta|ten|gov|feed)?\.net|zscloud\.net|zscalergov\.us|zpath\.net|zscaler\.com|zsapi\.net|zslogin\.net|zdxcloud\.net|zdxgov\.net|zscalerbeta\.net)$/;
function zscalerRole(name, port) {
  if (!name) return null;
  if (/(^|\.)private\.zscaler\.com$|(^|\.)zpath\.net$/.test(name)) return { via: 'ZPA', role: 'ZPA broker (Client Connector ↔ ZPA)' };
  if (!ZS_DOMAINS.test(name)) return null;
  if (/zdx(cloud|gov)\.net$/.test(name)) return { via: 'Zscaler', role: 'ZDX' };
  if (/^(pac|ipv6pac)\./.test(name)) return { via: 'Zscaler', role: 'PAC file' };
  if (/^(mobile|login|mobileadmin|config)\.|zslogin\.net$|zsapi\.net$/.test(name)) return { via: 'Zscaler', role: 'Client Connector / admin service' };
  if (/^gateway\.|^(z-tunnel|ztunnel)|\.(zscaler(one|two|three|beta|ten|gov)?|zscloud)\.net$/.test(name)) return { via: 'ZIA', role: port === 80 || port === 9400 || port === 9480 ? 'ZIA Service Edge (proxy / Z-Tunnel 1.0)' : 'ZIA Service Edge (Z-Tunnel 2.0 / proxy)' };
  return { via: 'Zscaler', role: 'Zscaler service' };
}
// Well-known Zscaler public ranges (fallback when the live config.zscaler.com lists aren't available).
const ZS_RANGES = ['165.225.0.0/16', '147.161.128.0/17', '136.226.0.0/16', '104.129.192.0/20', '185.46.212.0/22', '199.168.148.0/22', '170.85.0.0/16', '137.83.128.0/18', '198.14.64.0/18', '101.2.192.0/18', '8.25.203.0/24', '64.215.22.0/23', '211.144.19.0/24', '197.98.201.0/24'];
const toInt = (ip) => ip.split('.').reduce((a, x) => a * 256 + (+x), 0);
const cidr = (c) => { const [b, bits] = c.split('/'); const size = 2 ** (32 - +bits); const lo = Math.floor(toInt(b) / size) * size; return [lo, lo + size - 1]; };
function inRanges(ip, ranges) { if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false; const n = toInt(ip); return ranges.some(([lo, hi]) => n >= lo && n <= hi); }
const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255/32', '0.0.0.0/8'].map(cidr);
const CGNAT = [cidr('100.64.0.0/10')];
function addrKind(ip) {
  if (/^(fe80|ff0|::1$|fc|fd)/i.test(ip)) return 'local';
  if (inRanges(ip, PRIVATE)) return 'local';
  if (inRanges(ip, CGNAT)) return 'zpa-synthetic';
  return 'internet';
}

// ---------- the analysis ----------
const PORTS = { 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 3389: 'RDP', 445: 'SMB', 123: 'NTP', 25: 'SMTP', 587: 'SMTP', 993: 'IMAPS', 389: 'LDAP', 636: 'LDAPS', 88: 'Kerberos', 135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 5353: 'mDNS', 5355: 'LLMNR', 1900: 'SSDP', 67: 'DHCP', 68: 'DHCP', 9400: 'Zscaler proxy', 9480: 'Zscaler proxy', 9443: 'Zscaler proxy', 8080: 'HTTP proxy', 3128: 'HTTP proxy', 1433: 'SQL Server', 3306: 'MySQL', 104: 'DICOM', 2575: 'HL7', 5060: 'SIP', 5061: 'SIP-TLS', 3478: 'STUN/TURN', 8801: 'Zoom', 8802: 'Zoom' };

function analyze(input, opts = {}) {
  const fmt = formatOf(input);
  if (!fmt) throw Object.assign(new Error('Not a packet capture: expected .pcap, .pcapng, or a .zip containing them'), { status: 400 });
  const files = fmt === 'zip' ? zipCaptures(input) : [{ name: opts.name || 'capture', data: input }];
  if (!files.length) throw Object.assign(new Error('The zip has no .pcap / .pcapng files in it'), { status: 400 });
  const zsRanges = (opts.zscalerRanges && opts.zscalerRanges.length ? opts.zscalerRanges : ZS_RANGES).map(cidr);
  const stats = { packets: 0, bytes: 0, first: null, last: null, decoded: 0, other: 0, truncated: 0, links: {}, files: [] };
  const flows = new Map();
  const dnsTx = new Map(); const dns = []; const ipNames = new Map(); const icmp = [];
  const flowKey = (p, a, ap, b, bp) => `${p}|${a}|${ap}|${b}|${bp}`;

  for (const f of files) {
    const kind = formatOf(f.data);
    if (kind !== 'pcap' && kind !== 'pcapng') { stats.files.push({ name: f.name, error: 'not a capture' }); continue; }
    let count = 0;
    for (const pk of (kind === 'pcap' ? pcapPackets(f.data) : pcapngPackets(f.data))) {
      if (stats.packets >= LIMITS.packets) { stats.capped = true; break; }
      stats.packets++; count++; stats.bytes += pk.orig;
      if (pk.data.length < pk.orig) stats.truncated++;
      if (pk.ts) { if (stats.first == null || pk.ts < stats.first) stats.first = pk.ts; if (stats.last == null || pk.ts > stats.last) stats.last = pk.ts; }
      stats.links[pk.link] = (stats.links[pk.link] || 0) + 1;
      const l3 = decodeL3(pk.link, pk.data);
      if (!l3) { stats.other++; continue; }
      stats.decoded++;
      let proto, sp = 0, dp = 0, tcp = null, payload = Buffer.alloc(0);
      const l4 = l3.l4;
      if (l3.frag) { proto = 'frag'; }
      else if (l3.proto === 6 && l4.length >= 20) {
        proto = 'tcp'; sp = l4.readUInt16BE(0); dp = l4.readUInt16BE(2);
        const off = (l4[12] >> 4) * 4, fl = l4[13];
        tcp = { seq: l4.readUInt32BE(4), ack: l4.readUInt32BE(8), syn: !!(fl & 2), ackf: !!(fl & 16), rst: !!(fl & 4), fin: !!(fl & 1), win: l4.readUInt16BE(14) };
        payload = off >= 20 && off <= l4.length ? l4.subarray(off) : Buffer.alloc(0);
      } else if (l3.proto === 17 && l4.length >= 8) { proto = 'udp'; sp = l4.readUInt16BE(0); dp = l4.readUInt16BE(2); payload = l4.subarray(8, Math.min(l4.length, Math.max(8, l4.readUInt16BE(4)))); }
      else if ((l3.proto === 1 || l3.proto === 58) && l4.length >= 4) {
        const t = l4[0], c = l4[1];
        const v4 = l3.proto === 1;
        const unreach = v4 ? t === 3 : t === 1, ttl = v4 ? t === 11 : t === 3, big = (v4 && t === 3 && c === 4) || (!v4 && t === 2);
        if (unreach || ttl || big) {
          // the original packet that triggered it
          let orig = null; const inner = l4.subarray(8);
          if (v4 && inner.length >= 28 && inner[0] >> 4 === 4) { const ihl = (inner[0] & 15) * 4; orig = { dst: ip4(inner, 16), proto: inner[9], dport: inner.length >= ihl + 4 ? inner.readUInt16BE(ihl + 2) : null }; }
          icmp.push({ ts: pk.ts, from: l3.src, to: l3.dst, kind: big ? (v4 ? 'fragmentation needed (MTU)' : 'packet too big (MTU)') : ttl ? 'TTL exceeded' : `unreachable (code ${c})`, mtu: big && v4 ? l4.readUInt16BE(6) : null, orig });
        }
        proto = v4 ? 'icmp' : 'icmpv6';
      } else proto = `ip-${l3.proto}`;

      // conversation: the side that sent the first packet (or the SYN) is the client
      const k1 = flowKey(proto, l3.src, sp, l3.dst, dp), k2 = flowKey(proto, l3.dst, dp, l3.src, sp);
      let fl = flows.get(k1), dir = 'c2s';
      if (!fl) { fl = flows.get(k2); dir = 's2c'; }
      if (!fl) {
        if (flows.size >= LIMITS.flows) { stats.flowsCapped = true; continue; }
        let swap = false;
        if (tcp && tcp.syn && tcp.ackf) swap = true; // first packet seen is the SYN-ACK: the sender is the server
        else if (!tcp && sp && dp && sp < 1024 && dp >= 1024 && !PORTS[dp]) swap = true; // e.g. a DNS answer captured without its query
        fl = { proto, client: swap ? l3.dst : l3.src, cport: swap ? dp : sp, server: swap ? l3.src : l3.dst, sport: swap ? sp : dp, family: l3.family, first: pk.ts, last: pk.ts,
          pk: { c2s: 0, s2c: 0 }, by: { c2s: 0, s2c: 0 }, tcp: tcp ? { syn: 0, synack: 0, rst: null, fin: 0, retrans: 0, zeroWin: 0, dataPk: 0 } : null,
          stream: { c2s: [], s2c: [] }, sb: { c2s: 0, s2c: 0 }, seen: { c2s: new Set(), s2c: new Set() }, isn: {} };
        flows.set(swap ? k2 : k1, fl); dir = swap ? 's2c' : 'c2s';
      }
      fl.last = pk.ts; fl.pk[dir]++; fl.by[dir] += pk.orig;
      if (tcp) {
        const t = fl.tcp;
        if (tcp.syn && !tcp.ackf) { t.syn++; t.synTs = t.synTs || pk.ts; fl.isn.c2s = tcp.seq; }
        if (tcp.syn && tcp.ackf) { t.synack++; t.synackTs = t.synackTs || pk.ts; fl.isn.s2c = tcp.seq; }
        if (tcp.rst && !t.rst) t.rst = { from: dir === 'c2s' ? 'client' : 'server', ts: pk.ts, afterData: (fl.by.c2s + fl.by.s2c) > 0 && t.dataPk > 0 };
        if (tcp.fin) t.fin++;
        if (tcp.win === 0 && !tcp.rst && !tcp.syn) t.zeroWin++;
        if (payload.length) {
          t.dataPk++;
          const key = `${tcp.seq}:${payload.length}`;
          if (fl.seen[dir].has(key)) t.retrans++; else if (fl.seen[dir].size < LIMITS.perFlowSegs) fl.seen[dir].add(key);
          if (fl.sb[dir] < LIMITS.streamBytes) { fl.stream[dir].push({ seq: tcp.seq, data: Buffer.from(payload.subarray(0, LIMITS.streamBytes - fl.sb[dir])) }); fl.sb[dir] += Math.min(payload.length, LIMITS.streamBytes); }
        }
      } else if (payload.length && fl.sb[dir] < LIMITS.streamBytes && fl.stream[dir].length < 64) { fl.stream[dir].push({ data: Buffer.from(payload.subarray(0, 4096)) }); fl.sb[dir] += Math.min(payload.length, 4096); }

      // DNS over UDP (and mDNS/LLMNR ignored)
      if (proto === 'udp' && (sp === 53 || dp === 53) && payload.length) {
        const m = parseDns(payload);
        if (m) handleDns(m, pk.ts, fl.client, fl.server);
      }
    }
    stats.files.push({ name: f.name, format: kind, packets: count });
  }

  function handleDns(m, ts, client, server) {
    const q = m.questions[0]; if (!q) return;
    const k = `${client}|${server}|${m.id}|${q.name}`;
    if (!m.response) { if (!dnsTx.has(k)) { const e = { ts, client, server, name: q.name, type: q.type, rcode: null, answers: [], rtt: null }; dnsTx.set(k, e); dns.push(e); } else dnsTx.get(k).retries = (dnsTx.get(k).retries || 0) + 1; return; }
    let e = dnsTx.get(k);
    if (!e) { e = { ts, client, server, name: q.name, type: q.type, answers: [], rtt: null }; dnsTx.set(k, e); dns.push(e); }
    e.rcode = m.rcode; e.rtt = e.ts && ts ? +(ts - e.ts).toFixed(4) : null;
    e.answers = m.answers.map((a) => ({ type: a.type, data: a.data, ttl: a.ttl }));
    for (const a of m.answers) if ((a.type === 'A' || a.type === 'AAAA') && a.data && !ipNames.has(a.data)) ipNames.set(a.data, q.name);
  }

  // Reassemble the first bytes of each TCP direction (in sequence order) and read the application layer.
  const ordered = (fl, dir) => {
    const segs = fl.stream[dir]; if (!segs.length) return Buffer.alloc(0);
    if (!fl.tcp) return Buffer.concat(segs.map((s) => s.data));
    const base = fl.isn[dir] != null ? (fl.isn[dir] + 1) >>> 0 : segs.reduce((m, s) => (((s.seq - m) | 0) < 0 ? s.seq : m), segs[0].seq);
    const parts = segs.map((s) => ({ off: (s.seq - base) >>> 0, data: s.data })).filter((s) => s.off < LIMITS.streamBytes * 4).sort((a, b) => a.off - b.off);
    const out = []; let at = 0;
    for (const s of parts) { if (s.off > at) break; const skip = at - s.off; if (skip < s.data.length) { out.push(s.data.subarray(skip)); at += s.data.length - skip; } if (at >= LIMITS.streamBytes) break; }
    return Buffer.concat(out);
  };
  const list = [];
  for (const fl of flows.values()) {
    const c = ordered(fl, 'c2s'), s = ordered(fl, 's2c');
    const app = {};
    if (fl.proto === 'tcp' && (fl.sport === 53 || fl.cport === 53)) {
      for (const [buf, from] of [[c, 'c2s'], [s, 's2c']]) { let o = 0; while (o + 2 < buf.length) { const l = buf.readUInt16BE(o); const m = parseDns(buf.subarray(o + 2, o + 2 + l)); if (m) handleDns(m, from === 'c2s' ? fl.first : fl.last, fl.client, fl.server); o += 2 + l; } }
      app.protocol = 'DNS';
    } else if (c.length && c[0] === 0x16 && c.length > 5 && c[1] === 3) {
      const ct = parseTls(c, 'client'), st = s.length && s[0] >= 20 && s[0] <= 23 ? parseTls(s, 'server') : {};
      app.protocol = 'TLS';
      app.tls = { sni: ct.sni || null, alpn: ct.alpn || null, offered: ct.offered || null, ech: !!ct.ech, version: st.version || null,
        alerts: [...(ct.alerts || []), ...(st.alerts || [])], cert: st.cert || null, established: !!(st.appData || (st.serverHello && st.ccs) || (st.serverHello && ct.appData)) };
      if (app.tls.cert) app.tls.zscalerCert = /zscaler/i.test(`${app.tls.cert.issuer.CN || ''} ${app.tls.cert.issuer.O || ''}`);
    } else if (c.length && /^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) /.test(c.toString('latin1', 0, 8))) {
      app.protocol = 'HTTP'; app.http = Object.assign({}, parseHttp(c, 'client'), s.length ? { response: parseHttp(s, 'server') } : {});
      if (app.http.method === 'CONNECT') { app.protocol = 'HTTP proxy (CONNECT)'; app.http.connectTo = app.http.target; }
    } else if (fl.proto === 'udp' && (fl.sport === 443 || fl.sport === 80) && c.length && (c[0] & 0x80)) {
      app.protocol = 'QUIC'; if (c.length > 5) app.quicVersion = c.readUInt32BE(1).toString(16);
    } else if (fl.proto === 'udp' && fl.sport === 53) app.protocol = 'DNS';
    else app.protocol = PORTS[fl.sport] || (fl.proto === 'tcp' || fl.proto === 'udp' ? `${fl.proto.toUpperCase()}/${fl.sport}` : fl.proto.toUpperCase());
    // who is the server: name from TLS SNI, HTTP Host, CONNECT target or a DNS answer seen earlier
    const name = (app.tls && app.tls.sni) || (app.http && (app.http.host || '').replace(/:\d+$/, '')) || ipNames.get(fl.server) || null;
    const proxyTarget = app.http && app.http.connectTo ? app.http.connectTo.toLowerCase() : null;
    const kind = addrKind(fl.server);
    const zr = zscalerRole(name, fl.sport);
    let via = 'direct', role = null;
    if (zr) { via = zr.via; role = zr.role; }
    else if (inRanges(fl.server, zsRanges)) { via = 'ZIA'; role = 'Zscaler IP range'; }
    else if (kind === 'zpa-synthetic') { via = 'ZPA'; role = 'ZPA app (Client Connector synthetic IP)'; }
    else if (kind === 'local') via = 'local';
    // A certificate issued by Zscaler, or a Zscaler block/notification page, proves the session went through ZIA even
    // when the capture shows the real destination (captured on the tunnel adapter, or inside Z-Tunnel 2.0).
    if (via === 'direct' && app.tls && app.tls.zscalerCert) { via = 'ZIA'; role = 'SSL-inspected by ZIA (seen with its real destination)'; }
    else if (via === 'direct' && app.http && app.http.response && app.http.response.zscaler) { via = 'ZIA'; role = 'answered by ZIA (block or notification page)'; }
    const t = fl.tcp;
    let status = 'ok', detail = '';
    if (t) {
      if (t.syn && !t.synack && !t.rst) { status = 'no-answer'; detail = `${t.syn} SYN${t.syn > 1 ? 's' : ''}, no reply`; }
      else if (t.rst && t.rst.from === 'server' && !t.synack) { status = 'refused'; detail = 'reset by the server (port closed or blocked)'; }
      else if (t.rst) { status = 'reset'; detail = `reset by the ${t.rst.from}${t.rst.afterData ? ' after data' : ''}`; }
      else if (!t.syn && !t.synack) { status = 'partial'; detail = 'started before the capture'; }
    }
    if (app.tls && app.tls.alerts.some((a) => a.level === 'fatal')) { status = 'tls-alert'; detail = app.tls.alerts.filter((a) => a.level === 'fatal').map((a) => `${a.desc} from ${a.from}`).join(', '); }
    if (!t && fl.proto === 'udp' && fl.pk.s2c === 0 && fl.pk.c2s > 1 && kind !== 'local') { status = 'no-answer'; detail = `${fl.pk.c2s} packets out, none back`; }
    list.push({
      proto: fl.proto, client: fl.client, cport: fl.cport, server: fl.server, sport: fl.sport, name, proxyTarget, family: fl.family,
      first: fl.first, duration: +(fl.last - fl.first).toFixed(3), packets: fl.pk.c2s + fl.pk.s2c, bytes: fl.by.c2s + fl.by.s2c, bytesOut: fl.by.c2s, bytesIn: fl.by.s2c,
      app: app.protocol, tls: app.tls || null, http: app.http || null, quicVersion: app.quicVersion || null, via, role, kind, status, detail,
      rtt: t && t.synTs != null && t.synackTs != null ? +(t.synackTs - t.synTs).toFixed(4) : null,
      retrans: t ? t.retrans : 0, dataPackets: t ? t.dataPk : 0, zeroWindow: t ? t.zeroWin : 0, synTries: t ? t.syn : 0,
    });
  }
  list.sort((a, b) => b.bytes - a.bytes);
  for (const e of dns) e.status = e.rcode == null ? 'no-response' : e.rcode === 'NOERROR' ? (e.answers.length ? 'ok' : 'no-data') : 'error';
  const res = { file: Object.assign({}, stats, { duration: stats.first != null ? +(stats.last - stats.first).toFixed(3) : 0, links: Object.entries(stats.links).map(([k, v]) => ({ link: +k, name: LINKS[k] || `link type ${k}`, packets: v })) }),
    flows: list, dns, icmp };
  res.findings = findings(res);
  res.summary = summarize(res);
  return res;
}
const LINKS = { 0: 'Loopback', 1: 'Ethernet', 12: 'Raw IP', 14: 'Raw IP', 101: 'Raw IP (tunnel)', 108: 'Loopback', 113: 'Linux cooked', 228: 'Raw IPv4', 229: 'Raw IPv6', 276: 'Linux cooked v2', 105: 'Wi-Fi (802.11)', 127: 'Wi-Fi (radiotap)' };

function summarize(r) {
  const f = r.flows, ext = f.filter((x) => x.via !== 'local');
  const count = (pred) => f.filter(pred).length;
  return {
    flows: f.length, hosts: new Set(f.map((x) => x.name || x.server)).size,
    viaZia: count((x) => x.via === 'ZIA'), viaZpa: count((x) => x.via === 'ZPA'), viaZscaler: count((x) => x.via === 'Zscaler'), direct: count((x) => x.via === 'direct'), local: count((x) => x.via === 'local'),
    failed: count((x) => ['no-answer', 'refused', 'reset', 'tls-alert'].includes(x.status)),
    dnsQueries: r.dns.length, dnsFailed: r.dns.filter((d) => d.status === 'error' || d.status === 'no-response').length,
    tls: count((x) => x.tls), inspected: count((x) => x.tls && x.tls.zscalerCert), quic: count((x) => x.app === 'QUIC'),
    external: ext.length,
  };
}

// Plain-language problems, most important first. Each can carry a destination to simulate.
function findings(r) {
  const out = [];
  const add = (sev, title, detail, extra = {}) => out.push(Object.assign({ sev, title, detail }, extra));
  const host = (x) => x.name || x.server;
  const sim = (x) => ({ target: x.proxyTarget ? x.proxyTarget.replace(/:\d+$/, '') : host(x), port: x.proxyTarget && /:\d+$/.test(x.proxyTarget) ? +x.proxyTarget.split(':').pop() : x.sport, protocol: x.proto === 'udp' ? 'udp' : 'tcp' });
  const ext = r.flows.filter((x) => x.via !== 'local');
  // TLS: client rejected the certificate — classic SSL inspection / pinning problem
  for (const x of r.flows.filter((y) => y.tls && y.tls.alerts.some((a) => a.from === 'client' && /unknown_ca|bad_certificate|certificate_unknown|unsupported_certificate/.test(a.desc)))) {
    const a = x.tls.alerts.find((y) => y.from === 'client');
    add('high', `${host(x)}: the app rejected the server certificate (${a.desc})`, x.tls.zscalerCert
      ? `The certificate was issued by Zscaler (SSL inspection) and the client doesn't trust it: certificate pinning or the Zscaler root CA isn't installed. Consider an SSL Inspection "Do Not Inspect" rule for this destination.`
      : `The client closed the TLS handshake. If SSL inspection applies, the app may pin its certificate or not trust the Zscaler root CA.`, { simulate: sim(x), flow: x });
  }
  for (const x of r.flows.filter((y) => y.status === 'tls-alert' && !out.some((f) => f.flow === y))) add('high', `${host(x)}: TLS handshake failed (${x.detail})`, 'The TLS session ended with a fatal alert. Check the SSL Inspection policy and the server\'s TLS settings.', { simulate: sim(x), flow: x });
  // TCP
  const noAns = ext.filter((x) => x.proto === 'tcp' && x.status === 'no-answer');
  for (const x of noAns.slice(0, 15)) add('high', `${host(x)}:${x.sport} didn't answer`, `${x.detail}. Something dropped the connection attempt: a firewall rule (e.g. Block/Drop), routing, or the server is down.`, { simulate: sim(x), flow: x });
  if (noAns.length > 15) add('high', `${noAns.length - 15} more connections got no answer`, 'See Conversations, filtered to Failed.');
  for (const x of ext.filter((y) => y.status === 'refused').slice(0, 15)) add('high', `${host(x)}:${x.sport} refused the connection`, 'The server (or a device in the path, such as a firewall sending resets) reset the connection right away.', { simulate: sim(x), flow: x });
  for (const x of ext.filter((y) => y.status === 'reset' && y.detail.includes('server')).slice(0, 10)) add('medium', `${host(x)}:${x.sport} was reset mid-connection`, `${x.detail}. A reset from the "server" side can also come from a proxy or firewall in the path.`, { simulate: sim(x), flow: x });
  // retransmissions / zero window
  for (const x of r.flows.filter((y) => y.dataPackets >= 20 && y.retrans / y.dataPackets > 0.05).slice(0, 8)) add('medium', `${host(x)}: ${Math.round((x.retrans / x.dataPackets) * 100)}% of data packets were retransmitted`, `${x.retrans} of ${x.dataPackets}. Points at packet loss or a congested / lossy path (Wi-Fi, VPN, MTU).`, { flow: x });
  for (const x of r.flows.filter((y) => y.zeroWindow >= 3).slice(0, 5)) add('low', `${host(x)}: receiver ran out of buffer (${x.zeroWindow} zero-window packets)`, 'The receiving side was too slow to read data: usually an application or host problem, not the network.', { flow: x });
  // DNS
  const bad = new Map();
  for (const d of r.dns.filter((e) => e.status === 'error' || e.status === 'no-response')) { const k = `${d.name}|${d.rcode || 'no response'}`; bad.set(k, (bad.get(k) || 0) + 1); }
  for (const [k, n] of [...bad].slice(0, 15)) { const [name, rc] = k.split('|'); add(rc === 'NXDOMAIN' ? 'medium' : 'high', `DNS: ${name} → ${rc}${n > 1 ? ` (${n}×)` : ''}`, rc === 'NXDOMAIN' ? 'The name doesn\'t exist in DNS (typo, missing internal record, or a split-DNS / ZPA resolution problem).' : rc === 'no response' ? 'The DNS server never answered: blocked DNS, wrong resolver, or a DNS Control rule dropping it.' : `The DNS server returned ${rc}.`, { simulate: { target: name, port: 53, protocol: 'udp' } }); }
  // ICMP
  for (const i of r.icmp.filter((e) => /MTU/.test(e.kind)).slice(0, 3)) add('medium', `Path MTU problem: ${i.from} reports ${i.kind}${i.mtu ? ` (MTU ${i.mtu})` : ''}`, 'Large packets don\'t fit through a tunnel or link on the path. Common with GRE/IPsec tunnels; check MSS clamping.');
  for (const i of r.icmp.filter((e) => /unreachable/.test(e.kind)).slice(0, 5)) add('low', `${i.from} says ${i.orig ? `${i.orig.dst}${i.orig.dport ? ':' + i.orig.dport : ''}` : 'a destination'} is ${i.kind}`, 'An ICMP unreachable came back for this traffic.');
  // QUIC
  const quic = r.flows.filter((x) => x.app === 'QUIC');
  if (quic.length) {
    const blocked = quic.filter((x) => x.status === 'no-answer');
    add(blocked.length ? 'info' : 'low', blocked.length ? `QUIC (UDP 443) to ${blocked.length} destination(s) got no answer` : `${quic.length} QUIC (UDP 443) connection(s) seen`, blocked.length
      ? 'Expected when ZIA blocks QUIC: browsers fall back to TCP/HTTPS, which Zscaler can inspect.'
      : 'QUIC traffic can\'t be inspected by ZIA. Zscaler recommends a firewall rule that blocks UDP 443 so apps fall back to HTTPS.', blocked[0] ? { simulate: sim(blocked[0]) } : {});
  }
  // Path through Zscaler
  const zs = r.flows.filter((x) => ['ZIA', 'ZPA', 'Zscaler'].includes(x.via));
  const inet = ext.filter((x) => x.via === 'direct' && x.app !== 'DNS');
  if (!zs.length && inet.length) add('info', 'No Zscaler tunnel or proxy traffic in this capture', `${inet.length} internet connection(s) went straight to their destinations. Either Client Connector isn't forwarding this traffic (bypass, trusted network, or not running), or the capture was taken inside the tunnel adapter, where traffic shows its real destination.`);
  else if (zs.length && inet.length) add('info', `${inet.length} connection(s) went direct while others used Zscaler`, 'Check whether these destinations are bypassed on purpose (Client Connector app profile, PAC file or ZPA bypass).', { list: inet.slice(0, 8).map((x) => `${host(x)}:${x.sport}`) });
  const insp = r.flows.filter((x) => x.tls && x.tls.zscalerCert);
  if (insp.length) add('info', `${insp.length} TLS session(s) were SSL-inspected by Zscaler`, `The server certificate was issued by Zscaler (${insp[0].tls.cert.issuer.CN || insp[0].tls.cert.issuer.O}). TLS 1.3 certificates are encrypted, so only TLS 1.2 sessions can be checked.`);
  if (r.file.truncated) add('low', `${r.file.truncated} packet(s) were cut short when captured (snap length)`, 'Some application details (certificates, DNS answers) may be missing. Capture with a larger snap length.');
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  return out.sort((a, b) => order[a.sev] - order[b.sev]).map(({ flow, ...f }) => Object.assign(f, flow ? { flowRef: `${flow.proto}|${flow.client}|${flow.cport}|${flow.server}|${flow.sport}` } : {}));
}

module.exports = { analyze, formatOf, decodeL3, parseDns, parseTls, zscalerRole, addrKind, zipCaptures, ZS_RANGES, LIMITS };
