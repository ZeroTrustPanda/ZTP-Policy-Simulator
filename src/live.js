'use strict';
// Live state for end-to-end troubleshooting (OneAPI):
//  - Client Connector devices for a user: which app profile is applied, ZIA/ZPA service health, versions, last seen.
//  - ZPA path health for an application segment: server groups → App Connector groups → connectors up/down, certificates.
//  - Checks run from this computer: going through Zscaler?, DNS (system vs public, ZPA synthetic IPs), TCP, TLS issuer.
//  - ZIA audit log ("what changed recently?") and activation status.
// Everything here is read-only.

const dns = require('dns');
const net = require('net');
const tls = require('tls');

const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
const lc = (s) => String(s == null ? '' : s).toLowerCase();
const OS = { 1: 'iOS', 2: 'Android', 3: 'Windows', 4: 'macOS', 5: 'Linux' };
const PLATFORM_OF = { 3: 'Windows', 4: 'macOS' };
const ZCC = '/zcc/papi/public/v1';

// ---------- Client Connector devices ----------
// Seconds (ZCC, certificates), milliseconds, or microseconds (ZPA connector connect/disconnect times) → ms.
const epoch = (v) => { const n = Number(v); return n > 0 ? (n < 1e12 ? n * 1000 : n > 1e14 ? Math.floor(n / 1000) : n) : null; };
const bool = (v) => (v === true || lc(v) === 'true' ? true : v === false || lc(v) === 'false' ? false : null);
const health = (v) => { const s = String(v == null ? '' : v).trim(); return !s || /not\s*applicable/i.test(s) ? null : s; };

// Only these fields leave the server. Device details also carry one-time disable/uninstall passwords
// (deviceOtpArray) and other secrets: they are never copied, logged or shown.
function deviceSummary(d) {
  const type = Number(d.type != null ? d.type : d.osType);
  return {
    udid: d.udid || d.unique_id || null,
    hostname: d.machineHostname || d.machine_hostname || null,
    os: OS[type] || (d.osType ? String(d.osType) : null), osType: type || null,
    osVersion: d.osVersion || d.os_version || null,
    zccVersion: d.agentVersion || d.agent_version || d.clientConnectorVersion || null,
    profile: d.policyName || d.devicePolicyName || null,
    registration: d.registrationState || (d.state === 1 ? 'Registered' : d.state === 2 ? 'Unregistered' : d.state != null ? `state ${d.state}` : null),
    lastSeen: epoch(d.last_seen_time || d.lastSeenTime),
    owner: d.owner || null,
    user: d.user || d.username || d.user_name || null,
  };
}
function deviceHealth(d) {
  return {
    profile: d.devicePolicyName || d.policyName || null,
    tunnelVersion: d.tunnelVersion || d.zccTunnelVersion || null,
    zccVersion: d.agent_version || d.agentVersion || null,
    lastSeen: epoch(d.last_seen_time), keepAlive: epoch(d.keep_alive_time),
    zia: { enabled: bool(d.ziaEnabled), health: health(d.ziaHealth) },
    zpa: { enabled: bool(d.zpaEnabled), health: health(d.zpaHealth), lastSeen: epoch(d.zpaLastSeenTime) },
    zdx: { enabled: bool(d.zdxEnabled), health: health(d.zdxHealth) },
  };
}
async function listDevices(client, username) {
  const out = await client.get(`${ZCC}/getDevices`, { username, pageSize: '50' });
  const list = arr(Array.isArray(out) ? out : out && (out.list || out.devices));
  return list.map(deviceSummary).filter((d) => d.udid)
    .sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
}
async function deviceDetails(client, udid) {
  const d = await client.get(`${ZCC}/getDeviceDetails`, { udid });
  if (!d || typeof d !== 'object') return null;
  return Object.assign(deviceSummary(d), { health: deviceHealth(d) });
}
// What the simulation should warn about for this device.
function deviceWarnings(dev) {
  const w = [];
  if (!dev) return w;
  const h = dev.health || {};
  const off = (svc) => svc && svc.enabled === false;
  const bad = (svc) => svc && svc.health && !/^active$/i.test(svc.health);
  if (off(h.zia)) w.push({ svc: 'ZIA', text: 'ZIA is turned off on this device: internet traffic is not going through Zscaler.' });
  else if (bad(h.zia)) w.push({ svc: 'ZIA', text: `ZIA service on this device is "${h.zia.health}", not Active.` });
  if (off(h.zpa)) w.push({ svc: 'ZPA', text: 'ZPA is turned off on this device: private applications are unreachable through ZPA.' });
  else if (bad(h.zpa)) w.push({ svc: 'ZPA', text: `ZPA service on this device is "${h.zpa.health}", not Active.` });
  const seen = dev.lastSeen || h.lastSeen;
  if (seen && Date.now() - seen > 7 * 864e5) w.push({ svc: 'ZCC', text: `Device last checked in ${Math.round((Date.now() - seen) / 864e5)} days ago: its state may be stale.` });
  return w;
}

// ---------- ZPA path health ----------
const CONNECTED = (c) => {
  const s = String(c.controlChannelStatus || c.ctrlChannelStatus || c.status || '');
  if (/DISCONNECT/i.test(s)) return false;
  return /AUTHENTICATED|CONNECTED|ZPN_STATUS_ONLINE/i.test(s) ? true : null;
};
function certInfo(c, kind) {
  const exp = epoch(c && c.validToInEpochSec);
  return c ? { kind, name: c.name || c.cName, expires: exp, days: exp ? Math.floor((exp - Date.now()) / 864e5) : null } : null;
}
// For one application segment: server groups → connector groups → connectors, plus its Browser Access certificate.
function zpaPathHealth(data, segmentId) {
  const seg = arr(data.zpaApps).find((a) => String(a.id) === String(segmentId));
  if (!seg) return null;
  const haveConn = !!(data.zpaConnectors || data.zpaConnectorGroups);
  const sgs = arr(seg.serverGroups).map((g) => arr(data.zpaServerGroups).find((x) => String(x.id) === String(g.id)) || g);
  const groups = [];
  for (const sg of sgs) {
    for (const cgRef of arr(sg.appConnectorGroups)) {
      const cg = arr(data.zpaConnectorGroups).find((x) => String(x.id) === String(cgRef.id)) || cgRef;
      if (groups.some((g) => g.id === String(cg.id))) continue;
      let conns = arr(data.zpaConnectors).filter((c) => String(c.appConnectorGroupId) === String(cg.id));
      if (!conns.length) conns = arr(cg.connectors);
      const list = conns.map((c) => ({ name: c.name, up: c.enabled === false || lc(c.enabled) === 'false' ? false : CONNECTED(c), enabled: !(c.enabled === false || lc(c.enabled) === 'false'),
        version: c.currentVersion || null, lastConnect: epoch(c.lastBrokerConnectTime), lastDisconnect: epoch(c.lastBrokerDisconnectTime), publicIp: c.publicIp || null, privateIp: c.privateIp || null }));
      groups.push({ id: String(cg.id), name: cg.name, serverGroup: sg.name, enabled: !(cg.enabled === false || lc(cg.enabled) === 'false'), connectors: list,
        up: list.filter((c) => c.up === true).length, total: list.length });
    }
  }
  const ba = arr(seg.clientlessApps).map((c) => c.certificateId && arr(data.zpaBaCerts).find((x) => String(x.id) === String(c.certificateId))).filter(Boolean).map((c) => certInfo(c, 'Browser Access'));
  let status = 'unknown';
  if (!sgs.length) status = 'no-server-group';
  else if (haveConn && groups.length) {
    const live = groups.filter((g) => g.enabled);
    status = live.some((g) => g.up > 0) ? (live.every((g) => !g.total || g.up === g.total) ? 'ok' : 'degraded') : 'down';
    if (groups.every((g) => !g.total)) status = 'no-connectors';
  } else if (haveConn && !groups.length) status = 'no-connector-group';
  const certs = ba.filter((c) => c.days != null && c.days < 30);
  return { segment: seg.name, status, groups, certs, haveData: haveConn,
    dynamicDiscovery: !!seg.serverGroups && sgs.some((s) => s.dynamicDiscovery !== false) };
}
// Tenant-wide: enrollment / Browser Access certificates expiring within `days`, and connector groups with nothing up.
function zpaTenantHealth(data, days = 30) {
  const certs = [...arr(data.zpaEnrollmentCerts).map((c) => certInfo(c, 'Enrollment')), ...arr(data.zpaBaCerts).map((c) => certInfo(c, 'Browser Access'))]
    .filter((c) => c && c.days != null && c.days < days).sort((a, b) => a.days - b.days);
  const downGroups = arr(data.zpaConnectorGroups).filter((g) => !(g.enabled === false || lc(g.enabled) === 'false')).map((g) => {
    const conns = arr(data.zpaConnectors).filter((c) => String(c.appConnectorGroupId) === String(g.id));
    return { name: g.name, total: conns.length, up: conns.filter((c) => CONNECTED(c) === true).length };
  }).filter((g) => g.total && !g.up);
  return { certs, downGroups };
}

// ---------- checks from this computer ----------
function timed(p) { const t = Date.now(); return p.then((v) => ({ ok: true, ms: Date.now() - t, v }), (e) => ({ ok: false, ms: Date.now() - t, error: e.message || String(e) })); }
function withTimeout(p, ms, what) { return Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error(`${what} timed out after ${ms / 1000}s`)), ms))]); }
const inCidr = (ip, base, bits) => { const n = (s) => s.split('.').reduce((a, o) => a * 256 + +o, 0); return (n(ip) >>> (32 - bits)) === (n(base) >>> (32 - bits)); };

// "You are accessing the Internet via Zscaler…" page. Returns the plain-text lines that mention Zscaler.
async function zscalerIpCheck(fetchText) {
  const r = await timed(withTimeout(fetchText('https://ip.zscaler.com/'), 8000, 'ip.zscaler.com'));
  if (!r.ok) return { ok: false, error: r.error };
  const text = String(r.v).replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, '\n').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
  const lines = text.split('\n').map((s) => s.replace(/\s+/g, ' ').trim()).filter(Boolean);
  const via = lines.find((l) => /accessing (the internet|this host) via zscaler|via zscaler/i.test(l));
  const not = lines.find((l) => /not (going|accessing).*zscaler/i.test(l));
  const info = lines.filter((l) => /zscaler|proxy|cloud|data ?center|gateway|ip address/i.test(l) && l.length < 200).slice(0, 6);
  return { ok: true, viaZscaler: via ? true : not ? false : null, summary: via || not || info[0] || 'No Zscaler message on ip.zscaler.com', details: info, ms: r.ms };
}
async function dnsCheck(host) {
  const sys = await timed(withTimeout(dns.promises.lookup(host, { all: true }), 5000, 'System DNS'));
  const res = new dns.promises.Resolver(); res.setServers(['8.8.8.8', '1.1.1.1']);
  const pub = await timed(withTimeout(res.resolve4(host), 5000, 'Public DNS'));
  const sysIps = sys.ok ? sys.v.map((a) => a.address) : [];
  const pubIps = pub.ok ? pub.v : [];
  const synthetic = sysIps.filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && inCidr(ip, '100.64.0.0', 10));
  const notes = [];
  if (synthetic.length) notes.push(`System DNS returned ${synthetic.join(', ')} (100.64.0.0/10): Client Connector is answering for a ZPA application segment, so ZPA carries this name.`);
  else if (sys.ok && pub.ok && sysIps.length && !sysIps.some((ip) => pubIps.includes(ip))) notes.push('System and public DNS disagree: split DNS, a local override or an internal record.');
  if (sys.ok && !pub.ok) notes.push('Public DNS has no answer: internal-only name.');
  if (!sys.ok) notes.push(`System DNS failed: ${sys.error}`);
  return { system: sys.ok ? sysIps : null, systemError: sys.ok ? null : sys.error, public: pub.ok ? pubIps : null, publicError: pub.ok ? null : pub.error, synthetic: synthetic.length > 0, notes, ms: sys.ms };
}
function tcpCheck(host, port, ms = 5000) {
  return timed(new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    const t = setTimeout(() => { s.destroy(); reject(new Error(`no answer on TCP ${port} after ${ms / 1000}s`)); }, ms);
    s.once('connect', () => { clearTimeout(t); const a = s.remoteAddress; s.end(); resolve(a); });
    s.once('error', (e) => { clearTimeout(t); reject(e); });
  }));
}
function tlsCheck(host, port = 443, ms = 6000) {
  return timed(new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, servername: /^\d+\.\d+\.\d+\.\d+$/.test(host) ? undefined : host, rejectUnauthorized: false });
    const t = setTimeout(() => { s.destroy(); reject(new Error(`TLS handshake timed out after ${ms / 1000}s`)); }, ms);
    s.once('secureConnect', () => {
      clearTimeout(t);
      const c = s.getPeerCertificate(true) || {};
      const chain = []; let x = c; const seen = new Set();
      while (x && x.subject && !seen.has(x.fingerprint256)) { seen.add(x.fingerprint256); chain.push({ subject: x.subject.CN || x.subject.O, issuer: (x.issuer && (x.issuer.O || x.issuer.CN)) || null }); x = x.issuerCertificate; }
      resolve({ issuer: (c.issuer && [c.issuer.O, c.issuer.CN].filter(Boolean).join(' / ')) || null, subject: c.subject && c.subject.CN, validTo: c.valid_to, authorized: s.authorized, authError: s.authorizationError || null, protocol: s.getProtocol(), chain: chain.slice(0, 4) });
      s.end();
    });
    s.once('error', (e) => { clearTimeout(t); reject(e); });
  }));
}
async function localChecks({ host, port, fetchText }) {
  const out = { host, port, at: Date.now() };
  const [zs, d] = await Promise.all([zscalerIpCheck(fetchText), host ? dnsCheck(host) : Promise.resolve(null)]);
  out.zscaler = zs; out.dns = d;
  if (host && port) out.tcp = await tcpCheck(host, port);
  if (host && (port === 443 || port == null)) {
    const t = await tlsCheck(host, 443);
    out.tls = t.ok ? Object.assign({ ok: true, ms: t.ms, inspected: /zscaler/i.test(JSON.stringify(t.v.chain) + t.v.issuer) }, t.v) : { ok: false, ms: t.ms, error: t.error };
  }
  return out;
}

// ---------- ZIA audit log and activation ----------
// ZIA builds one audit-log report at a time: POST a time window, poll until it isn't EXECUTING, download the CSV.
async function auditLog(client, { hours = 24, wait = 60000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const end = Date.now(), start = end - Math.max(1, Math.min(hours, 24 * 30)) * 3600e3;
  try { await client.request('POST', '/zia/api/v1/auditlogEntryReport', { body: { startTime: start, endTime: end } }); }
  catch (e) {
    if (e.status === 409 || /in progress|already/i.test(e.message)) { await client.request('DELETE', '/zia/api/v1/auditlogEntryReport').catch(() => {}); await sleep(1000); await client.request('POST', '/zia/api/v1/auditlogEntryReport', { body: { startTime: start, endTime: end } }); }
    else throw e;
  }
  const t0 = Date.now(); let st = null, reposted = false;
  for (;;) {
    await sleep(1500);
    st = await client.request('GET', '/zia/api/v1/auditlogEntryReport').catch((e) => ({ status: e.status === 404 ? 'NOT_FOUND' : 'ERROR', errorMessage: e.message }));
    let s = String((st && st.status) || '').toUpperCase();
    // Right after the request ZIA can answer 404 "No Report to download" until the report is registered: keep polling,
    // and ask for the report once more if it still isn't there after a few seconds.
    if (s === 'NOT_FOUND') {
      if (!reposted && Date.now() - t0 > 6000) { reposted = true; await client.request('POST', '/zia/api/v1/auditlogEntryReport', { body: { startTime: start, endTime: end } }).catch(() => {}); }
      if (Date.now() - t0 < 20000) continue;
      throw Object.assign(new Error('ZIA did not create the audit log report (404 "No Report to download"). The API client may need the audit log permission in ZIA (admin role → Audit Logs).'), { status: 502 });
    }
    if (s === 'COMPLETE' || s === 'COMPLETED') break;
    if (s && s !== 'EXECUTING' && s !== 'IN_PROGRESS') throw Object.assign(new Error(`Audit log report ${s}: ${(st && (st.errorMessage || st.errorCode)) || ''}`.trim()), { status: 502 });
    if (Date.now() - t0 > wait) throw Object.assign(new Error('The audit log report is still building. Try again in a minute, or pick a shorter time range.'), { status: 504 });
  }
  const csv = await client.request('GET', '/zia/api/v1/auditlogEntryReport/download', { headers: { Accept: 'text/csv, application/octet-stream, */*' } });
  return Object.assign(parseAuditCsv(typeof csv === 'string' ? csv : JSON.stringify(csv)), { start, end });
}
function csvRows(text) {
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) { if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += ch; continue; }
    if (ch === '"') q = true; else if (ch === ',') { row.push(cell); cell = ''; } else if (ch === '\n' || ch === '\r') { if (ch === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; } else cell += ch;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((c) => c.trim()));
}
// The report starts with a few title lines; the header row is the first with Time/Action-style columns.
function parseAuditCsv(text) {
  const rows = csvRows(String(text || '').replace(/^﻿/, ''));
  const hi = rows.findIndex((r) => r.length >= 4 && r.some((c) => /time/i.test(c)) && r.some((c) => /action|admin|user/i.test(c)));
  if (hi < 0) return { columns: [], entries: [] };
  const columns = rows[hi].map((c) => c.trim());
  const entries = rows.slice(hi + 1).filter((r) => r.length >= Math.min(3, columns.length)).map((r) => Object.fromEntries(columns.map((c, i) => [c, (r[i] || '').trim()])));
  return { columns, entries };
}
function filterAudit(entries, q) {
  const t = lc(q).trim();
  if (!t) return entries;
  const words = t.split(/\s+/);
  return entries.filter((e) => { const s = lc(Object.values(e).join(' ')); return words.every((w) => s.includes(w)); });
}
async function activationStatus(client) {
  const r = await client.get('/zia/api/v1/status');
  return (r && r.status) || null;
}

module.exports = { listDevices, deviceDetails, deviceSummary, deviceHealth, deviceWarnings, zpaPathHealth, zpaTenantHealth, localChecks, dnsCheck, auditLog, parseAuditCsv, filterAudit, activationStatus, PLATFORM_OF };
