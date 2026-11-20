'use strict';
// From ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission;
// ported to CommonJS for the Zscaler Policy Troubleshooting Toolkit.
// ZPA-specific analysis over a parsed timeline.
//
// Everything here is derived from the ZSATunnel log. The broker <-> client
// protocol is logged as JSON objects:
//   received:  "ZPN:0: Control Message Response Data: {"zpn_x": {...}}"
//   sent:      "Writing Mtunnel request: Size: N Data: { "zpn_mtunnel_request": {...} }"
// We extract those objects and build sessions, app segments and mtunnels.

const { describeError, isFailureCode } = require('./errors');

const JSON_MSG_RX = /(Control Message Response Data|Data):\s*(\{[\s\S]*\})\s*$/;
const ZAPP_STATUS_RX =
  /^ZApp Status: getCurrentNetworkType:(\S+) getSmeProxyState:\s*(\S+) getZpnProxyState:(\S+) getZpnAuthState:(\S+) broker:(\S*) protocol:(\S*) type:(.*)$/;
const SETUP_TIME_RX = /^zpn_mtunnel_request_ack (?:error: \S+ protocol: \d+ )?tag_id: (\d+).*?Setup Time: ([\d.]+) seconds/;
const SERVICE_VERSION_RX = /Starting (?:Service|Tunnel)? ?version ([\d.]+)/i;
const NOTIFY_RX = /notifyUser: Received notification ID \d+ - message=(.*)$/;
const FWD_PROFILE_RX = /^Updating forwarding profile to: \((\w+)\)/;

/** Pull the embedded ZPN JSON object out of a log message, if any. */
function extractZpnMessage(msg) {
  if (!msg.includes('zpn_') && !msg.includes('fohh_')) return null;
  const m = JSON_MSG_RX.exec(msg);
  if (!m) return null;
  let obj;
  try {
    obj = JSON.parse(m[2]);
  } catch {
    return null;
  }
  const type = Object.keys(obj)[0];
  if (!type || typeof obj[type] !== 'object') return null;
  return { type, dir: m[1] === 'Control Message Response Data' ? 'in' : 'out', body: obj[type] };
}

const PROTO = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };

function domainKind(d) {
  if (d.includes('/')) return 'cidr';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d) || d.includes(':')) return 'ip';
  if (d.startsWith('.') || d.startsWith('*.')) return 'wildcard';
  return 'fqdn';
}

function pairs(arr) {
  const out = [];
  if (!Array.isArray(arr)) return out;
  for (let i = 0; i + 1 < arr.length; i += 2) out.push([arr[i], arr[i + 1]]);
  return out;
}

function formatRanges(arr) {
  const p = pairs(arr);
  if (!p.length) return '';
  if (p.length === 1 && p[0][0] <= 1 && p[0][1] >= 65535) return 'all';
  return p.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(', ');
}

function portIn(arr, port) {
  return pairs(arr).some(([a, b]) => port >= a && port <= b);
}

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !(x >= 0 && x <= 255))) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function cidrContains(cidr, ip) {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const b = ipToInt(base);
  const i = ipToInt(ip);
  if (b === null || i === null || !(bits >= 0 && bits <= 32)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (b & mask) === (i & mask);
}

/**
 * Find the app-segment domain the client would match for a destination.
 * This mirrors ZPA's most-specific-match behaviour as closely as the client
 * side data allows; it is an approximation, not the broker's policy decision.
 */
function matchSegment(segments, appName, port, proto) {
  const name = String(appName || '').toLowerCase();
  const isIp = ipToInt(name) !== null;
  let best = null;
  let bestScore = -1;
  for (const s of segments) {
    const d = s.domain.toLowerCase();
    let score = -1;
    if (s.kind === 'fqdn' && d === name) score = 1000 + d.length;
    else if (s.kind === 'ip' && d === name) score = 900;
    else if (s.kind === 'wildcard') {
      const suffix = d.startsWith('*.') ? d.slice(1) : d;
      if (!isIp && name.endsWith(suffix)) score = 500 + suffix.length;
    } else if (s.kind === 'cidr' && isIp && cidrContains(d, name)) score = 100 + Number(d.split('/')[1]);
    if (score > bestScore) {
      bestScore = score;
      best = s;
    }
  }
  if (!best) return null;
  const ranges = proto === 17 ? best.udp : best.tcp;
  const portOk = port == null || proto === 1 ? true : portIn(ranges, port);
  return { domain: best.domain, portOk };
}

/** Build the full ZPA analysis for a dataset. */
function analyzeZpa(tl) {
  const sessions = []; // broker connections (one per authenticate_ack)
  const events = []; // notable ZPA lifecycle events
  const states = []; // ZApp Status transitions
  const segBatches = []; // app segment downloads / updates
  const mtunnels = [];
  const dnsChecks = [];
  const zpnErrors = new Map(); // error code -> {count, first, last, sample, types}
  const info = { versions: new Set(), forwardingProfile: null, tunnelIds: new Set(), publicIps: new Set() };

  const segState = new Map(); // domain -> current segment record
  const segHistory = new Map(); // domain -> [{ts, i, change, ...}]
  let openBatch = null;
  let currentSession = null;
  const openMt = new Map(); // tag_id -> mtunnel
  const pendingDns = new Map();
  let lastState = null;

  const pushEvent = (e, type, detail, severity = 'info', extra = {}) =>
    events.push({ ts: e.ts, i: e.i, type, detail, severity, ...extra });

  const noteError = (e, code, type, err_code) => {
    if (!code) return;
    let rec = zpnErrors.get(code);
    if (!rec) {
      rec = { code, count: 0, first: e.ts, last: e.ts, sample: e.i, types: new Set(), err_code, ...describeError(code) };
      zpnErrors.set(code, rec);
    }
    rec.count++;
    rec.last = e.ts;
    rec.types.add(type);
  };

  // Domains received since the last full download started; a completed
  // download is a full snapshot, so anything not re-sent has been removed.
  let sinceSnapshot = new Set();
  const closeBatch = (complete, e) => {
    let b = openBatch;
    openBatch = null;
    if (!b && complete) {
      // The last zpn_client_app (has_next: 0) usually closes the batch right
      // before zpn_client_app_complete arrives; fold the two together.
      const last = segBatches[segBatches.length - 1];
      if (last && !last.complete && e.ts - last.ts < 30000) b = segBatches.pop();
      else b = { ts: e.ts, i: e.i, apps: [], removed: [], complete: false };
    }
    if (!b) return;
    b.complete = complete;
    if (complete) {
      for (const d of [...segState.keys()]) {
        if (!sinceSnapshot.has(d)) {
          segState.delete(d);
          addHistory(d, { ts: b.ts, i: b.i, change: 'removed', reason: 'not in new download' });
          b.removed.push(d);
        }
      }
      sinceSnapshot = new Set();
    }
    segBatches.push(b);
  };

  const addHistory = (domain, h) => {
    if (!segHistory.has(domain)) segHistory.set(domain, []);
    segHistory.get(domain).push(h);
  };

  const finishMt = (mt, status, reason, e) => {
    mt.status = status;
    if (reason) mt.reason = reason;
    if (e) {
      mt.endTs = e.ts;
      mt.endI = e.i;
    }
    openMt.delete(mt.tag);
  };

  const tunnel = tl.comps.indexOf('Tunnel');
  const service = tl.comps.indexOf('Service');
  for (let i = 0; i < tl.length; i++) {
    const c = tl.fileComp[tl.file[i]];
    if (c !== tunnel && c !== service) continue;
    const e = { i, ts: tl.ts[i], msg: tl.msg(i) };
    if (c === service) {
      const v = SERVICE_VERSION_RX.exec(e.msg);
      if (v) info.versions.add(v[1]);
      const n = NOTIFY_RX.exec(e.msg);
      if (n && /Private Access|\bZPA\b/i.test(n[1])) pushEvent(e, 'notification', n[1].trim(), /disconnect|fail|error|unable|required/i.test(n[1]) ? 'warn' : 'ok');
      continue;
    }
    const msg = e.msg;

    // --- Tunnel state heartbeat; record only transitions.
    if (msg.startsWith('ZApp Status:')) {
      const m = ZAPP_STATUS_RX.exec(msg);
      if (m) {
        const st = { network: m[1], zia: m[2], zpn: m[3], auth: m[4], broker: m[5], protocol: m[6], tunnelType: m[7].trim() };
        const key = `${st.network}|${st.zpn}|${st.auth}|${st.broker}|${st.protocol}|${st.zia}`;
        if (!lastState || lastState.key !== key) {
          states.push({ ts: e.ts, i: e.i, ...st, key });
          if (lastState) {
            const changes = [];
            if (lastState.zpn !== st.zpn) changes.push(`ZPA ${lastState.zpn} → ${st.zpn}`);
            if (lastState.auth !== st.auth) changes.push(`auth ${lastState.auth} → ${st.auth}`);
            if (lastState.broker !== st.broker) changes.push(`broker ${lastState.broker || '—'} → ${st.broker || '—'}`);
            if (lastState.network !== st.network) changes.push(`network ${lastState.network} → ${st.network}`);
            if (lastState.protocol !== st.protocol) changes.push(`protocol ${lastState.protocol} → ${st.protocol}`);
            if (lastState.zia !== st.zia) changes.push(`ZIA ${lastState.zia} → ${st.zia}`);
            const bad = st.zpn !== 'TUNNEL_FORWARDING' || st.auth !== 'AUTHENTICATED';
            pushEvent(e, 'state', changes.join(', '), bad ? 'warn' : 'ok');
          }
          lastState = { ...st, key };
        }
      }
      continue;
    }

    const fp = FWD_PROFILE_RX.exec(msg);
    if (fp) {
      info.forwardingProfile = fp[1];
      continue;
    }
    if (msg.startsWith('closeZpnSocket called')) {
      pushEvent(e, 'socket-close', msg.replace('closeZpnSocket called!! ', ''), 'warn');
      if (currentSession && !currentSession.end) {
        currentSession.end = e.ts;
        currentSession.endI = e.i;
      }
      continue;
    }
    if (msg.includes('ZPN Socket connect success to broker!!') && !msg.includes('Starting ssl')) {
      pushEvent(e, 'socket-connect', 'TCP connection to broker established', 'ok');
      continue;
    }
    const st = SETUP_TIME_RX.exec(msg);
    if (st) {
      const mt = findMt(mtunnels, Number(st[1]));
      if (mt && mt.setupMs == null) mt.setupMs = Number(st[2]) * 1000;
      continue;
    }

    const z = extractZpnMessage(msg);
    if (!z) continue;
    const b = z.body;

    if (z.dir === 'in' && b.error && typeof b.error === 'string' && z.type !== 'zpn_np_config') {
      noteError(e, b.error, z.type, b.err_code);
    }

    switch (z.type) {
      case 'zpn_version':
        if (b.ver_str) info.versions.add(b.ver_str);
        break;
      case 'zpn_broker_redirect':
        pushEvent(e, 'redirect', `Redirected to ${(b.brokers || []).join(', ')}`, 'info', {
          reason: b.reason,
          brokers: (b.brokers || []).map((name, k) => ({ name, ...(b.brokers_info?.[k]?.zpn_instance_info || {}) })),
          pubIp: b.pub_ip,
        });
        if (b.pub_ip) info.publicIps.add(b.pub_ip);
        break;
      case 'zpn_client_authenticate_ack': {
        const ok = !b.error;
        if (currentSession && !currentSession.end) {
          currentSession.end = e.ts;
          currentSession.endI = e.i;
          currentSession.endReason = 'superseded';
        }
        currentSession = {
          start: e.ts,
          i: e.i,
          broker: b.current_broker || '',
          tunnelId: b.tunnel_id || '',
          pubIp: b.pub_ip || '',
          error: b.error || null,
          mtunnels: 0,
          failed: 0,
        };
        sessions.push(currentSession);
        sinceSnapshot = new Set(); // a new broker session re-downloads all segments
        if (b.tunnel_id) info.tunnelIds.add(b.tunnel_id);
        if (b.pub_ip) info.publicIps.add(b.pub_ip);
        pushEvent(e, 'auth', ok ? `Authenticated to ${b.current_broker}` : `Authentication failed: ${b.error}`, ok ? 'ok' : 'error', {
          broker: b.current_broker,
          tunnelId: b.tunnel_id,
        });
        break;
      }
      case 'zpn_client_app': {
        if (!openBatch) {
          openBatch = { ts: e.ts, i: e.i, apps: [], removed: [], complete: false };
        }
        const domain = b.app_domain;
        const rec = {
          domain,
          kind: domainKind(domain),
          tcp: b.tcp_port_ranges || [],
          udp: b.udp_port_ranges || [],
          tcpText: formatRanges(b.tcp_port_ranges),
          udpText: formatRanges(b.udp_port_ranges),
          bypass: !!b.bypass,
          bypassType: b.bypass_type || '',
          bypassOnReauth: !!b.bypass_on_reauth,
          doubleEncrypt: !!b.double_encrypt,
          icmp: b.icmp_access_type || '',
          deleted: !!b.deleted,
          ts: e.ts,
          i: e.i,
        };
        openBatch.apps.push(rec);
        sinceSnapshot.add(domain);
        const prev = segState.get(domain);
        if (rec.deleted) {
          if (prev) segState.delete(domain);
          addHistory(domain, { ts: e.ts, i: e.i, change: 'deleted' });
        } else {
          const changed = !prev ? 'added' : diffSegment(prev, rec);
          segState.set(domain, { ...rec, firstSeen: prev?.firstSeen ?? e.ts, updates: (prev?.updates ?? 0) + (changed ? 1 : 0) });
          if (changed) addHistory(domain, { ts: e.ts, i: e.i, change: changed, tcp: rec.tcpText, udp: rec.udpText });
        }
        if (!b.has_next) closeBatch(false, e); // end of this batch (download or incremental update)
        break;
      }
      case 'zpn_client_app_complete':
        closeBatch(true, e);
        pushEvent(e, 'apps', `App segment download complete (${segState.size} domains)`, 'ok');
        break;
      case 'zpn_mtunnel_request': {
        const tag = b.tag_id;
        // Newer builds send ip_protocol + server_port; older ones send tcp_server_port / udp_server_port.
        const protoNum = b.ip_protocol ?? (b.udp_server_port != null ? 17 : b.tcp_server_port != null ? 6 : null);
        const port = b.server_port ?? b.tcp_server_port ?? b.udp_server_port ?? null;
        const stale = openMt.get(tag);
        if (stale) finishMt(stale, 'unknown', 'tag reused before completion');
        const mt = {
          id: mtunnels.length,
          tag,
          app: b.app_name,
          appType: b.app_type,
          proto: protoNum == null ? '?' : PROTO[protoNum] || String(protoNum),
          protoNum,
          port,
          dip: b.o_dip,
          sport: b.o_sport,
          doubleEncrypt: !!b.double_encrypt,
          probe: b.zpn_probe_type ?? null,
          ts: e.ts,
          i: e.i,
          status: 'pending',
          session: sessions.length - 1,
        };
        mtunnels.push(mt);
        openMt.set(tag, mt);
        if (currentSession) currentSession.mtunnels++;
        break;
      }
      case 'zpn_mtunnel_request_ack': {
        const mt = openMt.get(b.tag_id);
        if (!mt) break;
        mt.ackTs = e.ts;
        mt.ackI = e.i;
        mt.mtunnelId = b.mtunnel_id;
        if (mt.setupMs == null) mt.setupMs = e.ts - mt.ts;
        if (b.error) {
          mt.errCode = b.err_code;
          finishMt(mt, 'failed', b.error, e);
          if (currentSession) currentSession.failed++;
        } else {
          mt.status = 'established';
        }
        break;
      }
      case 'zpn_mtunnel_end': {
        if (z.dir === 'out') {
          const mt = openMt.get(b.tag_id);
          if (mt) finishMt(mt, mt.status === 'established' ? 'closed' : 'failed', b.error || 'closed by client', e);
          break;
        }
        const mt = openMt.get(b.tag_id);
        if (!mt) break;
        const failed = mt.status !== 'established' || isFailureCode(b.error);
        if (failed && currentSession) currentSession.failed++;
        mt.errCode = mt.errCode ?? b.err_code;
        finishMt(mt, failed ? 'failed' : 'closed', b.error || null, e);
        break;
      }
      case 'zpn_dns_client_check': {
        if (z.dir === 'out') {
          pendingDns.set(b.id, { ts: e.ts, i: e.i, name: b.name, type: b.type });
        } else {
          const req = pendingDns.get(b.id);
          pendingDns.delete(b.id);
          dnsChecks.push({
            ts: e.ts,
            i: e.i,
            reqI: req?.i,
            name: b.name,
            type: b.type,
            result: b.error || (b.has_a || b.has_aaaa ? 'FOUND' : 'NO_RECORDS'),
            hasA: !!b.has_a,
            hasAAAA: !!b.has_aaaa,
            latencyMs: req ? e.ts - req.ts : null,
          });
        }
        break;
      }
      case 'zpn_posture_profile_ack':
        pushEvent(e, 'posture', `Posture profile acknowledged (${b.id_str || '?'})`, 'info');
        break;
      case 'zpn_trusted_networks_ack':
        pushEvent(e, 'trusted-net', `Trusted networks acknowledged`, 'info');
        break;
      case 'zpn_client_app_registration_notification':
        if (b.error_code && b.error_code !== 'FQDN_EMPTY') pushEvent(e, 'c2c', `Client-to-client registration: ${b.error_code}`, 'warn');
        break;
      default:
        break;
    }
  }
  if (openBatch) closeBatch(false);
  // Anything still open at the end of the logs never got a response we can see.
  for (const mt of openMt.values()) if (mt.status === 'pending') mt.reason = 'no response in logs';

  const segments = [...segState.values()].sort((a, b) => a.domain.localeCompare(b.domain));
  // Annotate mtunnels with the segment they match and roll up per-segment stats.
  const segStats = new Map(segments.map((s) => [s.domain, { mtunnels: 0, failed: 0 }]));
  for (const mt of mtunnels) {
    const match = matchSegment(segments, mt.app, mt.port, mt.protoNum);
    mt.segment = match?.domain ?? null;
    mt.portInSegment = match ? match.portOk : null;
    if (match) {
      const s = segStats.get(match.domain);
      s.mtunnels++;
      if (mt.status === 'failed') s.failed++;
    }
  }
  for (const s of segments) Object.assign(s, segStats.get(s.domain));

  return {
    info: {
      versions: [...info.versions],
      forwardingProfile: info.forwardingProfile,
      tunnelIds: [...info.tunnelIds],
      publicIps: [...info.publicIps],
      lastState: lastState ? { ...lastState, key: undefined } : null,
    },
    sessions,
    events,
    states,
    segments,
    segmentHistory: Object.fromEntries(segHistory),
    segmentBatches: segBatches.map((b) => ({
      ts: b.ts,
      i: b.i,
      complete: b.complete,
      count: b.apps.length,
      domains: b.apps.map((a) => (a.deleted ? `-${a.domain}` : a.domain)),
      removed: b.removed,
    })),
    mtunnels,
    dnsChecks,
    zpnErrors: [...zpnErrors.values()].map((r) => ({ ...r, types: [...r.types] })).sort((a, b) => b.count - a.count),
  };
}

function findMt(mtunnels, tag) {
  for (let k = mtunnels.length - 1; k >= 0 && k > mtunnels.length - 500; k--) if (mtunnels[k].tag === tag) return mtunnels[k];
  return null;
}

function diffSegment(prev, next) {
  const parts = [];
  if (prev.tcpText !== next.tcpText) parts.push(`TCP ${prev.tcpText || '—'} → ${next.tcpText || '—'}`);
  if (prev.udpText !== next.udpText) parts.push(`UDP ${prev.udpText || '—'} → ${next.udpText || '—'}`);
  if (prev.bypassType !== next.bypassType) parts.push(`bypass ${prev.bypassType} → ${next.bypassType}`);
  if (prev.doubleEncrypt !== next.doubleEncrypt) parts.push(`double encrypt ${next.doubleEncrypt ? 'on' : 'off'}`);
  if (prev.icmp !== next.icmp) parts.push(`ICMP ${prev.icmp} → ${next.icmp}`);
  return parts.length ? `changed: ${parts.join('; ')}` : null;
}

/** Aggregate mtunnels by destination app. */
function summarizeApps(zpa) {
  const by = new Map();
  for (const mt of zpa.mtunnels) {
    const key = mt.app;
    let a = by.get(key);
    if (!a) {
      a = { app: key, appType: mt.appType, total: 0, established: 0, closed: 0, failed: 0, pending: 0, reasons: {}, ports: new Set(), protos: new Set(), setup: [], first: mt.ts, last: mt.ts, segment: mt.segment, portMismatch: 0 };
      by.set(key, a);
    }
    a.total++;
    if (mt.status === 'failed') a.failed++;
    else if (mt.status === 'closed') a.closed++;
    else if (mt.status === 'established') a.established++;
    else a.pending++;
    if (mt.status === 'failed' && mt.reason) a.reasons[mt.reason] = (a.reasons[mt.reason] || 0) + 1;
    if (mt.port != null) a.ports.add(`${mt.proto}/${mt.port}`);
    a.protos.add(mt.proto);
    if (mt.setupMs != null && mt.status !== 'failed') a.setup.push(mt.setupMs);
    if (mt.portInSegment === false) a.portMismatch++;
    a.last = mt.ts;
  }
  return [...by.values()]
    .map((a) => {
      const s = a.setup.sort((x, y) => x - y);
      return {
        ...a,
        ports: [...a.ports],
        protos: [...a.protos],
        setup: undefined,
        setupP50: s.length ? s[Math.floor(s.length * 0.5)] : null,
        setupP95: s.length ? s[Math.min(s.length - 1, Math.floor(s.length * 0.95))] : null,
        topReason: Object.entries(a.reasons).sort((x, y) => y[1] - x[1])[0]?.[0] ?? null,
      };
    })
    .sort((x, y) => y.total - x.total);
}

module.exports = { extractZpnMessage, domainKind, formatRanges, matchSegment, analyzeZpa, summarizeApps };
