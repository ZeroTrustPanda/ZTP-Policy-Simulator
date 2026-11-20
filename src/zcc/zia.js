'use strict';
// From ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission;
// ported to CommonJS for the Zscaler Policy Troubleshooting Toolkit.
// ZIA-specific analysis over a parsed timeline.
//
// ZIA traffic is handled by ZSATunnel. Each intercepted TCP connection gets a
// random connection id and every line about it is prefixed "ID=<n>, ":
//   ===> ID=9, TUN-Proxy: connection to 203.0.113.5 ... dst_port=443     (transparent, from the tun adapter)
//   ===> ID=9, LCL-Proxy: connection from 127.0.0.1:54391 ...              (explicit proxy to 127.0.0.1:9000)
//   ID=9, HTTPS, SNI-Host=example.org / readFromClient: Host Address: host:port
//   ID=9, PAC Parse Action: Proxy: 198.51.100.1 | Direct
//   ID=9, Forwarding connection for ... to packet modifier                  (sent through Z-Tunnel 2.0)
//   ID=9, Tunnel to SME for host=..., SME IP=...                            (HTTP CONNECT to the gateway)
//   ID=9, SME response: Version: HTTP/1.1 Status: 200 Reason: ...
//   ===> ID=9, ~ZTCPServerConnection state=closed ... clt_bytes=1070, srv_bytes=5042!
// ZDX synthetic probes arrive as LCL-Proxy CONNECTs carrying an X-UPM header; ones
// for ZPA apps are handed to ZPN ("Offloading ZDX request to Zpn") and excluded.
// The same ids are used for ZPA app connections ("ZPN Connection local:...");
// those are excluded here because the ZPA views cover them.

const FLOW_RX = /^(?:===> )?ID=(\d+), (.*)$/s;
const EXC_RX = /^Unexpected exception \(TcpConnection run for ID: (\d+)\): (.*)$/;
const START_TUN_RX = /^TUN-Proxy: connection to (\S+) sock-fd=\d+, src_port=(\d+), dst_port=(\d+)/;
const START_LCL_RX = /^LCL-Proxy: connection from (\S+) /;
const CLOSE_RX = /^~ZTCPServerConnection state=closed .*?clt_bytes=(\d+), srv_bytes=(\d+)/;
const SNI_RX = /^HTTPS, SNI-Host=(\S+)/;
const HOST_RX = /^readFromClient: Host Address: (\S+)/;
const HTTP_RX = /^HTTP Request Version: \S+ Host=(\S+) Method=(\S+)/;
const PAC_RX = /^PAC Parse Action: (Proxy|Direct)(?:: (\S+))?/;
const SME_TUNNEL_RX = /^Tunnel to SME for host=(\S+), SME IP=(\S+)/;
const SME_RESP_RX = /^SME response: Version: \S+ Status: (\d+) Reason: (.*)$/;
const ZIA_STATE_RX = /^Changing ZIA state from: (\S+) to (\S+)/;
const PROXY_HEALTH_RX = /^ZPHM: Changing proxy state from: \[(\S+)\] to \[(\S+)\]/;
const TET_RX = /^TET:(ZIA_T[12]): (\w+)/;
const GW_LIST_RX = /^refreshSMEIpFromPac: Proxy List \(pacRequestType= (\d+)\): (.*)$/;
const GW_ITEM_RX = /\{IP: \[([^\]]+)\] Port: \[(\d+)\] SNISuffix: \[([^\]]*)\]\}/g;
const FWD_RX = /^Updating forwarding profile to: \((\w+)\) (\{.*\})/s;
const HEALTH_START_RX = /^checkTunTcpEchoServerUpImpl: Connecting to (\S+) for (ZIA|ZPA) health check/;
const HEALTH_OK_RX = /^checkTunTcpEchoServerUpImpl: service: (ZIA|ZPA) Got signal\. Server is up/;
const HEALTH_ERR_RX = /^Error connecting to tcp echo server/;
const API_RX = /^Tunnel api request: (\{.*?\}) response: (\{.*\})\s*$/s;
const ZIA_OFF_BYPASS_RX = /^getTunnelRequestTypeJson: ZIA is not enabled or is Turned Off/;
const NOTIFY_RX = /notifyUser: Received notification ID (\d+) - message=(.*)$/;

const INTERNAL_HOST_RX = /^(127\.0\.0\.1|localhost|::1)(:|$)/;

// Forwarding-profile keys worth showing; the rest stays in the raw JSON.
const PROFILE_KEYS = [
  'primaryTransport',
  'allowTLSFallback',
  'DTLSTimeout',
  'TLSTimeout',
  'enablePacketTunnel',
  'pathMtuDiscovery',
  'dropIpv6Traffic',
  'blockUnreachableDomainsTraffic',
  'latencyBasedZenEnablement',
  'optimiseForUnstableConnections',
];

function analyzeZia(tl) {
  const tunnel = tl.comps.indexOf('Tunnel');
  const service = tl.comps.indexOf('Service');
  const flows = [];
  const open = new Map(); // id -> flow
  const lineFlags = []; // [entryIndex, flow] for flagging timeline lines later
  const events = [];
  const stateChanges = [];
  const gateways = new Map(); // ip -> {ip, port, sni, pacType, flows}
  const health = []; // {ts, i, service, ok}
  const pendingHealth = new Map(); // tid -> service
  const apiLookups = [];
  let profile = null;
  let ziaState = null;
  let ziaOffBypass = null; // index of last "ZIA is not enabled" line, attached to the next api lookup

  const pushEvent = (e, type, detail, severity = 'info') => events.push({ ts: e.ts, i: e.i, type, detail, severity });

  const finish = (f, reason) => {
    if (!f.endTs && reason) f.note = reason;
    open.delete(f.cid);
    classify(f);
  };

  for (let i = 0; i < tl.length; i++) {
    const c = tl.fileComp[tl.file[i]];
    if (c !== tunnel && c !== service) continue;
    const msg = tl.msg(i);
    const e = { i, ts: tl.ts[i] };

    if (c === service) {
      const n = NOTIFY_RX.exec(msg);
      // Only ZIA-related user notifications; ZPA ones go to the ZPA events.
      if (n && /Internet Security|\bZIA\b|Web Security/i.test(n[2])) pushEvent(e, 'notification', n[2].trim(), /disconnect|fail|error|unable/i.test(n[2]) ? 'warn' : 'ok');
      continue;
    }

    // --- per-connection lines
    if (msg.startsWith('ID=') || msg.startsWith('===> ID=')) {
      const m = FLOW_RX.exec(msg);
      if (!m) continue;
      const cid = m[1];
      const rest = m[2];
      let f = open.get(cid);
      let s;
      if ((s = START_TUN_RX.exec(rest))) {
        if (f) finish(f, 'id reused before close');
        f = newFlow(cid, e, 'tun', s[1], Number(s[3]));
        f.srcPort = Number(s[2]);
        open.set(cid, f);
        flows.push(f);
      } else if ((s = START_LCL_RX.exec(rest))) {
        if (f) finish(f, 'id reused before close');
        f = newFlow(cid, e, 'proxy', null, null);
        f.client = s[1];
        open.set(cid, f);
        flows.push(f);
      }
      if (!f) continue;
      lineFlags.push(i, f);
      if ((s = CLOSE_RX.exec(rest))) {
        f.endTs = e.ts;
        f.endI = i;
        f.bytesUp = Number(s[1]);
        f.bytesDown = Number(s[2]);
        finish(f);
      } else if ((s = SNI_RX.exec(rest))) f.host = s[1];
      else if ((s = HOST_RX.exec(rest))) {
        const hp = splitHostPort(s[1]);
        f.host ||= hp.host;
        if (f.port == null) f.port = hp.port;
      } else if ((s = HTTP_RX.exec(rest))) {
        f.method = s[2];
        const hp = splitHostPort(s[1]);
        f.host ||= hp.host;
        if (f.port == null) f.port = hp.port;
      } else if ((s = PAC_RX.exec(rest))) {
        f.pac = s[1] === 'Direct' ? 'DIRECT' : 'PROXY';
        if (s[2]) f.gateway = s[2];
      } else if (rest.startsWith('Forwarding connection for') && rest.includes('packet modifier')) f.path = 'zt2';
      else if ((s = SME_TUNNEL_RX.exec(rest))) {
        f.path = 'gateway';
        f.gateway = s[2].replace(/:\d+$/, '');
      } else if ((s = SME_RESP_RX.exec(rest))) {
        const code = Number(s[1]);
        if (code === 407) f.authChallenged = true;
        else {
          f.httpStatus = code;
          f.httpReason = s[2].trim();
        }
      } else if (rest.startsWith('ZPN Connection') || rest.includes('Zpn ') || rest.startsWith('Offloading ZDX request to Zpn')) f.zpa = true;
      else if (rest.startsWith('UPM Webload request found') || rest.startsWith('UPM zpa_zdx request found') || rest.startsWith('ZDX request:')) f.zdx = true;
      else if (rest.includes('EchoServerUpImpl') || rest.includes('Echo client')) f.internal = true;
      continue;
    }

    const exc = EXC_RX.exec(msg);
    if (exc) {
      const f = open.get(exc[1]);
      if (f) {
        lineFlags.push(i, f);
        // "Both client and server sockets are closed" is how every normal close ends; not an error.
        if (!/Both client and server sockets are closed/.test(exc[2])) f.error = exc[2].slice(0, 200);
      }
      continue;
    }

    // --- tunnel lifecycle
    let s;
    if ((s = ZIA_STATE_RX.exec(msg))) {
      if (s[1] !== s[2]) {
        stateChanges.push({ ts: e.ts, i, from: s[1], to: s[2] });
        pushEvent(e, 'zia-state', `ZIA ${s[1]} → ${s[2]}`, s[2] === 'ON' ? 'ok' : s[2] === 'CONNECTING' ? 'info' : 'warn');
      }
      ziaState = s[2];
    } else if ((s = PROXY_HEALTH_RX.exec(msg))) {
      if (s[1] !== s[2]) pushEvent(e, 'proxy-health', `Gateway health ${s[1]} → ${s[2]}`, s[2] === 'GOOD' ? 'ok' : 'warn');
    } else if ((s = TET_RX.exec(msg))) {
      const name = s[1] === 'ZIA_T2' ? 'Z-Tunnel 2.0' : 'Z-Tunnel 1.0';
      if (s[2] === 'established') pushEvent(e, 'tunnel', `${name} established`, 'ok');
      else if (s[2] === 'disconnected') pushEvent(e, 'tunnel', `${name} disconnected`, 'warn');
    } else if ((s = GW_LIST_RX.exec(msg))) {
      for (const g of s[2].matchAll(GW_ITEM_RX)) {
        if (!gateways.has(g[1])) gateways.set(g[1], { ip: g[1], port: Number(g[2]), sni: g[3], pacType: Number(s[1]), first: e.ts, i, flows: 0 });
      }
    } else if ((s = FWD_RX.exec(msg))) {
      try {
        const json = JSON.parse(s[2]);
        profile = { action: s[1], ts: e.ts, i, settings: Object.fromEntries(PROFILE_KEYS.filter((k) => k in json).map((k) => [k, json[k]])) };
      } catch {
        profile = { action: s[1], ts: e.ts, i, settings: {} };
      }
    } else if ((s = HEALTH_START_RX.exec(msg))) {
      pendingHealth.set(tl.tid[i], s[2]);
    } else if ((s = HEALTH_OK_RX.exec(msg))) {
      health.push({ ts: e.ts, i, service: s[1], ok: true });
      pendingHealth.delete(tl.tid[i]);
    } else if (HEALTH_ERR_RX.test(msg)) {
      const svc = pendingHealth.get(tl.tid[i]) || 'unknown';
      health.push({ ts: e.ts, i, service: svc, ok: false, detail: msg.slice(0, 160) });
      pendingHealth.delete(tl.tid[i]);
    } else if (ZIA_OFF_BYPASS_RX.test(msg)) {
      ziaOffBypass = i;
    } else if ((s = API_RX.exec(msg))) {
      try {
        const req = JSON.parse(s[1]);
        const res = JSON.parse(s[2]);
        apiLookups.push({
          ts: e.ts,
          i,
          host: req.host || hostFromUrl(req.url),
          url: req.url,
          port: req.port,
          destinationIp: res.destinationIp || '',
          gateway: res.smeIp || '',
          requestType: res.requestType,
          bypassReason: res.bypassReason ?? null,
          ziaOff: ziaOffBypass != null && i - ziaOffBypass < 40,
        });
      } catch {
        /* truncated line */
      }
      ziaOffBypass = null;
    }
  }
  for (const f of open.values()) classify(f);

  const zia = flows.filter((f) => !f.zpa && !f.internal);
  for (const f of zia) {
    if (f.gateway && gateways.has(f.gateway) && f.path !== 'direct') gateways.get(f.gateway).flows++;
  }

  return {
    info: { state: ziaState, profile, gateways: [...gateways.values()] },
    stateChanges,
    events,
    health: summarizeHealth(health),
    healthChecks: health,
    flows: zia,
    apiLookups,
    errors: ziaErrors(zia),
    // Pairs of [entryIndex, flow] so the store can tag timeline lines as ZIA.
    lineFlags,
  };
}

function newFlow(cid, e, kind, dst, port) {
  return { cid, ts: e.ts, i: e.i, kind, dst, port, host: null, pac: null, path: null, gateway: null, bytesUp: null, bytesDown: null, endTs: null };
}

function splitHostPort(hp) {
  const m = /^\[?([^\]]+?)\]?(?::(\d+))?$/.exec(hp);
  return m ? { host: m[1], port: m[2] ? Number(m[2]) : null } : { host: hp, port: null };
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || '';
  }
}

// Decide how a connection left the machine and whether it worked.
function classify(f) {
  if (f.kind === 'proxy' && f.host && INTERNAL_HOST_RX.test(f.host)) f.internal = true;
  if (!f.path) f.path = f.pac === 'DIRECT' ? 'direct' : f.pac === 'PROXY' ? 'gateway' : 'unknown';
  if (f.endTs == null) f.status = 'open';
  else if (f.httpStatus && f.httpStatus >= 400) {
    f.status = 'failed';
    f.reason = `HTTP ${f.httpStatus} ${f.httpReason || ''} from gateway`.trim();
  } else if (f.error) {
    f.status = 'failed';
    f.reason = f.error;
  } else if (f.bytesDown === 0 && f.bytesUp > 0) {
    f.status = 'failed';
    f.reason = 'no response (0 bytes received)';
  } else if (f.bytesDown === 0 && f.bytesUp === 0) {
    f.status = 'empty';
  } else f.status = 'ok';
}

function summarizeHealth(checks) {
  const out = {};
  for (const h of checks) {
    const s = (out[h.service] ||= { ok: 0, failed: 0, lastOk: null, lastFail: null });
    if (h.ok) {
      s.ok++;
      s.lastOk = h.ts;
    } else {
      s.failed++;
      s.lastFail = h.ts;
    }
  }
  return out;
}

function ziaErrors(flows) {
  const by = new Map();
  for (const f of flows) {
    if (f.status !== 'failed') continue;
    const key = f.reason.replace(/\d{3,}/g, 'N');
    let r = by.get(key);
    if (!r) by.set(key, (r = { reason: f.reason, count: 0, first: f.ts, last: f.ts, sample: f.i, hosts: new Set() }));
    r.count++;
    r.last = f.ts;
    r.hosts.add(f.host || f.dst);
  }
  return [...by.values()].map((r) => ({ ...r, hosts: [...r.hosts].slice(0, 20), hostCount: r.hosts.size })).sort((a, b) => b.count - a.count);
}

/** Aggregate ZIA connections by destination host. */
function summarizeHosts(zia) {
  const by = new Map();
  for (const f of zia.flows) {
    const key = f.host || f.dst || '(unknown)';
    let h = by.get(key);
    if (!h) {
      h = { host: key, zdx: 0, total: 0, ok: 0, failed: 0, empty: 0, open: 0, paths: {}, ports: new Set(), gateways: new Set(), bytesUp: 0, bytesDown: 0, first: f.ts, last: f.ts, reasons: {}, ips: new Set() };
      by.set(key, h);
    }
    h.total++;
    h[f.status]++;
    if (f.zdx) h.zdx++;
    h.paths[f.path] = (h.paths[f.path] || 0) + 1;
    if (f.port != null) h.ports.add(f.port);
    if (f.gateway && f.path !== 'direct') h.gateways.add(f.gateway);
    if (f.dst) h.ips.add(f.dst);
    h.bytesUp += f.bytesUp || 0;
    h.bytesDown += f.bytesDown || 0;
    if (f.status === 'failed') h.reasons[f.reason] = (h.reasons[f.reason] || 0) + 1;
    h.last = f.ts;
  }
  return [...by.values()]
    .map((h) => ({
      ...h,
      ports: [...h.ports].sort((a, b) => a - b),
      gateways: [...h.gateways],
      ips: [...h.ips].slice(0, 10),
      mainPath: Object.entries(h.paths).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown',
      topReason: Object.entries(h.reasons).sort((a, b) => b[1] - a[1])[0]?.[0] ?? null,
    }))
    .sort((a, b) => b.total - a.total);
}

module.exports = { analyzeZia, summarizeHosts };
