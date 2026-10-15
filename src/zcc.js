'use strict';
// Client Connector forwarding evaluation, per app profile.
// Field names follow the portal / public API shapes verified in the ZTP Policy Wizard
// (zcc-windows-profile-template.json, zcc-mac-profile-template.json, zcc-fwd-profile-template.json):
//   app profile:   packetTunnelIncludeList / packetTunnelExcludeList            (IPv4 include / exclude)
//                  packetTunnelDnsIncludeList / packetTunnelDnsExcludeList      (domain include / exclude)
//                  vpnGateways (VPN gateway bypass), sourcePortBasedBypasses, appServiceIds / bypassAppIds,
//                  pac_url, onNetPolicy / forwardingProfileId, groupAll / groupNames / userNames
//                  Settings appear flat (arrays) and/or under policyExtension (comma strings) — both are read.
//   fwd profile:   forwardingProfileActions[] { networkType 0..3, actionType 0 None | 1 Tunnel |
//                  2 Tunnel with local proxy | 3 Enforce proxy, enablePacketTunnel, customPac, systemProxyData.pacURL }

const M = require('./matchers');

const NET = { 0: 'On-Trusted', 1: 'VPN-Trusted', 2: 'Off-Trusted', 3: 'Split VPN-Trusted' };
const ACTION = { 0: 'None', 1: 'Tunnel', 2: 'Tunnel with local proxy', 3: 'Enforce proxy' };

const arr = (x) => (Array.isArray(x) ? x : x == null || x === '' ? [] : [x]);
function list(p, key) {
  // union of flat array and policyExtension comma string
  const out = [];
  const add = (v) => {
    if (Array.isArray(v)) v.forEach(add);
    else if (typeof v === 'string') v.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean).forEach((s) => out.push(s));
    else if (v && typeof v === 'object' && (v.value || v.label)) add(String(v.value || v.label));
  };
  add(p[key]);
  if (p.policyExtension) add(p.policyExtension[key]);
  return [...new Set(out.map((s) => s.replace(/^\[|\]$/g, '')))];
}

function hostMatches(t, entries) {
  // entries can be domains (with * / leading dot) or IPs/CIDRs
  const names = entries.filter((e) => !M.parseIpRange(e));
  if (!t || t.isIp || !names.length) return null;
  if (names.includes('*')) return { rel: 'match', entry: '*' };
  const r = M.domainInList(t, names);
  return r.rel === 'none' ? null : r;
}
function ipMatches(ips, entries) {
  const nets = entries.filter((e) => M.parseIpRange(e));
  if (!nets.length) return null;
  let partial = null;
  for (const ip of ips) {
    const r = M.ipInList(ip, nets);
    if (r.rel === 'match') return r;
    if (r.rel === 'partial') partial = r;
  }
  return partial;
}

function appServiceRanges(svc) {
  // webAppService entries: collect anything that parses as an IP range, from any field
  const out = [];
  const walk = (v) => {
    if (typeof v === 'string') { for (const s of v.split(/[\s,;]+/)) if (M.parseIpRange(s)) out.push(s); }
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(svc);
  return out;
}

function profileAppliesTo(p, ctx) {
  const groups = arr(p.groupNames).concat(arr(p.groups).map((g) => g && g.name)).filter(Boolean);
  const users = arr(p.userNames).concat(arr(p.users).map((u) => u && (u.name || u.loginName))).filter(Boolean);
  const all = String(p.groupAll) === '1' || p.groupAll === true || (!groups.length && !users.length);
  const label = all ? 'all users' : [...groups.map((g) => 'group ' + g), ...users.map((u) => 'user ' + u)].slice(0, 4).join(', ');
  let match = 'unknown';
  if (all) match = 'yes';
  else if (ctx.user || (ctx.groups || []).length) {
    const u = String(ctx.user || '').toLowerCase();
    match = users.some((x) => String(x).toLowerCase() === u) || groups.some((g) => (ctx.groups || []).some((x) => x.toLowerCase() === String(g).toLowerCase())) ? 'yes' : 'no';
  }
  return { all, label, match };
}

function findFwdProfile(p, fwds) {
  const id = (p.onNetPolicy && p.onNetPolicy.id) || p.forwardingProfileId || (p.forwardingProfile && p.forwardingProfile.id);
  const name = (p.onNetPolicy && p.onNetPolicy.name) || (p.forwardingProfile && p.forwardingProfile.name);
  return fwds.find((f) => (id != null && String(f.id) === String(id)) || (name && f.name === name)) || null;
}

function runPac(text, ctx, opts) {
  try {
    const url = (ctx.target && (ctx.target.raw || ctx.target.host)) || '';
    const res = M.evalPac(text, /^[a-z]+:\/\//i.test(url) ? url : (ctx.port === 80 ? 'http://' : 'https://') + url, null, opts);
    return { result: res, direct: /^\s*DIRECT/i.test(res) };
  } catch (e) { return { error: e.message }; }
}

// Evaluate one network type for one profile. Returns { outcome, how, detail[] }
// outcome: 'ZIA' (reaches ZIA), 'BYPASS' (sent direct), 'NOT_CAPTURED' (ZCC doesn't intercept it)
// Is a PAC result pointing at Zscaler (cloud proxy, ${GATEWAY} macros, or Client Connector's local listener)?
const ZS_PROXY = /zscaler|zscloud|zscalertwo|zscalerthree|zscalerbeta|zscalergov|zscalerten|zspreview|\$\{?(GATEWAY|SECONDARY_GATEWAY|COUNTRY_GATEWAY)|127\.0\.0\.1|localhost/i;
function pacVerdict(result) {
  const first = String(result || '').split(';')[0].trim();
  if (/^DIRECT/i.test(first)) return { kind: 'DIRECT', first };
  const m = first.match(/^(PROXY|HTTPS|SOCKS5?)\s+(\S+)/i);
  if (m && !ZS_PROXY.test(m[2])) return { kind: 'OTHER_PROXY', first, proxy: m[2] };
  return { kind: 'ZSCALER', first };
}

// Order (per profile and network type):
//   1. process-based bypass (flagged, not evaluated)   2. VPN gateway bypass
//   [3. ZPA segment always-bypass and 4. ZPA client forwarding policy are evaluated first, in the ZPA module]
//   5. PAC file (web traffic on 80/443): DIRECT / another proxy / Zscaler
//   6. IP-based application bypass   7. Z-Tunnel 2.0 exclusions (domain, IP)   8. Z-Tunnel 2.0 inclusions
function evalPath(p, fa, ctx, data, pacCache) {
  const t = ctx.target;
  const ips = t ? (t.isIp ? [t.host] : ctx.resolvedIps || []) : [];
  const isWeb = ctx.isWeb !== false;
  const steps = [];
  const action = fa ? Number(fa.actionType) : 1;
  if (fa && action === 0) return { outcome: 'BYPASS', how: `Forwarding action None — ZIA traffic is not forwarded`, steps };

  // 1. Process-based bypass: depends on the client process, which the simulator doesn't know.
  const procKeys = Object.entries(Object.assign({}, p, p.policyExtension || {}, p.macPolicy || {}, p.windowsPolicy || {}))
    .filter(([k, v]) => /process|applicationbasedbypass|appbasedbypass/i.test(k) && !/tunnelprocessexit|processmapping/i.test(k) && v && v !== '0' && v !== 0 && (!Array.isArray(v) || v.length));
  if (procKeys.length) steps.push(`1. process-based bypass configured (${procKeys.map(([k]) => k).join(', ')}): depends on the client process, not evaluated`);
  else steps.push('1. process-based bypass: none configured');

  // 2. VPN gateway bypass
  const vpn = list(p, 'vpnGateways');
  if (vpn.length && t) {
    const h = hostMatches(t, vpn), i = ipMatches(ips, vpn);
    if ((h && h.rel === 'match') || (i && i.rel === 'match')) return { outcome: 'BYPASS', how: `VPN gateway bypass (${(h || i).entry})`, steps };
    if (h || i) steps.push(`2. partially overlaps VPN gateway bypass ${(h || i).entry}`);
  }

  // 5. PAC files (web traffic on 80/443)
  const webPort = ctx.port == null || ctx.port === 80 || ctx.port === 443;
  if (isWeb && webPort && t) {
    const pacs = [];
    if (fa && fa.customPac && /FindProxyForURL/.test(fa.customPac)) pacs.push({ name: 'forwarding profile custom PAC', text: fa.customPac });
    const spu = fa && fa.systemProxyData && Number(fa.systemProxyData.enablePAC) === 1 && fa.systemProxyData.pacURL;
    if (spu && pacCache[spu]) pacs.push({ name: `system PAC ${spu}`, text: pacCache[spu] });
    const apu = p.pac_url || (p.policyExtension && p.policyExtension.pacUrl);
    if (apu && pacCache[apu]) pacs.push({ name: `app profile PAC ${apu}`, text: pacCache[apu] });
    else if (apu) steps.push(`5. app profile PAC ${apu} could not be fetched`);
    for (const pac of pacs) {
      const r = runPac(pac.text, ctx, { resolve: () => ips[0] || '0.0.0.0', myIp: ctx.sourceIp || '10.0.0.10' });
      if (r.error) { steps.push(`5. ${pac.name}: evaluation error ${r.error}`); continue; }
      const v = pacVerdict(r.result);
      if (v.kind === 'DIRECT') return { outcome: 'BYPASS', how: `${pac.name} returns DIRECT`, steps };
      if (v.kind === 'OTHER_PROXY') return { outcome: 'BYPASS', how: `${pac.name} sends it to another proxy (${v.proxy}), not Zscaler`, steps };
      steps.push(`5. ${pac.name} → ${r.result} (Zscaler)`);
    }
  }

  // 6. IP-based application bypass
  const appIds = [...arr(p.appServiceIds), ...arr(p.bypassAppIds)].map(String);
  if (appIds.length && ips.length) {
    for (const svc of arr(data.zccAppServices)) {
      if (!appIds.includes(String(svc.id))) continue;
      const r = M.ipInList(ips[0], appServiceRanges(svc));
      if (r.rel === 'match') return { outcome: 'BYPASS', how: `IP-based app bypass "${svc.appName || svc.name || svc.appSvcName || svc.id}" (${r.entry})`, steps };
    }
  }
  const sp = list(p, 'sourcePortBasedBypasses');
  if (sp.length) steps.push(`source-port bypasses configured: ${sp.join(', ')} (match on client source port, not evaluated)`);

  const packetTunnel = !fa || Number(fa.enablePacketTunnel) === 1 || action === 1;
  if (action === 3) {
    if (!isWeb) return { outcome: 'NOT_CAPTURED', how: 'Enforce proxy mode only proxies web traffic; this traffic goes direct', steps };
  } else if (packetTunnel) {
    // 7. Z-Tunnel 2.0 exclusions, then 8. inclusions
    const dEx = list(p, 'packetTunnelDnsExcludeList'), dIn = list(p, 'packetTunnelDnsIncludeList');
    const ipEx = list(p, 'packetTunnelExcludeList'), ipIn = list(p, 'packetTunnelIncludeList');
    const dx = hostMatches(t, dEx);
    if (dx && dx.rel === 'match') return { outcome: 'BYPASS', how: `Destination (domain) exclusion ${dx.entry}`, steps };
    const ix = ipMatches(ips, ipEx);
    const dinc = hostMatches(t, dIn);
    if (ix && ix.rel === 'match' && !(dinc && dinc.rel === 'match')) return { outcome: 'BYPASS', how: `IPv4 exclusion ${ix.entry}`, steps };
    if (ix && ix.rel === 'partial') steps.push(`7. partially overlaps IPv4 exclusion ${ix.entry}`);
    if (t && ipIn.length && !ipIn.some((e) => e === '0.0.0.0/0' || e === '*')) {
      const ii = ipMatches(ips, ipIn);
      if (!(ii && ii.rel === 'match') && !(dinc && dinc.rel === 'match')) {
        if (ips.length) return { outcome: 'BYPASS', how: `Not in IPv4 inclusions (${ipIn.slice(0, 3).join(', ')}${ipIn.length > 3 ? '…' : ''})`, steps };
        steps.push('8. IPv4 inclusions are restricted and the destination IP is unknown');
      } else steps.push(`8. in IPv4 inclusion ${(ii || dinc).entry}`);
    }
    if (dIn.length && !dIn.includes('*') && t && !t.isIp && !(dinc && dinc.rel === 'match')) steps.push(`8. not in destination inclusions (${dIn.slice(0, 3).join(', ')})`);
    else if (dinc && dinc.rel === 'match') steps.push(`8. in destination inclusion ${dinc.entry}`);
  } else if (!isWeb) {
    return { outcome: 'NOT_CAPTURED', how: `${ACTION[action] || 'Tunnel 1.0'} only carries web traffic; this traffic goes direct`, steps };
  }
  return { outcome: 'ZIA', how: fa ? `${ACTION[action] || 'Tunnel'}${packetTunnel && action !== 3 ? ' (Z-Tunnel 2.0)' : ''}` : 'Tunnel (no forwarding profile linked)', steps };
}

function evaluateProfiles(data, ctx, pacCache = {}) {
  const profiles = arr(data.zccPolicies);
  const fwds = arr(data.zccForwardingProfiles);
  const rows = [];
  for (const p of profiles) {
    if (String(p.active) === '0' || p.active === false) continue;
    const applies = profileAppliesTo(p, ctx);
    const fwd = findFwdProfile(p, fwds);
    const actions = fwd ? arr(fwd.forwardingProfileActions) : [];
    const nets = actions.length ? actions.map((fa) => ({ net: NET[fa.networkType] || `network ${fa.networkType}`, fa })) : [{ net: 'All networks', fa: null }];
    const perNet = nets.map(({ net, fa }) => Object.assign({ net, action: fa ? ACTION[fa.actionType] : null }, evalPath(p, fa, ctx, data, pacCache)));
    // collapse identical outcomes
    const groups = [];
    for (const r of perNet) {
      const g = groups.find((x) => x.outcome === r.outcome && x.how === r.how);
      if (g) g.nets.push(r.net); else groups.push({ outcome: r.outcome, how: r.how, steps: r.steps, nets: [r.net] });
    }
    rows.push({
      name: p.name, platform: p._platform || '', ruleOrder: p.ruleOrder, appliesTo: applies.label, applies: applies.match,
      forwardingProfile: fwd ? fwd.name : null, outcomes: groups,
      summary: groups.length === 1 ? groups[0].outcome : 'MIXED',
    });
  }
  rows.sort((a, b) => (a.platform || '').localeCompare(b.platform || '') || (Number(a.ruleOrder) || 0) - (Number(b.ruleOrder) || 0));
  return rows;
}

module.exports = { evaluateProfiles, evalPath, list, NET, ACTION };
