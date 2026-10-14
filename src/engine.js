'use strict';
// Policy evaluation engine. Pure functions over a snapshot (rules pulled from the APIs) and a transaction context.
// Each criterion returns {field, status: 'match'|'nomatch'|'unknown'|'any', detail}.
// A rule is: nomatch if any criterion is nomatch; unknown if none nomatch but some unknown; match otherwise.

const M = require('./matchers');

const lc = (s) => String(s == null ? '' : s).toLowerCase();
const arr = (x) => (Array.isArray(x) ? x : x == null || x === '' ? [] : [x]);
const names = (list) => arr(list).map((e) => (e && typeof e === 'object' ? e.name || String(e.id) : String(e)));
const nonAny = (list) => arr(list).filter((x) => lc(x && x.name ? x.name : x) !== 'any' && lc(x) !== 'any_rule' && lc(x) !== 'none');

// ---------- file type handling ----------
// Approximate extension -> category aliases. ZIA file type enums vary per tenant/version; matching is
// by exact extension token (FTCATEGORY_<EXT>) first, then these aliases. Alias hits are flagged "approximate".
const FILETYPE_ALIASES = {
  EXE: ['WINDOWS_EXECUTABLES', 'EXECUTABLES'], DLL: ['WINDOWS_EXECUTABLES'], MSI: ['WINDOWS_EXECUTABLES', 'INSTALLERS'],
  BAT: ['WINDOWS_EXECUTABLES', 'SCRIPTS'], PS1: ['SCRIPTS'], VBS: ['SCRIPTS'], JS: ['SCRIPTS'],
  DOC: ['MS_WORD', 'MICROSOFT_WORD', 'MSOFFICE'], DOCX: ['MS_WORD', 'MICROSOFT_WORD', 'MSOFFICE'],
  XLS: ['MS_EXCEL', 'MICROSOFT_EXCEL', 'MSOFFICE'], XLSX: ['MS_EXCEL', 'MICROSOFT_EXCEL', 'MSOFFICE'],
  PPT: ['MS_POWERPOINT', 'MICROSOFT_POWERPOINT', 'MSOFFICE'], PPTX: ['MS_POWERPOINT', 'MICROSOFT_POWERPOINT', 'MSOFFICE'],
  PDF: ['PDF_DOCUMENT', 'ADOBE_PDF'],
  ZIP: ['ARCHIVES', 'COMPRESSED', 'ZIP_ARCHIVE'], RAR: ['ARCHIVES', 'COMPRESSED'], '7Z': ['ARCHIVES', 'COMPRESSED'],
  TAR: ['ARCHIVES', 'COMPRESSED'], GZ: ['ARCHIVES', 'COMPRESSED'],
  ISO: ['DISK_IMAGES'], DMG: ['DISK_IMAGES'], JAR: ['JAVA'],
  MP3: ['AUDIO'], WAV: ['AUDIO'], MP4: ['VIDEO'], AVI: ['VIDEO'], MOV: ['VIDEO'],
  JPG: ['IMAGES'], JPEG: ['IMAGES'], PNG: ['IMAGES'], GIF: ['IMAGES'],
  DCM: ['DICOM', 'MEDICAL_IMAGING'],
};

function fileTypeMatch(ruleTypes, ext) {
  const E = String(ext).replace(/^\./, '').toUpperCase();
  const toks = arr(ruleTypes).map((t) => String(t).toUpperCase().replace(/^FTCATEGORY_/, ''));
  if (toks.includes('ANY') || toks.includes('ALL_OUTBOUND')) return { rel: 'match', via: 'ANY' };
  if (toks.includes(E)) return { rel: 'match', via: E };
  for (const a of FILETYPE_ALIASES[E] || []) if (toks.includes(a)) return { rel: 'match', via: a, approx: true };
  return { rel: 'none' };
}

// ---------- reusable criterion builders ----------
function critIdentity(rule, ctx) {
  const rl = { users: arr(rule.users), groups: arr(rule.groups), departments: arr(rule.departments) };
  if (!rl.users.length && !rl.groups.length && !rl.departments.length) return { field: 'user/group/department', status: 'any', detail: 'not restricted' };
  const hits = [];
  const haveAny = ctx.user || (ctx.groups && ctx.groups.length) || ctx.department;
  if (!haveAny) return { field: 'user/group/department', status: 'unknown', kind: 'identity', scope: [...names(rl.groups).map((x) => 'Group ' + x), ...names(rl.users).map((x) => 'User ' + x), ...names(rl.departments).map((x) => 'Department ' + x)].slice(0, 4).join(', ') + (rl.users.length + rl.groups.length + rl.departments.length > 4 ? '…' : ''), detail: `rule restricts to ${[...names(rl.users), ...names(rl.groups), ...names(rl.departments)].slice(0, 6).join(', ')} — no user context supplied` };
  if (ctx.user) for (const u of rl.users) if (lc(u.name).includes(lc(ctx.user))) hits.push(`user ${u.name}`);
  for (const g of rl.groups) if ((ctx.groups || []).some((x) => lc(x) === lc(g.name))) hits.push(`group ${g.name}`);
  for (const d of rl.departments) if (ctx.department && lc(d.name) === lc(ctx.department)) hits.push(`department ${d.name}`);
  if (hits.length) return { field: 'user/group/department', status: 'match', detail: hits.join(', ') };
  return { field: 'user/group/department', status: 'nomatch', detail: `rule applies to ${[...names(rl.users), ...names(rl.groups), ...names(rl.departments)].slice(0, 6).join(', ')}` };
}

function critLocation(rule, ctx) {
  const locs = arr(rule.locations), lgs = arr(rule.locationGroups);
  if (!locs.length && !lgs.length) return { field: 'location', status: 'any', detail: 'not restricted' };
  if (!ctx.location && !(ctx.locationGroups || []).length) return { field: 'location', status: 'unknown', kind: 'location', scope: [...names(locs).map((x) => 'Location ' + x), ...names(lgs).map((x) => 'Location group ' + x)].slice(0, 3).join(', '), detail: `rule restricts to ${[...names(locs), ...names(lgs)].slice(0, 6).join(', ')} — no location supplied` };
  const hits = [];
  for (const l of locs) if (ctx.location && lc(l.name) === lc(ctx.location)) hits.push(`location ${l.name}`);
  for (const g of lgs) if ((ctx.locationGroups || []).some((x) => lc(x) === lc(g.name))) hits.push(`location group ${g.name}`);
  if (!hits.length && lgs.length && ctx.location && !(ctx.locationGroups || []).length)
    return { field: 'location', status: 'unknown', scope: 'Location group ' + names(lgs).join(', '), detail: `rule uses location group(s) ${names(lgs).join(', ')}; group membership of "${ctx.location}" not supplied` };
  return hits.length ? { field: 'location', status: 'match', detail: hits.join(', ') } : { field: 'location', status: 'nomatch', detail: `rule applies to ${[...names(locs), ...names(lgs)].slice(0, 6).join(', ')}` };
}

function critProtocol(rule, ctx, key = 'protocols') {
  const p = nonAny(rule[key]);
  if (!p.length) return { field: 'protocol', status: 'any', detail: 'any' };
  const scheme = ctx.target && ctx.target.scheme;
  const want = scheme === 'https' || ctx.port === 443 ? 'HTTPS_RULE' : scheme === 'http' || ctx.port === 80 ? 'HTTP_RULE' : scheme === 'ftp' ? 'FTP_RULE' : null;
  if (!want) return { field: 'protocol', status: 'unknown', scope: 'Protocol ' + p.join(', ').replace(/_RULE/g, ''), detail: `rule protocols ${p.join(', ')}; transaction protocol not specified` };
  const ok = p.some((x) => x === want || (want === 'HTTPS_RULE' && /TUNNELSSL|DOHTTPS/.test(x)));
  return { field: 'protocol', status: ok ? 'match' : 'nomatch', detail: `rule ${p.join(', ')}; transaction ${want}` };
}

function critUrlCategories(rule, ctx, key = 'urlCategories') {
  const cats = nonAny([...arr(rule[key]), ...arr(rule[key + '2'])]);
  if (!cats.length) return { field: 'url category', status: 'any', detail: 'not restricted' };
  if (!ctx.categories || !ctx.categories.length) return { field: 'url category', status: 'unknown', scope: 'URL category ' + cats.slice(0, 3).join(', ') + (cats.length > 3 ? '…' : ''), detail: `rule categories ${cats.slice(0, 8).join(', ')}; no category for target (lookup unavailable)` };
  const hit = cats.filter((c) => ctx.categories.some((x) => lc(x) === lc(c)));
  const partial = ctx.target && ctx.target.isWildcard;
  if (hit.length) return { field: 'url category', status: partial ? 'unknown' : 'match', detail: `target in ${hit.join(', ')}${partial ? ' (wildcard query: category of probe host only)' : ''}` };
  return { field: 'url category', status: 'nomatch', detail: `target categories ${ctx.categories.join(', ')}; rule ${cats.slice(0, 8).join(', ')}` };
}

function critFileType(rule, ctx, key = 'fileTypes') {
  const ft = nonAny(arr(rule[key]));
  if (!ft.length) return { field: 'file type', status: 'any', detail: 'not restricted' };
  if (!ctx.fileType) return { field: 'file type', status: 'nomatch', detail: `no file in this transaction (rule needs ${ft.slice(0, 6).join(', ')}) — enter a file type to test a download/upload` };
  const r = fileTypeMatch(ft, ctx.fileType);
  if (r.rel === 'match') return { field: 'file type', status: 'match', detail: `.${ctx.fileType.replace(/^\./, '')} matches ${r.via}${r.approx ? ' (approximate alias mapping)' : ''}` };
  return { field: 'file type', status: 'nomatch', detail: `.${ctx.fileType.replace(/^\./, '')} not in ${ft.slice(0, 8).join(', ')}` };
}

function critSourceIp(rule, ctx, snap) {
  const addrs = [...arr(rule.srcIps)];
  for (const g of arr(rule.srcIpGroups)) {
    const full = (snap.ipSourceGroups || []).find((x) => x.id === g.id);
    if (full) addrs.push(...arr(full.ipAddresses));
  }
  if (!addrs.length) return { field: 'source IP', status: 'any', detail: 'not restricted' };
  if (!ctx.sourceIp) return { field: 'source IP', status: 'unknown', scope: 'Source IP ' + addrs.slice(0, 3).join(', '), detail: `rule source ${addrs.slice(0, 5).join(', ')}; no source IP supplied` };
  const r = M.ipInList(ctx.sourceIp, addrs);
  if (r.rel === 'match') return { field: 'source IP', status: 'match', detail: `${ctx.sourceIp} in ${r.entry}` };
  if (r.rel === 'partial') return { field: 'source IP', status: 'unknown', scope: 'Source IP ' + r.entry, detail: `${ctx.sourceIp} overlaps ${r.entry}` };
  return { field: 'source IP', status: 'nomatch', detail: `${ctx.sourceIp} not in ${addrs.slice(0, 5).join(', ')}` };
}

// Destination: addresses (ip/cidr/range/fqdn), ip groups, ip categories, countries (OR'd together).
function critDest(rule, ctx, snap) {
  const addrs = [...arr(rule.destAddresses)];
  const groupNames = [];
  for (const g of arr(rule.destIpGroups)) {
    const full = (snap.ipDestinationGroups || []).find((x) => x.id === g.id);
    groupNames.push(g.name || (full && full.name) || g.id);
    if (full) addrs.push(...arr(full.addresses));
  }
  const cats = nonAny(arr(rule.destIpCategories).map((c) => (c && c.name) || c));
  const countries = nonAny(arr(rule.destCountries));
  if (!addrs.length && !cats.length && !countries.length) return { field: 'destination', status: 'any', detail: 'not restricted' };
  const t = ctx.target;
  const hits = [];
  let sawUnknown = false;
  if (!t && !ctx.destCountry) return { field: 'destination', status: 'unknown', scope: 'Destination ' + [...addrs.slice(0, 3), ...cats.slice(0, 2), ...countries.slice(0, 2).map((x) => String(x).replace('COUNTRY_', ''))].join(', '), detail: `rule only applies to ${[...addrs.slice(0, 4), ...cats.slice(0, 3), ...countries.slice(0, 3)].join(', ')}${addrs.length + cats.length + countries.length > 10 ? '…' : ''} — no destination entered` };
  const ipEntries = addrs.filter((a) => M.parseIpRange(a));
  const nameEntries = addrs.filter((a) => !M.parseIpRange(a));
  if (t) {
    if (nameEntries.length && !t.isIp) {
      const r = M.domainInList(t, nameEntries);
      if (r.rel === 'match') hits.push(`${t.host} matches ${r.entry}`);
      else if (r.rel === 'partial') { sawUnknown = true; hits.push(`partial overlap with ${r.entry}`); }
    }
    if (ipEntries.length) {
      const ips = t.isIp ? [t.host] : ctx.resolvedIps || [];
      for (const ip of ips) {
        const r = M.ipInList(ip, ipEntries);
        if (r.rel === 'match') { hits.push(`${ip}${t.isIp ? '' : ' (resolved)'} in ${r.entry}`); break; }
        if (r.rel === 'partial') { sawUnknown = true; hits.push(`${ip} overlaps ${r.entry}`); }
      }
      if (!t.isIp && !(ctx.resolvedIps || []).length) sawUnknown = true;
    }
  }
  if (cats.length) {
    const have = ctx.categories || [];
    const c = cats.filter((x) => have.some((h) => lc(h) === lc(x)));
    if (c.length) hits.push(`category ${c.join(', ')}`);
    else if (!have.length) sawUnknown = true;
  }
  if (countries.length) {
    if (ctx.destCountry) { if (countries.some((c) => lc(c).replace('country_', '') === lc(ctx.destCountry).replace('country_', ''))) hits.push(`country ${ctx.destCountry}`); }
    else sawUnknown = true;
  }
  const desc = [...addrs.slice(0, 4), ...cats.slice(0, 3), ...countries.slice(0, 3), ...groupNames.map((g) => `group:${g}`)].join(', ');
  if (hits.length && !sawUnknown) return { field: 'destination', status: 'match', detail: hits.join('; ') };
  if (hits.length && sawUnknown && hits.some((h) => !/partial|overlaps/.test(h))) return { field: 'destination', status: 'match', detail: hits.join('; ') };
  if (sawUnknown) {
    const why = [];
    if (countries.length && !ctx.destCountry) why.push('destination country not entered');
    if (cats.length && !(ctx.categories || []).length) why.push('no IP category for target');
    if (ipEntries.length && t && !t.isIp && !(ctx.resolvedIps || []).length) why.push('host did not resolve to an IP');
    return { field: 'destination', status: 'unknown', scope: 'Destination ' + desc.split(', ').slice(0, 3).map((x) => x.replace('COUNTRY_', 'country ')).join(', '), detail: `rule destination ${desc}; ${hits.join('; ') || why.join(', ') || 'partial overlap'}` };
  }
  return { field: 'destination', status: 'nomatch', detail: `${t ? t.host : 'target'} not in ${desc}` };
}

// ---------- network service / application rationalization ----------
// Well-known protocol/port -> service tag + network application. Used to (a) resolve predefined services whose
// port list isn't returned by the API, (b) infer the network application from proto/port when not supplied, and
// (c) resolve a typed service name ("QUIC", "RDP") back to ports.
const WELL_KNOWN = [
  { tag: 'HTTP', apps: ['HTTP'], tcp: [[80, 80]] },
  { tag: 'HTTPS', apps: ['SSL', 'HTTPS'], tcp: [[443, 443]] },
  { tag: 'QUIC', apps: ['QUIC'], udp: [[443, 443], [80, 80]] },
  { tag: 'DNS', apps: ['DNS'], tcp: [[53, 53]], udp: [[53, 53]] },
  { tag: 'DOH', apps: ['DOH'], noInfer: true, tcp: [[443, 443]] },
  { tag: 'ZSCALER_PROXY_NW_SERVICES', apps: [], noInfer: true, tcp: [[80, 80], [443, 443], [8080, 8080], [9400, 9400], [9480, 9480], [9443, 9443]] },
  { tag: 'SSH', apps: ['SSH'], tcp: [[22, 22]] },
  { tag: 'TELNET', apps: ['TELNET'], tcp: [[23, 23]] },
  { tag: 'FTP', apps: ['FTP'], tcp: [[20, 21]] },
  { tag: 'SMTP', apps: ['SMTP'], tcp: [[25, 25], [587, 587]] },
  { tag: 'POP3', apps: ['POP3'], tcp: [[110, 110]] },
  { tag: 'IMAP', apps: ['IMAP'], tcp: [[143, 143]] },
  { tag: 'NTP', apps: ['NTP'], udp: [[123, 123]] },
  { tag: 'SNMP', apps: ['SNMP'], udp: [[161, 161]] },
  { tag: 'SNMPTRAP', apps: ['SNMPTRAP'], udp: [[162, 162]] },
  { tag: 'LDAP', apps: ['LDAP'], tcp: [[389, 389]], udp: [[389, 389]] },
  { tag: 'KERBEROS_SEC', apps: ['KERBEROS'], tcp: [[88, 88]], udp: [[88, 88]] },
  { tag: 'SMB', apps: ['SMB'], tcp: [[445, 445], [139, 139]] },
  { tag: 'NETBIOS', apps: ['NETBIOS'], tcp: [[139, 139]], udp: [[137, 138]] },
  { tag: 'RDP', name: 'RDP', apps: ['RDP'], tcp: [[3389, 3389]], udp: [[3389, 3389]] },
  { tag: 'VNC', apps: ['VNC'], tcp: [[5900, 5900]] },
  { tag: 'SIP', apps: ['SIP'], tcp: [[5060, 5061]], udp: [[5060, 5060]] },
  { tag: 'IKE', apps: ['IKE'], udp: [[500, 500]] },
  { tag: 'IKE_NAT', apps: ['IKE'], udp: [[4500, 4500]] },
  { tag: 'SYSLOG', apps: ['SYSLOG'], udp: [[514, 514]] },
  { tag: 'TFTP', apps: ['TFTP'], udp: [[69, 69]] },
  { tag: 'RADIUS', apps: ['RADIUS'], udp: [[1812, 1813]] },
  { tag: 'DHCP', apps: ['DHCP'], udp: [[67, 68]] },
  { tag: 'OPENVPN', apps: ['OPENVPN'], udp: [[1194, 1194]], tcp: [[1194, 1194]] },
  { tag: 'PPTP', apps: ['PPTP'], tcp: [[1723, 1723]] },
  { tag: 'L2TP', apps: ['L2TP'], udp: [[1701, 1701]] },
  { tag: 'STUN', apps: ['STUN'], udp: [[3478, 3478]] },
  { tag: 'RTSP', apps: ['RTSP'], tcp: [[554, 554]] },
  { tag: 'NFS', apps: ['NFS'], tcp: [[2049, 2049]], udp: [[2049, 2049]] },
  { tag: 'WHOIS', apps: ['WHOIS'], tcp: [[43, 43]] },
  { tag: 'TDS', apps: ['TDS', 'MSSQL'], tcp: [[1433, 1433]] },
];
const norm = (s) => String(s == null ? '' : s).toLowerCase().replace(/[^a-z0-9]/g, '');
function wkByName(s) {
  const n = norm(s);
  return WELL_KNOWN.find((w) => norm(w.tag) === n || norm(w.name) === n || w.apps.some((a) => norm(a) === n)) || null;
}
function svcRanges(s, proto) {
  const own = M.parsePorts(proto === 'udp' ? s.destUdpPorts : s.destTcpPorts);
  if (own.length) return { ranges: own, via: 'service ports' };
  if (s.destTcpPorts || s.destUdpPorts) return { ranges: [], via: 'service ports' }; // defined for the other protocol only
  const wk = WELL_KNOWN.find((w) => w.tag === s.tag) || wkByName(s.name);
  if (wk && wk[proto]) return { ranges: wk[proto], via: 'standard ports for ' + (wk.tag) };
  return { ranges: [], via: null };
}

// Fill ctx with inferred service/app from proto+port, or ports from a typed service name.
function rationalize(ctx, snap) {
  const inf = { services: [], apps: [], notes: [] };
  const t0 = ctx.target;
  if (!ctx.fileType && t0 && t0.path) {
    const m = t0.path.split('?')[0].match(/\.([a-z0-9]{1,5})$/i);
    if (m && !/^(html?|php|aspx?|jsp|cgi)$/i.test(m[1])) { ctx.fileType = m[1].toUpperCase(); if (!ctx.operation) ctx.operation = 'DOWNLOAD'; inf.notes.push(`File type .${m[1].toLowerCase()} taken from the URL path (treated as a download).`); }
  }
  if (ctx.port == null && !ctx.networkService && !ctx.application && t0 && (ctx.protocol || 'tcp') === 'tcp') {
    if (t0.scheme === 'https') ctx.port = 443;
    else if (t0.scheme === 'http') ctx.port = 80;
    else if (!t0.isIp) { ctx.port = 443; inf.notes.push('No port entered — assumed HTTPS (TCP/443). Enter a port to test something else.'); }
    if (ctx.port != null) ctx.portFromScheme = true;
  }
  const proto = ctx.protocol || 'tcp';
  if (ctx.networkService && ctx.port == null) {
    const s = arr(snap.networkServices).find((x) => lc(x.name) === lc(ctx.networkService));
    let r = s ? svcRanges(s, proto) : { ranges: [] };
    let p = proto;
    if (!r.ranges.length && s) { const o = svcRanges(s, proto === 'tcp' ? 'udp' : 'tcp'); if (o.ranges.length) { r = o; p = proto === 'tcp' ? 'udp' : 'tcp'; } }
    const wk = wkByName(ctx.networkService);
    if (!r.ranges.length && wk) { p = wk.udp && !wk.tcp ? 'udp' : proto in wk ? proto : wk.tcp ? 'tcp' : 'udp'; r = { ranges: wk[p] }; }
    if (r.ranges.length) {
      ctx.port = r.ranges[0][0]; ctx.protocol = p; ctx.portInferred = true;
      inf.notes.push(`Service ${ctx.networkService} → ${p.toUpperCase()}/${ctx.port}`);
    }
  }
  if (ctx.port != null) {
    const p = ctx.protocol || 'tcp';
    for (const s of arr(snap.networkServices)) {
      const r = svcRanges(s, p);
      if (r.ranges.length && M.portInRanges(ctx.port, r.ranges)) inf.services.push(s.name);
    }
    for (const w of WELL_KNOWN) if (!w.noInfer && w[p] && M.portInRanges(ctx.port, w[p])) inf.apps.push(...w.apps);
  }
  if (ctx.networkService) { const wk = wkByName(ctx.networkService); if (wk) inf.apps.push(...wk.apps); }
  inf.apps = [...new Set(inf.apps)];
  inf.services = [...new Set(inf.services)];
  if (!ctx.application && inf.apps.length && !ctx.portFromScheme) inf.notes.push(`${(ctx.protocol || 'tcp').toUpperCase()}/${ctx.port} → network application ${inf.apps.join(' / ')} (inferred)`);
  if (ctx.port == null && !ctx.networkService && !ctx.application) {
    const proto = (ctx.protocol || 'tcp').toUpperCase();
    inf.notes.push(`No port entered — firewall rules that match on network service or application (e.g. QUIC = UDP/443) can't be evaluated. Enter a Port${proto === 'UDP' ? ' (UDP selected)' : ''}, a Network service, or an Application.`);
  }
  ctx.inferred = inf;
  // Web proxy modules only see HTTP/HTTPS over TCP.
  const t = ctx.target;
  const scheme = t && t.scheme;
  ctx.isWeb = (ctx.protocol || 'tcp') === 'tcp' && (ctx.port == null || [80, 443, 8080, 8443].includes(ctx.port) || scheme === 'http' || scheme === 'https');
  return ctx;
}

function expandServices(rule, snap) {
  const all = [];
  const byId = (id) => arr(snap.networkServices).find((x) => x.id === id);
  for (const s of arr(rule.nwServices)) all.push(byId(s.id) || s);
  for (const g of arr(rule.nwServiceGroups)) {
    const full = arr(snap.networkServiceGroups).find((x) => x.id === g.id);
    if (full && arr(full.services).length) for (const s of full.services) all.push(byId(s.id) || s);
    else all.push(Object.assign({ _group: true }, g));
  }
  return all;
}

function critServices(rule, ctx, snap) {
  const all = expandServices(rule, snap).filter((s) => lc(s.name) !== 'any');
  if (!all.length) return null;
  const proto = ctx.protocol || 'tcp';
  const desc = all.map((s) => s.name).slice(0, 6).join(', ');
  if (ctx.port == null && !ctx.networkService) return { field: 'network service', status: 'unknown', scope: 'Network service ' + desc, detail: `rule services ${desc}; no port/protocol supplied` };
  const via = ctx.portInferred ? ` (port from service ${ctx.networkService})` : '';
  for (const s of all) {
    if (ctx.networkService && lc(s.name) === lc(ctx.networkService)) return { field: 'network service', status: 'match', detail: `service ${s.name}` };
    if (/_ANY$/.test(s.tag || '') && lc(s.tag).startsWith(proto)) return { field: 'network service', status: 'match', detail: `${proto.toUpperCase()}/${ctx.port} matches ${s.name} (any ${proto.toUpperCase()})${via}` };
    if (ctx.port != null) {
      const r = svcRanges(s, proto);
      if (r.ranges.length && M.portInRanges(ctx.port, r.ranges)) return { field: 'network service', status: 'match', detail: `${proto.toUpperCase()}/${ctx.port} matches ${s.name}${r.via && r.via !== 'service ports' ? ` (${r.via})` : ''}${via}` };
    }
  }
  const unresolved = all.filter((s) => s._group || !svcRanges(s, 'tcp').ranges.length && !svcRanges(s, 'udp').ranges.length && !/_ANY$/.test(s.tag || ''));
  if (unresolved.length) return { field: 'network service', status: 'unknown', scope: 'Network service ' + unresolved.map((x) => x.name).join(', '), detail: `${proto.toUpperCase()}/${ctx.port} not in resolvable services; ports unknown for ${unresolved.map((s) => s.name).join(', ')}` };
  return { field: 'network service', status: 'nomatch', detail: `${proto.toUpperCase()}/${ctx.port} not in ${desc}` };
}

function critApps(rule, ctx, snap) {
  const apps = nonAny(arr(rule.nwApplications).map((a) => (a && a.name) || a));
  for (const g of arr(rule.nwApplicationGroups)) {
    const full = arr(snap.networkApplicationGroups).find((x) => x.id === g.id);
    if (full && arr(full.networkApplications).length) apps.push(...full.networkApplications);
    else apps.push(`group:${g.name || g.id}`);
  }
  if (!apps.length) return null;
  const desc = apps.slice(0, 6).join(', ');
  if (ctx.application) {
    const ok = apps.some((a) => norm(a) === norm(ctx.application));
    return { field: 'network application', status: ok ? 'match' : apps.some((a) => a.startsWith('group:')) ? 'unknown' : 'nomatch', detail: `${ctx.application} ${ok ? 'in' : 'not in'} ${desc}` };
  }
  const inferred = (ctx.inferred && ctx.inferred.apps) || [];
  const hit = apps.find((a) => inferred.some((i) => norm(i) === norm(a)));
  if (hit) return { field: 'network application', status: 'match', detail: `${(ctx.protocol || 'tcp').toUpperCase()}/${ctx.port} identified as ${hit} (inferred from port — set Application to override)` };
  if (ctx.port == null) return { field: 'network application', status: 'unknown', scope: 'Network application ' + desc, detail: `rule applications ${desc}; no port/application supplied` };
  // If every rule app has known ports and none include this port, it cannot be that app.
  const proto = ctx.protocol || 'tcp';
  const known = apps.map((a) => ({ a, wk: WELL_KNOWN.find((w) => w.apps.some((x) => norm(x) === norm(a))) }));
  if (known.every((k) => k.wk)) {
    if (!known.some((k) => k.wk[proto] && M.portInRanges(ctx.port, k.wk[proto]))) return { field: 'network application', status: 'nomatch', detail: `${proto.toUpperCase()}/${ctx.port} is not ${desc}` };
  }
  return { field: 'network application', status: 'unknown', scope: 'Network application ' + desc, detail: `rule applications ${desc}; application on ${proto.toUpperCase()}/${ctx.port} can't be determined from the port — set Application` };
}

function critTimeWindows(rule) {
  const tw = arr(rule.timeWindows);
  return tw.length ? { field: 'time window', status: 'unknown', kind: 'other', scope: `Time window ${names(tw).join(', ')}`, detail: `time-restricted: ${names(tw).join(', ')} (not evaluated)` } : null;
}

// Criteria that exist on some rules but are not modelled; flagged unknown rather than silently ignored.
const UNMODELLED = ['userAgentTypes', 'deviceTrustLevels', 'userRiskScoreLevels', 'deviceGroups', 'devices', 'labels', 'workloadGroups', 'sourceCountries', 'cloudApplications', 'platforms', 'timeQuota', 'sizeQuota'];
const UNMODELLED_LABEL = { userAgentTypes: 'User agent', deviceTrustLevels: 'Device trust', userRiskScoreLevels: 'User risk score', deviceGroups: 'Device group', devices: 'Device', labels: 'Rule label', workloadGroups: 'Workload group', sourceCountries: 'Source country', cloudApplications: 'Cloud app', platforms: 'Platform', timeQuota: 'Time quota', sizeQuota: 'Size quota' };
function critUnmodelled(rule, skip = []) {
  const out = [];
  for (const k of UNMODELLED) {
    if (skip.includes(k)) continue;
    const v = arr(rule[k]);
    if (v.length && !(v.length === 1 && lc(v[0]) === 'any') && !(typeof rule[k] === 'number' && !rule[k])) out.push({ field: k, status: 'unknown', kind: 'other', scope: `${UNMODELLED_LABEL[k] || k}: ${names(v).slice(0, 3).join(', ')}`, detail: `rule restricts ${k} (${names(v).slice(0, 4).join(', ')}) — not evaluated` });
  }
  return out;
}

// ---------- rule evaluation ----------
// ZIA evaluates rules by `order` (admin rank only constrains where a rule may be placed).
// Default/catch-all rules come back with order -1 (or a defaultRule flag) and are evaluated LAST.
function isDefaultRule(r) {
  const o = Number(r.order);
  return r.defaultRule === true || r.default === true || (Number.isFinite(o) && o < 0) ||
    (r.predefined === true && /^default\b/i.test(String(r.name || '')));
}
function sortKey(r) {
  const o = Number(r.order);
  return [isDefaultRule(r) ? 1 : 0, Number.isFinite(o) && o >= 0 ? o : 1e9];
}
function sortRules(rules) {
  return arr(rules).slice().sort((a, b) => { const x = sortKey(a), y = sortKey(b); return x[0] - y[0] || x[1] - y[1]; });
}

// Request method. Explicit input wins; otherwise HTTP/decrypted HTTPS is assumed GET and
// non-decrypted HTTPS is CONNECT (ZIA applies URL policy to the CONNECT request when it can't decrypt).
function critMethod(rule, ctx) {
  const m = nonAny(rule.requestMethods);
  if (!m.length) return null;
  const method = ctx.method;
  if (!method) return { field: 'request method', status: 'unknown', scope: 'Request method ' + m.join(', '), detail: `rule methods ${m.join(', ')}; method not known` };
  const ok = m.some((x) => lc(x) === lc(method));
  const how = ctx.methodAssumed ? ` (assumed ${method}${ctx.methodReason ? ': ' + ctx.methodReason : ''} — set Request method to override)` : '';
  return { field: 'request method', status: ok ? 'match' : 'nomatch', detail: `${ok ? method + ' in' : method + ' not in'} ${m.join(', ')}${how}` };
}

function evalRule(rule, crits) {
  const list = crits.filter(Boolean);
  const status = list.some((c) => c.status === 'nomatch') ? 'nomatch' : list.some((c) => c.status === 'unknown') ? 'unknown' : 'match';
  return {
    id: rule.id, name: rule.name, order: rule.order, rank: rule.rank,
    action: ruleAction(rule), status, criteria: list,
    description: rule.description || undefined,
  };
}

function ruleAction(rule) {
  if (rule.action && typeof rule.action === 'object') return rule.action.type || JSON.stringify(rule.action);
  return rule.action || rule.baRuleAction || rule.filteringAction || rule.accessControl || null;
}

// Generic ordered module evaluator.
// mode 'first': first definite match decides; unknown rules ahead of it are "could override".
// mode 'content': content-dependent (DLP): report all rules whose non-content criteria match.
function runModule(module, rules, buildCrits, { blockRe, allowRe, defaultVerdict = 'ALLOW', defaultReason = 'no matching rule (default action)', skipNote } = {}) {
  const sorted = sortRules(rules).filter((r) => lc(r.state) !== 'disabled');
  const evaluated = sorted.map((r) => evalRule(r, buildCrits(r)));
  const decidingIdx = evaluated.findIndex((e) => e.status === 'match');
  const preempt = evaluated.slice(0, decidingIdx < 0 ? evaluated.length : decidingIdx).filter((e) => e.status === 'unknown');
  const deciding = decidingIdx >= 0 ? evaluated[decidingIdx] : null;
  const verdictOf = (a) => (a == null ? 'UNKNOWN' : /ISOLATE/i.test(a) ? 'ISOLATE' : /CAUTION/i.test(a) ? 'CAUTION' : blockRe && blockRe.test(a) ? 'BLOCK' : allowRe && allowRe.test(a) ? 'ALLOW' : a);
  let verdict = deciding ? verdictOf(deciding.action) : defaultVerdict;
  let confidence = 'definite';
  // Only unresolved earlier rules whose action would change the outcome matter.
  const changers = preempt.filter((e) => verdictOf(e.action) !== verdict);
  if (changers.length) confidence = 'conditional';
  const sameOutcome = preempt.filter((e) => verdictOf(e.action) === verdict);
  return {
    module, verdict, confidence,
    decidingRule: deciding, couldOverride: changers, sameOutcomeEarlier: sameOutcome,
    reason: deciding ? `Rule "${deciding.name}" (order ${deciding.order}) matched` : defaultReason,
    considered: evaluated.length, rules: evaluated, note: skipNote,
  };
}

// ---------- module builders ----------
function mUrlFiltering(snap, ctx) {
  return runModule('URL Filtering', snap.urlFilteringRules, (r) => [
    critProtocol(r, ctx), critUrlCategories(r, ctx), critMethod(r, ctx), critIdentity(r, ctx), critLocation(r, ctx), critSourceIp(r, ctx, snap), critTimeWindows(r),
    ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { blockRe: /^(BLOCK)$/, allowRe: /^(ALLOW|CAUTION|ISOLATE)$/ });
}

function mFirewall(snap, ctx) {
  const web = (ctx.protocol || 'tcp') === 'tcp' && (ctx.port === 80 || ctx.port === 443 || (ctx.target && /^https?$/.test(ctx.target.scheme || '')));
  const res = runModule('Firewall', snap.firewallRules, (r) => [
    critSourceIp(r, ctx, snap), critDest(r, ctx, snap), critServices(r, ctx, snap), critApps(r, ctx, snap), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r),
    ...critUnmodelled(r, ['sourceCountries', 'cloudApplications']),
  ].filter(Boolean), { blockRe: /^BLOCK/, allowRe: /^(ALLOW|EVAL_NWAPP)$/, defaultReason: 'no matching rule (default firewall rule applies)' });
  if (web) res.note = 'Ports 80/443 normally pass through the web proxy path (URL filtering etc.); firewall rules apply to all-port traffic from ZCC/GRE/IPsec depending on "Enable Firewall" and location settings.';
  return res;
}

function mDns(snap, ctx) {
  const dnsCtx = Object.assign({}, ctx);
  return runModule('DNS Control', snap.dnsRules, (r) => {
    const proto = nonAny(r.protocols);
    return [
      proto.length ? { field: 'dns protocol', status: ctx.dnsProtocol ? (proto.some((p) => lc(p).startsWith(lc(ctx.dnsProtocol))) ? 'match' : 'nomatch') : 'unknown', detail: `rule ${proto.join(', ')}` } : null,
      critSourceIp(r, dnsCtx, snap), critDest(r, dnsCtx, snap), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r),
      nonAny(r.applications).length ? (() => {
        const apps = nonAny(r.applications);
        if (ctx.application) { const ok = apps.some((a) => lc(a) === lc(ctx.application)); return { field: 'dns application', status: ok ? 'match' : 'nomatch', detail: `${ctx.application} ${ok ? 'in' : 'not in'} ${apps.slice(0, 5).join(', ')}` }; }
        const ok = apps.some((a) => /^(DNS|ANY)$/i.test(a));
        return { field: 'dns application', status: ok ? 'match' : 'nomatch', detail: `assumed a standard DNS lookup through your resolver; rule apps ${apps.slice(0, 5).join(', ')} — set Application (e.g. GOOGLE_DNS, DOH) to test those` };
      })() : null,
    ].filter(Boolean);
  }, { blockRe: /^BLOCK/, allowRe: /^(ALLOW|REDIR)/, defaultReason: 'no matching rule (DNS resolves normally)' });
}

function mSandbox(snap, ctx) {
  return runModule('Sandbox (Behavioral Analysis)', snap.sandboxRules, (r) => [
    critFileType(r, ctx), critUrlCategories(r, ctx), critProtocol(r, ctx), critIdentity(r, ctx), critLocation(r, ctx),
    ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { blockRe: /BLOCK/, allowRe: /ALLOW/, defaultReason: 'no matching rule (file is not held for sandbox analysis by policy)' });
}

function mFileType(snap, ctx) {
  const op = ctx.operation; // DOWNLOAD / UPLOAD
  return runModule('File Type Control', snap.fileTypeRules, (r) => [
    critFileType(r, ctx), critUrlCategories(r, ctx),
    nonAny(r.operation).length ? { field: 'operation', status: op ? (lc(r.operation) === lc(op) || lc(r.operation) === 'any' ? 'match' : 'nomatch') : 'unknown', detail: `rule ${r.operation}` } : null,
    critProtocol(r, ctx), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r),
    ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { blockRe: /BLOCK/, allowRe: /ALLOW|CAUTION/, defaultReason: 'no matching rule (file type allowed)' });
}

// DLP is content dependent: rules matching on non-content criteria are *candidates*; verdict is conditional.
function mDlp(snap, ctx) {
  const res = runModule('Data Loss Prevention', snap.webDlpRules, (r) => [
    critFileType(r, ctx), critUrlCategories(r, ctx), critProtocol(r, ctx), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r),
    ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { blockRe: /BLOCK/, allowRe: /ALLOW/, defaultReason: 'no DLP rule applies to this transaction' });
  const candidates = res.rules.filter((r) => r.status !== 'nomatch');
  const rules = sortRules(snap.webDlpRules);
  for (const c of candidates) {
    const src = rules.find((x) => x.id === c.id) || {};
    c.engines = names(src.dlpEngines);
    c.dictionaries = names(src.dlpDictionaries);
  }
  res.candidates = candidates;
  const blocks = candidates.filter((c) => /BLOCK/.test(c.action || ''));
  res.verdict = blocks.length ? 'CONDITIONAL_BLOCK' : candidates.length ? 'INSPECT_ONLY' : 'ALLOW';
  res.confidence = 'content-dependent';
  res.reason = candidates.length
    ? `${candidates.length} DLP rule(s) would inspect this transaction; it is blocked only if content matches the rule's DLP engine(s)`
    : 'No DLP rule applies to this transaction';
  res.note = 'DLP evaluation depends on content, not just metadata. Rules listed are those that would be applied to this transaction; engines/dictionaries show what would need to trigger.';
  return res;
}

function mSsl(snap, ctx) {
  const https = ctx.port === 443 || (ctx.target && ctx.target.scheme === 'https') || (!ctx.port && !(ctx.target && ctx.target.scheme));
  const res = runModule('SSL Inspection', snap.sslRules, (r) => [
    critUrlCategories(r, ctx, 'urlCategories'), critDest(Object.assign({}, r, { destIpCategories: [], destCountries: [] }), ctx, snap), critIdentity(r, ctx), critLocation(r, ctx), critSourceIp(r, ctx, snap),
    ...critUnmodelled(r, ['cloudApplications', 'platforms']),
  ].filter(Boolean), { blockRe: /BLOCK/, allowRe: /DECRYPT/, defaultReason: 'no matching rule (default SSL inspection action)' });
  if (res.decidingRule) {
    const a = res.decidingRule.action;
    res.verdict = /DO_NOT_DECRYPT/.test(a || '') ? 'NOT_DECRYPTED' : /DECRYPT/.test(a || '') ? 'DECRYPTED' : /BLOCK/.test(a || '') ? 'BLOCK' : a;
  } else res.verdict = 'DEFAULT';
  res.httpsApplicable = https;
  if (https && res.verdict === 'NOT_DECRYPTED') res.note = 'HTTPS is not decrypted for this transaction: URL-path, DLP, sandbox, file-type and ATP content checks cannot see inside it (domain/category-level checks still apply).';
  return res;
}

const ATP_CATEGORY_MAP = [
  ['MALWARE_SITE', 'malwareSitesBlocked', 'Malicious content'],
  ['PHISHING', 'knownPhishingSitesBlocked', 'Known phishing sites'],
  ['BOTNET', 'cmdCtlServerBlocked', 'Command & control servers'],
  ['SUSPICIOUS_DESTINATION', 'suspectedPhishingSitesBlocked', 'Suspected phishing/suspicious destinations'],
  ['SPYWARE_OR_ADWARE', 'suspectAdwareSpywareSitesBlocked', 'Suspected adware/spyware'],
  ['ADSPYWARE_SITES', 'adSpywareSitesBlocked', 'Adware/spyware sites'],
  ['WEB_SPAM', 'webspamBlocked', 'Web spam'],
  ['XSS', 'potentialMaliciousRequestsBlocked', 'Cross-site scripting / malicious requests'],
  ['BROWSER_EXPLOIT', 'browserExploitsBlocked', 'Browser exploits'],
  ['CRYPTOMINING', 'cryptoMiningBlocked', 'Cryptomining'],
  ['P2P', 'bitTorrentBlocked', 'P2P / BitTorrent'],
  ['ANONYMIZER', 'anonymizerBlocked', 'Anonymizers'],
  ['UNAUTHORIZED_COMMUNICATION', 'cmdCtlTrafficBlocked', 'Botnet/unauthorized communication'],
];
function mAtp(snap, ctx) {
  const rules = [];
  const t = ctx.target;
  const s = snap.atpSettings || {};
  const pickList = (o, keys) => { if (!o) return []; for (const k of keys) if (Array.isArray(o[k])) return o[k]; return Array.isArray(o) ? o : []; };
  const allow = pickList(snap.atpSecurityExceptions, ['whitelistUrls', 'bypassUrls']).filter((x) => typeof x === 'string');
  const deny = pickList(snap.atpMaliciousUrls, ['blacklistUrls', 'maliciousUrls']).filter((x) => typeof x === 'string');
  let decided = null;
  const out = { module: 'Advanced Threat Protection', verdict: 'ALLOW', confidence: 'definite', decidingRule: null, couldOverride: [], rules, reason: 'No ATP setting or list entry matches', considered: 0 };
  if (t) {
    const a = M.domainInList(t, allow);
    const d = M.domainInList(t, deny);
    if (a.rel !== 'none') rules.push({ name: 'Security exception (allowlist)', action: 'ALLOW', status: a.rel === 'match' ? 'match' : 'unknown', criteria: [{ field: 'URL', status: a.rel === 'match' ? 'match' : 'unknown', detail: `${t.host} vs ${a.entry}` }] });
    if (d.rel !== 'none') rules.push({ name: 'Malicious URL list (denylist)', action: 'BLOCK', status: d.rel === 'match' ? 'match' : 'unknown', criteria: [{ field: 'URL', status: d.rel === 'match' ? 'match' : 'unknown', detail: `${t.host} vs ${d.entry}` }] });
  }
  for (const [cat, flag, label] of ATP_CATEGORY_MAP) {
    if (s[flag] === undefined) continue;
    const inCat = (ctx.categories || []).some((c) => lc(c) === lc(cat));
    if (inCat) rules.push({ name: `ATP: ${label}`, action: s[flag] ? 'BLOCK' : 'ALLOW', status: 'match', criteria: [{ field: 'category', status: 'match', detail: `target categorized ${cat}; ${flag}=${s[flag]}` }] });
  }
  if (ctx.destCountry && arr(s.blockedCountries).some((c) => lc(c).replace('country_', '') === lc(ctx.destCountry).replace('country_', '')))
    rules.push({ name: 'ATP: Blocked countries', action: 'BLOCK', status: 'match', criteria: [{ field: 'country', status: 'match', detail: `${ctx.destCountry} is in blockedCountries` }] });
  const hit = rules.find((r) => r.status === 'match' && r.action === 'ALLOW' && /allowlist/.test(r.name)) || rules.find((r) => r.status === 'match' && r.action === 'BLOCK') || null;
  if (hit) { out.verdict = hit.action; out.decidingRule = hit; out.reason = `${hit.name} matched`; }
  out.couldOverride = rules.filter((r) => r.status === 'unknown');
  if (out.couldOverride.length) out.confidence = 'conditional';
  out.settings = {
    riskTolerance: s.riskTolerance, blockedCountries: s.blockedCountries,
    enabledBlocks: Object.keys(s).filter((k) => /Blocked$/.test(k) && s[k] === true),
  };
  out.note = 'Page-risk tolerance (riskTolerance) and signature-based detections are content/reputation-driven and cannot be simulated; category-based ATP blocks and allow/deny lists are evaluated. Allowlist is assumed to take precedence over denylist — verify in your tenant.';
  out.considered = rules.length;
  return out;
}

// ZPA access policy
function zpaMatch(snap, ctx) {
  const t = ctx.target;
  const apps = arr(snap.zpaApps);
  if (!t) return { apps: [], groups: [] };
  const matched = [];
  for (const a of apps) {
    if (lc(a.enabled) === 'false') continue;
    const dom = arr(a.domainNames);
    const r = M.domainInList(t, dom.filter((d) => !M.parseIpRange(d)));
    let ipRel = { rel: 'none' };
    if (t.isIp) ipRel = M.ipInList(t.host, dom.filter((d) => M.parseIpRange(d)));
    const rel = r.rel !== 'none' ? r.rel : ipRel.rel;
    if (rel === 'none') continue;
    let portOk = true, portNote = '';
    if (ctx.port != null) {
      const raw = ctx.protocol === 'udp' ? a.udpPortRanges || a.udpPortRange : a.tcpPortRanges || a.tcpPortRange;
      let ranges = [];
      if (Array.isArray(raw) && raw.length && typeof raw[0] === 'string' && raw.every((x) => /^\d+$/.test(x))) {
        for (let i = 0; i + 1 < raw.length; i += 2) ranges.push([+raw[i], +raw[i + 1]]); // ZPA returns flat [from,to,from,to]
      } else if (Array.isArray(raw) && raw.length && typeof raw[0] === 'object') {
        ranges = raw.map((p) => [+p.from, +p.to]);
      } else ranges = M.parsePorts(raw);
      if (ranges.length) portOk = M.portInRanges(ctx.port, ranges);
    }
    if (portOk) matched.push({ id: a.id, name: a.name, segmentGroupId: a.segmentGroupId, rel, via: r.entry || ipRel.entry });
  }
  return { apps: matched, groups: [...new Set(matched.map((m) => String(m.segmentGroupId)).filter(Boolean))] };
}
function mZpa(snap, ctx) {
  if (!snap.zpaAccessRules) return null;
  const z = zpaMatch(snap, ctx);
  const out = { module: 'ZPA Access Policy', verdict: 'NOT_A_ZPA_APP', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0, matchedSegments: z.apps, reason: 'Destination does not match any ZPA application segment, so ZPA policy does not apply (traffic follows ZIA/forwarding)' };
  if (!z.apps.length) return out;
  const appIds = z.apps.map((a) => String(a.id));
  const rules = sortRules(snap.zpaAccessRules.map((r) => Object.assign({ order: r.ruleOrder != null ? +r.ruleOrder : r.order }, r))).filter((r) => lc(r.disabled) !== '1' && lc(r.disabled) !== 'true');
  const evaluated = rules.map((r) => {
    const crits = [];
    for (const c of arr(r.conditions)) {
      const ops = arr(c.operands);
      const evalOp = (o) => {
        const vals = arr(o.values || (o.rhs != null ? [o.rhs] : []));
        if (o.objectType === 'APP') return vals.some((v) => appIds.includes(String(v))) ? 'match' : 'nomatch';
        if (o.objectType === 'APP_GROUP') return vals.some((v) => z.groups.includes(String(v))) ? 'match' : 'nomatch';
        return 'unknown';
      };
      const results = ops.map((o) => ({ o, s: evalOp(o) }));
      const types = [...new Set(ops.map((o) => o.objectType))].join('/');
      let status = results.some((x) => x.s === 'match') ? 'match' : results.some((x) => x.s === 'unknown') ? 'unknown' : 'nomatch';
      if (c.operator === 'AND') status = results.some((x) => x.s === 'nomatch') ? 'nomatch' : results.some((x) => x.s === 'unknown') ? 'unknown' : 'match';
      crits.push({ field: types || 'condition', status, detail: status === 'unknown' ? `${types} condition depends on user/device context (not supplied)` : `${types} ${status}` });
    }
    const e = evalRule(r, crits);
    e.action = r.action;
    return e;
  });
  const idx = evaluated.findIndex((e) => e.status === 'match');
  out.rules = evaluated; out.considered = evaluated.length;
  out.couldOverride = evaluated.slice(0, idx < 0 ? evaluated.length : idx).filter((e) => e.status === 'unknown');
  if (idx >= 0) { out.decidingRule = evaluated[idx]; out.verdict = /DENY/.test(evaluated[idx].action) ? 'BLOCK' : 'ALLOW'; out.reason = `Rule "${evaluated[idx].name}" matched`; }
  else { out.verdict = 'BLOCK'; out.reason = 'Matched an application segment but no access rule allows it (ZPA default deny)'; }
  if (out.couldOverride.length) out.confidence = 'conditional';
  return out;
}

// Forwarding / bypass: PAC, ZCC app profile + forwarding profile lists, plus manual lists.
function lines(s) { return String(s || '').split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean); }
function scanLists(obj, prefix, out) {
  if (!obj || typeof obj !== 'object') return;
  for (const [k, v] of Object.entries(obj)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (/(include|exclu|bypass|vpngateway|trustedgateway)/i.test(k) && /(ip|host|dest|domain|gateway|list|bypass|exclu|inclu)/i.test(k + p)) {
      const vals = Array.isArray(v) ? v.filter((x) => typeof x === 'string') : typeof v === 'string' ? lines(v) : [];
      if (vals.length) out.push({ key: p, values: vals });
    } else if (v && typeof v === 'object' && !Array.isArray(v)) scanLists(v, p, out);
  }
}
function mForwarding(snap, ctx, manual = {}) {
  const t = ctx.target;
  const out = { module: 'Forwarding & Bypass (PAC / ZCC)', verdict: 'VIA_ZSCALER', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], reason: 'Traffic reaches Zscaler', considered: 0, profiles: [] };
  if (!t) return Object.assign(out, { verdict: 'N/A', reason: 'Not evaluated: no destination entered (bypass lists and PAC files match on destination)' });
  const pacCache = {};
  for (const f of arr(snap.pacFetched)) if (f.text) pacCache[f.url] = f.text;

  // 1) Client Connector app profiles — one row per profile
  const ZCC = require('./zcc');
  out.profiles = ZCC.evaluateProfiles(snap, ctx, pacCache);
  out.considered = out.profiles.length;

  // 2) Manual inputs (pasted PAC, extra lists) as an extra "profile"
  const manualProfile = {
    name: 'Manual inputs', _platform: '', groupAll: 1,
    packetTunnelExcludeList: lines(manual.ipExclusions), packetTunnelIncludeList: lines(manual.ipInclusions),
    packetTunnelDnsExcludeList: lines(manual.destExclusions), packetTunnelDnsIncludeList: lines(manual.destInclusions),
    vpnGateways: lines(manual.vpnGateways),
  };
  const hasManual = [manual.ipExclusions, manual.ipInclusions, manual.destExclusions, manual.destInclusions, manual.vpnGateways, manual.pacText].some((x) => x && String(x).trim());
  if (hasManual) {
    const fa = manual.pacText && /FindProxyForURL/.test(manual.pacText) ? { networkType: 2, actionType: 1, enablePacketTunnel: 1, customPac: manual.pacText } : null;
    const r = ZCC.evalPath(manualProfile, fa, ctx, snap, pacCache);
    out.profiles.push({ name: 'Manual inputs', platform: '', appliesTo: 'what you entered', applies: 'yes', forwardingProfile: fa ? 'pasted PAC' : null, outcomes: [{ outcome: r.outcome, how: r.how, steps: r.steps, nets: ['—'] }], summary: r.outcome });
  }

  const relevant = out.profiles.filter((p) => p.applies !== 'no');
  const bypassing = relevant.filter((p) => p.summary !== 'ZIA');
  if (!relevant.length) { out.reason = 'No Client Connector app profiles loaded — assuming traffic reaches Zscaler'; return out; }
  if (bypassing.length === relevant.length && relevant.every((p) => p.outcomes.every((o) => o.outcome !== 'ZIA'))) {
    out.verdict = 'BYPASSES_ZSCALER';
    out.reason = `Bypassed in every applicable app profile — ${bypassing[0].outcomes[0].how}`;
    const hows = [...new Set(bypassing.flatMap((p) => p.outcomes.map((o) => o.how)))];
    out.decidingRule = { name: hows.length === 1 ? hows[0] : 'Bypassed in every applicable app profile', action: 'BYPASS',
      criteria: bypassing.flatMap((p) => p.outcomes.map((o) => ({ field: `${p.platform ? p.platform + ' — ' : ''}${p.name}`, status: 'match', detail: `${o.how}${o.nets && !['—', 'All networks'].includes(o.nets[0]) ? ' (' + o.nets.join(', ') + ')' : ''}` }))) };
  } else if (bypassing.length) {
    out.verdict = 'DEPENDS_ON_PROFILE';
    out.confidence = 'conditional';
    out.reason = `Bypassed in ${bypassing.length} of ${relevant.length} applicable app profile(s) or network types; reaches Zscaler in the others`;
  } else out.reason = `Reaches Zscaler in all ${relevant.length} applicable app profile(s)`;
  return out;
}

// ---------- top-level ----------
function simulate(snap, ctx, manual = {}) {
  const data = snap.data || snap;
  // custom URL categories -> add matching ids to ctx.categories
  const cats = new Set((ctx.categories || []).map(String));
  for (const c of arr(data.customUrlCategories)) {
    const ents = [...arr(c.urls), ...arr(c.dbCategorizedUrls)];
    const ips = arr(c.ipRanges);
    let hit = false;
    if (ctx.target) {
      if (!ctx.target.isIp && M.domainInList(ctx.target, ents).rel === 'match') hit = true;
      const ipsToTest = ctx.target.isIp ? [ctx.target.host] : ctx.resolvedIps || [];
      for (const ip of ipsToTest) if (M.ipInList(ip, ips).rel === 'match') hit = true;
    }
    if (hit) { cats.add(c.id); if (c.configuredName) cats.add(c.configuredName); }
  }
  const c2 = Object.assign({}, ctx, { categories: [...cats] });
  rationalize(c2, data);
  c2.notes = [...(c2.notes || []), ...c2.inferred.notes];
  const na = (module) => ({ module, verdict: 'N/A', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0,
    reason: !c2.target ? 'Not evaluated: no destination entered (web policies need a URL or host)' : `Not applicable: ${(c2.protocol || 'tcp').toUpperCase()}/${c2.port} is not web traffic, so it is handled by the firewall, not the web proxy` });
  const hasHost = !!(c2.target && !c2.target.isIp);
  const web = c2.isWeb && !!c2.target;
  const naNoDest = (module, why) => ({ module, verdict: 'N/A', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0, reason: why });
  const fwd = mForwarding(data, c2, manual);
  const ssl = web ? mSsl(data, c2) : na('SSL Inspection');
  // Derive the request method the proxy would evaluate, unless the user supplied one.
  if (!c2.method && web) {
    const t = c2.target;
    const isHttp = (t && t.scheme === 'http') || c2.port === 80;
    c2.methodAssumed = true;
    if (!isHttp && ssl.verdict === 'NOT_DECRYPTED') { c2.method = 'CONNECT'; c2.methodReason = 'HTTPS not decrypted'; }
    else { c2.method = 'GET'; c2.methodReason = isHttp ? 'plain HTTP' : 'HTTPS decrypted'; }
  }
  // Order roughly follows the ZIA processing path; the summary reports the first block in this order.
  const modules = [
    fwd,
    mFirewall(data, c2),
    hasHost ? mDns(data, c2) : naNoDest('DNS Control', c2.target ? 'Not applicable: destination is an IP address (no DNS lookup)' : 'Not evaluated: no destination host entered'),
    ssl,
    web ? mAtp(data, c2) : na('Advanced Threat Protection'),
    web ? mUrlFiltering(data, c2) : na('URL Filtering'),
    web ? mFileType(data, c2) : na('File Type Control'),
    web ? mSandbox(data, c2) : na('Sandbox (Behavioral Analysis)'),
    web ? mDlp(data, c2) : na('Data Loss Prevention'),
  ];
  const zpa = mZpa(data, c2);
  if (zpa) modules.push(zpa);
  return { context: c2, modules, summary: summarize(modules, c2) };
}

// Outcome model shown at the top of the results:
//   primary      — the Policy Rule Action for everyone the inputs don't narrow down
//                  (BLOCK | ALLOW | BYPASS | ISOLATE | CAUTION) with tags NOT_INSPECTED / INSPECT_ONLY
//   alsoBasedOn  — each condition that would change that action: identity, location, other rule conditions
//                  (time window, device trust, ...), Client Connector app profile / network type, uploaded content
const ACT_RE = (a) => { const x = String(a || ''); return /ISOLATE/i.test(x) ? 'ISOLATE' : /CAUTION/i.test(x) ? 'CAUTION' : /BYPASS/i.test(x) ? 'BYPASS' : /BLOCK|DROP|RESET|DENY|REJECT/i.test(x) ? 'BLOCK' : 'ALLOW'; };
function condKind(c) {
  if (c.kind) return c.kind;
  if (/user|group|department|scim|saml|idp/i.test(c.field)) return 'identity';
  if (/location/i.test(c.field)) return 'location';
  if (/time|device|posture|trusted|platform|risk|agent|country|label/i.test(c.field)) return 'other';
  return 'input';
}
const INPUT_HINT = { 'url category': 'URL category', destination: 'Destination', 'network service': 'Network service / port', 'network application': 'Network application', 'file type': 'File type', 'request method': 'Request method', 'dns application': 'DNS application', protocol: 'Protocol', 'source IP': 'Source IP', operation: 'File operation', 'dns protocol': 'DNS protocol' };
function condLabel(c) {
  if (c.scope) return c.scope;
  if (condKind(c) === 'input') return `${INPUT_HINT[c.field] || c.field}: ${String(c.detail).replace(/^rule /, '').slice(0, 90)}`;
  return `${c.field}: ${String(c.detail).slice(0, 90)}`;
}

function summarize(modules, ctx = {}) {
  const by = Object.fromEntries(modules.map((m) => [m.module, m]));
  const fw = by['Forwarding & Bypass (PAC / ZCC)'];
  const zpa = by['ZPA Access Policy'];
  const ssl = by['SSL Inspection'];
  const dlp = by['Data Loss Prevention'];
  const sandbox = by['Sandbox (Behavioral Analysis)'];
  const upload = /^(UPLOAD)$/i.test(ctx.operation || '') || /^(POST|PUT)$/i.test(ctx.method || '');
  const lines = [], bypasses = [], allowedBy = [], inspections = [], alsoBasedOn = [];
  const pick = (m, action) => ({ module: m.module, action: action || ACT_RE(m.decidingRule ? m.decidingRule.action : m.verdict), rule: m.decidingRule ? m.decidingRule.name : null, order: m.decidingRule ? m.decidingRule.order : null, criteria: m.decidingRule ? m.decidingRule.criteria : [], reason: m.reason, note: m.note, confidence: m.confidence });
  const label = (m) => `${m.module}: ${m.verdict}${m.decidingRule ? ` — rule "${m.decidingRule.name}"` : ''}`;
  const addConds = (m) => {
    for (const r of m.couldOverride || []) {
      const unk = (r.criteria || []).filter((c) => c.status === 'unknown');
      const kinds = [...new Set(unk.map(condKind))];
      const kind = ['identity', 'location', 'other', 'input'].find((k) => kinds.includes(k)) || 'other';
      alsoBasedOn.push({ kind, condition: unk.map(condLabel).join(' + ') || 'context not supplied', action: ACT_RE(r.action), module: m.module, rule: r.name, order: r.order });
    }
  };

  // Client Connector bypasses (per app profile / network type)
  const fwdProfiles = (fw && fw.profiles) || [];
  for (const p of fwdProfiles) for (const o of p.outcomes) if (o.outcome !== 'ZIA' && p.applies !== 'no')
    bypasses.push({ kind: 'forwarding', where: `${p.platform ? p.platform + ' · ' : ''}${p.name}${o.nets && !['—', 'All networks'].includes(o.nets[0]) ? ' · ' + o.nets.join(', ') : ''}`, how: o.how, captured: o.outcome !== 'NOT_CAPTURED' });
  if (ssl && ssl.verdict === 'NOT_DECRYPTED') bypasses.push({ kind: 'ssl', where: 'SSL Inspection', how: `not decrypted by rule "${ssl.decidingRule && ssl.decidingRule.name}"` });

  // ZIA (or ZPA) outcome for traffic that reaches Zscaler
  let zia;
  if (zpa && zpa.verdict !== 'NOT_A_ZPA_APP') {
    zia = pick(zpa, zpa.verdict === 'BLOCK' ? 'BLOCK' : 'ALLOW');
    lines.push(`Destination is a ZPA application segment (${(zpa.matchedSegments || []).map((x) => x.name).join(', ')}) — ZPA access policy decides, not ZIA.`);
    addConds(zpa);
  } else {
    const pipeline = modules.filter((m) => !m.module.startsWith('Forwarding') && m.module !== 'ZPA Access Policy' && !['N/A'].includes(m.verdict));
    const finalIdx = pipeline.findIndex((m) => ['BLOCK', 'ISOLATE', 'CAUTION'].includes(m.verdict) && m.confidence === 'definite' && !(m.module === 'Data Loss Prevention'));
    const upto = finalIdx >= 0 ? pipeline.slice(0, finalIdx + 1) : pipeline;
    if (finalIdx >= 0) { const m = pipeline[finalIdx]; zia = pick(m, m.verdict); lines.push(`${m.verdict === 'BLOCK' ? 'Blocked' : m.verdict === 'ISOLATE' ? 'Isolated' : 'Cautioned'} by ${label(m)}`); }
    else {
      const url = by['URL Filtering'];
      zia = url && url.verdict !== 'N/A' ? pick(url, 'ALLOW') : (pipeline[0] ? pick(pipeline.find((m) => m.module === 'Firewall') || pipeline[0], 'ALLOW') : { module: 'ZIA', action: 'ALLOW', rule: null, criteria: [], reason: 'No ZIA module applies' });
      for (const m of pipeline) {
        if (m.module === 'Data Loss Prevention' && m.verdict !== 'ALLOW') continue;
        allowedBy.push({ module: m.module, rule: m.decidingRule ? m.decidingRule.name : null, order: m.decidingRule ? m.decidingRule.order : null, action: m.decidingRule ? m.decidingRule.action : m.verdict, reason: m.reason, confidence: m.confidence });
      }
      lines.push('No module blocks this transaction based on the supplied context.');
    }
    for (const m of upto) if (m.module !== 'Data Loss Prevention') addConds(m);
    // DLP: content-dependent
    const notDecrypted = ssl && ssl.verdict === 'NOT_DECRYPTED' && !((ctx.target && ctx.target.scheme === 'http') || ctx.port === 80);
    if (dlp && dlp.verdict === 'CONDITIONAL_BLOCK' && !notDecrypted && (finalIdx < 0 || pipeline.indexOf(dlp) < finalIdx)) {
      const c = dlp.candidates || [];
      const blk = c.find((r) => /BLOCK/.test(r.action || '')) || c[0];
      if (blk) {
        alsoBasedOn.push({ kind: 'content', condition: `${upload ? 'Uploaded' : 'Uploaded / posted'} content matching ${blk.engines && blk.engines.length ? 'DLP engine ' + blk.engines.join(', ') : 'the DLP rule'}`, action: ACT_RE(blk.action), module: dlp.module, rule: blk.name, order: blk.order });
        inspections.push({ module: dlp.module, how: `${c.length} DLP rule(s) inspect uploaded content (e.g. "${blk.name}") — blocks only if content matches` });
      }
    }
  }
  const tags = [];
  if (ssl && ssl.verdict === 'NOT_DECRYPTED' && zia.action !== 'BLOCK') tags.push({ tag: 'NOT_INSPECTED', text: `SSL not decrypted — rule "${ssl.decidingRule && ssl.decidingRule.name}"` });
  const sslHidden = ssl && ssl.verdict === 'NOT_DECRYPTED' && !((ctx.target && ctx.target.scheme === 'http') || ctx.port === 80);
  if (!sslHidden && zia.action !== 'BLOCK' && ((dlp && (dlp.candidates || []).length) || (sandbox && sandbox.decidingRule && !/BLOCK/.test(sandbox.decidingRule.action || ''))))
    tags.push({ tag: 'INSPECT_ONLY', text: [dlp && (dlp.candidates || []).length ? 'DLP scans content' : null, sandbox && sandbox.decidingRule && !/BLOCK/.test(sandbox.decidingRule.action || '') ? `sandbox rule "${sandbox.decidingRule.name}"` : null].filter(Boolean).join(' · ') });

  // Forwarding decides whether ZIA sees it at all
  let primary;
  const fwdB = bypasses.filter((b) => b.kind === 'forwarding');
  if (fw && fw.verdict === 'BYPASSES_ZSCALER') {
    primary = { module: 'Client Connector forwarding', action: 'BYPASS', rule: fw.decidingRule.name, criteria: fw.decidingRule.criteria, reason: fw.reason, confidence: 'definite', tags: [] };
    alsoBasedOn.length = 0;
    alsoBasedOn.unshift({ kind: 'zia', condition: 'If it were forwarded to Zscaler', action: zia.action, module: zia.module, rule: zia.rule, order: zia.order });
    lines.unshift('Traffic bypasses Zscaler (PAC/ZCC bypass) — no ZIA policy is applied.');
  } else {
    primary = Object.assign({}, zia, { tags });
    for (const b of fwdB) alsoBasedOn.push({ kind: 'zcc', condition: b.where, action: 'BYPASS', module: 'Client Connector forwarding', rule: null, detail: b.how + (b.captured ? '' : ' (not captured by ZCC)') });
  }
  primary.tags = primary.tags || tags;

  // de-duplicate, keep order: identity, location, other, zcc, content, input
  const seen = new Set();
  const order = { zia: -1, identity: 0, location: 1, other: 2, zcc: 3, content: 4, input: 5 };
  const conds = alsoBasedOn.filter((c) => { const k = c.kind + c.condition + c.action + c.rule; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => (order[a.kind] - order[b.kind]));

  const overall = { BLOCK: 'BLOCKED', ALLOW: 'ALLOWED', BYPASS: 'BYPASSED', ISOLATE: 'ISOLATED', CAUTION: 'CAUTIONED' }[primary.action] || 'ALLOWED';
  const headline = primary.action === 'BYPASS' ? 'Never reaches Zscaler, so no ZIA policy applies'
    : `${{ BLOCK: 'Blocked', ALLOW: 'Allowed', ISOLATE: 'Isolated', CAUTION: 'Caution page' }[primary.action]} by ${primary.module}${primary.rule ? ` — rule "${primary.rule}"` : ''}`;
  if (ctx.methodAssumed) lines.push(`Request method assumed ${ctx.method} (${ctx.methodReason}).`);
  const decider = primary.action === 'ALLOW' && !conds.length ? null : primary;
  return { overall, headline, primary, alsoBasedOn: conds, decider, allowedBy, bypasses, inspections, lines };
}

module.exports = { simulate, rationalize, ATP_CATEGORY_MAP, WELL_KNOWN, fileTypeMatch, FILETYPE_ALIASES, mUrlFiltering, mFirewall, mDns, mSandbox, mFileType, mDlp, mSsl, mAtp, mZpa, mForwarding, sortRules };
