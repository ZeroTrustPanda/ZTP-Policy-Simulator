'use strict';
// Policy evaluation engine. Pure functions over a snapshot (rules pulled from the APIs) and a transaction context.
// Each criterion returns {field, status: 'match'|'nomatch'|'unknown'|'any', detail}.
// A rule is: nomatch if any criterion is nomatch; unknown if none nomatch but some unknown; match otherwise.

const M = require('./matchers');
const W = require('./workload');

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
  if (ctx.source === 'workload') return { field: 'user/group/department', status: 'nomatch', detail: `rule applies to ${[...names(rl.users), ...names(rl.groups), ...names(rl.departments)].slice(0, 4).join(', ')}; workload traffic carries no user identity` };
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
  const groupNames = [], emptyGroups = [];
  const gCats = [], gCountries = [];
  for (const g of arr(rule.destIpGroups)) {
    const full = (snap.ipDestinationGroups || []).find((x) => String(x.id) === String(g.id));
    const name = g.name || (full && full.name) || g.id;
    groupNames.push(name);
    if (!full) continue;
    const a = [...arr(full.addresses), ...arr(full.ipAddresses)];
    addrs.push(...a);
    gCats.push(...arr(full.ipCategories), ...arr(full.urlCategories)); gCountries.push(...arr(full.countries));
    if (!a.length && !arr(full.ipCategories).length && !arr(full.urlCategories).length && !arr(full.countries).length) emptyGroups.push({ name, type: full.type });
  }
  const cats = nonAny([...arr(rule.destIpCategories), ...gCats].map((c) => (c && c.name) || c));
  const countries = nonAny([...arr(rule.destCountries), ...gCountries]);
  if (!addrs.length && !cats.length && !countries.length) {
    if (!emptyGroups.length) return { field: 'destination', status: 'any', detail: 'not restricted' };
    // A group the API returns with no entries (e.g. the auto-created "ZPA Brokers" group, type DSTN_OTHER): its
    // members are managed by Zscaler. ZPA brokers are *.zpath.net / *.private.zscaler.com.
    const names = emptyGroups.map((g) => g.name).join(', ');
    if (emptyGroups.some((g) => /zpa broker/i.test(g.name))) {
      const t = ctx.target;
      if (!t) return { field: 'destination', status: 'unknown', scope: `Destination group ${names}`, detail: `rule applies to ${names} (ZPA brokers) — no destination entered` };
      const broker = !t.isIp && /(^|\.)(zpath\.net|private\.zscaler\.com)$/i.test(t.host);
      return { field: 'destination', status: broker ? 'match' : 'nomatch', detail: broker ? `${t.host} is a ZPA broker (${names})` : `${t.host} is not a ZPA broker (${names}: *.zpath.net, *.private.zscaler.com)` };
    }
    return { field: 'destination', status: 'unknown', scope: `Destination group ${names}`, detail: `destination group ${names} has no entries the API returns (managed by Zscaler) — can't check membership` };
  }
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
const UNMODELLED = ['userAgentTypes', 'deviceTrustLevels', 'userRiskScoreLevels', 'deviceGroups', 'devices', 'labels', 'sourceCountries', 'cloudApplications', 'platforms', 'timeQuota', 'sizeQuota'];
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
// ZIA evaluates rules by `order`. With Admin Ranking enabled (Advanced Settings → enableAdminRankAccess), rules are
// evaluated by admin rank first (0 = highest, 7 = lowest) and by order within a rank, as the ZIA policy table and the
// Terraform provider sort them. With ranking disabled the rank is ignored (ZIA may still store 0 or 7).
// Default/catch-all rules come back with order -1 (or a defaultRule flag) and are evaluated LAST.
function isDefaultRule(r) {
  const o = Number(r.order);
  return r.defaultRule === true || r.default === true || (Number.isFinite(o) && o < 0) ||
    (r.predefined === true && /^default\b/i.test(String(r.name || '')));
}
const rankOf = (r) => { const n = Number(r && r.rank); return Number.isFinite(n) && n >= 0 && n <= 7 ? n : 7; };
// Admin Ranking on? From ZIA Advanced Settings; an explicit simulator override wins.
function rankOn(snap) {
  if (snap && typeof snap._rankOverride === 'boolean') return snap._rankOverride;
  return !!(snap && snap.advancedSettings && snap.advancedSettings.enableAdminRankAccess === true);
}
function sortKey(r, ranked) {
  const o = Number(r.order);
  return [isDefaultRule(r) ? 1 : 0, ranked ? rankOf(r) : 0, Number.isFinite(o) && o >= 0 ? o : 1e9];
}
function sortRules(rules, ranked = false) {
  return arr(rules).slice().sort((a, b) => { const x = sortKey(a, ranked), y = sortKey(b, ranked); return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]; });
}
// Rules that admin rank moves ahead of the deciding rule although their order number is higher, or behind it although
// lower: shown so the result explains why a rule with a later order number decided.
function rankEffects(evaluated, deciding) {
  if (!deciding) return [];
  const di = evaluated.indexOf(deciding), out = [];
  evaluated.forEach((e, i) => {
    if (e === deciding || e._default) return;
    const eo = Number(e.order), dord = Number(deciding.order);
    if (!(eo >= 0 && dord >= 0)) return;
    if (i > di && eo < dord && e.status !== 'nomatch') out.push({ name: e.name, order: e.order, rank: e.rank, action: e.action, status: e.status, side: 'after' });
  });
  return out;
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

// Multi-match: rules after the deciding one whose criteria also match this transaction. They never apply
// (first match wins), but they show overlapping or shadowed policy. Catch-alls (default rules, or rules with no
// restricting criteria) match everything, so they are counted rather than listed.
const isCatchAll = (e) => !(e.criteria || []).some((c) => c.status !== 'any');
function multiMatch(evaluated, deciding, verdictOf) {
  if (!deciding) return { list: [], catchAll: 0 };
  const after = evaluated.slice(evaluated.indexOf(deciding) + 1).filter((e) => e.status === 'match');
  const listed = after.filter((e) => !e._default && !isCatchAll(e));
  const dv = verdictOf ? verdictOf(deciding) : deciding.action;
  return { list: listed.map((e) => ({ id: e.id, name: e.name, order: e.order, rank: e.rank, action: e.action, differs: (verdictOf ? verdictOf(e) : e.action) !== dv })), catchAll: after.length - listed.length };
}

function ruleAction(rule) {
  if (rule.action && typeof rule.action === 'object') return rule.action.type || JSON.stringify(rule.action);
  return rule.action || rule.baRuleAction || rule.filteringAction || rule.accessControl || null;
}

// Generic ordered module evaluator.
// mode 'first': first definite match decides; unknown rules ahead of it are "could override".
// mode 'content': content-dependent (DLP): report all rules whose non-content criteria match.
function runModule(module, rules, buildCrits, { blockRe, allowRe, defaultVerdict = 'ALLOW', defaultReason = 'no matching rule (default action)', skipNote, ranked = false } = {}) {
  const sorted = sortRules(rules, ranked).filter((r) => lc(r.state) !== 'disabled');
  const evaluated = sorted.map((r) => Object.assign(evalRule(r, buildCrits(r)), isDefaultRule(r) ? { _default: true } : {}));
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
  const mm = multiMatch(evaluated, deciding, (e) => verdictOf(e.action));
  return {
    alsoMatched: mm.list, alsoMatchedCatchAll: mm.catchAll,
    rankOrdered: ranked, rankEffects: ranked ? rankEffects(evaluated, deciding) : [],
    module, verdict, confidence,
    decidingRule: deciding, couldOverride: changers, sameOutcomeEarlier: sameOutcome,
    reason: deciding ? `Rule "${deciding.name}" (order ${deciding.order}${ranked ? `, admin rank ${rankOf(deciding)}` : ''}) matched` : defaultReason,
    considered: evaluated.length, rules: evaluated, note: skipNote,
  };
}

// ---------- module builders ----------
function mUrlFiltering(snap, ctx) {
  return runModule('URL Filtering', snap.urlFilteringRules, (r) => [
    critProtocol(r, ctx), critUrlCategories(r, ctx), critMethod(r, ctx), critIdentity(r, ctx), critLocation(r, ctx), critSourceIp(r, ctx, snap), critTimeWindows(r),
    W.critWorkload(r, ctx), ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { ranked: rankOn(snap), blockRe: /^(BLOCK)$/, allowRe: /^(ALLOW|CAUTION|ISOLATE)$/ });
}

function mFirewall(snap, ctx) {
  const web = (ctx.protocol || 'tcp') === 'tcp' && (ctx.port === 80 || ctx.port === 443 || (ctx.target && /^https?$/.test(ctx.target.scheme || '')));
  const res = runModule('Firewall', snap.firewallRules, (r) => [
    critSourceIp(r, ctx, snap), critDest(r, ctx, snap), critServices(r, ctx, snap), critApps(r, ctx, snap), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r),
    W.critWorkload(r, ctx), ...critUnmodelled(r, ['sourceCountries', 'cloudApplications']),
  ].filter(Boolean), { ranked: rankOn(snap), blockRe: /^BLOCK/, allowRe: /^(ALLOW|EVAL_NWAPP)$/, defaultReason: 'no matching rule (default firewall rule applies)' });
  if (web) res.note = 'Ports 80/443 normally pass through the web proxy path (URL filtering etc.); firewall rules apply to all-port traffic from ZCC/GRE/IPsec depending on "Enable Firewall" and location settings.';
  return res;
}

function mDns(snap, ctx) {
  const dnsCtx = Object.assign({}, ctx);
  return runModule('DNS Control', snap.dnsRules, (r) => {
    const proto = nonAny(r.protocols);
    return [
      proto.length ? { field: 'dns protocol', status: ctx.dnsProtocol ? (proto.some((p) => lc(p).startsWith(lc(ctx.dnsProtocol))) ? 'match' : 'nomatch') : 'unknown', detail: `rule ${proto.join(', ')}` } : null,
      critSourceIp(r, dnsCtx, snap), critDest(r, dnsCtx, snap), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r), W.critWorkload(r, ctx),
      nonAny(r.applications).length ? (() => {
        const apps = nonAny(r.applications);
        if (ctx.application) { const ok = apps.some((a) => lc(a) === lc(ctx.application)); return { field: 'dns application', status: ok ? 'match' : 'nomatch', detail: `${ctx.application} ${ok ? 'in' : 'not in'} ${apps.slice(0, 5).join(', ')}` }; }
        const ok = apps.some((a) => /^(DNS|ANY)$/i.test(a));
        return { field: 'dns application', status: ok ? 'match' : 'nomatch', detail: `assumed a standard DNS lookup through your resolver; rule apps ${apps.slice(0, 5).join(', ')} — set Application (e.g. GOOGLE_DNS, DOH) to test those` };
      })() : null,
    ].filter(Boolean);
  }, { ranked: rankOn(snap), blockRe: /^BLOCK/, allowRe: /^(ALLOW|REDIR)/, defaultReason: 'no matching rule (DNS resolves normally)' });
}

function mSandbox(snap, ctx) {
  return runModule('Sandbox (Behavioral Analysis)', snap.sandboxRules, (r) => [
    critFileType(r, ctx), critUrlCategories(r, ctx), critProtocol(r, ctx), critIdentity(r, ctx), critLocation(r, ctx),
    W.critWorkload(r, ctx), ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { ranked: rankOn(snap), blockRe: /BLOCK/, allowRe: /ALLOW/, defaultReason: 'no matching rule (file is not held for sandbox analysis by policy)' });
}

function mFileType(snap, ctx) {
  const op = ctx.operation; // DOWNLOAD / UPLOAD
  return runModule('File Type Control', snap.fileTypeRules, (r) => [
    critFileType(r, ctx), critUrlCategories(r, ctx),
    nonAny(r.operation).length ? { field: 'operation', status: op ? (lc(r.operation) === lc(op) || lc(r.operation) === 'any' ? 'match' : 'nomatch') : 'unknown', detail: `rule ${r.operation}` } : null,
    critProtocol(r, ctx), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r),
    W.critWorkload(r, ctx), ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { ranked: rankOn(snap), blockRe: /BLOCK/, allowRe: /ALLOW|CAUTION/, defaultReason: 'no matching rule (file type allowed)' });
}

// DLP is content dependent: rules matching on non-content criteria are *candidates*; verdict is conditional.
function mDlp(snap, ctx) {
  const res = runModule('Data Loss Prevention', snap.webDlpRules, (r) => [
    critFileType(r, ctx), critUrlCategories(r, ctx), critProtocol(r, ctx), critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r),
    W.critWorkload(r, ctx), ...critUnmodelled(r, ['cloudApplications']),
  ].filter(Boolean), { ranked: rankOn(snap), blockRe: /BLOCK/, allowRe: /ALLOW/, defaultReason: 'no DLP rule applies to this transaction' });
  const candidates = res.rules.filter((r) => r.status !== 'nomatch');
  const rules = sortRules(snap.webDlpRules, rankOn(snap));
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
    W.critWorkload(r, ctx), ...critUnmodelled(r, ['cloudApplications', 'platforms']),
  ].filter(Boolean), { ranked: rankOn(snap), blockRe: /BLOCK/, allowRe: /DECRYPT/, defaultReason: 'no matching rule (default SSL inspection action)' });
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
    const ipRel = (list) => { const l = list.filter((x) => M.parseIpRange(x)); const r = t.isIp && l.length ? M.ipInList(t.host, l) : { rel: 'none' }; return { rel: r.rel === 'match' ? 'match' : 'none', entry: r.entry }; };
    let a = M.domainInList(t, allow.filter((x) => !M.parseIpRange(x)));
    let d = M.domainInList(t, deny.filter((x) => !M.parseIpRange(x)));
    if (a.rel === 'none') a = ipRel(allow);
    if (d.rel === 'none') d = ipRel(deny);
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
// ZPA application segment matching (not ZIA URL semantics):
//   "host.example.com" matches that exact FQDN only; "*.example.com" (or ".example.com") matches any subdomain
//   but not example.com itself; IPs/CIDRs match addresses inside them. When several segments match, ZPA uses the
//   single most specific one (exact FQDN > longer wildcard suffix; longer IP prefix), among segments whose ports fit.
// Returns rel 'match' | 'partial' (wildcard query that overlaps a narrower entry) | 'none', plus a specificity score.
function zpaDomainRel(t, entry) {
  let e = String(entry || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/:].*$/, '');
  if (!e) return { rel: 'none' };
  const wild = /^\*\.|^\./.test(e), base = e.replace(/^\*\./, '').replace(/^\./, '');
  const labels = base.split('.').length;
  const h = t.host, within = (x, b) => x.endsWith('.' + b);
  if (!t.isWildcard) {
    if (!wild) return h === base ? { rel: 'match', score: 1000 + labels } : { rel: 'none' };
    if (base.includes('*')) { const re = new RegExp('^' + ('*.' + base).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^.]*(?:\\.[^.]*)*') + '$'); return re.test(h) ? { rel: 'match', score: labels } : { rel: 'none' }; }
    return within(h, base) ? { rel: 'match', score: labels } : { rel: 'none' };
  }
  const q = h.replace(/^\*\./, '');
  if (wild) {
    if (q === base || within(q, base)) return { rel: 'match', score: labels };
    if (within(base, q)) return { rel: 'partial', score: labels };
    return { rel: 'none' };
  }
  return within(base, q) ? { rel: 'partial', score: 1000 + labels } : { rel: 'none' };
}
function zpaSegPorts(a, ctx) {
  const raw = ctx.protocol === 'udp' ? a.udpPortRanges || a.udpPortRange : a.tcpPortRanges || a.tcpPortRange;
  let ranges = [];
  if (Array.isArray(raw) && raw.length && raw.every((x) => typeof x === 'string' || typeof x === 'number') && raw.every((x) => /^\d+$/.test(String(x)))) {
    for (let i = 0; i + 1 < raw.length; i += 2) ranges.push([+raw[i], +raw[i + 1]]); // ZPA returns flat [from,to,from,to]
  } else if (Array.isArray(raw) && raw.length && typeof raw[0] === 'object') ranges = raw.map((p) => [+p.from, +(p.to == null ? p.from : p.to)]);
  else ranges = M.parsePorts(raw);
  return ranges;
}
function zpaMatch(snap, ctx) {
  const t = ctx.target;
  const apps = arr(snap.zpaApps);
  if (!t) return { apps: [], groups: [], candidates: [], partial: [], skipped: [] };
  const full = [], partial = [], skipped = [];
  for (const a of apps) {
    if (lc(a.enabled) === 'false') continue;
    const dom = arr(a.domainNames);
    let best = { rel: 'none' }, via = null;
    for (const d of dom) {
      const r = M.parseIpRange(d)
        ? (t.isIp ? (() => { const x = M.ipInList(t.host, [d]); return x.rel === 'none' ? x : { rel: x.rel, score: 2000 + (+(String(d).split('/')[1] || 32)) }; })() : { rel: 'none' })
        : t.isIp ? { rel: 'none' } : zpaDomainRel(t, d);
      if (r.rel === 'none') continue;
      const better = best.rel === 'none' || (r.rel === 'match' && best.rel !== 'match') || (r.rel === best.rel && r.score > best.score);
      if (better) { best = r; via = d; }
    }
    if (best.rel === 'none') continue;
    if (ctx.port != null) {
      const ranges = zpaSegPorts(a, ctx);
      if (ranges.length && !M.portInRanges(ctx.port, ranges)) {
        skipped.push({ id: a.id, name: a.name, via, reason: `${(ctx.protocol || 'tcp').toUpperCase()} ${ctx.port} is not in its ports (${ranges.map(([x, y]) => (x === y ? x : `${x}-${y}`)).join(', ')}); enter one of those ports to test it` });
        continue;
      }
    }
    const m = { id: a.id, name: a.name, segmentGroupId: a.segmentGroupId, rel: best.rel, via, score: best.score };
    (best.rel === 'match' ? full : partial).push(m);
  }
  full.sort((x, y) => y.score - x.score);
  partial.sort((x, y) => y.score - x.score);
  // ZPA uses only the most specific full match. A wildcard query with no full match overlaps narrower segments.
  const used = full.length ? [full[0]] : partial;
  return {
    apps: used, groups: [...new Set(used.map((m) => String(m.segmentGroupId)).filter(Boolean))],
    candidates: full, partial: full.length ? partial : [], partialOnly: !full.length && partial.length > 0, skipped,
  };
}
// What a ZPA/Client Connector posture profile requires, in words, from its type and config.
function postureRequirement(pp) {
  if (!pp) return '';
  let cfg = pp.postureConfig;
  try { if (typeof cfg === 'string') cfg = JSON.parse(cfg); } catch {}
  const t = String(pp.postureTypeValue || pp.postureType || '');
  const c = cfg || {};
  let req;
  if (t === '2' || c.filePath) req = `file path ${c.filePath} exists`;
  else if (t === '3' || c.registryKey) req = `registry key ${c.registryKey}${c.nameValue && c.nameValue.name ? ` has value ${c.nameValue.name} = ${c.nameValue.data}` : ' exists'}`;
  else if (t === '5' || (c.status != null && /firewall/i.test(pp.name))) req = `firewall ${+c.status === 1 ? 'is on' : 'status ' + c.status}`;
  else if (t === '13' || c.ownership) req = `device ownership is ${c.ownership}`;
  else if (t === '17' || (Array.isArray(c) && c[0] && c[0].osVersion)) req = `OS version ${arr(c).map((x) => `${x.osVersion}${x.buildNumber ? ' build ' + x.buildNumber : ''}`).join(' or ')} or later`;
  else req = typeof cfg === 'object' && cfg ? Object.entries(Array.isArray(cfg) ? cfg[0] || {} : cfg).filter(([, v]) => v !== '' && v != null).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(', ') : String(cfg || '');
  const plat = arr(pp.platformType).map((x) => ({ WINDOWS: 'Windows', MAC: 'macOS', MACOS: 'macOS', LINUX: 'Linux', IOS: 'iOS', ANDROID: 'Android' }[x] || x)).join(', ');
  return req + (plat ? ` (${plat})` : '');
}

// ZPA operand evaluation shared by access and client forwarding policy: app / segment group are known, the rest
// (SCIM, SAML, posture, client type, trusted network…) depends on user and device context.
function zpaEvalRules(rules, z, snap = {}, ctx = {}) {
  const appIds = z.apps.map((a) => String(a.id));
  const appName = (id) => (arr(snap.zpaApps).find((a) => String(a.id) === String(id)) || {}).name;
  const sgName = (id) => (arr(snap.zpaSegmentGroups).find((g) => String(g.id) === String(id)) || {}).name;
  const idKnown = !!(ctx.userResolved || (ctx.groups && ctx.groups.length) || (ctx.zpaScimMember && Object.keys(ctx.zpaScimMember).length));
  const userGroups = new Set(arr(ctx.groups).map(lc));
  const email = lc((ctx.userResolved && ctx.userResolved.email) || ctx.userEmail || (/@/.test(ctx.user || '') ? ctx.user : '') || '');
  const emails = new Set([email, lc(ctx.userResolved && ctx.userResolved.loginName), lc(ctx.userEmail)].filter(Boolean));
  const here = z.apps.length ? `destination uses segment "${z.apps[0].name}"` : 'no segment';
  const sorted = sortRules(arr(rules).map((r) => Object.assign({ order: r.ruleOrder != null ? +r.ruleOrder : r.order }, r))).filter((r) => lc(r.disabled) !== '1' && lc(r.disabled) !== 'true');
  return sorted.map((r) => {
    const crits = [];
    for (const c of arr(r.conditions)) {
      const ops = arr(c.operands);
      const evalOp = (o) => {
        const vals = arr(o.values || (o.rhs != null ? [o.rhs] : [])).map(String);
        const t = o.objectType;
        const wl = ctx.source === 'workload';
        if (wl && /^(SCIM_GROUP|SCIM|SAML|POSTURE|TRUSTED_NETWORK|MACHINE_GRP|PLATFORM|COUNTRY_CODE|RISK_FACTOR_TYPE|CHROME_ENTERPRISE|IDP)$/.test(t))
          return { s: 'nomatch', d: `${t.replace(/_/g, ' ').toLowerCase()} ${vals.slice(0, 2).join(', ')} (doesn't apply to workload traffic from a connector)` };
        if (/(EDGE|BRANCH|CLOUD)_CONNECTOR_GROUP$/.test(t)) {
          const label = `${/BRANCH/.test(t) ? 'Branch' : 'Cloud'} Connector group ${o.name || vals.join(', ')}`;
          if (!wl) return { s: 'nomatch', d: label + ' (this is user-device traffic)' };
          if (!ctx.ecGroup || !o.name) return { s: 'unknown', d: label, kind: 'workload' };
          return { s: lc(o.name) === lc(ctx.ecGroup.name) ? 'match' : 'nomatch', d: `${label}; workload uses ${ctx.ecGroup.name}` };
        }
        if (t === 'APP') return { s: vals.some((v) => appIds.includes(v)) ? 'match' : 'nomatch', d: `segment ${vals.map((v) => `"${o.name && vals.length === 1 ? o.name : appName(v) || v}"`).join(', ')}` };
        if (t === 'APP_GROUP') return { s: vals.some((v) => z.groups.includes(v)) ? 'match' : 'nomatch', d: `segment group ${vals.map((v) => `"${o.name && vals.length === 1 ? o.name : sgName(v) || v}"`).join(', ')}` };
        if (t === 'SCIM_GROUP') {
          const names = vals.map((v) => (o.name && vals.length === 1 ? o.name : (ctx.zpaScimNames || {})[v]) || null);
          const label = `SCIM group ${vals.map((v, i) => `"${names[i] || v}"`).join(', ')}`;
          // Best source: ZPA's own SCIM membership for the user (group IDs per IdP).
          const mem = ctx.zpaScimMember || {};
          const idpKey = String(o.idpId || o.lhs || '');
          const ids = mem[idpKey] || (Object.keys(mem).length ? [].concat(...Object.values(mem)) : null);
          if (ids && (mem[idpKey] || Object.keys(mem).length)) return { s: vals.some((v) => ids.includes(v)) ? 'match' : 'nomatch', d: label + ' (ZPA SCIM membership)' };
          if (!idKnown || names.some((n) => !n)) return { s: 'unknown', d: label };
          return { s: names.some((n) => userGroups.has(lc(n))) ? 'match' : 'nomatch', d: label };
        }
        if (t === 'SAML' || t === 'SCIM') {
          const attr = t === 'SAML' ? arr(snap.zpaSamlAttributes).find((a) => String(a.id) === String(o.lhs)) || {} : {};
          const scimName = t === 'SCIM' ? (ctx.zpaScimAttrs || {})[String(o.lhs)] : null;
          const key = String(scimName || attr.samlName || attr.name || '');
          const label = `${t} attribute ${scimName || attr.name || o.lhs} = ${vals.join(', ')}`;
          const emailAttr = /mail|upn|nameid|login|username/i.test(key) || (!key && vals.length && vals.every((v) => /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)));
          if (emailAttr && emails.size) return { s: vals.some((v) => emails.has(lc(v))) ? 'match' : 'nomatch', d: label };
          if (/group|memberof/i.test(key) && idKnown) return { s: vals.some((v) => userGroups.has(lc(v))) ? 'match' : 'nomatch', d: label };
          if (/department/i.test(key) && ctx.department) return { s: vals.some((v) => lc(v) === lc(ctx.department)) ? 'match' : 'nomatch', d: label };
          return { s: 'unknown', d: label };
        }
        if (t === 'POSTURE') {
          const pp = arr(snap.zpaPostureProfiles).find((x) => String(x.postureUdid || x.id) === String(o.lhs));
          return { s: 'unknown', d: `device posture "${(pp && pp.name) || o.lhs}" ${lc(vals[0]) === 'false' ? 'fails' : 'passes'}`, posture: lc(vals[0]) !== 'false', postureInfo: { name: (pp && pp.name) || o.lhs, requirement: postureRequirement(pp) } };
        }
        if (t === 'TRUSTED_NETWORK') {
          const tn = arr(snap.zpaTrustedNetworks).find((x) => String(x.networkId || x.id) === String(o.lhs));
          return { s: 'unknown', d: `${lc(vals[0]) === 'false' ? 'not on' : 'on'} trusted network "${(tn && tn.name) || o.lhs}"` };
        }
        if (t === 'CLIENT_TYPE' && wl) {
          const kinds = vals.map((v) => (/edge_connector|cloud_connector/i.test(v) ? 'cloud' : /branch_connector/i.test(v) ? 'branch' : null));
          const label = `client type ${vals.map((v) => v.replace(/^zpn_client_type_/i, '')).join(', ')}`;
          if (ctx.connectorKind) return { s: kinds.includes(ctx.connectorKind) ? 'match' : 'nomatch', d: `${label} (${ctx.connectorKind === 'cloud' ? 'Cloud' : 'Branch'} Connector)` };
          if (kinds.includes('cloud') && kinds.includes('branch')) return { s: 'match', d: `${label} (connector traffic)` };
          return kinds.some(Boolean) ? { s: 'unknown', d: `${label} — choose Cloud or Branch Connector` } : { s: 'nomatch', d: `${label} (workload traffic comes from a connector)` };
        }
        if (t === 'CLIENT_TYPE') {
          // The simulator models Client Connector traffic, so that client type is assumed.
          const zcc = vals.some((v) => /zapp/i.test(v));
          return { s: zcc ? 'match' : 'nomatch', d: `client type ${vals.map((v) => v.replace(/^zpn_client_type_/, '')).join(', ')}${zcc ? ' (Client Connector assumed)' : ' (simulator assumes Client Connector)'}` };
        }
        return { s: 'unknown', d: `${t}${vals.length ? ' ' + vals.slice(0, 3).join(', ') : ''}` };
      };
      const results = ops.map((o) => Object.assign({ o }, evalOp(o)));
      const types = [...new Set(ops.map((o) => o.objectType))].join('/');
      let status = results.some((x) => x.s === 'match') ? 'match' : results.some((x) => x.s === 'unknown') ? 'unknown' : 'nomatch';
      if (c.operator === 'AND') status = results.some((x) => x.s === 'nomatch') ? 'nomatch' : results.some((x) => x.s === 'unknown') ? 'unknown' : 'match';
      if (c.negated === true || lc(c.negated) === 'true') status = status === 'match' ? 'nomatch' : status === 'nomatch' ? 'match' : status;
      const what = results.map((x) => x.d).join(c.operator === 'AND' ? ' and ' : ' or ');
      const isApp = /^(APP|APP_GROUP)(\/(APP|APP_GROUP))?$/.test(types);
      const detail = isApp ? `${what} — ${here}${z.apps.length && z.apps[0].segmentGroupId ? ` (group "${sgName(z.apps[0].segmentGroupId) || z.apps[0].segmentGroupId}")` : ''}`
        : status === 'unknown' ? `${what} — depends on user/device context${idKnown ? ' not available from the lookup' : ' (enter a user)'}` : `${what} — ${status === 'match' ? 'user matches' : 'user does not match'}`;
      // Posture-only condition: record which outcome it needs (true = posture passes), so both device cases can be evaluated.
      let postureNeed;
      if (results.length && results.every((x) => x.posture !== undefined) && new Set(results.map((x) => x.posture)).size === 1) {
        postureNeed = results[0].posture;
        if (c.negated === true || lc(c.negated) === 'true') postureNeed = !postureNeed;
      }
      const postureInfo = results.map((x) => x.postureInfo).filter(Boolean);
      crits.push({ matched: status === 'match' ? results.filter((x) => x.s === 'match').map((x) => x.d) : undefined, postureNeed, postureInfo: postureInfo.length ? postureInfo : undefined, field: types || 'condition', status, kind: /CONNECTOR_GROUP/.test(types) || (ctx.source === 'workload' && /CLIENT_TYPE/.test(types)) ? 'workload' : /SCIM|SAML|IDP|USER/.test(types) ? 'identity' : /POSTURE|TRUSTED_NETWORK|PLATFORM|COUNTRY|RISK|CHROME/.test(types) ? 'device' : 'other', scope: types, detail });
    }
    const e = evalRule(r, crits);
    e.action = r.action;
    return e;
  });
}

// ZPA is evaluated first. A destination that matches an application segment goes: segment Bypass setting →
// Client Forwarding Policy → Access Policy. If ZPA carries it, ZIA and Client Connector internet bypasses don't apply.
function mZpa(snap, ctx) {
  if (ctx.useZpa === false) return { module: 'ZPA Access Policy', verdict: 'N/A', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0, stages: [], reason: 'ZPA is turned off for this simulation' };
  if (!snap.zpaApps && !snap.zpaAccessRules) return null;
  const z = zpaMatch(snap, ctx);
  const out = { module: 'ZPA Access Policy', verdict: 'NOT_A_ZPA_APP', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0, matchedSegments: z.apps, stages: [], reason: 'Destination does not match any ZPA application segment, so ZPA does not carry it' };
  if (z.partialOnly) {
    const list = z.apps.map((a) => `"${a.name}" (${a.via})`).join(', ');
    out.stages.push({ step: 'Application segment', status: 'unknown', detail: `no segment covers all of ${ctx.target.host}; narrower segments inside it: ${list}` });
    return Object.assign(out, { confidence: 'conditional', matchedSegments: [], partialSegments: z.apps,
      reason: `No ZPA segment covers all of ${ctx.target.host}, so most hosts under it are internet traffic. Some hosts are ZPA applications: ${list}`,
      note: 'Simulate one of those hosts to see its ZPA result.' });
  }
  if (!z.apps.length) {
    const hints = [];
    if (z.skipped.length) hints.push(`Matched by domain but not port: ${z.skipped.map((x) => `"${x.name}" (${x.via}) — ${x.reason}`).join('; ')}`);
    if (ctx.target && !ctx.target.isIp && !ctx.target.isWildcard) {
      const apexOf = arr(snap.zpaApps).filter((a) => arr(a.domainNames).some((d) => /^(\*\.|\.)/.test(String(d)) && String(d).toLowerCase().replace(/^\*?\./, '') === ctx.target.host)).map((a) => `"${a.name}"`);
      if (apexOf.length) hints.push(`${apexOf.join(', ')} list *.${ctx.target.host}, which covers subdomains only. Add ${ctx.target.host} itself to the segment for ZPA to carry it.`);
    }
    if (hints.length) { out.note = hints.join(' '); out.stages.push({ step: 'Application segment', status: 'nomatch', detail: hints.join(' ') }); }
    return out;
  }
  const seg = arr(snap.zpaApps).find((a) => String(a.id) === String(z.apps[0].id)) || {};
  const segDetail = `"${z.apps[0].name}" (${z.apps[0].via})${z.candidates.length > 1 ? `, the most specific of ${z.candidates.length} matching segments; also matched: ${z.candidates.slice(1).map((a) => `"${a.name}" (${a.via})`).join(', ')}` : ''}`;
  out.stages.push({ step: 'Application segment', status: 'match', detail: segDetail });
  if (z.partial.length) out.note = `Hosts under ${ctx.target.host} that have their own segment use it instead: ${z.partial.map((a) => `"${a.name}" (${a.via})`).join(', ')}. Simulate one of those hosts to see its result.`;
  if (z.skipped.length) out.stages.push({ step: 'Segments skipped for port', status: 'nomatch', detail: z.skipped.map((x) => `"${x.name}" (${x.via}): ${x.reason}`).join('; ') });
  // Segment Bypass setting (a Client Connector setting; connector traffic isn't affected)
  const bt = ctx.source === 'workload' ? 'NEVER' : String(seg.bypassType || 'NEVER').toUpperCase();
  if (bt === 'ALWAYS') {
    out.stages.push({ step: 'Segment bypass', status: 'match', detail: `"${seg.name}" is set to always bypass ZPA` });
    return Object.assign(out, { verdict: 'ZPA_BYPASS', reason: `Segment "${seg.name}" is set to always bypass ZPA, so it is handled as internet traffic`, decidingRule: { name: `Segment "${seg.name}" Bypass: Always`, action: 'BYPASS', criteria: [] } });
  }
  if (bt === 'ON_NET') {
    out.stages.push({ step: 'Segment bypass', status: 'unknown', detail: `"${seg.name}" bypasses ZPA on trusted (on-net) networks; off-net it uses ZPA` });
    out.onNet = { segment: seg.name };
  } else out.stages.push({ step: 'Segment bypass', status: 'nomatch', detail: 'Never bypass' });
  // Client Forwarding Policy
  if (ctx.source === 'workload') out.stages.push({ step: 'Client forwarding policy', status: 'nomatch', detail: 'not used: the connector forwarding rule sends workload traffic to ZPA' });
  else if (snap.zpaForwardingRules) {
    const fr = zpaEvalRules(snap.zpaForwardingRules, z, snap, ctx);
    const idx = fr.findIndex((e) => e.status === 'match');
    const pre = fr.slice(0, idx < 0 ? fr.length : idx).filter((e) => e.status === 'unknown');
    const isBypass = (a) => /BYPASS/i.test(a || '');
    out.forwardingRules = fr;
    out.fwdCouldOverride = pre.filter((e) => isBypass(e.action) !== (idx >= 0 && isBypass(fr[idx].action)));
    if (idx >= 0 && isBypass(fr[idx].action)) {
      out.stages.push({ step: 'Client forwarding policy', status: 'match', detail: `rule "${fr[idx].name}" → ${fr[idx].action}` });
      return Object.assign(out, { verdict: 'ZPA_BYPASS', reason: `ZPA client forwarding rule "${fr[idx].name}" bypasses ZPA, so it is handled as internet traffic`, decidingRule: fr[idx], couldOverride: out.fwdCouldOverride });
    }
    out.stages.push({ step: 'Client forwarding policy', status: idx >= 0 ? 'match' : 'nomatch', detail: idx >= 0 ? `rule "${fr[idx].name}" → ${fr[idx].action}` : 'no rule matched; ZPA intercepts by default' });
  } else out.stages.push({ step: 'Client forwarding policy', status: 'unknown', detail: 'not loaded; assumed intercept' });
  // Access Policy
  if (!snap.zpaAccessRules) { out.stages.push({ step: 'Access policy', status: 'unknown', detail: 'not loaded' }); return Object.assign(out, { verdict: 'ALLOW', confidence: 'conditional', reason: 'ZPA carries it; access policy not loaded' }); }
  const evaluated = zpaEvalRules(snap.zpaAccessRules, z, snap, ctx);
  const idx = evaluated.findIndex((e) => e.status === 'match');
  out.rules = evaluated; out.considered = evaluated.length;
  out.couldOverride = evaluated.slice(0, idx < 0 ? evaluated.length : idx).filter((e) => e.status === 'unknown');
  if (idx >= 0) {
    out.decidingRule = evaluated[idx]; out.verdict = /DENY/.test(evaluated[idx].action) ? 'BLOCK' : 'ALLOW'; out.reason = `Access rule "${evaluated[idx].name}" matched`;
    const mm = multiMatch(evaluated, evaluated[idx], (e) => (/DENY/.test(e.action || '') ? 'BLOCK' : 'ALLOW'));
    out.alsoMatched = mm.list; out.alsoMatchedCatchAll = mm.catchAll;
  }
  else {
    out.verdict = 'BLOCK'; out.reason = 'Matched an application segment but no access rule allows it (ZPA default deny)';
    const maybe = out.couldOverride.filter((e) => !/DENY/.test(e.action || ''));
    // Rules whose only open conditions are device posture: evaluate the access policy twice, with posture passing and
    // failing, in rule order. If both cases resolve, report the posture-passing outcome and show the other.
    const decide = (pass) => {
      for (const e of evaluated) {
        if (e.status === 'match') return { rule: e };
        if (e.status !== 'unknown') continue;
        const open = e.criteria.filter((c) => c.status === 'unknown');
        if (!open.every((c) => c.postureNeed !== undefined)) return null; // depends on more than posture
        if (open.every((c) => c.postureNeed === pass)) return { rule: e };
      }
      return { rule: null };
    };
    const ok = decide(true), bad = decide(false);
    if (ok && bad && (ok.rule || bad.rule)) {
      const act = (d) => (d.rule ? (/DENY/.test(d.rule.action || '') ? 'BLOCK' : 'ALLOW') : 'BLOCK');
      const say = (d) => (d.rule ? `${act(d) === 'BLOCK' ? 'blocked' : 'allowed'} by "${d.rule.name}"` : 'blocked by ZPA default deny');
      const postures = [...new Set(evaluated.filter((e) => e.status === 'unknown').flatMap((e) => e.criteria.filter((c) => c.postureNeed !== undefined).map((c) => c.detail.replace(/ (passes|fails)( —.*)?$/, ''))))];
      out.decidingRule = ok.rule; out.verdict = act(ok); out.confidence = 'conditional';
      out.reason = `With ${postures.join(' and ') || 'device posture'} passing: ${say(ok)}. If it fails: ${say(bad)}.`;
      const seen = new Map();
      for (const e of evaluated.filter((e2) => e2.status === 'unknown')) for (const c of e.criteria) for (const pi of c.postureInfo || []) seen.set(pi.name, pi);
      out.deviceConditional = { profiles: [...seen.values()], pass: { action: act(ok), rule: ok.rule && ok.rule.name, order: ok.rule && ok.rule.order }, fail: { action: act(bad), rule: bad.rule && bad.rule.name, order: bad.rule && bad.rule.order }, postures };
      out.couldOverride = out.couldOverride.filter((e) => e !== ok.rule && e !== bad.rule);
      out.stages.push({ step: 'Access policy', status: 'unknown', detail: out.reason });
      return out;
    }
    if (maybe.length) out.reason = `No access rule allows everyone, so ZPA denies by default. Allowed for users who match ${maybe.slice(0, 3).map((e) => `"${e.name}" (${e.criteria.filter((c) => c.status === 'unknown').map((c) => c.detail.replace(/ — .*$/, '')).join('; ')})`).join(' or ')}. ${ctx.user ? (ctx.userResolved || (ctx.zpaScimMember && Object.keys(ctx.zpaScimMember).length) ? 'The user\'s details don\'t settle those conditions.' : `${ctx.user} wasn't found in ZIA, ZIdentity or ZPA SCIM, so its groups are unknown (see the notes below).`) : 'Enter the user to check.'}`;
    const misses = evaluated.filter((e) => e.status === 'nomatch' && !/DENY/.test(e.action || '')).slice(0, 4)
      .map((e) => `"${e.name}": ${(e.criteria.filter((c) => c.status === 'nomatch').map((c) => c.detail)[0]) || 'no match'}`);
    out.note = [out.note, misses.length ? `Allow rules that missed — ${misses.join('; ')}` : evaluated.length ? '' : 'No access rules were loaded.'].filter(Boolean).join(' ');
  }
  out.stages.push({ step: 'Access policy', status: idx >= 0 ? 'match' : 'nomatch', detail: out.reason });
  if (out.couldOverride.length || (out.fwdCouldOverride || []).length || out.onNet) out.confidence = 'conditional';
  return out;
}

// Cloud App Control: rules per application type; the destination's cloud app comes from Zscaler's URL lookup.
function cacAction(r) {
  const acts = arr(r.actions).map(String);
  if (!acts.length) return r.action || 'ALLOW';
  if (acts.some((a) => /ISOLATE/i.test(a))) return 'ISOLATE';
  if (acts.some((a) => /^BLOCK$|DENY.*(VIEW|ACCESS|BROWSE|ALL|USE)|BLOCK_ALL/i.test(a))) return 'BLOCK';
  if (acts.some((a) => /CAUTION/i.test(a))) return 'CAUTION';
  return 'ALLOW';
}
function mCloudApp(snap, ctx) {
  if (!snap.cloudAppRules) return { module: 'Cloud App Control', verdict: 'N/A', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0, reason: 'Cloud App Control rules not loaded' };
  const app = ctx.cloudApp;
  if (!app) return { module: 'Cloud App Control', verdict: 'ALLOW', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0, reason: 'No cloud application identified for this destination (Zscaler lookup returned none)' };
  const rel = arr(snap.cloudAppRules).filter((r) => arr(r.applications).some((a) => lc((a && (a.name || a.id)) || a) === lc(app)))
    .map((r) => Object.assign({}, r, { action: cacAction(r), _acts: arr(r.actions) }));
  const out = runModule('Cloud App Control', rel, (r) => [critIdentity(r, ctx), critLocation(r, ctx), critTimeWindows(r), W.critWorkload(r, ctx),
    { field: 'cloud app', status: 'match', detail: `${app} (${r.ruleType || r.type || 'app'}${r._acts.length ? '; actions ' + r._acts.slice(0, 4).join(', ') : ''})` }],
  { ranked: rankOn(snap), blockRe: /BLOCK/, allowRe: /ALLOW/, defaultReason: `no Cloud App Control rule for ${app}` });
  const partial = out.decidingRule && /ALLOW/.test(out.decidingRule.action) ? arr((rel.find((r) => r.id === out.decidingRule.id) || {})._acts).filter((a) => /DENY|BLOCK/i.test(a)) : [];
  if (partial.length) out.note = `Allowed, but restricts: ${partial.join(', ')}`;
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

// ---------- Cloud & Branch Connector traffic forwarding ----------
// Workload traffic is forwarded by the connector's traffic forwarding rules (ZTW ecRules/ecRdr), in rule order:
// ZIA (optionally via a proxy gateway), ZPA, Direct, Local switch, Proxy chaining or Drop.
const CONN_MODULE = 'Forwarding (Cloud & Branch Connector)';
const FWD_METHOD = {
  ZIA: { verdict: 'VIA_ZSCALER', text: 'forwarded to ZIA' }, ECSELF: { verdict: 'VIA_ZSCALER', text: 'forwarded to ZIA (connector self)' },
  ZPA: { verdict: 'VIA_ZPA', text: 'forwarded to ZPA' }, ECZPA: { verdict: 'VIA_ZPA', text: 'forwarded to ZPA' },
  DIRECT: { verdict: 'BYPASSES_ZSCALER', text: 'sent direct (bypasses Zscaler)' }, LOCAL_SWITCH: { verdict: 'BYPASSES_ZSCALER', text: 'switched locally between workloads (never leaves the connector)' },
  PROXYCHAIN: { verdict: 'BYPASSES_ZSCALER', text: 'proxy-chained to a third-party proxy' }, DROP: { verdict: 'BLOCK', text: 'dropped' },
};
const fwdOf = (r) => FWD_METHOD[String(r.forwardMethod || '').toUpperCase()] || { verdict: 'VIA_ZSCALER', text: `forward method ${r.forwardMethod || 'unknown'}` };
function critEcGroup(rule, ctx) {
  const g = arr(rule.ecGroups);
  if (!g.length) return null;
  const list = names(g).slice(0, 4).join(', ');
  if (!ctx.ecGroup) return { field: 'connector group', status: 'unknown', kind: 'workload', scope: `Connector group ${list}`, detail: `rule applies to connector group ${list} — pick the workload's connector group` };
  const ok = g.some((x) => String(x.id) === String(ctx.ecGroup.id) || lc(x.name) === lc(ctx.ecGroup.name));
  return { field: 'connector group', status: ok ? 'match' : 'nomatch', detail: `${ctx.ecGroup.name} ${ok ? 'is' : 'is not'} in ${list}` };
}
function critZpaSegments(rule, ctx, z) {
  const segs = [...arr(rule.zpaAppSegments), ...arr(rule.zpaApplicationSegments)];
  const sgs = arr(rule.zpaApplicationSegmentGroups);
  if (!segs.length && !sgs.length) return null;
  const list = [...names(segs), ...names(sgs)].slice(0, 4).join(', ');
  if (!z) return { field: 'ZPA segment', status: 'unknown', kind: 'input', scope: `ZPA segment ${list}`, detail: `rule forwards ZPA segments ${list}; ZPA segments not loaded` };
  // "ZPA Edge App Segment" is the connector's built-in reference to every ZPA application segment.
  const allApps = segs.find((x) => /^zpa edge app segment$/i.test(String(x.name || '')));
  if (allApps) return z.apps.length ? { field: 'ZPA segment', status: 'match', detail: `destination is ZPA segment "${z.apps[0].name}" (${allApps.name} covers every ZPA application)` } : { field: 'ZPA segment', status: 'nomatch', detail: `destination is not a ZPA application segment (${allApps.name} covers ZPA applications only)` };
  const hit = z.apps.find((a) => segs.some((x) => lc(x.name) === lc(a.name) || String(x.externalId || x.id) === String(a.id)));
  const ghit = !hit && sgs.length && z.groups.length ? sgs.find((x) => z.groups.includes(String(x.externalId || x.id))) : null;
  if (hit || ghit) return { field: 'ZPA segment', status: 'match', detail: hit ? `destination is ZPA segment "${hit.name}"` : `destination is in segment group "${ghit.name}"` };
  const known = (x) => arr(ctx._zpaAppNames).some((n) => lc(n) === lc(x.name));
  if (z.apps.length && segs.length && !segs.some(known)) return { field: 'ZPA segment', status: 'unknown', kind: 'input', scope: `ZPA segment ${list}`, detail: `destination is ZPA segment "${z.apps[0].name}"; the rule forwards ${list}, which isn't a ZPA segment by that name — check which ZPA applications it covers` };
  return { field: 'ZPA segment', status: 'nomatch', detail: z.apps.length ? `destination is segment "${z.apps[0].name}", not ${list}` : `destination is not in ZPA segment ${list}` };
}
function mConnectorForwarding(data, ctx) {
  const out = { module: CONN_MODULE, verdict: 'VIA_ZSCALER', confidence: 'definite', decidingRule: null, couldOverride: [], rules: [], considered: 0, profiles: [], connector: true };
  const all = arr(data.ztwForwardingRules).filter((r) => !r.type || /^(EC_RDR|FORWARDING)$/i.test(r.type));
  if (!all.length) return Object.assign(out, { confidence: 'conditional', reason: data.ztwForwardingRules ? 'No connector traffic forwarding rules — assuming the default rule forwards to ZIA' : 'Cloud & Branch Connector forwarding rules not loaded — assuming the traffic is forwarded to ZIA' });
  const view = Object.assign({}, data, {
    ipSourceGroups: data.ztwIpSourceGroups || data.ipSourceGroups, ipDestinationGroups: data.ztwIpDestinationGroups || data.ipDestinationGroups,
    networkServices: data.ztwNetworkServices || data.networkServices, networkServiceGroups: data.ztwNetworkServiceGroups || data.networkServiceGroups,
  });
  const z = data.zpaApps ? zpaMatch(data, ctx) : null;
  ctx._zpaAppNames = arr(data.zpaApps).map((a) => a.name);
  // Rule order: 1, 2, 3 … then the predefined rules with negative orders (-2 "ZPA Pool For Stray Traffic" before -1 "Default").
  const rank = (r) => { const o = Number(r.order); return Number.isFinite(o) && o >= 0 ? o : 1e9 + (Number.isFinite(o) ? o : 0); };
  all.sort((a, b) => rank(a) - rank(b));
  all.forEach((r, i) => { r._seq = i; });
  const ZPA_POOL = ['100.64.0.0/10'];
  const stray = (r) => {
    // The predefined "ZPA Pool For Stray Traffic" rule has no criteria in the API: it drops traffic to the connector's
    // ZPA IP pool (synthetic IPs) that isn't for a known ZPA application.
    if (!(Number(r.order) === -2 || /stray traffic/i.test(r.name || ''))) return null;
    const t = ctx.target;
    if (!t) return { field: 'destination', status: 'unknown', scope: 'Destination in the ZPA IP pool', detail: 'applies to traffic to the ZPA IP pool (synthetic IPs) — no destination entered' };
    const ips = t.isIp ? [t.host] : ctx.resolvedIps || [];
    const hit = ips.find((ip) => M.ipInList(ip, ZPA_POOL).rel === 'match');
    return { field: 'destination', status: hit ? 'match' : 'nomatch', detail: hit ? `${hit} is in the ZPA IP pool (${ZPA_POOL[0]}, assumed)` : `${t.host} is not in the ZPA IP pool (${ZPA_POOL[0]}, assumed)` };
  };
  const appSvc = (r) => (arr(r.appServiceGroups).length ? { field: 'app service group', status: 'unknown', kind: 'input', scope: `App service group ${names(r.appServiceGroups).join(', ')}`, detail: `rule applies to app service group ${names(r.appServiceGroups).join(', ')} (Zscaler-managed destinations) — not evaluated` } : null);
  const res = runModule(CONN_MODULE, all.map((r) => Object.assign({}, r, { order: r._seq, _order: r.order })), (r) => [
    stray(r), appSvc(r),
    critSourceIp(r, ctx, view), W.critWorkload(r, ctx, 'srcWorkloadGroups'), critEcGroup(r, ctx), critLocation(r, ctx),
    critDest(r, ctx, view), critUrlCategories(r, ctx, 'resCategories'), critServices(r, ctx, view), critApps(r, ctx, view), critTimeWindows(r),
    /^(ZPA|ECZPA)$/i.test(r.forwardMethod || '') ? critZpaSegments(r, ctx, z) : null,
  ].filter(Boolean), { defaultReason: 'no forwarding rule matched (default: forwarded to ZIA)' });
  // runModule compares raw actions; connector rules carry forwardMethod instead, so map each rule's outcome.
  for (const e of res.rules) { const r0 = all.find((x) => String(x.id) === String(e.id)); if (r0) e.order = r0.order; }
  const src = new Map(all.map((r) => [String(r.id), r]));
  const outcome = (e) => fwdOf(src.get(String(e.id)) || {});
  for (const e of res.rules) {
    const r = src.get(String(e.id)) || {};
    const f = outcome(e);
    e.action = r.forwardMethod || 'ZIA';
    e.forward = { method: r.forwardMethod, verdict: f.verdict, text: f.text, proxyGateway: r.proxyGateway && r.proxyGateway.name, zpaGateway: r.zpaGateway && r.zpaGateway.name, wanSelection: r.wanSelection };
  }
  const d = res.decidingRule;
  const f = d ? d.forward : FWD_METHOD.ZIA;
  const verdict = d ? f.verdict : 'VIA_ZSCALER';
  const pre = res.rules.slice(0, d ? res.rules.indexOf(d) : res.rules.length).filter((e) => e.status === 'unknown');
  const via = d && (f.proxyGateway || f.zpaGateway) ? ` via gateway "${f.proxyGateway || f.zpaGateway}"` : '';
  Object.assign(out, {
    verdict, decidingRule: d, rules: res.rules, considered: res.considered,
    ...(() => { const mm = multiMatch(res.rules, d, (e) => e.forward && e.forward.verdict); return { alsoMatched: mm.list, alsoMatchedCatchAll: mm.catchAll }; })(),
    couldOverride: pre.filter((e) => e.forward.verdict !== verdict), sameOutcomeEarlier: pre.filter((e) => e.forward.verdict === verdict),
    reason: d ? `Connector forwarding rule "${d.name}" (order ${d.order}): ${f.text}${via}` : 'No connector forwarding rule matched, so the default forwards it to ZIA',
    forward: d ? d.forward : { method: 'ZIA', verdict, text: 'forwarded to ZIA (default)' },
  });
  if (out.couldOverride.length) out.confidence = 'conditional';
  if (d && d.forward.wanSelection && !/^(NONE|INVALID)?$/i.test(d.forward.wanSelection)) out.note = `WAN selection: ${d.forward.wanSelection}`;
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
      const ipList = [...ips, ...ents.filter((u) => M.parseIpRange(u))]; // IPs may be listed as custom URLs too
      for (const ip of ipsToTest) if (M.ipInList(ip, ipList).rel === 'match') hit = true;
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
  c2.adminRanking = rankOn(data);
  if (c2.adminRanking) c2.notes.push('Admin ranking is on for this tenant: ZIA rules are evaluated by admin rank first (0 = highest), then by rule order.');
  const workload = c2.source === 'workload';
  if (workload) {
    c2.workload = W.membership(data, c2);
    if (c2.ecGroupName && !c2.ecGroup) c2.ecGroup = W.findEcGroup(data, c2.ecGroupName) || { id: null, name: c2.ecGroupName };
    if (!c2.location && c2.ecGroup && c2.ecGroup.location && c2.ecGroup.location.name) { c2.location = c2.ecGroup.location.name; c2.notes.push(`Location "${c2.location}" taken from connector group "${c2.ecGroup.name}".`); }
    if (!c2.connectorKind && c2.ecGroup) c2.connectorKind = /aws|azure|gcp|cloud/i.test(`${c2.ecGroup.platform || ''} ${c2.ecGroup.deployType || ''}`) ? 'cloud' : /branch|physical|vm|esx|kvm|hyper/i.test(`${c2.ecGroup.formFactor || ''} ${c2.ecGroup.platform || ''} ${c2.ecGroup.deployType || ''}`) ? 'branch' : null;
    const mg = c2.workload.groups.filter((g) => g.status === 'match').map((g) => g.name);
    if (c2.workload.tags.length || mg.length) c2.notes.push(`Workload ${c2.sourceIp ? c2.sourceIp + ' ' : ''}${c2.workload.tags.length ? 'tags ' + c2.workload.tags.map(W.tagLabel).join(', ') : ''}${mg.length ? ' → workload group' + (mg.length > 1 ? 's ' : ' ') + mg.join(', ') : ' → in no workload group'}.`);
  }
  const fwd = workload ? mConnectorForwarding(data, c2) : mForwarding(data, c2, manual);
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
  // Order: ZPA first, then Client Connector / PAC forwarding, then ZIA (SSL inspection as a modifier, ATP, Firewall,
  // DNS, URL Filtering, Cloud App Control, Sandbox, File Type Control, DLP).
  let zpa = mZpa(data, c2);
  if (workload && zpa && zpa.verdict !== 'N/A') {
    if (fwd.verdict !== 'VIA_ZPA') zpa = (zpa.matchedSegments || []).length ? Object.assign({}, zpa, { verdict: 'N/A', decidingRule: null, couldOverride: [], deviceConditional: undefined, onNet: undefined, fwdCouldOverride: [], note: undefined,
      reason: `The destination is ZPA segment "${zpa.matchedSegments[0].name}", but the connector forwarding rule ${fwd.decidingRule ? `"${fwd.decidingRule.name}" ` : ''}${fwd.forward.text}, so ZPA policy doesn't apply` }) : null;
    else if (!(zpa.matchedSegments || []).length) zpa = Object.assign({}, zpa, { verdict: 'BLOCK', confidence: 'definite', decidingRule: null, couldOverride: [],
      reason: `The connector forwards this to ZPA, but the destination isn't in any ZPA application segment, so the connection fails` });
  }
  const modules = [
    ...(zpa ? [zpa] : []),
    fwd,
    ssl,
    web ? mAtp(data, c2) : na('Advanced Threat Protection'),
    mFirewall(data, c2),
    hasHost ? mDns(data, c2) : naNoDest('DNS Control', c2.target ? 'Not applicable: destination is an IP address (no DNS lookup)' : 'Not evaluated: no destination host entered'),
    web ? mUrlFiltering(data, c2) : na('URL Filtering'),
    web ? mCloudApp(data, c2) : na('Cloud App Control'),
    web ? mSandbox(data, c2) : na('Sandbox (Behavioral Analysis)'),
    web ? mFileType(data, c2) : na('File Type Control'),
    web ? mDlp(data, c2) : na('Data Loss Prevention'),
  ];
  // Live state that doesn't change the policy verdict but decides whether it works in practice.
  if (zpa && (zpa.matchedSegments || []).length) zpa.pathHealth = require('./live').zpaPathHealth(data, zpa.matchedSegments[0].id);
  const summary = summarize(modules, c2);
  { const dm = modules.find((m) => m && m.decidingRule && summary.primary && m.decidingRule.name === summary.primary.rule && m.module === summary.primary.module);
    if (dm && dm.rankOrdered) summary.rank = { on: true, rank: rankOf(dm.decidingRule), effects: dm.rankEffects || [] }; }
  summary.multiMatch = modules.filter((m) => m && m.decidingRule && (m.alsoMatched || []).length)
    .map((m) => ({ module: m.module, rule: m.decidingRule.name, order: m.decidingRule.order, action: m.decidingRule.action, also: m.alsoMatched, catchAll: m.alsoMatchedCatchAll || 0, decides: !!summary.primary && m.decidingRule.name === summary.primary.rule && (m.module === summary.primary.module || !!m.connector) }));
  if (c2.device) summary.deviceWarnings = require('./live').deviceWarnings(c2.device);
  return { context: c2, modules, summary };
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
  const fw = by['Forwarding & Bypass (PAC / ZCC)'] || by[CONN_MODULE];
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
      const kind = ['identity', 'workload', 'location', 'other', 'input'].find((k) => kinds.includes(k)) || 'other';
      const action = r.forward ? ({ BLOCK: 'BLOCK', BYPASSES_ZSCALER: 'BYPASS' }[r.forward.verdict] || 'ALLOW') : ACT_RE(r.action);
      alsoBasedOn.push({ kind, condition: unk.map(condLabel).join(' + ') || 'context not supplied', action, module: m.module, rule: r.name, order: r.order, detail: r.forward ? `Connector: ${r.forward.text}` : undefined });
    }
  };

  // Client Connector bypasses (per app profile / network type)
  const fwdProfiles = (fw && fw.profiles) || [];
  for (const p of fwdProfiles) for (const o of p.outcomes) if (o.outcome !== 'ZIA' && p.applies !== 'no')
    bypasses.push({ kind: 'forwarding', where: `${p.platform ? p.platform + ' · ' : ''}${p.name}${o.nets && !['—', 'All networks'].includes(o.nets[0]) ? ' · ' + o.nets.join(', ') : ''}`, how: o.how, captured: o.outcome !== 'NOT_CAPTURED' });
  if (ssl && ssl.verdict === 'NOT_DECRYPTED') bypasses.push({ kind: 'ssl', where: 'SSL Inspection', how: `not decrypted by rule "${ssl.decidingRule && ssl.decidingRule.name}"` });

  // ZIA (or ZPA) outcome for traffic that reaches Zscaler
  let zia;
  const zpaDecides = !!(zpa && ['ALLOW', 'BLOCK'].includes(zpa.verdict));
  if (zpa && zpa.verdict === 'ZPA_BYPASS') lines.push(`${zpa.reason}.`);
  if (zpa && zpa.verdict === 'NOT_A_ZPA_APP' && (zpa.note || zpa.partialSegments)) lines.push(`ZPA: ${zpa.partialSegments ? zpa.reason + '. ' : ''}${zpa.note || ''}`.trim());
  if (zpaDecides) {
    zia = pick(zpa, zpa.verdict === 'BLOCK' ? 'BLOCK' : 'ALLOW');
    lines.push((zpa.matchedSegments || []).length ? `Destination is a ZPA application segment (${zpa.matchedSegments.map((x) => x.name).join(', ')}): ZPA carries it and its access policy decides; ZIA policy and internet bypasses don't apply.` : `${zpa.reason}.`);
    addConds(zpa);
    for (const r of zpa.fwdCouldOverride || []) {
      const unk = (r.criteria || []).filter((c) => c.status === 'unknown');
      alsoBasedOn.push({ kind: 'zpa', condition: unk.map(condLabel).join(' + ') || 'context not supplied', action: /BYPASS/i.test(r.action) ? 'BYPASS' : 'ALLOW', module: 'ZPA client forwarding policy', rule: r.name, order: r.order });
    }
    if (zpa.deviceConditional) { const f = zpa.deviceConditional.fail; alsoBasedOn.unshift({ kind: 'zpa', condition: `If the ${zpa.deviceConditional.postures.join(' / ') || 'device posture'} check fails`, action: f.action, module: 'ZPA Access Policy', rule: f.rule, order: f.order, detail: f.rule ? null : 'No rule allows it, so ZPA denies by default' }); }
    if (zpa.onNet) alsoBasedOn.push({ kind: 'zpa', condition: `On a trusted (on-net) network: segment "${zpa.onNet.segment}" bypasses ZPA`, action: 'BYPASS', module: 'ZPA segment', rule: null, detail: 'Then it is handled as internet traffic (Client Connector / ZIA)' });
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
  if (fw && fw.connector && fw.verdict === 'BLOCK') {
    primary = { module: 'Connector forwarding', action: 'BLOCK', rule: fw.decidingRule && fw.decidingRule.name, order: fw.decidingRule && fw.decidingRule.order, criteria: (fw.decidingRule && fw.decidingRule.criteria) || [], reason: fw.reason, confidence: fw.confidence, tags: [] };
    alsoBasedOn.length = 0; addConds(fw);
    lines.unshift('The connector drops this traffic — it never reaches ZIA or ZPA.');
  } else if (fw && fw.verdict === 'BYPASSES_ZSCALER' && !zpaDecides) {
    primary = { module: fw.connector ? 'Connector forwarding' : 'Client Connector forwarding', action: 'BYPASS', rule: fw.decidingRule.name, criteria: fw.decidingRule.criteria, reason: fw.reason, confidence: fw.connector ? fw.confidence : 'definite', tags: [] };
    alsoBasedOn.length = 0;
    if (fw.connector) addConds(fw);
    alsoBasedOn.unshift({ kind: 'zia', condition: 'If it were forwarded to Zscaler', action: zia.action, module: zia.module, rule: zia.rule, order: zia.order });
    lines.unshift(fw.connector ? `The connector ${fw.forward.text} — no ZIA policy is applied.` : 'Traffic bypasses Zscaler (PAC/ZCC bypass) — no ZIA policy is applied.');
  } else if (zpaDecides) {
    primary = Object.assign({}, zia, { tags: [] });
    if (fw && fw.connector) addConds(fw);
  } else {
    primary = Object.assign({}, zia, { tags });
    if (fw && fw.connector) addConds(fw);
    for (const b of fwdB) alsoBasedOn.push({ kind: 'zcc', condition: b.where, action: 'BYPASS', module: 'Client Connector forwarding', rule: null, detail: b.how + (b.captured ? '' : ' (not captured by ZCC)') });
  }
  primary.tags = primary.tags || tags;

  // de-duplicate, keep order: identity, location, other, zcc, content, input
  const seen = new Set();
  const order = { zia: -1, identity: 0, workload: 0, location: 1, other: 2, zpa: 3, zcc: 3, content: 4, input: 5 };
  const conds = alsoBasedOn.filter((c) => { const k = c.kind + c.condition + c.action + c.rule; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => (order[a.kind] - order[b.kind]));

  const overall = { BLOCK: 'BLOCKED', ALLOW: 'ALLOWED', BYPASS: 'BYPASSED', ISOLATE: 'ISOLATED', CAUTION: 'CAUTIONED' }[primary.action] || 'ALLOWED';
  const headline = primary.action === 'BYPASS' ? 'Never reaches Zscaler, so no ZIA policy applies'
    : `${{ BLOCK: 'Blocked', ALLOW: 'Allowed', ISOLATE: 'Isolated', CAUTION: 'Caution page' }[primary.action]} by ${primary.module}${primary.rule ? ` — rule "${primary.rule}"` : ''}`;
  if (ctx.methodAssumed) lines.push(`Request method assumed ${ctx.method} (${ctx.methodReason}).`);
  const decider = primary.action === 'ALLOW' && !conds.length ? null : primary;
  return { overall, headline, primary, alsoBasedOn: conds, decider, allowedBy, bypasses, inspections, lines };
}

module.exports = { rankOn, rankOf, mConnectorForwarding, CONN_MODULE, simulate, rationalize, mCloudApp, cacAction, ATP_CATEGORY_MAP, WELL_KNOWN, fileTypeMatch, FILETYPE_ALIASES, mUrlFiltering, mFirewall, mDns, mSandbox, mFileType, mDlp, mSsl, mAtp, mZpa, mForwarding, sortRules };
