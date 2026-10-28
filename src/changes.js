'use strict';
// Policy changes: turn "block these" / "allow these" into a reviewed plan of ZIA API calls, apply it, record an undo
// for every step, and report activation status. Nothing here runs unless the session has write mode on and the admin
// confirmed the exact plan. Payload shapes follow the ZeroTrustPanda Policy Wizard's verified templates.
const crypto = require('crypto');
const M = require('./matchers');

const GROUP_MAX = 8000;          // IP entries per destination group (Zscaler default)
const ORG_IP_MAX = 16000;        // source + destination group IP entries per organization (default)
const CUSTOM_URL_MAX = 25000;    // custom URLs across all custom categories (default)
const NAME_MAX = 31;             // ZIA rule names
const URL_METHODS = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OTHER', 'PROPFIND', 'PROPPATCH', 'MOVE', 'MKCOL', 'LOCK', 'COPY', 'UNLOCK', 'PATCH'];
const RULE_PATH = { url: '/urlFilteringRules', firewall: '/firewallFilteringRules', dns: '/firewallDnsRules' };
const RULE_KEY = { url: 'urlFilteringRules', firewall: 'firewallRules', dns: 'dnsRules' };
const AREA_LABEL = { url: 'URL Filtering', firewall: 'Firewall Filtering', dns: 'DNS Control', atp: 'Advanced Threat Protection' };
const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
const lc = (s) => String(s || '').toLowerCase();

// ---------- entries ----------
function intToIp(n) { return [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255].join('.'); }
function rangeToCidrs(lo, hi) {
  const out = [];
  while (lo <= hi) {
    let prefix = 32;
    while (prefix > 0) {
      const bigger = Math.pow(2, 32 - (prefix - 1));
      if (lo % bigger !== 0 || lo + bigger - 1 > hi) break;
      prefix--;
    }
    out.push(prefix === 32 ? intToIp(lo) : `${intToIp(lo)}/${prefix}`);
    lo += Math.pow(2, 32 - prefix);
  }
  return out;
}
// Split raw entries into single IPs, CIDRs and hosts. With collapse, adjacent IPs/ranges merge into the fewest CIDRs.
function normalizeEntries(list, { collapse = true } = {}) {
  const ranges = [], hosts = [], invalid = [];
  for (const raw0 of list) {
    const raw = String(raw0 || '').trim();
    if (!raw) continue;
    const r = /^\d{1,3}(\.\d{1,3}){3}([/-][\d.]+)?$/.test(raw) ? M.parseIpRange(raw) : null;
    if (r) { ranges.push(r); continue; }
    if (/^\d{1,3}(\.\d{1,3}){3}/.test(raw)) { invalid.push(raw); continue; }
    const t = M.parseTarget(raw);
    if (!t || !/\./.test(t.host) || /\s/.test(raw)) { invalid.push(raw); continue; }
    hosts.push((t.host + (t.path && t.path !== '/' ? t.path : '')).replace(/^\*\./, '.'));
  }
  let ips = [], cidrs = [];
  if (collapse) {
    ranges.sort((a, b) => a[0] - b[0]);
    const merged = [];
    for (const [lo, hi] of ranges) {
      const last = merged[merged.length - 1];
      if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi); else merged.push([lo, hi]);
    }
    for (const [lo, hi] of merged) for (const c of rangeToCidrs(lo, hi)) (c.includes('/') ? cidrs : ips).push(c);
  } else {
    for (const [lo, hi] of ranges) for (const c of rangeToCidrs(lo, hi)) (c.includes('/') ? cidrs : ips).push(c);
  }
  const uniq = (a) => [...new Set(a)];
  return { ips: uniq(ips), cidrs: uniq(cidrs), hosts: uniq(hosts), invalid, addresses: ranges.reduce((n, [lo, hi]) => n + (hi - lo + 1), 0) };
}

// ---------- planning ----------
const strip = (o, keys) => { const c = Object.assign({}, o); for (const k of keys) delete c[k]; return c; };
const CAT_RO = ['customUrlsCount', 'urlsRetainingParentCategoryCount', 'customIpRangesCount', 'ipRangesRetainingParentCategoryCount', 'val', 'editable'];
const ref = (k) => `{{${k}}}`;
const idRef = (x) => ({ id: x.id, name: x.name });

function placeOrder(rules, placeAbove) {
  const list = arr(rules).filter((r) => !r.defaultRule && +r.order >= 0);
  const max = list.reduce((m, r) => Math.max(m, +r.order || 0), 0);
  if (placeAbove === 'TOP') return 1;
  if (!placeAbove || placeAbove === 'BOTTOM') return max + 1;
  const r = list.find((x) => String(x.id) === String(placeAbove));
  if (!r) throw new Error(`Rule ${placeAbove} not found for placement.`);
  return +r.order;
}

// spec: see README "Policy changes". data: snapshot data.
function plan(spec, data) {
  const intent = spec.intent === 'ALLOW' ? 'ALLOW' : 'BLOCK';
  const e = normalizeEntries(spec.entries || [], { collapse: spec.collapse !== false });
  const errors = [], warnings = [], steps = [], summary = [];
  const crit = {};
  for (const k of ['users', 'groups', 'departments', 'locations', 'locationGroups']) if (arr(spec.criteria && spec.criteria[k]).length) crit[k] = spec.criteria[k].map(idRef);
  const who = Object.entries(crit).map(([k, v]) => `${k}: ${v.map((x) => x.name).join(', ')}`).join('; ') || 'everyone';
  const R = spec.rules || {};
  const on = (a) => R[a] && R[a].enabled;
  if (!e.ips.length && !e.cidrs.length && !e.hosts.length) errors.push('No valid destinations to add.');
  if (e.invalid.length) warnings.push(`${e.invalid.length} entr${e.invalid.length === 1 ? 'y is' : 'ies are'} not a valid IP, CIDR, range or host and will be skipped: ${e.invalid.slice(0, 5).join(', ')}${e.invalid.length > 5 ? '…' : ''}`);
  if (!on('url') && !on('firewall') && !on('dns') && !(spec.atp && spec.atp.enabled)) errors.push('Pick at least one place to apply the change.');
  const stamp = new Date().toISOString().slice(0, 10);
  const desc = `${intent === 'BLOCK' ? 'Block' : 'Allow'} list managed by ZeroTrustPanda ZS Policy Simulator (${stamp})`;

  // Custom URL category (URL Filtering and DNS Control use it).
  let catRef = null, catName = '';
  if ((on('url') || on('dns')) && !errors.length) {
    const urls = [...e.ips, ...e.hosts], ranges = e.cidrs;
    const c = spec.category || {};
    const all = arr(data.customUrlCategories);
    const totalNow = all.reduce((n, x) => n + arr(x.urls).length + arr(x.ipRanges).length, 0);
    if (c.mode === 'existing') {
      const cat = all.find((x) => String(x.id) === String(c.id));
      if (!cat) errors.push('Pick an existing custom URL category, or create a new one.');
      else {
        catRef = cat.id; catName = cat.configuredName || cat.id;
        const have = new Set(arr(cat.urls).map(lc)), haveR = new Set(arr(cat.ipRanges).map(lc));
        const addU = urls.filter((u) => !have.has(lc(u))), addR = ranges.filter((r) => !haveR.has(lc(r)));
        if (!addU.length && !addR.length) summary.push(`Custom URL category "${catName}" already contains every entry.`);
        else {
          const body = Object.assign(strip(cat, CAT_RO), { urls: [...arr(cat.urls), ...addU], ipRanges: [...arr(cat.ipRanges), ...addR] });
          steps.push({ area: 'category', title: `Add ${addU.length + addR.length} entr${addU.length + addR.length === 1 ? 'y' : 'ies'} to custom URL category "${catName}"`, method: 'PUT', path: `/urlCategories/${cat.id}`, body,
            undo: { method: 'PUT', path: `/urlCategories/${cat.id}`, body: strip(cat, CAT_RO), title: `Restore custom URL category "${catName}"` }, added: { urls: addU, ipRanges: addR } });
          summary.push(`Add ${addU.length + addR.length} entries to custom URL category "${catName}".`);
          if (totalNow + addU.length + addR.length > CUSTOM_URL_MAX) warnings.push(`Custom URL entries across all categories would be about ${(totalNow + addU.length + addR.length).toLocaleString()}, over the default limit of ${CUSTOM_URL_MAX.toLocaleString()}.`);
        }
      }
    } else {
      catName = String(c.name || '').trim();
      if (!catName) errors.push('Name the new custom URL category.');
      else if (all.some((x) => lc(x.configuredName) === lc(catName))) errors.push(`A custom URL category named "${catName}" already exists. Pick it as an existing category instead.`);
      else {
        catRef = ref('cat');
        steps.push({ area: 'category', title: `Create custom URL category "${catName}" with ${urls.length + ranges.length} entr${urls.length + ranges.length === 1 ? 'y' : 'ies'}`, method: 'POST', path: '/urlCategories',
          body: { configuredName: catName, superCategory: 'USER_DEFINED', description: desc, urls, ipRanges: ranges }, capture: 'cat',
          undo: { method: 'DELETE', path: `/urlCategories/${ref('cat')}`, title: `Delete custom URL category "${catName}"` } });
        summary.push(`Create custom URL category "${catName}" (${urls.length.toLocaleString()} IPs/hosts, ${ranges.length.toLocaleString()} CIDRs).`);
        if (totalNow + urls.length + ranges.length > CUSTOM_URL_MAX) warnings.push(`Custom URL entries across all categories would be about ${(totalNow + urls.length + ranges.length).toLocaleString()}, over the default limit of ${CUSTOM_URL_MAX.toLocaleString()}.`);
      }
    }
  }

  // Destination groups (Firewall Filtering): IPs/CIDRs in DSTN_IP groups of up to 8,000; hosts in a DSTN_FQDN group.
  const groupRefs = [], newGroupRefs = [];
  if (on('firewall') && !errors.length) {
    const groups = arr(data.ipDestinationGroups);
    const orgNow = groups.reduce((n, g) => n + arr(g.addresses).length, 0);
    const doGroup = (addrs, spec2, type, label) => {
      if (!addrs.length) return;
      const g = spec2 || {};
      let pending = addrs.slice(), baseName = String(g.name || '').trim();
      if (g.mode === 'existing') {
        const grp = groups.find((x) => String(x.id) === String(g.id));
        if (!grp) { errors.push(`Pick an existing ${label} destination group, or create a new one.`); return; }
        baseName = grp.name;
        const have = new Set(arr(grp.addresses).map(lc));
        pending = pending.filter((a) => !have.has(lc(a)));
        groupRefs.push(grp.id);
        const room = Math.max(0, GROUP_MAX - arr(grp.addresses).length);
        const take = pending.splice(0, room);
        if (take.length) {
          steps.push({ area: 'group', title: `Add ${take.length.toLocaleString()} entries to destination group "${grp.name}"`, method: 'PUT', path: `/ipDestinationGroups/${grp.id}`,
            body: Object.assign({}, grp, { addresses: [...arr(grp.addresses), ...take] }), undo: { method: 'PUT', path: `/ipDestinationGroups/${grp.id}`, body: grp, title: `Restore destination group "${grp.name}"` } });
          summary.push(`Add ${take.length.toLocaleString()} entries to destination group "${grp.name}".`);
        } else if (!pending.length) summary.push(`Destination group "${grp.name}" already contains every entry.`);
      } else if (!baseName) { errors.push(`Name the new ${label} destination group.`); return; }
      else if (groups.some((x) => lc(x.name) === lc(baseName))) { errors.push(`A destination group named "${baseName}" already exists. Pick it as an existing group instead.`); return; }
      let n = g.mode === 'existing' ? 2 : 1;
      while (pending.length) {
        const chunk = pending.splice(0, GROUP_MAX);
        let name = n === 1 ? baseName : `${baseName} ${n}`;
        while (groups.some((x) => lc(x.name) === lc(name))) name = `${baseName} ${++n}`;
        const key = `grp${steps.length}`;
        steps.push({ area: 'group', title: `Create ${label} destination group "${name}" with ${chunk.length.toLocaleString()} entries`, method: 'POST', path: '/ipDestinationGroups',
          body: { name, type, addresses: chunk, description: desc }, capture: key, undo: { method: 'DELETE', path: `/ipDestinationGroups/${ref(key)}`, title: `Delete destination group "${name}"` } });
        summary.push(`Create destination group "${name}" (${chunk.length.toLocaleString()} entries).`);
        groupRefs.push(ref(key)); newGroupRefs.push(ref(key)); n++;
      }
    };
    const ipAddrs = [...e.ips, ...e.cidrs];
    doGroup(ipAddrs, spec.ipGroup, 'DSTN_IP', 'IP');
    const fq = e.hosts.filter((h) => !h.startsWith('.') && !h.includes('/'));
    if (e.hosts.length > fq.length) warnings.push(`${e.hosts.length - fq.length} wildcard or path entries can't go in a Firewall FQDN group; URL Filtering and DNS Control cover them.`);
    if (fq.length) doGroup(fq, spec.fqdnGroup || { mode: 'new', name: `${(spec.ipGroup && spec.ipGroup.name) || 'Simulator list'} FQDN` }, 'DSTN_FQDN', 'FQDN');
    if (orgNow + ipAddrs.length > ORG_IP_MAX) warnings.push(`Destination group IP entries across the organization would be about ${(orgNow + ipAddrs.length).toLocaleString()}, over the default limit of ${ORG_IP_MAX.toLocaleString()} (source + destination groups).`);
  }

  // Rules.
  for (const a of ['url', 'firewall', 'dns']) {
    if (!on(a) || errors.length) continue;
    const r = R[a], rules = arr(data[RULE_KEY[a]]);
    if (r.mode === 'reuse') {
      const ex = rules.find((x) => String(x.id) === String(r.ruleId));
      if (!ex) { errors.push(`${AREA_LABEL[a]}: pick the existing rule to reuse.`); continue; }
      summary.push(`${AREA_LABEL[a]}: existing rule "${ex.name}" (order ${ex.order}) already uses this ${a === 'firewall' ? 'group' : 'category'}; its entries grow, so no new rule is needed.`);
      if (a === 'firewall' && newGroupRefs.length) {
        const body = Object.assign({}, ex, { destIpGroups: [...arr(ex.destIpGroups), ...newGroupRefs.map((id) => ({ id }))] });
        steps.push({ area: a, title: `Add the new destination group(s) to firewall rule "${ex.name}"`, method: 'PUT', path: `${RULE_PATH[a]}/${ex.id}`, body, undo: { method: 'PUT', path: `${RULE_PATH[a]}/${ex.id}`, body: ex, title: `Restore firewall rule "${ex.name}"` } });
      }
      continue;
    }
    const name = String(r.name || '').trim();
    if (!name) { errors.push(`${AREA_LABEL[a]}: name the new rule.`); continue; }
    if (name.length > NAME_MAX) { errors.push(`${AREA_LABEL[a]}: rule name "${name}" is ${name.length} characters; ZIA allows ${NAME_MAX}.`); continue; }
    if (rules.some((x) => lc(x.name) === lc(name))) { errors.push(`${AREA_LABEL[a]}: a rule named "${name}" already exists.`); continue; }
    let order;
    try { order = placeOrder(rules, r.placeAbove); } catch (err) { errors.push(`${AREA_LABEL[a]}: ${err.message}`); continue; }
    const above = rules.find((x) => String(x.id) === String(r.placeAbove));
    // With Admin Ranking on, ZIA only accepts a rule at a position its rank allows ("Rule with rank 7 is not allowed at
    // order N"), so the new rule takes the rank of the rule it is placed above.
    const ranking = !!(data && data.advancedSettings && data.advancedSettings.enableAdminRankAccess);
    const anchor = above || (r.placeAbove === 'TOP' ? rules.filter((x) => !x.defaultRule && +x.order > 0).sort((p1, p2) => p1.order - p2.order)[0] : null);
    const rank = ranking && anchor && Number.isFinite(Number(anchor.rank)) ? Number(anchor.rank) : 7;
    if (ranking && rank < 7) warnings.push(`${AREA_LABEL[a]}: admin ranking is on, so the new rule gets admin rank ${rank} (the rank of "${anchor.name}"). The API client's admin role needs rank ${rank} or higher to save it.`);
    const base = { name, description: desc, order, state: 'ENABLED', rank };
    let body;
    if (a === 'url') body = Object.assign(base, { action: intent, urlCategories: [catRef], protocols: ['ANY_RULE'], requestMethods: URL_METHODS, blockOverride: false, enforceTimeValidity: false }, crit);
    else if (a === 'firewall') body = Object.assign(base, { action: intent === 'BLOCK' ? (r.blockAction === 'BLOCK_RESET' ? 'BLOCK_RESET' : 'BLOCK_DROP') : 'ALLOW', destIpGroups: groupRefs.map((id) => ({ id })), enableFullLogging: false }, crit);
    else {
      body = Object.assign(base, { action: intent, protocols: ['ANY_RULE'] }, crit);
      if (e.hosts.length) body.destIpCategories = [catRef];       // requested domain is in the category
      if (e.ips.length || e.cidrs.length) body.resCategories = [catRef]; // resolves to an IP in the category
    }
    if (a === 'firewall' && !groupRefs.length) { errors.push('Firewall Filtering: no destination group to use.'); continue; }
    // Warn when an earlier enabled rule with the opposite action matches everything: the new rule would never apply.
    const opposite = (act) => (intent === 'BLOCK' ? /^ALLOW/.test(act || '') : /BLOCK/.test(act || ''));
    const restricts = (x) => ['users', 'groups', 'departments', 'locations', 'locationGroups', 'destIpGroups', 'destAddresses', 'destIpCategories', 'resCategories', 'destCountries', 'nwServices', 'nwServiceGroups', 'nwApplications', 'nwApplicationGroups', 'srcIps', 'srcIpGroups', 'applications', 'timeWindows', 'devices', 'deviceGroups']
      .some((k) => arr(x[k]).length) || (a === 'url' && arr(x.urlCategories).some((c) => c !== 'ANY'));
    const shadow = rules.filter((x) => lc(x.state) !== 'disabled' && !x.defaultRule && +x.order > 0 && +x.order < order && opposite(x.action) && !restricts(x)).sort((p1, p2) => p1.order - p2.order)[0];
    if (shadow) warnings.push(`${AREA_LABEL[a]}: rule "${shadow.name}" (order ${shadow.order}, ${shadow.action}) matches all traffic and sits above the new rule, so the new rule would never apply. Place the new rule above it.`);
    const where = r.placeAbove === 'TOP' ? 'at the top (order 1)' : above ? `above "${above.name}" (order ${above.order})` : `at the bottom (order ${order}, above the default rule)`;
    const key = `rule_${a}`;
    steps.push({ area: a, title: `Create ${AREA_LABEL[a]} ${body.action} rule "${name}" ${where}`, method: 'POST', path: RULE_PATH[a], body, capture: key,
      undo: { method: 'DELETE', path: `${RULE_PATH[a]}/${ref(key)}`, title: `Delete ${AREA_LABEL[a]} rule "${name}"` } });
    summary.push(`${AREA_LABEL[a]}: new ${body.action} rule "${name}" ${where}, for ${who}.`);
  }

  // ATP lists.
  if (spec.atp && spec.atp.enabled && !errors.length) {
    const items = [...e.ips, ...e.hosts];
    if (e.cidrs.length) warnings.push(`${e.cidrs.length} CIDR range(s) can't go in the ATP ${intent === 'BLOCK' ? 'denylist' : 'allowlist'}; use URL Filtering or Firewall for ranges.`);
    if (intent === 'BLOCK') {
      const have = new Set(arr(data.atpMaliciousUrls && data.atpMaliciousUrls.blacklistUrls).map(lc));
      const add = items.filter((x) => !have.has(lc(x)));
      if (add.length) {
        steps.push({ area: 'atp', title: `Add ${add.length.toLocaleString()} entries to the ATP denylist (Blocked Malicious URLs)`, method: 'POST', path: '/security/advanced/blacklistUrls?action=ADD_TO_LIST', body: { blacklistUrls: add },
          undo: { method: 'POST', path: '/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST', body: { blacklistUrls: add }, title: 'Remove the added entries from the ATP denylist' } });
        summary.push(`ATP: add ${add.length.toLocaleString()} entries to the denylist (applies to everyone; counts toward the 25K custom URL limit).`);
      } else summary.push('ATP: every entry is already on the denylist.');
    } else {
      const cur = arr(data.atpSecurityExceptions && data.atpSecurityExceptions.whitelistUrls);
      const have = new Set(cur.map(lc));
      const add = items.filter((x) => !have.has(lc(x)));
      if (add.length) {
        steps.push({ area: 'atp', title: `Add ${add.length.toLocaleString()} entries to ATP Security Exceptions (allowlist)`, method: 'PUT', path: '/security', body: { whitelistUrls: [...cur, ...add] },
          undo: { method: 'PUT', path: '/security', body: { whitelistUrls: cur }, title: 'Restore the ATP allowlist' } });
        summary.push(`ATP: add ${add.length.toLocaleString()} entries to Security Exceptions (they skip ATP checks for everyone).`);
      } else summary.push('ATP: every entry is already on the allowlist.');
    }
  }
  if (!errors.length && !steps.length) warnings.push('Nothing to change: every entry is already in place.');
  return { id: crypto.randomBytes(6).toString('hex'), intent, created: Date.now(), entries: e, counts: { ips: e.ips.length, cidrs: e.cidrs.length, hosts: e.hosts.length, addresses: e.addresses, invalid: e.invalid.length },
    steps, summary, warnings, errors, refreshKeys: [...new Set(steps.map((s) => ({ category: 'customUrlCategories', group: 'ipDestinationGroups', url: 'urlFilteringRules', firewall: 'firewallRules', dns: 'dnsRules', atp: intent === 'BLOCK' ? 'atpMaliciousUrls' : 'atpSecurityExceptions' }[s.area])))] };
}

// ---------- ZPA private application ----------
// spec: { intent, entries, collapse, ports: { tcp, udp }, segment: { mode, id, name }, segmentGroup: { mode, id, name },
//         serverGroups: [id], rule: { enabled, name, placeAbove, scim: [{ idpId, id, name }], saml: [{ id, name, value }] } }
function portPairs(s) {
  const out = [];
  for (const part of String(s || '').split(/[\s,]+/).filter(Boolean)) {
    const m = part.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!m || +m[1] > 65535 || (m[2] && +m[2] > 65535)) return null;
    out.push(m[1], m[2] || m[1]);
  }
  return out;
}
function planZpa(spec, data) {
  const intent = spec.intent === 'ALLOW' ? 'ALLOW' : 'BLOCK';
  const e = normalizeEntries(spec.entries || [], { collapse: spec.collapse !== false });
  const errors = [], warnings = [], steps = [], summary = [];
  const dests = [...e.hosts.map((h) => h.split('/')[0]), ...e.ips, ...e.cidrs];
  if (!dests.length) errors.push('No valid destinations to add.');
  if (e.invalid.length) warnings.push(`${e.invalid.length} entr${e.invalid.length === 1 ? 'y is' : 'ies are'} not valid and will be skipped.`);
  const tcp = portPairs(spec.ports && spec.ports.tcp), udp = portPairs(spec.ports && spec.ports.udp);
  if (tcp === null || udp === null) errors.push('Ports must be numbers or ranges such as 443, 8080-8090.');
  const apps = arr(data.zpaApps), segGroups = arr(data.zpaSegmentGroups), srvGroups = arr(data.zpaServerGroups);
  const stamp = new Date().toISOString().slice(0, 10);
  const desc = `Managed by ZeroTrustPanda ZS Policy Simulator (${stamp})`;
  let appRef = null, segName = '';
  const sg = spec.segment || {};
  if (!errors.length && sg.mode === 'existing') {
    const app = apps.find((a) => String(a.id) === String(sg.id));
    if (!app) errors.push('Pick an existing application segment, or create a new one.');
    else {
      appRef = app.id; segName = app.name;
      const have = new Set(arr(app.domainNames).map(lc));
      const add = dests.filter((d) => !have.has(lc(d)));
      if (add.length) {
        steps.push({ api: 'zpa', area: 'zpaApp', title: `Add ${add.length} destination${add.length === 1 ? '' : 's'} to application segment "${app.name}"`, method: 'PUT', path: `/application/${app.id}`,
          body: Object.assign({}, app, { domainNames: [...arr(app.domainNames), ...add] }), undo: { method: 'PUT', path: `/application/${app.id}`, body: app, title: `Restore application segment "${app.name}"` } });
        summary.push(`ZPA: add ${add.length} destinations to application segment "${app.name}".`);
      } else summary.push(`ZPA: application segment "${app.name}" already contains every destination.`);
    }
  } else if (!errors.length) {
    segName = String(sg.name || '').trim();
    if (!segName) errors.push('Name the new application segment.');
    else if (apps.some((a) => lc(a.name) === lc(segName))) errors.push(`An application segment named "${segName}" already exists. Pick it as an existing segment instead.`);
    if (!tcp.length && !udp.length) errors.push('Enter at least one TCP or UDP port for the new segment.');
    const grp = spec.segmentGroup || {};
    let groupRef = null;
    if (grp.mode === 'new') {
      const gname = String(grp.name || '').trim();
      if (!gname) errors.push('Name the new segment group.');
      else if (segGroups.some((x) => lc(x.name) === lc(gname))) errors.push(`A segment group named "${gname}" already exists.`);
      else if (!errors.length) {
        groupRef = ref('segGroup');
        steps.push({ api: 'zpa', area: 'zpaGroup', title: `Create segment group "${gname}"`, method: 'POST', path: '/segmentGroup', body: { name: gname, enabled: true, description: desc }, capture: 'segGroup',
          undo: { method: 'DELETE', path: `/segmentGroup/${ref('segGroup')}`, title: `Delete segment group "${gname}"` } });
        summary.push(`ZPA: create segment group "${gname}".`);
      }
    } else {
      const g = segGroups.find((x) => String(x.id) === String(grp.id));
      if (!g) errors.push('Pick a segment group for the new segment.'); else groupRef = g.id;
    }
    const sgs = arr(spec.serverGroups).map(String).filter((id) => srvGroups.some((x) => String(x.id) === id));
    if (!sgs.length) errors.push('Pick at least one server group (the App Connectors that reach this application).');
    if (!errors.length) {
      appRef = ref('app');
      steps.push({ api: 'zpa', area: 'zpaApp', title: `Create application segment "${segName}" with ${dests.length} destination${dests.length === 1 ? '' : 's'}`, method: 'POST', path: '/application',
        body: { name: segName, description: desc, enabled: true, domainNames: dests, segmentGroupId: groupRef, serverGroups: sgs.map((id) => ({ id })), tcpPortRanges: tcp, udpPortRanges: udp,
          bypassType: 'NEVER', healthReporting: 'ON_ACCESS', icmpAccessType: 'NONE', isCnameEnabled: true, ipAnchored: false, doubleEncrypt: false },
        capture: 'app', undo: { method: 'DELETE', path: `/application/${ref('app')}`, title: `Delete application segment "${segName}"` } });
      const gName = grp.mode === 'new' ? String(grp.name).trim() : (segGroups.find((x) => String(x.id) === String(grp.id)) || {}).name;
      summary.push(`ZPA: create application segment "${segName}" (${dests.length} destination${dests.length === 1 ? '' : 's'}; TCP ${tcp.length ? spec.ports.tcp : 'none'}${udp.length ? `; UDP ${spec.ports.udp}` : ''}) in segment group "${gName}", served by ${sgs.map((id) => (srvGroups.find((x) => String(x.id) === id) || {}).name || id).join(', ')}.`);
    }
  }
  // Access policy rule
  const r = spec.rule || {};
  if (r.enabled && !errors.length) {
    const ps = data.zpaAccessPolicySet && (data.zpaAccessPolicySet.id || (Array.isArray(data.zpaAccessPolicySet) && data.zpaAccessPolicySet[0] && data.zpaAccessPolicySet[0].id));
    const rules = arr(data.zpaAccessRules).map((x) => Object.assign({ order: x.ruleOrder != null ? +x.ruleOrder : +x.order }, x));
    const name = String(r.name || '').trim();
    if (!ps) errors.push('ZPA access policy set not loaded. Reload policies with ZPA ticked.');
    else if (!name) errors.push('Name the ZPA access rule.');
    else if (rules.some((x) => lc(x.name) === lc(name))) errors.push(`A ZPA access rule named "${name}" already exists.`);
    else {
      const conditions = [{ operator: 'OR', operands: [{ objectType: 'APP', lhs: 'id', rhs: appRef }] }];
      const scim = arr(r.scim), saml = arr(r.saml).filter((x) => x.id && String(x.value || '').trim());
      if (scim.length) conditions.push({ operator: 'OR', operands: scim.map((g) => ({ objectType: 'SCIM_GROUP', lhs: String(g.idpId), rhs: String(g.id) })) });
      if (saml.length) conditions.push({ operator: 'OR', operands: saml.map((a) => ({ objectType: 'SAML', lhs: String(a.id), rhs: String(a.value).trim() })) });
      const action = intent === 'ALLOW' ? 'ALLOW' : 'DENY';
      const above = rules.find((x) => String(x.id) === String(r.placeAbove));
      const order = r.placeAbove === 'TOP' ? 1 : above ? above.order : null;
      steps.push({ api: 'zpa', area: 'zpaRule', title: `Create ZPA access rule "${name}" (${action})`, method: 'POST', path: `/policySet/${ps}/rule`,
        body: { name, description: desc, action, operator: 'AND', conditions }, capture: 'zrule',
        undo: { method: 'DELETE', path: `/policySet/${ps}/rule/${ref('zrule')}`, title: `Delete ZPA access rule "${name}"` } });
      if (order) steps.push({ api: 'zpa', area: 'zpaRule', title: `Move ZPA access rule "${name}" to order ${order}${above ? ` (above "${above.name}")` : ''}`, method: 'PUT', path: `/policySet/${ps}/rule/${ref('zrule')}/reorder/${order}`, body: null });
      const who = [...scim.map((g) => `SCIM group ${g.name}`), ...saml.map((a) => `${a.name} = ${a.value}`)].join(', ') || 'everyone';
      summary.push(`ZPA: ${action} access rule "${name}" for the segment, ${order ? (above ? `above "${above.name}" (order ${order})` : 'at the top (order 1)') : 'at the bottom'}, for ${who}.`);
      if (!r.placeAbove) warnings.push('No position chosen: the rule is added at the bottom of the access policy, below any rule that already matches.');
    }
  }
  if (!errors.length && !steps.length) warnings.push('Nothing to change: everything is already in place.');
  return { id: crypto.randomBytes(6).toString('hex'), intent, kind: 'zpa', created: Date.now(), entries: e, counts: { ips: e.ips.length, cidrs: e.cidrs.length, hosts: e.hosts.length, addresses: e.addresses, invalid: e.invalid.length },
    steps, summary, warnings, errors, refreshKeys: ['zpaApps', 'zpaSegmentGroups', 'zpaAccessRules'] };
}

// ---------- apply / undo ----------
function subst(v, refs) {
  if (v == null) return v;
  let s = JSON.stringify(v);
  s = s.replace(/"\{\{(\w+)\}\}"/g, (m, k) => (refs[k] !== undefined ? JSON.stringify(refs[k]) : m)).replace(/\{\{(\w+)\}\}/g, (m, k) => (refs[k] !== undefined ? String(refs[k]) : m));
  return JSON.parse(s);
}

// api: { request(method, path, body) } with paths relative to /zia/api/v1.
async function apply(p, api) {
  const refs = {}, done = [];
  let failed = null;
  for (const st of p.steps) {
    const path = subst(st.path, refs), body = subst(st.body, refs);
    try {
      const out = await api.request(st.method, path, body, st.api);
      if (st.capture) refs[st.capture] = out && out.id !== undefined ? out.id : undefined;
      if (st.capture && refs[st.capture] === undefined) throw new Error('ZIA did not return an id for the new object.');
      done.push({ title: st.title, method: st.method, path, api: st.api, undo: subst(st.undo, refs) && Object.assign(subst(st.undo, refs), { api: st.api }) });
    } catch (e) { failed = { title: st.title, error: e.message }; break; }
  }
  return { id: p.id, at: Date.now(), intent: p.intent, summary: p.summary, done, failed, refs, undone: false, refreshKeys: p.refreshKeys };
}

async function undo(entry, api) {
  const results = [];
  for (const d of entry.done.slice().reverse()) {
    if (!d.undo) continue;
    try { await api.request(d.undo.method, d.undo.path, d.undo.body, d.undo.api); results.push({ title: d.undo.title, ok: true }); }
    catch (e) { results.push({ title: d.undo.title, ok: false, error: e.message }); }
  }
  entry.undone = results.every((r) => r.ok);
  entry.undoResults = results;
  return results;
}

// ---------- API adapters ----------
const ZIA = '/zia/api/v1';
function realApi(client) {
  const zpa = () => `/zpa/mgmtconfig/v1/admin/customers/${client.cfg.zpaCustomerId}`;
  return { request: (method, path, body, which) => client.request(method, (which === 'zpa' ? zpa() : ZIA) + path, { body: body == null ? undefined : body, rateRetries: 5 }) };
}

// In-memory ZIA for sample / offline sessions and tests: applies the same calls to the snapshot data and checks the
// fields ZIA requires, so a plan that works here has the same shape the real API expects.
function mockApi(data) {
  data.__status = data.__status || 'ACTIVE';
  let nextId = 900000;
  const need = (b, fields) => { for (const f of fields) if (b[f] === undefined || b[f] === null || b[f] === '') throw Object.assign(new Error(`HTTP 400: missing required field ${f}`), { status: 400 }); };
  const ruleList = { urlFilteringRules: 'urlFilteringRules', firewallFilteringRules: 'firewallRules', firewallDnsRules: 'dnsRules' };
  const insert = (list, rule) => {
    for (const r of list) if (!r.defaultRule && +r.order >= +rule.order) r.order = +r.order + 1;
    list.push(rule);
  };
  const remove = (list, id) => {
    const i = list.findIndex((r) => String(r.id) === String(id));
    if (i < 0) throw Object.assign(new Error('HTTP 404: not found'), { status: 404 });
    const [r] = list.splice(i, 1);
    for (const x of list) if (!x.defaultRule && +x.order > +r.order) x.order = +x.order - 1;
  };
  const dirty = () => { data.__status = 'PENDING'; };
  // ZPA: changes apply immediately (no activation).
  const zpaMock = (method, seg, body) => {
    const nf = () => Object.assign(new Error('HTTP 404: not found'), { status: 404 });
    if (seg[0] === 'application') {
      const list = data.zpaApps = arr(data.zpaApps);
      if (method === 'POST') { need(body, ['name', 'segmentGroupId']); if (!arr(body.domainNames).length) throw new Error('HTTP 400: domainNames required'); if (!arr(body.serverGroups).length) throw new Error('HTTP 400: serverGroups required'); const a = Object.assign({ id: String(nextId++) }, body); list.push(a); return a; }
      const a = list.find((x) => String(x.id) === seg[1]); if (!a) throw nf();
      if (method === 'PUT') { Object.keys(a).forEach((k) => delete a[k]); Object.assign(a, body, { id: seg[1] }); return null; }
      if (method === 'DELETE') { list.splice(list.indexOf(a), 1); return null; }
    }
    if (seg[0] === 'segmentGroup') {
      const list = data.zpaSegmentGroups = arr(data.zpaSegmentGroups);
      if (method === 'POST') { need(body, ['name']); const g = Object.assign({ id: String(nextId++) }, body); list.push(g); return g; }
      const g = list.find((x) => String(x.id) === seg[1]); if (!g) throw nf();
      if (method === 'DELETE') { if (arr(data.zpaApps).some((a) => String(a.segmentGroupId) === seg[1])) throw new Error('HTTP 400: segment group in use'); list.splice(list.indexOf(g), 1); return null; }
    }
    if (seg[0] === 'policySet' && seg[2] === 'rule') {
      const list = data.zpaAccessRules = arr(data.zpaAccessRules);
      const renum = () => list.sort((x, y) => +x.ruleOrder - +y.ruleOrder).forEach((x, i) => { x.ruleOrder = String(i + 1); });
      if (method === 'POST' && !seg[3]) { need(body, ['name', 'action']); for (const c of arr(body.conditions)) for (const o of arr(c.operands)) if (o.rhs == null || o.rhs === '') throw new Error('HTTP 400: operand rhs required'); const r = Object.assign({ id: String(nextId++), ruleOrder: String(list.length + 1) }, body); list.push(r); return r; }
      const r = list.find((x) => String(x.id) === seg[3]); if (!r) throw nf();
      if (method === 'PUT' && seg[4] === 'reorder') { r.ruleOrder = String(+seg[5] - 0.5); renum(); return null; }
      if (method === 'DELETE') { list.splice(list.indexOf(r), 1); renum(); return null; }
    }
    throw Object.assign(new Error(`HTTP 400: mock ZPA API does not support ${method} /${seg.join('/')}`), { status: 400 });
  };
  return {
    mock: true,
    async request(method, path, body, which) {
      if (which === 'zpa') { const seg = path.split('?')[0].split('/').filter(Boolean); return zpaMock(method, seg, body); }
      const [p, q] = path.split('?');
      const seg = p.split('/').filter(Boolean);
      const action = q && new URLSearchParams(q).get('action');
      if (p === '/status' && method === 'GET') return { status: data.__status };
      if (p === '/status/activate' && method === 'POST') { data.__status = 'ACTIVE'; return { status: 'ACTIVE' }; }
      if (seg[0] === 'urlCategories') {
        const list = data.customUrlCategories = arr(data.customUrlCategories);
        if (method === 'POST') {
          need(body, ['configuredName', 'superCategory']);
          if (!arr(body.urls).length && !arr(body.ipRanges).length) throw Object.assign(new Error('HTTP 400: a custom category needs at least one URL or IP range'), { status: 400 });
          const id = `CUSTOM_${String(list.length + 50).padStart(2, '0')}`;
          const c = Object.assign({ id, customCategory: true }, body); list.push(c); dirty(); return c;
        }
        const c = list.find((x) => String(x.id) === seg[1]);
        if (!c) throw Object.assign(new Error('HTTP 404: category not found'), { status: 404 });
        if (method === 'PUT') { if (action) throw new Error('mock: use full PUT'); need(body, ['configuredName']); Object.keys(c).forEach((k) => delete c[k]); Object.assign(c, body, { id: c.id || seg[1] }); dirty(); return c; }
        if (method === 'DELETE') { list.splice(list.indexOf(c), 1); dirty(); return {}; }
      }
      if (seg[0] === 'ipDestinationGroups') {
        const list = data.ipDestinationGroups = arr(data.ipDestinationGroups);
        if (method === 'POST') { need(body, ['name', 'type']); if (arr(body.addresses).length > GROUP_MAX) throw new Error(`HTTP 400: more than ${GROUP_MAX} addresses`); const g = Object.assign({ id: nextId++ }, body); list.push(g); dirty(); return g; }
        const g = list.find((x) => String(x.id) === seg[1]);
        if (!g) throw Object.assign(new Error('HTTP 404: group not found'), { status: 404 });
        if (method === 'PUT') { if (arr(body.addresses).length > GROUP_MAX) throw new Error(`HTTP 400: more than ${GROUP_MAX} addresses`); Object.keys(g).forEach((k) => delete g[k]); Object.assign(g, body, { id: g.id || +seg[1] }); dirty(); return g; }
        if (method === 'DELETE') { list.splice(list.indexOf(g), 1); dirty(); return {}; }
      }
      if (ruleList[seg[0]]) {
        const key = ruleList[seg[0]];
        const list = data[key] = arr(data[key]);
        if (method === 'POST') {
          need(body, ['name', 'order', 'rank', 'action']);
          if (seg[0] === 'urlFilteringRules') need(body, ['protocols']);
          if (list.some((r) => lc(r.name) === lc(body.name))) throw new Error('HTTP 409: DUPLICATE_ITEM');
          const r = Object.assign({ id: nextId++ }, body); insert(list, r); dirty(); return r;
        }
        const r = list.find((x) => String(x.id) === seg[1]);
        if (!r) throw Object.assign(new Error('HTTP 404: rule not found'), { status: 404 });
        if (method === 'PUT') { Object.keys(r).forEach((k) => delete r[k]); Object.assign(r, body); dirty(); return r; }
        if (method === 'DELETE') { remove(list, seg[1]); dirty(); return {}; }
      }
      if (p === '/security/advanced/blacklistUrls' && method === 'POST') {
        const o = data.atpMaliciousUrls = data.atpMaliciousUrls || { blacklistUrls: [] };
        const cur = arr(o.blacklistUrls), items = arr(body && body.blacklistUrls);
        o.blacklistUrls = action === 'REMOVE_FROM_LIST' ? cur.filter((x) => !items.map(lc).includes(lc(x))) : [...cur, ...items.filter((x) => !cur.map(lc).includes(lc(x)))];
        dirty(); return o;
      }
      if (p === '/security' && method === 'PUT') { data.atpSecurityExceptions = { whitelistUrls: arr(body && body.whitelistUrls) }; dirty(); return data.atpSecurityExceptions; }
      if (['groups', 'departments', 'users'].includes(seg[0]) && method === 'GET') return [];
      if (which === 'zpa') return zpaMock(method, seg, body);
      throw Object.assign(new Error(`HTTP 400: mock API does not support ${method} ${path}`), { status: 400 });
    },
  };
}

// Rules in an area that already reference a category / group with the same action (candidates to reuse).
function reusableRules(data, area, intent, { categoryId, groupId } = {}) {
  const want = (act) => (intent === 'ALLOW' ? /^ALLOW/.test(act || '') : /BLOCK/.test(act || ''));
  const list = arr(data[RULE_KEY[area]]).filter((r) => !r.defaultRule && want(r.action));
  if (area === 'firewall') return groupId == null ? [] : list.filter((r) => arr(r.destIpGroups).some((g) => String(g.id) === String(groupId)));
  if (categoryId == null) return [];
  const has = (l) => arr(l).some((c) => String((c && c.id) || c) === String(categoryId));
  return list.filter((r) => has(r.urlCategories) || has(r.destIpCategories) || has(r.resCategories));
}

module.exports = { plan, planZpa, portPairs, apply, undo, realApi, mockApi, normalizeEntries, rangeToCidrs, reusableRules, placeOrder, GROUP_MAX, NAME_MAX, AREA_LABEL, RULE_KEY };
