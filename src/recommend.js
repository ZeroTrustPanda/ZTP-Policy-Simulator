'use strict';
// Recommendations: given what a destination is expected to get (block or allow) and what the simulator found,
// say whether it meets the expectation and, if not, which policy area is the best place to fix it and how.
const { ATP_CATEGORY_MAP } = require('./engine');

const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
const lc = (s) => String(s || '').toLowerCase();

// Categories that are reasonable to block outright (low collateral). Everything else is treated as a broad
// business category: blocking it would also hit legitimate sites, so list the destination instead.
const RISKY = new Set(['MISCELLANEOUS_OR_UNKNOWN', 'NON_CATEGORIZABLE', 'NEWLY_REG_DOMAINS', 'NEWLY_REVIVED_DOMAINS', 'DYNAMIC_DNS',
  'ANONYMIZER', 'P2P', 'PEER_TO_PEER', 'HACKING', 'QUESTIONABLE', 'OTHER_ILLEGAL_OR_QUESTIONABLE', 'PARKED_DOMAINS']);
const ATP_BY_CAT = new Map(ATP_CATEGORY_MAP.map(([cat, flag, label]) => [cat, { flag, label }]));

function normExpected(v) {
  const s = lc(v).trim();
  if (/^(block|blocked|deny|denied|drop|should ?block|yes|bad|malicious|ioc)$/.test(s)) return 'BLOCK';
  if (/^(allow|allowed|permit|permitted|should ?allow|no|good|benign)$/.test(s)) return 'ALLOW';
  return '';
}

function categoryKind(cat) {
  if (ATP_BY_CAT.has(cat)) return 'security';
  if (RISKY.has(cat)) return 'risky';
  return 'broad';
}

// Existing URL filtering block rules that already list this category (to point at conditions instead of new rules).
function existingCategoryBlocks(data, cat) {
  return arr(data.urlFilteringRules).filter((r) => /BLOCK/.test(r.action || '') && lc(r.state) !== 'disabled'
    && [...arr(r.urlCategories), ...arr(r.urlCategories2)].some((c) => lc((c && c.name) || c) === lc(cat)))
    .map((r) => ({ name: r.name, order: r.order }));
}

const ruleRef = (name, order) => `"${name}"${order != null && order !== '' && +order >= 0 ? ` (order ${order})` : ''}`;

// row: a bulk result row. data: snapshot data. Returns { expected, meets, area, recommendation }.
function recommendRow(row, expected, data) {
  const out = { expected: expected || '', meets: '', area: '', recommendation: '' };
  if (!expected || row.error) return out;
  const act = row.action;
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(row.target || '');
  const cats = (row.category ? row.category.split('; ') : []).filter(Boolean);
  const sec = (row.securityCategory ? row.securityCategory.split('; ') : []).filter(Boolean);
  const atp = (data && data.atpSettings) || {};

  if (expected === 'BLOCK') {
    if (act === 'BLOCK') { out.meets = 'yes'; out.recommendation = `Already blocked by ${row.module} ${ruleRef(row.rule, row.order)}.`; return out; }
    out.meets = 'no';
    if (act === 'BYPASS' && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(row.target || '')) {
      out.area = 'ZPA';
      out.recommendation = 'Private address: Client Connector keeps it on the local network, so ZIA never sees it. If it is an internal application, publish it as a ZPA private application with a DENY access rule (or allow only the right users); otherwise block it on internal firewalls or EDR.';
      return out;
    }
    if (act === 'BYPASS') {
      out.area = 'Client Connector';
      out.recommendation = `Bypassed by Client Connector, so ZIA never sees it. Remove it from the app profile's exclusions, VPN gateway bypass or IP-based app bypass. If the bypass must stay, block it upstream (on-prem firewall).`;
      return out;
    }
    if (act === 'ISOLATE' || act === 'CAUTION') {
      out.area = row.module || 'URL Filtering';
      out.recommendation = `${act === 'ISOLATE' ? 'Isolated' : 'Cautioned'}, not blocked, by ${ruleRef(row.rule, row.order)}. Change that rule's action to Block, or add a Block rule above it.`;
      return out;
    }
    // Security category the ATP policy isn't blocking: fix it in ATP for everyone.
    const atpOff = [...sec, ...cats].map((c) => ATP_BY_CAT.get(c)).find((m) => m && atp[m.flag] === false);
    if (atpOff) { out.area = 'ATP'; out.recommendation = `Turn on "${atpOff.label}" in Advanced Threat Protection. Zscaler already classifies it as a threat, so this blocks it for all users without a custom list.`; return out; }
    const risky = cats.find((c) => categoryKind(c) === 'risky');
    if (risky) {
      const ex = existingCategoryBlocks(data, risky);
      out.area = 'URL Filtering';
      out.recommendation = ex.length
        ? `Category ${risky} is already blocked by ${ruleRef(ex[0].name, ex[0].order)} but that rule didn't apply here. Check its users, locations, time window and protocols${isIp ? ', and add a Firewall rule on the IP category for non-web ports' : ''}.`
        : `Block category ${risky} in a URL Filtering rule above ${ruleRef(row.urlRule || row.rule, row.order)}. It's a low-collateral category.${isIp ? ' For non-web ports, also block it as a destination IP category in Firewall Filtering.' : ''}`;
      return out;
    }
    const broad = cats[0];
    if (isIp) {
      out.area = 'Firewall';
      out.recommendation = `Add the IP to an IP destination group used by a Firewall Filtering Block rule above ${ruleRef(row.firewallRule || 'the allowing rule', row.firewallOrder)}. That covers every port and protocol, not just web.${broad ? ` Don't block category ${broad}: it would also block legitimate sites.` : ' It has no Zscaler category, so a category rule can\'t catch it.'}`;
    } else {
      out.area = 'URL Filtering';
      out.recommendation = `Add the host to a custom URL category used by a URL Filtering Block rule above ${ruleRef(row.urlRule || row.rule, row.order)}, or to the ATP denylist. Use DNS Control on the same category to stop it resolving for non-web apps.${broad ? ` Don't block category ${broad}: it would also block legitimate sites.` : ''}`;
    }
    if (row.application) out.recommendation += ` Zscaler identifies it as ${row.application}: Cloud App Control can block that app instead.`;
    return out;
  }

  // expected ALLOW
  if (act === 'ALLOW' || act === 'BYPASS') { out.meets = 'yes'; out.recommendation = act === 'BYPASS' ? 'Reaches the destination, but bypassed by Client Connector (not inspected).' : 'Allowed.'; return out; }
  out.meets = 'no';
  const m = row.module || '';
  if (/Threat Protection/.test(m)) {
    out.area = 'ATP';
    out.recommendation = /denylist/i.test(row.rule)
      ? 'Remove it from the ATP denylist (Malicious URLs).'
      : `Add it to ATP Security Exceptions (allowlist) rather than turning off ${ruleRef(row.rule)} for everyone. Confirm with your SOC first: Zscaler classifies it as a threat.`;
  } else if (m === 'Firewall') {
    out.area = 'Firewall';
    out.recommendation = `Add an Allow rule above ${ruleRef(row.rule, row.order)} matching an IP destination group with this ${isIp ? 'IP' : 'destination'}.`;
  } else if (m === 'DNS Control') {
    out.area = 'DNS';
    out.recommendation = `Add a DNS Control Allow rule above ${ruleRef(row.rule, row.order)} for this domain.`;
  } else {
    out.area = m || 'URL Filtering';
    const sec2 = [...sec, ...cats].find((c) => categoryKind(c) === 'security');
    out.recommendation = `Add it to a custom URL category used by an Allow rule above ${ruleRef(row.rule, row.order)}. Don't unblock ${cats[0] ? 'category ' + cats[0] : 'the category'} for everyone.${sec2 ? ` Note: Zscaler classifies it as ${sec2}.` : ''}`;
  }
  return out;
}

// Aggregate for the report: which areas to change, and per-category advice.
function summarizeRecommendations(results, data) {
  const withExp = results.filter((r) => r.expected);
  if (!withExp.length) return null;
  const miss = withExp.filter((r) => r.meets === 'no');
  const byArea = {};
  for (const r of miss) {
    const k = `${r.expected}|${r.area}`;
    (byArea[k] = byArea[k] || { expected: r.expected, area: r.area, count: 0, examples: [], recommendation: r.recommendation }).count++;
    if (byArea[k].examples.length < 5) byArea[k].examples.push(r.target);
  }
  const catAdvice = {};
  const atp = (data && data.atpSettings) || {};
  for (const r of miss) {
    const cats = (r.category ? r.category.split('; ') : ['(no category)']);
    for (const c of cats) {
      const k = `${r.expected}|${c}`;
      if (!catAdvice[k]) {
        const kind = c === '(no category)' ? 'none' : categoryKind(c);
        let advice;
        if (r.expected === 'BLOCK') {
          const a = ATP_BY_CAT.get(c);
          const ex = kind === 'risky' ? existingCategoryBlocks(data, c) : [];
          advice = kind === 'security' ? (a && atp[a.flag] === false ? `Block: turn on ATP "${a.label}"` : 'Block: Zscaler threat category; check ATP settings')
            : kind === 'risky' ? (ex.length ? `Block: already in ${ruleRef(ex[0].name, ex[0].order)}; check that rule's conditions` : 'Block this category (low collateral)')
            : kind === 'none' ? 'No category: list the destinations (IP group / custom category)'
            : 'Do not block the category (broad): list the destinations instead';
        } else {
          advice = kind === 'security' ? 'Keep blocked: Zscaler threat category. Use an ATP allowlist entry for specific sites only'
            : 'Allow the specific destinations via a custom URL category; leave the category rule as is';
        }
        catAdvice[k] = { expected: r.expected, category: c, kind, count: 0, advice };
      }
      catAdvice[k].count++;
    }
  }
  return {
    expectedRows: withExp.length, meets: withExp.length - miss.length, misses: miss.length,
    byArea: Object.values(byArea).sort((a, b) => b.count - a.count),
    categories: Object.values(catAdvice).sort((a, b) => b.count - a.count).slice(0, 25),
  };
}

// Policy rules that reference a category, for the single-lookup card.
function rulesForCategory(data, cat) {
  const hit = (list) => arr(list).some((c) => lc((c && c.name) || c) === lc(cat));
  const out = [];
  for (const r of arr(data.urlFilteringRules)) if (hit(r.urlCategories) || hit(r.urlCategories2)) out.push({ module: 'URL Filtering', rule: r.name, order: r.order, action: r.action, disabled: lc(r.state) === 'disabled' });
  for (const r of arr(data.firewallRules)) if (hit(r.destIpCategories)) out.push({ module: 'Firewall', rule: r.name, order: r.order, action: r.action, disabled: lc(r.state) === 'disabled' });
  for (const r of arr(data.dnsRules)) if (hit(r.destIpCategories) || hit(r.resCategories)) out.push({ module: 'DNS Control', rule: r.name, order: r.order, action: r.action, disabled: lc(r.state) === 'disabled' });
  for (const r of arr(data.sslRules)) if (hit(r.urlCategories)) out.push({ module: 'SSL Inspection', rule: r.name, order: r.order, action: (r.action && (r.action.type || r.action)) || '', disabled: lc(r.state) === 'disabled' });
  const a = ATP_BY_CAT.get(cat), atp = data.atpSettings || {};
  if (a && atp[a.flag] !== undefined) out.push({ module: 'Advanced Threat Protection', rule: a.label, order: null, action: atp[a.flag] ? 'BLOCK' : 'ALLOW (setting off)' });
  return out.sort((x, y) => (x.module === y.module ? (+x.order || 0) - (+y.order || 0) : 0));
}

module.exports = { recommendRow, summarizeRecommendations, normExpected, categoryKind, rulesForCategory };
