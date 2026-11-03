'use strict';
// Phase 3: replay aggregated log records through engine.simulate() under the current and proposed policy
// and report the records whose outcome changes.
const E = require('../engine');
const M = require('../matchers');
const { DEFAULT_TZ, dayIn, validTz } = require('./tz');

// Rule conditions logs cannot resolve. Any of these on a rule that decides (or could pre-empt) a record lowers confidence.
const UNRESOLVABLE = {
  timeWindows: 'time window', deviceTrustLevels: 'device trust', userRiskScoreLevels: 'user risk score',
  userAgentTypes: 'user agent', groups: 'group membership', deviceGroups: 'device group', devices: 'device',
  labels: 'rule label', locationGroups: 'location group', sourceCountries: 'source country', platforms: 'platform',
};
const BLOCKISH = new Set(['BLOCK']);
const URL_FILTERING = /^(url\s*filtering|url filter(ing)? policy|none|)$/i;

const catIds = (urlcat) => {
  if (!urlcat) return [];
  const s = String(urlcat).trim();
  const id = s.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_|_$/g, '');
  return [...new Set([s, id])];
};

// Engine context for one record. groupsByUser (optional) lets callers supply directory groups per user.
function contextOf(r, opts = {}) {
  const target = M.parseTarget(r.url || r.host || '');
  const groups = (opts.groupsByUser && opts.groupsByUser[r.user]) || [];
  return {
    target, port: target && target.port ? target.port : 443, protocol: 'tcp', method: 'GET',
    user: r.user || null, department: r.dept || null, location: r.location || null, locationGroups: [],
    groups, groupsKnown: !!(opts.groupsByUser && opts.groupsByUser[r.user]),
    categories: catIds(r.urlcat), resolvedIps: [], notes: [],
  };
}

const dataOf = (snap) => (snap && snap.data ? snap.data : snap);
const rawRule = (snap, name) => (dataOf(snap).urlFilteringRules || []).find((x) => x.name === name);
const nonEmpty = (v) => (Array.isArray(v) ? v.filter((x) => !(typeof x === 'string' && /^any$/i.test(x))).length > 0 : v != null && v !== '' && !(typeof v === 'object' && !Object.keys(v).length));

// Confidence from the URL Filtering rules that decide or could pre-empt this record in a run.
function reasonsFrom(res, snap, ctx) {
  const reasons = new Set();
  const url = res.modules.find((m) => m.module === 'URL Filtering');
  if (!url) return reasons;
  const deciding = url.decidingRule ? url.rules.indexOf(url.rules.find((r) => r.name === url.decidingRule.name)) : url.rules.length - 1;
  const considered = url.rules.slice(0, deciding + 1);
  for (const r of considered) {
    const raw = rawRule(snap, r.name); if (!raw) continue;
    // A rule ruled out by a criterion the logs do resolve (category, location, protocol) cannot matter.
    if ((r.criteria || []).some((c) => c.status === 'nomatch' && c.field !== 'user/group/department')) continue;
    for (const [k, label] of Object.entries(UNRESOLVABLE)) {
      if (!nonEmpty(raw[k])) continue;
      if (k === 'groups' && ctx.groupsKnown) continue;
      reasons.add(label);
    }
    for (const c of r.criteria || []) if (c.status === 'unknown') reasons.add(c.field);
  }
  if (res.summary.primary.confidence && res.summary.primary.confidence !== 'definite') reasons.add('conditional rule ahead of the deciding rule');
  return reasons;
}
function confidenceOf(reasons) {
  const r = [...reasons];
  if (!r.length) return { level: 'high', reasons: r };
  const hard = r.some((x) => ['group membership', 'time window', 'device trust', 'user risk score', 'user agent', 'device group', 'device', 'platform'].includes(x));
  return { level: hard ? 'low' : 'medium', reasons: r };
}

// The engine only reports a block when it is definite. For replay we take the deciding rule's verdict even when an
// earlier rule with unresolved conditions could override it; confidence then drops (see reasonsFrom).
function outcomeOf(res) {
  const p = res.summary.primary;
  if (p.action !== 'ALLOW') return { action: p.action, rule: p.rule };
  const m = res.modules.find((x) => !/^(Forwarding|ZPA|Data Loss)/.test(x.module) && x.verdict === 'BLOCK' && x.confidence === 'conditional');
  return m ? { action: 'BLOCK', rule: m.decidingRule ? m.decidingRule.name : null } : { action: p.action, rule: p.rule };
}
const ACT = (a) => (a === 'BLOCK' ? 'BLOCK' : a === 'BYPASS' ? 'BYPASS' : a === 'ISOLATE' ? 'ISOLATE' : a === 'CAUTION' ? 'CAUTION' : 'ALLOW');

function bucket() { return { records: [], transactions: 0, users: new Set(), departments: new Map(), locations: new Map(), urls: new Map(), hosts: new Map(), days: new Map(), rules: new Map(), confidence: { high: 0, medium: 0, low: 0 } }; }
const inc = (m, k, w) => m.set(k || '(none)', (m.get(k || '(none)') || 0) + w);
const top = (m, n) => [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))).slice(0, n).map(([key, weight]) => ({ key, weight }));
function addTo(b, row, tz) {
  const w = row.weight; b.records.push(row); b.transactions += w;
  if (row.user) b.users.add(row.user);
  inc(b.departments, row.dept, w); inc(b.locations, row.location, w); inc(b.urls, row.url, w); inc(b.hosts, row.host, w);
  inc(b.rules, row.rule, w); b.confidence[row.confidence.level] += w;
  for (const [d, c] of Object.entries(row.days || {})) b.days.set(d, (b.days.get(d) || 0) + c);
  if (!row.days || !Object.keys(row.days).length) inc(b.days, row.time ? dayIn(row.time, tz) : 'unknown', w);
}
function finish(b, n) {
  return {
    transactions: b.transactions, records: b.records.length, distinctUsers: b.users.size,
    departments: top(b.departments, n), locations: top(b.locations, n), topUrls: top(b.urls, n), topHosts: top(b.hosts, n),
    rules: top(b.rules, n), trend: [...b.days.entries()].sort((a, c) => a[0].localeCompare(c[0])).map(([day, weight]) => ({ day, weight })),
    confidence: b.confidence, rows: b.records,
  };
}

// records: aggregated (or raw) normalized records. Returns newlyBlocked / newlyAllowed / alreadyBlocked summaries.
function simulateDiff(records, currentSnap, proposedSnap, opts = {}) {
  const tz = opts.tz || DEFAULT_TZ;
  if (!validTz(tz)) throw new Error(`unknown time zone: ${tz}`);
  if (!currentSnap || !proposedSnap) throw new Error('simulateDiff needs current and proposed snapshots');
  const n = opts.top || 10;
  const out = { newlyBlocked: bucket(), newlyAllowed: bucket(), alreadyBlocked: bucket() };
  const ssl = { transactions: 0, records: 0, hosts: new Map(), users: new Set() };
  let evaluated = 0, transactions = 0, changed = 0, logMismatch = 0;
  const cache = new Map();
  for (const r of records || []) {
    const w = Number.isFinite(r.weight) && r.weight > 0 ? r.weight : 1;
    evaluated++; transactions += w;
    // Failed SSL/TLS handshakes: never inspected, so neither newly nor already blocked. Hosts are hints for SSL exemptions.
    if (r.action === 'SSL_FAILED') { ssl.records++; ssl.transactions += w; inc(ssl.hosts, r.host, w); if (r.user) ssl.users.add(r.user); continue; }
    const ctx = contextOf(r, opts);
    if (!ctx.target) continue;
    const key = [ctx.target.raw || ctx.target.host, ctx.user, ctx.department, ctx.location, ctx.categories.join(','), ctx.groups.join(',')].join('|');
    let pair = cache.get(key);
    if (!pair) {
      const cur = E.simulate({ data: dataOf(currentSnap) }, Object.assign({}, ctx, { notes: [] }), {});
      const pro = E.simulate({ data: dataOf(proposedSnap) }, Object.assign({}, ctx, { notes: [] }), {});
      const reasons = new Set([...reasonsFrom(cur, currentSnap, ctx), ...reasonsFrom(pro, proposedSnap, ctx)]);
      const co = outcomeOf(cur), po = outcomeOf(pro);
      pair = { cur: ACT(co.action), pro: ACT(po.action), curRule: co.rule, proRule: po.rule, confidence: confidenceOf(reasons) };
      cache.set(key, pair);
    }
    const loggedBlocked = r.action === 'BLOCKED';
    const otherEngine = loggedBlocked && r.ruleType && !URL_FILTERING.test(r.ruleType);
    if (loggedBlocked !== BLOCKISH.has(pair.cur)) logMismatch += w;
    if (pair.cur === pair.pro) continue;
    changed += w;
    const row = { user: r.user, dept: r.dept, location: r.location, url: r.url, host: r.host, urlcat: r.urlcat, loggedAction: r.action, ruleType: r.ruleType || null, weight: w, days: r.days, time: r.time,
      current: pair.cur, proposed: pair.pro, confidence: pair.confidence };
    if (BLOCKISH.has(pair.pro) && (loggedBlocked || otherEngine)) addTo(out.alreadyBlocked, Object.assign(row, { rule: r.blockedBy || pair.curRule, alreadyBlockedBy: r.blockedBy || null, blockedByEngine: r.ruleType || null }), tz);
    else if (BLOCKISH.has(pair.pro)) addTo(out.newlyBlocked, Object.assign(row, { rule: pair.proRule }), tz);
    else if (BLOCKISH.has(pair.cur)) addTo(out.newlyAllowed, Object.assign(row, { rule: pair.proRule }), tz);
  }
  return {
    ok: true, tz,
    totals: { records: evaluated, transactions, sslFailedTransactions: ssl.transactions, changedTransactions: changed, logMismatchTransactions: logMismatch, uniqueEvaluations: cache.size },
    sslFailed: { status: 'sslFailed', label: 'failed SSL, not inspected', transactions: ssl.transactions, records: ssl.records, distinctUsers: ssl.users.size,
      hosts: top(ssl.hosts, opts.sslHosts || 50), note: 'TLS handshake failed before policy applied; hosts may need an SSL inspection exemption' },
    newlyBlocked: finish(out.newlyBlocked, n), newlyAllowed: finish(out.newlyAllowed, n), alreadyBlocked: finish(out.alreadyBlocked, n),
  };
}

module.exports = { simulateDiff, contextOf, confidenceOf, UNRESOLVABLE };
