'use strict';
// Bulk testing: parse a CSV of destinations (IPs, CIDRs, ranges or hosts), look up Zscaler categories in batches,
// simulate each row against the loaded policy, and produce a results CSV plus a summary.
const M = require('./matchers');
const R = require('./recommend');

const MAX_ROWS = 250000;          // total addresses after CIDR/range expansion
const MAX_PER_ENTRY = 65536;      // a /16 per row at most
const PREVIEW_ROWS = 200;

// ---------- CSV ----------
function splitCsvLine(line) {
  const out = [];
  let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',' || ch === '\t' || ch === ';') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim());
}

const ALIASES = {
  ip: ['ip', 'ipaddress', 'ip_address', 'address', 'addr', 'destination', 'dest', 'destip', 'dest_ip', 'destinationip', 'target', 'host', 'url', 'domain'],
  port: ['port', 'destport', 'dest_port', 'dport'],
  protocol: ['protocol', 'proto'],
  sourceIp: ['sourceip', 'source_ip', 'srcip', 'src_ip', 'src', 'source'],
  location: ['location', 'loc'],
  destCountry: ['destcountry', 'dest_country', 'country'],
  categories: ['category', 'categories', 'urlcategory', 'url_category'],
  user: ['user', 'username', 'email'],
  label: ['label', 'name', 'note', 'notes', 'comment', 'description', 'tag'],
  expected: ['expected', 'expect', 'expectation', 'should', 'desired', 'intent', 'expectedaction', 'expected_action'],
};
function headerKey(cell) {
  const c = String(cell || '').toLowerCase().replace(/[\s-]/g, '');
  for (const [k, list] of Object.entries(ALIASES)) if (list.includes(c)) return k;
  return null;
}
const looksLikeDest = (s) => !!M.parseIpRange(s) || /^[a-z0-9*][a-z0-9.*-]*\.[a-z]{2,}([:/].*)?$/i.test(s) || /^[a-z]+:\/\//i.test(s);

// Returns { entries: [{line, input, port, protocol, ...}], skipped: [{line, text, why}], header: [...] | null }
function parseCsv(text) {
  const lines = String(text || '').replace(/^﻿/, '').split(/\r?\n/);
  const entries = [], skipped = [];
  let map = null, header = null, first = true;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (!raw || raw.startsWith('#')) continue;
    const cells = splitCsvLine(raw);
    if (first) {
      first = false;
      const keys = cells.map(headerKey);
      if (keys.includes('ip')) { map = keys; header = cells; continue; }
      if (!looksLikeDest(cells[0])) { skipped.push({ line: i + 1, text: raw.slice(0, 120), why: 'first line is not a destination and has no "ip" column header' }); continue; }
    }
    const e = { line: i + 1 };
    if (map) map.forEach((k, j) => { if (k && cells[j] !== undefined && cells[j] !== '') e[k] = cells[j]; });
    else {
      // No header: ip[,port][,protocol]
      e.ip = cells[0];
      if (/^\d{1,5}$/.test(cells[1] || '')) e.port = cells[1];
      const pr = (cells[2] || cells[1] || '').toLowerCase();
      if (pr === 'tcp' || pr === 'udp') e.protocol = pr;
    }
    if (!e.ip) { skipped.push({ line: i + 1, text: raw.slice(0, 120), why: 'no destination' }); continue; }
    e.input = e.ip;
    entries.push(e);
  }
  return { entries, skipped, header };
}

function intToIp(n) { return [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255].join('.'); }

// Expand CIDRs / ranges into individual addresses. Hosts and URLs pass through untouched.
function expand(entries, { maxRows = MAX_ROWS, maxPerEntry = MAX_PER_ENTRY } = {}) {
  const rows = [], skipped = [];
  let total = 0;
  for (const e of entries) {
    const v = String(e.ip).trim();
    const r = /^\d{1,3}(\.\d{1,3}){3}([/-].*)?$/.test(v) ? M.parseIpRange(v) : null;
    if (/^\d{1,3}(\.\d{1,3}){3}([/-].*)?$/.test(v) && !r) { skipped.push({ line: e.line, text: v, why: 'not a valid IPv4 address, CIDR or range' }); continue; }
    if (!r) {
      if (!looksLikeDest(v)) { skipped.push({ line: e.line, text: v, why: 'not an IPv4 address, CIDR, range, host or URL' }); continue; }
      total += 1;
      if (total > maxRows) return { error: `The file expands to more than ${maxRows.toLocaleString()} rows. Split it into smaller files.` };
      rows.push(Object.assign({}, e, { target: v }));
      continue;
    }
    const n = r[1] - r[0] + 1;
    if (n > maxPerEntry) { skipped.push({ line: e.line, text: v, why: `range has ${n.toLocaleString()} addresses; the limit per row is ${maxPerEntry.toLocaleString()} (a /16)` }); continue; }
    total += n;
    if (total > maxRows) return { error: `The file expands to more than ${maxRows.toLocaleString()} addresses. Split it into smaller files.` };
    for (let x = r[0]; x <= r[1]; x++) rows.push(Object.assign({}, e, { target: intToIp(x) }));
  }
  return { rows, skipped };
}

// The key urlLookup is asked for: bare IP or hostname (no scheme, path or port).
function lookupKey(target) {
  const t = M.parseTarget(target);
  if (!t) return null;
  if (t.isIp) return /[/-]/.test(t.host) ? null : t.host;
  if (t.isWildcard) return 'www.' + t.host.replace(/^\*\.?/, '');
  return t.host;
}

// Normalise one urlLookup result. `application` (the cloud app Zscaler maps the URL to) is optional in the response.
function fromLookup(o) {
  const a = o.application;
  const app = typeof a === 'string' ? a : a && (a.name || a.displayName || a.id) ? String(a.name || a.displayName || a.id) : '';
  return { categories: o.urlClassifications || [], security: o.urlClassificationsWithSecurityAlert || [], application: /^(none|null)?$/i.test(app) ? '' : app };
}

// ---------- results ----------
const COLUMNS = [
  ['row', 'Row'], ['line', 'Input line'], ['input', 'Input'], ['target', 'Destination'], ['port', 'Port'], ['protocol', 'Protocol'], ['label', 'Label'],
  ['category', 'Zscaler category'], ['securityCategory', 'Security alert category'], ['application', 'Zscaler cloud app'], ['categorySource', 'Category source'],
  ['expected', 'Expected'], ['meets', 'Meets expectation'], ['area', 'Recommended area'], ['recommendation', 'Recommendation'],
  ['result', 'Result'], ['action', 'Policy rule action'], ['module', 'Deciding module'], ['rule', 'Deciding rule'], ['order', 'Rule order'],
  ['firewall', 'Firewall'], ['firewallRule', 'Firewall rule'], ['urlFiltering', 'URL filtering'], ['urlRule', 'URL filtering rule'], ['forwarding', 'Client Connector forwarding'],
  ['alsoMatched', 'Also matched (first match wins)'], ['incomplete', 'Not evaluated (failed/timeout)'], ['couldBlock', 'Could be blocked by'], ['conditions', 'Conditions that change the result'], ['notes', 'Notes'], ['error', 'Error'],
];
function csvCell(v) {
  const s = v == null ? '' : String(v);
  return /[",\r\n]/.test(s) || /^[=+\-@]/.test(s) ? `"${(/^[=+\-@]/.test(s) ? "'" : '') + s.replace(/"/g, '""')}"` : s;
}
function toCsv(results, filter) {
  const head = COLUMNS.map((c) => c[1]).join(',');
  const body = results.filter(filter || (() => true)).map((r) => COLUMNS.map((c) => csvCell(r[c[0]])).join(','));
  return [head, ...body].join('\r\n') + '\r\n';
}

function resultRow(i, row, out, cat, expected, data) {
  const s = out.summary, p = s.primary || {};
  const mod = (name) => out.modules.find((m) => m.module === name) || {};
  const fw = mod('Firewall'), url = mod('URL Filtering'), fwd = out.modules.find((m) => m.module.startsWith('Forwarding')) || {};
  // A condition only counts as "could block" if it is about who/where/when — not a category we never had.
  const noCat = !(cat.categories || []).length && !(cat.security || []).length;
  const blk = p.action === 'BLOCK' ? null : (s.alsoBasedOn || []).find((c) => c.action === 'BLOCK' && ['identity', 'location', 'other'].includes(c.kind)
    && !(noCat && /category/i.test(c.condition || '')));
  const notes = (out.context.notes || []).filter((n) => !/^No port entered/.test(n));
  const r = {
    row: i + 1, line: row.line, input: row.input, target: row.target,
    port: out.context.port, protocol: (out.context.protocol || 'tcp').toUpperCase(), label: row.label || '',
    category: (cat.categories || []).join('; '), securityCategory: (cat.security || []).join('; '), categorySource: cat.source,
    result: s.overall, action: p.action, module: p.module, rule: p.rule || '', order: p.order != null && p.order >= 0 ? p.order : '',
    application: cat.application || '',
    firewall: fw.verdict || '', firewallRule: fw.decidingRule ? fw.decidingRule.name : '', firewallOrder: fw.decidingRule && fw.decidingRule.order >= 0 ? fw.decidingRule.order : '',
    urlFiltering: url.verdict || '', urlRule: url.decidingRule ? url.decidingRule.name : '',
    forwarding: fwd.verdict || '',
    alsoMatched: (() => { const mm = (s.multiMatch || []).find((x) => x.decides); return mm ? mm.also.map((e) => `${e.name}${e.order != null && e.order >= 0 ? ' (order ' + e.order + ')' : ''}${e.differs ? ' [' + e.action + ']' : ''}`).join('; ') : ''; })(),
    incomplete: (s.incomplete || []).map((x) => `${x.module}${x.timeout ? ' — ZIA timed out' : ''}: ${String(x.error).slice(0, 80)}`).join(' | '),
    couldBlock: blk ? `${blk.condition} → rule "${blk.rule || blk.module}"` : '',
    conditions: (s.alsoBasedOn || []).length,
    notes: notes.slice(0, 3).join(' | '), error: '',
  };
  return Object.assign(r, R.recommendRow(r, expected, data || {}));
}

function summarizeJob(results, data) {
  const counts = {}, rules = {}, cats = {};
  let lookedUp = 0, errors = 0, couldBlock = 0;
  for (const r of results) {
    if (r.error) { errors++; continue; }
    counts[r.result] = (counts[r.result] || 0) + 1;
    if (r.action !== 'ALLOW') { const k = `${r.module}|${r.rule || '(default)'}|${r.action}`; rules[k] = (rules[k] || 0) + 1; }
    for (const c of (r.category ? r.category.split('; ') : ['(no category)'])) cats[c] = (cats[c] || 0) + 1;
    if (r.categorySource === 'Zscaler lookup') lookedUp++;
    if (r.couldBlock) couldBlock++;
  }
  const top = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n);
  return {
    counts, errors, lookedUp, couldBlock, recommendations: R.summarizeRecommendations(results, data || {}),
    topRules: top(rules, 15).map(([k, n]) => { const [module, rule, action] = k.split('|'); return { module, rule, action, count: n }; }),
    topCategories: top(cats, 15).map(([category, count]) => ({ category, count })),
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tick = () => new Promise((r) => setImmediate(r));

// Batched category lookup. Fills cache (Map key -> {categories, security, error}). Waits out 429s.
// Retry schedule (seconds). Transient = Zscaler "please retry" (412), 5xx, timeouts, network errors.
// Refused = 401/403 after earlier calls succeeded — almost always a lookup quota, so pause and retry, don't stop.
const DEFAULT_TIMING = { transient: [5, 15, 30, 60, 120], refused: [60, 120, 300, 600, 900, 900, 900, 900, 900, 900], paceAfterTrouble: 2000 };
const shortMsg = (e) => String(e && e.message || e).replace(/^HTTP \d+ POST \S+: /, '').slice(0, 180);

async function waitFor(job, secs, reason) {
  job.lookup.waitingUntil = Date.now() + secs * 1000; job.lookup.waitReason = reason;
  while (Date.now() < job.lookup.waitingUntil && !job.cancelled) { await sleep(Math.max(5, Math.min(500, job.lookup.waitingUntil - Date.now()))); job.touch(); }
  job.lookup.waitingUntil = null; job.lookup.waitReason = null;
}

// Batched category lookup. Fills cache (Map key -> {categories, security, error?}). Entries cached with an error are retried.
async function lookupAll(job, client, keys, cache, urlLookup, batchSize, timing = DEFAULT_TIMING) {
  const todo = [...new Set(keys)].filter((k) => k && !(cache.has(k) && !cache.get(k).error));
  job.lookup = { total: todo.length, done: 0, failed: 0, calls: 0, okCalls: 0, retries: 0, waitingUntil: null, waitReason: null, stopped: null, stoppedKind: null, lastError: null };
  let transientTries = 0, refusedTries = 0, pace = 0;
  for (let i = 0; i < todo.length && !job.cancelled;) {
    const batch = todo.slice(i, i + batchSize);
    if (pace) await sleep(pace);
    try {
      job.lookup.calls++;
      const out = await urlLookup(client, batch, { rateRetries: 0 });
      const byKey = new Map(out.map((o) => [String(o.url || '').toLowerCase(), o]));
      for (const k of batch) {
        const o = byKey.get(k.toLowerCase());
        cache.set(k, o ? fromLookup(o) : { categories: [], security: [], error: 'not returned by lookup' });
      }
      job.lookup.done += batch.length; job.lookup.okCalls++; i += batch.length; transientTries = 0; refusedTries = 0;
    } catch (e) {
      const st = e.status;
      job.lookup.lastError = `${st || 'network error'}: ${shortMsg(e)}`;
      if (st === 429) {
        await waitFor(job, Math.min(Math.max(e.retryAfter || 60, 1), 3600), "Zscaler's lookup rate limit (429)");
        pace = timing.paceAfterTrouble; continue;
      }
      if (st === 401 || st === 403) {
        if (!job.lookup.okCalls) { job.lookup.stopped = `Category lookup not permitted for this API client (${st}: ${shortMsg(e)}). Results use policy only.`; job.lookup.stoppedKind = 'denied'; break; }
        if (refusedTries >= timing.refused.length) {
          job.lookup.stopped = `Zscaler kept refusing lookups (${st}) after ${job.lookup.okCalls} successful calls, probably a lookup quota. ${(todo.length - i).toLocaleString()} addresses were not looked up; rerun them later.`;
          job.lookup.stoppedKind = 'quota'; break;
        }
        if (st === 401 && client && client.auth) { try { await client.auth(true); } catch {} }
        job.lookup.retries++;
        await waitFor(job, timing.refused[refusedTries++], `Zscaler refused the lookup (${st}) after ${job.lookup.okCalls} successful calls, probably a quota. Retry ${refusedTries} of ${timing.refused.length}`);
        pace = timing.paceAfterTrouble; continue;
      }
      if (batch.length > 1 && st === 400) { batchSize = Math.max(1, Math.floor(batch.length / 4)); continue; } // isolate a bad entry
      const transient = !st || st === 408 || st === 412 || st >= 500;
      if (transient && transientTries < timing.transient.length) {
        job.lookup.retries++;
        await waitFor(job, timing.transient[transientTries++], `Zscaler asked to retry (${st || 'network error'}). Retry ${transientTries} of ${timing.transient.length}`);
        continue;
      }
      transientTries = 0;
      for (const k of batch) cache.set(k, { categories: [], security: [], error: shortMsg(e) });
      job.lookup.done += batch.length; job.lookup.failed += batch.length; i += batch.length;
    }
    job.touch();
  }
}

// deps: { buildContext(session, body), simulate(snap, ctx, manual), urlLookup, URL_LOOKUP_MAX }
async function runJob(session, job, rows, opts, deps) {
  job.data = (session.snap && session.snap.data) || {};
  try {
    // Fresh lookups for every run: nothing from an earlier run or single simulation is reused.
    const cache = new Map(); session.userCache = new Map(); session.scimMember = new Map();
    if (opts.lookup && session.client) {
      job.phase = 'lookup';
      await lookupAll(job, session.client, rows.filter((r) => !r.categories).map((r) => lookupKey(r.target)), cache, deps.urlLookup, deps.URL_LOOKUP_MAX || 100, deps.timing);
    }
    job.phase = 'simulate';
    for (let i = 0; i < rows.length && !job.cancelled; i++) {
      const row = rows[i];
      const key = lookupKey(row.target);
      let cat;
      if (row.categories) cat = { categories: row.categories.split(/[|; ]+/).map((c) => c.trim().toUpperCase()).filter(Boolean), security: [], source: 'file' };
      else if (key && cache.has(key)) { const c = cache.get(key); cat = { categories: c.categories, security: c.security, application: c.application, source: c.error ? `lookup failed: ${c.error}` : 'Zscaler lookup' }; }
      else cat = { categories: [], security: [], source: !(opts.lookup && session.client) ? 'lookup off' : job.lookup && job.lookup.stoppedKind === 'denied' ? 'lookup not permitted' : job.lookup && job.lookup.stoppedKind === 'quota' ? 'lookup stopped (Zscaler quota): rerun later' : 'not looked up' };
      try {
        const body = {
          target: row.target, protocol: (row.protocol || opts.defaultProtocol || 'tcp').toLowerCase(),
          port: row.port || opts.defaultPort || ((row.protocol || opts.defaultProtocol || 'tcp').toLowerCase() === 'tcp' && !/^[a-z]+:\/\//i.test(row.target) ? '443' : ''),
          sourceIp: row.sourceIp || '', location: row.location || '', destCountry: row.destCountry || '', user: row.user || '',
          categories: [...cat.categories, ...cat.security], noLookup: true, useZpa: opts.useZpa !== false, cloudApp: cat.application || null,
        };
        const ctx = await deps.buildContext(session, body);
        const out = deps.simulate(session.snap, ctx, {});
        job.results.push(resultRow(i, row, out, cat, R.normExpected(row.expected) || opts.expected || '', job.data));
      } catch (e) {
        job.results.push({ row: i + 1, line: row.line, input: row.input, target: row.target, label: row.label || '', categorySource: cat.source, error: e.message.slice(0, 200) });
      }
      job.done = i + 1;
      if (i % 250 === 0) { await tick(); job.touch(); }
    }
    job.phase = job.cancelled ? 'cancelled' : 'done';
  } catch (e) {
    job.phase = 'error'; job.error = e.message;
  }
  job.finished = Date.now();
  job.summary = summarizeJob(job.results, job.data);
}

function status(job, { full = false } = {}) {
  if (!job) return null;
  const finished = ['done', 'cancelled', 'error'].includes(job.phase);
  const summary = finished ? job.summary : summarizeJob(job.results, job.data);
  const anyExp = summary.recommendations && summary.recommendations.expectedRows;
  const preview = job.results.filter(anyExp ? (r) => r.error || r.meets === 'no' : (r) => r.error || r.action !== 'ALLOW' || r.couldBlock).slice(0, PREVIEW_ROWS);
  return {
    id: job.id, phase: job.phase, error: job.error, total: job.total, done: job.done, started: job.started, finished: job.finished,
    lookup: job.lookup, parse: job.parse, expectation: job.expectation || '', summary, preview: finished || full ? preview : preview.slice(0, 25), cancelled: job.cancelled,
  };
}

module.exports = { parseCsv, expand, lookupKey, fromLookup, toCsv, runJob, status, summarizeJob, COLUMNS, MAX_ROWS, MAX_PER_ENTRY };
