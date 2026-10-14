'use strict';
const test = require('node:test');
const assert = require('node:assert');
const bulk = require('../src/bulk');
const { simulate } = require('../src/engine');
const M = require('../src/matchers');

test('header-less list: one IP per line, optional port and protocol', () => {
  const p = bulk.parseCsv('8.8.8.8\n1.1.1.1,53,udp\n\n# comment\n10.0.0.0/30\n');
  assert.equal(p.entries.length, 3);
  assert.deepEqual([p.entries[1].ip, p.entries[1].port, p.entries[1].protocol], ['1.1.1.1', '53', 'udp']);
  assert.equal(p.header, null);
});

test('header with aliases, quotes and BOM', () => {
  const p = bulk.parseCsv('﻿IP Address,Port,Proto,Label,Category\n"203.0.113.10",443,tcp,"Vendor, Inc",GAMBLING\n');
  assert.equal(p.entries.length, 1);
  const e = p.entries[0];
  assert.equal(e.ip, '203.0.113.10'); assert.equal(e.label, 'Vendor, Inc'); assert.equal(e.categories, 'GAMBLING'); assert.equal(e.protocol, 'tcp');
});

test('expand CIDRs and ranges, reject oversize and invalid rows', () => {
  const p = bulk.parseCsv('ip\n10.0.0.0/30\n10.0.1.1-10.0.1.3\n300.1.1.1\n10.0.0.0/8\nexample.com\n');
  const ex = bulk.expand(p.entries);
  assert.equal(ex.rows.filter((r) => r.input === '10.0.0.0/30').length, 4);
  assert.equal(ex.rows.filter((r) => r.input === '10.0.1.1-10.0.1.3').length, 3);
  assert.ok(ex.rows.some((r) => r.target === 'example.com'));
  assert.equal(ex.skipped.length, 2); // 300.1.1.1 and the /8
  assert.ok(bulk.expand(p.entries, { maxRows: 5 }).error);
});

test('lookup key: single IPs and hosts only', () => {
  assert.equal(bulk.lookupKey('8.8.8.8'), '8.8.8.8');
  assert.equal(bulk.lookupKey('https://Example.com/a?b'), 'example.com');
  assert.equal(bulk.lookupKey('*.google.com'), 'www.google.com');
  assert.equal(bulk.lookupKey('10.0.0.0/24'), null);
});

test('CSV output escapes and neutralises formulas', () => {
  const csv = bulk.toCsv([{ row: 1, input: '=cmd', label: 'a,b', notes: 'say "hi"' }]);
  assert.ok(csv.includes(`"'=cmd"`)); assert.ok(csv.includes('"a,b"')); assert.ok(csv.includes('"say ""hi"""'));
});

test('job runs against sample policies with batched lookup and a 429 wait', async () => {
  const snap = { data: require('../src/demo-snapshot.json') };
  let calls = 0;
  const fakeLookup = async (client, urls) => {
    calls++;
    if (calls === 2) throw Object.assign(new Error('rate'), { status: 429, retryAfter: 1 });
    return urls.map((u) => ({ url: u, urlClassifications: [u === '203.0.113.99' ? 'GAMBLING' : 'WEB_SEARCH'], urlClassificationsWithSecurityAlert: [] }));
  };
  const session = { snap, client: {}, last: 0 };
  const rows = bulk.expand(bulk.parseCsv('ip,label\n203.0.113.10,deny\n203.0.113.96/29,block\n10.20.30.40,private\n').entries).rows;
  const job = { id: 't', total: rows.length, done: 0, results: [], touch() {} };
  const buildContext = async (s, b) => ({ target: M.parseTarget(b.target), port: b.port ? +b.port : null, protocol: b.protocol, categories: b.categories || [], resolvedIps: [], groups: [], notes: [] });
  await bulk.runJob(session, job, rows, { lookup: true }, { buildContext, simulate, urlLookup: fakeLookup, URL_LOOKUP_MAX: 4 });
  assert.equal(job.phase, 'done');
  assert.equal(job.results.length, 10);
  assert.ok(calls >= 3, 'retried after 429');
  const byIp = Object.fromEntries(job.results.map((r) => [r.target, r]));
  assert.equal(byIp['203.0.113.10'].action, 'BLOCK');
  assert.equal(byIp['10.20.30.40'].action, 'BYPASS');
  assert.equal(byIp['203.0.113.99'].category, 'GAMBLING');
  assert.equal(byIp['203.0.113.99'].categorySource, 'Zscaler lookup');
  const st = bulk.status(job);
  assert.equal(st.summary.lookedUp, 10);
  assert.ok(st.summary.counts.BLOCKED >= 1);
});

// Replays the SOC-list run: OK calls, a 412 "please retry", then 403s after success (quota), then recovery.
const FAST = { transient: [0.01, 0.01], refused: [0.01, 0.01, 0.01], paceAfterTrouble: 1 };
const ctxFor = async (s, b) => ({ target: M.parseTarget(b.target), port: b.port ? +b.port : null, protocol: b.protocol, categories: b.categories || [], resolvedIps: [], groups: [], notes: [] });
function runWith(script, csv, timing = FAST, session) {
  let n = 0;
  const lookup = async (c, urls) => {
    const step = script[n++] || 'ok';
    if (step !== 'ok') throw Object.assign(new Error(`HTTP ${step} POST /zia/api/v1/urlLookup: {"code":"X"}`), { status: step });
    return urls.map((u) => ({ url: u, urlClassifications: ['MISCELLANEOUS_OR_UNKNOWN'] }));
  };
  session = session || { snap: { data: require('../src/demo-snapshot.json') }, client: {}, last: 0 };
  const rows = bulk.expand(bulk.parseCsv(csv).entries).rows;
  const job = { id: 'x', total: rows.length, done: 0, results: [], touch() {} };
  return bulk.runJob(session, job, rows, { lookup: true }, { buildContext: ctxFor, simulate, urlLookup: lookup, URL_LOOKUP_MAX: 2, timing }).then(() => ({ job, session, calls: () => n }));
}

test('412 and quota 403s after success are retried, not treated as "not permitted"', async () => {
  const { job } = await runWith(['ok', 412, 'ok', 403, 403, 'ok'], 'ip\n45.0.0.0/29\n');
  assert.equal(job.lookup.stopped, null);
  assert.equal(job.lookup.failed, 0);
  assert.equal(job.lookup.retries, 3);
  assert.ok(job.results.every((r) => r.categorySource === 'Zscaler lookup'), 'every row categorised');
});

test('403 on the very first call means not permitted', async () => {
  const { job } = await runWith([403], 'ip\n45.0.0.1\n');
  assert.equal(job.lookup.stoppedKind, 'denied');
  assert.equal(job.results[0].categorySource, 'lookup not permitted');
});

test('quota that never clears stops with a rerun-later label', async () => {
  const { job } = await runWith(['ok', 403, 403, 403, 403], 'ip\n45.0.0.0/30\n');
  assert.equal(job.lookup.stoppedKind, 'quota');
  const src = job.results.map((r) => r.categorySource);
  assert.equal(src.filter((x) => x === 'Zscaler lookup').length, 2);
  assert.ok(src.filter((x) => /quota/.test(x)).length === 2);
});

test('failed lookups are retried on the next run in the same session', async () => {
  const first = await runWith([500, 500, 500], 'ip\n45.0.0.9\n', { transient: [0.01, 0.01], refused: [], paceAfterTrouble: 1 });
  assert.equal(first.job.lookup.failed, 1);
  const second = await runWith([], 'ip\n45.0.0.9\n', FAST, first.session);
  assert.equal(second.calls(), 1);
  assert.equal(second.job.results[0].categorySource, 'Zscaler lookup');
});

test('recommendations: expected block / allow → best policy area', async () => {
  const csv = [
    'ip,category,expected',
    '45.2.0.1,ANONYMIZER,block',            // ATP setting off in sample -> ATP
    '45.2.0.2,PROFESSIONAL_SERVICES,block', // broad category on an IP -> Firewall IP group
    '45.2.0.3,,block',                      // no category -> Firewall
    'bad.example.net,PROFESSIONAL_SERVICES,block', // host -> URL Filtering custom category
    '10.20.30.40,,block',                   // ZCC bypass -> Client Connector
    '203.0.113.10,,block',                  // already blocked
    '45.2.0.4,GAMBLING,allow',              // blocked by URL category rule -> custom allow category
    '45.2.0.5,MALWARE_SITE,allow',          // blocked by ATP -> allowlist
    '45.2.0.6,WEB_SEARCH,allow',            // fine
  ].join('\n');
  const { job } = await runWith([], csv);
  const by = Object.fromEntries(job.results.map((r) => [r.target, r]));
  assert.equal(by['45.2.0.1'].area, 'ATP'); assert.match(by['45.2.0.1'].recommendation, /Anonymizers/);
  assert.equal(by['45.2.0.2'].area, 'Firewall'); assert.match(by['45.2.0.2'].recommendation, /Don't block category PROFESSIONAL_SERVICES/);
  assert.equal(by['45.2.0.3'].category, 'MISCELLANEOUS_OR_UNKNOWN'); // from the fake lookup
  assert.equal(by['45.2.0.3'].area, 'URL Filtering'); assert.match(by['45.2.0.3'].recommendation, /Block category MISCELLANEOUS_OR_UNKNOWN/);
  assert.equal(by['bad.example.net'].area, 'URL Filtering'); assert.match(by['bad.example.net'].recommendation, /custom URL category/);
  assert.equal(by['10.20.30.40'].area, 'Client Connector');
  assert.equal(by['203.0.113.10'].meets, 'yes');
  assert.equal(by['45.2.0.4'].meets, 'no'); assert.match(by['45.2.0.4'].recommendation, /Allow rule above/);
  assert.equal(by['45.2.0.5'].area, 'ATP'); assert.match(by['45.2.0.5'].recommendation, /allowlist/);
  assert.equal(by['45.2.0.6'].meets, 'yes');
  const rec = bulk.status(job).summary.recommendations;
  assert.equal(rec.expectedRows, 9); assert.equal(rec.misses, 7);
  assert.ok(rec.byArea.find((a) => a.area === 'Firewall' && a.count === 1));
  assert.ok(rec.categories.find((c) => c.category === 'PROFESSIONAL_SERVICES' && /Do not block/.test(c.advice)));
});

test('run-wide expectation applies when the file has no expected column', async () => {
  const session = { snap: { data: require('../src/demo-snapshot.json') }, client: {}, last: 0 };
  const rows = bulk.expand(bulk.parseCsv('45.3.0.1\n203.0.113.10\n').entries).rows;
  const job = { id: 'e', total: rows.length, done: 0, results: [], touch() {} };
  await bulk.runJob(session, job, rows, { lookup: false, expected: 'BLOCK' }, { buildContext: ctxFor, simulate });
  assert.deepEqual(job.results.map((r) => r.meets), ['no', 'yes']);
});

test('lookup result keeps the cloud application when Zscaler returns one', () => {
  assert.equal(bulk.fromLookup({ url: 'x', urlClassifications: ['A'], application: 'DROPBOX' }).application, 'DROPBOX');
  assert.equal(bulk.fromLookup({ url: 'x', urlClassifications: ['A'], application: 'NONE' }).application, '');
});
