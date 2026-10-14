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
