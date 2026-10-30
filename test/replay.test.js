'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const R = require('../src/replay');
const { simulate } = require('../src/engine');
const M = require('../src/matchers');

// Synthetic data only: example.com hosts and RFC 5737 addresses.
const fx = (n) => path.join(__dirname, 'fixtures', 'replay', n);
const read = (n) => fs.readFileSync(fx(n), 'utf8');
const collect = async (it) => { const out = []; for await (const r of it) out.push(r); return out; };

function checkPair(recs) {
  assert.strictEqual(recs.length, 2);
  const [a, b] = recs;
  assert.strictEqual(a.user, 'alice@example.com'); assert.strictEqual(a.dept, 'Engineering'); assert.strictEqual(a.location, 'HQ');
  assert.strictEqual(a.host, 'social.example.com'); assert.strictEqual(a.url, 'social.example.com/feed');
  assert.strictEqual(a.urlcat, 'Social Networking'); assert.strictEqual(a.action, 'ALLOWED');
  assert.strictEqual(a.blockedBy, null); assert.strictEqual(a.urlRule, 'Allow_Social'); assert.strictEqual(a.clientIp, '192.0.2.10');
  assert.strictEqual(b.action, 'BLOCKED'); assert.strictEqual(b.blockedBy, 'Block_Games'); assert.strictEqual(b.host, 'games.example.com');
  assert.ok(a.time && a.time.startsWith('2026-10-30'));
  assert.strictEqual(a.weight, 1);
}

test('Web Insights CSV fixture: header-name mapping, quoted time', async () => checkPair(await collect(R.parseWebInsights(read('webinsights.csv')))));
test('NSS Cloud JSON array fixture (wrapped events)', async () => checkPair(await collect(R.parseNssJson(read('nss-cloud.json')))));
test('NSS JSON lines fixture', async () => checkPair(await collect(R.parseNssJson(read('nss-lines.jsonl')))));
test('NSS TSV fixture with default field list and with a feed format string', async () => {
  checkPair(await collect(R.parseNssTsv(read('nss.tsv'))));
  const fmt = '%s{time}\\t%s{login}\\t%s{dept}\\t%s{location}\\t%s{url}\\t%s{urlcat}\\t%s{action}\\t%s{reason}\\t%s{rulelabel}\\t%s{urlfilterrulelabel}\\t%s{cltip}\\n';
  checkPair(await collect(R.parseNssTsv(read('nss.tsv'), { fields: fmt })));
});

test('Web Insights: reordered, odd-case headers, preamble, embedded comma/quote/newline, unknown columns', async () => {
  const csv = [
    'Web Insights Logs report', 'Time range: last 24 hours', '',
    ' url ,POLICY  ACTION,user,Blocked Policy Name,Extra Column,Department',
    '"news.example.com/a,b",Blocked,carol@example.com,"Rule ""A""",x,"Multi',
    'line dept"',
    'news.example.com/c,Allowed,dave@example.com,,y,Ops',
  ].join('\r\n');
  const stats = {};
  const recs = await collect(R.parseWebInsights(csv, stats));
  assert.strictEqual(recs.length, 2);
  assert.strictEqual(recs[0].url, 'news.example.com/a,b'); assert.strictEqual(recs[0].blockedBy, 'Rule "A"');
  assert.strictEqual(recs[0].dept, 'Multi\nline dept'); assert.strictEqual(recs[0].action, 'BLOCKED');
  assert.deepStrictEqual(stats.unknownColumns, ['Extra Column']);
  assert.strictEqual(stats.rows, 2);
});

test('Web Insights: missing URL/Host header is a clear error', async () => {
  await assert.rejects(collect(R.parseWebInsights('User,Department\nalice@example.com,Eng\n')), /no header row/);
});

test('streaming: Readable input, 20k rows, JSON array split across chunks', async () => {
  const rows = ['URL,User,Policy Action'];
  for (let i = 0; i < 20000; i++) rows.push(`site${i % 5}.example.com/p,u${i % 3}@example.com,Allowed`);
  const recs = await R.aggregate(R.parseWebInsights(Readable.from([rows.join('\n')])));
  assert.strictEqual(recs.length, 15);
  assert.strictEqual(recs.reduce((s, r) => s + r.weight, 0), 20000);
  const arr = '[' + Array.from({ length: 50 }, (_, i) => JSON.stringify({ event: { login: 'x@example.com', url: `a${i % 2}.example.com/`, action: 'Allowed' } })).join(',\n') + ']';
  const chunks = arr.match(/[\s\S]{1,37}/g);
  const agg = await R.aggregate(R.parseNssJson(Readable.from(chunks)));
  assert.strictEqual(agg.length, 2); assert.strictEqual(agg[0].weight + agg[1].weight, 50);
});

test('NSS JSON: bad objects skipped and counted, braces inside strings ok', async () => {
  const stats = {};
  const recs = await collect(R.parseNssJson('{"url":"x.example.com/{a}","login":"a@example.com"}\n{"nope":1}\n{bad json}\n', stats));
  assert.strictEqual(recs.length, 1); assert.strictEqual(recs[0].host, 'x.example.com'); assert.strictEqual(stats.skipped, 2);
});

test('aggregate merges identical inputs, sums weight, keeps per-day counts', async () => {
  const recs = [
    R.record({ user: 'alice@example.com', url: 'www.example.com/', urlcat: 'News', time: '2026-10-29T10:00:00Z', weight: 3 }),
    R.record({ user: 'ALICE@example.com', url: 'www.example.com/', urlcat: 'news', time: '2026-10-30T10:00:00Z' }),
    R.record({ user: 'bob@example.com', url: '192.0.2.10/x', urlcat: 'Other' }),
  ];
  const out = await R.aggregate(recs);
  assert.strictEqual(out.length, 2);
  const a = out.find((r) => r.user === 'alice@example.com');
  assert.strictEqual(a.weight, 4); assert.deepStrictEqual(a.days, { '2026-10-29': 3, '2026-10-30': 1 });
  assert.strictEqual(out.find((r) => r.user === 'bob@example.com').host, '192.0.2.10');
});

test('parseLogs sniffs format', async () => {
  assert.strictEqual(R.sniff(read('webinsights.csv')), 'webinsights');
  assert.strictEqual(R.sniff(read('nss-cloud.json')), 'nss-json');
  assert.strictEqual(R.sniff(read('nss.tsv')), 'nss-tsv');
  checkPair(await collect(R.parseLogs(read('nss.tsv'))));
});

// ---------- phase 2 ----------
const demo = () => JSON.parse(JSON.stringify(require('../src/demo-snapshot.json')));
const verdict = (data, target) => simulate({ data }, { target: M.parseTarget(target), port: 443, protocol: 'tcp', categories: [], resolvedIps: [], groups: [], notes: [] }, {}).summary.primary.action;
const blockSpec = { intent: 'BLOCK', entries: ['blocked.example.com'], category: { mode: 'new', name: 'Replay Test Block' },
  rules: { url: { enabled: true, mode: 'new', name: 'Replay-Block', placeAbove: 'TOP' } } };

test('proposedPolicy applies the wizard plan to a clone; live snapshot untouched', async () => {
  const live = demo();
  const before = JSON.stringify(live);
  assert.strictEqual(verdict(live, 'blocked.example.com'), 'ALLOW');
  const res = await R.proposedPolicy({ data: live }, blockSpec);
  assert.ok(res.ok, JSON.stringify(res.errors));
  assert.strictEqual(JSON.stringify(live), before, 'live snapshot must not change');
  assert.strictEqual(verdict(res.data, 'blocked.example.com'), 'BLOCK');
  assert.strictEqual(verdict(live, 'blocked.example.com'), 'ALLOW');
  assert.ok(res.data.urlFilteringRules.some((r) => r.name === 'Replay-Block'));
  assert.strictEqual(res.data.__status, undefined);
});

test('proposedPolicy returns plan errors without applying', async () => {
  const live = demo();
  const res = await R.proposedPolicy(live, { intent: 'BLOCK', entries: [], rules: {} });
  assert.strictEqual(res.ok, false); assert.ok(res.errors.length);
});

test('simulateDiff is still a fail-safe stub', () => assert.deepStrictEqual(R.simulateDiff(), { ok: false, status: 'not_implemented' }));
