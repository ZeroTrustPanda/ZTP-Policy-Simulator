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


// ---------- real Web Insights export layout (synthetic values) ----------
test('Web Insights export layout: preamble, Event Time with zone abbreviation, block-reason actions, trailing comma', async () => {
  const stats = {};
  const rows = await collect(R.parseWebInsights(read('webinsights-export.csv'), stats));
  assert.strictEqual(stats.rows, 7); assert.strictEqual(stats.skipped, 0);
  assert.ok(!stats.unknownColumns.includes('') && !stats.unknownColumns.includes('No.'));
  assert.ok(!stats.unknownColumns.includes('Event Time') && !stats.unknownColumns.includes('Blocked Policy Type'));
  const [a, b, c, d] = rows;
  assert.strictEqual(R.record({ url: 'a.example.com', action: 'Blocked due to Bad SSL record' }).action, 'BLOCKED');
  assert.strictEqual(R.record({ url: 'a.example.com', action: 'TLS handshake failed' }).action, 'SSL_FAILED');
  assert.strictEqual(a.time, '2026-11-02T13:50:15.000Z'); assert.strictEqual(a.tzSource, 'PST');
  assert.strictEqual(a.host, 'social.example.com'); assert.strictEqual(a.location, 'Example HQ'); assert.strictEqual(a.dept, 'Dept-A');
  assert.strictEqual(a.urlSuperCat, 'Internet Communication'); assert.strictEqual(a.action, 'ALLOWED'); assert.strictEqual(a.blockedBy, null);
  assert.strictEqual(b.action, 'BLOCKED'); assert.strictEqual(b.blockedBy, 'DNS Over HTTPS Services'); assert.strictEqual(b.ruleType, null);
  assert.strictEqual(c.action, 'SSL_FAILED'); assert.strictEqual(c.host, 'games.example.com');
  // 9:30 PM PST Nov 2 = 00:30 EST Nov 3 -> Eastern trend day is Nov 3
  assert.deepStrictEqual((await R.aggregate([d]))[0].days, { '2026-11-03': 1 });
});

test('zone abbreviations: explicit offsets win; unknown ones fall back to opts.tz', () => {
  const t = (v, o) => R.record({ url: 'a.example.com', time: v }, o).time;
  assert.strictEqual(t('November 2, 2026 5:50:15 AM EST'), '2026-11-02T10:50:15.000Z');
  assert.strictEqual(t('July 1, 2026 5:50:15 AM PDT'), '2026-07-01T12:50:15.000Z');
  assert.strictEqual(t('November 2, 2026 5:50:15 AM UTC', { tz: 'America/Chicago' }), '2026-11-02T05:50:15.000Z');
  assert.strictEqual(t('November 2, 2026 5:50:15 AM XYZ'), '2026-11-02T10:50:15.000Z'); // unknown -> Eastern (EST)
});

test('simulateDiff: failed SSL handshakes get their own group, never blocked', async () => {
  const { live, proposed } = await blockedProposal();
  const recs = await R.aggregate(R.parseWebInsights(read('webinsights-export.csv')));
  const d = R.simulateDiff(recs, live, proposed);
  assert.strictEqual(d.sslFailed.status, 'sslFailed'); assert.strictEqual(d.sslFailed.label, 'failed SSL, not inspected');
  assert.strictEqual(d.sslFailed.transactions, 3); assert.strictEqual(d.totals.sslFailedTransactions, 3);
  assert.deepStrictEqual(d.sslFailed.hosts.map((h) => h.key).sort(), ['blocked.example.com', 'games.example.com', 'legacy.example.com']);
  // blocked.example.com: the allowed row is newly blocked; the SSL-failed row is not counted anywhere else.
  assert.strictEqual(d.newlyBlocked.transactions, 1); assert.strictEqual(d.newlyBlocked.rows[0].user, 'user1@example.com');
  for (const g of ['newlyBlocked', 'alreadyBlocked', 'newlyAllowed']) assert.ok(!d[g].rows.some((r) => r.loggedAction === 'SSL_FAILED'), g);
  assert.ok(!d.alreadyBlocked.rows.some((r) => r.host === 'games.example.com'));
});

// ---------- time zones ----------
test('zone-less timestamps default to America/New_York (EDT and EST)', async () => {
  const [a] = await collect(R.parseWebInsights(read('webinsights.csv')));
  assert.strictEqual(a.time, '2026-10-30T18:02:11.000Z'); // 2:02:11 PM EDT
  for (const f of ['nss.tsv', 'nss-lines.jsonl', 'nss-cloud.json']) {
    const [x] = await collect(R.parseLogs(read(f)));
    assert.strictEqual(x.time, '2026-10-30T18:02:11.000Z', f);
  }
  assert.strictEqual(R.record({ url: 'a.example.com', time: 'Mon Jan 12 09:00:00 2026' }).time, '2026-01-12T14:00:00.000Z'); // EST
  assert.strictEqual(R.record({ url: 'a.example.com', time: '2026-11-01 01:30:00' }).time, '2026-11-01T05:30:00.000Z'); // fall-back day, first 1:30 (EDT)
  assert.strictEqual(R.record({ url: 'a.example.com', time: '2026-10-30T14:00:00Z' }).time, '2026-10-30T14:00:00.000Z'); // explicit zone wins
});

test('time zone is configurable; invalid zones are rejected', async () => {
  const [a] = await collect(R.parseLogs(read('nss.tsv'), { tz: 'UTC' }));
  assert.strictEqual(a.time, '2026-10-30T14:02:11.000Z');
  assert.strictEqual(R.record({ url: 'a.example.com', time: 'October 30, 2026 2:02:11 PM' }, { tz: 'America/Los_Angeles' }).time, '2026-10-30T21:02:11.000Z');
  assert.throws(() => R.parseLogs('x', { tz: 'Not/AZone' }), /time zone/);
  await assert.rejects(R.aggregate([], { tz: 'Not/AZone' }), /time zone/);
});

test('aggregate trend buckets by Eastern day (default) or the chosen zone', async () => {
  const recs = () => [R.record({ user: 'alice@example.com', url: 'www.example.com/', time: '2026-10-31T02:30:00Z' })]; // 10:30 PM EDT Oct 30
  assert.deepStrictEqual((await R.aggregate(recs()))[0].days, { '2026-10-30': 1 });
  assert.deepStrictEqual((await R.aggregate(recs(), { tz: 'UTC' }))[0].days, { '2026-10-31': 1 });
});

// ---------- phase 3 ----------
const rec = (o) => Object.assign(R.record(Object.assign({ time: '2026-10-30T15:00:00Z' }, o)), o.weight ? { weight: o.weight } : {});
async function blockedProposal() {
  const live = demo();
  const res = await R.proposedPolicy({ data: live }, blockSpec);
  assert.ok(res.ok);
  return { live, proposed: res.data };
}

test('simulateDiff: newly blocked, unaffected, and already blocked by another engine', async () => {
  const { live, proposed } = await blockedProposal();
  const records = await R.aggregate([
    rec({ user: 'carol@example.com', dept: 'Engineering', location: 'HQ', url: 'blocked.example.com/a', urlcat: 'News', action: 'Allowed', weight: 3 }),
    rec({ user: 'carol@example.com', dept: 'Engineering', location: 'HQ', url: 'blocked.example.com/a', urlcat: 'News', action: 'Allowed', time: '2026-10-31T02:30:00Z' }),
    rec({ user: 'dan@example.com', dept: 'Sales', location: 'Branch-1', url: 'blocked.example.com/b', urlcat: 'News', action: 'Allowed', weight: 2 }),
    rec({ user: 'erin@example.com', dept: 'Sales', location: 'Branch-1', url: 'blocked.example.com/c', urlcat: 'News', action: 'Blocked', ruleType: 'Firewall Filtering', blockedBy: 'FW_Block_Test' }),
    rec({ user: 'alice@example.com', dept: 'Engineering', location: 'HQ', url: 'news.example.com/', urlcat: 'News', action: 'Allowed', weight: 7 }),
  ]);
  const d = R.simulateDiff(records, { data: live }, { data: proposed });
  assert.ok(d.ok); assert.strictEqual(d.tz, 'America/New_York');
  const nb = d.newlyBlocked;
  assert.strictEqual(nb.transactions, 6); assert.strictEqual(nb.distinctUsers, 2);
  assert.deepStrictEqual(nb.topHosts, [{ key: 'blocked.example.com', weight: 6 }]);
  assert.deepStrictEqual(nb.departments, [{ key: 'Engineering', weight: 4 }, { key: 'Sales', weight: 2 }]);
  assert.deepStrictEqual(nb.trend, [{ day: '2026-10-30', weight: 6 }]); // 02:30Z Oct 31 is still Oct 30 Eastern
  assert.deepStrictEqual(nb.rules, [{ key: 'Replay-Block', weight: 6 }]);
  assert.strictEqual(nb.confidence.high, 6);
  assert.strictEqual(d.alreadyBlocked.transactions, 1);
  assert.strictEqual(d.alreadyBlocked.rows[0].alreadyBlockedBy, 'FW_Block_Test');
  assert.strictEqual(d.alreadyBlocked.rows[0].blockedByEngine, 'Firewall Filtering');
  assert.strictEqual(d.newlyAllowed.transactions, 0);
  assert.strictEqual(d.totals.transactions, 14); assert.strictEqual(d.totals.changedTransactions, 7);
});

test('simulateDiff: removing a block shows newly allowed records', async () => {
  const { live, proposed } = await blockedProposal();
  const records = [rec({ user: 'carol@example.com', url: 'blocked.example.com/a', urlcat: 'News', action: 'Blocked', ruleType: 'URL Filtering', blockedBy: 'Replay-Block', weight: 4 })];
  const d = R.simulateDiff(records, proposed, live);
  assert.strictEqual(d.newlyAllowed.transactions, 4);
  assert.strictEqual(d.newlyAllowed.rows[0].current, 'BLOCK'); assert.strictEqual(d.newlyAllowed.rows[0].proposed, 'ALLOW');
  assert.strictEqual(d.newlyBlocked.transactions, 0);
});

test('simulateDiff: confidence drops when a relevant rule depends on group membership or time windows', async () => {
  const { live, proposed } = await blockedProposal();
  // Demo rule "Block Social for Guests" (group-scoped) sits ahead of the new block for social-category traffic.
  const social = [rec({ user: 'carol@example.com', url: 'blocked.example.com/s', urlcat: 'Social Networking', action: 'Allowed' })];
  let d = R.simulateDiff(social, live, proposed);
  assert.strictEqual(d.newlyBlocked.confidence.low, 1);
  assert.ok(d.newlyBlocked.rows[0].confidence.reasons.includes('group membership'));
  // Directory groups supplied -> no longer a guess.
  d = R.simulateDiff(social, live, proposed, { groupsByUser: { 'carol@example.com': ['Engineering'] } });
  assert.strictEqual(d.newlyBlocked.confidence.high, 1);
  // Category rules out the group-scoped rule -> high.
  d = R.simulateDiff([rec({ user: 'carol@example.com', url: 'blocked.example.com/n', urlcat: 'News', action: 'Allowed' })], live, proposed);
  assert.strictEqual(d.newlyBlocked.confidence.high, 1);
  // Time window on the deciding rule.
  const timed = JSON.parse(JSON.stringify(proposed));
  const rule = timed.urlFilteringRules.find((r) => r.name === 'Replay-Block');
  for (const r of timed.urlFilteringRules) r.order += 1;
  timed.urlFilteringRules.push(Object.assign({}, rule, { id: 999, name: 'Allow-After-Hours', action: 'ALLOW', order: 1, timeWindows: [{ id: 1, name: 'Evenings' }] }));
  const deny = timed;
  const res = R.simulateDiff([rec({ user: 'carol@example.com', url: 'blocked.example.com/n', urlcat: 'News', action: 'Allowed' })], live, deny);
  const rows = res.newlyBlocked.rows;
  assert.strictEqual(rows.length, 1); assert.strictEqual(rows[0].confidence.level, 'low');
  assert.ok(rows[0].confidence.reasons.includes('time window'));
});

test('simulateDiff validates inputs and caches identical evaluations', async () => {
  const { live, proposed } = await blockedProposal();
  assert.throws(() => R.simulateDiff([], live), /snapshots/);
  assert.throws(() => R.simulateDiff([], live, proposed, { tz: 'Nope/Zone' }), /time zone/);
  const rows = Array.from({ length: 50 }, () => rec({ user: 'carol@example.com', url: 'blocked.example.com/a', urlcat: 'News', action: 'Allowed' }));
  const d = R.simulateDiff(rows, live, proposed);
  assert.strictEqual(d.totals.uniqueEvaluations, 1); assert.strictEqual(d.newlyBlocked.transactions, 50);
});
