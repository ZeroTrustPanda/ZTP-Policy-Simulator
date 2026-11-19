'use strict';
// Decision path flowchart: built from the simulate result only (no recomputation), valid standalone SVG.
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const { simulate } = require('../src/engine');
const DP = require('../public/decision-path.js');
const data = require('../src/demo-snapshot.json');
const run = (target, o = {}) => simulate({ data }, Object.assign({ target: M.parseTarget(target), port: null, protocol: 'tcp', groups: [], categories: [], categorySource: 'entered', resolvedIps: [], notes: [], useZpa: true }, o), {});

test('steps follow evaluation order: forwarding first, decider marked, later steps "not reached" after a block', () => {
  const r = run('https://casino.example', { categories: ['GAMBLING'] });
  const st = DP.steps(r);
  assert.match(st[0].name, /^Forwarding/);
  const dec = st.filter((s) => s.isDec);
  assert.equal(dec.length, 1); assert.equal(dec[0].module, r.summary.primary.module);
  const i = st.indexOf(dec[0]);
  assert.ok(st.slice(i + 1).filter((s) => s.kind === 'module').every((s) => s.notReached));
  assert.ok(st.slice(0, i).every((s) => !s.notReached));
});

test('modules that do not apply are collapsed into one "skipped" step', () => {
  const r = run('8.8.8.8', { port: 3389 });
  const sk = DP.steps(r).filter((s) => s.kind === 'skipped');
  assert.ok(sk.length >= 1);
  assert.ok(sk.flatMap((s) => s.names.map((n) => n.name)).includes('URL Filtering'));
});

test('SVG is well-formed, escapes text, and shows the result and condition branches', () => {
  const r = run('https://casino.example/<script>&x', { categories: ['GAMBLING'] });
  const svg = DP.svg(r);
  assert.ok(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"'));
  assert.ok(!/<script/.test(svg), 'user text is escaped');
  assert.ok(!/&(?!amp;|lt;|gt;|quot;|#)/.test(svg), 'no bare ampersands');
  assert.match(svg, /BLOCKED/);
  if ((r.summary.alsoBasedOn || []).length) assert.match(svg, /stroke-dasharray="5 4"/);
  assert.match(DP.card(r), /data-dp-export="png"/);
});

test('an allowed result has no "not reached" steps', () => {
  const r = run('https://news.example', { categories: ['NEWS_AND_MEDIA'] });
  assert.equal(r.summary.overall, 'ALLOWED');
  assert.ok(DP.steps(r).every((s) => !s.notReached));
});

test('every condition is drawn on some step (none silently dropped)', () => {
  for (const [t, o] of [['https://casino.example', { categories: ['GAMBLING'] }], ['8.8.8.8', { port: 3389 }], ['pacs.hospital.example', { port: 104 }]]) {
    const r = run(t, o);
    const n = (r.summary.alsoBasedOn || []).filter((k) => !(k.kind === 'zpa' && /check fails/.test(k.condition))).length;
    const drawn = (DP.svg(r).match(/stroke-dasharray="5 4" opacity/g) || []).length;
    const more = (DP.svg(r).match(/\+(\d+) more condition/) || [0, 0])[1];
    assert.equal(drawn + Number(more), n, t);
  }
});
