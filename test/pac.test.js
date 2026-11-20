'use strict';
// PAC runtime: correct answers, which line decided, DNS on demand, sandboxing, lint and behaviour checks.
const test = require('node:test');
const assert = require('node:assert');
const P = require('../src/pac');
const M = require('../src/matchers');

const PAC = `function FindProxyForURL(url, host) {
  // internal names
  if (isPlainHostName(host) || dnsDomainIs(host, ".corp.example"))
    return "DIRECT";
  var ip = dnsResolve(host);
  if (isInNet(ip, "10.0.0.0", "255.0.0.0")) return 'DIRECT';
  if (shExpMatch(host, "*.zoom.us")) { return "DIRECT" }
  if (dnsDomainIs(host, "example.org")) return "PROXY proxy.other.net:8080";
  if (url.substring(0, 5) == "http:") return "PROXY \${GATEWAY}:80; PROXY \${SECONDARY_GATEWAY}:80";
  return "PROXY \${GATEWAY}:80; PROXY \${SECONDARY_GATEWAY}:80; DIRECT";
}`;
const run = (h, ip, url) => P.evaluate(PAC, url || `https://${h}/`, h, { resolve: (n) => (n === h ? ip : null) });
const retLine = (r) => r.trace.filter((t) => t.fn === 'return').pop().line;

test('pac: answers, deciding line, trace and verdicts', () => {
  assert.equal(run('intranet').result, 'DIRECT'); assert.equal(retLine(run('intranet')), 4);
  assert.equal(retLine(run('a.corp.example')), 4);
  const z = run('x.zoom.us'); assert.equal(z.result, 'DIRECT'); assert.equal(retLine(z), 7);
  assert.deepEqual(z.trace.filter((t) => t.fn === 'shExpMatch').map((t) => [t.line, t.result]), [[7, true]]);
  const inside = run('app.internal.example', '10.20.30.40'); assert.equal(retLine(inside), 6);
  assert.deepEqual(inside.dns, { 'app.internal.example': '10.20.30.40' }, 'DNS asked for on demand');
  const pub = run('google.com', '142.250.1.1');
  assert.equal(retLine(pub), 10);
  const chain = P.parseResult(pub.result);
  assert.deepEqual(chain.map((c) => c.type), ['PROXY', 'PROXY', 'DIRECT']);
  assert.equal(P.verdict(chain).kind, 'ZSCALER');
  assert.equal(retLine(run('google.com', '142.250.1.1', 'http://google.com/x')), 9);
  assert.equal(P.verdict(P.parseResult(run('www.example.org').result)).kind, 'OTHER_PROXY');
  assert.equal(P.verdict(P.parseResult('PROXY 127.0.0.1:9000')).kind, 'ZSCALER', 'Client Connector local listener');
  assert.equal(P.verdict(P.parseResult('PROXY a b')).kind, 'INVALID');
  // the simulator's PAC step uses the same runtime
  assert.equal(M.evalPac(PAC, 'https://x.zoom.us/', null, {}), 'DIRECT');
  assert.equal(M.evalPac(PAC, 'https://10.1.1.1/', null, {}), 'DIRECT');
});

test('pac: time functions, Microsoft extensions, odd returns', () => {
  const t = `function FindProxyForURL(u, h) {
    if (isInNetEx(h, "192.168.0.0/16")) return "DIRECT";
    if (weekdayRange("MON", "FRI") && timeRange(8, 17)) return "PROXY work.example:8080";
    return "PROXY home.example:8080";
  }`;
  const mon10 = Date.UTC(2026, 10, 16, 10, 0, 0), sat = Date.UTC(2026, 10, 21, 10, 0, 0);
  assert.equal(P.evaluate(t, 'https://a/', 'a', { now: mon10 }).result.startsWith('PROXY'), true);
  const gmt = `function FindProxyForURL(u, h) { return weekdayRange("MON", "FRI", "GMT") ? "PROXY w:1" : "PROXY e:1"; }`;
  assert.equal(P.evaluate(gmt, 'https://a/', 'a', { now: mon10 }).result, 'PROXY w:1');
  assert.equal(P.evaluate(gmt, 'https://a/', 'a', { now: sat }).result, 'PROXY e:1');
  assert.equal(P.evaluate(t, 'https://192.168.4.4/', '192.168.4.4', {}).result, 'DIRECT');
  // return without semicolon, multi-line expression, regex literal, "return" in a string
  const odd = `function FindProxyForURL(u, h) {
    var s = "please return DIRECT";
    if (/^ab+c/.test(h)) return "DIRECT"
    return h.length > 3 ?
      "PROXY long.example:80" :
      "PROXY short.example:80"
  }`;
  const r1 = P.evaluate(odd, 'https://abbc/', 'abbc', {}); assert.equal(r1.result, 'DIRECT'); assert.equal(r1.trace.pop().line, 3);
  const r2 = P.evaluate(odd, 'https://xyzzy/', 'xyzzy', {}); assert.equal(r2.result, 'PROXY long.example:80'); assert.equal(r2.trace.pop().line, 4);
});

test('pac: sandbox — no escape to Node, loops and syntax errors are contained', () => {
  for (const evil of [
    'function FindProxyForURL(u,h){ return isPlainHostName.constructor("return typeof process")(); }',
    'function FindProxyForURL(u,h){ return (function(){return this})().constructor.constructor("return process")().pid; }',
    'function FindProxyForURL(u,h){ return eval("1+1"); }',
    'function FindProxyForURL(u,h){ return typeof require + typeof process + typeof globalThis.process; }',
  ]) {
    const r = P.evaluate(evil, 'http://a/', 'a', {});
    assert.ok(r.error || r.result === 'undefinedundefinedundefined', `escaped: ${JSON.stringify(r)}`);
  }
  assert.match(P.evaluate('function FindProxyForURL(u,h){ while(1){} }', 'http://a/', 'a', {}).error, /longer than/);
  const as = P.evaluate('Promise.resolve().then(function(){ while(1){} }); function FindProxyForURL(u,h){ return "DIRECT" }', 'http://a/', 'a', {});
  assert.equal(as.result, 'DIRECT'); assert.match(as.asyncWarning, /never finished/);
  assert.equal(P.evaluate('function FindProxyForURL(u,h){ return "DIRECT" }', 'http://a/', 'a', {}).result, 'DIRECT', 'a fresh worker takes over');
  assert.match(P.evaluate('function FindProxyForURL(u,h){ return { toString: function(){ while(1){} } } }', 'http://a/', 'a', {}).error, /longer than/);
  const se = P.evaluate('function FindProxyForURL(u,h) {\n  return "DIRECT"\n  if (\n}', 'http://a/', 'a', {});
  assert.match(se.error, /Syntax error/);
  assert.match(P.evaluate('var x = 1;', 'http://a/', 'a', {}).error, /no FindProxyForURL/);
});

test('pac: lint and behaviour checks', () => {
  const titles = P.lint(PAC).map((x) => `${x.sev} ${x.line} ${x.title}`);
  assert.ok(titles.some((t) => /^medium 8 dnsDomainIs\(host, "example.org"\) also matches lookalike/.test(t)), titles.join('\n'));
  assert.ok(titles.some((t) => /^low 7 1 wildcard pattern/.test(t)));
  assert.ok(titles.some((t) => /Zscaler PAC variables/.test(t)));
  assert.ok(!titles.some((t) => /missing a ";"/.test(t)));
  const bad = P.lint('function FindProxyForURL(url, host) {\n if (isInNet(host, "10.0.0.0", "255.0.255.0")) return "DIRECT";\n if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";\n if (isResolvable(host)) return "PROXY a:80 DIRECT";\n if (shExpMatch(url, "https://x.example/login/*")) return "DIRECT";\n return "proxy b";\n}').map((x) => x.title);
  assert.ok(bad.some((t) => /3 DNS lookups/.test(t)), bad.join('\n'));
  assert.ok(bad.some((t) => /isn't a valid netmask/.test(t)));
  assert.ok(bad.some((t) => /missing a ";"/.test(t)));
  assert.ok(bad.some((t) => /won't work for HTTPS/.test(t)));
  assert.ok(bad.some((t) => /lower case/.test(t)));
  assert.match(P.lint('function FindProxyForURL(u,h){ return "DIRECT" ')[0].title, /Syntax error/);
  const b = P.behaviour('function FindProxyForURL(u, h) { if (isPlainHostName(h)) return "DIRECT"; return "PROXY gateway.zscaler.net:80"; }');
  assert.deepEqual(b.rows.map((r) => r.verdict), ['DIRECT', 'ZSCALER', 'ZSCALER', 'ZSCALER', 'ZSCALER', 'ZSCALER']);
  assert.match(b.findings[0].title, /Private addresses are sent to Zscaler/);
  const open = P.behaviour('function FindProxyForURL(u, h) { return "DIRECT"; }');
  assert.ok(open.findings.some((f) => f.sev === 'high' && /Ordinary websites go DIRECT/.test(f.title)));
  const inv = P.inventory(PAC);
  assert.deepEqual(inv.variables, ['${GATEWAY}', '${SECONDARY_GATEWAY}']);
  assert.ok(inv.items.some((i) => i.fn === 'shExpMatch' && i.value === '*.zoom.us' && i.line === 7));
});
