'use strict';
// PAC file runtime and analyzer.
//
// PAC files are code from outside this app (a tenant's forwarding profile, a PAC URL, a pasted file), so they run in a
// locked-down vm context: a null-prototype global, every helper defined *inside* the context (no host function or
// object is reachable, so `x.constructor.constructor('return process')` finds nothing), no code generation from strings,
// microtasks drained inside the timeout, and the result converted to a string inside the timeout too.
// DNS answers are passed in as data. A run reports which names it needed; callers resolve them and run again.
const vm = require('vm');

const RUNTIME = String.raw`
'use strict';
var __trace = [], __need = [], __dns = {}, __myIp = '10.0.0.10', __now = 0, __limit = 400;
function __line() {
  var s = new Error().stack || '', m = s.match(/pac\.js:(\d+):(\d+)/);
  return m ? +m[1] : null;
}
function __t(fn, args, res) { if (__trace.length < __limit) __trace.push({ fn: fn, args: args, result: res, line: __line() }); return res; }
function __isIp(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(h)); }
function __lookup(h) {
  if (h == null || h === '') return null;
  h = String(h).toLowerCase();
  if (__isIp(h)) return h;
  if (Object.prototype.hasOwnProperty.call(__dns, h)) return __dns[h];
  if (__need.indexOf(h) < 0) __need.push(h);
  return null;
}
function __ip2n(ip) { var p = String(ip).split('.'); if (p.length !== 4) return null; var n = 0; for (var i = 0; i < 4; i++) { var x = +p[i]; if (!(x >= 0 && x <= 255) || p[i] === '') return null; n = n * 256 + x; } return n; }
function __glob(g) { return new RegExp('^' + String(g).replace(/[.+^$(){}|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i'); }
function isPlainHostName(h) { return __t('isPlainHostName', [h], String(h).indexOf('.') < 0); }
function dnsDomainIs(h, d) { h = String(h).toLowerCase(); d = String(d).toLowerCase(); return __t('dnsDomainIs', [h, d], h.length >= d.length && h.substring(h.length - d.length) === d); }
function localHostOrDomainIs(h, hd) { h = String(h).toLowerCase(); hd = String(hd).toLowerCase(); return __t('localHostOrDomainIs', [h, hd], h === hd || (h.indexOf('.') < 0 && hd.indexOf(h + '.') === 0)); }
function isResolvable(h) { return __t('isResolvable', [h], __lookup(h) != null); }
function isResolvableEx(h) { return __t('isResolvableEx', [h], __lookup(h) != null); }
function dnsResolve(h) { return __t('dnsResolve', [h], __lookup(h)); }
function dnsResolveEx(h) { var r = __lookup(h); return __t('dnsResolveEx', [h], r || ''); }
function myIpAddress() { return __t('myIpAddress', [], __myIp); }
function myIpAddressEx() { return __t('myIpAddressEx', [], __myIp); }
function dnsDomainLevels(h) { return __t('dnsDomainLevels', [h], String(h).split('.').length - 1); }
function convert_addr(ip) { return __ip2n(ip) | 0; }
function shExpMatch(s, g) { return __t('shExpMatch', [s, g], __glob(g).test(String(s))); }
function isInNet(h, pat, mask) {
  var ip = __isIp(h) ? h : __lookup(h), a = __ip2n(ip), p = __ip2n(pat), m = __ip2n(mask);
  var r = a != null && p != null && m != null && ((a & m) >>> 0) === ((p & m) >>> 0);
  return __t('isInNet', [h, pat, mask], r);
}
function isInNetEx(h, prefix) {
  var ip = __isIp(h) ? h : __lookup(h), parts = String(prefix).split('/'), a = __ip2n(ip), p = __ip2n(parts[0]), bits = +parts[1];
  var r = false;
  if (a != null && p != null && bits >= 0 && bits <= 32) { var m = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0; r = ((a & m) >>> 0) === ((p & m) >>> 0); }
  return __t('isInNetEx', [h, prefix], r);
}
function sortIpAddressList(l) { return l; }
function getClientVersion() { return '1.0'; }
var __DAYS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'], __MON = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
function __d(args) { var a = Array.prototype.slice.call(args), gmt = a[a.length - 1] === 'GMT'; if (gmt) a.pop(); var d = new Date(__now); return { a: a, gmt: gmt, d: d }; }
function weekdayRange() {
  var x = __d(arguments), day = x.gmt ? x.d.getUTCDay() : x.d.getDay(), w1 = __DAYS.indexOf(x.a[0]), w2 = x.a.length > 1 ? __DAYS.indexOf(x.a[1]) : w1;
  var r = w1 >= 0 && w2 >= 0 && (w1 <= w2 ? day >= w1 && day <= w2 : day >= w1 || day <= w2);
  return __t('weekdayRange', Array.prototype.slice.call(arguments), r);
}
function timeRange() {
  var x = __d(arguments), h = x.gmt ? x.d.getUTCHours() : x.d.getHours(), mi = x.gmt ? x.d.getUTCMinutes() : x.d.getMinutes(), s = x.gmt ? x.d.getUTCSeconds() : x.d.getSeconds(), a = x.a.map(Number), r;
  var now = h * 3600 + mi * 60 + s, lo, hi;
  if (a.length === 1) { lo = a[0] * 3600; hi = lo + 3599; } else if (a.length === 2) { lo = a[0] * 3600; hi = a[1] * 3600 + 3599; if (a[0] === a[1]) hi = lo + 3599; } else if (a.length === 4) { lo = a[0] * 3600 + a[1] * 60; hi = a[2] * 3600 + a[3] * 60 + 59; } else { lo = a[0] * 3600 + a[1] * 60 + a[2]; hi = a[3] * 3600 + a[4] * 60 + a[5]; }
  r = lo <= hi ? now >= lo && now <= hi : now >= lo || now <= hi;
  return __t('timeRange', Array.prototype.slice.call(arguments), r);
}
function dateRange() {
  var x = __d(arguments), d = x.d, a = x.a, day = x.gmt ? d.getUTCDate() : d.getDate(), mon = x.gmt ? d.getUTCMonth() : d.getMonth(), yr = x.gmt ? d.getUTCFullYear() : d.getFullYear();
  function val(v) { var m = __MON.indexOf(String(v)); if (m >= 0) return { m: m }; v = +v; return v > 31 ? { y: v } : { d: v }; }
  var p = a.map(val), r;
  function key(o, ref) { return (o.y != null ? o.y : ref.y) * 10000 + (o.m != null ? o.m : ref.m) * 100 + (o.d != null ? o.d : ref.d); }
  var cur = { y: yr, m: mon, d: day };
  if (p.length === 1) { var o = p[0]; r = (o.y == null || o.y === yr) && (o.m == null || o.m === mon) && (o.d == null || o.d === day); }
  else { var half = p.length / 2, s = {}, e = {}; for (var i = 0; i < half; i++) { Object.assign(s, p[i]); Object.assign(e, p[half + i]); }
    var ks = key(s, { y: s.y != null ? s.y : yr, m: s.m != null ? s.m : 0, d: s.d != null ? s.d : 1 }), ke = key(e, { y: e.y != null ? e.y : yr, m: e.m != null ? e.m : 11, d: e.d != null ? e.d : 31 });
    var kc = key(cur, cur); r = ks <= ke ? kc >= ks && kc <= ke : kc >= ks || kc <= ke; }
  return __t('dateRange', Array.prototype.slice.call(arguments), r);
}
function alert() {}
function __ret(line, v) { __trace.push({ fn: 'return', args: [], result: v, line: line }); return v; }
`;

// Insert __ret(LINE, …) around every `return <expr>` so we know which line decided. Strings, comments, template literals
// and regex literals are skipped. If anything looks unusual the caller falls back to the original source.
function instrument(src) {
  let out = '', i = 0, line = 1, prevSig = '';
  const n = src.length;
  const isId = (c) => /[A-Za-z0-9_$]/.test(c);
  const regexOk = () => !prevSig || /[(,=:[!&|?{};+\-*%<>~^]$/.test(prevSig) || /\b(return|typeof|case|in|of|delete|void|throw|new)$/.test(prevSig);
  function skipString(q) { let s = src[i++]; while (i < n) { const c = src[i++]; s += c; if (c === '\\') { s += src[i++] || ''; continue; } if (c === '\n') line++; if (c === q) break; } return s; }
  function skipRegex() { let s = src[i++], cls = false; while (i < n) { const c = src[i++]; s += c; if (c === '\\') { s += src[i++] || ''; continue; } if (c === '[') cls = true; else if (c === ']') cls = false; else if (c === '/' && !cls) break; else if (c === '\n') throw new Error('regex'); } while (i < n && /[a-z]/i.test(src[i])) s += src[i++]; return s; }
  while (i < n) {
    const c = src[i];
    if (c === '\n') { line++; out += c; i++; continue; }
    if (c === '/' && src[i + 1] === '/') { const e = src.indexOf('\n', i); const end = e < 0 ? n : e; out += src.slice(i, end); i = end; continue; }
    if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; const chunk = src.slice(i, end); line += (chunk.match(/\n/g) || []).length; out += chunk; i = end; continue; }
    if (c === '"' || c === "'" || c === '`') { out += skipString(c); prevSig = c; continue; }
    if (c === '/' && regexOk()) { out += skipRegex(); prevSig = '/re/'; continue; }
    if (isId(c)) {
      let j = i; while (j < n && isId(src[j])) j++;
      const word = src.slice(i, j);
      const dotBefore = /\.\s*$/.test(out);
      if (word === 'return' && !dotBefore) {
        // the returned expression runs to ; or } (at depth 0) or a line end that can't continue the expression
        let k = j, depth = 0, exprStart = j, l2 = line;
        while (k < n && /[ \t]/.test(src[k])) k++;
        if (src[k] === ';' || src[k] === '}' || src[k] === '\n' || src[k] === '\r' || k >= n) { out += word; i = j; prevSig = word; continue; }
        let p = k, expr = '';
        while (p < n) {
          const ch = src[p];
          if (ch === '"' || ch === "'" || ch === '`') { const save = i; i = p; const s = skipString(ch); expr += s; p = i; i = save; continue; }
          if (ch === '/' && src[p + 1] === '/') break;
          if (ch === '(' || ch === '[' || ch === '{') depth++;
          else if (ch === ')' || ch === ']' || ch === '}') { if (depth === 0) break; depth--; }
          else if (ch === ';' && depth === 0) break;
          else if (ch === '\n' && depth === 0) {
            const before = expr.trimEnd().slice(-1), after = src.slice(p + 1).trimStart()[0];
            if (!/[+\-*/%&|?:,=<>!.]/.test(before) && !/[+\-*/%&|?:,.<>=]/.test(after || '')) break;
          }
          if (ch === '\n') l2++;
          expr += ch; p++;
        }
        if (!expr.trim()) { out += word; i = j; prevSig = word; continue; }
        out += `return __ret(${line}, (${expr.replace(/\s+$/, '')}))` + expr.match(/\s*$/)[0];
        line = l2; i = p; prevSig = ')'; void exprStart;
        continue;
      }
      out += word; i = j; prevSig = word; continue;
    }
    out += c; i++;
    if (!/\s/.test(c)) prevSig = c;
  }
  return out;
}

const scriptCache = new Map(); // source -> { script, instrumented }
function compile(src) {
  let e = scriptCache.get(src);
  if (e) return e;
  let script = null, instrumented = false, syntaxError = null;
  try {
    script = new vm.Script(instrument(src), { filename: 'pac.js' });
    instrumented = true;
  } catch {
    try { script = new vm.Script(src, { filename: 'pac.js' }); } catch (err) { syntaxError = syntaxInfo(err, src); }
  }
  const runtime = new vm.Script(RUNTIME, { filename: 'pac-runtime.js' });
  e = { script, runtime, instrumented, syntaxError };
  if (scriptCache.size > 20) scriptCache.delete(scriptCache.keys().next().value);
  scriptCache.set(src, e);
  return e;
}
function syntaxInfo(err, src) {
  const m = String(err.stack || '').match(/pac\.js:(\d+)/);
  const line = m ? +m[1] : null;
  return { message: err.message, line, code: line ? src.split('\n')[line - 1] : null };
}

// One evaluation inside a fresh locked-down context. dns: { name: ip | null } (names missing from it are reported
// in `needs`). This runs in the PAC worker thread (see below); `microtasks` is only for the in-process fallback.
function runLocal(src, url, host, opts, microtasks) {
  const dns = opts.dns || {}, myIp = opts.myIp || '10.0.0.10', now = opts.now || Date.now(), timeout = opts.timeout || 1000;
  const c = compile(src);
  if (c.syntaxError) return { error: `Syntax error: ${c.syntaxError.message}${c.syntaxError.line ? ` (line ${c.syntaxError.line})` : ''}`, syntaxError: c.syntaxError, trace: [], needs: [] };
  const ctx = vm.createContext(Object.create(null), Object.assign({ codeGeneration: { strings: false, wasm: false } }, microtasks ? { microtaskMode: 'afterEvaluate' } : {}));
  c.runtime.runInContext(ctx, { timeout });
  // Inputs go in as JSON text, parsed inside the context, so the PAC never touches an object from this realm.
  vm.runInContext(`__dns = JSON.parse(${JSON.stringify(JSON.stringify(lower(dns)))}); __myIp = ${JSON.stringify(String(myIp))}; __now = ${Number(now) || 0};`, ctx, { timeout });
  try {
    c.script.runInContext(ctx, { timeout });
    const out = vm.runInContext(`(function () {
      if (typeof FindProxyForURL !== 'function') return JSON.stringify({ error: 'The file has no FindProxyForURL(url, host) function' });
      var r = FindProxyForURL(${JSON.stringify(url)}, ${JSON.stringify(host)});
      return JSON.stringify({ result: r == null ? null : String(r), trace: __trace, needs: __need });
    })()`, ctx, { timeout });
    return JSON.parse(out);
  } catch (err) {
    const msg = err && err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT' ? `The PAC file ran longer than ${timeout} ms (endless loop?)` : String((err && err.message) || err);
    let trace = [], needs = [];
    try { const t = JSON.parse(vm.runInContext('JSON.stringify({ trace: __trace, needs: __need })', ctx, { timeout: 100 })); trace = t.trace; needs = t.needs; } catch {}
    const lm = String((err && err.stack) || '').match(/pac\.js:(\d+)/);
    return { error: msg, errorLine: lm ? +lm[1] : null, trace, needs };
  }
}
function lower(o) { return Object.fromEntries(Object.entries(o || {}).map(([k, v]) => [String(k).toLowerCase(), v == null ? null : String(v)])); }

// ---- PAC worker thread ----
// Evaluations run in a worker thread so a PAC that never finishes (including async code queued with promises, which a
// vm timeout can't stop) is cut off by terminating the worker; the app itself never hangs. Calls stay synchronous for
// the simulator: post the request, block on Atomics.wait, read the answer with receiveMessageOnPort.
// The worker's code is built from the functions above (no file to load, so it also works in the packaged app).
const { Worker, MessageChannel, receiveMessageOnPort } = require('worker_threads');
function workerMain() {
  const { workerData } = require('worker_threads');
  const { port, sab } = workerData;
  const flag = new Int32Array(sab);
  port.on('message', (req) => {
    let res;
    try { res = runLocal(req.src, req.url, req.host, req.opts, false); } catch (err) { res = { error: String(err && err.message || err), trace: [], needs: [] }; }
    port.postMessage(res);
    Atomics.store(flag, 0, 1); Atomics.notify(flag, 0);
    setImmediate(() => { Atomics.store(flag, 0, 2); Atomics.notify(flag, 0); }); // the event loop is free again (no runaway async code)
  });
}
const WORKER_CODE = [`'use strict'; const vm = require('vm'); const RUNTIME = ${JSON.stringify(RUNTIME)}; const scriptCache = new Map();`,
  instrument, compile, syntaxInfo, runLocal, lower, workerMain, 'workerMain();'].map(String).join('\n');
let W = null, workerBroken = false;
function startWorker() {
  const sab = new SharedArrayBuffer(4), flag = new Int32Array(sab), { port1, port2 } = new MessageChannel();
  const w = new Worker(WORKER_CODE, { eval: true, workerData: { port: port2, sab }, transferList: [port2], resourceLimits: { maxOldGenerationSizeMb: 256 }, stdout: true, stderr: true });
  w.unref(); w.on('error', () => {}); port1.unref && port1.unref();
  return { w, port: port1, flag, fresh: true };
}
function stopWorker() { if (W) { W.w.terminate().catch(() => {}); W.port.close(); W = null; } }
function runOnce(src, url, host, opts = {}) {
  const timeout = opts.timeout || 1000;
  const req = { src, url, host, opts: { dns: lower(opts.dns), myIp: opts.myIp, now: opts.now || Date.now(), timeout } };
  if (workerBroken) return runLocal(src, url, host, req.opts, true);
  if (!W) W = startWorker();
  Atomics.store(W.flag, 0, 0);
  W.port.postMessage(req);
  const st = Atomics.wait(W.flag, 0, 0, timeout + (W.fresh ? 10000 : 1000)); // first call includes the worker's start-up
  const msg = receiveMessageOnPort(W.port);
  if (!msg) {
    const fresh = W.fresh; stopWorker();
    if (fresh && st === 'timed-out') { workerBroken = true; return runLocal(src, url, host, req.opts, true); } // couldn't start a worker here
    return { error: `The PAC file ran longer than ${timeout} ms (endless loop?)`, trace: [], needs: [] };
  }
  W.fresh = false;
  // Wait for the worker to go idle; if the PAC left async code running forever, replace the worker.
  if (Atomics.wait(W.flag, 0, 1, timeout) === 'timed-out' && Atomics.load(W.flag, 0) !== 2) {
    stopWorker();
    msg.message.asyncWarning = 'The PAC file started async code that never finished; it was stopped.';
  }
  return msg.message;
}

// Evaluate with DNS answers supplied by a synchronous resolver (called for each name the PAC asks about).
function evaluate(src, url, host, opts = {}) {
  const dns = Object.assign({}, opts.dns);
  let r;
  for (let pass = 0; pass < 4; pass++) {
    r = runOnce(src, url, host, Object.assign({}, opts, { dns }));
    const missing = (r.needs || []).filter((h) => !(h in dns));
    if (!missing.length || !opts.resolve) break;
    for (const h of missing) { const ip = opts.resolve(h); dns[h] = ip == null ? null : String(ip); }
  }
  r.dns = dns;
  return r;
}
// Same, with an async resolver (real DNS): resolves what the PAC asked for, then runs again.
async function evaluateAsync(src, url, host, opts = {}) {
  const dns = Object.assign({}, lower(opts.dns));
  let r;
  for (let pass = 0; pass < 4; pass++) {
    r = runOnce(src, url, host, Object.assign({}, opts, { dns }));
    const missing = (r.needs || []).filter((h) => !(h in dns));
    if (!missing.length || !opts.resolveAsync) break;
    await Promise.all(missing.map(async (h) => { dns[h] = await opts.resolveAsync(h).catch(() => null); }));
  }
  r.dns = dns;
  return r;
}

// "PROXY a:80; PROXY b:80; DIRECT" → [{type, host, port, zscaler, raw}]
const ZS_PROXY = /zscaler|zscloud|zscalerone|zscalertwo|zscalerthree|zscalerbeta|zscalergov|zscalerten|zspreview|\$\{?(GATEWAY|SECONDARY_GATEWAY|COUNTRY_GATEWAY|ZAPP_[A-Z_]+)\}?/i;
function parseResult(result) {
  if (result == null) return [];
  return String(result).split(';').map((s) => s.trim()).filter(Boolean).map((raw) => {
    const m = raw.match(/^(DIRECT|PROXY|HTTPS|HTTP|SOCKS|SOCKS4|SOCKS5)\b\s*(.*)$/i);
    if (!m) return { type: 'INVALID', raw, problem: 'not DIRECT, PROXY, HTTPS or SOCKS' };
    const type = m[1].toUpperCase(), rest = m[2].trim();
    if (type === 'DIRECT') return rest ? { type, raw, problem: 'DIRECT takes no address' } : { type, raw };
    const hm = rest.match(/^(\[[^\]]+\]|[^\s:]+)(?::(\d+|\$\{[A-Z_]+\}))?$/);
    if (!hm) return { type, raw, problem: rest ? 'expected host:port' : 'missing host:port' };
    const local = /^(127\.0\.0\.1|localhost|\[::1\])$/i.test(hm[1]);
    return Object.assign({ type, raw, host: hm[1], port: hm[2] ? (/^\d+$/.test(hm[2]) ? +hm[2] : hm[2]) : null, zscaler: ZS_PROXY.test(hm[1]) || (local && [9000, 9400, 9480, 9443].includes(+hm[2])), local },
      hm[2] ? {} : { problem: 'no port (browsers assume 80 for PROXY, 443 for HTTPS; be explicit)' });
  });
}
function verdict(chain) {
  const first = chain[0];
  if (!first) return { kind: 'NONE', text: 'No result (the function returned nothing)' };
  if (first.type === 'INVALID' || (first.type !== 'DIRECT' && !first.host)) return { kind: 'INVALID', text: `Invalid result "${first.raw}"` };
  if (first.type === 'DIRECT') return { kind: 'DIRECT', text: 'Goes direct (not through Zscaler)' };
  if (first.zscaler) return { kind: 'ZSCALER', text: first.local ? 'Goes to Client Connector\'s local proxy, then Zscaler' : `Goes through Zscaler (${first.host}${first.port ? ':' + first.port : ''})` };
  return { kind: 'OTHER_PROXY', text: `Goes to another proxy (${first.host}${first.port ? ':' + first.port : ''}), not Zscaler` };
}

// Static checks. Returns [{sev, title, detail, line}]
function lint(src) {
  const out = [];
  const add = (sev, title, detail, line) => out.push({ sev, title, detail, line: line || null });
  const lines = String(src).split('\n');
  const code = stripComments(src);
  const c = compile(src);
  if (c.syntaxError) add('high', `Syntax error${c.syntaxError.line ? ` on line ${c.syntaxError.line}` : ''}`, `${c.syntaxError.message}. Browsers and Client Connector ignore a PAC that doesn't parse and fall back to their default (often DIRECT).`, c.syntaxError.line);
  if (!/function\s+FindProxyForURL\s*\(/.test(code) && !/FindProxyForURL\s*=\s*function/.test(code)) add('high', 'No FindProxyForURL function', 'Every PAC file must define FindProxyForURL(url, host).');
  const lineOf = (idx) => code.slice(0, idx).split('\n').length;
  const each = (rx, f) => { let m; rx.lastIndex = 0; while ((m = rx.exec(code))) f(m, lineOf(m.index)); };
  // DNS lookups
  let dnsCalls = 0, firstDns = null;
  each(/\b(dnsResolve|isInNet|isResolvable|dnsResolveEx|isInNetEx)\s*\(\s*host\b/g, (m, l) => { dnsCalls++; if (!firstDns) firstDns = l; });
  if (dnsCalls > 2) add('medium', `${dnsCalls} DNS lookups on the host`, 'isInNet(host, …), dnsResolve(host) and isResolvable(host) each make the browser resolve the name, and a lookup that times out stalls every request. Resolve once into a variable (var ip = dnsResolve(host);), and do it after the hostname checks.', firstDns);
  else if (dnsCalls && firstDns) {
    const firstName = code.search(/\b(shExpMatch|dnsDomainIs|isPlainHostName|localHostOrDomainIs)\s*\(/);
    if (firstName >= 0 && lineOf(firstName) > firstDns) add('low', 'DNS lookup before the hostname checks', 'The file resolves the host before its name-based bypasses, so every request waits on DNS. Move IP checks after the shExpMatch / dnsDomainIs checks.', firstDns);
  }
  // dnsDomainIs without a leading dot matches lookalikes
  each(/\bdnsDomainIs\s*\(\s*host\s*,\s*(["'])([^"']+)\1/g, (m, l) => { if (!m[2].startsWith('.')) add('medium', `dnsDomainIs(host, "${m[2]}") also matches lookalike domains`, `Without a leading dot it matches any name ending in "${m[2]}", e.g. "evil${m[2]}". Use ".${m[2]}" (and host == "${m[2]}" for the bare domain).`, l); });
  // shExpMatch "*.x.com" misses the bare domain
  const pats = []; each(/\bshExpMatch\s*\(\s*(host|url)\s*,\s*(["'])([^"']+)\2/g, (m, l) => pats.push({ on: m[1], p: m[3], l }));
  const hostPats = new Set(pats.filter((x) => x.on === 'host').map((x) => x.p.toLowerCase()));
  const bareHit = (d) => hostPats.has(d) || [...hostPats].some((p) => p === '*' + d || p === '*.' + d.split('.').slice(1).join('.')) || new RegExp(`dnsDomainIs\\s*\\(\\s*host\\s*,\\s*["']\\.?${d.replace(/\./g, '\\.')}["']|host\\s*===?\\s*["']${d.replace(/\./g, '\\.')}["']`).test(code);
  const missBare = pats.filter((x) => x.on === 'host' && /^\*\.[^*?]+$/.test(x.p) && !bareHit(x.p.slice(2).toLowerCase()));
  if (missBare.length) add('low', `${missBare.length} wildcard pattern(s) don't cover the bare domain`, `For example shExpMatch(host, "${missBare[0].p}") matches www.${missBare[0].p.slice(2)} but not ${missBare[0].p.slice(2)} itself. Add "${missBare[0].p.slice(2)}" too, or use "*${missBare[0].p.slice(1)}" (which also matches lookalikes).`, missBare[0].l);
  const urlPath = pats.filter((x) => x.on === 'url' && /^[a-z*]+:\/\/[^/]+\/./i.test(x.p));
  if (urlPath.length) add('medium', 'URL path matching won\'t work for HTTPS', `shExpMatch(url, "${urlPath[0].p}") relies on the path, but browsers pass only https://host/ for HTTPS, so it never matches HTTPS requests.`, urlPath[0].l);
  // isInNet with a mask that doesn't fit the network
  each(/\bisInNet\s*\(\s*[^,]+,\s*["'](\d+\.\d+\.\d+\.\d+)["']\s*,\s*["'](\d+\.\d+\.\d+\.\d+)["']/g, (m, l) => {
    const toN = (s) => s.split('.').reduce((a, x) => a * 256 + +x, 0); const net = toN(m[1]), mask = toN(m[2]);
    if (((net & mask) >>> 0) !== net) add('low', `isInNet(…, "${m[1]}", "${m[2]}"): network has bits outside the mask`, 'It still works (only masked bits are compared), but it usually means a typo in the network or the mask.', l);
    const bits = mask.toString(2).replace(/0+$/, ''); if (/0/.test(bits)) add('medium', `isInNet mask "${m[2]}" isn't a valid netmask`, 'Netmasks must be contiguous ones followed by zeros (e.g. 255.255.240.0).', l);
  });
  // return values
  const rets = new Map();
  each(/\breturn\s*(["'])([^"']*)\1/g, (m, l) => { if (!rets.has(m[2])) rets.set(m[2], l); });
  for (const [r, l] of rets) {
    const chain = parseResult(r);
    for (const e of chain) if (e.problem) add(e.type === 'INVALID' ? 'high' : 'medium', `Return value "${r}": ${e.problem}`, 'Browsers ignore entries they can\'t parse. Separate entries with ";", e.g. "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT".', l);
    if (/^(proxy|direct)\b/.test(r)) add('low', `Return value "${r}" is lower case`, 'Most clients accept it, but upper case (PROXY / DIRECT) is the standard.', l);
    if (/(PROXY|HTTPS|SOCKS5?)\s+[^\s;]+\s+(PROXY|DIRECT|HTTPS|SOCKS)/i.test(r)) add('high', `Return value "${r}" is missing a ";"`, 'Entries must be separated by semicolons, otherwise the whole string is invalid.', l);
  }
  const proxied = [...rets.keys()].filter((r) => /PROXY|HTTPS/i.test(r) && /\$\{GATEWAY|zscaler/i.test(r));
  if (proxied.length && proxied.every((r) => !/DIRECT\s*$/i.test(r.trim()))) add('info', 'No DIRECT fallback after the Zscaler proxies', `"${proxied[0]}" fails closed: if no Zscaler node answers, browsing stops. That's often intentional (security); add "; DIRECT" only if fail-open is what you want.`, rets.get(proxied[0]));
  if (/\$\{(GATEWAY|SECONDARY_GATEWAY|COUNTRY_GATEWAY|GATEWAY_HOST|SRCIP|ZAPP_[A-Z_]+)\}/.test(code)) add('info', 'Uses Zscaler PAC variables', 'Variables like ${GATEWAY} are filled in by Zscaler only when the PAC is hosted in ZIA (pac.<cloud>/…). Pasted or self-hosted copies return the literal text. The analyzer shows them unresolved.');
  if (/\balert\s*\(/.test(code)) add('low', 'Calls alert()', 'alert() in a PAC does nothing useful in most clients and can slow evaluation.', lineOf(code.search(/\balert\s*\(/)));
  if (/\b(weekdayRange|dateRange|timeRange)\s*\(/.test(code)) add('info', 'Result depends on the date or time', 'weekdayRange / dateRange / timeRange make the answer change through the day. Tests use the current time unless you set one.', lineOf(code.search(/\b(weekdayRange|dateRange|timeRange)\s*\(/)));
  if (src.length > 200 * 1024) add('medium', `Large PAC file (${Math.round(src.length / 1024)} KB)`, 'Browsers download and run the PAC for every request; very large files slow page loads. Consider moving bypass lists into the forwarding profile.');
  if (/\b(for|while)\s*\(/.test(code)) add('low', 'Contains loops', 'Loops run on every request; keep them short.', lineOf(code.search(/\b(for|while)\s*\(/)));
  void lines;
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  return out.sort((a, b) => order[a.sev] - order[b.sev] || (a.line || 0) - (b.line || 0));
}
function stripComments(src) {
  // keeps line numbers (comments become spaces), leaves strings alone
  let out = '', i = 0; const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '"' || c === "'") { const q = c; out += c; i++; while (i < n && src[i] !== q && src[i] !== '\n') { if (src[i] === '\\') { out += src[i++]; } out += src[i++] || ''; } if (i < n) out += src[i++]; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') { out += ' '; i++; } continue; }
    if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; out += src.slice(i, end).replace(/[^\n]/g, ' '); i = end; continue; }
    out += c; i++;
  }
  return out;
}

// What the file refers to: host patterns, networks, proxies (for the overview).
function inventory(src) {
  const code = stripComments(src);
  const lineOf = (idx) => code.slice(0, idx).split('\n').length;
  const items = []; let m;
  const rx = /\b(shExpMatch|dnsDomainIs|localHostOrDomainIs|isInNet|isInNetEx)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*(["'])([^"']+)\3(?:\s*,\s*(["'])([^"']+)\5)?/g;
  while ((m = rx.exec(code))) items.push({ fn: m[1], on: m[2], value: m[4] + (m[6] ? ' / ' + m[6] : ''), line: lineOf(m.index) });
  const returns = []; const rr = /\breturn\s*(["'])([^"']*)\1/g;
  while ((m = rr.exec(code))) returns.push({ value: m[2], line: lineOf(m.index) });
  const vars = [...new Set((code.match(/\$\{[A-Z_]+\}/g) || []))];
  return { items, returns, variables: vars, lines: src.split('\n').length, bytes: Buffer.byteLength(src) };
}

// Behaviour checks: run the PAC for destinations every PAC should handle on purpose.
const PROBES = [
  { id: 'plain', host: 'intranet', ip: '10.10.10.10', label: 'Plain hostname (intranet)' },
  { id: 'rfc1918a', host: '10.1.2.3', label: 'Private IP 10.1.2.3' },
  { id: 'rfc1918b', host: '192.168.1.10', label: 'Private IP 192.168.1.10' },
  { id: 'rfc1918c', host: '172.16.5.5', label: 'Private IP 172.16.5.5' },
  { id: 'loopback', host: '127.0.0.1', label: 'Loopback 127.0.0.1' },
  { id: 'public', host: 'www.example.com', ip: '93.184.215.14', label: 'Public website (www.example.com)' },
];
function behaviour(src, opts = {}) {
  const rows = PROBES.map((p) => {
    const r = evaluate(src, `https://${p.host}/`, p.host, Object.assign({}, opts, { resolve: (h) => (h === p.host ? p.ip || null : null) }));
    const chain = parseResult(r.result), v = verdict(chain);
    const ret = (r.trace || []).filter((t) => t.fn === 'return').pop();
    return { id: p.id, label: p.label, host: p.host, result: r.result, verdict: v.kind, text: v.text, line: ret ? ret.line : null, error: r.error || null };
  });
  const findings = [];
  const by = (id) => rows.find((x) => x.id === id);
  const priv = rows.filter((x) => /^rfc1918/.test(x.id) && x.verdict === 'ZSCALER');
  if (priv.length) findings.push({ sev: 'medium', title: `Private addresses are sent to Zscaler (${priv.map((x) => x.host).join(', ')})`, detail: 'ZIA can\'t reach internal networks, so these requests fail. Return DIRECT for RFC 1918 ranges (or leave them to ZPA).', line: priv[0].line });
  if (by('plain').verdict === 'ZSCALER') findings.push({ sev: 'medium', title: 'Plain hostnames (no dots) are sent to Zscaler', detail: 'Names like "intranet" are internal. Add if (isPlainHostName(host)) return "DIRECT"; near the top.', line: by('plain').line });
  if (by('loopback').verdict !== 'DIRECT' && by('loopback').verdict !== 'NONE' && !by('loopback').error) findings.push({ sev: 'low', title: 'Loopback (127.0.0.1) isn\'t returned DIRECT', detail: 'Local services on this computer should never be proxied.', line: by('loopback').line });
  if (by('public').verdict === 'DIRECT') findings.push({ sev: 'high', title: 'Ordinary websites go DIRECT', detail: 'www.example.com isn\'t sent to Zscaler, so internet traffic that reaches this point isn\'t inspected. Check the final return of FindProxyForURL.', line: by('public').line });
  if (by('public').verdict === 'OTHER_PROXY') findings.push({ sev: 'info', title: 'Ordinary websites go to a non-Zscaler proxy', detail: by('public').text, line: by('public').line });
  return { rows, findings };
}

module.exports = { stopWorker, runLocal, behaviour, PROBES, evaluate, evaluateAsync, runOnce, parseResult, verdict, lint, inventory, instrument, ZS_PROXY };
