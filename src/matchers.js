'use strict';
// Matching primitives: wildcard domains, IPs/CIDRs/ranges, ports, URLs, PAC evaluation.
const vm = require('vm');

// ---------- IPv4 helpers ----------
function ipToInt(ip) {
  const p = String(ip).trim().split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x) || +x > 255) return null;
    n = n * 256 + +x;
  }
  return n;
}
const isIPv4 = (s) => ipToInt(s) !== null;

// Parse "1.2.3.4", "1.2.3.0/24", "1.2.3.1-1.2.3.9" -> [lo, hi] or null
function parseIpRange(s) {
  s = String(s).trim();
  if (!s) return null;
  if (s.includes('/')) {
    const [ip, bits] = s.split('/');
    const base = ipToInt(ip);
    const b = parseInt(bits, 10);
    if (base === null || isNaN(b) || b < 0 || b > 32) return null;
    const size = Math.pow(2, 32 - b);
    const lo = Math.floor(base / size) * size;
    return [lo, lo + size - 1];
  }
  if (s.includes('-')) {
    const [a, b] = s.split('-');
    const lo = ipToInt(a), hi = ipToInt(b);
    if (lo === null || hi === null) return null;
    return [Math.min(lo, hi), Math.max(lo, hi)];
  }
  const n = ipToInt(s);
  return n === null ? null : [n, n];
}

// relation of query range q to rule range r: 'match' (q inside r), 'partial' (overlap), 'none'
function rangeRelation(q, r) {
  if (!q || !r) return 'none';
  if (q[0] >= r[0] && q[1] <= r[1]) return 'match';
  if (q[0] <= r[1] && r[0] <= q[1]) return 'partial';
  return 'none';
}

// Does query (ip/cidr) fall in any entry of list (strings)? returns {rel, entry}
function ipInList(query, list) {
  const q = parseIpRange(query);
  if (!q) return { rel: 'none' };
  let best = { rel: 'none' };
  for (const e of list || []) {
    const r = parseIpRange(e);
    const rel = rangeRelation(q, r);
    if (rel === 'match') return { rel, entry: e };
    if (rel === 'partial' && best.rel === 'none') best = { rel, entry: e };
  }
  return best;
}

// ---------- Domain / URL helpers ----------
function parseTarget(input) {
  // Accepts url, host, host:port, wildcard host, ip. Returns {raw, host, path, port, scheme, isWildcard, isIp}
  let raw = String(input || '').trim();
  if (!raw) return null;
  // Bare IP, CIDR or range (10.0.2.0/24, 10.0.0.1-10.0.0.9), optionally with :port — not a URL path.
  const ipm = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2}|-\d{1,3}(?:\.\d{1,3}){3})?)(?::(\d+))?$/);
  if (ipm && parseIpRange(ipm[1])) return { raw: input, scheme: null, host: ipm[1], path: '', port: ipm[2] ? +ipm[2] : null, isWildcard: false, isIp: true };
  let scheme = null;
  const m = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (m) { scheme = m[1].toLowerCase(); raw = raw.slice(m[0].length); }
  let hostport = raw, path = '';
  const slash = raw.indexOf('/');
  if (slash >= 0) { hostport = raw.slice(0, slash); path = raw.slice(slash); }
  let host = hostport, port = null;
  const pm = hostport.match(/^(.*):(\d+)$/);
  if (pm) { host = pm[1]; port = +pm[2]; }
  host = host.toLowerCase();
  const isIp = isIPv4(host) || /\//.test(host);
  return { raw: input, scheme, host, path, port, isWildcard: host.includes('*'), isIp };
}

function normPattern(p) {
  let s = String(p).trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  const slash = s.indexOf('/');
  const pathPart = slash >= 0 ? s.slice(slash) : '';
  let host = slash >= 0 ? s.slice(0, slash) : s;
  host = host.replace(/:\d+$/, '');
  return { host, path: pathPart };
}

function globToRegex(g) {
  return new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
}

// Zscaler URL entry semantics: "example.com" and ".example.com" match the domain and all subdomains.
// "*.example.com" accepted too. A pattern with a path only matches when the target path starts with it.
// relation: 'match' | 'partial' (query is a wildcard that overlaps, or rule is narrower than query) | 'none'
function domainRelation(target, pattern) {
  const t = typeof target === 'string' ? parseTarget(target) : target;
  if (!t) return 'none';
  const { host: ph, path: pp } = normPattern(pattern);
  if (!ph) return 'none';
  const base = ph.replace(/^\*\./, '').replace(/^\./, '');
  const hasGlob = base.includes('*');
  const th = t.host;
  const tbase = th.replace(/^\*\./, '');
  let hostRel = 'none';
  if (!t.isWildcard) {
    if (hasGlob) { if (globToRegex(base).test(th) || globToRegex('*.' + base).test(th)) hostRel = 'match'; }
    else if (th === base || th.endsWith('.' + base)) hostRel = 'match';
  } else {
    // Query is a wildcard like *.google.com: rule covers query if query base is within rule base.
    if (!hasGlob && (tbase === base || tbase.endsWith('.' + base))) hostRel = 'match';
    // Rule is narrower (e.g. mail.google.com inside *.google.com) -> partial overlap
    else if (!hasGlob && base.endsWith('.' + tbase)) hostRel = 'partial';
    else if (hasGlob && (globToRegex(base).test(tbase) || globToRegex(tbase.replace(/\*/g, 'x')).test(base))) hostRel = 'partial';
  }
  if (hostRel === 'none') return 'none';
  if (pp && pp !== '/') {
    if (!t.path) return 'partial';
    return t.path.toLowerCase().startsWith(pp) ? hostRel : 'none';
  }
  return hostRel;
}

function domainInList(target, list) {
  let best = { rel: 'none' };
  for (const e of list || []) {
    const rel = domainRelation(target, e);
    if (rel === 'match') return { rel, entry: e };
    if (rel === 'partial' && best.rel === 'none') best = { rel, entry: e };
  }
  return best;
}

// ---------- Ports ----------
function parsePorts(spec) {
  // "80", "80,443", "8000-8100" or array of {start,end}
  const out = [];
  if (Array.isArray(spec)) {
    for (const s of spec) {
      if (s && typeof s === 'object') out.push([s.start, s.end == null ? s.start : s.end]);
      else out.push(...parsePorts(String(s)));
    }
    return out;
  }
  for (const part of String(spec || '').split(/[,\s]+/).filter(Boolean)) {
    const m = part.match(/^(\d+)(?:-(\d+))?$/);
    if (m) out.push([+m[1], +(m[2] || m[1])]);
  }
  return out;
}
function portInRanges(port, ranges) {
  return ranges.some(([a, b]) => port >= a && port <= b);
}

// ---------- PAC evaluation ----------
function evalPac(pacText, url, hostOverride, opts = {}) {
  const t = parseTarget(url);
  const host = hostOverride || (t && t.host);
  const resolve = opts.resolve || (() => (t && t.isIp ? t.host : '0.0.0.0'));
  const myIp = opts.myIp || '10.0.0.10';
  const sandbox = {
    isPlainHostName: (h) => !h.includes('.'),
    dnsDomainIs: (h, d) => h.toLowerCase().endsWith(d.toLowerCase()),
    localHostOrDomainIs: (h, hd) => h === hd || hd.startsWith(h + '.'),
    isResolvable: () => true,
    isInNet: (h, pattern, mask) => {
      const ip = isIPv4(h) ? h : resolve(h);
      const a = ipToInt(ip), p = ipToInt(pattern), m = ipToInt(mask);
      if (a === null || p === null || m === null) return false;
      return ((a & m) >>> 0) === ((p & m) >>> 0);
    },
    dnsResolve: (h) => (isIPv4(h) ? h : resolve(h)),
    myIpAddress: () => myIp,
    dnsDomainLevels: (h) => h.split('.').length - 1,
    shExpMatch: (s, g) => globToRegex2(g).test(s),
    weekdayRange: () => true, dateRange: () => true, timeRange: () => true,
    alert: () => {},
  };
  function globToRegex2(g) {
    return new RegExp('^' + String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
  }
  const ctx = vm.createContext(sandbox);
  vm.runInContext(pacText, ctx, { timeout: 1000 });
  const fullUrl = (t && t.scheme ? t.scheme : 'http') + '://' + host + (t ? t.path : '');
  const result = vm.runInContext(`FindProxyForURL(${JSON.stringify(fullUrl)}, ${JSON.stringify(host)})`, ctx, { timeout: 1000 });
  return String(result);
}

module.exports = {
  ipToInt, isIPv4, parseIpRange, rangeRelation, ipInList,
  parseTarget, domainRelation, domainInList, globToRegex,
  parsePorts, portInRanges, evalPac,
};
