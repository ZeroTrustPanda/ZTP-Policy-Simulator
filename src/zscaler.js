'use strict';
// Zscaler OneAPI client (ZIdentity OAuth2 client-credentials) + policy snapshot loader.
// Reads policy with GET (plus POST /urlLookup, a read). Policy changes (PUT/POST/DELETE) are made only by
// src/changes.js, only when write mode is switched on for the session, and only after the admin confirms a preview.
//
// Auth mirrors the ZTP wizard's working client: POST {vanity}.zslogin.net/oauth2/v1/token with
// grant_type/client_id/client_secret and NO audience parameter. (An audience such as
// https://api.zscaler.com still returns a token, but api.zsapi.net rejects it on every endpoint.)
// Transport uses node's https module, as the wizard does.

const https = require('https');

function rawRequest(method, host, path, payload, headers, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: host, port: 443, path, method, headers: Object.assign({}, headers), rejectUnauthorized: true };
    if (payload) opts.headers['Content-Length'] = Buffer.byteLength(payload);
    const req = https.request(opts, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let body = data;
        try { body = data ? JSON.parse(data) : null; } catch { /* keep string */ }
        resolve({ status: res.statusCode, headers: res.headers, body, text: data });
      });
    });
    req.on('error', (e) => {
      const err = new Error(`${e.code || 'NETWORK'}: ${e.message} (${host})` +
        (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY/.test(e.code || e.message) ? ' — TLS interception? Set NODE_EXTRA_CA_CERTS to the Zscaler root CA' : ''));
      err.code = e.code || 'NETWORK';
      reject(err);
    });
    req.setTimeout(timeoutMs, () => req.destroy(Object.assign(new Error('Request timeout'), { code: 'ETIMEDOUT' })));
    if (payload) req.write(payload);
    req.end();
  });
}

function fetchText(url, redirects = 3) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('http:') ? require('http') : https;
    const req = mod.get(url, { timeout: 15000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) { res.resume(); return resolve(fetchText(new URL(res.headers.location, url).toString(), redirects - 1)); }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let d = ''; res.setEncoding('utf8'); res.on('data', (c) => { d += c; if (d.length > 2e6) req.destroy(); }); res.on('end', () => resolve(d));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
  });
}

function snippet(body) {
  const s = typeof body === 'string' ? body : JSON.stringify(body);
  return (s || '').replace(/\s+/g, ' ').slice(0, 300);
}

// Seconds to wait from a 429: Retry-After / X-RateLimit-Reset headers, or ZIA's body form {"Retry-After": "12 seconds"}.
function retryAfterSeconds(r) {
  const h = r.headers || {};
  let v = h['retry-after'] || h['x-ratelimit-reset'];
  if (!v && r.body && typeof r.body === 'object') v = r.body['Retry-After'] || r.body.retryAfter;
  const n = parseInt(String(v || '').replace(/[^0-9]/g, ''), 10);
  return isNaN(n) ? null : n;
}

class ZClient {
  constructor(cfg) {
    this.cfg = Object.assign({ cloud: 'production' }, cfg);
    const c = (this.cfg.cloud || 'production').trim().toLowerCase();
    const prod = !c || c === 'production';
    const vanity = String(this.cfg.vanityDomain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\.zslogin\.net.*$/, '').replace(/\/.*$/, '');
    this.tokenHost = vanity.includes('.') ? vanity : prod ? `${vanity}.zslogin.net` : `${vanity}.${c}.zslogin.net`;
    this.apiHost = (this.cfg.apiBase || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '') || (prod ? 'api.zsapi.net' : `api.${c}.zsapi.net`);
    this.token = null;
    this.tokenExp = 0;
    this.lastCall = 0;
    this.log = [];
  }

  // Tokens are cached per audience. ZIA/ZCC/ZPA work with a plain client-credentials token (as the wizard
  // uses); Z-Insights is requested with audience https://api.zscaler.com, as the official SDKs do.
  async auth(force = false, audience = null) {
    this.tokens = this.tokens || {};
    const key = audience || '';
    const t = this.tokens[key];
    if (!force && t && Date.now() < t.exp - 60000) return t.token;
    const { clientId, clientSecret } = this.cfg;
    if (!this.cfg.vanityDomain || !clientId || !clientSecret) throw new Error('Vanity domain, client ID and client secret are required');
    const form = { grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret };
    if (audience) form.audience = audience;
    const payload = new URLSearchParams(form).toString();
    const r = await rawRequest('POST', this.tokenHost, '/oauth2/v1/token', payload, { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' });
    this.pushLog('POST', `https://${this.tokenHost}/oauth2/v1/token${audience ? ' (audience ' + audience + ')' : ''}`, r.status, r.status === 200 ? '' : snippet(r.body));
    if (r.status !== 200 || !r.body || !r.body.access_token) {
      let hint = '';
      if (r.body && r.body.error === 'invalid_client') hint = ' — check client ID/secret, vanity domain, that the API client is enabled, and that it has ZIA/ZCC/ZPA scopes in ZIdentity';
      throw Object.assign(new Error(`ZIdentity token request to ${this.tokenHost} failed (${r.status}): ${snippet(r.body)}${hint}`), { status: 401 });
    }
    this.tokens[key] = { token: r.body.access_token, exp: Date.now() + (r.body.expires_in || 3600) * 1000 };
    if (!audience) { this.token = r.body.access_token; this.tokenExp = this.tokens[key].exp; }
    return r.body.access_token;
  }

  pushLog(method, url, status, err) {
    this.log.push({ t: Date.now(), method, url, status, err });
    if (this.log.length > 500) this.log.shift();
  }

  async request(method, path, { query, body, audience, headers: extra, rateRetries = 5 } = {}, attempt = 0) {
    if (audience === undefined && path.startsWith('/zins')) audience = ZINS_AUDIENCE;
    // ZIA OneAPI allows roughly 1-2 req/s per endpoint family; space calls like the wizard does.
    const gap = Date.now() - this.lastCall;
    if (gap < 600) await new Promise((r) => setTimeout(r, 600 - gap));
    this.lastCall = Date.now();
    const token = await this.auth(false, audience || null);
    let p = path;
    if (query) p += (p.includes('?') ? '&' : '?') + new URLSearchParams(query).toString();
    const h = Object.assign({ Authorization: `Bearer ${token}`, Accept: 'application/json', 'Cache-Control': 'no-cache' }, extra || {});
    if (body) h['Content-Type'] = 'application/json';
    const r = await rawRequest(method, this.apiHost, p, body ? JSON.stringify(body) : null, h);
    this.pushLog(method, `https://${this.apiHost}${p}`, r.status, r.status >= 400 ? snippet(r.body) : '');
    if (r.status === 429 && attempt < rateRetries) {
      const ra = retryAfterSeconds(r) || 2;
      await new Promise((res) => setTimeout(res, Math.min(ra, 30) * 1000));
      return this.request(method, path, { query, body, audience, headers: extra, rateRetries }, attempt + 1);
    }
    if (r.status === 401 && attempt === 0) {
      // Z-Insights: if the audience token is rejected, try the plain token before giving up (and vice versa).
      if (path.startsWith('/zins') || path.startsWith('/private')) return this.request(method, path, { query, body, audience: audience ? null : ZINS_AUDIENCE, headers: extra }, 1);
      await this.auth(true, audience || null); return this.request(method, path, { query, body, audience, headers: extra }, 1);
    }
    if (r.status < 200 || r.status >= 300) {
      throw Object.assign(new Error(`HTTP ${r.status} ${method} ${p}: ${snippet(r.body) || '(empty body)'}${hintFor(r.status, path)}`), { status: r.status, retryAfter: r.status === 429 ? retryAfterSeconds(r) : null });
    }
    return r.body;
  }

  get(path, query) { return this.request('GET', path, { query }); }
  post(path, body, query) { return this.request('POST', path, { body, query }); }
  put(path, body, query) { return this.request('PUT', path, { body, query }); }
  del(path, query) { return this.request('DELETE', path, { query }); }
}

function hintFor(status, path) {
  const prod = path.startsWith('/zcc') ? 'Client Connector' : path.startsWith('/zpa') ? 'ZPA' : path.startsWith('/zins') ? 'Z-Insights' : path.startsWith('/private') ? 'ZIA logs' : 'ZIA';
  if (status === 401) return prod === 'Z-Insights' ? ' — rejected with both token types; in ZIdentity give this API client the Z-Insights (Analytics) API resource/role' : ` — token rejected; the API client may lack ${prod} scope in ZIdentity`;
  if (status === 403) return ` — API client lacks permission for this ${prod} resource (ZIdentity role/scope)`;
  if (status === 404) return ' — endpoint not available on this tenant/subscription';
  return '';
}

const ZIA = '/zia/api/v1';
const ZINS_AUDIENCE = 'https://api.zscaler.com';

// Endpoint catalog. group drives the UI checkboxes; required means the module needs it to evaluate.
const CAC_TYPES = ['SOCIAL_NETWORKING', 'STREAMING_MEDIA', 'WEBMAIL', 'INSTANT_MESSAGING', 'BUSINESS_PRODUCTIVITY', 'ENTERPRISE_COLLABORATION', 'SALES_AND_MARKETING',
  'SYSTEM_AND_DEVELOPMENT', 'CONSUMER', 'HOSTING_PROVIDER', 'IT_SERVICES', 'FILE_SHARE', 'DNS_OVER_HTTPS', 'HUMAN_RESOURCES', 'LEGAL', 'HEALTH_CARE', 'FINANCE', 'CUSTOM_CAPP', 'AI_ML'];
const ENDPOINTS = [
  { key: 'urlFilteringRules', group: 'zia', label: 'URL filtering rules', path: `${ZIA}/urlFilteringRules` },
  { key: 'firewallRules', group: 'zia', label: 'Firewall rules', path: `${ZIA}/firewallFilteringRules` },
  { key: 'dnsRules', group: 'zia', label: 'DNS control rules', path: `${ZIA}/firewallDnsRules` },
  { key: 'sslRules', group: 'zia', label: 'SSL inspection rules', path: `${ZIA}/sslInspectionRules` },
  { key: 'cloudAppRules', group: 'zia', label: 'Cloud App Control rules', multi: CAC_TYPES.map((t) => ({ type: t, path: `${ZIA}/webApplicationRules/${t}` })) },
  { key: 'fileTypeRules', group: 'zia', label: 'File type control rules', path: `${ZIA}/fileTypeRules` },
  { key: 'sandboxRules', group: 'zia', label: 'Sandbox rules', path: `${ZIA}/sandboxRules` },
  { key: 'webDlpRules', group: 'zia', label: 'Web DLP rules', path: `${ZIA}/webDlpRules` },
  { key: 'atpSettings', group: 'zia', label: 'ATP settings', path: `${ZIA}/cyberThreatProtection/advancedThreatSettings` },
  { key: 'atpMaliciousUrls', group: 'zia', label: 'ATP denylist (security/advanced)', path: `${ZIA}/security/advanced` },
  { key: 'atpSecurityExceptions', group: 'zia', label: 'ATP allowlist (security)', path: `${ZIA}/security` },
  { key: 'customUrlCategories', group: 'zia', label: 'Custom URL categories', path: `${ZIA}/urlCategories`, query: { customOnly: 'true' } },
  { key: 'networkServices', group: 'zia', label: 'Network services', path: `${ZIA}/networkServices` },
  { key: 'networkServiceGroups', group: 'zia', label: 'Network service groups', path: `${ZIA}/networkServiceGroups` },
  { key: 'networkApplicationGroups', group: 'zia', label: 'Network application groups', path: `${ZIA}/networkApplicationGroups` },
  { key: 'ipDestinationGroups', group: 'zia', label: 'IP destination groups', path: `${ZIA}/ipDestinationGroups` },
  { key: 'ipSourceGroups', group: 'zia', label: 'IP source groups', path: `${ZIA}/ipSourceGroups` },
  { key: 'locations', group: 'zia', label: 'Locations', path: `${ZIA}/locations`, query: { pageSize: '1000' } },
  { key: 'zccPoliciesWin', group: 'zcc', label: 'ZCC app profiles (Windows)', path: '/zcc/papi/public/v1/web/policy/listByCompany', query: { deviceType: '3', pageSize: '500' } },
  { key: 'zccPoliciesMac', group: 'zcc', label: 'ZCC app profiles (macOS)', path: '/zcc/papi/public/v1/web/policy/listByCompany', query: { deviceType: '4', pageSize: '500' } },
  { key: 'zccForwardingProfiles', group: 'zcc', label: 'ZCC forwarding profiles', path: '/zcc/papi/public/v1/webForwardingProfile/listByCompany' },
  { key: 'zccAppServices', group: 'zcc', label: 'ZCC IP-based app bypass definitions', path: '/zcc/papi/public/v1/webAppService/listByCompany' },
];

const zpaBase = (id, v = 1) => `/zpa/mgmtconfig/v${v}/admin/customers/${id}`;
function zpaEndpoints(customerId) {
  const base = zpaBase(customerId), v2 = zpaBase(customerId, 2);
  return [
    { key: 'zpaApps', group: 'zpa', label: 'ZPA application segments', path: `${base}/application`, query: { pagesize: '500' } },
    { key: 'zpaSegmentGroups', group: 'zpa', label: 'ZPA segment groups', path: `${base}/segmentGroup`, query: { pagesize: '500' } },
    { key: 'zpaAccessRules', group: 'zpa', label: 'ZPA access policy', path: `${base}/policySet/rules/policyType/ACCESS_POLICY`, query: { pagesize: '500' } },
    { key: 'zpaForwardingRules', group: 'zpa', label: 'ZPA client forwarding policy', path: `${base}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY`, query: { pagesize: '500' } },
    { key: 'zpaServerGroups', group: 'zpa', label: 'ZPA server groups', path: `${base}/serverGroup`, query: { pagesize: '500' } },
    { key: 'zpaAccessPolicySet', group: 'zpa', label: 'ZPA access policy set', path: `${base}/policySet/policyType/ACCESS_POLICY` },
    { key: 'zpaIdps', group: 'zpa', label: 'ZPA identity providers', path: `${v2}/idp`, query: { pagesize: '500' } },
    { key: 'zpaSamlAttributes', group: 'zpa', label: 'ZPA SAML attributes', path: `${v2}/samlAttribute`, query: { pagesize: '500' } },
  ];
}

function catalog(client) {
  const list = ENDPOINTS.slice();
  if (client && client.cfg.zpaCustomerId) list.push(...zpaEndpoints(client.cfg.zpaCustomerId));
  return list;
}

function unwrap(d) {
  if (d && !Array.isArray(d) && typeof d === 'object') {
    for (const k of ['list', 'policies', 'items', 'data']) if (Array.isArray(d[k])) return d[k];
  }
  return d;
}

// ZPA customer ID from the OneAPI token. Zscaler doesn't document a lookup, so read the token's claims
// (no verification needed: we only use them as candidates) and keep the first one ZPA accepts.
function jwtClaims(token) {
  try { return JSON.parse(Buffer.from(String(token).split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch { return null; }
}
function zpaIdCandidates(claims) {
  const named = [], other = [];
  const walk = (v, key, depth) => {
    if (depth > 4 || v == null) return;
    if (Array.isArray(v)) { v.forEach((x) => walk(x, key, depth + 1)); return; }
    if (typeof v === 'object') { for (const [k, x] of Object.entries(v)) walk(x, k, depth + 1); return; }
    const str = String(v);
    for (const m of str.match(/\b\d{15,20}\b/g) || []) (/zpa|customer|tenant|org/i.test(key || '') ? named : other).push(m);
  };
  walk(claims, '', 0);
  return [...new Set([...named, ...other])].slice(0, 8);
}
async function zpaWorks(client, id) {
  try { await client.get(`${zpaBase(id)}/segmentGroup`, { pagesize: '1' }); return { ok: true }; }
  catch (e) { return { ok: false, error: e.message, status: e.status }; }
}
async function discoverZpaCustomerId(client) {
  const claims = jwtClaims(await client.auth());
  const cands = zpaIdCandidates(claims);
  client.pushLog('INFO', `ZPA customer ID: ${cands.length} candidate(s) in token claims [${Object.keys(claims || {}).join(', ')}]`, 0, '');
  for (const id of cands) if ((await zpaWorks(client, id)).ok) return id;
  return null;
}

// Connect probe: one cheap call per product so the user sees what the API client can reach.
async function probe(client) {
  const checks = [
    ['ZIA', `${ZIA}/status`],
    ['ZCC', '/zcc/papi/public/v1/webForwardingProfile/listByCompany'],
  ];
  const out = {};
  for (const [name, path] of checks) {
    try { await client.get(path); out[name] = { ok: true }; }
    catch (e) { out[name] = { ok: false, error: e.message, status: e.status }; }
  }
  if (!client.cfg.zpaCustomerId) {
    try { client.cfg.zpaCustomerId = await discoverZpaCustomerId(client) || undefined; if (client.cfg.zpaCustomerId) client.cfg.zpaIdSource = 'token'; } catch {}
  }
  out.ZPA = client.cfg.zpaCustomerId ? await zpaWorks(client, client.cfg.zpaCustomerId)
    : { ok: false, needsId: true, error: 'The ZPA customer ID isn\'t in the API token. Enter it in Load policies to include ZPA.' };
  return out;
}

// Load selected endpoints. job.items[key] = {label, group, state: pending|loading|ok|error, count, error}
async function loadSnapshot(client, { groups = ['zia', 'zcc', 'zpa'], job } = {}) {
  const snap = { loadedAt: null, data: {}, errors: {} };
  const items = catalog(client).filter((e) => groups.includes(e.group));
  if (job) { job.items = {}; for (const e of items) job.items[e.key] = { label: e.label, group: e.group, state: 'pending' }; }
  for (const e of items) {
    if (job) job.items[e.key].state = 'loading';
    try {
      const d = await fetchEndpoint(client, e);
      snap.data[e.key] = d.data;
      if (job) Object.assign(job.items[e.key], { state: 'ok', count: Array.isArray(d.data) ? d.data.length : d.data ? 1 : 0, error: d.warning });
    } catch (err) {
      snap.errors[e.key] = err.message;
      if (job) Object.assign(job.items[e.key], { state: 'error', error: err.message });
    }
  }
  // Merge per-platform ZCC app profiles into one list for the engine.
  const zp = [...(snap.data.zccPoliciesWin || []).map((p) => Object.assign({ _platform: 'Windows' }, p)), ...(snap.data.zccPoliciesMac || []).map((p) => Object.assign({ _platform: 'macOS' }, p))];
  if (snap.data.zccPoliciesWin || snap.data.zccPoliciesMac) snap.data.zccPolicies = zp;
  // Fetch PAC files referenced by app profiles (pac_url) so they can be evaluated locally.
  const pacUrls = new Map();
  const addPac = (u, owner) => { if (u && /^https?:\/\//i.test(u)) pacUrls.set(u, (pacUrls.get(u) || []).concat(owner)); };
  for (const p of zp) addPac(p.pac_url || p.pacUrl || (p.policyExtension && p.policyExtension.pacUrl), `${p._platform} app profile "${p.name}"`);
  for (const f of snap.data.zccForwardingProfiles || []) for (const a of f.forwardingProfileActions || []) if (a.systemProxyData && Number(a.systemProxyData.enablePAC) === 1) addPac(a.systemProxyData.pacURL, `forwarding profile "${f.name}"`);
  if (pacUrls.size) {
    if (job) job.items.pacFiles = { label: `PAC files referenced by app profiles (${pacUrls.size})`, group: 'zcc', state: 'loading' };
    snap.data.pacFetched = [];
    for (const [u, owners] of pacUrls) {
      try { snap.data.pacFetched.push({ url: u, owners, text: await fetchText(u) }); }
      catch (e) { snap.data.pacFetched.push({ url: u, owners, error: e.message }); }
    }
    const ok = snap.data.pacFetched.filter((x) => x.text).length;
    if (job) Object.assign(job.items.pacFiles, { state: ok === pacUrls.size ? 'ok' : 'error', count: ok, error: ok === pacUrls.size ? undefined : snap.data.pacFetched.filter((x) => x.error).map((x) => `${x.url}: ${x.error}`).join('; ') });
  }
  snap.loadedAt = Date.now();
  return snap;
}

// Resolve a user's groups/department from ZIA (best effort).
// User lookup: ZIA's user list first, then ZIdentity (OneAPI /ziam), which is where ZPA's SCIM/SAML identity comes
// from and which still works when ZIA's /users is blocked for the API client.
const ZID = '/ziam/admin/api/v1';
const recs = (d) => (Array.isArray(d) ? d : (d && (d.records || d.list || d.items)) || []);
async function lookupUser(client, nameOrEmail) {
  const q = String(nameOrEmail).toLowerCase();
  let zia = null, ziaErr = null, zid = null, zidErr = null;
  try {
    const list = await client.get(`${ZIA}/users`, { search: nameOrEmail, pageSize: '10' });
    const arr2 = Array.isArray(list) ? list : [];
    const u = arr2.find((x) => String(x.email || '').toLowerCase() === q || String(x.name || '').toLowerCase() === q) || arr2[0];
    if (u) zia = { name: u.name, email: u.email, groups: (u.groups || []).map((g) => g.name), department: u.department && u.department.name };
  } catch (e) { ziaErr = e; }
  try {
    let list = recs(await client.get(`${ZID}/users`, { loginName: nameOrEmail, limit: '10' }));
    if (!list.length) list = recs(await client.get(`${ZID}/users`, { 'primaryEmail[like]': nameOrEmail, limit: '10' }));
    const u = list.find((x) => [x.loginName, x.primaryEmail, x.displayName].some((v) => String(v || '').toLowerCase() === q)) || list[0];
    if (u) {
      const g = recs(await client.get(`${ZID}/users/${encodeURIComponent(u.id)}/groups`, { limit: '1000' }));
      zid = { name: u.displayName || u.loginName, email: u.primaryEmail || u.loginName, groups: g.map((x) => x.name || x.displayName).filter(Boolean),
        department: u.department && (u.department.displayName || u.department.name), idp: u.idp && (u.idp.displayName || u.idp.name) };
    }
  } catch (e) { zidErr = e; }
  if (!zia && !zid) {
    if (ziaErr && zidErr) throw new Error(`ZIA: ${ziaErr.message} · ZIdentity: ${zidErr.message}`);
    if (ziaErr && !zidErr) return null;
    if (zidErr && !ziaErr) return null;
    return null;
  }
  const groups = [...new Set([...(zia ? zia.groups : []), ...(zid ? zid.groups : [])])];
  return Object.assign({}, zid || {}, zia || {}, { groups, department: (zia && zia.department) || (zid && zid.department),
    source: zia && zid ? 'ZIA + ZIdentity' : zia ? 'ZIA' : 'ZIdentity', ziaError: ziaErr && !zia ? ziaErr.message : undefined });
}

// ZPA SCIM group name by ID (rules reference SCIM groups by ID).
async function zpaScimGroupName(client, id) {
  const g = await client.get(`/zpa/userconfig/v1/customers/${client.cfg.zpaCustomerId}/scimgroup/${encodeURIComponent(id)}`);
  return g && g.name;
}

// URL / IP category lookup (read-only POST, up to 100 entries per call). Pass rateRetries: 0 to get 429s back
// as errors (with err.retryAfter) so a long-running caller can wait and report progress itself.
const URL_LOOKUP_MAX = 100;
async function urlLookup(client, urls, { rateRetries } = {}) {
  const out = await client.request('POST', `${ZIA}/urlLookup`, { body: urls, rateRetries });
  return Array.isArray(out) ? out : [];
}

// One catalog entry: a single GET, a multi-part entry (Cloud App Control rule types), or a paged ZPA list.
async function fetchEndpoint(client, e) {
  if (e.multi) {
    const all = [], failed = [];
    for (const part of e.multi) {
      try { for (const r of arr(unwrap(await client.get(part.path)))) all.push(Object.assign({ ruleType: part.type }, r)); }
      catch (err) { failed.push(`${part.type}: ${err.status || err.message}`); }
    }
    if (failed.length === e.multi.length) throw new Error(`all rule types failed (${failed[0]})`);
    return { data: all, warning: failed.length ? `${failed.length} rule type(s) not available: ${failed.slice(0, 3).join('; ')}` : undefined };
  }
  const first = await client.get(e.path, e.query);
  let data = unwrap(first);
  const pages = first && +first.totalPages;
  if (e.group === 'zpa' && Array.isArray(data) && pages > 1) {
    for (let pg = 2; pg <= Math.min(pages, 50); pg++) data = data.concat(arr(unwrap(await client.get(e.path, Object.assign({}, e.query, { page: String(pg) })))));
  }
  return { data };
}
const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);

// Re-read selected policy sets (after a change) into an existing snapshot.
async function refreshKeys(client, snap, keys) {
  for (const e of catalog(client).filter((x) => keys.includes(x.key))) {
    try { snap.data[e.key] = (await fetchEndpoint(client, e)).data; delete snap.errors[e.key]; }
    catch (err) { snap.errors[e.key] = err.message; }
  }
  snap.loadedAt = Date.now();
}

module.exports = { zpaScimGroupName, zpaWorks, zpaIdCandidates, jwtClaims, ZClient, loadSnapshot, refreshKeys, ZIA, zpaBase, CAC_TYPES, probe, catalog, lookupUser, urlLookup, URL_LOOKUP_MAX, ENDPOINTS };
