'use strict';
// ZIA policy semantics found while validating a full customer policy (URL Filtering, Cloud App Control, SSL, Sandbox,
// DNS, Firewall). Synthetic data only.
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const { simulate, cacAction, sortRules } = require('../src/engine');

const ALLP = ['WEBSOCKETSSL_RULE', 'WEBSOCKET_RULE', 'DOHTTPS_RULE', 'TUNNELSSL_RULE', 'HTTP_PROXY', 'FOHTTP_RULE', 'FTP_RULE', 'HTTPS_RULE', 'HTTP_RULE', 'SSL_RULE', 'TUNNEL_RULE'];
const dnd = (bypass) => ({ type: 'DO_NOT_DECRYPT', doNotDecryptSubActions: { bypassOtherPolicies: bypass } });
const base = () => ({
  data: {
    advancedSettings: { enableAdminRankAccess: true },
    customUrlCategories: [
      { id: 'CUSTOM_01', configuredName: 'Allow list', customCategory: true, urls: ['exact.example', '.wild.example', 'files.example.org/ok'] },
      { id: 'CUSTOM_02', configuredName: 'Coach words', customCategory: true, urls: [], keywords: ['coachme'] },
      { id: 'CUSTOM_03', configuredName: 'No inspect', customCategory: true, urls: ['.noinspect.example'] },
      { id: 'CUSTOM_04', configuredName: 'Block list', customCategory: true, urls: ['.blocklist.example'] },
      { id: 'WEBMAIL', configuredName: 'Webmail', customCategory: false, urls: ['.mymail.example'] }, // URLs added to a predefined category
    ],
    sslRules: [
      { id: 1, order: 1, rank: 1, name: 'UCaaS', state: 'ENABLED', action: dnd(true), cloudApplications: ['ZOOM'] },
      { id: 2, order: 2, rank: 7, name: 'Bypass list', state: 'ENABLED', action: dnd(false), cloudApplications: ['YOUTUBE'], destIpGroups: [{ id: 50, name: 'Bypass IPs' }], urlCategories: ['CUSTOM_03'] },
      { id: 3, order: 3, rank: 7, name: 'Inspect user', state: 'ENABLED', action: { type: 'DECRYPT' }, users: [{ id: 9, name: 'Dana Graves(dgraves@acme.org)' }] },
      { id: 4, order: 4, rank: 7, name: 'Inspect All', state: 'ENABLED', action: { type: 'DECRYPT' } },
    ],
    ipDestinationGroups: [{ id: 50, name: 'Bypass IPs', type: 'DSTN_IP', addresses: ['192.0.2.0/24'] }],
    cloudAppRules: [
      { id: 11, ruleType: 'CONSUMER', order: 1, rank: 7, name: 'CASB Block', state: 'ENABLED', applications: ['IMAGE_EDITOR'], actions: ['BLOCK_CONSUMER_APPS'] },
      { id: 12, ruleType: 'INSTANT_MESSAGING', order: 1, rank: 7, name: 'Chat for nurses', state: 'ENABLED', applications: ['GOOGLE_CHAT'], actions: ['ALLOW_CHAT'], groups: [{ id: 7, name: 'Nurses' }], cascadingEnabled: false },
      { id: 13, ruleType: 'WEBMAIL', order: 1, rank: 7, name: 'Webmail cascade', state: 'ENABLED', applications: ['OUTLOOK'], actions: ['ALLOW_WEBMAIL_VIEW'], cascadingEnabled: true },
    ],
    urlFilteringRules: [
      { id: 21, order: 1, rank: 7, name: 'Allow list', state: 'ENABLED', action: 'ALLOW', protocols: ALLP, urlCategories: ['CUSTOM_01'] },
      { id: 22, order: 2, rank: 7, name: 'Category Block', state: 'ENABLED', action: 'BLOCK', protocols: ['ANY_RULE'], urlCategories: ['GAMBLING', 'ONLINE_CHAT'] },
      { id: 23, order: 3, rank: 7, name: 'Block list', state: 'ENABLED', action: 'BLOCK', protocols: ALLP, requestMethods: ['GET', 'CONNECT'], urlCategories: ['CUSTOM_04'] },
      { id: 24, order: 4, rank: 7, name: 'Tunnel only', state: 'ENABLED', action: 'BLOCK', protocols: ['TUNNELSSL_RULE'], urlCategories: ['STREAMING'] },
      { id: 25, order: 5, rank: 7, name: 'Testers', state: 'ENABLED', action: 'ALLOW', protocols: ALLP, urlCategories: ['AI_ML_APPS'], groups: [{ id: 8, name: 'Test DLP' }] },
      { id: 26, order: 6, rank: 7, name: 'Coaching', state: 'ENABLED', action: 'CAUTION', protocols: ['HTTPS_RULE', 'HTTP_RULE'], requestMethods: ['GET', 'HEAD', 'CONNECT'], urlCategories: ['WEBMAIL', 'CUSTOM_02', 'AI_ML_APPS'] },
    ],
    sandboxRules: [
      { id: 31, order: 1, rank: 7, name: 'Quarantine', state: 'ENABLED', baRuleAction: 'BLOCK', firstTimeEnable: true, firstTimeOperation: 'QUARANTINE', fileTypes: ['FTCATEGORY_WINDOWS_EXECUTABLES'], protocols: ['HTTPS_RULE', 'HTTP_RULE'] },
      { id: 32, order: -1, rank: 7, name: 'Default BA Rule', state: 'ENABLED', defaultRule: true, baRuleAction: 'BLOCK', firstTimeEnable: true, firstTimeOperation: 'ALLOW_SCAN', fileTypes: ['FTCATEGORY_ZIP'], urlCategories: ['MISCELLANEOUS_OR_UNKNOWN'], protocols: ['ANY_RULE'] },
    ],
    fileTypeRules: [{ id: 41, order: 1, rank: 7, name: 'No ISOs', state: 'ENABLED', filteringAction: 'BLOCK', action: 'BLOCK', operation: 'UPLOAD_DOWNLOAD', fileTypes: ['FTCATEGORY_ISO'] }],
    dnsRules: [
      { id: 51, order: 1, rank: 7, name: 'Critical DNS', state: 'ENABLED', action: 'BLOCK', protocols: ['ANY_RULE'], destIpCategories: ['PHISHING'] },
      { id: 52, order: -1, rank: 7, name: 'Default Firewall DNS Rule', state: 'ENABLED', action: 'ALLOW', protocols: ['ANY_RULE'], predefined: true, defaultRule: true },
      { id: 53, order: -2, rank: 7, name: 'Unknown DNS Traffic', state: 'ENABLED', action: 'BLOCK', protocols: ['ANY_RULE'], predefined: true },
    ],
    firewallRules: [
      { id: 61, order: 1, rank: 7, name: 'From group', state: 'ENABLED', action: 'ALLOW', srcIpGroups: [{ id: 999, name: 'Branch nets' }], nwServices: [{ id: 1, name: 'RDP' }] },
      { id: 63, order: 2, rank: 7, name: 'Web and DNS', state: 'ENABLED', action: 'ALLOW', nwServices: [{ id: 2, name: 'HTTP' }, { id: 3, name: 'HTTPS' }, { id: 4, name: 'DNS' }] },
      { id: 62, order: -1, rank: 7, name: 'Default Firewall Filtering Rule', state: 'ENABLED', action: 'BLOCK_DROP', defaultRule: true },
    ],
    networkServices: [{ id: 1, name: 'RDP', tag: 'RDP', destTcpPorts: [{ start: 3389, end: 3389 }] }, { id: 2, name: 'HTTP', tag: 'HTTP' }, { id: 3, name: 'HTTPS', tag: 'HTTPS' }, { id: 4, name: 'DNS', tag: 'DNS' }],
  },
  errors: {},
});
const sim = (target, o = {}, snap = base()) => simulate(snap, Object.assign({ target: M.parseTarget(target), port: null, protocol: 'tcp', groups: [], categories: [], categorySource: 'Zscaler lookup', resolvedIps: [], notes: [] }, o), {});
const mod = (r, name) => r.modules.find((m) => m.module.startsWith(name));

test('Cloud App Control "Block Application Access" enums block (BLOCK_CONSUMER_APPS, DENY_*_USE, BLOCK_CHAT …)', () => {
  for (const a of ['BLOCK_CONSUMER_APPS', 'BLOCK_ENTERPRISE_COLLABORATION_APPS', 'BLOCK_SALES_MARKETING_APPS', 'BLOCK_SYSTEM_DEVELOPMENT_APPS', 'DENY_IT_SERVICES_USE', 'BLOCK_CHAT', 'BLOCK_WEBMAIL_VIEW', 'DENY_FILE_SHARE_VIEW', 'BLOCK_SOCIAL_NETWORKING_VIEW'])
    assert.equal(cacAction({ actions: [a] }), 'BLOCK', a);
  assert.equal(cacAction({ actions: ['ALLOW_AI_ML_WEB_USE', 'DENY_AI_ML_UPLOAD'] }), 'ALLOW');
  assert.equal(cacAction({ actions: ['ALLOW_AI_ML_WEB_USE', 'DENY_AI_ML_UPLOAD'] }, 'UPLOAD'), 'BLOCK');
  assert.equal(cacAction({ actions: ['ALLOW_FILE_SHARE_VIEW', 'ALLOW_FILE_SHARE_UPLOAD'] }), 'ALLOW');
  assert.equal(cacAction({ actions: ['CAUTION_AI_ML_WEB_USE'] }), 'CAUTION');
  const r = sim('https://imageeditor.example', { categories: ['ENTERTAINMENT'], cloudApp: 'IMAGE_EDITOR' });
  assert.equal(r.summary.overall, 'BLOCKED'); assert.equal(r.summary.primary.rule, 'CASB Block');
});

test('Cloud App Control is evaluated before URL Filtering; an allow without cascading stops URL Filtering', () => {
  const names = sim('https://x.example', { categories: ['NEWS'] }).modules.map((m) => m.module);
  assert.ok(names.indexOf('Cloud App Control') < names.indexOf('URL Filtering'));
  const nurse = sim('https://chat.google.com', { categories: ['ONLINE_CHAT'], cloudApp: 'GOOGLE_CHAT', user: 'n@acme.org', groups: ['Nurses'], userResolved: { email: 'n@acme.org' } });
  assert.equal(nurse.summary.overall, 'ALLOWED'); assert.equal(nurse.summary.primary.rule, 'Chat for nurses');
  assert.equal(mod(nurse, 'URL Filtering').verdict, 'N/A');
  const clerk = sim('https://chat.google.com', { categories: ['ONLINE_CHAT'], cloudApp: 'GOOGLE_CHAT', user: 'c@acme.org', groups: ['Staff'], userResolved: { email: 'c@acme.org' } });
  assert.equal(clerk.summary.overall, 'BLOCKED'); assert.equal(clerk.summary.primary.rule, 'Category Block');
  // Nobody entered: blocked, but being in the group would allow it — shown as a condition
  const anyone = sim('https://chat.google.com', { categories: ['ONLINE_CHAT'], cloudApp: 'GOOGLE_CHAT' });
  assert.equal(anyone.summary.overall, 'BLOCKED');
  assert.ok(anyone.summary.alsoBasedOn.some((c) => c.action === 'ALLOW' && /Nurses/.test(c.condition)), JSON.stringify(anyone.summary.alsoBasedOn));
  // cascadingEnabled: URL Filtering still applies after the Cloud App Control allow
  const owa = sim('https://outlook.office.com', { categories: ['WEBMAIL'], cloudApp: 'OUTLOOK' });
  assert.equal(owa.summary.overall, 'CAUTIONED'); assert.equal(owa.summary.primary.rule, 'Coaching');
});

test('SSL "Do Not Inspect" + "Bypass Other Policies" skips the other web policies', () => {
  const r = sim('https://zoom.us', { categories: ['GAMBLING'], cloudApp: 'ZOOM' });
  assert.equal(mod(r, 'SSL').verdict, 'NOT_DECRYPTED');
  for (const m of ['URL Filtering', 'Cloud App Control', 'Advanced Threat', 'Sandbox', 'File Type', 'Data Loss']) assert.equal(mod(r, m).verdict, 'N/A', m);
  assert.equal(r.summary.overall, 'ALLOWED'); assert.equal(r.summary.primary.rule, 'UCaaS');
});

test('SSL rule destination criteria are alternatives (category OR cloud app OR destination group)', () => {
  assert.equal(mod(sim('https://192.0.2.10', { categories: ['WEB_SEARCH'] }), 'SSL').verdict, 'NOT_DECRYPTED');
  assert.equal(mod(sim('https://www.youtube.com', { categories: ['STREAMING'], cloudApp: 'YOUTUBE' }), 'SSL').verdict, 'NOT_DECRYPTED');
  assert.equal(mod(sim('https://a.noinspect.example', { categories: ['NEWS'] }), 'SSL').verdict, 'NOT_DECRYPTED');
  assert.equal(mod(sim('https://news.example', { categories: ['NEWS'] }), 'SSL').verdict, 'DECRYPTED');
});

test('undecrypted HTTPS is SSL/TLS or Tunnel SSL/TLS to URL Filtering, not HTTPS', () => {
  const r = sim('https://mail.noinspect.example', { categories: ['WEBMAIL'] });
  assert.equal(mod(r, 'SSL').verdict, 'NOT_DECRYPTED');
  const coach = mod(r, 'URL Filtering').rules.find((e) => e.name === 'Coaching');
  assert.equal(coach.status, 'nomatch'); // HTTPS/HTTP only
  assert.equal(r.summary.overall, 'ALLOWED');
  // a rule that lists SSL/TLS and Tunnel SSL/TLS (and CONNECT) still blocks undecrypted HTTPS
  const blk = sim('https://y.noinspect.example', { categories: ['FINANCE'] }, (() => { const s = base(); s.data.customUrlCategories[3].urls.push('.noinspect.example'); return s; })());
  assert.equal(mod(blk, 'SSL').verdict, 'NOT_DECRYPTED');
  assert.equal(blk.summary.overall, 'BLOCKED'); assert.equal(blk.summary.primary.rule, 'Block list');
  // a rule listing only one of the two undecrypted protocols depends on how the traffic is forwarded
  const tun = sim('https://www.youtube.com', { categories: ['STREAMING'], cloudApp: 'YOUTUBE' });
  const t = mod(tun, 'URL Filtering').rules.find((e) => e.name === 'Tunnel only');
  assert.equal(t.status, 'unknown');
  assert.ok(tun.summary.alsoBasedOn.some((c) => /Forwarding method/.test(c.condition) && c.action === 'BLOCK'));
  // decrypted HTTPS doesn't match a Tunnel SSL/TLS-only rule
  const dec = sim('https://video.example', { categories: ['STREAMING'] });
  assert.equal(mod(dec, 'URL Filtering').rules.find((e) => e.name === 'Tunnel only').status, 'nomatch');
});

test('URL entries: no leading dot = that host only; leading dot = subdomains too; keywords; predefined additions', () => {
  assert.equal(sim('https://exact.example', { categories: ['GAMBLING'] }).summary.primary.rule, 'Allow list');
  assert.equal(sim('https://www.exact.example', { categories: ['GAMBLING'] }).summary.primary.rule, 'Category Block');
  assert.equal(sim('https://a.b.wild.example', { categories: ['GAMBLING'] }).summary.primary.rule, 'Allow list');
  assert.equal(sim('https://files.example.org/ok/report.html', { categories: ['GAMBLING'] }).summary.primary.rule, 'Allow list');
  assert.equal(sim('https://files.example.org/other', { categories: ['GAMBLING'] }).summary.primary.rule, 'Category Block');
  assert.equal(sim('https://news.example/coachme/today', { categories: ['NEWS'] }).summary.primary.rule, 'Coaching');
  assert.equal(sim('https://portal.mymail.example', { categories: ['NEWS'] }).summary.primary.rule, 'Coaching'); // added to predefined Webmail
});

test('users match by login exactly, not by substring; an unresolved user\'s groups are unknown', () => {
  const ssl = (u, resolved) => mod(sim('https://news.example', { categories: ['NEWS'], user: u, userResolved: resolved ? { email: u } : null }), 'SSL').rules.find((e) => e.name === 'Inspect user').status;
  assert.equal(ssl('graves@acme.org', true), 'nomatch');
  assert.equal(ssl('dgraves@acme.org', true), 'match');
  const r = sim('https://ai.example', { categories: ['AI_ML_APPS'], user: 'ghost@acme.org' }); // not found in the directory
  assert.equal(mod(r, 'URL Filtering').rules.find((e) => e.name === 'Testers').status, 'unknown');
  const known = sim('https://ai.example', { categories: ['AI_ML_APPS'], user: 'c@acme.org', groups: ['Staff'], userResolved: { email: 'c@acme.org' } });
  assert.equal(mod(known, 'URL Filtering').rules.find((e) => e.name === 'Testers').status, 'nomatch');
});

test('sandbox: first-time action (quarantine / scan), blocked only when the sandbox finds it malicious', () => {
  const exe = sim('https://dl.example/setup.exe', { categories: ['NEWS'], fileType: 'EXE', operation: 'DOWNLOAD' });
  assert.equal(mod(exe, 'Sandbox').verdict, 'QUARANTINE');
  assert.notEqual(exe.summary.overall, 'BLOCKED');
  assert.ok(exe.summary.alsoBasedOn.some((c) => c.kind === 'content' && c.action === 'BLOCK' && /sandbox/i.test(c.condition)));
  const zip = sim('https://dl.example/a.zip', { categories: ['MISCELLANEOUS_OR_UNKNOWN'], fileType: 'ZIP', operation: 'DOWNLOAD' });
  assert.equal(mod(zip, 'Sandbox').verdict, 'SCAN'); assert.equal(mod(zip, 'Sandbox').decidingRule.name, 'Default BA Rule');
  // the default BA rule's own criteria must fit: no file → no sandbox rule
  assert.equal(mod(sim('https://news.example', { categories: ['MISCELLANEOUS_OR_UNKNOWN'] }), 'Sandbox').decidingRule, null);
});

test('DNS: "Unknown DNS Traffic" is not a catch-all; predefined rules run -2 before -1', () => {
  const r = sim('www.example.com', { port: 53, protocol: 'udp', categories: ['NEWS'] });
  assert.equal(mod(r, 'DNS').decidingRule.name, 'Default Firewall DNS Rule');
  assert.equal(r.summary.overall, 'ALLOWED');
  assert.equal(mod(sim('phish.example', { port: 53, protocol: 'udp', categories: ['PHISHING'] }), 'DNS').verdict, 'BLOCK');
  const order = sortRules(base().data.dnsRules, true).map((x) => x.name);
  assert.deepEqual(order, ['Critical DNS', 'Unknown DNS Traffic', 'Default Firewall DNS Rule']);
});

test('file type operation UPLOAD_DOWNLOAD covers downloads and uploads', () => {
  for (const op of ['DOWNLOAD', 'UPLOAD']) assert.equal(mod(sim('https://dl.example/x.iso', { categories: ['NEWS'], fileType: 'ISO', operation: op }), 'File Type').verdict, 'BLOCK', op);
});

test('a source IP group missing from the snapshot is unknown, never "any source"', () => {
  const r = sim('8.8.8.8', { port: 3389, categories: ['WEB_SEARCH'] });
  const e = mod(r, 'Firewall').rules.find((x) => x.name === 'From group');
  assert.equal(e.criteria.find((c) => c.field === 'source IP').status, 'unknown');
  assert.equal(mod(r, 'Firewall').decidingRule.name, 'Default Firewall Filtering Rule');
});

test('parsed IP ranges are cached and immutable', () => {
  const a = M.parseIpRange('10.1.0.0/16');
  assert.ok(Object.isFrozen(a));
  assert.strictEqual(M.parseIpRange('10.1.0.0/16'), a);
  assert.deepEqual(M.parseIpRange('10.1.2.3-10.1.2.1'), [M.ipToInt('10.1.2.1'), M.ipToInt('10.1.2.3')]);
});
