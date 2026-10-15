'use strict';
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const { simulate } = require('../src/engine');
const snap = require('../src/demo-snapshot.json');

function run(over, manual) {
  const t = M.parseTarget(over.target || over.ip);
  const ctx = Object.assign({ target: t, port: t && t.port, protocol: 'tcp', groups: [], categories: [], resolvedIps: [] }, over);
  ctx.target = t;
  return simulate({ data: snap }, ctx, manual || {});
}
const mod = (r, name) => r.modules.find((m) => m.module.startsWith(name));

test('domain wildcard relations', () => {
  assert.equal(M.domainRelation('www.google.com', '.google.com'), 'match');
  assert.equal(M.domainRelation('google.com', '*.google.com'), 'match');
  assert.equal(M.domainRelation('notgoogle.com', 'google.com'), 'none');
  assert.equal(M.domainRelation('*.google.com', 'google.com'), 'match');
  assert.equal(M.domainRelation('*.google.com', 'mail.google.com'), 'partial');
  assert.equal(M.domainRelation('https://a.example.com/x/y', 'example.com/x'), 'match');
  assert.equal(M.domainRelation('https://a.example.com/z', 'example.com/x'), 'none');
});

test('ip / cidr relations', () => {
  assert.equal(M.ipInList('10.0.2.5', ['10.0.2.0/24']).rel, 'match');
  assert.equal(M.ipInList('10.0.2.0/24', ['10.0.0.0/8']).rel, 'match');
  assert.equal(M.ipInList('10.0.0.0/8', ['10.0.2.0/24']).rel, 'partial');
  assert.equal(M.ipInList('192.168.1.1', ['10.0.0.1-10.0.0.9']).rel, 'none');
  assert.equal(M.ipInList('10.0.0.5', ['10.0.0.1-10.0.0.9']).rel, 'match');
});

test('URL filtering blocks category and names the rule', () => {
  const r = run({ target: 'https://casino.example', categories: ['GAMBLING'] });
  const m = mod(r, 'URL Filtering');
  assert.equal(m.verdict, 'BLOCK');
  assert.equal(m.decidingRule.name, 'Block Gambling and Adult');
  assert.equal(r.summary.overall, 'BLOCKED');
});

test('group-scoped rule is conditional without user, definite with user', () => {
  const a = mod(run({ target: 'https://facebook.com', categories: ['SOCIAL_NETWORKING'] }), 'URL Filtering');
  assert.equal(a.verdict, 'ALLOW');
  assert.equal(a.confidence, 'conditional');
  assert.equal(a.couldOverride[0].name, 'Block Social for Guests');
  const b = mod(run({ target: 'https://facebook.com', categories: ['SOCIAL_NETWORKING'], user: 'jdoe', groups: ['Guests'] }), 'URL Filtering');
  assert.equal(b.verdict, 'BLOCK');
  assert.equal(b.confidence, 'definite');
  const c = mod(run({ target: 'https://facebook.com', categories: ['SOCIAL_NETWORKING'], user: 'jdoe', groups: ['Staff'] }), 'URL Filtering');
  assert.equal(c.verdict, 'ALLOW');
  assert.equal(c.confidence, 'definite');
});

test('custom URL category match', () => {
  const r = run({ target: 'https://files.sketchy.example/a' });
  assert.ok(r.context.categories.includes('CUSTOM_01'));
  assert.equal(mod(r, 'URL Filtering').decidingRule.name, 'Block Custom Denylist');
});

test('firewall: port-based service block and CIDR query', () => {
  const rdp = mod(run({ target: '10.0.2.5', port: 3389 }), 'Firewall');
  assert.equal(rdp.verdict, 'BLOCK');
  assert.equal(rdp.decidingRule.name, 'Block RDP Outbound');
  const cidr = mod(run({ target: '10.0.2.0/24', port: 8080 }), 'Firewall');
  assert.equal(cidr.decidingRule.name, 'Allow Lab Subnet');
  const smbPublic = mod(run({ target: '8.8.8.8', port: 445 }), 'Firewall');
  assert.equal(smbPublic.decidingRule.name, 'Block SMB to Internet');
  const smbInternal = mod(run({ target: '10.0.2.9', port: 445 }), 'Firewall');
  assert.equal(smbInternal.decidingRule.name, 'Allow Lab Subnet');
});

test('firewall without port is conditional', () => {
  const r = mod(run({ target: '10.0.2.5', port: null }), 'Firewall');
  assert.equal(r.confidence, 'conditional');
});

test('DNS wildcard query', () => {
  const r = mod(run({ target: '*.badzone.example' }), 'DNS');
  assert.equal(r.verdict, 'BLOCK');
  assert.equal(r.decidingRule.name, 'Block Newly Registered Domains');
});

test('file type: download exe -> file type control + sandbox', () => {
  const r = run({ target: 'https://downloads.example/setup.exe', fileType: 'EXE', operation: 'DOWNLOAD', categories: ['OTHER_BUSINESS_AND_ECONOMY'] });
  assert.equal(mod(r, 'File Type').verdict, 'BLOCK');
  assert.equal(mod(r, 'Sandbox').verdict, 'BLOCK');
  const doc = run({ target: 'https://x.example/a.docx', fileType: 'DOCX', operation: 'DOWNLOAD' });
  assert.equal(mod(doc, 'File Type').verdict, 'ALLOW');
});

test('SSL inspection exemption flags limited visibility', () => {
  const r = mod(run({ target: 'https://www.mychart.example', categories: ['HEALTH'] }), 'SSL');
  assert.equal(r.verdict, 'NOT_DECRYPTED');
  assert.ok(/not decrypted/i.test(r.note));
});

test('DLP is content dependent', () => {
  const r = mod(run({ target: 'https://upload.example', categories: ['FILE_HOST'], fileType: 'PDF' }), 'Data Loss');
  assert.equal(r.verdict, 'CONDITIONAL_BLOCK');
  assert.equal(r.candidates[0].engines[0], 'HIPAA PHI');
});

test('ATP: category flags, country, allow/deny lists', () => {
  assert.equal(mod(run({ target: 'https://x.example', categories: ['MALWARE_SITE'] }), 'Advanced Threat').verdict, 'BLOCK');
  assert.equal(mod(run({ target: 'https://a.evil-denylist.example' }), 'Advanced Threat').verdict, 'BLOCK');
  assert.equal(mod(run({ target: 'https://trusted.partner.example', categories: ['MALWARE_SITE'] }), 'Advanced Threat').verdict, 'ALLOW');
  assert.equal(mod(run({ target: 'https://x.example', destCountry: 'KP' }), 'Advanced Threat').verdict, 'BLOCK');
});

test('ZCC per-profile forwarding: exclusions, VPN gateway, app bypass, PAC, network types', () => {
  const fw = (over, manual) => mod(run(over, manual), 'Forwarding');
  const prof = (m, name) => m.profiles.find((p) => p.name === name);
  // Internal IP: excluded on Windows (Z-Tunnel 2.0 IPv4 exclusion), DIRECT via Mac PAC; On-Trusted action None on Windows
  let m = fw({ target: '10.0.2.5', port: 443 });
  assert.equal(m.verdict, 'BYPASSES_ZSCALER');
  assert.ok(prof(m, 'Corp Windows').outcomes.some((o) => /IPv4 exclusion 10.0.0.0\/8/.test(o.how)));
  assert.ok(prof(m, 'Corp macOS').outcomes.some((o) => /returns DIRECT/.test(o.how)));
  // Public site: reaches ZIA off-trusted on both, but Windows On-Trusted is "None" -> depends on profile/network
  m = fw({ target: 'https://www.example.com/', resolvedIps: ['93.184.216.34'] });
  assert.equal(m.verdict, 'DEPENDS_ON_PROFILE');
  const win = prof(m, 'Corp Windows');
  assert.ok(win.outcomes.find((o) => o.outcome === 'ZIA' && o.nets.includes('Off-Trusted')));
  assert.ok(win.outcomes.find((o) => o.outcome === 'BYPASS' && o.nets.includes('On-Trusted')));
  // Domain exclusion and VPN gateway bypass (Windows), not on macOS
  m = fw({ target: 'https://intranet.corp.example', resolvedIps: ['93.1.1.1'] });
  assert.ok(prof(m, 'Corp Windows').outcomes.some((o) => /Destination \(domain\) exclusion intranet.corp.example/.test(o.how)));
  assert.equal(prof(m, 'Corp macOS').summary, 'ZIA');
  m = fw({ target: 'vpn.corp.example', port: 443, protocol: 'udp' });
  assert.ok(prof(m, 'Corp Windows').outcomes.some((o) => /VPN gateway bypass/.test(o.how)));
  // macOS local proxy does not carry non-web traffic
  assert.ok(prof(m, 'Corp macOS').outcomes.some((o) => o.outcome === 'NOT_CAPTURED'));
  // IP-based app bypass (Teams)
  m = fw({ target: '52.113.1.1', port: 443 });
  assert.ok(prof(m, 'Corp Windows').outcomes.some((o) => /app bypass "Microsoft Teams"/.test(o.how)));
  // Manual inputs still work
  m = fw({ target: 'https://x.test' }, { pacText: 'function FindProxyForURL(u,h){ return shExpMatch(h,"*.test") ? "DIRECT" : "PROXY p:80"; }' });
  assert.ok(prof(m, 'Manual inputs').outcomes[0].how.includes('DIRECT'));
});

test('ZPA segment match, conditional on identity', () => {
  const r = mod(run({ target: 'https://pacs.hospital.example', port: 104 }), 'ZPA');
  assert.equal(r.matchedSegments[0].name, 'Radiology PACS');
  assert.equal(r.confidence, 'conditional');
  const wrongPort = mod(run({ target: 'https://pacs.hospital.example', port: 9999 }), 'ZPA');
  assert.equal(wrongPort.verdict, 'NOT_A_ZPA_APP');
  const other = mod(run({ target: 'https://google.com', port: 443 }), 'ZPA');
  assert.equal(other.verdict, 'NOT_A_ZPA_APP');
});

test('default rule (order -1) is evaluated last; services without port lists fall back by tag', () => {
  const s = {
    firewallRules: [
      { id: 1, name: 'Default Firewall Filtering Rule', order: -1, rank: 7, state: 'ENABLED', action: 'BLOCK_DROP', defaultRule: true },
      { id: 2, name: 'Zscaler Proxy Traffic', order: 1, rank: 7, state: 'ENABLED', action: 'ALLOW', nwServices: [{ id: 7, name: 'Zscaler Proxy Nw Services' }] },
    ],
    networkServices: [{ id: 7, name: 'Zscaler Proxy Nw Services', tag: 'ZSCALER_PROXY_NW_SERVICES' }],
    sslRules: [
      { id: 10, name: 'Default SSL Inspection Rule', order: -1, state: 'ENABLED', action: { type: 'DO_NOT_DECRYPT' }, defaultRule: true },
      { id: 11, name: 'Decrypt Everything', order: 1, state: 'ENABLED', action: { type: 'DECRYPT' } },
    ],
    urlFilteringRules: [
      { id: 20, name: 'Block-Legal-Liability', order: 3, rank: 7, state: 'ENABLED', action: 'BLOCK', urlCategories: ['GAMBLING'], requestMethods: ['OPTIONS', 'GET', 'HEAD', 'POST'] },
    ],
  };
  const t = M.parseTarget('draftkings.com');
  const r = simulate({ data: s }, { target: t, port: 443, protocol: 'tcp', groups: [], categories: ['GAMBLING'], resolvedIps: ['23.215.11.242'] }, {});
  assert.equal(mod(r, 'Firewall').decidingRule.name, 'Zscaler Proxy Traffic');
  assert.equal(mod(r, 'SSL').verdict, 'DECRYPTED');
  assert.equal(mod(r, 'URL Filtering').verdict, 'BLOCK');
  assert.equal(mod(r, 'URL Filtering').confidence, 'definite');
  assert.equal(r.summary.overall, 'BLOCKED');
  assert.match(r.summary.lines[0], /Blocked by URL Filtering.*Block-Legal-Liability/);
  // not decrypted -> CONNECT, which this rule does not list
  s.sslRules[1].state = 'DISABLED';
  const r2 = simulate({ data: s }, { target: t, port: 443, protocol: 'tcp', groups: [], categories: ['GAMBLING'], resolvedIps: [] }, {});
  assert.equal(mod(r2, 'SSL').verdict, 'NOT_DECRYPTED');
  assert.equal(mod(r2, 'URL Filtering').verdict, 'ALLOW');
  assert.match(JSON.stringify(mod(r2, 'URL Filtering').rules[0].criteria), /CONNECT not in/);
  // explicit method override
  const r3 = simulate({ data: s }, { target: t, port: 443, protocol: 'tcp', groups: [], categories: ['GAMBLING'], resolvedIps: [], method: 'GET' }, {});
  assert.equal(mod(r3, 'URL Filtering').verdict, 'BLOCK');
});

test('QUIC: UDP/443 rationalizes to the QUIC service/app; TCP/443 does not', () => {
  const s = {
    firewallRules: [
      { id: 1, name: 'Block QUIC (app)', order: 1, state: 'ENABLED', action: 'BLOCK_DROP', nwApplications: ['QUIC'] },
      { id: 2, name: 'Allow All', order: 2, state: 'ENABLED', action: 'ALLOW' },
      { id: 3, name: 'Default Firewall Filtering Rule', order: -1, state: 'ENABLED', action: 'BLOCK_DROP', defaultRule: true },
    ],
  };
  const go = (ctx) => simulate({ data: s }, Object.assign({ groups: [], categories: [], resolvedIps: [] }, ctx), {});
  const udp = go({ target: M.parseTarget('google.com'), port: 443, protocol: 'udp' });
  assert.equal(mod(udp, 'Firewall').decidingRule.name, 'Block QUIC (app)');
  assert.equal(udp.summary.overall, 'BLOCKED');
  assert.equal(mod(udp, 'URL Filtering').verdict, 'N/A');
  assert.ok(udp.context.notes.some((n) => /QUIC/.test(n)));
  const tcp = go({ target: M.parseTarget('google.com'), port: 443, protocol: 'tcp' });
  assert.equal(mod(tcp, 'Firewall').decidingRule.name, 'Allow All');
  // service-based QUIC rule where the API returned no ports for the predefined service
  s.firewallRules[0] = { id: 1, name: 'Block QUIC (service)', order: 1, state: 'ENABLED', action: 'BLOCK_DROP', nwServices: [{ id: 50, name: 'QUIC' }] };
  s.networkServices = [{ id: 50, name: 'QUIC', tag: 'QUIC', type: 'PREDEFINED' }];
  assert.equal(mod(go({ target: M.parseTarget('google.com'), port: 443, protocol: 'udp' }), 'Firewall').decidingRule.name, 'Block QUIC (service)');
  // typing the service name instead of a port
  const byName = go({ target: M.parseTarget('google.com'), networkService: 'QUIC' });
  assert.equal(byName.context.port, 443);
  assert.equal(byName.context.protocol, 'udp');
  assert.equal(mod(byName, 'Firewall').decidingRule.name, 'Block QUIC (service)');
  // services AND applications must both match
  s.firewallRules[0] = { id: 1, name: 'Block SSH on 443 only', order: 1, state: 'ENABLED', action: 'BLOCK_DROP', nwServices: [{ id: 51, name: 'HTTPS' }], nwApplications: ['SSH'] };
  s.networkServices.push({ id: 51, name: 'HTTPS', tag: 'HTTPS', destTcpPorts: [{ start: 443 }] });
  assert.equal(mod(go({ target: M.parseTarget('x.example'), port: 443, protocol: 'tcp' }), 'Firewall').decidingRule.name, 'Allow All');
});

test('no destination: port-only firewall question', () => {
  const s = {
    firewallRules: [
      { id: 9, name: 'Block FR', order: 1, state: 'ENABLED', action: 'BLOCK_DROP', destCountries: ['COUNTRY_FR'] },
      { id: 1, name: 'Block-QUIC', order: 2, state: 'ENABLED', action: 'BLOCK_ICMP', nwApplications: ['QUIC'] },
      { id: 2, name: 'Allow all', order: 3, state: 'ENABLED', action: 'ALLOW' },
    ],
    urlFilteringRules: [{ id: 3, name: 'Block gambling', order: 1, state: 'ENABLED', action: 'BLOCK', urlCategories: ['GAMBLING'] }],
  };
  const r = simulate({ data: s }, { target: null, port: 443, protocol: 'udp', groups: [], categories: [], resolvedIps: [] }, {});
  assert.equal(mod(r, 'Firewall').decidingRule.name, 'Block-QUIC');
  assert.equal(mod(r, 'Firewall').sameOutcomeEarlier[0].name, 'Block FR');
  assert.equal(mod(r, 'Firewall').confidence, 'definite');
  assert.equal(mod(r, 'URL Filtering').verdict, 'N/A');
  assert.equal(mod(r, 'DNS').verdict, 'N/A');
  assert.equal(mod(r, 'Forwarding').verdict, 'N/A');
  const tcp = simulate({ data: s }, { target: null, port: 3389, protocol: 'tcp', groups: [], categories: [], resolvedIps: [] }, {});
  assert.equal(mod(tcp, 'Firewall').decidingRule.name, 'Allow all');
});


test('parseTarget keeps CIDR and ranges intact', () => {
  assert.equal(M.parseTarget('10.0.2.0/24').host, '10.0.2.0/24');
  assert.equal(M.parseTarget('10.0.0.1-10.0.0.9').host, '10.0.0.1-10.0.0.9');
  assert.equal(M.parseTarget('10.0.0.5:3389').port, 3389);
  assert.equal(M.parseTarget('https://example.com/a/b').path, '/a/b');
});

test('port comes from the URL scheme, hostnames assume HTTPS', () => {
  assert.equal(run({ target: 'http://x.example' }).context.port, 80);
  const h = run({ target: 'x.example' });
  assert.equal(h.context.port, 443);
  assert.ok(h.context.notes.some((n) => /assumed HTTPS/.test(n)));
  assert.equal(run({ target: '10.0.2.5' }).context.port, null);
});

test('outcome model: primary action + also-based-on conditions', () => {
  // group-scoped block, no user entered -> ALLOW for everyone else, Group Guests -> BLOCK
  const g = run({ target: 'https://facebook.com', categories: ['SOCIAL_NETWORKING'], resolvedIps: ['157.240.1.35'] });
  assert.equal(g.summary.primary.action, 'ALLOW');
  assert.equal(g.summary.primary.rule, 'Allow Everything Else');
  const guests = g.summary.alsoBasedOn.find((c) => c.kind === 'identity');
  assert.equal(guests.condition, 'Group Guests');
  assert.equal(guests.action, 'BLOCK');
  assert.equal(guests.rule, 'Block Social for Guests');
  // ZCC: Windows On-Trusted forwarding action None shows as a BYPASS condition
  assert.ok(g.summary.alsoBasedOn.some((c) => c.kind === 'zcc' && c.action === 'BYPASS' && /On-Trusted/.test(c.condition)));
  // with the user in Guests -> definite BLOCK
  const gb = run({ target: 'https://facebook.com', categories: ['SOCIAL_NETWORKING'], resolvedIps: ['157.240.1.35'], user: 'a', groups: ['Guests'] });
  assert.equal(gb.summary.primary.action, 'BLOCK');
  assert.equal(gb.summary.overall, 'BLOCKED');
  assert.ok(!gb.summary.alsoBasedOn.some((c) => c.kind === 'identity'));
  // bypassed everywhere -> BYPASS + "if it were forwarded" line
  const by = run({ target: '10.0.2.5', port: 443 });
  assert.equal(by.summary.primary.action, 'BYPASS');
  assert.equal(by.summary.alsoBasedOn[0].condition, 'If it were forwarded to Zscaler');
  // SSL not decrypted tag
  const h = run({ target: 'https://www.mychart.example', categories: ['HEALTH'], resolvedIps: ['93.1.1.2'] });
  assert.ok(h.summary.primary.tags.some((t) => t.tag === 'NOT_INSPECTED'));
  assert.ok(!h.summary.primary.tags.some((t) => t.tag === 'INSPECT_ONLY'));
  assert.ok(!h.summary.alsoBasedOn.some((c) => c.kind === 'content'));
  // DLP: content condition + inspect-only tag, never the primary
  const d = run({ target: 'https://www.example.com/', categories: ['OTHER'], resolvedIps: ['93.184.216.34'], user: 'x', groups: ['Staff'] });
  assert.equal(d.summary.primary.action, 'ALLOW');
  assert.ok(d.summary.alsoBasedOn.some((c) => c.kind === 'content' && c.action === 'BLOCK' && /HIPAA PHI/.test(c.condition)));
  assert.ok(d.summary.primary.tags.some((t) => t.tag === 'INSPECT_ONLY'));
  // blocked: decider is URL filtering
  const b = run({ target: 'https://casino.example', categories: ['GAMBLING'], resolvedIps: ['93.1.1.1'] });
  assert.equal(b.summary.primary.action, 'BLOCK');
  assert.equal(b.summary.primary.rule, 'Block Gambling and Adult');
});

test('isolate and caution are their own actions', () => {
  const s2 = { urlFilteringRules: [
    { id: 1, name: 'Isolate Webmail', order: 1, state: 'ENABLED', action: 'ISOLATE', urlCategories: ['WEB_MAIL'] },
    { id: 2, name: 'Caution Streaming', order: 2, state: 'ENABLED', action: 'CAUTION', urlCategories: ['STREAMING_MEDIA'] },
    { id: 3, name: 'Allow', order: 3, state: 'ENABLED', action: 'ALLOW' }] };
  const go = (cat) => simulate({ data: s2 }, { target: M.parseTarget('https://x.example'), groups: [], categories: [cat], resolvedIps: ['1.1.1.1'], protocol: 'tcp' }, {}).summary.primary;
  assert.equal(go('WEB_MAIL').action, 'ISOLATE');
  assert.equal(go('STREAMING_MEDIA').action, 'CAUTION');
  assert.equal(go('OTHER').action, 'ALLOW');
});

// ---------- 1.5.0: evaluation order ----------
const demo15 = () => JSON.parse(JSON.stringify(require('../src/demo-snapshot.json')));
const sim15 = (data, target, extra = {}) => simulate({ data }, Object.assign({ target: M.parseTarget(target), port: 443, protocol: 'tcp', categories: [], resolvedIps: [], groups: [], notes: [] }, extra), {});

test('ZPA decides first: segment match + intercept → access policy, ZIA and internet bypasses skipped', () => {
  const data = demo15();
  data.zccPolicies.forEach((p) => { p.packetTunnelExcludeList = ['10.0.0.0/8']; });
  const out = sim15(data, '10.50.1.20');
  assert.equal(out.summary.primary.module, 'ZPA Access Policy');
  assert.equal(out.summary.primary.action, 'ALLOW');
  assert.equal(out.modules[0].module, 'ZPA Access Policy', 'ZPA is the first module');
  assert.ok(out.summary.alsoBasedOn.some((c) => c.kind === 'zpa' && /on-net/i.test(c.condition)), 'On-Net segment bypass is a condition');
});

test('segment set to Always bypass and a client forwarding BYPASS rule hand off to ZIA', () => {
  const data = demo15();
  const a = sim15(data, 'portal.hospital.example');
  assert.equal(a.modules[0].verdict, 'ZPA_BYPASS');
  assert.notEqual(a.summary.primary.module, 'ZPA Access Policy');
  const b = sim15(data, 'lab.hospital.example');
  assert.equal(b.modules[0].verdict, 'ZPA_BYPASS');
  assert.match(b.modules[0].reason, /client forwarding rule "Bypass Lab Systems"/);
});

test('ZPA toggle off: ZPA not evaluated', () => {
  const out = sim15(demo15(), 'pacs.hospital.example', { port: 104, useZpa: false });
  assert.equal(out.modules[0].verdict, 'N/A');
  assert.notEqual(out.summary.primary.module, 'ZPA Access Policy');
});

test('ZIA order: ATP is evaluated before Firewall, Cloud App Control after URL Filtering', () => {
  const out = sim15(demo15(), 'files.example.org', { categories: ['MALWARE_SITE'] });
  const names = out.modules.map((m) => m.module);
  assert.ok(names.indexOf('Advanced Threat Protection') < names.indexOf('Firewall'));
  assert.ok(names.indexOf('URL Filtering') < names.indexOf('Cloud App Control'));
  assert.ok(names.indexOf('Cloud App Control') < names.indexOf('Sandbox (Behavioral Analysis)'));
  assert.ok(names.indexOf('Sandbox (Behavioral Analysis)') < names.indexOf('File Type Control'));
  assert.equal(out.summary.primary.module, 'Advanced Threat Protection');
});

test('Cloud App Control: blocks by app, notes partial restrictions', () => {
  const data = demo15();
  const a = sim15(data, 'www.dropbox.com', { cloudApp: 'DROPBOX', categories: ['FILE_HOST'] });
  assert.equal(a.summary.primary.module, 'Cloud App Control'); assert.equal(a.summary.primary.action, 'BLOCK');
  const b = sim15(data, 'chat.openai.com', { cloudApp: 'CHATGPT_AI' });
  const cac = b.modules.find((m) => m.module === 'Cloud App Control');
  assert.equal(cac.verdict, 'ALLOW'); assert.match(cac.note, /DENY_AI_ML_UPLOAD/);
});

test('PAC to a non-Zscaler proxy is a bypass; to Zscaler it is not', () => {
  const ZCC = require('../src/zcc');
  const ctx = { target: M.parseTarget('app.example.com'), port: 443, resolvedIps: ['1.2.3.4'] };
  const other = ZCC.evalPath({}, { actionType: 2, customPac: 'function FindProxyForURL(u,h){return "PROXY proxy.corp.local:8080";}' }, ctx, {}, {});
  assert.equal(other.outcome, 'BYPASS'); assert.match(other.how, /another proxy/);
  const zs = ZCC.evalPath({}, { actionType: 2, customPac: 'function FindProxyForURL(u,h){return "PROXY ${GATEWAY}:80; DIRECT";}' }, ctx, {}, {});
  assert.equal(zs.outcome, 'ZIA');
});

test('ZPA customer ID candidates come from token claims, named claims first', () => {
  const { zpaIdCandidates, jwtClaims } = require('../src/zscaler');
  const tok = 'h.' + Buffer.from(JSON.stringify({ iat: 1700000000, other: '123456789012345678', org: { zpa_customer_id: '72058304855015424' } })).toString('base64url') + '.s';
  const c = zpaIdCandidates(jwtClaims(tok));
  assert.deepEqual(c, ['72058304855015424', '123456789012345678']);
  assert.deepEqual(zpaIdCandidates(jwtClaims('not-a-jwt')), []);
});

test('ZPA segment matching: exact FQDN only, wildcard is subdomains only, most specific segment wins', () => {
  const { simulate } = require('../src/engine');
  const data = JSON.parse(JSON.stringify(require('../src/demo-snapshot.json')));
  data.zpaApps.push(
    { id: '8001', name: 'ZTH Wildcard', domainNames: ['*.zerotrusthospital.org'], segmentGroupId: '5001', bypassType: 'NEVER', tcpPortRanges: ['1', '65535'] },
    { id: '8002', name: 'ZTH PACS', domainNames: ['pacs.zerotrusthospital.org'], segmentGroupId: '5001', bypassType: 'NEVER', tcpPortRanges: ['104', '104'] },
    { id: '8003', name: 'Exact apex', domainNames: ['example.org'], segmentGroupId: '5001', bypassType: 'NEVER', tcpPortRanges: ['1', '65535'] });
  data.zpaAccessRules.unshift(
    { id: 'r1', name: 'Allow ZTH wildcard', action: 'ALLOW', ruleOrder: '1', conditions: [{ operands: [{ objectType: 'APP', rhs: '8001' }] }] },
    { id: 'r2', name: 'Deny ZTH PACS', action: 'DENY', ruleOrder: '2', conditions: [{ operands: [{ objectType: 'APP', rhs: '8002' }] }] });
  const z = (t, port) => simulate({ data }, { target: M.parseTarget(t), port: port || null, protocol: 'tcp', categories: [], resolvedIps: [], groups: [], notes: [], useZpa: true }, {}).modules[0];
  assert.equal(z('pacs.zerotrusthospital.org', 104).verdict, 'BLOCK');            // exact PACS segment beats the wildcard
  assert.equal(z('pacs.zerotrusthospital.org', 104).decidingRule.name, 'Deny ZTH PACS');
  assert.equal(z('pacs.zerotrusthospital.org', 443).decidingRule.name, 'Allow ZTH wildcard'); // PACS segment lacks 443
  assert.equal(z('ehr.zerotrusthospital.org').verdict, 'ALLOW');
  const apex = z('zerotrusthospital.org');
  assert.equal(apex.verdict, 'NOT_A_ZPA_APP');                                       // *.x is subdomains only
  assert.match(apex.note, /covers subdomains only/);
  assert.equal(z('www.example.org').verdict, 'NOT_A_ZPA_APP');                      // exact entry is not a suffix
  assert.equal(z('example.org').verdict, 'BLOCK');                                   // matched, no access rule → ZPA default deny
  const w = z('*.hospital.example');                                                 // only narrower segments → ZIA decides
  assert.equal(w.verdict, 'NOT_A_ZPA_APP'); assert.equal(w.confidence, 'conditional');
});

test('user lookup falls back to ZIdentity when ZIA /users is blocked', async () => {
  const { lookupUser } = require('../src/zscaler');
  const calls = [];
  const client = { get: async (p, q) => {
    calls.push(p);
    if (p === '/zia/api/v1/users') throw Object.assign(new Error('HTTP 403 GET /zia/api/v1/users: {"message":"Resource Access Blocked"}'), { status: 403 });
    if (p === '/ziam/admin/api/v1/users') return { records: q.loginName ? [{ id: 'u1', loginName: 'jpuglise@zerotrusthospital.org', displayName: 'J Puglise', primaryEmail: 'jpuglise@zerotrusthospital.org' }] : [] };
    if (p === '/ziam/admin/api/v1/users/u1/groups') return { records: [{ id: 'g1', name: 'Radiologists' }, { id: 'g2', name: 'All Staff' }] };
    throw new Error('unexpected ' + p);
  } };
  const u = await lookupUser(client, 'jpuglise@zerotrusthospital.org');
  assert.equal(u.source, 'ZIdentity');
  assert.deepEqual(u.groups, ['Radiologists', 'All Staff']);
  assert.match(u.ziaError, /403/);
});

test('ZPA access rules match SCIM groups and SAML email for a looked-up user', () => {
  const { simulate } = require('../src/engine');
  const data = JSON.parse(JSON.stringify(require('../src/demo-snapshot.json')));
  data.zpaSegmentGroups.push({ id: '5050', name: 'Radiology' });
  data.zpaApps.push({ id: '8010', name: 'Orthanc', domainNames: ['rad.zerotrusthospital.org'], segmentGroupId: '5050', tcpPortRanges: ['8042', '8042'] });
  data.zpaSamlAttributes.push({ id: '3009', name: 'Email_ZIdentity', samlName: 'email' });
  data.zpaAccessRules.unshift(
    { id: 'r1', name: 'Radiologists to Orthanc', action: 'ALLOW', ruleOrder: '1', conditions: [{ operands: [{ objectType: 'APP_GROUP', rhs: '5050' }] }, { operands: [{ objectType: 'SCIM_GROUP', lhs: '123', rhs: '777' }] }] },
    { id: 'r2', name: 'One user by email', action: 'ALLOW', ruleOrder: '2', conditions: [{ operands: [{ objectType: 'APP', rhs: '8010' }] }, { operands: [{ objectType: 'SAML', lhs: '3009', rhs: 'boss@zerotrusthospital.org' }] }] });
  const z = (extra) => simulate({ data }, Object.assign({ target: M.parseTarget('rad.zerotrusthospital.org'), port: 8042, protocol: 'tcp', categories: [], resolvedIps: [], groups: [], notes: [], useZpa: true, zpaScimNames: { 777: 'Radiologists' } }, extra), {}).modules[0];
  const none = z({});
  assert.equal(none.confidence, 'conditional'); assert.match(none.reason, /Allowed for users who match "Radiologists to Orthanc"/);
  assert.equal(z({ user: 'j@x', userResolved: { email: 'j@x' }, groups: ['Radiologists'] }).decidingRule.name, 'Radiologists to Orthanc');
  assert.equal(z({ user: 'boss@zerotrusthospital.org', userResolved: { email: 'boss@zerotrusthospital.org' }, groups: ['Execs'] }).decidingRule.name, 'One user by email');
  const no = z({ user: 'n@x', userResolved: { email: 'n@x' }, groups: ['Nurses'] });
  assert.equal(no.verdict, 'BLOCK'); assert.equal(no.confidence, 'definite'); assert.match(no.note, /user does not match/);
});

test('ZPA SCIM attribute (email) condition in the same OR block as a SCIM group', () => {
  const { simulate } = require('../src/engine');
  const data = JSON.parse(JSON.stringify(require('../src/demo-snapshot.json')));
  data.zpaApps.push({ id: '8020', name: 'ZTH Rad', domainNames: ['rad.zerotrusthospital.org'], segmentGroupId: '5060', tcpPortRanges: ['8042', '8042'] });
  data.zpaAccessRules.push({ id: 'h1', name: 'Hajny Admin Access', action: 'ALLOW', ruleOrder: '4', conditions: [
    { operator: 'OR', operands: [{ objectType: 'APP_GROUP', rhs: '5060' }] },
    { operator: 'OR', operands: [{ objectType: 'SCIM_GROUP', idpId: '123', rhs: '999' }, { objectType: 'SCIM', idpId: '123', lhs: '2882', rhs: 'hajny@zerotrusthospital.org' }] }] });
  const z = (extra) => simulate({ data }, Object.assign({ target: M.parseTarget('rad.zerotrusthospital.org'), port: 8042, protocol: 'tcp', categories: [], resolvedIps: [], groups: [], notes: [], useZpa: true, zpaScimNames: { 999: 'ZTH Admins' }, zpaScimAttrs: { 2882: 'emails.value' } }, extra), {}).modules[0];
  assert.equal(z({ user: 'hajny@zerotrusthospital.org', userEmail: 'hajny@zerotrusthospital.org', userResolved: { email: 'hajny@zerotrusthospital.org' }, groups: ['Admins'] }).decidingRule.name, 'Hajny Admin Access');
  assert.equal(z({ user: 'hajny@zerotrusthospital.org', userEmail: 'hajny@zerotrusthospital.org' }).decidingRule.name, 'Hajny Admin Access'); // not found, typed email still checks
  const other = z({ user: 'x@zerotrusthospital.org', userEmail: 'x@zerotrusthospital.org', userResolved: { email: 'x@zerotrusthospital.org' }, groups: ['Nurses'] });
  assert.equal(other.verdict, 'BLOCK'); assert.equal(other.confidence, 'definite');
});

test('sample directory users differ on the ZPA PACS rule', () => {
  const { simulate } = require('../src/engine');
  const data = require('../src/demo-snapshot.json');
  const names = Object.fromEntries(Object.values(data.zpaScimGroups).flat().map((g) => [String(g.id), g.name]));
  const run = (u) => simulate({ data }, { target: M.parseTarget('pacs.hospital.example'), port: 104, protocol: 'tcp', categories: [], resolvedIps: [], groups: u.groups, userResolved: u, user: u.email, notes: [], useZpa: true, zpaScimNames: names }, {}).summary.primary;
  const [dana, sam] = data.demoUsers;
  assert.equal(run(dana).action, 'ALLOW');
  assert.equal(run(sam).action, 'BLOCK');
});
