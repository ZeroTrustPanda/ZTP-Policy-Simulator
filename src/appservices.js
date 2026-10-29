'use strict';
// Zscaler-managed destination sets used by the predefined "One Click" rules (appServiceGroups / appServices).
// The API returns only the group name, never its members, so the simulator matches them by:
//   - hostnames: the services' published domains (below)
//   - IPs: published ranges loaded with the policy (Microsoft 365 endpoints web service) and the Client Connector
//     IP-based app definitions in the tenant (M365, Microsoft Teams, ZOOMMEETING, …)
// When neither can settle an IP, the criterion is "unknown" — never "matches everything".
const M = require('./matchers');
const lc = (s) => String(s == null ? '' : s).toLowerCase();
const arr = (x) => (Array.isArray(x) ? x : x == null || x === '' ? [] : [x]);

const DOMAINS = {
  OFFICE365: ['office.com', 'office.net', 'office365.com', 'microsoftonline.com', 'microsoftonline-p.com', 'sharepoint.com', 'sharepointonline.com', 'outlook.com', 'outlook.office.com',
    'outlook.office365.com', 'lync.com', 'teams.microsoft.com', 'skype.com', 'onmicrosoft.com', 'msocdn.com', 'officeapps.live.com', 'onedrive.com', 'svc.ms', 'protection.outlook.com',
    'mail.protection.outlook.com', 'login.microsoft.com', 'login.windows.net', 'graph.microsoft.com', 'cloud.microsoft', 'static.microsoft', 'usercontent.microsoft'],
  ZOOM: ['zoom.us', 'zoom.com', 'zoomgov.com', 'zoom.com.cn'],
  WEBEX: ['webex.com', 'wbx2.com', 'ciscospark.com', 'webexcontent.com'],
  RINGCENTRAL: ['ringcentral.com', 'ringcentral.biz', 'glip.com', 'ringcentral.co.uk'],
  LOGMEIN: ['logmein.com', 'goto.com', 'gotomeeting.com', 'gotowebinar.com', 'logme.in', 'getgo.com', 'gotoconnect.com', 'jive.com'],
  TALK_DESK: ['talkdesk.com', 'talkdeskapp.com', 'talkdeskid.com'],
  ZSCALER_CLOUD_ENDPOINTS: ['zscaler.net', 'zscalerone.net', 'zscalertwo.net', 'zscalerthree.net', 'zscloud.net', 'zscalerbeta.net', 'zscalergov.net', 'zscalerten.net', 'zscaler.com', 'zpath.net', 'zscalerfeed.net', 'zsdemo.net'],
};
// Client Connector IP-based app definitions (webAppService) that carry the same service's IP ranges.
const ZCC_APP = { OFFICE365: /^(m365|microsoft (365|teams|sharepoint|exchange)|office ?365)/i, ZOOM: /zoom/i, WEBEX: /webex/i, RINGCENTRAL: /ringcentral/i, LOGMEIN: /logmein|goto/i, TALK_DESK: /talk ?desk/i };

function zccRanges(data, group) {
  const re = ZCC_APP[group]; if (!re) return [];
  const out = [];
  for (const svc of arr(data.zccAppServices)) {
    if (!re.test(String(svc.appName || svc.name || ''))) continue;
    for (const b of arr(svc.appDataBlob)) for (const s of String(b.ipaddr || '').split(/[\s,;]+/)) if (M.parseIpRange(s)) out.push(s);
    for (const s of String(svc.zappDataBlob || '').split(/[\s,;]+/)) if (M.parseIpRange(s)) out.push(s);
  }
  return [...new Set(out)];
}
function rangesFor(data, group) {
  const r = [...zccRanges(data, group)];
  if (group === 'OFFICE365' && data.m365Endpoints) r.push(...arr(data.m365Endpoints.ips).filter((x) => M.parseIpRange(x)));
  return r;
}
function domainsFor(data, group) {
  const d = [...(DOMAINS[group] || [])];
  if (group === 'OFFICE365' && data.m365Endpoints) d.push(...arr(data.m365Endpoints.urls));
  return d;
}

// Criterion for appServiceGroups / appServices on a rule.
function critAppServices(rule, ctx, data) {
  const groups = [...arr(rule.appServiceGroups), ...arr(rule.appServices)].map((g) => String((g && (g.name || g.id)) || g));
  if (!groups.length) return null;
  const list = groups.join(', ');
  const t = ctx.target;
  if (!t) return { field: 'app service group', status: 'unknown', kind: 'input', scope: `App service group ${list}`, detail: `rule applies only to ${list} destinations — no destination entered` };
  const known = groups.filter((g) => DOMAINS[g.toUpperCase()]);
  if (!t.isIp) {
    for (const g of known) {
      const r = M.domainInList(t, domainsFor(data || {}, g.toUpperCase()).map((x) => (/^\*?\./.test(x) ? x : '.' + x)).concat(domainsFor(data || {}, g.toUpperCase())));
      if (r.rel === 'match') return { field: 'app service group', status: 'match', detail: `${t.host} is a ${g} destination (${r.entry})` };
    }
  }
  const ips = t.isIp ? [t.host] : ctx.resolvedIps || [];
  let checked = 0;
  for (const g of groups) {
    const ranges = rangesFor(data || {}, g.toUpperCase());
    if (!ranges.length) continue;
    checked++;
    for (const ip of ips) { const r = M.ipInList(ip, ranges); if (r.rel === 'match') return { field: 'app service group', status: 'match', detail: `${ip} is in ${g} (${r.entry})` }; }
  }
  if (!t.isIp && known.length === groups.length) return { field: 'app service group', status: 'nomatch', detail: `${t.host} is not a ${list} destination` };
  if (ips.length && checked === groups.length) return { field: 'app service group', status: 'nomatch', detail: `${ips[0]} is not in the ${list} IP ranges` };
  const unknownGroups = groups.filter((g, i) => !rangesFor(data || {}, g.toUpperCase()).length);
  return { field: 'app service group', status: 'unknown', kind: 'input', scope: `App service group ${unknownGroups.join(', ') || list}`,
    detail: `rule applies only to ${list} destinations (Zscaler-managed); ${t.isIp ? `the IP ranges for ${unknownGroups.join(', ')} aren't available, so ${t.host} can't be checked` : 'not checked'}` };
}

module.exports = { critAppServices, DOMAINS, rangesFor };
