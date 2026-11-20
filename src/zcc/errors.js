'use strict';
// From ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission;
// ported to CommonJS for the Zscaler Policy Troubleshooting Toolkit.
// Known ZPA error codes and generic ERR/WAR grouping for triage.
//
// Descriptions are written from the client's perspective and are meant as a
// starting point for troubleshooting, not as authoritative documentation.

const KNOWN = {
  BRK_MT_SETUP_FAIL_NO_POLICY_FOUND: {
    title: 'No access policy matched',
    hint: 'The broker found no Access Policy rule allowing this user/device to reach the app, so the default deny applied. Check Access Policy rules, the user\'s SAML/SCIM attributes and posture/trusted-network criteria.',
    category: 'policy',
  },
  BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY: {
    title: 'Blocked by access policy',
    hint: 'An Access Policy rule with a Block action matched this request.',
    category: 'policy',
  },
  BRK_MT_SETUP_FAIL_SAML_EXPIRED: { title: 'SAML assertion expired', hint: 'The user needs to re-authenticate to ZPA.', category: 'auth' },
  BRK_MT_SETUP_FAIL_REAUTH_EXPIRED: { title: 'Re-authentication timeout reached', hint: 'The session exceeded the re-auth timeout of the matching policy; the user must log in again.', category: 'auth' },
  BRK_MT_SETUP_FAIL_APP_NOT_FOUND: {
    title: 'App not found',
    hint: 'The requested name/IP did not match any enabled application segment for this customer.',
    category: 'config',
  },
  BRK_MT_SETUP_FAIL_CANNOT_SEND_TO_DISPATCHER: { title: 'Broker could not reach dispatcher', hint: 'Transient ZPA cloud-side issue. Retry; escalate to Zscaler if persistent.', category: 'cloud' },
  BRK_MT_SETUP_TIMEOUT: {
    title: 'mTunnel setup timed out',
    hint: 'No App Connector answered in time. Check connector group health, connector-to-app reachability and server group assignment.',
    category: 'connector',
  },
  BRK_MT_CLOSED_FROM_ASSISTANT: {
    title: 'Closed by App Connector',
    hint: 'The App Connector side closed the mTunnel. Usually a normal close by the server; investigate only if paired with user-visible failures.',
    category: 'normal',
  },
  BRK_MT_CLOSED_FROM_CLIENT: { title: 'Closed by client', hint: 'Normal close initiated by Client Connector.', category: 'normal' },
  BRK_MT_TERMINATED: { title: 'mTunnel terminated', hint: 'The broker terminated the mTunnel.', category: 'normal' },
  APP_NOT_REACHABLE: {
    title: 'App not reachable from App Connector',
    hint: 'The connector could not connect to the application server (refused, no route, DNS failure or timeout from the connector). For UDP this is common for probes/discovery traffic. Test reachability from the connector host.',
    category: 'connector',
  },
  ZPN_ERR_DNS_CHECK_NOT_FOUND: {
    title: 'DNS check: name not found',
    hint: 'The broker reported no A/AAAA record for this name in any app segment / connector DNS. Expected for names that are not ZPA apps (e.g. DNS-SD lookups).',
    category: 'dns',
  },
  FQDN_EMPTY: { title: 'Client FQDN empty', hint: 'Client-to-client registration skipped; benign unless C2C is in use.', category: 'normal' },
};

const NORMAL_CODES = new Set(['BRK_MT_CLOSED_FROM_ASSISTANT', 'BRK_MT_CLOSED_FROM_CLIENT', 'BRK_MT_TERMINATED']);

function describeError(code) {
  const k = KNOWN[code];
  if (k) return { ...k, known: true };
  let category = 'unknown';
  if (/POLICY/.test(code)) category = 'policy';
  else if (/SAML|AUTH|REAUTH/.test(code)) category = 'auth';
  else if (/TIMEOUT|CONNECTOR|ASSISTANT/.test(code)) category = 'connector';
  else if (/DNS/.test(code)) category = 'dns';
  return { title: code.replace(/_/g, ' ').toLowerCase(), hint: '', category, known: false };
}

/** Whether an mtunnel_end error code means the connection failed (vs. a normal close). */
function isFailureCode(code) {
  if (!code) return false;
  if (NORMAL_CODES.has(code)) return false;
  return /FAIL|NOT_REACHABLE|TIMEOUT|REJECT|DENIED|ERR|EXPIRED|UNAVAILABLE|NOT_AVAILABLE/.test(code);
}

// Normalize variable parts so similar messages group together.
function signature(msg) {
  return msg
    .split('\n')[0]
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<uuid>')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/g, '<ip>')
    .replace(/0x[0-9a-f]+/gi, '<hex>')
    .replace(/"[^"]{0,200}"/g, '"…"')
    .replace(/\b\d+(\.\d+)?\b/g, '<n>')
    .replace(/\s+/g, ' ')
    .slice(0, 180);
}

/** Group ERR/WAR entries into signatures with counts and first/last seen. */
function triage(tl, { levels = ['ERR', 'WAR'] } = {}) {
  const want = new Set(levels);
  const groups = new Map();
  for (let i = 0; i < tl.length; i++) {
    const lvl = tl.level(i);
    if (!want.has(lvl)) continue;
    const msg = tl.msg(i);
    const comp = tl.comp(i);
    const sg = signature(msg);
    const key = `${comp}|${lvl}|${sg}`;
    let g = groups.get(key);
    if (!g) {
      g = { sig: sg, comp, lvl, count: 0, first: tl.ts[i], last: tl.ts[i], sample: i, sampleMsg: msg.slice(0, 600), zpa: tl.isZpa(i), zia: false };
      groups.set(key, g);
    }
    g.count++;
    g.last = tl.ts[i];
    if (tl.isZia(i)) g.zia = true;
  }
  return [...groups.values()].sort((a, b) => (a.lvl === b.lvl ? b.count - a.count : a.lvl === 'ERR' ? -1 : 1));
}

module.exports = { describeError, isFailureCode, signature, triage };
