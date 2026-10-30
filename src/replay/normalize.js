'use strict';
// Common replay record: { time, user, dept, location, url, host, urlcat, action, ruleType, blockedBy, urlRule, clientIp, weight }
const NONE = new Set(['', 'none', 'n/a', 'na', '-', 'null']);
const clean = (v) => { if (v == null) return null; const s = String(v).trim(); return NONE.has(s.toLowerCase()) ? null : s; };

function hostOf(url) {
  const s = clean(url); if (!s) return null;
  const m = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').match(/^([^/?#:]+)/);
  return m ? m[1].toLowerCase() : null;
}

function normAction(a) {
  const s = (clean(a) || '').toLowerCase();
  if (!s) return null;
  if (s.startsWith('block') || s === 'denied' || s === 'deny') return 'BLOCKED';
  if (s.startsWith('allow')) return 'ALLOWED';
  if (s.startsWith('caution')) return 'CAUTIONED';
  if (s.startsWith('isolat')) return 'ISOLATED';
  return s.toUpperCase();
}

// Time: epoch seconds/ms, ISO, ctime ("Fri Oct 30 14:02:11 2026"), or "October 30, 2026 2:02:11 PM".
// Zone is unknown for the text formats, so they are parsed as box-local and flagged.
function parseTime(v, epoch) {
  const e = clean(epoch);
  if (e && /^\d{9,13}$/.test(e)) { const n = Number(e); return { iso: new Date(n < 1e12 ? n * 1000 : n).toISOString(), tzKnown: true }; }
  const s = clean(v); if (!s) return { iso: null, tzKnown: false };
  if (/^\d{9,13}$/.test(s)) return parseTime(null, s);
  const tzKnown = /(z|[+-]\d{2}:?\d{2})$/i.test(s);
  const d = new Date(s.replace(/^(mon|tue|wed|thu|fri|sat|sun)\s+/i, ''));
  return { iso: isNaN(d) ? null : d.toISOString(), tzKnown };
}

function record(f) {
  const t = parseTime(f.time, f.epochtime);
  const url = clean(f.url);
  const w = Number(f.weight);
  return {
    time: t.iso, timeRaw: clean(f.time), tzKnown: t.tzKnown,
    user: (clean(f.user) || '').toLowerCase() || null,
    dept: clean(f.dept), location: clean(f.location),
    url, host: (clean(f.host) || '').toLowerCase() || hostOf(url),
    urlcat: clean(f.urlcat), action: normAction(f.action),
    ruleType: clean(f.ruleType), blockedBy: clean(f.blockedBy), urlRule: clean(f.urlRule),
    clientIp: clean(f.clientIp),
    weight: Number.isFinite(w) && w > 0 ? w : 1,
  };
}

module.exports = { record, hostOf, normAction, parseTime, clean };
