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
  // Web Insights writes the block reason as the action, e.g. "Not allowed the use of this … site",
  // "Blocked due to …", "Dropped due to failed client SSL handshake".
  if (/^(block|not allowed|denied|deny|drop|reject|quarantin)/.test(s)) return 'BLOCKED';
  if (s.startsWith('allow')) return 'ALLOWED';
  if (s.startsWith('caution')) return 'CAUTIONED';
  if (s.startsWith('isolat')) return 'ISOLATED';
  return s.toUpperCase();
}

// Time: epoch seconds/ms, ISO with zone, or zone-less text (ctime "Fri Oct 30 14:02:11 2026",
// "October 30, 2026 2:02:11 PM", "2026-10-30 14:02:11"). Zone-less text is wall-clock in opts.tz (default Eastern).
const { zonedToUtc, DEFAULT_TZ } = require('./tz');
// Offsets (minutes east of UTC) for zone abbreviations seen in exports. Ambiguous ones (IST, CST-China) are left out
// on purpose: such values fall back to opts.tz.
const ABBR = { UTC: 0, GMT: 0, Z: 0, EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420,
  AKST: -540, AKDT: -480, HST: -600, WET: 0, WEST: 60, BST: 60, CET: 60, CEST: 120, EET: 120, EEST: 180, JST: 540, AEST: 600, AEDT: 660 };
function parseTime(v, epoch, tz = DEFAULT_TZ) {
  const e = clean(epoch);
  if (e && /^\d{9,13}$/.test(e)) { const n = Number(e); return { iso: new Date(n < 1e12 ? n * 1000 : n).toISOString(), tzSource: 'epoch' }; }
  const s = clean(v); if (!s) return { iso: null, tzSource: null };
  if (/^\d{9,13}$/.test(s)) return parseTime(null, s, tz);
  // Trailing zone abbreviation (Web Insights: "November 3, 2026 5:50:15 AM PST"): fixed offset from the abbreviation.
  const ab = /^(.*\S)\s+([A-Z]{2,5})$/.exec(s);
  if (ab && ABBR[ab[2]] != null) {
    const w = new Date(ab[1].replace(/^(mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+/i, ''));
    if (isNaN(w)) return { iso: null, tzSource: null };
    const ms = Date.UTC(w.getFullYear(), w.getMonth(), w.getDate(), w.getHours(), w.getMinutes(), w.getSeconds()) - ABBR[ab[2]] * 60000;
    return { iso: new Date(ms).toISOString(), tzSource: ab[2] };
  }
  if (/(\dz|[+-]\d{2}:?\d{2})$/i.test(s)) { const d = new Date(s); return { iso: isNaN(d) ? null : d.toISOString(), tzSource: 'explicit' }; }
  // Parse wall-clock fields; the box zone does not matter because only the fields are read back.
  const bare = ab && !/^(AM|PM)$/.test(ab[2]) ? ab[1] : s; // unknown abbreviation: ignore it, use opts.tz
  const d = new Date(bare.replace(/^(mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+/i, '').replace(/^(\d{4}-\d{2}-\d{2})[ T]/, '$1T'));
  if (isNaN(d)) return { iso: null, tzSource: null };
  const ms = zonedToUtc(d.getFullYear(), d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds(), tz);
  return { iso: new Date(ms).toISOString(), tzSource: tz };
}

function record(f, opts = {}) {
  const t = parseTime(f.time, f.epochtime, opts.tz || DEFAULT_TZ);
  const url = clean(f.url);
  const w = Number(f.weight);
  return {
    time: t.iso, timeRaw: clean(f.time), tzSource: t.tzSource,
    user: (clean(f.user) || '').toLowerCase() || null,
    dept: clean(f.dept), location: clean(f.location),
    url, host: (clean(f.host) || '').toLowerCase() || hostOf(url),
    urlcat: clean(f.urlcat), action: normAction(f.action),
    ruleType: clean(f.ruleType), blockedBy: clean(f.blockedBy) || clean(f.blockedPolicyType), blockedPolicyType: clean(f.blockedPolicyType), urlRule: clean(f.urlRule),
    urlSuperCat: clean(f.urlSuperCat), cloudApp: clean(f.cloudApp),
    clientIp: clean(f.clientIp),
    weight: Number.isFinite(w) && w > 0 ? w : 1,
  };
}

module.exports = { record, hostOf, normAction, parseTime, clean };
