'use strict';
// Workload traffic: Cloud Connector / Branch Connector.
// A workload is identified by its source IP and by its cloud tags (ATTR, VM, ENI, VPC, SUBNET). Workload groups
// (ZIA and Cloud & Branch Connector share them) are tag expressions; ZIA rules and connector forwarding rules can
// match on them.

const lc = (s) => String(s == null ? '' : s).toLowerCase();
const arr = (x) => (Array.isArray(x) ? x : x == null || x === '' ? [] : [x]);

const TAG_TYPES = ['ATTR', 'VM', 'ENI', 'VPC', 'SUBNET'];

// "VPC:Vpc-id=vpc-123, Env=prod; ENI:Name=web" → [{type:'VPC', key:'Vpc-id', value:'vpc-123'}, {type:null, key:'Env', ...}, ...]
function parseTags(input) {
  if (Array.isArray(input)) return input.filter((t) => t && t.key).map((t) => ({ type: t.type ? String(t.type).toUpperCase() : null, key: String(t.key).trim(), value: String(t.value == null ? '' : t.value).trim() }));
  const out = [];
  for (const raw of String(input || '').split(/[\n,;]+/)) {
    const s = raw.trim(); if (!s) continue;
    let type = null, rest = s;
    const m = s.match(/^([A-Za-z]+)\s*:\s*(.+)$/);
    if (m && TAG_TYPES.includes(m[1].toUpperCase())) { type = m[1].toUpperCase(); rest = m[2]; }
    const eq = rest.indexOf('=');
    const key = (eq >= 0 ? rest.slice(0, eq) : rest).trim();
    const value = eq >= 0 ? rest.slice(eq + 1).trim() : '';
    if (key) out.push({ type, key, value });
  }
  return out;
}

const tagLabel = (t) => `${t.type ? t.type + ':' : ''}${t.key}${t.value !== '' ? '=' + t.value : ''}`;

function tagHit(want, type, tags) {
  return tags.some((t) => (!t.type || !type || t.type === type) && lc(t.key) === lc(want.key) && (want.value === '' || want.value == null || lc(t.value) === lc(want.value)));
}

// One workload group against a workload's tags → {status: match|nomatch|unknown, why}
function evalGroup(g, tags) {
  const conts = arr(g && g.expressionJson && g.expressionJson.expressionContainers);
  if (!conts.length) return { status: 'unknown', why: `workload group "${g && g.name}" has no readable tag expression` };
  if (!tags.length) return { status: 'unknown', why: 'no workload tags entered' };
  const results = conts.map((c) => {
    const tc = c.tagContainer || {};
    const want = arr(tc.tags);
    const or = lc(tc.operator) === 'or';
    const hits = want.map((w) => tagHit(w, c.tagType ? String(c.tagType).toUpperCase() : null, tags));
    const ok = want.length ? (or ? hits.some(Boolean) : hits.every(Boolean)) : false;
    return { ok, text: `${c.tagType || 'tag'} ${want.map((w) => `${w.key}=${w.value}`).join(or ? ' or ' : ' and ')}` };
  });
  // The containers' operator joins them; Zscaler uses one operator for the whole expression.
  const anyOr = conts.some((c) => lc(c.operator) === 'or');
  const ok = anyOr ? results.some((r) => r.ok) : results.every((r) => r.ok);
  return { status: ok ? 'match' : 'nomatch', why: results.map((r) => `${r.ok ? '✓' : '✗'} ${r.text}`).join(anyOr ? ' OR ' : ' AND ') };
}

// All workload groups (ZIA + connector lists, merged by id) and the workload's membership in each.
function allGroups(data) {
  const byId = new Map();
  for (const g of [...arr(data.ztwWorkloadGroups), ...arr(data.workloadGroups)]) if (g && g.id != null && !byId.has(String(g.id))) byId.set(String(g.id), g);
  return [...byId.values()];
}
function membership(data, ctx) {
  const tags = parseTags(ctx.workloadTags);
  const picked = arr(ctx.workloadGroups).map(String);
  const groups = allGroups(data).map((g) => {
    if (picked.some((p) => p === String(g.id) || lc(p) === lc(g.name))) return { id: g.id, name: g.name, status: 'match', why: 'picked' };
    const r = evalGroup(g, tags);
    return { id: g.id, name: g.name, status: picked.length && !tags.length ? 'nomatch' : r.status, why: picked.length && !tags.length ? 'not picked' : r.why };
  });
  // Picked names that aren't in the loaded lists still count (rules reference them by id and name).
  for (const p of picked) if (!groups.some((g) => String(g.id) === p || lc(g.name) === lc(p))) groups.push({ id: null, name: p, status: 'match', why: 'picked' });
  return { tags, groups, known: !!(tags.length || picked.length) };
}

// Rule criterion: workloadGroups (ZIA rules) or srcWorkloadGroups (connector forwarding rules).
function critWorkload(rule, ctx, key = 'workloadGroups') {
  const want = arr(rule[key]).filter((x) => x && lc(x.name || x) !== 'any');
  if (!want.length) return null;
  const list = want.map((w) => w.name || String(w.id || w)).slice(0, 4).join(', ');
  if (ctx.source === 'device') return { field: 'workload group', status: 'nomatch', detail: `rule applies to workload group ${list}; this is user-device traffic, not a workload` };
  const mem = ctx.workload;
  if (!mem || !mem.known) return { field: 'workload group', status: 'unknown', kind: 'workload', scope: `Workload group ${list}`, detail: `rule applies to workload group ${list} — enter the workload's tags or pick its group` };
  const hit = mem.groups.find((g) => g.status === 'match' && want.some((w) => (w.id != null && String(w.id) === String(g.id)) || lc(w.name) === lc(g.name)));
  if (hit) return { field: 'workload group', status: 'match', detail: `workload is in ${hit.name}${hit.why && hit.why !== 'picked' ? ` (${hit.why})` : ''}` };
  const unk = mem.groups.find((g) => g.status === 'unknown' && want.some((w) => String(w.id) === String(g.id) || lc(w.name) === lc(g.name)));
  if (unk) return { field: 'workload group', status: 'unknown', kind: 'workload', scope: `Workload group ${unk.name}`, detail: unk.why };
  return { field: 'workload group', status: 'nomatch', detail: `workload is not in ${list}` };
}

// Connector group picked by name or id → the group, plus its location (connector traffic lands in ZIA at that location).
function findEcGroup(data, name) {
  if (!name) return null;
  return arr(data.ztwEcGroups).find((g) => String(g.id) === String(name) || lc(g.name) === lc(name)) || null;
}

module.exports = { TAG_TYPES, parseTags, tagLabel, evalGroup, allGroups, membership, critWorkload, findEcGroup };
