'use strict';
// Decision path: a flowchart of how ZIA/ZPA evaluated one simulated transaction, drawn as a self-contained SVG
// (no libraries, works offline in the standalone build, exportable as SVG/PNG).
// Input: the /api/simulate result (modules in evaluation order + summary). Nothing is recomputed here.
(function (root) {
  const COL = {
    green: ['#065f46', '#10b981', '#d1fae5'], red: ['#7f1d1d', '#ef4444', '#fee2e2'], amber: ['#78350f', '#f59e0b', '#fef3c7'],
    blue: ['#1e3a8a', '#3b82f6', '#dbeafe'], purple: ['#4c1d95', '#8b5cf6', '#ede9fe'], cyan: ['#164e63', '#06b6d4', '#cffafe'],
    slate: ['#1f2937', '#64748b', '#e2e8f0'], grey: ['#151c2c', '#334155', '#8896b3'],
  };
  const VERDICT = {
    ALLOW: ['green', 'Allow'], BLOCK: ['red', 'Block'], CONDITIONAL_BLOCK: ['red', 'Block (conditional)'], CAUTION: ['amber', 'Caution'], ISOLATE: ['cyan', 'Isolate'],
    DECRYPTED: ['blue', 'Inspected (decrypted)'], NOT_DECRYPTED: ['amber', 'Not inspected'], DEFAULT: ['slate', 'Default'], SCAN: ['blue', 'Scan in sandbox'], QUARANTINE: ['amber', 'Quarantine first download'],
    BYPASS: ['slate', 'Bypassed'], ZIA: ['green', 'To Zscaler'], ZPA: ['purple', 'To ZPA'], DIRECT: ['slate', 'Direct'], NOT_A_ZPA_APP: ['slate', 'Not a ZPA app'],
    REDIR_ZPA: ['purple', 'Resolve via ZPA'], 'N/A': ['grey', 'Not applied'], NOT_EVALUATED: ['red', 'Not evaluated'],
  };
  let UID = 0; // marker ids must be unique per SVG: a hidden copy's markers don't render in the visible one
  const ACTION_COL = { BLOCK: 'red', ALLOW: 'green', CAUTION: 'amber', ISOLATE: 'cyan', BYPASS: 'slate' };
  const SHORT = { 'Sandbox (Behavioral Analysis)': 'Sandbox', 'Advanced Threat Protection': 'Advanced Threat Protection', 'Data Loss Prevention': 'Data Loss Prevention' };
  const x = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const cut = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  const vOf = (m) => VERDICT[m.verdict] || [ACTION_COL[m.verdict] || 'slate', String(m.verdict || '').replace(/_/g, ' ').toLowerCase()];

  // One step per module, in evaluation order. Steps that didn't apply are collapsed into a single grey line.
  function steps(res) {
    const s = res.summary || {}, out = [];
    const decMod = s.primary && s.primary.module;
    const stopped = ['BLOCKED', 'ISOLATED', 'BYPASSED'].includes(s.overall);
    let reachedDecider = false, skipped = [];
    const flush = () => { if (skipped.length) { out.push({ kind: 'skipped', names: skipped }); skipped = []; } };
    // Traffic is forwarded (Client Connector / PAC / connector) before any policy sees it, so forwarding comes first.
    const mods = (res.modules || []).slice().sort((a, b) => (/^Forwarding|^Connector forwarding/.test(b.module) ? 1 : 0) - (/^Forwarding|^Connector forwarding/.test(a.module) ? 1 : 0));
    for (const m of mods) {
      const na = m.verdict === 'N/A';
      const isDec = m.module === decMod;
      if (na && !isDec) { skipped.push({ name: SHORT[m.module] || m.module, why: m.reason }); continue; }
      flush();
      const [col, word] = vOf(m);
      out.push({ kind: 'module', module: m.module, name: SHORT[m.module] || m.module, col, word,
        rule: m.decidingRule ? m.decidingRule.name : null, reason: m.reason, conf: m.confidence, isDec,
        notReached: stopped && reachedDecider, extra: (m.alsoMatched || []).length });
      if (isDec) reachedDecider = true;
    }
    flush();
    return out;
  }

  // Layout + SVG
  function svg(res, opts = {}) {
    const u = 'd' + (++UID);
    const s = res.summary || {}, c = res.context || {}, p = s.primary || {};
    const st = steps(res);
    const conds = (s.alsoBasedOn || []).filter((k) => !(k.kind === 'zpa' && /check fails/.test(k.condition)));
    // Compact: the branch column only takes space when there are conditions to draw.
    const LX = 16, NW = 330, GAP = 34, RW = 214, RX = LX + NW + GAP;
    const W = conds.length ? RX + RW + 12 : LX + NW + LX;
    const byMod = new Map();
    // Attach each condition to the step it belongs to; anything that names no drawn step (e.g. "Client Connector
    // forwarding") goes to the forwarding step for Client Connector conditions, else to the deciding step.
    const drawn = st.filter((q) => q.kind === 'module');
    const home = (k) => {
      const exact = drawn.find((q) => q.module === k.module);
      if (exact) return exact.module;
      if (k.kind === 'zcc' || /forwarding|connector/i.test(k.module || '')) { const f = drawn.find((q) => /^Forwarding|^Connector forwarding/.test(q.module)); if (f) return f.module; }
      const d = drawn.find((q) => q.isDec) || drawn[drawn.length - 1];
      return d ? d.module : '';
    };
    for (const k of conds) { const key = home(k); if (!byMod.has(key)) byMod.set(key, []); byMod.get(key).push(k); }
    const parts = [], defs = [];
    let y = 20;
    const arrow = (y1, y2, faded) => parts.push(`<line x1="${LX + NW / 2}" y1="${y1}" x2="${LX + NW / 2}" y2="${y2 - 6}" stroke="${faded ? '#334155' : '#5c6b8a'}" stroke-width="2" marker-end="url(#${u}ah${faded ? 'f' : ''})"${faded ? ' stroke-dasharray="4 4"' : ''}/>`);

    // Start: the transaction
    const who = c.user || ((c.groups || []).length ? 'group ' + c.groups.join(', ') : c.source === 'workload' ? 'workload ' + (c.sourceIp || '') : 'any user');
    const dest = c.target ? (c.target.raw || c.target.host) : 'any destination';
    const port = c.port != null ? `${String(c.protocol || 'tcp').toUpperCase()}/${c.port}` : '';
    parts.push(`<rect x="${LX}" y="${y}" width="${NW}" height="52" rx="26" fill="#111827" stroke="#3b82f6" stroke-width="1.5"/>
      <text x="${LX + 20}" y="${y + 22}" class="t1">${x(cut(dest, 30))}${port ? `  ·  ${x(port)}` : ''}</text>
      <text x="${LX + 20}" y="${y + 40}" class="t3">${x(cut([who, (c.categories || []).slice(0, 2).join(', '), c.cloudApp].filter(Boolean).join('  ·  '), 46))}</text>`);
    y += 52;
    let hiddenMore = 0;
    for (const sp of st) {
      const faded = sp.kind === 'module' && sp.notReached;
      if (sp.kind === 'skipped') {
        const h = 30;
        arrow(y, y + 18, false); y += 18;
        const names = sp.names.map((n) => n.name).join(', ');
        parts.push(`<g><title>${x(sp.names.map((n) => `${n.name}: ${n.why || 'not applied'}`).join('\n'))}</title><rect x="${LX + 30}" y="${y}" width="${NW - 60}" height="${h}" rx="6" fill="none" stroke="#334155" stroke-dasharray="4 3"/>
          <text x="${LX + 44}" y="${y + 19}" class="t3">Skipped: ${x(cut(names, 36))}</text></g>`);
        y += h; continue;
      }
      const [bg, fg, tx] = COL[sp.col] || COL.slate;
      const h = sp.isDec ? 68 : 54;
      arrow(y, y + 20, faded); y += 20;
      const op = faded ? ' opacity="0.38"' : '';
      parts.push(`<g${op} data-module="${x(sp.module)}" class="dp-node" style="cursor:pointer"><title>${x(sp.reason || '')}</title>
        <rect x="${LX}" y="${y}" width="${NW}" height="${h}" rx="10" fill="${bg}" fill-opacity="${sp.col === 'grey' ? 1 : 0.55}" stroke="${fg}" stroke-width="${sp.isDec ? 3 : 1.5}"/>
        <rect x="${LX}" y="${y}" width="6" height="${h}" rx="3" fill="${fg}"/>
        <text x="${LX + 18}" y="${y + 21}" class="t1">${x(cut(sp.name, sp.word.length > 16 ? 20 : 30))}</text>
        <text x="${LX + NW - 14}" y="${y + 21}" class="t2" text-anchor="end" fill="${tx}">${x(sp.word)}</text>
        <text x="${LX + 18}" y="${y + 40}" class="t3">${x(cut(sp.rule ? `rule "${sp.rule}"` : sp.reason, faded ? 32 : 46))}</text>
        ${sp.isDec ? `<text x="${LX + 18}" y="${y + 58}" class="tdec" fill="${fg}">▲ DECIDES THE RESULT${sp.conf && sp.conf !== 'definite' ? ' · conditional' : ''}${sp.extra ? ` · ${sp.extra} more rule(s) also match` : ''}</text>` : ''}
        ${faded ? `<text x="${LX + NW - 14}" y="${y + 40}" class="t3" text-anchor="end">not reached</text>` : ''}</g>`);
      // conditions that would change the result, branching off this module
      const ks = byMod.get(sp.module) || [];
      const show = ks.slice(0, 2); hiddenMore += Math.max(0, ks.length - 2);
      show.forEach((k, i) => {
        const by = y + (i * 44) - (show.length > 1 ? 12 : 0) + (show.length === 1 ? (h - 40) / 2 : 0), [kbg, kfg, ktx] = COL[ACTION_COL[k.action] || 'slate'];
        parts.push(`<path d="M ${LX + NW} ${y + h / 2} C ${LX + NW + 20} ${y + h / 2}, ${RX - 20} ${by + 20}, ${RX} ${by + 20}" fill="none" stroke="${kfg}" stroke-width="1.5" stroke-dasharray="5 4" opacity="0.8"/>
          <g><title>${x(`${k.condition} → ${k.action}${k.rule ? ` (rule "${k.rule}")` : ''}`)}</title><rect x="${RX}" y="${by}" width="${RW}" height="40" rx="8" fill="${kbg}" fill-opacity="0.3" stroke="${kfg}" stroke-dasharray="5 4"/>
          <text x="${RX + 10}" y="${by + 16}" class="t4">${x(cut('If ' + String(k.condition).replace(/^If /i, ''), 32))}</text>
          <text x="${RX + 10}" y="${by + 32}" class="t4" fill="${ktx}">→ ${x(k.action)}${k.rule ? x(cut(` · "${k.rule}"`, 22)) : ''}</text></g>`);
      });
      y += Math.max(h, show.length * 44 - 4);
    }
    // Result
    const [rbg, rfg, rtx] = COL[ACTION_COL[p.action] || 'slate'];
    arrow(y, y + 22, false); y += 22;
    const overall = String(s.overall || p.action || '').replace(/_/g, ' ');
    parts.push(`<rect x="${LX}" y="${y}" width="${NW}" height="62" rx="12" fill="${rbg}" stroke="${rfg}" stroke-width="3"/>
      <text x="${LX + 20}" y="${y + 27}" class="tres" fill="${rtx}">${x(overall)}</text>
      <text x="${LX + 20}" y="${y + 47}" class="t3" fill="${rtx}">${x(cut(p.rule ? `${p.module} · rule "${p.rule}"` : `${p.module || ''} · ${p.reason || 'default action'}`, 46))}</text>`);
    y += 62;
    if (hiddenMore) parts.push(`<text x="${RX}" y="${y - 8}" class="t3">+${hiddenMore} more condition(s) — see "Would change if…"</text>`);
    const H = y + 16;
    defs.push(`<marker id="${u}ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#5c6b8a"/></marker>
      <marker id="${u}ahf" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#334155"/></marker>`);
    const style = `<style>text{font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',sans-serif}.t1{font-size:14px;font-weight:600;fill:#e8ecf4}.t2{font-size:13px;font-weight:600}.t3{font-size:12px;fill:#8896b3}.t4{font-size:11.5px;fill:#cbd5e1}.tdec{font-size:10.5px;font-weight:700;letter-spacing:.6px}.tres{font-size:20px;font-weight:700;letter-spacing:.5px}</style>`;
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${opts.width || W}" role="img" aria-label="Decision path: ${x(overall)}">${style}<defs>${defs.join('')}</defs><rect width="${W}" height="${H}" fill="#0f1629" rx="12"/>${parts.join('')}</svg>`;
  }

  // ---------- Network path: where the traffic physically goes (device → Zscaler → internet / App Connector) ----------
  function route(res) {
    const s = res.summary || {}, c = res.context || {}, mods = res.modules || [];
    const by = (re) => mods.find((m) => re.test(m.module));
    const fwd = by(/^Forwarding/), zpa = by(/^ZPA Access Policy$/), conn = mods.find((m) => m.connector);
    const p = s.primary || {};
    const zpaApp = zpa && (zpa.matchedSegments || []).length && !['NOT_A_ZPA_APP', 'N/A', 'NOT_EVALUATED'].includes(zpa.verdict) && !/BYPASS/.test(zpa.verdict || '');
    let mode = s.overall === 'BYPASSED' ? 'direct' : zpaApp ? 'zpa' : 'zia';
    const cm = conn && conn.forward && String(conn.forward.method || '').toUpperCase();
    if (cm === 'ZPA') mode = 'zpa'; else if (cm === 'DIRECT' || cm === 'LOCAL_SWITCH') mode = 'direct'; else if (cm === 'DROP') mode = 'drop';
    // source
    const workload = c.source === 'workload';
    const prof = fwd && (fwd.profiles || []).find((q) => q.applies === 'yes');
    const zOut = prof && prof.outcomes.find((o) => o.outcome === 'ZIA');
    const src = workload
      ? { kind: 'server', title: c.sourceIp || 'Workload', sub: conn ? `${c.connectorKind === 'branch' ? 'Branch' : 'Cloud'} Connector${c.ecGroup ? ' · ' + c.ecGroup.name : ''}` : 'Cloud / Branch Connector' }
      : { kind: 'laptop', title: c.device ? c.device.hostname || 'Device' : c.user || ((c.groups || []).length ? 'Group ' + c.groups[0] : 'User device'), sub: prof ? `Client Connector · ${prof.name}` : 'Client Connector / PAC' };
    const how = workload ? (conn && conn.forward ? conn.forward.text : 'forwarded') : mode === 'zpa' ? 'ZPA tunnel' : zOut ? zOut.how : 'to Zscaler';
    // the Zscaler step and its deciding rule
    const zia = mode === 'zia', blocked = ['BLOCKED', 'ISOLATED'].includes(s.overall) || mode === 'drop';
    const ssl = by(/^SSL Inspection/);
    const zs = mode === 'zpa'
      ? { title: 'Zscaler Private Access', verdict: zpa ? zpa.verdict : 'ALLOW', rule: zpa && zpa.decidingRule ? zpa.decidingRule.name : (zpa ? zpa.reason : '') }
      : { title: 'Zscaler Internet Access', verdict: p.action, rule: p.rule ? `${p.module} · ${p.rule}` : `${p.module || 'ZIA'} · ${p.reason || 'no blocking rule'}`, ssl: ssl && ssl.verdict === 'NOT_DECRYPTED' ? 'not inspected' : ssl && ssl.verdict === 'DECRYPTED' ? 'SSL inspected' : '' };
    // destination
    const dest = c.target ? (c.target.host || c.target.raw) : 'destination';
    const port = c.port != null ? `${String(c.protocol || 'tcp').toUpperCase()}/${c.port}` : '';
    const ph = zpa && zpa.pathHealth;
    const acg = ph && (ph.groups || [])[0];
    const app = mode === 'zpa' ? { segment: (zpa.matchedSegments[0] || {}).name || ph && ph.segment, group: acg ? acg.name : 'App Connector', connectors: acg ? acg.connectors || [] : [], health: ph ? ph.status : null } : null;
    const alt = (s.bypasses || []).filter((b) => b.kind === 'forwarding' || b.kind === 'zcc').map((b) => `${b.where}: ${b.how}`);
    const bypassHow = mode === 'direct' ? ((s.bypasses || [])[0] || {}).how || (conn && conn.forward && conn.forward.text) || 'bypassed' : '';
    return { mode, src, how, zs, blocked, dest, port, app, alt: mode === 'zia' ? alt : [], bypassHow };
  }
  const ICON = {
    laptop: (cx, cy, col) => `<rect x="${cx - 26}" y="${cy - 22}" width="52" height="34" rx="4" fill="#111827" stroke="${col}" stroke-width="2"/><rect x="${cx - 21}" y="${cy - 17}" width="42" height="24" rx="2" fill="${col}" opacity=".25"/><path d="M ${cx - 34} ${cy + 14} h 68 l -6 7 h -56 z" fill="${col}"/>`,
    server: (cx, cy, col) => [0, 1, 2].map((i) => `<rect x="${cx - 24}" y="${cy - 24 + i * 17}" width="48" height="14" rx="3" fill="#111827" stroke="${col}" stroke-width="2"/><circle cx="${cx + 15}" cy="${cy - 17 + i * 17}" r="2.5" fill="${col}"/>`).join(''),
    // Centred cloud from a rounded base and three bumps: outline pass first, then a fill pass so inner seams don't show.
    cloud: (cx, cy, w, col, fill) => {
      const h = w * 0.5;
      const sh = [`<rect x="${cx - w / 2}" y="${cy - h * 0.12}" width="${w}" height="${h * 0.6}" rx="${h * 0.3}"/>`, `<circle cx="${cx - w * 0.2}" cy="${cy - h * 0.1}" r="${h * 0.36}"/>`,
        `<circle cx="${cx + w * 0.04}" cy="${cy - h * 0.3}" r="${h * 0.5}"/>`, `<circle cx="${cx + w * 0.26}" cy="${cy - h * 0.06}" r="${h * 0.34}"/>`].join('');
      return `<g fill="${col}" stroke="${col}" stroke-width="4.4">${sh}</g><g fill="${fill}">${sh}</g>`;
    },
    globe: (cx, cy, col) => `<circle cx="${cx}" cy="${cy}" r="11" fill="none" stroke="${col}" stroke-width="1.6"/><ellipse cx="${cx}" cy="${cy}" rx="5" ry="11" fill="none" stroke="${col}" stroke-width="1.3"/><line x1="${cx - 11}" y1="${cy}" x2="${cx + 11}" y2="${cy}" stroke="${col}" stroke-width="1.3"/>`,
    building: (x0, y0, w, h, col) => `<rect x="${x0}" y="${y0}" width="${w}" height="${h}" rx="10" fill="#0b1220" stroke="${col}" stroke-width="1.6" stroke-dasharray="6 4"/>`,
    ac: (cx, cy, col) => `<rect x="${cx - 22}" y="${cy - 18}" width="44" height="36" rx="6" fill="#111827" stroke="${col}" stroke-width="2"/><text x="${cx}" y="${cy + 5}" text-anchor="middle" class="nt2" fill="${col}">AC</text>`,
    x: (cx, cy) => `<circle cx="${cx}" cy="${cy}" r="14" fill="#7f1d1d" stroke="#ef4444" stroke-width="2.5"/><path d="M ${cx - 6} ${cy - 6} L ${cx + 6} ${cy + 6} M ${cx + 6} ${cy - 6} L ${cx - 6} ${cy + 6}" stroke="#fee2e2" stroke-width="3" stroke-linecap="round"/>`,
  };
  function networkSvg(res) {
    const u = 'n' + (++UID);
    const r = route(res);
    const W = 1000, CY = 92;
    const out = [];
    const VC = { ALLOW: '#10b981', BLOCK: '#ef4444', CAUTION: '#f59e0b', ISOLATE: '#06b6d4', BYPASS: '#64748b' };
    const zcol = r.mode === 'direct' ? '#334155' : VC[r.zs.verdict] || '#3b82f6';
    const label = (cx, y, t1, t2, t3, col, n = 26) => `<text x="${cx}" y="${y}" text-anchor="middle" class="nt1">${x(cut(t1, n))}</text>${t2 ? `<text x="${cx}" y="${y + 17}" text-anchor="middle" class="nt3"${col ? ` fill="${col}"` : ''}>${x(cut(t2, n + 8))}</text>` : ''}${t3 ? `<text x="${cx}" y="${y + 33}" text-anchor="middle" class="nt3">${x(cut(t3, n + 8))}</text>` : ''}`;
    const link = (x1, x2, y, col, dashed, txt, faded) => `<line x1="${x1}" y1="${y}" x2="${x2 - 8}" y2="${y}" stroke="${col}" stroke-width="3"${dashed ? ' stroke-dasharray="7 6"' : ''} marker-end="url(#${u}na${faded ? 'f' : ''})"${faded ? ' opacity=".35"' : ''}/>${txt ? `<text x="${(x1 + x2) / 2}" y="${y - 10}" text-anchor="middle" class="nt3">${x(cut(txt, 26))}</text>` : ''}`;
    // 1. source
    out.push(ICON[r.src.kind](100, CY, '#3b82f6'), label(100, CY + 48, r.src.title, r.src.sub, '', null, 24));
    const ZX = 410, ZW = 170, faded = r.blocked;
    if (r.mode === 'direct') {
      // Zscaler is skipped: greyed cloud, traffic arcs over it straight to the internet
      out.push(ICON.cloud(ZX, CY, ZW, '#334155', '#111827'), `<text x="${ZX}" y="${CY + 6}" text-anchor="middle" class="nt2" fill="#5c6b8a">Zscaler</text>`,
        label(ZX, CY + 48, 'Not sent to Zscaler', r.bypassHow, '', '#f59e0b', 40),
        `<path d="M 140 ${CY - 10} C 260 ${CY - 120}, 560 ${CY - 120}, 640 ${CY - 14}" fill="none" stroke="#f59e0b" stroke-width="3" stroke-dasharray="7 6" marker-end="url(#${u}nab)"/>`,
        `<text x="${ZX}" y="${CY - 92}" text-anchor="middle" class="nt3" fill="#fcd34d">direct (bypassed)</text>`);
    } else {
      out.push(link(142, ZX - ZW / 2 - 10, CY, '#3b82f6', false, r.how));
      out.push(ICON.cloud(ZX, CY, ZW, zcol, '#0f2347'), `<text x="${ZX}" y="${CY + 2}" text-anchor="middle" class="nt2">${r.mode === 'zpa' ? 'ZPA' : 'ZIA'}</text>`,
        `<text x="${ZX}" y="${CY + 18}" text-anchor="middle" class="nt3">Zscaler</text>`);
      const act = r.mode === 'zpa' ? (/BLOCK/.test(r.zs.verdict) ? 'BLOCK' : 'ALLOW') : r.zs.verdict;
      out.push(`<rect x="${ZX - 34}" y="${CY + 38}" width="68" height="20" rx="10" fill="${VC[act] || '#3b82f6'}"/><text x="${ZX}" y="${CY + 52}" text-anchor="middle" class="nt4">${x(act || '')}</text>`,
        label(ZX, CY + 76, r.zs.rule, r.zs.ssl ? `${r.zs.title} · ${r.zs.ssl}` : r.zs.title, '', null, 44));
    }
    // 3. destination
    if (r.mode === 'zpa') {
      out.push(link(ZX + ZW / 2 + 12, 600, CY, faded ? '#334155' : '#8b5cf6', false, faded ? '' : 'Microtunnel', faded));
      if (faded) out.push(ICON.x(ZX + ZW / 2 + 40, CY));
      out.push(`<g${faded ? ' opacity=".4"' : ''}>${ICON.building(600, 18, 380, 168, '#8b5cf6')}<text x="616" y="38" class="nt3" fill="#c4b5fd">🏢 Data center · ${x(cut(r.app.group, 30))}</text>
        ${ICON.ac(680, CY, '#8b5cf6')}${label(680, CY + 40, 'App Connector', r.app.connectors.length ? `${r.app.connectors.filter((q) => q.up).length}/${r.app.connectors.length} up` : '', r.app.connectors.slice(0, 2).map((q) => q.name).join(', '), null, 18)}
        ${link(706, 860, CY, '#8b5cf6', false, r.port)}${ICON.server(900, CY, '#8b5cf6')}${label(900, CY + 40, r.app.segment || 'Private app', r.dest, '', null, 20)}</g>`);
      if (r.app.health && r.app.health !== 'ok') out.push(`<text x="790" y="178" text-anchor="middle" class="nt3" fill="#fca5a5">⚠ connector health: ${x(r.app.health)}</text>`);
    } else {
      const ix = 700;
      if (r.mode !== 'direct') out.push(link(ZX + ZW / 2 + 12, ix - 68, CY, faded ? '#334155' : '#10b981', false, '', faded));
      if (faded && r.mode !== 'direct') out.push(ICON.x(ZX + ZW / 2 + 40, CY));
      out.push(`<g${faded ? ' opacity=".4"' : ''}>${ICON.cloud(ix, CY, 120, '#64748b', '#141c2c')}${ICON.globe(ix, CY - 6, '#94a3b8')}${label(ix, CY + 48, 'Internet', '')}
        ${link(ix + 72, 862, CY, '#64748b', false, r.port)}${ICON.server(905, CY, '#94a3b8')}${label(905, CY + 48, r.dest, '', '', null, 22)}</g>`);
    }
    // other paths for other app profiles / networks
    let H = 196;
    if (r.alt.length) { out.push(`<text x="20" y="${H + 4}" class="nt3" fill="#fcd34d">↪ Other paths: ${x(cut(r.alt.slice(0, 2).join('  ·  '), 150))}${r.alt.length > 2 ? ` (+${r.alt.length - 2} more)` : ''}</text>`); H += 18; }
    const style = `<style>text{font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',sans-serif}.nt1{font-size:13px;font-weight:600;fill:#e8ecf4}.nt2{font-size:15px;font-weight:700;fill:#e8ecf4}.nt3{font-size:11.5px;fill:#8896b3}.nt4{font-size:11px;font-weight:700;fill:#fff;letter-spacing:.5px}</style>`;
    const mk = (id, col) => `<marker id="${id}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="${col}"/></marker>`;
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H + 12}" width="100%" role="img" aria-label="Network path">${style}<defs>${mk(u + 'na', '#94a3b8')}${mk(u + 'naf', '#334155')}${mk(u + 'nab', '#f59e0b')}</defs><rect width="${W}" height="${H + 12}" fill="#0f1629" rx="12"/>${out.join('')}</svg>`;
  }
  function netCard(res) {
    return `<div class="card dp-net"><div class="dp-head"><h3>🌐 Network path</h3><div class="dp-btns"><button class="btn btn-ghost btn-sm" data-dp-export="net-svg">⬇ SVG</button><button class="btn btn-ghost btn-sm" data-dp-export="net-png">⬇ PNG</button></div></div><div class="dp-wrap" style="margin-top:8px">${networkSvg(res)}</div></div>`;
  }

  function card(res) {
    return `<div class="card dp-card"><div class="dp-head"><h3>🧭 Decision path</h3><div class="dp-btns"><button class="btn btn-ghost btn-sm" data-dp-export="svg" title="Download as SVG">⬇ SVG</button><button class="btn btn-ghost btn-sm" data-dp-export="png" title="Download as PNG">⬇ PNG</button></div></div>
      <p class="form-hint" style="margin:2px 0 10px;width:0;min-width:100%">Evaluation order, top to bottom. The outlined box decides; dashed branches would change the result. Click a box for its rules.</p>
      <div class="dp-wrap">${svg(res)}</div></div>`;
  }

  function download(name, blob) { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); }
  function exportPath(res, kind) {
    const isNet = /^net-/.test(kind); kind = kind.replace(/^net-/, '');
    const markup = isNet ? networkSvg(res).replace('width="100%"', 'width="1000"') : svg(res);
    const base = `${isNet ? 'network-path' : 'decision-path'}-${String((res.context && res.context.target && (res.context.target.host || res.context.target.raw)) || 'result').replace(/[^\w.-]+/g, '_')}`;
    if (kind === 'svg') return download(base + '.svg', new Blob([markup], { type: 'image/svg+xml' }));
    const img = new Image();
    img.onload = () => { const k = 2, cv = document.createElement('canvas'); cv.width = img.width * k; cv.height = img.height * k; const g = cv.getContext('2d'); g.scale(k, k); g.drawImage(img, 0, 0); cv.toBlob((b) => download(base + '.png', b), 'image/png'); };
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(markup);
  }

  // Wire clicks once: export buttons, and node → open that module in "Every module".
  if (typeof document !== 'undefined') document.addEventListener('click', (e) => {
    const b = e.target.closest && e.target.closest('[data-dp-export]');
    if (b && root.dpResult) { exportPath(root.dpResult, b.dataset.dpExport); return; }
    const n = e.target.closest && e.target.closest('.dp-node');
    if (n && typeof root.dpShowModule === 'function') root.dpShowModule(n.getAttribute('data-module'));
  });

  root.DecisionPath = { svg, card, steps, exportPath, route, networkSvg, netCard };
  if (typeof module !== 'undefined') module.exports = root.DecisionPath;
})(typeof window !== 'undefined' ? window : globalThis);
