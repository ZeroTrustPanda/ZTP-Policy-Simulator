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
    const s = res.summary || {}, c = res.context || {}, p = s.primary || {};
    const W = 860, LX = 24, NW = 430, RX = LX + NW + 56, RW = W - RX - 20;
    const st = steps(res);
    const conds = (s.alsoBasedOn || []).filter((k) => !(k.kind === 'zpa' && /check fails/.test(k.condition)));
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
    const arrow = (y1, y2, faded) => parts.push(`<line x1="${LX + NW / 2}" y1="${y1}" x2="${LX + NW / 2}" y2="${y2 - 6}" stroke="${faded ? '#334155' : '#5c6b8a'}" stroke-width="2" marker-end="url(#ah${faded ? 'f' : ''})"${faded ? ' stroke-dasharray="4 4"' : ''}/>`);

    // Start: the transaction
    const who = c.user || ((c.groups || []).length ? 'group ' + c.groups.join(', ') : c.source === 'workload' ? 'workload ' + (c.sourceIp || '') : 'any user');
    const dest = c.target ? (c.target.raw || c.target.host) : 'any destination';
    const port = c.port != null ? `${String(c.protocol || 'tcp').toUpperCase()}/${c.port}` : '';
    parts.push(`<rect x="${LX}" y="${y}" width="${NW}" height="58" rx="29" fill="#111827" stroke="#3b82f6" stroke-width="1.5"/>
      <text x="${LX + 22}" y="${y + 24}" class="t1">${x(cut(dest, 44))}${port ? `  ·  ${x(port)}` : ''}</text>
      <text x="${LX + 22}" y="${y + 43}" class="t3">${x(cut([who, (c.categories || []).slice(0, 2).join(', '), c.cloudApp].filter(Boolean).join('  ·  '), 62))}</text>`);
    y += 58;
    let hiddenMore = 0;
    for (const sp of st) {
      const faded = sp.kind === 'module' && sp.notReached;
      if (sp.kind === 'skipped') {
        const h = 30;
        arrow(y, y + 22, false); y += 22;
        const names = sp.names.map((n) => n.name).join(', ');
        parts.push(`<g><title>${x(sp.names.map((n) => `${n.name}: ${n.why || 'not applied'}`).join('\n'))}</title><rect x="${LX + 30}" y="${y}" width="${NW - 60}" height="${h}" rx="6" fill="none" stroke="#334155" stroke-dasharray="4 3"/>
          <text x="${LX + 44}" y="${y + 19}" class="t3">Skipped: ${x(cut(names, 52))}</text></g>`);
        y += h; continue;
      }
      const [bg, fg, tx] = COL[sp.col] || COL.slate;
      const h = sp.isDec ? 74 : 60;
      arrow(y, y + 26, faded); y += 26;
      const op = faded ? ' opacity="0.38"' : '';
      parts.push(`<g${op} data-module="${x(sp.module)}" class="dp-node" style="cursor:pointer"><title>${x(sp.reason || '')}</title>
        <rect x="${LX}" y="${y}" width="${NW}" height="${h}" rx="10" fill="${bg}" fill-opacity="${sp.col === 'grey' ? 1 : 0.55}" stroke="${fg}" stroke-width="${sp.isDec ? 3 : 1.5}"/>
        <rect x="${LX}" y="${y}" width="6" height="${h}" rx="3" fill="${fg}"/>
        <text x="${LX + 20}" y="${y + 23}" class="t1">${x(sp.name)}</text>
        <text x="${LX + NW - 16}" y="${y + 23}" class="t2" text-anchor="end" fill="${tx}">${x(sp.word)}</text>
        <text x="${LX + 20}" y="${y + 43}" class="t3">${x(cut(sp.rule ? `rule "${sp.rule}"` : sp.reason, faded ? 46 : 60))}</text>
        ${sp.isDec ? `<text x="${LX + 20}" y="${y + 62}" class="tdec" fill="${fg}">▲ DECIDES THE RESULT${sp.conf && sp.conf !== 'definite' ? ' · conditional' : ''}${sp.extra ? ` · ${sp.extra} more rule(s) also match` : ''}</text>` : ''}
        ${faded ? `<text x="${LX + NW - 16}" y="${y + 43}" class="t3" text-anchor="end">not reached</text>` : ''}</g>`);
      // conditions that would change the result, branching off this module
      const ks = byMod.get(sp.module) || [];
      const show = ks.slice(0, 2); hiddenMore += Math.max(0, ks.length - 2);
      show.forEach((k, i) => {
        const by = y + (i * 44) - (show.length > 1 ? 10 : 0), [kbg, kfg, ktx] = COL[ACTION_COL[k.action] || 'slate'];
        parts.push(`<path d="M ${LX + NW} ${y + h / 2} C ${LX + NW + 30} ${y + h / 2}, ${RX - 30} ${by + 20}, ${RX} ${by + 20}" fill="none" stroke="${kfg}" stroke-width="1.5" stroke-dasharray="5 4" opacity="0.8"/>
          <g><title>${x(`${k.condition} → ${k.action}${k.rule ? ` (rule "${k.rule}")` : ''}`)}</title><rect x="${RX}" y="${by}" width="${RW}" height="40" rx="8" fill="${kbg}" fill-opacity="0.3" stroke="${kfg}" stroke-dasharray="5 4"/>
          <text x="${RX + 10}" y="${by + 16}" class="t4">${x(cut('If ' + String(k.condition).replace(/^If /i, ''), 44))}</text>
          <text x="${RX + 10}" y="${by + 32}" class="t4" fill="${ktx}">→ ${x(k.action)}${k.rule ? x(cut(` · "${k.rule}"`, 34)) : ''}</text></g>`);
      });
      y += Math.max(h, show.length * 44 - 4);
    }
    // Result
    const [rbg, rfg, rtx] = COL[ACTION_COL[p.action] || 'slate'];
    arrow(y, y + 30, false); y += 30;
    const overall = String(s.overall || p.action || '').replace(/_/g, ' ');
    parts.push(`<rect x="${LX}" y="${y}" width="${NW}" height="70" rx="12" fill="${rbg}" stroke="${rfg}" stroke-width="3"/>
      <text x="${LX + 22}" y="${y + 30}" class="tres" fill="${rtx}">${x(overall)}</text>
      <text x="${LX + 22}" y="${y + 52}" class="t3" fill="${rtx}">${x(cut(p.rule ? `${p.module} · rule "${p.rule}"` : `${p.module || ''} · ${p.reason || 'default action'}`, 62))}</text>`);
    y += 70;
    if (hiddenMore) parts.push(`<text x="${RX}" y="${y - 8}" class="t3">+${hiddenMore} more condition(s) in "Policy action also based on"</text>`);
    const H = y + 20;
    defs.push(`<marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#5c6b8a"/></marker>
      <marker id="ahf" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#334155"/></marker>`);
    const style = `<style>text{font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',sans-serif}.t1{font-size:14px;font-weight:600;fill:#e8ecf4}.t2{font-size:13px;font-weight:600}.t3{font-size:12px;fill:#8896b3}.t4{font-size:11.5px;fill:#cbd5e1}.tdec{font-size:10.5px;font-weight:700;letter-spacing:.6px}.tres{font-size:20px;font-weight:700;letter-spacing:.5px}</style>`;
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${opts.width || W}" role="img" aria-label="Decision path: ${x(overall)}">${style}<defs>${defs.join('')}</defs><rect width="${W}" height="${H}" fill="#0f1629" rx="12"/>${parts.join('')}</svg>`;
  }

  function card(res) {
    return `<div class="card dp-card"><div class="card-header" style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px"><div><h3>🧭 Decision path</h3><p style="font-size:13px">Each policy in the order ZIA evaluates it. The thick box decides the result; dashed branches are conditions that would change it. Click a box for its rules.</p></div>
      <div style="display:flex;gap:6px;flex-shrink:0"><button class="btn btn-ghost btn-sm" data-dp-export="svg">⬇ SVG</button><button class="btn btn-ghost btn-sm" data-dp-export="png">⬇ PNG</button></div></div>
      <div class="dp-wrap" style="overflow-x:auto">${svg(res, { width: '100%' })}</div></div>`;
  }

  function download(name, blob) { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); }
  function exportPath(res, kind) {
    const markup = svg(res);
    const base = `decision-path-${String((res.context && res.context.target && (res.context.target.host || res.context.target.raw)) || 'result').replace(/[^\w.-]+/g, '_')}`;
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

  root.DecisionPath = { svg, card, steps, exportPath };
  if (typeof module !== 'undefined') module.exports = root.DecisionPath;
})(typeof window !== 'undefined' ? window : globalThis);
