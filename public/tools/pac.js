// PAC Analyzer UI (Zscaler Policy Troubleshooting Toolkit). The PAC runs in a locked-down sandbox on the local server.
// Uses the page's esc(), toast(), simulateDest(), and sid/loaded for the "from your tenant" list.
const PACUI = (() => {
  let ready = false, text = '', source = '', A = null, T = null, selected = -1;
  const el = (id) => document.getElementById(id);
  const post = async (path, body) => {
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
    if (!r.ok || j.error) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  };
  const VERDICT = { ZSCALER: ['zs', 'Zscaler'], DIRECT: ['direct', 'Direct'], OTHER_PROXY: ['warn', 'Other proxy'], INVALID: ['bad', 'Invalid'], NONE: ['bad', 'No result'] };
  const vBadge = (k) => { const [c, t] = VERDICT[k] || ['dim', k]; return c === 'zs' ? '<span class="via ZIA">Zscaler</span>' : c === 'direct' ? '<span class="via direct">Direct</span>' : `<span class="st ${c}">${esc(t)}</span>`; };
  const SAMPLE_URLS = 'https://www.google.com\nhttps://login.microsoftonline.com\nhttps://zoom.us\nhttp://intranet/\nhttps://10.1.2.3/\nhttps://app.example.internal';
  const store = { get: (k) => { try { return localStorage.getItem('ztp-pac.' + k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem('ztp-pac.' + k, v); } catch {} } };

  function shell() {
    el('pacSec').innerHTML = `
      <div class="tool-head"><div><h2>🧭 PAC Analyzer</h2>
        <p>Check a PAC file for mistakes, then see where each URL goes (Zscaler, direct or another proxy) and which line decided. The file runs in a sandbox on this computer and is never saved.</p></div></div>
      <div class="card">
        <div class="tbar" style="margin-bottom:12px">
          <button class="btn btn-ghost btn-sm" id="pacPick">📂 Open a PAC file…</button>
          <input type="file" id="pacFileIn" accept=".pac,.js,.dat,.txt,application/x-ns-proxy-autoconfig,text/plain" style="position:absolute;width:1px;height:1px;opacity:0;pointer-events:none" tabindex="-1" aria-hidden="true">
          <input type="text" id="pacUrl" placeholder="or a PAC URL, e.g. https://pac.zscalerthree.net/acme.com/proxy.pac">
          <button class="btn btn-ghost btn-sm" id="pacFetch">⬇ Load URL</button>
          <select id="pacTenant" class="hidden" style="max-width:360px"></select>
        </div>
        <label class="form-label">PAC file <span class="form-hint" id="pacSrc" style="margin-left:6px"></span></label>
        <textarea id="pacEdit" spellcheck="false" style="min-height:220px;font-size:12px;line-height:1.55" placeholder="function FindProxyForURL(url, host) {\n  if (isPlainHostName(host)) return &quot;DIRECT&quot;;\n  return &quot;PROXY \${GATEWAY}:80; PROXY \${SECONDARY_GATEWAY}:80; DIRECT&quot;;\n}"></textarea>
        <div class="btn-group"><button class="btn btn-primary" id="pacGo">Analyze</button><span class="msg" id="pacMsg"></span></div>
      </div>
      <div id="pacOut"></div>`;
    el('pacPick').onclick = () => el('pacFileIn').click();
    el('pacFileIn').onchange = async () => { const f = el('pacFileIn').files[0]; el('pacFileIn').value = ''; if (!f) return; if (f.size > 5 * 1024 * 1024) return msg('That file is larger than 5 MB.', true); setText(await f.text(), f.name); analyze(); };
    el('pacFetch').onclick = fetchUrl;
    el('pacUrl').addEventListener('keydown', (e) => { if (e.key === 'Enter') fetchUrl(); });
    el('pacGo').onclick = analyze;
    el('pacEdit').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyze(); if (e.key === 'Tab') { e.preventDefault(); const t = e.target, s = t.selectionStart; t.setRangeText('  ', s, t.selectionEnd, 'end'); } });
    el('pacEdit').addEventListener('input', () => { el('pacSrc').textContent = source ? `${source} (edited)` : ''; });
    el('pacOut').addEventListener('click', onClick);
    el('pacTenant').onchange = () => { const i = +el('pacTenant').value; const p = tenantPacs[i]; if (p && p.text) { setText(p.text, p.name); analyze(); } };
  }
  let tenantPacs = [];
  async function tenant() {
    const sel = el('pacTenant');
    if (typeof sid === 'undefined' || !sid || !loaded) { sel.classList.add('hidden'); return; }
    try {
      const j = await (await fetch(`/api/pac/tenant?sessionId=${encodeURIComponent(sid)}`)).json();
      tenantPacs = (j.pacs || []).filter((p) => p.text);
      sel.classList.toggle('hidden', !tenantPacs.length);
      sel.innerHTML = `<option value="">From your tenant (${tenantPacs.length})…</option>` + tenantPacs.map((p, i) => `<option value="${i}">${esc(p.name)}</option>`).join('');
    } catch { sel.classList.add('hidden'); }
  }
  const msg = (m, bad) => { el('pacMsg').innerHTML = bad ? `<span class="err">${esc(m)}</span>` : m; };
  function setText(t, src) { el('pacEdit').value = t; source = src || ''; el('pacSrc').textContent = source; }
  async function fetchUrl() {
    const url = el('pacUrl').value.trim(); if (!url) return el('pacUrl').focus();
    msg('<span class="spinner"></span> Downloading…');
    try { const j = await post('/api/pac/fetch', { url }); setText(j.text, url); store.set('url', url); analyze(); } catch (e) { msg(e.message, true); }
  }

  async function analyze() {
    text = el('pacEdit').value;
    if (!text.trim()) { msg('Paste a PAC file, open one, or load it from a URL.', true); return; }
    msg('<span class="spinner"></span> Checking…');
    try {
      A = await post('/api/pac/analyze', { text, myIp: store.get('myIp') || undefined });
      T = null; selected = -1;
      msg(`${A.inventory.lines} lines · ${(A.inventory.bytes / 1024).toFixed(1)} KB`);
      render();
      runTests();
    } catch (e) { msg(e.message, true); }
  }
  function render() {
    const inv = A.inventory, findings = [...A.lint, ...A.behaviour.findings].sort((a, b) => ['high', 'medium', 'low', 'info'].indexOf(a.sev) - ['high', 'medium', 'low', 'info'].indexOf(b.sev));
    const proxies = [...new Set(inv.returns.map((r) => r.value))];
    el('pacOut').innerHTML = `
      <div class="stat-strip">
        <div class="stat"><div class="k">Size</div><div class="v">${inv.lines}</div><div class="s">lines · ${(inv.bytes / 1024).toFixed(1)} KB</div></div>
        <div class="stat"><div class="k">Checks</div><div class="v">${inv.items.length}</div><div class="s">host / URL / network tests</div></div>
        <div class="stat"><div class="k">Answers</div><div class="v">${proxies.length}</div><div class="s">distinct return values</div></div>
        <div class="stat ${findings.some((f) => f.sev === 'high') ? 'bad' : findings.some((f) => f.sev === 'medium') ? 'warn' : 'good'}"><div class="k">Problems</div><div class="v">${findings.filter((f) => f.sev !== 'info').length}</div><div class="s">${findings.filter((f) => f.sev === 'high').length} high · ${findings.filter((f) => f.sev === 'medium').length} medium</div></div>
        <div class="stat ${inv.variables.length ? 'zs' : ''}"><div class="k">Zscaler variables</div><div class="v">${inv.variables.length}</div><div class="s">${esc(inv.variables.join(' ') || 'none')}</div></div>
      </div>
      <div class="split">
        <div>
          <div class="card"><div class="card-header"><h3>Test URLs</h3><p style="font-size:13px">One URL or host per line. HTTPS URLs are tested as <span class="mono">https://host/</span>, the way browsers pass them.</p></div>
            <div class="grid">
              <div class="span2"><label class="form-label">URLs or hosts</label><textarea id="pacUrls" style="min-height:120px">${esc(store.get('urls') || SAMPLE_URLS)}</textarea></div>
              <div><label class="form-label">Client IP (myIpAddress)</label><input type="text" id="pacMyIp" value="${esc(store.get('myIp') || '10.0.0.10')}"><div class="form-hint">Matters for PACs that branch on the client's network.</div></div>
              <div><label class="form-label">Date and time</label><input type="text" id="pacNow" placeholder="now (e.g. 2026-11-23 09:30)"><div class="form-hint">For weekdayRange / timeRange.</div></div>
              <div class="span2"><label class="form-label">DNS answers <span class="form-hint">(host = IP, one per line; blank IP = doesn't resolve)</span></label><textarea id="pacDns" placeholder="app.example.internal = 10.20.30.40">${esc(store.get('dns') || '')}</textarea>
                <label style="display:flex;gap:8px;align-items:center;margin-top:8px;font-size:13px"><input type="checkbox" id="pacReal" ${store.get('real') === '0' ? '' : 'checked'}> Look up other names with this computer's DNS</label></div>
            </div>
            <div class="btn-group"><button class="btn btn-primary" id="pacRun">Test</button><span class="msg" id="pacRunMsg"></span></div>
            <div id="pacRes" style="margin-top:12px"></div></div>
          <div class="card"><div class="card-header"><h3>Checks</h3><p style="font-size:13px">Line numbers jump to the code.</p></div>
            ${findings.length ? findings.map((f) => `<div class="finding"><div><span class="sev ${f.sev}">${f.sev}</span></div><div><div class="ft">${esc(f.title)}</div><div class="fd">${esc(f.detail)}</div></div><div class="fa">${f.line ? `<button class="linkbtn2" data-pline="${f.line}">line ${f.line}</button>` : ''}</div></div>`).join('') : '<div class="empty">No problems found.</div>'}</div>
          <div class="card"><div class="card-header"><h3>How it treats the basics</h3><p style="font-size:13px">Destinations every PAC should handle on purpose.</p></div>
            <table><tr><th>Destination</th><th>Goes</th><th>Answer</th><th></th></tr>${A.behaviour.rows.map((r) => `<tr><td>${esc(r.label)}</td><td>${r.error ? '<span class="st bad">error</span>' : vBadge(r.verdict)}</td><td class="mono" style="word-break:break-all">${esc(r.error || r.result || '')}</td><td>${r.line ? `<button class="linkbtn2" data-pline="${r.line}">line ${r.line}</button>` : ''}</td></tr>`).join('')}</table></div>

        </div>
        <div style="position:sticky;top:80px">
          <div class="card" style="padding:1rem"><div class="card-header" style="margin-bottom:8px;display:flex;justify-content:space-between;gap:8px;align-items:center"><h3 id="pacCodeTitle">The PAC file</h3><span class="form-hint" id="pacLegend"></span></div><div class="code" id="pacCode"></div></div>
        </div>
      </div>`;
    el('pacRun').onclick = runTests;
    el('pacUrls').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runTests(); });
    drawCode();
  }
  function drawCode(highlight) {
    const lines = text.split('\n');
    const h = highlight || {};
    el('pacCode').innerHTML = lines.map((l, i) => {
      const n = i + 1, m = h[n];
      return `<div class="ln ${m ? m.cls : ''}" data-ln="${n}"><span class="no">${n}</span><span>${esc(l) || ' '}</span><span class="lt" title="${m && m.title ? esc(m.title) : ''}">${m && m.tag ? esc(m.tag) : ''}</span></div>`;
    }).join('');
    el('pacLegend').innerHTML = highlight ? '<span style="color:#6ee7b7">■</span> true · <span style="color:var(--text-muted)">■</span> false · <span style="color:#93c5fd">■</span> returned here' : '';
  }
  function jump(line) {
    const row = document.querySelector(`#pacCode [data-ln="${line}"]`); if (!row) return;
    row.classList.remove('flash'); void row.offsetWidth; row.classList.add('flash');
    const box = el('pacCode'); box.scrollTo({ top: row.offsetTop - box.clientHeight / 3, behavior: 'smooth' });
  }
  function parseDns(t) {
    const out = {};
    for (const line of t.split('\n')) { const m = line.trim().match(/^([^\s=#]+)\s*(?:=|\s)\s*([\d.]*)\s*$/); if (m) out[m[1].toLowerCase()] = m[2] || null; }
    return out;
  }
  async function runTests() {
    if (!A || !el('pacUrls')) return;
    const urls = el('pacUrls').value.split('\n').map((s) => s.trim()).filter(Boolean);
    store.set('urls', el('pacUrls').value); store.set('myIp', el('pacMyIp').value.trim()); store.set('dns', el('pacDns').value); store.set('real', el('pacReal').checked ? '1' : '0');
    if (!urls.length) { el('pacRunMsg').innerHTML = '<span class="err">Enter at least one URL.</span>'; return; }
    el('pacRunMsg').innerHTML = '<span class="spinner"></span> Running…';
    const nowTxt = el('pacNow').value.trim();
    try {
      T = (await post('/api/pac/test', { text, urls, myIp: el('pacMyIp').value.trim() || '10.0.0.10', dns: parseDns(el('pacDns').value), realDns: el('pacReal').checked, now: nowTxt ? new Date(nowTxt.replace(' ', 'T')).toISOString() : undefined })).results;
      el('pacRunMsg').textContent = `${T.length} tested`;
      drawResults();
      if (T.length) select(0);
    } catch (e) { el('pacRunMsg').innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  }
  function drawResults() {
    const dnsNote = (r) => { const e = Object.entries(r.dns || {}); if (!e.length) return ''; return `<div class="form-hint" style="margin:2px 0 0">DNS: ${esc(e.map(([k, v]) => `${k === r.host ? '' : k + ' '}${v || 'no answer'}`).join(', '))}</div>`; };
    el('pacRes').innerHTML = `<div class="tscroll" style="max-height:none"><table><tr><th>URL</th><th>Goes</th><th>Answer</th><th></th></tr>${T.map((r, i) => `<tr data-pres="${i}" class="${i === selected ? 'sel' : ''}" style="cursor:pointer">
      <td class="mono" style="word-break:break-word;min-width:170px">${esc(r.input)}${dnsNote(r)}</td>
      <td>${r.error ? '<span class="st bad">error</span>' : vBadge(r.verdict)}</td>
      <td>${r.error ? `<span class="err">${esc(r.error)}</span>` : `<div class="mono" style="font-size:11.5px;word-break:break-word">${r.chain.map((c) => esc(c.raw)).join('; ')}</div>`}${r.line ? `<div class="form-hint" style="margin:2px 0 0">decided on line ${r.line}</div>` : ''}${r.asyncWarning ? `<div class="note">${esc(r.asyncWarning)}</div>` : ''}</td>
      <td class="nowrap">${r.error ? '' : `<button class="simbtn" data-psim2="${i}" title="Simulate this URL in the Policy Simulator, with this PAC as the forwarding PAC">▶ Simulate</button>`}</td></tr>`).join('')}</table></div>`;
  }
  function select(i) {
    selected = i; const r = T[i]; if (!r) return;
    document.querySelectorAll('#pacRes tr[data-pres]').forEach((tr) => tr.classList.toggle('sel', +tr.dataset.pres === i));
    const hl = {};
    for (const t of r.trace || []) {
      if (!t.line) continue;
      const full = `${t.fn}(${(t.args || []).map((a) => JSON.stringify(a)).join(', ')}) → ${JSON.stringify(t.result)}`;
      const short = typeof t.result === 'boolean' ? `${t.fn} ${t.result ? '✓' : '✗'}` : `${t.fn} → ${t.result == null ? 'no answer' : t.result}`;
      const prev = hl[t.line];
      const truthy = t.result === true || (t.fn !== 'dnsResolve' && typeof t.result === 'string') || (t.fn === 'dnsResolve' && t.result);
      hl[t.line] = { cls: prev && prev.cls === 'hit-t' ? 'hit-t' : truthy ? 'hit-t' : 'hit-f', tag: prev ? `${prev.tag} · ${short}` : short, title: prev ? `${prev.title}\n${full}` : full };
    }
    if (r.line) hl[r.line] = { cls: r.error ? 'err' : 'ret', tag: r.error ? r.error : `returned here (${r.verdict === 'ZSCALER' ? 'Zscaler' : r.verdict === 'DIRECT' ? 'direct' : r.verdict.toLowerCase().replace('_', ' ')})`, title: r.error || r.result };
    drawCode(hl);
    el('pacCodeTitle').textContent = `The PAC file · ${r.host}`;
    if (r.line) jump(r.line);
  }
  function onClick(e) {
    const t = e.target.closest('[data-pline],[data-pres],[data-psim2]');
    if (!t) return;
    if (t.dataset.psim2 != null) {
      e.stopPropagation();
      const r = T[+t.dataset.psim2]; let port = null;
      try { const u = new URL(/^[a-z]+:\/\//i.test(r.input) ? r.input : 'https://' + r.input); port = u.port ? +u.port : u.protocol === 'http:' ? 80 : 443; } catch {}
      simulateDest({ target: r.input, port, protocol: 'tcp', source: 'PAC Analyzer', pac: text });
    } else if (t.dataset.pline) jump(+t.dataset.pline);
    else if (t.dataset.pres != null) select(+t.dataset.pres);
  }
  return {
    init() {
      if (!ready) { shell(); ready = true; const u = store.get('url'); if (u) el('pacUrl').value = u; }
      tenant();
    },
  };
})();
