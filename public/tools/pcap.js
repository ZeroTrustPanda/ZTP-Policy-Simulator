// Packet Capture Analyzer UI (Zscaler Policy Troubleshooting Toolkit). The file goes to the local server, is analyzed
// in memory, and is never saved. Uses the page's esc(), toast() and simulateDest().
const PCAP = (() => {
  let ready = false, R = null, tab = 'conv', flowFilter = null;
  const el = (id) => document.getElementById(id);
  const fmtB = (n) => (n == null ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`);
  const fmtN = (n) => Number(n || 0).toLocaleString();
  const ms = (s) => (s == null ? '—' : s < 1 ? `${Math.round(s * 1000)} ms` : `${s.toFixed(2)} s`);
  const rel = (t) => (R && R.file.first != null && t ? `+${(t - R.file.first).toFixed(3)}s` : '');
  const ref = (f) => `${f.proto}|${f.client}|${f.cport}|${f.server}|${f.sport}`;
  const STATUS = { ok: ['ok', 'ok'], 'no-answer': ['bad', 'no answer'], refused: ['bad', 'refused'], reset: ['warn', 'reset'], 'tls-alert': ['bad', 'TLS alert'], partial: ['dim', 'mid-stream'] };
  const stBadge = (f) => { const [c, t] = STATUS[f.status] || ['dim', f.status]; return `<span class="st ${c}" title="${esc(f.detail || '')}">${esc(t)}</span>`; };
  const viaBadge = (v, role) => `<span class="via ${esc(v)}" title="${esc(role || '')}">${esc(v === 'direct' ? 'Direct' : v === 'local' ? 'Local' : v)}</span>`;
  const simAttrs = (s) => `data-psim="${esc(JSON.stringify(s))}"`;
  const simFor = (f) => {
    if (f.via === 'local' || ['ZIA', 'ZPA', 'Zscaler'].includes(f.via) && !f.proxyTarget && /Service Edge|broker|Client Connector|ZDX|PAC file/.test(f.role || '')) return null;
    const target = f.proxyTarget ? f.proxyTarget.replace(/:\d+$/, '') : f.name || f.server;
    const port = f.proxyTarget && /:\d+$/.test(f.proxyTarget) ? +f.proxyTarget.split(':').pop() : f.sport;
    return { target, port, protocol: f.proto === 'udp' ? 'udp' : 'tcp' };
  };

  function shell() {
    el('pcapSec').innerHTML = `
      <div class="tool-head"><div><h2>📡 Packet Capture Analyzer</h2>
        <p>Load a capture from Wireshark, tcpdump, pktmon (converted to pcapng) or a Client Connector packet capture. It's analyzed on this computer, kept in memory only, and never uploaded anywhere.</p></div></div>
      <div class="card">
        <div class="drop" id="pcDrop">
          <input type="file" id="pcFile" accept=".pcap,.pcapng,.cap,.zip,application/vnd.tcpdump.pcap,application/zip" style="position:absolute;width:1px;height:1px;opacity:0;pointer-events:none" tabindex="-1" aria-hidden="true">
          <div class="drop-main">📦 Drop a <b>.pcap</b>, <b>.pcapng</b> or a <b>.zip</b> with captures here, or <button class="linkbtn" id="pcPick">choose a file</button></div>
          <div class="form-hint">Up to 1 GB. Zips (e.g. a Client Connector log bundle) are searched for capture files.</div>
          <div class="fname" id="pcName"></div>
        </div>
        <div class="msg" id="pcMsg" style="margin-top:10px"></div>
      </div>
      <div id="pcOut"></div>`;
    const drop = el('pcDrop');
    el('pcPick').onclick = (e) => { e.preventDefault(); el('pcFile').click(); };
    drop.onclick = (e) => { if (e.target === drop || e.target.classList.contains('drop-main')) el('pcFile').click(); };
    el('pcFile').onchange = () => { if (el('pcFile').files[0]) load(el('pcFile').files[0]); el('pcFile').value = ''; };
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); const f = e.dataTransfer.files[0]; if (f) load(f); });
    el('pcOut').addEventListener('click', onClick);
  }

  async function load(file) {
    if (file.size > 1024 * 1024 * 1024) { el('pcMsg').innerHTML = '<span class="err">That file is larger than 1 GB. Trim it in Wireshark (File → Export Specified Packets) first.</span>'; return; }
    el('pcName').textContent = `${file.name} · ${fmtB(file.size)}`;
    el('pcMsg').innerHTML = '<span class="spinner"></span> Reading the capture…'; el('pcOut').innerHTML = '';
    try {
      const res = await fetch('/api/pcap/analyze', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(file.name) }, body: file });
      const j = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      if (!res.ok || j.error) throw new Error(j.error || `HTTP ${res.status}`);
      R = j; flowFilter = null; tab = 'conv';
      el('pcMsg').textContent = `${fmtN(j.file.packets)} packets in ${j.file.ms} ms${j.file.capped ? ' (stopped at the packet limit)' : ''}${j.file.files.length > 1 ? ` · ${j.file.files.length} captures in the zip` : ''}.`;
      render();
    } catch (e) { el('pcMsg').innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  }

  function render() {
    const s = R.summary, f = R.file;
    const start = f.first ? new Date(f.first * 1000).toLocaleString() : '—';
    const stats = [
      ['Capture', fmtN(f.packets), `${ms(f.duration)} · ${start}`, ''],
      ['Conversations', fmtN(s.flows), `${fmtN(s.hosts)} hosts`, ''],
      ['Through ZIA', fmtN(s.viaZia), 'Service Edges / Zscaler IPs', s.viaZia ? 'zs' : ''],
      ['Through ZPA', fmtN(s.viaZpa), 'brokers / synthetic IPs', s.viaZpa ? 'zs' : ''],
      ['Direct', fmtN(s.direct), 'to the internet', s.direct ? 'warn' : ''],
      ['Failed', fmtN(s.failed), 'no answer, reset, TLS alert', s.failed ? 'bad' : 'good'],
      ['DNS', fmtN(s.dnsQueries), `${fmtN(s.dnsFailed)} failed`, s.dnsFailed ? 'bad' : ''],
      ['TLS', fmtN(s.tls), `${fmtN(s.inspected)} inspected by Zscaler${s.quic ? ` · ${s.quic} QUIC` : ''}`, ''],
    ];
    const tabs = [['conv', 'Conversations', R.flows.length], ['dns', 'DNS', R.dns.length], ['tls', 'TLS / HTTPS', R.flows.filter((x) => x.tls).length], ['path', 'Zscaler path', null]];
    el('pcOut').innerHTML = `
      <div class="stat-strip">${stats.map(([k, v, sub, c]) => `<div class="stat ${c}"><div class="k">${k}</div><div class="v">${v}</div><div class="s" title="${esc(sub)}">${esc(sub)}</div></div>`).join('')}</div>
      <div class="card"><div class="card-header" style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div><h3>What stands out</h3><p style="font-size:13px">Most important first. ▶ runs the destination through the Policy Simulator.</p></div>
        <button class="btn btn-ghost btn-sm" data-pact="csv">⬇ Conversations CSV</button></div>
        ${R.findings.length ? R.findings.map(findingRow).join('') : '<div class="empty">Nothing unusual: every connection completed and DNS answered.</div>'}</div>
      <div class="card"><div class="rtabs">${tabs.map(([k, l, n]) => `<button data-ptab="${k}" class="${k === tab ? 'on' : ''}">${l}${n != null ? `<span class="n">${fmtN(n)}</span>` : ''}</button>`).join('')}</div><div id="pcTab"></div></div>`;
    renderTab();
  }
  function findingRow(x) {
    return `<div class="finding"><div><span class="sev ${x.sev}">${x.sev}</span></div><div><div class="ft">${esc(x.title)}</div><div class="fd">${esc(x.detail)}</div>
      ${x.list ? `<div class="fd mono" style="margin-top:4px">${x.list.map(esc).join(' · ')}</div>` : ''}</div>
      <div class="fa">${x.flowRef ? `<button class="linkbtn2" data-pflow="${esc(x.flowRef)}">Show</button>` : ''}${x.simulate ? `<button class="simbtn" ${simAttrs(x.simulate)}>▶ Simulate</button>` : ''}</div></div>`;
  }
  function renderTab() {
    const box = el('pcTab'); if (!box) return;
    if (tab === 'conv') return convTab(box);
    if (tab === 'dns') return dnsTab(box);
    if (tab === 'tls') return tlsTab(box);
    return pathTab(box);
  }
  function convTab(box) {
    box.innerHTML = `<div class="tbar"><input type="text" id="pcQ" placeholder="Filter by host, IP or port…" value="${esc(flowFilter && flowFilter.q || '')}">
      <select id="pcSt"><option value="">All results</option><option value="failed">Failed only</option><option value="ok">Completed</option></select>
      <select id="pcVia"><option value="">All paths</option><option value="ZIA">ZIA</option><option value="ZPA">ZPA</option><option value="Zscaler">Zscaler services</option><option value="direct">Direct</option><option value="local">Local network</option></select>
      <select id="pcProto"><option value="">TCP + UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="other">Other</option></select>
      ${flowFilter && flowFilter.ref ? '<button class="btn btn-ghost btn-sm" id="pcClr">Show all</button>' : ''}<span class="form-hint" id="pcCount"></span></div><div class="tscroll" id="pcTbl"></div>`;
    const draw = () => {
      const q = el('pcQ').value.trim().toLowerCase(), st = el('pcSt').value, via = el('pcVia').value, pr = el('pcProto').value;
      let rows = R.flows;
      if (flowFilter && flowFilter.ref) rows = rows.filter((f) => ref(f) === flowFilter.ref);
      if (q) rows = rows.filter((f) => `${f.name || ''} ${f.server} ${f.client} ${f.sport} ${f.app} ${f.proxyTarget || ''}`.toLowerCase().includes(q));
      if (st === 'failed') rows = rows.filter((f) => ['no-answer', 'refused', 'reset', 'tls-alert'].includes(f.status)); else if (st === 'ok') rows = rows.filter((f) => f.status === 'ok');
      if (via) rows = rows.filter((f) => f.via === via);
      if (pr) rows = rows.filter((f) => (pr === 'other' ? !['tcp', 'udp'].includes(f.proto) : f.proto === pr));
      const shown = rows.slice(0, 800);
      el('pcCount').textContent = rows.length > shown.length ? `showing ${shown.length} of ${fmtN(rows.length)} (largest first)` : `${fmtN(rows.length)} conversation${rows.length === 1 ? '' : 's'}`;
      el('pcTbl').innerHTML = `<table><tr><th>Start</th><th>Proto</th><th>Client</th><th>Server</th><th>Name</th><th>App</th><th>Path</th><th>Result</th><th class="num">Pkts</th><th class="num">Out / In</th><th class="num">RTT</th><th class="num">Retx</th><th></th></tr>${shown.map((f) => {
        const s = simFor(f);
        return `<tr class="${flowFilter && flowFilter.ref === ref(f) ? 'sel' : ''}"><td class="mono nowrap dim">${rel(f.first)}</td><td class="mono">${esc(f.proto.toUpperCase())}</td><td class="mono nowrap">${esc(f.client)}${f.cport ? `<span class="dim">:${f.cport}</span>` : ''}</td>
          <td class="mono nowrap">${esc(f.server)}${f.sport ? `:${f.sport}` : ''}</td><td class="mono" style="word-break:break-all">${esc(f.name || '')}${f.proxyTarget ? `<div class="dim">→ ${esc(f.proxyTarget)}</div>` : ''}</td>
          <td class="nowrap">${esc(f.app || '')}${f.tls && f.tls.zscalerCert ? ' <span class="st warn" title="certificate issued by Zscaler">inspected</span>' : ''}</td><td>${viaBadge(f.via, f.role)}${f.role ? `<div class="form-hint" style="margin:2px 0 0">${esc(f.role)}</div>` : ''}</td>
          <td>${stBadge(f)}${f.detail ? `<div class="form-hint" style="margin:2px 0 0">${esc(f.detail)}</div>` : ''}</td><td class="num">${fmtN(f.packets)}</td><td class="num nowrap">${fmtB(f.bytesOut)} / ${fmtB(f.bytesIn)}</td>
          <td class="num">${f.rtt != null ? ms(f.rtt) : '—'}</td><td class="num">${f.retrans || ''}</td><td>${s ? `<button class="simbtn" ${simAttrs(s)}>▶</button>` : ''}</td></tr>`;
      }).join('')}</table>`;
    };
    for (const id of ['pcQ', 'pcSt', 'pcVia', 'pcProto']) el(id).addEventListener(id === 'pcQ' ? 'input' : 'change', draw);
    if (el('pcClr')) el('pcClr').onclick = () => { flowFilter = null; convTab(box); };
    draw();
  }
  function dnsTab(box) {
    box.innerHTML = `<div class="tbar"><input type="text" id="pcDq" placeholder="Filter names…"><select id="pcDs"><option value="">All</option><option value="bad">Failed or unanswered</option></select><span class="form-hint" id="pcDc"></span></div><div class="tscroll" id="pcDt"></div>`;
    const ST = { ok: ['ok', 'answered'], 'no-data': ['warn', 'no records'], error: ['bad', ''], 'no-response': ['bad', 'no response'] };
    const draw = () => {
      const q = el('pcDq').value.trim().toLowerCase(), bad = el('pcDs').value === 'bad';
      let rows = R.dns.filter((d) => (!q || d.name.includes(q)) && (!bad || d.status === 'error' || d.status === 'no-response'));
      el('pcDc').textContent = `${fmtN(rows.length)} quer${rows.length === 1 ? 'y' : 'ies'}`;
      rows = rows.slice(0, 1500);
      el('pcDt').innerHTML = `<table><tr><th>Time</th><th>Name</th><th>Type</th><th>Server</th><th>Answer</th><th>Result</th><th class="num">Time taken</th><th></th></tr>${rows.map((d) => {
        const [c, t] = ST[d.status] || ['dim', d.status];
        return `<tr><td class="mono nowrap dim">${rel(d.ts)}</td><td class="mono" style="word-break:break-all">${esc(d.name)}</td><td class="mono">${esc(d.type)}</td><td class="mono">${esc(d.server)}</td>
        <td class="mono" style="word-break:break-all">${esc(d.answers.map((a) => a.data).filter(Boolean).slice(0, 4).join(', '))}${d.answers.length > 4 ? ' …' : ''}</td><td><span class="st ${c}">${esc(t || d.rcode)}</span>${d.retries ? ` <span class="form-hint">${d.retries} retr${d.retries === 1 ? 'y' : 'ies'}</span>` : ''}</td>
        <td class="num">${d.rtt != null ? ms(d.rtt) : '—'}</td><td><button class="simbtn" ${simAttrs({ target: d.name, port: 443, protocol: 'tcp' })} title="Simulate HTTPS to this name">▶</button></td></tr>`;
      }).join('')}</table>`;
    };
    el('pcDq').addEventListener('input', draw); el('pcDs').addEventListener('change', draw); draw();
  }
  function tlsTab(box) {
    const rows = R.flows.filter((f) => f.tls);
    box.innerHTML = rows.length ? `<div class="form-hint" style="margin-bottom:8px">Certificates are only visible for TLS 1.2 and earlier (TLS 1.3 encrypts them). An issuer of Zscaler means ZIA SSL inspection decrypted the session.</div><div class="tscroll"><table><tr><th>Start</th><th>Server name (SNI)</th><th>Server</th><th>Version</th><th>ALPN</th><th>Certificate issuer</th><th>Alerts</th><th>Path</th><th></th></tr>${rows.slice(0, 1500).map((f) => {
      const t = f.tls, iss = t.cert ? [t.cert.issuer.CN, t.cert.issuer.O].filter(Boolean).join(' · ') : '';
      return `<tr><td class="mono nowrap dim">${rel(f.first)}</td><td class="mono" style="word-break:break-all">${esc(t.sni || '—')}${t.ech ? ' <span class="st dim" title="Encrypted Client Hello: real name hidden">ECH</span>' : ''}</td><td class="mono nowrap">${esc(f.server)}:${f.sport}</td>
        <td class="nowrap">${esc(t.version || (t.offered ? 'offered ' + t.offered.join(', ') : '—'))}</td><td class="mono">${esc((t.alpn || []).join(', '))}</td>
        <td>${t.cert ? `${t.zscalerCert ? '<span class="st warn">Zscaler</span> ' : ''}${esc(iss)}` : '<span class="dim">not visible</span>'}</td>
        <td>${t.alerts.length ? t.alerts.map((a) => `<span class="st ${a.level === 'fatal' ? 'bad' : 'dim'}">${esc(a.desc)}</span> <span class="form-hint">from ${esc(a.from)}</span>`).join('<br>') : '<span class="dim">none</span>'}</td>
        <td>${viaBadge(f.via, f.role)}</td><td>${simFor(f) ? `<button class="simbtn" ${simAttrs(simFor(f))}>▶</button>` : ''}</td></tr>`;
    }).join('')}</table></div>` : '<div class="empty">No TLS handshakes in this capture.</div>';
  }
  function pathTab(box) {
    const g = (pred) => R.flows.filter(pred);
    const group = (list) => { const m = new Map(); for (const f of list) { const k = f.name || f.server; const e = m.get(k) || { k, n: 0, bytes: 0, fail: 0, role: f.role, f }; e.n++; e.bytes += f.bytes; if (['no-answer', 'refused', 'reset', 'tls-alert'].includes(f.status)) e.fail++; m.set(k, e); } return [...m.values()].sort((a, b) => b.bytes - a.bytes); };
    const block = (title, hint, list, cls) => {
      const rows = group(list);
      return `<div class="card" style="background:var(--bg-input)"><div class="card-header"><h3>${viaBadge(cls)} ${esc(title)} <span class="form-hint">${fmtN(list.length)} conversation${list.length === 1 ? '' : 's'}</span></h3><p style="font-size:13px">${hint}</p></div>
        ${rows.length ? `<table><tr><th>Destination</th><th>Role</th><th class="num">Conns</th><th class="num">Failed</th><th class="num">Bytes</th><th></th></tr>${rows.slice(0, 25).map((r) => `<tr><td class="mono" style="word-break:break-all">${esc(r.k)}</td><td class="form-hint">${esc(r.role || '')}</td><td class="num">${r.n}</td><td class="num">${r.fail ? `<span class="err">${r.fail}</span>` : '0'}</td><td class="num">${fmtB(r.bytes)}</td><td>${simFor(r.f) ? `<button class="simbtn" ${simAttrs(simFor(r.f))}>▶</button>` : ''}</td></tr>`).join('')}</table>${rows.length > 25 ? `<div class="form-hint">… ${rows.length - 25} more</div>` : ''}` : '<div class="empty">None.</div>'}</div>`;
    };
    box.innerHTML = block('Zscaler Internet Access', 'Tunnels or proxy connections to ZIA Service Edges. Traffic inside a tunnel shows up here as one long connection.', g((f) => f.via === 'ZIA'), 'ZIA')
      + block('Zscaler Private Access', 'Client Connector to ZPA brokers, and app traffic to ZPA synthetic IPs (100.64.0.0/10).', g((f) => f.via === 'ZPA'), 'ZPA')
      + block('Other Zscaler services', 'Client Connector sign-in and config, ZDX, PAC downloads.', g((f) => f.via === 'Zscaler'), 'Zscaler')
      + block('Direct to the internet', 'Not through Zscaler. Expected for bypassed destinations; otherwise check the forwarding profile, app profile bypasses and PAC file.', g((f) => f.via === 'direct' && f.app !== 'DNS'), 'direct');
  }
  function onClick(e) {
    const t = e.target.closest('[data-ptab],[data-psim],[data-pflow],[data-pact]');
    if (!t) return;
    if (t.dataset.ptab) { tab = t.dataset.ptab; document.querySelectorAll('#pcOut [data-ptab]').forEach((b) => b.classList.toggle('on', b === t)); renderTab(); }
    else if (t.dataset.psim) { try { simulateDest(Object.assign(JSON.parse(t.dataset.psim), { source: 'Packet Capture Analyzer' })); } catch {} }
    else if (t.dataset.pflow) { flowFilter = { ref: t.dataset.pflow }; tab = 'conv'; document.querySelectorAll('#pcOut [data-ptab]').forEach((b) => b.classList.toggle('on', b.dataset.ptab === 'conv')); renderTab(); el('pcTab').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    else if (t.dataset.pact === 'csv') csv();
  }
  function csv() {
    const cols = ['start_s', 'proto', 'client', 'client_port', 'server', 'server_port', 'name', 'app', 'path', 'role', 'result', 'detail', 'packets', 'bytes_out', 'bytes_in', 'rtt_ms', 'retransmissions', 'tls_sni', 'tls_version', 'cert_issuer', 'ssl_inspected'];
    const q = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const rows = R.flows.map((f) => [f.first != null && R.file.first != null ? (f.first - R.file.first).toFixed(3) : '', f.proto, f.client, f.cport, f.server, f.sport, f.name, f.app, f.via, f.role, f.status, f.detail, f.packets, f.bytesOut, f.bytesIn,
      f.rtt != null ? Math.round(f.rtt * 1000) : '', f.retrans, f.tls && f.tls.sni, f.tls && f.tls.version, f.tls && f.tls.cert ? [f.tls.cert.issuer.CN, f.tls.cert.issuer.O].filter(Boolean).join(' / ') : '', f.tls ? (f.tls.zscalerCert ? 'yes' : 'no') : ''].map(q).join(','));
    const blob = new Blob([[cols.join(','), ...rows].join('\r\n')], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `${(R.file.name || 'capture').replace(/\.[^.]+$/, '')}-conversations.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  return { init() { if (!ready) { shell(); ready = true; } }, _state: () => R };
})();
