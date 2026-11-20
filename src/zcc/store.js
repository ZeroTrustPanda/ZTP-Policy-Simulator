'use strict';
// From ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission;
// ported to CommonJS for the Zscaler Policy Troubleshooting Toolkit.
// In-memory datasets. Each dataset is one log bundle (uploaded or read from this machine).

const { randomUUID } = require('node:crypto');
const { buildTimeline } = require('./parser');
const { analyzeZpa, summarizeApps } = require('./zpa');
const { triage } = require('./errors');
const { analyzeZia, summarizeHosts } = require('./zia');
const { FLAG_ZIA, TS_MODE } = require('./parser');

const datasets = new Map();

function listDatasets() {
  return [...datasets.values()].map((d) => d.meta());
}

function getDataset(id) {
  return datasets.get(id) || null;
}

function deleteDataset(id) {
  return datasets.delete(id);
}

function createDataset(name, source) {
  const d = new Dataset(name, source);
  datasets.set(d.id, d);
  return d;
}

class Dataset {
  constructor(name, source) {
    this.id = randomUUID().slice(0, 8);
    this.name = name;
    this.source = source;
    this.created = Date.now();
    this.pending = []; // {name, text} files waiting for finalize()
    this.warnings = [];
    this.ready = false;
    this.filterCache = new Map();
  }

  addFiles(files) {
    for (const f of files) {
      if (f.error) this.warnings.push(`${f.name}: ${f.error}`);
      else this.pending.push(f);
    }
  }

  finalize() {
    const t0 = Date.now();
    const tl = buildTimeline(this.pending);
    this.pending = [];
    this.files = tl.files;
    this.tl = tl;
    this.zpa = analyzeZpa(tl);
    this.apps = summarizeApps(this.zpa);
    this.zia = analyzeZia(tl);
    this.hosts = summarizeHosts(this.zia);
    // Tag every line of a ZIA connection so the timeline's ZIA filter finds them.
    const lf = this.zia.lineFlags;
    for (let k = 0; k < lf.length; k += 2) if (!lf[k + 1].zpa && !lf[k + 1].internal) tl.flags[lf[k]] |= FLAG_ZIA;
    delete this.zia.lineFlags;
    this.triage = triage(tl);
    const files = tl.files;
    this.ready = true;
    this.buildMs = Date.now() - t0;
    for (const f of files) if (!f.entries && f.lines) this.warnings.push(`Skipped ${f.name}: no ZCC-format timestamps`);
    if (!files.some((f) => f.component === 'Tunnel')) {
      this.warnings.push('No ZSATunnel log found. ZPA views need ZSATunnel_*.log files.');
    }
    return this;
  }

  meta() {
    return {
      id: this.id,
      name: this.name,
      source: this.source,
      created: this.created,
      ready: this.ready,
      entries: this.tl?.length ?? 0,
      files: this.files?.length ?? this.pending.length,
    };
  }

  summary() {
    const tl = this.tl;
    const levels = { DBG: 0, INF: 0, WAR: 0, ERR: 0 };
    const comps = {};
    for (let i = 0; i < tl.length; i++) {
      levels[tl.level(i)]++;
      const c = tl.comp(i);
      comps[c] = (comps[c] || 0) + 1;
    }
    const mt = this.zpa.mtunnels;
    const mtStatus = { established: 0, closed: 0, failed: 0, pending: 0, unknown: 0 };
    for (const m of mt) mtStatus[m.status] = (mtStatus[m.status] || 0) + 1;
    return {
      ...this.meta(),
      buildMs: this.buildMs,
      warnings: this.warnings,
      fileList: this.files,
      range: tl.length ? { from: tl.ts[0], to: tl.ts[tl.length - 1] } : null,
      tz: mostCommonTz(tl),
      tsMode: TS_MODE,
      levels,
      components: comps,
      zpa: {
        info: this.zpa.info,
        sessions: this.zpa.sessions.length,
        segments: this.zpa.segments.length,
        segmentDownloads: this.zpa.segmentBatches.filter((b) => b.complete).length,
        segmentUpdates: this.zpa.segmentBatches.filter((b) => !b.complete).length,
        mtunnels: mt.length,
        mtStatus,
        apps: this.apps.length,
        topErrors: this.zpa.zpnErrors.slice(0, 8),
        dnsChecks: this.zpa.dnsChecks.length,
        histogram: histogram(mt),
      },
      zia: {
        state: this.zia.info.state,
        lastState: this.zpa.info.lastState?.zia ?? null,
        gateways: this.zia.info.gateways.length,
        transport: this.zia.info.profile?.settings?.primaryTransport ?? null,
        forwarding: this.zia.info.profile?.action ?? null,
        flows: this.zia.flows.length,
        flowStatus: countBy(this.zia.flows, (f) => f.status),
        paths: countBy(this.zia.flows, (f) => f.path),
        hosts: this.hosts.length,
        health: this.zia.health.ZIA || null,
        topErrors: this.zia.errors.slice(0, 5).map(({ hosts, ...r }) => r),
        histogram: histogram(this.zia.flows),
      },
      errorGroups: this.triage.filter((g) => g.lvl === 'ERR').length,
    };
  }

  /** Indices of entries matching a filter; cached because the UI pages through results. */
  filter(params) {
    const key = JSON.stringify(params);
    const hit = this.filterCache.get(key);
    if (hit) return hit;
    const { q, regex, levels, comps, svc, hideNoise, from, to, tag } = params;
    const svcBit = svc === 'zpa' ? 2 : svc === 'zia' ? 4 : 0;
    let rx = null;
    if (q) {
      try {
        rx = regex ? new RegExp(q, 'i') : null;
      } catch (err) {
        throw Object.assign(new Error(`Invalid regex: ${err.message}`), { status: 400 });
      }
    }
    const needle = q && !regex ? q.toLowerCase() : null;
    const tl = this.tl;
    const LV = ['DBG', 'INF', 'WAR', 'ERR'];
    const lv = levels ? new Set(levels.split(',').map((l) => LV.indexOf(l))) : null;
    const cp = comps ? new Set(comps.split(',').map((c) => tl.comps.indexOf(c))) : null;
    // A ZPA mTunnel tag_id or a ZSATunnel connection id ("ID=123, ...").
    const tagRx = tag ? new RegExp(`(tag_id"?:\\s*${tag}\\b|TAG[-=]ID=${tag}\\b|tag id:? ${tag}\\b|TAG=${tag}\\b|\\bID=${tag},|for ID: ${tag}\\))`, 'i') : null;
    const out = [];
    for (let i = 0; i < tl.length; i++) {
      if (lv && !lv.has(tl.lvl[i])) continue;
      if (cp && !cp.has(tl.fileComp[tl.file[i]])) continue;
      const fl = tl.flags[i];
      if (svcBit && !(fl & svcBit)) continue;
      if (hideNoise && fl & 1) continue;
      if (from && tl.ts[i] < from) continue;
      if (to && tl.ts[i] > to) continue;
      if (!tagRx && !needle && !rx) {
        out.push(i);
        continue;
      }
      const msg = tl.msg(i);
      if (tagRx && !tagRx.test(msg)) continue;
      if (needle && !msg.toLowerCase().includes(needle)) continue;
      if (rx && !rx.test(msg)) continue;
      out.push(i);
    }
    const arr = Int32Array.from(out);
    if (this.filterCache.size > 30) this.filterCache.delete(this.filterCache.keys().next().value);
    this.filterCache.set(key, arr);
    return arr;
  }
}

// Offset like "-0400" that most lines were written in; the UI shows times in it.
function countBy(arr, fn) {
  const m = {};
  for (const x of arr) {
    const k = fn(x);
    m[k] = (m[k] || 0) + 1;
  }
  return m;
}

function mostCommonTz(tl) {
  const c = {};
  for (let k = 0; k < tl.length; k += 97) {
    const tz = tl.tzText(k);
    c[tz] = (c[tz] || 0) + 1;
  }
  return Object.entries(c).sort((a, b) => b[1] - a[1])[0]?.[0] || '';
}

// Connection outcomes (failed vs. everything else) bucketed over time for the overview charts.
function histogram(mt) {
  if (!mt.length) return null;
  const from = mt[0].ts;
  const to = mt[mt.length - 1].ts;
  const span = Math.max(to - from, 60000);
  const steps = [60e3, 5 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 86400e3];
  const bucket = steps.find((s) => span / s <= 120) || 86400e3;
  const start = Math.floor(from / bucket) * bucket;
  const n = Math.floor((to - start) / bucket) + 1;
  const ok = new Array(n).fill(0);
  const failed = new Array(n).fill(0);
  for (const m of mt) {
    const k = Math.floor((m.ts - start) / bucket);
    if (m.status === 'failed') failed[k]++;
    else ok[k]++;
  }
  return { start, bucket, ok, failed };
}

module.exports = { listDatasets, getDataset, deleteDataset, createDataset };
