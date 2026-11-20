'use strict';
// From ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission;
// ported to CommonJS for the Zscaler Policy Troubleshooting Toolkit.
// Parses Zscaler Client Connector log files into normalized entries.
//
// Observed macOS line format (ZCC 4.x/5.x):
//   2026-10-14 18:20:30.383195(-0400)[59125:4427296] INF [LogMon] message
// Lines that don't start with a timestamp continue the previous entry
// (e.g. pretty-printed XPC dictionaries). The header regex is deliberately
// lenient about the offset/pid/level parts so Linux builds that vary slightly
// still parse.
//
// Timestamps: ZCC on macOS writes the UTC wall clock but labels it with the
// machine's local offset (a line stamped "23:55:15(-0400)" was written at
// 19:55 EDT). So by default the clock is read as UTC and the label is kept
// only for display. Set ZCC_TS_MODE=offset to honor the label instead.

const { readZip } = require('../zip');

// Largest a log bundle may expand to (all files together).
const ZIP_MAX = 2 * 1024 * 1024 * 1024 - 1;
const path = require('node:path');

const HEADER_RX =
  /^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?\s*(?:\(?\s*(Z|[+-]\d\d:?\d\d)\s*\)?)?\s*(?:\[(\d+):(\d+)\])?\s*(DBG|INF|WAR|WRN|ERR|FTL|TRC|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE|CRITICAL)?\s?(.*)$/;

const TS_MODE = process.env.ZCC_TS_MODE === 'offset' ? 'offset' : 'utc';

const LEVELS = ['DBG', 'INF', 'WAR', 'ERR'];
const FLAG_NOISE = 1;
const FLAG_ZPA = 2;
const FLAG_ZIA = 4;
const LEVEL_CODE = {
  DBG: 0, DEBUG: 0, TRC: 0, TRACE: 0,
  INF: 1, INFO: 1,
  WAR: 2, WRN: 2, WARN: 2, WARNING: 2,
  ERR: 3, ERROR: 3, FTL: 3, FATAL: 3, CRITICAL: 3,
};

// Messages that repeat constantly and drown out signal when reading a timeline.
const NOISE_RX = new RegExp(
  [
    'fohh_status_(?:request|response)',
    'zpnSocketReadCallback',
    'Zpn socket (?:read|Written) bytes',
    'socketreadcallback brokerIp',
    '^START_TLV_PARSING',
    'Response tag: \\d+; Response length',
    'XPC connection initiated',
    'Ignored response of XPC request',
    'registerEventsForZpnSocket',
    'sendNotificationToTray',
    'isZTunnelStartCompleted',
    '^notify tunnel status update',
    '^ZApp Status:',
    'sendNotificationToFirewall',
    'Status Response json: Written',
    'Zpn Not enough bytes to process',
  ].join('|'),
);

const ZPA_RX = /zpn|zpa|mtunnel|broker|fohh|app.?connector|tag_id|TAG-ID/i;
// Tunnel-level ZIA lines; per-connection ZIA lines are flagged later by the ZIA analyzer.
const ZIA_RX = /\bSME\b|\bZIA|ZPHM|ZT2|Z-?Tunnel ?2|tunnel2|TUN-Proxy|LCL-Proxy|PAC Parse|refreshSMEIp|gateway\.zscaler/;

/** Map a log file name to a short component label. */
function classifyFile(name) {
  const base = path.basename(name);
  const m = base.match(/^(ZSA[A-Za-z]+?)(?:_([A-Za-z]+))?_\d{4}-\d\d-\d\d/);
  if (m) {
    const comp = m[1].replace(/^ZSA/, '');
    if (comp === 'Upm') return m[2] ? `UPM/${m[2]}` : 'UPM';
    return comp; // Tunnel, Service, Tray, TrayManager, ...
  }
  if (/UPMServiceController/i.test(base)) return 'UPM';
  return base.replace(/(_\d{4}-\d\d-\d\d[-\d.]*)?\.log(\.zip)?$/i, '') || base;
}

/** Files that are worth parsing at all. UPM files are opt-in because they are large and not ZPA. */
function isLogFileName(name, { includeUpm = false } = {}) {
  const base = path.basename(name);
  if (base.startsWith('.') || base.startsWith('__MACOSX')) return false;
  if (!/\.(log|txt)$/i.test(base) && !/\.log\.\d+$/i.test(base)) return false;
  if (!includeUpm && /^(ZSAUpm|com\.zscaler\.UPMServiceController)/i.test(base)) return false;
  return true;
}

function parseTs(m) {
  const frac = (m[7] || '0').padEnd(6, '0');
  let ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + Number(frac.slice(0, 6)) / 1000;
  return TS_MODE === 'offset' ? ms - tzMinutes(m[8]) * 60000 : ms;
}

// "-0400" / "+05:30" / "Z" → minutes east of UTC. Lines without an offset are treated as UTC.
function tzMinutes(off) {
  if (!off || off === 'Z') return 0;
  const sign = off[0] === '-' ? -1 : 1;
  const digits = off.slice(1).replace(':', '');
  return sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4)));
}

/**
 * Parse one file's text, appending one row per entry to the column arrays.
 * An entry spans from its header line through any continuation lines; we
 * keep [start, end) offsets into the text instead of copying the message.
 */
function parseInto(text, fileIdx, cols) {
  const first = cols.ts.length;
  let lineNo = 0;
  let pos = 0;
  let open = false; // whether an entry is open and awaiting its end offset
  const len = text.length;
  const close = (at) => {
    if (!open) return;
    let e = at;
    while (e > cols.msgStart[cols.msgStart.length - 1] && (text[e - 1] === '\n' || text[e - 1] === '\r')) e--;
    cols.end.push(e);
    open = false;
  };
  while (pos < len) {
    let nl = text.indexOf('\n', pos);
    if (nl === -1) nl = len;
    lineNo++;
    const lineLen = nl - pos;
    const m = lineLen > 18 && text.charCodeAt(pos) >= 48 && text.charCodeAt(pos) <= 57 ? HEADER_RX.exec(text.slice(pos, Math.min(nl, pos + 120))) : null;
    if (m) {
      close(pos);
      cols.ts.push(parseTs(m));
      cols.tz.push(tzMinutes(m[8]));
      cols.pid.push(m[9] ? Number(m[9]) : 0);
      cols.tid.push(m[10] ? Number(m[10]) : 0);
      cols.lvl.push(LEVEL_CODE[m[11]] ?? 1);
      cols.file.push(fileIdx);
      cols.line.push(lineNo);
      // Message starts after the header; m.index is 0 so the header length is total - message.
      const headerLen = m[0].length - m[12].length;
      cols.msgStart.push(pos + headerLen);
      open = true;
    } else if (!open && text.slice(pos, nl).trim()) {
      // Preamble before the first timestamped line (e.g. "Redirected stderr").
      cols.ts.push(NaN);
      cols.tz.push(0);
      cols.pid.push(0);
      cols.tid.push(0);
      cols.lvl.push(1);
      cols.file.push(fileIdx);
      cols.line.push(lineNo);
      cols.msgStart.push(pos);
      open = true;
    }
    pos = nl + 1;
  }
  close(len);
  // Give preamble lines the first real timestamp so they sort with their file.
  let real = first;
  while (real < cols.ts.length && Number.isNaN(cols.ts[real])) real++;
  if (real === cols.ts.length) {
    // No ZCC-format timestamps at all (e.g. routeMonitor.log): not a log we can place on the timeline.
    for (const col of Object.values(cols)) col.length = first;
    return { lines: lineNo, entries: 0 };
  }
  for (let k = first; k < real; k++) {
    cols.ts[k] = cols.ts[real];
    cols.tz[k] = cols.tz[real];
  }
  return { lines: lineNo, entries: cols.ts.length - first };
}

/**
 * Expand an uploaded blob into a flat list of {name, text} log files.
 * Handles ZCC "Export Logs" bundles, which nest rotated .log.zip files inside the outer zip.
 */
function expandUpload(name, bytes, opts = {}, depth = 0) {
  const out = [];
  const isZip = bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
  if (isZip) {
    if (depth > 4) return out;
    let files;
    try {
      // Inflate only what the loop below keeps: log files and nested rotated .log.zip files.
      const want = (inner) => {
        const b = path.basename(inner);
        if (b.startsWith('.') || inner.includes('__MACOSX')) return false;
        if (/\.zip$/i.test(b)) { const logName = b.replace(/\.zip$/i, ''); return !/\.log$/i.test(logName) || isLogFileName(logName, opts); }
        return isLogFileName(b, opts);
      };
      files = {};
      for (const e of readZip(bytes, { want, maxTotal: ZIP_MAX })) {
        if (e.data) files[e.name] = e.data;
        else out.push({ name: e.name, error: e.error });
      }
    } catch (err) {
      if (err.status === 413) throw err;
      out.push({ name, error: `Could not unzip: ${err.message}` });
      return out;
    }
    for (const [inner, data] of Object.entries(files)) {
      if (inner.endsWith('/') || data.length === 0) continue;
      const innerName = path.basename(inner);
      if (innerName.startsWith('.') || inner.includes('__MACOSX')) continue;
      if (/\.zip$/i.test(innerName)) {
        // Rotated logs are named like X.log.zip; apply the name filter before inflating them.
        const logName = innerName.replace(/\.zip$/i, '');
        if (/\.log$/i.test(logName) && !isLogFileName(logName, opts)) continue;
        out.push(...expandUpload(innerName, data, opts, depth + 1));
      } else if (isLogFileName(innerName, opts)) {
        out.push({ name: innerName, text: decode(data) });
      }
    }
    return out;
  }
  if (isLogFileName(name, opts) || depth === 0) out.push({ name: path.basename(name), text: decode(bytes) });
  return out;
}

const decoder = new TextDecoder('utf-8', { fatal: false });
function decode(bytes) {
  return decoder.decode(bytes);
}

/**
 * Columnar, chronologically sorted view over all parsed files.
 * Memory is ~30 bytes per entry plus the original file text.
 */
class Timeline {
  constructor(files, texts, cols) {
    this.files = files;
    this.texts = texts;
    this.comps = [...new Set(files.map((f) => f.component))];
    this.fileComp = Uint8Array.from(files.map((f) => this.comps.indexOf(f.component)));
    Object.assign(this, cols);
    this.length = cols.ts.length;
  }
  msg(i) {
    return this.texts[this.file[i]].slice(this.start[i], this.end[i]);
  }
  comp(i) {
    return this.comps[this.fileComp[this.file[i]]];
  }
  level(i) {
    return LEVELS[this.lvl[i]];
  }
  isNoise(i) {
    return (this.flags[i] & FLAG_NOISE) !== 0;
  }
  isZpa(i) {
    return (this.flags[i] & FLAG_ZPA) !== 0;
  }
  isZia(i) {
    return (this.flags[i] & FLAG_ZIA) !== 0;
  }
  isMulti(i) {
    const t = this.texts[this.file[i]];
    const nl = t.indexOf('\n', this.start[i]);
    return nl !== -1 && nl < this.end[i];
  }
  /** Original timestamp text as written in the log, e.g. "2026-10-14 18:20:30.383195". */
  time(i) {
    const us = Math.round(this.ts[i] * 1000) + (TS_MODE === 'offset' ? this.tz[i] * 60e6 : 0);
    const d = new Date(Math.floor(us / 1000));
    const p = (n, w = 2) => String(n).padStart(w, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(((us % 1e6) + 1e6) % 1e6, 6)}`;
  }
  tzText(i) {
    const m = this.tz[i];
    const a = Math.abs(m);
    return `${m < 0 ? '-' : '+'}${String(Math.floor(a / 60)).padStart(2, '0')}${String(a % 60).padStart(2, '0')}`;
  }
}

/**
 * Parse many files and merge them into one chronologically sorted timeline.
 * @param {{name: string, text: string}[]} files
 */
function buildTimeline(files) {
  const fileMeta = [];
  const texts = [];
  const seen = new Set();
  const raw = { ts: [], tz: [], pid: [], tid: [], lvl: [], file: [], line: [], msgStart: [], end: [] };
  for (const f of files) {
    if (!f.text || seen.has(f.name)) continue;
    seen.add(f.name);
    const idx = fileMeta.length;
    const before = raw.ts.length;
    const { entries, lines } = parseInto(f.text, idx, raw);
    texts.push(f.text);
    fileMeta.push({
      name: f.name,
      component: classifyFile(f.name),
      lines,
      entries,
      first: entries ? raw.ts[before] : null,
      last: entries ? raw.ts[raw.ts.length - 1] : null,
    });
  }
  const n = raw.ts.length;
  const ts0 = Float64Array.from(raw.ts);
  const file0 = Uint16Array.from(raw.file);
  // Rows are appended file by file in line order, so the row index is the final tie-breaker.
  const order = new Uint32Array(n);
  for (let k = 0; k < n; k++) order[k] = k;
  order.sort((a, b) => ts0[a] - ts0[b] || file0[a] - file0[b] || a - b);
  const pick = (src, Type) => {
    const out = new Type(n);
    for (let k = 0; k < n; k++) out[k] = src[order[k]];
    return out;
  };
  const cols = {
    ts: pick(ts0, Float64Array),
    tz: pick(raw.tz, Int16Array),
    pid: pick(raw.pid, Uint32Array),
    tid: pick(raw.tid, Uint32Array),
    lvl: pick(raw.lvl, Uint8Array),
    file: pick(file0, Uint16Array),
    line: pick(raw.line, Uint32Array),
    start: pick(raw.msgStart, Uint32Array),
    end: pick(raw.end, Uint32Array),
    flags: new Uint8Array(n),
  };
  const tl = new Timeline(fileMeta, texts, cols);
  const tunnelOrService = new Set(['Tunnel', 'Service'].map((c) => tl.comps.indexOf(c)).filter((x) => x >= 0));
  const tunnel = tl.comps.indexOf('Tunnel');
  for (let i = 0; i < n; i++) {
    const msg = tl.msg(i);
    let fl = NOISE_RX.test(msg) ? FLAG_NOISE : 0;
    const comp = tl.fileComp[cols.file[i]];
    if (tunnelOrService.has(comp) && ZPA_RX.test(msg)) fl |= FLAG_ZPA;
    if (comp === tunnel && ZIA_RX.test(msg)) fl |= FLAG_ZIA;
    cols.flags[i] = fl;
  }
  return tl;
}

module.exports = { TS_MODE, LEVELS, FLAG_NOISE, FLAG_ZPA, FLAG_ZIA, classifyFile, isLogFileName, expandUpload, Timeline, buildTimeline };
