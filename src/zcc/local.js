'use strict';
// From ZCC Log Explorer by Alex Bonner (github.com/alexbnn/zcc-log-explorer), included with permission;
// ported to CommonJS for the Zscaler Policy Troubleshooting Toolkit.
// Collect ZCC logs from the machine the server runs on.

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { expandUpload, isLogFileName } = require('./parser');

// macOS paths are verified against ZCC 5.x. Linux paths are best guesses;
// override with ZCC_LOG_DIRS (separated by ':' on macOS/Linux, ';' on Windows) if your install differs.
const DEFAULT_DIRS = {
  darwin: ['/Library/Application Support/Zscaler'],
  win32: [`${process.env.ProgramData || 'C:\\ProgramData'}\\Zscaler`],
  linux: ['/var/log/zscaler', '/opt/zscaler/var/log', '/opt/zscaler/log', '/var/lib/zscaler'],
};

function localLogDirs() {
  if (process.env.ZCC_LOG_DIRS) return process.env.ZCC_LOG_DIRS.split(path.delimiter).filter(Boolean);
  return DEFAULT_DIRS[os.platform()] || [];
}

async function walk(dir, depth, out) {
  let items;
  try {
    items = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const it of items) {
    const p = path.join(dir, it.name);
    if (it.isDirectory()) {
      if (depth > 0) await walk(p, depth - 1, out);
    } else if (it.isFile()) {
      out.push(p);
    }
  }
}

/**
 * Read local ZCC logs.
 * @param {{includeUpm?: boolean, sinceDays?: number}} opts
 */
async function readLocalLogs(opts = {}) {
  const dirs = localLogDirs();
  const paths = [];
  for (const d of dirs) await walk(d, 3, paths);
  const cutoff = opts.sinceDays ? Date.now() - opts.sinceDays * 86400e3 : 0;
  const files = [];
  const skipped = [];
  for (const p of paths) {
    const base = path.basename(p);
    const logName = base.replace(/\.zip$/i, '');
    if (!isLogFileName(logName, opts)) continue;
    try {
      const st = await fs.stat(p);
      if (st.size === 0) continue;
      if (cutoff && st.mtimeMs < cutoff) continue;
      const bytes = new Uint8Array(await fs.readFile(p));
      files.push(...expandUpload(base, bytes, opts));
    } catch (err) {
      skipped.push(`${p}: ${err.code || err.message}`);
    }
  }
  return { dirs, files, skipped };
}

module.exports = { localLogDirs, readLocalLogs };
