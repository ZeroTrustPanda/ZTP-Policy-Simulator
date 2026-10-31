'use strict';
// Line sources: a string, an array of lines, or a Readable stream (streamed via readline, constant memory).
const readline = require('readline');

async function* linesOf(src) {
  if (typeof src === 'string') { yield* src.replace(/^\uFEFF/, '').split(/\r?\n/); return; }
  if (Array.isArray(src)) { yield* src; return; }
  if (src && typeof src.pipe === 'function') {
    let first = true;
    for await (const l of readline.createInterface({ input: src, crlfDelay: Infinity })) { yield first ? l.replace(/^\uFEFF/, '') : l; first = false; }
    return;
  }
  throw new TypeError('expected string, array of lines, or readable stream');
}

// RFC 4180-ish: comma-delimited, quoted fields with "" escapes and embedded newlines.
async function* csvRows(src, delim = ',') {
  let cells = [], cur = '', q = false, any = false;
  for await (const line of linesOf(src)) {
    if (q) cur += '\n';
    for (let i = 0; i < line.length; i++) {
      const ch = line[i]; any = true;
      if (q) {
        if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch;
      } else if (ch === '"') q = true;
      else if (ch === delim) { cells.push(cur); cur = ''; } else cur += ch;
    }
    if (q) continue;
    cells.push(cur);
    if (any) yield cells.map((c) => c.trim());
    cells = []; cur = ''; any = false;
  }
  if (q) { cells.push(cur); yield cells.map((c) => c.trim()); }
}

module.exports = { linesOf, csvRows };
