'use strict';
// Minimal ZIP reader (stored + deflate) using the central directory. Used for ZCC log bundles and capture bundles.
// Size-capped so a zip bomb can't exhaust memory; entries are inflated only if `want(name)` says so.
const zlib = require('zlib');

function readZip(buf, { want = () => true, maxTotal = 1024 * 1024 * 1024 } = {}) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('not a readable zip file');
  let n = buf.readUInt16LE(eocd + 10), p = buf.readUInt32LE(eocd + 16);
  if (n === 0xffff || p === 0xffffffff) { // Zip64: read the real count / offset from the Zip64 end record
    const loc = eocd - 20;
    if (loc >= 0 && buf.readUInt32LE(loc) === 0x07064b50) {
      const z = Number(buf.readBigUInt64LE(loc + 8));
      if (z + 56 <= buf.length && buf.readUInt32LE(z) === 0x06064b50) { n = Number(buf.readBigUInt64LE(z + 32)); p = Number(buf.readBigUInt64LE(z + 48)); }
    }
  }
  const out = []; let total = 0;
  for (let i = 0; i < n && p + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    let csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24), loc = buf.readUInt32LE(p + 42);
    const nlen = buf.readUInt16LE(p + 28), elen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const name = buf.toString('utf8', p + 46, p + 46 + nlen);
    // Zip64 extra field carries the sizes / offset that didn't fit in 32 bits
    if (usize === 0xffffffff || csize === 0xffffffff || loc === 0xffffffff) {
      let e = p + 46 + nlen; const end = e + elen;
      while (e + 4 <= end) {
        const id = buf.readUInt16LE(e), sz = buf.readUInt16LE(e + 2); let q = e + 4;
        if (id === 1) {
          if (usize === 0xffffffff && q + 8 <= end) { usize = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (csize === 0xffffffff && q + 8 <= end) { csize = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (loc === 0xffffffff && q + 8 <= end) { loc = Number(buf.readBigUInt64LE(q)); }
        }
        e += 4 + sz;
      }
    }
    p += 46 + nlen + elen + clen;
    if (name.endsWith('/') || !want(name, usize)) continue;
    if (loc + 30 > buf.length || buf.readUInt32LE(loc) !== 0x04034b50) { out.push({ name, error: 'damaged entry' }); continue; }
    const start = loc + 30 + buf.readUInt16LE(loc + 26) + buf.readUInt16LE(loc + 28);
    if (start + csize > buf.length) { out.push({ name, error: 'truncated entry' }); continue; }
    if (total + usize > maxTotal) throw Object.assign(new Error(`The zip expands to more than ${Math.round(maxTotal / 1048576)} MB`), { status: 413 });
    const raw = buf.subarray(start, start + csize);
    let data;
    try {
      if (method === 0) data = raw;
      else if (method === 8) data = zlib.inflateRawSync(raw, { maxOutputLength: Math.max(1, maxTotal - total) });
      else { out.push({ name, error: `unsupported compression (method ${method})` }); continue; }
    } catch (err) {
      if (err.code === 'ERR_BUFFER_TOO_LARGE') throw Object.assign(new Error(`The zip expands to more than ${Math.round(maxTotal / 1048576)} MB`), { status: 413 });
      out.push({ name, error: `could not inflate: ${err.message}` }); continue;
    }
    total += data.length; out.push({ name, data });
  }
  return out;
}
const isZip = (b) => b.length > 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04;

module.exports = { readZip, isZip };
