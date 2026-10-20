'use strict';
// Update check: compares this build with the version on GitHub main (package.json), like the Policy Wizard.
// Read-only: it only tells the user. Nothing is downloaded or replaced automatically.
const { fetchText } = require('./zscaler');

const REPO = 'ZeroTrustPanda/ZTP-Policy-Simulator';
const PKG_URL = `https://raw.githubusercontent.com/${REPO}/main/package.json`;
const TTL = 3600e3;

function cmp(a, b) {
  const pa = String(a || '0').split(/[.-]/).map((x) => parseInt(x, 10) || 0), pb = String(b || '0').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
}

// The zip for this computer, named as in downloads/vX.Y.Z/.
function platformAsset(v, platform = process.platform, arch = process.arch) {
  const plat = platform === 'win32' ? 'windows-x64' : platform === 'darwin' ? (arch === 'arm64' ? 'macos-arm64' : 'macos-x64') : null;
  if (!plat) return null;
  const name = `ZTP-Policy-Simulator-${v}-${plat}.zip`;
  return { platform: plat, name, url: `https://github.com/${REPO}/raw/main/downloads/v${v}/${name}` };
}

function result(current, latest, extra = {}) {
  const newer = !!latest && cmp(latest, current) > 0;
  return Object.assign({
    current, latest: latest || null, newer,
    releaseUrl: newer ? `https://github.com/${REPO}/releases/tag/v${latest}` : null,
    download: newer ? platformAsset(latest) : null,
    allDownloads: newer ? `https://github.com/${REPO}/releases/latest` : null,
  }, extra);
}

let cache = null;
async function checkUpdate(current, { fetch = fetchText, force = false } = {}) {
  if (process.env.NO_UPDATE_CHECK === '1') return result(current, null, { disabled: true });
  if (!force && cache && Date.now() - cache.at < TTL) return cache.body;
  let body;
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('timed out')), 8000).unref());
  try { body = result(current, JSON.parse(await Promise.race([fetch(PKG_URL), timeout])).version); }
  catch (e) { return result(current, null, { offline: true, error: String(e.message || e).slice(0, 120) }); } // not cached: try again next time
  cache = { at: Date.now(), body };
  return body;
}

module.exports = { checkUpdate, cmp, platformAsset, PKG_URL, _reset: () => { cache = null; } };
