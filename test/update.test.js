'use strict';
const test = require('node:test');
const assert = require('node:assert');
const U = require('../src/update');

test('version compare', () => {
  assert.ok(U.cmp('1.8.1', '1.8.0') > 0);
  assert.ok(U.cmp('1.10.0', '1.9.9') > 0);
  assert.equal(U.cmp('1.8.0', '1.8.0'), 0);
  assert.ok(U.cmp('1.7.9', '1.8.0') < 0);
});

test('platform download names match the release assets', () => {
  assert.equal(U.platformAsset('1.9.0', 'win32', 'x64').name, 'ZTP-Policy-Simulator-1.9.0-windows-x64.zip');
  assert.equal(U.platformAsset('1.9.0', 'darwin', 'arm64').url, 'https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.9.0/ZTP-Policy-Simulator-1.9.0-macos-arm64.zip');
  assert.equal(U.platformAsset('1.9.0', 'linux', 'x64'), null);
});

test('update check: newer, same, offline (not cached), disabled', async () => {
  U._reset();
  const newer = await U.checkUpdate('1.8.0', { fetch: async () => '{"version":"1.9.0"}', force: true });
  assert.equal(newer.newer, true); assert.equal(newer.latest, '1.9.0'); assert.match(newer.releaseUrl, /releases\/tag\/v1\.9\.0$/);
  const same = await U.checkUpdate('1.9.0', { fetch: async () => '{"version":"1.9.0"}', force: true });
  assert.equal(same.newer, false); assert.equal(same.download, null);
  U._reset();
  const off = await U.checkUpdate('1.8.0', { fetch: async () => { throw new Error('ENOTFOUND'); } });
  assert.equal(off.offline, true); assert.equal(off.newer, false);
  const again = await U.checkUpdate('1.8.0', { fetch: async () => '{"version":"2.0.0"}' });
  assert.equal(again.latest, '2.0.0'); // the failure wasn't cached
  process.env.NO_UPDATE_CHECK = '1';
  assert.equal((await U.checkUpdate('1.8.0', { force: true })).disabled, true);
  delete process.env.NO_UPDATE_CHECK;
});
