'use strict';
// Policy loading: products load in parallel, calls stay spaced per product, one token request is shared.
const test = require('node:test');
const assert = require('node:assert');
const https = require('https');
const { EventEmitter } = require('events');

test('policy load: parallel product lanes, per-product spacing, one shared token request', async () => {
  const realRequest = https.request;
  const starts = [];
  let tokenCalls = 0, inflight = 0, maxInflight = 0;
  https.request = (opts, cb) => {
    const req = new EventEmitter();
    req.setTimeout = () => {}; req.write = () => {}; req.destroy = () => {};
    req.end = () => {
      if (opts.path.includes('/oauth2/')) tokenCalls++;
      else starts.push({ fam: opts.path.split('/')[1], t: Date.now(), path: opts.path });
      inflight++; maxInflight = Math.max(maxInflight, inflight);
      setTimeout(() => {
        inflight--;
        const res = new EventEmitter(); res.statusCode = 200; res.headers = {}; res.setEncoding = () => {};
        cb(res);
        const body = opts.path.includes('/oauth2/') ? { access_token: 'h.e30.s', expires_in: 3600 }
          : /webApplicationRules\/WEBMAIL$/.test(opts.path) ? [{ id: 1, name: 'W' }] : /webApplicationRules\/AI_ML$/.test(opts.path) ? [{ id: 2, name: 'A' }]
            : /urlCategories/.test(opts.path) ? [{ id: 'CUSTOM_01', customCategory: true, urls: ['a.example'] }, { id: 'WEBMAIL', customCategory: false, urls: ['.mail.example'] }, { id: 'NEWS', customCategory: false, urls: [] }] : [];
        res.emit('data', JSON.stringify(body)); res.emit('end');
      }, 30);
    };
    return req;
  };
  try {
    delete require.cache[require.resolve('../src/zscaler')];
    const Z = require('../src/zscaler');
    const c = new Z.ZClient({ vanityDomain: 'acme', clientId: 'a', clientSecret: 'b', zpaCustomerId: '123456789012345678', rateGaps: { zia: 40, zcc: 40, ztw: 20, zpa: 10 } });
    const snap = await Z.loadSnapshot(c, { groups: ['zia', 'zcc', 'zpa', 'ztw'] });
    assert.equal(tokenCalls, 1, 'one token request shared by all lanes');
    assert.deepEqual(Object.keys(snap.errors), []);
    assert.ok(maxInflight > 1, 'products load in parallel');
    const zia = starts.filter((s) => s.fam === 'zia').map((s) => s.t);
    for (let i = 1; i < zia.length; i++) assert.ok(zia[i] - zia[i - 1] >= 38, `ZIA calls spaced (${zia[i] - zia[i - 1]} ms)`);
    // Cloud App Control rule types keep a stable order whatever order the responses arrive in
    assert.deepEqual(snap.data.cloudAppRules.map((r) => r.ruleType), ['WEBMAIL', 'AI_ML']);
    // URL categories: custom ones, plus predefined ones the tenant added URLs to; untouched predefined ones dropped
    assert.deepEqual(snap.data.customUrlCategories.map((x) => x.id), ['CUSTOM_01', 'WEBMAIL']);
  } finally {
    https.request = realRequest;
    delete require.cache[require.resolve('../src/zscaler')];
  }
});

test('npm test runs every test file (a new file left out of the list would be skipped silently)', () => {
  const fs = require('fs'), path = require('path');
  const script = require('../package.json').scripts.test;
  for (const f of fs.readdirSync(path.join(__dirname)).filter((x) => x.endsWith('.test.js'))) assert.ok(script.includes(`test/${f}`), `${f} is not in npm test`);
});
