'use strict';
const test = require('node:test');
const assert = require('node:assert');
const M = require('../src/matchers');
const W = require('../src/workload');
const { simulate } = require('../src/engine');
const snap = require('../src/demo-snapshot.json');

function run(over) {
  const t = M.parseTarget(over.target || '');
  const ctx = Object.assign({ port: t && t.port, protocol: 'tcp', groups: [], categories: [], resolvedIps: [], notes: [] }, over);
  ctx.target = t;
  if (over.port != null) ctx.port = over.port;
  return simulate({ data: snap }, ctx, {});
}
const mod = (r, name) => r.modules.find((m) => m.module.startsWith(name));

test('workload tags parse with and without a type', () => {
  assert.deepEqual(W.parseTags('VPC:Vpc-id=vpc-1, Env=prod; ENI:Name=web'), [
    { type: 'VPC', key: 'Vpc-id', value: 'vpc-1' }, { type: null, key: 'Env', value: 'prod' }, { type: 'ENI', key: 'Name', value: 'web' }]);
  assert.deepEqual(W.parseTags('http://x=1'), [{ type: null, key: 'http://x', value: '1' }]);
});

test('workload group expression: AND of containers, typed and untyped tags', () => {
  const g = snap.workloadGroups[0];
  assert.equal(W.evalGroup(g, W.parseTags('VPC:Vpc-id=vpc-0prod1, Env=prod')).status, 'match');
  assert.equal(W.evalGroup(g, W.parseTags('Vpc-id=vpc-0prod1')).status, 'nomatch');
  assert.equal(W.evalGroup(g, W.parseTags('ENI:Vpc-id=vpc-0prod1, Env=prod')).status, 'nomatch'); // wrong tag type
  assert.equal(W.evalGroup(g, []).status, 'unknown');
  const orG = { name: 'or', expressionJson: { expressionContainers: [
    { tagType: 'ATTR', operator: 'OR', tagContainer: { operator: 'OR', tags: [{ key: 'A', value: '1' }, { key: 'B', value: '2' }] } },
    { tagType: 'VM', operator: 'OR', tagContainer: { operator: 'AND', tags: [{ key: 'C', value: '3' }] } }] } };
  assert.equal(W.evalGroup(orG, W.parseTags('B=2')).status, 'match');
  assert.equal(W.evalGroup(orG, W.parseTags('D=4')).status, 'nomatch');
});

test('connector forwarding: workload group to ZPA, then the ZPA access policy for edge connectors', () => {
  const r = run({ source: 'workload', target: 'lab.hospital.example', port: 443, workloadTags: 'ENI:Role=lab-analyzer', ecGroupName: 'AWS us-east-1 Connectors' });
  const f = mod(r, 'Forwarding (Cloud');
  assert.equal(f.verdict, 'VIA_ZPA');
  assert.equal(f.decidingRule.name, 'Lab Analyzers to ZPA');
  const z = mod(r, 'ZPA Access');
  assert.equal(z.verdict, 'ALLOW');
  assert.equal(z.decidingRule.name, 'Allow Lab Analyzers (Cloud Connector)');
  assert.equal(r.summary.primary.action, 'ALLOW');
  assert.equal(r.context.location, 'AWS us-east-1'); // from the connector group
  assert.equal(r.context.connectorKind, 'cloud');
});

test('workloads never match user/SCIM rules, and branch connectors miss edge-connector client types', () => {
  const r = run({ source: 'workload', target: 'lab.hospital.example', port: 443, workloadTags: 'ENI:Role=lab-analyzer', connectorKind: 'branch' });
  const z = mod(r, 'ZPA Access');
  assert.equal(z.verdict, 'BLOCK');
  assert.ok(z.rules.every((e) => e.status === 'nomatch'));
});

test('ZPA segment, but the connector forwards to ZIA: ZPA does not decide', () => {
  const r = run({ source: 'workload', target: 'lab.hospital.example', port: 443, sourceIp: '10.20.1.5' });
  assert.equal(mod(r, 'Forwarding (Cloud').verdict, 'VIA_ZSCALER');
  assert.equal(mod(r, 'ZPA Access').verdict, 'N/A');
  assert.notEqual(r.summary.primary.module, 'ZPA Access Policy');
});

test('DROP rule blocks; workload group criterion in ZIA firewall rules', () => {
  const drop = run({ source: 'workload', target: '203.0.113.9', port: 445, workloadGroups: ['AWS Prod Web'] });
  assert.equal(drop.summary.primary.action, 'BLOCK');
  assert.equal(drop.summary.primary.rule, 'Drop SMB from Prod');
  const ssh = run({ source: 'workload', target: '203.0.113.9', port: 22, workloadTags: 'VPC:Vpc-id=vpc-0prod1, ATTR:Env=prod' });
  assert.equal(mod(ssh, 'Firewall').decidingRule.name, 'Block SSH from Prod Workloads');
  assert.equal(ssh.summary.primary.action, 'BLOCK');
  const other = run({ source: 'workload', target: '203.0.113.9', port: 22, workloadTags: 'Env=dev' });
  assert.notEqual(mod(other, 'Firewall').decidingRule && mod(other, 'Firewall').decidingRule.name, 'Block SSH from Prod Workloads');
  const user = run({ source: 'device', target: '203.0.113.9', port: 22 });
  const fwRule = mod(user, 'Firewall').rules.find((e) => e.name === 'Block SSH from Prod Workloads');
  assert.equal(fwRule.status, 'nomatch'); // user-device traffic is not a workload
});

test('source IP group sends medical devices direct; unknown workload context is conditional', () => {
  const d = run({ source: 'workload', target: 'updates.vendor.example', port: 443, sourceIp: '10.12.40.7' });
  assert.equal(d.summary.primary.action, 'BYPASS');
  assert.equal(d.summary.primary.rule, 'Medical Devices Direct to Vendor');
  const u = run({ source: 'workload', target: '203.0.113.9', port: 445 });
  const f = mod(u, 'Forwarding (Cloud');
  assert.equal(f.confidence, 'conditional');
  assert.ok(u.summary.alsoBasedOn.some((c) => c.kind === 'workload' && c.rule === 'Drop SMB from Prod' && c.action === 'BLOCK'));
});
