'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const spl = require('../js/spl.js');
const sim = require('../tools/simulate.js');

const mock = (f) => path.join(__dirname, '..', 'mock', f);
const files = [mock('spl-banking-mock.log'), mock('spl-ms-mock.log')];
const rows = sim.run(spl.DEFAULT_CONFIG, files, []);
const bySession = (sid) => rows.filter((r) => r.sessionId === sid);
const S1 = 'aaaaaaaa-0000-4000-8000-000000000001';
const S2 = 'bbbbbbbb-0000-4000-8000-000000000002';
const S3 = 'cccccccc-0000-4000-8000-000000000003';

test('mock output matches mock/expected.txt (regenerate it after an intended change)', () => {
  const expected = fs.readFileSync(mock('expected.txt'), 'utf8').replace(/\r/g, '');
  assert.strictEqual(sim.format(rows, spl.DEFAULT_CONFIG.columns), expected);
});

test('every mock event is returned and gets a layer, a direction and a sessionId', () => {
  const total = files.map((f) => fs.readFileSync(f, 'utf8').match(/^\d{4}-\d\d-\d\d /gm).length).reduce((a, b) => a + b);
  assert.strictEqual(rows.length, total);
  for (const r of rows) {
    assert.ok(r.LayerName, r.raw.slice(0, 80));
    assert.ok(r.Direction === 'Request' || r.Direction === 'Response', r.raw.slice(0, 80));
    assert.ok([S1, S2, S3].includes(r.sessionId), r.raw.slice(0, 80));
  }
});

test('E: multi-subservice EAI call pairs SvcCodes', () => {
  const host = bySession(S1).find((r) => r.LayerName === 'Host' && r.SvcCode.includes('AC_ACCT_SUM_X'));
  assert.deepStrictEqual(host.ServiceInfo.slice(1), ['- [AC_ACCT_SUM_X ~ AC_RBK_SUMM_N] [?]', '- [AC_VSA_SUMM_N ~ AC_VSA_SUMM_N] [?]']);
});

test('H: interleaved sessions keep their own Step numbers', () => {
  assert.deepStrictEqual(bySession(S1).map((r) => r.Step), [...Array(16).keys()].map((i) => i + 1));
  assert.deepStrictEqual(bySession(S2).map((r) => r.Step), [...Array(8).keys()].map((i) => i + 1));
});

test('G1: WS timeout leaves a request without a response and the Enterprise hop takes ~30s', () => {
  const s3 = bySession(S3);
  const ws = s3.filter((r) => r.LayerName === 'WS' && r.API === '/dge-bfs/bfs/bp/initiate');
  assert.deepStrictEqual(ws.map((r) => r.Direction), ['Request']);
  const ent = s3.find((r) => r.API === '/bfs/quick/bp/initiate' && r.Direction === 'Response');
  assert.strictEqual(ent.ElapsedMs, 30006);
});

test('search terms keep only the listed sessions', () => {
  const only = sim.run(spl.DEFAULT_CONFIG, files, [S2]);
  assert.ok(only.length > 0);
  assert.ok(only.every((r) => r.sessionId === S2));
});
