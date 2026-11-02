'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const spl = require('../js/spl.js');
const sim = require('../tools/simulate.js');
const flow = require('../js/flow.js');

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

test('PlantUML: one diagram per session with nested calls and elapsed times', () => {
  const puml = simPuml();
  const blocks = puml.split(/(?=@startuml)/);
  assert.strictEqual(blocks.length, 3);
  for (const b of blocks) assert.match(b.trim(), /^@startuml[\s\S]*@enduml$/);
  const s1 = blocks[0];
  assert.match(s1, /^actor App as P_App$/m);
  assert.match(s1, /^participant "Host" as P_Host$/m);
  assert.match(s1, /^P_Enterprise -> P_WS : \/dge-idm\/idm\/user\/profile\/get\\n<size:10>TxnCode=SEC02<\/size>$/m);
  assert.match(s1, /^P_Host --> P_WS : dge-enq:enq\.customer\.portfolio\.VN\.V2\.3 \(1100 ms\)\\nAC_ACCT_SUM_X ~ AC_RBK_SUMM_N\\nAC_VSA_SUMM_N ~ AC_VSA_SUMM_N$/m);
  assert.match(s1, /^P_eComm --> P_App : \/spl-banking\/services\/vn\/security\/auth\/v2\/login \(2110 ms\)$/m);
  // every activate has a matching deactivate
  for (const b of blocks) assert.strictEqual((b.match(/^activate /gm) || []).length, (b.match(/^deactivate /gm) || []).length);
});

test('PlantUML: a request without a response gets a note and is closed', () => {
  const s3 = simPuml().split(/(?=@startuml)/)[2];
  assert.match(s3, /^note over P_WS #FFE0B2 : No response\\n\/dge-bfs\/bfs\/bp\/initiate\ndeactivate P_WS$/m);
  assert.match(s3, /^P_Enterprise --> P_eComm : \/bfs\/quick\/bp\/initiate \(30006 ms\)/m);
});

test('PlantUML server encoding uses its 64-character alphabet, 4 characters per 3 bytes', () => {
  const flow = require('../js/flow.js');
  assert.strictEqual(flow.plantUmlEncode64(new Uint8Array([0, 0, 0])), '0000');
  assert.strictEqual(flow.plantUmlEncode64(new Uint8Array([255, 255, 255])), '____');
  assert.strictEqual(flow.plantUmlEncode64(new Uint8Array(7)).length, 12);
});

function simPuml() {
  return require('../js/flow.js').toPlantUml(rows, spl.DEFAULT_CONFIG);
}

test('dropNoDirection: an event no direction rule matches is excluded, or kept when off', () => {
  const log = '2026-10-26 09:30:00.000 [x] INFO\n[SPLMessage][aaaaaaaa-0000-4000-8000-000000000009][U][VN][9.14][t][A][][] -/x/hello - note -\n';
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  const trace = [];
  assert.strictEqual(flow.run(cfg, [{ name: 'a.log', text: log, anySource: true }], [], trace).length, 0);
  assert.ok(trace.some((t) => /no Direction/.test(t.reason || '')));
  cfg.dropNoDirection = false;
  assert.strictEqual(flow.run(cfg, [{ name: 'a.log', text: log, anySource: true }], []).length, 1);
});

test('same millisecond: requests eComm > Enterprise > WS > Host, responses Host > WS > Enterprise > eComm', () => {
  const sid = 'aaaaaaaa-0000-4000-8000-000000000007';
  const ev = (line) => `2026-10-26 09:30:00.000 [x] INFO\n${line}\n`;
  // written to the file in the wrong order on purpose
  const req = ev(`<EAI> <SvcCode>A_X</SvcCode> Request Message - [::dge-enq:enq.a.VN.V1] WLS:${sid} |`)
    + ev(`WSAppLog | WLS:${sid} | request: URL:/dge-enq/a |`)
    + ev(`[SPLHostMessage][${sid}][U][VN][9.14][t][A][] -/enq/a - Request -`)
    + ev(`[SPLMessage][${sid}][U][VN][9.14][t][A][][] -/spl-banking/a - Request -`);
  const res = ev(`[SPLMessage][${sid}][U][VN][9.14][t][A][][1ms] -/spl-banking/a - Response -`)
    + ev(`[SPLHostMessage][${sid}][U][VN][9.14][t][A][1ms] -/enq/a - Response -`)
    + ev(`WSAppLog | WLS:${sid} | Response: URL:/dge-enq/a |`)
    + ev(`<EAI> <SvcCode>A_X</SvcCode> Response Message - [::dge-enq:enq.a.VN.V1] WLS:${sid} |`);
  const order = (text) => flow.run(spl.DEFAULT_CONFIG, [{ name: 'a.log', text, anySource: true }], [])
    .map((r) => `${r.LayerName} ${r.Direction} ${r.SortKey}`);
  assert.deepStrictEqual(order(req), ['eComm Request 10', 'Enterprise Request 20', 'WS Request 21', 'Host Request 30']);
  assert.deepStrictEqual(order(res), ['Host Response -30', 'WS Response -21', 'Enterprise Response -20', 'eComm Response -10']);
});

test('a Host event without its own [::dge-…] shows API N/A; a WS response without a URL takes LastWsURL', () => {
  const sid = 'aaaaaaaa-0000-4000-8000-000000000008';
  const at = (ms, line) => `2026-10-26 09:30:00.${ms} [x] INFO\n${line}\n`;
  const log = at('100', `WSAppLog | WLS:${sid} | request: URL:/dge-enq/a | [::dge-enq:enq.a.VN.V1]`)
    + at('200', `<EAI> <SvcCode>A_X</SvcCode> Request Message WLS:${sid} |`)
    + at('300', `<EAI> <SvcCode>A_X</SvcCode> Response Message WLS:${sid} |`)
    + at('400', `WSAppLog | WLS:${sid} | Response: | [::dge-enq:enq.a.VN.V1]`);
  const rows = flow.run(spl.DEFAULT_CONFIG, [{ name: 'a.log', text: log, anySource: true }], []);
  assert.deepStrictEqual(rows.map((r) => [r.LayerName, r.Direction, r.API]), [
    ['WS', 'Request', '/dge-enq/a'],
    ['Host', 'Request', 'N/A'],
    ['Host', 'Response', 'N/A'],
    ['WS', 'Response', '/dge-enq/a'], // no URL of its own: LastWsURL, so it pairs with the request
  ]);
  assert.deepStrictEqual(rows.map((r) => r.ElapsedMs ?? null), [null, null, 100, 300]);
});

test('an eComm event without an Endpoint shows API N/A instead of dropping out', () => {
  const log = '2026-10-26 09:30:00.000 [x] INFO\n[SPLMessage][aaaaaaaa-0000-4000-8000-000000000006][U][VN][9.14][t][A][][] Request received\n';
  const rows = flow.run(spl.DEFAULT_CONFIG, [{ name: 'a.log', text: log, anySource: true }], []);
  assert.deepStrictEqual(rows.map((r) => [r.LayerName, r.Direction, r.API, r.Flow]), [['eComm', 'Request', 'N/A', 'eComm: N/A [?]']]);
});

test('pairing is by layer name: an Enterprise request and a WS response with the same API do not pair', () => {
  const sid = 'aaaaaaaa-0000-4000-8000-000000000005';
  const at = (ms, line) => `2026-10-26 09:30:00.${ms} [x] INFO\n${line}\n`;
  const log = at('100', `[SPLHostMessage][${sid}][U][VN][9.14][t][A][] -/same/api - Request -`)
    + at('300', `WSAppLog | WLS:${sid} | Response: URL:/same/api |`);
  const rows = flow.run(spl.DEFAULT_CONFIG, [{ name: 'a.log', text: log, anySource: true }], []);
  assert.deepStrictEqual(rows.map((r) => [r.LayerName, r.Direction, r.PairKey, r.ElapsedMs ?? null]), [
    ['Enterprise', 'Request', 'Enterprise|/same/api', null],
    ['WS', 'Response', 'WS|/same/api', null],
  ]);
});

test('a * in a search term is a wildcard: "*WSAppLog*" finds [ENQWSAppLog] lines', () => {
  const log = '2026-10-26 09:30:00.000 [x] [INFO ] [ENQWSAppLog] [t] - [::dge-enq:enq.a.VN.V1] - X: | WLS:aaaaaaaa-0000-4000-8000-000000000004 | URL is /dge-enq/a request:\n';
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  const found = (filter) => { cfg.sources[1].filter = filter; return flow.run(cfg, [{ name: 'spl-ms-x.log', text: log }], []).length; };
  assert.strictEqual(found('("*WSAppLog*" ("request:"))'), 1);
  assert.strictEqual(found('("*WSAppLog" ("request:"))'), 1);
  assert.strictEqual(found('("WSApp*Log" ("request:"))'), 1);
  assert.strictEqual(found('("*OPIAppLog*" ("request:"))'), 0);
});
