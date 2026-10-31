'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const spl = require('../js/spl.js');
const flow = require('../js/flow.js');
const imp = require('../js/importer.js');
const sim = require('../tools/simulate.js');

const mock = (f) => path.join(__dirname, '..', 'mock', f);
const fromLogs = sim.run(spl.DEFAULT_CONFIG, [mock('spl-banking-mock.log'), mock('spl-ms-mock.log')], []);
const load = async (f) => imp.toFlowRows(await imp.readTable(f, fs.readFileSync(mock(f))), spl.DEFAULT_CONFIG);

for (const file of ['mock-flow.csv', 'mock-flow.xlsx']) {
  test(`${file}: imports every flow row and joins Host continuation rows`, async () => {
    const { rows, problems } = await load(file);
    assert.deepStrictEqual(problems, []);
    assert.strictEqual(rows.length, fromLogs.length);
    const host = rows.find((r) => r.LayerName === 'Host' && r.ServiceInfo.length === 3);
    assert.deepStrictEqual(host.ServiceInfo.slice(1), ['- [AC_ACCT_SUM_X ~ AC_RBK_SUMM_N] [?]', '- [AC_VSA_SUMM_N ~ AC_VSA_SUMM_N] [?]']);
    assert.deepStrictEqual(rows.find((r) => r.ElapsedMs === 45).Params, ['TxnRefNo=9990000000000101', 'TxnCode=SEC02']);
  });

  test(`${file}: gives the same diagrams as analysing the raw logs`, async () => {
    const { rows } = await load(file);
    assert.strictEqual(flow.toPlantUml(rows, spl.DEFAULT_CONFIG), flow.toPlantUml(fromLogs, spl.DEFAULT_CONFIG));
  });
}

test('CSV: quoted cells with commas, quotes and line breaks; semicolon separator', () => {
  assert.deepStrictEqual(imp.parseCsv('a,b\r\n"x, ""y""","1\n2"\r\n'), [['a', 'b'], ['x, "y"', '1\n2']]);
  assert.deepStrictEqual(imp.parseCsv('﻿a;b\n1;2\n'), [['a', 'b'], ['1', '2']]);
});

test('EventTime formats: dd/mm/yyyy, ISO with ms, Excel date number', () => {
  assert.strictEqual(imp.parseTime('26/10/2026 16:28:59'), Date.UTC(2026, 9, 26, 16, 28, 59));
  assert.strictEqual(imp.parseTime('2026-10-26 09:30:00.004'), Date.UTC(2026, 9, 26, 9, 30, 0, 4));
  assert.strictEqual(imp.parseTime('46321.5'), Date.UTC(2026, 9, 26, 12, 0, 0));
});

test('rows without a [?]/[!] marker are kept with an unknown direction and reported', () => {
  const table = [['Step', 'EventTime', 'sessionId', 'ServiceInfo', 'Params', 'ElapsedMs'],
    ['1', '26/10/2026 16:29:06', 'sid-1', 'eComm: /spl-banking/x', '', ''],
    ['2', '26/10/2026 16:29:06', 'sid-1', 'not a flow line', '', '']];
  const { rows, problems } = imp.toFlowRows(table, spl.DEFAULT_CONFIG);
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].Direction, null);
  assert.deepStrictEqual(problems.map((p) => p.line), [2, 3]);
  assert.match(flow.toPlantUml(rows, spl.DEFAULT_CONFIG), /note over P_eComm #FFE0B2 : Direction unknown/);
});

test('overlapping calls: each request goes to its own caller and closes on its own response', () => {
  // asv runs in the background while softtoken -> stn runs; asv's WS call matches asv by path.
  const csv = [
    'Step,EventTime,sessionId,ServiceInfo,Params,ElapsedMs',
    '1,26/10/2026 16:29:04,s,eComm: /spl-banking/login [?],,',
    '2,26/10/2026 16:29:04,s,> Enterprise: /asv/channelaccess/update [?],,',
    '3,26/10/2026 16:29:04,s,> Enterprise: /softtoken/validateSoftTokenOTP [?],,',
    '4,26/10/2026 16:29:04,s,>> WS: /dge-stn/stn/validate [?],,',
    '5,26/10/2026 16:29:04,s,>> WS: /dge-asv/asv/channelaccess/update [?],,',
    '6,26/10/2026 16:29:04,s,>> WS: /dge-asv/asv/channelaccess/update [!],,20',
    '7,26/10/2026 16:29:04,s,>> WS: /dge-stn/stn/validate [!],,56',
    '8,26/10/2026 16:29:04,s,> Enterprise: /softtoken/validateSoftTokenOTP [!],,62',
    '9,26/10/2026 16:29:04,s,> Enterprise: /asv/channelaccess/update [!],,70',
    '10,26/10/2026 16:29:04,s,eComm: /spl-banking/login [!],,90',
  ].join('\n');
  const { rows } = imp.toFlowRows(imp.parseCsv(csv), spl.DEFAULT_CONFIG);
  const puml = flow.toPlantUml(rows, spl.DEFAULT_CONFIG);
  assert.match(puml, /^P_eComm -> P_Enterprise : \/softtoken\/validateSoftTokenOTP$/m);
  assert.match(puml, /^P_Enterprise -> P_WS : \/dge-asv\/asv\/channelaccess\/update$/m);
  assert.match(puml, /^P_Enterprise --> P_eComm : \/asv\/channelaccess\/update \(70 ms\)$/m);
  assert.doesNotMatch(puml, /No response|without a request/);
});

test('a non-zip, non-CSV upload is reported, not misread', async () => {
  await assert.rejects(imp.readTable('x.xls', new Uint8Array([0xd0, 0xcf, 0x11, 0xe0])), /\.xls format is not supported/);
  assert.throws(() => imp.toFlowRows([['a', 'b'], ['1', '2']], spl.DEFAULT_CONFIG), /no ServiceInfo or Flow column/);
});
