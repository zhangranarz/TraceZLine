'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const spl = require('../js/spl.js');
const flow = require('../js/flow.js');
const imp = require('../js/importer.js');
const { compare, formatOffset } = require('../js/compare.js');

const mock = (f) => path.join(__dirname, '..', 'mock', f);
const log = flow.run(spl.DEFAULT_CONFIG, ['spl-banking-mock.log', 'spl-ms-mock.log'].map((f) => ({ name: f, text: fs.readFileSync(mock(f), 'utf8') })), []);
const excel = imp.toFlowRows(imp.parseCsv(fs.readFileSync(mock('mock-flow.csv'), 'utf8')), spl.DEFAULT_CONFIG).rows;
const shift = (rows, ms) => rows.map((r) => ({ ...r, time: r.time + ms }));

test('the mock flow matches its own logs row for row', () => {
  const r = compare(excel, log);
  assert.strictEqual(r.matched, excel.length);
  assert.ok(r.pairs.every((p) => p.kind === 'by order' && p.delta === 0));
  assert.strictEqual(r.unmatchedLog.length, 0);
  // the only finding is the intended WS timeout
  assert.deepStrictEqual(r.quality.map((q) => q.kind), ['Requests without a response (in the Excel)']);
  assert.match(r.quality[0].items[0], /WS \/dge-bfs\/bfs\/bp\/initiate/);
});

test('a time-zone offset is detected and removed', () => {
  const r = compare(shift(excel, 3600000), log);
  assert.strictEqual(r.offsetText, '+1h 0m 0.000s');
  assert.ok(r.pairs.every((p) => !p.issues.length));
  assert.strictEqual(formatOffset(-90061), '-0h 1m 30.061s');
});

test('a row far from its log event is flagged beyond the tolerance', () => {
  const moved = excel.map((r, i) => (i === 5 ? { ...r, time: r.time + 5000 } : r));
  const r = compare(moved, log, { toleranceMs: 1000 });
  assert.match(r.pairs[5].issues.join(), /time differs by 5000 ms/);
  assert.ok(r.quality.some((q) => q.kind === 'Time differences beyond 1000 ms' && q.count === 1));
});

test('missing Excel rows show up as unmapped log events and missing hops', () => {
  const noHost = excel.filter((r) => r.LayerName !== 'Host');
  const r = compare(noHost, log);
  assert.strictEqual(r.unmatchedLog.length, log.filter((l) => l.LayerName === 'Host').length);
  const missing = r.quality.find((q) => q.kind === 'Hops in the log that never appear in the Excel');
  assert.ok(missing.items.every((h) => h.startsWith('Host ')));
});

test('a row whose API differs falls back to the nearest log event in time', () => {
  const renamed = excel.map((r, i) => (i === 3 ? { ...r, API: '/renamed/api' } : r));
  const r = compare(renamed, log);
  assert.strictEqual(r.pairs[3].kind, 'nearest time');
  assert.match(r.pairs[3].issues.join(), /API differs: log has \/idm\/user\/profile\/get/);
});

test('rows with no sessionId or direction are reported', () => {
  const broken = excel.map((r, i) => (i === 0 ? { ...r, sessionId: null } : i === 1 ? { ...r, Direction: null } : r));
  const kinds = compare(broken, log).quality.map((q) => q.kind);
  assert.ok(kinds.includes('Excel rows with no sessionId'));
  assert.ok(kinds.includes('Excel rows with an unknown direction'));
});
