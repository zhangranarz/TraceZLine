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
// Every parsed log event, annotated by the query logic where it applies (as the page does).
const trace = [];
flow.run(spl.DEFAULT_CONFIG, ['spl-banking-mock.log', 'spl-ms-mock.log'].map((f) => ({ name: f, text: fs.readFileSync(mock(f), 'utf8'), anySource: true })), [], trace);
const events = trace.map((t) => Object.assign(t.ev, { head: t.head }));
const excel = imp.toFlowRows(imp.parseCsv(fs.readFileSync(mock('mock-flow.csv'), 'utf8')), spl.DEFAULT_CONFIG).rows;
const shift = (rows, ms) => rows.map((r) => ({ ...r, time: r.time + ms }));

test('every Splunk line maps to its log event by timestamp', () => {
  const r = compare(excel, events);
  assert.strictEqual(r.mapped, excel.length);
  assert.strictEqual(r.agreeing, excel.length);
  assert.ok(r.rows.every((x) => x.delta === 0 && x.l.LayerName === x.x.LayerName && x.l.Direction === x.x.Direction));
  assert.strictEqual(r.offsetText, '+0h 0m 0.000s');
  assert.strictEqual(r.unmappedLog.length, events.length - excel.length);
});

test('a time-zone offset is detected, or taken as given', () => {
  const r = compare(shift(excel, 3600000), events);
  assert.strictEqual(r.offsetText, '+1h 0m 0.000s');
  assert.strictEqual(r.offsetAuto, true);
  assert.strictEqual(r.agreeing, excel.length);
  const manual = compare(shift(excel, 3600000), events, { offsetMs: 0 });
  assert.strictEqual(manual.offsetAuto, false);
  assert.strictEqual(manual.mapped, 0);
  assert.strictEqual(formatOffset(-90061), '-0h 1m 30.061s');
});

test('whole-second EventTimes still map each line to the agreeing event', () => {
  const seconds = excel.map((r) => ({ ...r, time: Math.floor(r.time / 1000) * 1000 }));
  const r = compare(seconds, events, { toleranceMs: 1000 });
  assert.strictEqual(r.mapped, excel.length);
  assert.strictEqual(r.agreeing, excel.length);
});

test('lines without a log event in the window are reported', () => {
  const moved = excel.map((r, i) => (i === 5 ? { ...r, time: r.time + 60000 } : r));
  const r = compare(moved, events, { toleranceMs: 1000 });
  assert.strictEqual(r.rows[5].status, 'not mapped');
  assert.ok(r.quality.some((q) => q.kind === 'Lines with no log event in the time window' && q.count === 1));
});

test('a line mapped to an event of another layer is flagged', () => {
  const relabeled = excel.map((r, i) => (i === 4 ? { ...r, LayerName: 'Enterprise' } : r));
  const r = compare(relabeled, events);
  assert.strictEqual(r.rows[4].status, 'mapped, differs');
  assert.match(r.rows[4].checks.join(), /log layer: WS/);
});

test('an unreadable EventTime is reported, not guessed', () => {
  const broken = excel.map((r, i) => (i === 0 ? { ...r, time: NaN, EventTime: 'yesterday' } : r));
  const r = compare(broken, events);
  assert.strictEqual(r.rows[0].status, 'not mapped');
  assert.ok(r.quality.some((q) => q.kind === 'Lines with an unreadable EventTime'));
});

test('files without a shared session are reported as unrelated, with no offset guessed', () => {
  const other = excel.map((r) => ({ ...r, sessionId: 'eeeeeeee-0000-4000-8000-000000000005', time: r.time + 26290000 }));
  const r = compare(other, events);
  assert.strictEqual(r.unrelated, true);
  assert.strictEqual(r.sharedSessions, 0);
  assert.strictEqual(r.offsetMs, 0);
  assert.strictEqual(r.quality[0].kind, 'The files do not seem to belong together');
});
