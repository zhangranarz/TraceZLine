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
  assert.match(r.rows[4].checks.join(), /log layer: MS/);
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

test('JSON payload of a log event: found after the text prefix and flattened to paths', () => {
  const { extractJson, flattenJson } = require('../js/compare.js');
  const ecomm = events.find((e) => /- Request -/.test(e.raw) && e.raw.includes('[SPLMessage]'));
  const rows = flattenJson(extractJson(ecomm.raw));
  assert.ok(rows.some(([p, v]) => p === 'meta.requestContext.sessionId' && v === 'aaaaaaaa-0000-4000-8000-000000000001'));
  assert.ok(rows.some(([p]) => p === 'data.device.deviceId'));
  assert.deepStrictEqual(flattenJson({ a: { b: [1, { c: null }], e: {}, f: [] } }), [['a.b[0]', '1'], ['a.b[1].c', 'null'], ['a.e', '{}'], ['a.f', '[]']]);
  // braces inside strings and a brace in the prefix do not break it
  assert.deepStrictEqual(extractJson('x [{bad] - Response:{"m":"a}b","n":{"k":"v"}} tail'), { m: 'a}b', n: { k: 'v' } });
  // Host XML and truncated JSON have no structure
  const host = events.find((e) => e.raw.includes('<EAI>'));
  assert.strictEqual(extractJson(host.raw), null);
  assert.strictEqual(extractJson('Request - {"a":{"b":1'), null);
});

test('JSON paths can use | between levels', () => {
  const { flattenJson } = require('../js/compare.js');
  const v = { responseHeader: { encryptParameters: { encryptionInformation: { modSize: '2048' } } }, list: [{ id: 1 }] };
  assert.deepStrictEqual(flattenJson(v, { sep: '|' }), [
    ['responseHeader|encryptParameters|encryptionInformation|modSize', '2048'],
    ['list[0]|id', '1'],
  ]);
});

test('XML payload of a log event: element paths with | , indexes for repeats, empties kept', () => {
  const { payloadStructure } = require('../js/compare.js');
  const host = events.find((e) => e.raw.includes('Request Message') && e.raw.includes('AC_ACCT_SUM_X'));
  const s = payloadStructure(host.raw);
  assert.strictEqual(s.kind, 'XML');
  const get = (p) => (s.rows.find(([k]) => k === p) || [])[1];
  assert.strictEqual(get('EAI|SvcRq|SvcCode'), 'AC_ACCT_SUM_X');
  assert.strictEqual(get('EAI|SvcRq|SvcRqHdr|SubSvc[0]|SubSvcRqHeader|SvcCode'), 'AC_RBK_SUMM_N');
  assert.strictEqual(get('EAI|SvcRq|SvcRqHdr|SubSvc[1]|SubSvcRqHeader|SvcCode'), 'AC_VSA_SUMM_N');
  const res = payloadStructure(events.find((e) => e.raw.includes('Response Message')).raw);
  assert.ok(res.rows.some(([k, v]) => k === 'EAI|SvcRs|ErrorCode' && v === ''));
  // JSON events stay JSON
  assert.strictEqual(payloadStructure(events.find((e) => e.raw.includes('[SPLMessage]')).raw).kind, 'JSON');
});

test('XML from real logs: placeholders, attributes, a mismatched end tag and truncation are tolerated', () => {
  const { extractXml, flattenXml } = require('../js/compare.js');
  const raw = 'INFO Request Message:<?xml version="1.0" ?> <EAI><SvcRq id="7"><UserId><<USER_ID>></UserId>'
    + '<Info><LastLoginTime>091056</LastLogin><Next>x</Next></Info><Cut>abc';
  const rows = flattenXml(extractXml(raw));
  const get = (p) => (rows.find(([k]) => k === p) || [])[1];
  assert.strictEqual(get('EAI|SvcRq@id'), '7');
  assert.strictEqual(get('EAI|SvcRq|UserId'), '<<USER_ID>>');
  assert.strictEqual(get('EAI|SvcRq|Info|LastLoginTime'), '091056');
  assert.strictEqual(get('EAI|SvcRq|Info|LastLoginTime|Next'), 'x');
  assert.strictEqual(get('EAI|SvcRq|Cut'), 'abc'); // </Info> closed back up to Info
  assert.strictEqual(extractXml('no markup here'), null);
});

test('masked log: the CSV session IDs masked the same way still map, offset included', async () => {
  const mask = require('../js/mask.js');
  const names = ['spl-banking-mock.log', 'spl-ms-mock.log'];
  const results = [];
  for (const n of names) results.push(await mask.maskText(fs.readFileSync(mock(n), 'utf8'), mask.DEFAULT_RULES, { key: 'k1' }));
  const t = [];
  flow.run(spl.DEFAULT_CONFIG, results.map((r, i) => ({ name: names[i], text: r.text, anySource: true })), [], t);
  const maskedEvents = t.map((x) => Object.assign(x.ev, { head: x.head }));
  const later = shift(excel, 8 * 3600000);
  // the real IDs against the masked log: nothing lines up once the clocks differ
  assert.strictEqual(compare(later, maskedEvents).mapped, 0);
  const sids = await mask.maskSessionIds(later, results, { key: 'k1' });
  assert.strictEqual(sids.masked, excel.length);
  assert.ok(sids.rows.every((x, i) => x.sessionId !== excel[i].sessionId && !x.raw.includes(excel[i].sessionId)));
  const r = compare(sids.rows, maskedEvents);
  assert.strictEqual(r.offsetText, '+8h 0m 0.000s');
  assert.strictEqual(r.mapped, excel.length);
  assert.strictEqual(r.agreeing, excel.length);
});

test('maskSessionIds: NA stays, a session the log kept unmasked stays, one not in the log is masked', async () => {
  const mask = require('../js/mask.js');
  const results = [{ text: 'x kept-session-1 y', replaced: new Map([['real-session-1', 'fake-session-1']]) }];
  const rows = ['real-session-1', 'kept-session-1', 'other-session-1', 'NA', null].map((sessionId) => ({ sessionId, raw: `1 | ${sessionId}` }));
  const r = await mask.maskSessionIds(rows, results, { key: 'k' });
  assert.deepStrictEqual(r.rows.slice(0, 2).map((x) => x.sessionId), ['fake-session-1', 'kept-session-1']);
  assert.notStrictEqual(r.rows[2].sessionId, 'other-session-1');
  assert.match(r.rows[2].sessionId, /^[a-z]{5}-[a-z]{7}-\d$/);
  assert.deepStrictEqual(r.rows.slice(3).map((x) => x.sessionId), ['NA', null]);
  assert.deepStrictEqual([r.masked, r.kept], [2, 1]);
});

const cmp = require('../js/compare.js');
test('diffRows: same, differs, only A / only B, repeated paths numbered', () => {
  const d = cmp.diffRows(
    [['a|x', '1'], ['a|y', '2'], ['l', 'p'], ['l', 'q'], ['onlyA', 'z']],
    [['a|y', '3'], ['a|x', '1'], ['l', 'p'], ['l', 'r'], ['onlyB', 'w']],
  );
  assert.deepStrictEqual(d.map((r) => `${r.path}:${r.status}`), ['a|x:same', 'a|y:differs', 'l:same', 'l #2:differs', 'onlyA:only A', 'onlyB:only B']);
  assert.deepStrictEqual(d[1], { path: 'a|y', a: '2', b: '3', status: 'differs' });
});
