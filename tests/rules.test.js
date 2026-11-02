'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const spl = require('../js/spl.js');
const flow = require('../js/flow.js');
const rules = require('../js/rules.js');
const imp = require('../js/importer.js');
const sim = require('../tools/simulate.js');

const mock = (f) => path.join(__dirname, '..', 'mock', f);
const rows = sim.run(spl.DEFAULT_CONFIG, [mock('spl-banking-mock.log'), mock('spl-ms-mock.log')], []);
const r = rules.analyze(flow.sequenceModel(rows, spl.DEFAULT_CONFIG));

test('routing: entry calls list their direct downstream calls in order', () => {
  const login = r.routing.find((x) => x.entry.endsWith('/security/auth/v2/login'));
  assert.deepStrictEqual(login.calls, ['Enterprise /idm/user/profile/get', 'Enterprise /enq/customer/portfolio']);
  assert.deepStrictEqual(r.routing.find((x) => x.entry.endsWith('/security/preLogin')).calls, []);
});

test('call map: Host links carry their SvcCode pairs', () => {
  const host = r.edges.filter((x) => x.callee.startsWith('Host dge-enq:enq.customer.portfolio'));
  assert.deepStrictEqual(host.map((x) => x.svc), [['BA_ACCT_INFO_N3 ~ BA_ACCT_INFO_N3'], ['AC_ACCT_SUM_X ~ AC_RBK_SUMM_N', 'AC_VSA_SUMM_N ~ AC_VSA_SUMM_N']]);
  assert.ok(host.every((x) => x.caller === 'WS /dge-enq/enq/customer/portfolio'));
});

test('gaps and latency: the WS timeout and the Host latency range', () => {
  assert.deepStrictEqual(r.gaps.map((g) => [g.kind, g.call, g.caller]), [['No response', 'WS /dge-bfs/bfs/bp/initiate', 'Enterprise /bfs/quick/bp/initiate']]);
  const hostLat = r.latency.find((x) => x.call === 'Host dge-enq:enq.customer.portfolio.VN.V2.3');
  assert.deepStrictEqual([hostLat.n, hostLat.min, hostLat.median, hostLat.max], [2, 397, 749, 1100]);
});

test('confidence: one session is a single-sample observation, two are observed', () => {
  assert.ok(r.edges.every((x) => x.sessions === 1 && x.confidence === 'Single-sample observation'));
  // the same preLogin flow in two sessions
  const two = imp.toFlowRows(imp.parseCsv([
    'Step,EventTime,sessionId,ServiceInfo,Params,ElapsedMs',
    '1,26/10/2026 10:00:00,s1,eComm: /pre [?],,', '2,26/10/2026 10:00:00,s1,> Enterprise: /e [?],,',
    '3,26/10/2026 10:00:01,s1,> Enterprise: /e [!],,100', '4,26/10/2026 10:00:01,s1,eComm: /pre [!],,120',
    '1,26/10/2026 11:00:00,s2,eComm: /pre [?],,', '2,26/10/2026 11:00:00,s2,> Enterprise: /e [?],,',
    '3,26/10/2026 11:00:02,s2,> Enterprise: /e [!],,2000', '4,26/10/2026 11:00:02,s2,eComm: /pre [!],,2100',
  ].join('\n')), spl.DEFAULT_CONFIG).rows;
  const r2 = rules.analyze(flow.sequenceModel(two, spl.DEFAULT_CONFIG));
  assert.deepStrictEqual(r2.edges.map((x) => [x.caller, x.callee, x.sessions, x.confidence]), [['eComm /pre', 'Enterprise /e', 2, 'Observed in 2 sessions']]);
  assert.deepStrictEqual(r2.latency.find((x) => x.call === 'Enterprise /e').median, 1050);
});

test('order of calls: overlapping calls are reported as such', () => {
  const csv = imp.parseCsv([
    'Step,EventTime,sessionId,ServiceInfo,Params,ElapsedMs',
    '1,26/10/2026 10:00:00.000,s,eComm: /login [?],,', '2,26/10/2026 10:00:00.010,s,> Enterprise: /a [?],,',
    '3,26/10/2026 10:00:00.020,s,> Enterprise: /b [?],,', '4,26/10/2026 10:00:00.030,s,> Enterprise: /b [!],,10',
    '5,26/10/2026 10:00:00.040,s,> Enterprise: /a [!],,30', '6,26/10/2026 10:00:00.050,s,eComm: /login [!],,50',
  ].join('\n'));
  const r3 = rules.analyze(flow.sequenceModel(imp.toFlowRows(csv, spl.DEFAULT_CONFIG).rows, spl.DEFAULT_CONFIG));
  assert.strictEqual(r3.ordering[0].parent, 'eComm /login');
  assert.strictEqual(r3.ordering[0].verdict, 'Overlapping');
});

test('API table: one row per API with a description of the call', () => {
  assert.strictEqual(r.apis.length, r.distinctApis);
  const desc = (api) => r.apis.find((x) => x.api === api).description;
  const login = r.apis.find((x) => x.api.endsWith('/security/auth/v2/login'));
  assert.ok(login.description.includes('Entry call from the App.'));
  assert.ok(login.description.includes('Calls, in order: Enterprise /idm/user/profile/get → Enterprise /enq/customer/portfolio.'));
  assert.ok(desc('Enterprise /enq/customer/portfolio')[0].startsWith('Called by eComm '));
  assert.ok(desc('Host dge-enq:enq.customer.portfolio.VN.V2.3').includes('Takes 749 ms (median; 397–1100 ms over 2 responses).'));
  assert.ok(desc('Host dge-enq:enq.customer.portfolio.VN.V2.3').some((s) => s.startsWith('SvcCodes (request ~ response): BA_ACCT_INFO_N3 ~ BA_ACCT_INFO_N3')));
  assert.ok(desc('WS /dge-bfs/bfs/bp/initiate').includes('No response once (possible timeout).'));
  assert.ok(desc(r.routing.find((x) => x.entry.endsWith('/security/preLogin')).entry).includes('Handled internally (no downstream call).'));
});

test('Markdown export is the two-column API table and flags a single session', () => {
  const md = rules.toMarkdown(r);
  assert.ok(md.includes('# Processing rules'));
  assert.ok(md.includes('| API | Description |'));
  assert.ok(!md.includes('## Routing'));
  const one = rules.toMarkdown(rules.analyze(flow.sequenceModel(rows.filter((x) => x.sessionId === rows[0].sessionId), spl.DEFAULT_CONFIG)));
  assert.match(one, /Only one session: every rule below is a hypothesis/);
});
