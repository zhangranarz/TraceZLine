'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const spl = require('../js/spl.js');

// Line breaks and indentation in the hand-written base query are free-form and
// not significant to SPL, so compare with every whitespace run collapsed and
// spaces after commas dropped.
const norm = (s) => s.replace(/\s+/g, ' ').replace(/, /g, ',').trim();

test('default source block matches the base query exactly, including tabs', () => {
  const base = fs.readFileSync(path.join(__dirname, 'base.spl'), 'utf8').replace(/\r/g, '');
  const head = base.slice(0, base.indexOf('\n)\n') + 3);
  assert.ok(spl.generate(spl.DEFAULT_CONFIG).startsWith(head));
});

test('default config reproduces the base query', () => {
  const base = fs.readFileSync(path.join(__dirname, 'base.spl'), 'utf8');
  assert.strictEqual(norm(spl.generate(spl.DEFAULT_CONFIG)), norm(base));
});

test('Layer=case() follows layer number order, LayerName=case() keeps list order', () => {
  const out = spl.generate(spl.DEFAULT_CONFIG);
  assert.match(out, /\| eval LayerName=case\(match\(_raw,"\\\[SPLMessage\\\]"\),"eComm",match/);
  assert.match(out, /"Host",match\(_raw,"WSAppLog"\),"WS"\)\n/);
  assert.match(out, /\| eval Layer=case\(LayerName="eComm",1,LayerName="Enterprise",2,LayerName="WS",2,LayerName="Host",3\)/);
});

test('search terms are quoted, escaped and OR-joined; empty list drops the line', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.terms = ['abc', 'a"b'];
  // right after the source block, without a leading |
  assert.match(spl.generate(cfg), /^\)\n\("abc" OR "a\\"b"\)\n\| eval/m);
  cfg.terms = ['abc'];
  assert.match(spl.generate(cfg), /^\)\n"abc"\n\| eval/m, 'one term: no parentheses');
  cfg.terms = [];
  assert.match(spl.generate(cfg), /^\)\n\| eval/m);
});

test('parseTerms splits on newlines and commas', () => {
  assert.deepStrictEqual(spl.parseTerms(' a\r\nb, c,,\n'), ['a', 'b', 'c']);
});

test('adding a source and removing a param', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.sources.push({ enabled: true, source: '/var/log/pods/spl-opi-*.log', filter: '"OPIAppLog"' });
  cfg.params = cfg.params.slice(0, 1);
  const out = spl.generate(cfg);
  assert.match(out, /\n\tOR\n\t\(\n\t\tsource="\/var\/log\/pods\/spl-opi-\*\.log"\n\t\t"OPIAppLog"\n\t\)\n\)\n/);
  assert.match(out, /\| eval Params=mvappend\(\n    if\(isnotnull\(transactionRef\).*"TxnRefNo="\.transactionRef, null\(\)\)\n\)$/m);
  assert.doesNotMatch(out, /transactionCode/);
});

test('disabled sources are left out', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.sources[2].enabled = false;
  cfg.sources[3].enabled = false;
  assert.doesNotMatch(spl.generate(cfg), /spl-ms/);
});

test('default config has no warnings', () => {
  assert.deepStrictEqual(spl.validate(spl.DEFAULT_CONFIG), []);
});

test('ungrouped sources and a Layer<=2 first rule are flagged', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.groupSources = false;
  cfg.directionFirst = 'Layer<=2,DirWord';
  const w = spl.validate(cfg);
  assert.strictEqual(w.length, 2);
  assert.ok(w.some((m) => /not grouped/.test(m)));
  assert.ok(w.some((m) => /Layer<=2\) also matches WS/.test(m)));
});

test('ungrouped sources share only the outer parentheses', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.groupSources = false;
  assert.ok(spl.generate(cfg).startsWith('(\n\tsource="/var/log/pods/spl-banking-*log"\n\t"[SPLMessage]"\n\tOR\n\tsource="/var/log/pods/spl-banking-*log"\n\t"[SPLHostMessage]"\n\tOR\n'));
});

test('DirWord and rex lines without a named group are flagged', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.dirWordRex = String.raw`(?i)\b(?:DirWord=Request|Response)\b`;
  const w = spl.validate(cfg);
  assert.ok(w.some((m) => /no \(\?<DirWord>/.test(m)));
  assert.ok(w.some((m) => /reject.*\(\?:DirWord=Request/.test(m)));
});

test('Params rules extract from the JSON key formats seen in the logs', () => {
  const toJs = (rex) => new RegExp(rex.replace(/\\"/g, '"').replace(/^\(\?i\)/, ''), 'i');
  const [ref, code] = spl.DEFAULT_CONFIG.params.map((p) => toJs(p.rex));
  assert.strictEqual('"transactionReferenceNumber":"9990000000000201"'.match(ref).groups.transactionRef, '9990000000000201');
  assert.strictEqual('{"transactionRef": "ABC123",'.match(ref).groups.transactionRef, 'ABC123');
  assert.strictEqual('{ "transactionCode": "AES01"'.match(code).groups.transactionCode, 'AES01');
  assert.strictEqual(':{"transactionCode":"SEC02"'.match(code).groups.transactionCode, 'SEC02');
});

test('DirectionSymbol is set before ServiceInfo uses it', () => {
  const out = spl.generate(spl.DEFAULT_CONFIG);
  assert.ok(out.indexOf('| eval DirectionSymbol=') < out.indexOf('| eval ServiceInfo='));
});

test('endpoint rules: add, remove and coalesce order', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.endpointRules = [cfg.endpointRules[1], { field: 'EpX', rex: '(?<EpX>\\S+)' }];
  const out = spl.generate(cfg);
  assert.match(out, /\| eval Endpoint=coalesce\(EnterpriseEndpoint,EpX\)/);
  assert.doesNotMatch(out, /eCommEndpoint/);
});

test('empty DirWord rex and first rule drop out of the query', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.dirWordRex = '';
  cfg.directionFirst = '';
  const out = spl.generate(cfg);
  assert.doesNotMatch(out, /DirWord/);
  assert.match(out, /\| eval Direction=case\(LayerName="Host" AND/);
});

test('groupSources wraps each source in its own parentheses inside the outer ones', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.groupSources = true;
  const out = spl.generate(cfg);
  assert.ok(out.startsWith('(\n\t(\n\t\tsource="/var/log/pods/spl-banking-*log"\n\t\t"[SPLMessage]"\n\t)\n\tOR\n\t(\n\t\tsource="/var/log/pods/spl-banking-*log"\n\t\t"[SPLHostMessage]"\n\t)\n\tOR\n'));
  assert.match(out, /Response Message"\)\n\t\)\n\)\n\("2576dfc8/);
});

test('a filter with a top-level OR is wrapped in parentheses', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  const filter = (f) => { cfg.sources[1].filter = f; return spl.generate(cfg).split('\n')[8].trim(); }; // 2nd source's filter line
  assert.strictEqual(filter('("A" "x") OR ("B")'), '(("A" "x") OR ("B"))');
  assert.strictEqual(filter('"A" OR "B"'), '("A" OR "B")');
  assert.strictEqual(filter('("A" OR "B")'), '("A" OR "B")', 'already wrapped');
  assert.strictEqual(filter('"A" "B"'), '"A" "B"', 'no top-level OR');
  assert.strictEqual(filter('"x OR y" "B"'), '"x OR y" "B"', 'OR inside quotes');
});

test('validate flags an unnamed rex group and unknown layers', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.sessionRules.push({ field: 'sidOpi', rex: 'sidOpi:([0-9a-f-]{36})' });
  cfg.directions.push({ layer: 'OPI', pattern: 'x', direction: 'Request' });
  const w = spl.validate(cfg);
  assert.ok(w.some((m) => m.includes('sidOpi')));
  assert.ok(w.some((m) => m.includes('"OPI"')));
});

test('sessionId rules extract a dashed UUID from each layer format', () => {
  const uuid = 'dddddddd-0000-4000-8000-000000000004';
  // SPL rex strings use \" for a literal quote; a leading (?i) becomes the JS i flag.
  const toJs = (rex) => {
    const src = rex.replace(/\\"/g, '"');
    return src.startsWith('(?i)') ? new RegExp(src.slice(4), 'i') : new RegExp(src);
  };
  const [ecomm, ent, wls, any] = spl.DEFAULT_CONFIG.sessionRules.map((r) => toJs(r.rex));
  assert.strictEqual(`INFO [SPLMessage][${uuid}][][VN]`.match(ecomm).groups.sidEcomm, uuid);
  assert.strictEqual(`INFO [SPLMessage]${uuid}|[VN]`.match(ecomm).groups.sidEcomm, uuid);
  // no id in the header: "sessionId" or "sessionIdentity" in the same eComm event
  assert.strictEqual(`INFO [SPLMessage][][u] -/x - Request -\n{"meta":{"sessionId":"${uuid}"}}`.match(ecomm).groups.sidEcomm, uuid);
  assert.strictEqual(`INFO [SPLMessage][][u] -/x -\n{"requesterContext":{"sessionIdentity": "${uuid}"}}`.match(ecomm).groups.sidEcomm, uuid);
  assert.strictEqual(`INFO [SPLHostMessage][x] {"sessionId":"${uuid}"}`.match(ecomm), null, 'not in other layers');
  assert.strictEqual(`INFO [SPLHostMessage][${uuid}][<<USER_ID>>]`.match(ent).groups.sidEnterprise, uuid);
  assert.strictEqual(`INFO [SPLHostMessage] [${uuid}]|[<<USER_ID>>]`.match(ent).groups.sidEnterprise, uuid);
  assert.strictEqual(`INFO [SPLHostMessage][][u] - /enq/x - [Request]:\n{"meta":{"sessionId":"${uuid}"}}`.match(ent).groups.sidEnterprise, uuid);
  assert.strictEqual(`INFO [SPLHostMessage][][u] - /enq/x - [Response]: {"sessionIdentity": "${uuid}"}`.match(ent).groups.sidEnterprise, uuid);
  assert.strictEqual(`INFO [SPLMessage][x] {"sessionId":"${uuid}"}`.match(ent), null, 'not in other layers');
  assert.strictEqual(`| CIF:<<CIF_NUM>> | WLS:${uuid} | WS`.match(wls).groups.sidWls, uuid);
  // without WLS: "sessionId" or "sessionIdentity" in the WSAppLog event; WLS: wins when both are there
  const other = 'eeeeeeee-0000-4000-8000-000000000005';
  assert.strictEqual(`[ENQWSAppLog] x | URL is /a request:\n{"meta":{"sessionId":"${uuid}"}}`.match(wls).groups.sidWls, uuid);
  assert.strictEqual(`[ENQWSAppLog] x | Response: {"requesterContext":{"sessionIdentity": "${uuid}"}}`.match(wls).groups.sidWls, uuid);
  assert.strictEqual(`[ENQWSAppLog] x | WLS:${uuid} | URL:/a |\nResponse:{"sessionIdentity":"${other}"}`.match(wls).groups.sidWls, uuid);
  assert.strictEqual(`[SPLMessage][] {"sessionId":"${uuid}"}`.match(wls), null, 'not in other layers');
  assert.strictEqual(`id=${uuid};`.match(any).groups.sidAny, uuid);
  assert.strictEqual('id=--------------------------------------;'.match(any), null);
});

test('Flow format: per-layer indent and [?]/[!] direction markers', () => {
  const out = spl.generate(spl.DEFAULT_CONFIG);
  assert.match(out, /\| eval Indent=case\(LayerName="eComm","",LayerName="Enterprise","> ",LayerName="Host",">>> ",LayerName="WS",">> "\)/);
  assert.match(out, /\| eval DirectionSymbol=if\(Direction="Request","\?","!"\)/);
  assert.match(out, /\n\| eval HostEndpoint=if\(LayerName="Host",coalesce\(DGEEndpoint,"NA"\),null\(\)\)\n/);
  assert.match(out, /LayerName="Host",HostEndpoint\)\n/);
  assert.match(out, /\| eval PairKey=case\(LayerName="Host",LayerName\."\|"\.HostEndpoint,/);
});

test('URL, eCommEndpoint (eComm) and EnterpriseEndpoint (Enterprise) read their line formats', () => {
  // SPL rex strings use \" for a literal quote; a leading (?i) becomes the JS i flag.
  const toJs = (rex) => {
    const src = rex.replace(/\\"/g, '"');
    return src.startsWith('(?i)') ? new RegExp(src.slice(4), 'i') : new RegExp(src);
  };
  const urlLine = spl.generate(spl.DEFAULT_CONFIG).split('\n').find((l) => l.includes('(?<URL>'));
  const url = toJs(urlLine.match(/"(.*)"$/)[1]);
  assert.strictEqual('RestEndPointUFWAspect: | URL is /dge-idm/idm/user/profile/get:'.match(url).groups.URL, '/dge-idm/idm/user/profile/get');
  assert.strictEqual('WebLogUFWAspect: | URL:/dge-enq/enq/customer/portfolio | StartTime'.match(url).groups.URL, '/dge-enq/enq/customer/portfolio');

  const ecomm = toJs(spl.DEFAULT_CONFIG.endpointRules[0].rex);
  const ent = toJs(spl.DEFAULT_CONFIG.endpointRules[1].rex);
  const head = '[SPLMessage][dddddddd-0000-4000-8000-000000000004][U][VN][9.14][t][Android-SPL][][]';
  // eComm: the path before "- Request-" / "- Response-", after a - or a space, with or without the leading /
  for (const sep of ['-', ' ']) {
    for (const path of ['/dge-asv/aaa/bbb', 'dge-asv/aaa/bbb']) {
      for (const dir of ['Request', 'Response']) {
        assert.strictEqual(`${head}${sep}${path} - ${dir}-`.match(ecomm)?.groups.eCommEndpoint, path, `${sep}${path} - ${dir}-`);
      }
    }
  }
  assert.strictEqual(`${head}\n-/spl-banking/services/vn/security/preLogin - Request -`.match(ecomm).groups.eCommEndpoint, '/spl-banking/services/vn/security/preLogin');
  // eComm responses log no direction word: the payload follows on the next line or the same line
  assert.strictEqual(`${head} -/spl-banking/a/b -\n{"x":1}`.match(ecomm).groups.eCommEndpoint, '/spl-banking/a/b');
  assert.strictEqual(`${head} -/spl-banking/a/b - {"x":1}`.match(ecomm).groups.eCommEndpoint, '/spl-banking/a/b');
  assert.strictEqual(`${head} -/spl-banking/a/b - something else`.match(ecomm), null, 'not before other text');
  assert.strictEqual('[SPLHostMessage][x][] -/idm/user/profile/get - [Response]:'.match(ecomm), null, 'eComm only');

  // Enterprise: the same, after [SPLHostMessage]
  assert.strictEqual('[SPLHostMessage][x][Android-SPL][49ms] -/idm/user/profile/get - [Response]:'.match(ent).groups.EnterpriseEndpoint, '/idm/user/profile/get');
  assert.strictEqual('[SPLHostMessage] [x]|[u]\n[Android-SPL] - /insights/initInsights - [Request]:'.match(ent).groups.EnterpriseEndpoint, '/insights/initInsights');
  assert.strictEqual(`${head} -/spl-banking/a/b - Request -`.match(ent), null, 'Enterprise only');
  assert.strictEqual('[SPLHostMessage][x][] -/idm/user/profile/get - Request -'.match(ent), null, 'only before [Request] / [Response]');
  assert.strictEqual('[ENQWSAppLog] [t] - [::dge-enq:enq.a] - RestEndPointUFWAspect: | URL is /a request:'.match(ent), null);
});

test('SubLayer: WS is layer 2 with sub-layer 1; a layer without a sub-layer number counts as 0', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  assert.match(spl.generate(cfg), /\n\| eval SubLayer=case\(LayerName="eComm",0,LayerName="Enterprise",0,LayerName="WS",1,LayerName="Host",0\)\n/);
  cfg.layers.push({ name: 'OPI', match: 'match(_raw,"OPIAppLog")', layer: 4, indent: '' });
  assert.match(spl.generate(cfg), /LayerName="Host",0,LayerName="OPI",0\)\n/);
});

test('dropNoDirection adds | where isnotnull(Direction) right after Direction', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  assert.match(spl.generate(cfg), /"Response"\)\n\| where isnotnull\(Direction\)\n\| rex /);
  cfg.dropNoDirection = false;
  assert.doesNotMatch(spl.generate(cfg), /isnotnull\(Direction\)/);
});

test('DGEEndpoint reads [::name] only, not [:name]', () => {
  const flow = require('../js/flow.js');
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  const at = (stamp, line) => `2026-10-26 ${stamp} [x] INFO\n${line}\n`;
  const log = at('09:30:00.000', '<EAI> <SvcCode>A_X</SvcCode> Request Message - [:dge-enq:enq.a.VN.V1] WLS:aaaaaaaa-0000-4000-8000-000000000001 |')
    + at('09:30:01.000', '<EAI> <SvcCode>B_X</SvcCode> Request Message - [::dge-enq:enq.b.VN.V1] WLS:aaaaaaaa-0000-4000-8000-000000000001 |');
  const rows = flow.run(cfg, [{ name: 'a.log', text: log, anySource: true }], []);
  assert.deepStrictEqual(rows.map((r) => r.DGEEndpoint ?? null), [null, 'dge-enq:enq.b.VN.V1']);
});

test('URL reads "URL:/path |" and "URL is /path", not a longer word ending in URL', () => {
  const line = spl.generate(spl.DEFAULT_CONFIG).split('\n').find((l) => l.includes('(?<URL>'));
  const re = new RegExp(line.match(/"(.*)"$/)[1]);
  const url = (s) => s.match(re)?.groups.URL;
  assert.strictEqual(url('URL:/dge-asv/cpm/user/getActive |'), '/dge-asv/cpm/user/getActive');
  assert.strictEqual(url('URL is /dge-asv/cpm/user/getActive '), '/dge-asv/cpm/user/getActive');
  assert.strictEqual(url('redirectURL:/other |'), undefined);
});

test('transactionRef / transactionCode read the JSON keys, not a longer key that ends in them', () => {
  // (?i) is Splunk's inline flag; JavaScript takes it as the i flag
  const rex = (field) => new RegExp(spl.DEFAULT_CONFIG.params.find((p) => p.field === field).rex.replace(/\\"/g, '"').replace('(?i)', ''), 'i');
  const ref = rex('transactionRef'); const code = rex('transactionCode');
  assert.strictEqual('{"transactionReferenceNumber":"9990000000000101"}'.match(ref).groups.transactionRef, '9990000000000101');
  assert.strictEqual('transactionRef=ABC123,'.match(ref).groups.transactionRef, 'ABC123');
  assert.strictEqual('{"transactionCode": "SEC02"}'.match(code).groups.transactionCode, 'SEC02');
  assert.strictEqual('{"originalTransactionReferenceNumber":"111"}'.match(ref), null);
  assert.strictEqual('{"oldTransactionCode":"X"}'.match(code), null);
});

test('renameMarker: a marker renamed in a source filter is renamed in the layer logic', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  const changed = spl.renameMarker(cfg, '"[SPLMessage]"', '"[MightyMesage]"');
  assert.deepStrictEqual(changed, ['Layer eComm', 'Session rule sidEcomm', 'Endpoint rule eCommEndpoint']);
  assert.strictEqual(cfg.layers[0].match, String.raw`match(_raw,"\[MightyMesage\]")`);
  assert.ok(cfg.sessionRules[0].rex.startsWith(String.raw`(?i)\[MightyMesage\](?:\s*`), cfg.sessionRules[0].rex);
  assert.strictEqual(cfg.layers[1].match, String.raw`match(_raw,"\[SPLHostMessage\]")`, 'other markers untouched');
  assert.deepStrictEqual(spl.renameMarker(cfg, '"[SPLHostMessage]"', '"[MightyHostMessage]"'), ['Layer Enterprise', 'Session rule sidEnterprise', 'Endpoint rule EnterpriseEndpoint']);
  assert.strictEqual(cfg.layers[1].match, String.raw`match(_raw,"\[MightyHostMessage\]")`);
  assert.ok(cfg.sessionRules[1].rex.startsWith(String.raw`(?i)\[MightyHostMessage\](?:\s*`), cfg.sessionRules[1].rex);
  // wildcards are not copied into the regex
  assert.deepStrictEqual(spl.renameMarker(cfg, '"*WSAppLog*" ("request:")', '"*OPIAppLog*" ("request:")'), ['Layer WS', 'Session rule sidWls']);
  assert.strictEqual(cfg.layers.find((l) => l.name === 'WS').match, 'match(_raw,"OPIAppLog")');
  // nothing when several terms change, or none
  assert.deepStrictEqual(spl.renameMarker(cfg, '"A" "B"', '"C" "D"'), []);
  assert.deepStrictEqual(spl.renameMarker(cfg, '"A"', '"A" OR "B"'), []);
});

test('Start time / End time: earliest/latest in whole seconds and a where clause with the milliseconds', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  assert.doesNotMatch(spl.generate(cfg), /earliest=|_time>=/, 'empty: no time limit');
  cfg.startTime = '2026-11-18 15:28:25.554';
  cfg.endTime = '2026-11-18 15:30:00';
  const out = spl.generate(cfg);
  assert.ok(out.includes('\nearliest="11/18/2026:15:28:25" latest="11/18/2026:15:30:01"\n'));
  assert.ok(out.includes('\n| where _time>=strptime("2026-11-18 15:28:25.554","%Y-%m-%d %H:%M:%S.%3N") AND _time<=strptime("2026-11-18 15:30:00.000","%Y-%m-%d %H:%M:%S.%3N")\n| eval LayerName='));
  assert.deepStrictEqual(spl.validate(cfg), []);
  cfg.endTime = '';
  assert.ok(spl.generate(cfg).includes('\nearliest="11/18/2026:15:28:25"\n| where _time>=strptime("2026-11-18 15:28:25.554"'));
  cfg.endTime = '2026-11-18 15:00:00.000';
  assert.ok(spl.validate(cfg).some((w) => /Start time must be earlier than End time/.test(w)));
  cfg.endTime = cfg.startTime;
  assert.ok(spl.validate(cfg).some((w) => /Start time must be earlier than End time/.test(w)), 'equal times too');
  cfg.startTime = '2026-02-30 10:00:00';
  assert.ok(spl.validate(cfg).some((w) => /Start time .* is not a time/.test(w)));
});
