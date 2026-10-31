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
  assert.match(spl.generate(cfg), /^\| "abc" OR "a\\"b"$/m);
  cfg.terms = [];
  assert.doesNotMatch(spl.generate(cfg), /^\| "/m);
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
  cfg.sources[1].enabled = false;
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
  assert.ok(spl.generate(cfg).startsWith('(\n\tsource="/var/log/pods/spl-banking-*log"\n\t("[SPLMessage]" OR "[SPLHostMessage]")\n\tOR\n\tsource="/var/log/pods/spl-ms-*log"\n'));
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
  cfg.endpointRules = [cfg.endpointRules[2], { field: 'EpX', rex: '(?<EpX>\\S+)' }];
  const out = spl.generate(cfg);
  assert.match(out, /\| eval Endpoint=coalesce\(Endpoint3,EpX\)/);
  assert.doesNotMatch(out, /Endpoint1/);
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
  assert.ok(out.startsWith('(\n\t(\n\t\tsource="/var/log/pods/spl-banking-*log"\n\t\t("[SPLMessage]" OR "[SPLHostMessage]")\n\t)\n\tOR\n\t(\n\t\tsource="/var/log/pods/spl-ms-*log"\n'));
  assert.match(out, /Response Message"\)\)\n\t\)\n\)\n\| "/);
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
  assert.strictEqual(`INFO [SPLHostMessage][${uuid}][<<USER_ID>>]`.match(ent).groups.sidEnterprise, uuid);
  assert.strictEqual(`| CIF:<<CIF_NUM>> | WLS:${uuid} | WS`.match(wls).groups.sidWls, uuid);
  assert.strictEqual(`id=${uuid};`.match(any).groups.sidAny, uuid);
  assert.strictEqual('id=--------------------------------------;'.match(any), null);
});

test('Flow format: per-layer indent and [?]/[!] direction markers', () => {
  const out = spl.generate(spl.DEFAULT_CONFIG);
  assert.match(out, /\| eval Indent=case\(LayerName="eComm","",LayerName="Enterprise","> ",LayerName="Host",">>> ",LayerName="WS",">> "\)/);
  assert.match(out, /\| eval DirectionSymbol=if\(Direction="Request","\?","!"\)/);
  assert.match(out, /LayerName="Host",replace\(DGEEndpoint,":","."\)\)/);
});

test('URL and Endpoint1 rules read the WS, eComm and Enterprise line formats', () => {
  const toJs = (rex) => new RegExp(rex.replace(/\\"/g, '"'));
  const urlLine = spl.generate(spl.DEFAULT_CONFIG).split('\n').find((l) => l.includes('(?<URL>'));
  const url = toJs(urlLine.match(/"(.*)"$/)[1]);
  assert.strictEqual('RestEndPointUFWAspect: | URL is /dge-idm/idm/user/profile/get:'.match(url).groups.URL, '/dge-idm/idm/user/profile/get');
  assert.strictEqual('WebLogUFWAspect: | URL:/dge-enq/enq/customer/portfolio | StartTime'.match(url).groups.URL, '/dge-enq/enq/customer/portfolio');
  const ep = toJs(spl.DEFAULT_CONFIG.endpointRules[0].rex);
  assert.strictEqual('[6adeb69a][][]\n-/spl-banking/services/vn/security/preLogin - Request -'.match(ep).groups.Endpoint1, '/spl-banking/services/vn/security/preLogin');
  assert.strictEqual('[Android-SPL][49ms] -/idm/user/profile/get - [Response]:'.match(ep).groups.Endpoint1, '/idm/user/profile/get');
  assert.strictEqual('[SPLHostMessage][11ms] - /insights/initInsights - [Response]:'.match(ep).groups.Endpoint1, '/insights/initInsights');
});
