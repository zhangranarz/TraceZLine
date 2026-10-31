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
  assert.match(out, /\nOR\nsource="\/var\/log\/pods\/spl-opi-\*\.log"\n"OPIAppLog"\n\)\n/);
  assert.match(out, /\| eval Params=mvappend\(\nif\(isnotnull\(transactionRef\).*null\(\)\)\)$/m);
  assert.doesNotMatch(out, /transactionCode/);
});

test('disabled sources are left out', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.sources[1].enabled = false;
  assert.doesNotMatch(spl.generate(cfg), /spl-ms/);
});

test('default config only warns about ungrouped sources', () => {
  const w = spl.validate(spl.DEFAULT_CONFIG);
  assert.strictEqual(w.length, 1);
  assert.match(w[0], /not grouped/);
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.groupSources = true;
  assert.deepStrictEqual(spl.validate(cfg), []);
});

test('groupSources wraps each source in its own parentheses inside the outer ones', () => {
  const cfg = spl.clone(spl.DEFAULT_CONFIG);
  cfg.groupSources = true;
  const out = spl.generate(cfg);
  assert.ok(out.startsWith('(\n(\n  source="/var/log/pods/spl-banking-*log"\n  ("[SPLMessage]" OR "[SPLHostMessage]")\n)\nOR\n(\n  source="/var/log/pods/spl-ms-*log"\n'));
  assert.match(out, /Response Message"\)\)\n\)\n\)\n\| "/);
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
  // SPL rex strings use \" for a literal quote; JS regex needs named groups as-is.
  const toJs = (rex) => new RegExp(rex.replace(/\\"/g, '"'));
  const [ecomm, ent, wls, any] = spl.DEFAULT_CONFIG.sessionRules.map((r) => toJs(r.rex));
  assert.strictEqual(`[SPLMessage]x|{"sessionId" : "${uuid}"}`.match(ecomm).groups.sidEcomm, uuid);
  assert.strictEqual(`[SPLHostMessage]{"sessionIdentity":"${uuid}"}`.match(ent).groups.sidEnterprise, uuid);
  assert.strictEqual(`INFO | WLS: ${uuid} | rest`.match(wls).groups.sidWls, uuid);
  assert.strictEqual(`id=${uuid};`.match(any).groups.sidAny, uuid);
});
