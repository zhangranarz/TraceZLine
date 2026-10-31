'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const spl = require('../js/spl.js');
const flow = require('../js/flow.js');
const seq = require('../js/sequence.js');

const mock = (f) => path.join(__dirname, '..', 'mock', f);
const logs = ['spl-banking-mock.log', 'spl-ms-mock.log'].map((f) => ({ name: f, text: fs.readFileSync(mock(f), 'utf8') }));
const models = flow.sequenceModel(flow.run(spl.DEFAULT_CONFIG, logs, []), spl.DEFAULT_CONFIG);

test('sequence model: one diagram per session, App first, layers in order', () => {
  assert.strictEqual(models.length, 3);
  // WS is drawn on Enterprise's lifeline (Diagram as = Enterprise), so it has no column.
  assert.deepStrictEqual(models[0].participants.map((p) => p.name), ['App', 'eComm', 'Enterprise', 'Host']);
  assert.deepStrictEqual(models[2].participants.map((p) => p.name), ['App', 'eComm', 'Enterprise']);
  const self = models[0].items.filter((i) => i.t === 'msg' && i.from === i.to);
  assert.ok(self.length >= 4 && self.every((i) => i.from === 'P_Enterprise' && i.lines[0].text.startsWith('WS: ')));
});

test('SVG: one arrow per message, boxes top and bottom, bars balanced', () => {
  for (const d of models) {
    const svg = seq.render(d);
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"[\s\S]*<\/svg>$/);
    const msgs = d.items.filter((i) => i.t === 'msg');
    const selfCalls = msgs.filter((i) => i.from === i.to).length;
    assert.strictEqual((svg.match(/<line [^>]*stroke-width="1\.2"/g) || []).length, msgs.length - selfCalls);
    // a self-call is a 4-point polyline loop
    assert.strictEqual((svg.match(/<polyline points="[^"]*( [\d.]+,[\d.]+){3}" fill="none" stroke="[^"]*" stroke-width="1\.2"/g) || []).length, selfCalls);
    assert.strictEqual((svg.match(/<rect [^>]*height="30"/g) || []).length, d.participants.length * 2);
    const acts = d.items.filter((i) => i.t === 'act').length;
    assert.strictEqual((svg.match(/<rect [^>]*width="10"/g) || []).length, acts);
  }
});

test('SVG: a note over the last participant fits inside the drawing', () => {
  const svg = seq.render(models[2]);
  const width = Number(svg.match(/<svg [^>]*width="(\d+)"/)[1]);
  const note = svg.match(/<path d="M([\d.]+),[\d.]+ h([\d.]+) l8,8/);
  assert.ok(note, 'no-response note drawn');
  assert.ok(Number(note[1]) + Number(note[2]) + 8 <= width);
});

test('SVG: log text is escaped', () => {
  const d = {
    sessionId: 'x', title: ['<b>&"'], participants: [{ id: 'P_App', name: 'App', actor: true }, { id: 'P_A', name: '<A>' }],
    items: [{ t: 'msg', from: 'P_App', to: 'P_A', dashed: false, lines: [{ text: '<script>alert(1)</script>' }] }],
  };
  const svg = seq.render(d);
  assert.doesNotMatch(svg, /<script>|<b>|<A>/);
  assert.match(svg, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});
