'use strict';
// Writes mock-flow.csv and mock-flow.xlsx: the flow table of the mock logs laid out like a
// Splunk export (Step, EventTime, sessionId, ServiceInfo, Params, ElapsedMs), with the extra
// ServiceInfo lines (Host SvcCode pairs, WS service endpoint) on continuation rows.
// Run after make-mock.js: node mock/make-mock-flow.js
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const spl = require('../js/spl.js');
const sim = require('../tools/simulate.js');

const logs = ['spl-banking-mock.log', 'spl-ms-mock.log'].map((f) => path.join(__dirname, f));
const flowRows = sim.run(spl.DEFAULT_CONFIG, logs, []);

const head = ['Step', 'EventTime', 'sessionId', 'Flow', 'Params', 'ElapsedMs'];
const table = [head];
for (const r of flowRows) {
  const lines = [].concat(r.ServiceInfo);
  table.push([r.Step, r.EventTime, r.sessionId, lines[0], r.Params.join('; '), r.ElapsedMs ?? '']);
  lines.slice(1).forEach((l) => table.push(['', '', '', l, '', '']));
}

// CSV
const cell = (v) => (/[",\r\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
fs.writeFileSync(path.join(__dirname, 'mock-flow.csv'), table.map((r) => r.map(cell).join(',')).join('\n') + '\n');

// XLSX: one sheet, shared strings, numbers for Step and ElapsedMs; zip entries stored.
const strings = [];
const sid = (s) => { let i = strings.indexOf(s); if (i < 0) i = strings.push(s) - 1; return i; };
const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const col = (i) => 'ABCDEF'[i];
const sheetRows = table.map((r, ri) => `<row r="${ri + 1}">` + r.map((v, ci) => {
  if (v === '' || v == null) return '';
  const ref = `${col(ci)}${ri + 1}`;
  return typeof v === 'number' ? `<c r="${ref}"><v>${v}</v></c>` : `<c r="${ref}" t="s"><v>${sid(String(v))}</v></c>`;
}).join('') + '</row>').join('');
const NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
const R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const files = {
  '[Content_Types].xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>',
  '_rels/.rels': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${R}/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
  'xl/workbook.xml': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="${NS}" xmlns:r="${R}"><sheets><sheet name="flow" sheetId="1" r:id="rId1"/></sheets></workbook>`,
  'xl/_rels/workbook.xml.rels': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${R}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="${R}/sharedStrings" Target="sharedStrings.xml"/></Relationships>`,
  'xl/worksheets/sheet1.xml': `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="${NS}"><sheetData>${sheetRows}</sheetData></worksheet>`,
};
files['xl/sharedStrings.xml'] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="${NS}" count="${strings.length}" uniqueCount="${strings.length}">${strings.map((s) => `<si><t xml:space="preserve">${xml(s)}</t></si>`).join('')}</sst>`;

function zip(entries) {
  const local = []; const central = []; let offset = 0;
  for (const [name, text] of Object.entries(entries)) {
    const data = Buffer.from(text, 'utf8');
    const n = Buffer.from(name, 'utf8');
    const crc = zlib.crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(n.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(offset, 42);
    local.push(lh, n, data);
    central.push(ch, n);
    offset += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(central.length / 2, 8); end.writeUInt16LE(central.length / 2, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, cd, end]);
}
fs.writeFileSync(path.join(__dirname, 'mock-flow.xlsx'), zip(files));
console.log(`mock-flow.csv / mock-flow.xlsx: ${flowRows.length} flow rows, ${table.length - 1} table rows`);
