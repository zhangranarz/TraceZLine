// Reads a Splunk flow result (the table the query produces, exported as .xlsx or
// .csv) and turns it into flow rows, so the summary, PlantUML and sequence views
// work without the raw logs. No library: .xlsx is a zip of XML parts, unzipped
// with the platform's raw-deflate decoder.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceImport = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------- zip ----------

  async function inflateRaw(bytes) {
    if (typeof DecompressionStream !== 'undefined') {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
      return new Uint8Array(await new Response(stream).arrayBuffer());
    }
    return new Uint8Array(require('zlib').inflateRawSync(bytes));
  }

  // Map of entry name -> async () => Uint8Array, read from the central directory.
  function readZip(buf) {
    const u8 = new Uint8Array(buf);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    let eocd = -1;
    for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('not a zip file (no end of central directory)');
    const count = dv.getUint16(eocd + 10, true);
    let p = dv.getUint32(eocd + 16, true);
    const entries = {};
    const dec = new TextDecoder();
    for (let n = 0; n < count; n++) {
      if (dv.getUint32(p, true) !== 0x02014b50) throw new Error('corrupt zip central directory');
      const method = dv.getUint16(p + 10, true);
      const size = dv.getUint32(p + 20, true);
      const nameLen = dv.getUint16(p + 28, true);
      const extraLen = dv.getUint16(p + 30, true);
      const commentLen = dv.getUint16(p + 32, true);
      const local = dv.getUint32(p + 42, true);
      const name = dec.decode(u8.subarray(p + 46, p + 46 + nameLen));
      entries[name] = async () => {
        const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
        const data = u8.subarray(start, start + size);
        if (method === 0) return data;
        if (method === 8) return inflateRaw(data);
        throw new Error(`${name}: unsupported zip compression ${method}`);
      };
      p += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
  }

  // ---------- xlsx ----------

  const unescapeXml = (s) => s
    .replace(/_x([0-9A-Fa-f]{4})_/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9A-Fa-f]+);/g, (_, e) => ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[e]
      ?? String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10))));
  const textOf = (xml) => unescapeXml([...xml.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)].map((m) => m[1]).join(''));
  const colIndex = (ref) => [...ref.replace(/\d+$/, '')].reduce((n, c) => n * 26 + c.charCodeAt(0) - 64, 0) - 1;

  // First worksheet as an array of rows (arrays of strings).
  async function readXlsx(buf) {
    const zip = readZip(buf);
    const dec = new TextDecoder();
    const read = async (name) => (zip[name] ? dec.decode(await zip[name]()) : '');
    const sheetName = zip['xl/worksheets/sheet1.xml'] ? 'xl/worksheets/sheet1.xml'
      : Object.keys(zip).filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/.test(n)).sort()[0];
    if (!sheetName) throw new Error('no worksheet found in the workbook');
    const shared = [...(await read('xl/sharedStrings.xml')).matchAll(/<si>([\s\S]*?)<\/si>/g)].map((m) => textOf(m[1]));
    const rows = [];
    for (const [, rowXml] of (await read(sheetName)).matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
      const row = [];
      for (const [, attrs, inner = ''] of rowXml.matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
        const ref = (attrs.match(/\br="([A-Z]+\d+)"/) || [])[1];
        const type = (attrs.match(/\bt="(\w+)"/) || [])[1];
        const v = (inner.match(/<v>([\s\S]*?)<\/v>/) || [])[1];
        let value = '';
        if (type === 's') value = shared[Number(v)] ?? '';
        else if (type === 'inlineStr') value = textOf(inner);
        else if (v != null) value = unescapeXml(v);
        row[ref ? colIndex(ref) : row.length] = value;
      }
      rows.push(Array.from(row, (x) => x ?? ''));
    }
    return rows;
  }

  // ---------- csv ----------

  function parseCsv(text) {
    const s = text.replace(/^﻿/, '');
    const firstLine = s.slice(0, s.indexOf('\n') + 1 || s.length);
    const sep = [',', ';', '\t'].sort((a, b) => firstLine.split(b).length - firstLine.split(a).length)[0];
    const rows = [];
    let row = []; let cell = ''; let quoted = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (quoted) {
        if (c === '"' && s[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') quoted = false; else cell += c;
      } else if (c === '"') quoted = true;
      else if (c === sep) { row.push(cell); cell = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && s[i + 1] === '\n') i++;
        row.push(cell); rows.push(row); row = []; cell = '';
      } else cell += c;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    return rows;
  }

  // ---------- flow rows ----------

  // "> Enterprise: /idm/user/profile/get [?]" -> layer, API, direction symbol (may be missing).
  const FLOW_RE = /^\s*[>\-\s]*?([A-Za-z][\w.\- ]*?)\s*:\s*(.*?)\s*(?:\[([?!<>])\])?\s*$/;
  const SERVICE_RE = /^\s*-\s*\[(.*)\]\s*\[[?!<>]\]\s*$/;

  // "26/10/2026 16:28:59", "2026-10-26 16:28:59.123" or an Excel date number -> ms (UTC wall clock).
  function parseTime(s) {
    const t = String(s ?? '').trim();
    let m;
    if ((m = t.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,3}))?)?$/))) {
      return Date.UTC(+m[3], +m[2] - 1, +m[1], +m[4], +m[5], +(m[6] || 0), +((m[7] || '0').padEnd(3, '0')));
    }
    if ((m = t.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,3}))?)?/))) {
      return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0), +((m[7] || '0').padEnd(3, '0')));
    }
    if (/^\d+(\.\d+)?$/.test(t) && Number(t) > 20000) return Math.round((Number(t) - 25569) * 86400000);
    return null;
  }

  // table: rows of cells with a header row (Step, EventTime, sessionId, ServiceInfo or
  // Flow, Params, ElapsedMs; any order, case-insensitive). Rows without Step and
  // EventTime continue the row above (Splunk multivalue cells exported as extra rows).
  // Returns { rows, problems: [{ line, text, reason }] }.
  function toFlowRows(table, cfg) {
    const head = (table[0] || []).map((h) => String(h).trim().toLowerCase());
    const col = (...names) => names.map((n) => head.indexOf(n.toLowerCase())).find((i) => i >= 0) ?? -1;
    const c = {
      step: col('Step'), time: col('EventTime', '_time', 'Time'), sid: col('sessionId'),
      flow: col('ServiceInfo', 'Flow'), params: col('Params'), ms: col('ElapsedMs'),
    };
    if (c.flow < 0) throw new Error('no ServiceInfo or Flow column in the header row: ' + (table[0] || []).join(', '));
    const layerNo = Object.fromEntries((cfg.layers || []).filter((l) => l.name.trim()).map((l) => [l.name.trim().toLowerCase(), [l.name.trim(), Number(l.layer)]]));
    const get = (r, i) => (i >= 0 ? String(r[i] ?? '') : '');
    const lines = (s) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);

    const rows = []; const problems = [];
    table.slice(1).forEach((r, k) => {
      const line = k + 2;
      const flowLines = lines(get(r, c.flow));
      if (!r.some((x) => String(x ?? '').trim())) return;
      const continuation = !get(r, c.step).trim() && !get(r, c.time).trim() && rows.length;
      if (continuation) {
        const prev = rows[rows.length - 1];
        prev.ServiceInfo = [].concat(prev.ServiceInfo, flowLines);
        prev.Params = prev.Params.concat(lines(get(r, c.params)).flatMap((p) => p.split(/;\s*/)).filter(Boolean));
        return;
      }
      const first = flowLines[0] || '';
      const m = first.match(FLOW_RE);
      if (!m) { problems.push({ line, text: first, reason: 'ServiceInfo is not "Layer: API [?]" / "[!]"; row skipped' }); return; }
      if (!m[3]) problems.push({ line, text: first, reason: 'no [?] / [!] marker; direction unknown' });
      const [name, layer] = layerNo[m[1].toLowerCase()] || [m[1], null];
      const time = parseTime(get(r, c.time));
      if (time == null) problems.push({ line, text: get(r, c.time), reason: 'EventTime not recognised; using the row order' });
      const ms = get(r, c.ms).trim();
      rows.push({
        Step: get(r, c.step).trim() ? Number(get(r, c.step)) : null,
        EventTime: get(r, c.time).trim(),
        time: time ?? (rows.length ? rows[rows.length - 1].time + 1 : 0),
        sessionId: get(r, c.sid).trim() || null,
        LayerName: name,
        Layer: layer,
        API: m[2],
        PairKey: `${name}|${m[2] || 'N/A'}`,
        Direction: !m[3] ? null : /[?>]/.test(m[3]) ? 'Request' : 'Response',
        DirectionSymbol: m[3] || '',
        Flow: first,
        ServiceInfo: flowLines.length > 1 ? flowLines : first,
        Params: lines(get(r, c.params)).flatMap((p) => p.split(/;\s*/)).filter(Boolean),
        ElapsedMs: ms && Number.isFinite(Number(ms)) ? Number(ms) : null,
        source: 'import',
        line,
        raw: r.map((x) => String(x ?? '')).join(' | '),
      });
    });
    // Host rows list their SvcCode pairs as "- [A ~ B] [?]" lines, which the diagrams read from ServiceInfo.
    rows.forEach((row) => {
      if (Array.isArray(row.ServiceInfo)) row.ServiceInfo = [row.Flow, ...row.ServiceInfo.slice(1).filter((s) => SERVICE_RE.test(s))];
    });
    return { rows, problems };
  }

  // Bytes -> table, by content: zip signature means .xlsx, anything else is CSV text.
  async function readTable(name, buf) {
    const u8 = new Uint8Array(buf);
    if (u8[0] === 0x50 && u8[1] === 0x4b) return readXlsx(buf);
    if (/\.xls$/i.test(name)) throw new Error('old .xls format is not supported; save it as .xlsx or .csv');
    return parseCsv(new TextDecoder().decode(u8));
  }

  return { readZip, readXlsx, parseCsv, parseTime, toFlowRows, readTable };
});
