// Maps each line of a Splunk flow result (Excel/CSV rows from TraceImport) to a raw log
// event by timestamp.
//
// Splunk's EventTime and the log's own timestamp can differ by a time-zone offset, and an
// Excel export often keeps whole seconds only. So:
//   1. the offset is the shift that lines up the most rows with a log event within the
//      tolerance (or the one given);
//   2. each row is mapped to the closest log event in time after that shift; when several
//      events are equally close (same second), the one whose layer, direction and API
//      agree with the row wins. Each log event is used once.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceCompare = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const hop = (r) => `${r.LayerName ?? '?'} ${r.API ?? 'N/A'}`;
  const same = (a, b) => a != null && b != null && String(a).trim().toLowerCase() === String(b).trim().toLowerCase();

  // "+1h 0m 0.001s" style text for an offset in ms.
  function formatOffset(ms) {
    const sign = ms < 0 ? '-' : '+';
    let a = Math.abs(ms);
    const h = Math.floor(a / 3600000); a -= h * 3600000;
    const m = Math.floor(a / 60000); a -= m * 60000;
    return `${sign}${h}h ${m}m ${(a / 1000).toFixed(3)}s`;
  }

  // A log event agrees with a row when layer, direction and (when both have one) sessionId
  // are the same. The sessionId is what keeps unrelated files from lining up by chance.
  const agrees = (x, l) => (!x.LayerName || same(x.LayerName, l.LayerName)) && (!x.Direction || same(x.Direction, l.Direction))
    && (!x.sessionId || !l.sessionId || same(x.sessionId, l.sessionId));

  // How many rows have an agreeing log event within the tolerance once the offset is
  // removed, and how far those rows are from it in total (smaller is a better fit).
  // Counting only agreeing events keeps a coincidental shift between unrelated files out.
  function coverage(xs, sorted, offset, tol) {
    let n = 0; let gap = 0;
    for (const x of xs) {
      const t = x.time - offset;
      let lo = 0; let hi = sorted.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (sorted[mid].time < t - tol) lo = mid + 1; else hi = mid; }
      let best = Infinity;
      for (let k = lo; k < sorted.length && sorted[k].time <= t + tol; k++) {
        if (agrees(x, sorted[k])) best = Math.min(best, Math.abs(sorted[k].time - t));
      }
      if (best <= tol) { n++; gap += best; }
    }
    return { n, gap };
  }

  // The shift that lines up the most rows with agreeing events: try the most common
  // whole-second differences. Returns { offset, rows } (rows = rows it lines up).
  function detectOffset(xs, logs, tol) {
    const sorted = [...logs].sort((a, b) => a.time - b.time);
    const freq = new Map();
    const step = Math.max(1, Math.ceil((xs.length * logs.length) / 400000)); // keep big inputs fast
    for (let i = 0; i < xs.length; i += step) {
      for (const l of logs) {
        if (!agrees(xs[i], l)) continue;
        const d = Math.round((xs[i].time - l.time) / 1000) * 1000;
        freq.set(d, (freq.get(d) || 0) + 1);
      }
    }
    const candidates = [...freq].sort((a, b) => b[1] - a[1]).slice(0, 25).map(([d]) => d);
    if (!candidates.includes(0)) candidates.push(0);
    // most rows lined up, then the tightest fit, then the smallest shift
    let best = 0; let bestFit = { n: -1, gap: Infinity };
    for (const c of candidates) {
      const fit = coverage(xs, sorted, c, tol);
      if (fit.n > bestFit.n || (fit.n === bestFit.n && (fit.gap < bestFit.gap || (fit.gap === bestFit.gap && Math.abs(c) < Math.abs(best))))) {
        best = c; bestFit = fit;
      }
    }
    return bestFit.n > 0 ? { offset: best, rows: bestFit.n } : { offset: 0, rows: 0 };
  }

  // excel: rows from TraceImport.toFlowRows (with .time).
  // logs: every parsed log event: { time, source, lineNo, raw, head, LayerName, Direction, API, sessionId }.
  // offsetMs: number to force the offset, or null/undefined to detect it.
  function compare(excel, logs, { toleranceMs = 1000, offsetMs = null } = {}) {
    const xs = excel.filter((x) => Number.isFinite(x.time));
    const ls = logs.filter((l) => Number.isFinite(l.time));
    const auto = offsetMs == null;
    // Both sides name their sessions but share none: unrelated files, so no offset is guessed.
    const xSids = new Set(xs.map((x) => x.sessionId).filter(Boolean));
    const lSids = new Set(ls.map((l) => l.sessionId).filter(Boolean));
    const sharedSessions = [...xSids].filter((s) => lSids.has(s)).length;
    const noSharedSession = xSids.size > 0 && lSids.size > 0 && sharedSessions === 0;
    const detected = auto && xs.length && ls.length && !noSharedSession ? detectOffset(xs, ls, toleranceMs) : { offset: 0, rows: 0 };
    const offset = auto ? detected.offset : offsetMs;

    // every row/event pair within the tolerance, best first
    const byTime = [...ls].sort((a, b) => a.time - b.time);
    const cands = [];
    xs.forEach((x) => {
      const t = x.time - offset;
      for (const l of byTime) {
        if (l.time < t - toleranceMs) continue;
        if (l.time > t + toleranceMs) break;
        const layerOk = same(x.LayerName, l.LayerName);
        const dirOk = same(x.Direction, l.Direction);
        const apiOk = same(x.API, l.API);
        const sidOk = !x.sessionId || !l.sessionId || same(x.sessionId, l.sessionId);
        // Within the window, fewer mismatches (layer, direction, API; another session counts
        // double) beat closeness: an Excel export keeps whole seconds, so a wrong event can sit
        // nearer than the right one. Between equal mismatch counts, the closer event wins.
        const w = Math.max(toleranceMs, 1) + 1;
        const mismatches = (layerOk ? 0 : 1) + (dirOk ? 0 : 1) + (apiOk ? 0 : 1) + (sidOk ? 0 : 2);
        const score = Math.abs(t - l.time) + mismatches * w;
        cands.push({ x, l, score, delta: Math.round(t - l.time), layerOk, dirOk, apiOk, sidOk });
      }
    });
    // Lines are mapped in time order, each taking its best still-free event, so that lines of
    // one flow keep their order: with whole-second times, a later line can sit nearer to an
    // earlier line's event than the earlier line does.
    const perRow = new Map();
    for (const c of cands) {
      if (!perRow.has(c.x)) perRow.set(c.x, []);
      perRow.get(c.x).push(c);
    }
    const mapOf = new Map(); const used = new Set();
    for (const x of [...xs].sort((a, b) => a.time - b.time || a.line - b.line)) {
      const pick = (perRow.get(x) || []).filter((c) => !used.has(c.l)).sort((a, b) => a.score - b.score || a.l.time - b.l.time)[0];
      if (!pick) continue;
      mapOf.set(x, pick);
      used.add(pick.l);
    }

    const rows = excel.map((x) => {
      const c = mapOf.get(x);
      const checks = [];
      if (!Number.isFinite(x.time)) checks.push('EventTime not recognised');
      if (!c) {
        if (Number.isFinite(x.time)) checks.push(`no log event within ${toleranceMs} ms`);
        return { x, l: null, delta: null, status: 'not mapped', checks };
      }
      if (!c.layerOk) checks.push(`log layer: ${c.l.LayerName ?? 'unknown'}`);
      if (!c.dirOk) checks.push(`log direction: ${c.l.Direction ?? 'unknown'}`);
      if (c.layerOk && !c.apiOk) checks.push(`log API: ${c.l.API ?? 'N/A'}`);
      if (!c.sidOk) checks.push(`log sessionId: ${c.l.sessionId}`);
      return { x, l: c.l, delta: c.delta, status: checks.length ? 'mapped, differs' : 'mapped', checks };
    });

    const unmappedLog = logs.filter((l) => !used.has(l));
    const quality = [];
    const add = (kind, items) => { if (items.length) quality.push({ kind, count: items.length, items }); };
    add('Lines with no log event in the time window', rows.filter((r) => r.status === 'not mapped').map((r) => `row ${r.x.line}: ${r.x.EventTime} ${r.x.Flow}`));
    add('Lines mapped to an event of another layer, direction or API', rows.filter((r) => r.status === 'mapped, differs').map((r) => `row ${r.x.line}: ${r.x.Flow} ↔ ${base(r.l.source)}:${r.l.lineNo} (${r.checks.join('; ')})`));
    add('Lines with an unreadable EventTime', rows.filter((r) => !Number.isFinite(r.x.time)).map((r) => `row ${r.x.line}: "${r.x.EventTime}"`));
    add('Log events not mapped to any line', unmappedLog.map((l) => `${base(l.source)}:${l.lineNo} ${l.head.slice(0, 120)}`));
    add('Hops in the mapped log events that never appear in the Splunk result',
      [...new Set(logs.filter((l) => l.LayerName).map(hop))].filter((h) => !excel.some((x) => hop(x) === h)));

    // With no shift lining up a single agreeing pair, the files most likely cover other
    // sessions or times; say so rather than present coincidental matches as an alignment.
    const unrelated = xs.length > 0 && ls.length > 0 && (noSharedSession || (auto && detected.rows === 0));
    if (unrelated) {
      quality.unshift({ kind: 'The files do not seem to belong together', count: 1,
        items: [noSharedSession
          ? `The Splunk result has ${xSids.size} session(s) and the log files ${lSids.size}, with none in common. Load the log files of the same sessions.`
          : 'No time offset lines up any Splunk line with a log event of the same session, layer and direction. Check that the log files cover the same sessions and time as the Splunk result, or set the offset yourself.'] });
    }

    return {
      rows, unmappedLog, quality, unrelated, sharedSessions,
      offsetMs: offset, offsetText: formatOffset(offset), offsetAuto: auto,
      mapped: rows.filter((r) => r.l).length,
      agreeing: rows.filter((r) => r.status === 'mapped').length,
    };
  }

  const base = (p) => String(p ?? '').split(/[\\/]/).pop();

  // ---------- JSON payload of a log event ----------

  // The JSON object a log event carries after its text prefix ("- Request -", "[Request]:",
  // "Response:"). Finds a balanced {...} (strings and escapes respected) and parses it; tries
  // the first few "{" so a brace in the prefix does not hide the payload. null when none parses.
  function extractJson(raw) {
    const s = String(raw ?? '');
    let from = 0;
    for (let attempt = 0; attempt < 5; attempt++) {
      const start = s.indexOf('{', from);
      if (start < 0) return null;
      let depth = 0; let inStr = false; let esc = false; let end = -1;
      for (let i = start; i < s.length; i++) {
        const c = s[i];
        if (inStr) {
          if (esc) esc = false;
          else if (c === '\\') esc = true;
          else if (c === '"') inStr = false;
        } else if (c === '"') inStr = true;
        else if (c === '{' || c === '[') depth++;
        else if (c === '}' || c === ']') { depth--; if (depth === 0) { end = i; break; } }
      }
      if (end > start) {
        try {
          const value = JSON.parse(s.slice(start, end + 1));
          if (value && typeof value === 'object') return value;
        } catch (e) { /* not JSON from this brace; try the next one */ }
      }
      from = start + 1;
    }
    return null;
  }

  // Parameter paths and values: { a: { b: [1, { c: 2 }] } } -> a.b[0] = 1, a.b[1].c = 2
  // (with sep '|': a|b[0], a|b[1]|c). Empty objects/arrays are kept as {} / []; at most `limit` rows.
  function flattenJson(value, { sep = '.', limit = 1000 } = {}) {
    const rows = [];
    const walk = (v, p) => {
      if (rows.length >= limit) return;
      if (Array.isArray(v)) {
        if (!v.length) rows.push([p, '[]']);
        v.forEach((x, i) => walk(x, `${p}[${i}]`));
      } else if (v && typeof v === 'object') {
        const keys = Object.keys(v);
        if (!keys.length) rows.push([p, '{}']);
        keys.forEach((k) => walk(v[k], p ? `${p}${sep}${k}` : k));
      } else {
        rows.push([p, v === null ? 'null' : String(v)]);
      }
    };
    walk(value, '');
    return rows;
  }

  // ---------- XML payload of a log event ----------

  const XML_ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
  const unescapeXml = (s) => s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (_, e) => XML_ENTITIES[e]
    ?? String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)));

  // The XML a log event carries (e.g. "Request Message:<?xml ...?> <EAI>...</EAI>") as an element
  // tree { name, attrs, children, text }, or null. Tolerant of log XML: desensitised placeholders
  // like <<USER_ID>> stay text, a mismatched end tag closes up to its open element (or is
  // ignored), and a truncated document keeps what was read.
  function extractXml(raw) {
    const s0 = String(raw ?? '');
    let start = s0.indexOf('<?xml');
    if (start < 0) {
      // no declaration: the first element that is also closed later
      const m = /<([A-Za-z_][\w.-]*)[\s>]/g;
      let hit;
      while ((hit = m.exec(s0))) {
        if (s0.indexOf(`</${hit[1]}>`, hit.index) > 0) { start = hit.index; break; }
      }
      if (start < 0) return null;
    }
    const s = s0.slice(start).replace(/<<([A-Za-z0-9_]+)>>/g, '«$1»');
    const restore = (t) => t.replace(/«([A-Za-z0-9_]+)»/g, '<<$1>>');
    const root = { name: '#root', attrs: [], children: [], text: '' };
    const stack = [root];
    const re = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[([\s\S]*?)\]\]>|<\/([A-Za-z_][\w.:-]*)\s*>|<([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)|</g;
    let m;
    while ((m = re.exec(s))) {
      const top = stack[stack.length - 1];
      if (m[1] != null) top.text += m[1];
      else if (m[2]) {
        const i = stack.map((e) => e.name).lastIndexOf(m[2]);
        if (i > 0) stack.length = i;
      } else if (m[3]) {
        const el = { name: m[3], attrs: [...(m[4] || '').matchAll(/([\w.:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)].map((a) => [a[1], unescapeXml(a[2] ?? a[3] ?? '')]), children: [], text: '' };
        top.children.push(el);
        if (!m[5]) stack.push(el);
      } else if (m[6] != null) top.text += m[6];
      else top.text += '<';
    }
    const fix = (e) => { e.text = restore(unescapeXml(e.text)).trim(); e.attrs = e.attrs.map(([k, v]) => [k, restore(v)]); e.children.forEach(fix); };
    fix(root);
    return root.children.length ? (root.children.length === 1 ? root.children[0] : root) : null;
  }

  // Parameter paths and values of an element tree: EAI|SvcRq|SvcCode = BA_ACCT_INFO_N3.
  // Repeated siblings get an index (SubSvc[0], SubSvc[1]); attributes are path@name; empty
  // elements are listed with an empty value. At most `limit` rows.
  function flattenXml(node, { sep = '|', limit = 1000 } = {}) {
    const rows = [];
    const walk = (e, p) => {
      if (rows.length >= limit) return;
      e.attrs.forEach(([k, v]) => rows.push([`${p}@${k}`, v]));
      if (!e.children.length) { rows.push([p, e.text]); return; }
      if (e.text) rows.push([p, e.text]);
      const count = {};
      e.children.forEach((c) => { count[c.name] = (count[c.name] || 0) + 1; });
      const seen = {};
      e.children.forEach((c) => {
        const idx = count[c.name] > 1 ? `[${(seen[c.name] = (seen[c.name] ?? -1) + 1)}]` : '';
        walk(c, `${p}${sep}${c.name}${idx}`);
      });
    };
    if (node.name === '#root') node.children.forEach((c) => walk(c, c.name));
    else walk(node, node.name);
    return rows;
  }

  // The structure of an event's payload: JSON first, else XML. { kind: 'JSON' | 'XML', rows } or null.
  function payloadStructure(raw, { sep = '|' } = {}) {
    const json = extractJson(raw);
    if (json) return { kind: 'JSON', rows: flattenJson(json, { sep }) };
    const xml = extractXml(raw);
    if (xml) {
      const rows = flattenXml(xml, { sep });
      if (rows.length) return { kind: 'XML', rows };
    }
    return null;
  }

  return { compare, detectOffset, formatOffset, extractJson, flattenJson, extractXml, flattenXml, payloadStructure };
});
