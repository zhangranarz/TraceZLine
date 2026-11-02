// Flow analysis: runs the generated query's logic over log text, without Splunk.
// Used by the page (Flow tab) and by tools/simulate.js.
//
// A log's name is matched against the basename of each configured source="..." pattern.
// The search, LayerName, Direction, rex and Params steps come from the config; the
// steps after sessionId mirror FLOW_BLOCK in js/spl.js and must be kept in step with
// it. This approximates Splunk for local checks; it does not replace a Splunk run.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./spl.js'));
  else root.TraceFlow = factory(root.TraceSpl);
})(typeof self !== 'undefined' ? self : this, function (spl) {
  'use strict';

  const basename = (p) => String(p).split(/[\\/]/).pop();

  // ---------- helpers ----------

  // SPL regex string -> JS RegExp. A leading (?i) becomes the i flag; [^]] is valid PCRE but not JS.
  function rx(src, flags = '') {
    let s = src.replace(/\\"/g, '"').replace(/\[\^\]\]/g, '[^\\]]');
    if (s.startsWith('(?i)')) { s = s.slice(4); flags += 'i'; }
    return new RegExp(s, flags);
  }
  const extract = (re, raw) => { const m = raw.match(re); return (m && m.groups) || {}; };

  // Splunk search: quoted or bare terms, ( ), OR, implicit AND. OR binds tighter than AND.
  function parseSearch(text) {
    const tokens = text.match(/"(?:[^"\\]|\\.)*"|\(|\)|[^\s()"=]+(?:="(?:[^"\\]|\\.)*"|=[^\s()]+)?/g) || [];
    let i = 0;
    const primary = () => {
      const t = tokens[i++];
      if (t === '(') { const e = andExpr(); i++; return e; }
      const m = t.match(/^source="(.*)"$/);
      if (m) return { source: m[1] };
      return { term: t.replace(/^"|"$/g, '').replace(/\\(.)/g, '$1').toLowerCase() };
    };
    const orExpr = () => {
      const parts = [primary()];
      while (tokens[i] === 'OR') { i++; parts.push(primary()); }
      return parts.length === 1 ? parts[0] : { or: parts };
    };
    function andExpr() {
      const parts = [];
      while (i < tokens.length && tokens[i] !== ')') parts.push(orExpr());
      return { and: parts };
    }
    return andExpr();
  }
  const globToRe = (g) => new RegExp('^' + g.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$', 'i');
  function matches(node, ev) {
    if (node.and) return node.and.every((n) => matches(n, ev));
    if (node.or) return node.or.some((n) => matches(n, ev));
    if (node.source) return ev.anySource || globToRe(basename(node.source)).test(basename(ev.source));
    return ev.lower.includes(node.term);
  }

  // eval condition: LayerName="X" / Layer<=N / match(_raw,"re"), joined by AND or OR.
  function evalCond(expr, ev) {
    return expr.split(/\s+OR\s+/).some((orPart) => orPart.split(/\s+AND\s+/).every((p) => {
      let m;
      if ((m = p.match(/^match\(_raw,"((?:[^"\\]|\\.)*)"\)$/))) return rx(m[1]).test(ev.raw);
      if ((m = p.match(/^LayerName="(.*)"$/))) return ev.LayerName === m[1];
      if ((m = p.match(/^Layer\s*(<=|<|=|>=|>)\s*(\d+)$/))) {
        const n = Number(m[2]); const v = ev.Layer;
        return v != null && { '<=': v <= n, '<': v < n, '=': v === n, '>=': v >= n, '>': v > n }[m[1]];
      }
      throw new Error('Unsupported condition: ' + p);
    }));
  }

  // Index of the first comma outside quotes and parentheses.
  function topLevelComma(s) {
    let depth = 0; let quoted = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '"' && s[i - 1] !== '\\') quoted = !quoted;
      else if (!quoted && c === '(') depth++;
      else if (!quoted && c === ')') depth--;
      else if (!quoted && depth === 0 && c === ',') return i;
    }
    return -1;
  }

  // eval value: "literal", a field name, or case(lower(F)="x","X",...).
  function evalValue(v, ev) {
    if (v.startsWith('"')) return v.slice(1, -1);
    const m = v.match(/^case\((.*)\)$/);
    if (m) {
      for (const [, field, test, out] of m[1].matchAll(/lower\((\w+)\)="([^"]*)","([^"]*)"/g)) {
        if (ev[field] != null && ev[field].toLowerCase() === test) return out;
      }
      return null;
    }
    if (/^\w+$/.test(v)) return ev[v];
    throw new Error('Unsupported value: ' + v);
  }

  // ---------- input ----------

  // A Splunk table export (EventTime + PopulatedLog) has numbered lines, a time-only
  // line and a "===== Layer ..." header before each raw event.
  const isExport = (text) => /^\d+\s+=+\s*Layer/m.test(text);
  function stripExport(text) {
    return text.split('\n')
      .filter((l) => !/^\d+\s+\d{4}-\d\d-\d\d \d\d:\d\d:[\d.]+\s*$/.test(l) && !/^\d+\s+=+\s*Layer/.test(l))
      .map((l) => l.replace(/^\d+\s+(?=\d{4}-\d\d-\d\d )/, ''))
      .join('\n');
  }

  // Splits one log file's text into events; each event starts with "YYYY-MM-DD hh:mm:ss.mmm".
  // anySource: treat the file as belonging to every configured source.
  function parseEvents(source, text, anySource = false) {
    let body = text.replace(/\r/g, '');
    if (isExport(body)) body = stripExport(body);
    const events = [];
    body.split('\n').forEach((line, i) => {
      const m = line.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\s/);
      if (m) events.push({ source, anySource, lineNo: i + 1, time: Date.parse(m[1].replace(' ', 'T') + 'Z'), lines: [line] });
      else if (events.length) events[events.length - 1].lines.push(line);
    });
    return events.map((e) => ({ ...e, raw: e.lines.join('\n').trimEnd(), lower: e.lines.join('\n').toLowerCase() }));
  }

  // What a loaded file looks like, for the debug log.
  function describeLog(text) {
    if (text.startsWith('PK\u0003\u0004')) return { format: 'xlsx', events: 0 };
    if (/\u0000/.test(text.slice(0, 4096))) return { format: 'binary', events: 0 };
    const events = parseEvents('', text).length;
    return { format: isExport(text.replace(/\r/g, '')) ? 'splunk-export' : events ? 'raw' : 'unknown', events };
  }

  // ---------- pipeline ----------

  // True when a file name matches the basename of at least one configured source.
  function matchesAnySource(cfg, name) {
    return cfg.sources.some((s) => s.enabled && s.source.trim() && globToRe(basename(s.source.trim())).test(basename(name)));
  }

  // logs: [{ name, text, anySource? }], one per file. terms: search terms; [] keeps every session.
  // trace: optional array; gets one record per event with the decision taken for it.
  function run(cfg, logs, terms, trace) {
    const query = spl.generate(cfg);
    const lineRex = (startsWith) => rx(query.split('\n').find((l) => l.startsWith(startsWith)).match(/"(.*)"$/)[1]);
    const sourceExpr = parseSearch(query.slice(0, query.indexOf('\n)\n') + 2));
    const termExpr = terms.length ? parseSearch(terms.map(spl.quoteTerm).join(' OR ')) : { and: [] };
    const layers = cfg.layers.filter((l) => l.name.trim());
    const dirWordRe = cfg.dirWordRex.trim() ? rx(cfg.dirWordRex) : null;
    const URL_RE = lineRex('| rex field=_raw "\\bURL');
    const DGE_RE = lineRex('| rex field=_raw "\\[:');
    const SVC_RE = /<SvcCode>([^<]+)<\/SvcCode>/g;

    const rows = [];
    for (const ev of logs.flatMap((l) => parseEvents(l.name, l.text, l.anySource))) {
      const rec = trace ? { file: basename(ev.source), lineNo: ev.lineNo, head: ev.lines[0], ev } : null;
      if (rec) trace.push(rec);
      if (!matches(sourceExpr, ev)) { if (rec) rec.reason = 'Excluded: source filter (source="…" and its filter terms)'; continue; }
      if (!matches(termExpr, ev)) { if (rec) rec.reason = 'Excluded: no Search term in the event'; continue; }
      const r = ev.raw;
      const L = layers.find((l) => evalCond(l.match, ev));
      ev.LayerName = L ? L.name : null;
      ev.Layer = L ? Number(L.layer) : null;
      ev.SubLayer = L ? Number(L.subLayer) || 0 : null;
      ev.DirWord = dirWordRe ? extract(dirWordRe, r).DirWord : undefined;
      const first = cfg.directionFirst.trim();
      const cut = topLevelComma(first);
      if (first && cut > 0 && evalCond(first.slice(0, cut), ev)) {
        ev.Direction = evalValue(first.slice(cut + 1).trim(), ev);
      } else {
        const d = cfg.directions.find((x) => ev.LayerName === x.layer && rx(x.pattern).test(r));
        ev.Direction = d ? d.direction : null;
      }
      if (cfg.dropNoDirection && ev.Direction == null) { if (rec) rec.reason = 'Excluded: no Direction (where isnotnull(Direction))'; continue; }
      for (const ep of cfg.endpointRules) if (ep.rex.trim()) Object.assign(ev, extract(rx(ep.rex), r));
      ev.Endpoint = cfg.endpointRules.map((ep) => ev[ep.field]).find((v) => v != null);
      for (const sr of cfg.sessionRules) if (sr.rex.trim()) Object.assign(ev, extract(rx(sr.rex), r));
      ev.sessionId = cfg.sessionRules.map((sr) => ev[sr.field]).find((v) => v != null);
      Object.assign(ev, extract(DGE_RE, r), extract(URL_RE, r));
      ev.SvcCode = [...r.matchAll(SVC_RE)].map((m) => m[1]);
      for (const p of cfg.params) if (p.rex.trim()) Object.assign(ev, extract(rx(p.rex), r));
      if (!(ev.LayerName !== 'Host' || ev.SvcCode.length >= 1)) { if (rec) rec.reason = 'Excluded: Host event without <SvcCode> (where clause)'; continue; }
      if (rec) {
        rec.kept = true;
        rec.warn = [!ev.LayerName && 'no layer matched', !ev.Direction && 'no direction', ev.sessionId == null && 'no sessionId']
          .filter(Boolean).join(', ');
      }
      // SPL string comparison is case-sensitive: "response" is not "Response".
      // Events in the same millisecond: requests go down the layers (eComm 10, Enterprise 20,
      // WS 21, Host 30) and responses come back up (Host -30 ... eComm -10).
      ev.LayerOrder = ev.Layer == null ? null : ev.Layer * 10 + (ev.SubLayer || 0);
      ev.SortKey = ev.LayerOrder == null ? null : (ev.Direction === 'Request' ? ev.LayerOrder : -ev.LayerOrder);
      rows.push(ev);
    }
    rows.sort((a, b) => a.time - b.time || (a.SortKey ?? -Infinity) - (b.SortKey ?? -Infinity));

    const lastWs = {}; const lastReq = {}; const step = {};
    for (const ev of rows) {
      const sid = ev.sessionId ?? '';
      if (ev.LayerName === 'WS' && ev.URL) lastWs[sid] = ev.URL;
      const sv = ev.SvcCode; const pairs = [];
      for (let k = 0; k < Math.ceil(sv.length / 2); k++) pairs.push(`${sv[k * 2]} ~ ${sv[k * 2 + 1] ?? sv[k * 2]}`);
      ev.API = {
        eComm: ev.Endpoint, Enterprise: ev.Endpoint,
        WS: ev.URL || lastWs[sid] || ev.DGEEndpoint || 'N/A',
        Host: ev.DGEEndpoint && ev.DGEEndpoint.replace(/:/g, '.'),
      }[ev.LayerName];
      ev.DirectionSymbol = ev.Direction === 'Request' ? '?' : '!';
      ev.PairKey = ev.LayerName === 'Host' ? (ev.DGEEndpoint || '') : ev.API;
      const key = [sid, ev.Layer, ev.PairKey].join('|');
      if (ev.Direction === 'Response' && lastReq[key] != null) ev.ElapsedMs = Math.round(ev.time - lastReq[key]);
      if (ev.Direction === 'Request') lastReq[key] = ev.time;
      const L = layers.find((l) => l.name === ev.LayerName);
      // A null API makes the whole Flow string null in SPL.
      ev.Flow = ev.API == null || ev.LayerName == null ? null : `${L.indent ?? ''}${ev.LayerName}: ${ev.API} [${ev.DirectionSymbol}]`;
      const svc = ev.LayerName === 'Host' ? pairs.map((p) => `- [${p}] [${ev.DirectionSymbol}]`) : [];
      ev.ServiceInfo = ev.LayerName === 'Host' && svc.length ? [ev.Flow, ...svc].filter((x) => x != null) : ev.Flow;
      ev.Params = cfg.params.filter((p) => ev[p.field] && ev[p.field].trim()).map((p) => `${p.label || p.field}=${ev[p.field]}`);
      if (ev.sessionId != null) ev.Step = step[sid] = (step[sid] || 0) + 1;
      ev.EventTime = new Date(ev.time).toISOString().replace('T', ' ').slice(0, 23);
    }
    return rows;
  }

  // Per session: steps, time span, slowest hop and requests with no later response.
  function summarize(rows) {
    const out = new Map();
    for (const ev of rows) {
      if (ev.sessionId == null) continue;
      let s = out.get(ev.sessionId);
      if (!s) out.set(ev.sessionId, s = { steps: 0, start: ev.time, end: ev.time, slowest: null, pending: new Map() });
      s.steps++;
      s.end = ev.time;
      const key = [ev.Layer, ev.PairKey].join('|');
      if (ev.Direction === 'Request') s.pending.set(key, ev);
      else if (ev.Direction === 'Response') s.pending.delete(key);
      if (ev.ElapsedMs != null && (!s.slowest || ev.ElapsedMs > s.slowest.ElapsedMs)) s.slowest = ev;
    }
    return [...out].map(([sessionId, s]) => ({
      sessionId,
      steps: s.steps,
      start: new Date(s.start).toISOString().replace('T', ' ').slice(0, 23),
      durationMs: Math.round(s.end - s.start),
      slowest: s.slowest && { flow: s.slowest.Flow, ms: s.slowest.ElapsedMs },
      noResponse: [...s.pending.values()].map((ev) => ev.Flow),
    }));
  }

  // ---------- sequence diagram ----------

  // One diagram per session, shared by the PlantUML text and the SVG view.
  // Callers come from a call stack: a request is sent by the participant whose
  // request is still open (App when none), and a response closes the latest open
  // request with the same Layer and PairKey. Requests that never get a response
  // are closed with a note.
  //
  // Returns [{ sessionId, title: [line], participants: [{ id, name, actor }], items }]
  // where items are { t: 'msg', from, to, dashed, lines }, { t: 'act' | 'deact', who }
  // or { t: 'note', who, lines }, and a line is { text, small }.
  function sequenceModel(rows, cfg) {
    const order = cfg.layers.filter((l) => l.name.trim()).map((l, i) => ({ name: l.name.trim(), layer: Number(l.layer), i }))
      .sort((a, b) => a.layer - b.layer || a.i - b.i);
    const alias = (name) => 'P_' + name.replace(/\W/g, '_');
    const sessions = new Map();
    for (const r of rows) {
      if (r.sessionId == null || !r.LayerName) continue;
      if (!sessions.has(r.sessionId)) sessions.set(r.sessionId, []);
      sessions.get(r.sessionId).push(r);
    }

    const diagrams = [];
    for (const [sid, rs] of sessions) {
      const used = new Set(rs.map((r) => r.LayerName));
      const total = Math.round(rs[rs.length - 1].time - rs[0].time);
      const items = [];
      const label = (r, ms) => {
        const lines = [{ text: (r.API ?? 'N/A') + (ms != null ? ` (${ms} ms)` : '') }];
        if (r.LayerName === 'Host' && Array.isArray(r.ServiceInfo)) {
          r.ServiceInfo.slice(1).forEach((s) => lines.push({ text: s.replace(/^- \[(.*)\] \[.\]$/, '$1') }));
        }
        (r.Params || []).forEach((p) => lines.push({ text: p, small: true }));
        return lines;
      };
      const noResponse = (s) => {
        items.push({ t: 'note', who: s.who, lines: [{ text: 'No response' }, { text: s.row.API ?? 'N/A' }] });
        items.push({ t: 'deact', who: s.who });
      };
      // Column order decides who can call whom: a request comes from an open call in an
      // earlier column. With several candidates (overlapping calls), prefer one whose API
      // shares its path with this one (/asv/x -> /dge-asv/asv/x), else the latest.
      const rank = Object.fromEntries(order.map((l, i) => [l.name, i]));
      const rankOf = (name) => rank[name] ?? order.length;
      const norm = (api) => String(api ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '/').replace(/^\/|\/$/g, '');
      const related = (a, b) => a.length > 3 && b.length > 3 && (a.includes(b) || b.includes(a));
      // calls: the call tree behind the diagram, one entry per request (and per orphan row),
      // { layer, api, parent (call or null for App), req, res, orphan: 'response' | 'direction' }.
      const calls = [];
      const stack = [];
      for (const r of rs) {
        const me = alias(r.LayerName);
        const key = r.Layer + '|' + r.PairKey;
        if (r.Direction === 'Request') {
          const open = stack.filter((s) => rankOf(s.row.LayerName) < rankOf(r.LayerName));
          const mine = norm(r.API);
          const pick = [...open].reverse().find((s) => related(mine, norm(s.row.API))) || open[open.length - 1];
          const caller = pick ? pick.who : 'P_App';
          items.push({ t: 'msg', from: caller, to: me, dashed: false, lines: label(r) }, { t: 'act', who: me });
          const call = { layer: r.LayerName, api: r.API, parent: pick ? pick.call : null, req: r, res: null };
          calls.push(call);
          stack.push({ who: me, caller, key, row: r, call });
          continue;
        }
        if (r.Direction !== 'Response') {
          items.push({ t: 'note', who: me, lines: [{ text: 'Direction unknown' }, ...label(r, r.ElapsedMs)] });
          calls.push({ layer: r.LayerName, api: r.API, parent: null, req: null, res: r, orphan: 'direction' });
          continue;
        }
        let idx = -1;
        for (let k = stack.length - 1; k >= 0; k--) if (stack[k].key === key) { idx = k; break; }
        if (idx < 0) {
          items.push({ t: 'note', who: me, lines: [{ text: 'Response without a request' }, ...label(r, r.ElapsedMs)] });
          calls.push({ layer: r.LayerName, api: r.API, parent: null, req: null, res: r, orphan: 'response' });
          continue;
        }
        // Only the matching call closes; calls opened after it may still be running (async work).
        const [s] = stack.splice(idx, 1);
        s.call.res = r;
        items.push({ t: 'msg', from: me, to: s.caller, dashed: true, lines: label(r, r.ElapsedMs) }, { t: 'deact', who: me });
      }
      while (stack.length) noResponse(stack.pop());
      diagrams.push({
        sessionId: sid,
        title: [`Session ${sid}`, `${rs.length} steps, ${total} ms`],
        participants: [{ id: 'P_App', name: 'App', actor: true },
          ...order.filter((l) => used.has(l.name)).map((l) => ({ id: alias(l.name), name: l.name })),
          // Layers not in the settings (possible in an imported result) go after the known ones.
          ...[...used].filter((n) => !order.some((l) => l.name === n)).map((n) => ({ id: alias(n), name: n }))],
        items,
        calls,
      });
    }
    return diagrams;
  }

  // One @startuml block per session.
  function toPlantUml(rows, cfg) {
    // Labels are single-line PlantUML text: lines are joined with a literal \n, so real newlines are dropped.
    const esc = (s) => String(s).replace(/[\r\n]+/g, ' ');
    const text = (lines) => lines.map((l) => (l.small ? `<size:10>${esc(l.text)}</size>` : esc(l.text))).join('\\n');
    const blocks = sequenceModel(rows, cfg).map((d) => {
      const out = [
        '@startuml',
        `title ${d.title.map(esc).join('\\n')}`,
        'skinparam responseMessageBelowArrow true',
        'skinparam sequenceMessageAlign center',
        ...d.participants.map((p) => (p.actor ? `actor ${p.name} as ${p.id}` : `participant "${p.name}" as ${p.id}`)),
        '',
      ];
      for (const it of d.items) {
        if (it.t === 'msg') out.push(`${it.from} ${it.dashed ? '-->' : '->'} ${it.to} : ${text(it.lines)}`);
        else if (it.t === 'act') out.push(`activate ${it.who}`);
        else if (it.t === 'deact') out.push(`deactivate ${it.who}`);
        else out.push(`note over ${it.who} #FFE0B2 : ${text(it.lines)}`);
      }
      out.push('@enduml');
      return out.join('\n');
    });
    return blocks.join('\n\n') + (blocks.length ? '\n' : '');
  }

  // PlantUML server text encoding: raw deflate, then PlantUML's 64-character alphabet.
  const PUML_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_';
  function plantUmlEncode64(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const b1 = bytes[i]; const b2 = bytes[i + 1] ?? 0; const b3 = bytes[i + 2] ?? 0;
      out += PUML_ALPHABET[b1 >> 2] + PUML_ALPHABET[((b1 & 3) << 4) | (b2 >> 4)]
        + PUML_ALPHABET[((b2 & 15) << 2) | (b3 >> 6)] + PUML_ALPHABET[b3 & 63];
    }
    return out;
  }

  // ---------- output ----------

  // Plain-text table; multivalue cells continue on the following lines.
  function format(rows, columns) {
    const cells = rows.map((ev) => columns.map((c) => {
      const v = ev[c];
      return (Array.isArray(v) ? v : [v]).map((x) => (x == null ? '' : String(x)));
    }));
    const width = columns.map((c, i) => Math.max(c.length, ...cells.map((r) => Math.max(...r[i].map((x) => x.length)))));
    const line = (vals) => vals.map((v, i) => v.padEnd(width[i])).join(' | ').trimEnd();
    const out = [line(columns), width.map((w) => '-'.repeat(w)).join('-|-')];
    for (const r of cells) {
      const h = Math.max(...r.map((c) => c.length));
      for (let k = 0; k < h; k++) out.push(line(r.map((c) => c[k] ?? '')));
    }
    return out.join('\n') + '\n';
  }

  return { parseEvents, describeLog, matchesAnySource, run, summarize, sequenceModel, toPlantUml, plantUmlEncode64, format, parseSearch };
});
