// Runs the generated query's logic over local log files, without Splunk.
//
//   node tools/simulate.js [--config tracezline-config.json] [--terms id1,id2 | --all] file...
//
// Files are raw logs (each event starts with "YYYY-MM-DD hh:mm:ss.mmm"); a file's
// name is matched against the basename of each configured source="..." pattern.
// The search, LayerName, Direction, rex and Params steps come from the config;
// the steps after sessionId mirror FLOW_BLOCK in js/spl.js and must be kept in
// step with it. This is an approximation of Splunk for local checks, not a replacement.
'use strict';
const fs = require('fs');
const path = require('path');
const spl = require('../js/spl.js');

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
  if (node.source) return globToRe(path.basename(node.source)).test(path.basename(ev.source));
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

// ---------- input ----------

function readEvents(file) {
  const lines = fs.readFileSync(file, 'utf8').replace(/\r/g, '').split('\n');
  const events = [];
  for (const line of lines) {
    const m = line.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\s/);
    if (m) events.push({ source: file, time: Date.parse(m[1].replace(' ', 'T') + 'Z'), lines: [line] });
    else if (events.length) events[events.length - 1].lines.push(line);
  }
  return events.map((e) => ({ ...e, raw: e.lines.join('\n').trimEnd(), lower: e.lines.join('\n').toLowerCase() }));
}

// ---------- pipeline ----------

function run(cfg, files, terms) {
  const query = spl.generate(cfg);
  const lineRex = (startsWith) => rx(query.split('\n').find((l) => l.startsWith(startsWith)).match(/"(.*)"$/)[1]);
  const sourceExpr = parseSearch(query.slice(0, query.indexOf('\n)\n') + 2));
  const termExpr = terms.length ? parseSearch(terms.map(spl.quoteTerm).join(' OR ')) : { and: [] };
  const layers = cfg.layers.filter((l) => l.name.trim());
  const dirWordRe = cfg.dirWordRex.trim() ? rx(cfg.dirWordRex) : null;
  const URL_RE = lineRex('| rex field=_raw "URL');
  const DGE_RE = lineRex('| rex field=_raw "\\[:');
  const SVC_RE = /<SvcCode>([^<]+)<\/SvcCode>/g;

  const rows = [];
  for (const ev of files.flatMap(readEvents)) {
    if (!matches(sourceExpr, ev) || !matches(termExpr, ev)) continue;
    const r = ev.raw;
    const L = layers.find((l) => evalCond(l.match, ev));
    ev.LayerName = L ? L.name : null;
    ev.Layer = L ? Number(L.layer) : null;
    ev.DirWord = dirWordRe ? extract(dirWordRe, r).DirWord : undefined;
    const first = cfg.directionFirst.trim();
    if (first && evalCond(first.slice(0, first.lastIndexOf(',')), ev)) {
      const v = first.slice(first.lastIndexOf(',') + 1);
      ev.Direction = v.startsWith('"') ? v.slice(1, -1) : ev[v];
    } else {
      const d = cfg.directions.find((x) => ev.LayerName === x.layer && rx(x.pattern).test(r));
      ev.Direction = d ? d.direction : null;
    }
    for (const ep of cfg.endpointRules) if (ep.rex.trim()) Object.assign(ev, extract(rx(ep.rex), r));
    ev.Endpoint = cfg.endpointRules.map((ep) => ev[ep.field]).find((v) => v != null);
    for (const sr of cfg.sessionRules) if (sr.rex.trim()) Object.assign(ev, extract(rx(sr.rex), r));
    ev.sessionId = cfg.sessionRules.map((sr) => ev[sr.field]).find((v) => v != null);
    Object.assign(ev, extract(DGE_RE, r), extract(URL_RE, r));
    ev.SvcCode = [...r.matchAll(SVC_RE)].map((m) => m[1]);
    for (const p of cfg.params) if (p.rex.trim()) Object.assign(ev, extract(rx(p.rex), r));
    if (!(ev.LayerName !== 'Host' || ev.SvcCode.length >= 1)) continue;
    // SPL string comparison is case-sensitive: "response" is not "Response".
    ev.SortKey = ev.Layer == null ? null : (ev.Direction === 'Request' ? ev.Layer : -ev.Layer);
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
    const pairKey = ev.LayerName === 'Host' ? (ev.DGEEndpoint || '') : ev.API;
    const key = [sid, ev.Layer, pairKey].join('|');
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

// ---------- output ----------

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

if (require.main === module) {
  const args = process.argv.slice(2);
  let cfg = spl.DEFAULT_CONFIG; let terms = null; const files = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--config') cfg = { ...spl.DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(args[++i], 'utf8')) };
    else if (args[i] === '--terms') terms = spl.parseTerms(args[++i]);
    else if (args[i] === '--all') terms = [];
    else files.push(args[i]);
  }
  if (!files.length) {
    console.error('usage: node tools/simulate.js [--config file.json] [--terms id1,id2 | --all] file...');
    process.exit(1);
  }
  process.stdout.write(format(run(cfg, files, terms ?? cfg.terms), cfg.columns.filter((c) => c.trim())));
}

module.exports = { run, format, parseSearch };
