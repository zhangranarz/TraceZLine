// SPL generator: builds the base flow query from a config object.
// The query structure is fixed; only the values in the config are variable.
// Regex and match() text is inserted exactly as typed (already SPL-escaped).
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceSpl = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const DEFAULT_CONFIG = {
    version: 1,
    // true: each source in its own ( ) inside the outer ( ); false: sources only share the outer ( ).
    groupSources: true,
    // true: | where isnotnull(Direction) drops events no direction rule matched; they would
    // otherwise read as responses ([!]) further down.
    dropNoDirection: true,
    // One source block per layer marker: eComm, Enterprise, WS, Host.
    // filter: the key condition (which layer); dirFilter: the direction condition (request or
    // response). Each is a line of its own in the source block.
    sources: [
      { enabled: true, source: '/var/log/pods/spl-banking-*log', filter: '"[SPLMessage]"', dirFilter: '("- Request -" OR "- Response -")' },
      { enabled: true, source: '/var/log/pods/spl-banking-*log', filter: '"[SPLHostMessage]"', dirFilter: '("[Request]" OR "[Response]")' },
      { enabled: true, source: '/var/log/pods/spl-ms-*log', filter: '("*WSAppLog*" OR "*UFWApsect*" OR "*UFWAspect*")', dirFilter: '("request:" OR "RESPONSE from" OR "Response:")' },
      { enabled: true, source: '/var/log/pods/spl-ms-*log', filter: '"<EAI>" "<SvcCode>"', dirFilter: '("Request Message" OR "Response Message")' },
    ],
    terms: ['2576dfc8-495a-837a-8a2f291fd003d', '7f269c48-f03a-4fef-bc3007538ec1a2'],
    // Optional time window, "2026-11-18 15:28:25.554" (milliseconds optional); empty = no limit.
    startTime: '',
    endTime: '',
    layers: [
      { name: 'eComm', match: String.raw`match(_raw,"\[SPLMessage\]")`, layer: 1, indent: '', subLayer: 0 },
      { name: 'Enterprise', match: String.raw`match(_raw,"\[SPLHostMessage\]")`, layer: 2, indent: '> ', subLayer: 0 },
      { name: 'Host', match: String.raw`match(_raw,"<EAI>") AND match(_raw,"<SvcCode>")`, layer: 3, indent: '>>> ', subLayer: 0 },
      { name: 'WS', match: String.raw`match(_raw,"(?i)WSAppLog|UFWApsect|UFWAspect")`, layer: 2, indent: '>> ', subLayer: 1 },
    ],
    // rex that extracts the direction word, and an optional raw first case() pair.
    // Optional: a DirWord rex and a first raw case() rule. Not used by default.
    dirWordRex: '',
    directionFirst: '',
    // One Request / Response rule per layer, the same text as that layer's source filter.
    directions: [
      { layer: 'eComm', pattern: '(?i)- Request -', direction: 'Request' },
      { layer: 'eComm', pattern: '(?i)- Response -', direction: 'Response' },
      { layer: 'Enterprise', pattern: String.raw`(?i)\[Request\]`, direction: 'Request' },
      { layer: 'Enterprise', pattern: String.raw`(?i)\[Response\]`, direction: 'Response' },
      { layer: 'Host', pattern: '(?i)Request Message', direction: 'Request' },
      { layer: 'Host', pattern: '(?i)Response Message', direction: 'Response' },
      { layer: 'WS', pattern: '(?i)request:', direction: 'Request' },
      { layer: 'WS', pattern: '(?i)(RESPONSE from|Response:)', direction: 'Response' },
    ],
    endpointRules: [
      // eComm: -/path - Request-, -/path - Response-, or -/path - then the payload
      // (eComm responses log no direction word).
      { field: 'eCommEndpoint', layer: 'eComm', rex: String.raw`\s*-\s*(?<eCommEndpoint>/\S+)\s*-\s*(?:Request|Response|\{|\r?\n|$)` },
      // Enterprise: " -/path", " - /path" or " /path" before [Request] / [Response]
      { field: 'EnterpriseEndpoint', layer: 'Enterprise', rex: String.raw`(?:\s+-|\s+)(?<EnterpriseEndpoint>/\S+)\s*-\s*\[(?:Request|Response)\]` },
    ],
    // sessionId = the first of these that is found, else "NA". The marker in sidEcomm and
    // sidEnterprise follows the source filter (renaming a marker there renames it here).
    sessionRules: [
      { field: 'sidSessionId', rex: String.raw`\"sessionId\"\s*:\s*\"(?<sidSessionId>[^\"]+)\"` },
      { field: 'sidSessionIdentity', rex: String.raw`\"sessionIdentity\"\s*:\s*\"(?<sidSessionIdentity>[^\"]+)\"` },
      { field: 'sidEcomm', rex: String.raw`(?i)\[SPLMessage\]\[(?<sidEcomm>[^\]]+)\]` },
      { field: 'sidEnterprise', rex: String.raw`(?i)\[SPLHostMessage\]\[(?<sidEnterprise>[^\]]+)\]` },
      { field: 'sidWls', rex: String.raw`(?i)\bWLS:\s*(?<sidWls>[^\s|]+)` },
    ],
    params: [
      { field: 'transactionRef', label: 'TxnRefNo', rex: String.raw`(?i)\btransactionRef(?:erenceNumber)?\"?\s*[:=]\s*\"?(?<transactionRef>[^\",]+)` },
      { field: 'transactionCode', label: 'TxnCode', rex: String.raw`(?i)\btransactionCode\"?\s*[:=]\s*\"?(?<transactionCode>[^\",]+)` },
    ],
    columns: ['Step', 'EventTime', 'sessionId', 'ServiceInfo', 'Params', 'ElapsedMs'],
  };

  const FLOW_BLOCK = String.raw`| rex field=_raw "\[::(?<DGEEndpoint>[^]]+)\]"
| rex field=_raw "\bURL(?:\s+is\s+|\s*:\s*)(?<URL>/[^\s:|]+)"
__ENDPOINT__
| rex field=_raw max_match=0 "<SvcCode>(?<SvcCode>[^<]+)</SvcCode>"
| where LayerName!="Host" OR mvcount(SvcCode)>=1
| sort 0 _time SortKey
| eval CurrentWsURL=if(LayerName="WS",URL,null())
| eval CurrentDGEEndpoint=if(LayerName="WS",DGEEndpoint,null())
| streamstats last(CurrentWsURL) as LastWsURL last(CurrentDGEEndpoint) as LastDGEEndpoint by sessionId
| eval pairIndex=if(LayerName="Host",mvrange(0,ceil(mvcount(SvcCode)/2)),null())
| eval HostPairs=if(LayerName="Host",mvmap(pairIndex, mvindex(SvcCode,pairIndex*2) . " ~ ".coalesce(mvindex(SvcCode,pairIndex*2+1),mvindex(SvcCode,pairIndex*2))),null())
| eval API=case(LayerName="eComm",coalesce(Endpoint,"N/A"),
    LayerName="Enterprise",coalesce(Endpoint,"N/A"),
    LayerName="WS",coalesce(URL,LastWsURL,DGEEndpoint,LastDGEEndpoint,"N/A"),
    LayerName="Host",Endpoint)
| eval PairKey=case(LayerName="Host",LayerName."|".Endpoint,true(),LayerName."|".coalesce(API,"N/A"))
| eval ReqTime=if(Direction="Request",_time,null())
| streamstats last(ReqTime) as LastReqTime by sessionId LayerName PairKey
| eval ElapsedMs=if(Direction="Response" AND isnotnull(LastReqTime),round((_time-LastReqTime)*1000,0),null())
__INDENT__
| eval DisplayLayer=if(LayerName="WS","WS [Enterprise]",LayerName)
| eval FlowHead=Indent.DisplayLayer.": ".if(LayerName="WS",mvindex(Endpoint,0),coalesce(API,"N/A"))." [".DirectionSymbol."]"
| eval ServiceLines=if(LayerName="Host",mvmap(HostPairs,"- [".HostPairs."] [".DirectionSymbol."]"),null())
| eval WsDetails=if(LayerName="WS",mvindex(Endpoint,1),null())
| eval Flow=case(LayerName="Host" AND isnotnull(ServiceLines),mvappend(FlowHead,ServiceLines),
    LayerName="WS" AND isnotnull(WsDetails),mvappend(FlowHead,WsDetails),
    true(),FlowHead)
| eval ServiceInfo=Flow`;

  const TAIL_BLOCK = String.raw`| streamstats count as Step by sessionId
| eval EventTime=strftime(_time,"%Y-%m-%d %H:%M:%S.%3N")`;

  function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function quoteTerm(term) {
    return '"' + term.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }

  // "2026-11-18 15:28:25.554" (milliseconds optional) -> ms since 1970 as UTC wall clock, the
  // same clock as the parsed log times; null when empty or not in that format.
  const TIME_RE = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?$/;
  function parseTime(s) {
    const m = String(s ?? '').trim().match(TIME_RE);
    if (!m) return null;
    const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], +(m[7] || '0').padEnd(3, '0'));
    return new Date(t).getUTCDate() === +m[3] ? t : null; // rejects 2026-02-30
  }
  // { from, to } in ms (either may be null), or null when neither is set.
  function timeRange(cfg) {
    const from = parseTime(cfg.startTime);
    const to = parseTime(cfg.endTime);
    return from == null && to == null ? null : { from, to };
  }

  // Splits a pasted block of search terms on newlines and commas.
  function parseTerms(text) {
    return text.split(/[\r\n,]+/).map((t) => t.trim()).filter(Boolean);
  }

  // A filter with OR at its top level is wrapped in ( ), so the OR stays inside it:
  // a OR b -> (a OR b). Text in quotes is ignored; an already wrapped filter is kept.
  function wrapFilter(filter) {
    let depth = 0;
    let quoted = false;
    let topOr = false;
    let wrapped = filter.startsWith('(');
    for (let i = 0; i < filter.length; i++) {
      const c = filter[i];
      if (quoted) {
        if (c === '\\') i++;
        else if (c === '"') quoted = false;
        continue;
      }
      if (c === '"') quoted = true;
      else if (c === '(') depth++;
      else if (c === ')') {
        depth--;
        if (depth === 0 && i < filter.length - 1) wrapped = false; // the first group closes early
      } else if (depth === 0 && /^\sOR\s/.test(filter.slice(i, i + 4))) topOr = true;
    }
    return topOr && !wrapped ? `(${filter})` : filter;
  }

  function generate(cfg) {
    const out = [];

    const sources = cfg.sources.filter((s) => s.enabled && s.source.trim());
    // Everything inside the outer ( ) is tab-indented; grouped sources get one more tab.
    const indent = cfg.groupSources ? '\t\t' : '\t';
    const blocks = sources.map((s) => {
      const body = [`${indent}source="${s.source.trim()}"`];
      if (s.filter.trim()) body.push(indent + wrapFilter(s.filter.trim()));
      if (String(s.dirFilter ?? '').trim()) body.push(indent + wrapFilter(s.dirFilter.trim()));
      return cfg.groupSources ? ['\t(', ...body, '\t)'].join('\n') : body.join('\n');
    });
    out.push('(\n' + blocks.join('\n\tOR\n') + '\n)');

    const terms = cfg.terms.map((t) => t.trim()).filter(Boolean);
    // part of the base search, so no |; two or more terms are grouped: ("a" OR "b")
    if (terms.length) out.push(terms.length > 1 ? '(' + terms.map(quoteTerm).join(' OR ') + ')' : quoteTerm(terms[0]));

    // Time window: earliest/latest (whole seconds, Splunk's MM/DD/YYYY:HH:MM:SS) let Splunk skip
    // the rest of the index; the where clause then keeps the exact milliseconds.
    const range = timeRange(cfg);
    if (range) {
      const pad = (n, w = 2) => String(n).padStart(w, '0');
      const d = (t) => new Date(t);
      const splunk = (t) => `${pad(d(t).getUTCMonth() + 1)}/${pad(d(t).getUTCDate())}/${d(t).getUTCFullYear()}:${pad(d(t).getUTCHours())}:${pad(d(t).getUTCMinutes())}:${pad(d(t).getUTCSeconds())}`;
      const exact = (t) => d(t).toISOString().replace('T', ' ').slice(0, 23);
      const mods = [];
      if (range.from != null) mods.push(`earliest="${splunk(Math.floor(range.from / 1000) * 1000)}"`);
      if (range.to != null) mods.push(`latest="${splunk(Math.floor(range.to / 1000) * 1000 + 1000)}"`);
      out.push(mods.join(' '));
      const conds = [];
      if (range.from != null) conds.push(`_time>=strptime("${exact(range.from)}","%Y-%m-%d %H:%M:%S.%3N")`);
      if (range.to != null) conds.push(`_time<=strptime("${exact(range.to)}","%Y-%m-%d %H:%M:%S.%3N")`);
      out.push('| where ' + conds.join(' AND '));
    }

    const layers = cfg.layers.filter((l) => l.name.trim());
    // One condition per line; events no layer condition matches are dropped. Layer=case() is
    // listed by layer number (stable for equal numbers).
    out.push('| eval LayerName=case(' + layers.map((l) => `${l.match.trim()},"${l.name.trim()}"`).join(',\n    ') + ')');
    out.push('| where isnotnull(LayerName)');
    const byNumber = layers.slice().sort((a, b) => Number(a.layer) - Number(b.layer));
    out.push('| eval Layer=case(' + byNumber.map((l) => `LayerName="${l.name.trim()}",${l.layer}`).join(',\n    ') + ')');
    // SubLayer marks processing inside a layer: WS is layer 2 like Enterprise, with SubLayer 1
    // because it runs inside Enterprise. A layer without a sub-layer number counts as 0, so
    // one such layer reads if(LayerName="WS",1,0).
    const subs = byNumber.filter((l) => Number(l.subLayer));
    out.push('| eval SubLayer=' + (!subs.length ? '0'
      : subs.length === 1 ? `if(LayerName="${subs[0].name.trim()}",${Number(subs[0].subLayer)},0)`
        : 'case(' + subs.map((l) => `LayerName="${l.name.trim()}",${Number(l.subLayer)}`).join(',') + ',true(),0)'));
    out.push('| eval LayerOrder=Layer*10+SubLayer');

    if (cfg.dirWordRex.trim()) out.push(`| rex field=_raw "${cfg.dirWordRex.trim()}"`);
    const dirCases = cfg.directions.filter((d) => d.layer.trim() && d.pattern.trim())
      .map((d) => `LayerName="${d.layer.trim()}" AND match(_raw,"${d.pattern.trim()}"),"${d.direction}"`);
    if (cfg.directionFirst.trim()) dirCases.unshift(cfg.directionFirst.trim());
    out.push('| eval Direction=case(' + dirCases.join(',\n    ') + ')');
    if (cfg.dropNoDirection) out.push('| where isnotnull(Direction)');
    out.push('| eval DirectionSymbol=if(Direction="Request","?","!")');
    // Order within one millisecond: requests down the layers, responses back up. The sort itself
    // stays later, just before the first streamstats (after the where clauses, so less to sort).
    out.push('| eval SortKey=if(Direction="Request",LayerOrder,-LayerOrder)');

    // Endpoint rules: their rex lines go with the DGEEndpoint and URL rex, just above Endpoint=case().
    // Endpoint=case() per layer: each rule's field for its layer, else N/A (several rules for one
    // layer: the first found), then WS = URL and service endpoint on separate lines, Host = service endpoint.
    const eps = cfg.endpointRules.filter((r) => r.field.trim());
    const endpointRex = eps.filter((r) => r.rex.trim()).map((r) => `| rex field=_raw "${r.rex.trim()}"`);
    const byLayer = new Map();
    eps.filter((r) => String(r.layer ?? '').trim()).forEach((r) => {
      const k = r.layer.trim();
      if (!byLayer.has(k)) byLayer.set(k, []);
      byLayer.get(k).push(r.field.trim());
    });
    const endpointCases = [...byLayer].map(([layer, f]) => `LayerName="${layer}",coalesce(${f.join(',')},"N/A")`)
      .concat(['LayerName="WS",mvappend(coalesce(URL,"NA"),coalesce(DGEEndpoint,"NA"))', 'LayerName="Host",coalesce(DGEEndpoint,"NA")']);
    const endpointLine = '| eval Endpoint=case(' + endpointCases.join(',\n    ') + ')';

    const sids = cfg.sessionRules.filter((r) => r.field.trim());
    sids.filter((r) => r.rex.trim()).forEach((r) => out.push(`| rex field=_raw "${r.rex.trim()}"`));
    out.push('| eval sessionId=coalesce(' + sids.map((r) => r.field.trim()).concat('"NA"').join(', ') + ')');

    // Indent is per layer name: layers can share a number (Enterprise and WS are both 2).
    const indentLine = '| eval Indent=case('
      + layers.map((l) => `LayerName="${l.name.trim()}","${l.indent ?? ''}"`).join(',') + ')';
    out.push(...endpointRex);
    out.push(FLOW_BLOCK.replace('__ENDPOINT__', endpointLine).replace('__INDENT__', indentLine));

    const params = cfg.params.filter((p) => p.field.trim());
    params.filter((p) => p.rex.trim()).forEach((p) => out.push(`| rex field=_raw "${p.rex.trim()}"`));
    if (params.length) {
      out.push('| eval Params=mvappend(\n    ' + params.map((p) => {
        const f = p.field.trim();
        const label = (p.label || f).trim();
        return `if(isnotnull(${f}) AND len(trim(${f}))>0,"${label}=".${f}, null())`;
      }).join(',\n    ') + '\n)');
    } else {
      out.push('| eval Params=null()');
    }

    out.push(TAIL_BLOCK);
    out.push('| table ' + cfg.columns.map((c) => c.trim()).filter(Boolean).join(' '));

    return out.join('\n') + '\n';
  }

  // Non-fatal problems worth showing next to the preview.
  function validate(cfg) {
    const warnings = [];
    const layerNames = new Set(cfg.layers.map((l) => l.name.trim()).filter(Boolean));
    const activeSources = cfg.sources.filter((s) => s.enabled && s.source.trim());
    if (!activeSources.length) warnings.push('No enabled source: the search has no base filter.');
    if (!cfg.groupSources && activeSources.length > 1 && activeSources.some((s) => s.filter.trim())) {
      warnings.push('Sources are not grouped. Splunk evaluates OR before the implicit AND, so '
        + 'source="A" filterA OR source="B" filterB reads as source="A" AND (filterA OR source="B") AND filterB. '
        + 'Tick "Group each source" if events from the second source are missing.');
    }
    if (!cfg.terms.some((t) => t.trim())) warnings.push('No search terms: the query will scan every event from the sources.');
    [['Start time', cfg.startTime], ['End time', cfg.endTime]].forEach(([label, v]) => {
      if (String(v ?? '').trim() && parseTime(v) == null) warnings.push(`${label} "${v}" is not a time like 2026-11-18 15:28:25.554; it is ignored.`);
    });
    const range = timeRange(cfg);
    if (range && range.from != null && range.to != null && range.from >= range.to) warnings.push('Start time must be earlier than End time: nothing can match.');
    if (!layerNames.size) warnings.push('No layers defined: LayerName=case() is empty and Splunk will reject it.');
    cfg.layers.forEach((l) => {
      if (l.name.trim() && !l.match.trim()) warnings.push(`Layer "${l.name}" has no match condition.`);
      if (l.name.trim() && !Number.isFinite(Number(l.layer))) warnings.push(`Layer "${l.name}" needs a numeric layer number.`);
      if (l.name.trim() && l.subLayer != null && l.subLayer !== '' && !Number.isFinite(Number(l.subLayer))) warnings.push(`Layer "${l.name}" needs a numeric sub-layer number.`);
    });
    cfg.directions.forEach((d) => {
      if (d.layer.trim() && !layerNames.has(d.layer.trim())) warnings.push(`Direction rule refers to unknown layer "${d.layer}".`);
    });
    if (!cfg.directionFirst.trim() && !cfg.directions.some((d) => d.layer.trim() && d.pattern.trim())) warnings.push('No direction rules: Direction=case() is empty.');
    if (/\bDirWord\b/.test(cfg.directionFirst) && !cfg.dirWordRex.includes('(?<DirWord>')) {
      warnings.push('The first direction rule uses DirWord, but the DirWord rex has no (?<DirWord>...) named group, '
        + 'so DirWord is always null and Direction is empty for those events. Did you mean (?i)\\b(?<DirWord>Request|Response)\\b ?');
    }
    // case() stops at the first true pair, so a Layer<=N first rule hides later rules for layers it covers.
    const firstLayer = cfg.directionFirst.match(/^\s*Layer\s*(<=|<|=)\s*(\d+)\s*,/);
    if (firstLayer) {
      const [, op, n] = firstLayer;
      const covered = (num) => (op === '<=' ? num <= n : op === '<' ? num < n : num === Number(n));
      const shadowed = [...new Set(cfg.directions
        .filter((d) => cfg.layers.some((l) => l.name.trim() === d.layer.trim() && covered(Number(l.layer))))
        .map((d) => d.layer.trim()))];
      if (shadowed.length) {
        warnings.push(`The first direction rule (Layer${op}${n}) also matches ${shadowed.join(', ')}, `
          + `so the ${shadowed.join(', ')} direction rules below it are never used.`);
      }
    }
    if (!cfg.sessionRules.some((r) => r.field.trim())) warnings.push('No Session Rule: sessionId is always NA.');
    if (!cfg.endpointRules.some((r) => r.field.trim())) warnings.push('No Endpoint rules: the eComm and Enterprise API will be N/A.');
    cfg.endpointRules.forEach((r) => {
      if (!r.field.trim()) return;
      const layer = String(r.layer ?? '').trim();
      if (!layer) warnings.push(`Endpoint rule "${r.field}" has no layer: it is not used for Endpoint.`);
      else if (!layerNames.has(layer)) warnings.push(`Endpoint rule "${r.field}" refers to unknown layer "${layer}".`);
    });
    // Splunk rejects a rex with no named group ("does not extract anything"), which fails the whole search.
    generate(cfg).split('\n').filter((l) => /^\| rex /.test(l) && !l.includes('(?<')).forEach((l) => {
      warnings.push('Splunk will reject this rex because it has no (?<name>...) group: ' + l);
    });
    const fields = [...cfg.endpointRules, ...cfg.sessionRules, ...cfg.params].map((r) => r.field.trim()).filter(Boolean);
    const dup = fields.filter((f, i) => fields.indexOf(f) !== i);
    if (dup.length) warnings.push('Duplicate field name(s): ' + [...new Set(dup)].join(', '));
    cfg.endpointRules.concat(cfg.sessionRules, cfg.params).forEach((r) => {
      const f = r.field.trim();
      if (f && r.rex.trim() && !r.rex.includes(`(?<${f}>`)) warnings.push(`rex for "${f}" has no named group (?<${f}>...).`);
    });
    if (!cfg.columns.some((c) => c.trim())) warnings.push('No output columns selected.');
    return warnings;
  }

  // A source filter edited from oldFilter to newFilter: when exactly one quoted term changed
  // ("[SPLMessage]" -> "[MightyMesage]"), the same marker is renamed where the layer logic
  // uses it: layer conditions, session, endpoint and direction rules. * wildcards are left
  // out ("*WSAppLog*" is WSAppLog in match(_raw,"WSAppLog")); regex forms are matched escaped
  // (\[SPLMessage\]). Changes cfg; returns what changed, e.g. ['Layer eComm', 'Session rule sidEcomm'].
  function renameMarker(cfg, oldFilter, newFilter) {
    const terms = (f) => [...new Set([...String(f ?? '').matchAll(/"((?:\\.|[^"\\])*)"/g)].map((m) => m[1]))];
    const before = terms(oldFilter);
    const after = terms(newFilter);
    const removed = before.filter((t) => !after.includes(t));
    const added = after.filter((t) => !before.includes(t));
    if (removed.length !== 1 || added.length !== 1) return [];
    const core = (t) => t.replace(/^\*+|\*+$/g, '');
    const from = core(removed[0]);
    const to = core(added[0]);
    if (!from || !to || from === to) return [];
    const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rename = (s) => s.split(esc(from)).join(esc(to)).split(from).join(to);
    const changed = [];
    const fix = (list, key, label) => list.forEach((item) => {
      if (typeof item[key] !== 'string') return;
      const next = rename(item[key]);
      if (next !== item[key]) { item[key] = next; changed.push(label(item)); }
    });
    fix(cfg.layers, 'match', (l) => `Layer ${l.name}`);
    fix(cfg.sessionRules, 'rex', (r) => `Session rule ${r.field}`);
    fix(cfg.endpointRules, 'rex', (r) => `Endpoint rule ${r.field}`);
    fix(cfg.directions, 'pattern', (d) => `Direction rule ${d.layer}`);
    return changed;
  }

  return { DEFAULT_CONFIG, clone, generate, validate, parseTerms, quoteTerm, renameMarker, parseTime, timeRange };
});
