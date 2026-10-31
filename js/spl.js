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
    sources: [
      {
        enabled: true,
        source: '/var/log/pods/spl-banking-*log',
        filter: '("[SPLMessage]" OR "[SPLHostMessage]")',
      },
      {
        enabled: true,
        source: '/var/log/pods/spl-ms-*log',
        filter: '("WSAppLog" ("request:" OR "RESPONSE from" OR "Response:")) OR ("<EAI>" "<SvcCode>" ("Request Message" OR "Response Message"))',
      },
    ],
    terms: ['2576dfc8-495a-837a-8a2f291fd003d', '7f269c48-f03a-4fef-bc3007538ec1a2'],
    layers: [
      { name: 'eComm', match: String.raw`match(_raw,"\[SPLMessage\]")`, layer: 1 },
      { name: 'Enterprise', match: String.raw`match(_raw,"\[SPLHostMessage\]")`, layer: 2 },
      { name: 'Host', match: String.raw`match(_raw,"<SvcCode>") AND match(_raw,"(?i)(request|response) message")`, layer: 3 },
      { name: 'WS', match: String.raw`match(_raw,"WSAppLog")`, layer: 2 },
    ],
    // rex that extracts the direction word, and an optional raw first case() pair.
    dirWordRex: String.raw`(?i)\b(?<DirWord>Request|Response)\b`,
    directionFirst: 'LayerName="eComm" OR LayerName="Enterprise",DirWord',
    directions: [
      { layer: 'Host', pattern: '(?i)Request Message', direction: 'Request' },
      { layer: 'Host', pattern: '(?i)Response Message', direction: 'Response' },
      { layer: 'WS', pattern: '(?i)request:', direction: 'Request' },
      { layer: 'WS', pattern: '(?i)(RESPONSE from|Response:)', direction: 'Response' },
    ],
    endpointRules: [
      { field: 'Endpoint1', rex: String.raw`(?<Endpoint1>[^ ]+)\s*\-\s*(?:'?Request|Response)'?\s*\-` },
      { field: 'Endpoint2', rex: String.raw`\s\s\s(?<Endpoint2>[^ ]+)\s\-\s(?:'?Request|Response)'` },
      { field: 'Endpoint3', rex: String.raw`(?i)endpoint\"?\s*[:=]\s*\"?(?<Endpoint3>[^\",]+)` },
    ],
    sessionRules: [
      { field: 'sidEcomm', rex: String.raw`(?i)\[SPLMessage\]\[?(?<sidEcomm>[0-9a-fA-F-]{36})` },
      { field: 'sidEnterprise', rex: String.raw`(?i)\[SPLHostMessage\]\[?(?<sidEnterprise>[0-9a-fA-F-]{36})` },
      { field: 'sidWls', rex: String.raw`(?i)\bWLS:\s*(?<sidWls>[0-9a-fA-F-]{36})` },
      { field: 'sidAny', rex: String.raw`(?<sidAny>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})` },
    ],
    params: [
      { field: 'transactionRef', label: 'TxnRefNo', rex: String.raw`(?i)transactionRef(?:erenceNumber)?\"?\s*[:=]\s*\"?(?<transactionRef>[^\",]+)` },
      { field: 'transactionCode', label: 'TxnCode', rex: String.raw`(?i)transactionCode\"?\s*[:=]\s*\"?(?<transactionCode>[^\",]+)` },
    ],
    columns: ['Step', 'EventTime', 'sessionId', 'ServiceInfo', 'Params', 'ElapsedMs'],
  };

  const FLOW_BLOCK = String.raw`| rex field=_raw "\[:(?<DGEEndpoint>[^]]+)\]"
| rex field=_raw "URL\s*=\s*is\s*\:\s*(?<URL>\S+)"
| rex field=_raw max_match=0 "<SvcCode>(?<SvcCode>[^<]+)</SvcCode>"
| where LayerName!="Host" OR mvcount(SvcCode)>=1
| eval SortKey=if(Direction="Request",Layer,-Layer)
| sort 0 _time SortKey
| eval WsURL=if(LayerName="WS",URL,null())
| streamstats last(WsURL) as LastWsURL by sessionId
| eval pairIndex=mvrange(0,ceil(mvcount(SvcCode)/2))
| eval HostPairs=mvmap(pairIndex, mvindex(SvcCode,pairIndex*2) . " ~ ".coalesce(mvindex(SvcCode,pairIndex*2+1),mvindex(SvcCode,pairIndex*2)))
| eval API=case(LayerName="eComm",Endpoint,LayerName="Enterprise",Endpoint,LayerName="WS",
    coalesce(URL,LastWsURL,DGEEndpoint,"N/A"),LayerName="Host",DGEEndpoint)
| eval DirectionSymbol=if(Direction="Request",">","<")
| eval ServiceInfo=if(LayerName="Host", mvmap(HostPairs,"- [".HostPairs."] [".DirectionSymbol."]"),null())
| eval PairKey=case(LayerName="Host",coalesce(DGEEndpoint,""),true(),API)
| eval ReqTime=if(Direction="Request",_time,null())
| streamstats last(ReqTime) as LastReqTime by sessionId Layer PairKey
| eval ElapsedMs=if(Direction="Response" AND isnotnull(LastReqTime),round((_time-LastReqTime)*1000,0),null())
| eval Indent=case(Layer=1,"",Layer=2,"-->",Layer=3,"------>")
| eval Flow=Indent.LayerName.": ".API." [".DirectionSymbol."]"
| eval ServiceInfo=if(LayerName="Host" AND isnotnull(ServiceInfo), mvappend(Flow,ServiceInfo), Flow)`;

  const TAIL_BLOCK = String.raw`| streamstats count as Step by sessionId
| eval EventTime=strftime(_time,"%Y-%m-%d %H:%M:%S.%3N")`;

  function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function quoteTerm(term) {
    return '"' + term.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }

  // Splits a pasted block of search terms on newlines and commas.
  function parseTerms(text) {
    return text.split(/[\r\n,]+/).map((t) => t.trim()).filter(Boolean);
  }

  function generate(cfg) {
    const out = [];

    const sources = cfg.sources.filter((s) => s.enabled && s.source.trim());
    // Everything inside the outer ( ) is tab-indented; grouped sources get one more tab.
    const indent = cfg.groupSources ? '\t\t' : '\t';
    const blocks = sources.map((s) => {
      const body = [`${indent}source="${s.source.trim()}"`];
      if (s.filter.trim()) body.push(indent + s.filter.trim());
      return cfg.groupSources ? ['\t(', ...body, '\t)'].join('\n') : body.join('\n');
    });
    out.push('(\n' + blocks.join('\n\tOR\n') + '\n)');

    const terms = cfg.terms.map((t) => t.trim()).filter(Boolean);
    if (terms.length) out.push('| ' + terms.map(quoteTerm).join(' OR '));

    const layers = cfg.layers.filter((l) => l.name.trim());
    // Two conditions per line; Layer=case() is listed by layer number (stable for equal numbers).
    const nameCases = layers.map((l) => `${l.match.trim()},"${l.name.trim()}"`);
    const nameLines = [];
    for (let i = 0; i < nameCases.length; i += 2) nameLines.push(nameCases.slice(i, i + 2).join(','));
    out.push('| eval LayerName=case(' + nameLines.join(',\n    ') + ')');
    const byNumber = layers.slice().sort((a, b) => Number(a.layer) - Number(b.layer));
    out.push('| eval Layer=case('
      + byNumber.map((l) => `LayerName="${l.name.trim()}",${l.layer}`).join(',')
      + ')');

    if (cfg.dirWordRex.trim()) out.push(`| rex field=_raw "${cfg.dirWordRex.trim()}"`);
    const dirCases = cfg.directions.filter((d) => d.layer.trim() && d.pattern.trim())
      .map((d) => `LayerName="${d.layer.trim()}" AND match(_raw,"${d.pattern.trim()}"),"${d.direction}"`);
    if (cfg.directionFirst.trim()) dirCases.unshift(cfg.directionFirst.trim());
    out.push('| eval Direction=case(' + dirCases.join(',\n    ') + ')');

    const eps = cfg.endpointRules.filter((r) => r.field.trim());
    eps.filter((r) => r.rex.trim()).forEach((r) => out.push(`| rex field=_raw "${r.rex.trim()}"`));
    out.push('| eval Endpoint=coalesce(' + eps.map((r) => r.field.trim()).join(',') + ')');

    const sids = cfg.sessionRules.filter((r) => r.field.trim());
    sids.filter((r) => r.rex.trim()).forEach((r) => out.push(`| rex field=_raw "${r.rex.trim()}"`));
    out.push('| eval sessionId=coalesce(' + sids.map((r) => r.field.trim()).join(', ') + ')');

    out.push(FLOW_BLOCK);

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
    if (!layerNames.size) warnings.push('No layers defined: LayerName=case() is empty and Splunk will reject it.');
    cfg.layers.forEach((l) => {
      if (l.name.trim() && !l.match.trim()) warnings.push(`Layer "${l.name}" has no match condition.`);
      if (l.name.trim() && !Number.isFinite(Number(l.layer))) warnings.push(`Layer "${l.name}" needs a numeric layer number.`);
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
    if (!cfg.sessionRules.some((r) => r.field.trim())) warnings.push('No sessionId rules: coalesce() is empty.');
    if (!cfg.endpointRules.some((r) => r.field.trim())) warnings.push('No Endpoint rules: Endpoint=coalesce() is empty.');
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

  return { DEFAULT_CONFIG, clone, generate, validate, parseTerms, quoteTerm };
});
