// Processing rules observed in the analysed flow: who calls what, in which order,
// what never got a response, and how long each hop takes. Built from the call tree
// of TraceFlow.sequenceModel(), so it agrees with the Sequence view.
//
// Every rule carries its evidence (sessions, occurrences). A rule seen in one session
// only is a single-sample observation, not a confirmed rule.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceRules = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const name = (c) => `${c.layer} ${c.api ?? 'N/A'}`;
  const svcOf = (c) => {
    const info = c.req && Array.isArray(c.req.ServiceInfo) ? c.req.ServiceInfo.slice(1) : [];
    return info.map((s) => s.replace(/^- \[(.*)\] \[.\]$/, '$1'));
  };
  const median = (xs) => {
    const s = [...xs].sort((a, b) => a - b);
    const m = s.length >> 1;
    return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
  };
  const confidence = (sessions) => (sessions >= 2 ? `Observed in ${sessions} sessions` : 'Single-sample observation');

  // Groups items by key; each group counts occurrences and distinct sessions.
  function tally(entries) {
    const map = new Map();
    for (const { key, sid, data } of entries) {
      if (!map.has(key)) map.set(key, { ...data, sessions: new Set(), occurrences: 0 });
      const g = map.get(key);
      g.sessions.add(sid);
      g.occurrences++;
    }
    return [...map.values()].map((g) => ({ ...g, sessions: g.sessions.size, confidence: confidence(g.sessions.size) }))
      .sort((a, b) => b.sessions - a.sessions || b.occurrences - a.occurrences);
  }

  // models: TraceFlow.sequenceModel(rows, cfg) output.
  function analyze(models) {
    // Copies carry the session id; parent links still point at the original call objects.
    const all = models.flatMap((d) => d.calls.map((c) => ({ ...c, orig: c, sid: d.sessionId })));
    const real = all.filter((c) => c.req);
    const childrenOf = (c) => real.filter((x) => x.parent === c.orig);

    // 1. Routing: what each entry call (from App) does next, as an ordered list of direct calls.
    const routing = tally(real.filter((c) => !c.parent).map((c) => {
      const kids = childrenOf(c).map(name);
      return { key: name(c) + ' => ' + kids.join(' | '), sid: c.sid, data: { entry: name(c), calls: kids } };
    }));

    // 2. Call map: every caller -> callee edge, with Host SvcCodes.
    const edges = tally(real.filter((c) => c.parent).map((c) => {
      const svc = svcOf(c);
      return { key: name(c.parent) + ' -> ' + name(c) + ' ' + svc.join(','), sid: c.sid, data: { caller: name(c.parent), callee: name(c), svc } };
    }));

    // 3. Order of calls made by one parent: sequential when each call ends before the next starts.
    const orderMap = new Map();
    for (const c of real) {
      const kids = childrenOf(c);
      if (kids.length < 2) continue;
      const key = name(c);
      if (!orderMap.has(key)) orderMap.set(key, { parent: key, sessions: new Set(), occurrences: 0, pairs: 0, overlapping: 0, examples: [] });
      const g = orderMap.get(key);
      g.sessions.add(c.sid);
      g.occurrences++;
      for (let i = 0; i + 1 < kids.length; i++) {
        g.pairs++;
        const a = kids[i]; const b = kids[i + 1];
        if (!a.res || b.req.time < a.res.time) {
          g.overlapping++;
          if (g.examples.length < 3) g.examples.push(`${name(b)} starts before ${name(a)} ${a.res ? 'returns' : 'gets a response'}`);
        }
      }
    }
    const ordering = [...orderMap.values()].map((g) => ({
      ...g, sessions: g.sessions.size, confidence: confidence(g.sessions.size),
      verdict: !g.overlapping ? 'Sequential' : g.overlapping === g.pairs ? 'Overlapping' : `Mixed (${g.overlapping} of ${g.pairs} overlap)`,
    })).sort((a, b) => b.sessions - a.sessions || b.occurrences - a.occurrences);

    // 4. Gaps: requests without a response (possible timeouts), responses without a request, unknown direction.
    const gaps = tally(all.filter((c) => (c.req && !c.res) || c.orphan).map((c) => {
      const kind = c.orphan === 'response' ? 'Response without a request' : c.orphan === 'direction' ? 'Direction unknown' : 'No response';
      return { key: kind + '|' + name(c), sid: c.sid, data: { kind, call: name(c), caller: c.parent ? name(c.parent) : (c.req ? 'App' : '') } };
    }));

    // 5. Latency per hop: min / median / max ElapsedMs; outliers are > 3x the median and at least 500 ms above it.
    const lat = new Map();
    for (const c of real) {
      const ms = c.res && c.res.ElapsedMs;
      if (ms == null) continue;
      const key = name(c);
      if (!lat.has(key)) lat.set(key, { call: key, layer: c.layer, values: [], sessions: new Set() });
      lat.get(key).values.push(ms);
      lat.get(key).sessions.add(c.sid);
    }
    const latency = [...lat.values()].map((g) => {
      const med = median(g.values);
      return {
        call: g.call, layer: g.layer, n: g.values.length, sessions: g.sessions.size,
        min: Math.min(...g.values), median: med, max: Math.max(...g.values),
        outliers: g.values.filter((v) => v > 3 * med && v - med >= 500),
      };
    }).sort((a, b) => b.max - a.max);

    const svcCodes = new Set(real.flatMap(svcOf).flatMap((p) => p.split(/\s*~\s*/)));
    return {
      sessions: models.length,
      calls: real.length,
      distinctApis: new Set(real.map(name)).size,
      svcCodes: svcCodes.size,
      routing, edges, ordering, gaps, latency,
    };
  }

  // ---------- Markdown ----------

  const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, '<br>');
  const table = (head, rows) => [
    `| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`,
    ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`),
  ].join('\n');

  function toMarkdown(r) {
    const out = ['# Processing rules', '',
      `${r.sessions} sessions, ${r.calls} calls, ${r.distinctApis} distinct APIs, ${r.svcCodes} SvcCodes.`
      + ' A rule seen in one session is a single-sample observation, not a confirmed rule.', ''];
    if (r.sessions < 2) out.push('> Only one session: every rule below is a hypothesis until more sessions confirm it.', '');
    out.push('## Routing (entry calls and what they call)', '',
      table(['Entry call', 'Calls, in order', 'Sessions', 'Occurrences', 'Confidence'],
        r.routing.map((x) => [x.entry, x.calls.length ? x.calls.join('\n') : 'Handled internally (no downstream call)', x.sessions, x.occurrences, x.confidence])), '');
    out.push('## Call map (caller → callee)', '',
      table(['Caller', 'Callee', 'SvcCodes', 'Sessions', 'Occurrences', 'Confidence'],
        r.edges.map((x) => [x.caller, x.callee, x.svc.join('\n'), x.sessions, x.occurrences, x.confidence])), '');
    out.push('## Order of calls', '',
      r.ordering.length ? table(['Caller', 'Order', 'Occurrences', 'Sessions', 'Notes'],
        r.ordering.map((x) => [x.parent, x.verdict, x.occurrences, x.sessions, x.examples.join('\n')])) : 'No call makes more than one downstream call.', '');
    out.push('## Gaps', '',
      r.gaps.length ? table(['Kind', 'Call', 'Called by', 'Sessions', 'Occurrences'],
        r.gaps.map((x) => [x.kind, x.call, x.caller, x.sessions, x.occurrences])) : 'Every request has a response.', '');
    out.push('## Latency baseline (ElapsedMs)', '',
      table(['Call', 'Responses', 'Min', 'Median', 'Max', 'Outliers'],
        r.latency.map((x) => [x.call, x.n, x.min, x.median, x.max, x.outliers.join(', ')])), '');
    out.push('## Not covered yet', '',
      '- Success / failure (HopStatus, SessionStatus, error codes): the flow table has no response codes yet.',
      '- Retries and fallbacks: need response codes to tell a retry from a second business call.', '');
    return out.join('\n');
  }

  return { analyze, toMarkdown };
});
