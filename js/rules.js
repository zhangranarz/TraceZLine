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
    const result = {
      sessions: models.length,
      calls: real.length,
      distinctApis: new Set(real.map(name)).size,
      svcCodes: svcCodes.size,
      routing, edges, ordering, gaps, latency,
    };
    result.apis = describeApis(all, childrenOf, result);
    return result;
  }

  // 6. One row per API, in order of first appearance: { api, description: [sentences] }.
  // The description sums up the rules above for that API.
  function describeApis(all, childrenOf, r) {
    const byApi = new Map();
    for (const c of all) {
      const key = name(c);
      if (!byApi.has(key)) byApi.set(key, { api: key, calls: [], sessions: new Set() });
      byApi.get(key).calls.push(c);
      byApi.get(key).sessions.add(c.sid);
    }
    const list = (xs) => (xs.length > 1 ? xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1] : xs[0] || '');
    const times = (n) => (n === 1 ? 'once' : `${n} times`);
    return [...byApi.values()].map(({ api, calls, sessions }) => {
      const d = [];
      const reqs = calls.filter((c) => c.req);
      const callers = [...new Set(reqs.map((c) => (c.parent ? name(c.parent) : 'App')))];
      if (callers.length) d.push(callers.length === 1 && callers[0] === 'App' ? 'Entry call from the App.' : `Called by ${list(callers)}.`);

      // what it calls: each distinct ordered list of direct calls
      const variants = [...new Set(reqs.map((c) => childrenOf(c).map(name).join(' → ')))];
      if (variants.length === 1 && variants[0]) d.push(`Calls, in order: ${variants[0]}.`);
      else if (variants.length > 1) d.push(`Calls vary: ${variants.map((v) => v || 'nothing').join('; or ')}.`);
      else if (reqs.length) d.push(reqs[0].parent ? 'No downstream call.' : 'Handled internally (no downstream call).');

      const svc = [...new Set(reqs.flatMap(svcOf))];
      if (svc.length) d.push(`SvcCodes (request ~ response): ${svc.join(', ')}.`);

      const order = r.ordering.find((o) => o.parent === api);
      if (order) d.push(order.verdict === 'Sequential' ? 'Its downstream calls run one after another.' : `Its downstream calls overlap: ${order.verdict.toLowerCase()}.`);

      for (const g of r.gaps.filter((x) => x.call === api)) {
        d.push(g.kind === 'No response' ? `No response ${times(g.occurrences)} (possible timeout).`
          : g.kind === 'Response without a request' ? `Response without a request ${times(g.occurrences)}.`
            : `Direction unknown ${times(g.occurrences)}.`);
      }

      const lat = r.latency.find((x) => x.call === api);
      if (lat) {
        d.push(lat.n === 1 ? `Takes ${lat.median} ms.` : `Takes ${lat.median} ms (median; ${lat.min}–${lat.max} ms over ${lat.n} responses).`);
        if (lat.outliers.length) d.push(`Slow outliers: ${lat.outliers.join(', ')} ms.`);
      }

      d.push(sessions.size >= 2 ? `Seen ${times(reqs.length || calls.length)} in ${sessions.size} sessions.`
        : `Seen ${times(reqs.length || calls.length)} in one session (single-sample observation).`);
      return { api, description: d };
    });
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
    out.push(table(['API', 'Description'], r.apis.map((x) => [x.api, x.description.join('\n')])), '');
    return out.join('\n');
  }

  return { analyze, toMarkdown };
});
