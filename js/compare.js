// Aligns a Splunk flow result (Excel/CSV rows from TraceImport) with the raw log events
// (rows from TraceFlow.run) and reports data-quality problems between the two.
//
// Matching, in order:
//   1. by order: the n-th Excel row with a given sessionId + layer + direction + API pairs
//      with the n-th log event with the same key;
//   2. nearest time: an unmatched Excel row pairs with the closest unmatched log event of
//      the same sessionId + layer + direction within the tolerance (the API differs).
// Splunk's EventTime and the log's own timestamp can differ by a time-zone offset; the
// median difference of the by-order pairs is taken as that offset and removed before
// times are compared.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceCompare = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const key = (r) => [r.sessionId ?? '', r.LayerName ?? '', r.Direction ?? '', String(r.API ?? '').trim()].join('|');
  const hop = (r) => `${r.LayerName ?? '?'} ${r.API ?? 'N/A'}`;
  const median = (xs) => {
    if (!xs.length) return 0;
    const s = [...xs].sort((a, b) => a - b);
    const m = s.length >> 1;
    return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
  };

  // "+1h 0m 0.001s" style text for an offset in ms.
  function formatOffset(ms) {
    const sign = ms < 0 ? '-' : '+';
    let a = Math.abs(ms);
    const h = Math.floor(a / 3600000); a -= h * 3600000;
    const m = Math.floor(a / 60000); a -= m * 60000;
    return `${sign}${h}h ${m}m ${(a / 1000).toFixed(3)}s`;
  }

  // excel: rows from TraceImport.toFlowRows; log: rows from TraceFlow.run (time order).
  function compare(excel, log, { toleranceMs = 1000 } = {}) {
    const used = new Set();
    const pool = new Map();
    for (const l of log) {
      const k = key(l);
      if (!pool.has(k)) pool.set(k, []);
      pool.get(k).push(l);
    }

    // 1. by order
    const pairs = excel.map((x) => {
      const l = (pool.get(key(x)) || []).find((c) => !used.has(c));
      if (l) used.add(l);
      return { x, l: l || null, kind: l ? 'by order' : 'none', issues: [] };
    });

    const timed = pairs.filter((p) => p.l && Number.isFinite(p.x.time) && Number.isFinite(p.l.time));
    const offsetMs = median(timed.map((p) => p.x.time - p.l.time));

    // 2. nearest time for what is left
    for (const p of pairs.filter((q) => !q.l && Number.isFinite(q.x.time))) {
      let best = null; let bestGap = Infinity;
      for (const l of log) {
        if (used.has(l) || l.sessionId !== p.x.sessionId || l.LayerName !== p.x.LayerName || l.Direction !== p.x.Direction) continue;
        const gap = Math.abs(p.x.time - offsetMs - l.time);
        if (gap <= toleranceMs && gap < bestGap) { best = l; bestGap = gap; }
      }
      if (best) {
        used.add(best);
        p.l = best;
        p.kind = 'nearest time';
        p.issues.push(`API differs: log has ${best.API ?? 'N/A'}`);
      }
    }

    // per-pair checks
    for (const p of pairs) {
      if (!p.x.sessionId) p.issues.push('no sessionId');
      if (!p.x.Direction) p.issues.push('direction unknown ([?]/[!] missing)');
      if (!p.l) { p.issues.push('no matching log event'); continue; }
      if (Number.isFinite(p.x.time) && Number.isFinite(p.l.time)) {
        p.delta = Math.round(p.x.time - offsetMs - p.l.time);
        if (Math.abs(p.delta) > toleranceMs) p.issues.push(`time differs by ${p.delta} ms (after the ${formatOffset(offsetMs)} offset)`);
      }
    }

    const unmatchedLog = log.filter((l) => !used.has(l));
    const excelHops = new Set(excel.map(hop));
    const quality = [];
    const add = (kind, items) => { if (items.length) quality.push({ kind, count: items.length, items }); };

    add('Excel rows with no sessionId', pairs.filter((p) => !p.x.sessionId).map((p) => `row ${p.x.line}: ${p.x.Flow}`));
    add('Excel rows with an unknown direction', pairs.filter((p) => !p.x.Direction).map((p) => `row ${p.x.line}: ${p.x.Flow}`));

    // requests and responses per session and hop, from the Excel side
    const counts = new Map();
    for (const x of excel) {
      if (!x.Direction) continue;
      const k = `${x.sessionId ?? ''}\u0000${hop(x)}`;
      if (!counts.has(k)) counts.set(k, { sid: x.sessionId, hop: hop(x), req: 0, res: 0 });
      counts.get(k)[x.Direction === 'Request' ? 'req' : 'res']++;
    }
    const cs = [...counts.values()];
    add('Requests without a response (in the Excel)', cs.filter((c) => c.req > c.res).map((c) => `${c.sid}: ${c.hop} (${c.req} requests, ${c.res} responses)`));
    add('Responses without a request (in the Excel)', cs.filter((c) => c.res > c.req).map((c) => `${c.sid}: ${c.hop} (${c.req} requests, ${c.res} responses)`));

    add('Excel rows with no matching log event', pairs.filter((p) => !p.l).map((p) => `row ${p.x.line}: ${p.x.sessionId ?? ''} ${p.x.Flow}`));
    add(`Time differences beyond ${toleranceMs} ms`, pairs.filter((p) => p.l && p.delta != null && Math.abs(p.delta) > toleranceMs)
      .map((p) => `row ${p.x.line}: ${p.x.Flow} (Δ ${p.delta} ms)`));
    add('Log events not mapped to any Excel row', unmatchedLog.map((l) => `${l.source ? String(l.source).split(/[\\/]/).pop() : ''}:${l.lineNo ?? '?'} ${l.sessionId ?? '(no sessionId)'} ${l.Flow ?? hop(l)}`));
    add('Hops in the log that never appear in the Excel', [...new Set(log.map(hop))].filter((h) => !excelHops.has(h)));

    return {
      pairs,
      unmatchedLog,
      offsetMs,
      offsetText: formatOffset(offsetMs),
      matched: pairs.filter((p) => p.l).length,
      sessions: { excel: new Set(excel.map((x) => x.sessionId)).size, log: new Set(log.map((l) => l.sessionId)).size,
        common: [...new Set(excel.map((x) => x.sessionId))].filter((s) => log.some((l) => l.sessionId === s)).length },
      quality,
    };
  }

  return { compare, formatOffset };
});
