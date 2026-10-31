// Draws a sequence diagram from TraceFlow.sequenceModel() as SVG markup, in the
// browser, so the diagram never leaves the machine. Layout follows PlantUML's
// look: participant boxes top and bottom, dashed lifelines, activation bars,
// solid request arrows, dashed response arrows, notes over a participant.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceSequence = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif';
  const SIZE = 12;
  const SMALL = 10;
  const LINE = 15;
  const SMALL_LINE = 13;
  const BOX_H = 30;
  const BAR_W = 10;
  const C = {
    bg: '#ffffff', text: '#1f2328', muted: '#59636e', box: '#eef2f7', actor: '#ddf4e4',
    stroke: '#5b6b7f', life: '#9aa5b1', bar: '#ffffff', note: '#ffe0b2', noteStroke: '#e0a04b',
  };

  const xml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Text width in px: canvas measurement in the browser, an estimate elsewhere.
  function measurer() {
    try {
      const ctx = document.createElement('canvas').getContext('2d');
      return (text, size) => { ctx.font = `${size}px ${FONT}`; return ctx.measureText(text).width; };
    } catch (e) {
      return (text, size) => text.length * size * 0.56;
    }
  }

  const lineH = (l) => (l.small ? SMALL_LINE : LINE);
  const blockH = (lines) => lines.reduce((h, l) => h + lineH(l), 0);

  function render(d, measure = measurer()) {
    const textW = (l) => measure(l.text, l.small ? SMALL : SIZE);
    const blockW = (lines) => Math.max(...lines.map(textW));
    const ids = d.participants.map((p) => p.id);
    const col = Object.fromEntries(ids.map((id, i) => [id, i]));

    // Column centres: every gap starts wide enough for both boxes, then grows until
    // each message label fits between its two participants (short spans first).
    const boxW = d.participants.map((p) => Math.max(70, measure(p.name, SIZE + 1) + 28));
    const gaps = ids.slice(1).map((_, i) => Math.max(110, (boxW[i] + boxW[i + 1]) / 2 + 30));
    const spans = [];
    for (const it of d.items) {
      if (it.t === 'msg') {
        const a = Math.min(col[it.from], col[it.to]); const b = Math.max(col[it.from], col[it.to]);
        if (a !== b) spans.push({ a, b, need: blockW(it.lines) + 36 });
      } else if (it.t === 'note') {
        const i = col[it.who];
        const half = (blockW(it.lines) + 24) / 2 + 12;
        if (i > 0) spans.push({ a: i - 1, b: i, need: half + boxW[i - 1] / 2 });
        if (i < ids.length - 1) spans.push({ a: i, b: i + 1, need: half + boxW[i + 1] / 2 });
      }
    }
    spans.sort((x, y) => (x.b - x.a) - (y.b - y.a));
    for (const s of spans) {
      const have = gaps.slice(s.a, s.b).reduce((t, g) => t + g, 0);
      if (have < s.need) for (let k = s.a; k < s.b; k++) gaps[k] += (s.need - have) / (s.b - s.a);
    }
    const left = Math.max(20 + boxW[0] / 2, 20);
    const cx = [left];
    gaps.forEach((g) => cx.push(cx[cx.length - 1] + g));
    const x = (id) => cx[col[id]];

    const titleH = d.title.length ? 16 + 4 + (d.title.length - 1) * LINE + 12 : 0;
    const top = 12 + titleH;
    const out = [];
    let y = top + BOX_H + 16;

    // Activation bars: per participant, a stack of open bars (start y, depth).
    const open = Object.fromEntries(ids.map((id) => [id, []]));
    const bars = [];
    let lastArrowY = y;
    let right = 0; // right edge of notes, which can stick out past the last participant
    const edge = (id, towards) => {
      const depth = open[id].length;
      if (!depth) return x(id);
      const off = (depth - 1) * 4 + BAR_W / 2;
      return x(id) + (towards > x(id) ? off : -off);
    };

    for (const it of d.items) {
      if (it.t === 'msg') {
        const x1raw = x(it.from); const x2raw = x(it.to);
        // The target of a request is about to be activated: end the arrow at the new bar's edge.
        const x1 = edge(it.from, x2raw);
        const x2 = it.dashed ? edge(it.to, x1raw)
          : x2raw + (x1raw < x2raw ? -1 : 1) * (open[it.to].length * 4 + BAR_W / 2);
        const h = blockH(it.lines);
        let ty = y;
        const mid = (x1 + x2) / 2;
        for (const l of it.lines) {
          ty += lineH(l);
          out.push(`<text x="${mid.toFixed(1)}" y="${(ty - 3).toFixed(1)}" text-anchor="middle" font-size="${l.small ? SMALL : SIZE}" fill="${l.small ? C.muted : C.text}">${xml(l.text)}</text>`);
        }
        const ay = y + h + 5;
        const dir = x2 > x1 ? 1 : -1;
        out.push(`<line x1="${x1.toFixed(1)}" y1="${ay}" x2="${x2.toFixed(1)}" y2="${ay}" stroke="${C.text}" stroke-width="1.2"${it.dashed ? ' stroke-dasharray="5 4"' : ''}/>`);
        const hx = x2 - dir * 9;
        out.push(it.dashed
          ? `<polyline points="${hx.toFixed(1)},${ay - 4} ${x2.toFixed(1)},${ay} ${hx.toFixed(1)},${ay + 4}" fill="none" stroke="${C.text}" stroke-width="1.2"/>`
          : `<polygon points="${hx.toFixed(1)},${ay - 4} ${x2.toFixed(1)},${ay} ${hx.toFixed(1)},${ay + 4}" fill="${C.text}"/>`);
        lastArrowY = ay;
        y = ay + 14;
      } else if (it.t === 'act') {
        open[it.who].push({ y: lastArrowY, depth: open[it.who].length });
      } else if (it.t === 'deact') {
        const b = open[it.who].pop();
        if (b) bars.push({ id: it.who, y1: b.y, y2: Math.max(lastArrowY, b.y + 8), depth: b.depth });
      } else {
        const w = blockW(it.lines) + 20;
        const h = blockH(it.lines) + 10;
        const nx = x(it.who) - w / 2;
        right = Math.max(right, nx + w);
        out.push(`<path d="M${nx.toFixed(1)},${y} h${(w - 8).toFixed(1)} l8,8 v${h - 8} h${(-w).toFixed(1)} z" fill="${C.note}" stroke="${C.noteStroke}"/>`);
        let ty = y + 5;
        it.lines.forEach((l, i) => {
          ty += lineH(l);
          out.push(`<text x="${(nx + 10).toFixed(1)}" y="${(ty - 3).toFixed(1)}" font-size="${l.small ? SMALL : SIZE}" fill="${C.text}"${i === 0 ? ' font-weight="600"' : ''}>${xml(l.text)}</text>`);
        });
        lastArrowY = y + h;
        y += h + 12;
      }
    }
    for (const id of ids) while (open[id].length) {
      const b = open[id].pop();
      bars.push({ id, y1: b.y, y2: lastArrowY, depth: b.depth });
    }

    const bottom = y + 6;
    const width = Math.max(cx[cx.length - 1] + boxW[boxW.length - 1] / 2, right) + 20;
    const height = bottom + BOX_H + 12;

    const head = [];
    if (d.title.length) {
      head.push(`<text x="${(width / 2).toFixed(1)}" y="${12 + 16}" text-anchor="middle" font-size="14" font-weight="600" fill="${C.text}">${xml(d.title[0])}</text>`);
      d.title.slice(1).forEach((t, i) => head.push(`<text x="${(width / 2).toFixed(1)}" y="${12 + 16 + (i + 1) * LINE + 2}" text-anchor="middle" font-size="${SIZE}" fill="${C.muted}">${xml(t)}</text>`));
    }
    const lifelines = ids.map((id) => `<line x1="${x(id).toFixed(1)}" y1="${top + BOX_H}" x2="${x(id).toFixed(1)}" y2="${bottom}" stroke="${C.life}" stroke-dasharray="4 4"/>`);
    const barRects = bars.sort((a, b) => a.depth - b.depth).map((b) => {
      const bx = x(b.id) - BAR_W / 2 + b.depth * 4;
      return `<rect x="${bx.toFixed(1)}" y="${b.y1}" width="${BAR_W}" height="${(b.y2 - b.y1).toFixed(1)}" fill="${C.bar}" stroke="${C.stroke}"/>`;
    });
    const boxes = (by) => d.participants.map((p, i) => {
      const bx = cx[i] - boxW[i] / 2;
      return `<rect x="${bx.toFixed(1)}" y="${by}" width="${boxW[i].toFixed(1)}" height="${BOX_H}" rx="${p.actor ? 15 : 4}" fill="${p.actor ? C.actor : C.box}" stroke="${C.stroke}"/>`
        + `<text x="${cx[i].toFixed(1)}" y="${by + 19}" text-anchor="middle" font-size="${SIZE + 1}" font-weight="600" fill="${C.text}">${xml(p.name)}</text>`;
    });

    return `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.ceil(width)}" height="${Math.ceil(height)}" viewBox="0 0 ${Math.ceil(width)} ${Math.ceil(height)}" font-family='${FONT}' role="img" aria-label="${xml(d.title.join(', '))}">`
      + `<rect width="100%" height="100%" fill="${C.bg}"/>`
      + head.join('') + lifelines.join('') + barRects.join('') + out.join('')
      + boxes(top).join('') + boxes(bottom).join('')
      + '</svg>';
  }

  return { render };
});
