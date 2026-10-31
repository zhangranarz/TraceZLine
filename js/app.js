'use strict';
// TraceZLine page: list editors for each config section, live SPL preview.
(function () {
  const STORAGE_KEY = 'tracezline.config.v1';
  const { DEFAULT_CONFIG, clone, generate, validate, parseTerms } = window.TraceSpl;

  const COLUMN_SUGGESTIONS = ['Step', 'EventTime', 'sessionId', 'Flow', 'Params', 'ElapsedMs',
    'LayerName', 'Layer', 'Direction', 'API', 'Endpoint', 'URL', 'SvcCode', 'HostPairs',
    'ServiceInfo', 'transactionRef', 'transactionCode', '_raw'];

  // Field specs per list section. Columns are stored as plain strings.
  const SECTIONS = {
    sources: {
      fields: [
        { key: 'enabled', type: 'checkbox', label: 'On' },
        { key: 'source', label: 'source=', placeholder: '/var/log/pods/app-*.log', size: 'm' },
        { key: 'filter', label: 'Filter', placeholder: '("Marker1" OR "Marker2")', size: 'l', multiline: true },
      ],
      blank: () => ({ enabled: true, source: '', filter: '' }),
    },
    layers: {
      fields: [
        { key: 'name', label: 'Name', placeholder: 'OPI', size: 's' },
        { key: 'layer', label: 'Layer #', type: 'number', size: 'xs' },
        { key: 'indent', label: 'Indent', placeholder: '(none)', size: 'xs' },
        { key: 'match', label: 'Condition', placeholder: 'match(_raw,"OPIAppLog")', size: 'l' },
      ],
      blank: () => ({ name: '', layer: 3, indent: '', match: '' }),
    },
    directions: {
      fields: [
        { key: 'layer', label: 'Layer', size: 's', list: 'dl-layers' },
        { key: 'pattern', label: 'Regex', placeholder: '(?i)Request Message', size: 'l' },
        { key: 'direction', label: 'Direction', type: 'select', options: ['Request', 'Response'], size: 's' },
      ],
      blank: () => ({ layer: '', pattern: '', direction: 'Request' }),
    },
    endpointRules: {
      fields: [
        { key: 'field', label: 'Field', placeholder: 'Endpoint4', size: 's' },
        { key: 'rex', label: 'rex', placeholder: '(?<Endpoint4>/[^\\s]+)', size: 'l' },
      ],
      blank: () => ({ field: '', rex: '' }),
    },
    sessionRules: {
      fields: [
        { key: 'field', label: 'Field', placeholder: 'sidOpi', size: 's' },
        { key: 'rex', label: 'rex', placeholder: 'sessionId\\"\\:\\"(?<sidOpi>[0-9a-fA-F-]{36})', size: 'l' },
      ],
      blank: () => ({ field: '', rex: '' }),
    },
    params: {
      fields: [
        { key: 'field', label: 'Field', placeholder: 'accountType', size: 's' },
        { key: 'label', label: 'Label', placeholder: 'AcctType', size: 's' },
        { key: 'rex', label: 'rex', placeholder: 'accountType\\"\\:\\"(?<accountType>[^\\",]+)', size: 'l' },
      ],
      blank: () => ({ field: '', label: '', rex: '' }),
    },
    columns: {
      fields: [{ key: null, label: 'Column', size: 'm', list: 'dl-columns' }],
      blank: () => '',
    },
  };

  let state = load();

  function load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) return normalise(JSON.parse(raw));
    } catch (e) { /* storage blocked or corrupt: fall back to defaults */ }
    return clone(DEFAULT_CONFIG);
  }

  function save() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch (e) { /* ignore */ }
  }

  // Fills missing sections from the defaults so older or partial configs still load.
  function normalise(cfg) {
    if (!cfg || typeof cfg !== 'object') throw new Error('Config must be a JSON object.');
    const out = clone(DEFAULT_CONFIG);
    Object.keys(out).forEach((k) => {
      if (k === 'version' || cfg[k] === undefined) return;
      if (Array.isArray(out[k]) && !Array.isArray(cfg[k])) throw new Error(`"${k}" must be an array.`);
      if (typeof out[k] === 'boolean' && typeof cfg[k] !== 'boolean') throw new Error(`"${k}" must be true or false.`);
      if (typeof out[k] === 'string' && typeof cfg[k] !== 'string') throw new Error(`"${k}" must be text.`);
      out[k] = cfg[k];
    });
    return out;
  }

  // ---------- rendering ----------

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'class') node.className = v;
      else if (k in node && typeof v !== 'string') node[k] = v;
      else node.setAttribute(k, v);
    });
    (children || []).forEach((c) => node.append(c));
    return node;
  }

  function renderList(name) {
    const spec = SECTIONS[name];
    const host = document.getElementById('list-' + name);
    host.replaceChildren();
    const items = state[name];
    if (!items.length) host.append(el('p', { class: 'empty' }, ['None.']));

    items.forEach((item, i) => {
      const row = el('div', { class: 'row' });
      spec.fields.forEach((f) => {
        const value = f.key === null ? item : item[f.key];
        let input;
        if (f.type === 'checkbox') {
          input = el('input', { type: 'checkbox', checked: !!value });
        } else if (f.type === 'select') {
          input = el('select', {}, f.options.map((o) => el('option', { value: o, selected: o === value }, [o])));
        } else if (f.multiline) {
          input = el('textarea', { rows: 1, spellcheck: false, placeholder: f.placeholder || '' });
          input.value = value ?? '';
        } else {
          input = el('input', { type: f.type || 'text', spellcheck: false, placeholder: f.placeholder || '' });
          if (f.list) input.setAttribute('list', f.list);
          input.value = value ?? '';
        }
        input.addEventListener('input', () => {
          let v = f.type === 'checkbox' ? input.checked : input.value;
          if (f.type === 'number') v = input.value === '' ? '' : Number(input.value);
          if (f.key === null) state[name][i] = v;
          else state[name][i][f.key] = v;
          if (name === 'layers' && f.key === 'name') refreshDatalists();
          update();
        });
        row.append(el('label', { class: 'field size-' + (f.size || 'm') }, [el('span', {}, [f.label]), input]));
      });

      const btns = el('div', { class: 'row-btns' }, [
        iconBtn('↑', 'Move up', i === 0, () => move(name, i, -1)),
        iconBtn('↓', 'Move down', i === items.length - 1, () => move(name, i, 1)),
        iconBtn('✕', 'Remove', false, () => { state[name].splice(i, 1); renderList(name); update(); }),
      ]);
      row.append(btns);
      host.append(row);
    });
  }

  function iconBtn(text, title, disabled, onClick) {
    const b = el('button', { type: 'button', class: 'icon', title, 'aria-label': title, disabled }, [text]);
    b.addEventListener('click', onClick);
    return b;
  }

  function move(name, i, delta) {
    const list = state[name];
    const j = i + delta;
    [list[i], list[j]] = [list[j], list[i]];
    renderList(name);
    update();
  }

  function refreshDatalists() {
    const layers = [...new Set(state.layers.map((l) => l.name.trim()).filter(Boolean))];
    document.getElementById('dl-layers').replaceChildren(...layers.map((n) => el('option', { value: n })));
    document.getElementById('dl-columns').replaceChildren(...COLUMN_SUGGESTIONS.map((n) => el('option', { value: n })));
  }

  function renderAll() {
    Object.keys(SECTIONS).forEach(renderList);
    document.getElementById('terms').value = state.terms.join('\n');
    document.getElementById('group-sources').checked = state.groupSources;
    document.getElementById('dir-word-rex').value = state.dirWordRex;
    document.getElementById('dir-first').value = state.directionFirst;
    refreshDatalists();
    update();
  }

  function update() {
    const text = generate(state);
    document.getElementById('spl').textContent = text;
    document.getElementById('line-count').textContent = (text.trimEnd().split('\n').length) + ' lines';
    const n = state.terms.filter((t) => t.trim()).length;
    document.getElementById('terms-count').textContent = n + (n === 1 ? ' term' : ' terms');
    const warnings = validate(state);
    document.getElementById('warnings').replaceChildren(...warnings.map((w) => el('li', {}, [w])));
    save();
    refreshFlow();
  }

  // ---------- actions ----------

  function toast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => t.classList.remove('show'), 1800);
  }

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  document.getElementById('terms').addEventListener('input', (e) => {
    state.terms = parseTerms(e.target.value);
    update();
  });

  document.getElementById('group-sources').addEventListener('change', (e) => {
    state.groupSources = e.target.checked;
    update();
  });

  [['dir-word-rex', 'dirWordRex'], ['dir-first', 'directionFirst']].forEach(([id, key]) => {
    document.getElementById(id).addEventListener('input', (e) => {
      state[key] = e.target.value;
      update();
    });
  });

  document.querySelectorAll('[data-add]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const name = btn.dataset.add;
      state[name].push(SECTIONS[name].blank());
      renderList(name);
      update();
      const rows = document.querySelectorAll(`#list-${name} .row`);
      const last = rows[rows.length - 1];
      if (last) last.querySelector('input:not([type=checkbox]), textarea')?.focus();
    });
  });

  document.getElementById('btn-copy').addEventListener('click', async () => {
    const text = generate(state);
    try {
      await navigator.clipboard.writeText(text);
      toast('SPL copied');
    } catch (e) {
      const range = document.createRange();
      range.selectNodeContents(document.getElementById('spl'));
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      toast('Clipboard blocked: SPL selected, press Ctrl+C');
    }
  });

  document.getElementById('btn-download').addEventListener('click', () => {
    download('tracezline-query.spl', generate(state), 'text/plain');
  });

  document.getElementById('btn-export').addEventListener('click', () => {
    download('tracezline-config.json', JSON.stringify(state, null, 2), 'application/json');
  });

  document.getElementById('file-import').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    try {
      state = normalise(JSON.parse(await file.text()));
      renderAll();
      toast('Config imported');
    } catch (err) {
      toast('Import failed: ' + err.message);
    }
  });

  document.getElementById('btn-reset').addEventListener('click', () => {
    if (!confirm('Replace the current settings with the base query?')) return;
    state = clone(DEFAULT_CONFIG);
    renderAll();
    toast('Reset to base query');
  });

  // ---------- flow result ----------

  // Loaded log files stay in memory only: they may hold real data, so they are never stored.
  let logs = [];
  let flowRows = [];
  const SLOW_MS = 1000;

  function flowColumns() {
    return state.columns.map((c) => c.trim()).filter(Boolean);
  }

  function selectedRows() {
    const sid = document.getElementById('session-filter').value;
    return sid ? flowRows.filter((r) => r.sessionId === sid) : flowRows;
  }

  function refreshFlow() {
    const status = document.getElementById('flow-status');
    if (!logs.length) return;
    const useTerms = document.getElementById('use-terms').checked;
    try {
      flowRows = window.TraceFlow.run(state, logs, useTerms ? state.terms.filter((t) => t.trim()) : []);
    } catch (err) {
      flowRows = [];
      document.getElementById('flow-count').textContent = 'error';
      status.textContent = 'Could not run the query logic: ' + err.message;
      renderFlow([]);
      renderDiagram([]);
      return;
    }
    const sessions = window.TraceFlow.summarize(flowRows);
    const noSid = flowRows.filter((r) => r.sessionId == null).length;
    const anyNote = logs.some((l) => l.anySource)
      ? ' File names that match no source are treated as every source.' : '';
    document.getElementById('flow-count').textContent = `${flowRows.length} rows`;
    status.textContent = `${logs.map((l) => l.name).join(', ')}: ${flowRows.length} events, ${sessions.length} sessions`
      + (noSid ? `, ${noSid} without a sessionId` : '') + '.' + anyNote
      + (!flowRows.length && useTerms ? ' Nothing matches the Search terms; untick "Only sessions in Search terms" to see everything.' : '');

    const select = document.getElementById('session-filter');
    const keep = select.value;
    select.replaceChildren(
      el('option', { value: '' }, [`All sessions (${sessions.length})`]),
      ...sessions.map((s) => el('option', { value: s.sessionId }, [`${s.sessionId} (${s.steps})`])));
    select.value = sessions.some((s) => s.sessionId === keep) ? keep : '';
    renderSummary(sessions);
    renderFlow(selectedRows());
    renderDiagram(selectedRows());
  }

  // ---------- sequence diagram ----------

  let pumlText = '';

  function renderDiagram(rows) {
    pumlText = window.TraceFlow.toPlantUml(rows, state);
    document.getElementById('puml').textContent = pumlText || '(no sessions)';
    // Images belong to the previous text; drop them so they never show a stale flow.
    document.getElementById('puml-images').replaceChildren();
    ['btn-copy-puml', 'btn-download-puml', 'btn-render-puml'].forEach((id) => {
      document.getElementById(id).disabled = !pumlText;
    });
  }

  function showView(name) {
    document.querySelectorAll('.seg-btn').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === name)));
    document.getElementById('view-table').hidden = name !== 'table';
    document.getElementById('view-diagram').hidden = name !== 'diagram';
    document.querySelectorAll('.view-actions').forEach((s) => { s.hidden = s.dataset.for !== name; });
  }

  document.querySelectorAll('.seg-btn').forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));

  document.getElementById('btn-copy-puml').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pumlText);
      toast('PlantUML copied');
    } catch (e) {
      toast('Clipboard blocked: use Download .puml');
    }
  });

  document.getElementById('btn-download-puml').addEventListener('click', () => {
    download('tracezline-flow.puml', pumlText, 'text/plain');
  });

  // Rendering sends the diagram text to plantuml.com, so it always asks first.
  document.getElementById('btn-render-puml').addEventListener('click', async () => {
    if (!confirm('Render image sends the diagram text (endpoints, session IDs, Params values) to www.plantuml.com.\n\n'
      + 'Only continue with mock or desensitised data. Continue?')) return;
    const host = document.getElementById('puml-images');
    host.replaceChildren();
    try {
      for (const block of pumlText.split(/(?=@startuml)/)) {
        const stream = new Blob([new TextEncoder().encode(block)]).stream().pipeThrough(new CompressionStream('deflate-raw'));
        const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
        const src = 'https://www.plantuml.com/plantuml/svg/' + window.TraceFlow.plantUmlEncode64(bytes);
        host.append(el('img', { src, alt: block.match(/^title (.*)$/m)?.[1].replace(/\\n/g, ' ') || 'Sequence diagram', loading: 'lazy' }));
      }
    } catch (err) {
      toast('Could not render: ' + err.message);
    }
  });

  function renderSummary(sessions) {
    const sid = document.getElementById('session-filter').value;
    const cards = sessions.filter((s) => !sid || s.sessionId === sid).map((s) => {
      const lines = [
        el('div', { class: 'sum-id' }, [s.sessionId]),
        el('div', {}, [`${s.steps} steps · ${s.start} · ${(s.durationMs / 1000).toFixed(3)} s total`]),
      ];
      if (s.slowest) lines.push(el('div', { class: s.slowest.ms >= SLOW_MS ? 'slow' : '' }, [`Slowest: ${s.slowest.flow} ${s.slowest.ms} ms`]));
      s.noResponse.forEach((f) => lines.push(el('div', { class: 'missing' }, [`No response: ${f}`])));
      return el('div', { class: 'sum-card' }, lines);
    });
    document.getElementById('flow-summary').replaceChildren(...cards);
  }

  // Rows are grouped by session (first appearance) and keep time order inside a session.
  // Each group has a heading row, so the sessionId column is left out on screen (not in Copy/CSV).
  function renderFlow(rows) {
    const cols = flowColumns().filter((c) => c !== 'sessionId');
    const table = document.getElementById('flow-table');
    const order = [...new Set(rows.map((r) => r.sessionId ?? ''))];
    const grouped = order.flatMap((sid) => rows.filter((r) => (r.sessionId ?? '') === sid));
    const head = el('thead', {}, [el('tr', {}, cols.map((c) => el('th', { class: 'col-' + c }, [c])))]);
    const body = el('tbody');
    let prev;
    for (const r of grouped) {
      const sid = r.sessionId ?? '';
      if (sid !== prev) {
        body.append(el('tr', { class: 'group' }, [el('td', { colSpan: cols.length }, [sid || '(no sessionId)'])]));
      }
      prev = sid;
      const tr = el('tr', { class: [r.Direction === 'Request' ? 'req' : 'res', 'layer-' + (r.LayerName || 'none')].join(' ') });
      for (const c of cols) {
        const v = r[c];
        const td = el('td', { class: 'col-' + c });
        (Array.isArray(v) ? v : [v]).forEach((x, i) => td.append(el('div', { class: i ? 'sub' : '' }, [x == null ? '' : String(x)])));
        if (c === 'ElapsedMs' && v >= SLOW_MS) td.classList.add('slow');
        tr.append(td);
      }
      body.append(tr);
    }
    table.replaceChildren(head, body);
    document.getElementById('btn-copy-flow').disabled = !rows.length;
    document.getElementById('btn-csv').disabled = !rows.length;
  }

  // Multivalue cells become one cell with line breaks, quoted for Excel.
  function toDelimited(rows, sep) {
    const cols = flowColumns();
    const cell = (v) => {
      const s = (Array.isArray(v) ? v.join('\n') : v == null ? '' : String(v));
      return /[",\n\t]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return [cols.join(sep), ...rows.map((r) => cols.map((c) => cell(r[c])).join(sep))].join('\r\n') + '\r\n';
  }

  function setLogs(files) {
    logs = files.map((f) => ({ ...f, anySource: !window.TraceFlow.matchesAnySource(state, f.name) }));
    refreshFlow();
  }

  document.getElementById('log-files').addEventListener('change', async (e) => {
    const files = [...e.target.files];
    e.target.value = '';
    if (!files.length) return;
    setLogs(await Promise.all(files.map(async (f) => ({ name: f.name, text: await f.text() }))));
  });

  document.getElementById('btn-mock').addEventListener('click', async () => {
    try {
      const names = ['spl-banking-mock.log', 'spl-ms-mock.log'];
      const texts = await Promise.all(names.map(async (n) => {
        const res = await fetch('mock/' + n);
        if (!res.ok) throw new Error(`${n}: HTTP ${res.status}`);
        return res.text();
      }));
      document.getElementById('use-terms').checked = false;
      setLogs(names.map((name, i) => ({ name, text: texts[i] })));
    } catch (err) {
      toast('Could not load mock logs: ' + err.message);
    }
  });

  document.getElementById('btn-wide').addEventListener('click', (e) => {
    const wide = document.body.classList.toggle('flow-wide');
    e.target.setAttribute('aria-pressed', String(wide));
    e.target.textContent = wide ? 'Show settings' : 'Full width';
  });

  document.getElementById('use-terms').addEventListener('change', refreshFlow);
  document.getElementById('session-filter').addEventListener('change', refreshFlow);

  document.getElementById('btn-copy-flow').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(toDelimited(selectedRows(), '\t'));
      toast('Table copied: paste into Excel');
    } catch (e) {
      toast('Clipboard blocked: use Download CSV');
    }
  });

  document.getElementById('btn-csv').addEventListener('click', () => {
    download('tracezline-flow.csv', '﻿' + toDelimited(selectedRows(), ','), 'text/csv');
  });

  // ---------- tabs ----------

  const TAB_KEY = 'tracezline.tab';

  function showTab(name) {
    document.querySelectorAll('.tab').forEach((t) => {
      const on = t.dataset.tab === name;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
    });
    try { localStorage.setItem(TAB_KEY, name); } catch (e) { /* ignore */ }
  }

  document.querySelectorAll('.tab').forEach((t) => {
    t.addEventListener('click', () => showTab(t.dataset.tab));
    t.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      const tabs = [...document.querySelectorAll('.tab')];
      const next = tabs[(tabs.indexOf(t) + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      showTab(next.dataset.tab);
      next.focus();
    });
  });

  let savedTab = 'spl';
  try { savedTab = localStorage.getItem(TAB_KEY) || 'spl'; } catch (e) { /* ignore */ }
  showTab(savedTab === 'flow' ? 'flow' : 'spl');

  renderAll();
  // Demo links: index.html#mock opens the Flow tab with the mock logs loaded;
  // #mock/diagram opens it on the sequence diagram.
  if (location.hash.startsWith('#mock')) {
    showTab('flow');
    if (location.hash === '#mock/diagram') showView('diagram');
    document.getElementById('btn-mock').click();
  }
})();
