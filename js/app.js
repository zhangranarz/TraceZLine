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

  // The Load File and Mock Test tabs share the flow pane; each keeps its own data.
  // `logs` and `imported` always hold the current tab's data; the other tab's waits in ctx.
  let mode = 'file';
  const ctx = { file: { logs: [], imported: null }, mock: { logs: [], imported: null } };
  const IDLE_STATUS = {
    file: 'Local Test loads raw log files (or a Splunk EventTime/PopulatedLog export) and runs this query\'s logic on them; Upload in the Table view loads the flow table exported from Splunk. Files are read in this browser only and never uploaded. The result updates as you edit the settings on the left.',
    mock: 'Loading the bundled mock logs (fake data)…',
  };

  function setCount(text) {
    document.getElementById('count-' + mode).textContent = text;
  }

  function flowColumns() {
    return state.columns.map((c) => c.trim()).filter(Boolean);
  }

  function selectedRows() {
    const sid = document.getElementById('session-filter').value;
    return sid ? flowRows.filter((r) => r.sessionId === sid) : flowRows;
  }

  // An uploaded Splunk result ({ name, rows, problems, trace }) replaces the loaded logs.
  let imported = null;

  // Search terms on imported rows: a term must appear in the row (as Splunk matches raw text).
  const rowHasTerm = (r, terms) => terms.some((t) => r.raw.toLowerCase().includes(t.toLowerCase()));

  function refreshFlow() {
    const status = document.getElementById('flow-status');
    if (!logs.length && !imported) return;
    const useTerms = document.getElementById('use-terms').checked;
    const terms = useTerms ? state.terms.filter((t) => t.trim()) : [];
    if (imported) {
      flowRows = terms.length ? imported.rows.filter((r) => rowHasTerm(r, terms)) : imported.rows;
      renderDebugTable(imported.trace);
    } else {
      const trace = [];
      try {
        flowRows = window.TraceFlow.run(state, logs, terms, trace);
      } catch (err) {
        flowRows = [];
        setCount('error');
        status.textContent = 'Could not run the query logic: ' + err.message;
        logDebug('error', 'Run failed: ' + err.message);
        renderFlow([]);
        renderDiagram([]);
        renderDebugTable(trace);
        return;
      }
      logRun(trace, useTerms, terms);
      renderDebugTable(trace);
    }
    const sessions = window.TraceFlow.summarize(flowRows);
    const noSid = flowRows.filter((r) => r.sessionId == null).length;
    setCount(`${flowRows.length} rows`);
    if (imported) {
      status.textContent = `${imported.name}: imported Splunk result, ${flowRows.length} rows, ${sessions.length} sessions`
        + (imported.problems.length ? `; ${imported.problems.length} rows need attention (see Debug)` : '') + '.';
    } else {
      const anyNote = logs.some((l) => l.anySource)
        ? ' File names that match no source are treated as every source.' : '';
      status.textContent = `${logs.map((l) => l.name).join(', ')}: ${flowRows.length} events, ${sessions.length} sessions`
        + (noSid ? `, ${noSid} without a sessionId` : '') + '.' + anyNote;
    }
    renderFlowProblem(useTerms);

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

  // When nothing is shown, say why: unreadable files, or Search terms that match none
  // of the sessions in the files (with one-click fixes).
  function renderFlowProblem(useTerms) {
    const box = document.getElementById('flow-problem');
    box.replaceChildren();
    box.hidden = true;
    if (flowRows.length) return;
    const show = (...nodes) => { box.append(...nodes); box.hidden = false; };

    if (imported) {
      if (!imported.rows.length) {
        show(el('p', {}, [`${imported.name}: no flow rows could be read. The file needs a header row with ServiceInfo (or Flow) and rows like "> Enterprise: /path [?]". See Debug.`]));
        return;
      }
      if (useTerms) showTermsProblem(window.TraceFlow.summarize(imported.rows).map((s) => s.sessionId), show);
      return;
    }

    const parsed = logs.map((l) => ({ name: l.name, events: window.TraceFlow.parseEvents(l.name, l.text).length, first: l.text.split(/\r?\n/).find((x) => x.trim()) || '' }));
    if (parsed.every((p) => !p.events)) {
      show(el('p', {}, ['No log events found. Each event must start with a timestamp line like ',
        el('code', {}, ['2026-10-26 09:10:34.535 [thread] INFO …']),
        ' (or be a Splunk EventTime/PopulatedLog export). First line of ', el('b', {}, [parsed[0].name]), ':']),
      el('pre', {}, [parsed[0].first.slice(0, 200)]));
      return;
    }
    if (!useTerms) {
      show(el('p', {}, [`${parsed.reduce((t, p) => t + p.events, 0)} events were read, but none matched the sources and layer rules on the left. Check Sources (file names are matched against source=) and Layers.`]));
      return;
    }
    const all = window.TraceFlow.summarize(window.TraceFlow.run(state, logs, []));
    if (!all.length) return;
    showTermsProblem(all.map((s) => s.sessionId), show);
  }

  // Search terms match none of the sessions found: list them, with one-click fixes.
  function showTermsProblem(ids, show) {
    const showAll = el('button', { type: 'button' }, ['Show all sessions']);
    showAll.addEventListener('click', () => { document.getElementById('use-terms').checked = false; refreshFlow(); });
    const useIds = el('button', { type: 'button', class: 'primary' }, ['Use these IDs as Search terms']);
    useIds.addEventListener('click', () => {
      state.terms = ids;
      document.getElementById('terms').value = ids.join('\n');
      update();
      toast('Search terms updated');
    });
    show(el('p', {}, [`No events match the Search terms (${state.terms.filter((t) => t.trim()).length}). The loaded files contain these sessions:`]),
      el('ul', {}, ids.slice(0, 20).map((id) => el('li', {}, [el('code', {}, [id])]))),
      ...(ids.length > 20 ? [el('p', {}, [`… and ${ids.length - 20} more.`])] : []),
      el('div', { class: 'problem-actions' }, [showAll, useIds]));
  }

  // ---------- debug ----------

  const debugLines = [];
  const MAX_DEBUG_LINES = 300;
  let lastTrace = [];

  function logDebug(level, msg) {
    const t = new Date().toTimeString().slice(0, 8);
    debugLines.push(`${t} ${level === 'error' ? 'ERROR' : level === 'warn' ? 'WARN ' : 'INFO '} ${msg}`);
    if (debugLines.length > MAX_DEBUG_LINES) debugLines.splice(0, debugLines.length - MAX_DEBUG_LINES);
    const pre = document.getElementById('debug-log');
    pre.textContent = debugLines.join('\n');
    pre.scrollTop = pre.scrollHeight;
    if (level === 'error') toast(msg.length > 90 ? msg.slice(0, 90) + '…' : msg);
  }

  // One summary line per run, skipped when nothing changed since the last run (edits re-run often).
  let lastRunLine = '';
  function logRun(trace, useTerms, terms) {
    const count = (re) => trace.filter((r) => re.test(r.reason || '')).length;
    const kept = trace.filter((r) => r.kept);
    const sources = state.sources.filter((s) => s.enabled && s.source.trim()).map((s) => s.source.trim()).join(', ');
    const line = `Run: ${trace.length} events read; excluded by source filter ${count(/source filter/)}, `
      + `by Search terms ${count(/Search term/)}, by Host/SvcCode where-clause ${count(/where clause/)}; kept ${kept.length}`
      + ` (no layer ${kept.filter((r) => /no layer/.test(r.warn)).length}, no direction ${kept.filter((r) => /no direction/.test(r.warn)).length},`
      + ` no sessionId ${kept.filter((r) => /no sessionId/.test(r.warn)).length}). Sources: ${sources || '(none)'}. `
      + (useTerms ? `Search terms (${terms.length}): ${terms.join(', ') || '(none)'}` : 'Search terms: not applied');
    if (line === lastRunLine) return;
    lastRunLine = line;
    logDebug(kept.length ? 'info' : 'warn', line);
  }

  function renderDebugTable(trace) {
    lastTrace = trace;
    const onlyProblems = document.getElementById('debug-problems').checked;
    const rows = onlyProblems ? trace.filter((r) => !r.kept || r.warn) : trace;
    const cols = ['#', 'File:line', 'Time', 'Result', 'Layer', 'Direction', 'sessionId', 'API / Endpoint', 'Event (first line)'];
    const head = el('thead', {}, [el('tr', {}, cols.map((c) => el('th', {}, [c])))]);
    const body = el('tbody', {}, rows.map((r) => {
      const ev = r.ev;
      const result = r.kept ? (r.warn ? `Kept, ${r.warn}` : 'Kept') : r.reason;
      return el('tr', { class: r.kept ? (r.warn ? 'dbg-warn' : 'dbg-ok') : 'dbg-out' }, [
        el('td', {}, [String(trace.indexOf(r) + 1)]),
        el('td', {}, [`${r.file}:${r.lineNo}`]),
        el('td', {}, [ev.EventTime && ev.source === 'import' ? ev.EventTime
          : Number.isFinite(ev.time) ? new Date(ev.time).toISOString().slice(11, 23) : '']),
        el('td', {}, [result]),
        el('td', {}, [ev.LayerName ?? '']),
        el('td', {}, [ev.Direction ?? '']),
        el('td', {}, [ev.sessionId ?? '']),
        el('td', {}, [ev.API ?? ev.Endpoint ?? ev.URL ?? '']),
        el('td', { class: 'dbg-head', title: (ev.raw || '').slice(0, 2000) }, [r.head.slice(0, 160)]),
      ]);
    }));
    document.getElementById('debug-table').replaceChildren(head, body);
  }

  document.getElementById('debug-problems').addEventListener('change', () => renderDebugTable(lastTrace));

  document.getElementById('btn-copy-debug').addEventListener('click', async () => {
    const table = lastTrace.map((r, i) => [i + 1, `${r.file}:${r.lineNo}`, r.kept ? (r.warn ? `Kept, ${r.warn}` : 'Kept') : r.reason,
      r.ev.LayerName ?? '', r.ev.Direction ?? '', r.ev.sessionId ?? '', r.ev.API ?? r.ev.Endpoint ?? '', r.head.slice(0, 160)].join('\t'));
    try {
      await navigator.clipboard.writeText(debugLines.join('\n') + '\n\n' + table.join('\n') + '\n');
      toast('Debug log copied');
    } catch (e) {
      toast('Clipboard blocked: select the log and press Ctrl+C');
    }
  });

  // ---------- sequence diagram ----------

  let pumlText = '';

  let svgs = [];

  function renderDiagram(rows) {
    pumlText = window.TraceFlow.toPlantUml(rows, state);
    document.getElementById('puml').textContent = pumlText || '(no sessions)';
    // Images belong to the previous text; drop them so they never show a stale flow.
    document.getElementById('puml-images').replaceChildren();
    ['btn-copy-puml', 'btn-download-puml', 'btn-render-puml'].forEach((id) => {
      document.getElementById(id).disabled = !pumlText;
    });

    // render() escapes every log-derived string, so the markup is safe to insert.
    const models = window.TraceFlow.sequenceModel(rows, state);
    svgs = models.map((d) => ({ sessionId: d.sessionId, svg: window.TraceSequence.render(d) }));
    const host = document.getElementById('sequence');
    host.innerHTML = svgs.map((s) => `<figure class="seq-fig">${s.svg}</figure>`).join('');
    if (!svgs.length) host.textContent = '(no sessions)';
    document.getElementById('btn-svg').disabled = !svgs.length;
  }

  function showView(name) {
    document.querySelectorAll('.seg-btn').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === name)));
    ['table', 'diagram', 'sequence', 'debug'].forEach((v) => { document.getElementById('view-' + v).hidden = v !== name; });
    document.querySelectorAll('.view-actions').forEach((s) => { s.hidden = s.dataset.for !== name; });
  }

  document.getElementById('seq-fit').addEventListener('change', (e) => {
    document.getElementById('sequence').classList.toggle('fit', e.target.checked);
  });

  // One file per session; with one session selected, a single download.
  document.getElementById('btn-svg').addEventListener('click', () => {
    svgs.forEach((s) => download(`tracezline-sequence-${s.sessionId}.svg`, s.svg, 'image/svg+xml'));
  });

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

  // Splunk result upload: Excel or CSV flow table -> rows for the summary, table and diagrams.
  document.getElementById('flow-upload').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    logDebug('info', `Upload: ${file.name} (${file.size.toLocaleString()} bytes)`);
    try {
      const table = await window.TraceImport.readTable(file.name, await file.arrayBuffer());
      const { rows, problems } = window.TraceImport.toFlowRows(table, state);
      const byLine = new Map(problems.map((p) => [p.line, p]));
      const trace = rows.map((r) => ({ file: file.name, lineNo: r.line, head: r.Flow, ev: r, kept: true, warn: byLine.get(r.line)?.reason || '' }));
      problems.filter((p) => !rows.some((r) => r.line === p.line)).forEach((p) => {
        trace.push({ file: file.name, lineNo: p.line, head: p.text || '', ev: { raw: p.text || '' }, kept: false, reason: 'Skipped: ' + p.reason });
      });
      trace.sort((a, b) => a.lineNo - b.lineNo);
      imported = { name: file.name, rows, problems, trace };
      logs = [];
      logDebug(rows.length ? 'info' : 'error', `${file.name}: ${table.length - 1} table rows read, ${rows.length} flow rows, `
        + `${new Set(rows.map((r) => r.sessionId)).size} sessions; header: ${(table[0] || []).join(', ')}`);
      problems.forEach((p) => logDebug('warn', `${file.name} row ${p.line}: ${p.reason}: ${String(p.text).slice(0, 120)}`));
      showView('table');
      refreshFlow();
    } catch (err) {
      logDebug('error', `${file.name}: could not be read as a flow table (${err.message}).`);
    }
  });

  // Files that cannot hold log events (Excel, binary, no timestamped lines) are reported and skipped.
  function setLogs(files) {
    imported = null;
    logs = [];
    for (const f of files) {
      const info = window.TraceFlow.describeLog(f.text);
      const size = `${f.text.length.toLocaleString()} chars`;
      if (info.format === 'xlsx') {
        logDebug('error', `${f.name}: Excel workbook (.xlsx), not a log file. Load the raw log, or the Splunk EventTime/PopulatedLog export saved as text.`);
        continue;
      }
      if (info.format === 'binary') {
        logDebug('error', `${f.name}: binary file (${size}), not a text log. Skipped.`);
        continue;
      }
      if (!info.events) {
        const first = f.text.split(/\r?\n/).find((x) => x.trim()) || '(empty)';
        logDebug('error', `${f.name}: ${size}, no events found. Each event must start with "YYYY-MM-DD hh:mm:ss.mmm ". First line: ${first.slice(0, 160)}`);
        continue;
      }
      const anySource = !window.TraceFlow.matchesAnySource(state, f.name);
      logs.push({ ...f, anySource });
      logDebug('info', `${f.name}: ${size}, format ${info.format}, ${info.events} events`
        + (anySource ? '; name matches no source= pattern, so it is treated as every source' : '; name matches a source= pattern'));
    }
    if (!logs.length) {
      flowRows = [];
      setCount('0 rows');
      document.getElementById('flow-status').textContent = 'No usable log file loaded. See the Debug view for details.';
      renderFlow([]);
      renderDiagram([]);
      renderDebugTable([]);
      showView('debug');
      return;
    }
    refreshFlow();
  }

  document.getElementById('log-files').addEventListener('change', async (e) => {
    const files = [...e.target.files];
    e.target.value = '';
    if (!files.length) return;
    logDebug('info', `Local Test: ${files.map((f) => `${f.name} (${f.size.toLocaleString()} bytes)`).join(', ')}`);
    const read = [];
    for (const f of files) {
      try {
        read.push({ name: f.name, text: await f.text() });
      } catch (err) {
        logDebug('error', `${f.name}: could not be read (${err.message}).`);
      }
    }
    setLogs(read);
  });

  async function loadMock() {
    try {
      const names = ['spl-banking-mock.log', 'spl-ms-mock.log'];
      const texts = await Promise.all(names.map(async (n) => {
        const res = await fetch('mock/' + n);
        if (!res.ok) throw new Error(`${n}: HTTP ${res.status}`);
        return res.text();
      }));
      if (mode !== 'mock') return; // the user switched tabs while loading
      document.getElementById('use-terms').checked = false;
      logDebug('info', 'Mock Test: ' + names.join(', '));
      setLogs(names.map((name, i) => ({ name, text: texts[i] })));
    } catch (err) {
      document.getElementById('flow-status').textContent = 'Could not load the mock logs: ' + err.message
        + '. Open the page through the local server (python tools/serve.py) or the published site, not as a file.';
      logDebug('error', 'Could not load mock logs: ' + err.message);
    }
  }

  document.getElementById('btn-mock').addEventListener('click', loadMock);

  // Empty flow pane for a tab with nothing loaded yet.
  function clearFlow() {
    flowRows = [];
    document.getElementById('flow-status').textContent = IDLE_STATUS[mode];
    document.getElementById('flow-problem').hidden = true;
    document.getElementById('flow-summary').replaceChildren();
    document.getElementById('session-filter').replaceChildren(el('option', { value: '' }, ['All sessions']));
    renderFlow([]);
    renderDiagram([]);
    renderDebugTable([]);
  }

  // Swap the flow pane to the Load File or Mock Test tab's data.
  function switchMode(next) {
    ctx[mode] = { logs, imported };
    mode = next;
    ({ logs, imported } = ctx[mode]);
    document.getElementById('pane-flow').dataset.mode = mode;
    document.getElementById('pane-flow').setAttribute('aria-labelledby', 'tab-' + mode);
    if (logs.length || imported) {
      refreshFlow();
    } else {
      clearFlow();
      if (mode === 'mock') loadMock();
    }
  }

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

  // Tabs: spl, file, mock. file and mock share #pane-flow, so panes are shown by the selected tab only.
  function showTab(name) {
    const tabs = [...document.querySelectorAll('.tab')];
    const selected = tabs.find((t) => t.dataset.tab === name) || tabs[0];
    tabs.forEach((t) => {
      const on = t === selected;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
    });
    document.querySelectorAll('.pane').forEach((p) => { p.hidden = p.id !== selected.getAttribute('aria-controls'); });
    if ((selected.dataset.tab === 'file' || selected.dataset.tab === 'mock') && selected.dataset.tab !== mode) switchMode(selected.dataset.tab);
    try { localStorage.setItem(TAB_KEY, selected.dataset.tab); } catch (e) { /* ignore */ }
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

  renderAll();
  clearFlow();

  // Demo links: index.html#mock opens the Mock Test tab; #mock/diagram, #mock/sequence
  // and #mock/debug open it on that view. Otherwise reopen the last tab (the old
  // single Flow tab maps to Load File).
  let savedTab = 'spl';
  try { savedTab = localStorage.getItem(TAB_KEY) || 'spl'; } catch (e) { /* ignore */ }
  if (location.hash.startsWith('#mock')) {
    const view = location.hash.split('/')[1];
    if (['diagram', 'sequence', 'debug'].includes(view)) showView(view);
    showTab('mock');
  } else {
    showTab({ flow: 'file', file: 'file', mock: 'mock' }[savedTab] || 'spl');
  }
})();
