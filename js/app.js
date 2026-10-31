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
        { key: 'match', label: 'Condition', placeholder: 'match(_raw,"OPIAppLog")', size: 'l' },
      ],
      blank: () => ({ name: '', layer: 3, match: '' }),
    },
    directions: {
      fields: [
        { key: 'layer', label: 'Layer', size: 's', list: 'dl-layers' },
        { key: 'pattern', label: 'Regex', placeholder: '(?i)Request Message', size: 'l' },
        { key: 'direction', label: 'Direction', type: 'select', options: ['Request', 'Response'], size: 's' },
      ],
      blank: () => ({ layer: '', pattern: '', direction: 'Request' }),
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

  renderAll();
})();
