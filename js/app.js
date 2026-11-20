'use strict';
// TraceZLine page: list editors for each config section, live SPL preview.
(function () {
  const STORAGE_KEY = 'tracezline.config.v1';
  const { DEFAULT_CONFIG, clone, generate, generateLogs, validate, parseTerms } = window.TraceSpl;

  const COLUMN_SUGGESTIONS = ['Step', 'EventTime', 'sessionId', 'Flow', 'Params', 'ElapsedMs',
    'LayerName', 'Layer', 'Direction', 'API', 'Endpoint', 'URL', 'SvcCode', 'HostPairs',
    'ServiceInfo', 'transactionRef', 'transactionCode', '_raw'];

  // Field specs per list section. Columns are stored as plain strings.
  const SECTIONS = {
    sources: {
      fields: [
        { key: 'enabled', type: 'checkbox', label: 'On' },
        { key: 'source', label: 'source=', placeholder: '/var/log/pods/app-*.log', size: 'm' },
        { key: 'filter', label: 'Key filter', placeholder: '"[Marker]"', size: 'l', multiline: true },
        { key: 'dirFilter', label: 'Direction filter', placeholder: '("Request" OR "Response")', size: 'l', multiline: true },
      ],
      blank: () => ({ enabled: true, source: '', filter: '', dirFilter: '' }),
    },
    layers: {
      fields: [
        { key: 'name', label: 'Name', placeholder: 'OPI', size: 's' },
        { key: 'layer', label: 'Layer #', type: 'number', size: 'xs' },
        { key: 'subLayer', label: 'Sub-layer #', type: 'number', size: 'xs' },
        { key: 'indent', label: 'Indent', placeholder: '(none)', size: 'xs' },
        { key: 'match', label: 'Condition', placeholder: 'match(_raw,"OPIAppLog")', size: 'l' },
      ],
      blank: () => ({ name: '', layer: 3, subLayer: 0, indent: '', match: '' }),
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
        { key: 'field', label: 'Field', placeholder: 'OPIEndpoint', size: 's' },
        { key: 'layer', label: 'Layer', size: 's', list: 'dl-layers' },
        { key: 'rex', label: 'rex', placeholder: '(?<OPIEndpoint>/[^\\s]+)', size: 'l' },
      ],
      blank: () => ({ field: '', layer: '', rex: '' }),
    },
    sessionRules: {
      fields: [
        { key: 'field', label: 'Field', placeholder: 'sidOpi', size: 's' },
        { key: 'rex', label: 'rex', placeholder: 'sessionId\\"\\:\\"(?<sidOpi>[0-9a-fA-F-]{36})', size: 'l' },
      ],
      blank: () => ({ field: '', rex: '' }),
    },
    sessionOrder: {
      fields: [
        { key: 'layer', label: 'Layer', size: 's', list: 'dl-layers' },
        { key: 'fields', label: 'Session rules, in order', placeholder: 'sidEcomm, sidSessionId', size: 'l' },
      ],
      blank: () => ({ layer: '', fields: '' }),
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
    // Settings saved before SubLayer existed: take the default for a layer of the same name, else 0.
    out.layers.forEach((l) => {
      if (l && typeof l === 'object' && l.subLayer === undefined) {
        l.subLayer = DEFAULT_CONFIG.layers.find((d) => d.name === String(l.name).trim())?.subLayer ?? 0;
      }
    });
    // Settings saved before the wildcard: Splunk indexes [ENQWSAppLog] as one token, so the
    // term "WSAppLog" alone misses it.
    out.sources.forEach((s) => {
      if (s && typeof s.filter === 'string') s.filter = s.filter.replace(/"WSAppLog"/g, '"*WSAppLog*"');
    });
    // Settings saved with the old two default sources (one per log file): the default is now
    // one source per layer marker. Edited sources are kept as they are.
    const OLD_SOURCES = [
      ['/var/log/pods/spl-banking-*log', '("[SPLMessage]" OR "[SPLHostMessage]")'],
      ['/var/log/pods/spl-ms-*log', '("*WSAppLog*" ("request:" OR "RESPONSE from" OR "Response:")) OR ("<EAI>" "<SvcCode>" ("Request Message" OR "Response Message"))'],
    ];
    // Session rules saved as one of the earlier default sets: the five rules now (sessionId,
    // sessionIdentity, [SPLMessage], [SPLHostMessage], WLS:). Edited rule sets are kept.
    const OLD_SID_SETS = [
      [['sidEcomm', String.raw`(?i)\[SPLMessage\]\s*\[?(?<sidEcomm>[0-9a-fA-F-]{36})`], ['sidEnterprise', String.raw`(?i)\[SPLHostMessage\]\s*\[?(?<sidEnterprise>[0-9a-fA-F-]{36})`], ['sidWls', String.raw`(?i)\bWLS:\s*(?<sidWls>[0-9a-fA-F-]{36})`], ['sidAny', String.raw`(?<sidAny>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`]],
      [['sidEcomm', String.raw`(?i)\[SPLMessage\](?:\s*\[?|[\s\S]*?\"session(?:Id|Identity)\"\s*:\s*\")(?<sidEcomm>[0-9a-fA-F-]{36})`], ['sidEnterprise', String.raw`(?i)\[SPLHostMessage\](?:\s*\[?|[\s\S]*?\"session(?:Id|Identity)\"\s*:\s*\")(?<sidEnterprise>[0-9a-fA-F-]{36})`], ['sidWls', String.raw`(?i)(?:\bWLS:\s*|WSAppLog(?![\s\S]*\bWLS:)[\s\S]*?\"session(?:Id|Identity)\"\s*:\s*\")(?<sidWls>[0-9a-fA-F-]{36})`], ['sidAny', String.raw`(?<sidAny>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`]],
      [['sidSessionId', String.raw`\"sessionId\"\s*:\s*\"(?<sidSessionId>[0-9a-fA-F-]{36})`], ['sidSessionIdentity', String.raw`\"sessionIdentity\"\s*:\s*\"(?<sidSessionIdentity>[0-9a-fA-F-]{36})`], ['sidEcomm', String.raw`(?i)\[SPLMessage\]\s*\[?(?<sidEcomm>[0-9a-fA-F-]{36})`], ['sidEnterprise', String.raw`(?i)\[SPLHostMessage\]\s*\[?(?<sidEnterprise>[0-9a-fA-F-]{36})`], ['sidWls', String.raw`(?i)\bWLS:\s*(?<sidWls>[0-9a-fA-F-]{36})`]],
      [['sidSessionId', String.raw`\"sessionId\"\s*:\s*\"(?<sidSessionId>[^\"]+)\"`], ['sidSessionIdentity', String.raw`\"sessionIdentity\"\s*:\s*\"(?<sidSessionIdentity>[0-9a-fA-F-]{36})`], ['sidEcomm', String.raw`(?i)\[SPLMessage\]\s*\[?(?<sidEcomm>[0-9a-fA-F-]{36})`], ['sidEnterprise', String.raw`(?i)\[SPLHostMessage\]\s*\[?(?<sidEnterprise>[0-9a-fA-F-]{36})`], ['sidWls', String.raw`(?i)\bWLS:\s*(?<sidWls>[0-9a-fA-F-]{36})`]],
      [['sidSessionId', String.raw`\"sessionId\"\s*:\s*\"(?<sidSessionId>[^\"]+)\"`], ['sidSessionIdentity', String.raw`\"sessionIdentity\"\s*:\s*\"(?<sidSessionIdentity>[^\"]+)\"`], ['sidEcomm', String.raw`(?i)\[SPLMessage\]\s*\[?(?<sidEcomm>[0-9a-fA-F-]{36})`], ['sidEnterprise', String.raw`(?i)\[SPLHostMessage\]\s*\[?(?<sidEnterprise>[0-9a-fA-F-]{36})`], ['sidWls', String.raw`(?i)\bWLS:\s*(?<sidWls>[0-9a-fA-F-]{36})`]],
      [['sidSessionId', String.raw`\"sessionId\"\s*:\s*\"(?<sidSessionId>[^\"]+)\"`], ['sidSessionIdentity', String.raw`\"sessionIdentity\"\s*:\s*\"(?<sidSessionIdentity>[^\"]+)\"`], ['sidEcomm', String.raw`(?i)\[SPLMessage\]\s*\[?(?<sidEcomm>[^\"]+)\"`], ['sidEnterprise', String.raw`(?i)\[SPLHostMessage\]\s*\[?(?<sidEnterprise>[0-9a-fA-F-]{36})`], ['sidWls', String.raw`(?i)\bWLS:\s*(?<sidWls>[0-9a-fA-F-]{36})`]],
    ];
    const sidKey = (rules) => JSON.stringify(rules.map((r) => [r && r.field, r && r.rex]));
    // sidEcomm / sidEnterprise saved as (?i)\[Marker\]\s*\[?(?<field>[^\"]+)\" (any marker): the
    // bracket form now, with the same marker.
    out.sessionRules.forEach((r) => {
      const f = r && (r.field === 'sidEcomm' || r.field === 'sidEnterprise') ? r.field : null;
      const m = f && String(r.rex).match(new RegExp(String.raw`^\(\?i\)(\\\[.+?\\\])\\s\*\\\[\?\(\?<${f}>\[\^\\"\]\+\)\\"$`));
      if (m) r.rex = `(?i)${m[1]}\\[(?<${f}>[^\\]]+)\\]`;
      // sidWls saved as the UUID-only default: any value up to a space or |
      if (r && r.field === 'sidWls' && r.rex === String.raw`(?i)\bWLS:\s*(?<sidWls>[0-9a-fA-F-]{36})`) {
        r.rex = DEFAULT_CONFIG.sessionRules.find((d) => d.field === 'sidWls').rex;
      }
    });
    if (OLD_SID_SETS.some((set) => JSON.stringify(set) === sidKey(out.sessionRules))) out.sessionRules = clone(DEFAULT_CONFIG.sessionRules);
    // Endpoint rules saved before they were the eComm and Enterprise rules, and before they were
    // named eCommEndpoint / EnterpriseEndpoint: field -> [its earlier default rex] and the field now.
    const OLD_EP = {
      Endpoint1: {
        now: 'eCommEndpoint',
        rex: [String.raw`\]\s*-\s*(?<Endpoint1>[^\s\[\]]*/\S*)\s+-`,
          String.raw`\]\s*(?:-\s*)?(?<Endpoint1>(?:/[^\s\[\]/]+)+|[^\s\[\]/-][^\s\[\]/]*(?:/[^\s\[\]/]+)+)\s*-`,
          String.raw`(?i)\[SPLMessage\][\s\S]*?\]\s*(?:-\s*)?(?<Endpoint1>(?:/[^\s\[\]/]+)+|[^\s\[\]/-][^\s\[\]/]*(?:/[^\s\[\]/]+)+)\s*-\s*(?:\[?(?:Request|Response)\b|\{|\r?\n|$)`],
      },
      EnterpriseEndpoint: { now: 'EnterpriseEndpoint', rex: [String.raw`(?:\s+-|\s+)(?<EnterpriseEndpoint>/\S+)\s*-\s*\[(?:Request|Response)\]`, String.raw`\s*-\s*(?<EnterpriseEndpoint>/\S+)\s*-\s*\[(?:Request|Response)\]`, String.raw`(?i)\[SPLHostMessage\][\s\S]*?\]\s*(?:-\s*)?(?<EnterpriseEndpoint>(?:/[^\s\[\]/]+)+|[^\s\[\]/-][^\s\[\]/]*(?:/[^\s\[\]/]+)+)\s*-\s*\[(?:Request|Response)\]`] },
      eCommEndpoint: {
        now: 'eCommEndpoint',
        rex: [String.raw`(?i)\[SPLMessage\][\s\S]*?\]\s*(?:-\s*)?(?<eCommEndpoint>(?:/[^\s\[\]/]+)+|[^\s\[\]/-][^\s\[\]/]*(?:/[^\s\[\]/]+)+)\s*-\s*(?:\[?(?:Request|Response)\b|\{|\r?\n|$)`],
      },
      Endpoint2: { now: 'EnterpriseEndpoint', rex: [String.raw`\s\s\s(?<Endpoint2>[^ ]+)\s\-\s(?:'?Request|Response)'`, String.raw`(?i)\[SPLHostMessage\][\s\S]*?\]\s*(?:-\s*)?(?<Endpoint2>(?:/[^\s\[\]/]+)+|[^\s\[\]/-][^\s\[\]/]*(?:/[^\s\[\]/]+)+)\s*-\s*(?:\[?(?:Request|Response)\b|\{|\r?\n|$)`] },
    };
    out.endpointRules.forEach((r) => {
      const old = r && OLD_EP[r.field];
      if (old && old.rex.includes(r.rex)) Object.assign(r, DEFAULT_CONFIG.endpointRules.find((d) => d.field === old.now) || { field: old.now, rex: '' });
      // Endpoint rules saved before they had a layer: the default rule of the same name gives it.
      if (r && r.layer === undefined) r.layer = DEFAULT_CONFIG.endpointRules.find((d) => d.field === r.field)?.layer ?? '';
    });
    // EnterpriseEndpoint saved as one default rule (earlier forms are mapped to it above, with an
    // empty rex): the two rules now (after a comma / after " -").
    const prevEnt = [String.raw`(?:\s+-|\s+)(?<EnterpriseEndpoint>/\S+)\s*-\s*\[(?:Request|Response)\]`, ''];
    const ei = out.endpointRules.findIndex((r) => r && r.field === 'EnterpriseEndpoint' && prevEnt.includes(r.rex));
    if (ei >= 0) out.endpointRules.splice(ei, 1, ...clone(DEFAULT_CONFIG.endpointRules.filter((d) => d.layer === 'Enterprise')));
    // The default Endpoint3 rule (endpoint: … in a payload) is gone: WS uses WSEndpoint (URL and [::…]).
    out.endpointRules = out.endpointRules.filter((r) => !(r && r.field === 'Endpoint3' && r.rex === String.raw`(?i)endpoint\"?\s*[:=]\s*\"?(?<Endpoint3>[^\",]+)`));
    // Direction saved as the earlier default (DirWord + first rule for eComm / Enterprise, rules for
    // Host and WS): the per-layer Request / Response rules now.
    const OLD_DIRECTIONS = JSON.stringify([['Host', '(?i)Request Message', 'Request'], ['Host', '(?i)Response Message', 'Response'],
      ['WS', '(?i)request:', 'Request'], ['WS', '(?i)(RESPONSE from|Response:)', 'Response']]);
    if (out.dirWordRex === String.raw`(?i)\b(?<DirWord>Request|Response)\b`
      && out.directionFirst === 'LayerName="eComm" OR LayerName="Enterprise",case(lower(DirWord)="request","Request",lower(DirWord)="response","Response")'
      && JSON.stringify(out.directions.map((d) => [d.layer, d.pattern, d.direction])) === OLD_DIRECTIONS) {
      out.dirWordRex = DEFAULT_CONFIG.dirWordRex;
      out.directionFirst = DEFAULT_CONFIG.directionFirst;
      out.directions = clone(DEFAULT_CONFIG.directions);
    }
    // WS condition saved as WSAppLog alone: also UFWAspect (and UFWApsect), as in the WS key filter.
    out.layers.forEach((l) => {
      if (l && l.name === 'WS' && l.match === 'match(_raw,"WSAppLog")') l.match = DEFAULT_CONFIG.layers.find((d) => d.name === 'WS').match;
    });
    // Columns saved as the earlier default: Flow instead of ServiceInfo.
    if (JSON.stringify(out.columns) === JSON.stringify(['Step', 'EventTime', 'sessionId', 'ServiceInfo', 'Params', 'ElapsedMs'])) out.columns = clone(DEFAULT_CONFIG.columns);
    // Host condition saved before it was <EAI> AND <SvcCode>.
    out.layers.forEach((l) => {
      if (l && l.name === 'Host' && l.match === String.raw`match(_raw,"<SvcCode>") AND match(_raw,"(?i)(request|response) message")`) {
        l.match = DEFAULT_CONFIG.layers.find((d) => d.name === 'Host').match;
      }
    });
    // eComm / Enterprise source filters saved as an earlier default get the current one.
    out.sources.forEach((s) => {
      if (!s || typeof s.filter !== 'string' || s.dirFilter !== undefined) return;
      if (s.filter === '"[SPLMessage]"' || s.filter === '"[SPLMessage]" ("Request" OR "Response")') s.filter = '"[SPLMessage]" ("- Request -" OR "- Response -")';
      if (s.filter === '"[SPLHostMessage]"' || s.filter === '"[SPLHostMessage]" ("Request" OR "Response")') s.filter = '"[SPLHostMessage]" ("[Request]" OR "[Response]")';
    });
    const same = out.sources.length === OLD_SOURCES.length
      && out.sources.every((s, i) => s && s.enabled && s.source === OLD_SOURCES[i][0] && String(s.filter).trim() === OLD_SOURCES[i][1]);
    if (same) out.sources = clone(DEFAULT_CONFIG.sources);
    // Sources saved as one combined filter: the earlier four defaults are split into key and
    // direction conditions; any other source keeps its filter (with an empty direction filter).
    const COMBINED = [
      '"[SPLMessage]" ("- Request -" OR "- Response -")',
      '"[SPLHostMessage]" ("[Request]" OR "[Response]")',
      '"*WSAppLog*" ("request:" OR "RESPONSE from" OR "Response:")',
      '"<EAI>" "<SvcCode>" ("Request Message" OR "Response Message")',
    ];
    if (out.sources.length === COMBINED.length && out.sources.every((s, i) => s && s.dirFilter === undefined && s.source === DEFAULT_CONFIG.sources[i].source && String(s.filter).trim() === COMBINED[i])) {
      out.sources = out.sources.map((s, i) => ({ ...clone(DEFAULT_CONFIG.sources[i]), enabled: s.enabled }));
    }
    out.sources.forEach((s) => { if (s && s.dirFilter === undefined) s.dirFilter = ''; });
    // eComm / Enterprise saved with one marker (key filter, layer condition, session rule): also
    // [MightyMessage] / [MightyHostMessage]. Edited values are kept.
    [['eComm', '"[SPLMessage]"', '("- Request -" OR "- Response -")', String.raw`match(_raw,"\[SPLMessage\]")`,
      'sidEcomm', String.raw`(?i)\[SPLMessage\]\[(?<sidEcomm>[^\]]+)\]`],
    ['Enterprise', '"[SPLHostMessage]"', '("[Request]" OR "[Response]")', String.raw`match(_raw,"\[SPLHostMessage\]")`,
      'sidEnterprise', String.raw`(?i)\[SPLHostMessage\]\[(?<sidEnterprise>[^\]]+)\]`],
    ].forEach(([layer, filter, dirFilter, match, field, rex]) => {
      const now = DEFAULT_CONFIG.sources.find((d) => d.dirFilter === dirFilter);
      out.sources.forEach((s) => { if (s && s.filter === filter && s.dirFilter === dirFilter) s.filter = now.filter; });
      out.layers.forEach((l) => { if (l && l.name === layer && l.match === match) l.match = DEFAULT_CONFIG.layers.find((d) => d.name === layer).match; });
      out.sessionRules.forEach((r) => { if (r && r.field === field && r.rex === rex) r.rex = DEFAULT_CONFIG.sessionRules.find((d) => d.field === field).rex; });
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
        // A marker renamed in a source filter is renamed in the layer logic too, once the
        // edit is done (not per keystroke, so half-typed text is not copied around).
        if (name === 'sources' && (f.key === 'filter' || f.key === 'dirFilter')) {
          let before = input.value;
          input.addEventListener('focus', () => { before = input.value; });
          input.addEventListener('change', () => {
            const changed = window.TraceSpl.renameMarker(state, before, input.value);
            before = input.value;
            if (!changed.length) return;
            ['layers', 'sessionRules', 'endpointRules', 'directions'].forEach(renderList);
            update();
            toast('Also updated: ' + changed.join(', '));
          });
        }
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
    document.getElementById('drop-no-direction').checked = state.dropNoDirection;
    document.getElementById('dir-word-rex').value = state.dirWordRex;
    document.getElementById('dir-first').value = state.directionFirst;
    document.getElementById('start-time').value = state.startTime || '';
    document.getElementById('end-time').value = state.endTime || '';
    document.querySelectorAll('.time-box input').forEach((b) => b.classList.remove('invalid'));
    limitTimePickers();
    refreshDatalists();
    update();
  }

  function update() {
    const text = generate(state);
    document.getElementById('spl').textContent = text;
    document.getElementById('line-count').textContent = (text.trimEnd().split('\n').length) + ' lines';
    document.getElementById('spl-logs').textContent = generateLogs(state);
    const n = state.terms.filter((t) => t.trim()).length;
    document.getElementById('terms-count').textContent = n + (n === 1 ? ' term' : ' terms');
    const warnings = validate(state);
    document.getElementById('warnings').replaceChildren(...warnings.map((w) => el('li', {}, [w])));
    save();
    refreshFlow();
    // Settings change how the logs are read, so the comparison is redone too.
    if (cmp.excel && cmp.logs.length) runCompare();
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

  document.getElementById('drop-no-direction').addEventListener('change', (e) => {
    state.dropNoDirection = e.target.checked;
    update();
  });

  // Start / End time are typed into a text box (2026-10-26 09:30, 2026/10/26 09:30:15.250,
  // 10/26/2026:09:30:00 …) or picked with the calendar button, which opens the browser's
  // date-time picker. The settings keep "2026-11-18 15:28:25.554".
  const timeBox = (key) => document.getElementById(key === 'startTime' ? 'start-time' : 'end-time');
  const timePicker = (id) => document.querySelector(`.time-picker[data-for="${id}"]`);
  function toPicker(v) {
    return window.TraceSpl.parseTime(v) == null ? '' : String(v).trim().replace(' ', 'T');
  }
  // Start time must be earlier than End time: each calendar is limited by the other (it greys
  // out the rest), and a value that breaks the order is refused.
  function limitTimePickers() {
    timePicker('end-time').min = toPicker(state.startTime);
    timePicker('start-time').max = toPicker(state.endTime);
  }
  // A typed value counts once it reads as a time (or the box is empty); until then the box is
  // marked and the query keeps the last good value. Leaving the box tidies the text.
  function setTime(key, text, fromPicker) {
    const box = timeBox(key);
    const next = text.trim() === '' ? '' : window.TraceSpl.normaliseTime(text);
    if (next == null) {
      box.classList.add('invalid');
      box.title = 'Not a time yet: use e.g. 2026-10-26 09:30:00.000';
      return;
    }
    const from = window.TraceSpl.parseTime(key === 'startTime' ? next : state.startTime);
    const to = window.TraceSpl.parseTime(key === 'endTime' ? next : state.endTime);
    if (from != null && to != null && from >= to) {
      box.classList.add('invalid');
      box.title = 'Start time must be earlier than End time';
      if (fromPicker) toast('Start time must be earlier than End time');
      return;
    }
    box.classList.remove('invalid');
    box.title = '';
    if (fromPicker) box.value = next;
    if (next === state[key]) return;
    state[key] = next;
    limitTimePickers();
    update();
    // the other box may have been refused only because of the order: check it again
    const other = key === 'startTime' ? 'endTime' : 'startTime';
    if (timeBox(other).classList.contains('invalid')) setTime(other, timeBox(other).value, false);
  }
  [['start-time', 'startTime'], ['end-time', 'endTime']].forEach(([id, key]) => {
    const box = document.getElementById(id);
    box.addEventListener('input', () => setTime(key, box.value, false));
    box.addEventListener('change', () => {
      if (!box.classList.contains('invalid')) box.value = state[key] || '';
      else if (box.title.startsWith('Start time')) toast('Start time must be earlier than End time');
    });
    const picker = timePicker(id);
    picker.addEventListener('input', () => {
      const m = picker.value.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/);
      if (m) setTime(key, `${m[1]} ${m[2]}:${m[3] || '00'}.${(m[4] || '0').padEnd(3, '0')}`, true);
    });
    document.querySelector(`.time-pick[data-for="${id}"]`).addEventListener('click', () => {
      picker.value = toPicker(state[key]);
      try { picker.showPicker(); } catch (e) { picker.focus(); picker.click(); }
    });
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

  async function copyQuery(text, pre) {
    try {
      await navigator.clipboard.writeText(text);
      toast('SPL copied');
    } catch (e) {
      const range = document.createRange();
      range.selectNodeContents(document.getElementById(pre));
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      toast('Clipboard blocked: SPL selected, press Ctrl+C');
    }
  }

  document.getElementById('btn-copy').addEventListener('click', () => copyQuery(generate(state), 'spl'));
  document.getElementById('btn-copy-logs').addEventListener('click', () => copyQuery(generateLogs(state), 'spl-logs'));

  document.getElementById('btn-download').addEventListener('click', () => {
    download('tracezline-query.spl', generate(state), 'text/plain');
  });
  document.getElementById('btn-download-logs').addEventListener('click', () => {
    download('tracezline-logs.spl', generateLogs(state), 'text/plain');
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

  // The Flow Analysis and Mock Test tabs share the flow pane; each keeps its own data.
  // `logs` and `imported` always hold the current tab's data; the other tab's waits in ctx.
  let mode = 'file';
  const ctx = { file: { logs: [], imported: null }, mock: { logs: [], imported: null } };
  const IDLE_STATUS = {
    file: 'Local File loads raw log files (or a Splunk EventTime/PopulatedLog export) and runs this query\'s logic on them; Upload in the Flow view loads the flow table exported from Splunk. Files are read in this browser only and never uploaded. The result updates as you edit the settings on the left.',
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
      const range = window.TraceSpl.timeRange(state);
      const inRange = (r) => !range || ((range.from == null || r.time >= range.from) && (range.to == null || r.time <= range.to));
      flowRows = imported.rows.filter((r) => (!terms.length || rowHasTerm(r, terms)) && inRange(r));
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
    const noSid = flowRows.filter((r) => r.sessionId == null || r.sessionId === 'NA').length;
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
    renderStepRanges();
    renderDiagram(selectedRows());
    renderLogFiles();
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
    showTermsProblem(all.map((s) => s.sessionId).filter((id) => id !== 'NA'), show);
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
  let diagramRows = [];

  // Diagram options shared by the Sequence and PlantUML views, kept in this browser:
  // one diagram for all sessions, notes, elapsed times. The same checkbox sits in both views.
  // Defaults: one diagram for all sessions, without notes or elapsed times.
  const diagramOpts = { combine: true, notes: false, elapsed: false };
  [['combine', '.combine-sessions', 'tracezline.combineSessions'],
    ['notes', '.seq-notes', 'tracezline.seqNotes'],
    ['elapsed', '.seq-elapsed', 'tracezline.seqElapsed']].forEach(([opt, selector, key]) => {
    try { const v = localStorage.getItem(key); if (v != null) diagramOpts[opt] = v === '1'; } catch (e) { /* ignore */ }
    const boxes = document.querySelectorAll(selector);
    boxes.forEach((box) => {
      box.checked = diagramOpts[opt];
      box.addEventListener('change', () => {
        diagramOpts[opt] = box.checked;
        boxes.forEach((b) => { b.checked = box.checked; });
        try { localStorage.setItem(key, box.checked ? '1' : '0'); } catch (e) { /* ignore */ }
        renderDiagram(diagramRows);
      });
    });
  });

  // Steps per session (PlantUML and Sequence views): rows of { sessionId, from, to }; not saved.
  // The first row starts as All sessions, so it works like one step range for every session.
  let stepRangeRows = [{ sessionId: '', from: '', to: '' }];
  function renderStepRanges() {
    const sessions = window.TraceFlow.summarize(flowRows);
    const list = document.getElementById('step-range-list');
    list.replaceChildren(...stepRangeRows.map((g, i) => {
      const pick = el('select', { 'aria-label': 'Session' }, [
        el('option', { value: '' }, ['All sessions']),
        ...sessions.map((s) => el('option', { value: s.sessionId }, [`${s.sessionId} (${s.steps} steps)`])),
      ]);
      if (!sessions.some((s) => s.sessionId === g.sessionId)) g.sessionId = ''; // that session is no longer loaded
      pick.value = g.sessionId;
      pick.addEventListener('change', () => { g.sessionId = pick.value; renderDiagram(diagramRows); });
      const num = (key, label, hint) => {
        const input = el('input', { type: 'number', min: '1', step: '1', placeholder: hint, 'aria-label': label });
        input.value = g[key];
        input.addEventListener('input', () => { g[key] = input.value; renderDiagram(diagramRows); });
        return input;
      };
      return el('div', { class: 'step-range' }, [
        pick, 'Steps', num('from', 'From step', 'first'), 'to', num('to', 'To step', 'last'),
        iconBtn('✕', 'Remove', stepRangeRows.length === 1, () => { stepRangeRows.splice(i, 1); renderStepRanges(); renderDiagram(diagramRows); }),
      ]);
    }));
  }
  document.getElementById('step-range-add').addEventListener('click', () => {
    // a new row picks the first session not used yet
    const used = new Set(stepRangeRows.map((g) => g.sessionId));
    const next = window.TraceFlow.summarize(flowRows).find((s) => !used.has(s.sessionId));
    stepRangeRows.push({ sessionId: next ? next.sessionId : '', from: '', to: '' });
    renderStepRanges();
    renderDiagram(diagramRows);
  });

  function renderDiagram(rows) {
    diagramRows = rows;
    // the diagrams show the chosen steps; Processing Rule below keeps all of them
    const all = rows;
    rows = window.TraceFlow.stepRanges(rows, stepRangeRows);
    pumlText = window.TraceFlow.toPlantUml(rows, state, diagramOpts);
    document.getElementById('puml').textContent = pumlText || '(no sessions)';
    // Images belong to the previous text; drop them so they never show a stale flow.
    document.getElementById('puml-images').replaceChildren();
    ['btn-copy-puml', 'btn-download-puml', 'btn-render-puml'].forEach((id) => {
      document.getElementById(id).disabled = !pumlText;
    });

    // render() escapes every log-derived string, so the markup is safe to insert.
    const models = window.TraceFlow.sequenceModel(rows, state);
    const views = models.map((d) => window.TraceFlow.viewDiagram(d, diagramOpts));
    const shown = diagramOpts.combine ? window.TraceFlow.combineDiagrams(views) : views;
    svgs = shown.map((d) => ({ sessionId: d.sessionId, svg: window.TraceSequence.render(d) }));
    const host = document.getElementById('sequence');
    host.innerHTML = svgs.map((s) => `<figure class="seq-fig">${s.svg}</figure>`).join('');
    if (!svgs.length) host.textContent = '(no sessions)';
    document.getElementById('btn-svg').disabled = !svgs.length;
    renderRules(rows === all ? models : window.TraceFlow.sequenceModel(all, state));
  }

  // ---------- processing rules ----------

  let rulesMd = '';

  // Tables built with el(), so log-derived text is never parsed as HTML.
  function renderRules(models) {
    const host = document.getElementById('rules');
    ['btn-copy-rules', 'btn-download-rules'].forEach((id) => { document.getElementById(id).disabled = !models.length; });
    if (!models.length) {
      rulesMd = '';
      host.replaceChildren(el('p', { class: 'note' }, ['No sessions to analyse.']));
      return;
    }
    const r = window.TraceRules.analyze(models);
    rulesMd = window.TraceRules.toMarkdown(r);
    // API = layer + endpoint; Description = one sentence per line
    const apiCell = (api) => {
      const [layer, ...rest] = api.split(' ');
      return [el('div', { class: 'hint' }, [layer]), el('code', {}, [rest.join(' ')])];
    };
    host.replaceChildren(
      el('p', { class: 'rules-head' }, [`${r.sessions} sessions · ${r.calls} calls · ${r.distinctApis} distinct APIs · ${r.svcCodes} SvcCodes. `
        + 'From the Flow rows and the Sequence call tree. A rule seen in one session is a single-sample observation, not a confirmed rule.']),
      ...(r.sessions < 2 ? [el('p', { class: 'problem' }, ['Only one session: every rule below is a hypothesis until more sessions confirm it.'])] : []),
      el('div', { class: 'table-wrap rules-table' }, [el('table', {}, [
        el('thead', {}, [el('tr', {}, [el('th', {}, ['API']), el('th', {}, ['Description'])])]),
        el('tbody', {}, r.apis.map((x) => el('tr', {}, [
          el('td', { class: 'api' }, apiCell(x.api)),
          el('td', {}, x.description.map((s) => el('div', {}, [s]))),
        ]))),
      ])]),
    );
  }

  document.getElementById('btn-copy-rules').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(rulesMd);
      toast('Processing rules copied (Markdown)');
    } catch (e) {
      toast('Clipboard blocked: use Download');
    }
  });

  document.getElementById('btn-download-rules').addEventListener('click', () => {
    download('tracezline-processing-rules.md', rulesMd, 'text/markdown');
  });

  let currentView = 'table';

  function showView(name) {
    currentView = name;
    document.querySelectorAll('.seg-btn').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === name)));
    ['table', 'diagram', 'sequence', 'rules', 'debug', 'logs'].forEach((v) => { document.getElementById('view-' + v).hidden = v !== name; });
    document.querySelectorAll('.view-actions').forEach((s) => { s.hidden = s.dataset.for !== name; });
    document.getElementById('step-ranges').hidden = name !== 'diagram' && name !== 'sequence';
  }

  // ---------- log files preview ----------

  const PREVIEW_MAX_LINES = 5000;
  const EVENT_START = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\s/;

  // Drop-down of the current tab's loaded log files; keeps the chosen file when it is still loaded.
  function renderLogFiles() {
    const select = document.getElementById('log-file-select');
    const keep = select.value;
    select.replaceChildren(...logs.map((l) => el('option', { value: l.name }, [l.name])));
    if (logs.some((l) => l.name === keep)) select.value = keep;
    renderLogPreview();
  }

  // Shows the chosen file with line numbers; lines that start an event are highlighted.
  function renderLogPreview() {
    const info = document.getElementById('log-file-info');
    const pre = document.getElementById('log-preview');
    const log = logs.find((l) => l.name === document.getElementById('log-file-select').value);
    if (!log) {
      info.textContent = 'No log files loaded.';
      pre.replaceChildren();
      return;
    }
    const lines = log.text.replace(/\r/g, '').replace(/\n$/, '').split('\n');
    const events = lines.filter((l) => EVENT_START.test(l)).length;
    info.textContent = `${log.name}: ${events} events, ${lines.length.toLocaleString()} lines, ${log.text.length.toLocaleString()} characters.`
      + ' Highlighted lines start an event.'
      + (lines.length > PREVIEW_MAX_LINES ? ` Showing the first ${PREVIEW_MAX_LINES.toLocaleString()} lines.` : '');
    const width = String(Math.min(lines.length, PREVIEW_MAX_LINES)).length;
    pre.replaceChildren(...lines.slice(0, PREVIEW_MAX_LINES).map((line, i) => el('div', { class: EVENT_START.test(line) ? 'ln ev' : 'ln' }, [
      el('span', { class: 'ln-no' }, [String(i + 1).padStart(width)]),
      line,
    ])));
    pre.scrollTop = 0;
  }

  document.getElementById('log-file-select').addEventListener('change', renderLogPreview);

  document.getElementById('seq-fit').addEventListener('change', (e) => {
    document.getElementById('sequence').classList.toggle('fit', e.target.checked);
  });

  // One file per session (one file when combined or with one session selected).
  document.getElementById('btn-svg').addEventListener('click', () => {
    svgs.forEach((s) => download(`tracezline-sequence-${s.sessionId}.svg`, s.svg, 'image/svg+xml'));
  });

  document.querySelectorAll('.seg-btn').forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));

  document.getElementById('btn-copy-puml').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pumlText);
      toast('PlantUML copied');
    } catch (e) {
      toast('Clipboard blocked: use Download');
    }
  });

  document.getElementById('btn-download-puml').addEventListener('click', () => {
    download('tracezline-flow.puml', pumlText, 'text/plain');
  });

  // Rendering sends the diagram text to plantuml.com, so it always asks first.
  document.getElementById('btn-render-puml').addEventListener('click', async () => {
    if (!confirm('Render sends the diagram text (endpoints, session IDs, Params values) to www.plantuml.com.\n\n'
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
    await importResult(file, await file.arrayBuffer());
  });

  // An Excel / CSV Splunk result ({ name }, bytes) becomes the Flow Analysis rows.
  async function importResult(file, buffer) {
    try {
      const table = await window.TraceImport.readTable(file.name, buffer);
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
  }

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
    logDebug('info', `Local File: ${files.map((f) => `${f.name} (${f.size.toLocaleString()} bytes)`).join(', ')}`);
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

  // Empty flow pane for a tab with nothing loaded yet.
  function clearFlow() {
    flowRows = [];
    document.getElementById('flow-status').textContent = IDLE_STATUS[mode];
    document.getElementById('flow-problem').hidden = true;
    document.getElementById('flow-summary').replaceChildren();
    document.getElementById('session-filter').replaceChildren(el('option', { value: '' }, ['All sessions']));
    renderFlow([]);
    renderStepRanges();
    renderDiagram([]);
    renderDebugTable([]);
    renderLogFiles();
  }

  // Swap the flow pane to another tab's data (only Flow Analysis uses it now).
  function switchMode(next) {
    ctx[mode] = { logs, imported };
    mode = next;
    ({ logs, imported } = ctx[mode]);
    document.getElementById('pane-flow').dataset.mode = mode;
    document.getElementById('pane-flow').setAttribute('aria-labelledby', 'tab-' + mode);
    if (currentView === 'logs') showView('table');
    if (logs.length || imported) refreshFlow();
    else clearFlow();
  }

  // Expand / Collapse buttons (flow pane and Compare) share one page-wide setting.
  document.querySelectorAll('.wide-toggle').forEach((btn) => btn.addEventListener('click', () => {
    const wide = document.body.classList.toggle('flow-wide');
    document.querySelectorAll('.wide-toggle').forEach((b) => {
      b.setAttribute('aria-pressed', String(wide));
      b.textContent = wide ? 'Collapse' : 'Expand';
      b.title = wide ? 'Show the settings again' : 'Hide the settings and use the full page width';
    });
  }));

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

  // ---------- compare ----------

  // The API Analysis tab's own inputs; kept in memory only, like the other loaded files.
  const cmp = { excel: null, logs: [] };
  let cmpResult = null;
  const base = (p) => String(p ?? '').split(/[\\/]/).pop();
  const RAW_PREVIEW = 4000;

  // Every log event, annotated by the query logic where it applies; the mapping uses them all.
  function cmpEvents() {
    const trace = [];
    window.TraceFlow.run(state, cmp.logs, [], trace);
    return trace.map((t) => Object.assign(t.ev, { head: t.head }));
  }

  // Offset field in hours (e.g. 1, -7, 0.5); empty means detect it.
  function cmpOffsetMs() {
    const v = document.getElementById('cmp-offset').value.trim();
    return v === '' || !Number.isFinite(Number(v)) ? null : Math.round(Number(v) * 3600000);
  }

  function runCompare() {
    const status = document.getElementById('cmp-status');
    if (!cmp.excel || !cmp.logs.length) {
      const have = [cmp.excel && `Splunk result ${cmp.excel.name} (${cmp.excel.rows.length} lines)`,
        cmp.logs.length && `log files ${cmp.logs.map((l) => l.name).join(', ')}`].filter(Boolean);
      if (have.length) status.textContent = `Loaded: ${have.join('; ')}. Now load the ${cmp.excel ? 'Log' : 'Excel'} file.`;
      return;
    }
    let events;
    try {
      events = cmpEvents();
    } catch (err) {
      status.textContent = 'Could not read the log files with the current settings: ' + err.message;
      return;
    }
    const toleranceMs = Math.max(0, Number(document.getElementById('cmp-tolerance').value) || 0);
    cmpResult = window.TraceCompare.compare(cmp.excel.rows, events, { toleranceMs, offsetMs: cmpOffsetMs() });
    const r = cmpResult;
    const total = r.rows.length;
    const notMapped = r.rows.filter((x) => !x.l).length;
    document.getElementById('count-compare').textContent = `${r.mapped}/${total} mapped`;
    status.textContent = `${cmp.excel.name} (${total} lines) mapped by timestamp to ${cmp.logs.map((l) => l.name).join(', ')} (${events.length} log events), tolerance ${toleranceMs} ms.`;
    const card = (title, lines, cls) => el('div', { class: 'sum-card' + (cls ? ' ' + cls : '') }, [el('div', { class: 'sum-id' }, [title]), ...lines.map((t) => el('div', {}, [t]))]);
    const sidsX = new Set(cmp.excel.rows.map((x) => x.sessionId).filter(Boolean));
    const sidsL = new Set(events.map((l) => l.sessionId).filter(Boolean));
    document.getElementById('cmp-summary').replaceChildren(
      card('Excel', [`${total} lines, ${sidsX.size} sessions`]),
      card('Log', [`${events.length} events, ${sidsL.size} sessions`, `${r.sharedSessions} sessions in both`]),
      card('Mapping', [`${r.mapped} of ${total} lines mapped: ${r.agreeing} agree, ${r.mapped - r.agreeing} differ`,
        `${notMapped} lines without a log event in the window`, `${r.unmappedLog.length} log events not mapped`], r.unrelated ? 'card-bad' : ''),
      card('Time offset', [`${r.offsetAuto ? 'Detected' : 'Set'}: Excel EventTime = log time ${r.offsetText}`,
        r.offsetAuto ? 'Set Offset (hours) to override.' : 'Clear Offset to detect it again.']),
    );
    document.getElementById('cmp-quality').replaceChildren(
      el('h3', {}, ['Data quality']),
      ...(r.quality.length ? r.quality.map((q, i) => el('details', { class: 'cmp-q', open: r.unrelated && i === 0 }, [
        el('summary', {}, [`${q.kind} (${q.count})`]),
        el('ul', {}, [...q.items.slice(0, 200).map((t) => el('li', {}, [t])), ...(q.items.length > 200 ? [el('li', {}, [`… and ${q.items.length - 200} more`])] : [])]),
      ])) : [el('p', { class: 'note' }, ['Every line mapped to an agreeing log event within the tolerance.'])]),
    );
    document.getElementById('cmp-analysis').hidden = false;
    renderCompareTable();
    ['cmp-copy', 'cmp-csv'].forEach((id) => { document.getElementById(id).disabled = false; });
  }

  // The Splunk line (what it says) first, then where it maps in the log, then the rest of the row.
  const svcLines = (x) => (Array.isArray(x.ServiceInfo) ? x.ServiceInfo : [x.ServiceInfo ?? x.Flow]);
  const logTime = (l) => (l ? new Date(l.time).toISOString().replace('T', ' ').slice(0, 23) : '');
  // The JSON or XML a log event carries as { kind: 'JSON' | 'XML', rows: [[path, value]] },
  // or null; parsed once per event.
  const structCache = new WeakMap();
  function structureOf(ev) {
    if (!structCache.has(ev)) structCache.set(ev, window.TraceCompare.payloadStructure(ev.raw, { sep: '|' }));
    return structCache.get(ev);
  }

  // The event on one line without its timestamp (LogTime shows it).
  const logEventText = (r) => (r.l ? r.l.raw.replace(/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\s+/, '').replace(/\s+/g, ' ').slice(0, 300) : '');
  // On screen the Log column shows a short "Log:" that expands to the raw event ('log');
  // the export gets the event text. 'export' columns appear in Copy/Download only.
  const CMP = [
    ['Step', (r) => (r.x.Step == null ? '' : String(r.x.Step))],
    ['EventTime', (r) => r.x.EventTime],
    ['ServiceInfo', (r) => svcLines(r.x).join('\n'), 'multi'],
    ['Log', logEventText, 'log'],
    // On screen an expandable Parameter / Value table; in Copy/Download "path = value" lines.
    ['Payload', (r) => {
      const s = r.l && structureOf(r.l);
      return s ? `${s.kind}\n` + s.rows.map(([p, v]) => `${p} = ${v}`).join('\n') : '';
    }, 'struct'],
    ['LogRow', (r) => (r.l ? `${base(r.l.source)}:${r.l.lineNo}` : '')],
    ['LogTime', (r) => logTime(r.l)],
    ['Δ ms', (r) => (r.delta == null ? '' : String(r.delta)), 'export'],
    ['Check', (r) => (r.status === 'mapped' ? 'agrees' : r.checks.join('; ')), 'export'],
    ['sessionId', (r) => r.x.sessionId ?? ''],
    ['Params', (r) => (r.x.Params || []).join('\n'), 'multi'],
    ['ElapsedMs', (r) => (r.x.ElapsedMs == null ? '' : String(r.x.ElapsedMs))],
  ];
  const CMP_COLS = CMP.map(([h]) => h);
  const cmpCells = (r) => CMP.map(([, get]) => get(r));

  function renderCompareTable() {
    if (!cmpResult) return;
    const only = document.getElementById('cmp-issues').checked;
    const rows = only ? cmpResult.rows.filter((r) => r.status !== 'mapped') : cmpResult.rows;
    const multi = (s) => String(s).split('\n').map((t, i) => el('div', { class: i ? 'sub' : '' }, [t]));
    const shown = CMP.filter(([, , kind]) => kind !== 'export');
    document.getElementById('cmp-table').replaceChildren(
      el('thead', {}, [el('tr', {}, shown.map(([h]) => el('th', {}, [h])))]),
      // Lines that differ or are not mapped get a coloured edge (CSS) and say why on hover.
      el('tbody', {}, rows.map((r) => el('tr', {
        class: r.status === 'mapped' ? 'dbg-ok' : r.l ? 'dbg-warn' : 'dbg-out',
        ...(r.status === 'mapped' ? {} : { title: r.checks.join('; ') }),
      },
        shown.map(([, get, kind]) => {
          const text = get(r);
          if (kind === 'multi') return el('td', {}, multi(text));
          if (kind === 'issue') return el('td', { class: 'cmp-issue' }, [text]);
          // Log: the matched event as a short "Log:"; hover shows the event text, expanding the raw event.
          if (kind === 'log') {
            return el('td', { class: 'cmp-log' }, r.l ? [el('details', { class: 'cmp-raw' }, [
              el('summary', { title: text, class: 'icon-after' }, ['Log']),
              el('pre', {}, [r.l.raw.length > RAW_PREVIEW ? r.l.raw.slice(0, RAW_PREVIEW) + '\n…' : r.l.raw]),
            ])] : []);
          }
          // Payload: the event's JSON or XML body ("JSON ▸" / "XML ▸") expands to a Parameter / Value table.
          if (kind === 'struct') {
            const s = r.l && structureOf(r.l);
            return el('td', { class: 'cmp-log' }, s ? [el('details', { class: 'cmp-raw cmp-struct' }, [
              el('summary', { title: `${s.rows.length} parameters`, class: 'icon-after' }, [s.kind]),
              el('div', { class: 'cmp-struct-wrap' }, [el('table', {}, [
                el('thead', {}, [el('tr', {}, [el('th', {}, ['Parameter']), el('th', {}, ['Value'])])]),
                el('tbody', {}, s.rows.map(([p, v]) => el('tr', {}, [el('td', {}, [p]), el('td', {}, [v])]))),
              ])]),
            ])] : []);
          }
          return el('td', {}, [text]);
        })))),
    );
  }

  function cmpDelimited(sep) {
    const cell = (s) => (/[",\n\t]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s);
    return [CMP_COLS, ...cmpResult.rows.map(cmpCells)].map((r) => r.map(cell).join(sep)).join('\r\n') + '\r\n';
  }

  // Compare logs: every file with log events counts as every source, so nothing is filtered by name.
  function setCmpLogs(files) {
    cmp.logs = [];
    for (const f of files) {
      const info = window.TraceFlow.describeLog(f.text);
      if (!info.events) { toast(`${f.name}: not a log file (${info.format}); skipped`); continue; }
      cmp.logs.push({ ...f, anySource: true });
    }
    runCompare();
  }

  document.getElementById('cmp-excel').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    try {
      const table = await window.TraceImport.readTable(file.name, await file.arrayBuffer());
      cmp.excel = { name: file.name, ...window.TraceImport.toFlowRows(table, state) };
      runCompare();
    } catch (err) {
      toast(`${file.name}: could not be read as a flow table (${err.message})`);
    }
  });

  document.getElementById('cmp-logs').addEventListener('change', async (e) => {
    const files = [...e.target.files];
    e.target.value = '';
    const read = [];
    for (const f of files) {
      try { read.push({ name: f.name, text: await f.text() }); } catch (err) { toast(`${f.name}: could not be read`); }
    }
    if (read.length) setCmpLogs(read);
  });

  document.getElementById('cmp-mock').addEventListener('click', async () => {
    try {
      const get = async (n) => { const res = await fetch('mock/' + n); if (!res.ok) throw new Error(`${n}: HTTP ${res.status}`); return res; };
      const csv = await (await get('mock-flow.csv')).arrayBuffer();
      cmp.excel = { name: 'mock-flow.csv', ...window.TraceImport.toFlowRows(await window.TraceImport.readTable('mock-flow.csv', csv), state) };
      const names = ['spl-banking-mock.log', 'spl-ms-mock.log'];
      setCmpLogs(await Promise.all(names.map(async (n) => ({ name: n, text: await (await get(n)).text() }))));
    } catch (err) {
      toast('Could not load the mock files: ' + err.message);
    }
  });

  document.getElementById('cmp-tolerance').addEventListener('input', runCompare);
  document.getElementById('cmp-offset').addEventListener('input', runCompare);
  document.getElementById('cmp-issues').addEventListener('change', renderCompareTable);
  document.getElementById('cmp-copy').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(cmpDelimited('\t')); toast('Mapping copied: paste into Excel'); } catch (e) { toast('Clipboard blocked: use Download'); }
  });
  document.getElementById('cmp-csv').addEventListener('click', () => {
    download('tracezline-compare.csv', '﻿' + cmpDelimited(','), 'text/csv');
  });

  // ---------- mask ----------

  // Rules and key are kept in this browser; the files themselves stay in memory only.
  // v2 added rule types; v1 rules are dropped (their key is kept).
  const MASK_KEY = 'tracezline.mask.v2';
  const MASK_TYPES = [['json', 'JSON key'], ['xml', 'XML tag'], ['text', 'Exact text'], ['prepost', 'Pre/Post']];
  const MASK_MODES = [['replace', 'Replace'], ['digits', 'Digits → *'], ['last4', 'Keep last 4'], ['consistent', 'Consistent']];
  const MASK_MATCH_HINT = { json: 'userId', xml: 'UserId', text: 'ABC Company', prepost: '"userId":"' };
  const MASK_PREVIEW_LINES = 3000;
  const randomKey = () => {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  };
  const mask = (() => {
    try {
      const saved = JSON.parse(localStorage.getItem(MASK_KEY) || 'null');
      if (saved && Array.isArray(saved.rules) && typeof saved.key === 'string') {
        // rules saved before the Mighty markers: each session rule goes after its SPL marker's rule
        [['[SPLMessage][', '[MightyMessage]['], ['[SPLHostMessage][', '[MightyHostMessage][']].forEach(([after, pre]) => {
          if (saved.rules.some((r) => r && r.pre === pre)) return;
          const i = saved.rules.findIndex((r) => r && r.pre === after);
          if (i >= 0) saved.rules.splice(i + 1, 0, clone(window.TraceMask.DEFAULT_RULES.find((r) => r.pre === pre)));
        });
        return { ...saved, files: [], results: [] };
      }
    } catch (e) { /* storage blocked or corrupt: defaults */ }
    let key = randomKey();
    try { key = JSON.parse(localStorage.getItem('tracezline.mask.v1') || 'null')?.key || key; } catch (e) { /* ignore */ }
    return { rules: clone(window.TraceMask.DEFAULT_RULES), key, files: [], results: [] };
  })();
  const saveMask = () => {
    try { localStorage.setItem(MASK_KEY, JSON.stringify({ rules: mask.rules, key: mask.key })); } catch (e) { /* ignore */ }
  };

  function renderMaskRules() {
    const counts = mask.rules.map((_, i) => mask.results.reduce((t, r) => t + (r.counts[i] || 0), 0));
    const field = (rule, key, attrs = {}) => {
      const input = el('input', { type: 'text', spellcheck: false, autocomplete: 'off', ...attrs });
      input.value = rule[key] ?? '';
      input.addEventListener('input', () => { rule[key] = input.value; onMaskRulesChanged(); });
      return input;
    };
    const select = (rule, key, options) => {
      const s = el('select', {}, options.map(([v, label]) => el('option', { value: v, selected: v === rule[key] }, [label])));
      s.addEventListener('change', () => { rule[key] = s.value; renderMaskRules(); onMaskRulesChanged(); });
      return s;
    };
    const dash = () => el('span', { class: 'hint' }, ['—']);
    const head = el('thead', {}, [el('tr', {}, ['On', 'Name', 'Type', 'Match', 'Mode', 'Mask', 'Found', ''].map((h) => el('th', {}, [h])))]);
    const body = el('tbody', {}, mask.rules.map((rule, i) => {
      const type = rule.type || 'prepost';
      const on = el('input', { type: 'checkbox', checked: rule.on });
      on.addEventListener('change', () => { rule.on = on.checked; onMaskRulesChanged(); });
      const move = (d) => { const j = i + d; [mask.rules[i], mask.rules[j]] = [mask.rules[j], mask.rules[i]]; renderMaskRules(); onMaskRulesChanged(); };
      // An empty Mask shows what will be used, e.g. <<MASK_USERID>> for the JSON key userId.
      const maskInput = rule.mode === 'replace' ? field(rule, 'mask', { class: 'w-mask', placeholder: window.TraceMask.autoMask(rule) }) : null;
      // Pre/Post rules show both texts in the Match cell: [Pre] … [Post]
      const find = field(rule, 'pre', { class: type === 'prepost' ? 'w-pre short' : 'w-pre', placeholder: MASK_MATCH_HINT[type], title: type === 'prepost' ? 'Pre: text before the value' : '' });
      find.addEventListener('input', () => { if (maskInput) maskInput.placeholder = window.TraceMask.autoMask(rule); });
      return el('tr', { class: rule.on ? '' : 'off' }, [
        el('td', {}, [on]),
        el('td', {}, [field(rule, 'name', { class: 'w-name' })]),
        el('td', {}, [select(rule, 'type', MASK_TYPES)]),
        el('td', { class: 'match' }, type === 'prepost'
          ? [find, el('span', { class: 'hint' }, ['…']), field(rule, 'post', { class: 'w-post', placeholder: '"', title: 'Post: text after the value' })]
          : [find]),
        el('td', {}, [select(rule, 'mode', MASK_MODES)]),
        el('td', {}, [maskInput || dash()]),
        el('td', { class: 'num' }, [mask.results.length ? String(counts[i]) : '']),
        el('td', { class: 'row-btns' }, [
          iconBtn('↑', 'Move up', i === 0, () => move(-1)),
          iconBtn('↓', 'Move down', i === mask.rules.length - 1, () => move(1)),
          iconBtn('✕', 'Remove', false, () => { mask.rules.splice(i, 1); renderMaskRules(); onMaskRulesChanged(); }),
        ]),
      ]);
    }));
    document.getElementById('mask-rules').replaceChildren(head, body);
    document.getElementById('mask-rule-count').textContent = `${mask.rules.filter((r) => r.on).length} of ${mask.rules.length} on`;
  }

  // Masking re-runs shortly after the last edit, not on every keystroke.
  let maskTimer = null;
  function onMaskRulesChanged() {
    saveMask();
    clearTimeout(maskTimer);
    maskTimer = setTimeout(runMask, 250);
  }

  async function runMask() {
    if (!mask.files.length) { renderMaskRules(); return; }
    const status = document.getElementById('mask-status');
    try {
      mask.results = [];
      for (const f of mask.files) {
        const r = await window.TraceMask.maskText(f.text, mask.rules, { key: mask.key });
        mask.results.push({ ...r, name: f.name, left: window.TraceMask.leftovers(r.text, r.fakes) });
      }
    } catch (err) {
      status.textContent = 'Masking failed: ' + err.message;
      return;
    }
    const total = mask.results.reduce((t, r) => t + r.counts.reduce((a, b) => a + b, 0), 0);
    const left = mask.results.reduce((t, r) => t + r.left.length, 0);
    document.getElementById('count-mask').textContent = `${total} masked`;
    status.textContent = `${mask.files.length} file(s): ${total} values masked by ${mask.rules.filter((r) => r.on).length} rules`
      + (left ? `; ${left} values still look sensitive (see below).` : '; nothing else looks sensitive.');
    document.getElementById('mask-download').disabled = false;
    renderMaskRules();
    renderLeftovers();
    const select = document.getElementById('mask-file');
    const keep = select.value;
    select.replaceChildren(...mask.results.map((r) => el('option', { value: r.name }, [r.name])));
    if (mask.results.some((r) => r.name === keep)) select.value = keep;
    renderMaskPreview();
  }

  function renderLeftovers() {
    const box = document.getElementById('mask-leftovers');
    const items = mask.results.flatMap((r) => r.left.map((x) => ({ ...x, file: r.name })));
    box.hidden = !items.length;
    if (!items.length) { box.replaceChildren(); return; }
    // Shown masked: the point is where to look, not to show the value again.
    const hint = (v) => (v.length <= 6 ? '***' : v.slice(0, 3) + '…' + v.slice(-2));
    box.replaceChildren(
      el('p', {}, [`Still looks sensitive after masking (${items.length}). Add a rule for these, or check them before sharing:`]),
      el('ul', {}, items.slice(0, 50).map((x) => el('li', {}, [`${x.file}:${x.line} ${x.kind} ${hint(x.value)}`]))),
      ...(items.length > 50 ? [el('p', {}, [`… and ${items.length - 50} more.`])] : []),
    );
  }

  // The masked text, line numbers, masked values highlighted.
  function renderMaskPreview() {
    const r = mask.results.find((x) => x.name === document.getElementById('mask-file').value) || mask.results[0];
    const pre = document.getElementById('mask-preview');
    if (!r) { pre.replaceChildren(); document.getElementById('mask-file-info').textContent = ''; return; }
    const lines = r.marked.replace(/\r/g, '').split('\n');
    const n = r.counts.reduce((a, b) => a + b, 0);
    document.getElementById('mask-file-info').textContent = `${n} values masked, ${lines.length.toLocaleString()} lines`
      + (lines.length > MASK_PREVIEW_LINES ? `; showing the first ${MASK_PREVIEW_LINES.toLocaleString()}` : '') + '. Highlighted: masked values.';
    const width = String(Math.min(lines.length, MASK_PREVIEW_LINES)).length;
    pre.replaceChildren(...lines.slice(0, MASK_PREVIEW_LINES).map((line, i) => {
      const parts = [el('span', { class: 'ln-no' }, [String(i + 1).padStart(width)])];
      // \u0001value\u0002 marks a masked value
      line.split(/(\u0001[^\u0002]*\u0002)/).forEach((seg) => {
        if (seg.startsWith('\u0001')) parts.push(el('mark', { class: 'masked' }, [seg.slice(1, -1)]));
        else if (seg) parts.push(seg);
      });
      return el('div', { class: 'ln' }, parts);
    }));
    pre.scrollTop = 0;
  }

  async function setMaskFiles(files) {
    mask.files = files;
    mask.results = [];
    await runMask();
  }

  document.getElementById('mask-files').addEventListener('change', async (e) => {
    const files = [...e.target.files];
    e.target.value = '';
    const read = [];
    for (const f of files) {
      try {
        const text = await f.text();
        if (/\u0000/.test(text.slice(0, 4096)) || text.startsWith('PK\u0003\u0004')) { toast(`${f.name}: not a text file; skipped`); continue; }
        read.push({ name: f.name, text });
      } catch (err) { toast(`${f.name}: could not be read`); }
    }
    if (read.length) setMaskFiles(read);
  });

  document.getElementById('mask-mock').addEventListener('click', async () => {
    try {
      const names = ['spl-banking-mock.log', 'spl-ms-mock.log'];
      setMaskFiles(await Promise.all(names.map(async (n) => {
        const res = await fetch('mock/' + n);
        if (!res.ok) throw new Error(`${n}: HTTP ${res.status}`);
        return { name: n, text: await res.text() };
      })));
    } catch (err) {
      toast('Could not load the mock logs: ' + err.message);
    }
  });

  document.getElementById('mask-download').addEventListener('click', () => {
    mask.results.forEach((r) => download(window.TraceMask.maskedName(r.name), r.text, 'text/plain'));
  });

  document.getElementById('mask-file').addEventListener('change', renderMaskPreview);

  const keyInput = document.getElementById('mask-key');
  keyInput.value = mask.key;
  keyInput.addEventListener('input', () => { mask.key = keyInput.value || 'tracezline'; onMaskRulesChanged(); });
  document.getElementById('mask-newkey').addEventListener('click', () => {
    mask.key = randomKey();
    keyInput.value = mask.key;
    onMaskRulesChanged();
  });

  document.getElementById('mask-add').addEventListener('click', () => {
    mask.rules.push({ on: true, name: 'New rule', type: 'json', pre: '', post: '', mode: 'replace', mask: '' });
    renderMaskRules();
    saveMask();
    const rows = document.querySelectorAll('#mask-rules tbody tr');
    rows[rows.length - 1]?.querySelector('.w-pre')?.focus();
  });

  document.getElementById('mask-reset').addEventListener('click', () => {
    if (!confirm('Replace the mask rules with the defaults?')) return;
    mask.rules = clone(window.TraceMask.DEFAULT_RULES);
    renderMaskRules();
    onMaskRulesChanged();
  });

  renderMaskRules();

  // ---------- tabs ----------

  // ---------- run in Splunk ----------

  // URL, username and the certificate choice are kept in this browser; the password is not.
  const SPLUNK_KEY = 'tracezline.splunk';
  const splunkEls = Object.fromEntries(['mode', 'url', 'user', 'pass', 'range', 'insecure', 'note', 'status', 'csv'].map((k) => [k, document.getElementById('splunk-' + k)]));
  // REST API on the management port, or Splunk Web (the browser UI) when only that is reachable
  const splunkPlaceholder = () => { splunkEls.url.placeholder = splunkEls.mode.value === 'web' ? 'https://splunk-host:8000' : 'https://splunk-host:8089'; };
  const splunkBtn = (k) => document.getElementById('btn-splunk-' + k);
  let splunkResult = null; // { sid, csv }
  try {
    const saved = JSON.parse(localStorage.getItem(SPLUNK_KEY) || '{}');
    splunkEls.mode.value = saved.mode === 'web' ? 'web' : 'rest';
    if (typeof saved.range === 'string' && [...splunkEls.range.options].some((o) => o.value === saved.range)) splunkEls.range.value = saved.range;
    splunkEls.url.value = saved.url || '';
    splunkEls.user.value = saved.user || '';
    splunkEls.insecure.checked = !!saved.insecure;
  } catch (e) { /* ignore */ }
  const saveSplunk = () => {
    try { localStorage.setItem(SPLUNK_KEY, JSON.stringify({ mode: splunkEls.mode.value, range: splunkEls.range.value, url: splunkEls.url.value.trim(), user: splunkEls.user.value.trim(), insecure: splunkEls.insecure.checked })); } catch (e) { /* ignore */ }
  };
  ['mode', 'url', 'user', 'range', 'insecure'].forEach((k) => splunkEls[k].addEventListener('change', saveSplunk));
  splunkEls.mode.addEventListener('change', splunkPlaceholder);
  splunkPlaceholder();

  // GitHub Pages has no forwarding server: say how to get one.
  window.TraceSplunk.available().then((ok) => {
    if (ok) return;
    splunkBtn('run').disabled = true;
    splunkEls.note.textContent = 'Not available here: Splunk only answers this page through the local server. '
      + 'Run python tools/serve.py and open http://localhost:8765/.';
    splunkEls.note.classList.add('problem');
  });

  function splunkStatus(lines) {
    splunkEls.status.replaceChildren(...lines.map(([cls, text]) => el('li', { class: cls }, [text])));
  }

  // One run, four steps: the flow query (CSV) goes into Flow Analysis; the log query (raw events)
  // is masked by the Mask rules; API Analysis then maps the CSV lines to the masked log events.
  splunkBtn('run').addEventListener('click', async () => {
    const steps = { login: 'Logging in…', job: 'Creating the search job…', wait: 'Search running…', results: 'Fetching the results as CSV…' };
    const range = window.TraceSpl.timeRange(state);
    const lines = [['ok', range ? `Time range: Start time / End time (${state.startTime || 'open'} … ${state.endTime || 'open'})`
      : `Time range: ${splunkEls.range.selectedOptions[0].textContent}`]];
    let key = '';
    let current = '';
    let sid = '';
    const show = (busy) => splunkStatus([
      ...(key ? [['ok', `Logged in (${splunkEls.mode.value === 'web' ? 'Splunk Web session, token' : 'session key'} ${window.TraceSplunk.maskKey(key)})`]] : []),
      ...lines, ...(busy ? [['busy', busy]] : []),
    ]);
    const opts = {
      base: splunkEls.url.value, mode: splunkEls.mode.value, username: splunkEls.user.value.trim(), password: splunkEls.pass.value,
      insecure: splunkEls.insecure.checked,
      // Start / End time are in the query (earliest=/latest=); otherwise the chosen range
      earliest: range ? '' : splunkEls.range.value,
      onStatus: (s) => {
        if (s.sessionKey) key = s.sessionKey;
        if (s.sid && s.sid !== sid) { sid = s.sid; lines.push(['ok', `${current}: search job (access id) ${sid}`]); }
        show(`${current}: ` + (s.step === 'wait' ? `search running… ${Math.round(s.progress * 100)}%, ${s.results} results` : steps[s.step]));
      },
    };
    splunkResult = null;
    splunkBtn('run').disabled = true;
    splunkBtn('csv').disabled = true;
    splunkBtn('log').disabled = true;
    document.querySelectorAll('.splunk-view, .splunk-tab').forEach((b) => { b.disabled = true; });
    splunkEls.csv.hidden = true;
    saveSplunk();
    try {
      // 1. Base Splunk query -> CSV -> Flow Analysis
      current = 'Flow query';
      const res = await window.TraceSplunk.run({ ...opts, query: generate(state) });
      const table = window.TraceImport.parseCsv(res.csv);
      splunkResult = { sid: res.sid, csv: res.csv, logs: [] };
      lines.push(['ok', `Flow query: ${Math.max(0, table.length - 1).toLocaleString()} rows (CSV, ${res.csv.length.toLocaleString()} chars)`]);
      show();
      const preview = res.csv.split('\n');
      splunkEls.csv.textContent = preview.slice(0, 200).join('\n') + (preview.length > 200 ? `\n… ${preview.length - 200} more lines (Download CSV)` : '');
      splunkEls.csv.hidden = false;
      splunkBtn('csv').disabled = false;
      if (table.length > 1) {
        await loadSplunkResult();
        const sessions = new Set((imported?.rows || []).map((r) => r.sessionId)).size;
        lines.push(imported?.rows?.length
          ? ['ok', `In Flow Analysis: ${imported.rows.length.toLocaleString()} flow rows, ${sessions} sessions.`]
          : ['problem', 'The results have no flow rows (the table needs the Flow or ServiceInfo column); see Flow Analysis > Debug.']);
        document.querySelectorAll('.splunk-view').forEach((b) => { b.disabled = !imported?.rows?.length; });
      }
      // 2. Log query -> raw events as one log file per source
      current = 'Log query';
      const logRes = await window.TraceSplunk.run({ ...opts, query: generateLogs(state) });
      const files = splunkLogFiles(window.TraceImport.parseCsv(logRes.csv));
      splunkResult.logs = files;
      const events = files.reduce((t, f) => t + window.TraceFlow.describeLog(f.text).events, 0);
      lines.push(['ok', `Log query: ${events.toLocaleString()} log events in ${files.length} log file(s): ${files.map((f) => f.name).join(', ') || 'none'}`]);
      splunkBtn('log').disabled = !files.length;
      show(files.length ? 'Masking the log…' : '');
      if (!files.length) throw new Error('The log query returned no events, so there is nothing to mask or analyse.');
      // 3. Mask rules on the log
      await setMaskFiles(files);
      const masked = mask.results.reduce((t, r) => t + r.counts.reduce((a, b) => a + b, 0), 0);
      const left = mask.results.reduce((t, r) => t + r.left.length, 0);
      lines.push([left ? 'problem' : 'ok', `Mask: ${masked.toLocaleString()} values masked by ${mask.rules.filter((r) => r.on).length} rules`
        + (left ? `; ${left} values still look sensitive (see Data Masking)` : '')]);
      show('API Analysis…');
      // 4. API Analysis: the flow CSV against the masked log. The CSV's session IDs are masked the
      // same way (same key, same fakes), or no line would agree with its log event.
      const flowTable = window.TraceImport.toFlowRows(table, state);
      const sids = await window.TraceMask.maskSessionIds(flowTable.rows, mask.results, { key: mask.key });
      lines.push(['ok', `Data Masking: ${sids.masked.toLocaleString()} CSV session ID(s) masked to match the log`
        + (sids.kept ? `; ${sids.kept.toLocaleString()} kept, as in the log (their rule is off)` : '')]);
      cmp.excel = { name: `splunk-${res.sid}.csv`, ...flowTable, rows: sids.rows };
      cmpResult = null;
      setCmpLogs(mask.results.map((r) => ({ name: window.TraceMask.maskedName(r.name), text: r.text })));
      lines.push(cmpResult
        ? ['ok', `API Analysis: ${cmpResult.mapped.toLocaleString()} of ${cmpResult.rows.length.toLocaleString()} lines mapped to a log event. Open a tab below.`]
        : ['problem', 'API Analysis could not run; see the API Analysis tab.']);
      show();
      document.querySelectorAll('.splunk-tab').forEach((b) => { b.disabled = false; });
    } catch (err) {
      lines.push(['problem', `${current}: ${err.message}`]);
      show();
    } finally {
      splunkEls.pass.value = '';
      splunkBtn('run').disabled = false;
    }
  });

  splunkBtn('csv').addEventListener('click', () => {
    if (splunkResult) download(`splunk-${splunkResult.sid}.csv`, splunkResult.csv, 'text/csv');
  });
  // the raw log as Splunk returned it, before masking (Mask has the masked download)
  splunkBtn('log').addEventListener('click', () => {
    (splunkResult?.logs || []).forEach((f) => download(f.name, f.text, 'text/plain'));
  });

  // Log query results (_time, source, _raw) as one log file per source (named by the file part of
  // the source), events in time order.
  function splunkLogFiles(table) {
    if (!table.length) return [];
    const [head, ...rows] = table;
    const col = (name) => head.indexOf(name);
    const iTime = col('_time');
    const iSource = col('source');
    const iRaw = col('_raw');
    if (iRaw < 0) throw new Error('The results have no _raw column.');
    const bySource = new Map();
    rows.map((r, i) => ({ r, i, t: iTime < 0 ? 0 : Date.parse(r[iTime]) || 0 }))
      .sort((a, b) => a.t - b.t || a.i - b.i)
      .forEach(({ r }) => {
        const name = base(iSource < 0 ? '' : r[iSource]) || 'splunk.log';
        if (!bySource.has(name)) bySource.set(name, []);
        bySource.get(name).push(String(r[iRaw] ?? '').replace(/\r?\n$/, ''));
      });
    return [...bySource].map(([name, raws]) => ({ name, text: raws.join('\n') + '\n' }));
  }

  // Flow Analysis and Mock Test keep their own data: the results go to Flow Analysis.
  async function loadSplunkResult() {
    if (mode !== 'file') switchMode('file');
    logDebug('info', `Splunk search ${splunkResult.sid}: results loaded into Flow Analysis`);
    await importResult({ name: `splunk-${splunkResult.sid}.csv` }, new TextEncoder().encode(splunkResult.csv).buffer);
  }

  document.querySelectorAll('.splunk-tab').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  document.querySelectorAll('.splunk-view').forEach((b) => b.addEventListener('click', () => {
    showTab('file');
    showView(b.dataset.view);
  }));

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
    if (selected.dataset.tab === 'file' && mode !== 'file') switchMode('file');
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

  // Demo links: #compare opens API Analysis with the mock pair loaded, #mask Mask with the mock logs.
  // Old #mock links (the Mock Test tab is gone) open Flow Analysis. Otherwise reopen the last tab
  // (the old single Flow tab and the old Mock Test tab map to Flow Analysis).
  let savedTab = 'spl';
  try { savedTab = localStorage.getItem(TAB_KEY) || 'spl'; } catch (e) { /* ignore */ }
  if (location.hash.startsWith('#mock')) {
    showTab('file');
  } else if (location.hash === '#mask') {
    showTab('mask');
    document.getElementById('mask-mock').click();
  } else if (location.hash === '#compare') {
    showTab('compare');
    document.getElementById('cmp-mock').click();
  } else {
    showTab({ flow: 'file', file: 'file', mock: 'file', compare: 'compare', mask: 'mask' }[savedTab] || 'spl');
  }
})();
