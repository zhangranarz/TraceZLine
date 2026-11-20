// Runs the generated query in Splunk: log in (session key), create a search job (sid), wait
// until it is done, fetch the results as CSV. Splunk's REST API (management port, usually
// 8089) sends no CORS headers, so the page calls the local server (tools/serve.py), which
// forwards ./splunk-api/<path> to the Splunk URL given in the X-Splunk-Base header.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceSplunk = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // A query starting with | is a generating command; anything else needs "search ".
  const searchString = (query) => (/^\s*\|/.test(query) ? query.trim() : 'search ' + query.trim());

  // "Splunk error text" from a JSON or XML error body, else the body itself.
  function errorText(status, body) {
    try {
      const msg = JSON.parse(body).messages?.map((m) => m.text).filter(Boolean).join('; ');
      if (msg) return `${status}: ${msg}`;
    } catch (e) { /* not JSON */ }
    const xml = [...String(body).matchAll(/<msg[^>]*>([^<]*)<\/msg>/g)].map((m) => m[1].trim()).filter(Boolean).join('; ');
    return `${status}: ${xml || String(body).trim().slice(0, 300) || 'no details'}`;
  }

  // The last 4 characters only: enough to tell keys apart, not enough to use one.
  const maskKey = (key) => (key ? '…' + String(key).slice(-4) : '');

  const defaultFetch = (path, opts) => fetch(`./splunk-api${path}`, opts);
  const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // base: https://splunk-host:8089. onStatus({ step: 'login'|'job'|'wait'|'results'|'done', ... }).
  // Returns { sessionKey, sid, csv }. The password is sent once, to log in, and not kept.
  async function run({ base, username, password, query, insecure = false, onStatus = () => {},
    fetchFn = defaultFetch, sleep = defaultSleep, pollMs = 1000, timeoutMs = 10 * 60 * 1000 }) {
    if (!/^https?:\/\/[^/\s]+\/?$/.test(String(base || '').trim())) throw new Error('Splunk URL must look like https://host:8089 (scheme, host and port only).');
    if (!username || !password) throw new Error('Username and password are needed to log in.');
    const headers = { 'X-Splunk-Base': base.trim().replace(/\/$/, ''), 'X-Splunk-Insecure': insecure ? '1' : '0' };
    const call = async (path, { method = 'GET', form, key } = {}) => {
      const h = { ...headers };
      if (key) h.Authorization = 'Splunk ' + key;
      let body;
      if (form) {
        h['Content-Type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(form).toString();
      }
      const res = await fetchFn(path, { method, headers: h, body });
      const text = await res.text();
      if (!res.ok) throw new Error(errorText(res.status, text));
      return text;
    };
    const json = (text, what) => {
      try { return JSON.parse(text); } catch (e) { throw new Error(`${what}: Splunk did not return JSON (${text.slice(0, 120)})`); }
    };

    onStatus({ step: 'login' });
    const sessionKey = json(await call('/services/auth/login', { method: 'POST', form: { username, password, output_mode: 'json' } }), 'Login').sessionKey;
    if (!sessionKey) throw new Error('Login: no session key in the answer.');

    onStatus({ step: 'job', sessionKey });
    const sid = json(await call('/services/search/jobs', { method: 'POST', key: sessionKey, form: { search: searchString(query), output_mode: 'json' } }), 'Search job').sid;
    if (!sid) throw new Error('Search job: no sid in the answer.');

    const started = Date.now();
    for (;;) {
      const entry = json(await call(`/services/search/jobs/${encodeURIComponent(sid)}?output_mode=json`, { key: sessionKey }), 'Job status').entry?.[0]?.content || {};
      if (entry.dispatchState === 'FAILED') {
        throw new Error('Search failed: ' + ((entry.messages || []).map((m) => m.text).join('; ') || 'no details'));
      }
      onStatus({ step: 'wait', sessionKey, sid, progress: Number(entry.doneProgress) || 0, results: Number(entry.resultCount) || 0 });
      if (entry.isDone === true || entry.isDone === 1 || entry.isDone === '1' || entry.dispatchState === 'DONE') break;
      if (Date.now() - started > timeoutMs) throw new Error(`Search ${sid} is still running after ${Math.round(timeoutMs / 60000)} min.`);
      await sleep(pollMs);
    }

    onStatus({ step: 'results', sessionKey, sid });
    const csv = await call(`/services/search/jobs/${encodeURIComponent(sid)}/results?output_mode=csv&count=0`, { key: sessionKey });
    onStatus({ step: 'done', sessionKey, sid });
    return { sessionKey, sid, csv };
  }

  // Is the local forwarding server there (python tools/serve.py)? GitHub Pages has none.
  async function available(fetchFn = defaultFetch) {
    try { return (await fetchFn('/ping', {})).ok; } catch (e) { return false; }
  }

  return { run, available, searchString, errorText, maskKey };
});
