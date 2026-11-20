// Runs the generated query in Splunk: log in, create a search job (sid), wait until it is done,
// fetch the results as CSV. Two ways in:
//   rest  Splunk's REST API (management port, usually 8089): POST /services/auth/login gives a
//         session key, sent as "Authorization: Splunk <key>".
//   web   Splunk Web (the browser UI, e.g. port 8000): the web login form gives session cookies
//         and a CSRF token; the same REST calls go through /<locale>/splunkd/__raw/services/...
//         with those cookies and the token in X-Splunk-Form-Key.
// Neither port sends CORS headers, so the page calls the local server (tools/serve.py), which
// forwards ./splunk-api/<path> to the Splunk URL in the X-Splunk-Base header. Splunk Web's
// cookies travel in X-Splunk-Cookie / X-Splunk-Set-Cookie, so the browser never stores them.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceSplunk = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const LOCALE = 'en-US';

  // A query starting with | is a generating command; anything else needs "search ".
  const searchString = (query) => (/^\s*\|/.test(query) ? query.trim() : 'search ' + query.trim());

  // "Splunk error text" from a JSON or XML error body, else the body itself.
  function errorText(status, body) {
    try {
      const j = JSON.parse(body);
      const msg = (j.messages || []).map((m) => m.text).filter(Boolean).join('; ') || j.message;
      if (msg) return `${status}: ${msg}`;
    } catch (e) { /* not JSON */ }
    const xml = [...String(body).matchAll(/<msg[^>]*>([^<]*)<\/msg>/g)].map((m) => m[1].trim()).filter(Boolean).join('; ');
    return `${status}: ${xml || String(body).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300) || 'no details'}`;
  }

  // The last 4 characters only: enough to tell keys apart, not enough to use one.
  const maskKey = (key) => (key ? '…' + String(key).slice(-4) : '');

  const defaultFetch = (path, opts) => fetch(`./splunk-api${path}`, opts);
  const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // rest: scheme, host and port only. web: may also have the root path Splunk Web is served under.
  function checkBase(base, mode) {
    const b = String(base || '').trim().replace(/\/+$/, '');
    const ok = mode === 'web' ? /^https?:\/\/[^/\s]+(\/[^\s?#]*)?$/.test(b) : /^https?:\/\/[^/\s]+$/.test(b);
    if (!ok) {
      throw new Error(mode === 'web'
        ? 'Splunk Web URL must look like https://host:8000 (scheme, host and port, plus Splunk Web\'s root path if it has one).'
        : 'Splunk URL must look like https://host:8089 (scheme, host and port only).');
    }
    return b;
  }

  // mode: 'rest' (default) or 'web'. onStatus({ step: 'login'|'job'|'wait'|'results'|'done', ... }).
  // Returns { sessionKey, sid, csv }: in web mode sessionKey is the CSRF token (shown masked).
  // The password is sent once, to log in, and not kept.
  // earliest: the job's time range, Splunk time syntax (-24h, -7d; '' = all time), up to now.
  // An earliest=/latest= in the query itself wins over it.
  async function run({ base, mode = 'rest', username, password, query, insecure = false, earliest = '', onStatus = () => {},
    fetchFn = defaultFetch, sleep = defaultSleep, pollMs = 1000, timeoutMs = 10 * 60 * 1000 }) {
    const target = checkBase(base, mode);
    if (!username || !password) throw new Error('Username and password are needed to log in.');
    const cookies = new Map(); // Splunk Web session cookies, name -> value
    const call = async (path, { method = 'GET', form, headers = {}, accept3xx = false } = {}) => {
      const h = { 'X-Splunk-Base': target, 'X-Splunk-Insecure': insecure ? '1' : '0', ...headers };
      if (cookies.size) h['X-Splunk-Cookie'] = [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
      let body;
      if (form) {
        h['Content-Type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(form).toString();
      }
      const res = await fetchFn(path, { method, headers: h, body });
      for (const c of JSON.parse(res.headers?.get?.('X-Splunk-Set-Cookie') || '[]')) {
        const i = c.indexOf('=');
        if (i > 0) cookies.set(c.slice(0, i), c.slice(i + 1));
      }
      const text = await res.text();
      // the forwarding server reports a redirect as 200 with X-Splunk-Status (fetch would follow it)
      const status = Number(res.headers?.get?.('X-Splunk-Status')) || res.status;
      if (!(res.ok && (status < 300 || (accept3xx && status < 400)))) throw new Error(errorText(status, text));
      return text;
    };
    const json = (text, what) => {
      try { return JSON.parse(text); } catch (e) { throw new Error(`${what}: Splunk did not return JSON (${text.slice(0, 120)})`); }
    };

    // Log in; afterwards api(path, opts) calls a REST endpoint with the session.
    onStatus({ step: 'login' });
    let api;
    let sessionKey;
    if (mode === 'web') {
      await call(`/${LOCALE}/account/login`, { accept3xx: true }); // sets the cval cookie
      const text = await call(`/${LOCALE}/account/login`, {
        method: 'POST', accept3xx: true, headers: { 'X-Requested-With': 'XMLHttpRequest' },
        form: { username, password, cval: cookies.get('cval') || '', set_has_logged_in: 'false' },
      });
      const csrf = [...cookies].find(([k]) => /^splunkweb_csrf_token_/.test(k));
      if (!csrf || ![...cookies.keys()].some((k) => /^splunkd_/.test(k))) {
        let msg = '';
        try { msg = JSON.parse(text).message || ''; } catch (e) { /* not JSON */ }
        throw new Error('Login: Splunk Web did not open a session' + (msg ? ` (${msg})` : '; check the username and password, or whether this Splunk uses single sign-on.'));
      }
      sessionKey = csrf[1];
      api = (path, opts = {}) => call(`/${LOCALE}/splunkd/__raw${path}`, { ...opts, headers: { 'X-Splunk-Form-Key': csrf[1], 'X-Requested-With': 'XMLHttpRequest' } });
    } else {
      sessionKey = json(await call('/services/auth/login', { method: 'POST', form: { username, password, output_mode: 'json' } }), 'Login').sessionKey;
      if (!sessionKey) throw new Error('Login: no session key in the answer.');
      api = (path, opts = {}) => call(path, { ...opts, headers: { Authorization: 'Splunk ' + sessionKey } });
    }

    onStatus({ step: 'job', sessionKey });
    const jobForm = { search: searchString(query), output_mode: 'json' };
    if (earliest) Object.assign(jobForm, { earliest_time: earliest, latest_time: 'now' });
    const sid = json(await api('/services/search/jobs', { method: 'POST', form: jobForm }), 'Search job').sid;
    if (!sid) throw new Error('Search job: no sid in the answer.');

    const started = Date.now();
    for (;;) {
      const entry = json(await api(`/services/search/jobs/${encodeURIComponent(sid)}?output_mode=json`), 'Job status').entry?.[0]?.content || {};
      if (entry.dispatchState === 'FAILED') {
        throw new Error('Search failed: ' + ((entry.messages || []).map((m) => m.text).join('; ') || 'no details'));
      }
      onStatus({ step: 'wait', sessionKey, sid, progress: Number(entry.doneProgress) || 0, results: Number(entry.resultCount) || 0 });
      if (entry.isDone === true || entry.isDone === 1 || entry.isDone === '1' || entry.dispatchState === 'DONE') break;
      if (Date.now() - started > timeoutMs) throw new Error(`Search ${sid} is still running after ${Math.round(timeoutMs / 60000)} min.`);
      await sleep(pollMs);
    }

    onStatus({ step: 'results', sessionKey, sid });
    const csv = await api(`/services/search/jobs/${encodeURIComponent(sid)}/results?output_mode=csv&count=0`);
    onStatus({ step: 'done', sessionKey, sid });
    return { sessionKey, sid, csv };
  }

  // Is the local forwarding server there (python tools/serve.py)? GitHub Pages has none.
  async function available(fetchFn = defaultFetch) {
    try { return (await fetchFn('/ping', {})).ok; } catch (e) { return false; }
  }

  return { run, available, searchString, errorText, maskKey };
});
