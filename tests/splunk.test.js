'use strict';
const test = require('node:test');
const assert = require('node:assert');
const sp = require('../js/splunk.js');

// A fake Splunk REST API: records each call and answers like Splunk does.
function fakeSplunk({ loginStatus = 200, jobStates = ['RUNNING', 'DONE'], failed = false } = {}) {
  const calls = [];
  let polls = 0;
  const reply = (status, body) => ({ ok: status < 400, status, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)) });
  const fetchFn = async (path, opts) => {
    calls.push({ path, method: opts.method || 'GET', headers: opts.headers || {}, body: opts.body || '' });
    if (path === '/services/auth/login') {
      return loginStatus === 200 ? reply(200, { sessionKey: 'KEY-123456' }) : reply(loginStatus, { messages: [{ type: 'WARN', text: 'Login failed' }] });
    }
    if (path === '/services/search/jobs') return reply(201, { sid: '1700000000.42' });
    if (path.startsWith('/services/search/jobs/1700000000.42?')) {
      const state = failed ? 'FAILED' : jobStates[Math.min(polls++, jobStates.length - 1)];
      return reply(200, { entry: [{ content: { dispatchState: state, isDone: state === 'DONE', doneProgress: state === 'DONE' ? 1 : 0.5, resultCount: 2, messages: failed ? [{ text: 'Error in search' }] : [] } }] });
    }
    if (path.startsWith('/services/search/jobs/1700000000.42/results?')) {
      return reply(200, 'Step,EventTime,sessionId,Flow,Params,ElapsedMs\n1,2026-10-26 09:30:00.000,s1,eComm: /a[?],,\n2,2026-10-26 09:30:00.010,s1,eComm: /a[!],,10\n');
    }
    return reply(404, 'not found');
  };
  return { fetchFn, calls };
}

test('run: login, search job (sid), wait until done, results as CSV', async () => {
  const { fetchFn, calls } = fakeSplunk();
  const steps = [];
  const res = await sp.run({
    base: 'https://splunk-host:8089/', username: 'me', password: 'pw-1', query: '(\n\tsource="x"\n)\n| table a',
    insecure: true, fetchFn, sleep: async () => {}, onStatus: (s) => steps.push(s.step),
  });
  assert.strictEqual(res.sessionKey, 'KEY-123456');
  assert.strictEqual(res.sid, '1700000000.42');
  assert.match(res.csv, /^Step,EventTime,sessionId,Flow,Params,ElapsedMs\n/);
  assert.deepStrictEqual(steps, ['login', 'job', 'wait', 'wait', 'results', 'done']);

  const [login, job, poll] = calls;
  assert.strictEqual(login.method, 'POST');
  assert.strictEqual(new URLSearchParams(login.body).get('password'), 'pw-1');
  assert.strictEqual(login.headers.Authorization, undefined);
  assert.strictEqual(login.headers['X-Splunk-Base'], 'https://splunk-host:8089', 'no trailing slash');
  assert.strictEqual(login.headers['X-Splunk-Insecure'], '1');
  // the query is sent as "search <query>", with the session key
  assert.strictEqual(new URLSearchParams(job.body).get('search'), 'search (\n\tsource="x"\n)\n| table a');
  assert.strictEqual(job.headers.Authorization, 'Splunk KEY-123456');
  assert.strictEqual(poll.path, '/services/search/jobs/1700000000.42?output_mode=json');
  assert.strictEqual(calls[calls.length - 1].path, '/services/search/jobs/1700000000.42/results?output_mode=csv&count=0');
  // the password is only in the login call
  assert.ok(calls.slice(1).every((c) => !c.body.includes('pw-1')));
});

test('run: Splunk errors and bad input are reported', async () => {
  await assert.rejects(sp.run({ base: 'https://h:8089', username: 'me', password: 'x', query: 'q', fetchFn: fakeSplunk({ loginStatus: 401 }).fetchFn, sleep: async () => {} }), /401: Login failed/);
  await assert.rejects(sp.run({ base: 'https://h:8089', username: 'me', password: 'x', query: 'q', fetchFn: fakeSplunk({ failed: true }).fetchFn, sleep: async () => {} }), /Search failed: Error in search/);
  await assert.rejects(sp.run({ base: 'splunk-host', username: 'me', password: 'x', query: 'q' }), /must look like https:\/\/host:8089/);
  await assert.rejects(sp.run({ base: 'https://h:8089/servicesNS', username: 'me', password: 'x', query: 'q' }), /scheme, host and port only/);
  await assert.rejects(sp.run({ base: 'https://h:8089', username: 'me', password: '', query: 'q' }), /Username and password/);
});

test('helpers: search string, error text, masked key', () => {
  assert.strictEqual(sp.searchString('  index=a x '), 'search index=a x');
  assert.strictEqual(sp.searchString('| makeresults'), '| makeresults');
  assert.strictEqual(sp.errorText(400, '<response><messages><msg type="FATAL">Unknown search command</msg></messages></response>'), '400: Unknown search command');
  assert.strictEqual(sp.errorText(502, 'Could not reach https://h:8089: timed out'), '502: Could not reach https://h:8089: timed out');
  assert.strictEqual(sp.maskKey('abcdefgh1234'), '…1234');
});
