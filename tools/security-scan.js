// Pre-publish security scan: run before every push.
//
//   node tools/security-scan.js          exit 0 = clean (warnings may need a decision), 1 = blocking findings
//
// Checks the files git tracks or has staged:
//   1. forbidden files   real/sample data (ToolBase/, .xlsx/.log outside mock/), env and key files
//   2. secrets           tokens, private keys, password assignments
//   3. real-data leaks   IDs, long numbers, emails, IPs taken from the untracked/ignored data files (local only)
//   4. network use       what the shipped page (index.html, css/, js/) could send or load off-site
//   5. sample names      endpoint paths and service codes that also appear in those files (warning)
'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const git = (args) => execSync(`git ${args}`, { cwd: ROOT, encoding: 'utf8' });
const tracked = [...new Set([
  ...git('ls-files').split('\n'),
  ...git('diff --cached --name-only --diff-filter=ACMR').split('\n'),
].filter(Boolean))].filter((f) => fs.existsSync(path.join(ROOT, f)));

const blocking = [];
const warnings = [];
const isText = (buf) => !buf.subarray(0, 8000).includes(0);
const read = (f) => {
  const buf = fs.readFileSync(path.join(ROOT, f));
  return isText(buf) ? buf.toString('utf8') : null;
};
const mask = (s) => (s.length <= 8 ? '****' : s.slice(0, 4) + '…' + s.slice(-2));
const lineOf = (text, index) => text.slice(0, index).split('\n').length;

// 1. forbidden files (by name; raw-log content is checked below, whatever the name)
for (const f of tracked) {
  if (/^ToolBase\//i.test(f)) blocking.push(`forbidden file: ${f} (ToolBase/ holds real/sample data)`);
  else if (/\.(xlsx|xls|log)$/i.test(f) && !/^mock\//.test(f)) blocking.push(`forbidden file: ${f} (data files are only allowed in mock/)`);
  else if (/(^|\/)\.env(\.|$)|\.(pem|key|p12|pfx|jks|keystore)$/i.test(f)) blocking.push(`forbidden file: ${f} (credentials/keys)`);
}
// The data folder can be renamed (it was once ToolBase/, once AAAAAAAAAA/), so also block
// any tracked file outside mock/ and tests/ that reads like raw logs or the analysis spec.
const LOG_LINE = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\s/gm;
for (const f of tracked) {
  if (/^(mock|tests)\//.test(f) || /\.(js|css|html|md|json|yml|py)$/i.test(f)) continue;
  const buf = fs.readFileSync(path.join(ROOT, f));
  if (!isText(buf)) continue;
  const t = buf.toString('utf8');
  if ((t.match(LOG_LINE) || []).length >= 3) blocking.push(`forbidden file: ${f} looks like raw log data (timestamped events); only mock/ may hold logs`);
  else if (/\[SPLMessage\]|\[SPLHostMessage\]|WSAppLog|<SvcCode>/.test(t) && !/^(mock|tests)\//.test(f)) blocking.push(`forbidden file: ${f} contains log/sample content (SPL markers); keep it out of the repo`);
}

// 2. secrets
const SECRETS = [
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g],
  ['AWS access key', /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g],
  ['private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
  ['password assignment', /\b(pass(word|wd)?|secret|api[_-]?key|token)\s*[:=]\s*["'][^"'\s]{6,}["']/gi],
];
const texts = new Map(tracked.map((f) => [f, read(f)]).filter(([, t]) => t != null));
for (const [f, t] of texts) {
  if (f === 'tools/security-scan.js') continue; // holds the patterns themselves
  for (const [label, re] of SECRETS) {
    for (const m of t.matchAll(re)) blocking.push(`${label}: ${f}:${lineOf(t, m.index)} (${mask(m[0])})`);
  }
}

// Lines added by commits not yet on the remote: a push publishes every one of them,
// including values a later commit removed.
let upstream = '';
try { upstream = git('rev-parse --abbrev-ref --symbolic-full-name @{u}').trim(); } catch (e) { /* no upstream yet */ }
const unpushed = (upstream ? git(`log -p --format= ${upstream}..HEAD`) : git('log -p --format=')).split('\n')
  .filter((l) => l.startsWith('+') && !l.startsWith('+++')).join('\n');
for (const [label, re] of SECRETS) {
  for (const m of unpushed.matchAll(re)) {
    if (!/\bSECRETS\b|\/g\],?$/.test(unpushed.slice(unpushed.lastIndexOf('\n', m.index), unpushed.indexOf('\n', m.index)))) {
      blocking.push(`${label} in an unpushed commit (${mask(m[0])}); rewrite that commit before pushing`);
    }
  }
}

// 3 + 5. compare with the local data files: everything git does not track (untracked or
// ignored) that can hold log or export data, wherever it lives (ToolBase/, a renamed
// folder, …). On a CI checkout there are none, so these checks only run locally.
const DATA_EXT = /\.(log|txt|csv|tsv|json|xml|xlsx)$/i;
const SKIP_DIR = /^(node_modules|_site|\.git|\.claude)\//;
const localData = [...new Set([
  ...git('ls-files --others --exclude-standard').split('\n'),
  ...git('ls-files --others --ignored --exclude-standard').split('\n'),
])].filter((f) => f && DATA_EXT.test(f) && !SKIP_DIR.test(f) && !path.basename(f).startsWith('~$')
  && fs.existsSync(path.join(ROOT, f)) && fs.statSync(path.join(ROOT, f)).size < 50 * 1024 * 1024);
(async () => {
if (localData.length) {
  // Text files as they are; .xlsx cells through the importer's reader (Splunk exports hold real values).
  const parts = [];
  for (const f of localData) {
    const buf = fs.readFileSync(path.join(ROOT, f));
    if (/\.xlsx$/i.test(f)) {
      try { parts.push((await require('../js/importer.js').readXlsx(buf)).map((r) => r.join(' ')).join('\n')); } catch (e) { warnings.push(`could not read ${f}: ${e.message}`); }
    } else if (isText(buf)) parts.push(buf.toString('utf8'));
  }
  const dirs = [...new Set(localData.map((f) => (f.includes('/') ? f.split('/')[0] + '/' : f)))];
  console.log(`Local data compared: ${localData.length} files in ${dirs.join(', ')}`);
  const sample = parts.join('\n');
  const tokens = new Set([
    ...sample.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi) || [], // session IDs
    ...sample.match(/\b\d{12,}\b/g) || [], // reference / journal numbers
    ...sample.match(/\b[0-9a-f]{24,}\b/gi) || [], // trace IDs
    ...sample.match(/\b[\w.+-]+@[\w-]+\.[\w.]+\b/g) || [], // emails
    ...sample.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [], // IPs
  ].filter((t) => !/^0+$/.test(t) && !/^(\d)\1+$/.test(t)));
  for (const [f, t] of texts) {
    for (const tok of tokens) {
      const i = t.indexOf(tok);
      if (i >= 0) blocking.push(`real-data value from the local data files in ${f}:${lineOf(t, i)} (${mask(tok)})`);
    }
  }
  for (const tok of tokens) {
    if (unpushed.includes(tok) && !blocking.some((b) => b.includes(mask(tok)))) {
      blocking.push(`real-data value from the local data files in an unpushed commit (${mask(tok)}); it was removed later but would still be published`);
    }
  }
  const names = new Set([
    ...sample.match(/\/[a-z][\w-]*(?:\/[\w.-]+){2,}/g) || [], // endpoint paths
    ...sample.match(/\b[A-Z]{2,}_[A-Z0-9_]{3,}\b/g) || [], // SvcCodes
  ].filter((n) => n.length >= 8));
  const hits = new Map();
  for (const [f, t] of texts) for (const n of names) if (t.includes(n)) hits.set(n, [...(hits.get(n) || []), f]);
  if (hits.size) {
    warnings.push(`${hits.size} endpoint/service names from the local data files appear in tracked files (needs your OK for a public repo): `
      + [...hits.keys()].slice(0, 12).join(', ') + (hits.size > 12 ? ', …' : ''));
  }
} else {
  warnings.push('No local data files found: real-data leak check skipped (expected in CI).');
}

// 4. network use in the shipped page
const ALLOWED_URLS = [
  'http://www.w3.org/2000/svg', // SVG namespace, not a request
  'https://www.plantuml.com/plantuml/svg/', // PlantUML Render, behind a confirm() dialog
];
const shipped = [...texts.keys()].filter((f) => f === 'index.html' || /^(css|js)\//.test(f));
for (const f of shipped) {
  const t = texts.get(f);
  for (const m of t.matchAll(/\b(?:https?:)?\/\/[\w.-]+\.[a-z]{2,}[^\s"'`)<>]*/gi)) {
    if (ALLOWED_URLS.some((u) => m[0].startsWith(u) || u.startsWith(m[0]))) continue;
    blocking.push(`external URL in shipped page: ${f}:${lineOf(t, m.index)} ${m[0]}`);
  }
  for (const [label, re] of [['XMLHttpRequest', /\bXMLHttpRequest\b/g], ['sendBeacon', /\bsendBeacon\b/g],
    ['WebSocket', /\bnew WebSocket\b/g], ['EventSource', /\bnew EventSource\b/g]]) {
    for (const m of t.matchAll(re)) blocking.push(`${label} in shipped page: ${f}:${lineOf(t, m.index)}`);
  }
  for (const m of t.matchAll(/\bfetch\(\s*([^)]*)\)/g)) {
    if (!/^['"`]mock\//.test(m[1].trim()) && !/^['"`](ToolBase|\.\/)/.test(m[1].trim())) {
      blocking.push(`fetch() to a non-local target in shipped page: ${f}:${lineOf(t, m.index)} fetch(${m[1].slice(0, 60)})`);
    }
  }
}
// The confirm() text itself contains brackets, so look for confirm( shortly before the host name.
if (texts.get('js/app.js') && texts.get('js/app.js').includes('plantuml.com') && !/confirm\([\s\S]{0,300}?plantuml\.com/.test(texts.get('js/app.js'))) {
  blocking.push('PlantUML Render must ask (confirm) before sending the diagram to plantuml.com');
}

console.log(`Security scan: ${tracked.length} tracked files, ${shipped.length} shipped page files.`);
for (const b of blocking) console.log('BLOCK ' + b);
for (const w of warnings) console.log('WARN  ' + w);
console.log(blocking.length ? `\n${blocking.length} blocking finding(s): do not push.` : '\nNo blocking findings.');
process.exit(blocking.length ? 1 : 0);
})();
