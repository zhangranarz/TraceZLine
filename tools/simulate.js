// Runs the generated query's logic over local log files, without Splunk.
//
//   node tools/simulate.js [--config tracezline-config.json] [--terms id1,id2 | --all] file...
//
// The logic lives in js/flow.js (shared with the page's Flow result panel).
'use strict';
const fs = require('fs');
const spl = require('../js/spl.js');
const flow = require('../js/flow.js');

// Same as flow.run, but takes file paths.
const run = (cfg, files, terms) => flow.run(cfg, files.map((f) => ({ name: f, text: fs.readFileSync(f, 'utf8') })), terms);

if (require.main === module) {
  const args = process.argv.slice(2);
  let cfg = spl.DEFAULT_CONFIG; let terms = null; const files = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--config') cfg = { ...spl.DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(args[++i], 'utf8')) };
    else if (args[i] === '--terms') terms = spl.parseTerms(args[++i]);
    else if (args[i] === '--all') terms = [];
    else files.push(args[i]);
  }
  if (!files.length) {
    console.error('usage: node tools/simulate.js [--config file.json] [--terms id1,id2 | --all] file...');
    process.exit(1);
  }
  process.stdout.write(flow.format(run(cfg, files, terms ?? cfg.terms), cfg.columns.filter((c) => c.trim())));
}

module.exports = { run, format: flow.format, parseSearch: flow.parseSearch };
