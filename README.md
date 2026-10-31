# TraceZLine

[![CI](https://github.com/zhangranarz/TraceZLine/actions/workflows/ci.yml/badge.svg)](https://github.com/zhangranarz/TraceZLine/actions/workflows/ci.yml)
[![Deploy to GitHub Pages](https://github.com/zhangranarz/TraceZLine/actions/workflows/pages.yml/badge.svg)](https://github.com/zhangranarz/TraceZLine/actions/workflows/pages.yml)
[![GitHub Pages](https://img.shields.io/badge/demo-GitHub%20Pages-222?logo=github)](https://zhangranarz.github.io/TraceZLine/)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-F7DF1E?logo=javascript&logoColor=black)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)
![Node.js](https://img.shields.io/badge/tests-Node.js%20%E2%89%A5%2018-339933?logo=nodedotjs&logoColor=white)
![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Data stays local](https://img.shields.io/badge/data-stays%20in%20your%20browser-blue)

A browser-only tool for tracing banking API call flows through Splunk logs:
**Mobile App → eComm → Enterprise → WS → EAI/Host**.
It generates a parameterised SPL query, runs the same logic over your log files or a
Splunk Excel/CSV export in the browser, and shows the flow table, PlantUML and SVG
sequence diagrams, and the processing rules it observes. Nothing is uploaded.

**Live demo:** https://zhangranarz.github.io/TraceZLine/ ·
[with mock data](https://zhangranarz.github.io/TraceZLine/#mock) ·
[sequence diagram](https://zhangranarz.github.io/TraceZLine/#mock/sequence)

## Features

| Tab | What it does |
|---|---|
| **Splunk** | Generates the SPL query from editable sources, session IDs, layers and rex rules; copy or download it |
| **Load File** | Runs the query logic over your raw logs (**Local File**) or a Splunk `.xlsx`/`.csv` export (**Upload**) |
| **Mock Test** | The same views over bundled fake logs |
| **Compare** | Maps each line of a Splunk result to its raw log event by timestamp, with the JSON/XML payload as a Parameter / Value table and a data-quality report |

Views in Load File and Mock Test: **Flow** (session summary and flow table), **PlantUML**,
**Sequence** (SVG diagram), **Processing Rule** (routing, call map, call order, gaps,
latency), **Debug** and **Log Files**.

Everything runs in the browser; settings are saved there too. Demo links: `#mock`,
`#mock/sequence`, `#mock/rules`, `#compare`.

## How to install

```sh
git clone https://github.com/zhangranarz/TraceZLine.git
cd TraceZLine
```

There is nothing to install: the page is plain HTML, CSS and JavaScript with no
dependencies and no build step.

- **Node.js ≥ 18** is needed only for the tests and the command-line tools.
- **Python 3** is needed only for the local web server.

## How to run

- **Online:** open https://zhangranarz.github.io/TraceZLine/.
- **Locally:**

  ```sh
  python tools/serve.py 8765
  ```

  then open http://localhost:8765/ (or http://localhost:8765/#mock for the demo).
  Use the server rather than opening `index.html` as a file: the Mock Test tab loads
  `mock/*.log` over HTTP.

Command-line tools:

```sh
npm test                                     # unit and end-to-end tests
node tools/simulate.js --all mock/*.log      # run the query logic over log files
node tools/simulate.js --config tracezline-config.json --terms <sessionId> my.log
npm run mock                                 # regenerate the mock logs
npm run security-scan                        # pre-push scan (also run in CI)
```

## Data safety

- Files you load are read in your browser and never uploaded. The page loads nothing
  from other sites; the only outbound request is the optional PlantUML **Render**,
  which asks before sending the diagram text to plantuml.com.
- Never commit real or undesensitised logs. `ToolBase/`, `*.log` and `*.xlsx` are
  git-ignored (only the fake files in `mock/` are tracked).
- `npm run security-scan` blocks a push when it finds data files, secrets, values copied
  from your local (untracked or ignored) data files, or off-site network use by the page.

## Project layout

| Path | Contents |
|---|---|
| `index.html`, `css/` | The page |
| `js/spl.js` | SPL generator and settings validation |
| `js/flow.js` | Query logic over log text, session summary, sequence model, PlantUML |
| `js/sequence.js` | SVG sequence diagram renderer |
| `js/importer.js` | Excel (`.xlsx`) and CSV reader for Splunk flow exports |
| `js/rules.js` | Processing-rule analysis and Markdown export |
| `js/compare.js` | Timestamp mapping of a Splunk result to the raw logs, data-quality checks |
| `js/app.js` | Page wiring |
| `mock/` | Fake logs, flow exports and expected output ([details](mock/README.md)) |
| `tests/` | `node --test` suites |
| `tools/` | `serve.py`, `simulate.js`, `security-scan.js` |
| `.github/workflows/` | CI and GitHub Pages deployment |
| `.claude/commands/publish.md` | `/publish` command for Claude Code |
