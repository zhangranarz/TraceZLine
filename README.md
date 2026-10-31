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

The left side holds the query settings; the right side has three tabs.

**Splunk** — the generated SPL query. Edit sources, search terms (session IDs), layers
(name, number, indent, match condition), direction rules, endpoint / sessionId / Params
rex rules and output columns; the structure of the base query stays fixed. Live preview
with warnings, **Copy**, **Download** (`.spl`). Settings are saved in the browser;
**Export config** / **Import config** / **Reset to base** are at the bottom of the page.

**Load File** — your own data, read in the browser only:
- **Local File**: raw log files, or a Splunk EventTime/PopulatedLog export.
- **Upload** (in the Flow view): the flow table exported from Splunk as `.xlsx` or `.csv`
  (Step, EventTime, sessionId, ServiceInfo, Params, ElapsedMs). Rows with an empty Step
  continue the row above (Host SvcCode lines).

**Mock Test** — the same views over bundled fake logs, loaded when the tab opens.

**Compare** — load the Splunk result with **Excel** (`.xlsx`/`.csv`) and the raw log files it came from with **Log**.
Every line of the Splunk result is listed and mapped to the log event with the closest
timestamp, within a tolerance; when several events are equally close (an Excel export keeps
whole seconds), the one with the same session, layer, direction and API wins. The time
offset between Splunk's EventTime and the log timestamps (e.g. a time-zone difference) is
detected, or set in **Offset** (hours). Columns: Step, EventTime, ServiceInfo, Log (the matched log event as "Log ▸"; expand it for the raw text), Structure (when the event carries JSON, "JSON:" expands to a Parameter / Value table, paths written like `responseHeader|responseContext|responseCode`; for XML such as Host/EAI messages, "XML:" does the same, e.g. `EAI|SvcRq|SubSvc[0]|SubSvcRqHeader|SvcCode`), LogRow (`file:line`), LogTime, sessionId, Params, ElapsedMs. Lines that differ or are not mapped have a coloured edge and say why on hover. Copy/Download also include Δ ms and Check, and the event text in Log. Each line shows the log time, the difference in ms,
the log event (`file:line`, expand it for the raw text) and whether it agrees. Data quality
lists lines with no event in the window, lines mapped to another layer/direction/API, log
events not mapped, and warns when the files share no session. **Use Mock** loads the mock
flow and logs; **Copy** / **Download** (CSV) export the mapping.

Views in Load File and Mock Test:

| View | What it shows |
|---|---|
| **Flow** | Session summary (steps, total time, slowest hop, requests with no response) and the flow table grouped by session; **Copy table**, **Download CSV** |
| **PlantUML** | One sequence diagram per session as PlantUML text; **Copy**, **Download**, **Render** (asks first, then uses plantuml.com) |
| **Sequence** | The same diagrams drawn as SVG in the browser; **Fit to width**, **Download SVG** |
| **Processing Rule** | Routing, caller → callee map with Host SvcCodes, call order (sequential / overlapping), gaps and latency baseline, each with its evidence (single-sample observations are labelled); **Copy**, **Download** as Markdown |
| **Debug** | Execution log of every load and run, and every event with the decision taken for it; **Copy Log** |
| **Log Files** | Mock Test only: preview each log file, event start lines highlighted |

Demo links: `#mock`, `#mock/diagram`, `#mock/sequence`, `#mock/rules`, `#mock/debug`, `#mock/logs`, `#compare`.

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
  from `ToolBase/` (in files or unpushed commits) or off-site network use by the page.

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
