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
**Mobile App → eComm → Enterprise → MS (MicroService) → EAI/Host**.
It generates a parameterised SPL query, runs the same logic over your log files or a
Splunk Excel/CSV export in the browser, and shows the flow table, PlantUML and SVG
sequence diagrams, and the processing rules it observes. Nothing is uploaded.

**Live demo:** https://zhangranarz.github.io/TraceZLine/ ·
[API Analysis with mock data](https://zhangranarz.github.io/TraceZLine/#compare)

## Features

| Tab | What it does |
|---|---|
| **Data Source** | Generates the SPL query from editable sources (or a **Source table**: an Excel/CSV of Country, Module and one source= path per layer; choosing a Country and Module sets each source's path; N/A leaves that source out of the search), Search terms (1) session IDs, or 2) the last session of an eComm API such as /application/confirm: the newest eComm event with that text gives the session ID, held in the queries as a subsearch and run first by Run in Splunk), an optional Start/End time, layers and rex rules; copy or download it, or **Run in Splunk**. A second **Log query** returns the raw events (EventTime, _raw) of the same sources and search terms, sorted by time. Run in Splunk logs in and runs both: the flow query's CSV opens in Flow Analysis, the log query's raw log is masked with the Mask rules, then API Analysis maps the CSV lines to the masked log. **Include API Analysis** (off by default) adds the log query, masking and mapping; off, only the flow query runs |
| **Flow Analysis** | Runs the query logic over your raw logs (**Local File**) or a Splunk `.xlsx`/`.csv` export (**Upload**) |
| **API Analysis** | Maps each line of a Splunk result to its raw log event by timestamp, with the JSON/XML payload as a Parameter / Value table and a data-quality report |
| **Data Masking** | Masks sensitive values in log/text files by JSON key, XML tag, exact text or Pre/Post text (replace with `<<MASK_NAME>>` or your own text, digits to `*`, keep last 4, or consistent pseudonyms), flags what still looks sensitive, and downloads the masked files |

Views in Flow Analysis: **Flow** (session summary and flow table), **PlantUML**,
**Sequence** (SVG diagram: one for all sessions or one per session, with optional notes and elapsed times), **Processing Rule** (each API with a description of the call:
callers, downstream calls, SvcCodes, gaps, latency) and **Debug**.

Everything runs in the browser; settings are saved there too. Demo links: `#compare`,
`#mask` (both with the bundled mock data).

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

  then open http://localhost:8765/ (or http://localhost:8765/#compare for the demo).
  Use the server rather than opening `index.html` as a file: the **Use Mock** buttons load
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
- **Run in Splunk** goes only to the Splunk URL you enter, through the local server
  (`python tools/serve.py`), because neither Splunk's REST API (port 8089) nor Splunk Web
  (e.g. port 8000, **Splunk Web** mode) answers a web page directly. Splunk Web's session
  cookies stay in the local server's answers, not in your browser. The password is sent once, to log in, and is not saved; the URL and username
  are kept in your browser. It is not available on GitHub Pages.
- Use the **Data Masking** tab before sharing a log. Its consistent mode keeps sessions linkable
  through a key-based HMAC; the key stays in your browser.
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
| `js/splunk.js` | Run in Splunk: login, search job, results as CSV (through `tools/serve.py`) |
| `js/mask.js` | Masking rules (JSON key, XML tag, exact text, Pre/Post) and the leftover scan |
| `js/app.js` | Page wiring |
| `mock/` | Fake logs, flow exports and expected output ([details](mock/README.md)) |
| `tests/` | `node --test` suites |
| `tools/` | `serve.py` (also forwards Run in Splunk), `simulate.js`, `security-scan.js` |
| `.github/workflows/` | CI and GitHub Pages deployment |
| `.claude/commands/publish.md` | `/publish` command for Claude Code |
