# TraceZLine

A browser-only tool for tracing banking API call flows through Splunk logs:
Mobile App → eCommerce → Enterprise API / WebService → EAI → downstream systems.

## SPL generator (available now)

Rebuilds the base flow query from editable values while keeping its structure fixed:

- **Sources**: add/remove/disable `source="..."` blocks and their filters
- **Search terms**: paste session IDs (one per line); quoted and OR-joined
- **Layers**, **Direction rules**, **sessionId rules**, **Params**, **Output columns**: add, remove, reorder
- Live preview with warnings, Copy, Download (`.spl`), Export/Import config JSON
- Settings are kept in the browser's localStorage

The default settings reproduce the base query exactly (`tests/base.spl`, checked by `npm test`).

## Load File and Mock Test tabs (available now)

In the **Load File** tab (next to **Splunk**), **Local File** runs the generated query's logic over raw log
files (or a Splunk EventTime/PopulatedLog export) in the browser and shows the flow
table: per-session summary (steps, total time, slowest hop, requests with no
response), then the rows grouped by session. **Copy table** pastes into Excel;
**Download CSV** saves it. The **Mock Test** tab shows the same views for the bundled mock logs, loaded when the tab opens; each tab keeps its own data. Files never leave the browser. The **PlantUML** view
turns the same rows into PlantUML (one diagram per session: App, eComm, Enterprise,
WS, Host; request/response arrows with activation, elapsed times, Params and Host
SvcCode pairs; an orange note where a request got no response). Copy it or download
`.puml` and draw it locally; **Render image…** asks first, then uses plantuml.com. The **Sequence** view
draws the same diagram as SVG in the browser (nothing is sent anywhere), with
**Fit to width** and **Download SVG**. The **Debug** view logs every file
load and run (file format, events read, how many each filter excluded, the Search
terms used) and lists every event with the decision taken for it; **Copy debug log**
copies both. `index.html#mock` opens the Mock Test tab
(`#mock/diagram` and `#mock/sequence` open those views). The same logic runs from the command line:
`node tools/simulate.js --all mock/*.log`.

### Upload a Splunk flow result

In the **Flow** view, **Upload** loads the table the query produced in
Splunk (columns Step, EventTime, sessionId, ServiceInfo or Flow, Params, ElapsedMs) and
builds the summary, Diagram and Sequence views from it, without the raw logs. Rows with
an empty Step continue the row above (Host SvcCode lines). Rows the importer cannot read
fully are listed in the Debug view. `mock/mock-flow.xlsx` and `mock/mock-flow.csv` are
examples.

## Planned

- Import of the Splunk result (Excel/CSV) and the raw request/response log
- Alignment and data-quality checks between the two
- PlantUML sequence diagram per session, with HopStatus / SessionStatus colouring
- Observed processing-rule analysis

Everything runs locally in the browser; no data leaves your machine.

## Run locally

```sh
python tools/serve.py 8765
```

Then open http://localhost:8765/.

## Data safety

Never commit real or undesensitised logs. `ToolBase/`, `*.log` and `*.xlsx` are git-ignored.
