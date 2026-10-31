# TraceZLine

A browser-only tool for tracing banking API call flows through Splunk logs:
Mobile App → eCommerce → Enterprise API / WebService → EAI → downstream systems.

Planned features:

- Parameterised SPL generator (layers, sessionId rules, success codes, output columns)
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
