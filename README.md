# TraceZLine

A browser-only tool for tracing banking API call flows through Splunk logs:
Mobile App → eCommerce → Enterprise API / WebService → EAI → downstream systems.

## SPL generator (available now)

Rebuilds the base flow query from editable values while keeping its structure fixed:

- **Sources**: add/remove/disable `source="..."` blocks and their filters
- **Search terms**: paste session IDs (one per line); quoted and OR-joined
- **Layers**, **Direction rules**, **sessionId rules**, **Params**, **Output columns**: add, remove, reorder
- Live preview with warnings, Copy, Download `.spl`, Export/Import config JSON
- Settings are kept in the browser's localStorage

The default settings reproduce the base query exactly (`tests/base.spl`, checked by `npm test`).

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
