---
description: Security-scan, then publish TraceZLine to GitHub (push, README, About, Pages, CI/CD)
argument-hint: "[commit message for pending changes]"
---

Publish this project (TraceZLine) to GitHub. Work through the steps **in this order**.
The security gate (step 1) runs before anything leaves this machine; never skip it,
and stop to ask the user whenever a step below says so.

Pending-changes commit message, if the user gave one: $ARGUMENTS

## Project facts

- Local repo: this folder. GitHub: `zhangranarz/TraceZLine` (public), branch `main`.
- GitHub Pages: `https://zhangranarz.github.io/TraceZLine/`, deployed by GitHub Actions.
- Purpose (use it for the description, README intro and topics): a browser-only Splunk
  API flow tracer for banking call chains (App → eComm → Enterprise → WS → EAI/Host).
  It generates a parameterised SPL query, runs the same logic over local log files or a
  Splunk Excel/CSV export in the browser, and shows the flow table, PlantUML and SVG
  sequence diagrams, and observed processing rules. Nothing is uploaded.
- Stack: plain HTML/CSS/JavaScript (no framework, no build, no runtime dependencies),
  Node.js ≥ 18 for `npm test` and `tools/simulate.js`, Python 3 for `tools/serve.py`.
- `ToolBase/` holds the user's real/sample data and spec. It is git-ignored and must
  never be committed, pushed, quoted in commits/README, or sent to any service.
- Git identity for commits: the repo-local `zhangranarz` no-reply address (already set).

## 1. Security gate (must pass before any push)

1. Run `node tools/security-scan.js`. It checks tracked and staged files plus every line
   added by unpushed commits for: forbidden files (ToolBase/, data files outside mock/,
   env/key files), secrets, real values copied from ToolBase/ (IDs, reference numbers,
   emails, IPs, Excel cells included), and network use by the shipped page.
2. Any `BLOCK` line: stop. Fix the cause (replace real values with obviously fake ones,
   remove the file, untrack with `git rm --cached`), commit, and rerun until clean. If a
   blocked value sits in an unpushed commit, tell the user and ask before rewriting history.
3. `WARN` about endpoint/service names from ToolBase/: show the list and ask the user
   whether these names may be public. Do not push until they answer. If they say no,
   replace the names with generic ones (in defaults, mock data, tests, fixtures) first.
4. Check the published history too: compare real values from ToolBase/ with
   `git log -p origin/main`. If any are already public, tell the user exactly which
   commits contain them and offer to rewrite history (`git filter-repo` or an
   interactive-free `git rebase` alternative) plus a force push. **Only with an explicit
   "yes" from the user**; a force push is irreversible for anyone who cloned.
5. Confirm `.gitignore` still covers `ToolBase/`, `*.log`, `*.xlsx` (with only the
   `mock/` exceptions), env and key files.
6. Run `npm test`; all tests must pass.

Report the scan result (counts of BLOCK/WARN, what was fixed) before continuing.

## 2. README

Create or update `README.md` (keep any accurate existing sections, fix stale ones):

- Title, one-line purpose, and a live-demo link to the Pages URL and `#mock`.
- Badges (shields.io, one line), only for things that are true:
  CI status for the workflows from step 4
  (`https://github.com/zhangranarz/TraceZLine/actions/workflows/<file>/badge.svg`),
  GitHub Pages, JavaScript, HTML5, CSS3, Node.js (tests), "no dependencies",
  "runs in the browser / data stays local". Add a license badge only if a LICENSE exists.
- Features: Splunk tab (query generator), Load File tab (Local File, Upload),
  Mock Test tab, views (Flow, PlantUML, Sequence, Processing Rule, Debug, Log Files).
- **How to install**: `git clone https://github.com/zhangranarz/TraceZLine.git`,
  `cd TraceZLine`; no packages to install; Node.js ≥ 18 only for tests and the CLI;
  Python 3 only for the local server.
- **How to run**: open the Pages URL; or locally `python tools/serve.py 8765` and open
  `http://localhost:8765/` (`#mock` for the demo); `npm test`;
  `node tools/simulate.js --all mock/*.log`; `npm run mock`; `node tools/security-scan.js`.
- Data safety: files are read in the browser only; the only outbound request is the
  optional PlantUML **Render**, which asks first; never commit real logs.
- Project layout (js/, tests/, mock/, tools/, .github/workflows/).

## 3. GitHub About section

Use `gh repo edit zhangranarz/TraceZLine`:

- `--description` (≤ 350 chars) from the purpose above.
- `--homepage https://zhangranarz.github.io/TraceZLine/` (the Pages link).
- `--add-topic` for: splunk, spl, observability, log-analysis, sequence-diagram,
  plantuml, banking, api-tracing, javascript, github-pages (lowercase, hyphenated).
- The About box cannot hold badges; the tech badges belong in the README (step 2).

Verify with `gh repo view zhangranarz/TraceZLine --json description,homepageUrl,repositoryTopics`.

## 4. CI/CD (GitHub Actions)

Make sure `.github/workflows/` has, with least-privilege `permissions` and actions
pinned to a major version:

- `ci.yml`: on push and pull_request to `main` — checkout, setup-node 22, `npm test`,
  `node tools/security-scan.js` (the ToolBase/ comparison skips itself in CI).
- `pages.yml`: on push to `main` and manual dispatch — run the same tests and scan,
  assemble `_site` (index.html, css/, js/, mock/*.log, mock/mock-flow.*), then
  `actions/upload-pages-artifact` and `actions/deploy-pages`. Keep `concurrency: pages`.
- Optional, if the user agrees: CodeQL for JavaScript and a gitleaks job.

Do not add secrets to workflows; none are needed.

## 5. Push

1. `git status`; commit pending changes (use $ARGUMENTS as the message if given),
   ending the message with the attribution line from the session instructions.
2. `git fetch origin`, then compare: `git rev-list --left-right --count origin/main...HEAD`.
   If the remote has commits the local branch lacks, stop and ask; never force-push
   unless the user explicitly approved it in step 1.4.
3. Rerun `node tools/security-scan.js` right before pushing (commits may have changed).
4. `git push origin main`.

## 6. GitHub Pages

1. `gh api repos/zhangranarz/TraceZLine/pages`; if it 404s, create it with
   `gh api -X POST repos/zhangranarz/TraceZLine/pages -f build_type=workflow`;
   if it exists with another build type, switch it to `workflow`.
2. Watch the run (`gh run list --limit 3`, `gh run watch <id> --exit-status`).
3. Check the site answers: `curl -s -o /dev/null -w "%{http_code}" https://zhangranarz.github.io/TraceZLine/`
   and that `mock/spl-banking-mock.log` is served (the Mock Test tab needs it).
4. Make sure the About homepage (step 3) is this Pages URL.

## 7. Final security check of what is now public

- Rerun `node tools/security-scan.js` against the pushed state.
- Confirm the published site only loads files from its own origin: fetch the deployed
  `index.html` and `js/*.js` and check there are no external `<script>`, stylesheet, font
  or analytics URLs, and no network calls other than the confirmed PlantUML Render.
- Confirm nothing from `ToolBase/` is in the repo: `git ls-files | grep -i toolbase`
  must print nothing.

## Report

End with: scan result, commits pushed, README/About/topics changes, workflow files,
CI and Pages run status with links, the Pages URL, and anything left for the user to
decide (sample-derived names, history rewrite).
