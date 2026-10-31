# Mock logs

Fake raw logs in the same formats as the desensitised sample, for testing the
generated SPL without real data. Every ID, user and value here is made up.

| File | Layers | Matches source |
|---|---|---|
| `spl-banking-mock.log` | eComm `[SPLMessage]`, Enterprise `[SPLHostMessage]` | `spl-banking-*log` |
| `spl-ms-mock.log` | WS `[*WSAppLog]`, Host/EAI `[*MQLog]` XML | `spl-ms-*log` |

Regenerate with `npm run mock` (edit `make-mock.js` to change scenarios).

## Sessions and scenarios

| sessionId | Flow | Scenarios |
|---|---|---|
| `aaaaaaaa-0000-4000-8000-000000000001` | preLogin; login → `/idm/user/profile/get` → WS idm; `/enq/customer/portfolio` → WS → Host `BA_ACCT_INFO_N3`, then Host `AC_ACCT_SUM_X` with subservices `AC_RBK_SUMM_N`, `AC_VSA_SUMM_N` | A eComm only, B Enterprise → WS, D one subservice, E multiple subservices |
| `bbbbbbbb-0000-4000-8000-000000000002` | card transactions → `/enq/card/transactions` → WS → Host `CC_INFO_STMT_X` | H interleaved with session 1, G2 EAI `StatusCode` `E0012`, G3 Enterprise HTTP 200 with `errorCode`, G4 eComm `responseCode` `40010001` |
| `cccccccc-0000-4000-8000-000000000003` | precapture → `/bfs/payee/list/bp` (OK) → `/bfs/quick/bp/initiate` → WS with no response | C two Enterprise APIs in sequence, G1 timeout, I one hop OK and one failed |

Not covered: F (OPI, WAM, CUS downstream systems), because no sample of their log format exists yet.

Format variants copied from the sample: eComm responses without a `Response:` label
(the JSON starts with `{"response":`), Enterprise headers split over two lines
(`[SPLHostMessage] [sid]|...` then `[Android-SPL] - /path - [Request]:`), Enterprise
headers without a session ID (only `sessionIdentity` in the JSON), Host headers with
`SERVICE CODE:`, WS responses with `Response:` on the same line, and a non-zero
`StatusCode` `0005000` on `AC_ACCT_SUM_X`.

Expected statuses, for when HopStatus / SessionStatus are added to the query:

| Session | Failed hops | SessionStatus | FirstFailedHop |
|---|---|---|---|
| 1 | none | SUCCESS | — |
| 2 | Host `CC_INFO_STMT_X`, WS `/dge-enq/enq/card/transactions`, Enterprise `/enq/card/transactions` (business error with `00000000`), eComm | FAILED | Host `CC_INFO_STMT_X` |
| 3 | WS `/dge-bfs/bfs/bp/initiate` (no response), Enterprise `/bfs/quick/bp/initiate`, eComm | PARTIAL | WS `/dge-bfs/bfs/bp/initiate` |

## Running the query locally

```sh
node tools/simulate.js --all mock/spl-banking-mock.log mock/spl-ms-mock.log
node tools/simulate.js --terms bbbbbbbb-0000-4000-8000-000000000002 mock/*.log
node tools/simulate.js --config tracezline-config.json --all mock/*.log   # config exported from the page
```

`--all` ignores the search terms; without it the terms from the config are used.
`expected.txt` is the output for the default config and is checked by `npm test`.

## Using the mock logs in Splunk

Upload both files (Settings → Add Data → Upload) to a test index. Splunk sets
`source` to the uploaded file name, so on the page change the sources to
`*spl-banking-*log` and `*spl-ms-*log`, put the three session IDs in Search
terms, and add `index=<your test index>` if needed. Events start with a
`YYYY-MM-DD hh:mm:ss.mmm` timestamp, so the default line breaking keeps each
multi-line event together.
