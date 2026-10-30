# Impact replay — plan and scoped estimate

Question it answers: "If I block site X (or apply this wizard change), how many users and transactions would be blocked that aren't today?" ZIA has no native what-if, so we replay exported logs through `src/engine.js` against the current policy and a proposed copy, and keep only records whose outcome changes.

Status: skeleton only (`src/replay/index.js`, fail-safe `not_implemented` returns). Nothing wired into `server.js` or the UI yet.

## Inputs (per Research notes, 2026-10-30)
- **Web Insights CSV**: one row per transaction (weight aggregation optional). Headers vary by report, so parse **by header name**, never by position. Confirmed columns: `User`, `Department`, `Policy Action`, `Blocked Policy Name`, `URL Filtering Policy Name`. Full header set unverified.
- **NSS web logs**: JSON, TSV or custom format strings; Cloud NSS sends JSON array batches. Key fields: `time`, `epochtime`, `login`, `dept`, `location`, `url`, `host`, `urlcat`, `urlclass`, `action`, `reason`, `ruletype`, `rulelabel`, `urlfilterrulelabel`. `rulelabel` is only populated for block rules, so it feeds the "already blocked by" column.
- Exports can reach ~1M rows.

## Phases and effort
| # | Phase | Files | Effort |
|---|---|---|---|
| 1 | Parsers + normalizer + weighted aggregation (streaming line reader; header-name mapping for WI; JSON / JSON-array / TSV for NSS; custom format via user-supplied field map) | `src/replay/parse-webinsights.js`, `src/replay/parse-nss.js`, `src/replay/normalize.js`, `src/replay/index.js`, reuse `src/bulk.js` `splitCsvLine` | 1.5–2 days |
| 2 | Proposed policy copy: deep-clone snapshot, run `changes.plan()` and apply via `changes.mockApi()` to the clone only | `src/replay/proposed.js` (small export tweak in `src/changes.js` if needed) | 0.5 day |
| 3 | `simulateDiff()`: per aggregated record build an engine ctx (`M.parseTarget(url)`, categories from `urlcat`, user/dept/location), run `engine.simulate()` on both snapshots, keep outcome changes; per-record confidence from engine `unknown` criteria | `src/replay/diff.js`, possibly a ctx helper exported from `src/engine.js` | 1.5–2 days |
| 4 | Report + API + UI: newly blocked transactions (weighted), distinct users, departments, locations, top URLs, daily trend, "already blocked by", confidence note, CSV export (reuse `bulk.toCsv` style); upload endpoint with size limit + background job like bulk | `src/replay/report.js`, `server.js` (`/api/replay/start|status|result`), `public/index.html` (Impact tab) | 2–3 days |
| 5 | (Later) Cloud NSS pull / HTTP receiver for JSON batches | `src/replay/cloud-nss.js`, `server.js` | 2–3 days, separate PR |
| — | Tests, docs, README/CHANGELOG | `test/replay*.test.js`, `test/fixtures/replay/*`, `README.md`, `CHANGELOG.md` | 1 day |

**Total for phases 1–4 + tests: ~6.5–8.5 working days (~50–65 h).** Phase 5 adds 2–3 days.

## Risks and unknowns
1. **Formats unverified**: default NSS feed format strings and the full Web Insights header set aren't confirmed. Need one sanitized export of each from Jonathan before phase 1 is final; parsers will be header/field-map driven to absorb drift.
2. **Conditions logs can't resolve**: time windows, device trust, user risk, user agent, cloud app, quotas, etc. are already "unknown" in the engine (`critUnmodelled`, `critTimeWindows`); logs lack group membership unless we join the directory. Results carry a confidence split (definite vs. depends-on-unknown) rather than guessing.
3. **Category drift**: logs record the category at request time; the snapshot's custom categories may differ. We trust `urlcat` from the log and re-check custom categories against the host.
4. **Volume/memory**: up to 1M rows. Stream parse, aggregate before evaluating (dedupe on evaluation inputs), cap upload size, run as a background job, and only evaluate the relevant modules (URL Filtering / DNS / Firewall) for speed.
5. **PII**: logs contain usernames, departments, client IPs. Process in memory only, never write to `snapshots/` or disk, no logging of record contents, offer hashed-user mode in reports, add log patterns to `.gitignore`.
6. **Engine fidelity**: replay only reflects modules the engine models; SSL-bypass/no-decrypt traffic only exposes host, not full URL path.
7. **Wizard coupling**: `changes.plan()` assumes a live/mock API shape; must make sure the clone is never the session's live snapshot.

## Test strategy
- Synthetic fixtures only (`test/fixtures/replay/`): `example.com`/`example.net` hosts, RFC 5737 IPs (192.0.2.x, 198.51.100.x, 203.0.113.x), fake users like `alice@example.com`. No vendor/third-party sample logs, no real hostnames or IPs. Source: Research's synthetic fixtures in `log-formats.md`.
- Unit: header-name mapping incl. reordered/missing columns, NSS JSON / JSON-array / TSV, aggregation weights, malformed lines skipped with counts.
- Diff: demo snapshot (`src/demo-snapshot.json`) + proposed block of `blocked.example.com` → expected newly blocked counts; records already blocked keep their "already blocked by" rule; unknown-condition rules reduce confidence.
- Volume: generated 1M-row synthetic stream to check memory/time budget (run manually, not in CI).

## Docker / Zscaler cert check
- Detection exists (`scripts/detect-zscaler-cert.sh`) and build/runtime trust works (`Dockerfile` COPY + `update-ca-certificates`, `docker/entrypoint.sh` runtime mount).
- **Gap 1:** `docker/zscaler-ca.crt` is **committed to git with a real Zscaler Root CA** (commit c1f49b6) and isn't in `.gitignore`. Rule says the cert stays out of git. Fix: commit an empty placeholder, `.gitignore` the populated file (or `git update-index --skip-worktree`), or generate it outside the repo.
- **Gap 2:** the build-time cert is `COPY`'d into `/usr/local/share/ca-certificates` and stays in the final image. Rule says out of the image. Fix: multi-stage build (trust cert only in the `npm ci` stage, copy `node_modules` to a clean final stage); runtime trust stays via the bind mount.
- Neither is changed in this PR; suggest a small separate PR.
- **No CI**: the repo has no `.github/workflows`. Suggest adding a `npm test` workflow.
