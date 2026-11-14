# Impact replay — plan and scoped estimate

Question it answers: "If I block site X (or apply this wizard change), how many users and transactions would be blocked that aren't today?" ZIA has no native what-if, so we replay exported logs through `src/engine.js` against the current policy and a proposed copy, and keep only records whose outcome changes.

Status: **phases 1–3 done** (parsers, aggregation, offline proposed policy, `simulateDiff()` in `src/replay/diff.js`). Zone-less log timestamps and the daily trend default to America/New_York (DST-aware, `tz` option). Nothing wired into `server.js` or the UI yet (phase 4).

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

## Outcome groups

`simulateDiff` reports `newlyBlocked`, `newlyAllowed`, `alreadyBlocked` and `sslFailed`.
**sslFailed ("failed SSL, not inspected")**: rows whose action is a TLS/SSL handshake failure (Web Insights: "Dropped due to failed client SSL handshake"; normalized action `SSL_FAILED`). The connection failed before any policy was applied, so these rows are never counted as newly or already blocked and are not simulated. The group has a transaction count, distinct users and the top hosts as hints for possible SSL inspection exemptions. Other SSL-related actions that name a block (e.g. "Blocked due to Bad SSL record") still count as blocked.

Web Insights export layout (verified against a real export): 2 preamble lines, header on line 3, trailing comma on every row, `Event Time` like `November 2, 2026 5:50:15 AM PST` (zone abbreviation honoured), `Policy Action` carries the block reason, `Blocked Policy Type` is the blocked category (no policy-name column).

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
Fixed. Detection (`scripts/detect-zscaler-cert.sh`) still writes a local build-time CA to `docker/zscaler-ca.crt` when Zscaler Client Connector or a Zscaler cert is present, and records the live path for the runtime bind mount. Machines without Zscaler get an empty file and build and run with the default trust store.

- **Gap 1 (fixed):** the real Zscaler Root CA is removed from the tree (`git rm --cached docker/zscaler-ca.crt`). `docker/zscaler-ca.crt` is listed in `.gitignore`. The detector still writes that path locally, outside git. The Dockerfile copies the `docker/` directory and trusts the file only when it is non-empty, so a missing or empty file still builds. History was not rewritten: commit c1f49b6 still contains that public root CA (a public CA, not a private key).
- **Gap 2 (fixed):** multi-stage `Dockerfile`. The `deps` stage trusts the cert only for `npm ci`. The `final` stage copies `node_modules` and the app onto a clean `node:20-slim` image with no Zscaler cert. Runtime trust stays the `docker/entrypoint.sh` bind mount (`ZSCALER_CERT_PATH`, default `docker/empty-ca.crt`).
- **CI:** `.github/workflows/ci.yml` runs `npm ci` and `npm test` on pull requests and on pushes to `main`, on Node 20 (the `node:20-slim` image and the `pkg` node20 targets; `package.json` has no `engines` field). The same workflow runs `docker build` with no cert file present.
