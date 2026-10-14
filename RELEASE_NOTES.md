# ZeroTrustPanda ZS Policy Simulator v1.3.0

**Would this be allowed, blocked or bypassed — and by what?** A standalone, read-only simulator that pulls your live Zscaler policy over OneAPI and evaluates a transaction across ZIA, ZPA and Client Connector the way the cloud would, in rule order, then shows the deciding rule and everything else that could change the outcome.

Companion to the [ZeroTrustPanda ZS Policy Wizard](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard) — same look, same OneAPI authentication.

## Downloads
| Platform | File |
|---|---|
| Windows x64 | [ZTP-Policy-Simulator-1.3.0-windows-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/ZTP-Policy-Simulator-1.3.0-windows-x64.zip) → `ZTP-Policy-Simulator.exe` |
| macOS Apple Silicon | [ZTP-Policy-Simulator-1.3.0-macos-arm64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/ZTP-Policy-Simulator-1.3.0-macos-arm64.zip) |
| macOS Intel | [ZTP-Policy-Simulator-1.3.0-macos-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/ZTP-Policy-Simulator-1.3.0-macos-x64.zip) |
| Source | clone the repo, or GitHub's "Source code" download on the release |

Checksums: [SHA256SUMS.txt](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/SHA256SUMS.txt)

No install, no Node.js required. Run it and it opens `http://127.0.0.1:8787`.
macOS builds are unsigned — before first run: `codesign --sign - ./ZTP-Policy-Simulator-macos-arm64 && xattr -d com.apple.quarantine ./ZTP-Policy-Simulator-macos-arm64`.

## What it does
**1 · Connect → 2 · Load policies → 3 · Simulate**  — one transaction, or a bulk CSV of thousands of IPs or hosts

- **Connect** with ZIdentity OneAPI client credentials (vanity domain, client ID, secret, optional ZPA customer ID). Credentials stay in memory, never written to disk; the server listens on loopback only.
- **Load policies** — URL filtering, firewall, DNS, SSL inspection, file type, sandbox, web DLP, ATP settings and lists, custom URL categories, network services/groups, network application groups, IP source/destination groups, locations; Client Connector Windows/macOS app profiles, forwarding profiles, IP-based app bypasses and referenced PAC files; ZPA application segments and access policy. Per-policy-set status table with real API errors.
- **Simulate** any mix of: destination (URL, host, IP, CIDR, range, wildcards like `*.google.com`), protocol/port, network service, user/group/department/location, file type/operation, request method, URL category, network application, source IP, destination country, plus test PAC / inclusion / exclusion / VPN gateway lists. Leave the destination blank to ask "is this port blocked for everyone?".

### Results
- **Policy rule action** — Block · Allow · Bypass · Isolate · Caution, with the deciding module and rule (and order), plus **Not inspected** (SSL Do Not Decrypt) and **Inspect only** (DLP/sandbox) tags.
- **Policy action also based on** — every condition that would change that action, each with its own action and rule: user/group/department, location, time window / device trust, Client Connector app profile + network type, uploaded content (DLP). For bypassed traffic it shows what ZIA would do if it were forwarded.
- **How it gets there** — each Client Connector app profile, per network type (On-/Off-/VPN-/Split VPN-Trusted): forwarding action (None / Tunnel / Tunnel with local proxy / Enforce proxy), IPv4 and domain inclusions/exclusions, VPN gateway bypasses, IP-based app bypasses, PAC results (evaluated with `FindProxyForURL`).
- **Every module** — firewall, DNS, SSL, ATP, URL filtering, file type, sandbox, DLP and ZPA with every evaluated rule and each criterion's match / no match / unknown.

### Bulk test (CSV) — new in 1.2.0
Switch the Simulate step to **📋 Bulk test (CSV)** to run thousands of destinations at once (about a minute for 50,000 IPs, plus the category lookup).

- **Input:** drop a CSV, choose a file or paste a list. Use one destination per line, or a header row with an `ip` column. Optional columns are `port`, `protocol`, `sourceIp`, `location`, `destCountry`, `category`, `user` and `label`. A blank port means TCP/443. CIDRs and ranges expand to one row per address (up to a /16 per row, 250,000 rows in all). Hosts and URLs work too. **Download a template** in the UI gives an example file.
- **Zscaler categories:** each unique IP or host is looked up with ZIA's `urlLookup`, 100 per call. If Zscaler rate-limits, asks to retry (HTTP 412 or 5xx) or refuses lookups after earlier calls succeeded (a quota), the run pauses and retries on its own and shows why. If the quota never clears, the rows it couldn't look up are labelled "lookup stopped (Zscaler quota): rerun later". A `category` column in your file overrides the lookup.
- **Output:** counts (Blocked / Allowed / Bypassed / Isolated / Caution / allowed but blockable), the rules that decided the rows that weren't allowed, top categories, and a preview of the flagged rows. **Download all results** or **Flagged rows only** as a CSV with one row per address:
  - the category and any security-alert category
  - the result and deciding module, rule and order
  - the firewall and URL filtering verdicts with their rules
  - the Client Connector forwarding verdict
  - "Could be blocked by", for user, location or time conditions that would block an allowed row
- **Expected result and recommendations:** set **Expected result** (Should be blocked / Should be allowed) for the whole run, or add an `expected` column (block / allow) per row. Each row gets *Meets expectation*, *Recommended area* and *Recommendation*, and the report adds a **Recommendations** card:
  - **By area:** how many rows to fix where (🛡 ATP, 🧱 Firewall, 🌐 URL Filtering, 🔤 DNS, 💻 Client Connector, ☁️ Cloud App), what to do, and a **⬇ list** of the destinations, one per line, to paste into an IP destination group or custom URL category.
  - **By category:** whether to block or allow each category. Threat categories go to ATP. Low-collateral categories such as `MISCELLANEOUS_OR_UNKNOWN`, `NEWLY_REG_DOMAINS` and `ANONYMIZER` can be blocked outright. Broad business categories should stay as they are; list the destinations instead.
  - **How the area is chosen:** a threat category whose ATP setting is off → turn on the ATP setting. An IP with a broad category or none → a Firewall IP destination group in a Block rule above the allowing rule, which covers all ports. A host → a custom URL category in URL Filtering (or the ATP denylist), plus DNS Control. A Client Connector bypass → fix the app profile. Expected allow but blocked → an ATP allowlist entry or a custom-category Allow rule above the blocking rule, not unblocking the category for everyone.
  - **Downloads:** **Not as expected only** downloads just the mismatches.
- **What an IP can match:** Client Connector inclusions, exclusions and bypasses; firewall destination IPs, IP groups, IP categories and countries; custom URL categories that list IP ranges; URL filtering category rules (once the category is known); ZPA segments defined by IP or CIDR. DNS Control doesn't apply to a bare IP, because there's no DNS lookup.

Single simulations of a single IP or host now also show its Zscaler category (`category: … (Zscaler lookup)`).

### Category lookup (single page)
**🏷 Look up category** next to Simulate looks up the Destination with Zscaler (up to 100 entries, separated by commas or spaces). It shows each category, tagged *threat*, *low collateral* or *broad*, plus any cloud app Zscaler maps it to, and lists every loaded rule that uses that category (URL Filtering, Firewall, DNS, SSL Inspection, ATP setting) with its order and action. It needs a live tenant connection.

### Smart defaults (always stated, always overridable)
Port from the URL scheme (hostnames assume HTTPS/443) · network service and application from protocol+port (UDP/443 → QUIC) · request method GET, or CONNECT when not decrypted · file type from the URL path · standard DNS resolver for DNS app rules · default rules (order −1) evaluated last.

### Also
- **Save policy snapshot** (rules only, no credentials) to `~/ZTP-Policy-Simulator/snapshots/` and **open** it later to simulate offline.
- **Try with sample policies** — explore without a tenant.
- **Diagnostics** — every API call with status and error body.

## Known limits
- Zscaler offers no "evaluate this transaction" API, so evaluation is re-implemented from rule data. Time windows, user agent, device trust, risk score and source-port bypasses are flagged as unknown rather than evaluated.
- No per-transaction log lookup: the console's transaction-log endpoints refuse API-client tokens. Use the console's Web / Firewall Insights logs for per-transaction proof.
- ZCC field names follow the shapes verified by the Policy Wizard; report any app profile that shows "no forwarding profile linked".

## Changes in 1.3.0
- **🏷 Look up category** button on the single-transaction page: Zscaler category, threat / low-collateral / broad tag, cloud app, and the policy rules that use each category.
- **Bulk recommendations:** expected result (run-wide or per-row `expected` column), meets / doesn't meet, the recommended area (ATP / Firewall / URL Filtering / DNS / Client Connector / Cloud App) with a specific fix, advice per category, and per-area destination lists to paste into policy.
- Results CSV adds *Zscaler cloud app*, *Expected*, *Meets expectation*, *Recommended area* and *Recommendation*.

## Changes in 1.2.1
- Category lookup no longer gives up on a large list. Zscaler's "please retry" (HTTP 412), 5xx and network errors are retried with backoff. A 401/403 after earlier calls succeeded is treated as a quota: the run pauses and retries for up to about 2 hours instead of marking the rest "lookup not permitted". Only a refusal on the first call means not permitted.
- Lookups that failed are retried on the next run in the same session, instead of being skipped from the cache.
- The progress card shows why the run is paused, the retry count and the last Zscaler error.

## Changes in 1.2.0
- **Bulk test (CSV):** upload or paste IPs, CIDRs, ranges or hosts and get a results CSV with category, action, deciding rule and "could be blocked by" for every address. The run shows live progress, waits out rate limits, can be cancelled, and caps at 250,000 rows.
- **Zscaler category lookup for IPs**, in bulk and for single simulations. It feeds firewall IP-category rules and URL filtering category rules.
- User lookups are cached per session.
- Binaries are built with source embedded (`--no-bytecode`). This fixes the 1.1.0 startup error `Cannot find module '/snapshot/zps/server.js'`.

## Changes in 1.1.0
- New two-tile result header: Policy rule action + Policy action also based on.
- Isolate and Caution reported as their own actions.
- Per-app-profile Client Connector forwarding evaluation (inclusions/exclusions, VPN gateway bypass, app bypass, PAC, forwarding action per network type).
- Only conditions that would change the outcome are shown; DLP suppressed when SSL isn't decrypted.
- Removed the Z-Insights activity panel.
