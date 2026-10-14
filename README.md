# 🐼 ZeroTrustPanda ZS Policy Simulator

**Downloads (v1.3.0):** [Windows x64](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/ZTP-Policy-Simulator-1.3.0-windows-x64.zip) · [macOS Apple Silicon](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/ZTP-Policy-Simulator-1.3.0-macos-arm64.zip) · [macOS Intel](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/ZTP-Policy-Simulator-1.3.0-macos-x64.zip) · [SHA256SUMS](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.3.0/SHA256SUMS.txt) — all builds in [`downloads/`](downloads/). Release notes: [RELEASE_NOTES.md](RELEASE_NOTES.md) · history: [CHANGELOG.md](CHANGELOG.md)

Standalone, read-only tool that answers "would this be allowed, blocked or bypassed — and by what?" against your live Zscaler policy. Same look as the [ZeroTrustPanda ZS Policy Wizard](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard).

## Flow
1. **Connect** — OneAPI client credentials (ZIdentity vanity domain, client ID, secret; optional ZPA customer ID). Probes ZIA / Client Connector / ZPA reachability.
2. **Load policies** — pulls the rule sets with a live per-policy-set status table. Reload any time.
3. **Simulate** — one transaction at a time, or a **bulk CSV** of IPs/hosts (see below). Enter a destination (URL, host, IP, CIDR, wildcards), protocol/port or network service, and optional details (user/group/location, file/method/category, application, source IP/country, test bypass inputs). Leave the destination blank for "is this port/service blocked for everyone?".

## Result
Two tiles at the top:
- **Policy rule action** — what happens for anyone your inputs don't narrow down: **Block · Allow · Bypass · Isolate · Caution**, the module and rule that decides it (with order), and tags: **Not inspected** (SSL Do Not Decrypt) and **Inspect only** (DLP / sandbox scan content). "Why this rule matched" and "Rule that decided in each module" expand underneath.
- **Policy action also based on** — every condition that would change that action, each with its own action and rule: 👥 user / group / department, 📍 location, ⏱ time window / device trust / other rule conditions, 💻 Client Connector app profile + network type (bypasses), 📄 uploaded content (DLP), ✏️ inputs you haven't entered. Top 3 shown, the rest under "Show more". For a bypassed result it shows what ZIA would do if the traffic were forwarded.

Below the tiles:
- **How it gets there** — every Client Connector app profile, one row each, per network type: forwarding action, IPv4 / domain inclusions and exclusions, VPN gateway bypasses, IP-based app bypasses, PAC files (evaluated with FindProxyForURL).
- **Every module** — firewall, DNS, SSL, ATP, URL filtering, file type, sandbox, DLP, ZPA, with all evaluated rules on click.

Smart defaults: port from the URL scheme (hostnames assume HTTPS/443), network service/application inferred from protocol+port (UDP/443 → QUIC), request method GET (CONNECT when not decrypted), file type from the URL path, standard DNS resolver for DNS app rules. Every assumption is stated on the result and can be overridden.

## Bulk test (CSV)
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

## Category lookup (single page)
**🏷 Look up category** next to Simulate looks up the Destination with Zscaler (up to 100 entries, separated by commas or spaces). It shows each category, tagged *threat*, *low collateral* or *broad*, plus any cloud app Zscaler maps it to, and lists every loaded rule that uses that category (URL Filtering, Firewall, DNS, SSL Inspection, ATP setting) with its order and action. It needs a live tenant connection.

## Run
- Windows: `ZTP-Policy-Simulator.exe` — serves http://127.0.0.1:8787 and opens your browser (`PORT`, `NO_OPEN=1` supported).
- macOS: `codesign --sign - ./ZTP-Policy-Simulator-macos-arm64 && xattr -d com.apple.quarantine ./ZTP-Policy-Simulator-macos-arm64`, then run it.
- From source: `npm install && npm start`; tests `npm test`; build `npm run build`.
- **Try with sample policies** works with no tenant. **Save policy snapshot** (rules only, no credentials) writes to `~/ZTP-Policy-Simulator/snapshots/`; **Open saved snapshot** simulates offline.

## API notes
- Auth mirrors the wizard: client-credentials token without audience for ZIA/ZCC/ZPA.
- ZCC field names follow the wizard's verified templates (`packetTunnelIncludeList/ExcludeList`, `packetTunnelDnsIncludeList/ExcludeList`, `vpnGateways`, `appServiceIds`, `pac_url`, `onNetPolicy`, `forwardingProfileActions[]`).
- Not evaluated (flagged as unknown): time windows, user-agent, device trust, risk score, source-port bypasses.

## Project layout
- `server.js` — local Express server (loopback only) and API routes
- `src/zscaler.js` — OneAPI client and policy loader
- `src/engine.js` — ordered rule evaluation and outcome model
- `src/zcc.js` — Client Connector per-profile forwarding evaluation
- `src/recommend.js` — expected-vs-actual recommendations, category advice, rules per category
- `src/bulk.js` — CSV parsing, CIDR/range expansion, batched category lookup, results CSV
- `src/matchers.js` — wildcard domain, IP/CIDR/range, port and PAC matching
- `public/index.html` — single-file UI
- `test/` — `node --test` suite with sample policies
