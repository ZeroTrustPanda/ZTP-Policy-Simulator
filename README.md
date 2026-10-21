# 🐼 ZeroTrustPanda ZS Policy Simulator

**Downloads (v1.8.3):** [Windows x64](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.3/ZTP-Policy-Simulator-1.8.3-windows-x64.zip) · [macOS Apple Silicon](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.3/ZTP-Policy-Simulator-1.8.3-macos-arm64.zip) · [macOS Intel](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.3/ZTP-Policy-Simulator-1.8.3-macos-x64.zip) · [SHA256SUMS](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.3/SHA256SUMS.txt) — all builds in [`downloads/`](downloads/). Release notes: [RELEASE_NOTES.md](RELEASE_NOTES.md) · history: [CHANGELOG.md](CHANGELOG.md)

Standalone tool that answers "would this be allowed, blocked or bypassed — and by what?" against your live Zscaler policy. Same look as the [ZeroTrustPanda ZS Policy Wizard](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard).

## Flow
1. **Connect** — OneAPI client credentials (ZIdentity vanity domain, client ID, secret). The same API client is used for ZIA, Client Connector and ZPA. Probes each one's reachability.
2. **Load policies** — tick the products to load (ZIA, Client Connector, ZPA) and pull the rule sets with a live per-policy-set status table. Reload any time.
3. **Simulate** — one transaction at a time, or a **bulk CSV** of IPs/hosts (see below). Enter a destination (URL, host, IP, CIDR, wildcards), protocol/port or network service, and optional details (user/group/location, file/method/category, application, source IP/country, test bypass inputs). Leave the destination blank for "is this port/service blocked for everyone?".

## Result
Two tiles at the top:
- **Policy rule action** — what happens for anyone your inputs don't narrow down: **Block · Allow · Bypass · Isolate · Caution**, the module and rule that decides it (with order), and tags: **Not inspected** (SSL Do Not Decrypt) and **Inspect only** (DLP / sandbox scan content). "Why this rule matched" and "Rule that decided in each module" expand underneath.
- **Policy action also based on** — every condition that would change that action, each with its own action and rule: 👥 user / group / department, 📍 location, ⏱ time window / device trust / other rule conditions, 💻 Client Connector app profile + network type (bypasses), 📄 uploaded content (DLP), ✏️ inputs you haven't entered. Top 3 shown, the rest under "Show more". For a bypassed result it shows what ZIA would do if the traffic were forwarded.

Below the tiles:
- **How it gets there** — every Client Connector app profile, one row each, per network type: forwarding action, IPv4 / domain inclusions and exclusions, VPN gateway bypasses, IP-based app bypasses, PAC files (evaluated with FindProxyForURL).
- **Every module** — firewall, DNS, SSL, ATP, URL filtering, file type, sandbox, DLP, ZPA, with all evaluated rules on click.

Smart defaults: port from the URL scheme (hostnames assume HTTPS/443), network service/application inferred from protocol+port (UDP/443 → QUIC), request method GET (CONNECT when not decrypted), file type from the URL path, standard DNS resolver for DNS app rules. Every assumption is stated on the result and can be overridden.

## Workloads (Cloud & Branch Connector)
Switch **Traffic from** to *Workload* and enter the workload's source IP, tags (`VPC:Vpc-id=vpc-0abc, Env=prod`), workload group and connector group. The simulator works out workload-group membership from the tags, evaluates the connector's traffic forwarding rules (ZIA, ZPA, Direct, Local switch, Proxy chaining, Drop), then ZIA policy (including each rule's workload group condition) or ZPA access policy (Cloud/Branch Connector client type and connector groups). Tick **☁️ Cloud & Branch Connector** in Load policies; the API client needs Cloud & Branch Connector access in ZIdentity.

## Evaluation order
The simulator follows the path a transaction takes:

1. **ZPA first.** If the destination (and port) matches an application segment, it checks the segment's **Bypass** setting (Never / On-Net / Always), then the **Client Forwarding Policy** (Intercept / Intercept Accessible / Bypass). If ZPA carries the traffic, the **Access Policy** decides, and ZIA and the internet bypasses don't apply.
2. **Client Connector bypasses, per app profile and network type:**
   1. Process-based bypass. This is flagged when configured but not evaluated, because it depends on the client process.
   2. VPN gateway bypass.
   3. ZPA segment Always-bypass and 4. ZPA client forwarding (both in step 1).
   5. **PAC file** for web traffic on 80/443: DIRECT, sent to another proxy, or sent to Zscaler.
   6. IP-based application bypass.
   7. Z-Tunnel 2.0 exclusions (domain and IP).
   8. Z-Tunnel 2.0 inclusions.
3. **ZIA, in this order:** Advanced Threat Protection → Firewall → DNS Control → URL Filtering → **Cloud App Control** (new) → Sandbox → File Type Control → DLP. SSL Inspection is applied as a modifier: it decides whether ATP, URL Filtering, DLP and the others can see inside HTTPS.

**🔒 Private Access (ZPA)** is a product chip in **Load policies**, next to Internet Access (ZIA) and Client Connector: tick it to load ZPA policy, untick it to skip ZPA entirely. ZPA uses the same OneAPI API client. The ZPA customer ID is read from the API token when it's there; otherwise the step asks for it once (ZPA Admin Portal → Administration → API Keys), checks it, and remembers it for that tenant. **🔒 Include ZPA** (next to the Single / Bulk switch) then turns ZPA on or off per simulation; it is greyed out when ZPA wasn't loaded.

**Cloud App Control** rules are loaded for every rule type. A rule matches when Zscaler's URL lookup names the destination's cloud application. Partial restrictions, such as allowing use but denying uploads, are shown as notes.

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

## Policy changes: block it / allow it
The simulator can now fix what it finds. It is **read-only until you switch on "Allow policy changes"** for the session, and every change is previewed call by call before anything is sent.

- **Single result:** under the result tiles, *Change this result* offers **✅ Allow it…** for a blocked, cautioned or isolated destination, and **⛔ Block it…** for an allowed one. For a Client Connector bypass it explains that ZIA rules apply only once the bypass is removed.
- **Bulk run:** tick rows in the results, or use the filter (result, "not as expected", category) to select across the whole run, then **⛔ Block selected…** or **✅ Allow selected…**.
- **The wizard** asks, in order:
  1. **Destinations:** editable, with optional CIDR collapsing.
  2. **Where to apply:** 🌐 URL Filtering (web), 🧱 Firewall Filtering (all ports), 🔤 DNS Control, or 🛡 ATP (denylist to block, Security Exceptions allowlist to allow). It preselects the area that decided the traffic.
  3. **Custom URL category:** create one or add to an existing one. URL Filtering uses it, and DNS Control uses it as both the requested-domain and resolved-IP category.
  4. **Destination group:** create one or add to an existing one, for Firewall Filtering. Groups fill to 8,000 entries and extra groups are created automatically. Hostnames go in a separate FQDN group.
  5. **Rule per area:** create a new rule with a name (31 characters max), a position you choose from the current rule list (the rule that currently decides is marked) and, for firewall blocks, Drop or Reset. Or reuse an existing rule that already uses the chosen category or group, so only the entries are added.
  6. **Who:** everyone, or specific groups, departments, users and locations, searched live from ZIA.
- **Preview** lists every API call with its body, plus warnings: limits, names, and an earlier catch-all rule with the opposite action that would stop the new rule ever applying.
- **Save** runs the calls in order and stops at the first error. Changes are saved but not live: a *Changes pending activation* badge appears, and **Activate** is in the dialog and under **🧾 Policy changes**.
- **Undo:** every change can be undone from 🧾 Policy changes (deletes what was created, restores what was edited). Each change is also written to `~/ZTP-Policy-Simulator/changes/<tenant>.jsonl`, with no credentials.
- **Sample and offline sessions** apply changes to the in-memory policy only, so you can rehearse a change and re-simulate before touching a tenant.
- **API client:** needs ZIA read/write scope in ZIdentity for changes. Payloads follow the ZeroTrustPanda Policy Wizard's verified templates, and the block workflow has been tested end to end on a live ZIA tenant. If ZIA rejects a call, the result names the call and ZIA's error, and undo reverts the steps that ran.

### ZPA private application
In the change wizard, switch to **🔒 Private application (ZPA)**. It is preselected when ZPA decided the result, or when allowing private (RFC 1918) addresses. Single results that Client Connector bypasses also offer **🔒 Add as a ZPA private application…**.
- **Application segment:** create one (name, TCP/UDP ports, existing or new segment group, server groups), or add the destinations to an existing segment.
- **Access policy rule:** Allow, or Block (DENY), at a position you choose from the live access policy. It applies to everyone (the app only), to **SCIM groups** (pick the IdP, search groups), or to **SAML attribute = value** conditions.
- **Preview, save and undo** work the same as for ZIA. ZPA changes take effect when saved (no activation).
- **Bulk recommendations** now point private addresses that Client Connector bypasses to ZPA.
- **Not yet run against a live tenant:** the ZPA reads added in 1.5.0 (client forwarding policy, server groups, IdPs, SAML attributes, SCIM groups), ZPA writes (create/update segment, segment group, access rule, reorder) and Cloud App Control matching, and reading the ZPA customer ID from the OneAPI token (Zscaler doesn't document a claim for it, so the manual entry is the fallback). They follow Zscaler's API reference and the SDK conventions and are tested against the in-memory ZPA. Try them on ZTH first.

## Run
- Windows: `ZTP-Policy-Simulator.exe` — serves http://127.0.0.1:8787 and opens your browser (`PORT`, `NO_OPEN=1` and `NO_UPDATE_CHECK=1` supported). When a newer version is on GitHub it shows an update prompt with the download for your computer.
- macOS: `codesign --sign - ./ZTP-Policy-Simulator-macos-arm64 && xattr -d com.apple.quarantine ./ZTP-Policy-Simulator-macos-arm64`, then run it.
- From source: `npm install && npm start`; tests `npm test`; build `npm run build`.
- **Try with sample policies** works with no tenant. **Save policy snapshot** (rules only, no credentials) writes to `~/ZTP-Policy-Simulator/snapshots/`; **Open saved snapshot** simulates offline.

## API notes
- Auth mirrors the wizard: client-credentials token without audience for ZIA/ZCC/ZPA.
- ZCC field names follow the wizard's verified templates (`packetTunnelIncludeList/ExcludeList`, `packetTunnelDnsIncludeList/ExcludeList`, `vpnGateways`, `appServiceIds`, `pac_url`, `onNetPolicy`, `forwardingProfileActions[]`).
- Not evaluated (flagged as unknown): time windows, user-agent, device trust, risk score, source-port bypasses, process-based bypasses, ZPA user/posture conditions.

## Project layout
- `server.js` — local Express server (loopback only) and API routes
- `src/zscaler.js` — OneAPI client and policy loader
- `src/engine.js` — ordered rule evaluation and outcome model
- `src/zcc.js` — Client Connector per-profile forwarding evaluation
- `src/workload.js` — workload tags, workload group expressions and membership
- `src/update.js` — update check against GitHub
- `src/live.js` — devices, ZPA path health, local checks, ZIA audit log
- `src/changes.js` — block/allow change plans, apply, undo, activation, in-memory ZIA for sample sessions
- `src/recommend.js` — expected-vs-actual recommendations, category advice, rules per category
- `src/bulk.js` — CSV parsing, CIDR/range expansion, batched category lookup, results CSV
- `src/matchers.js` — wildcard domain, IP/CIDR/range, port and PAC matching
- `public/index.html` — single-file UI
- `test/` — `node --test` suite with sample policies
