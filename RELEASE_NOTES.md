# ZeroTrustPanda ZS Policy Simulator v1.8.4

**Would this be allowed, blocked or bypassed — and by what?** A standalone simulator that pulls your live Zscaler policy over OneAPI and evaluates a transaction across ZIA, ZPA, Client Connector and Cloud & Branch Connector the way the cloud would, in rule order, then shows the deciding rule and everything else that could change the outcome.

Companion to the [ZeroTrustPanda ZS Policy Wizard](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard) — same look, same OneAPI authentication.

## Downloads
| Platform | File |
|---|---|
| Windows x64 | [ZTP-Policy-Simulator-1.8.4-windows-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.4/ZTP-Policy-Simulator-1.8.4-windows-x64.zip) → `ZTP-Policy-Simulator.exe` |
| macOS Apple Silicon | [ZTP-Policy-Simulator-1.8.4-macos-arm64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.4/ZTP-Policy-Simulator-1.8.4-macos-arm64.zip) |
| macOS Intel | [ZTP-Policy-Simulator-1.8.4-macos-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.4/ZTP-Policy-Simulator-1.8.4-macos-x64.zip) |
| Source | clone the repo, or GitHub's "Source code" download on the release |

Checksums: [SHA256SUMS.txt](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.8.4/SHA256SUMS.txt)

No install, no Node.js required. Run it and it opens `http://127.0.0.1:8787`.
macOS builds are unsigned — before first run: `codesign --sign - ./ZTP-Policy-Simulator-macos-arm64 && xattr -d com.apple.quarantine ./ZTP-Policy-Simulator-macos-arm64`.

## What it does
**1 · Connect → 2 · Load policies → 3 · Simulate**  — one transaction, or a bulk CSV of thousands of IPs or hosts

- **Connect** with ZIdentity OneAPI client credentials (vanity domain, client ID, secret). The same API client is used for ZPA. Credentials stay in memory, never written to disk; the server listens on loopback only.
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

### Policy changes (new in 1.4.0): block it / allow it
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

### Evaluation order (new in 1.5.0)
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

### ZPA private application (new in 1.5.0)
In the change wizard, switch to **🔒 Private application (ZPA)**. It is preselected when ZPA decided the result, or when allowing private (RFC 1918) addresses. Single results that Client Connector bypasses also offer **🔒 Add as a ZPA private application…**.
- **Application segment:** create one (name, TCP/UDP ports, existing or new segment group, server groups), or add the destinations to an existing segment.
- **Access policy rule:** Allow, or Block (DENY), at a position you choose from the live access policy. It applies to everyone (the app only), to **SCIM groups** (pick the IdP, search groups), or to **SAML attribute = value** conditions.
- **Preview, save and undo** work the same as for ZIA. ZPA changes take effect when saved (no activation).
- **Bulk recommendations** now point private addresses that Client Connector bypasses to ZPA.
- **Not yet run against a live tenant:** the ZPA reads added in 1.5.0 (client forwarding policy, server groups, IdPs, SAML attributes, SCIM groups), ZPA writes (create/update segment, segment group, access rule, reorder) and Cloud App Control matching, and reading the ZPA customer ID from the OneAPI token (Zscaler doesn't document a claim for it, so the manual entry is the fallback). They follow Zscaler's API reference and the SDK conventions and are tested against the in-memory ZPA. Try them on ZTH first.

### Smart defaults (always stated, always overridable)
Port from the URL scheme (hostnames assume HTTPS/443) · network service and application from protocol+port (UDP/443 → QUIC) · request method GET, or CONNECT when not decrypted · file type from the URL path · standard DNS resolver for DNS app rules · default rules (order −1) evaluated last.

### Also
- **Save policy snapshot** (rules only, no credentials) to `~/ZTP-Policy-Simulator/snapshots/` and **open** it later to simulate offline.
- **Try with sample policies** — explore without a tenant.
- **Diagnostics** — every API call with status and error body.

## Known limits
- Zscaler offers no "evaluate this transaction" API, so evaluation is re-implemented from rule data. Time windows, user agent, device trust, risk score and source-port bypasses are flagged as unknown rather than evaluated.
- Cloud & Branch Connector support follows Zscaler's API reference and SDK; it was tested against sample policies, not yet a live connector tenant. When a workload group has several tag sets joined by different AND/OR operators, check one against the console.
- No per-transaction log lookup: the console's transaction-log endpoints refuse API-client tokens. Use the console's Web / Firewall Insights logs for per-transaction proof.
- ZCC field names follow the shapes verified by the Policy Wizard; report any app profile that shows "no forwarding profile linked".

## Changes in 1.8.4
- **Admin rank.** The simulator now reads **Admin Ranking** from ZIA Advanced Settings (`GET /zia/api/v1/advancedSettings`, `enableAdminRankAccess`).
  - **When it's on**, ZIA rules are evaluated by admin rank first (0 = highest, 7 = lowest), then by rule order within a rank. This matches how the ZIA policy table and Zscaler's Terraform provider sort rules.
  - **When it's off**, rank is ignored, because ZIA can still store 0 or 7 on rules.
  - Applies to URL filtering, firewall, DNS, SSL inspection, Cloud App Control, sandbox, file type and DLP.
- **🏅 Admin rank decided this.** When a rule with a lower order number but a lower rank also matches, or might match, the result tile lists it. Without ranking, that rule would decide instead.
- **Rank badges:** rule boxes, the result tile and the multi-match list show each rule's rank while ranking is on. A note in *Lookup details* says ranking is on.
- **Policy changes:** with ranking on, a new rule takes the rank of the rule it's placed above, or of the top rule for *Top*, so ZIA doesn't reject it with "Rule with rank 7 is not allowed at order N". The preview warns that the API client's admin role needs that rank.
- **Older snapshots** have no advanced settings, so they evaluate with ranking off. Reload policies to pick it up.

## Changes in 1.8.3
- **Multi-match.** When a transaction matches more than one rule in a module, the result says so and lists them.
  - The deciding rule still wins (first match in rule order).
  - The result tile gets a **🔀 Multiple rules match** box listing every later rule that also matches, with its order and action. Rules whose action differs from the deciding rule are tagged **different action**, so shadowed or conflicting policy stands out.
  - Overlaps in other modules are summarized in the same box, e.g. *Firewall (1)*. In **Every module**, each module shows a **🔀 +N match** badge and the list.
  - Catch-all and default rules (no restricting criteria, e.g. *Allow Everything Else* on category ANY) match everything, so they are counted, not listed.
  - Rules that only *might* match, because the inputs don't settle a condition such as a user group, stay under *Policy action also based on*.
  - Covered: URL filtering, firewall, DNS, SSL inspection, Cloud App Control, sandbox, file type, ZPA access policy and Cloud & Branch Connector forwarding.
  - Bulk CSV results gain an **Also matched (first match wins)** column for the deciding module.

## Changes in 1.8.2
Fixes from the first run against a live tenant (ZTH, Branch Connector):
- **Connector rule order:** the predefined rules now run in Zscaler's order, so *ZPA Pool For Stray Traffic* (order −2) comes before *Default Forwarding Rule* (order −1).
- ***ZPA Pool For Stray Traffic*** (Drop) applies only to destinations in the connector's ZPA IP pool (100.64.0.0/10 assumed). The API returns it with no criteria, so before this fix it would have dropped everything.
- **Destination groups the API returns empty**, such as the auto-created *ZPA Brokers* group (type `DSTN_OTHER`), no longer match every destination. *ZPA Brokers* matches `*.zpath.net` and `*.private.zscaler.com`; other empty groups show as "can't check". This fixes *Client Connector to ZPA* (Direct) catching all traffic.
- ***ZPA Edge App Segment*** in a ZPA forwarding rule means every ZPA application segment, so ZPA apps from a workload go to the ZPA access policy.
- **Destination groups** now also use their `ipAddresses`, IP and URL categories and countries.
- **App service groups** (e.g. `ZSCALER_CLOUD_ENDPOINTS`) are flagged as not evaluated instead of being ignored.
- **Not subscribed:** policy sets the tenant doesn't license (e.g. workload groups without a Workload Connector subscription) show as *not subscribed* instead of *failed*, and the workload panel says to simulate by source IP.
- **Recent changes (ZIA audit log):** an early `404 No Report to download` is retried instead of failing straight away.

## Changes in 1.8.1
- **Update prompt**, like the Policy Wizard. On start the simulator compares its version with the one on GitHub (`package.json` on main, cached for an hour). If a newer one is out it shows **⬆ Update available: vX** in the header and a prompt with:
  - **Download for Windows / macOS (Apple Silicon) / macOS (Intel)**, the zip for this computer;
  - **What's new**, the release page;
  - **Remind me later** (until the next start) or **Skip this version**.

  Nothing is downloaded or replaced automatically. If GitHub can't be reached the check stays quiet. Set `NO_UPDATE_CHECK=1` to turn it off.

## Changes in 1.8.0
- **Workload traffic (Cloud & Branch Connector).** A new **Traffic from** switch on Simulate: *User device (Client Connector)* or *Workload (Cloud / Branch Connector)*. For a workload, enter any of:
  - the workload's **source IP**;
  - its **tags** as `key=value`, comma-separated, optionally typed (`ATTR`, `VM`, `ENI`, `VPC`, `SUBNET`), e.g. `VPC:Vpc-id=vpc-0abc, Env=prod`;
  - a **workload group** to simulate as;
  - the **connector group** and **Cloud / Branch** connector type (Auto reads it from the connector group).
- **New product in Load policies: ☁️ Cloud & Branch Connector.** Loads the connector traffic forwarding rules (`/ztw/api/v1/ecRules/ecRdr`), workload groups, connector groups, forwarding gateways and the connector's IP source/destination groups and network services. ZIA workload groups (`/zia/api/v1/workloadGroups`) load with ZIA. Connect shows a ZTW reachability badge.
- **Workload group membership** is worked out from the tags against each group's tag expression, and shown on the result.
- **Connector forwarding** is evaluated in rule order on source IP / IP group, source workload group, connector group, location, destination (address, IP group, IP category, URL category, country), network service and application, and ZPA segment:
  - ZIA → ZIA policy applies (gateway shown);
  - ZPA → the ZPA access policy decides; if the destination isn't a ZPA segment the connection fails;
  - Direct, Local switch, Proxy chaining → bypasses Zscaler;
  - Drop → blocked;
  - no match → the default rule (ZIA).

  A new *How it gets there — Cloud & Branch Connector forwarding* card lists every rule and why it matched or not.
- **ZIA rules now evaluate their workload group condition** (firewall, DNS, URL filtering, SSL, Cloud App Control, file type, sandbox, DLP) instead of flagging it as not evaluated. User-device traffic never matches a workload-only rule, and user/group rules never match workload traffic.
- **ZPA for workloads:** SCIM, SAML, posture and trusted-network conditions don't match; *Client type* is checked against Cloud Connector (`edge_connector`) or Branch Connector; Cloud/Branch Connector group conditions are matched by name; segment bypass and the Client Connector forwarding policy are skipped.
- Location defaults to the connector group's location.
- Sample policies include workloads: lab analyzers forwarded to ZPA, SMB dropped from production, clinic medical devices sent direct to a vendor, and an SSH block for production workloads.

## Changes in 1.7.0
- **Devices:** picking a user lists their Client Connector devices (newest first) with OS, ZCC version, app profile, last seen and ZIA/ZPA/ZDX health. Simulating with a device applies only that device's app profile and platform, and flags device problems (ZPA disabled, unhealthy tunnel, stale check-in). Device one-time passwords are never read out.
- **ZPA path health:** for an allowed or blocked ZPA segment, the tile shows the App Connector groups behind it with connected/total counts, which connectors are down and since when, and Browser Access / enrollment certificates that are expiring or expired.
- **Health bar** at the top of Simulate: disconnected App Connectors, expiring certificates, and ZIA changes waiting for activation.
- **🕘 Recent changes (ZIA):** pulls the ZIA audit log for the last hours and lists who changed what; **What changed recently?** on a result filters it to the deciding rule.
- **🩺 Test from this computer:** checks what this machine sees: ip.zscaler.com (is traffic going through Zscaler, and which node), DNS through the system resolver vs 8.8.8.8 (a 100.64.x.x answer means ZPA synthetic IP), a TCP connect and the TLS certificate issuer.

## Changes in 1.6.4
- **Cleaner result tile.** It shows:
  - the action, plus the deciding rule and its order;
  - the destination and port;
  - one *Matched on* line naming the group or user that matched, for example `SCIM group "radiologists"` or `user jane@acme.org`.
- The URL category shows only when ZIA decides, not for ZPA application segments.
- **⚠️ Device posture caution.** When ZPA access depends on posture, the tile names each posture profile and what it requires, read from the ZPA posture profile (for example "file path C:\test exists (Windows)", "OS version 11.0 build 22000 or later", "device ownership is corporate"). It also shows what happens if posture fails. The simulator can't check posture itself.
- Lookup notes (DNS, directory and SCIM results) are collapsed under *Lookup details*.

## Changes in 1.6.3
- **ZPA posture rules evaluated both ways.** When the user and app match but a rule depends only on device posture, the access policy is evaluated in rule order twice: once with posture passing and once with it failing. The result shows the passing case, and *Policy action also based on* shows the failing case. For example: allowed by "Radiologists Only"; if the check fails, blocked by "Radiologist Failed Posture".
- **Fixed:** a deny-on-failed-posture rule placed above an allow-on-posture rule made the result default deny.
- Tested against a live tenant snapshot: Okta SCIM membership, posture rules and SCIM attribute (email) rules.

## Changes in 1.6.2
- **ZPA reads the user's SCIM groups from ZPA itself.** For each SCIM-enabled IdP, the simulator asks ZPA which SCIM groups it holds for the user (`scimgroup/idpId/{idp}?scimUserName=…`) and matches SCIM group conditions by group ID. This works for users who exist only in the IdP (for example Entra ID or Okta) and not in ZIdentity or ZIA.
- Checks against the API ignoring that filter: if it returns every group, the result isn't trusted and says so. An empty answer leaves SCIM conditions as *depends on user*, never as "not a member".
- **A user that isn't found now comes with the reason:** how many ZIdentity users were read, and what ZPA SCIM returned.

## Changes in 1.6.1
- **One "User or group" field** replaces the separate User, Groups and Compare as fields. Pick one user or group to simulate as it. Pick a second to compare side by side. The button changes to **Compare**.
  - Arrow keys and Enter choose from the list. Backspace removes the last pick.
  - "Use … as a user" and "Use … as a group" cover names that aren't in the directory.
- **Search shows only what matches what you typed.** The ZIdentity directory is read once per session (paged, up to 25,000 users) and filtered locally, so results stay relevant even when the API ignores its search filters. ZIA and ZPA SCIM results are filtered the same way.
- **Fixed:** a user shown in the list could come back as "not found in ZIA or ZIdentity". Lookups now use the same directory index, or the ZIdentity ID from the pick, and still require an exact match.
- **ZPA device conditions:**
  - When the user and app match an Allow rule and only device posture or trusted network is left open, the result is **Allow if the device passes**, instead of default deny. *Policy action also based on* shows that a failing device is blocked.
  - Posture profiles and trusted networks are loaded so conditions show their names.
  - Client type is assumed to be Client Connector.

## Changes in 1.6.0
- **⚖️ Compare as — up to two users or groups.** In *User / group / location*, search and pick up to two identities, each a user or a group. Simulate runs the same transaction once per pick and shows:
  - a one-line verdict: different results, same action by different rules, or the same result;
  - both result tiles side by side;
  - a module-by-module table of each verdict and deciding rule, with rows that differ highlighted;
  - full detail for each pick (conditions, Client Connector, every module).
- **Search across sources** with the same API key. Users and groups come from ZIdentity and ZIA, and groups also from ZPA SCIM (per SCIM-enabled IdP). Each result is labelled with its source. A group found in several sources shows once. Sources that refuse the API client are listed, not fatal.
- A **user pick** is simulated with their real groups and email. A **group pick** is simulated as a member of that group only.
- Sample policies include a small directory (four users) so the comparison can be tried offline.
- The Block it / Allow it user and group search shows ZIdentity matches when ZIA refuses the API client. Those matches are for reference only, because a ZIA rule needs ZIA IDs.

## Changes in 1.5.4
- **SCIM attribute conditions are evaluated.** Rules like *SCIM attribute emails.value = jane@acme.org* now match on the user's email. They sit in the same OR block as SCIM groups, so either one allows. Attribute names are read from the IdP's SCIM attribute definitions.
- **User lookup only accepts an exact match.** Before, if ZIA or ZIdentity had no exact match, the first user returned was used (for example a tenant admin account).
- **Pasted text works in the User field.** Text like `288261371856945305 = jane@acme.org` uses the email in it.
- If the user isn't in ZIA or ZIdentity, ZPA email conditions are still checked against the email you typed.
- SCIM group and SCIM attribute names are resolved even before a user is entered, so the conditions show names instead of IDs.
- The "Change this result" card speaks ZPA (application segment and access rule) when ZPA decided.

## Changes in 1.5.3
- **User lookup works for ZPA.** The user is looked up in ZIA and in **ZIdentity** (`/ziam/admin/api/v1/users` and the user's groups) with the same API key. If ZIA's user list refuses the API client (for example 403 "Resource Access Blocked"), the groups come from ZIdentity, and the result notes it.
- **ZPA access rules use the user's identity:**
  - SCIM group conditions are matched by group name. The simulator resolves the SCIM group IDs the rules reference.
  - SAML email and group attributes are matched against the user's email and groups.
  - Conditions it can't evaluate (posture, client type and other SCIM attributes) still show as *depends on user/device*.
- **ZPA results explain themselves:**
  - Each rule condition names the segments, segment groups and SCIM groups it targets, next to the segment the destination actually uses.
  - When ZPA denies by default, the card lists the Allow rules that missed and why.
  - If access depends on the user and you didn't enter one, it says which rules would allow them.

## Changes in 1.5.2
- **ZPA segments now match the way ZPA does,** not with ZIA URL rules:
  - `host.example.com` is that exact host only (in ZIA it would include subdomains).
  - `*.example.com` covers subdomains but not `example.com` itself. The simulator tells you when the bare domain only appears as a wildcard.
  - When several segments match, only the most specific one is used: an exact FQDN beats a wildcard, and a longer IP prefix wins. That segment's access rules decide. Segments whose ports don't fit are listed with their ports.
- **Wildcard queries** that only overlap narrower segments (for example `*.example.com` when only `pacs.example.com` is a segment) no longer let ZPA decide for the whole domain. ZIA decides, and the ZPA hosts underneath are listed.
- **Fixed:** a host such as `pacs.zerotrusthospital.org` could be judged by the wrong segment (whichever came first in the API list) instead of the most specific one.

## Changes in 1.5.1
- **ZPA is a product chip in Load policies**, alongside ZIA and Client Connector, so you choose whether ZPA policy loads.
- **ZPA uses the API key you connected with.** The separate *ZPA customer ID* field on Connect is gone. The simulator looks for the customer ID in the API token. If it isn't there, Load policies asks for it once, checks it against ZPA, and remembers it for that tenant (the ID only, never credentials).
- **Fixed:** after connecting without a customer ID, the ZPA chip disappeared and the 🔒 Include ZPA switch stayed greyed out, so ZPA couldn't be turned on.
- The Connect probe shows ZPA as *customer ID needed* instead of omitting it.

## Changes in 1.5.0
- **New evaluation order:** ZPA first (segment match → segment Bypass → Client Forwarding Policy → Access Policy), then the Client Connector bypasses in order (process-based flagged, VPN gateway, PAC on 80/443, IP-based app bypass, Z-Tunnel 2.0 exclusions, then inclusions), then ZIA: ATP → Firewall → DNS → URL Filtering → Cloud App Control → Sandbox → File Type → DLP.
- **ZPA decides when it carries the traffic:** ZIA and internet bypasses are skipped. On-Net segments and forwarding rules with user/device conditions appear under *Policy action also based on*.
- **🔒 Include ZPA switch:** skips loading and evaluating ZPA for customers without it.
- **Cloud App Control** rules are loaded (all 19 rule types) and evaluated by the cloud app Zscaler's lookup returns.
- **PAC results** distinguish DIRECT, another proxy and Zscaler.
- **ZPA private application change:** create or extend an app segment (segment group, server groups, ports) plus an Allow/Deny access rule placed where you choose, for everyone, SCIM groups or SAML attributes; preview, undo and audit log.
- New ZPA data loaded: client forwarding policy, server groups, access policy set, IdPs, SAML attributes; ZPA lists are paged.
- Bulk recommendations send private addresses that Client Connector bypasses to ZPA.

## Changes in 1.4.0
- **Block it / Allow it** on any single result, and **Block / Allow selected** for bulk rows (ticked rows or a filter across the whole run).
- Change wizard for URL Filtering, Firewall Filtering, DNS Control and the ATP denylist/allowlist: new or existing custom URL category and destination group (auto-split at 8,000), new rule at a position you choose or reuse an existing rule, user/group/department/location criteria.
- Preview of every API call, warnings for limits and shadowing catch-all rules, save with stop-on-error, undo, activation status and Activate, audit log file.
- Write mode is off by default per session; sample and offline sessions apply to the in-memory policy.
- Simulator now matches IPs listed as custom-category URLs and IPs on ATP allow/deny lists.
- Tested end to end on a live ZIA tenant: a 1,252-entry SOC indicator list was blocked through a new custom URL category, destination group and URL Filtering / Firewall Filtering rules.

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
