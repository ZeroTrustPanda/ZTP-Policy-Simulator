# Changelog

## 1.8.5 — 2026-10-29
- App service groups (Office 365 / UCaaS One Click) evaluated by domain and published IP ranges; generic guard makes any unevaluated rule condition "unknown"; cloud apps, REDIR_ZPA, resolved-IP and file-type categories evaluated.
- No caching: lookups re-queried per simulation, fresh bulk runs, no-store responses, stale result cleared.
- Failed/timed-out policy sets and lookups reported ("Couldn't fully run: Zscaler timed out"); bulk column.
- Save snapshot downloads in the browser with a confirmation; Open snapshot / bulk file pickers fixed; toasts.

## 1.8.4 — 2026-10-28
- Admin rank: reads enableAdminRankAccess from ZIA advanced settings; when on, ZIA rules evaluate by rank then order; rank effects shown on the result; rank badges; new rules in policy changes take the anchor rule's rank.

## 1.8.3 — 2026-10-21
- Multi-match: later rules that also match are listed per module (tile box, module badge, bulk CSV column); different actions flagged; catch-alls counted.

## 1.8.2 — 2026-10-20
- Live-tenant fixes: predefined connector rule order (−2 before −1), ZPA Pool For Stray Traffic scoped to the ZPA IP pool, empty Zscaler-managed destination groups (ZPA Brokers) no longer match everything, ZPA Edge App Segment = all ZPA apps, app service groups flagged, NOT_SUBSCRIBED shown as not subscribed, audit-log 404 retry.

## 1.8.1 — 2026-10-20
- Update check against GitHub (header badge + prompt with the download for this platform, remind later / skip version, `NO_UPDATE_CHECK=1`).

## 1.8.0 — 2026-10-20
- Workload traffic: "Traffic from" switch (user device / workload); workload source IP, tags, workload group, connector group and type.
- Cloud & Branch Connector product: forwarding rules (ecRules/ecRdr), workload groups, connector groups, gateways, ZTW IP groups and network services; ZIA workload groups.
- Connector forwarding module (ZIA / ZPA / Direct / Local switch / Proxy chain / Drop) with its own result card; ZPA handoff only when the connector forwards to ZPA.
- workloadGroups criterion evaluated in all ZIA rule modules; ZPA client type, connector group and identity/posture operands handled for workloads.
- Sample workload policies and tests.

## 1.7.0 — 2026-10-20
- Client Connector devices per user with health; device-specific app profile evaluation and device warnings.
- ZPA path health (App Connector status, certificate expiry) on ZPA results; health bar.
- ZIA audit log ("Recent changes", "What changed recently?").
- Local checks from this computer (ip.zscaler.com, DNS, TCP, TLS issuer).

## 1.6.4 — 2026-10-15
- Result tile trimmed: action, rule, destination, Matched on (matching operand only), category only for ZIA; notes collapsed.
- Posture caution box with each profile's requirement from postureConfig and the fail-case outcome.

## 1.6.3 — 2026-10-15
- ZPA: posture-only open conditions evaluated as pass/fail scenarios in rule order (handles deny-if-fails above allow-if-passes); verified on a live ZTH snapshot.

## 1.6.2 — 2026-10-15
- ZPA SCIM membership lookup per SCIM IdP (scimUserName filter, ignored-filter guard); SCIM_GROUP matched by ID.
- Not-found diagnostics for ZIdentity and ZPA SCIM in the result notes.

## 1.6.1 — 2026-10-15
- Single "User or group" picker (1 = simulate as, 2 = compare); keyboard navigation; typed fallbacks.
- ZIdentity directory index (paged, cached 10 min) for search and exact lookups; all search sources filtered locally; picks carry the ZIdentity ID.
- ZPA: allow conditional on device posture / trusted network when identity matches; posture profiles and trusted networks loaded; CLIENT_TYPE assumes Client Connector.

## 1.6.0 — 2026-10-15
- Compare as: up to two user/group picks, side-by-side tiles, module-by-module diff table, verdict line.
- /api/identities: users and groups from ZIdentity, ZIA and ZPA SCIM, merged and labelled by source.
- Sample directory users; directory search falls back to ZIdentity when ZIA refuses.

## 1.5.4 — 2026-10-15
- ZPA SCIM attribute conditions (email/userName/department/groups) evaluated; attribute names resolved via /idp/{idp}/scimattribute/{id}.
- User lookup: exact match only (no first-result fallback); email extracted from pasted text; typed email used for ZPA conditions when the user isn't found.
- SCIM names resolved without a user; ZPA wording on the change card.

## 1.5.3 — 2026-10-15
- User lookup: ZIA then ZIdentity (/ziam/admin/api/v1/users + /users/{id}/groups); ZIA 403 no longer blocks user context.
- ZPA access/forwarding rules: SCIM_GROUP matched by resolved group name, SAML email/group attributes matched, negated conditions honoured; condition details name targets vs the destination's segment; default-deny lists the Allow rules that missed; user-dependent results name the rules that would allow.

## 1.5.2 — 2026-10-15
- ZPA segment matching uses ZPA semantics: exact FQDN entries, *.domain = subdomains only, most specific segment wins (port-aware); hint when the apex is only covered by a wildcard; wildcard queries overlapping only narrower segments fall through to ZIA.

## 1.5.1 — 2026-10-15
- ZPA moved to a Load policies product chip (with ZIA and Client Connector); the Connect form no longer has a ZPA customer ID field.
- ZPA uses the same OneAPI client: customer ID read from the token claims when present (verified against ZPA), otherwise asked inline once in Load policies, verified, and remembered per tenant.
- Fix: ZPA chip hidden and Include ZPA switch stuck disabled after connecting without a customer ID.

## 1.5.0 — 2026-10-15
- Evaluation order: ZPA (segment match, segment bypass type, client forwarding policy, access policy) → Client Connector bypasses (process flagged, VPN gateway, PAC 80/443, IP app bypass, Tunnel 2.0 exclusions, inclusions) → ZIA (ATP, Firewall, DNS, URL, Cloud App Control, Sandbox, File Type, DLP; SSL as modifier).
- Include ZPA switch (persisted; also controls loading). Cloud App Control module and loader (19 rule types). PAC other-proxy detection.
- ZPA private application change: app segment create/extend, segment group, server groups, ports, access rule (Allow/Deny, placement, everyone / SCIM / SAML), undo, in-memory ZPA.
- Loader: ZPA client forwarding policy, server groups, access policy set, IdPs, SAML attributes, SCIM group search; ZPA paging.
- Recommendations: private bypassed addresses → ZPA.

## 1.4.0 — 2026-10-14
- Policy changes: Block it / Allow it (single) and Block / Allow selected (bulk); wizard for URL Filtering, Firewall Filtering, DNS Control and ATP lists; create or reuse custom URL categories, destination groups (auto-split at 8,000) and rules; placement chosen from the live rule list; user/group/department/location criteria.
- Preview of every call, shadowing and limit warnings, stop-on-error apply, undo, activation, per-tenant audit log; write mode opt-in per session; in-memory ZIA for sample/offline sessions.
- Engine: IPs in custom-category URL lists and ATP lists now match IP destinations.
- Sample policy: ATP lists use the real API field names; firewall default rule flagged as default.
- Tested end to end on a live ZIA tenant (block workflow with a 1,252-entry list).

## 1.3.0 — 2026-10-14
- Single page: 🏷 Look up category (up to 100 entries) with category risk tag, cloud app and the rules referencing each category.
- Bulk: expected result (run-wide or `expected` column); per-row meets / recommended area / recommendation; Recommendations card by area and by category; per-area destination list download; "Not as expected only" CSV.
- Lookup keeps Zscaler's cloud `application` when returned.

## 1.2.1 — 2026-10-14
- Bulk category lookup: retry 412 / 5xx / network errors with backoff; treat 401/403 after successful calls as a quota (pause and retry, up to ~2 h) instead of stopping; only a first-call refusal means not permitted.
- Failed lookups are not cached as final, so a rerun retries them.
- Progress shows the pause reason, retry count and last Zscaler error.

## 1.2.0 — 2026-10-14
- Bulk test (CSV) mode in the Simulate step: CSV/paste input with header aliases, CIDR/range expansion (/16 per row, 250,000 rows max), batched ZIA `urlLookup` (100 per call) with rate-limit waits, progress, cancel, summary and preview, and results CSV (all or flagged only, formula-safe).
- Zscaler category lookup for single IPs in one-off simulations (cached per session); user lookups cached.
- "Could be blocked by" only counts user / location / time conditions, and ignores category conditions when no category is known.
- Build script uses `--no-bytecode --public` (fixes the startup error in 1.1.0 binaries).

## 1.1.0 — 2026-10-13
- Two-tile result header: **Policy rule action** (Block / Allow / Bypass / Isolate / Caution, with Not inspected and Inspect only tags) and **Policy action also based on** (identity, location, other rule conditions, Client Connector profile + network type, DLP content).
- Isolate and Caution are distinct actions.
- Earlier rules that depend on missing context are only shown when they'd change the outcome.
- DLP / inspect-only suppressed when SSL is not decrypted.
- Removed the Z-Insights activity panel.
- Rebuilt all binaries with source embedded (`--no-bytecode`). Fixes `Cannot find module '/snapshot/zps/server.js'` on launch in the 1.1.0 macOS and Windows builds.

## 1.0.0 — 2026-10-13
- Renamed **ZeroTrustPanda ZS Policy Simulator**; UI rebuilt in the Policy Wizard theme with Connect → Load policies → Simulate steps.
- Per-app-profile Client Connector forwarding evaluator using the wizard's verified field names, IP-based app bypass definitions, app-profile and system PAC fetching.
- Smart defaults: port from scheme, file type from URL path, standard DNS resolver for DNS app rules.

## 0.x — 2026-10-13
- 0.3: Logs tab experiments (Z-Insights summaries; console transaction-log endpoints proved to refuse API-client tokens).
- 0.2: Fixed OneAPI auth (wizard-style token, ZCC `deviceType`), connect/load split with progress, default rules last, request-method evaluation, protocol/port → service/application inference (QUIC), CIDR destinations, snapshots, optional destination.
- 0.1: First engine — ordered evaluation for URL filtering, firewall, DNS, SSL, file type, sandbox, DLP, ATP, ZPA and PAC.
