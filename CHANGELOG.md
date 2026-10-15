# Changelog

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
