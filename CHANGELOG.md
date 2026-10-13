# Changelog

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
