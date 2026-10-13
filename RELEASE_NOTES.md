# ZeroTrustPanda ZS Policy Simulator v1.1.0

**Would this be allowed, blocked or bypassed — and by what?** A standalone, read-only simulator that pulls your live Zscaler policy over OneAPI and evaluates a transaction across ZIA, ZPA and Client Connector the way the cloud would, in rule order, then shows the deciding rule and everything else that could change the outcome.

Companion to the [ZeroTrustPanda ZS Policy Wizard](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard) — same look, same OneAPI authentication.

## Downloads
| Platform | File |
|---|---|
| Windows x64 | [ZTP-Policy-Simulator-1.1.0-windows-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.1.0/ZTP-Policy-Simulator-1.1.0-windows-x64.zip) → `ZTP-Policy-Simulator.exe` |
| macOS Apple Silicon | [ZTP-Policy-Simulator-1.1.0-macos-arm64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.1.0/ZTP-Policy-Simulator-1.1.0-macos-arm64.zip) |
| macOS Intel | [ZTP-Policy-Simulator-1.1.0-macos-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.1.0/ZTP-Policy-Simulator-1.1.0-macos-x64.zip) |
| Source | clone the repo, or GitHub's "Source code" download on the release |

Checksums: [SHA256SUMS.txt](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/raw/main/downloads/v1.1.0/SHA256SUMS.txt)

No install, no Node.js required. Run it and it opens `http://127.0.0.1:8787`.
macOS builds are unsigned — before first run: `codesign --sign - ./ZTP-Policy-Simulator-macos-arm64 && xattr -d com.apple.quarantine ./ZTP-Policy-Simulator-macos-arm64`.

## What it does
**1 · Connect → 2 · Load policies → 3 · Simulate**

- **Connect** with ZIdentity OneAPI client credentials (vanity domain, client ID, secret, optional ZPA customer ID). Credentials stay in memory, never written to disk; the server listens on loopback only.
- **Load policies** — URL filtering, firewall, DNS, SSL inspection, file type, sandbox, web DLP, ATP settings and lists, custom URL categories, network services/groups, network application groups, IP source/destination groups, locations; Client Connector Windows/macOS app profiles, forwarding profiles, IP-based app bypasses and referenced PAC files; ZPA application segments and access policy. Per-policy-set status table with real API errors.
- **Simulate** any mix of: destination (URL, host, IP, CIDR, range, wildcards like `*.google.com`), protocol/port, network service, user/group/department/location, file type/operation, request method, URL category, network application, source IP, destination country, plus test PAC / inclusion / exclusion / VPN gateway lists. Leave the destination blank to ask "is this port blocked for everyone?".

### Results
- **Policy rule action** — Block · Allow · Bypass · Isolate · Caution, with the deciding module and rule (and order), plus **Not inspected** (SSL Do Not Decrypt) and **Inspect only** (DLP/sandbox) tags.
- **Policy action also based on** — every condition that would change that action, each with its own action and rule: user/group/department, location, time window / device trust, Client Connector app profile + network type, uploaded content (DLP). For bypassed traffic it shows what ZIA would do if it were forwarded.
- **How it gets there** — each Client Connector app profile, per network type (On-/Off-/VPN-/Split VPN-Trusted): forwarding action (None / Tunnel / Tunnel with local proxy / Enforce proxy), IPv4 and domain inclusions/exclusions, VPN gateway bypasses, IP-based app bypasses, PAC results (evaluated with `FindProxyForURL`).
- **Every module** — firewall, DNS, SSL, ATP, URL filtering, file type, sandbox, DLP and ZPA with every evaluated rule and each criterion's match / no match / unknown.

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

## Changes in 1.1.0
- New two-tile result header: Policy rule action + Policy action also based on.
- Isolate and Caution reported as their own actions.
- Per-app-profile Client Connector forwarding evaluation (inclusions/exclusions, VPN gateway bypass, app bypass, PAC, forwarding action per network type).
- Only conditions that would change the outcome are shown; DLP suppressed when SSL isn't decrypted.
- Removed the Z-Insights activity panel.
