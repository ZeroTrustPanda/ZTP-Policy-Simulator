# 🐼 ZeroTrustPanda ZS Policy Simulator

**Downloads:** see [Releases](https://github.com/ZeroTrustPanda/ZTP-Policy-Simulator/releases) for the Windows and macOS standalone builds. Release notes: [RELEASE_NOTES.md](RELEASE_NOTES.md) · history: [CHANGELOG.md](CHANGELOG.md)

Standalone, read-only tool that answers "would this be allowed, blocked or bypassed — and by what?" against your live Zscaler policy. Same look as the [ZeroTrustPanda ZS Policy Wizard](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard).

## Flow
1. **Connect** — OneAPI client credentials (ZIdentity vanity domain, client ID, secret; optional ZPA customer ID). Probes ZIA / Client Connector / ZPA reachability.
2. **Load policies** — pulls the rule sets with a live per-policy-set status table. Reload any time.
3. **Simulate** — enter a destination (URL, host, IP, CIDR, wildcards), protocol/port or network service, and optional details (user/group/location, file/method/category, application, source IP/country, test bypass inputs). Leave the destination blank for "is this port/service blocked for everyone?".

## Result
Two tiles at the top:
- **Policy rule action** — what happens for anyone your inputs don't narrow down: **Block · Allow · Bypass · Isolate · Caution**, the module and rule that decides it (with order), and tags: **Not inspected** (SSL Do Not Decrypt) and **Inspect only** (DLP / sandbox scan content). "Why this rule matched" and "Rule that decided in each module" expand underneath.
- **Policy action also based on** — every condition that would change that action, each with its own action and rule: 👥 user / group / department, 📍 location, ⏱ time window / device trust / other rule conditions, 💻 Client Connector app profile + network type (bypasses), 📄 uploaded content (DLP), ✏️ inputs you haven't entered. Top 3 shown, the rest under "Show more". For a bypassed result it shows what ZIA would do if the traffic were forwarded.

Below the tiles:
- **How it gets there** — every Client Connector app profile, one row each, per network type: forwarding action, IPv4 / domain inclusions and exclusions, VPN gateway bypasses, IP-based app bypasses, PAC files (evaluated with FindProxyForURL).
- **Every module** — firewall, DNS, SSL, ATP, URL filtering, file type, sandbox, DLP, ZPA, with all evaluated rules on click.

Smart defaults: port from the URL scheme (hostnames assume HTTPS/443), network service/application inferred from protocol+port (UDP/443 → QUIC), request method GET (CONNECT when not decrypted), file type from the URL path, standard DNS resolver for DNS app rules. Every assumption is stated on the result and can be overridden.

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
- `src/matchers.js` — wildcard domain, IP/CIDR/range, port and PAC matching
- `public/index.html` — single-file UI
- `test/` — `node --test` suite with sample policies
