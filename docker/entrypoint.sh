#!/usr/bin/env bash
# Trusts a Zscaler (or other TLS-inspecting proxy) root CA mounted at
# container start, before handing off to the real command. This covers
# the app's own runtime HTTPS calls (OAuth token requests, api.zsapi.net,
# PAC fetches) on whichever customer site the container is run at — the
# cert baked in at build time (if any) is a different, possibly stale,
# machine's cert and isn't enough on its own.
set -euo pipefail

RUNTIME_CERT=/usr/local/share/ca-certificates/zscaler-runtime-ca.crt

if [ -s "$RUNTIME_CERT" ]; then
  update-ca-certificates >/dev/null
fi

exec "$@"
