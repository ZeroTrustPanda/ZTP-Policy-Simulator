#!/usr/bin/env bash
# Finds this machine's Zscaler root CA (if Zscaler Client Connector is
# running) and wires it into Docker two ways:
#   1. Copies it to docker/zscaler-ca.crt, which the Dockerfile trusts at
#      build time so `npm ci` can reach the registry through this
#      machine's proxy.
#   2. Records its live path in .env as ZSCALER_CERT_PATH, which
#      docker-compose.yml bind-mounts into the running container so the
#      app's own runtime HTTPS calls (OAuth, api.zsapi.net, PAC fetches)
#      are trusted too — reading the live file rather than a copy means a
#      cert rotation just needs `docker compose restart`, not a rebuild.
#
# Run this once per machine (or again after installing/updating ZCC);
# then `docker compose up --build`.
#
# On a machine without ZCC, this clears both to their empty defaults —
# build and run proceed normally with no CA injected.
#
# Override detection by setting ZSCALER_CERT_PATH yourself before running.
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE=.env
BUILD_CERT=docker/zscaler-ca.crt
[[ -f "$ENV_FILE" ]] || { [[ -f .env.example ]] && cp .env.example "$ENV_FILE"; }
touch "$ENV_FILE"

find_cert() {
  if [[ -n "${ZSCALER_CERT_PATH:-}" && -r "$ZSCALER_CERT_PATH" ]]; then
    echo "$ZSCALER_CERT_PATH"
    return 0
  fi

  # Linux: ZCC installs its root CA directly into the system trust store.
  local candidates=(
    /etc/ssl/certs/ZscalerRoot0.pem
    /usr/local/share/ca-certificates/ZscalerRoot0.crt
  )
  for c in "${candidates[@]}"; do
    if [[ -r "$c" ]]; then
      echo "$c"
      return 0
    fi
  done

  # Fallback: any other Zscaler cert someone dropped into the trust store.
  local glob
  glob=$(ls /etc/ssl/certs/*[Zz]scaler* /usr/local/share/ca-certificates/*[Zz]scaler* 2>/dev/null | head -n1 || true)
  if [[ -n "$glob" ]]; then
    echo "$glob"
    return 0
  fi

  # macOS: exported from the System keychain. Written next to .env so the
  # path stays valid after this script exits (compose reads it later).
  if command -v security >/dev/null 2>&1; then
    local out="docker/zscaler-ca.macos.crt"
    if security find-certificate -a -c "Zscaler" -p /Library/Keychains/System.keychain >"$out" 2>/dev/null && [[ -s "$out" ]]; then
      echo "$out"
      return 0
    fi
    rm -f "$out"
  fi

  return 1
}

set_env_var() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >>"$ENV_FILE"
  fi
}

if cert_path="$(find_cert)"; then
  openssl x509 -in "$cert_path" -outform PEM >"$BUILD_CERT" 2>/dev/null || cp "$cert_path" "$BUILD_CERT"
  set_env_var ZSCALER_CERT_PATH "$cert_path"
  echo "Detected Zscaler root CA at $cert_path."
  echo "  Build-time trust: $BUILD_CERT"
  echo "  Runtime mount (recorded in $ENV_FILE): $cert_path"
else
  : >"$BUILD_CERT"
  set_env_var ZSCALER_CERT_PATH "./docker/empty-ca.crt"
  echo "No Zscaler root CA detected — building/running without one."
fi

echo "Now run: docker compose up --build"
