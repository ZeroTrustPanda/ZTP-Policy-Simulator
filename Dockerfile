# Dependency stage. An optional TLS-inspection CA is trusted only here,
# for `npm ci`. This stage is discarded; the published image is `final`.
FROM node:20-slim AS deps

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Optional corporate TLS-inspection root (Zscaler Client Connector).
# scripts/detect-zscaler-cert.sh writes it to docker/zscaler-ca.crt, which
# is gitignored and is often missing. Copying the whole docker/ directory
# lets this build succeed when that file is absent or empty. A non-empty
# file is installed only in this stage so npm can reach the registry.
#
# Plain COPY, not a BuildKit secret mount — a secret mount reproducibly
# hangs `npm ci` on this toolchain.
COPY docker/ /tmp/docker-src/
RUN if [ -s /tmp/docker-src/zscaler-ca.crt ]; then \
      cp /tmp/docker-src/zscaler-ca.crt /usr/local/share/ca-certificates/zscaler-ca.crt \
      && update-ca-certificates \
      && echo "Trusted build-time TLS inspection CA for npm ci"; \
    else \
      echo "No build-time TLS inspection CA; npm ci uses the default trust store"; \
    fi \
    && rm -rf /tmp/docker-src

# Node doesn't trust the OS CA store by default (it ships its own bundled
# list), so this must be set BEFORE `npm ci` or a CA just added above is
# invisible to it — TLS to the registry fails, npm retries repeatedly, and
# that retry storm is what triggers npm's unrelated "Exit handler never
# called!" bug.
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

COPY package.json package-lock.json ./
# npm ci always wipes node_modules before installing, so retrying on
# failure is safe. This host occasionally hits npm's "Exit handler never
# called!" bug (npm/cli#4028-style) regardless of the Zscaler cert path,
# and a retry reliably clears it.
RUN npm ci --omit=dev --no-audit --no-fund \
    || npm ci --omit=dev --no-audit --no-fund \
    || npm ci --omit=dev --no-audit --no-fund

# Install is done. Drop the build-time CA from this stage.
# `--fresh` clears the local-CA symlinks; deleting the file alone leaves
# them in place because update-ca-certificates only auto-removes certs
# marked with "!" in ca-certificates.conf.
RUN rm -f /usr/local/share/ca-certificates/zscaler-ca.crt \
    && update-ca-certificates --fresh

# Published image. node_modules comes from the deps stage. The build-time
# CA is not copied. Runtime trust is the bind mount in docker/entrypoint.sh.
FROM node:20-slim AS final

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY server.js ./
COPY public ./public
COPY src ./src
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Point Node at the OS bundle so a CA mounted at start (entrypoint.sh)
# is visible after update-ca-certificates. This bundle is the stock
# ca-certificates set from this stage.
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
ENV HOST=0.0.0.0 PORT=8787 NO_OPEN=1
EXPOSE 8787

ENTRYPOINT ["entrypoint.sh"]
CMD ["node", "server.js"]
