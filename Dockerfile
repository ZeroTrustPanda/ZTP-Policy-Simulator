FROM node:20-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Optional corporate TLS-inspection root CA (e.g. Zscaler Client Connector),
# populated by scripts/detect-zscaler-cert.sh when this build machine has
# one. Trusting it here is only so `npm ci` can reach the registry through
# this machine's proxy — it's unrelated to the cert the *running* container
# trusts (that's handled at runtime by docker/entrypoint.sh, since whoever
# runs the image may be on a different site with a different cert).
#
# (Deliberately a plain COPY, not a BuildKit secret mount — a secret mount
# here reproducibly hangs `npm ci` on this toolchain.)
COPY docker/zscaler-ca.crt /usr/local/share/ca-certificates/zscaler-ca.crt
RUN if [ -s /usr/local/share/ca-certificates/zscaler-ca.crt ]; then update-ca-certificates; fi

# Node doesn't trust the OS CA store by default (it ships its own bundled
# list), so this must be set BEFORE `npm ci` or the Zscaler cert just
# added above is invisible to it — TLS to the registry fails, npm retries
# repeatedly, and that retry storm is what triggers npm's unrelated
# "Exit handler never called!" bug.
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

COPY package.json package-lock.json ./
# npm ci always wipes node_modules before installing, so retrying on
# failure is safe. This host occasionally hits npm's "Exit handler never
# called!" bug (npm/cli#4028-style) regardless of the Zscaler cert path,
# and a retry reliably clears it.
RUN npm ci --omit=dev --no-audit --no-fund \
    || npm ci --omit=dev --no-audit --no-fund \
    || npm ci --omit=dev --no-audit --no-fund

COPY server.js ./
COPY public ./public
COPY src ./src
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV HOST=0.0.0.0 PORT=8787 NO_OPEN=1
EXPOSE 8787

ENTRYPOINT ["entrypoint.sh"]
CMD ["node", "server.js"]
