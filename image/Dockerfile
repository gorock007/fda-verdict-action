# Namlo verdict execution image (decision 0027): Node 22 with Playwright's
# Chromium. Jarvis builds it from this file, pushes it and pins it by digest
# in the reusable workflow; nothing is ever built from a PR. The supervisor
# runs every container read-only, non-root and without capabilities, so
# nothing here needs to be writable at run time.
FROM node:22-bookworm@sha256:18a6d90fd60542269850c80ca03b29b1d9b14d6b221ac7ee8e35b0d33ef904bd
ENV CI=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false
RUN npx --yes playwright@1.64.1 install --with-deps chromium \
 && chmod -R a+rX /ms-playwright \
 && corepack enable \
 && rm -rf /root/.npm /root/.cache /var/lib/apt/lists/*
WORKDIR /workspace
USER 1001:1001
