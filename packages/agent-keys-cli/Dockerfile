# ─── Stage 1: Build ──────────────────────────────────────────────────────
# Build context MUST be the repository root (the file: dependency on
# ../agent-keys lives outside the packages/agent-keys-cli subtree):
#
#   docker build -f packages/agent-keys-cli/Dockerfile \
#     -t aegis/signer:latest .
#
FROM node:20-alpine AS builder

WORKDIR /build

# Copy the library package and install its dependencies.
COPY packages/agent-keys/package.json packages/agent-keys/package.json
COPY packages/agent-keys/src packages/agent-keys/src
RUN cd packages/agent-keys && npm install --omit=dev --no-audit --no-fund

# Assemble the runtime tree WITHOUT relying on npm's `file:` symlink
# behavior (symlinks would dangle after COPY into the next stage):
#   /build/out/node_modules/aegis-vault/{package.json,src,node_modules}
#   /build/out/{package.json,src}
RUN mkdir -p /build/out/node_modules/aegis-vault \
 && cp -r /build/packages/agent-keys/package.json \
          /build/packages/agent-keys/src \
          /build/packages/agent-keys/node_modules \
          /build/out/node_modules/aegis-vault/ \
 && cp -r /build/packages/agent-keys-cli/src /build/out/src \
 && cp /build/packages/agent-keys-cli/package.json /build/out/package.json

# ─── Stage 2: Hardened Runtime ──────────────────────────────────────────
FROM node:20-alpine

# Security: non-root user
RUN addgroup -S signer && adduser -S signer -G signer

WORKDIR /app

# Copy only the assembled runtime tree
COPY --from=builder --chown=signer:signer /build/out /app

# Read-only root filesystem compatible
RUN mkdir -p /tmp && chmod 1777 /tmp

USER signer

STOPSIGNAL SIGTERM

# Process-level health check (busybox pgrep ships with alpine)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD pgrep -f "node" || exit 1

# The signer daemon reads the envelope from KEY_ENVELOPE_FILE (default
# /app/key.json) and the password from KEY_PASSWORD.
#
# Usage:
#   docker run -v /path/to/key.json:/app/key.json:ro \
#     -e KEY_PASSWORD=your-password \
#     aegis/signer:latest
#
# Recommended hardening flags (see docs/OPERATIONS.md):
#   --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges
ENTRYPOINT ["node", "src/cli.js", "serve"]