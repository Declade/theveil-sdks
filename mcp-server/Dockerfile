# Lucairn MCP server — Glama-introspection-friendly Dockerfile.
#
# Builds the published @lucairn/mcp-server stdio entry point so introspection
# scanners (Glama, Smithery) can spawn the server, list its tools, and grade
# the package without needing local Node.js + pnpm setup.
#
# Runtime: speaks MCP over stdio. Has no HTTP listener. Configured via env:
#   LUCAIRN_API_KEY       (required at first tool call)
#   ANTHROPIC_API_KEY     (required at first tool call; BYOK)
#   LUCAIRN_GATEWAY_URL   (optional; defaults to https://gateway.lucairn.eu)
#
# Listing-tool introspection (e.g. Glama) does NOT call any LLM tool — it only
# enumerates capabilities — so the server starts cleanly without keys.

FROM node:20-alpine AS build

WORKDIR /build

# Layer-cache deps before source.
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --omit=optional

# Compile TypeScript to dist/.
COPY src ./src
RUN npm run build && npm prune --omit=dev

# --- Runtime image: minimal, non-root.
FROM node:20-alpine AS runtime

# Run as a non-root user; matches the project's defence-in-depth posture.
RUN addgroup -S lucairn && adduser -S lucairn -G lucairn
USER lucairn

WORKDIR /app

COPY --from=build --chown=lucairn:lucairn /build/dist ./dist
COPY --from=build --chown=lucairn:lucairn /build/node_modules ./node_modules
COPY --from=build --chown=lucairn:lucairn /build/package.json ./package.json
COPY --from=build --chown=lucairn:lucairn /build/README.md ./README.md
COPY --from=build --chown=lucairn:lucairn /build/LICENSE ./LICENSE

# stdio MCP server: stdout is the protocol, stderr is logs.
ENTRYPOINT ["node", "dist/index.js"]
