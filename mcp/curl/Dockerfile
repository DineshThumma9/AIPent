# ==============================================================================
# AIPENT — Curl MCP Server Container
# Exposes @calibress/curl-mcp HTTP server on port 7458
# ==============================================================================
FROM node:22-alpine

RUN apk add --no-cache curl

RUN npm install -g @calibress/curl-mcp@0.0.5

ENV PORT=7458
EXPOSE 7458

CMD ["curl-mcp", "--http"]
