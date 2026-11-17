# ==============================================================================
# AIPENT Frontend — Production Multi-Stage Dockerfile
# Builds React/Vite assets and serves with Nginx on port 5173
# ==============================================================================
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine AS runner

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 5173

HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=5s \
  CMD wget -qO- http://127.0.0.1:5173/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
