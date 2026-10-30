# =============================================================================
# Frontend — Production Dockerfile
# Multi-stage: Node builds the React app, nginx serves the static files.
# =============================================================================

FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first (cached layer unless package.json changes)
COPY package.json package-lock.json* ./
RUN npm ci --prefer-offline

# Copy source and build
COPY . .
RUN npm run build

# ---------------------------------------------------------------------------
# Production image — nginx serving static files
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine

# Copy compiled app
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy SPA nginx config (handles client-side routing)
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
