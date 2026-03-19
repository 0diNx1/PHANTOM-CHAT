# ── PHANTOM CHAT - Backend Dockerfile ────────────────────────────────────────
# Multi-stage build for production

# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

# Stage 2: Production
FROM node:20-alpine AS production
RUN apk add --no-cache dumb-init

# Create non-root user for security
RUN addgroup -g 1001 -S phantom && \
    adduser -S -u 1001 -G phantom phantom

WORKDIR /app

# Copy only production dependencies
COPY --from=builder --chown=phantom:phantom /app/node_modules ./node_modules
COPY --chown=phantom:phantom . .

# Create logs directory
RUN mkdir -p logs && chown phantom:phantom logs

USER phantom

EXPOSE 3001

# Use dumb-init to handle PID 1 and signal forwarding
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
