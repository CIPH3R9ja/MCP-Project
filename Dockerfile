FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src/ ./src/
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
COPY public/ ./public/

EXPOSE 7842

# Database stored in a volume-mounted directory
ENV CAM_DB_PATH=/data/audit.db

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:7842/health || exit 1

CMD ["node", "dist/server.js"]
