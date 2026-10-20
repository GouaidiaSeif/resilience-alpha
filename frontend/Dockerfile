# Image du front (Next.js, sortie « standalone »). Contexte de build = frontend/.
#   lancé avec la pile : docker compose up -d --build   (service « frontend » de docker-compose.yml)
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# public/ peut être vide (donc absent d'un clone Git) : le créer pour la copie finale.
RUN mkdir -p public && npm run build

FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3001 \
    HOSTNAME=0.0.0.0
COPY --from=build --chown=10001:10001 /app/.next/standalone ./
COPY --from=build --chown=10001:10001 /app/.next/static ./.next/static
COPY --from=build --chown=10001:10001 /app/public ./public
USER 10001
EXPOSE 3001
CMD ["node", "server.js"]
