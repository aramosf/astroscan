FROM node:22-bookworm-slim

ARG ASTRO_VERSION=5.13.4
ARG CLOUDFLARE_ADAPTER_VERSION=12.6.8

WORKDIR /app
ENV ASTRO_TELEMETRY_DISABLED=1
ENV HOST=0.0.0.0
COPY . .
RUN npm install --no-audit --no-fund --save-exact "astro@${ASTRO_VERSION}" "@astrojs/cloudflare@${CLOUDFLARE_ADAPTER_VERSION}" \
 && npm run build
EXPOSE 4321
CMD ["node", "server.mjs"]
