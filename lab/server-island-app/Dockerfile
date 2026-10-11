FROM node:22-bookworm-slim

ARG ASTRO_VERSION
ARG NODE_ADAPTER_VERSION=10.0.0

WORKDIR /app
ENV ASTRO_TELEMETRY_DISABLED=1
ENV ASTRO_KEY=eKBaVEuI7YjfanEXHuJe/pwZKKt3LkAHeMxvTU7aR0M=
ENV HOST=0.0.0.0
COPY . .
RUN npm install --no-audit --no-fund --save-exact "astro@${ASTRO_VERSION}" "@astrojs/node@${NODE_ADAPTER_VERSION}" \
 && npm run build
EXPOSE 4321
CMD ["node", "./dist/server/entry.mjs"]
