FROM node:22-bookworm-slim

ARG ASTRO_VERSION

WORKDIR /app
ENV ASTRO_TELEMETRY_DISABLED=1
COPY . .
RUN npm install --no-audit --no-fund --save-exact "astro@${ASTRO_VERSION}" \
 && npm run build
EXPOSE 4321
CMD ["node", "./dist/server/entry.mjs"]
