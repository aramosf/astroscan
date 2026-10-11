FROM node:22-bookworm-slim

ARG ASTRO_VERSION
ARG NODE_ADAPTER_VERSION=11.0.2

WORKDIR /app
ENV ASTRO_TELEMETRY_DISABLED=1
COPY . .
RUN npm install --no-audit --no-fund --save-exact \
      "astro@${ASTRO_VERSION}" \
      "@astrojs/node@${NODE_ADAPTER_VERSION}" \
      happy-dom@15.11.7 \
 && npm run build
ENV HOST=0.0.0.0
ENV PORT=4321
EXPOSE 4321
CMD ["npm", "run", "start"]
