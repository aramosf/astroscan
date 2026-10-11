FROM node:22-bookworm-slim

ARG ASTRO_VERSION

WORKDIR /app
ENV ASTRO_TELEMETRY_DISABLED=1
COPY . .
RUN npm install --no-audit --no-fund --save-exact "astro@${ASTRO_VERSION}"
ENV HOST=0.0.0.0
ENV PORT=4321
EXPOSE 4321
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "4321"]
