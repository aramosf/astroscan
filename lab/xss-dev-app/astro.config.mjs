import { defineConfig } from 'astro/config';

export default defineConfig({
  trailingSlash: 'never',
  server: {
    host: true,
    port: 4321,
  },
});
