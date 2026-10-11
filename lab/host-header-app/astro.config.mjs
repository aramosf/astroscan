import hostHeaderAdapter from './adapter.mjs';
import { defineConfig } from 'astro/config';

export default defineConfig({
  adapter: hostHeaderAdapter(),
  output: 'server',
});
