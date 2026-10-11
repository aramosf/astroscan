import node from '@astrojs/node';
import { defineConfig } from 'astro/config';

export default defineConfig({
  adapter: node({ mode: 'standalone' }),
  output: 'server',
  image: {
    remotePatterns: [
      { protocol: 'http', hostname: 'remote-server', port: '9999', pathname: '/img/*' },
    ],
  },
});
