const virtualId = '@host-header-fixture/server';

export default function hostHeaderAdapter() {
  return {
    name: '@host-header-fixture/adapter',
    hooks: {
      'astro:config:setup': ({ updateConfig }) => {
        updateConfig({
          vite: {
            plugins: [{
              name: 'host-header-fixture-server',
              resolveId(id) {
                if (id === virtualId) return id;
              },
              load(id) {
                if (id !== virtualId) return;
                return `
                  import { createServer } from 'node:http';
                  import { App } from 'astro/app';
                  import { createRequestFromNodeRequest, writeResponse } from 'astro/app/node';
                  import { manifest } from 'virtual:astro:manifest';

                  const app = new App(manifest, false);
                  const server = createServer(async (req, res) => {
                    try {
                      const request = createRequestFromNodeRequest(req, { port: 4321 });
                      const response = await app.render(request);
                      await writeResponse(response, res);
                    } catch (error) {
                      console.error(error);
                      res.writeHead(500, { 'content-type': 'text/plain' });
                      res.end('fixture error');
                    }
                  });
                  server.listen(4321, '0.0.0.0');
                `;
              },
            }],
          },
        });
      },
      'astro:config:done': ({ setAdapter }) => {
        setAdapter({
          name: '@host-header-fixture/adapter',
          entrypointResolution: 'auto',
          serverEntrypoint: virtualId,
          supportedAstroFeatures: {
            serverOutput: 'stable',
            staticOutput: 'stable',
            hybridOutput: 'stable',
          },
        });
      },
    },
  };
}
