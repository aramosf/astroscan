# Cloudflare compile image endpoint fixture

This fixture builds with the stock `@astrojs/cloudflare/image-endpoint` package export and mounts that handler at `/image`. The vulnerable matrix uses Astro `5.13.4` with adapter `12.6.8`; the fixed control uses Astro `5.13.10` with adapter `12.6.10`.

The local process serves the compiled handler with Node 22. Wrangler Pages is the production runtime, but its local bundler cannot resolve the fixture's native `sharp` dependency after the build in this environment. The Node runner changes only transport: the request query, `URL` normalization, domain check, redirect, and stock endpoint `fetch` remain the compiled application code.

The positive proof requires the endpoint to return the unique token from the operator-controlled SVG callback. The fixed control must return `403 Forbidden` and must not return the token.
