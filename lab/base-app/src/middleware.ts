import type { MiddlewareHandler } from 'astro';

export const onRequest: MiddlewareHandler = (context, next) => {
  if (context.url.pathname === '/app/admin' || context.url.pathname.startsWith('/app/admin/')) {
    return new Response('Forbidden', { status: 403 });
  }
  return next();
};
