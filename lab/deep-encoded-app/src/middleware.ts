import { defineMiddleware } from 'astro:middleware';

export const onRequest = defineMiddleware((context, next) => {
  if (context.url.pathname.startsWith('/admin')) {
    return new Response('Forbidden: canonical admin path blocked', { status: 403 });
  }
  return next(context.url);
});
