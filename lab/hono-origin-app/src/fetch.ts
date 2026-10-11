import { Hono } from 'hono';
import { pages } from 'astro/hono';

const app = new Hono();
app.use(pages());

export default app;
