import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { page } from './dist/_worker.js/pages/image.astro.mjs';

const endpoint = page().GET;

const server = http.createServer(async (incoming, outgoing) => {
  const url = new URL(incoming.url || '/', 'http://127.0.0.1:4321');
  if (incoming.method === 'GET' && url.pathname === '/') {
    const body = await readFile('./dist/index.html');
    outgoing.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    outgoing.end(body);
    return;
  }
  const response = await endpoint({ url });
  const headers = Object.fromEntries(response.headers);
  const body = Buffer.from(await response.arrayBuffer());
  outgoing.writeHead(response.status, headers);
  outgoing.end(body);
});

server.listen(4321, '0.0.0.0');
