import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createStorage } from './storage.js';

const storage = await createStorage();
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
]);
const port = Number(process.env.PORT || 8080);

function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

async function body(req) {
  if (!req.headers['content-type']?.startsWith('application/json')) {
    throw Object.assign(new Error('Gunakan Content-Type application/json.'), { status: 415 });
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 8192) throw Object.assign(new Error('Request terlalu besar.'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString());
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw Object.assign(new Error('JSON tidak valid.'), { status: 400 });
  }
}

function title(value) {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 200) {
    throw Object.assign(new Error('Judul wajib diisi, maksimal 200 karakter.'), { status: 400 });
  }
  return value.trim();
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'");
  try {
    const path = new URL(req.url, 'http://localhost').pathname;
    if (req.method === 'GET' && assets.has(path)) {
      const [file, type] = assets.get(path);
      const data = await readFile(new URL(`../public/${file}`, import.meta.url));
      res.writeHead(200, { 'Content-Type': type });
      return res.end(data);
    }
    if (req.method === 'GET' && path === '/healthz') return send(res, 200, { status: 'healthy' });
    if (req.method === 'GET' && path === '/readyz') {
      await storage.ready();
      return send(res, 200, { status: 'ready', storage: storage.mode });
    }
    if (req.method === 'GET' && path === '/version') return send(res, 200, { version: '1.0.0' });
    if (path === '/api/todos' && req.method === 'GET') {
      return send(res, 200, await storage.list());
    }
    if (path === '/api/todos' && req.method === 'POST') {
      const data = await body(req);
      return send(res, 201, await storage.create(title(data.title)));
    }
    const match = /^\/api\/todos\/(\d+)$/.exec(path);
    if (match && ['PATCH', 'DELETE'].includes(req.method)) {
      const id = Number(match[1]);
      if (!Number.isSafeInteger(id) || id > 2147483647) return send(res, 400, { error: 'ID tidak valid.' });
      let result;
      if (req.method === 'DELETE') result = await storage.remove(id);
      else {
        const data = await body(req);
        if (typeof data.completed !== 'boolean') return send(res, 400, { error: 'completed harus boolean.' });
        result = await storage.toggle(id, data.completed);
      }
      if (!result) return send(res, 404, { error: 'Todo tidak ditemukan.' });
      return send(res, 200, req.method === 'DELETE' ? { deleted: true } : result);
    }
    return send(res, 404, { error: 'Endpoint tidak ditemukan.' });
  } catch (error) {
    if (error.status) return send(res, error.status, { error: error.message });
    console.error('Request failed: database or server unavailable.');
    send(res, 503, { error: 'Layanan belum siap. Silakan coba lagi.' });
  }
});
server.listen(port, '0.0.0.0', () => console.log(`Todo app listening on port ${port}`));

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  const timer = setTimeout(() => process.exit(1), 8000);
  timer.unref();
  server.close(async () => {
    await storage.close();
    clearTimeout(timer);
    process.exit(0);
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
