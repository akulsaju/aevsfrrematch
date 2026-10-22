// Local development server. On Vercel, public/ is served statically and api/[...path].js handles the API.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { handleApi } = require('./lib/api');

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/api/')) return handleApi(req, res, url);
  const file = path.normalize(path.join(PUBLIC, url.pathname === '/' ? '/index.html' : url.pathname));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    res.end(data);
  });
}).listen(PORT, () => console.log(`Privacy suite on http://localhost:${PORT}`));
