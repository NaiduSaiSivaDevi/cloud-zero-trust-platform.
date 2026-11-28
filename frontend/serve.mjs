import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 5600);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

const server = http.createServer((req, res) => {
  const reqPath = (req.url || "/").split("?")[0];
  const relPath = reqPath === "/" ? "index.html" : reqPath.replace(/^\/+/, "");
  const fullPath = path.resolve(__dirname, relPath);

  if (!fullPath.startsWith(__dirname) || !fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
    return;
  }

  const ext = path.extname(fullPath).toLowerCase();
  res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
  fs.createReadStream(fullPath).pipe(res);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`CloudGuard HTML Frontend running at http://localhost:${PORT}/`);
});
