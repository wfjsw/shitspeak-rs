import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const port = Number(process.env.PORT ?? 5173);

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  const requestPath = url.pathname === "/" ? "/demo/index.html" : url.pathname;
  const relative = normalize(decodeURIComponent(requestPath)).replace(/^([/\\])+/, "");
  const path = resolve(join(root, relative));

  if (path !== root && !path.startsWith(`${root}${sep}`)) {
    response.writeHead(403).end("Forbidden");
    return;
  }

  try {
    const info = await stat(path);
    if (!info.isFile()) {
      response.writeHead(404).end("Not found");
      return;
    }
    response.writeHead(200, {
      "content-type": types[extname(path)] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    createReadStream(path).pipe(response);
  } catch {
    response.writeHead(404).end("Not found");
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Serving ${root} at http://127.0.0.1:${port}/`);
});
