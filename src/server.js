import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { runScenario } from "./scenario.js";

const assets = new Map([
  ["/", ["../web/index.html", "text/html; charset=utf-8"]],
  ["/app.js", ["../web/app.js", "text/javascript; charset=utf-8"]],
  ["/styles.css", ["../web/styles.css", "text/css; charset=utf-8"]],
  [
    "/architecture.svg",
    ["../docs/media/architecture.svg", "image/svg+xml"]
  ],
  [
    "/evidence/gate1-authority",
    [
      "../evidence/gate1-authority-2026-07-30.md",
      "text/markdown; charset=utf-8"
    ]
  ],
  [
    "/evidence/gate1-recovery",
    [
      "../evidence/gate1-recovery-broker-2026-07-30.md",
      "text/markdown; charset=utf-8"
    ]
  ],
  [
    "/evidence/gate1-ambiguity",
    [
      "../evidence/gate1-ambiguity-2026-07-30.md",
      "text/markdown; charset=utf-8"
    ]
  ],
  ["/claims", ["../CLAIMS.md", "text/markdown; charset=utf-8"]]
]);

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

export function createTideproofServer() {
  return createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");

    if (request.method !== "GET") {
      sendJson(response, 405, { error: "method_not_allowed" });
      return;
    }

    if (url.pathname === "/api/health") {
      sendJson(response, 200, { ok: true, mode: "local-clean-room" });
      return;
    }

    if (url.pathname === "/api/scenario") {
      sendJson(response, 200, runScenario());
      return;
    }

    const asset = assets.get(url.pathname);
    if (!asset) {
      sendJson(response, 404, { error: "not_found" });
      return;
    }

    try {
      const [fileName, contentType] = asset;
      const body = await readFile(new URL(fileName, import.meta.url));
      response.writeHead(200, {
        "content-type": contentType,
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "content-security-policy":
          "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
      });
      response.end(body);
    } catch {
      sendJson(response, 500, { error: "asset_read_failed" });
    }
  });
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  const port = Number.parseInt(process.env.PORT ?? "4173", 10);
  const server = createTideproofServer();
  server.listen(port, "127.0.0.1", () => {
    process.stdout.write(`Tideproof local proof: http://127.0.0.1:${port}\n`);
  });
}
