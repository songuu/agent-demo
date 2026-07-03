import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { getDemoSnapshot } from "./demo-model";
import { renderDemoPage } from "./demo-page";

export type DemoServerOptions = {
  host?: string;
  port?: number;
  basePath?: string;
  publicUrl?: string;
};

type ResolvedDemoServerOptions = {
  host: string;
  port: number;
  basePath: string;
  publicUrl?: string;
};

const architectureAssetsDirs = [
  path.resolve(__dirname, "../..", "docs", "architecture"),
  path.resolve(__dirname, "../../..", "docs", "architecture"),
];
const allowedAssets = new Set([
  "spiffe-agent-mtls-complete-architecture.svg",
  "spiffe-agent-mtls-complete-architecture.png",
  "spiffe-agent-learning-map.svg",
  "spiffe-mtls-handshake-sequence.svg",
  "spiffe-svid-rotation-lifecycle.svg",
  "spiffe-agent-code-map.svg",
]);

function normalizeBasePath(value?: string): string {
  const trimmed = (value ?? "").trim();
  if (!trimmed || trimmed === "/") return "";
  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeadingSlash.replace(/\/+$/, "");
}

function publicHost(host: string): string {
  return host === "0.0.0.0" ? "127.0.0.1" : host;
}

function publicUrlFor(options: ResolvedDemoServerOptions): string {
  if (options.publicUrl) return options.publicUrl.replace(/\/+$/, "") + "/";
  return `http://${publicHost(options.host)}:${options.port}${options.basePath || ""}`;
}

function resolveOptions(options: DemoServerOptions): ResolvedDemoServerOptions {
  return {
    host: options.host ?? process.env.HOST ?? "127.0.0.1",
    port: options.port ?? Number.parseInt(process.env.PORT ?? "5173", 10),
    basePath: normalizeBasePath(options.basePath ?? process.env.BASE_PATH),
    publicUrl: options.publicUrl ?? process.env.PUBLIC_URL,
  };
}

function stripBasePath(pathname: string, basePath: string): string {
  if (!basePath) return pathname;
  if (pathname === basePath) return "/";
  if (pathname.startsWith(`${basePath}/`)) return pathname.slice(basePath.length) || "/";
  return pathname;
}

function send(response: ServerResponse, statusCode: number, body: string | Buffer, contentType: string, headOnly = false): void {
  response.writeHead(statusCode, {
    "content-type": contentType,
    "cache-control": "no-store",
  });
  response.end(headOnly ? undefined : body);
}

function sendJson(response: ServerResponse, statusCode: number, body: unknown, headOnly = false): void {
  send(response, statusCode, JSON.stringify(body, null, 2), "application/json; charset=utf-8", headOnly);
}

function contentTypeForAsset(fileName: string): string {
  if (fileName.endsWith(".svg")) return "image/svg+xml; charset=utf-8";
  if (fileName.endsWith(".png")) return "image/png";
  return "application/octet-stream";
}

async function serveAsset(fileName: string, response: ServerResponse, headOnly: boolean): Promise<void> {
  if (!allowedAssets.has(fileName)) {
    sendJson(response, 404, { ok: false, error: "asset is not part of the demo allow-list" }, headOnly);
    return;
  }

  for (const architectureAssetsDir of architectureAssetsDirs) {
    const assetPath = path.join(architectureAssetsDir, fileName);
    try {
      const asset = await readFile(assetPath);
      send(response, 200, asset, contentTypeForAsset(fileName), headOnly);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  sendJson(response, 404, { ok: false, error: "asset file is missing from demo docs" }, headOnly);
}

export function createDemoHttpServer(options: DemoServerOptions = {}): Server {
  const resolved = resolveOptions(options);

  return createServer(async (request: IncomingMessage, response: ServerResponse) => {
    try {
      const requestUrl = new URL(request.url ?? "/", `http://${resolved.host}:${resolved.port}`);
      const routePath = stripBasePath(requestUrl.pathname, resolved.basePath);
      const snapshot = getDemoSnapshot(publicHost(resolved.host), resolved.port, resolved.basePath, publicUrlFor(resolved));
      const headOnly = request.method === "HEAD";

      if (request.method !== "GET" && request.method !== "HEAD") {
        sendJson(response, 405, { ok: false, error: "method not allowed" }, headOnly);
        return;
      }

      if (routePath === "/" || routePath === "/index.html") {
        send(response, 200, renderDemoPage(snapshot), "text/html; charset=utf-8", headOnly);
        return;
      }

      if (routePath === "/api/demo") {
        sendJson(response, 200, { ok: true, demo: snapshot }, headOnly);
        return;
      }

      if (routePath === "/healthz") {
        sendJson(response, 200, { ok: true, service: "spiffe-mtls-agent-web-demo", basePath: resolved.basePath }, headOnly);
        return;
      }

      if (routePath.startsWith("/assets/")) {
        const fileName = path.basename(decodeURIComponent(routePath.slice("/assets/".length)));
        await serveAsset(fileName, response, headOnly);
        return;
      }

      sendJson(response, 404, { ok: false, error: "not found" }, headOnly);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      sendJson(response, 500, { ok: false, error: message });
    }
  });
}

export async function startDemoServer(options: DemoServerOptions = {}): Promise<Server> {
  const resolved = resolveOptions(options);
  const server = createDemoHttpServer(resolved);

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(resolved.port, resolved.host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  return server;
}

if (require.main === module) {
  startDemoServer()
    .then((server) => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : Number.parseInt(process.env.PORT ?? "5173", 10);
      const resolved = resolveOptions({ port });
      console.log(JSON.stringify({ ok: true, mode: "web-demo", url: publicUrlFor(resolved) }, null, 2));
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.stack ?? error.message : error);
      process.exitCode = 1;
    });
}