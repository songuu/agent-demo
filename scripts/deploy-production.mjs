import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const options = parseArgs(process.argv.slice(2));
const registry = JSON.parse(readFileSync(new URL("../app-registry.json", import.meta.url), "utf8"));
const app = registry.apps.find((entry) => entry.id === "spiffe-mtls-agent");

if (!app) {
  throw new Error("app-registry.json must contain spiffe-mtls-agent");
}

const deployHost = options.deployHost ?? "root@47.253.230.197";
const domain = options.domain ?? "songuu.top";
const repositoryUrl = options.repositoryUrl ?? "https://github.com/songuu/agent-demo.git";
const branch = options.branch ?? "main";
const releaseRoot = options.releaseRoot ?? "/opt/agent-demo";
const port = options.port ?? String(app.deploy.port ?? 5173);
const basePath = options.basePath ?? String(app.deploy.basePath).replace(/\/+$/, "");
const apply = options.apply === true;

const registryBasePath = String(app.deploy.basePath).replace(/\/+$/, "");
if (basePath !== registryBasePath) {
  throw new Error(`basePath ${basePath} does not match app registry basePath ${app.deploy.basePath}`);
}

const releaseId = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
const releasePath = `${releaseRoot}/releases/${releaseId}`;
const currentPath = `${releaseRoot}/current`;
const publicUrl = `https://${domain}${basePath}/`;
const nginxConfig = "/etc/nginx/conf.d/default.conf";
const pm2Name = "agent-demo-spiffe";

const remoteScript = `
set -euo pipefail
release=${quoteBash(releasePath)}
current=${quoteBash(currentPath)}
release_root=${quoteBash(releaseRoot)}
repo=${quoteBash(repositoryUrl)}
branch=${quoteBash(branch)}
port=${quoteBash(port)}
base_path=${quoteBash(basePath)}
public_url=${quoteBash(publicUrl)}
nginx_config=${quoteBash(nginxConfig)}
pm2_name=${quoteBash(pm2Name)}
domain=${quoteBash(domain)}

mkdir -p "$release_root/releases"
if [ ! -d "$release/.git" ]; then
  git clone --depth 1 --branch "$branch" "$repo" "$release"
fi
cd "$release"
pnpm install --frozen-lockfile
pnpm build
BASE_PATH="$base_path" PORT="$port" node -e "const demo=require('./apps/spiffe-mtls-agent/dist/src/web/demo-model.js'); const s=demo.getDemoSnapshot('127.0.0.1', Number(process.env.PORT), process.env.BASE_PATH); if (s.basePath !== process.env.BASE_PATH || s.steps.length !== 8) process.exit(1); console.log('snapshot-ok=' + s.steps.length);"
ln -sfn "$release" "$current"

cd "$current/apps/spiffe-mtls-agent"
HOST=127.0.0.1 PORT="$port" BASE_PATH="$base_path" PUBLIC_URL="$public_url" pm2 startOrReload "$current/deploy/pm2/ecosystem.config.cjs" --only "$pm2_name"
pm2 save

if ! grep -q "location /agent-demo/spiffe/" "$nginx_config"; then
  backup="$nginx_config.bak.agent-demo-$(date +%Y%m%d%H%M%S)"
  cp "$nginx_config" "$backup"
  tmp="$(mktemp)"
  awk '
    /location = \\\/ \\{/ && inserted == 0 {
      print "    location = /agent-demo/spiffe {";
      print "        return 301 /agent-demo/spiffe/;";
      print "    }";
      print "";
      print "    location /agent-demo/spiffe/ {";
      print "        proxy_pass http://127.0.0.1:5173/agent-demo/spiffe/;";
      print "        proxy_http_version 1.1;";
      print "        proxy_set_header Host $host;";
      print "        proxy_set_header X-Real-IP $remote_addr;";
      print "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;";
      print "        proxy_set_header X-Forwarded-Proto $scheme;";
      print "    }";
      print "";
      inserted = 1;
    }
    { print }
  ' "$nginx_config" > "$tmp"
  mv "$tmp" "$nginx_config"
  if ! nginx -t; then
    cp "$backup" "$nginx_config"
    nginx -t
    exit 1
  fi
else
  nginx -t
fi
nginx -s reload

health_url="http://127.0.0.1:$port$base_path/healthz"
for attempt in $(seq 1 30); do
  if curl -fsS "$health_url"; then
    break
  fi
  if [ "$attempt" = "30" ]; then
    echo "health check failed after $attempt attempts: $health_url" >&2
    exit 1
  fi
  sleep 1
done
curl -fsSI "https://$domain$base_path/"
curl -fsSI "https://$domain$base_path/assets/spiffe-agent-mtls-complete-architecture.svg"
echo "deployed=$release"
`.trim();

if (!apply) {
  console.log("DRY RUN: no server mutation. Re-run with --apply to deploy.");
  console.log(`Target: ${deployHost}`);
  console.log(`Release: ${releasePath}`);
  console.log(`Public URL: ${publicUrl}`);
  console.log("Remote script:");
  console.log(remoteScript);
  process.exit(0);
}

const result = spawnSync("ssh", [deployHost, `bash -lc ${quoteBash(remoteScript)}`], { stdio: "inherit" });
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

function parseArgs(args) {
  const parsed = { apply: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--") {
      continue;
    }
    if (arg === "--apply" || arg === "-Apply") {
      parsed.apply = true;
      continue;
    }
    if (!arg.startsWith("--")) continue;
    const key = toCamelCase(arg.slice(2));
    const next = args[index + 1];
    if (!next || next.startsWith("--")) {
      throw new Error(`missing value for ${arg}`);
    }
    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
}

function quoteBash(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}