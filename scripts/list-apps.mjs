import { readFileSync } from "node:fs";

const registry = JSON.parse(readFileSync(new URL("../app-registry.json", import.meta.url), "utf8"));

for (const app of registry.apps) {
  console.log(`${app.id}\t${app.workspace}\t${app.deploy.basePath}\t${app.deploy.port}`);
}