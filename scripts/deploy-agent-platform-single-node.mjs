import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createGzip } from "node:zlib";
import { pipeline } from "node:stream/promises";

const options = parseArgs(process.argv.slice(2));
const registry = JSON.parse(
  readFileSync(new URL("../app-registry.json", import.meta.url), "utf8"),
);
const app = registry.apps.find((entry) => entry.id === "agent-platform");
if (!app) {
  throw new Error("app-registry.json must contain agent-platform");
}

const deployHost = options.deployHost ?? "root@47.253.230.197";
const domain = options.domain ?? "songuu.top";
const repositoryUrl = options.repositoryUrl ?? "https://github.com/songuu/agent-demo.git";
const branch = options.branch ?? "main";
const releaseRoot = options.releaseRoot ?? "/opt/agent-demo/agent-platform";
const registryBasePath = normalizeBasePath(app.deploy.basePath);
const registryPort = parseInteger(app.deploy.port, "registry port");
const basePath = normalizeBasePath(options.basePath ?? registryBasePath);
const port = parseInteger(options.port ?? registryPort, "port");
if (basePath !== registryBasePath || port !== registryPort) {
  throw new Error("single-node base path and port must match app-registry.json");
}
const suppliedGitSha = options.gitSha;
if (suppliedGitSha !== undefined) {
  assertGitSha(suppliedGitSha);
}
const gitSha = suppliedGitSha ?? readCommand("git", ["rev-parse", "HEAD"]);
assertGitSha(gitSha);
const releaseId = options.releaseId ?? `git-${gitSha}`;
assertReleaseId(releaseId);
const apply = options.apply === true;
const minimumFreeDiskBytes = parseInteger(
  options.minimumFreeDiskBytes ?? "2000000000",
  "minimum-free-disk-bytes",
);
const minimumAvailableRuntimeBytes = parseInteger(
  options.minimumAvailableRuntimeBytes ?? "2000000000",
  "minimum-available-runtime-bytes",
);
const publicUrl = `https://${domain}${basePath}/`;
const localUrl = `http://127.0.0.1:${port}`;
const image = options.image ?? `agent-platform:single-node-${releaseId}`;
assertImageReference(image);
const releasePath = `${releaseRoot}/releases/${releaseId}`;
const sshKeepaliveArgs = [
  "-o",
  "ServerAliveInterval=30",
  "-o",
  "ServerAliveCountMax=20",
];

const displayGitSha = gitSha;
const plan = [
  "DRY RUN: no local or server mutation. Re-run with --apply after review.",
  `Target: ${deployHost}`,
  `Release: ${releasePath}`,
  `Git SHA: ${displayGitSha}`,
  `Image: ${image}`,
  `Local API: 127.0.0.1:${port}`,
  `Public URL: ${publicUrl}`,
  "Profile: constrained single-node dev validation (not HA production)",
].join("\n");

if (!apply) {
  console.log(plan);
  process.exit(0);
}

assertCleanWorktree();
const localGitSha = readCommand("git", ["rev-parse", "HEAD"]);
if (localGitSha !== gitSha) {
  throw new Error(`local Git SHA mismatch: expected ${gitSha}, got ${localGitSha}`);
}

runCommand("docker", [
  "build",
  "--label",
  `org.opencontainers.image.revision=${gitSha}`,
  "--label",
  "io.songuu.agent-platform.profile=single-node",
  "--tag",
  image,
  "--file",
  "apps/agent-platform/deploy/docker/Dockerfile",
  "apps/agent-platform",
]);
const imageDigest = readCommand("docker", [
  "image",
  "inspect",
  "--format",
  "{{.Id}}",
  image,
]);
assertImageDigest(imageDigest);

const remotePreflight = buildRemotePreflight({
  branch,
  gitSha,
  minimumAvailableRuntimeBytes,
  minimumFreeDiskBytes,
  releasePath,
  releaseRoot,
  repositoryUrl,
});
runCommand("ssh", [
  ...sshKeepaliveArgs,
  deployHost,
  `bash -lc ${quoteBash(remotePreflight)}`,
]);

await streamImageToHost(image, deployHost);

const remoteDeploy = buildRemoteDeploy({
  basePath,
  domain,
  gitSha,
  image,
  imageDigest,
  localUrl,
  port,
  publicUrl,
  releasePath,
  releaseRoot,
});
runCommand("ssh", [
  ...sshKeepaliveArgs,
  deployHost,
  `bash -lc ${quoteBash(remoteDeploy)}`,
]);

function buildRemotePreflight({
  branch,
  gitSha,
  minimumAvailableRuntimeBytes,
  minimumFreeDiskBytes,
  releasePath,
  releaseRoot,
  repositoryUrl,
}) {
  return `
set -euo pipefail
release=${quoteBash(releasePath)}
release_root=${quoteBash(releaseRoot)}
repository_url=${quoteBash(repositoryUrl)}
branch=${quoteBash(branch)}
expected_git_sha=${quoteBash(gitSha)}
minimum_free_disk_bytes=${quoteBash(minimumFreeDiskBytes)}
minimum_available_runtime_bytes=${quoteBash(minimumAvailableRuntimeBytes)}

command -v docker >/dev/null
docker compose version >/dev/null
command -v openssl >/dev/null
command -v nginx >/dev/null

current="$release_root/current"
if [ -e "$current" ] && [ ! -L "$current" ]; then
  echo "current path exists but is not a symlink: $current" >&2
  exit 78
fi
if [ -L "$current" ]; then
  previous_release="$(readlink -f "$current")"
  if [ "$previous_release" != "$release" ]; then
    echo "single-node upgrades are refused without a transactional database rollback plan" >&2
    exit 78
  fi
fi

free_disk_bytes="$(df -B1 --output=avail / | tail -n 1 | tr -d ' ')"
memory_available_bytes="$(awk '/MemAvailable:/ { print $2 * 1024 }' /proc/meminfo)"
swap_free_bytes="$(awk '/SwapFree:/ { print $2 * 1024 }' /proc/meminfo)"
runtime_available_bytes="$(awk -v memory="$memory_available_bytes" -v swap="$swap_free_bytes" 'BEGIN { printf "%.0f", memory + swap }')"

if [ "$free_disk_bytes" -lt "$minimum_free_disk_bytes" ]; then
  echo "single-node preflight failed: free disk $free_disk_bytes < required $minimum_free_disk_bytes" >&2
  exit 70
fi
if [ "$runtime_available_bytes" -lt "$minimum_available_runtime_bytes" ]; then
  echo "single-node preflight failed: available memory+swap $runtime_available_bytes < required $minimum_available_runtime_bytes" >&2
  exit 71
fi

mkdir -p "$release_root/releases"
if [ -e "$release" ] && [ ! -d "$release/.git" ]; then
  echo "release path exists without a Git checkout: $release" >&2
  exit 72
fi
if [ ! -d "$release/.git" ]; then
  remote_branch_sha="$(git ls-remote "$repository_url" "refs/heads/$branch" | awk 'NR == 1 { print $1 }')"
  if [ "$remote_branch_sha" != "$expected_git_sha" ]; then
    echo "remote branch mismatch: expected $expected_git_sha, got $remote_branch_sha" >&2
    exit 72
  fi
  clone_dir="$(mktemp -d "$release_root/releases/.clone.XXXXXX")"
  case "$clone_dir" in
    "$release_root/releases/.clone."*) ;;
    *)
      echo "unsafe temporary clone path: $clone_dir" >&2
      exit 72
      ;;
  esac
  cleanup_clone() {
    if [ -n "$clone_dir" ] && [ -d "$clone_dir" ]; then
      rm -rf -- "$clone_dir"
    fi
  }
  trap cleanup_clone EXIT
  git clone --depth 1 --branch "$branch" "$repository_url" "$clone_dir"
  cloned_git_sha="$(git -C "$clone_dir" rev-parse HEAD)"
  if [ "$cloned_git_sha" != "$expected_git_sha" ]; then
    echo "cloned release mismatch: expected $expected_git_sha, got $cloned_git_sha" >&2
    exit 72
  fi
  mv -T --no-clobber "$clone_dir" "$release"
  if [ -d "$clone_dir" ]; then
    if [ ! -d "$release/.git" ]; then
      echo "competing release promotion did not create a Git checkout" >&2
      exit 72
    fi
    competing_git_sha="$(git -C "$release" rev-parse HEAD)"
    if [ "$competing_git_sha" != "$expected_git_sha" ]; then
      echo "competing release mismatch: expected $expected_git_sha, got $competing_git_sha" >&2
      exit 72
    fi
    cleanup_clone
  fi
  clone_dir=""
  trap - EXIT
fi
actual_git_sha="$(git -C "$release" rev-parse HEAD)"
if [ "$actual_git_sha" != "$expected_git_sha" ]; then
  echo "release checkout mismatch: expected $expected_git_sha, got $actual_git_sha" >&2
  exit 72
fi

echo "preflight=ok"
echo "free_disk_bytes=$free_disk_bytes"
echo "runtime_available_bytes=$runtime_available_bytes"
`.trim();
}

function buildRemoteDeploy({
  basePath,
  domain,
  gitSha,
  image,
  imageDigest,
  localUrl,
  port,
  publicUrl,
  releasePath,
  releaseRoot,
}) {
  return `
set -euo pipefail
release=${quoteBash(releasePath)}
release_root=${quoteBash(releaseRoot)}
current="$release_root/current"
state_dir="$release_root/state"
secret_env_file="$state_dir/single-node.secrets.env"
release_env_file="$release/.agent-platform-release.env"
image=${quoteBash(image)}
expected_image_digest=${quoteBash(imageDigest)}
expected_git_sha=${quoteBash(gitSha)}
base_path=${quoteBash(basePath)}
port=${quoteBash(port)}
local_url=${quoteBash(localUrl)}
public_url=${quoteBash(publicUrl)}
domain=${quoteBash(domain)}
nginx_config=/etc/nginx/conf.d/default.conf
base_compose="$release/apps/agent-platform/deploy/docker/docker-compose.yml"
override_compose="$release/apps/agent-platform/deploy/docker/docker-compose.single-node.yml"

actual_git_sha="$(git -C "$release" rev-parse HEAD)"
if [ "$actual_git_sha" != "$expected_git_sha" ]; then
  echo "refusing mismatched release checkout" >&2
  exit 73
fi
if [ -e "$current" ] && [ ! -L "$current" ]; then
  echo "current path exists but is not a symlink: $current" >&2
  exit 78
fi
if [ -L "$current" ]; then
  previous_release="$(readlink -f "$current")"
  if [ "$previous_release" != "$release" ]; then
    echo "single-node upgrades are refused without a transactional database rollback plan" >&2
    exit 78
  fi
fi
actual_image_digest="$(docker image inspect --format '{{.Id}}' "$image")"
if [ "$actual_image_digest" != "$expected_image_digest" ]; then
  echo "remote image digest mismatch: expected $expected_image_digest, got $actual_image_digest" >&2
  exit 76
fi
require_free_disk() {
  stage="$1"
  minimum="$2"
  available="$(df -B1 --output=avail / | tail -n 1 | tr -d ' ')"
  if [ "$available" -lt "$minimum" ]; then
    echo "single-node $stage disk guard failed: $available < $minimum" >&2
    exit 79
  fi
  echo "disk_guard_$stage=$available"
}
require_free_disk post_image_load 1700000000

install -d -m 0700 "$state_dir"
if [ ! -s "$secret_env_file" ]; then
  postgres_password="$(openssl rand -hex 24)"
  minio_password="$(openssl rand -hex 32)"
  quota_hmac_secret="$(openssl rand -base64 32 | tr -d '\\n')"
  {
    printf 'AGENT_PLATFORM_SINGLE_NODE_POSTGRES_USER=%s\\n' 'agent_platform'
    printf 'AGENT_PLATFORM_SINGLE_NODE_POSTGRES_PASSWORD=%s\\n' "$postgres_password"
    printf 'AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_USER=%s\\n' 'agent-platform'
    printf 'AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_PASSWORD=%s\\n' "$minio_password"
    printf 'AGENT_PLATFORM_SINGLE_NODE_QUOTA_HMAC_SECRET=%s\\n' "$quota_hmac_secret"
  } > "$secret_env_file"
  chmod 0600 "$secret_env_file"
fi
{
  printf 'AGENT_PLATFORM_IMAGE=%s\\n' "$image"
  printf 'AGENT_PLATFORM_RELEASE_GIT_SHA=%s\\n' "$expected_git_sha"
  printf 'AGENT_PLATFORM_RELEASE_IMAGE_DIGEST=%s\\n' "$expected_image_digest"
} > "$release_env_file"
chmod 0600 "$release_env_file"

compose() {
  docker compose \\
    --env-file "$secret_env_file" \\
    --env-file "$release_env_file" \\
    --profile local \\
    -f "$base_compose" \\
    -f "$override_compose" \\
    "$@"
}

container_id_for() {
  service="$1"
  compose ps --all -q "$service"
}
service_is_running() {
  service="$1"
  container_id="$(container_id_for "$service")"
  [ -n "$container_id" ] || return 1
  [ "$(docker inspect --format '{{.State.Status}}' "$container_id")" = "running" ]
}
service_is_healthy() {
  service="$1"
  container_id="$(container_id_for "$service")"
  [ -n "$container_id" ] || return 1
  [ "$(docker inspect --format '{{.State.Status}}' "$container_id")" = "running" ] || return 1
  [ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id")" = "healthy" ]
}
job_completed_successfully() {
  service="$1"
  container_id="$(container_id_for "$service")"
  [ -n "$container_id" ] || return 1
  [ "$(docker inspect --format '{{.State.Status}}' "$container_id")" = "exited" ] || return 1
  [ "$(docker inspect --format '{{.State.ExitCode}}' "$container_id")" = "0" ]
}
job_failed() {
  service="$1"
  container_id="$(container_id_for "$service")"
  [ -n "$container_id" ] || return 1
  [ "$(docker inspect --format '{{.State.Status}}' "$container_id")" = "exited" ] || return 1
  [ "$(docker inspect --format '{{.State.ExitCode}}' "$container_id")" != "0" ]
}
startup_deadline_reached() {
  [ "$(date +%s)" -ge "$startup_deadline_epoch" ]
}
wait_for_healthy_service() {
  service="$1"
  attempt_limit="$2"
  for attempt in $(seq 1 "$attempt_limit"); do
    if service_is_healthy "$service"; then
      echo "single-node service ready service=$service attempt=$attempt/$attempt_limit"
      return 0
    fi
    if [ $((attempt % 15)) -eq 0 ]; then
      echo "single-node service wait service=$service attempt=$attempt/$attempt_limit"
    fi
    if startup_deadline_reached; then
      echo "single-node startup deadline reached service=$service" >&2
      break
    fi
    sleep 2
  done
  compose ps --all "$service"
  compose logs --tail 100 "$service"
  echo "single-node service failed health gate: $service" >&2
  exit 82
}
wait_for_running_service() {
  service="$1"
  attempt_limit="$2"
  for attempt in $(seq 1 "$attempt_limit"); do
    if service_is_running "$service"; then
      echo "single-node service running service=$service attempt=$attempt/$attempt_limit"
      return 0
    fi
    if [ $((attempt % 15)) -eq 0 ]; then
      echo "single-node running wait service=$service attempt=$attempt/$attempt_limit"
    fi
    if startup_deadline_reached; then
      echo "single-node startup deadline reached service=$service" >&2
      break
    fi
    sleep 2
  done
  compose ps --all "$service"
  compose logs --tail 100 "$service"
  echo "single-node service failed running gate: $service" >&2
  exit 82
}
wait_for_successful_job() {
  service="$1"
  attempt_limit="$2"
  for attempt in $(seq 1 "$attempt_limit"); do
    if job_completed_successfully "$service"; then
      echo "single-node job complete service=$service attempt=$attempt/$attempt_limit"
      return 0
    fi
    if job_failed "$service"; then
      compose ps --all "$service"
      compose logs --tail 100 "$service"
      echo "single-node job exited non-zero: $service" >&2
      exit 82
    fi
    if [ $((attempt % 15)) -eq 0 ]; then
      echo "single-node job wait service=$service attempt=$attempt/$attempt_limit"
    fi
    if startup_deadline_reached; then
      echo "single-node startup deadline reached service=$service" >&2
      break
    fi
    sleep 2
  done
  compose ps --all "$service"
  compose logs --tail 100 "$service"
  echo "single-node job failed completion gate: $service" >&2
  exit 82
}

compose config >/dev/null
compose pull postgres redis temporal minio minio-init opa
require_free_disk post_dependency_pull 1000000000
startup_timeout_seconds=720
startup_deadline_epoch=$(( $(date +%s) + startup_timeout_seconds ))
compose stop agent-api agent-worker commit-worker outbox-worker retention-worker
compose rm -f agent-api agent-worker commit-worker outbox-worker retention-worker
compose up -d --no-build \\
  postgres redis temporal minio minio-init opa migration webhook-secret-init

# Avoid concurrent Python imports on the constrained host: they can saturate
# swap I/O and make Temporal worker validation fail even when Temporal is healthy.
health_attempt_limit=360
for service in postgres redis temporal minio; do
  wait_for_healthy_service "$service" "$health_attempt_limit"
done
wait_for_running_service "opa" "$health_attempt_limit"
for service in minio-init migration webhook-secret-init; do
  wait_for_successful_job "$service" "$health_attempt_limit"
done

compose up -d --no-build --no-deps agent-api
wait_for_healthy_service "agent-api" "$health_attempt_limit"
for attempt in $(seq 1 "$health_attempt_limit"); do
  if curl -fsS "$local_url/health" >/dev/null; then
    break
  fi
  if [ $((attempt % 15)) -eq 0 ]; then
    echo "single-node API wait attempt=$attempt/$health_attempt_limit"
  fi
  if startup_deadline_reached; then
    compose ps --all agent-api
    compose logs --tail 100 agent-api
    echo "single-node startup deadline reached while waiting for API" >&2
    exit 74
  fi
  if [ "$attempt" = "$health_attempt_limit" ]; then
    compose ps
    compose logs --tail 100 agent-api
    echo "single-node health failed: $local_url/health" >&2
    exit 74
  fi
  sleep 2
done

compose up -d --no-build --no-deps agent-worker
wait_for_healthy_service "agent-worker" "$health_attempt_limit"
compose up -d --no-build --no-deps commit-worker
wait_for_healthy_service "commit-worker" "$health_attempt_limit"
compose up -d --no-build --no-deps outbox-worker
wait_for_healthy_service "outbox-worker" "$health_attempt_limit"
compose up -d --no-build --no-deps retention-worker
wait_for_running_service "retention-worker" "$health_attempt_limit"

require_free_disk post_start 750000000
all_required_services_ready() {
  for service in postgres redis temporal minio agent-api agent-worker commit-worker outbox-worker; do
    service_is_healthy "$service" || return 1
  done
  for service in opa retention-worker; do
    service_is_running "$service" || return 1
  done
  for service in minio-init migration webhook-secret-init; do
    job_completed_successfully "$service" || return 1
  done
}

for attempt in $(seq 1 60); do
  if all_required_services_ready; then
    break
  fi
  if [ $((attempt % 15)) -eq 0 ]; then
    echo "single-node aggregate wait attempt=$attempt/60"
  fi
  if startup_deadline_reached; then
    compose ps --all
    compose logs --tail 100 agent-api agent-worker commit-worker outbox-worker retention-worker
    echo "single-node startup deadline reached during aggregate gate" >&2
    exit 82
  fi
  if [ "$attempt" = "60" ]; then
    compose ps --all
    compose logs --tail 100 agent-api agent-worker commit-worker outbox-worker retention-worker
    echo "single-node required service state gate failed" >&2
    exit 82
  fi
  sleep 2
done

compose exec -T agent-api python - \
  --base-url http://127.0.0.1:8080 \
  --expected-git-sha "$expected_git_sha" \
  --expected-image-digest "$expected_image_digest" \
  --expect-structural-only-readiness-block \
  < "$release/apps/agent-platform/scripts/smoke_single_node_deployment.py"

if ! all_required_services_ready; then
  compose ps --all
  compose logs --tail 100 agent-api agent-worker commit-worker outbox-worker retention-worker
  echo "single-node required service state changed during smoke" >&2
  exit 82
fi

nginx_begin_marker="# BEGIN managed Agent Platform single-node $base_path"
nginx_end_marker="# END managed Agent Platform single-node $base_path"
expected_nginx_block="$(mktemp)"
actual_nginx_block="$(mktemp)"
unmanaged_nginx_config="$(mktemp)"
cleanup_nginx_validation() {
  rm -f -- "$expected_nginx_block" "$actual_nginx_block" "$unmanaged_nginx_config"
}
trap cleanup_nginx_validation EXIT
awk -v base_path="$base_path" -v port="$port" '
  BEGIN {
    print "    # BEGIN managed Agent Platform single-node " base_path;
    print "    location = " base_path " {";
    print "        return 301 " base_path "/;";
    print "    }";
    print "";
    print "    location = " base_path "/ {";
    print "        proxy_pass http://127.0.0.1:" port "/health;";
    print "        proxy_set_header Host $host;";
    print "        proxy_set_header X-Real-IP $remote_addr;";
    print "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;";
    print "        proxy_set_header X-Forwarded-Proto $scheme;";
    print "    }";
    print "";
    print "    location = " base_path "/health {";
    print "        proxy_pass http://127.0.0.1:" port "/health;";
    print "        proxy_set_header Host $host;";
    print "        proxy_set_header X-Forwarded-Proto $scheme;";
    print "    }";
    print "";
    print "    location = " base_path "/ready {";
    print "        proxy_pass http://127.0.0.1:" port "/ready;";
    print "        proxy_set_header Host $host;";
    print "        proxy_set_header X-Forwarded-Proto $scheme;";
    print "    }";
    print "";
    print "    location ^~ " base_path "/ {";
    print "        return 404;";
    print "    }";
    print "    # END managed Agent Platform single-node " base_path;
  }
' > "$expected_nginx_block"

backup=""
if ! grep -Fq -- "$nginx_begin_marker" "$nginx_config"; then
  if grep -Fq -- "$base_path" "$nginx_config"; then
    echo "refusing unmanaged Agent Platform Nginx routes for $base_path" >&2
    exit 80
  fi
  backup="$nginx_config.bak.agent-platform-$(date +%Y%m%d%H%M%S)"
  cp "$nginx_config" "$backup"
  tmp="$(mktemp)"
  awk -v block_file="$expected_nginx_block" -v domain="$domain" '
    function brace_delta(line, copy, opens, closes) {
      copy = line;
      opens = gsub(/\\{/, "", copy);
      copy = line;
      closes = gsub(/\\}/, "", copy);
      return opens - closes;
    }
    /^[[:space:]]*server[[:space:]]*\\{/ {
      in_server = 1;
      server_depth = 0;
      target_server = 0;
    }
    in_server && $1 == "server_name" {
      for (field_index = 2; field_index <= NF; field_index++) {
        candidate = $field_index;
        sub(/;$/, "", candidate);
        if (candidate == domain) {
          target_server = 1;
        }
      }
    }
    target_server && /^[[:space:]]*location[[:space:]]*=[[:space:]]*\\/[[:space:]]*\\{[[:space:]]*$/ {
      matched_servers++;
      while ((getline line < block_file) > 0) {
        print line;
      }
      close(block_file);
      print "";
      inserted++;
    }
    { print }
    in_server {
      server_depth += brace_delta($0);
      if (server_depth == 0) {
        in_server = 0;
        target_server = 0;
      }
    }
    END {
      if (inserted != 1 || matched_servers != 1) {
        exit 42;
      }
    }
  ' "$nginx_config" > "$tmp"
  mv "$tmp" "$nginx_config"
fi
if ! nginx -t; then
  if [ -n "$backup" ]; then
    cp "$backup" "$nginx_config"
    nginx -t
  fi
  exit 75
fi
begin_count="$(grep -Fxc -- "    $nginx_begin_marker" "$nginx_config" || true)"
end_count="$(grep -Fxc -- "    $nginx_end_marker" "$nginx_config" || true)"
if [ "$begin_count" != "1" ] || [ "$end_count" != "1" ]; then
  echo "Agent Platform Nginx managed block markers are not unique" >&2
  exit 80
fi
awk -v begin_marker="$nginx_begin_marker" -v end_marker="$nginx_end_marker" '
  index($0, begin_marker) {
    capture = 1;
  }
  capture {
    print;
  }
  capture && index($0, end_marker) {
    found = 1;
    exit;
  }
  END {
    if (!found) {
      exit 43;
    }
  }
' "$nginx_config" > "$actual_nginx_block"
if ! cmp -s "$expected_nginx_block" "$actual_nginx_block"; then
  echo "Agent Platform Nginx managed block differs from the fail-closed template" >&2
  diff -u "$expected_nginx_block" "$actual_nginx_block" >&2 || true
  exit 80
fi
awk -v begin_marker="$nginx_begin_marker" -v domain="$domain" '
  function brace_delta(line, copy, opens, closes) {
    copy = line;
    opens = gsub(/\\{/, "", copy);
    copy = line;
    closes = gsub(/\\}/, "", copy);
    return opens - closes;
  }
  /^[[:space:]]*server[[:space:]]*\\{/ {
    in_server = 1;
    server_depth = 0;
    target_server = 0;
  }
  in_server && $1 == "server_name" {
    for (field_index = 2; field_index <= NF; field_index++) {
      candidate = $field_index;
      sub(/;$/, "", candidate);
      if (candidate == domain) {
        target_server = 1;
      }
    }
  }
  index($0, begin_marker) {
    marker_count++;
    if (!in_server || !target_server) {
      wrong_server = 1;
    }
  }
  in_server {
    server_depth += brace_delta($0);
    if (server_depth == 0) {
      in_server = 0;
      target_server = 0;
    }
  }
  END {
    if (marker_count != 1 || wrong_server) {
      exit 44;
    }
  }
' "$nginx_config" || {
  echo "Agent Platform Nginx managed block is outside the exact domain server" >&2
  exit 80
}
awk -v begin_marker="$nginx_begin_marker" -v end_marker="$nginx_end_marker" '
  index($0, begin_marker) {
    managed = 1;
    next;
  }
  managed && index($0, end_marker) {
    managed = 0;
    next;
  }
  !managed {
    print;
  }
' "$nginx_config" > "$unmanaged_nginx_config"
if grep -Fq -- "$base_path" "$unmanaged_nginx_config"; then
  echo "refusing Agent Platform Nginx routes outside the managed block" >&2
  exit 80
fi
cleanup_nginx_validation
trap - EXIT
nginx -s reload

public_health=""
public_identity_ready=0
public_identity_last_error=""
public_identity_attempt=0
public_identity_deadline_epoch=$(( $(date +%s) + 30 ))
while true; do
  public_identity_remaining_seconds=$(( public_identity_deadline_epoch - $(date +%s) ))
  if [ "$public_identity_remaining_seconds" -le 0 ]; then
    break
  fi
  public_identity_request_timeout="$public_identity_remaining_seconds"
  if [ "$public_identity_request_timeout" -gt 5 ]; then
    public_identity_request_timeout=5
  fi
  public_identity_connect_timeout="$public_identity_request_timeout"
  if [ "$public_identity_connect_timeout" -gt 2 ]; then
    public_identity_connect_timeout=2
  fi
  public_identity_attempt=$((public_identity_attempt + 1))
  if public_identity_response="$(curl -fsS \
    --connect-timeout "$public_identity_connect_timeout" \
    --max-time "$public_identity_request_timeout" \
    "$public_url"health 2>&1)"; then
    public_health="$public_identity_response"
    public_identity_last_error=""
    if grep -Fq '"release_git_sha":"'"$expected_git_sha"'"' <<<"$public_health" &&
      grep -Fq '"release_image_digest":"'"$expected_image_digest"'"' <<<"$public_health"; then
      public_identity_ready=1
      break
    fi
  else
    public_health=""
    public_identity_last_error="$public_identity_response"
  fi
  public_identity_remaining_seconds=$(( public_identity_deadline_epoch - $(date +%s) ))
  if [ "$public_identity_remaining_seconds" -le 0 ]; then
    break
  fi
  if [ $((public_identity_attempt % 5)) -eq 0 ]; then
    echo "public Agent Platform release identity wait attempt=$public_identity_attempt remaining_seconds=$public_identity_remaining_seconds"
  fi
  sleep 1
done
if [ "$public_identity_ready" != "1" ]; then
  echo "public Agent Platform release identity did not converge: expected git=$expected_git_sha digest=$expected_image_digest" >&2
  if [ -n "$public_identity_last_error" ]; then
    printf 'last public health curl error: %s\n' "$public_identity_last_error" >&2
  else
    printf 'last public health response: %s\n' "$public_health" >&2
  fi
  exit 81
fi
public_denied_code="$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' \
  --header 'X-Agent-Roles: admin' \
  "$public_url""v1/runs")"
if [ "$public_denied_code" != "404" ]; then
  echo "expected public Agent Platform API denial HTTP 404, got $public_denied_code" >&2
  exit 81
fi
curl -fsS "$public_url" >/dev/null
public_ready_body="$(mktemp)"
public_ready_code="$(curl -sS -o "$public_ready_body" -w '%{http_code}' "$public_url"ready)"
if [ "$public_ready_code" != "503" ]; then
  cat "$public_ready_body" >&2
  echo "expected constrained public readiness HTTP 503, got $public_ready_code" >&2
  exit 77
fi
if ! grep -Fq '"artifact_malware_scanner":"error:policy-fail-closed:structural-only"' "$public_ready_body"; then
  cat "$public_ready_body" >&2
  echo "public readiness omitted the expected structural-only malware scanner block" >&2
  exit 77
fi
rm -f "$public_ready_body"

if ! all_required_services_ready; then
  compose ps --all
  compose logs --tail 100 agent-api agent-worker commit-worker outbox-worker retention-worker
  echo "single-node required service state changed before release switch" >&2
  exit 82
fi
ln -sfn "$release" "$current"
compose ps --all
echo "deployment_status=single-node-deployed-with-known-readiness-block"
echo "deployed_release=$release"
echo "deployed_image=$image"
echo "deployed_image_digest=$expected_image_digest"
echo "public_url=$public_url"
`.trim();
}

async function streamImageToHost(image, deployHost) {
  console.log(`Streaming ${image} to ${deployHost} without a remote tarball...`);
  const save = spawn("docker", ["save", image], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  const gzip = createGzip({ level: 1 });
  const load = spawn(
    "ssh",
    [...sshKeepaliveArgs, deployHost, "gzip -dc | docker load"],
    {
      stdio: ["pipe", "inherit", "inherit"],
    },
  );

  const transfer = pipeline(save.stdout, gzip, load.stdin);
  const [saveStatus, loadStatus] = await Promise.all([
    waitForProcess(save, "docker save"),
    waitForProcess(load, "remote docker load"),
    transfer,
  ]);
  if (saveStatus !== 0 || loadStatus !== 0) {
    throw new Error(
      `image transfer failed: docker save=${saveStatus}, remote docker load=${loadStatus}`,
    );
  }
}

function waitForProcess(child, label) {
  return new Promise((resolve, reject) => {
    child.once("error", (error) => reject(new Error(`${label} failed to start`, { cause: error })));
    child.once("close", (code) => resolve(code ?? 1));
  });
}

function assertCleanWorktree() {
  const status = readCommand("git", ["status", "--porcelain"]);
  if (status) {
    throw new Error("deployment requires a clean worktree bound to the requested Git SHA");
  }
}

function assertGitSha(value) {
  if (!/^[0-9a-f]{40}$/u.test(value)) {
    throw new Error(`git SHA must be 40 lowercase hexadecimal characters: ${value}`);
  }
}

function assertImageDigest(value) {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`image digest must be a sha256 image ID: ${value}`);
  }
}

function assertImageReference(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9][a-zA-Z0-9._-]*)?$/u.test(value)) {
    throw new Error(`invalid local image reference: ${value}`);
  }
}

function assertReleaseId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/u.test(value)) {
    throw new Error(`invalid release id: ${value}`);
  }
}

function normalizeBasePath(value) {
  const normalized = `/${String(value).replace(/^\/+|\/+$/gu, "")}`;
  if (normalized === "/") {
    throw new Error("base path must not be root");
  }
  return normalized;
}

function parseInteger(value, name) {
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return parsed;
}

function runCommand(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) {
    throw new Error(`${command} failed to start`, { cause: result.error });
  }
  if (result.status !== 0) {
    throw new Error(`${command} exited with ${result.status}`);
  }
}

function readCommand(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error) {
    throw new Error(`${command} failed to start`, { cause: result.error });
  }
  if (result.status !== 0) {
    throw new Error(`${command} exited with ${result.status}: ${result.stderr}`);
  }
  return result.stdout.trim();
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
    if (!arg.startsWith("--")) {
      throw new Error(`unexpected positional argument: ${arg}`);
    }
    const next = args[index + 1];
    if (!next || next.startsWith("--")) {
      throw new Error(`missing value for ${arg}`);
    }
    parsed[toCamelCase(arg.slice(2))] = next;
    index += 1;
  }
  return parsed;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/gu, (_, char) => char.toUpperCase());
}

function quoteBash(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
