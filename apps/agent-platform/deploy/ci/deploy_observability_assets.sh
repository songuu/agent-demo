#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: deploy_observability_assets.sh \
  --namespace NAMESPACE \
  --release-id RELEASE_ID \
  --git-sha SHA \
  --image-digest SHA256 \
  --output PATH \
  [--otel-namespace NAMESPACE] [--otel-service NAME] \
  [--grafana-namespace NAMESPACE] [--grafana-deployment NAME] \
  [--prometheus-namespace NAMESPACE] [--prometheus-service NAME] \
  [--alertmanager-namespace NAMESPACE] [--alertmanager-service NAME] \
  [--trace-namespace NAMESPACE] [--trace-service NAME] \
  --grafana-api-url HTTPS_URL --grafana-token-env ENV_NAME \
  --alertmanager-api-url HTTPS_URL --alertmanager-token-env ENV_NAME \
  --alert-receipt-base-url HTTPS_URL --alert-receipt-token-env ENV_NAME \
  [--http-timeout-seconds SECONDS] [--delivery-timeout-seconds SECONDS]
EOF
}

namespace=""
release_id=""
git_sha=""
image_digest=""
output=""
otel_namespace="observability"
otel_service="otel-collector"
grafana_namespace="observability"
grafana_deployment="grafana"
prometheus_namespace="observability"
prometheus_service="prometheus-operated"
alertmanager_namespace="observability"
alertmanager_service="alertmanager-operated"
trace_namespace="observability"
trace_service="tempo-query-frontend"
grafana_api_url=""
grafana_token_env="GRAFANA_API_TOKEN"
alertmanager_api_url=""
alertmanager_token_env="ALERTMANAGER_API_TOKEN"
alert_receipt_base_url=""
alert_receipt_token_env="ALERT_DELIVERY_RECEIPT_TOKEN"
http_timeout_seconds=10
delivery_timeout_seconds=180
while (($#)); do
  case "$1" in
    --namespace)
      namespace="${2:-}"
      shift 2
      ;;
    --release-id)
      release_id="${2:-}"
      shift 2
      ;;
    --git-sha)
      git_sha="${2:-}"
      shift 2
      ;;
    --image-digest)
      image_digest="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    --otel-namespace)
      otel_namespace="${2:-}"
      shift 2
      ;;
    --otel-service)
      otel_service="${2:-}"
      shift 2
      ;;
    --grafana-namespace)
      grafana_namespace="${2:-}"
      shift 2
      ;;
    --grafana-deployment)
      grafana_deployment="${2:-}"
      shift 2
      ;;
    --prometheus-namespace)
      prometheus_namespace="${2:-}"
      shift 2
      ;;
    --prometheus-service)
      prometheus_service="${2:-}"
      shift 2
      ;;
    --alertmanager-namespace)
      alertmanager_namespace="${2:-}"
      shift 2
      ;;
    --alertmanager-service)
      alertmanager_service="${2:-}"
      shift 2
      ;;
    --trace-namespace)
      trace_namespace="${2:-}"
      shift 2
      ;;
    --trace-service)
      trace_service="${2:-}"
      shift 2
      ;;
    --grafana-api-url)
      grafana_api_url="${2:-}"
      shift 2
      ;;
    --grafana-token-env)
      grafana_token_env="${2:-}"
      shift 2
      ;;
    --alertmanager-api-url)
      alertmanager_api_url="${2:-}"
      shift 2
      ;;
    --alertmanager-token-env)
      alertmanager_token_env="${2:-}"
      shift 2
      ;;
    --alert-receipt-base-url)
      alert_receipt_base_url="${2:-}"
      shift 2
      ;;
    --alert-receipt-token-env)
      alert_receipt_token_env="${2:-}"
      shift 2
      ;;
    --http-timeout-seconds)
      http_timeout_seconds="${2:-}"
      shift 2
      ;;
    --delivery-timeout-seconds)
      delivery_timeout_seconds="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done


if [[ -z "${namespace}" || -z "${output}" ]]; then
  usage
  exit 2
fi
if [[ ! "${release_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "release ID must use the governed release identity format" >&2
  exit 2
fi
if [[ ! "${git_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "git SHA must be exactly 40 lowercase hexadecimal characters" >&2
  exit 2
fi
if [[ ! "${image_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "image digest must be an immutable sha256 digest" >&2
  exit 2
fi
if [[ ! "${http_timeout_seconds}" =~ ^[0-9]+$ ]] ||
  ((http_timeout_seconds < 1 || http_timeout_seconds > 60)); then
  echo "HTTP timeout must be between 1 and 60 seconds" >&2
  exit 2
fi
if [[ ! "${delivery_timeout_seconds}" =~ ^[0-9]+$ ]] ||
  ((delivery_timeout_seconds < 10 || delivery_timeout_seconds > 900)); then
  echo "delivery timeout must be between 10 and 900 seconds" >&2
  exit 2
fi

validate_https_base_url() {
  local name="$1"
  local url="$2"
  local authority
  if [[ ! "${url}" =~ ^https:// ]] || [[ "${url}" == *"?"* ]] || [[ "${url}" == *"#"* ]]; then
    echo "${name} must be an HTTPS base URL without query or fragment" >&2
    exit 2
  fi
  authority="${url#https://}"
  authority="${authority%%/*}"
  if [[ -z "${authority}" || "${authority}" == *"@"* ]]; then
    echo "${name} must not contain userinfo" >&2
    exit 2
  fi
}

validate_token_env() {
  local name="$1"
  if [[ ! "${name}" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    echo "token environment variable name is invalid" >&2
    exit 2
  fi
  if [[ -z "${!name:-}" ]] || [[ "${!name}" == *$'\n'* ]] || [[ "${!name}" == *$'\r'* ]]; then
    echo "required short-lived token is missing or malformed: ${name}" >&2
    exit 2
  fi
}

validate_https_base_url "Grafana API URL" "${grafana_api_url}"
validate_https_base_url "Alertmanager API URL" "${alertmanager_api_url}"
validate_https_base_url "alert receipt base URL" "${alert_receipt_base_url}"
validate_token_env "${grafana_token_env}"
validate_token_env "${alertmanager_token_env}"
validate_token_env "${alert_receipt_token_env}"
grafana_api_url="${grafana_api_url%/}"
alertmanager_api_url="${alertmanager_api_url%/}"
alert_receipt_base_url="${alert_receipt_base_url%/}"

for command in kubectl jq curl mktemp sha256sum date grep cut chmod rm mkdir basename sleep seq; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "Required command is unavailable: ${command}" >&2
    exit 2
  fi
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
platform_root="$(cd "${script_dir}/../.." && pwd)"
prometheus_rules="${platform_root}/deploy/observability/prometheus-rules.yaml"
dashboard_dir="${platform_root}/deploy/observability/dashboards"
temporary_dir="$(mktemp -d)"
temporary_marker="${temporary_dir}/.agent-platform-observability-temp"
: >"${temporary_marker}"
port_forward_pid=""
synthetic_alert_submitted="false"
synthetic_alert_resolved="false"
synthetic_alert_starts_at=""
synthetic_alert_labels_json=""
delivery_id=""

write_auth_header() {
  local token_env="$1"
  local output_path="$2"
  umask 077
  printf 'Authorization: Bearer %s\n' "${!token_env}" >"${output_path}"
  chmod 600 "${output_path}"
}
write_auth_header "${grafana_token_env}" "${temporary_dir}/grafana-auth-header"
write_auth_header "${alertmanager_token_env}" "${temporary_dir}/alertmanager-auth-header"
write_auth_header "${alert_receipt_token_env}" "${temporary_dir}/receipt-auth-header"

stop_port_forward() {
  if [[ -n "${port_forward_pid}" ]] && kill -0 "${port_forward_pid}" 2>/dev/null; then
    kill "${port_forward_pid}" 2>/dev/null || true
    wait "${port_forward_pid}" 2>/dev/null || true
  fi
  port_forward_pid=""
}

post_alert_payload() {
  local payload_path="$1"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout "${http_timeout_seconds}" \
    --max-time "${http_timeout_seconds}" \
    --header "@${temporary_dir}/alertmanager-auth-header" \
    --header 'Content-Type: application/json' \
    --data-binary "@${payload_path}" \
    "${alertmanager_api_url}/api/v2/alerts" >/dev/null
}

resolve_synthetic_alert() {
  local resolved_payload
  if [[ "${synthetic_alert_submitted}" != "true" || \
    "${synthetic_alert_resolved}" == "true" ]]; then
    return 0
  fi
  resolved_payload="${temporary_dir}/synthetic-alert-resolved.json"
  jq -n \
    --argjson labels "${synthetic_alert_labels_json}" \
    --arg starts_at "${synthetic_alert_starts_at}" \
    --arg ends_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    '[{labels: $labels, annotations: {
       summary: "Agent Platform governed release verification resolved"
     }, startsAt: $starts_at, endsAt: $ends_at}]' \
    >"${resolved_payload}"
  post_alert_payload "${resolved_payload}"
  synthetic_alert_resolved="true"
}

cleanup() {
  stop_port_forward
  if ! resolve_synthetic_alert; then
    echo "Failed to resolve governed synthetic alert during cleanup" >&2
  fi
  if [[ -n "${temporary_dir}" && -d "${temporary_dir}" &&
    -f "${temporary_marker}" ]]; then
    rm -rf -- "${temporary_dir}"
  else
    echo "Refusing to remove unverified temporary directory" >&2
  fi
}
trap cleanup EXIT

expected_dashboard_contract='[
  {"uid":"agent-platform-actions","title":"Agent Platform - Actions"},
  {"uid":"agent-platform-executive","title":"Agent Platform - Executive"},
  {"uid":"agent-platform-model","title":"Agent Platform - Model"},
  {"uid":"agent-platform-operations","title":"Agent Platform - Operations"},
  {"uid":"agent-platform-safety","title":"Agent Platform - Safety"},
  {"uid":"agent-platform-tools","title":"Agent Platform - Tools"}
]'
release_dashboard_dir="${temporary_dir}/release-dashboards"
dashboard_manifest="${temporary_dir}/dashboard-manifest.ndjson"
mkdir -p "${release_dashboard_dir}"
: >"${dashboard_manifest}"
release_id_tag="agent-platform-release-id:${release_id}"
git_sha_tag="agent-platform-git-sha:${git_sha}"
image_digest_tag="agent-platform-image-digest:${image_digest}"
for dashboard_path in "${dashboard_dir}"/*.json; do
  dashboard_uid="$(jq -er '.uid | strings | select(length > 0)' "${dashboard_path}")"
  dashboard_title="$(jq -er '.title | strings | select(length > 0)' "${dashboard_path}")"
  if [[ ! "${dashboard_uid}" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "Grafana dashboard UID is invalid: ${dashboard_uid}" >&2
    exit 2
  fi
  jq \
    --arg release_id_tag "${release_id_tag}" \
    --arg git_sha_tag "${git_sha_tag}" \
    --arg image_digest_tag "${image_digest_tag}" \
    '.tags = (((.tags // []) + [$release_id_tag, $git_sha_tag, $image_digest_tag]) |
      unique)' \
    "${dashboard_path}" >"${release_dashboard_dir}/$(basename "${dashboard_path}")"
  jq -cn \
    --arg uid "${dashboard_uid}" \
    --arg title "${dashboard_title}" \
    '{uid: $uid, title: $title}' >>"${dashboard_manifest}"
done
local_dashboard_contract="$(jq -cs 'sort_by(.uid)' "${dashboard_manifest}")"
if ! jq -e \
  --argjson expected "${expected_dashboard_contract}" \
  --argjson actual "${local_dashboard_contract}" \
  '$actual == ($expected | sort_by(.uid))' <<<"{}" >/dev/null; then
  echo "Local Grafana dashboard UID/title contract is incomplete or drifted" >&2
  exit 2
fi

require_ready_service() {
  local service_namespace="$1"
  local service_name="$2"
  local service_port="$3"
  local service_json endpoint_json
  service_json="$(
    kubectl --namespace "${service_namespace}" get service "${service_name}" -o json
  )"
  jq -e --argjson port "${service_port}" \
    'any(.spec.ports[]?; .port == $port)' <<<"${service_json}" >/dev/null
  endpoint_json="$(
    kubectl --namespace "${service_namespace}" get endpointslices.discovery.k8s.io \
      --selector "kubernetes.io/service-name=${service_name}" -o json
  )"
  jq -e \
    '[.items[].endpoints[]? | select(.conditions.ready != false)] | length > 0' \
    <<<"${endpoint_json}" >/dev/null
}

start_port_forward() {
  local service_namespace="$1"
  local service_name="$2"
  local local_port="$3"
  local remote_port="$4"
  local log_name="$5"
  stop_port_forward
  kubectl --namespace "${service_namespace}" port-forward \
    "service/${service_name}" "${local_port}:${remote_port}" \
    >"${temporary_dir}/${log_name}.log" 2>&1 &
  port_forward_pid="$!"
}

wait_http_ready() {
  local url="$1"
  local log_name="$2"
  for _ in $(seq 1 30); do
    if curl --fail --silent --show-error --max-time 2 "${url}" >/dev/null; then
      return 0
    fi
    if ! kill -0 "${port_forward_pid}" 2>/dev/null; then
      cat "${temporary_dir}/${log_name}.log" >&2
      return 1
    fi
    sleep 1
  done
  return 1
}
# The platform owns rules and dashboards, while the operator/collector/Grafana
# installations are cluster prerequisites managed by the observability platform.
kubectl get crd prometheusrules.monitoring.coreos.com >/dev/null
kubectl api-resources --api-group=monitoring.coreos.com \
  | grep -q '^prometheusrules'

otel_service_json="$(
  kubectl --namespace "${otel_namespace}" get service "${otel_service}" -o json
)"
jq -e 'any(.spec.ports[]?; .port == 4317)' <<<"${otel_service_json}" >/dev/null
jq -e 'any(.spec.ports[]?; .port == 4318)' <<<"${otel_service_json}" >/dev/null
jq -e 'any(.spec.ports[]?; .port == 13133)' <<<"${otel_service_json}" >/dev/null
otel_endpoints_json="$(
  kubectl --namespace "${otel_namespace}" get endpointslices.discovery.k8s.io \
    --selector "kubernetes.io/service-name=${otel_service}" \
    -o json
)"
jq -e \
  '[.items[].endpoints[]? | select(.conditions.ready != false)] | length > 0' \
  <<<"${otel_endpoints_json}" >/dev/null

grafana_deployment_json="$(
  kubectl --namespace "${grafana_namespace}" get deployment \
    "${grafana_deployment}" -o json
)"
jq -e \
  '[.spec.template.spec.containers[]?.env[]? |
    select(.name == "LABEL" and .value == "grafana_dashboard")] |
    length > 0' \
  <<<"${grafana_deployment_json}" >/dev/null
jq -e \
  '[.spec.template.spec.containers[]?.env[]? |
    select(.name == "NAMESPACE" and .value == "ALL")] |
    length > 0' \
  <<<"${grafana_deployment_json}" >/dev/null
jq -e \
  '([.spec.template.spec.containers[]?.env[]? |
    select(.name == "LABEL_VALUE")] | length == 0) or
    ([.spec.template.spec.containers[]?.env[]? |
    select(.name == "LABEL_VALUE" and .value == "1")] | length > 0)' \
  <<<"${grafana_deployment_json}" >/dev/null

kubectl --namespace "${otel_namespace}" port-forward \
  "service/${otel_service}" 13133:13133 \
  >"${temporary_dir}/otel-port-forward.log" 2>&1 &
port_forward_pid="$!"
otel_healthy="false"
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error \
    --max-time 2 http://127.0.0.1:13133/ >/dev/null; then
    otel_healthy="true"
    break
  fi
  if ! kill -0 "${port_forward_pid}" 2>/dev/null; then
    cat "${temporary_dir}/otel-port-forward.log" >&2
    break
  fi
  sleep 1
done
if [[ "${otel_healthy}" != "true" ]]; then
  echo "OTel Collector health endpoint did not become ready" >&2
  exit 2
fi
stop_port_forward

kubectl annotate --local \
  --filename "${prometheus_rules}" \
  "agent-platform/release-id=${release_id}" \
  "agent-platform/release-git-sha=${git_sha}" \
  "agent-platform/release-image-digest=${image_digest}" \
  --overwrite \
  --output yaml \
  >"${temporary_dir}/prometheus-rules.yaml"
kubectl --namespace "${namespace}" apply \
  --filename "${temporary_dir}/prometheus-rules.yaml"

kubectl --namespace "${namespace}" create configmap \
  agent-platform-grafana-dashboards \
  --from-file="${release_dashboard_dir}" \
  --dry-run=client \
  --output yaml \
  >"${temporary_dir}/dashboards-raw.yaml"
kubectl label --local \
  --filename "${temporary_dir}/dashboards-raw.yaml" \
  grafana_dashboard=1 \
  --overwrite \
  --output yaml \
  >"${temporary_dir}/dashboards-labeled.yaml"
kubectl annotate --local \
  --filename "${temporary_dir}/dashboards-labeled.yaml" \
  "agent-platform/release-id=${release_id}" \
  "agent-platform/release-git-sha=${git_sha}" \
  "agent-platform/release-image-digest=${image_digest}" \
  --overwrite \
  --output yaml \
  >"${temporary_dir}/dashboards.yaml"
kubectl apply --filename "${temporary_dir}/dashboards.yaml"

prometheus_readback="$(
  kubectl --namespace "${namespace}" get prometheusrule agent-platform -o json
)"
dashboard_readback="$(
  kubectl --namespace "${namespace}" get configmap \
    agent-platform-grafana-dashboards -o json
)"
for resource in "${prometheus_readback}" "${dashboard_readback}"; do
  jq -e \
    --arg release_id "${release_id}" \
    --arg git_sha "${git_sha}" \
    --arg image_digest "${image_digest}" \
    '.metadata.annotations["agent-platform/release-id"] == $release_id and
     .metadata.annotations["agent-platform/release-git-sha"] == $git_sha and
     .metadata.annotations["agent-platform/release-image-digest"] == $image_digest' \
    <<<"${resource}" >/dev/null
done
dashboard_count="$(jq '.data | length' <<<"${dashboard_readback}")"
if [[ "${dashboard_count}" -ne 6 ]]; then
  echo "Expected six Grafana dashboards, got ${dashboard_count}" >&2
  exit 2
fi
jq -e \
  '.metadata.labels.grafana_dashboard == "1"' \
  <<<"${dashboard_readback}" >/dev/null

# Read back the actual telemetry path. Resource existence alone is not release evidence.
require_ready_service "${prometheus_namespace}" "${prometheus_service}" 9090
require_ready_service "${alertmanager_namespace}" "${alertmanager_service}" 9093
require_ready_service "${trace_namespace}" "${trace_service}" 3200

start_port_forward \
  "${prometheus_namespace}" "${prometheus_service}" 19090 9090 prometheus-port-forward
if ! wait_http_ready "http://127.0.0.1:19090/-/ready" prometheus-port-forward; then
  echo "Prometheus readiness endpoint did not become ready" >&2
  exit 2
fi
prometheus_targets="$(
  curl --fail --silent --show-error \
    'http://127.0.0.1:19090/api/v1/targets?state=active'
)"
jq -e --arg namespace "${namespace}" \
  'any(.data.activeTargets[]?;
    .health == "up" and
    (.scrapeUrl | contains("/metrics")) and
    (.labels.namespace == $namespace or
     .discoveredLabels.__meta_kubernetes_namespace == $namespace) and
    (.labels.app == "agent-api" or
     .labels["app.kubernetes.io/name"] == "agent-platform" or
     .discoveredLabels.__meta_kubernetes_pod_label_app == "agent-api" or
     ((.labels.job // "") | test("agent-(api|worker)|agent-platform"))))' \
  <<<"${prometheus_targets}" >/dev/null
scrape_target_up="true"

prometheus_query="$(
  curl --fail --silent --show-error --get \
    --data-urlencode 'query=vector(1)' \
    http://127.0.0.1:19090/api/v1/query
)"
jq -e \
  '.status == "success" and .data.resultType == "vector" and
   (.data.result | length) == 1 and .data.result[0].value[1] == "1"' \
  <<<"${prometheus_query}" >/dev/null
query_api="ok"

rules_loaded="false"
for _ in $(seq 1 30); do
  prometheus_rules_json="$(
    curl --fail --silent --show-error \
      'http://127.0.0.1:19090/api/v1/rules?type=alert'
  )"
  if jq -e \
    'any(.data.groups[]?; .name | endswith("agent-platform-alerts"))' \
    <<<"${prometheus_rules_json}" >/dev/null; then
    rules_loaded="true"
    break
  fi
  sleep 1
done
if [[ "${rules_loaded}" != "true" ]]; then
  echo "Prometheus did not load the Agent Platform alert group" >&2
  exit 2
fi
prometheus_alertmanagers="$(
  curl --fail --silent --show-error \
    http://127.0.0.1:19090/api/v1/alertmanagers
)"
jq -e \
  '.status == "success" and (.data.activeAlertmanagers | length) > 0' \
  <<<"${prometheus_alertmanagers}" >/dev/null
prometheus_active_alertmanager="true"
stop_port_forward

start_port_forward \
  "${alertmanager_namespace}" "${alertmanager_service}" 19093 9093 \
  alertmanager-port-forward
if ! wait_http_ready "http://127.0.0.1:19093/-/ready" alertmanager-port-forward; then
  echo "Alertmanager readiness endpoint did not become ready" >&2
  exit 2
fi
alertmanager_status="$(
  curl --fail --silent --show-error http://127.0.0.1:19093/api/v2/status
)"
jq -e \
  '.config.original | contains("route:") and contains("receiver:")' \
  <<<"${alertmanager_status}" >/dev/null
alertmanager_route_receiver_config_present="true"
stop_port_forward

# Submit a release-bound synthetic span through the real collector and require
# query-back from the configured trace backend. This proves ingest and export.
trace_id="${git_sha:0:32}"
span_id="${git_sha:0:16}"
start_time_unix_nano="$(date +%s%N)"
end_time_unix_nano="$((start_time_unix_nano + 1000000))"
trace_payload="$(
  jq -n \
    --arg trace_id "${trace_id}" \
    --arg span_id "${span_id}" \
    --arg start "${start_time_unix_nano}" \
    --arg end "${end_time_unix_nano}" \
    --arg git_sha "${git_sha}" \
    --arg image_digest "${image_digest}" \
    --arg namespace "${namespace}" \
    '{resourceSpans: [{resource: {attributes: [
       {key: "service.name", value: {stringValue: "agent-platform-release-verifier"}},
       {key: "deployment.environment.name", value: {stringValue: $namespace}}
     ]}, scopeSpans: [{scope: {name: "agent-platform.release"}, spans: [{
       traceId: $trace_id,
       spanId: $span_id,
       name: "release.observability.synthetic",
       kind: 1,
       startTimeUnixNano: $start,
       endTimeUnixNano: $end,
       attributes: [
         {key: "release.git_sha", value: {stringValue: $git_sha}},
         {key: "release.image_digest", value: {stringValue: $image_digest}}
       ],
       status: {code: 1}
     }]}]}]}'
)"
start_port_forward \
  "${otel_namespace}" "${otel_service}" 14318 4318 otel-trace-port-forward
# The HTTP receiver has no readiness path; the collector health check above is
# authoritative and curl retry covers port-forward startup.
trace_accepted="false"
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error \
    --header 'Content-Type: application/json' \
    --data "${trace_payload}" \
    http://127.0.0.1:14318/v1/traces >/dev/null; then
    trace_accepted="true"
    break
  fi
  sleep 1
done
if [[ "${trace_accepted}" != "true" ]]; then
  echo "OTel Collector did not accept the synthetic release trace" >&2
  exit 2
fi
stop_port_forward

start_port_forward \
  "${trace_namespace}" "${trace_service}" 19200 3200 trace-query-port-forward
if ! wait_http_ready "http://127.0.0.1:19200/ready" trace-query-port-forward; then
  echo "Trace query backend readiness endpoint did not become ready" >&2
  exit 2
fi
synthetic_trace_roundtrip="false"
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:19200/api/traces/${trace_id}" \
    >"${temporary_dir}/trace-readback.json"; then
    if jq -e 'type == "object" and length > 0' \
      "${temporary_dir}/trace-readback.json" >/dev/null; then
      synthetic_trace_roundtrip="true"
      break
    fi
  fi
  sleep 1
done
if [[ "${synthetic_trace_roundtrip}" != "true" ]]; then
  echo "Synthetic release trace was not queryable from the trace backend" >&2
  exit 2
fi
stop_port_forward

# ConfigMap discovery is not runtime proof. Read all six dashboards from the
# authenticated Grafana API and require exact UID/title/release tags.
grafana_dashboards_json='[]'
grafana_runtime_api_readback="true"
while IFS= read -r expected_dashboard; do
  dashboard_uid="$(jq -er '.uid' <<<"${expected_dashboard}")"
  dashboard_title="$(jq -er '.title' <<<"${expected_dashboard}")"
  dashboard_response="${temporary_dir}/grafana-${dashboard_uid}.json"
  dashboard_verified="false"
  deadline=$((SECONDS + delivery_timeout_seconds))
  while ((SECONDS < deadline)); do
    if curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout "${http_timeout_seconds}" \
      --max-time "${http_timeout_seconds}" \
      --header "@${temporary_dir}/grafana-auth-header" \
      --header 'Accept: application/json' \
      --output "${dashboard_response}" \
      "${grafana_api_url}/api/dashboards/uid/${dashboard_uid}"; then
      if jq -e \
        --arg uid "${dashboard_uid}" \
        --arg title "${dashboard_title}" \
        --arg release_id_tag "${release_id_tag}" \
        --arg git_sha_tag "${git_sha_tag}" \
        --arg image_digest_tag "${image_digest_tag}" \
        '.dashboard.uid == $uid and .dashboard.title == $title and
         (.meta.version | type == "number" and . >= 1) and
         (.dashboard.tags | index($release_id_tag) != null) and
         (.dashboard.tags | index($git_sha_tag) != null) and
         (.dashboard.tags | index($image_digest_tag) != null)' \
        "${dashboard_response}" >/dev/null; then
        dashboard_verified="true"
        break
      fi
    fi
    sleep 2
  done
  if [[ "${dashboard_verified}" != "true" ]]; then
    echo "Grafana API did not return the exact release-bound dashboard: ${dashboard_uid}" >&2
    exit 2
  fi
  dashboard_version="$(jq -er '.meta.version | floor' "${dashboard_response}")"
  dashboard_evidence="$(
    jq -cn \
      --arg uid "${dashboard_uid}" \
      --arg title "${dashboard_title}" \
      --argjson version "${dashboard_version}" \
      --arg release_id_tag "${release_id_tag}" \
      --arg git_sha_tag "${git_sha_tag}" \
      --arg image_digest_tag "${image_digest_tag}" \
      '{uid: $uid, title: $title, version: $version,
        release_tags: [$release_id_tag, $git_sha_tag, $image_digest_tag],
        release_identity_verified: true}'
  )"
  grafana_dashboards_json="$(
    jq -cn \
      --argjson dashboards "${grafana_dashboards_json}" \
      --argjson dashboard "${dashboard_evidence}" \
      '$dashboards + [$dashboard]'
  )"
done < <(jq -c 'sort_by(.uid)[]' <<<"${expected_dashboard_contract}")
if [[ "$(jq 'length' <<<"${grafana_dashboards_json}")" -ne 6 ]]; then
  echo "Grafana API runtime readback did not verify exactly six dashboards" >&2
  exit 2
fi

# The externally reachable Alertmanager API must be authenticated TLS. Submit
# a governed synthetic alert, prove API visibility, then require the receiver's
# content-addressed delivery receipt before resolving the alert.
external_alertmanager_status="${temporary_dir}/external-alertmanager-status.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout "${http_timeout_seconds}" \
  --max-time "${http_timeout_seconds}" \
  --header "@${temporary_dir}/alertmanager-auth-header" \
  --header 'Accept: application/json' \
  --output "${external_alertmanager_status}" \
  "${alertmanager_api_url}/api/v2/status"
jq -e '.config.original | contains("route:") and contains("receiver:")' \
  "${external_alertmanager_status}" >/dev/null

release_identity_sha256="$(
  printf '%s\n%s\n%s\n%s\n' \
    "${release_id}" "${git_sha}" "${image_digest}" "${namespace}" \
    | sha256sum | cut -d ' ' -f 1
)"
delivery_id="release-check-${release_identity_sha256}"
synthetic_alert_starts_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
synthetic_alert_ends_at="$(date -u -d '+10 minutes' +'%Y-%m-%dT%H:%M:%SZ')"
synthetic_alert_labels_json="$(
  jq -cn \
    --arg release_id "${release_id}" \
    --arg git_sha "${git_sha}" \
    --arg image_digest "${image_digest}" \
    --arg namespace "${namespace}" \
    --arg delivery_id "${delivery_id}" \
    '{alertname: "AgentPlatformReleaseSynthetic", severity: "info",
      verification: "governed-release", release_id: $release_id,
      git_sha: $git_sha, image_digest: $image_digest,
      namespace: $namespace, delivery_id: $delivery_id}'
)"
synthetic_alert_payload="${temporary_dir}/synthetic-alert.json"
jq -n \
  --argjson labels "${synthetic_alert_labels_json}" \
  --arg starts_at "${synthetic_alert_starts_at}" \
  --arg ends_at "${synthetic_alert_ends_at}" \
  --arg generator_url "${grafana_api_url}/d/agent-platform-operations" \
  '[{labels: $labels, annotations: {
     summary: "Agent Platform governed release delivery verification"
   }, startsAt: $starts_at, endsAt: $ends_at, generatorURL: $generator_url}]' \
  >"${synthetic_alert_payload}"
post_alert_payload "${synthetic_alert_payload}"
synthetic_alert_submitted="true"

alertmanager_api_readback="false"
alertmanager_alerts="${temporary_dir}/alertmanager-alerts.json"
deadline=$((SECONDS + delivery_timeout_seconds))
while ((SECONDS < deadline)); do
  if curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout "${http_timeout_seconds}" \
    --max-time "${http_timeout_seconds}" \
    --header "@${temporary_dir}/alertmanager-auth-header" \
    --header 'Accept: application/json' \
    --get \
    --data-urlencode "filter=delivery_id=\"${delivery_id}\"" \
    --output "${alertmanager_alerts}" \
    "${alertmanager_api_url}/api/v2/alerts"; then
    if jq -e \
      --arg release_id "${release_id}" \
      --arg git_sha "${git_sha}" \
      --arg image_digest "${image_digest}" \
      --arg namespace "${namespace}" \
      --arg delivery_id "${delivery_id}" \
      'any(.[]?;
        .labels.alertname == "AgentPlatformReleaseSynthetic" and
        .labels.verification == "governed-release" and
        .labels.release_id == $release_id and .labels.git_sha == $git_sha and
        .labels.image_digest == $image_digest and .labels.namespace == $namespace and
        .labels.delivery_id == $delivery_id)' \
      "${alertmanager_alerts}" >/dev/null; then
      alertmanager_api_readback="true"
      break
    fi
  fi
  sleep 2
done
if [[ "${alertmanager_api_readback}" != "true" ]]; then
  echo "Synthetic release alert was not visible through the Alertmanager API" >&2
  exit 2
fi

receiver_lookup_url="${alert_receipt_base_url}/${delivery_id}"
receiver_lookup="${temporary_dir}/receiver-lookup.json"
receiver_delivery_verified="false"
deadline=$((SECONDS + delivery_timeout_seconds))
while ((SECONDS < deadline)); do
  if curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout "${http_timeout_seconds}" \
    --max-time "${http_timeout_seconds}" \
    --header "@${temporary_dir}/receipt-auth-header" \
    --header 'Accept: application/json' \
    --output "${receiver_lookup}" \
    "${receiver_lookup_url}"; then
    if jq -e \
      --arg release_id "${release_id}" \
      --arg git_sha "${git_sha}" \
      --arg image_digest "${image_digest}" \
      --arg delivery_id "${delivery_id}" \
      'select(
        .schema_version == "1.0" and .status == "delivered" and
        .release_id == $release_id and .git_sha == $git_sha and
        .image_digest == $image_digest and .delivery_id == $delivery_id and
        (.receiver | type == "string" and length > 0) and
        (.received_at | type == "string" and length > 0) and
        (.evidence_uri | type == "string" and startswith("https://")) and
        (.evidence_sha256 | test("^sha256:[0-9a-f]{64}$"))
      )' "${receiver_lookup}" >/dev/null; then
      receiver_delivery_verified="true"
      break
    fi
  fi
  sleep 2
done
if [[ "${receiver_delivery_verified}" != "true" ]]; then
  echo "Alert receiver did not produce a release-bound delivery receipt" >&2
  exit 2
fi

receiver_name="$(jq -er '.receiver' "${receiver_lookup}")"
receiver_received_at="$(jq -er '.received_at' "${receiver_lookup}")"
receipt_evidence_uri="$(jq -er '.evidence_uri' "${receiver_lookup}")"
receipt_evidence_sha256="$(jq -er '.evidence_sha256' "${receiver_lookup}")"
validate_https_base_url "receipt evidence URI" "${receipt_evidence_uri}"
receipt_base_authority="${alert_receipt_base_url#https://}"
receipt_base_authority="${receipt_base_authority%%/*}"
receipt_evidence_authority="${receipt_evidence_uri#https://}"
receipt_evidence_authority="${receipt_evidence_authority%%/*}"
if [[ "${receipt_base_authority}" != "${receipt_evidence_authority}" ]]; then
  echo "Receipt evidence URI escaped the authenticated receiver origin" >&2
  exit 2
fi
if [[ "${receipt_evidence_uri}" != *"${receipt_evidence_sha256#sha256:}"* ]]; then
  echo "Receiver receipt evidence URI is not content addressed" >&2
  exit 2
fi

receipt_evidence="${temporary_dir}/immutable-receiver-receipt.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout "${http_timeout_seconds}" \
  --max-time "${http_timeout_seconds}" \
  --header "@${temporary_dir}/receipt-auth-header" \
  --header 'Accept: application/json' \
  --output "${receipt_evidence}" \
  "${receipt_evidence_uri}"
actual_receipt_sha256="sha256:$(sha256sum "${receipt_evidence}" | cut -d ' ' -f 1)"
if [[ "${actual_receipt_sha256}" != "${receipt_evidence_sha256}" ]]; then
  echo "Immutable receiver receipt digest mismatch" >&2
  exit 2
fi
jq -e \
  --arg release_id "${release_id}" \
  --arg git_sha "${git_sha}" \
  --arg image_digest "${image_digest}" \
  --arg namespace "${namespace}" \
  --arg delivery_id "${delivery_id}" \
  --arg receiver "${receiver_name}" \
  --arg received_at "${receiver_received_at}" \
  'select(
    .schema_version == "1.0" and .status == "delivered" and
    .release_id == $release_id and .git_sha == $git_sha and
    .image_digest == $image_digest and .delivery_id == $delivery_id and
    .receiver == $receiver and .received_at == $received_at and
    .alert.labels.alertname == "AgentPlatformReleaseSynthetic" and
    .alert.labels.verification == "governed-release" and
    .alert.labels.release_id == $release_id and .alert.labels.git_sha == $git_sha and
    .alert.labels.image_digest == $image_digest and
    .alert.labels.namespace == $namespace and
    .alert.labels.delivery_id == $delivery_id
  )' "${receipt_evidence}" >/dev/null
immutable_receipt_readback="true"

if ! resolve_synthetic_alert; then
  echo "Alertmanager did not accept synthetic alert resolution" >&2
  exit 2
fi
if [[ "${synthetic_alert_resolved}" != "true" ]]; then
  echo "Synthetic alert cleanup state was not recorded" >&2
  exit 2
fi
generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

mkdir -p "$(dirname "${output}")"
jq -n \
  --arg release_id "${release_id}" \
  --arg namespace "${namespace}" \
  --arg git_sha "${git_sha}" \
  --arg image_digest "${image_digest}" \
  --arg generated_at "${generated_at}" \
  --arg otel_namespace "${otel_namespace}" \
  --arg otel_service "${otel_service}" \
  --arg grafana_namespace "${grafana_namespace}" \
  --arg grafana_deployment "${grafana_deployment}" \
  --arg grafana_api_url "${grafana_api_url}" \
  --arg prometheus_namespace "${prometheus_namespace}" \
  --arg prometheus_service "${prometheus_service}" \
  --arg alertmanager_namespace "${alertmanager_namespace}" \
  --arg alertmanager_service "${alertmanager_service}" \
  --arg alertmanager_api_url "${alertmanager_api_url}" \
  --arg trace_namespace "${trace_namespace}" \
  --arg trace_service "${trace_service}" \
  --arg trace_id "${trace_id}" \
  --arg delivery_id "${delivery_id}" \
  --arg receiver "${receiver_name}" \
  --arg received_at "${receiver_received_at}" \
  --arg receipt_evidence_uri "${receipt_evidence_uri}" \
  --arg receipt_evidence_sha256 "${receipt_evidence_sha256}" \
  --argjson dashboard_count "${dashboard_count}" \
  --argjson dashboards "${grafana_dashboards_json}" \
  '{
    schema_version: "1.0",
    release_id: $release_id,
    namespace: $namespace,
    git_sha: $git_sha,
    image_digest: $image_digest,
    generated_at: $generated_at,
    prometheus_rule: "agent-platform",
    grafana_configmap: "agent-platform-grafana-dashboards",
    otel_collector: {
      namespace: $otel_namespace,
      service: $otel_service,
      health: "ok"
    },
    prometheus: {
      namespace: $prometheus_namespace,
      service: $prometheus_service,
      scrape_target_up: true,
      query_api: "ok",
      rules_loaded: true
    },
    alertmanager: {
      namespace: $alertmanager_namespace,
      service: $alertmanager_service,
      prometheus_active_alertmanager: true,
      route_receiver_config_present: true
    },
    trace_backend: {
      namespace: $trace_namespace,
      service: $trace_service,
      trace_id: $trace_id,
      synthetic_trace_roundtrip: true
    },
    grafana_sidecar: {
      namespace: $grafana_namespace,
      deployment: $grafana_deployment,
      label: "grafana_dashboard=1",
      watches_all_namespaces: true
    },
    grafana: {
      api_url: $grafana_api_url,
      runtime_api_readback: true,
      dashboard_count: $dashboard_count,
      dashboards: $dashboards
    },
    alert_delivery: {
      alertmanager_api_url: $alertmanager_api_url,
      delivery_id: $delivery_id,
      release_id: $release_id,
      git_sha: $git_sha,
      image_digest: $image_digest,
      synthetic_alert_submitted: true,
      alertmanager_api_readback: true,
      synthetic_alert_resolved: true,
      receiver_delivery_verified: true,
      receiver: $receiver,
      received_at: $received_at,
      receipt_evidence_uri: $receipt_evidence_uri,
      receipt_evidence_sha256: $receipt_evidence_sha256,
      immutable_receipt_readback: true
    },
    applied: true
  }' >"${output}"
