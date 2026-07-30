(() => {
  "use strict";

  const dependencyLabels = {
    artifact_malware_scanner: "制品恶意软件扫描",
    database: "PostgreSQL",
    opa: "OPA 策略引擎",
    operational_metrics: "运行指标",
    quota_redis: "Redis 配额",
    s3: "S3 / MinIO",
    temporal: "Temporal",
    temporal_queue_telemetry: "Temporal 队列遥测",
  };

  const healthUrl = new URL("health", window.location.href);
  const readyUrl = new URL("ready", window.location.href);
  const refreshButton = document.querySelector("#refresh-status");
  const serviceStatus = document.querySelector("#service-status");
  const readinessBanner = document.querySelector("#readiness-banner");
  const readinessIcon = readinessBanner.querySelector(".readiness-icon");
  const dependencyGrid = document.querySelector("#dependency-grid");

  const setText = (selector, value) => {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  };

  const setServiceStatus = (state, label) => {
    const dot = document.createElement("span");
    dot.setAttribute("aria-hidden", "true");
    serviceStatus.className = `status-pill ${state}`;
    serviceStatus.replaceChildren(dot, document.createTextNode(label));
  };

  const compactIdentity = (value, length = 14) => {
    if (typeof value !== "string" || value.length === 0) {
      return "未提供";
    }
    return value.length > length ? `${value.slice(0, length)}…` : value;
  };

  const classifyDependency = (status) => {
    if (status === "ok") {
      return { className: "is-healthy", label: "正常" };
    }
    if (typeof status === "string" && status.includes("structural-only")) {
      return { className: "is-constrained", label: "受约束" };
    }
    return { className: "is-error", label: "异常" };
  };

  const renderDependencies = (dependencies) => {
    const entries = Object.entries(dependencies || {}).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    if (entries.length === 0) {
      const empty = document.createElement("article");
      empty.className = "dependency-card is-error";
      const indicator = document.createElement("span");
      indicator.setAttribute("aria-hidden", "true");
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      const detail = document.createElement("small");
      title.textContent = "依赖状态不可用";
      detail.textContent = "health 未返回 dependencies";
      copy.append(title, detail);
      empty.append(indicator, copy);
      dependencyGrid.replaceChildren(empty);
      return;
    }

    const cards = entries.map(([name, status]) => {
      const classification = classifyDependency(status);
      const card = document.createElement("article");
      const indicator = document.createElement("span");
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      const detail = document.createElement("small");

      card.className = `dependency-card ${classification.className}`;
      indicator.setAttribute("aria-hidden", "true");
      title.textContent = dependencyLabels[name] || name.replaceAll("_", " ");
      detail.textContent = `${classification.label} · ${String(status)}`;
      copy.append(title, detail);
      card.append(indicator, copy);
      return card;
    });
    dependencyGrid.replaceChildren(...cards);
  };

  const fetchJson = async (url, acceptedStatuses) => {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!acceptedStatuses.includes(response.status)) {
      throw new Error(`${url.pathname} 返回 HTTP ${response.status}`);
    }
    const payload = await response.json();
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error(`${url.pathname} 返回了无效 JSON`);
    }
    return { payload, status: response.status };
  };

  const renderReadiness = ({ payload, status }) => {
    readinessBanner.className = "readiness-banner";
    if (status === 200 && payload.ready === true) {
      readinessBanner.classList.add("is-ready");
      readinessIcon.textContent = "✓";
      setText("#readiness-title", "控制平面已就绪");
      setText("#readiness-description", "全部就绪门禁通过，可以接受受约束执行。");
      return;
    }

    const dependencies = payload.dependencies || {};
    const scannerStatus = dependencies.artifact_malware_scanner;
    const unexpectedFailures = Object.entries(dependencies).filter(
      ([name, dependencyStatus]) =>
        name !== "artifact_malware_scanner" && dependencyStatus !== "ok",
    );
    const expectedStructuralBlock =
      scannerStatus === "error:policy-fail-closed:structural-only" &&
      unexpectedFailures.length === 0;
    if (status === 503 && expectedStructuralBlock) {
      readinessBanner.classList.add("is-loading");
      readinessIcon.textContent = "!";
      setText("#readiness-title", "按策略保持未就绪");
      setText(
        "#readiness-description",
        "服务存活；恶意软件扫描器仅具备结构检查能力，因此 fail-closed 门禁保持 503。",
      );
      return;
    }

    readinessBanner.classList.add("is-error");
    readinessIcon.textContent = "×";
    setText("#readiness-title", "控制平面尚未就绪");
    setText("#readiness-description", "一个或多个依赖未通过就绪门禁，请查看详情。");
  };

  const renderFailure = (error) => {
    setServiceStatus("is-error", "连接异常");
    setText("#release-sha", "不可用");
    setText("#release-digest", "不可用");
    readinessBanner.className = "readiness-banner is-error";
    readinessIcon.textContent = "×";
    setText("#readiness-title", "状态读取失败");
    setText(
      "#readiness-description",
      error instanceof Error ? error.message : "无法连接运行状态端点。",
    );
    renderDependencies({});
  };

  const refresh = async () => {
    refreshButton.disabled = true;
    refreshButton.setAttribute("aria-busy", "true");
    setServiceStatus("is-loading", "正在连接");
    try {
      const [health, readiness] = await Promise.all([
        fetchJson(healthUrl, [200]),
        fetchJson(readyUrl, [200, 503]),
      ]);
      const releaseSha = health.payload.release_git_sha;
      const releaseDigest = health.payload.release_image_digest;

      const serviceHealthy = health.payload.ok === true;
      setServiceStatus(
        serviceHealthy ? "is-healthy" : "is-error",
        serviceHealthy ? "服务在线" : "服务异常",
      );
      setText("#release-sha", compactIdentity(releaseSha));
      setText("#release-digest", compactIdentity(releaseDigest, 22));
      document.querySelector("#release-sha").title = String(releaseSha || "");
      document.querySelector("#release-digest").title = String(releaseDigest || "");
      renderDependencies(health.payload.dependencies);
      renderReadiness(readiness);
      setText(
        "#last-updated",
        `更新于 ${new Intl.DateTimeFormat("zh-CN", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }).format(new Date())}`,
      );
    } catch (error) {
      renderFailure(error);
      setText("#last-updated", "刷新失败");
    } finally {
      refreshButton.disabled = false;
      refreshButton.removeAttribute("aria-busy");
    }
  };

  refreshButton.addEventListener("click", refresh);
  window.setInterval(refresh, 60_000);
  void refresh();
})();
(() => {
  "use strict";

  const routes = {
    runs: new URL("v1/runs", window.location.href),
    capabilities: new URL("v1/capabilities", window.location.href),
    artifacts: new URL("v1/artifacts", window.location.href),
    memories: new URL("v1/memories", window.location.href),
    killSwitches: new URL("v1/admin/kill-switches", window.location.href),
    webhooks: new URL("v1/admin/webhooks", window.location.href),
  };
  const terminalStatuses = new Set(["completed", "failed", "cancelled"]);
  const select = (selector) => document.querySelector(selector);
  const value = (selector) => select(selector)?.value.trim() || "";
  const tokenInput = select("#console-token");
  const feedback = select("#console-feedback");
  const connectionState = select("#console-connection-state");
  let currentRunId = "";
  let pollTimer = null;

  class ApiError extends Error {
    constructor(message, status, code, correlationId) {
      super(message);
      this.status = status;
      this.code = code;
      this.correlationId = correlationId;
    }
  }

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  };

  const showFeedback = (message, state = "is-success") => {
    feedback.hidden = false;
    feedback.className = `console-feedback ${state}`;
    feedback.textContent = message;
  };

  const showError = (error) => {
    if (error instanceof ApiError) {
      showFeedback(
        `${error.code} · HTTP ${error.status} · ${error.message} · correlation ${error.correlationId}`,
        "is-error",
      );
      if (error.status === 401) {
        connectionState.className = "connection-state is-error";
        connectionState.textContent = "认证失败";
      }
      return;
    }
    showFeedback(error instanceof Error ? error.message : "未知错误", "is-error");
  };

  const parseApiError = async (response) => {
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    const detail = body?.error;
    return new ApiError(
      detail?.message || `API 返回 HTTP ${response.status}`,
      response.status,
      detail?.code || "HTTP_ERROR",
      detail?.correlation_id || response.headers.get("X-Correlation-ID") || "unavailable",
    );
  };

  const apiFetch = async (url, options = {}) => {
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    const token = tokenInput.value.trim();
    if (token) headers.Authorization = `Bearer ${token}`;
    let body = options.body;
    if (body !== undefined && options.rawBody !== true) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    const response = await fetch(url, {
      method: options.method || "GET",
      body,
      cache: "no-store",
      credentials: "same-origin",
      headers,
    });
    if (!response.ok) throw await parseApiError(response);
    if (options.rawResponse === true) return response;
    if (response.status === 204) return null;
    if (!(response.headers.get("content-type") || "").includes("application/json")) {
      throw new ApiError(
        "API 返回了非 JSON 响应",
        response.status,
        "INVALID_API_RESPONSE",
        response.headers.get("X-Correlation-ID") || "unavailable",
      );
    }
    return response.json();
  };

  const operate = async (button, task, successMessage) => {
    if (button) {
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    }
    try {
      const result = await task();
      if (successMessage) showFeedback(successMessage);
      return result;
    } catch (error) {
      showError(error);
      return undefined;
    } finally {
      if (button) {
        button.disabled = false;
        button.removeAttribute("aria-busy");
      }
    }
  };

  const renderJson = (container, payload, emptyMessage) => {
    if (payload === null || payload === undefined || (Array.isArray(payload) && payload.length === 0)) {
      container.replaceChildren(element("div", "empty-state", emptyMessage));
      return;
    }
    const pre = element("pre", "json-block");
    pre.textContent = JSON.stringify(payload, null, 2);
    container.className = "console-data-view";
    container.replaceChildren(pre);
  };

  const activateTab = (name) => {
    for (const tab of document.querySelectorAll("[data-console-tab]")) {
      const active = tab.dataset.consoleTab === name;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    }
    for (const panel of document.querySelectorAll("[data-console-panel]")) {
      panel.hidden = panel.dataset.consolePanel !== name;
    }
  };

  const apiUrl = (path) => new URL(path, window.location.href);
  const setRunId = (runId) => {
    currentRunId = runId;
    select("#run-id-input").value = runId;
    select("#artifact-run-id").value = runId;
  };

  const schedulePoll = (status) => {
    if (pollTimer !== null) window.clearTimeout(pollTimer);
    pollTimer = null;
    if (!terminalStatuses.has(status)) {
      pollTimer = window.setTimeout(() => void loadRun(true), 3_000);
    }
  };

  const loadRun = async (quiet = false) => {
    if (!currentRunId) {
      renderJson(select("#run-view"), null, "请先创建运行或输入 Run ID。");
      return null;
    }
    try {
      const run = await apiFetch(apiUrl(`v1/runs/${encodeURIComponent(currentRunId)}`));
      renderJson(select("#run-view"), run, "运行不存在。");
      schedulePoll(run.status);
      await loadActions(true);
      if (!quiet) showFeedback(`已加载运行 ${currentRunId}`);
      return run;
    } catch (error) {
      schedulePoll("failed");
      if (!quiet) showError(error);
      return null;
    }
  };

  const renderActions = (actions) => {
    const list = select("#actions-list");
    if (!Array.isArray(actions) || actions.length === 0) {
      list.replaceChildren(element("div", "empty-state", "当前运行没有 ActionProposal。"));
      return;
    }
    list.replaceChildren(...actions.map((action) => {
      const card = element("article", "record-card action-card");
      const heading = element("div", "record-heading");
      heading.append(element("strong", "", action.action_type), element("span", "record-status", action.status));
      const preview = element("pre", "json-block");
      preview.textContent = JSON.stringify(action.preview, null, 2);
      const note = element("input");
      note.placeholder = "审批备注或拒绝原因";
      note.maxLength = 2000;
      const approve = element("button", "button button-primary", "批准");
      approve.type = "button";
      approve.addEventListener("click", () => void decideAction(action, "approve", note.value.trim(), approve));
      const reject = element("button", "button button-danger", "拒绝");
      reject.type = "button";
      reject.addEventListener("click", () => void decideAction(action, "reject", note.value.trim(), reject));
      const recover = element("button", "button button-secondary", "对账恢复");
      recover.type = "button";
      recover.addEventListener("click", () => void recoverAction(action, note.value.trim(), recover));
      const controls = element("div", "record-controls");
      controls.append(note, approve, reject, recover);
      card.append(
        heading,
        element("p", "record-meta", `${action.risk} · approvals ${action.approvals_received}/${action.required_approvals} · ${action.payload_hash}`),
        preview,
        controls,
      );
      return card;
    }));
  };

  const loadActions = async (quiet = false) => {
    if (!currentRunId) {
      renderActions([]);
      return [];
    }
    try {
      const actions = await apiFetch(apiUrl(`v1/runs/${encodeURIComponent(currentRunId)}/actions`));
      renderActions(actions);
      if (!quiet) showFeedback(`已刷新 ${actions.length} 个审批项`);
      return actions;
    } catch (error) {
      if (!quiet) showError(error);
      throw error;
    }
  };

  const decideAction = async (action, operation, note, button) => {
    if (operation === "reject" && !note) {
      showFeedback("拒绝操作必须填写原因。", "is-error");
      return;
    }
    await operate(button, async () => {
      await apiFetch(apiUrl(`v1/actions/${encodeURIComponent(action.action_id)}:${operation}`), {
        method: "POST",
        body: operation === "approve"
          ? { payload_hash: action.payload_hash, comment: note || null }
          : { payload_hash: action.payload_hash, reason: note },
      });
      await Promise.all([loadActions(true), loadRun(true)]);
    }, `Action 已${operation === "approve" ? "批准" : "拒绝"}`);
  };

  const recoverAction = async (action, reason, button) => {
    await operate(button, () => apiFetch(apiUrl(`v1/actions/${encodeURIComponent(action.action_id)}:recover`), {
      method: "POST",
      body: { operation: "reconcile", reason: reason || null },
    }), "恢复工作流已提交；服务端仍会校验 phishing-resistant 身份。");
  };
  const loadCapabilities = async () => {
    const capabilities = await apiFetch(routes.capabilities);
    renderJson(select("#capabilities-list"), capabilities, "没有可用能力；可通过名称显式启用。");
    return capabilities;
  };

  const loadMemories = async () => {
    const url = new URL(routes.memories);
    const purpose = value("#memory-purpose");
    if (purpose) url.searchParams.set("purpose", purpose);
    const memories = await apiFetch(url);
    renderJson(select("#memories-list"), memories, "当前身份没有可见记忆。");
    return memories;
  };

  const governanceButton = (label, className, handler) => {
    const button = element("button", className, label);
    button.type = "button";
    button.addEventListener("click", handler);
    return button;
  };

  const renderKillSwitches = (switches) => {
    const list = select("#kill-switch-list");
    if (!Array.isArray(switches) || switches.length === 0) {
      list.replaceChildren(element("div", "empty-state", "没有活动的 Kill Switch。"));
      return;
    }
    list.replaceChildren(...switches.map((item) => {
      const card = element("article", "record-card compact-card");
      const deactivate = governanceButton("解除", "text-button danger-text", () => {
        void operate(deactivate, async () => {
          await apiFetch(apiUrl(`v1/admin/kill-switches/${encodeURIComponent(item.switch_id)}:deactivate`), {
            method: "POST",
            body: { reason: "Operator deactivated from governed console" },
          });
          await loadGovernance();
        }, "Kill Switch 已解除");
      });
      const heading = element("div", "record-heading");
      heading.append(element("strong", "", `${item.scope}:${item.scope_id}`), deactivate);
      card.append(heading, element("span", "record-meta", `${item.mode} · ${item.incident_id} · ${item.reason}`));
      return card;
    }));
  };

  const updateWebhook = async (endpointId, operation, button) => {
    await operate(button, async () => {
      const result = await apiFetch(apiUrl(`v1/admin/webhooks/${encodeURIComponent(endpointId)}:${operation}`), { method: "POST" });
      await loadGovernance();
      if (result.signing_secret) {
        showFeedback(`新签名密钥（仅显示一次）：${result.signing_secret}`, "is-warning");
      }
    }, operation === "disable" ? "Webhook 已停用" : "Webhook 密钥已轮换");
  };

  const renderWebhooks = (webhooks) => {
    const list = select("#webhook-list");
    if (!Array.isArray(webhooks) || webhooks.length === 0) {
      list.replaceChildren(element("div", "empty-state", "尚未注册 Webhook。"));
      return;
    }
    list.replaceChildren(...webhooks.map((hook) => {
      const card = element("article", "record-card compact-card");
      const disable = governanceButton("停用", "text-button danger-text", () => void updateWebhook(hook.endpoint_id, "disable", disable));
      disable.disabled = !hook.enabled;
      const rotate = governanceButton("轮换密钥", "text-button", () => void updateWebhook(hook.endpoint_id, "rotate-secret", rotate));
      const controls = element("div", "record-inline-actions");
      controls.append(rotate, disable);
      const heading = element("div", "record-heading");
      heading.append(element("strong", "", hook.endpoint_name), controls);
      card.append(
        heading,
        element("span", "record-meta", `${hook.enabled ? "enabled" : "disabled"} · secret v${hook.secret_version}`),
        element("span", "record-content", hook.url),
      );
      return card;
    }));
  };

  const loadGovernance = async () => {
    const [switches, webhooks] = await Promise.all([
      apiFetch(routes.killSwitches),
      apiFetch(routes.webhooks),
    ]);
    renderKillSwitches(switches);
    renderWebhooks(webhooks);
    return { switches, webhooks };
  };

  const connect = async () => {
    const button = select("#connect-console");
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    connectionState.className = "connection-state is-loading";
    connectionState.textContent = "正在鉴权";
    const results = await Promise.allSettled([loadCapabilities(), loadMemories(), loadGovernance()]);
    const failures = results.filter((result) => result.status === "rejected");
    if (failures.length === results.length) {
      connectionState.className = "connection-state is-error";
      connectionState.textContent = "连接失败";
      showError(failures[0].reason);
    } else if (failures.length > 0) {
      connectionState.className = "connection-state is-warning";
      connectionState.textContent = "部分能力可用";
      showFeedback(`连接成功，但 ${failures.length} 个模块因权限或配置不可用。`, "is-warning");
    } else {
      connectionState.className = "connection-state is-connected";
      connectionState.textContent = "已连接";
      showFeedback("API 连接成功，功能数据已加载。");
    }
    button.disabled = false;
    button.removeAttribute("aria-busy");
  };

  const createRun = async (event) => {
    event.preventDefault();
    await operate(event.submitter, async () => {
      const accepted = await apiFetch(routes.runs, {
        method: "POST",
        headers: { "Idempotency-Key": `console-${crypto.randomUUID()}` },
        body: {
          goal: value("#run-goal"),
          success_criteria: [{
            id: "operator_goal",
            description: value("#run-criterion"),
            severity: "must",
            verification: "evidence",
          }],
          allowed_capabilities: value("#run-capabilities").split(",").map((item) => item.trim()).filter(Boolean),
          constraints: { use_case: "governed-console" },
          budget: {
            max_cost_usd: Number(value("#run-max-cost")),
            max_duration_seconds: Number(value("#run-max-duration")),
            max_tool_calls: Number(value("#run-max-tools")),
          },
          external_write_policy: value("#run-write-policy"),
          requested_output: { format: value("#run-output-format") },
        },
      });
      setRunId(accepted.run_id);
      await loadRun(true);
    }, "运行已创建并进入受治理工作流。");
  };

  const controlRun = async (operation, button) => {
    if (!currentRunId) {
      showFeedback("请先选择运行。", "is-error");
      return;
    }
    await operate(button, async () => {
      await apiFetch(apiUrl(`v1/runs/${encodeURIComponent(currentRunId)}:${operation}`), {
        method: "POST",
        body: operation === "resume"
          ? { constraints: null }
          : { reason: value("#run-control-reason") },
      });
      await loadRun(true);
    }, `运行已提交${operation === "pause" ? "暂停" : operation === "resume" ? "恢复" : "取消"}请求。`);
  };

  const triggerDownload = (blob, filename) => {
    const objectUrl = URL.createObjectURL(blob);
    const link = element("a");
    link.href = objectUrl;
    link.download = filename;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  };

  const exportAudit = async () => {
    if (!currentRunId) {
      showFeedback("请先选择运行。", "is-error");
      return;
    }
    const audit = await operate(select("#export-audit"), () => apiFetch(apiUrl(`v1/audit/runs/${encodeURIComponent(currentRunId)}`)));
    if (audit !== undefined) {
      triggerDownload(new Blob([JSON.stringify(audit, null, 2)], { type: "application/json" }), `run-${currentRunId}-audit.json`);
      showFeedback("审计导出已下载。");
    }
  };

  const changeCapability = async (event) => {
    event.preventDefault();
    const operation = value("#capability-operation");
    const name = value("#capability-name");
    await operate(event.submitter, async () => {
      await apiFetch(apiUrl(`v1/admin/capabilities/${encodeURIComponent(name)}:${operation}`), {
        method: "POST",
        body: { reason: value("#capability-reason"), scope: "capability" },
      });
      await loadCapabilities();
    }, `能力 ${name} 已${operation === "enable" ? "启用" : "禁用"}。`);
  };

  const uploadArtifact = async (event) => {
    event.preventDefault();
    const file = select("#artifact-file").files[0];
    if (!file) {
      showFeedback("请选择文件。", "is-error");
      return;
    }
    await operate(event.submitter, async () => {
      const url = new URL(routes.artifacts);
      if (value("#artifact-run-id")) url.searchParams.set("run_id", value("#artifact-run-id"));
      url.searchParams.set("kind", value("#artifact-kind"));
      url.searchParams.set("classification", value("#artifact-classification"));
      const artifact = await apiFetch(url, {
        method: "POST",
        body: file,
        rawBody: true,
        headers: { "Content-Type": file.type || "application/octet-stream" },
      });
      select("#artifact-id-input").value = artifact.artifact_id;
      renderJson(select("#artifact-view"), artifact, "制品不可用。");
    }, "制品已上传，并返回扫描与保留元数据。");
  };

  const loadArtifact = async (event) => {
    event.preventDefault();
    const artifact = await operate(event.submitter, () => apiFetch(apiUrl(`v1/artifacts/${encodeURIComponent(value("#artifact-id-input"))}`)));
    if (artifact !== undefined) renderJson(select("#artifact-view"), artifact, "制品不存在。");
  };

  const downloadArtifact = async () => {
    const artifactId = value("#artifact-id-input");
    if (!artifactId) {
      showFeedback("请输入 Artifact ID。", "is-error");
      return;
    }
    const url = apiUrl(`v1/artifacts/${encodeURIComponent(artifactId)}`);
    url.searchParams.set("download", "true");
    url.searchParams.set("purpose", value("#artifact-download-purpose"));
    const response = await operate(select("#download-artifact"), () => apiFetch(url, { rawResponse: true }));
    if (!response) return;
    if ((response.headers.get("content-type") || "").includes("application/json")) {
      const issued = await response.json();
      const link = element("a");
      link.href = issued.url;
      link.rel = "noopener noreferrer";
      link.click();
    } else {
      triggerDownload(await response.blob(), artifactId);
    }
    showFeedback("制品下载已开始。");
  };

  const deleteArtifact = async () => {
    const artifactId = value("#artifact-id-input");
    if (!artifactId || !window.confirm(`确认删除制品 ${artifactId}？`)) return;
    await operate(select("#delete-artifact"), async () => {
      await apiFetch(apiUrl(`v1/artifacts/${encodeURIComponent(artifactId)}`), { method: "DELETE" });
      select("#artifact-id-input").value = "";
      renderJson(select("#artifact-view"), null, "制品已删除。");
    }, "制品已删除。");
  };
  const createMemory = async (event) => {
    event.preventDefault();
    await operate(event.submitter, async () => {
      await apiFetch(routes.memories, {
        method: "POST",
        body: {
          subject_type: value("#memory-subject-type"),
          subject_id: value("#memory-subject-id"),
          memory_type: value("#memory-type"),
          content: value("#memory-content"),
          classification: value("#memory-classification"),
          write_policy: "user_confirmed",
          confirm_write: select("#memory-confirm").checked,
          source_refs: [],
          purpose: value("#memory-purpose"),
        },
      });
      select("#memory-content").value = "";
      await loadMemories();
    }, "记忆已写入并完成可见性回读。");
  };

  const updateMemory = async (operation, button) => {
    const memoryId = value("#memory-operation-id");
    const reason = value("#memory-operation-reason");
    if (!memoryId) {
      showFeedback("请输入 Memory ID。", "is-error");
      return;
    }
    if (operation === "delete" && !window.confirm(`确认删除记忆 ${memoryId}？`)) return;
    const body = operation === "correct"
      ? { content: value("#memory-correction-content"), reason }
      : { reason };
    await operate(button, async () => {
      await apiFetch(apiUrl(`v1/memories/${encodeURIComponent(memoryId)}:${operation}`), {
        method: "POST",
        body,
      });
      await loadMemories();
    }, operation === "correct" ? "记忆已修正并生成新版本。" : "记忆已删除。");
  };

  const activateKillSwitch = async (event) => {
    event.preventDefault();
    await operate(event.submitter, async () => {
      await apiFetch(routes.killSwitches, {
        method: "POST",
        body: {
          scope: value("#kill-switch-scope"),
          scope_id: value("#kill-switch-scope-id"),
          mode: value("#kill-switch-mode"),
          reason: value("#kill-switch-reason"),
          incident_id: value("#kill-switch-incident"),
          expires_at: null,
        },
      });
      await loadGovernance();
    }, "Kill Switch 已激活并完成回读。");
  };

  const registerWebhook = async (event) => {
    event.preventDefault();
    await operate(event.submitter, async () => {
      const result = await apiFetch(routes.webhooks, {
        method: "POST",
        body: {
          endpoint_name: value("#webhook-name"),
          url: value("#webhook-url"),
          event_types: value("#webhook-events").split(",").map((item) => item.trim()).filter(Boolean),
        },
      });
      await loadGovernance();
      if (result.signing_secret) {
        showFeedback(`签名密钥（仅显示一次）：${result.signing_secret}`, "is-warning");
      }
    }, "Webhook 已注册。");
  };

  for (const tab of document.querySelectorAll("[data-console-tab]")) {
    tab.addEventListener("click", () => activateTab(tab.dataset.consoleTab));
  }
  select("#connect-console").addEventListener("click", () => void connect());
  select("#run-create-form").addEventListener("submit", (event) => void createRun(event));
  select("#run-lookup-form").addEventListener("submit", (event) => {
    event.preventDefault();
    setRunId(value("#run-id-input"));
    void loadRun();
  });
  select("#refresh-run").addEventListener("click", () => void loadRun());
  select("#pause-run").addEventListener("click", (event) => void controlRun("pause", event.currentTarget));
  select("#resume-run").addEventListener("click", (event) => void controlRun("resume", event.currentTarget));
  select("#cancel-run").addEventListener("click", (event) => void controlRun("cancel", event.currentTarget));
  select("#export-audit").addEventListener("click", () => void exportAudit());
  select("#refresh-actions").addEventListener("click", () => void loadActions());
  select("#refresh-capabilities").addEventListener("click", () => void operate(select("#refresh-capabilities"), loadCapabilities, "能力已刷新。"));
  select("#capability-operation-form").addEventListener("submit", (event) => void changeCapability(event));
  select("#artifact-upload-form").addEventListener("submit", (event) => void uploadArtifact(event));
  select("#artifact-lookup-form").addEventListener("submit", (event) => void loadArtifact(event));
  select("#download-artifact").addEventListener("click", () => void downloadArtifact());
  select("#delete-artifact").addEventListener("click", () => void deleteArtifact());
  select("#memory-create-form").addEventListener("submit", (event) => void createMemory(event));
  select("#refresh-memories").addEventListener("click", () => void operate(select("#refresh-memories"), loadMemories, "记忆已刷新。"));
  select("#correct-memory").addEventListener("click", (event) => void updateMemory("correct", event.currentTarget));
  select("#delete-memory").addEventListener("click", (event) => void updateMemory("delete", event.currentTarget));
  select("#kill-switch-form").addEventListener("submit", (event) => void activateKillSwitch(event));
  select("#webhook-form").addEventListener("submit", (event) => void registerWebhook(event));
  select("#refresh-governance").addEventListener("click", () => void operate(select("#refresh-governance"), loadGovernance, "治理状态已刷新。"));
  window.addEventListener("pagehide", () => {
    tokenInput.value = "";
    if (pollTimer !== null) window.clearTimeout(pollTimer);
  });
})();
