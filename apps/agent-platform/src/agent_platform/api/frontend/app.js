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