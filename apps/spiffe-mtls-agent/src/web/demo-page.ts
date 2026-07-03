import type { DemoSnapshot } from "./demo-model";

function safeJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export function renderDemoPage(snapshot: DemoSnapshot): string {
  const assetBasePath = snapshot.basePath || "";
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SPIFFE mTLS Agent Demo</title>
  <style>
    :root {
      --bg: #f7f8fb;
      --surface: #ffffff;
      --surface-2: #f8fafc;
      --text: #111827;
      --muted: #5b6472;
      --line: #d6dbe5;
      --trust: #2563eb;
      --identity: #b7791f;
      --transport: #138a61;
      --policy: #c2413d;
      --runtime: #6d5bd0;
      --observe: #6366a1;
      --shadow: 0 14px 35px rgba(15, 23, 42, 0.08);
    }

    * { box-sizing: border-box; }
    html { min-width: 320px; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background: var(--bg);
      font-family: Inter, "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      letter-spacing: 0;
    }

    button, input, select { font: inherit; }
    .app-shell { min-height: 100vh; display: flex; flex-direction: column; }

    .topbar {
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 24px;
      background: rgba(255, 255, 255, 0.92);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(10px);
    }

    .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
    .brand-mark {
      width: 38px;
      height: 38px;
      display: grid;
      place-items: center;
      border: 2px solid #111827;
      border-radius: 8px;
      font-weight: 800;
      font-size: 13px;
      background: #fff;
    }
    .brand h1 { margin: 0; font-size: 18px; line-height: 1.2; }
    .brand p { margin: 3px 0 0; color: var(--muted); font-size: 13px; }

    .top-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
    .button {
      min-height: 38px;
      border: 1px solid #cbd5e1;
      border-radius: 7px;
      background: #fff;
      color: #111827;
      padding: 8px 12px;
      cursor: pointer;
      transition: transform 120ms ease, border-color 120ms ease, background 120ms ease;
    }
    .button:hover { transform: translateY(-1px); border-color: #94a3b8; }
    .button.primary { background: #111827; color: #fff; border-color: #111827; }
    .button.danger { border-color: #f3b1ad; color: #9f1d1d; background: #fff7f7; }

    main { width: min(1480px, calc(100vw - 32px)); margin: 22px auto 42px; }
    .grid { display: grid; grid-template-columns: minmax(360px, 0.92fr) minmax(600px, 1.35fr); gap: 18px; align-items: start; }

    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }

    .panel-header { padding: 18px 20px 12px; border-bottom: 1px solid #e6eaf0; }
    .panel-header h2 { margin: 0; font-size: 18px; }
    .panel-header p { margin: 7px 0 0; color: var(--muted); line-height: 1.55; font-size: 14px; }
    .panel-body { padding: 18px 20px 20px; }

    .status-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 16px; }
    .stat {
      border: 1px solid #e3e8ef;
      border-radius: 8px;
      padding: 12px;
      background: var(--surface-2);
      min-height: 76px;
    }
    .stat label { display: block; color: var(--muted); font-size: 12px; margin-bottom: 8px; }
    .stat strong { font-size: 14px; line-height: 1.35; overflow-wrap: anywhere; }

    .actors { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
    .actor {
      border: 1px solid #e3e8ef;
      border-left: 4px solid #94a3b8;
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      min-height: 96px;
    }
    .actor strong { display: block; font-size: 14px; margin-bottom: 6px; }
    .actor span { display: block; color: var(--muted); font-size: 13px; line-height: 1.45; }
    .actor code { display: block; margin-top: 8px; font-size: 11px; color: #334155; white-space: normal; overflow-wrap: anywhere; }

    .flow-board {
      position: relative;
      display: grid;
      grid-template-columns: repeat(8, minmax(72px, 1fr));
      gap: 8px;
      padding: 14px;
      margin-bottom: 16px;
      background: #fbfcfe;
      border: 1px solid #e3e8ef;
      border-radius: 8px;
      overflow-x: auto;
    }
    .flow-step {
      position: relative;
      min-width: 88px;
      border: 1px solid #d9dee8;
      border-radius: 8px;
      padding: 10px 8px;
      background: #fff;
      min-height: 94px;
      cursor: pointer;
    }
    .flow-step::after {
      content: "";
      position: absolute;
      top: 45px;
      right: -9px;
      width: 9px;
      border-top: 2px solid #cbd5e1;
    }
    .flow-step:last-child::after { display: none; }
    .flow-step .num {
      width: 24px;
      height: 24px;
      display: grid;
      place-items: center;
      border-radius: 999px;
      font-size: 12px;
      background: #eef2f7;
      color: #0f172a;
      margin-bottom: 8px;
    }
    .flow-step strong { display: block; font-size: 12px; line-height: 1.25; }
    .flow-step small { display: block; color: var(--muted); margin-top: 6px; font-size: 11px; overflow-wrap: anywhere; }
    .flow-step.done { border-color: #16a34a; background: #f5fff8; }
    .flow-step.active { border-color: #111827; box-shadow: 0 0 0 3px rgba(17, 24, 39, 0.10); }
    .flow-step.blocked { border-color: #dc2626; background: #fff7f7; }

    .detail-layout { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(280px, 0.95fr); gap: 14px; }
    .step-detail, .terminal, .commands, .diagram-card, .layer-list, .failure-card {
      border: 1px solid #e3e8ef;
      border-radius: 8px;
      background: #fff;
    }
    .step-detail { padding: 18px; min-height: 276px; }
    .eyebrow { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
    .step-detail h3 { margin: 8px 0 10px; font-size: 24px; letter-spacing: 0; }
    .step-detail p { color: #334155; line-height: 1.65; margin: 0 0 12px; }
    .evidence {
      padding: 10px 12px;
      border-radius: 7px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      color: #1f2937;
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .code-refs { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; }
    .code-refs code {
      padding: 6px 8px;
      border-radius: 6px;
      background: #111827;
      color: #fff;
      font-size: 12px;
      overflow-wrap: anywhere;
    }

    .terminal { background: #111827; color: #dbeafe; padding: 14px; min-height: 276px; }
    .terminal h3 { margin: 0 0 10px; color: #fff; font-size: 14px; }
    .log-line { font-family: Consolas, "SFMono-Regular", monospace; font-size: 12px; line-height: 1.65; color: #cbd5e1; overflow-wrap: anywhere; }
    .log-line .ok { color: #86efac; }
    .log-line .warn { color: #fca5a5; }

    .section-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(360px, 0.72fr); gap: 18px; margin-top: 18px; }
    .diagram-card { padding: 16px; }
    .diagram-card h2, .layer-list h2, .commands h2, .failure-card h2 { margin: 0 0 12px; font-size: 18px; }
    .diagram-card img { display: block; width: 100%; height: auto; border: 1px solid #e2e8f0; border-radius: 8px; background: #fff; }
    .layer-list { padding: 16px; }
    .layer-item { padding: 12px 0; border-top: 1px solid #edf1f7; }
    .layer-item:first-of-type { border-top: 0; }
    .layer-item strong { display: block; font-size: 14px; margin-bottom: 5px; }
    .layer-item p { margin: 0 0 7px; color: #475569; font-size: 13px; line-height: 1.45; }
    .layer-item code { display: inline-block; margin: 2px 4px 2px 0; font-size: 11px; padding: 4px 6px; border-radius: 5px; background: #f1f5f9; color: #334155; }

    .bottom-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 18px; margin-top: 18px; }
    .commands, .failure-card { padding: 16px; }
    pre {
      margin: 10px 0 0;
      padding: 12px;
      border-radius: 8px;
      background: #111827;
      color: #e5e7eb;
      overflow-x: auto;
      font-size: 12px;
      line-height: 1.55;
    }
    .scenario-list { display: grid; gap: 10px; }
    .scenario {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 10px;
      background: #fff;
    }
    .scenario strong { display: block; font-size: 13px; }
    .scenario span { display: block; color: #64748b; font-size: 12px; line-height: 1.45; margin-top: 3px; }
    .scenario button { min-width: 86px; }

    .trust { border-left-color: var(--trust); }
    .identity { border-left-color: var(--identity); }
    .transport { border-left-color: var(--transport); }
    .policy { border-left-color: var(--policy); }
    .runtime { border-left-color: var(--runtime); }
    .observe { border-left-color: var(--observe); }

    @media (max-width: 1100px) {
      .grid, .section-grid, .bottom-grid, .detail-layout { grid-template-columns: 1fr; }
      .status-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .actors { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .topbar { align-items: flex-start; }
    }

    @media (max-width: 640px) {
      .topbar { position: static; flex-direction: column; padding: 14px; }
      main { width: calc(100vw - 20px); margin-top: 12px; }
      .status-row, .actors { grid-template-columns: 1fr; }
      .brand h1 { font-size: 16px; }
      .step-detail h3 { font-size: 20px; }
      .panel-header, .panel-body { padding-left: 14px; padding-right: 14px; }
      .scenario { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">SPIFFE</div>
        <div>
          <h1>SPIFFE mTLS Agent 过程演示</h1>
          <p>启动一个服务，直接看完整架构最小实现。</p>
        </div>
      </div>
      <div class="top-actions">
        <button class="button" id="resetButton" type="button">重置</button>
        <button class="button primary" id="playButton" type="button">播放成功路径</button>
      </div>
    </header>

    <main>
      <section class="grid">
        <aside class="panel">
          <div class="panel-header">
            <h2>最小运行模型</h2>
            <p>这个页面把真实项目拆成 6 层：Trust Plane、Identity、mTLS Transport、Policy、Runtime、Audit。</p>
          </div>
          <div class="panel-body">
            <div class="status-row">
              <div class="stat"><label>Trust Domain</label><strong id="trustDomain"></strong></div>
              <div class="stat"><label>当前步骤</label><strong id="currentStepLabel"></strong></div>
              <div class="stat"><label>状态</label><strong id="runState">ready</strong></div>
              <div class="stat"><label>本地服务</label><strong id="localUrl"></strong></div>
            </div>
            <div class="actors" id="actors"></div>
          </div>
        </aside>

        <section class="panel">
          <div class="panel-header">
            <h2>一次 Agent 通信过程</h2>
            <p>点任一步查看对应职责、代码文件和审计含义；也可以播放完整路径。</p>
          </div>
          <div class="panel-body">
            <div class="flow-board" id="flowBoard"></div>
            <div class="detail-layout">
              <article class="step-detail" id="stepDetail"></article>
              <aside class="terminal">
                <h3>Live trace</h3>
                <div id="terminal"></div>
              </aside>
            </div>
          </div>
        </section>
      </section>

      <section class="section-grid">
        <article class="diagram-card">
          <h2>完整架构图</h2>
          <img src="${assetBasePath}/assets/spiffe-agent-mtls-complete-architecture.svg" alt="SPIFFE mTLS Agent 完整架构图" />
        </article>
        <aside class="layer-list">
          <h2>代码层映射</h2>
          <div id="layers"></div>
        </aside>
      </section>

      <section class="bottom-grid">
        <article class="commands">
          <h2>启动命令</h2>
          <p class="evidence">页面服务：不用真实 SPIRE，负责可视化学习。真实 mTLS：继续用 server/client 命令接 Workload API socket。</p>
          <pre><code id="webCommand"></code></pre>
          <pre><code id="serverCommand"></code></pre>
          <pre><code id="clientCommand"></code></pre>
        </article>
        <article class="failure-card">
          <h2>失败路径演示</h2>
          <div class="scenario-list" id="scenarios"></div>
        </article>
      </section>
    </main>
  </div>

  <script>
    window.__DEMO__ = ${safeJson(snapshot)};
  </script>
  <script>
    const demo = window.__DEMO__;
    const apiPath = (demo.basePath || '') + '/api/demo';
    const state = { activeIndex: 0, doneUntil: -1, blockedStepId: null, logs: [] };
    const layerClass = { trust: 'trust', identity: 'identity', transport: 'transport', policy: 'policy', runtime: 'runtime', observe: 'observe' };

    const byId = (id) => document.getElementById(id);

    function renderActors() {
      byId('actors').innerHTML = demo.actors.map((actor) => {
        const className = actor.id.includes('agent') || actor.id === 'coordinator' || actor.id === 'worker' ? 'identity' : '';
        const spiffeId = actor.spiffeId ? '<code>' + actor.spiffeId + '</code>' : '';
        return '<div class="actor ' + className + '">' +
          '<strong>' + actor.title + '</strong>' +
          '<span>' + actor.subtitle + '</span>' +
          spiffeId +
        '</div>';
      }).join('');
    }

    function renderFlow() {
      byId('flowBoard').innerHTML = demo.steps.map((step, index) => {
        const isDone = index <= state.doneUntil;
        const isActive = index === state.activeIndex;
        const isBlocked = state.blockedStepId === step.id;
        const classes = ['flow-step', layerClass[step.layer], isDone ? 'done' : '', isActive ? 'active' : '', isBlocked ? 'blocked' : ''].join(' ');
        return '<button class="' + classes + '" type="button" data-index="' + index + '">' +
          '<span class="num">' + step.index + '</span>' +
          '<strong>' + step.shortTitle + '</strong>' +
          '<small>' + step.actor + '</small>' +
        '</button>';
      }).join('');
      document.querySelectorAll('.flow-step').forEach((button) => {
        button.addEventListener('click', () => selectStep(Number(button.dataset.index), false));
      });
    }

    function renderDetail() {
      const step = demo.steps[state.activeIndex];
      byId('currentStepLabel').textContent = step.index + '. ' + step.shortTitle;
      byId('stepDetail').innerHTML =
        '<div class="eyebrow">' + step.layer + ' / ' + step.actor + '</div>' +
        '<h3>' + step.title + '</h3>' +
        '<p>' + step.description + '</p>' +
        '<div class="evidence"><strong>证据:</strong> ' + step.evidence + '</div>' +
        '<div class="code-refs">' + step.codeRefs.map((ref) => '<code>' + ref + '</code>').join('') + '</div>';
    }

    function renderTerminal() {
      byId('terminal').innerHTML = state.logs.map((line) => '<div class="log-line">' + line + '</div>').join('');
    }

    function renderLayers() {
      byId('layers').innerHTML = demo.layers.map((layer) => {
        return '<div class="layer-item">' +
          '<strong>' + layer.title + '</strong>' +
          '<p>' + layer.purpose + '</p>' +
          layer.files.map((file) => '<code>' + file + '</code>').join('') +
        '</div>';
      }).join('');
    }

    function renderScenarios() {
      byId('scenarios').innerHTML = demo.failureScenarios.map((scenario) => {
        return '<div class="scenario">' +
          '<div>' +
            '<strong>' + scenario.title + '</strong>' +
            '<span>' + scenario.trigger + '</span>' +
          '</div>' +
          '<button class="button danger" type="button" data-scenario="' + scenario.id + '">演示</button>' +
        '</div>';
      }).join('');
      document.querySelectorAll('[data-scenario]').forEach((button) => {
        button.addEventListener('click', () => playFailure(button.dataset.scenario));
      });
    }

    function renderCommands() {
      byId('webCommand').textContent = demo.commands.web;
      byId('serverCommand').textContent = demo.commands.server;
      byId('clientCommand').textContent = demo.commands.client;
    }

    function selectStep(index, markDone) {
      state.activeIndex = index;
      if (markDone) state.doneUntil = Math.max(state.doneUntil, index);
      renderFlow();
      renderDetail();
    }

    function pushLog(step, variant = 'ok') {
      const cls = variant === 'warn' ? 'warn' : 'ok';
      state.logs.push('<span class="' + cls + '">[' + step.index + ']</span> ' + step.log);
      renderTerminal();
    }

    async function playSuccess() {
      reset(false);
      byId('runState').textContent = 'running success path';
      for (let index = 0; index < demo.steps.length; index += 1) {
        const step = demo.steps[index];
        selectStep(index, true);
        pushLog(step);
        await new Promise((resolve) => setTimeout(resolve, 520));
      }
      byId('runState').textContent = 'success: request reached handler';
    }

    async function playFailure(id) {
      reset(false);
      const scenario = demo.failureScenarios.find((item) => item.id === id);
      if (!scenario) return;
      byId('runState').textContent = 'failure: ' + scenario.title;
      for (let index = 0; index < demo.steps.length; index += 1) {
        const step = demo.steps[index];
        selectStep(index, true);
        if (step.id === scenario.blockedAtStepId) {
          state.blockedStepId = step.id;
          state.logs.push('<span class="warn">[blocked]</span> ' + scenario.expectedResult);
          renderFlow();
          renderTerminal();
          byId('runState').textContent = 'blocked at ' + step.shortTitle;
          return;
        }
        pushLog(step);
        await new Promise((resolve) => setTimeout(resolve, 420));
      }
    }

    function reset(render = true) {
      state.activeIndex = 0;
      state.doneUntil = -1;
      state.blockedStepId = null;
      state.logs = ['<span class="ok">[ready]</span> demo model loaded from ' + apiPath];
      byId('runState').textContent = 'ready';
      if (render) renderAll();
    }
    function renderAll() {
      byId('trustDomain').textContent = demo.trustDomain;
      byId('localUrl').textContent = demo.localUrl;
      renderActors();
      renderFlow();
      renderDetail();
      renderTerminal();
      renderLayers();
      renderScenarios();
      renderCommands();
    }

    byId('playButton').addEventListener('click', playSuccess);
    byId('resetButton').addEventListener('click', () => reset(true));
    reset(true);
  </script>
</body>
</html>`;
}