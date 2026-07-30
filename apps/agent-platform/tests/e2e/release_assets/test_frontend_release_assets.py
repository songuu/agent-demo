from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[5]
FRONTEND = REPO_ROOT / "apps" / "agent-platform" / "src" / "agent_platform" / "api" / "frontend"
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy-agent-platform-single-node.mjs"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "agent-demo-deploy.yml"


def test_frontend_assets_are_local_responsive_and_status_driven() -> None:
    index = FRONTEND / "index.html"
    stylesheet = FRONTEND / "app.css"
    script = FRONTEND / "app.js"

    assert index.is_file()
    assert stylesheet.is_file()
    assert script.is_file()

    html = index.read_text(encoding="utf-8")
    css = stylesheet.read_text(encoding="utf-8")
    javascript = script.read_text(encoding="utf-8")

    assert 'data-agent-platform-shell="v1"' in html
    assert 'href="assets/app.css"' in html
    assert 'src="assets/app.js"' in html
    assert "Executive" in html
    assert "Operations" in html
    assert "Model" in html
    assert "Tools" in html
    assert "Actions" in html
    assert "Safety" in html
    assert "http://" not in html
    assert "https://" not in html
    assert "@media" in css
    assert "prefers-reduced-motion" in css
    assert 'new URL("health", window.location.href)' in javascript
    assert 'new URL("ready", window.location.href)' in javascript
    assert "/v1/" not in javascript


def test_single_node_release_routes_the_frontend_without_exposing_business_apis() -> None:
    deploy_source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    workflow_source = WORKFLOW.read_text(encoding="utf-8")

    frontend_proxy = 'print "        proxy_pass http://127.0.0.1:" port "/;";'
    css_route = 'location = " base_path "/assets/app.css'
    script_route = 'location = " base_path "/assets/app.js'
    catch_all = 'location ^~ " base_path "/ {'

    assert frontend_proxy in deploy_source
    assert css_route in deploy_source
    assert script_route in deploy_source
    assert deploy_source.index(css_route) < deploy_source.index(catch_all)
    assert deploy_source.index(script_route) < deploy_source.index(catch_all)
    assert 'data-agent-platform-shell="v1"' in deploy_source
    assert "expected public Agent Platform frontend HTML" in deploy_source
    assert 'data-agent-platform-shell="v1"' in workflow_source
    assert "text/html" in workflow_source
    assert "content-security-policy" in workflow_source
    assert "x-frame-options" in workflow_source
    assert "x-content-type-options" in workflow_source
    assert "referrer-policy" in workflow_source
    assert "cache-control" in workflow_source
    assert "/agent-demo/agent-platform/assets/app.css" in workflow_source
    assert "/agent-demo/agent-platform/assets/app.js" in workflow_source
    assert "--header 'X-Agent-Roles: admin'" in workflow_source
    assert 'test "${denied_code}" = "404"' in workflow_source
