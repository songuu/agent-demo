# Deployment

Target shape:

- Source: `songuu/agent-demo`
- Release path: `/opt/agent-demo/releases/<timestamp>`
- Current symlink: `/opt/agent-demo/current`
- Runtime owner: PM2 app `agent-demo-spiffe`
- Public route: `/agent-demo/spiffe/`
- Local upstream: `127.0.0.1:5173`

Host Nginx remains the shared router. New sub-apps should add one registry entry in `app-registry.json`, one PM2 process, and one route block under `/agent-demo/<app>/`.