module.exports = {
  apps: [
    {
      name: "agent-demo-spiffe",
      cwd: "/opt/agent-demo/current/apps/spiffe-mtls-agent",
      script: "dist/src/web/demo-server.js",
      interpreter: "node",
      env: {
        NODE_ENV: "production",
        HOST: "127.0.0.1",
        PORT: "5173",
        BASE_PATH: "/agent-demo/spiffe",
        PUBLIC_URL: "https://songuu.com/agent-demo/spiffe/"
      }
    }
  ]
};