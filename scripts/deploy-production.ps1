$script = Join-Path $PSScriptRoot "deploy-production.mjs"
node $script @args
exit $LASTEXITCODE