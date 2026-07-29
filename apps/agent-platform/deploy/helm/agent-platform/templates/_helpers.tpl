{{- define "agent-platform.toolCatalogConfigMapName" -}}
{{- $digest := required "global.toolCatalogDigest is required" .Values.global.toolCatalogDigest -}}
{{- printf "agent-platform-tool-catalog-%s" (trunc 12 (trimPrefix "sha256:" $digest)) -}}
{{- end -}}
