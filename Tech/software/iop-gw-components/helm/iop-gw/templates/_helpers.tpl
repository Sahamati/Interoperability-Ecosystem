{{- define "iop-gw.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "iop-gw.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "iop-gw.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The gateway configuration, with the cache directory added when the persistent
cache is on. It is a subdirectory of the volume: the volume's own root belongs
to root, and the gateway creates its cache directory itself (mode 0700).
*/}}
{{- define "iop-gw.config" -}}
{{- $c := deepCopy .Values.config -}}
{{- if .Values.cache.persistent -}}{{- $_ := set $c "cache" (dict "dir" "/var/lib/iop-gw/cache/store") -}}{{- end -}}
{{- toYaml $c -}}
{{- end -}}

{{- define "iop-gw.envSecret" -}}
{{- if .Values.createSecrets.enabled -}}{{ include "iop-gw.fullname" . }}-env{{- else -}}{{ .Values.secretEnv.existingSecret }}{{- end -}}
{{- end -}}

{{- define "iop-gw.filesSecret" -}}
{{- if .Values.createSecrets.enabled -}}{{ include "iop-gw.fullname" . }}-files{{- else -}}{{ .Values.files.existingSecret }}{{- end -}}
{{- end -}}

{{/* The image's JVM options, plus the truststore and any extra options. */}}
{{- define "iop-gw.javaToolOptions" -}}
{{- $o := list "-XX:MaxRAMPercentage=75" "-XX:+ExitOnOutOfMemoryError" "-XX:-HeapDumpOnOutOfMemoryError" -}}
{{- if .Values.truststore.existingSecret -}}
{{- $o = append $o "-Djavax.net.ssl.trustStore=/etc/iop-gw/truststore/truststore.p12" -}}
{{- $o = append $o (printf "-Djavax.net.ssl.trustStorePassword=%s" .Values.truststore.password) -}}
{{- $o = append $o "-Djavax.net.ssl.trustStoreType=PKCS12" -}}
{{- end -}}
{{- if .Values.javaOpts -}}{{- $o = append $o .Values.javaOpts -}}{{- end -}}
{{- join " " $o -}}
{{- end -}}
