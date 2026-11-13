{{/* The Service and objects are named after the release, so "mocks" gives https://mocks:9443. */}}
{{- define "iop-gw-mocks.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "iop-gw-mocks.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "iop-gw-mocks.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The configuration with the chart's own settings: listener, output folder, TLS and signing key from keysSecret. */}}
{{- define "iop-gw-mocks.config" -}}
{{- $c := deepCopy .Values.config -}}
{{- $_ := set $c "listenAddr" (printf "0.0.0.0:%v" .Values.service.port) -}}
{{- $_ := set $c "outDir" "/var/lib/iop-gw-mocks/out" -}}
{{- $_ := set $c "tls" (dict "certFile" "/etc/iop-gw-mocks/keys/tls.crt" "keyFile" "/etc/iop-gw-mocks/keys/tls.key") -}}
{{- $ts := default (dict) $c.tokenService -}}
{{- $_ := set $ts "signingKeyFile" "/etc/iop-gw-mocks/keys/signing.pem" -}}
{{- $_ := set $c "tokenService" $ts -}}
{{- toYaml $c -}}
{{- end -}}
