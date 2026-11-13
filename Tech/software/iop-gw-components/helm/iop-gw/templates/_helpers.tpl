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

{{/*
Refuses to render until every value only the deploying entity can know is set,
naming each one. (The gateway checks its whole configuration again at start-up.)
*/}}
{{- define "iop-gw.validate" -}}
{{- $c := .Values.config -}}
{{- $missing := list -}}
{{- if not .Values.image.repository }}{{ $missing = append $missing "image.repository: where the iop-gw image is (your registry)" }}{{ end -}}
{{- if not (dig "self" "id" "" $c) }}{{ $missing = append $missing "config.self.id: your Central Registry id" }}{{ end -}}
{{- if eq (dig "self" "signingKey" "source" "file" $c) "file" -}}
{{- if not (dig "self" "signingKey" "kid" "" $c) }}{{ $missing = append $missing "config.self.signingKey.kid: the key id of your signing key in the Central Registry" }}{{ end -}}
{{- end -}}
{{- if eq (dig "self" "decryptionKeys" "source" "file" $c) "file" -}}
{{- $keys := dig "self" "decryptionKeys" "keys" (list) $c -}}
{{- if not $keys }}{{ $missing = append $missing "config.self.decryptionKeys.keys: at least one {kid, file}" }}{{ end -}}
{{- range $keys }}{{ if not .kid }}{{ $missing = append $missing "config.self.decryptionKeys.keys[].kid: the key id of each decryption key in the Central Registry" }}{{ end }}{{ end -}}
{{- end -}}
{{- if not (dig "core" "baseUrl" "" $c) }}{{ $missing = append $missing "config.core.baseUrl: where your core is reached" }}{{ end -}}
{{- if and (hasKey $c "tokenService") (not (dig "tokenService" "baseUrl" "" $c)) }}{{ $missing = append $missing "config.tokenService.baseUrl: the token service" }}{{ end -}}
{{- if eq (dig "apiKey" "mode" "jwt" $c) "jwt" -}}
{{- if and (not (dig "apiKey" "issuerKeysUrl" "" $c)) (not (dig "apiKey" "issuerPublicKeys" (list) $c)) }}{{ $missing = append $missing "config.apiKey.issuerKeysUrl: the token service's JWKS URL" }}{{ end -}}
{{- end -}}
{{- if and (eq (dig "cr" "source" "config" $c) "api") (not (dig "cr" "baseUrl" "" $c)) }}{{ $missing = append $missing "config.cr.baseUrl: the Central Registry" }}{{ end -}}
{{- if and (eq (default "config" $c.aigSource) "api") (not $c.aigBaseUrl) }}{{ $missing = append $missing "config.aigBaseUrl: the AIG" }}{{ end -}}
{{- if and (eq (dig "linkedAAs" "source" "config" $c) "config") (not (dig "linkedAAs" "aas" (list) $c)) }}{{ $missing = append $missing "config.linkedAAs.aas: the AAs you are linked to" }}{{ end -}}
{{- if $missing -}}
{{- fail (printf "\n\nThese values must be set (see SETUP.md, section 5):\n  - %s\n" (join "\n  - " $missing)) -}}
{{- end -}}
{{- end -}}
