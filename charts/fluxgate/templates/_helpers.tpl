{{- define "fluxgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fluxgate.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "fluxgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fluxgate.labels" -}}
helm.sh/chart: {{ include "fluxgate.chart" . }}
{{ include "fluxgate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "fluxgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fluxgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "fluxgate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "fluxgate.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "fluxgate.secretName" -}}
{{- if .Values.externalSecret.targetSecretName -}}
{{- .Values.externalSecret.targetSecretName -}}
{{- else if .Values.vault.envSecretName -}}
{{- .Values.vault.envSecretName -}}
{{- else -}}
{{- printf "%s-cloudflare-kv" (include "fluxgate.fullname" .) -}}
{{- end -}}
{{- end -}}
