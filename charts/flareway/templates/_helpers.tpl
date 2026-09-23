{{/* Chart name. */}}
{{- define "flareway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Release-scoped resource name. */}}
{{- define "flareway.fullname" -}}
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

{{/* Fixed operator namespace required by the data-plane bootstrap and xDS PKI. */}}
{{- define "flareway.namespace" -}}
{{- .Values.namespace.name -}}
{{- end -}}

{{/* Service account name. */}}
{{- define "flareway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (printf "%s-controller-manager" (include "flareway.fullname" .)) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Operator image reference. */}}
{{- define "flareway.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "flareway.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{ include "flareway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Controller selector labels. */}}
{{- define "flareway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "flareway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller-manager
control-plane: controller-manager
{{- end -}}

{{/* Controller-manager feature flags. New reconcilers stay in their owning controller group. */}}
{{- define "flareway.controllerArgs" -}}
- --enable-gateway-controllers={{ .Values.controllers.gateway }}
- --enable-access-controllers={{ .Values.controllers.access }}
- --enable-private-network-controllers={{ .Values.controllers.privateNetwork }}
- --enable-device-controllers={{ .Values.controllers.device }}
- --enable-organization-controllers={{ .Values.controllers.organization }}
{{- end -}}

{{/* Controller-manager logging flags, appended last so they always win. */}}
{{- define "flareway.loggingArgs" -}}
- --zap-devel={{ .Values.logging.development }}
- --zap-log-level={{ .Values.logging.level }}
- --zap-encoder={{ .Values.logging.encoder }}
{{- end -}}
