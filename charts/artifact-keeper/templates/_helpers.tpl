{{/*
Expand the name of the chart.
*/}}
{{- define "artifact-keeper.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "artifact-keeper.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "artifact-keeper.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "artifact-keeper.labels" -}}
helm.sh/chart: {{ include "artifact-keeper.chart" . }}
{{ include "artifact-keeper.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "artifact-keeper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "artifact-keeper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend image
*/}}
{{- define "artifact-keeper.backend.image" -}}
{{- printf "%s:%s" .Values.backend.image.repository (default .Chart.AppVersion .Values.backend.image.tag) }}
{{- end }}

{{/*
Web image
*/}}
{{- define "artifact-keeper.web.image" -}}
{{- printf "%s:%s" .Values.web.image.repository (default .Chart.AppVersion .Values.web.image.tag) }}
{{- end }}

{{/*
OpenSCAP image
*/}}
{{- define "artifact-keeper.openscap.image" -}}
{{- printf "%s:%s" .Values.openscap.image.repository (default .Chart.AppVersion .Values.openscap.image.tag) }}
{{- end }}

{{/*
PostgreSQL host — subchart or external
*/}}
{{- define "artifact-keeper.postgresql.host" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- .Values.externalPostgresql.host }}
{{- end }}
{{- end }}

{{/*
PostgreSQL port
*/}}
{{- define "artifact-keeper.postgresql.port" -}}
{{- if .Values.postgresql.enabled }}
{{- 5432 }}
{{- else }}
{{- .Values.externalPostgresql.port | default 5432 }}
{{- end }}
{{- end }}

{{/*
PostgreSQL DATABASE_URL
*/}}
{{- define "artifact-keeper.databaseUrl" -}}
{{- $host := include "artifact-keeper.postgresql.host" . }}
{{- $port := include "artifact-keeper.postgresql.port" . }}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s:%s/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password $host $port .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql://%s:%s@%s:%s/%s?sslmode=%s" .Values.externalPostgresql.username .Values.externalPostgresql.password $host $port .Values.externalPostgresql.database (.Values.externalPostgresql.sslMode | default "prefer") }}
{{- end }}
{{- end }}

{{/*
Dependency-Track database URL (JDBC format, separate database)
*/}}
{{- define "artifact-keeper.dtrack.databaseUrl" -}}
{{- $host := include "artifact-keeper.postgresql.host" . }}
{{- $port := include "artifact-keeper.postgresql.port" . }}
{{- printf "jdbc:postgresql://%s:%s/dependency_track" $host $port }}
{{- end }}

{{/*
Dependency-Track PostgreSQL credentials
*/}}
{{- define "artifact-keeper.dtrack.dbUsername" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.username }}
{{- else }}
{{- .Values.externalPostgresql.username }}
{{- end }}
{{- end }}

{{- define "artifact-keeper.dtrack.dbPassword" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.password }}
{{- else }}
{{- .Values.externalPostgresql.password }}
{{- end }}
{{- end }}

{{/*
Meilisearch URL — subchart or external
*/}}
{{- define "artifact-keeper.meilisearch.url" -}}
{{- if .Values.meilisearch.enabled }}
{{- printf "http://%s-meilisearch:7700" .Release.Name }}
{{- else }}
{{- printf "http://%s:%s" .Values.externalMeilisearch.host (toString (.Values.externalMeilisearch.port | default 7700)) }}
{{- end }}
{{- end }}

{{/*
Meilisearch API key
*/}}
{{- define "artifact-keeper.meilisearch.apiKey" -}}
{{- if .Values.meilisearch.enabled }}
{{- .Values.meilisearch.masterKey | default "artifact-keeper-production-key" }}
{{- else }}
{{- .Values.externalMeilisearch.apiKey }}
{{- end }}
{{- end }}
