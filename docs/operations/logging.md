# Diagnostics logging

The backend writes its diagnostics log (request lines, warnings, errors) to
stdout through `tracing`. Two environment variables shape it, both read once at
startup:

| Variable | Values | Default | Effect |
|---|---|---|---|
| `LOG_FORMAT` | `text`, `json` (`pretty` is accepted as an alias for `text`) | `text` | Line format. |
| `LOG_ANSI` | `auto`, `true`, `false` | `auto` | ANSI colour in the `text` format. |

`RUST_LOG` still selects which events are logged (default
`artifact_keeper_backend=debug,tower_http=debug,sqlx::query=info`). The audit
stream (`AUDIT_STREAM`) is separate; see [audit-events.md](../audit-events.md).

## OpenTelemetry export (`OTEL_EXPORTER_OTLP_ENDPOINT`)

Setting `OTEL_EXPORTER_OTLP_ENDPOINT` exports spans over OTLP. Since 1.12.0
the backend can also export its diagnostics log as OpenTelemetry log records
and its metrics as OTLP metrics, to the same collector and over the same
protocol (#4337). Both are opt-in: an endpoint that only accepts traces (Tempo
or Jaeger used directly) keeps working after an upgrade.

| Variable | Values | Default | Effect |
|---|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | a URL | unset (export off) | Turns OTLP export on. With `http/protobuf` this is the full traces URL, ending in `/v1/traces`. An empty value counts as unset. |
| `OTEL_TRACES_EXPORTER` | `otlp`, `none` | `otlp` | `none` stops span export. |
| `OTEL_LOGS_EXPORTER` | `otlp`, `none` | `none` | `otlp` exports log records. |
| `OTEL_METRICS_EXPORTER` | `otlp`, `none` | `none` | `otlp` pushes metrics. |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | a URL | derived | Log endpoint, used verbatim. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | a URL | derived | Metric endpoint, used verbatim. |
| `OTEL_METRIC_EXPORT_INTERVAL` | milliseconds | `60000` | How often metrics are pushed. |
| `OTEL_RESOURCE_ATTRIBUTES` | `k=v,...` | unset | Extra resource attributes, including `service.instance.id`. |
| `DB_QUERY_SPANS` | `log`, `all`, `off` | `log` | Which SQL statements become database `CLIENT` spans; see below. |

Any other value of an `OTEL_*_EXPORTER` variable keeps that signal's default
and is reported by a startup warning. The derived endpoints are the shared one
for gRPC, and for `http/protobuf` the traces URL with `/v1/traces` replaced by
`/v1/logs` or `/v1/metrics`. The startup line `OpenTelemetry tracing enabled`
lists the exported signals in its `signals` field. The spans and their
attributes, and how a request joins the trace of the proxy in front of the
backend (`traceparent`), are described in [tracing.md](tracing.md).

**Log records.** Every event that `RUST_LOG` lets through to stdout is also
exported, so stdout output is unchanged and is not replaced: turn
`OTEL_LOGS_EXPORTER` on only where the collector, not stdout collection, is
the log pipeline, or the same lines are stored twice. `LOG_FORMAT` and
`LOG_ANSI` affect stdout only; a log record always carries the message as its
body, the event's fields as typed attributes, its level as the severity, and
the `trace_id` / `span_id` of the span it was emitted under, so a line
correlates with its trace in a backend such as Grafana Tempo. Events emitted
outside any span carry no trace context. Only the event's own fields are
exported, not those of the enclosing spans, and they carry the same redacted
values stdout prints (upstream URLs without credentials, tokens removed from
request URIs). The `Request completed` event therefore copies `method`, `uri`
and `status` from the request itself, so a log backend that does not join
records to traces can still identify the request (#4931). Not exported: SQL
text (`sqlx::query` events stay stdout-only,
#4455; slow statements still appear as `CLIENT` spans) and events of the
export's own transport (`opentelemetry*`, `tonic`, `h2`, `hyper`,
`hyper_util`, `tower`, `reqwest`), which would otherwise feed back into the
export.

**Database spans (`DB_QUERY_SPANS`).** Each SQL statement sqlx reports can
become a `CLIENT` span under the span it ran in (`db.system.name`,
`db.operation.name`, `db.collection.name`, never the SQL text). With `log`, the
default and the 1.11 behaviour, a statement becomes a span only when `RUST_LOG`
lets its `sqlx::query` event through, which under the default filter means the
statements sqlx reports as slow (over 1 s); a span for every statement then
needs `sqlx::query=debug`, which also prints every statement on stdout. Since
1.12.0, `all` gives a span for every statement whatever `RUST_LOG` says, while
stdout and exported log records still show only what `RUST_LOG` asks for (the
filter is applied to each output separately). `off` turns database spans off.
Any other value keeps `log` and is reported by a startup warning; the startup
line shows the mode in its `db_query_spans` field. A busy instance runs many
statements per request, so `all` multiplies the span volume: pair it with a
sampler (`OTEL_TRACES_SAMPLER`) where that matters.

**Metrics.** The instruments behind `/metrics` are pushed with the same names
and labels (`ak_http_requests_total`, `ak_http_request_duration_seconds` with
the same buckets, and so on), cumulatively. `/metrics` is served exactly as
before, so Prometheus scraping and dashboards built on it are unaffected.
Counters export as sums, gauges that are set as gauges, gauges that move up and
down (`ak_http_connections_open`) as non-monotonic sums. Every signal carries
`service.name`, `service.version` and `service.instance.id` (from
`OTEL_RESOURCE_ATTRIBUTES`, else `HOSTNAME`, else a random id per process), so
pushed series of different replicas stay apart.

**An unreachable collector** never blocks startup or requests: log records
queue in a bounded buffer (`OTEL_BLRP_MAX_QUEUE_SIZE`, 2048) and are dropped
when it is full, metrics are pushed from a background thread, and an exporter
that cannot be built (an unparseable endpoint) turns its signal off with a
message on stderr (since 1.12.0 this includes the span exporter, which used
to abort startup). On shutdown the pipelines flush what they hold at the same
time against one shared 5 s deadline, inside the 10 s a container runtime
grants before it kills the process (1.12.0; before, the signals flushed one
after another and an unreachable collector held shutdown for about 15 s,
while 1.12.0's first pass gave each signal its own 5 s timeout).

## ANSI colour (`LOG_ANSI`)

Before 1.11.2 the `text` format always coloured its output, including in a
container whose stdout is a pipe. The escape codes sit between a key and its
value (`uri` `ESC[0m=` `/api/...`), so a plain string filter such as
`|= "status=500"` in Loki, or any line-oriented SIEM rule, never matched (#4674).

- `auto` (the default) colours only when stdout is a terminal and `NO_COLOR`
  is unset or empty. Under Kubernetes, Docker or systemd the output is
  uncoloured with no setting needed.
- `true` forces colour on, whatever stdout is (and overrides `NO_COLOR`); the
  formatter is the one earlier releases used, so the output matches theirs
  apart from the fields added to the `Request completed` line since 1.11.2.
- `false` forces colour off.

Any other value is treated as `auto`. `LOG_ANSI` has no effect on the `json`
format, which never contains escape codes.

## JSON format (`LOG_FORMAT=json`)

One JSON object per line. The layout `LOG_FORMAT=json` has written since
1.10.0 (#2413) is unchanged: every key below under "Existing keys" is still
emitted with the same nesting and types, so existing parsers keep working.
From 1.11.2 (#4674) each line also carries the request fields as **top-level
keys**; target those in new detection rules.

```json
{"timestamp":"2026-10-17T14:12:29.509037Z","level":"INFO","fields":{"message":"Request completed","correlation_id":"3d0f6a52-...","method":"GET","uri":"/api/v1/repositories/npm-local/download/a.tgz","status":"200","user":"alice","ip":"203.0.113.7","latency_ms":42},"target":"artifact_keeper_backend::api::middleware::tracing","span":{"correlation_id":"3d0f6a52-...","http.route":"/api/v1/repositories/:key/download/*path","method":"GET","otel.kind":"server","uri":"/api/v1/repositories/npm-local/download/a.tgz","name":"http_request"},"spans":[{"correlation_id":"3d0f6a52-...","http.route":"/api/v1/repositories/:key/download/*path","method":"GET","otel.kind":"server","uri":"/api/v1/repositories/npm-local/download/a.tgz","name":"http_request"}],"method":"GET","uri":"/api/v1/repositories/npm-local/download/a.tgz","status":200,"correlation_id":"3d0f6a52-...","http.route":"/api/v1/repositories/:key/download/*path","user":"alice","ip":"203.0.113.7","latency_ms":42}
```

### Top-level request fields (target these)

Each key is present only when something in scope recorded it. The value is
the event's own field when it has one, else the outermost span's, so `uri` is
always the request's URI and never, say, the upstream URL of a proxy fetch
inside it.

| Field | Type | Present on | Notes |
|---|---|---|---|
| `method` | string | every line logged during a request | HTTP method. |
| `uri` | string | every line logged during a request | Request path and query, with credential-bearing query parameters replaced by `[REDACTED]` (#544). |
| `correlation_id` | string | every line logged during a request | The `X-Correlation-ID` echoed to the caller; also the `correlation_id` of audit records (#2414), so it joins the two streams. |
| `http.route` | string | every line logged during a request, once routed | Matched route pattern, e.g. `/api/v1/repositories/:key`. Absent when no route matched. |
| `status` | integer | `Request completed` | HTTP response status code. (The nested `fields.status` keeps its historical string form.) |
| `user` | string | `Request completed` | Username the request authenticated as. **Absent** for an anonymous request. |
| `ip` | string | `Request completed` | Client IP, resolved from the TCP peer; `X-Forwarded-For` is believed only from peers inside `RATE_LIMIT_TRUSTED_PROXY_CIDRS`. Absent when no address could be resolved. |
| `latency_ms` | integer | `Request completed` | Time from the request reaching the correlation middleware to its response, in milliseconds. |
| `request_id` | any | any line that records it | Hoisted when an event or span records a `request_id` field. |

The per-request summary line has `fields.message` equal to
`"Request completed"` and is logged once per request at `INFO` when the
response is ready. Write rules against it: it is the only line guaranteed to
carry `status`, `user`, `ip` and `latency_ms`. Successful health-probe
requests (`/health`, `/healthz`, `/ready`, `/readyz`, `/livez`) are not logged
unless `LOG_PROBE_REQUESTS` is set.

`user` is recorded by the shared authentication middleware (all `/api/v1`
routes and the native package-format routes) and by the OCI `/v2` credential
check. A format handler that verifies a credential on its own, outside those
paths, logs the request without `user`.

### Existing keys (unchanged since 1.10.0)

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | RFC 3339, UTC, microseconds. |
| `level` | string | `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`. |
| `fields` | object | The event's own fields, including `message` (the human-readable text; do not parse it). On `Request completed` it also holds `correlation_id`, `method`, `uri`, `status` (a string), and from 1.11.2 `user`, `ip`, `latency_ms`. |
| `target` | string | Rust module path that logged the event. |
| `span` | object | The current (innermost) span: its `name` and recorded fields. Omitted outside any span. |
| `spans` | array | The span stack, root first, each with its `name` and recorded fields. Omitted outside any span. |

The top-level request keys duplicate values already present under `fields`,
`span` or `spans`; that copy is what lets a rule address them without
descending into the nesting.

## Example queries

Loki, JSON format:

```logql
{app="artifact-keeper-backend"} | json | fields_message = "Request completed" | status >= 500
{app="artifact-keeper-backend"} | json | fields_message = "Request completed" | user = "alice" | line_format "{{.method}} {{.uri}} {{.status}} {{.ip}}"
```

Loki, text format (needs `LOG_ANSI` at its default or `false`):

```logql
{app="artifact-keeper-backend"} |= "Request completed" |= "status=500"
```

## Helm chart

The chart does not yet expose these two settings as values; set them with the
backend's extra environment variables until
[artifact-keeper-iac#387](https://github.com/artifact-keeper/artifact-keeper-iac/issues/387)
lands. With `LOG_ANSI` at its default, pods already log without colour.
