//! Telemetry initialization: tracing subscriber with optional OpenTelemetry export.
//!
//! When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, an OTLP span exporter
//! (`tracing-opentelemetry`) is added alongside the existing stdout fmt layer,
//! and log records (`otel_logs`) and metric measurements (`otel_metrics`, a
//! `metrics` recorder) can be exported to the same collector as well (#4337).
//! When unset, behavior is identical to the previous stdout-only setup.
//!
//! The OpenTelemetry-standard `OTEL_TRACES_EXPORTER` / `OTEL_METRICS_EXPORTER`
//! / `OTEL_LOGS_EXPORTER` variables pick the signals: traces are exported
//! unless set to `none`, logs and metrics only when set to `otlp` (see
//! [`SignalExporter`]).
//!
//! The transport protocol is selected via the standard `OTEL_EXPORTER_OTLP_PROTOCOL`
//! environment variable:
//!   - `grpc` (default) -- gRPC over HTTP/2 using tonic
//!   - `http/protobuf`  -- HTTP/1.1 with binary protobuf bodies using the
//!     blocking reqwest client (see the `opentelemetry-otlp` feature note in
//!     the workspace `Cargo.toml`). Span and log batches are driven from a
//!     dedicated thread with no Tokio runtime, so those exporters must not use
//!     an async client, and exporter construction runs inside `#[tokio::main]`
//!     -- otlp builds the blocking client via `std::thread::spawn(…).join()`,
//!     so it is never constructed on the runtime either.
//!
//! The diagnostics stdout format is selected via `LOG_FORMAT`:
//!   - `text` (default; `pretty` is accepted as an alias) -- the human-readable
//!     single-line `fmt` output
//!   - `json` -- one flat JSON object per line, for structured stdout
//!     collection by a SIEM / log shipper (#2413 item 1, #4674); see
//!     [`json_log`]
//!
//! ANSI colour in the `text` format is selected via `LOG_ANSI` (#4674):
//!   - `auto` (default) -- colour only when stdout is a terminal (and
//!     `NO_COLOR` is unset), so container logs collected by a line-oriented
//!     store carry no escape codes between `key=` and its value
//!   - `true` / `false` -- force it on or off

mod db_spans;
mod json_log;
mod otel_logs;
mod otel_metrics;

use std::time::{Duration, Instant};

use opentelemetry::KeyValue;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Diagnostics stdout log format, selected via `LOG_FORMAT` (#2413 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    /// Human-readable single-line `fmt` output (default, unchanged behavior).
    /// `LOG_FORMAT=text` or the original spelling `pretty`.
    Text,
    /// One flat JSON object per line for structured stdout collection.
    Json,
}

impl LogFormat {
    /// Parse a `LOG_FORMAT` value. Defaults to `text` for empty or
    /// unrecognised values so an operator typo never silently drops
    /// diagnostics to an unexpected shape.
    fn from_value(val: &str) -> Self {
        match val.trim().to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Text,
        }
    }

    /// Read from `LOG_FORMAT`. Defaults to `text` when unset or unrecognised.
    fn from_env() -> Self {
        Self::from_value(&std::env::var("LOG_FORMAT").unwrap_or_default())
    }

    /// Canonical name, for the startup log line.
    fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

/// ANSI colour policy for the `text` format, selected via `LOG_ANSI` (#4674).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogAnsi {
    /// Colour only when stdout is a terminal and `NO_COLOR` is unset (default).
    Auto,
    /// Always colour (the pre-#4674 behaviour, minus `NO_COLOR`).
    Always,
    /// Never colour.
    Never,
}

impl LogAnsi {
    /// Parse a `LOG_ANSI` value. Empty or unrecognised values mean `auto`:
    /// a typo must not put escape codes back into collected logs.
    fn from_value(val: &str) -> Self {
        match val.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "always" => Self::Always,
            "0" | "false" | "no" | "off" | "never" => Self::Never,
            _ => Self::Auto,
        }
    }

    /// Read from `LOG_ANSI`. Defaults to `auto` when unset or unrecognised.
    fn from_env() -> Self {
        Self::from_value(&std::env::var("LOG_ANSI").unwrap_or_default())
    }

    /// Whether to emit ANSI escapes, given whether stdout is a terminal and
    /// the `NO_COLOR` value (<https://no-color.org>: any non-empty value
    /// disables colour). An explicit `true`/`false` overrides both.
    fn resolve(self, stdout_is_tty: bool, no_color: Option<&str>) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => stdout_is_tty && no_color.is_none_or(str::is_empty),
        }
    }

    /// Resolve against the real stdout and environment.
    fn resolve_from_env(self) -> bool {
        use std::io::IsTerminal;
        self.resolve(
            std::io::stdout().is_terminal(),
            std::env::var("NO_COLOR").ok().as_deref(),
        )
    }
}

/// Build the diagnostics `fmt` layer in the configured format, writing to
/// stdout.
fn build_fmt_layer<S>(format: LogFormat, ansi: bool) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    build_fmt_layer_with_writer(format, ansi, std::io::stdout)
}

/// Build the diagnostics `fmt` layer in the configured format.
///
/// Boxed so both arms have the same type regardless of the concrete
/// per-format layer. The workspace `tracing-subscriber` dependency already
/// carries the `json` feature, so the JSON arm adds no new dependency. `ansi`
/// applies to the text format only: a JSON line never carries escapes.
fn build_fmt_layer_with_writer<S, W>(
    format: LogFormat,
    ansi: bool,
    writer: W,
) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    match format {
        LogFormat::Text => tracing_subscriber::fmt::layer()
            .with_ansi(ansi)
            .with_writer(writer)
            .boxed(),
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_ansi(false)
            .event_format(json_log::FlatJson::default())
            .with_writer(writer)
            .boxed(),
    }
}

/// OTLP transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OtlpProtocol {
    /// gRPC over HTTP/2 (default).
    Grpc,
    /// HTTP/1.1 with binary protobuf bodies.
    HttpProtobuf,
}

/// Which OTLP signals are exported, from the OpenTelemetry-standard
/// `OTEL_<SIGNAL>_EXPORTER` variables (#4337).
///
/// | Variable | unset | `otlp` | `none` |
/// |---|---|---|---|
/// | `OTEL_TRACES_EXPORTER`  | exported | exported | not exported |
/// | `OTEL_LOGS_EXPORTER`    | not exported | exported | not exported |
/// | `OTEL_METRICS_EXPORTER` | not exported | exported | not exported |
///
/// Traces keep the behaviour they had before #4337: setting
/// `OTEL_EXPORTER_OTLP_ENDPOINT` exports them. Logs and metrics are opt-in on
/// top of that. The OpenTelemetry specification defaults every signal to
/// `otlp`, but a deployment that already points the endpoint at a
/// traces-only backend (Tempo, Jaeger) would start sending it two signals it
/// rejects on upgrade, and stdout logging would be duplicated into the
/// collector without anyone asking for it. Any other value (`console`,
/// `prometheus`, a typo) is not supported: it keeps the signal's default and
/// is reported by [`SignalExporter::unsupported`] so startup can warn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignalExporter {
    traces: bool,
    metrics: bool,
    logs: bool,
}

/// One `OTEL_<SIGNAL>_EXPORTER` value, parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalSetting {
    Unset,
    Otlp,
    None,
    Unsupported,
}

impl SignalSetting {
    /// Parse a raw value: case-insensitive, surrounding whitespace ignored, an
    /// empty value is the same as unset.
    fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            None | Some("") => Self::Unset,
            Some(v) if v.eq_ignore_ascii_case("otlp") => Self::Otlp,
            Some(v) if v.eq_ignore_ascii_case("none") => Self::None,
            Some(_) => Self::Unsupported,
        }
    }

    /// Whether the signal is exported, given its default when unset.
    fn enabled(self, default: bool) -> bool {
        match self {
            Self::Otlp => true,
            Self::None => false,
            Self::Unset | Self::Unsupported => default,
        }
    }
}

/// Variable names, in the order [`SignalExporter::from_values`] takes them.
const SIGNAL_EXPORTER_VARS: [&str; 3] = [
    "OTEL_TRACES_EXPORTER",
    "OTEL_METRICS_EXPORTER",
    "OTEL_LOGS_EXPORTER",
];

impl SignalExporter {
    /// Resolve the three signals from their raw variable values (traces,
    /// metrics, logs).
    fn from_values(traces: Option<&str>, metrics: Option<&str>, logs: Option<&str>) -> Self {
        Self {
            traces: SignalSetting::parse(traces).enabled(true),
            metrics: SignalSetting::parse(metrics).enabled(false),
            logs: SignalSetting::parse(logs).enabled(false),
        }
    }

    fn from_env() -> Self {
        let [traces, metrics, logs] = SIGNAL_EXPORTER_VARS.map(|v| std::env::var(v).ok());
        Self::from_values(traces.as_deref(), metrics.as_deref(), logs.as_deref())
    }

    /// The `OTEL_<SIGNAL>_EXPORTER` variables set to a value other than
    /// `otlp` or `none`, with that value, for a startup warning.
    fn unsupported() -> Vec<(&'static str, String)> {
        SIGNAL_EXPORTER_VARS
            .into_iter()
            .filter_map(|var| {
                let value = std::env::var(var).ok()?;
                (SignalSetting::parse(Some(&value)) == SignalSetting::Unsupported)
                    .then_some((var, value))
            })
            .collect()
    }

    /// The enabled signals, for the startup log line.
    fn names(self) -> String {
        let mut names = Vec::new();
        if self.traces {
            names.push("traces");
        }
        if self.metrics {
            names.push("metrics");
        }
        if self.logs {
            names.push("logs");
        }
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(",")
        }
    }
}

/// An OTLP signal other than traces, for [`signal_endpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OtlpSignal {
    Logs,
    Metrics,
}

impl OtlpSignal {
    /// The per-signal endpoint variable of the OpenTelemetry specification.
    fn endpoint_var(self) -> &'static str {
        match self {
            Self::Logs => "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            Self::Metrics => "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        }
    }

    /// The OTLP/HTTP path of the signal.
    fn http_path(self) -> &'static str {
        match self {
            Self::Logs => "/v1/logs",
            Self::Metrics => "/v1/metrics",
        }
    }
}

/// The endpoint the logs or metrics exporter is built with.
///
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is handed to the span exporter verbatim, and
/// a programmatic endpoint is never extended with a signal path by
/// `opentelemetry-otlp`. For http/protobuf deployments therefore set it to the
/// full traces URL (`http://collector:4318/v1/traces`); reusing that URL for
/// logs and metrics would post them to the traces path, which a collector
/// rejects. So, in order:
///
/// 1. `OTEL_EXPORTER_OTLP_{LOGS,METRICS}_ENDPOINT`, when set, verbatim;
/// 2. gRPC: the shared endpoint (one service serves every signal);
/// 3. http/protobuf: the shared endpoint with a trailing `/v1/traces`
///    replaced by the signal's path, or the signal's path appended when the
///    endpoint does not end in `/v1/traces`.
fn signal_endpoint(
    protocol: OtlpProtocol,
    endpoint: &str,
    signal: OtlpSignal,
    signal_override: Option<&str>,
) -> String {
    if let Some(explicit) = signal_override.map(str::trim).filter(|v| !v.is_empty()) {
        return explicit.to_owned();
    }
    match protocol {
        OtlpProtocol::Grpc => endpoint.to_owned(),
        OtlpProtocol::HttpProtobuf => {
            let base = endpoint.trim_end_matches('/');
            let base = base.strip_suffix("/v1/traces").unwrap_or(base);
            format!("{base}{}", signal.http_path())
        }
    }
}

/// [`signal_endpoint`] with the per-signal override read from the environment.
fn signal_endpoint_from_env(protocol: OtlpProtocol, endpoint: &str, signal: OtlpSignal) -> String {
    let explicit = std::env::var(signal.endpoint_var()).ok();
    signal_endpoint(protocol, endpoint, signal, explicit.as_deref())
}

impl OtlpProtocol {
    /// Parse a protocol value string. Defaults to gRPC for unrecognised values,
    /// matching the OTel spec default.
    fn from_value(val: &str) -> Self {
        match val.to_lowercase().as_str() {
            "http/protobuf" | "http-protobuf" | "http_protobuf" => Self::HttpProtobuf,
            _ => Self::Grpc,
        }
    }

    /// Read from `OTEL_EXPORTER_OTLP_PROTOCOL`. Defaults to gRPC when unset
    /// or unrecognised, matching the OTel spec default.
    fn from_env() -> Self {
        let val = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").unwrap_or_default();
        Self::from_value(&val)
    }

    /// Return the canonical protocol name for logging.
    fn name(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::HttpProtobuf => "http/protobuf",
        }
    }
}

/// Build the OTel resource describing this service.
fn build_otel_resource(service_name: &str) -> Resource {
    let mut attributes = vec![
        KeyValue::new("service.name", service_name.to_owned()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_owned()),
    ];
    if let Some(instance) = service_instance_id(
        std::env::var("OTEL_RESOURCE_ATTRIBUTES").ok().as_deref(),
        std::env::var("HOSTNAME").ok().as_deref(),
    ) {
        attributes.push(KeyValue::new("service.instance.id", instance));
    }
    Resource::builder().with_attributes(attributes).build()
}

/// The `service.instance.id` resource attribute, shared by every signal.
///
/// Metrics pushed over OTLP carry no scrape `instance` label, so without this
/// the cumulative series of two replicas would collide in the collector (#4337).
/// `None` when `OTEL_RESOURCE_ATTRIBUTES` already sets it (the SDK's
/// environment detector supplies it then, and an explicit attribute here
/// would override the operator's value). Otherwise `HOSTNAME` (the pod name
/// under Kubernetes, the container id under Docker), or a random UUID when
/// that is unset.
fn service_instance_id(
    resource_attributes: Option<&str>,
    hostname: Option<&str>,
) -> Option<String> {
    let set_by_operator = resource_attributes.is_some_and(|attrs| {
        attrs
            .split(',')
            .filter_map(|pair| pair.split_once('='))
            .any(|(key, _)| key.trim() == "service.instance.id")
    });
    if set_by_operator {
        return None;
    }
    Some(
        hostname
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
    )
}

/// Build an OTLP span exporter for the given protocol and endpoint. Fails
/// soft like [`build_metric_exporter`] (#4931): before 1.12.0 an unparseable
/// endpoint panicked at startup.
fn build_span_exporter(protocol: OtlpProtocol, endpoint: &str) -> Option<SpanExporter> {
    let built = match protocol {
        OtlpProtocol::Grpc => SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build(),
        OtlpProtocol::HttpProtobuf => SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build(),
    };
    built
        .inspect_err(|e| eprintln!("OTLP span export disabled, exporter for {endpoint}: {e}"))
        .ok()
}

/// Build an OTLP metric exporter for the given protocol and endpoint.
///
/// Fails soft: an exporter that cannot be built (an unparseable endpoint) is
/// reported and the signal stays off, rather than aborting startup. An
/// unreachable collector is not a build error; connections are made lazily.
fn build_metric_exporter(protocol: OtlpProtocol, endpoint: &str) -> Option<MetricExporter> {
    let built = match protocol {
        OtlpProtocol::Grpc => MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build(),
        OtlpProtocol::HttpProtobuf => MetricExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build(),
    };
    built
        .inspect_err(|e| eprintln!("OTLP metric export disabled, exporter for {endpoint}: {e}"))
        .ok()
}

/// Build an OTLP log exporter for the given protocol and endpoint. Fails soft
/// like [`build_metric_exporter`].
fn build_log_exporter(protocol: OtlpProtocol, endpoint: &str) -> Option<LogExporter> {
    let built = match protocol {
        OtlpProtocol::Grpc => LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build(),
        OtlpProtocol::HttpProtobuf => LogExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build(),
    };
    built
        .inspect_err(|e| eprintln!("OTLP log export disabled, exporter for {endpoint}: {e}"))
        .ok()
}

/// Trace sampler, selected by the OpenTelemetry-standard
/// `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` environment variables.
///
/// The default is `parentbased_always_on`, which is both the OTel
/// specification's default and the SDK's own default — so a deployment that
/// sets neither variable samples exactly as it did before this was
/// configurable.
///
/// Recognised values, matching the spec's vocabulary:
///
/// | `OTEL_TRACES_SAMPLER`      | behaviour |
/// |---|---|
/// | `always_on`                | sample every trace, ignoring any parent |
/// | `always_off`               | sample nothing |
/// | `traceidratio`             | sample a fraction, ignoring any parent |
/// | `parentbased_always_on`    | follow the parent; sample roots (**default**) |
/// | `parentbased_always_off`   | follow the parent; drop roots |
/// | `parentbased_traceidratio` | follow the parent; sample a fraction of roots |
///
/// `OTEL_TRACES_SAMPLER_ARG` is the ratio for the two `traceidratio` forms, in
/// `[0.0, 1.0]`; it is ignored by the others. An absent, unparseable or
/// out-of-range value falls back to `1.0` (the spec's default), which makes a
/// misconfigured ratio sampler behave like `always_on` rather than silently
/// dropping every trace — losing all telemetry is the worse failure.
///
/// ## Interaction with inbound trace context
///
/// The `parentbased_*` forms honour a remote parent's sampling decision, and
/// that parent arrives on an unauthenticated, caller-controlled header (see
/// [`crate::api::middleware::tracing::remote_trace_context`]). Under the
/// default this cannot be abused to force export: the root decision is already
/// `AlwaysOn`, so a caller can only suppress its own trace. **Under
/// `parentbased_traceidratio` or `parentbased_always_off` that changes** — an
/// untrusted `sampled=01` then forces export of a trace the sampler would have
/// dropped. Setting `RATE_LIMIT_TRUSTED_PROXY_CIDRS` gates extraction on the
/// trusted-proxy range (#4195); with that list empty, extraction stays
/// accept-all for compatibility and startup logs a warning under those two
/// samplers (see [`sampler_obeys_remote_sampled_upgrade`]).
#[derive(Debug, Clone, Copy, PartialEq)]
enum SamplerChoice {
    AlwaysOn,
    AlwaysOff,
    TraceIdRatio,
    ParentBasedAlwaysOn,
    ParentBasedAlwaysOff,
    ParentBasedTraceIdRatio,
}

impl SamplerChoice {
    /// Parse `OTEL_TRACES_SAMPLER`, case- and whitespace-insensitively.
    /// Anything unrecognised — including an empty value — falls back to the
    /// default rather than failing startup, matching how `OtlpProtocol` and
    /// `LogFormat` treat their own variables.
    fn from_str_value(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "always_on" => Some(Self::AlwaysOn),
            "always_off" => Some(Self::AlwaysOff),
            "traceidratio" => Some(Self::TraceIdRatio),
            "parentbased_always_on" => Some(Self::ParentBasedAlwaysOn),
            "parentbased_always_off" => Some(Self::ParentBasedAlwaysOff),
            "parentbased_traceidratio" => Some(Self::ParentBasedTraceIdRatio),
            _ => None,
        }
    }

    fn from_env() -> Self {
        std::env::var("OTEL_TRACES_SAMPLER")
            .ok()
            .and_then(|raw| Self::from_str_value(&raw))
            .unwrap_or(Self::ParentBasedAlwaysOn)
    }

    fn name(self) -> &'static str {
        match self {
            Self::AlwaysOn => "always_on",
            Self::AlwaysOff => "always_off",
            Self::TraceIdRatio => "traceidratio",
            Self::ParentBasedAlwaysOn => "parentbased_always_on",
            Self::ParentBasedAlwaysOff => "parentbased_always_off",
            Self::ParentBasedTraceIdRatio => "parentbased_traceidratio",
        }
    }

    /// Whether a remote parent's `sampled=01` can make this sampler export a
    /// trace it would have dropped as a root (#4195). `parentbased_always_on`
    /// samples every root already, and the non-parent-based forms ignore the
    /// parent's flag entirely.
    fn obeys_remote_sampled_upgrade(self) -> bool {
        matches!(
            self,
            Self::ParentBasedAlwaysOff | Self::ParentBasedTraceIdRatio
        )
    }

    /// Whether this choice consults `OTEL_TRACES_SAMPLER_ARG`.
    fn uses_ratio(self) -> bool {
        matches!(self, Self::TraceIdRatio | Self::ParentBasedTraceIdRatio)
    }
}

/// Whether the sampler configured by `OTEL_TRACES_SAMPLER` lets an inbound
/// `sampled=01` force export of a trace it would have dropped (#4195). Used by
/// the startup warning in
/// [`crate::api::middleware::tracing::warn_if_trace_context_untrusted`].
pub fn sampler_obeys_remote_sampled_upgrade() -> bool {
    SamplerChoice::from_env().obeys_remote_sampled_upgrade()
}

/// Default sampling ratio per the OTel specification when
/// `OTEL_TRACES_SAMPLER_ARG` is absent or unusable.
const DEFAULT_SAMPLER_RATIO: f64 = 1.0;

/// Read `OTEL_TRACES_SAMPLER_ARG` as a ratio in `[0.0, 1.0]`.
///
/// Out-of-range and unparseable values fall back to
/// [`DEFAULT_SAMPLER_RATIO`]; a NaN cannot pass the range check, so it falls
/// back too.
fn sampler_ratio_from_env() -> f64 {
    std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|ratio| (0.0..=1.0).contains(ratio))
        .unwrap_or(DEFAULT_SAMPLER_RATIO)
}

fn build_sampler(choice: SamplerChoice, ratio: f64) -> opentelemetry_sdk::trace::Sampler {
    use opentelemetry_sdk::trace::Sampler;
    match choice {
        SamplerChoice::AlwaysOn => Sampler::AlwaysOn,
        SamplerChoice::AlwaysOff => Sampler::AlwaysOff,
        SamplerChoice::TraceIdRatio => Sampler::TraceIdRatioBased(ratio),
        SamplerChoice::ParentBasedAlwaysOn => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
        SamplerChoice::ParentBasedAlwaysOff => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
        SamplerChoice::ParentBasedTraceIdRatio => {
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio)))
        }
    }
}

/// Initialize the tracing subscriber.
///
/// Returns an optional guard that must be held for the lifetime of the
/// application to ensure spans, log records and metric measurements are
/// flushed on shutdown.
pub fn init_tracing(otel_endpoint: Option<&str>, service_name: &str) -> Option<OtelGuard> {
    let log_format = LogFormat::from_env();
    let log_ansi = LogAnsi::from_env().resolve_from_env();

    match otel_endpoint_if_set(otel_endpoint) {
        Some(endpoint) => {
            let protocol = OtlpProtocol::from_env();
            let requested = SignalExporter::from_env();
            let (db_query_spans, unsupported_db_query_spans) = db_spans::DbQuerySpans::from_env();
            let (guard, signals) = init_with_otel(
                endpoint,
                service_name,
                subscriber_filters(rust_log_filter, db_query_spans),
                protocol,
                log_format,
                log_ansi,
                requested,
                db_query_spans,
            );
            // Log the resolved sampler: a typo in OTEL_TRACES_SAMPLER falls
            // back to the default rather than failing startup, so the only way
            // an operator can tell which sampler is actually in force is to be
            // told at boot.
            let sampler_choice = SamplerChoice::from_env();
            tracing::info!(
                otel_endpoint = endpoint,
                service_name,
                protocol = protocol.name(),
                signals = signals.names(),
                log_format = log_format.name(),
                log_ansi,
                sampler = sampler_choice.name(),
                db_query_spans = db_query_spans.name(),
                sampler_ratio = sampler_choice
                    .uses_ratio()
                    .then(sampler_ratio_from_env)
                    .map(tracing::field::display),
                "OpenTelemetry tracing enabled"
            );
            for (var, value) in SignalExporter::unsupported() {
                tracing::warn!(
                    variable = var,
                    value = %value,
                    "unsupported OTel exporter value, only `otlp` and `none` are recognised; \
                     the signal keeps its default"
                );
            }
            if let Some(value) = unsupported_db_query_spans {
                tracing::warn!(
                    variable = db_spans::DB_QUERY_SPANS_VAR,
                    value = %value,
                    "unsupported DB_QUERY_SPANS value, only `log`, `all` and `off` are \
                     recognised; DB spans follow RUST_LOG"
                );
            }
            Some(guard)
        }
        None => {
            tracing_subscriber::registry()
                .with(rust_log_filter())
                .with(build_fmt_layer(log_format, log_ansi))
                .init();
            None
        }
    }
}

/// The OTLP endpoint to export to, if any. An empty or blank
/// `OTEL_EXPORTER_OTLP_ENDPOINT` counts as unset (#4931): before 1.12.0 it
/// turned the OTel path on with an endpoint nothing could be sent to.
fn otel_endpoint_if_set(endpoint: Option<&str>) -> Option<&str> {
    endpoint.map(str::trim).filter(|e| !e.is_empty())
}

/// The filter used when `RUST_LOG` is unset or invalid.
const DEFAULT_RUST_LOG: &str = "artifact_keeper_backend=debug,tower_http=debug,sqlx::query=info";

/// The `RUST_LOG` filter, or [`DEFAULT_RUST_LOG`].
fn rust_log_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT_RUST_LOG.into())
}

/// The filters of the OTLP-path subscriber (#3954).
///
/// With DB spans following `RUST_LOG` (the default) there is one global
/// filter, `RUST_LOG`, exactly as before. With `DB_QUERY_SPANS=all` the
/// global filter is `RUST_LOG` plus [`db_spans::ALL_QUERIES_DIRECTIVE`], so
/// the DB span layer sees every statement, and `RUST_LOG` itself becomes the
/// per-layer filter of the stdout layer and of the OTel log layer, so neither
/// shows a statement `RUST_LOG` did not ask for. The span export layer needs
/// none: the only events the extra directive admits are `sqlx::query`
/// events, which [`db_spans::otel_export_layer`] already drops.
struct SubscriberFilters {
    global: EnvFilter,
    stdout: Option<EnvFilter>,
    exported_logs: Option<EnvFilter>,
}

/// Build the [`SubscriberFilters`] for `db_query_spans`; `rust_log` builds a
/// fresh `RUST_LOG` filter (an `EnvFilter` is not `Clone`).
fn subscriber_filters(
    rust_log: impl Fn() -> EnvFilter,
    db_query_spans: db_spans::DbQuerySpans,
) -> SubscriberFilters {
    if db_query_spans.needs_per_layer_log_filters() {
        let all_queries = db_spans::ALL_QUERIES_DIRECTIVE
            .parse()
            .expect("the all-queries directive is valid");
        SubscriberFilters {
            global: rust_log().add_directive(all_queries),
            stdout: Some(rust_log()),
            exported_logs: Some(rust_log()),
        }
    } else {
        SubscriberFilters {
            global: rust_log(),
            stdout: None,
            exported_logs: None,
        }
    }
}

/// The stdout layer of the OTLP-path subscriber, under its global filter.
type FmtLayer = Box<
    dyn Layer<tracing_subscriber::layer::Layered<EnvFilter, tracing_subscriber::Registry>>
        + Send
        + Sync,
>;

/// The OTLP-path subscriber: `filters`, the stdout layer, the OTel log layer
/// (when logs are exported), the span export layer and, when `db_tracer` is
/// given, the DB span layer.
fn otel_path_subscriber(
    filters: SubscriberFilters,
    fmt_layer: FmtLayer,
    log_layer: Option<otel_logs::OtelLogLayer>,
    tracer: opentelemetry_sdk::trace::SdkTracer,
    db_tracer: Option<opentelemetry_sdk::trace::SdkTracer>,
) -> impl tracing::Subscriber + Send + Sync + 'static {
    let SubscriberFilters {
        global,
        stdout,
        exported_logs,
    } = filters;
    tracing_subscriber::registry()
        .with(global)
        .with(fmt_layer.with_filter(stdout))
        .with(layer_or_identity(
            log_layer.map(|layer| layer.with_filter(exported_logs)),
        ))
        // sqlx's per-statement events carry SQL text and stay out of the OTel
        // export; stdout and the DB span layer below still see them (#4455).
        .with(db_spans::otel_export_layer(tracer))
        // Per-query DB `CLIENT` spans from sqlx's `sqlx::query` events (#4455).
        .with(layer_or_identity(
            db_tracer.map(db_spans::DbQuerySpanLayer::new),
        ))
}

/// `layer`, or a layer that does nothing.
///
/// Not `Option<L>`: tracing-subscriber's `Layer` impl for `Option` does not
/// forward `on_register_dispatch`, and both the OTel log layer and the DB
/// span layer use the dispatch to look up the enclosing span's OTel context.
/// In an `Option` the DB span layer exports nothing at all, and the log layer
/// only keeps its trace ids because the SDK falls back to the active OTel
/// context.
fn layer_or_identity<S, L>(layer: Option<L>) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    L: Layer<S> + Send + Sync + 'static,
{
    match layer {
        Some(layer) => layer.boxed(),
        None => tracing_subscriber::layer::Identity::new().boxed(),
    }
}

/// The one deadline every OTLP signal shares during shutdown (#4931).
///
/// The SDK's batch processors use the same 5 s default one at a time. Starting
/// all signals at this deadline, rather than letting each `shutdown()` apply
/// its own default, keeps shutdown bounded by one 5 s window even if one
/// provider is scheduled late. Docker's default stop grace is 10 s.
const OTEL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Guard that shuts the OTel providers down on drop, flushing any pending
/// spans, log records and metric measurements.
pub struct OtelGuard {
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
    logger_provider: Option<opentelemetry_sdk::logs::SdkLoggerProvider>,
    /// Kept alive here so the [`PeriodicReader`] it owns keeps pushing
    /// measurements to the collector for the lifetime of the process.
    ///
    /// [`PeriodicReader`]: opentelemetry_sdk::metrics::PeriodicReader
    _meter_provider: Option<otel_metrics::MetricsGuard>,
}

impl Drop for OtelGuard {
    /// Shut the three providers down at the same time, sharing one deadline
    /// (#4931). Each flush waits up to a few seconds for an unreachable
    /// collector; one after the other they took about 15 s, longer than the
    /// 10 s a container runtime grants before `SIGKILL`, so the final flush
    /// was lost. Concurrently the wait is that of the slowest one, bounded by
    /// [`OTEL_SHUTDOWN_TIMEOUT`].
    fn drop(&mut self) {
        let deadline = Instant::now() + OTEL_SHUTDOWN_TIMEOUT;
        let meter_provider = self._meter_provider.take();
        let provider = &self.provider;
        let logger_provider = self.logger_provider.as_ref();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let timeout = deadline.saturating_duration_since(Instant::now());
                if let Err(e) = provider.shutdown_with_timeout(timeout) {
                    eprintln!("Failed to shutdown OTel tracer provider: {e:?}");
                }
            });
            if let Some(logger_provider) = logger_provider {
                scope.spawn(move || {
                    let timeout = deadline.saturating_duration_since(Instant::now());
                    if let Err(e) = logger_provider.shutdown_with_timeout(timeout) {
                        eprintln!("Failed to shutdown OTel logger provider: {e:?}");
                    }
                });
            }
            if let Some(meter_provider) = meter_provider {
                scope.spawn(move || {
                    let timeout = deadline.saturating_duration_since(Instant::now());
                    meter_provider.shutdown(timeout);
                });
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn init_with_otel(
    endpoint: &str,
    service_name: &str,
    filters: SubscriberFilters,
    protocol: OtlpProtocol,
    log_format: LogFormat,
    log_ansi: bool,
    requested: SignalExporter,
    db_query_spans: db_spans::DbQuerySpans,
) -> (OtelGuard, SignalExporter) {
    use opentelemetry::trace::TracerProvider;

    let mut signals = requested;

    let resource = build_otel_resource(service_name);

    // Metrics (#4337). The recorder is handed to `metrics_service`, which
    // installs it together with the Prometheus recorder when `main` calls
    // `init_metrics`; the guard owns the provider for the process lifetime.
    let metrics_exporter = signals
        .metrics
        .then(|| {
            let endpoint = signal_endpoint_from_env(protocol, endpoint, OtlpSignal::Metrics);
            build_metric_exporter(protocol, &endpoint)
        })
        .flatten();
    signals.metrics = metrics_exporter.is_some();
    let meter_provider = metrics_exporter.map(|exporter| {
        let (recorder, provider) =
            otel_metrics::build_otel_metrics_recorder(exporter, resource.clone());
        crate::services::metrics_service::install_otel_recorder(recorder);
        otel_metrics::MetricsGuard::new(provider)
    });

    // ── Traces ──────────────────────────────────────────────────────────
    let span_exporter = signals
        .traces
        .then(|| build_span_exporter(protocol, endpoint))
        .flatten();
    signals.traces = span_exporter.is_some();
    let provider = span_exporter.map(|exporter| {
        use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};

        let sampler_choice = SamplerChoice::from_env();
        let sampler_ratio = sampler_ratio_from_env();
        SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_sampler(build_sampler(sampler_choice, sampler_ratio))
            .with_span_processor(BatchSpanProcessor::builder(exporter).build())
            .build()
    });

    // The tracer provider always exists for the subscriber's layers (the SDK's
    // default is a no-op provider when traces are disabled); the guard holds
    // the export-backed one when traces are on.
    let tracer_provider = provider.clone().unwrap_or_default();

    let tracer = tracer_provider.tracer("artifact-keeper");
    // The DB span layer sees what the global filter lets through: slow
    // statements by default, every statement with `sqlx::query=debug` or
    // `DB_QUERY_SPANS=all` (#3954); none with `DB_QUERY_SPANS=off`.
    let db_tracer = db_query_spans
        .enabled()
        .then(|| tracer_provider.tracer("artifact-keeper"));

    // Logs (#4337). The batch processor's queue is bounded
    // (OTEL_BLRP_MAX_QUEUE_SIZE, 2048 by default) and drops records when the
    // collector cannot keep up, so a slow or unreachable collector never
    // blocks the thread that logged.
    let log_exporter = signals
        .logs
        .then(|| {
            let endpoint = signal_endpoint_from_env(protocol, endpoint, OtlpSignal::Logs);
            build_log_exporter(protocol, &endpoint)
        })
        .flatten();
    signals.logs = log_exporter.is_some();
    let (logger_provider, log_layer) = match log_exporter {
        Some(exporter) => {
            use opentelemetry::logs::LoggerProvider as _;
            let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
                .with_resource(resource.clone())
                .with_batch_exporter(exporter)
                .build();
            let layer = otel_logs::OtelLogLayer::new(provider.logger("artifact-keeper"));
            (Some(provider), Some(layer))
        }
        None => (None, None),
    };

    // Install the W3C Trace Context propagator globally.
    //
    // Without this, `get_text_map_propagator` hands back the SDK's no-op
    // propagator and every extract/inject silently does nothing -- which is
    // why an inbound `traceparent` was previously read for its trace-id
    // (see `api::middleware::tracing`) but never became a span parent, and
    // why the backend's spans landed in their own traces rather than the
    // caller's. Installed only on the OTel path: with no exporter configured
    // there are no spans to correlate, so there is nothing to propagate.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    otel_path_subscriber(
        filters,
        build_fmt_layer(log_format, log_ansi),
        log_layer,
        tracer,
        db_tracer,
    )
    .init();

    let guard = OtelGuard {
        provider: provider.unwrap_or_default(),
        logger_provider,
        _meter_provider: meter_provider,
    };
    (guard, signals)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env var tests mutate process-wide state, so they must not run in parallel
    // with each other. This mutex serialises access to OTEL_EXPORTER_OTLP_PROTOCOL.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // ── from_value ──────────────────────────────────────────────────────

    #[test]
    fn test_protocol_defaults_to_grpc_for_empty_string() {
        assert_eq!(OtlpProtocol::from_value(""), OtlpProtocol::Grpc);
    }

    #[test]
    fn test_protocol_accepts_http_protobuf_variants() {
        for val in [
            "http/protobuf",
            "http-protobuf",
            "http_protobuf",
            "HTTP/PROTOBUF",
            "Http/Protobuf",
            "HTTP-PROTOBUF",
            "HTTP_PROTOBUF",
        ] {
            assert_eq!(
                OtlpProtocol::from_value(val),
                OtlpProtocol::HttpProtobuf,
                "failed for {val}"
            );
        }
    }

    #[test]
    fn test_protocol_grpc_explicit() {
        assert_eq!(OtlpProtocol::from_value("grpc"), OtlpProtocol::Grpc);
        assert_eq!(OtlpProtocol::from_value("GRPC"), OtlpProtocol::Grpc);
        assert_eq!(OtlpProtocol::from_value("Grpc"), OtlpProtocol::Grpc);
    }

    #[test]
    fn test_protocol_unrecognized_falls_back_to_grpc() {
        assert_eq!(OtlpProtocol::from_value("http/json"), OtlpProtocol::Grpc);
        assert_eq!(OtlpProtocol::from_value("bogus"), OtlpProtocol::Grpc);
        assert_eq!(OtlpProtocol::from_value("thrift"), OtlpProtocol::Grpc);
    }

    // ── from_env ────────────────────────────────────────────────────────

    #[test]
    fn test_from_env_defaults_to_grpc_when_unset() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
        assert_eq!(OtlpProtocol::from_env(), OtlpProtocol::Grpc);
    }

    #[test]
    fn test_from_env_reads_grpc() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc");
        let result = OtlpProtocol::from_env();
        std::env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
        assert_eq!(result, OtlpProtocol::Grpc);
    }

    #[test]
    fn test_from_env_reads_http_protobuf() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");
        let result = OtlpProtocol::from_env();
        std::env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
        assert_eq!(result, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn test_from_env_unrecognised_value_falls_back_to_grpc() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "unknown-proto");
        let result = OtlpProtocol::from_env();
        std::env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
        assert_eq!(result, OtlpProtocol::Grpc);
    }

    // ── name ────────────────────────────────────────────────────────────

    #[test]
    fn test_protocol_name_grpc() {
        assert_eq!(OtlpProtocol::Grpc.name(), "grpc");
    }

    #[test]
    fn test_protocol_name_http_protobuf() {
        assert_eq!(OtlpProtocol::HttpProtobuf.name(), "http/protobuf");
    }

    // ── derived traits ──────────────────────────────────────────────────

    #[test]
    fn test_protocol_debug_format() {
        assert_eq!(format!("{:?}", OtlpProtocol::Grpc), "Grpc");
        assert_eq!(format!("{:?}", OtlpProtocol::HttpProtobuf), "HttpProtobuf");
    }

    #[test]
    fn test_protocol_clone_and_copy() {
        let original = OtlpProtocol::HttpProtobuf;
        let cloned = original;
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_protocol_equality() {
        assert_eq!(OtlpProtocol::Grpc, OtlpProtocol::Grpc);
        assert_eq!(OtlpProtocol::HttpProtobuf, OtlpProtocol::HttpProtobuf);
        assert_ne!(OtlpProtocol::Grpc, OtlpProtocol::HttpProtobuf);
    }

    // ── LogFormat (#2413 item 1, #4674) ────────────────────────────────

    #[test]
    fn test_log_format_defaults_to_text_for_empty_string() {
        assert_eq!(LogFormat::from_value(""), LogFormat::Text);
    }

    #[test]
    fn test_log_format_accepts_json_variants() {
        for val in ["json", "JSON", "Json", " json ", "json\n"] {
            assert_eq!(
                LogFormat::from_value(val),
                LogFormat::Json,
                "failed for {val:?}"
            );
        }
    }

    #[test]
    fn test_log_format_text_and_pretty_alias_explicit() {
        for val in ["text", "TEXT", "pretty", "PRETTY"] {
            assert_eq!(
                LogFormat::from_value(val),
                LogFormat::Text,
                "failed for {val:?}"
            );
        }
    }

    #[test]
    fn test_log_format_unrecognised_falls_back_to_text() {
        assert_eq!(LogFormat::from_value("logfmt"), LogFormat::Text);
        assert_eq!(LogFormat::from_value("bogus"), LogFormat::Text);
    }

    #[test]
    fn test_log_format_from_env_defaults_to_text_when_unset() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("LOG_FORMAT");
        assert_eq!(LogFormat::from_env(), LogFormat::Text);
    }

    #[test]
    fn test_log_format_from_env_reads_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("LOG_FORMAT", "json");
        let result = LogFormat::from_env();
        std::env::remove_var("LOG_FORMAT");
        assert_eq!(result, LogFormat::Json);
    }

    #[test]
    fn test_log_format_name() {
        assert_eq!(LogFormat::Text.name(), "text");
        assert_eq!(LogFormat::Json.name(), "json");
    }

    #[test]
    fn test_build_fmt_layer_builds_both_formats() {
        // Both arms must type-check to the same boxed layer and construct
        // without panicking against the registry subscriber type.
        let _text = build_fmt_layer::<tracing_subscriber::Registry>(LogFormat::Text, true);
        let _json = build_fmt_layer::<tracing_subscriber::Registry>(LogFormat::Json, false);
    }

    // ── LogAnsi (#4674) ─────────────────────────────────────────────────

    #[test]
    fn test_log_ansi_parses_values() {
        for val in ["", "auto", "AUTO", "bogus"] {
            assert_eq!(
                LogAnsi::from_value(val),
                LogAnsi::Auto,
                "failed for {val:?}"
            );
        }
        for val in ["true", "1", "yes", "on", "always", " TRUE "] {
            assert_eq!(
                LogAnsi::from_value(val),
                LogAnsi::Always,
                "failed for {val:?}"
            );
        }
        for val in ["false", "0", "no", "off", "never"] {
            assert_eq!(
                LogAnsi::from_value(val),
                LogAnsi::Never,
                "failed for {val:?}"
            );
        }
    }

    #[test]
    fn test_log_ansi_auto_is_off_when_stdout_is_not_a_tty() {
        // The #4674 default: a container's stdout is a pipe, not a TTY.
        assert!(!LogAnsi::Auto.resolve(false, None));
        assert!(LogAnsi::Auto.resolve(true, None));
        assert!(LogAnsi::Auto.resolve(true, Some("")));
        assert!(!LogAnsi::Auto.resolve(true, Some("1")));
    }

    #[test]
    fn test_log_ansi_explicit_overrides_tty_and_no_color() {
        assert!(LogAnsi::Always.resolve(false, Some("1")));
        assert!(!LogAnsi::Never.resolve(true, None));
    }

    #[test]
    fn test_log_ansi_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("LOG_ANSI");
        let unset = LogAnsi::from_env();
        std::env::set_var("LOG_ANSI", "false");
        let off = LogAnsi::from_env();
        std::env::remove_var("LOG_ANSI");
        assert_eq!(unset, LogAnsi::Auto);
        assert_eq!(off, LogAnsi::Never);
    }

    // ── fmt layer output (#4674) ────────────────────────────────────────

    /// A `MakeWriter` that appends every line to a shared buffer.
    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("log output is UTF-8")
        }
    }

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // ── DB_QUERY_SPANS (#3954) ──────────────────────────────────────────

    /// Run one request's worth of events through the production OTLP-path
    /// subscriber with `RUST_LOG=rust_log` and `mode`: a statement at sqlx's
    /// per-statement level (DEBUG) inside an `http_request` span, plus an
    /// INFO and a DEBUG line from a crate the filter keeps at INFO. Returns the
    /// stdout text and the exported spans.
    fn run_db_query_spans(
        rust_log: &'static str,
        mode: db_spans::DbQuerySpans,
    ) -> (String, crate::testing::otel::ExportedSpans) {
        let capture = Capture::default();
        let exported = crate::testing::otel::ExportedSpans::default();
        let subscriber = otel_path_subscriber(
            subscriber_filters(|| EnvFilter::new(rust_log), mode),
            build_fmt_layer_with_writer(LogFormat::Text, false, capture.clone()),
            None,
            exported.tracer(),
            mode.enabled().then(|| exported.tracer()),
        );
        tracing::subscriber::with_default(subscriber, || {
            let request = tracing::info_span!("http_request");
            let _entered = request.enter();
            tracing::event!(
                target: "sqlx::query",
                tracing::Level::DEBUG,
                summary = "SELECT id FROM …",
                db.statement = "SELECT id FROM repositories WHERE key = $1",
                rows_affected = 0u64,
                rows_returned = 1u64,
                elapsed_secs = 0.002,
            );
            tracing::info!(target: "other_crate", "kept at info");
            tracing::debug!(target: "other_crate", "dropped at debug");
        });
        (capture.text(), exported)
    }

    const DEFAULT_FILTER_WITH_OTHER_AT_INFO: &str =
        "artifact_keeper_backend=debug,tower_http=debug,sqlx::query=info,other_crate=info";

    #[test]
    fn all_mode_exports_every_statement_without_logging_it() {
        let (stdout, exported) = run_db_query_spans(
            DEFAULT_FILTER_WITH_OTHER_AT_INFO,
            db_spans::DbQuerySpans::All,
        );
        assert_eq!(
            exported.named("SELECT repositories").len(),
            1,
            "with DB_QUERY_SPANS=all a DEBUG statement becomes a DB span"
        );
        assert!(
            !stdout.contains("SELECT"),
            "stdout must still follow RUST_LOG (sqlx::query=info): {stdout}"
        );
        assert!(stdout.contains("kept at info"), "{stdout}");
        assert!(!stdout.contains("dropped at debug"), "{stdout}");
        assert_eq!(exported.named("http_request").len(), 1);
    }

    #[test]
    fn log_mode_keeps_the_rust_log_coupling() {
        let (stdout, exported) = run_db_query_spans(
            DEFAULT_FILTER_WITH_OTHER_AT_INFO,
            db_spans::DbQuerySpans::Log,
        );
        assert!(exported.named("SELECT repositories").is_empty());
        assert!(!stdout.contains("SELECT"), "{stdout}");

        let (stdout, exported) = run_db_query_spans(
            "artifact_keeper_backend=info,sqlx::query=debug,other_crate=info",
            db_spans::DbQuerySpans::Log,
        );
        assert_eq!(exported.named("SELECT repositories").len(), 1);
        assert!(stdout.contains("SELECT"), "{stdout}");
    }

    #[test]
    fn off_mode_exports_no_db_spans() {
        let (stdout, exported) = run_db_query_spans(
            "artifact_keeper_backend=info,sqlx::query=debug,other_crate=info",
            db_spans::DbQuerySpans::Off,
        );
        assert!(exported.named("SELECT repositories").is_empty());
        assert!(stdout.contains("SELECT"), "stdout is unaffected: {stdout}");
    }

    /// #4931 item 5: a log backend that only sees the exported record, and
    /// not the enclosing span, can still identify the request. The production
    /// middleware copies method and redacted URI onto the completion event.
    #[tokio::test]
    async fn exported_request_completed_record_carries_method_and_uri() {
        use axum::{body::Body, routing::put, Router};
        use opentelemetry::logs::{AnyValue, LoggerProvider as _};
        use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
        use tower::ServiceExt;

        let log_exporter = InMemoryLogExporter::default();
        let logger_provider = SdkLoggerProvider::builder()
            .with_simple_exporter(log_exporter.clone())
            .build();
        let exported = crate::testing::otel::ExportedSpans::default();
        let subscriber = otel_path_subscriber(
            subscriber_filters(
                || EnvFilter::new(DEFAULT_RUST_LOG),
                db_spans::DbQuerySpans::Log,
            ),
            build_fmt_layer_with_writer(LogFormat::Text, false, Capture::default()),
            Some(otel_logs::OtelLogLayer::new(logger_provider.logger("test"))),
            exported.tracer(),
            None,
        );
        let _guard = tracing::subscriber::set_default(subscriber);

        async fn authed() -> axum::http::StatusCode {
            crate::api::middleware::request_span::record_user("alice");
            axum::http::StatusCode::CREATED
        }
        let app = Router::new()
            .route("/api/v1/things/:id", put(authed))
            .layer(axum::middleware::from_fn(
                crate::api::middleware::tracing::correlation_id_middleware,
            ))
            .layer(
                tower_http::trace::TraceLayer::new_for_http().make_span_with(
                    |request: &axum::http::Request<Body>| {
                        crate::api::middleware::tracing::make_http_request_span(request, &[])
                    },
                ),
            );
        let request = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/things/7?password=hunter2")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);

        logger_provider.force_flush().expect("flush");
        let records = log_exporter.get_emitted_logs().expect("emitted logs");
        let done = records
            .iter()
            .find(|r| r.record.body() == Some(&AnyValue::from("Request completed".to_owned())))
            .unwrap_or_else(|| {
                panic!(
                    "no exported Request completed record in {:?}",
                    records
                        .iter()
                        .filter_map(|r| r.record.body().cloned())
                        .collect::<Vec<_>>()
                )
            });
        let attribute = |key: &str| {
            done.record
                .attributes_iter()
                .find(|(name, _)| name.as_str() == key)
                .map(|(_, value)| value)
        };
        assert_eq!(attribute("method"), Some(&AnyValue::from("PUT".to_owned())));
        assert_eq!(
            attribute("uri"),
            Some(&AnyValue::from(
                "/api/v1/things/7?password=[REDACTED]".to_owned()
            ))
        );
        assert_eq!(attribute("status"), Some(&AnyValue::from("201".to_owned())));
        assert!(
            done.record.trace_context().is_some(),
            "the record still carries its trace context"
        );
    }

    /// A log record exported through the production subscriber carries the
    /// trace and span id of the span it was emitted under (the layer is not
    /// wrapped in an `Option`, see [`layer_or_identity`]).
    #[test]
    fn exported_log_records_carry_the_trace_context() {
        use opentelemetry::logs::LoggerProvider as _;
        use opentelemetry::trace::TraceContextExt as _;
        use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};

        let log_exporter = InMemoryLogExporter::default();
        let logger_provider = SdkLoggerProvider::builder()
            .with_simple_exporter(log_exporter.clone())
            .build();
        let exported = crate::testing::otel::ExportedSpans::default();
        let subscriber = otel_path_subscriber(
            subscriber_filters(
                || EnvFilter::new(DEFAULT_RUST_LOG),
                db_spans::DbQuerySpans::Log,
            ),
            build_fmt_layer_with_writer(LogFormat::Text, false, Capture::default()),
            Some(otel_logs::OtelLogLayer::new(logger_provider.logger("test"))),
            exported.tracer(),
            Some(exported.tracer()),
        );
        let mut ids = None;
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http_request");
            let _entered = span.enter();
            let cx = tracing_opentelemetry::OpenTelemetrySpanExt::context(&span);
            let sc = cx.span().span_context().clone();
            ids = Some((sc.trace_id(), sc.span_id()));
            tracing::info!("Request completed");
        });
        logger_provider.force_flush().expect("flush");
        let records = log_exporter.get_emitted_logs().expect("emitted logs");
        let (trace_id, span_id) = ids.expect("span ids");
        assert_eq!(records.len(), 1);
        let trace = records[0]
            .record
            .trace_context()
            .expect("the record carries the enclosing span's trace context");
        assert_eq!(trace.trace_id, trace_id);
        assert_eq!(trace.span_id, span_id);
    }

    #[test]
    fn db_query_spans_values_parse() {
        use db_spans::DbQuerySpans as M;
        assert_eq!(M::parse(None), Some(M::Log));
        assert_eq!(M::parse(Some("")), Some(M::Log));
        assert_eq!(M::parse(Some(" LOG ")), Some(M::Log));
        assert_eq!(M::parse(Some("all")), Some(M::All));
        assert_eq!(M::parse(Some("Off")), Some(M::Off));
        assert_eq!(M::parse(Some("debug")), None);
        for mode in [M::Log, M::All, M::Off] {
            assert_eq!(M::parse(Some(mode.name())), Some(mode));
        }
    }

    /// `DB_QUERY_SPANS` from the environment: a recognised value is used, and
    /// an unsupported one falls back to `log` and is handed back for the
    /// startup warning.
    #[test]
    fn db_query_spans_from_env_falls_back_to_log_on_an_unsupported_value() {
        use db_spans::DbQuerySpans as M;
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var(db_spans::DB_QUERY_SPANS_VAR).ok();

        std::env::remove_var(db_spans::DB_QUERY_SPANS_VAR);
        assert_eq!(M::from_env(), (M::Log, None));
        std::env::set_var(db_spans::DB_QUERY_SPANS_VAR, "ALL");
        assert_eq!(M::from_env(), (M::All, None));
        std::env::set_var(db_spans::DB_QUERY_SPANS_VAR, "verbose");
        assert_eq!(M::from_env(), (M::Log, Some("verbose".to_string())));

        match previous {
            Some(value) => std::env::set_var(db_spans::DB_QUERY_SPANS_VAR, value),
            None => std::env::remove_var(db_spans::DB_QUERY_SPANS_VAR),
        }
    }

    /// Emit, under `layer`, the events of one request the way production does:
    /// the `http_request` span from the real span builder, the correlation ID
    /// recorded onto it, an inner span carrying its own `uri`, and the
    /// per-request `Request completed` line.
    fn emit_request_lines(layer: Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>) {
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let request = axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v1/repositories/npm-local/artifacts/a.tgz?token=secret")
                .body(())
                .unwrap();
            let span = crate::api::middleware::tracing::make_http_request_span(&request, &[]);
            span.record("correlation_id", "corr-4674");
            let _request = span.enter();
            {
                let inner = tracing::info_span!("proxy_fetch", uri = "https://upstream.example/a");
                let _inner = inner.enter();
                tracing::info!("fetching upstream");
            }
            tracing::info!(
                correlation_id = "corr-4674",
                status = %201u16,
                user = "alice",
                ip = "203.0.113.7",
                latency_ms = 42u64,
                "Request completed"
            );
        });
    }

    fn json_lines(capture: &Capture) -> Vec<serde_json::Map<String, serde_json::Value>> {
        capture
            .text()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
            .collect()
    }

    #[test]
    fn test_json_request_line_has_siem_fields_top_level() {
        let capture = Capture::default();
        emit_request_lines(build_fmt_layer_with_writer(
            LogFormat::Json,
            true,
            capture.clone(),
        ));
        let lines = json_lines(&capture);
        assert_eq!(lines.len(), 2, "{lines:?}");
        let done = &lines[1];

        assert_eq!(done["fields"]["message"], "Request completed");
        assert_eq!(done["level"], "INFO");
        assert!(done["timestamp"].is_string());
        assert_eq!(done["method"], "PUT");
        // The redacted request URI from the span, never the inner span's URL.
        let uri = done["uri"].as_str().expect("uri is top-level");
        assert!(
            uri.starts_with("/api/v1/repositories/npm-local/artifacts/a.tgz"),
            "{uri}"
        );
        assert!(!uri.contains("secret"), "token must stay redacted: {uri}");
        assert_eq!(done["correlation_id"], "corr-4674");
        assert_eq!(done["status"], 201);
        assert_eq!(done["user"], "alice");
        assert_eq!(done["ip"], "203.0.113.7");
        assert_eq!(done["latency_ms"], 42);
        // The hoisted keys are copies: the nested originals keep their shape,
        // including `fields.status` as the string it has always been.
        assert_eq!(done["fields"]["status"], "201");
        assert_eq!(done["fields"]["user"], "alice");
        assert_eq!(done["span"]["name"], "http_request");
        assert_eq!(done["span"]["correlation_id"], "corr-4674");
        assert!(!done.contains_key("message"), "message stays nested");

        // The span stack survives under `spans`.
        let spans = done["spans"].as_array().expect("spans list");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "http_request");

        // A line inside an inner span: request fields still top-level and the
        // outer span wins the `uri` clash; the inner one stays under `spans`.
        let inner = &lines[0];
        assert_eq!(inner["fields"]["message"], "fetching upstream");
        assert_eq!(inner["span"]["name"], "proxy_fetch");
        assert_eq!(inner["uri"], uri);
        assert_eq!(inner["correlation_id"], "corr-4674");
        let inner_spans = inner["spans"].as_array().unwrap();
        assert_eq!(inner_spans[1]["name"], "proxy_fetch");
        assert_eq!(inner_spans[1]["uri"], "https://upstream.example/a");

        assert!(
            !capture.text().contains('\u{1b}'),
            "JSON never carries ANSI"
        );
    }

    /// Backward compatibility (#4674): `LOG_FORMAT=json` shipped in 1.10.0 with
    /// the stock `fmt::layer().json()` layout. Every key that layout emits must
    /// still be emitted with the same value, nesting and type; the only
    /// difference allowed is the extra top-level request keys.
    #[test]
    fn test_json_keeps_every_key_of_the_1_10_layout() {
        let ours = Capture::default();
        emit_request_lines(build_fmt_layer_with_writer(
            LogFormat::Json,
            false,
            ours.clone(),
        ));
        let stock = Capture::default();
        emit_request_lines(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(stock.clone())
                .boxed(),
        );
        let ours = json_lines(&ours);
        let stock = json_lines(&stock);
        assert_eq!(ours.len(), stock.len());
        for (new, old) in ours.iter().zip(&stock) {
            for (key, old_value) in old {
                if key == "timestamp" {
                    assert!(new[key].is_string(), "{new:?}");
                    continue;
                }
                assert_eq!(new.get(key), Some(old_value), "key {key} changed: {new:?}");
            }
            for key in new.keys().filter(|k| !old.contains_key(*k)) {
                assert!(
                    json_log::HOISTED.contains(&key.as_str()),
                    "unexpected new key {key}: {new:?}"
                );
            }
        }
        // The stock layout really is the nested one this test protects.
        assert!(stock[1].contains_key("fields") && stock[1].contains_key("span"));
        assert!(stock[1].contains_key("spans") && stock[1].contains_key("target"));
    }

    /// Strip the leading timestamp (the only part that differs run to run).
    fn without_timestamps(text: &str) -> String {
        regex::Regex::new(r"\d{4}-\d\d-\d\dT[0-9:.]+Z")
            .unwrap()
            .replace_all(text, "<ts>")
            .into_owned()
    }

    #[test]
    fn test_text_with_ansi_forced_on_is_byte_identical_to_the_stock_layer() {
        let ours = Capture::default();
        emit_request_lines(build_fmt_layer_with_writer(
            LogFormat::Text,
            true,
            ours.clone(),
        ));
        let stock = Capture::default();
        emit_request_lines(
            tracing_subscriber::fmt::layer()
                .with_ansi(true)
                .with_writer(stock.clone())
                .boxed(),
        );
        assert!(
            ours.text().contains('\u{1b}'),
            "ANSI forced on: {}",
            ours.text()
        );
        assert_eq!(
            without_timestamps(&ours.text()),
            without_timestamps(&stock.text())
        );
    }

    #[test]
    fn test_text_with_ansi_off_has_no_escapes_between_key_and_value() {
        let capture = Capture::default();
        emit_request_lines(build_fmt_layer_with_writer(
            LogFormat::Text,
            false,
            capture.clone(),
        ));
        let text = capture.text();
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(text.contains("correlation_id=\"corr-4674\""), "{text}");
        assert!(text.contains("status=201"), "{text}");
    }

    /// The real per-request line end to end: `TraceLayer` with the production
    /// span builder, the client-IP scope, `correlation_id_middleware`, and a
    /// handler that authenticates (records the user) the way the auth
    /// middleware does. Every SIEM field must come out top-level (#4674).
    #[tokio::test]
    async fn test_json_request_completed_line_from_the_real_middleware() {
        use axum::{body::Body, routing::put, Router};
        use tower::ServiceExt;

        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("info"))
            .with(build_fmt_layer_with_writer(
                LogFormat::Json,
                false,
                capture.clone(),
            ));
        let _guard = tracing::subscriber::set_default(subscriber);

        async fn authed() -> axum::http::StatusCode {
            crate::api::middleware::request_span::record_user("alice");
            axum::http::StatusCode::CREATED
        }
        let app = Router::new()
            .route("/api/v1/things/:id", put(authed))
            .layer(axum::middleware::from_fn(
                crate::api::middleware::tracing::correlation_id_middleware,
            ))
            .layer(
                tower_http::trace::TraceLayer::new_for_http().make_span_with(
                    |request: &axum::http::Request<Body>| {
                        crate::api::middleware::tracing::make_http_request_span(request, &[])
                    },
                ),
            );
        let request = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/things/7?password=hunter2")
            .header("x-correlation-id", "corr-e2e-4674")
            .body(Body::empty())
            .unwrap();
        let ip: std::net::IpAddr = "198.51.100.9".parse().unwrap();
        let response =
            crate::api::middleware::client_ip::with_client_ip_scope(Some(ip), app.oneshot(request))
                .await
                .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);

        let lines = json_lines(&capture);
        let done = lines
            .iter()
            .find(|l| l["fields"]["message"] == "Request completed")
            .unwrap_or_else(|| panic!("no Request completed line in {lines:?}"));
        assert_eq!(done["method"], "PUT");
        let uri = done["uri"].as_str().unwrap();
        assert!(uri.starts_with("/api/v1/things/7"), "{uri}");
        assert!(!uri.contains("hunter2"), "{uri}");
        // #4931 item 5: the completion event itself carries these, not only
        // the enclosing span, so the OTLP log exporter sends them.
        assert_eq!(done["fields"]["method"], "PUT");
        assert_eq!(done["fields"]["uri"], uri);
        assert_eq!(done["correlation_id"], "corr-e2e-4674");
        assert_eq!(done["http.route"], "/api/v1/things/:id");
        assert_eq!(done["status"], 201);
        assert_eq!(done["user"], "alice");
        assert_eq!(done["ip"], "198.51.100.9");
        assert!(done["latency_ms"].is_u64(), "{done:?}");
    }

    /// An anonymous request carries no `user` key at all, rather than a
    /// placeholder a SIEM rule could mistake for a principal.
    #[tokio::test]
    async fn test_json_request_completed_line_omits_user_when_anonymous() {
        use axum::{body::Body, routing::get, Router};
        use tower::ServiceExt;

        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("info"))
            .with(build_fmt_layer_with_writer(
                LogFormat::Json,
                false,
                capture.clone(),
            ));
        let _guard = tracing::subscriber::set_default(subscriber);

        let app =
            Router::new()
                .route("/anon", get(|| async { "ok" }))
                .layer(axum::middleware::from_fn(
                    crate::api::middleware::tracing::correlation_id_middleware,
                ));
        let request = axum::http::Request::builder()
            .uri("/anon")
            .body(Body::empty())
            .unwrap();
        app.oneshot(request).await.unwrap();

        let lines = json_lines(&capture);
        let done = lines
            .iter()
            .find(|l| l["fields"]["message"] == "Request completed")
            .unwrap_or_else(|| panic!("no Request completed line in {lines:?}"));
        assert!(!done.contains_key("user"), "{done:?}");
        assert!(!done.contains_key("ip"), "no client-IP scope: {done:?}");
        assert_eq!(done["status"], 200);
    }

    // ── build_otel_resource ─────────────────────────────────────────────

    #[test]
    fn test_build_otel_resource_contains_service_name() {
        let resource = build_otel_resource("test-service");
        let debug = format!("{:?}", resource);
        assert!(debug.contains("service.name"));
    }

    #[test]
    fn test_build_otel_resource_with_empty_service_name() {
        let resource = build_otel_resource("");
        let debug = format!("{:?}", resource);
        assert!(debug.contains("service.name"));
    }

    #[test]
    fn test_build_otel_resource_includes_version() {
        let resource = build_otel_resource("my-svc");
        let debug = format!("{:?}", resource);
        assert!(debug.contains("service.version"));
    }

    // ── build_span_exporter ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_build_span_exporter_grpc() {
        // Builds an exporter configured for gRPC. The exporter is created
        // successfully even without a running collector (connection is lazy).
        assert!(build_span_exporter(OtlpProtocol::Grpc, "http://localhost:4317").is_some());
    }

    #[tokio::test]
    async fn test_build_span_exporter_http_protobuf() {
        // Builds an exporter configured for HTTP/protobuf. As with gRPC the
        // exporter is created successfully without a running collector.
        //
        // This previously asserted the builder returned NoHttpClient, on the
        // premise that opentelemetry-otlp's reqwest-client and
        // reqwest-blocking-client cfg guards were mutually exclusive. They are
        // not: since 0.32 the builder selects between the enabled clients by a
        // documented priority order, so the build always succeeds and the old
        // assertion could never fail. What actually matters is which client is
        // selected, which the regression test below pins down.
        assert!(build_span_exporter(OtlpProtocol::HttpProtobuf, "http://localhost:4318").is_some());
    }

    #[test]
    fn test_http_protobuf_export_does_not_require_a_tokio_reactor() {
        // Regression test: the HTTP/protobuf exporter must be backed by the
        // BLOCKING reqwest client.
        //
        // `BatchSpanProcessor` drives `SpanExporter::export` on a dedicated OS
        // thread with no Tokio runtime. Backed by the async reqwest client the
        // first flush panics there with "there is no reactor running, must be
        // called from the context of a Tokio 1.x runtime". The panic kills the
        // processor thread rather than the process, so the service keeps
        // serving while every subsequent span is silently dropped with a
        // `BatchSpanProcessor.OnEnd.AfterShutdown` warning -- tracing looks
        // enabled and exports nothing.
        //
        // Reproduce that thread shape directly: drive one export to completion
        // on a plain `std::thread` (no reactor in scope) using a non-Tokio
        // executor. Deliberately NOT a `#[tokio::test]` -- a reactor in scope
        // is exactly what this must not depend on.
        //
        // Port 1 is used so the request fails fast without reaching a real
        // collector. The export result is ignored; only the absence of a panic
        // is asserted, which is what distinguishes the two clients. An empty
        // batch is enough: the exporter has no empty-batch short circuit, so
        // the HTTP send is still attempted. Call the exporter directly --
        // `BatchSpanProcessor` short-circuits an empty batch and would never
        // reach export, so routing through the processor would pass even with
        // the async client.
        use opentelemetry_sdk::trace::SpanExporter as _;

        let outcome = std::thread::spawn(|| {
            let exporter =
                build_span_exporter(OtlpProtocol::HttpProtobuf, "http://127.0.0.1:1/v1/traces")
                    .expect("a valid endpoint builds");
            let _ = futures::executor::block_on(exporter.export(Vec::new()));
        })
        .join();

        assert!(
            outcome.is_ok(),
            "HTTP/protobuf export panicked on a thread with no Tokio reactor; \
             the exporter must use the blocking reqwest client because \
             BatchSpanProcessor exports from a dedicated thread"
        );
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod otlp_signal_tests {
    use super::*;
    use std::time::{Duration, Instant};

    // ── OTEL_<SIGNAL>_EXPORTER ──────────────────────────────────────────

    #[test]
    fn only_traces_are_exported_by_default() {
        let signals = SignalExporter::from_values(None, None, None);
        assert_eq!(
            signals,
            SignalExporter {
                traces: true,
                metrics: false,
                logs: false
            }
        );
        assert_eq!(signals.names(), "traces");
    }

    #[test]
    fn otlp_opts_logs_and_metrics_in() {
        let signals = SignalExporter::from_values(None, Some("otlp"), Some(" OTLP "));
        assert!(signals.traces && signals.metrics && signals.logs);
        assert_eq!(signals.names(), "traces,metrics,logs");
    }

    #[test]
    fn none_turns_a_signal_off() {
        let signals = SignalExporter::from_values(Some("None"), Some("none"), Some("otlp"));
        assert!(!signals.traces && !signals.metrics && signals.logs);
        let off = SignalExporter::from_values(Some("none"), None, None);
        assert_eq!(off.names(), "none");
    }

    #[test]
    fn unsupported_and_empty_values_keep_the_default() {
        for value in ["", "  ", "console", "prometheus", "otlpp"] {
            let signals = SignalExporter::from_values(Some(value), Some(value), Some(value));
            assert!(signals.traces, "{value:?} must leave traces on");
            assert!(!signals.metrics, "{value:?} must not turn metrics on");
            assert!(!signals.logs, "{value:?} must not turn logs on");
        }
        assert_eq!(
            SignalSetting::parse(Some("console")),
            SignalSetting::Unsupported
        );
        assert_eq!(SignalSetting::parse(Some("")), SignalSetting::Unset);
    }

    // ── per-signal endpoints ────────────────────────────────────────────

    #[test]
    fn http_endpoints_swap_the_traces_path_for_the_signal_path() {
        let traces = "http://collector:4318/v1/traces";
        assert_eq!(
            signal_endpoint(OtlpProtocol::HttpProtobuf, traces, OtlpSignal::Logs, None),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            signal_endpoint(
                OtlpProtocol::HttpProtobuf,
                "http://gw/otlp/v1/traces/",
                OtlpSignal::Metrics,
                None
            ),
            "http://gw/otlp/v1/metrics"
        );
        assert_eq!(
            signal_endpoint(
                OtlpProtocol::HttpProtobuf,
                "http://collector:4318/",
                OtlpSignal::Metrics,
                None
            ),
            "http://collector:4318/v1/metrics"
        );
    }

    #[test]
    fn grpc_endpoints_are_shared() {
        assert_eq!(
            signal_endpoint(
                OtlpProtocol::Grpc,
                "http://collector:4317",
                OtlpSignal::Logs,
                None
            ),
            "http://collector:4317"
        );
    }

    #[test]
    fn a_per_signal_endpoint_wins_verbatim() {
        for protocol in [OtlpProtocol::Grpc, OtlpProtocol::HttpProtobuf] {
            assert_eq!(
                signal_endpoint(
                    protocol,
                    "http://collector:4318/v1/traces",
                    OtlpSignal::Logs,
                    Some("http://loki:3100/otlp/v1/logs"),
                ),
                "http://loki:3100/otlp/v1/logs"
            );
        }
        // An empty override is ignored.
        assert_eq!(
            signal_endpoint(
                OtlpProtocol::Grpc,
                "http://c:4317",
                OtlpSignal::Metrics,
                Some(" ")
            ),
            "http://c:4317"
        );
    }

    // ── resource ────────────────────────────────────────────────────────

    #[test]
    fn instance_id_comes_from_hostname_unless_the_operator_set_one() {
        assert_eq!(
            service_instance_id(None, Some("ak-backend-7f9c")).as_deref(),
            Some("ak-backend-7f9c")
        );
        assert_eq!(
            service_instance_id(
                Some("deployment.environment=prod, service.instance.id=replica-2"),
                Some("ak-backend-7f9c")
            ),
            None
        );
        let generated = service_instance_id(Some("deployment.environment=prod"), Some(" "))
            .expect("generated id");
        assert!(uuid::Uuid::parse_str(&generated).is_ok(), "{generated}");
    }

    #[test]
    fn every_signal_shares_service_name_version_and_instance() {
        let resource = build_otel_resource("artifact-keeper-test");
        let get = |key: &'static str| resource.get(&opentelemetry::Key::from_static_str(key));
        assert_eq!(
            get("service.name"),
            Some(opentelemetry::Value::from("artifact-keeper-test"))
        );
        assert_eq!(
            get("service.version"),
            Some(opentelemetry::Value::from(env!("CARGO_PKG_VERSION")))
        );
        assert!(get("service.instance.id").is_some());
    }

    // ── no collector ────────────────────────────────────────────────────

    /// With nothing listening, logging never blocks the caller (the batch
    /// queue is bounded and drops), and shutdown returns within the SDK's
    /// bounded timeouts instead of hanging the process on exit.
    #[test]
    fn an_unreachable_collector_blocks_neither_logging_nor_shutdown() {
        use opentelemetry::logs::{LogRecord as _, Logger as _, LoggerProvider as _};

        for (protocol, endpoint) in [
            (OtlpProtocol::HttpProtobuf, "http://127.0.0.1:1/v1/traces"),
            (OtlpProtocol::Grpc, "http://127.0.0.1:1"),
        ] {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _rt = runtime.enter();
            let exporter = build_log_exporter(
                protocol,
                &signal_endpoint(protocol, endpoint, OtlpSignal::Logs, None),
            )
            .expect("an unreachable endpoint still builds");
            let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
                .with_batch_exporter(exporter)
                .build();
            let logger = provider.logger("test");

            let started = Instant::now();
            for i in 0..10_000 {
                let mut record = logger.create_log_record();
                record.set_body(format!("record {i}").into());
                logger.emit(record);
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{protocol:?}: emitting with no collector took {:?}",
                started.elapsed()
            );

            let started = Instant::now();
            let _ = provider.shutdown();
            assert!(
                started.elapsed() < Duration::from_secs(40),
                "{protocol:?}: log shutdown took {:?}",
                started.elapsed()
            );

            let metric_exporter = build_metric_exporter(
                protocol,
                &signal_endpoint(protocol, endpoint, OtlpSignal::Metrics, None),
            )
            .expect("an unreachable endpoint still builds");
            let (recorder, meter_provider) = otel_metrics::build_otel_metrics_recorder(
                metric_exporter,
                build_otel_resource("test"),
            );
            metrics::with_local_recorder(&recorder, || {
                metrics::counter!("ak_uploads_total").increment(1);
            });
            let started = Instant::now();
            drop(otel_metrics::MetricsGuard::new(meter_provider));
            assert!(
                started.elapsed() < Duration::from_secs(40),
                "{protocol:?}: meter shutdown took {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn an_unparseable_endpoint_turns_the_signal_off_instead_of_panicking() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _rt = runtime.enter();
        assert!(build_log_exporter(OtlpProtocol::HttpProtobuf, "not a url").is_none());
        assert!(build_metric_exporter(OtlpProtocol::HttpProtobuf, "not a url").is_none());
        // #4931: the span exporter panicked here before 1.12.0.
        assert!(build_span_exporter(OtlpProtocol::HttpProtobuf, "not a url").is_none());
    }

    /// #4931: an empty or blank endpoint is the same as no endpoint, so the
    /// OTel path is not entered with nothing to export to.
    #[test]
    fn an_empty_endpoint_counts_as_unset() {
        assert_eq!(otel_endpoint_if_set(None), None);
        assert_eq!(otel_endpoint_if_set(Some("")), None);
        assert_eq!(otel_endpoint_if_set(Some("  ")), None);
        assert_eq!(
            otel_endpoint_if_set(Some(" http://collector:4317 ")),
            Some("http://collector:4317")
        );
    }

    /// A collector that accepts connections and never answers: every export
    /// and every shutdown flush waits for its full timeout.
    fn hanging_collector() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, format!("http://{addr}/v1/traces"))
    }

    /// #4931: the guard flushes the three signals at the same time, so a
    /// collector that never answers delays exit by the slowest flush, not by
    /// the sum of three. Sequentially this took three flush timeouts (about
    /// 15 s), past a container runtime's 10 s stop grace.
    #[test]
    fn shutdown_flushes_the_signals_concurrently() {
        use opentelemetry::logs::{LogRecord as _, Logger as _, LoggerProvider as _};
        use opentelemetry::trace::{Tracer as _, TracerProvider as _};

        let (_listener, endpoint) = hanging_collector();
        let protocol = OtlpProtocol::HttpProtobuf;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _rt = runtime.enter();

        let span_exporter = build_span_exporter(protocol, &endpoint).unwrap();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .build();
        provider.tracer("test").in_span("pending", |_| {});

        let log_exporter = build_log_exporter(
            protocol,
            &signal_endpoint(protocol, &endpoint, OtlpSignal::Logs, None),
        )
        .unwrap();
        let logger_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .build();
        let logger = logger_provider.logger("test");
        let mut record = logger.create_log_record();
        record.set_body("pending".into());
        logger.emit(record);

        let metric_exporter = build_metric_exporter(
            protocol,
            &signal_endpoint(protocol, &endpoint, OtlpSignal::Metrics, None),
        )
        .unwrap();
        let (recorder, meter_provider) =
            otel_metrics::build_otel_metrics_recorder(metric_exporter, build_otel_resource("test"));
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("ak_uploads_total").increment(1);
        });

        // One signal alone, for the bound below.
        let (_single_listener, single_endpoint) = hanging_collector();
        let single = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(build_span_exporter(protocol, &single_endpoint).unwrap())
            .build();
        single.tracer("test").in_span("pending", |_| {});
        let started = Instant::now();
        let _ = single.shutdown();
        let one_flush = started.elapsed();

        let guard = OtelGuard {
            provider,
            logger_provider: Some(logger_provider),
            _meter_provider: Some(otel_metrics::MetricsGuard::new(meter_provider)),
        };
        let started = Instant::now();
        drop(guard);
        let all_three = started.elapsed();
        assert!(
            all_three < one_flush * 2,
            "three flushes took {all_three:?}, one alone {one_flush:?}: they ran one after another"
        );
        assert!(
            all_three < OTEL_SHUTDOWN_TIMEOUT + Duration::from_secs(2),
            "three flushes took {all_three:?}, past the shared {OTEL_SHUTDOWN_TIMEOUT:?} deadline"
        );
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod sampler_tests {
    use super::*;

    /// Env vars are process-wide; `cargo nextest` runs one process per test, so
    /// these do not interfere with each other.
    fn clear() {
        std::env::remove_var("OTEL_TRACES_SAMPLER");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    /// The whole point of the default: a deployment that sets nothing samples
    /// exactly as it did before the sampler became configurable.
    #[test]
    fn defaults_to_parentbased_always_on() {
        clear();
        assert_eq!(
            SamplerChoice::from_env(),
            SamplerChoice::ParentBasedAlwaysOn
        );
    }

    #[test]
    fn parses_every_spec_value() {
        for (raw, expected) in [
            ("always_on", SamplerChoice::AlwaysOn),
            ("always_off", SamplerChoice::AlwaysOff),
            ("traceidratio", SamplerChoice::TraceIdRatio),
            ("parentbased_always_on", SamplerChoice::ParentBasedAlwaysOn),
            (
                "parentbased_always_off",
                SamplerChoice::ParentBasedAlwaysOff,
            ),
            (
                "parentbased_traceidratio",
                SamplerChoice::ParentBasedTraceIdRatio,
            ),
        ] {
            assert_eq!(SamplerChoice::from_str_value(raw), Some(expected), "{raw}");
        }
    }

    #[test]
    fn parsing_is_case_and_whitespace_insensitive() {
        assert_eq!(
            SamplerChoice::from_str_value("  ALWAYS_OFF  "),
            Some(SamplerChoice::AlwaysOff)
        );
    }

    /// An unrecognised or empty value must not fail startup — it falls back to
    /// the default, which is why the resolved sampler is logged at boot.
    #[test]
    fn unrecognised_values_fall_back_to_the_default() {
        for raw in ["", "   ", "nonsense", "parentbased", "ratio"] {
            assert_eq!(SamplerChoice::from_str_value(raw), None, "{raw:?}");
        }
        clear();
        std::env::set_var("OTEL_TRACES_SAMPLER", "nonsense");
        assert_eq!(
            SamplerChoice::from_env(),
            SamplerChoice::ParentBasedAlwaysOn
        );
        clear();
    }

    #[test]
    fn ratio_defaults_to_one_when_absent() {
        clear();
        assert_eq!(sampler_ratio_from_env(), DEFAULT_SAMPLER_RATIO);
    }

    #[test]
    fn ratio_is_read_when_valid() {
        clear();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.25");
        assert_eq!(sampler_ratio_from_env(), 0.25);
        clear();
    }

    /// Out-of-range, unparseable and NaN all fall back to 1.0 rather than to
    /// 0.0: a misconfigured ratio should behave like `always_on`, because
    /// silently dropping all telemetry is the worse failure.
    #[test]
    fn unusable_ratios_fall_back_to_one_not_zero() {
        for raw in ["-0.5", "1.5", "abc", "", "NaN", "inf"] {
            clear();
            std::env::set_var("OTEL_TRACES_SAMPLER_ARG", raw);
            assert_eq!(
                sampler_ratio_from_env(),
                DEFAULT_SAMPLER_RATIO,
                "ratio {raw:?} must fall back to 1.0"
            );
        }
        clear();
    }

    #[test]
    fn only_the_ratio_forms_consult_the_arg() {
        for choice in [
            SamplerChoice::TraceIdRatio,
            SamplerChoice::ParentBasedTraceIdRatio,
        ] {
            assert!(choice.uses_ratio(), "{}", choice.name());
        }
        for choice in [
            SamplerChoice::AlwaysOn,
            SamplerChoice::AlwaysOff,
            SamplerChoice::ParentBasedAlwaysOn,
            SamplerChoice::ParentBasedAlwaysOff,
        ] {
            assert!(!choice.uses_ratio(), "{}", choice.name());
        }
    }

    /// #4195: only the two samplers for which a remote `sampled=01` overrides
    /// a root decision of "drop" trigger the accept-all startup warning.
    #[test]
    fn only_drop_capable_parentbased_samplers_obey_a_remote_upgrade() {
        for choice in [
            SamplerChoice::ParentBasedAlwaysOff,
            SamplerChoice::ParentBasedTraceIdRatio,
        ] {
            assert!(choice.obeys_remote_sampled_upgrade(), "{}", choice.name());
        }
        for choice in [
            SamplerChoice::AlwaysOn,
            SamplerChoice::AlwaysOff,
            SamplerChoice::TraceIdRatio,
            SamplerChoice::ParentBasedAlwaysOn,
        ] {
            assert!(!choice.obeys_remote_sampled_upgrade(), "{}", choice.name());
        }
        clear();
        assert!(
            !sampler_obeys_remote_sampled_upgrade(),
            "the default sampler must not trigger the warning"
        );
        std::env::set_var("OTEL_TRACES_SAMPLER", "parentbased_always_off");
        assert!(sampler_obeys_remote_sampled_upgrade());
        clear();
    }

    /// Every choice builds, and the names round-trip — a name that does not
    /// parse back would make the boot log unusable for diagnosing a typo.
    #[test]
    fn every_choice_builds_and_its_name_round_trips() {
        for choice in [
            SamplerChoice::AlwaysOn,
            SamplerChoice::AlwaysOff,
            SamplerChoice::TraceIdRatio,
            SamplerChoice::ParentBasedAlwaysOn,
            SamplerChoice::ParentBasedAlwaysOff,
            SamplerChoice::ParentBasedTraceIdRatio,
        ] {
            let _ = build_sampler(choice, 0.5);
            assert_eq!(
                SamplerChoice::from_str_value(choice.name()),
                Some(choice),
                "{} must parse back from its own name",
                choice.name()
            );
        }
    }
}
