//! Telemetry initialization: tracing subscriber with optional OpenTelemetry export.
//!
//! When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, an OTLP span exporter is added
//! alongside the existing stdout fmt layer. When unset, behavior is identical
//! to the previous stdout-only setup.
//!
//! The transport protocol is selected via the standard `OTEL_EXPORTER_OTLP_PROTOCOL`
//! environment variable:
//!   - `grpc` (default) -- gRPC over HTTP/2 using tonic
//!   - `http/protobuf`  -- HTTP/1.1 with binary protobuf bodies using the
//!     blocking reqwest client (see the `opentelemetry-otlp` feature note in
//!     the workspace `Cargo.toml`). Two sites must not see an async client:
//!     `BatchSpanProcessor` exports from a dedicated thread with no Tokio
//!     runtime, and exporter construction runs inside `#[tokio::main]` --
//!     otlp builds the blocking client via `std::thread::spawn(…).join()`,
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

use opentelemetry::KeyValue;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
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
    Resource::builder()
        .with_attributes([
            KeyValue::new("service.name", service_name.to_owned()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_owned()),
        ])
        .build()
}

/// Build an OTLP span exporter for the given protocol and endpoint.
fn build_span_exporter(protocol: OtlpProtocol, endpoint: &str) -> SpanExporter {
    match protocol {
        OtlpProtocol::Grpc => SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .expect("Failed to create OTLP gRPC span exporter"),
        OtlpProtocol::HttpProtobuf => SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build()
            .expect("Failed to create OTLP HTTP/protobuf span exporter"),
    }
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
/// application to ensure spans are flushed on shutdown.
pub fn init_tracing(otel_endpoint: Option<&str>, service_name: &str) -> Option<OtelGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        "artifact_keeper_backend=debug,tower_http=debug,sqlx::query=info".into()
    });
    let log_format = LogFormat::from_env();
    let log_ansi = LogAnsi::from_env().resolve_from_env();

    match otel_endpoint {
        Some(endpoint) => {
            let protocol = OtlpProtocol::from_env();
            let guard = init_with_otel(
                endpoint,
                service_name,
                env_filter,
                protocol,
                log_format,
                log_ansi,
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
                log_format = log_format.name(),
                log_ansi,
                sampler = sampler_choice.name(),
                sampler_ratio = sampler_choice
                    .uses_ratio()
                    .then(sampler_ratio_from_env)
                    .map(tracing::field::display),
                "OpenTelemetry tracing enabled"
            );
            Some(guard)
        }
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(build_fmt_layer(log_format, log_ansi))
                .init();
            None
        }
    }
}

/// Guard that shuts down the OTel tracer provider on drop,
/// flushing any pending spans.
pub struct OtelGuard {
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            eprintln!("Failed to shutdown OTel tracer provider: {e:?}");
        }
    }
}

fn init_with_otel(
    endpoint: &str,
    service_name: &str,
    env_filter: EnvFilter,
    protocol: OtlpProtocol,
    log_format: LogFormat,
    log_ansi: bool,
) -> OtelGuard {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};

    let exporter = build_span_exporter(protocol, endpoint);
    let resource = build_otel_resource(service_name);

    let sampler_choice = SamplerChoice::from_env();
    let sampler_ratio = sampler_ratio_from_env();

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(build_sampler(sampler_choice, sampler_ratio))
        .with_span_processor(BatchSpanProcessor::builder(exporter).build())
        .build();

    let tracer = provider.tracer("artifact-keeper");
    // sqlx's per-statement events carry SQL text and stay out of the OTel
    // export; stdout and the DB span layer below still see them (#4455).
    let otel_layer = db_spans::otel_export_layer(tracer);
    // Per-query DB `CLIENT` spans from sqlx's `sqlx::query` events (#4455).
    // It sees what the filter above lets through: slow statements by default,
    // every statement with `sqlx::query=debug`.
    let db_span_layer = db_spans::DbQuerySpanLayer::new(provider.tracer("artifact-keeper"));

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

    tracing_subscriber::registry()
        .with(env_filter)
        .with(build_fmt_layer(log_format, log_ansi))
        .with(otel_layer)
        .with(db_span_layer)
        .init();

    OtelGuard { provider }
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
        assert_eq!(done["correlation_id"], "corr-e2e-4674");
        assert_eq!(done["http.route"], "/api/v1/things/:id");
        assert_eq!(done["status"], 201);
        assert_eq!(done["user"], "alice");
        assert_eq!(done["ip"], "198.51.100.9");
        assert!(done["latency_ms"].is_u64(), "{done:?}");
        // A request that completed is not also reported as cancelled (#5220).
        assert!(
            !lines
                .iter()
                .any(|l| l["fields"]["message"] == "Request cancelled"),
            "{lines:?}"
        );
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

    /// A request whose future is dropped before the handler returns (the
    /// client disconnected, or a timeout layer gave up) logs `Request
    /// cancelled` with the fields of `Request completed` minus the status,
    /// instead of leaving no line at all (#5220).
    #[tokio::test]
    async fn test_json_request_cancelled_line_when_the_future_is_dropped() {
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

        let app = Router::new()
            .route(
                "/slow/:id",
                get(|| async {
                    crate::api::middleware::request_span::record_user("bob");
                    std::future::pending::<()>().await
                }),
            )
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
            .uri("/slow/1?token=secret")
            .header("x-correlation-id", "corr-5220")
            .body(Body::empty())
            .unwrap();
        let ip: std::net::IpAddr = "198.51.100.20".parse().unwrap();
        let in_flight =
            crate::api::middleware::client_ip::with_client_ip_scope(Some(ip), app.oneshot(request));
        let outcome = tokio::time::timeout(std::time::Duration::from_millis(100), in_flight).await;
        assert!(outcome.is_err(), "the handler never answers");

        let lines = json_lines(&capture);
        assert!(
            !lines
                .iter()
                .any(|l| l["fields"]["message"] == "Request completed"),
            "{lines:?}"
        );
        let cancelled = lines
            .iter()
            .find(|l| l["fields"]["message"] == "Request cancelled")
            .unwrap_or_else(|| panic!("no Request cancelled line in {lines:?}"));
        assert_eq!(cancelled["level"], "WARN");
        assert_eq!(cancelled["fields"]["method"], "GET");
        let uri = cancelled["fields"]["uri"].as_str().unwrap();
        assert!(uri.starts_with("/slow/1"), "{uri}");
        assert!(!uri.contains("secret"), "{uri}");
        assert_eq!(cancelled["correlation_id"], "corr-5220");
        assert_eq!(cancelled["http.route"], "/slow/:id");
        assert_eq!(cancelled["user"], "bob");
        assert_eq!(cancelled["ip"], "198.51.100.20");
        // The middleware's clock starts a little after the caller's timeout
        // does, and `latency_ms` truncates, so allow for that slack.
        assert!(
            cancelled["latency_ms"].as_u64().unwrap() >= 50,
            "{cancelled:?}"
        );
        assert!(!cancelled.contains_key("status"), "{cancelled:?}");
    }

    /// A panic that unwinds through the middleware drops the same guard, but
    /// the client did not cancel anything: it is logged as `Request panicked`
    /// at ERROR, not as `Request cancelled`.
    #[tokio::test]
    async fn test_json_request_panicked_line_when_the_handler_panics() {
        use axum::{body::Body, routing::get, Router};
        use futures::FutureExt;
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

        let app = Router::new()
            .route(
                "/boom",
                get(|| async {
                    if std::hint::black_box(true) {
                        panic!("handler bug");
                    }
                    "unreachable"
                }),
            )
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
            .uri("/boom")
            .header("x-correlation-id", "corr-5220-panic")
            .body(Body::empty())
            .unwrap();
        let outcome = std::panic::AssertUnwindSafe(app.oneshot(request))
            .catch_unwind()
            .await;
        assert!(outcome.is_err(), "the handler panics");

        let lines = json_lines(&capture);
        assert!(
            !lines
                .iter()
                .any(|l| l["fields"]["message"] == "Request cancelled"),
            "{lines:?}"
        );
        let panicked = lines
            .iter()
            .find(|l| l["fields"]["message"] == "Request panicked")
            .unwrap_or_else(|| panic!("no Request panicked line in {lines:?}"));
        assert_eq!(panicked["level"], "ERROR");
        assert_eq!(panicked["correlation_id"], "corr-5220-panic");
        assert_eq!(panicked["fields"]["method"], "GET");
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
        let _exporter = build_span_exporter(OtlpProtocol::Grpc, "http://localhost:4317");
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
        let _exporter = build_span_exporter(OtlpProtocol::HttpProtobuf, "http://localhost:4318");
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
                build_span_exporter(OtlpProtocol::HttpProtobuf, "http://127.0.0.1:1/v1/traces");
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
