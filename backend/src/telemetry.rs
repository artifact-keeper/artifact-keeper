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
//!   - `pretty` (default) -- the human-readable multi-line `fmt` output
//!   - `json` -- one JSON object per line, for structured stdout collection by a SIEM / log shipper (#2413 item 1)

use opentelemetry::KeyValue;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Diagnostics stdout log format, selected via `LOG_FORMAT` (#2413 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    /// Human-readable multi-line `fmt` output (default, unchanged behavior).
    Pretty,
    /// One JSON object per line for structured stdout collection.
    Json,
}

impl LogFormat {
    /// Parse a `LOG_FORMAT` value. Defaults to `pretty` for empty or
    /// unrecognised values so an operator typo never silently drops
    /// diagnostics to an unexpected shape.
    fn from_value(val: &str) -> Self {
        match val.trim().to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Pretty,
        }
    }

    /// Read from `LOG_FORMAT`. Defaults to `pretty` when unset or unrecognised.
    fn from_env() -> Self {
        Self::from_value(&std::env::var("LOG_FORMAT").unwrap_or_default())
    }

    /// Canonical name, for the startup log line.
    fn name(self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }
}

/// Build the diagnostics `fmt` layer in the configured format.
///
/// Boxed so both arms have the same type regardless of the concrete
/// per-format layer. The workspace `tracing-subscriber` dependency already
/// carries the `json` feature, so the JSON arm adds no new dependency.
fn build_fmt_layer<S>(format: LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    match format {
        LogFormat::Pretty => tracing_subscriber::fmt::layer().boxed(),
        LogFormat::Json => tracing_subscriber::fmt::layer().json().boxed(),
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
/// dropped. An operator choosing those values on a publicly reachable
/// deployment should gate trace-context extraction on their trusted-proxy
/// range; that gate does not exist yet and is the obvious follow-up.
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

    /// Whether this choice consults `OTEL_TRACES_SAMPLER_ARG`.
    fn uses_ratio(self) -> bool {
        matches!(self, Self::TraceIdRatio | Self::ParentBasedTraceIdRatio)
    }
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

    match otel_endpoint {
        Some(endpoint) => {
            let protocol = OtlpProtocol::from_env();
            let guard = init_with_otel(endpoint, service_name, env_filter, protocol, log_format);
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
                .with(build_fmt_layer(log_format))
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
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

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
        .with(build_fmt_layer(log_format))
        .with(otel_layer)
        .init();

    OtelGuard { provider }
}

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

    // ── LogFormat (#2413 item 1) ────────────────────────────────────────

    #[test]
    fn test_log_format_defaults_to_pretty_for_empty_string() {
        assert_eq!(LogFormat::from_value(""), LogFormat::Pretty);
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
    fn test_log_format_pretty_explicit() {
        assert_eq!(LogFormat::from_value("pretty"), LogFormat::Pretty);
        assert_eq!(LogFormat::from_value("PRETTY"), LogFormat::Pretty);
    }

    #[test]
    fn test_log_format_unrecognised_falls_back_to_pretty() {
        assert_eq!(LogFormat::from_value("logfmt"), LogFormat::Pretty);
        assert_eq!(LogFormat::from_value("bogus"), LogFormat::Pretty);
    }

    #[test]
    fn test_log_format_from_env_defaults_to_pretty_when_unset() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("LOG_FORMAT");
        assert_eq!(LogFormat::from_env(), LogFormat::Pretty);
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
        assert_eq!(LogFormat::Pretty.name(), "pretty");
        assert_eq!(LogFormat::Json.name(), "json");
    }

    #[test]
    fn test_build_fmt_layer_builds_both_formats() {
        // Both arms must type-check to the same boxed layer and construct
        // without panicking against the registry subscriber type.
        let _pretty = build_fmt_layer::<tracing_subscriber::Registry>(LogFormat::Pretty);
        let _json = build_fmt_layer::<tracing_subscriber::Registry>(LogFormat::Json);
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
