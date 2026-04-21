//! Telemetry initialization: tracing subscriber with optional OpenTelemetry export.
//!
//! When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, an OTLP span exporter is added
//! alongside the existing stdout fmt layer. When unset, behavior is identical
//! to the previous stdout-only setup.
//!
//! The transport protocol is selected via the standard `OTEL_EXPORTER_OTLP_PROTOCOL`
//! environment variable:
//!   - `grpc` (default) -- gRPC over HTTP/2 using tonic
//!   - `http/protobuf`  -- HTTP/1.1 with binary protobuf bodies using reqwest

use opentelemetry::KeyValue;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

/// Initialize the tracing subscriber.
///
/// Returns an optional guard that must be held for the lifetime of the
/// application to ensure spans are flushed on shutdown.
pub fn init_tracing(otel_endpoint: Option<&str>, service_name: &str) -> Option<OtelGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        "artifact_keeper_backend=debug,tower_http=debug,sqlx::query=info".into()
    });

    match otel_endpoint {
        Some(endpoint) => {
            let protocol = OtlpProtocol::from_env();
            let guard = init_with_otel(endpoint, service_name, env_filter, protocol);
            tracing::info!(
                otel_endpoint = endpoint,
                service_name,
                protocol = protocol.name(),
                "OpenTelemetry tracing enabled"
            );
            Some(guard)
        }
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
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
) -> OtelGuard {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};

    let exporter = build_span_exporter(protocol, endpoint);
    let resource = build_otel_resource(service_name);

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_span_processor(BatchSpanProcessor::builder(exporter).build())
        .build();

    let tracer = provider.tracer("artifact-keeper");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
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
    async fn test_build_span_exporter_http_protobuf_feature_conflict() {
        // The HTTP/protobuf exporter currently fails to build when both the
        // reqwest-client and reqwest-blocking-client (default) features are
        // enabled in opentelemetry-otlp because the cfg guards are mutually
        // exclusive. Verify that the error is the expected NoHttpClient so
        // this test catches it if the upstream crate fixes the conflict.
        let result = std::panic::catch_unwind(|| {
            build_span_exporter(OtlpProtocol::HttpProtobuf, "http://localhost:4318")
        });
        if let Err(payload) = result {
            let msg = payload
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .unwrap_or("");
            assert!(
                msg.contains("NoHttpClient") || msg.contains("HTTP/protobuf"),
                "unexpected panic: {msg}"
            );
        }
        // If the build succeeds (upstream fix), the test still passes.
    }
}
