//! Shared OpenTelemetry test helpers (#4455).
//!
//! Tests that assert what a span EXPORTS (kind, parent, status, attributes) or
//! that a request carries `traceparent` run under [`otel_subscriber`]: a real
//! `tracing-opentelemetry` layer whose spans land in [`ExportedSpans`] once
//! they end. [`SpanFields`] captures the raw `tracing` fields of one span name
//! for tests that only need those.

use std::sync::{Arc, Mutex};

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanProcessor};
use tracing_subscriber::layer::SubscriberExt;

/// Install the W3C `traceparent` propagator, as `telemetry::init_with_otel`
/// does on the OTLP path. Process-global; nextest runs each test in its own
/// process.
pub(crate) fn install_w3c_propagator() {
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
}

/// OTel spans as the SDK hands them to an exporter.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExportedSpans(Arc<Mutex<Vec<SpanData>>>);

impl SpanProcessor for ExportedSpans {
    fn on_start(&self, _: &mut opentelemetry_sdk::trace::Span, _: &opentelemetry::Context) {}
    fn on_end(&self, span: SpanData) {
        self.0.lock().unwrap().push(span);
    }
    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        Ok(())
    }
    fn shutdown_with_timeout(
        &self,
        _: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        Ok(())
    }
}

impl ExportedSpans {
    /// Every exported span named `name`, in end order.
    pub(crate) fn named(&self, name: &str) -> Vec<SpanData> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.name == name)
            .cloned()
            .collect()
    }

    /// The single exported span named `name`; panics unless exactly one.
    pub(crate) fn one(&self, name: &str) -> SpanData {
        let spans = self.named(name);
        assert_eq!(spans.len(), 1, "exactly one `{name}` span expected");
        spans.into_iter().next().unwrap()
    }

    /// A tracer whose finished spans land here.
    pub(crate) fn tracer(&self) -> opentelemetry_sdk::trace::SdkTracer {
        SdkTracerProvider::builder()
            .with_span_processor(self.clone())
            .build()
            .tracer("test")
    }
}

/// The exported value of attribute `key` on `span`.
pub(crate) fn attr(span: &SpanData, key: &str) -> Option<opentelemetry::Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.clone())
}

/// A registry with a real `tracing-opentelemetry` layer exporting to
/// `exported`.
pub(crate) fn otel_subscriber(
    exported: &ExportedSpans,
) -> impl tracing::Subscriber + Send + Sync + for<'a> tracing_subscriber::registry::LookupSpan<'a> {
    tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(exported.tracer()))
}

/// Install the W3C propagator and a default OTel subscriber for the rest of
/// the current thread's scope, so an upstream send injects `traceparent`.
/// Hold the guard for as long as the sends run.
pub(crate) fn trace_upstream_sends() -> tracing::subscriber::DefaultGuard {
    install_w3c_propagator();
    tracing::subscriber::set_default(otel_subscriber(&ExportedSpans::default()))
}

/// `(field, value)` pairs recorded on spans named `span_name`, both at
/// creation and through later `Span::record` calls.
#[derive(Clone)]
pub(crate) struct SpanFields {
    span_name: &'static str,
    values: Arc<Mutex<Vec<(String, String)>>>,
}

impl SpanFields {
    pub(crate) fn new(span_name: &'static str) -> Self {
        Self {
            span_name,
            values: Arc::default(),
        }
    }

    /// The last value recorded for `name`.
    pub(crate) fn get(&self, name: &str) -> Option<String> {
        self.values
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

impl tracing::field::Visit for SpanFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.values
            .lock()
            .unwrap()
            .push((field.name().to_string(), format!("{value:?}")));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.values
            .lock()
            .unwrap()
            .push((field.name().to_string(), value.to_string()));
    }
}

impl<S> tracing_subscriber::Layer<S> for SpanFields
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if attrs.metadata().name() == self.span_name {
            attrs.record(&mut self.clone());
        }
    }
    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if ctx.span(id).is_some_and(|s| s.name() == self.span_name) {
            values.record(&mut self.clone());
        }
    }
}
