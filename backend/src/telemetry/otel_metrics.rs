//! OTLP metric export for the existing `metrics` instruments (#4337).
//!
//! The backend records business-level and HTTP metrics through the `metrics`
//! facade (see [`crate::services::metrics_service`]); today they are only
//! scraped as Prometheus text from `/metrics`. This module adds a second
//! destination: a `metrics` [`Recorder`] that aggregates what it is given with
//! the OpenTelemetry SDK and pushes it to the OTLP endpoint.
//!
//! Installation (`metrics_service::init_metrics`) fans the process-global
//! recorder out to the Prometheus recorder and this one, so enabling
//! OpenTelemetry adds a destination rather than replacing the scrape endpoint.
//! The recorder is built only on the OTLP path and only when
//! `OTEL_METRICS_EXPORTER=otlp` (see [`super::SignalExporter`]).
//!
//! ## Instrument shapes
//!
//! The `metrics` recorder sees each `Key` several times over a scrape interval
//! — `register_counter` per call site, then `absolute`/`increment` on every
//! recording — and the OTel SDK expects handles to be registered once and then
//! recorded. So instruments are created lazily on first use and memoised by
//! [`MetricsRecorder::slot`]:
//!
//! | `metrics` handle | `Key` call | OTel instrument |
//! |---|---|---|
//! | counter | `register_counter` / `absolute` / `increment` | `u64` **counter** (`add`) |
//! | gauge | `set` | `f64` **gauge** (`record`) |
//! | gauge | `increment` / `decrement` | `f64` **up-down counter** (`add`, negative for `decrement`) |
//! | histogram | `register_histogram` / `record` | `f64` **histogram** (`record(value)`) |
//!
//! A counter's `absolute(total)` sets the running total. The OTel `Counter`
//! only adds, so the recorder remembers the largest total seen per key and
//! adds the difference; a total lower than that is ignored, as a monotonic
//! counter cannot go down.
//!
//! A gauge's `increment`/`decrement` go to an *up-down counter* because an OTel
//! gauge's `record` replaces the last value rather than accumulating it: an
//! `increment(1)` on the `ak_http_connections_open` gauge
//! (`metrics_service::OpenConnectionGuard`) must add one, and the guard's
//! `decrement(1)` must subtract one, or the gauge would only ever report `1`.
//! `set` still replaces, which is the same split the Prometheus exporter makes.
//! The two OTel instruments share the gauge's name, so each is created only
//! when the gauge first uses it: a gauge that is only ever `set` (most of
//! them) or only ever incremented exports one instrument, and the SDK's
//! duplicate-name conflict warning is not triggered.
//!
//! ## Attributes and names
//!
//! Label pairs become OTel attributes with the type preserved (metrics-rs
//! stringifies `RecordValue` for most exporters; a numeric attribute is far
//! more useful — and cheaper — than a stringified one).
//!
//! `metrics` names are Prometheus-shaped (`ak_http_request_duration_seconds`,
//! `ak_uploads_total`) and are exported to OTLP verbatim: the semantic
//! convention suffixes stay meaningful in the OTel data model, so renaming
//! them would only make an OTLP metric harder to line up with the `/metrics`
//! series of the same name. The units are also preserved verbatim (a unit is
//! a free-form string in OTel, and the `metrics` facade carries none anyway
//! for these instruments).
//!
//! ## Export cadence
//!
//! The SDK's [`PeriodicReader`] drives export on its own background task with
//! the OTel default 60 s interval (`OTEL_METRIC_EXPORT_INTERVAL` is honoured by
//! the SDK), cumulatively, so a scrape is independent of the Prometheus
//! scrape interval and no data is lost between the two.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit};
use opentelemetry::metrics::{Meter, MeterProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::{SdkMeterProvider, Stream};

/// Namespace the OTel instruments are created under (instrumentation scope).
const SCOPE_NAME: &str = "artifact-keeper";

/// The OTel-based `metrics` recorder. See the module docs for the mapping.
pub(crate) struct MetricsRecorder {
    inner: Arc<RecorderInner>,
}

/// State shared by the recorder and the handles it returns, so a gauge handle
/// can create its instruments lazily.
struct RecorderInner {
    meter: Meter,
    /// Instrument handles created so far, keyed by the `metrics` key (name and
    /// label names). Each instrument is registered with the SDK exactly once
    /// and the cheap handle is then reused; re-registering on every recording
    /// would leak an instrument per call site per scrape.
    instruments: Mutex<MetricsInstruments>,
}

/// Handles for every instrument the recorder has created, so each one is
/// registered with the SDK exactly once.
#[derive(Default)]
struct MetricsInstruments {
    /// With the largest `absolute` total seen for the key, see the module docs.
    counters: HashMap<Key, (opentelemetry::metrics::Counter<u64>, Arc<AtomicU64>)>,
    gauges: HashMap<Key, opentelemetry::metrics::Gauge<f64>>,
    /// `increment`/`decrement` on a `metrics` gauge are additive, so they go to
    /// an up-down counter; `set` replaces and goes to the gauge above.
    up_down_counters: HashMap<Key, opentelemetry::metrics::UpDownCounter<f64>>,
    histograms: HashMap<Key, opentelemetry::metrics::Histogram<f64>>,
}

impl MetricsRecorder {
    fn new(provider: &SdkMeterProvider) -> Self {
        Self {
            inner: Arc::new(RecorderInner {
                meter: provider.meter(SCOPE_NAME),
                instruments: Mutex::new(MetricsInstruments::default()),
            }),
        }
    }

    /// The attributes of `key`'s labels, numeric values kept numeric.
    fn attributes(key: &Key) -> Vec<KeyValue> {
        key.labels()
            .map(|label| KeyValue::new(label.key().to_string(), label_value(label.value())))
            .collect()
    }

    #[cfg(test)]
    fn instruments(&self) -> std::sync::MutexGuard<'_, MetricsInstruments> {
        self.inner.lock()
    }
}

impl RecorderInner {
    fn lock(&self) -> std::sync::MutexGuard<'_, MetricsInstruments> {
        self.instruments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn counter_for(&self, key: &Key) -> (opentelemetry::metrics::Counter<u64>, Arc<AtomicU64>) {
        self.lock()
            .counters
            .entry(key.clone())
            .or_insert_with(|| {
                (
                    self.meter.u64_counter(key.name().to_string()).build(),
                    Arc::new(AtomicU64::new(0)),
                )
            })
            .clone()
    }

    fn gauge_for(&self, key: &Key) -> opentelemetry::metrics::Gauge<f64> {
        self.lock()
            .gauges
            .entry(key.clone())
            .or_insert_with(|| self.meter.f64_gauge(key.name().to_string()).build())
            .clone()
    }

    fn up_down_counter_for(&self, key: &Key) -> opentelemetry::metrics::UpDownCounter<f64> {
        self.lock()
            .up_down_counters
            .entry(key.clone())
            .or_insert_with(|| {
                self.meter
                    .f64_up_down_counter(key.name().to_string())
                    .build()
            })
            .clone()
    }

    fn histogram_for(&self, key: &Key) -> opentelemetry::metrics::Histogram<f64> {
        self.lock()
            .histograms
            .entry(key.clone())
            .or_insert_with(|| self.meter.f64_histogram(key.name().to_string()).build())
            .clone()
    }
}

/// Label value to attribute value: integers and floats are kept numeric, every
/// other string is passed through.
fn label_value(value: &str) -> opentelemetry::Value {
    value
        .parse::<i64>()
        .map(opentelemetry::Value::from)
        .or_else(|_| value.parse::<f64>().map(opentelemetry::Value::from))
        .unwrap_or_else(|_| opentelemetry::Value::from(value.to_owned()))
}

impl Recorder for MetricsRecorder {
    fn describe_counter(
        &self,
        _key_name: KeyName,
        _unit: Option<Unit>,
        _description: SharedString,
    ) {
    }
    fn describe_gauge(&self, _key_name: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(
        &self,
        _key_name: KeyName,
        _unit: Option<Unit>,
        _description: SharedString,
    ) {
    }

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let (counter, absolute_total) = self.inner.counter_for(key);
        let attributes = Self::attributes(key);
        Counter::from_arc(Arc::new(OtelCounter {
            counter,
            absolute_total,
            attributes,
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let attributes = Self::attributes(key);
        Gauge::from_arc(Arc::new(OtelGauge {
            inner: Arc::clone(&self.inner),
            key: key.clone(),
            gauge: OnceLock::new(),
            up_down: OnceLock::new(),
            attributes,
        }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let histogram = self.inner.histogram_for(key);
        let attributes = Self::attributes(key);
        Histogram::from_arc(Arc::new(OtelHistogram {
            histogram,
            attributes,
        }))
    }
}

/// `metrics` counter handle backed by an OTel `u64` counter.
struct OtelCounter {
    counter: opentelemetry::metrics::Counter<u64>,
    /// The largest `absolute` total reported for this key, shared by every
    /// handle of the key.
    absolute_total: Arc<AtomicU64>,
    attributes: Vec<KeyValue>,
}

impl metrics::CounterFn for OtelCounter {
    fn increment(&self, value: u64) {
        self.counter.add(value, &self.attributes);
    }

    fn absolute(&self, value: u64) {
        // See the module docs: OTel has no set-once counter, so add the
        // difference to the largest total seen so far.
        let previous = self.absolute_total.fetch_max(value, Ordering::Relaxed);
        if value > previous {
            self.counter.add(value - previous, &self.attributes);
        }
    }
}

/// `metrics` gauge handle backed by an OTel `f64` gauge (`set`) and `f64`
/// up-down counter (`increment` / `decrement`), each created on first use.
struct OtelGauge {
    inner: Arc<RecorderInner>,
    key: Key,
    gauge: OnceLock<opentelemetry::metrics::Gauge<f64>>,
    up_down: OnceLock<opentelemetry::metrics::UpDownCounter<f64>>,
    attributes: Vec<KeyValue>,
}

impl OtelGauge {
    fn up_down(&self) -> &opentelemetry::metrics::UpDownCounter<f64> {
        self.up_down
            .get_or_init(|| self.inner.up_down_counter_for(&self.key))
    }
}

impl metrics::GaugeFn for OtelGauge {
    fn increment(&self, value: f64) {
        self.up_down().add(value, &self.attributes);
    }

    fn decrement(&self, value: f64) {
        self.up_down().add(-value, &self.attributes);
    }

    fn set(&self, value: f64) {
        self.gauge
            .get_or_init(|| self.inner.gauge_for(&self.key))
            .record(value, &self.attributes);
    }
}

/// `metrics` histogram handle backed by an OTel `f64` histogram.
struct OtelHistogram {
    histogram: opentelemetry::metrics::Histogram<f64>,
    attributes: Vec<KeyValue>,
}

impl metrics::HistogramFn for OtelHistogram {
    fn record(&self, value: f64) {
        self.histogram.record(value, &self.attributes);
    }
}

/// Build the OTel metrics pipeline and return the recorder to fan out to.
///
/// `exporter` is the OTLP metric exporter for the configured endpoint and
/// protocol; the returned provider owns the [`PeriodicReader`] that drives it.
///
/// [`PeriodicReader`]: opentelemetry_sdk::metrics::PeriodicReader
pub(crate) fn build_otel_metrics_recorder(
    exporter: opentelemetry_otlp::MetricExporter,
    resource: opentelemetry_sdk::Resource,
) -> (MetricsRecorder, SdkMeterProvider) {
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build();
    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .with_view(http_duration_view)
        .build();
    let recorder = MetricsRecorder::new(&provider);
    (recorder, provider)
}

/// Keep the HTTP request latency histogram's explicit buckets when it is
/// exported over OTLP, matching the Prometheus side's
/// [`crate::services::metrics_service::HTTP_REQUEST_DURATION_BUCKETS`].
///
/// The `metrics` facade does not pass bucket boundaries through
/// `Recorder::register_histogram`, so without this view the SDK would use its
/// default boundaries (0, 5, 10, 25, 50, 75, 100, 250, ... in *seconds*),
/// which are useless for a request that finishes in milliseconds.
fn http_duration_view(instrument: &opentelemetry_sdk::metrics::Instrument) -> Option<Stream> {
    if instrument.name() != crate::services::metrics_service::HTTP_REQUEST_DURATION_METRIC {
        return None;
    }
    Stream::builder()
        .with_aggregation(
            opentelemetry_sdk::metrics::Aggregation::ExplicitBucketHistogram {
                boundaries: crate::services::metrics_service::HTTP_REQUEST_DURATION_BUCKETS
                    .to_vec(),
                record_min_max: true,
            },
        )
        .build()
        .ok()
}

/// The SDK meter provider, kept alive for the process lifetime. Dropping it
/// shuts the [`PeriodicReader`] down, which stops OTLP export.
///
/// [`PeriodicReader`]: opentelemetry_sdk::metrics::PeriodicReader
pub(crate) struct MetricsGuard {
    provider: Option<SdkMeterProvider>,
}

impl MetricsGuard {
    pub(crate) fn new(provider: SdkMeterProvider) -> Self {
        Self {
            provider: Some(provider),
        }
    }

    /// Shut the meter provider down as part of the process-wide telemetry
    /// deadline (#4931). The SDK's meter provider currently ignores the
    /// timeout argument, but taking the guard here still prevents a second
    /// shutdown from `Drop` and keeps all three signals on one deadline.
    pub(crate) fn shutdown(mut self, timeout: Duration) {
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown_with_timeout(timeout) {
                eprintln!("Failed to shutdown OTel meter provider: {e:?}");
            }
        }
    }
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("Failed to shutdown OTel meter provider: {e:?}");
            }
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::metrics::data::{
        AggregatedMetrics, Gauge as GaugeData, Histogram as HistogramData, Metric, MetricData,
        ResourceMetrics, Sum,
    };
    use opentelemetry_sdk::metrics::reader::MetricReader;
    use opentelemetry_sdk::metrics::ManualReader;
    use std::sync::Arc;

    /// A `MetricReader` that forwards to a shared [`ManualReader`], so the
    /// provider and the test can hold the same reader (`ManualReader` is not
    /// `Clone` and does not implement `MetricReader` through `Arc`).
    #[derive(Debug)]
    struct SharedManualReader(Arc<ManualReader>);

    impl MetricReader for SharedManualReader {
        fn temporality(
            &self,
            kind: opentelemetry_sdk::metrics::InstrumentKind,
        ) -> opentelemetry_sdk::metrics::Temporality {
            self.0.temporality(kind)
        }

        fn register_pipeline(
            &self,
            pipeline: std::sync::Weak<opentelemetry_sdk::metrics::Pipeline>,
        ) {
            self.0.register_pipeline(pipeline);
        }

        fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
            self.0.collect(rm)
        }

        fn force_flush(&self) -> OTelSdkResult {
            self.0.force_flush()
        }

        fn shutdown(&self) -> OTelSdkResult {
            self.0.shutdown()
        }

        fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> OTelSdkResult {
            self.0.shutdown_with_timeout(timeout)
        }
    }

    /// A recorder exporting to a manual reader, so a test can collect exactly
    /// what was recorded without an endpoint or a background task.
    ///
    /// The [`SdkMeterProvider`] is returned alongside the reader: dropping it
    /// shuts the reader down (`InternalFailure("reader is shut down or not
    /// registered")` on the next `collect`), so the test must keep it alive
    /// until it has collected.
    struct TestMetrics {
        recorder: MetricsRecorder,
        provider: SdkMeterProvider,
        reader: Arc<ManualReader>,
    }

    fn recording_recorder() -> TestMetrics {
        let reader = Arc::new(ManualReader::builder().build());
        let provider = SdkMeterProvider::builder()
            .with_reader(SharedManualReader(Arc::clone(&reader)))
            .with_view(http_duration_view)
            .build();
        let recorder = MetricsRecorder::new(&provider);
        TestMetrics {
            recorder,
            provider,
            reader,
        }
    }

    fn collect(reader: &ManualReader) -> ResourceMetrics {
        let mut out = ResourceMetrics::default();
        reader.collect(&mut out).expect("collect");
        out
    }

    /// The single exported metric named `name`.
    fn named_metric<'a>(data: &'a ResourceMetrics, name: &str) -> &'a Metric {
        data.scope_metrics()
            .flat_map(|scope| scope.metrics())
            .find(|m| m.name() == name)
            .unwrap_or_else(|| panic!("{name} not exported"))
    }

    fn expect_u64_sum(metric: &Metric) -> &Sum<u64> {
        let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
            panic!("expected a U64 sum, got {:?}", metric.data());
        };
        sum
    }

    fn expect_f64_gauge(metric: &Metric) -> &GaugeData<f64> {
        let AggregatedMetrics::F64(MetricData::Gauge(gauge)) = metric.data() else {
            panic!("expected an F64 gauge, got {:?}", metric.data());
        };
        gauge
    }

    fn expect_f64_histogram(metric: &Metric) -> &HistogramData<f64> {
        let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data() else {
            panic!("expected an F64 histogram, got {:?}", metric.data());
        };
        histogram
    }

    #[test]
    fn counter_increments_become_a_monotonic_sum() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let key = Key::from_name("ak_uploads_total");
        let counter =
            recorder.register_counter(&key, &Metadata::new("", metrics::Level::INFO, None));
        counter.increment(1);
        counter.increment(2);

        let data = collect(&reader);
        let sum = expect_u64_sum(named_metric(&data, "ak_uploads_total"));
        let points: Vec<_> = sum.data_points().collect();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].value(), 3);
    }

    /// `absolute` sets the running total: the exported sum is the largest
    /// total reported, not the sum of every report.
    #[test]
    fn counter_absolute_sets_the_total() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let key = Key::from_name("ak_backups_total");
        let metadata = Metadata::new("", metrics::Level::INFO, None);
        recorder.register_counter(&key, &metadata).absolute(5);
        // A second handle for the same key shares the total.
        let counter = recorder.register_counter(&key, &metadata);
        counter.absolute(3);
        counter.absolute(8);

        let data = collect(&reader);
        let sum = expect_u64_sum(named_metric(&data, "ak_backups_total"));
        assert_eq!(sum.data_points().next().unwrap().value(), 8);
    }

    #[test]
    fn labels_become_attributes_with_numeric_types_preserved() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let key = Key::from_parts(
            "ak_downloads_total",
            vec![
                metrics::Label::new("format", "npm"),
                metrics::Label::new("status", "404"),
            ],
        );
        recorder
            .register_counter(&key, &Metadata::new("", metrics::Level::INFO, None))
            .increment(1);

        let data = collect(&reader);
        let sum = expect_u64_sum(named_metric(&data, "ak_downloads_total"));
        let attributes: Vec<_> = sum.data_points().next().unwrap().attributes().collect();
        assert!(attributes.contains(&&KeyValue::new("format", "npm")));
        assert!(attributes.contains(&&KeyValue::new("status", 404i64)));
    }

    #[test]
    fn gauge_set_replaces_the_value() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let key = Key::from_name("ak_storage_used_bytes");
        let gauge = recorder.register_gauge(&key, &Metadata::new("", metrics::Level::INFO, None));
        gauge.set(4.0);
        gauge.set(9.0);

        let data = collect(&reader);
        let gauge = expect_f64_gauge(named_metric(&data, "ak_storage_used_bytes"));
        assert_eq!(gauge.data_points().next().unwrap().value(), 9.0);
    }

    /// A gauge that is only `set` creates only the OTel gauge, and one that is
    /// only incremented only the up-down counter: creating both eagerly would
    /// register two instruments under one name for every gauge.
    #[test]
    fn a_gauge_creates_only_the_instrument_it_uses() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let metadata = Metadata::new("", metrics::Level::INFO, None);
        recorder
            .register_gauge(&Key::from_name("ak_set_only"), &metadata)
            .set(1.0);
        recorder
            .register_gauge(&Key::from_name("ak_incremented_only"), &metadata)
            .increment(1.0);

        {
            let instruments = recorder.instruments();
            assert_eq!(instruments.gauges.len(), 1);
            assert_eq!(instruments.up_down_counters.len(), 1);
        }
        let data = collect(&reader);
        let names: Vec<_> = data
            .scope_metrics()
            .flat_map(|scope| scope.metrics())
            .map(|m| m.name().to_owned())
            .collect();
        assert_eq!(names.iter().filter(|n| *n == "ak_set_only").count(), 1);
        assert_eq!(
            names.iter().filter(|n| *n == "ak_incremented_only").count(),
            1
        );
    }

    /// `increment`/`decrement` are additive, so they need an up-down counter:
    /// an OTel gauge's `record` would replace the value, and the connection
    /// gauge would only ever report `1` while a connection is open.
    #[test]
    fn gauge_increment_accumulates_instead_of_replacing() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let key = Key::from_name("ak_http_connections_open");
        let gauge = recorder.register_gauge(&key, &Metadata::new("", metrics::Level::INFO, None));
        gauge.increment(1.0);
        gauge.increment(1.0);
        gauge.decrement(1.0);

        let data = collect(&reader);
        let metric = named_metric(&data, "ak_http_connections_open");
        let AggregatedMetrics::F64(MetricData::Sum(sum)) = metric.data() else {
            panic!(
                "gauge increments must be an F64 sum, got {:?}",
                metric.data()
            );
        };
        assert_eq!(sum.data_points().next().unwrap().value(), 1.0);
    }

    #[test]
    fn histograms_record_every_value() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let key = Key::from_name("ak_bytes_uploaded");
        let histogram =
            recorder.register_histogram(&key, &Metadata::new("", metrics::Level::INFO, None));
        histogram.record(0.25);
        histogram.record(0.75);

        let data = collect(&reader);
        let histogram = expect_f64_histogram(named_metric(&data, "ak_bytes_uploaded"));
        let point = histogram.data_points().next().unwrap();
        assert_eq!(point.count(), 2);
        assert_eq!(point.sum(), 1.0);
    }

    /// The HTTP latency histogram keeps the Prometheus side's buckets, so a
    /// millisecond-scale request does not land in one default 5s bucket.
    #[test]
    fn http_duration_histogram_keeps_the_prometheus_buckets() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let key = Key::from_name(crate::services::metrics_service::HTTP_REQUEST_DURATION_METRIC);
        recorder
            .register_histogram(&key, &Metadata::new("", metrics::Level::INFO, None))
            .record(0.03);

        let data = collect(&reader);
        let histogram = expect_f64_histogram(named_metric(
            &data,
            crate::services::metrics_service::HTTP_REQUEST_DURATION_METRIC,
        ));
        let point = histogram.data_points().next().unwrap();
        let bounds: Vec<f64> = point.bounds().collect();
        assert_eq!(
            bounds,
            crate::services::metrics_service::HTTP_REQUEST_DURATION_BUCKETS.to_vec()
        );
        // 0.03s belongs to the 0.05 bucket and nothing below it.
        let counts: Vec<u64> = point.bucket_counts().collect();
        assert_eq!(counts.iter().sum::<u64>(), 1);
    }

    #[test]
    fn instrument_is_registered_once_per_key() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader: _reader,
        } = recording_recorder();
        let key = Key::from_name("ak_scans_total");
        let metadata = Metadata::new("", metrics::Level::INFO, None);
        recorder.register_counter(&key, &metadata).increment(1);
        recorder.register_counter(&key, &metadata).increment(1);
        let instruments = recorder.instruments();
        assert_eq!(instruments.counters.len(), 1);
    }

    /// `main` runs `telemetry::init_tracing` (which hands the OTel recorder
    /// over) before `metrics_service::init_metrics` (which installs the
    /// Prometheus recorder ahead of the startup pool connect, #4828). In that
    /// order a metric must reach both `/metrics` and the OTel pipeline. This
    /// is the only test in the crate that installs the process-global
    /// recorder.
    #[test]
    fn main_startup_order_exports_metrics_to_prometheus_and_otel() {
        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        // telemetry::init_tracing
        crate::services::metrics_service::install_otel_recorder(recorder);
        // main, before db::create_pool
        let handle = crate::services::metrics_service::init_metrics();

        metrics::counter!("ak_startup_order_probe_total").increment(1);

        let data = collect(&reader);
        let sum = expect_u64_sum(named_metric(&data, "ak_startup_order_probe_total"));
        assert_eq!(sum.data_points().next().unwrap().value(), 1);
        let rendered = handle.render();
        assert!(
            rendered.contains("ak_startup_order_probe_total 1"),
            "/metrics must still report the counter once: {rendered}"
        );
    }

    /// The fan-out leaves the Prometheus side as it is without OTLP: the same
    /// series names, values counted once, histogram buckets unchanged.
    #[test]
    fn fanout_keeps_the_prometheus_rendering_unchanged() {
        fn record() {
            metrics::counter!("ak_uploads_total", "format" => "npm").increment(2);
            metrics::gauge!("ak_http_connections_open").increment(1.0);
            metrics::histogram!(
                crate::services::metrics_service::HTTP_REQUEST_DURATION_METRIC,
                "method" => "GET"
            )
            .record(0.03);
        }

        let (prometheus_only, plain) =
            crate::services::metrics_service::build_global_recorder(None);
        metrics::with_local_recorder(&prometheus_only, record);

        let TestMetrics {
            recorder,
            provider: _provider,
            reader,
        } = recording_recorder();
        let (fanout, fanned) =
            crate::services::metrics_service::build_global_recorder(Some(Box::new(recorder)));
        metrics::with_local_recorder(&fanout, record);

        assert_eq!(plain.render(), fanned.render());
        let data = collect(&reader);
        let sum = expect_u64_sum(named_metric(&data, "ak_uploads_total"));
        assert_eq!(sum.data_points().next().unwrap().value(), 2);
    }

    #[test]
    fn label_values_keep_their_type() {
        assert_eq!(label_value("404"), opentelemetry::Value::from(404i64));
        assert_eq!(label_value("0.5"), opentelemetry::Value::from(0.5f64));
        assert_eq!(
            label_value("npm"),
            opentelemetry::Value::from("npm".to_owned())
        );
        assert_eq!(
            label_value("1.2.3"),
            opentelemetry::Value::from("1.2.3".to_owned())
        );
    }
}
