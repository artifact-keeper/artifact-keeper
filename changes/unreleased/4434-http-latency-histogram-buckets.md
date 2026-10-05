---
section: Changed
issues: [#4434, #3954]
---
- **`ak_http_request_duration_seconds` is now exported as a Prometheus histogram with buckets, not as a summary** (#4434, #3954). The Prometheus recorder had no buckets configured, so the request-latency histogram rendered as a summary: per-series `quantile="0|0.5|0.9|0.95|0.99|0.999|1"` values pre-computed over the exporter's own window, which cannot be aggregated across replicas, paths or a chosen time range. The metric now exports `ak_http_request_duration_seconds_bucket{le=...}` series with bounds 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 and 60 seconds (plus `+Inf`), so `histogram_quantile(0.99, sum by (le) (rate(ak_http_request_duration_seconds_bucket[5m])))` gives a fleet-wide percentile. `_sum` and `_count` are unchanged. The labels are unchanged too, but each label set now exports 16 series instead of 9 (14 `_bucket` series plus `_sum` and `_count`, where the summary had 7 quantiles plus `_sum` and `_count`), so operators with tight series budgets should expect this metric to grow by about 78%.

  **Breaking for dashboards and alerts:** the `quantile` series of this metric are gone. A panel or rule that selects `ak_http_request_duration_seconds{quantile="0.99"}` must be rewritten with `histogram_quantile()` over the `_bucket` series. Other histograms keep their existing export.
