---
section: Fixed
issues: [#3833, #3834]
---
- **OTLP `http/protobuf` never exported a span** (#3833, #3834). `opentelemetry-otlp`'s `reqwest-client` feature, added in #812, selects the *async* reqwest client, which is first in the builder's priority order. `BatchSpanProcessor` drives exports from a dedicated OS thread with no Tokio runtime, so the first flush panicked with `there is no reactor running`, killing the processor thread while the process kept serving — every later span dropped with a `BatchSpanProcessor.OnEnd.AfterShutdown` warning, one per request. The feature is removed so the crate's default `reqwest-blocking-client` supplies the client. `grpc` is unaffected.
