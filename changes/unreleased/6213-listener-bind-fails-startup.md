---
section: Fixed
issues: [#6213]
---
- **A dedicated gRPC or metrics listener that cannot come up is no longer silently missing** (#6213). With `METRICS_PORT=9090` and `GRPC_PORT` unset (default 9090), the backend logged one ERROR line and kept running and reporting healthy without the metrics listener, and the gRPC task logged "gRPC server listening" before it had bound. Listener addresses are now resolved before anything binds. When the default gRPC port collides with `METRICS_PORT` or `BIND_ADDRESS`, gRPC is turned off with an ERROR naming both settings, and the listener the operator configured binds, so `METRICS_PORT=9090` now serves `/metrics`. Every listener is bound before anything is served, and "listening" is logged only after the bind succeeds.

  Upgrade note: only two explicitly configured listeners on the same address now refuse to start (`METRICS_PORT` against an explicit `GRPC_PORT`, or either against `BIND_ADDRESS`). A default gRPC port that collides is disabled with an ERROR. Startup also fails when `METRICS_PORT`, or an explicitly set `GRPC_PORT`, cannot be bound (for example because the port is taken). With `GRPC_PORT` unset, a gRPC bind failure is still only logged, and an unset or invalid `METRICS_PORT` still leaves the metrics listener off.
