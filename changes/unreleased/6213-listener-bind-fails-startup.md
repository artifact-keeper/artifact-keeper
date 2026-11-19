---
section: Fixed
issues: [#6213]
---
- **A configured gRPC or metrics listener that cannot bind now stops startup with a clear error** (#6213). With `METRICS_PORT=9090` next to the default gRPC port 9090, the backend logged one ERROR line and kept running and reporting healthy without the metrics listener, and the gRPC task logged "gRPC server listening" before it had bound. Two listeners given the same address (HTTP `BIND_ADDRESS`, gRPC, `METRICS_PORT`) are now refused at startup with a message naming both settings, every listener is bound before anything is served, and "listening" is logged only after the bind succeeds. A metrics listener that cannot bind, or a gRPC listener whose explicitly set `GRPC_PORT` cannot bind, fails startup. With `GRPC_PORT` unset, a gRPC bind failure is still logged and the server runs without gRPC as before, and an unset or invalid `METRICS_PORT` still leaves the metrics listener off.
