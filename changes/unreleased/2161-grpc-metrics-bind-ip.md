---
section: Added
issues: [#2161]
---
- **The gRPC and metrics listeners can bind a specific IP via `GRPC_BIND_IP` and `METRICS_BIND_IP`** (#2161). Both listeners hard-coded `0.0.0.0`, so a deployment that must bind everything to loopback (for example Nomad behind a Consul service mesh, where another allocation on the same node could otherwise bypass the mesh) had no way to do it for these two ports. Both variables default to `0.0.0.0`, so nothing changes unless they are set; IPv6 literals (`::1`, or `[::1]`) are accepted, and an invalid value now fails startup rather than silently binding every interface.
