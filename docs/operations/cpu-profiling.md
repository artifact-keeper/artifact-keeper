# CPU profiling

The backend can expose an opt-in CPU profile endpoint. It is not part of the
published binaries or images: build with the `profiling` feature to enable it.

## Building with symbols

Released binaries keep `strip = true`, so a profile from one resolves to hex
addresses. Build a dedicated profiling binary with symbols instead:

```sh
CARGO_PROFILE_RELEASE_STRIP=none RUSTFLAGS="-C debuginfo=2" \
  cargo build --release --features profiling
```

This only changes the local build. It does not disable stripping for releases.
The binary is much larger, so do not deploy it as the default image. The
profiler uses Unix `setitimer` and signals, so the endpoint is available on
Linux and macOS but not Windows, even when `profiling` is enabled.

## Capturing a profile

The endpoint is admin-only, like `/heap-profile`:

```sh
curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" \
  'https://backend.example/api/v1/admin/cpu-profile?duration=30' \
  -o cpu.pb
go tool pprof -top cpu.pb
```

`duration` is the sampling window in seconds. It defaults to 10 and is capped
at 60. Invalid durations get `400`, and a second request while a profile is
running gets `409`. The response is a pprof-compatible protobuf.

Keep the profiling binary and the debug info used to symbolize it together.
If the process runs in a container, copy `cpu.pb` out before the container is
replaced and symbolize it against the same build.
