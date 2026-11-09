# Backend RSS and the memory allocator

Why a proxy-heavy backend's resident set can climb across bursts and stay
there while it is idle, and what the shipped image does about it (#5130).

## The symptom

A deployment whose repositories are all Remote (proxy) repositories — a
Maven Central mirror, Go modules, npm, NuGet and raw remotes — saw the
backend's RSS rise with each burst of CI downloads and not come back down:

| time | RSS MiB |
|---|---|
| after a fresh start | 77 |
| after the next burst | 627 |
| after the next burst | 1539 |
| later, still idle | flat |
| after further bursts | 3919, then OOM-killed |

`smaps_rollup` showed almost all of it as anonymous memory (`RssAnon`), not
file-backed pages, and the process had a normal thread count (35). Requests
were overwhelmingly `/maven/:repo_key/*path`. The container limit was 4 GiB.

## Why this is the allocator, not an unbounded cache

The Maven proxy path streams bodies; it does not accumulate them per request.
A download writes through a bounded tee (64 chunks of at most 64 KiB) to the
proxy cache, buffered metadata draws on `AK_PROXY_METADATA_BUDGET_BYTES`
(default 1 GiB), and small stored bodies checked before they are served draw
on `AK_SERVE_VERIFY_BUFFER_BUDGET_BYTES` (default 256 MiB). Those budgets
bound in-flight bytes, and the metadata/verdict caches have size and TTL
caps — see [overload and load shedding](load-shedding.md).

What they do not bound is what the C library does with freed memory. The
published image is UBI 9, so it uses glibc's `malloc`. glibc serves each
thread from an arena and keeps freed chunks in that arena for reuse instead of
returning them to the kernel. A burst hands multi-megabyte download buffers to
many request threads; when the burst ends, every arena still holds its share.
The next burst with a different mix of sizes fragments those arenas further.
Over thousands of requests the resident high-water mark climbs even though no
single allocation is retained. Idle time does not shrink it because glibc has
no background decay.

jemalloc (`tikv-jemallocator`) uses its own arenas and *decays*: dirty pages
are returned with `madvise` after `dirty_decay_ms` (10 s by default), and
`muzzy_decay_ms` is 0, so they are released outright rather than parked as
muzzy pages. Background threads are off by default, so the purge runs on the
backend's own allocation activity; an idle backend still allocates often
enough for it to run. The resident set therefore follows the working set
instead of the historical high-water mark.

## What the shipped image does

`docker/Dockerfile.backend` builds the backend with `CARGO_FEATURES=jemalloc`
in both compiling stages, and `.github/workflows/docker-publish.yml` passes
the same value explicitly for the published image. The image is Linux; the
feature is unavailable on Windows, where the system allocator is used.

Other images and builds:

* **Compose builds from this repository** use `docker/Dockerfile.backend` and
  inherit the default.
* **Linux release tarballs.** `.github/workflows/release.yml` and
  `publish-binaries.yml` build the Linux binaries with
  `--features vendored-openssl,jemalloc`, and `release-cli-caches.yml` warms
  the same feature set. The aarch64 leg is cross-compiled on a 4 KiB-page
  runner, so it sets `JEMALLOC_SYS_WITH_LG_PAGE=16`; the tarball starts on
  both 4 KiB and 64 KiB-page kernels. The macOS and Windows tarballs keep
  their platform allocator.
* **Source builds** (`cargo build --release`) use the system allocator unless
  you ask for jemalloc:
  ```sh
  cargo build --release --features jemalloc
  ```
  `--features profiling` implies `jemalloc` and adds heap profiling; see
  `backend/src/main.rs`.
* **arm64.** jemalloc fixes its page size when it is compiled, and refuses to
  start on a kernel with larger pages (`<jemalloc>: Unsupported system page
  size`). The Dockerfile builds it for 64 KiB pages on aarch64, which also
  runs on 4 KiB-page kernels. An aarch64 source build that must run on a
  64 KiB-page kernel (RHEL's `kernel-64k`, NVIDIA Grace) needs the same:
  `JEMALLOC_SYS_WITH_LG_PAGE=16 cargo build --release --features jemalloc`.
* **The Alpine/musl image** (`docker/Dockerfile.backend.alpine`) does not use
  glibc and keeps its current allocator.

## Verifying which allocator a process is using

The backend logs its allocator at startup: `Global allocator: jemalloc`, or
`Global allocator: system` for a build without the feature.

For jemalloc's own view, set `_RJEM_MALLOC_CONF=stats_print:true` and restart
the container; on exit jemalloc writes its statistics to stderr, beginning with
`___ Begin jemalloc statistics ___`, a `Version:` line, the page size and the
configured decay values. The variable has the `_RJEM_` prefix because
`tikv-jemallocator` builds jemalloc with prefixed symbols. Plain `MALLOC_CONF`
is ignored.

`_RJEM_MALLOC_CONF=abort_conf:true` makes an invalid configuration abort at
startup instead of being ignored, which is useful when you are also setting
decay options, for example
`_RJEM_MALLOC_CONF=background_thread:true,dirty_decay_ms:5000`.

## If you cannot switch allocators

For a glibc build, capping the arena count is the cheapest mitigation:

```sh
MALLOC_ARENA_MAX=2
```

This limits how many per-thread arenas exist, trading some allocation
parallelism on many-core hosts for a smaller resident set. It is a mitigation,
not a guarantee: a single arena can still fragment, and workloads that
allocate very large temporary buffers need the same headroom they did before.
Setting it on the jemalloc image has no effect.

## Sizing and alerting

* Size the container for the working set plus headroom, not for the steady
  baseline. The budgets above can be in use at the same time as proxied
  downloads; [sizing memory for virtual conda
  channels](conda-virtual-merge-memory.md) shows the same reasoning for the
  largest buffered path.
* Alert on `container_memory_working_set_bytes` (the value the kernel uses to
  decide OOM) and watch its trend across bursts. Container RSS alone includes
  page cache and can hide the anonymous-memory growth that caused the
  OOM-kill.
* The backend's own `/metrics` endpoint reports the budgets and proxy caches
  described in [proxy cache metrics](proxy-cache-metrics.md); it does not
  measure allocator retention, so compare it with the container's memory
  metrics.
