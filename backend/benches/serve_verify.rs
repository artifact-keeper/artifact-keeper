//! Serve-time SHA-256 verification cost (#6468).
//!
//! Measures `storage::verify::verify_sha256_stream`, the wrapper every
//! verified serve puts around the object stream (hosted downloads, OCI blobs,
//! proxy-cache hits since #6467), against a pass-through drain of the same
//! stream. Bodies are served from memory (a 1 MiB random buffer sliced into
//! chunks without copying), so the numbers are the hashing and the stream
//! adapter alone: no storage or network I/O.
//!
//! For each object size, chunk size and concurrency (independent streams on
//! a multi-thread runtime, one per object), it reports the median of
//! `AK_BENCH_RUNS` runs: wall time, process CPU time (getrusage, user +
//! system), CPU seconds per GiB served, aggregate MB/s and MB/s per CPU
//! second. The verified run's CPU time minus the pass-through run's is the
//! cost of the verification.
//!
//! Run (no database, no network):
//!
//! ```text
//! cargo bench -p artifact-keeper-backend --bench serve_verify --profile ci
//! ```
//!
//! Env: `AK_BENCH_SIZES_MIB` (default `1,100,1024,4096`),
//! `AK_BENCH_CONCURRENCY` (default `1,8`), `AK_BENCH_CHUNK_KIB` (default
//! `256,16`: the filesystem backend's read size, and a typical object-store
//! response chunk), `AK_BENCH_RUNS` (default 3), `AK_BENCH_WORKERS` (tokio
//! worker threads, default 8). Output is a tab-separated table on stdout.

use std::time::{Duration, Instant};

use artifact_keeper_backend::storage::verify::verify_sha256_stream;
use bytes::Bytes;
use futures::stream::{self, BoxStream, StreamExt};
use sha2::{Digest, Sha256};

const MIB: u64 = 1024 * 1024;

fn env_list(name: &str, default: &str) -> Vec<u64> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

/// Process CPU time (user + system) so far.
fn cpu_time() -> Duration {
    // SAFETY: getrusage only writes the struct it is handed.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let tv = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
    };
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

/// A body of `size` bytes in `chunk`-byte pieces, sliced out of `pool`.
fn body(
    pool: &Bytes,
    size: u64,
    chunk: usize,
) -> BoxStream<'static, artifact_keeper_backend::error::Result<Bytes>> {
    let pool = pool.clone();
    let pool_len = pool.len();
    let chunks = size.div_ceil(chunk as u64);
    stream::iter((0..chunks).map(move |i| {
        let start = (i as usize * chunk) % pool_len;
        let left = (size - i * chunk as u64).min(chunk as u64) as usize;
        let end = (start + left).min(pool_len);
        let mut piece = pool.slice(start..end);
        if piece.len() < left {
            // Wrap around the pool for the tail of this chunk.
            let mut joined = Vec::with_capacity(left);
            joined.extend_from_slice(&piece);
            joined.extend_from_slice(&pool[..left - piece.len()]);
            piece = Bytes::from(joined);
        }
        Ok(piece)
    }))
    .boxed()
}

/// SHA-256 of the body `body(pool, size, chunk)` yields.
fn digest_of(pool: &Bytes, size: u64, chunk: usize) -> [u8; 32] {
    let mut h = Sha256::new();
    futures::executor::block_on(async {
        let mut s = body(pool, size, chunk);
        while let Some(c) = s.next().await {
            h.update(c.unwrap());
        }
    });
    h.finalize().into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Passthrough,
    Verify,
}

/// Drain `concurrency` bodies at once; returns (wall, cpu).
fn run_once(
    rt: &tokio::runtime::Runtime,
    pool: &Bytes,
    size: u64,
    chunk: usize,
    concurrency: usize,
    mode: Mode,
    expected: [u8; 32],
) -> (Duration, Duration) {
    let cpu0 = cpu_time();
    let t0 = Instant::now();
    rt.block_on(async {
        let mut tasks = Vec::with_capacity(concurrency);
        for i in 0..concurrency {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                let raw = body(&pool, size, chunk);
                let mut s = match mode {
                    Mode::Passthrough => raw,
                    Mode::Verify => {
                        verify_sha256_stream(raw, expected, Some(size), format!("bench/{i}"))
                    }
                };
                let mut n = 0u64;
                while let Some(c) = s.next().await {
                    n += c.expect("verified body must be intact").len() as u64;
                }
                assert_eq!(n, size, "the whole body is delivered");
            }));
        }
        for t in tasks {
            t.await.expect("stream task");
        }
    });
    (t0.elapsed(), cpu_time() - cpu0)
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn main() {
    // `cargo bench` passes `--bench`. Without it (`cargo test --benches`)
    // this is a smoke run: 1 MiB, one run, so a test build never hashes GiBs.
    let smoke = !std::env::args().any(|a| a == "--bench");
    let sizes = if smoke {
        vec![1]
    } else {
        env_list("AK_BENCH_SIZES_MIB", "1,100,1024,4096")
    };
    let concurrencies = env_list("AK_BENCH_CONCURRENCY", "1,8");
    let chunks = env_list("AK_BENCH_CHUNK_KIB", "256,16");
    let runs = if smoke {
        1
    } else {
        env_list("AK_BENCH_RUNS", "3")
            .first()
            .copied()
            .unwrap_or(3)
            .max(1) as usize
    };
    let workers = env_list("AK_BENCH_WORKERS", "8")
        .first()
        .copied()
        .unwrap_or(8)
        .max(1) as usize;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("runtime");
    let pool = {
        let mut buf = vec![0u8; MIB as usize];
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for b in buf.iter_mut() {
            // xorshift64: incompressible enough for a hash, no rand dependency.
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        Bytes::from(buf)
    };

    println!(
        "# serve_verify: {} worker threads, {} runs per row (median), {} CPUs online",
        workers,
        runs,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    println!(
        "size_mib\tchunk_kib\tconcurrency\tmode\twall_s\tcpu_s\tcpu_s_per_gib\tagg_mb_s\tper_stream_mb_s\tmb_per_cpu_s"
    );
    for &chunk_kib in &chunks {
        let chunk = (chunk_kib * 1024) as usize;
        for &size_mib in &sizes {
            let size = size_mib * MIB;
            let expected = digest_of(&pool, size, chunk);
            for &conc in &concurrencies {
                let conc = conc as usize;
                for mode in [Mode::Passthrough, Mode::Verify] {
                    let mut walls = Vec::new();
                    let mut cpus = Vec::new();
                    for _ in 0..runs {
                        let (w, c) = run_once(&rt, &pool, size, chunk, conc, mode, expected);
                        walls.push(w);
                        cpus.push(c);
                    }
                    let wall = median(walls).as_secs_f64();
                    let cpu = median(cpus).as_secs_f64();
                    let total = (size * conc as u64) as f64;
                    let gib = total / (1024.0 * MIB as f64);
                    let mb = total / 1e6;
                    println!(
                        "{}\t{}\t{}\t{}\t{:.4}\t{:.4}\t{:.3}\t{:.1}\t{:.1}\t{:.1}",
                        size_mib,
                        chunk_kib,
                        conc,
                        if mode == Mode::Verify {
                            "verify"
                        } else {
                            "passthrough"
                        },
                        wall,
                        cpu,
                        cpu / gib,
                        mb / wall,
                        mb / wall / conc as f64,
                        if cpu > 0.0 { mb / cpu } else { 0.0 },
                    );
                }
            }
        }
    }
}
