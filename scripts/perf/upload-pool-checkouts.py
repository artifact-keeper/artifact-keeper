#!/usr/bin/env python3
"""Database work per upload, and uploads under a small pool (#6318).

Driven by upload-pool-checkouts.sh, which stands up Postgres (with
pg_stat_statements) and one backend per image. Two measurements:

1. Sequential: N PyPI uploads (twine's multipart form) and N generic PUTs of
   a PyPI wheel into a PyPI repository (the native-finalize path), one at a
   time. Statements and transactions are read from pg_stat_statements and
   pg_stat_database before and after; an idle window of the same length,
   measured first, is subtracted so background jobs do not count. Every
   autocommit statement on a pooled connection is its own transaction, so the
   transaction count tracks pool checkouts closely.
2. Burst: CONCURRENCY simultaneous PyPI uploads of BURST_MIB MiB each, the
   issue's reproduction; counts statuses and latency.

Stdlib only. Writes one JSON object to --out.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile


def psql(container: str, sql: str) -> str:
    return subprocess.run(
        ["docker", "exec", container, "psql", "-U", "registry", "-d", "artifact_registry",
         "-tAc", sql],
        check=True, capture_output=True, text=True).stdout.strip()


def db_counters(container: str) -> tuple:
    calls = int(psql(container, "SELECT COALESCE(SUM(calls),0)::bigint FROM pg_stat_statements") or 0)
    xacts = int(psql(container,
                     "SELECT xact_commit + xact_rollback FROM pg_stat_database "
                     "WHERE datname = 'artifact_registry'") or 0)
    return calls, xacts


def settle(container: str) -> None:
    # An idle backend flushes its transaction counters within
    # PGSTAT_IDLE_INTERVAL (10 s); pg_stat_statements is immediate.
    del container
    time.sleep(11.0)


def request(base: str, method: str, path: str, auth: str, body: bytes = b"",
            ctype: str = "application/octet-stream", timeout: float = 120) -> tuple:
    req = urllib.request.Request(base + path, data=body if body else None, method=method)
    req.add_header("Authorization", auth)
    if body:
        req.add_header("Content-Type", ctype)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        e.read()
        status = e.code
    except Exception:  # noqa: BLE001 -- a transport failure is a result here
        status = 0
    return status, (time.monotonic() - started) * 1000.0


def wheel(name: str, version: str, payload: bytes) -> tuple:
    dist = name.replace("-", "_")
    filename = f"{dist}-{version}-py3-none-any.whl"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(f"{dist}/__init__.py", "")
        z.writestr(f"{dist}/blob.bin", payload)
        z.writestr(f"{dist}-{version}.dist-info/METADATA",
                   f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                   f"Summary: perf {name}\nRequires-Python: >=3.8\n")
        z.writestr(f"{dist}-{version}.dist-info/WHEEL",
                   "Wheel-Version: 1.0\nGenerator: perf\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        z.writestr(f"{dist}-{version}.dist-info/RECORD", "")
    return filename, buf.getvalue()


def twine_form(name: str, version: str, filename: str, content: bytes) -> tuple:
    boundary = "akperf6318" + hashlib.sha1(filename.encode()).hexdigest()[:12]
    fields = [(":action", "file_upload"), ("protocol_version", "1"), ("metadata_version", "2.1"),
              ("name", name), ("version", version), ("summary", f"perf {name}"),
              ("requires_python", ">=3.8"), ("filetype", "bdist_wheel"), ("pyversion", "py3"),
              ("sha256_digest", hashlib.sha256(content).hexdigest())]
    out = io.BytesIO()
    for k, v in fields:
        out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; "
              f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
    out.write(content)
    out.write(f"\r\n--{boundary}--\r\n".encode())
    return f"multipart/form-data; boundary={boundary}", out.getvalue()


def pct(values: list, p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return round(s[min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1))))], 1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--db-container", required=True)
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-pass", required=True)
    ap.add_argument("--uploads", type=int, default=40)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--burst-mib", type=int, default=24)
    ap.add_argument("--label", default="run")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    auth = "Basic " + base64.b64encode(f"{args.admin_user}:{args.admin_pass}".encode()).decode()
    base = args.base_url

    for key in ("perf-pypi", "perf-pypi-generic", "perf-pypi-burst"):
        body = json.dumps({"key": key, "name": key, "format": "pypi", "repo_type": "local",
                           "is_public": False}).encode()
        status, _ = request(base, "POST", "/api/v1/repositories", auth, body, "application/json")
        if status not in (200, 201, 409):
            sys.exit(f"creating {key}: HTTP {status}")
    # Warm the pool and caches with one upload of each kind.
    for i, path in ((0, "/pypi/perf-pypi/"),):
        fn, whl = wheel(f"warm-{i}", "1.0.0", b"w")
        ctype, form = twine_form(f"warm-{i}", "1.0.0", fn, whl)
        request(base, "POST", path, auth, form, ctype)
    fn, whl = wheel("warm-g", "1.0.0", b"w")
    request(base, "PUT", f"/api/v1/repositories/perf-pypi-generic/artifacts/warm-g/1.0.0/{fn}",
            auth, whl)

    # Background rate over an idle window.
    settle(args.db_container)
    c0, x0 = db_counters(args.db_container)
    idle_s = 20.0
    time.sleep(idle_s)
    settle(args.db_container)
    c1, x1 = db_counters(args.db_container)
    idle_calls_per_s = (c1 - c0 - 2) / (idle_s + 11.0)
    idle_xacts_per_s = (x1 - x0 - 2) / (idle_s + 11.0)

    def sequential(kind: str) -> dict:
        settle(args.db_container)
        a_calls, a_xacts = db_counters(args.db_container)
        started = time.monotonic()
        statuses, lat = {}, []
        for i in range(args.uploads):
            name = f"{kind}-{i}"
            fn, whl = wheel(name, "1.0.0", os.urandom(4096))
            if kind == "pypi":
                ctype, form = twine_form(name, "1.0.0", fn, whl)
                st, ms = request(base, "POST", "/pypi/perf-pypi/", auth, form, ctype)
            else:
                st, ms = request(base, "PUT",
                                 f"/api/v1/repositories/perf-pypi-generic/artifacts/{name}/1.0.0/{fn}",
                                 auth, whl)
            statuses[str(st)] = statuses.get(str(st), 0) + 1
            lat.append(ms)
        busy = time.monotonic() - started
        settle(args.db_container)
        b_calls, b_xacts = db_counters(args.db_container)
        window = busy + 11.0
        return {
            "uploads": args.uploads, "status_mix": statuses,
            "statements_per_upload": round(
                (b_calls - a_calls - 2 - idle_calls_per_s * window) / args.uploads, 1),
            "transactions_per_upload": round(
                (b_xacts - a_xacts - 2 - idle_xacts_per_s * window) / args.uploads, 1),
            "latency_ms": {"p50": pct(lat, 50), "p95": pct(lat, 95)},
        }

    result = {"label": args.label,
              "idle_per_s": {"statements": round(idle_calls_per_s, 2),
                             "transactions": round(idle_xacts_per_s, 2)},
              "pypi_upload": sequential("pypi"),
              "generic_put_wheel": sequential("gput")}

    payload = os.urandom(args.burst_mib * 1024 * 1024)
    forms = []
    for i in range(args.concurrency):
        name = f"burst-{i}"
        fn, whl = wheel(name, "1.0.0", payload + i.to_bytes(4, "big"))
        forms.append(twine_form(name, "1.0.0", fn, whl))
    with concurrent.futures.ThreadPoolExecutor(args.concurrency) as pool:
        started = time.monotonic()
        outcomes = list(pool.map(
            lambda f: request(base, "POST", "/pypi/perf-pypi-burst/", auth, f[1], f[0], 300),
            forms))
        wall = time.monotonic() - started
    mix = {}
    for st, _ in outcomes:
        mix[str(st)] = mix.get(str(st), 0) + 1
    ok = [ms for st, ms in outcomes if 200 <= st < 300]
    result["burst"] = {"concurrency": args.concurrency, "mib": args.burst_mib,
                       "status_mix": mix, "ok": len(ok), "failed": len(outcomes) - len(ok),
                       "wall_s": round(wall, 1),
                       "latency_ms": {"p50": pct([m for _, m in outcomes], 50),
                                      "max": pct([m for _, m in outcomes], 100)}}
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
