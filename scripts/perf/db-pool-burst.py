#!/usr/bin/env python3
"""Installer-fleet burst against the database pool (#4182).

Models N package installers that each fetch a list of files with M parallel
fetchers, the shape rattler-based clients (pixi, micromamba, conda with
libmamba) put on a registry: 24 installers x 50 fetches is 1,200 requests in
flight. Every fetch is an anonymous GET of one artifact from a public
repository, so each request needs a pooled database connection (visibility,
repository and artifact lookups) and then streams bytes from storage.

A fetch answered 503 or 429 is retried after its Retry-After (at most
--retries times), as the package clients do; a timeout or another 5xx is
retried after one second. A /readyz poller runs for the whole burst, because a
readiness probe that fails under load takes a busy replica out of service.

Reported, per run, as JSON on stdout (and to --out):
  * attempts: every HTTP attempt, its status mix, and latency p50/p90/p99/max
    overall, for 2xx answers, and for 503 answers (how long a client waited to
    be told to back off);
  * installs: how many installers fetched every file, how many gave up, and
    the fleet wall time;
  * readyz: status mix and latency of the probes taken during the burst.

Seed the repository first with --seed (needs admin credentials), then run the
burst. Example, against a backend on :8080:

  scripts/perf/db-pool-burst.py --base-url http://127.0.0.1:8080 \\
      --admin-user admin --admin-pass "$ADMIN_PASS" --repo perf-burst \\
      --files 200 --seed
  scripts/perf/db-pool-burst.py --base-url http://127.0.0.1:8080 \\
      --repo perf-burst --files 200 --installers 24 --parallel 50 \\
      --label after --out results/after.json

Standard library only (asyncio with a minimal HTTP/1.1 client), so it runs
on any host with Python 3.9+.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import random
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field


# --------------------------------------------------------------------------
# Minimal HTTP/1.1 client: one GET per connection, enough for a load test and
# free of third-party dependencies.
# --------------------------------------------------------------------------


@dataclass
class Answer:
    status: int  # 0 = transport failure or client timeout
    retry_after: float | None
    seconds: float


async def http_get(host: str, port: int, path: str, timeout: float) -> Answer:
    started = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "User-Agent: ak-perf-db-pool-burst\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        async def read_all() -> tuple[int, float | None]:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            status = int(lines[0].split(" ", 2)[1])
            retry_after = None
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "retry-after":
                    try:
                        retry_after = float(value.strip())
                    except ValueError:
                        retry_after = None
            # Drain the body (Connection: close ends it).
            while await reader.read(65536):
                pass
            return status, retry_after

        status, retry_after = await asyncio.wait_for(read_all(), timeout)
        return Answer(status, retry_after, time.monotonic() - started)
    except (asyncio.TimeoutError, OSError, ValueError, asyncio.IncompleteReadError):
        return Answer(0, None, time.monotonic() - started)
    finally:
        if writer is not None:
            writer.close()


# --------------------------------------------------------------------------
# Seeding (synchronous, admin credentials).
# --------------------------------------------------------------------------


def api(base: str, method: str, path: str, auth: str, body: bytes | None = None,
        ctype: str = "application/json") -> int:
    req = urllib.request.Request(base + path, data=body, method=method)
    req.add_header("Authorization", auth)
    if body is not None:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code


def file_path(i: int) -> str:
    return f"pkgs/pkg-{i:05d}-1.0.0.tar.bz2"


def seed(args: argparse.Namespace) -> None:
    token = base64.b64encode(f"{args.admin_user}:{args.admin_pass}".encode()).decode()
    auth = f"Basic {token}"
    body = json.dumps({
        "key": args.repo, "name": args.repo, "format": "generic",
        "repo_type": "local", "is_public": True,
    }).encode()
    status = api(args.base_url, "POST", "/api/v1/repositories", auth, body)
    if status not in (200, 201, 409):
        sys.exit(f"creating repository {args.repo}: HTTP {status}")
    payload = b"x" * args.file_bytes
    for i in range(args.files):
        status = api(args.base_url, "PUT",
                     f"/api/v1/repositories/{args.repo}/artifacts/{file_path(i)}",
                     auth, payload, "application/octet-stream")
        if status not in (200, 201, 409):
            sys.exit(f"uploading {file_path(i)}: HTTP {status}")
    print(f"seeded {args.files} files into {args.repo}", file=sys.stderr)


# --------------------------------------------------------------------------
# The burst.
# --------------------------------------------------------------------------


@dataclass
class Stats:
    attempts: list[Answer] = field(default_factory=list)
    installs_ok: int = 0
    installs_failed: int = 0
    files_failed: int = 0
    readyz: list[Answer] = field(default_factory=list)


async def fetch_with_retries(host, port, path, args, stats: Stats) -> bool:
    for attempt in range(args.retries + 1):
        answer = await http_get(host, port, path, args.timeout)
        stats.attempts.append(answer)
        if 200 <= answer.status < 300:
            return True
        if answer.status in (404, 401, 403):
            return False
        if attempt == args.retries:
            return False
        delay = answer.retry_after if answer.retry_after is not None else 1.0
        # Jitter as the clients do, so retries do not arrive in lockstep.
        await asyncio.sleep(min(delay, 10.0) * random.uniform(0.75, 1.25))
    return False


async def installer(host, port, args, stats: Stats) -> None:
    queue: asyncio.Queue[str] = asyncio.Queue()
    order = list(range(args.files))
    random.shuffle(order)
    for i in order:
        queue.put_nowait(f"/api/v1/repositories/{args.repo}/download/{file_path(i)}")
    failed = 0

    async def fetcher() -> None:
        nonlocal failed
        while True:
            try:
                path = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if not await fetch_with_retries(host, port, path, args, stats):
                failed += 1

    await asyncio.gather(*(fetcher() for _ in range(args.parallel)))
    stats.files_failed += failed
    if failed:
        stats.installs_failed += 1
    else:
        stats.installs_ok += 1


async def readyz_poller(host, port, args, stats: Stats, done: asyncio.Event) -> None:
    while not done.is_set():
        stats.readyz.append(await http_get(host, port, "/readyz", 10.0))
        try:
            await asyncio.wait_for(done.wait(), args.readyz_interval)
        except asyncio.TimeoutError:
            pass


def pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = min(len(ordered) - 1, max(0, round(p / 100 * (len(ordered) - 1))))
    return round(ordered[k] * 1000, 1)


def latency(answers: list[Answer]) -> dict:
    secs = [a.seconds for a in answers]
    return {
        "count": len(secs),
        "p50_ms": pct(secs, 50),
        "p90_ms": pct(secs, 90),
        "p99_ms": pct(secs, 99),
        "max_ms": pct(secs, 100),
        "mean_ms": round(statistics.fmean(secs) * 1000, 1) if secs else None,
    }


async def burst(args: argparse.Namespace) -> dict:
    url = urllib.parse.urlsplit(args.base_url)
    host, port = url.hostname, url.port or 80
    stats = Stats()
    done = asyncio.Event()
    poller = asyncio.create_task(readyz_poller(host, port, args, stats, done))
    started = time.monotonic()
    await asyncio.gather(*(installer(host, port, args, stats) for _ in range(args.installers)))
    wall = time.monotonic() - started
    done.set()
    await poller

    mix = Counter(str(a.status) if a.status else "timeout/conn" for a in stats.attempts)
    total = len(stats.attempts)
    errors = sum(n for s, n in mix.items() if not s.startswith("2"))
    ok = [a for a in stats.attempts if 200 <= a.status < 300]
    shed = [a for a in stats.attempts if a.status == 503]
    ready_mix = Counter(str(a.status) if a.status else "timeout/conn" for a in stats.readyz)
    return {
        "label": args.label,
        "shape": {
            "installers": args.installers, "parallel": args.parallel,
            "files": args.files, "in_flight": args.installers * args.parallel,
            "retries": args.retries,
        },
        "installs": {
            "ok": stats.installs_ok, "failed": stats.installs_failed,
            "files_failed": stats.files_failed, "wall_s": round(wall, 2),
            "files_per_s": round(args.installers * args.files / wall, 1),
        },
        "attempts": {
            "total": total,
            "status_mix": dict(sorted(mix.items())),
            "error_rate": round(errors / total, 4) if total else None,
            "with_retry_after_503": sum(1 for a in shed if a.retry_after is not None),
            "all": latency(stats.attempts),
            "ok_2xx": latency(ok),
            "shed_503": latency(shed),
        },
        "readyz": {
            "status_mix": dict(sorted(ready_mix.items())),
            "latency": latency(stats.readyz),
        },
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--base-url", required=True)
    p.add_argument("--repo", default="perf-burst")
    p.add_argument("--files", type=int, default=200, help="files per install list")
    p.add_argument("--file-bytes", type=int, default=4096)
    p.add_argument("--seed", action="store_true", help="create the repo and upload the files")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-pass")
    p.add_argument("--installers", type=int, default=24)
    p.add_argument("--parallel", type=int, default=50, help="fetches in flight per installer")
    p.add_argument("--retries", type=int, default=5)
    p.add_argument("--timeout", type=float, default=30.0, help="client timeout per attempt (s)")
    p.add_argument("--readyz-interval", type=float, default=0.5)
    p.add_argument("--label", default="run")
    p.add_argument("--out")
    args = p.parse_args()

    if args.seed:
        if not args.admin_pass:
            sys.exit("--seed needs --admin-pass")
        seed(args)
        return
    report = asyncio.run(burst(args))
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
