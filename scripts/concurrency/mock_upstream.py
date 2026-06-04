#!/usr/bin/env python3
"""Mock upstream registry for the multi-replica single-flight race harness (#1624).

Serves ONE large artifact with a known, fixed SHA-256 and:
  - injects a configurable per-response latency to widen the race window so
    that concurrent cold-cache fetches from multiple backend replicas overlap;
  - counts how many times the artifact was *actually* fetched (the assertion
    that a correct cross-process single-flight makes exactly one upstream call);
  - exposes the published digest, size and counter via control endpoints.

This is deliberately dependency-light: Python 3 standard library only, single
file, so it can run standalone for unit tests AND be containerised with a stock
`python:3-slim` image (no pip install).

Endpoints
---------
  GET  /race/<ARTIFACT_NAME>   -> the large artifact (200), after LATENCY_MS delay.
                                  Increments the fetch counter exactly once per
                                  fully-served response start.
  GET  /__count__              -> JSON: {"fetches": N}
  GET  /__digest__             -> JSON: {"sha256": "...", "size": N, "name": "..."}
  POST /__reset__              -> resets the fetch counter to 0 (JSON {"fetches":0})
  GET  /healthz                -> "ok" (no counter side-effect)

The artifact bytes are generated deterministically from a fixed seed so the
SHA-256 is stable across container restarts WITHOUT shipping a 256 MB blob in
the image. We stream it in chunks to keep memory flat.

Environment
-----------
  ARTIFACT_SIZE_BYTES  default 268435456 (256 MiB)
  ARTIFACT_NAME        default big-artifact.bin
  LATENCY_MS           default 1500  (delay before the body is sent)
  PORT                 default 9999
  SEED                 default 1624  (deterministic content seed)
"""

import hashlib
import io
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ARTIFACT_SIZE_BYTES = int(os.environ.get("ARTIFACT_SIZE_BYTES", str(256 * 1024 * 1024)))
ARTIFACT_NAME = os.environ.get("ARTIFACT_NAME", "big-artifact.bin")
LATENCY_MS = int(os.environ.get("LATENCY_MS", "1500"))
PORT = int(os.environ.get("PORT", "9999"))
SEED = int(os.environ.get("SEED", "1624"))

CHUNK = 1024 * 1024  # 1 MiB streaming chunk

# --- deterministic content generation -------------------------------------------------

def _block(index: int) -> bytes:
    """Deterministic 1 MiB-ish block derived from (SEED, index).

    Uses repeated SHA-256 expansion so the content is pseudo-random yet fully
    reproducible. The same (SEED, ARTIFACT_SIZE_BYTES) always yields the same
    bytes and therefore the same overall digest.
    """
    out = bytearray()
    counter = 0
    base = f"{SEED}:{index}".encode()
    while len(out) < CHUNK:
        out.extend(hashlib.sha256(base + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:CHUNK])


def iter_artifact():
    """Yield the artifact body in CHUNK-sized pieces, totalling ARTIFACT_SIZE_BYTES."""
    remaining = ARTIFACT_SIZE_BYTES
    index = 0
    while remaining > 0:
        blk = _block(index)
        if len(blk) > remaining:
            blk = blk[:remaining]
        yield blk
        remaining -= len(blk)
        index += 1


def compute_digest():
    """Compute (sha256_hex, size) of the artifact without holding it in memory."""
    h = hashlib.sha256()
    size = 0
    for blk in iter_artifact():
        h.update(blk)
        size += len(blk)
    return h.hexdigest(), size


# Computed once at startup; this is the PUBLISHED digest the harness asserts against.
PUBLISHED_SHA256, PUBLISHED_SIZE = compute_digest()

# --- fetch counter --------------------------------------------------------------------

_counter_lock = threading.Lock()
_fetch_count = 0


def _bump_counter():
    global _fetch_count
    with _counter_lock:
        _fetch_count += 1
        return _fetch_count


def _read_counter():
    with _counter_lock:
        return _fetch_count


def _reset_counter():
    global _fetch_count
    with _counter_lock:
        _fetch_count = 0


# --- HTTP handler ---------------------------------------------------------------------

ARTIFACT_PATH = f"/race/{ARTIFACT_NAME}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter logs; one line per request
        sys.stderr.write("[mock-upstream] %s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, code, obj):
        body = (
            "{"
            + ",".join(f'"{k}":{_json_val(v)}' for k, v in obj.items())
            + "}"
        ).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if path == "/__count__":
            self._json(200, {"fetches": _read_counter()})
            return
        if path == "/__digest__":
            self._json(
                200,
                {
                    "sha256": PUBLISHED_SHA256,
                    "size": PUBLISHED_SIZE,
                    "name": ARTIFACT_NAME,
                },
            )
            return
        if path == ARTIFACT_PATH:
            self._serve_artifact()
            return
        self.send_error(404, "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/__reset__":
            _reset_counter()
            self._json(200, {"fetches": 0})
            return
        self.send_error(404, "not found")

    def _serve_artifact(self):
        # Count the fetch BEFORE serving so even a client that disconnects
        # mid-stream is counted as a real upstream hit. This makes the
        # "exactly one upstream fetch" assertion strict.
        n = _bump_counter()
        self.log_message("ARTIFACT FETCH #%d begins (latency=%dms)", n, LATENCY_MS)

        # Widen the race window: delay before sending the body. This is the
        # critical knob that lets N replica requests pile up on a cold cache.
        if LATENCY_MS > 0:
            time.sleep(LATENCY_MS / 1000.0)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(PUBLISHED_SIZE))
        self.send_header("X-Mock-Upstream-Fetch", str(n))
        self.end_headers()
        try:
            for blk in iter_artifact():
                self.wfile.write(blk)
        except (BrokenPipeError, ConnectionResetError):
            self.log_message("client disconnected during ARTIFACT FETCH #%d", n)


def _json_val(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    sys.stderr.write(
        "[mock-upstream] artifact=%s size=%d bytes sha256=%s latency=%dms port=%d\n"
        % (ARTIFACT_NAME, PUBLISHED_SIZE, PUBLISHED_SHA256, LATENCY_MS, PORT)
    )
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
