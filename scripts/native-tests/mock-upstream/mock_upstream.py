#!/usr/bin/env python3
"""ETag / counter / mutation-aware mock upstream for cache-correctness E2E tests.

This is a deliberately small HTTP server used by `test-proxy-cache-correctness.sh`
and `test-virtual-resolution.sh` to give the artifact-keeper proxy a *controllable*
upstream. Unlike a static nginx fixture it can:

  * count requests per path (to assert immutable artifacts are fetched exactly once),
  * answer conditional requests (If-None-Match / If-Modified-Since -> 304) on
    GET *and* HEAD -- the backend revalidates an expired TTL with a conditional
    HEAD, not a GET (#3950),
  * MUTATE a resource between requests (to assert mutable paths revalidate),
  * 404 a path then "publish" it (to assert negative-cache TTL expiry),
  * (optionally) inject latency.

It also serves a handful of Maven/PyPI shaped paths so the virtual-resolution
regression tests (#1562, #1595) have a deterministic remote member.

CONTROL PLANE (out-of-band, never proxied through artifact-keeper):
  GET  /__mock__/health                       -> 200 "ok"
  GET  /__mock__/count?path=/p                 -> {"path": "/p", "count": N}
  GET  /__mock__/count_all                     -> {"/p": N, ...}
  POST /__mock__/reset                         -> zero all counters
  POST /__mock__/mutate?path=/p                -> change body+ETag of a mutable path
  POST /__mock__/publish?path=/p   (body=data) -> make a previously-404 path exist
  POST /__mock__/unpublish?path=/p             -> make a path 404 again
  POST /__mock__/latency?ms=N                  -> set artificial per-response latency

DATA PLANE (what artifact-keeper's remote repo proxies):
  Immutable example:  /maven2/com/example/widget/1.0.0/widget-1.0.0.jar
  Mutable example:    /maven2/com/example/widget/maven-metadata.xml
  Plugin-prefix (1595): /maven2/org/example/plugins/maven-metadata.xml
  Parent POM (1562):    /maven2/com/example/parent/1.0.0/parent-1.0.0.pom
  PyPI simple index:  /simple/<name>/  (mutable) and the wheel file (immutable)

The server is intentionally self-contained (stdlib only) so it can run either
standalone (`python3 mock_upstream.py --port 9101`) or inside a tiny container.
"""

import argparse
import hashlib
import io
import json
import threading
import time
import zipfile
from email.utils import formatdate, parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Resource:
    """A single served path with body, content-type, mutability and a counter."""

    def __init__(self, body: bytes, content_type: str, mutable: bool, exists: bool = True):
        self.body = body
        self.content_type = content_type
        self.mutable = mutable
        self.exists = exists
        # Number of DATA-PLANE fetches that returned a BODY (a 200 GET). A HEAD
        # never returns a body and so never bumps this -- see `_serve`.
        self.count = 0
        # Conditional requests (GET or HEAD) answered with 304.
        self.revalidations = 0
        self.last_modified = time.time()
        self.etag = self._compute_etag()

    def _compute_etag(self) -> str:
        return '"' + hashlib.sha256(self.body).hexdigest()[:32] + '"'

    def set_body(self, body: bytes):
        self.body = body
        self.last_modified = time.time()
        self.etag = self._compute_etag()


class MockState:
    def __init__(self):
        self.lock = threading.Lock()
        self.latency_ms = 0
        self.resources: dict[str, Resource] = {}
        self._seed()

    def _seed(self):
        # --- Immutable: versioned Maven jar (cache forever) ---
        jar = b"PK\x03\x04" + b"immutable-widget-jar-v1.0.0-payload" * 16
        self.resources["/maven2/com/example/widget/1.0.0/widget-1.0.0.jar"] = Resource(
            jar, "application/java-archive", mutable=False
        )

        # --- Mutable: maven-metadata.xml (short TTL + revalidate) ---
        md_v1 = self._maven_metadata("com.example", "widget", ["1.0.0"])
        self.resources["/maven2/com/example/widget/maven-metadata.xml"] = Resource(
            md_v1, "text/xml", mutable=True
        )

        # --- #1595: group-level plugin-prefix metadata (mutable, remote-only) ---
        prefix_md = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b"<metadata>\n"
            b"  <plugins>\n"
            b"    <plugin>\n"
            b"      <name>Example Maven Plugin</name>\n"
            b"      <prefix>example</prefix>\n"
            b"      <artifactId>example-maven-plugin</artifactId>\n"
            b"    </plugin>\n"
            b"  </plugins>\n"
            b"</metadata>\n"
        )
        self.resources["/maven2/org/example/plugins/maven-metadata.xml"] = Resource(
            prefix_md, "text/xml", mutable=True
        )

        # --- #1562: remote-only parent POM (immutable; must resolve via virtual) ---
        parent_pom = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            b"  <modelVersion>4.0.0</modelVersion>\n"
            b"  <groupId>com.example</groupId>\n"
            b"  <artifactId>parent</artifactId>\n"
            b"  <version>1.0.0</version>\n"
            b"  <packaging>pom</packaging>\n"
            b"</project>\n"
        )
        self.resources["/maven2/com/example/parent/1.0.0/parent-1.0.0.pom"] = Resource(
            parent_pom, "text/xml", mutable=False
        )
        # A SECOND remote-only parent POM used ONLY for the virtual first-request
        # assertion. It is never fetched via the remote member directly, so the
        # virtual path cannot be masked by a warm cache (the real #1562 condition
        # is "remote-only artifact not yet cached, requested through the virtual").
        vonly_pom = parent_pom.replace(b"<artifactId>parent</artifactId>",
                                       b"<artifactId>vonly-parent</artifactId>")
        self.resources["/maven2/com/example/vonly-parent/1.0.0/vonly-parent-1.0.0.pom"] = Resource(
            vonly_pom, "text/xml", mutable=False
        )

        # --- PyPI: simple index (mutable) + wheel (immutable) for #1600-style remote-only pkg ---
        # `lonelydep` exists ONLY on the mock upstream (the remote member).
        whl_name = "lonelydep-2.3.0-py3-none-any.whl"
        whl_path = "/packages/ld/lonelydep/" + whl_name
        wheel = MockState._wheel("lonelydep", "2.3.0")
        self.resources[whl_path] = Resource(
            wheel, "application/octet-stream", mutable=False
        )
        simple = (
            "<!DOCTYPE html><html><head>"
            '<meta name="pypi:repository-version" content="1.0">'
            "<title>Links for lonelydep</title></head><body>"
            "<h1>Links for lonelydep</h1>"
            f'<a href="{whl_path}">{whl_name}</a><br/>'
            "</body></html>"
        ).encode()
        self.resources["/simple/lonelydep/"] = Resource(
            simple, "text/html", mutable=True
        )

        # --- Negative-cache target: starts as NON-existent, gets published later ---
        self.resources["/maven2/com/example/late/1.0.0/late-1.0.0.jar"] = Resource(
            b"", "application/java-archive", mutable=False, exists=False
        )

    @staticmethod
    def _wheel(name: str, version: str) -> bytes:
        """A REAL (if minimal) PEP 427 wheel, in memory.

        It has to be a genuine zip: `pip download` opens the archive to read
        `METADATA` even under `--no-deps`, so a fake `PK\\x03\\x04` blob makes
        the PEP-503 end-to-end assertion in test-virtual-resolution.sh fail
        with "Wheel ... is invalid" no matter what the registry does (#3950).

        Deterministic: fixed timestamps and no compression, so the bytes — and
        therefore the ETag the mock derives from them — are stable across
        restarts. ~600 bytes.
        """
        dist_info = f"{name}-{version}.dist-info"
        members = [
            (
                f"{dist_info}/METADATA",
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
            ),
            (
                f"{dist_info}/WHEEL",
                "Wheel-Version: 1.0\nGenerator: artifact-keeper-mock-upstream\n"
                "Root-Is-Purelib: true\nTag: py3-none-any\n",
            ),
            # RECORD may list entries without hash/size; pip does not require
            # them for a download.
            (
                f"{dist_info}/RECORD",
                f"{dist_info}/METADATA,,\n{dist_info}/WHEEL,,\n"
                f"{dist_info}/RECORD,,\n",
            ),
        ]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            for member_name, text in members:
                info = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
                info.external_attr = 0o644 << 16
                zf.writestr(info, text)
        return buf.getvalue()

    @staticmethod
    def _maven_metadata(group: str, artifact: str, versions: list[str]) -> bytes:
        vers = "".join(f"      <version>{v}</version>\n" for v in versions)
        latest = versions[-1]
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<metadata>\n"
            f"  <groupId>{group}</groupId>\n"
            f"  <artifactId>{artifact}</artifactId>\n"
            "  <versioning>\n"
            f"    <latest>{latest}</latest>\n"
            f"    <release>{latest}</release>\n"
            "    <versions>\n"
            f"{vers}"
            "    </versions>\n"
            "  </versioning>\n"
            "</metadata>\n"
        ).encode()


STATE = MockState()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Quieter logs; comment out to debug.
    def log_message(self, fmt, *args):  # noqa: N802
        pass

    # ---- helpers -----------------------------------------------------------
    def _json(self, code: int, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code: int, text: str):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _maybe_sleep(self):
        if STATE.latency_ms:
            time.sleep(STATE.latency_ms / 1000.0)

    def _is_not_modified(self, res) -> bool:
        """Evaluate If-None-Match / If-Modified-Since against `res`.

        RFC 9110 §13.1.1/§13.1.3 apply to any method that would otherwise be a
        200, so this is shared by GET and HEAD rather than living in do_GET.
        """
        inm = self.headers.get("If-None-Match")
        ims = self.headers.get("If-Modified-Since")
        if inm is not None and inm.strip() == res.etag:
            return True
        if ims is not None:
            try:
                ims_dt = parsedate_to_datetime(ims).timestamp()
                return int(res.last_modified) <= int(ims_dt)
            except (TypeError, ValueError):
                return False
        return False

    def _serve(self, path: str, with_body: bool):
        """Serve a data-plane path. `with_body` False is the HEAD form.

        HEAD has to answer conditionally, because the backend's TTL-expiry
        revalidation IS a conditional HEAD: `UpstreamClient::check_etag_changed`
        (backend/src/services/proxy_service.rs:3165) sends
        `HEAD` + `If-None-Match` and reads a 304 as "unchanged", a 200 whose
        ETag matches as "unchanged", and anything else as "refetch". A HEAD
        that answers an unconditional 200 with no ETag — what this mock used to
        do — reads as "changed" every time and never counts as a revalidation,
        which is why the cache-correctness suite saw revalidations=0 after the
        TTL expired (#3950).

        COUNTER CONTRACT: a HEAD never bumps `count`, only `revalidations`.
        `count` means "upstream served a body" and is what the immutable /
        within-TTL assertions read; the backend's revalidation is a HEAD that,
        when upstream HAS changed, is followed by a full GET, so counting the
        HEAD too would double-count that single refill.
        """
        self._maybe_sleep()
        with STATE.lock:
            res = STATE.resources.get(path)
            if res is None or not res.exists:
                if with_body:
                    return self._text(404, "not found")
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None

            if self._is_not_modified(res):
                res.revalidations += 1
                self.send_response(304)
                self.send_header("ETag", res.etag)
                self.send_header("Last-Modified", formatdate(res.last_modified, usegmt=True))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None

            if with_body:
                res.count += 1
            body = res.body
            etag = res.etag
            ctype = res.content_type
            lm = res.last_modified

        # HEAD sends exactly the headers GET would, and no body (RFC 9110 §9.3.2).
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", formatdate(lm, usegmt=True))
        # Mark immutable resources cacheable-forever; mutable get a short hint.
        self.end_headers()
        if with_body:
            self.wfile.write(body)
        return None

    # ---- GET / HEAD --------------------------------------------------------
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/__mock__/"):
            return self._control_get(path, parse_qs(parsed.query))

        return self._serve(path, with_body=True)

    def do_HEAD(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        # The control plane is GET-only; a HEAD of it is not a data-plane path
        # either, so answer 405 rather than inventing a resource.
        if path.startswith("/__mock__/"):
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None

        return self._serve(path, with_body=False)

    # ---- POST (control plane only) ----------------------------------------
    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/__mock__/"):
            return self._text(405, "method not allowed")
        return self._control_post(parsed.path, parse_qs(parsed.query))

    # ---- control plane -----------------------------------------------------
    def _control_get(self, path, q):
        if path == "/__mock__/health":
            return self._text(200, "ok")
        if path == "/__mock__/count":
            target = q.get("path", [""])[0]
            with STATE.lock:
                res = STATE.resources.get(target)
                count = res.count if res else 0
                reval = res.revalidations if res else 0
            return self._json(200, {"path": target, "count": count, "revalidations": reval})
        if path == "/__mock__/count_all":
            with STATE.lock:
                data = {p: {"count": r.count, "revalidations": r.revalidations}
                        for p, r in STATE.resources.items()}
            return self._json(200, data)
        return self._text(404, "unknown control endpoint")

    def _control_post(self, path, q):
        if path == "/__mock__/reset":
            with STATE.lock:
                for r in STATE.resources.values():
                    r.count = 0
                    r.revalidations = 0
            return self._text(200, "reset")

        if path == "/__mock__/latency":
            ms = int(q.get("ms", ["0"])[0])
            with STATE.lock:
                STATE.latency_ms = ms
            return self._text(200, f"latency={ms}ms")

        if path == "/__mock__/mutate":
            target = q.get("path", [""])[0]
            with STATE.lock:
                res = STATE.resources.get(target)
                if res is None:
                    return self._text(404, "no such path")
                # Produce a deterministically-different body (new ETag).
                if target.endswith("maven-metadata.xml") and b"<versioning>" in res.body:
                    res.set_body(MockState._maven_metadata(
                        "com.example", "widget", ["1.0.0", "1.1.0"]))
                elif target.endswith("/simple/lonelydep/"):
                    res.set_body(res.body.replace(b"2.3.0", b"2.4.0"))
                else:
                    res.set_body(res.body + b"\n<!-- mutated -->")
            return self._text(200, "mutated")

        if path == "/__mock__/publish":
            target = q.get("path", [""])[0]
            length = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(length) if length else b"published-payload"
            with STATE.lock:
                res = STATE.resources.get(target)
                if res is None:
                    res = Resource(data, "application/octet-stream", mutable=False)
                    STATE.resources[target] = res
                else:
                    res.set_body(data)
                    res.exists = True
            return self._text(200, "published")

        if path == "/__mock__/unpublish":
            target = q.get("path", [""])[0]
            with STATE.lock:
                res = STATE.resources.get(target)
                if res:
                    res.exists = False
            return self._text(200, "unpublished")

        return self._text(404, "unknown control endpoint")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9101)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock-upstream listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        # Allow clean shutdown on Ctrl+C; cleanup is handled in finally.
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
