#!/usr/bin/env python3
"""Maven upstream for scripts/perf/proxy-scan-db-update.sh (#6300).

Serves PERF_N jars `com.example.perf:perf-<i>:1.0.0`, each a few hundred bytes
with its own pom.properties (so the backend establishes the coordinate and
Grype catalogs one component, which no advisory names), built at start-up with
fixed timestamps. Control endpoints:

  GET /__hits     {"count": n}   GETs under /maven2/ since start (or reset)
  POST /__reset   zero the count
  GET /__digests  {"<maven path>": "<sha256>"} for every jar
  GET /__readyz   "ok"

Stdlib only.
"""
import hashlib
import io
import json
import os
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

N = int(os.environ.get("PERF_N", "200"))
PORT = int(os.environ.get("MOCK_PORT", "80"))
FIXED = (2020, 1, 1, 0, 0, 0)
FILES = {}
LOCK = threading.Lock()
HITS = 0


def jar(group, artifact, version):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in [
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
            (
                f"META-INF/maven/{group}/{artifact}/pom.properties",
                f"groupId={group}\nartifactId={artifact}\nversion={version}\n".encode(),
            ),
            (f"com/example/perf/{artifact}.txt", artifact.encode()),
        ]:
            info = zipfile.ZipInfo(name, FIXED)
            z.writestr(info, body)
    return buf.getvalue()


def pom(group, artifact, version):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        f"  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n"
        f"  <version>{version}</version>\n  <packaging>jar</packaging>\n</project>\n"
    ).encode()


DIGESTS = {}
for i in range(N):
    a = f"perf-{i}"
    base = f"/maven2/com/example/perf/{a}/1.0.0/{a}-1.0.0"
    body = jar("com.example.perf", a, "1.0.0")
    FILES[base + ".jar"] = body
    FILES[base + ".jar.sha1"] = hashlib.sha1(body).hexdigest().encode()
    FILES[base + ".pom"] = pom("com.example.perf", a, "1.0.0")
    DIGESTS[base[len("/maven2/"):] + ".jar"] = hashlib.sha256(body).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        global HITS
        path = self.path.split("?", 1)[0]
        if path == "/__readyz":
            return self.send(200, b"ok", "text/plain")
        if path == "/__hits":
            return self.send(200, json.dumps({"count": HITS}).encode(), "application/json")
        if path == "/__digests":
            return self.send(200, json.dumps(DIGESTS).encode(), "application/json")
        if path.startswith("/maven2/"):
            with LOCK:
                HITS += 1
        body = FILES.get(path)
        if body is None:
            return self.send(404, b"not found", "text/plain")
        return self.send(200, body)

    do_HEAD = do_GET

    def do_POST(self):
        global HITS
        if self.path == "/__reset":
            with LOCK:
                HITS = 0
            return self.send(200, b"ok", "text/plain")
        return self.send(404, b"not found", "text/plain")


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
