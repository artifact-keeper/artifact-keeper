#!/usr/bin/env python3
"""Thin HTTP wrapper around the oscap CLI for use as a sidecar scanner.

Endpoints:
    GET  /health  - Health check with oscap version
    POST /scan    - Run XCCDF compliance evaluation and return JSON findings
"""

import json
import os
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("OPENSCAP_PORT", "8091"))

# Allowed base directories for scan paths (container-extracted filesystems)
ALLOWED_SCAN_DIRS = os.environ.get(
    "OPENSCAP_ALLOWED_SCAN_DIRS", "/tmp/:/var/tmp/"
).split(":")


def validate_scan_path(path):
    """Validate that a scan path is safe (absolute, real, under allowed dirs)."""
    if not path or not os.path.isabs(path):
        return None
    real_path = os.path.realpath(path)
    for allowed in ALLOWED_SCAN_DIRS:
        if allowed and real_path.startswith(os.path.realpath(allowed)):
            return real_path
    return None


# XCCDF 1.2 namespace
XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"

# Auto-detect available SCAP content
SSG_CONTENT_DIR = "/usr/share/xml/scap/ssg/content"


def find_scap_content():
    """Return a dict mapping OS label to datastream file path."""
    content = {}
    if not os.path.isdir(SSG_CONTENT_DIR):
        return content
    for f in sorted(os.listdir(SSG_CONTENT_DIR)):
        if f.startswith("ssg-") and f.endswith("-ds.xml"):
            label = f.replace("ssg-", "").replace("-ds.xml", "")
            content[label] = os.path.join(SSG_CONTENT_DIR, f)
    return content


def detect_os_from_path(scan_path):
    """Try to detect the OS family from os-release in an extracted filesystem.

    scan_path must already be validated by validate_scan_path().
    """
    os_release = os.path.realpath(os.path.join(scan_path, "etc", "os-release"))
    # Verify the resolved path is still under the scan_path (prevent traversal)
    if not os_release.startswith(os.path.realpath(scan_path)):
        return None
    if not os.path.exists(os_release):
        return None
    try:
        with open(os_release) as f:
            for line in f:
                if line.startswith("ID="):
                    return line.strip().split("=", 1)[1].strip('"').lower()
    except OSError:
        pass
    return None


def select_content_file(scan_path, available_content):
    """Pick the best SCAP content file for the target being scanned."""
    os_id = detect_os_from_path(scan_path)

    if os_id and os_id in available_content:
        return available_content[os_id]

    # Common mappings
    mappings = {
        "rhel": "rhel9",
        "centos": "centos8",
        "rocky": "rhel9",
        "alma": "rhel9",
        "ol": "ol8",
        "fedora": "fedora",
    }
    if os_id:
        for prefix, key in mappings.items():
            if os_id.startswith(prefix) and key in available_content:
                return available_content[key]

    # Fallback: use fedora content (broadest compatibility)
    if "fedora" in available_content:
        return available_content["fedora"]

    # Last resort: first available
    if available_content:
        return next(iter(available_content.values()))

    return None


def list_profiles(content_file):
    """List available profile IDs in the given SCAP content file."""
    try:
        result = subprocess.run(
            ["oscap", "info", "--profiles", content_file],
            capture_output=True, text=True, timeout=30,
        )
        profiles = []
        for line in result.stdout.strip().splitlines():
            if ":" in line:
                profiles.append(line.split(":")[0].strip())
            elif line.strip():
                profiles.append(line.strip())
        return profiles
    except Exception:
        return []


def run_oscap_scan(scan_path, profile, content_file):
    """Run oscap xccdf eval and return parsed findings."""
    results_file = f"/tmp/oscap-results-{uuid.uuid4()}.xml"

    cmd = [
        "oscap", "xccdf", "eval",
        "--profile", profile,
        "--results", results_file,
    ]

    # If scanning an extracted filesystem (chroot), use --chroot
    if os.path.isdir(os.path.join(scan_path, "etc")):
        cmd.extend(["--chroot", scan_path])

    cmd.append(content_file)

    try:
        # oscap returns exit code 2 for "some rules failed" which is normal
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if result.returncode not in (0, 2):
            return {
                "findings": [],
                "error": f"oscap exited with code {result.returncode}: {result.stderr[:500]}",
            }
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "oscap scan timed out (10 minutes)"}
    except Exception as e:
        return {"findings": [], "error": str(e)}

    # Parse XCCDF results XML
    findings = parse_xccdf_results(results_file, content_file)

    # Cleanup
    try:
        os.unlink(results_file)
    except OSError:
        pass

    return {"findings": findings, "profile": profile}


def parse_xccdf_results(results_file, content_file):
    """Parse XCCDF results XML into a list of finding dicts."""
    if not os.path.exists(results_file):
        return []

    try:
        tree = ET.parse(results_file)
        root = tree.getroot()
    except ET.ParseError:
        return []

    # Build a rule metadata lookup from the benchmark content
    rule_meta = {}
    try:
        content_tree = ET.parse(content_file)
        content_root = content_tree.getroot()
        for rule in content_root.iter(f"{{{XCCDF_NS}}}Rule"):
            rule_id = rule.get("id", "")
            title_el = rule.find(f"{{{XCCDF_NS}}}title")
            desc_el = rule.find(f"{{{XCCDF_NS}}}description")
            severity = rule.get("severity", "unknown")
            rule_meta[rule_id] = {
                "title": title_el.text if title_el is not None else rule_id,
                "description": desc_el.text if desc_el is not None else None,
                "severity": severity,
            }
    except Exception:
        pass

    findings = []
    for rule_result in root.iter(f"{{{XCCDF_NS}}}rule-result"):
        idref = rule_result.get("idref", "")
        result_el = rule_result.find(f"{{{XCCDF_NS}}}result")
        result_val = result_el.text if result_el is not None else "unknown"

        # Only report failures
        if result_val not in ("fail", "error", "unknown"):
            continue

        meta = rule_meta.get(idref, {})
        severity = rule_result.get("severity") or meta.get("severity", "unknown")

        # Collect references (CCE, NIST, etc.)
        references = []
        for ident in rule_result.findall(f"{{{XCCDF_NS}}}ident"):
            if ident.text:
                references.append(ident.text)

        findings.append({
            "rule_id": idref,
            "result": result_val,
            "severity": severity,
            "title": meta.get("title", idref),
            "description": meta.get("description"),
            "references": references,
        })

    return findings


class OpenSCAPHandler(BaseHTTPRequestHandler):
    available_content = find_scap_content()

    def do_GET(self):
        if self.path == "/health":
            try:
                version = subprocess.run(
                    ["oscap", "--version"], capture_output=True, text=True, timeout=5,
                ).stdout.strip().splitlines()[0]
            except Exception:
                version = "unknown"
            self._json_response(200, {
                "status": "ok",
                "version": version,
                "content_files": list(self.available_content.keys()),
            })
        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/scan":
            self._json_response(404, {"error": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._json_response(400, {"error": "invalid JSON"})
            return

        raw_path = req.get("path", "")
        profile = req.get("profile", "xccdf_org.ssgproject.content_profile_standard")

        scan_path = validate_scan_path(raw_path)
        if not scan_path or not os.path.isdir(scan_path):
            self._json_response(400, {"error": "scan path not found or not allowed"})
            return

        content_file = select_content_file(scan_path, self.available_content)
        if not content_file:
            self._json_response(500, {
                "error": "no SCAP content available",
                "findings": [],
            })
            return

        # Verify the requested profile exists
        profiles = list_profiles(content_file)
        if profile not in profiles and profiles:
            # Fall back to first available profile
            profile = profiles[0]

        result = run_oscap_scan(scan_path, profile, content_file)
        self._json_response(200, result)

    def _json_response(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[openscap-wrapper] {fmt % args}\n")


if __name__ == "__main__":
    print(f"OpenSCAP wrapper starting on port {PORT}", flush=True)
    content = find_scap_content()
    print(f"Available SCAP content: {list(content.keys())}", flush=True)
    server = HTTPServer(("0.0.0.0", PORT), OpenSCAPHandler)
    server.serve_forever()
