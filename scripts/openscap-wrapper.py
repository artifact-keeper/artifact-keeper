#!/usr/bin/env python3
"""Thin HTTP wrapper around the oscap CLI for use as a sidecar scanner.

Endpoints:
    GET  /health  - Health check with oscap version
    POST /scan    - Run XCCDF compliance evaluation and return JSON findings

What a scan evaluates (#6000)
-----------------------------
The backend unpacks the artifact's root filesystem (a container image's
layers, applied in order) into the shared scan workspace and POSTs that
directory. The wrapper evaluates THAT tree, offline, by pointing oscap's
probes at it with the ``OSCAP_PROBE_ROOT`` environment variable. oscap 1.3 has
no ``--chroot`` option (``oscap-chroot`` is a shell wrapper that sets the same
variable), and every probe that does not handle the root itself (``rpminfo``,
for one) ``chroot(2)``s into it, which needs ``CAP_SYS_CHROOT``. There are two
ways to get it:

* default: the wrapper runs as a non-root UID and starts oscap in a fresh user
  namespace, where it is root over the files the backend wrote (their owner
  UID is mapped to 0). Rootless Podman allows this out of the box; Docker's
  default seccomp profile blocks ``unshare(CLONE_NEWUSER)``.
* root mode, opt-in: ``OPENSCAP_RUN_AS_ROOT=true`` with the container started
  as root (compose ``user: "0"``). oscap is started without a user namespace,
  but NOT as full root: the child drops to the image's ``oscap`` UID (1001),
  keeps only ``CAP_SYS_CHROOT`` (plus ``CAP_DAC_READ_SEARCH``, read-only
  access to every file, when the container grants it), shrinks its
  capability bounding set to those, and sets ``no_new_privs``. librpm, which the ``rpminfo`` probe drives
  inside the chroot, reads the image's own rpm configuration, so the probe
  child must not hold real root.

When neither is available the scan is answered ``not_applicable`` with that
reason. It is never evaluated against this container's own filesystem, which
is what every scan did before.

Symlinks: the backend writes every symlink in the tree with a relative target
that resolves inside the tree, so a probe that does not chroot (oscap's own
offline mode for the file probes) cannot be led out of it either.

A scan that cannot be evaluated meaningfully is ``not_applicable``, never a
clean pass: no ``os-release`` in the tree, no shipped datastream for its OS,
or a profile in which no rule applies to it. A profile that no shipped
datastream defines is an error naming the available profiles, never a silent
substitute.
"""

import ctypes
import json
import os
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("OPENSCAP_PORT", "8091"))

# Allowed base directories for scan paths (container-extracted filesystems).
#
# The backend writes per-artifact scan workspaces under SCAN_WORKSPACE_PATH
# (defaults to /scan-workspace) and sends that path to the wrapper. The
# wrapper container mounts the same volume at /scan-workspace. Keeping
# /scan-workspace/ in the default allowlist means the out-of-the-box
# docker-compose and Helm deployments work without per-deployment env
# tweaks; otherwise every fresh install hits "scan path not found or not
# allowed" (issue #1466).
#
# Operators who customise SCAN_WORKSPACE_PATH or want to lock the wrapper
# down further can still override via the OPENSCAP_ALLOWED_SCAN_DIRS env
# var (colon-separated list of allowed base dirs).
ALLOWED_SCAN_DIRS = os.environ.get(
    "OPENSCAP_ALLOWED_SCAN_DIRS", "/scan-workspace/:/tmp/:/var/tmp/"
).split(":")

# The profile evaluated when a request names none. It must exist in the
# shipped content (#6000: the old default, content_profile_standard, is in
# neither RHEL 9 family datastream). Kept in step with the backend's
# OPENSCAP_PROFILE default in backend/src/config.rs.
DEFAULT_PROFILE = "xccdf_org.ssgproject.content_profile_cis_server_l1"

PROFILE_RE = re.compile(r"[a-zA-Z0-9._\-]+")

# Where an unpacked root filesystem identifies its OS, in lookup order.
OS_RELEASE_PATHS = ("etc/os-release", "usr/lib/os-release")

# os-release ID -> the SSG content label prefix, where they differ.
OS_ID_CONTENT_PREFIX = {"centos": "cs", "sles": "sle", "opensuse-leap": "opensuse"}

# Rules whose verdict depends on file ownership. The backend unpacks image
# layers without root, so every file in the tree is owned by the scanning UID
# (shown as root inside the user namespace): an owner or group-owner check
# reads that, not the image's own ownership. Those rules are reported as not
# evaluated instead of as a pass or a fail. Matched against the rule id after
# `content_rule_`.
OWNERSHIP_RULE_RE = re.compile(
    r"^(file|dir|directory)_(group_?)?owner"
    r"|_(group_?)?ownership$"
    r"|unowned|ungroupowned"
    r"|_(root|system)_owned$"
    r"|^file_etc_security_opasswd$"
)

# XCCDF results that mean the rule was evaluated against the target.
EVALUATED_RESULTS = ("pass", "fail", "error", "unknown", "fixed")
# Results reported as findings.
FINDING_RESULTS = ("fail", "error", "unknown")

# Linux unshare(2) flag.
CLONE_NEWUSER = 0x10000000
# Capability numbers (linux/capability.h).
CAP_DAC_READ_SEARCH = 2
CAP_SYS_CHROOT = 18
# The only capabilities a root-mode probe child keeps: CAP_SYS_CHROOT always,
# CAP_DAC_READ_SEARCH (read any file, write none) when the container grants it.
# Neither Docker nor Podman grants CAP_DAC_READ_SEARCH by default; without it
# the child reads the tree as its owner, so a file the image ships at mode
# 0000 (/etc/shadow) cannot be read and the rules that read it report error.
ROOT_MODE_REQUIRED_CAPS = (CAP_SYS_CHROOT,)
ROOT_MODE_OPTIONAL_CAPS = (CAP_DAC_READ_SEARCH,)
# prctl(2) options.
PR_CAPBSET_DROP = 24
PR_SET_KEEPCAPS = 8
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
_LINUX_CAPABILITY_VERSION_3 = 0x20080522

# Opt-in root mode (see the module docstring). Read once at start-up.
RUN_AS_ROOT_ENV = "OPENSCAP_RUN_AS_ROOT"
# The UID a root-mode probe child drops to: the image's `oscap` user.
SCAN_UID = int(os.environ.get("OPENSCAP_SCAN_UID", "1001"))

# How to get real results, quoted in every "cannot evaluate here" reason.
ENABLE_HINT = (
    "run the sidecar on rootless Podman, allow unprivileged user namespaces "
    "for it (for example seccomp=unconfined), or start it as root with "
    f"{RUN_AS_ROOT_ENV}=true"
)


def _is_under(path, base):
    """True when the real `path` is `base` itself or below it."""
    try:
        return os.path.commonpath([path, base]) == base
    except ValueError:
        return False


def validate_scan_path(path):
    """Validate that a scan path is safe (absolute, real, under allowed dirs)."""
    if not path or not os.path.isabs(path):
        return None
    real_path = os.path.realpath(path)
    for allowed in ALLOWED_SCAN_DIRS:
        if allowed and _is_under(real_path, os.path.realpath(allowed)):
            return real_path
    return None


# XCCDF 1.2 namespace
XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"

# Auto-detect available SCAP content
SSG_CONTENT_DIR = "/usr/share/xml/scap/ssg/content"


def find_scap_content(content_dir=SSG_CONTENT_DIR):
    """Return a dict mapping OS label to datastream file path."""
    content = {}
    if not os.path.isdir(content_dir):
        return content
    for f in sorted(os.listdir(content_dir)):
        if f.startswith("ssg-") and f.endswith("-ds.xml"):
            label = f[len("ssg-"):-len("-ds.xml")]
            content[label] = os.path.join(content_dir, f)
    return content


def resolve_in_root(root, rel_path, max_links=40):
    """Resolve `rel_path` inside `root` with chroot semantics.

    Symlinks are followed as the target system would follow them: an absolute
    link target restarts at `root`, and `..` never climbs above it. Returns
    the resolved host path, or None when the link chain is too deep. Nothing
    outside `root` is ever returned.
    """
    root = os.path.realpath(root)
    pending = [c for c in rel_path.split("/") if c not in ("", ".")]
    pending.reverse()
    resolved = []
    links = 0
    while pending:
        part = pending.pop()
        if part == "..":
            if resolved:
                resolved.pop()
            continue
        candidate = os.path.join(root, *resolved, part)
        if os.path.islink(candidate):
            links += 1
            if links > max_links:
                return None
            target = os.readlink(candidate)
            if target.startswith("/"):
                resolved = []
            more = [c for c in target.split("/") if c not in ("", ".")]
            pending.extend(reversed(more))
            continue
        resolved.append(part)
    return os.path.join(root, *resolved)


def read_os_release(scan_path):
    """Parse the unpacked tree's os-release into a dict, or None.

    scan_path must already be validated by validate_scan_path().
    """
    for rel in OS_RELEASE_PATHS:
        path = resolve_in_root(scan_path, rel)
        if not path or not os.path.isfile(path):
            continue
        fields = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    fields[key.strip()] = value.strip().strip("\"'")
        except OSError:
            continue
        if fields.get("ID"):
            return fields
    return None


def content_labels_for(os_release):
    """The SSG content labels that describe this OS, most specific first.

    `ID=rhel VERSION_ID=9.6` -> rhel9; `ID=centos VERSION_ID=9` -> cs9;
    `ID=ubuntu VERSION_ID=22.04` -> ubuntu2204; `ID=fedora` -> fedora.
    """
    os_id = os_release.get("ID", "").lower()
    if not os_id:
        return []
    prefix = OS_ID_CONTENT_PREFIX.get(os_id, os_id)
    version = os_release.get("VERSION_ID", "")
    major = version.split(".", 1)[0]
    labels = []
    if version:
        labels.append(prefix + version.replace(".", ""))
    if major:
        labels.append(prefix + major)
    labels.append(prefix)
    seen = []
    for label in labels:
        if label not in seen:
            seen.append(label)
    return seen


def select_content_file(os_release, available_content):
    """Pick the datastream written for this OS, or None.

    There is no fallback to another OS's content: SSG checks each rule's
    platform first, so a datastream for another OS marks every rule
    `notapplicable` and the scan would read as clean.
    """
    for label in content_labels_for(os_release):
        if label in available_content:
            return label, available_content[label]
    return None


_PROFILE_CACHE = {}


def list_profiles(content_file):
    """List available profile IDs in the given SCAP content file.

    The content is baked into the image, so a successful listing is cached
    for the life of the process (each `oscap info` parses a ~30 MB datastream).
    """
    cached = _PROFILE_CACHE.get(content_file)
    if cached is not None:
        return cached
    profiles = _list_profiles_uncached(content_file)
    if profiles:
        _PROFILE_CACHE[content_file] = profiles
    return profiles


def _list_profiles_uncached(content_file):
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


def is_ownership_rule(rule_id):
    """Whether a rule's verdict depends on file ownership (see the regex)."""
    short = rule_id.split("content_rule_", 1)[-1]
    return bool(OWNERSHIP_RULE_RE.search(short))


def run_as_root_requested(environ=None):
    """Whether the operator opted in to root mode."""
    value = (environ if environ is not None else os.environ).get(RUN_AS_ROOT_ENV, "")
    return value.strip().lower() in ("1", "true", "yes", "on")


def isolation_plan(euid, root_requested, userns_blocked):
    """Decide how oscap's probes get CAP_SYS_CHROOT.

    Returns ("root", None), ("userns", None) or (None, reason). Root mode is
    used only when it was asked for AND the process is root; nothing else
    ever runs oscap without a user namespace.
    """
    if root_requested and euid == 0:
        return "root", None
    if not userns_blocked:
        return "userns", None
    if root_requested:
        return None, (
            f"{RUN_AS_ROOT_ENV} is set but the OpenSCAP sidecar is not running as "
            "root (start the container with user \"0\"), and user namespaces are "
            "blocked in this container runtime"
        )
    return None, (
        "the OpenSCAP sidecar cannot evaluate an unpacked filesystem here: user "
        f"namespaces are blocked in this container runtime; {ENABLE_HINT}"
    )


def _userns_preexec(uid, gid):
    """preexec_fn: move the child into a new user namespace as root.

    The single mapping `0 <uid> 1` makes the files the backend wrote (owned by
    the shared scanning UID) root-owned inside the namespace, and gives the
    child CAP_SYS_CHROOT there, which is what oscap's probes need to chroot
    into OSCAP_PROBE_ROOT. No other UID is mapped, so nothing outside the
    tree the process could already touch becomes writable.
    """
    def enter():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.unshare(CLONE_NEWUSER) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
        with open("/proc/self/uid_map", "w") as f:
            f.write(f"0 {uid} 1")
        with open("/proc/self/gid_map", "w") as f:
            f.write(f"0 {gid} 1")
    return enter


def cap_mask(caps):
    """The 64-bit capability mask of `caps`, as the (low, high) u32 words."""
    mask = 0
    for c in caps:
        mask |= 1 << c
    return mask & 0xFFFFFFFF, mask >> 32


def bounding_caps(status_text=None):
    """The capability numbers in this process's bounding set."""
    if status_text is None:
        try:
            with open("/proc/self/status") as f:
                status_text = f.read()
        except OSError:
            return set()
    for line in status_text.splitlines():
        if line.startswith("CapBnd:"):
            mask = int(line.split()[1], 16)
            return {c for c in range(64) if mask & (1 << c)}
    return set()


def root_mode_caps(bounding):
    """What a root-mode child keeps, or None when CAP_SYS_CHROOT is missing."""
    if not all(c in bounding for c in ROOT_MODE_REQUIRED_CAPS):
        return None
    return tuple(ROOT_MODE_REQUIRED_CAPS) + tuple(
        c for c in ROOT_MODE_OPTIONAL_CAPS if c in bounding)


def _last_cap():
    try:
        with open("/proc/sys/kernel/cap_last_cap") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 40


def _root_mode_preexec(scan_uid, keep):
    """preexec_fn for root mode: drop from root to `scan_uid` with `keep` only.

    Runs in the forked child, before exec. Every step must succeed, or the
    child raises and the scan is refused rather than run with more privilege
    than intended.
    """
    def enter():
        libc = ctypes.CDLL(None, use_errno=True)

        def check(rc, what):
            if rc != 0:
                err = ctypes.get_errno()
                raise OSError(err, f"{what}: {os.strerror(err)}")

        # 1. Shrink the bounding set to `keep`: nothing dropped here can come
        #    back, whatever this process execs.
        for cap in range(_last_cap() + 1):
            if cap not in keep:
                check(libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0), f"drop capability {cap}")
        # 2. Keep the permitted set across the UID change, then become the
        #    unprivileged scanning user (supplementary groups cleared, GID 0
        #    kept as the image's arbitrary-UID convention has it).
        check(libc.prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), "PR_SET_KEEPCAPS")
        os.setgroups([])
        os.setgid(0)
        os.setuid(scan_uid)
        # 3. Effective, permitted and inheritable = `keep`.
        low, high = cap_mask(keep)

        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

        class Data(ctypes.Structure):
            _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                        ("inheritable", ctypes.c_uint32)]

        header = Header(_LINUX_CAPABILITY_VERSION_3, 0)
        data = (Data * 2)(Data(low, low, low), Data(high, high, high))
        check(libc.capset(ctypes.byref(header), data), "capset")
        # 4. Ambient, so the capabilities survive exec of oscap (which has no
        #    file capabilities) for a non-root UID.
        for cap in keep:
            check(libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0),
                  f"raise ambient capability {cap}")
        # 5. Nothing oscap execs can gain privilege (setuid files, file caps).
        check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "PR_SET_NO_NEW_PRIVS")
    return enter


# A deployment that blocks user namespaces blocks them for every scan, so the
# failed attempt is not repeated.
_ISOLATION = {"userns_blocked": False}
RUN_AS_ROOT = run_as_root_requested()
# Scans evaluated per isolation mode since start-up, reported by /health.
EVALUATIONS = {}


def _run_oscap_offline(cmd, scan_path, timeout):
    """Run `cmd` with its probes rooted at `scan_path`.

    Returns (CompletedProcess, isolation) or raises OfflineUnsupported.
    """
    env = dict(os.environ, OSCAP_PROBE_ROOT=scan_path)
    while True:
        mode, reason = isolation_plan(os.geteuid(), RUN_AS_ROOT, _ISOLATION["userns_blocked"])
        if mode is None:
            raise OfflineUnsupported(reason)
        if mode == "root":
            keep = root_mode_caps(bounding_caps())
            if keep is None:
                raise OfflineUnsupported(
                    f"{RUN_AS_ROOT_ENV} is set but the container does not grant "
                    "CAP_SYS_CHROOT, which oscap needs to enter the unpacked filesystem"
                )
            preexec = _root_mode_preexec(SCAN_UID, keep)
        else:
            preexec = _userns_preexec(os.getuid(), os.getgid())
        try:
            result = subprocess.run(  # noqa: S603 - inputs validated by caller
                cmd, capture_output=True, text=True, timeout=timeout, env=env,
                preexec_fn=preexec,
            )
            return result, mode
        except subprocess.TimeoutExpired:
            raise
        except subprocess.SubprocessError as e:
            # The preexec_fn raised.
            if mode == "root":
                raise OfflineUnsupported(
                    f"{RUN_AS_ROOT_ENV} is set but the OpenSCAP sidecar could not drop "
                    f"to UID {SCAN_UID} with only CAP_SYS_CHROOT ({e}); the container "
                    "must keep CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_SYS_CHROOT"
                )
            _ISOLATION["userns_blocked"] = True


class OfflineUnsupported(Exception):
    """The runtime cannot root oscap's probes in the unpacked tree."""


def run_oscap_scan(scan_path, profile, content_file):
    """Run oscap xccdf eval against the tree at scan_path.

    Returns (http_status, response dict).
    """
    # Re-validate inputs at point of use (defense in depth, satisfies static analysis)
    if not PROFILE_RE.fullmatch(profile):
        return 400, {"findings": [], "error": "invalid profile name"}
    scan_path = os.path.realpath(scan_path)
    if not any(_is_under(scan_path, os.path.realpath(d)) for d in ALLOWED_SCAN_DIRS if d):
        return 400, {"findings": [], "error": "scan path not under allowed directories"}
    if not os.path.isfile(content_file) or not content_file.startswith(SSG_CONTENT_DIR + "/"):
        return 500, {"findings": [], "error": "invalid content file"}

    results_file = f"/tmp/oscap-results-{uuid.uuid4()}.xml"
    cmd = [
        "oscap", "xccdf", "eval",
        "--profile", profile,
        "--results", results_file,
        content_file,
    ]

    try:
        result, isolation = _run_oscap_offline(cmd, scan_path, timeout=600)
    except OfflineUnsupported as e:
        return 200, {"status": "not_applicable", "reason": str(e), "findings": []}
    except subprocess.TimeoutExpired:
        _unlink(results_file)
        return 500, {"findings": [], "error": "oscap scan timed out (10 minutes)"}
    except Exception as e:
        _unlink(results_file)
        return 500, {"findings": [], "error": str(e)}

    # oscap returns 2 for "some rules failed", which is a normal result.
    if result.returncode not in (0, 2):
        _unlink(results_file)
        if "chroot" in result.stderr and "not permitted" in result.stderr:
            return 200, {
                "status": "not_applicable",
                "reason": "the OpenSCAP sidecar cannot chroot into the unpacked filesystem; "
                          + ENABLE_HINT,
                "findings": [],
            }
        return 500, {
            "findings": [],
            "error": f"oscap exited with code {result.returncode}: {result.stderr[:500]}",
        }

    rule_results = parse_xccdf_results(results_file, content_file)
    _unlink(results_file)
    EVALUATIONS[isolation] = EVALUATIONS.get(isolation, 0) + 1
    sys.stderr.write(f"[openscap-wrapper] evaluated {scan_path} isolation={isolation}\n")
    summary = summarize_results(rule_results)
    response = {
        "status": "completed",
        "profile": profile,
        "isolation": isolation,
        **summary,
    }
    if summary["evaluated"] == 0:
        response["status"] = "not_applicable"
        response["reason"] = (
            f"no rule in profile {profile} applies to this target "
            "(every rule was notapplicable or not selected)"
        )
        response["findings"] = []
    return 200, response


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def summarize_results(rule_results):
    """Fold per-rule results into findings, counts and the unevaluated list."""
    counts = {}
    findings = []
    not_evaluated = []
    evaluated = 0
    for r in rule_results:
        if r["result"] in EVALUATED_RESULTS and is_ownership_rule(r["rule_id"]):
            not_evaluated.append(r["rule_id"])
            counts["not_evaluated_ownership"] = counts.get("not_evaluated_ownership", 0) + 1
            continue
        counts[r["result"]] = counts.get(r["result"], 0) + 1
        if r["result"] in EVALUATED_RESULTS:
            evaluated += 1
        if r["result"] in FINDING_RESULTS:
            findings.append(r)
    return {
        "findings": findings,
        "counts": counts,
        "evaluated": evaluated,
        "not_evaluated": not_evaluated,
    }


def parse_xccdf_results(results_file, content_file):
    """Parse XCCDF results XML into a list of per-rule result dicts."""
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

    results = []
    for rule_result in root.iter(f"{{{XCCDF_NS}}}rule-result"):
        idref = rule_result.get("idref", "")
        result_el = rule_result.find(f"{{{XCCDF_NS}}}result")
        result_val = result_el.text if result_el is not None else "unknown"

        meta = rule_meta.get(idref, {})
        severity = rule_result.get("severity") or meta.get("severity", "unknown")

        # Collect references (CCE, NIST, etc.)
        references = []
        for ident in rule_result.findall(f"{{{XCCDF_NS}}}ident"):
            if ident.text:
                references.append(ident.text)

        results.append({
            "rule_id": idref,
            "result": result_val,
            "severity": severity,
            "title": meta.get("title", idref),
            "description": meta.get("description"),
            "references": references,
        })

    return results


def plan_scan(scan_path, profile, available_content, profiles_of=list_profiles):
    """Decide what to evaluate, before running oscap.

    Returns ("scan", content_label, content_file, target_os), or
    (http_status, response) for every request that must not be evaluated. Pure apart from reading
    the tree's os-release and `profiles_of`, so it is unit-tested directly.
    """
    if not available_content:
        return 500, {"error": "no SCAP content available", "findings": []}

    # A profile no shipped datastream defines is a configuration error, never
    # a silent substitute (#6000: the old wrapper fell back to profiles[0]).
    profiles_by_label = {label: profiles_of(path) for label, path in available_content.items()}
    if not any(profile in p for p in profiles_by_label.values()):
        available = sorted({p for ps in profiles_by_label.values() for p in ps})
        return 422, {
            "error": f"profile {profile} is not defined in any shipped SCAP datastream "
                     f"({', '.join(sorted(available_content))})",
            "code": "unknown_profile",
            "available_profiles": available,
            "findings": [],
        }

    os_release = read_os_release(scan_path)
    if os_release is None:
        return 200, {
            "status": "not_applicable",
            "reason": "the scanned tree has no os-release, so it is not an operating "
                      "system root filesystem OpenSCAP content can evaluate",
            "findings": [],
        }
    selected = select_content_file(os_release, available_content)
    target_os = " ".join(x for x in (os_release.get("ID"), os_release.get("VERSION_ID")) if x)
    if selected is None:
        return 200, {
            "status": "not_applicable",
            "reason": f"no SCAP content for {target_os} in this sidecar "
                      f"(available: {', '.join(sorted(available_content))})",
            "target_os": target_os,
            "findings": [],
        }
    label, content_file = selected
    if profile not in profiles_by_label.get(label, []):
        return 200, {
            "status": "not_applicable",
            "reason": f"profile {profile} is not defined in the {label} datastream",
            "target_os": target_os,
            "findings": [],
        }
    return "scan", label, content_file, target_os


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
                "default_profile": DEFAULT_PROFILE,
                "run_as_root": RUN_AS_ROOT and os.geteuid() == 0,
                "evaluations": dict(EVALUATIONS),
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
        profile = req.get("profile") or DEFAULT_PROFILE

        # Validate profile string: XCCDF profile IDs only contain
        # alphanumerics, dots, underscores, and hyphens.
        if not isinstance(profile, str) or not PROFILE_RE.fullmatch(profile):
            self._json_response(400, {"error": "invalid profile name"})
            return

        scan_path = validate_scan_path(raw_path)
        if not scan_path or not os.path.isdir(scan_path):
            self._json_response(400, {"error": "scan path not found or not allowed"})
            return

        plan = plan_scan(scan_path, profile, self.available_content)
        if plan[0] != "scan":
            self._json_response(plan[0], plan[1])
            return
        _, label, content_file, target_os = plan

        status, result = run_oscap_scan(scan_path, profile, content_file)
        result.setdefault("content", label)
        result.setdefault("target_os", target_os)
        self._json_response(status, result)

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
    if RUN_AS_ROOT:
        state = "active" if os.geteuid() == 0 else "requested, but the process is not root"
        print(f"{RUN_AS_ROOT_ENV}: {state}", flush=True)
    server = HTTPServer(("0.0.0.0", PORT), OpenSCAPHandler)
    server.serve_forever()
