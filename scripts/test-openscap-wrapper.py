#!/usr/bin/env python3
"""Unit tests for scripts/openscap-wrapper.py (#6000).

Covers the decisions the wrapper makes before and after running oscap: which
datastream describes the scanned tree, whether the profile exists, how
symlinks inside the tree resolve, and how rule results become findings. No
oscap binary is needed. Run: python3 -I scripts/test-openscap-wrapper.py
"""

import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "openscap_wrapper", os.path.join(HERE, "openscap-wrapper.py")
)
w = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(w)

RHEL9 = "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
CS9 = "/usr/share/xml/scap/ssg/content/ssg-cs9-ds.xml"
CONTENT = {"cs9": CS9, "rhel9": RHEL9}
SHIPPED_PROFILES = [
    "xccdf_org.ssgproject.content_profile_anssi_bp28_enhanced",
    "xccdf_org.ssgproject.content_profile_cis_server_l1",
    "xccdf_org.ssgproject.content_profile_stig",
]


def profiles_of(_path):
    return list(SHIPPED_PROFILES)


def make_tree(files, links=()):
    root = tempfile.mkdtemp(prefix="oscap-wrapper-test-")
    for rel, body in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body)
    for rel, target in links:
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(target, path)
    return root


class ContentSelection(unittest.TestCase):
    def test_rhel_minor_version_selects_rhel9(self):
        self.assertEqual(
            w.select_content_file({"ID": "rhel", "VERSION_ID": "9.6"}, CONTENT),
            ("rhel9", RHEL9),
        )

    def test_centos_stream_selects_cs9(self):
        self.assertEqual(
            w.select_content_file({"ID": "centos", "VERSION_ID": "9"}, CONTENT),
            ("cs9", CS9),
        )

    def test_other_os_has_no_content_and_no_fallback(self):
        # The old wrapper fell back to the first datastream; SSG then marks
        # every rule notapplicable and the scan reads as clean.
        for osr in (
            {"ID": "debian", "VERSION_ID": "12"},
            {"ID": "rhel", "VERSION_ID": "8.10"},
            {"ID": "rocky", "VERSION_ID": "9.4"},
            {"ID": "alpine", "VERSION_ID": "3.20.1"},
        ):
            self.assertIsNone(w.select_content_file(osr, CONTENT), osr)

    def test_labels(self):
        self.assertEqual(
            w.content_labels_for({"ID": "ubuntu", "VERSION_ID": "22.04"}),
            ["ubuntu2204", "ubuntu22", "ubuntu"],
        )
        self.assertEqual(w.content_labels_for({"ID": "fedora"}), ["fedora"])


class TreeReading(unittest.TestCase):
    def test_os_release_through_absolute_symlink_stays_in_tree(self):
        # etc/os-release -> /usr/lib/os-release must resolve inside the tree,
        # never to the sidecar's own /usr/lib/os-release.
        root = make_tree(
            {"usr/lib/os-release": 'ID="rhel"\nVERSION_ID="9.6"\n'},
            links=[("etc/os-release", "/usr/lib/os-release")],
        )
        self.assertEqual(w.read_os_release(root)["ID"], "rhel")

    def test_escaping_relative_symlink_is_clamped_to_root(self):
        root = make_tree(
            {"usr/lib/os-release": "ID=centos\nVERSION_ID=9\n"},
            links=[("etc/os-release", "../../../../../usr/lib/os-release")],
        )
        resolved = w.resolve_in_root(root, "etc/os-release")
        self.assertTrue(resolved.startswith(os.path.realpath(root) + os.sep))
        self.assertEqual(w.read_os_release(root)["ID"], "centos")

    def test_symlink_loop_is_refused(self):
        root = make_tree({}, links=[("etc/a", "b"), ("etc/b", "a")])
        self.assertIsNone(w.resolve_in_root(root, "etc/a"))

    def test_tree_without_os_release(self):
        # What every scan sent before #6000: one raw artifact file.
        root = make_tree({"hello-1.0-1.x86_64.rpm": "\xed\xab\xee\xdb"})
        self.assertIsNone(w.read_os_release(root))


class Planning(unittest.TestCase):
    def rhel_tree(self):
        return make_tree({"etc/os-release": "ID=rhel\nVERSION_ID=9.6\n"})

    def test_unknown_profile_is_an_error_not_a_substitute(self):
        status, body = w.plan_scan(
            self.rhel_tree(), "xccdf_org.ssgproject.content_profile_standard",
            CONTENT, profiles_of,
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["code"], "unknown_profile")
        self.assertIn(w.DEFAULT_PROFILE, body["available_profiles"])

    def test_default_profile_is_shipped(self):
        self.assertIn(w.DEFAULT_PROFILE, SHIPPED_PROFILES)

    def test_configured_profile_is_kept(self):
        plan = w.plan_scan(
            self.rhel_tree(), "xccdf_org.ssgproject.content_profile_stig",
            CONTENT, profiles_of,
        )
        self.assertEqual(plan, ("scan", "rhel9", RHEL9, "rhel 9.6"))

    def test_raw_file_workspace_is_not_applicable(self):
        root = make_tree({"hello.rpm": "x"})
        status, body = w.plan_scan(root, w.DEFAULT_PROFILE, CONTENT, profiles_of)
        self.assertEqual((status, body["status"]), (200, "not_applicable"))
        self.assertEqual(body["findings"], [])

    def test_os_without_content_is_not_applicable(self):
        root = make_tree({"etc/os-release": "ID=debian\nVERSION_ID=12\n"})
        status, body = w.plan_scan(root, w.DEFAULT_PROFILE, CONTENT, profiles_of)
        self.assertEqual(body["status"], "not_applicable")
        self.assertIn("debian 12", body["reason"])

    def test_profile_missing_from_this_os_content_is_not_applicable(self):
        def only_in_cs9(path):
            return SHIPPED_PROFILES + (["x_only_cs9"] if path == CS9 else [])

        status, body = w.plan_scan(self.rhel_tree(), "x_only_cs9", CONTENT, only_in_cs9)
        self.assertEqual(body["status"], "not_applicable")

    def test_no_content(self):
        status, _ = w.plan_scan(self.rhel_tree(), w.DEFAULT_PROFILE, {}, profiles_of)
        self.assertEqual(status, 500)


class Results(unittest.TestCase):
    def rr(self, rule, result):
        return {"rule_id": "xccdf_org.ssgproject.content_rule_" + rule, "result": result,
                "severity": "medium", "title": rule, "description": None, "references": []}

    def test_findings_counts_and_ownership(self):
        summary = w.summarize_results([
            self.rr("accounts_umask_etc_profile", "fail"),
            self.rr("no_empty_passwords", "pass"),
            self.rr("file_owner_etc_shadow", "fail"),
            self.rr("file_groupowner_etc_passwd", "pass"),
            self.rr("grub2_password", "notapplicable"),
            self.rr("audit_owner_change_success", "fail"),
        ])
        ids = [f["rule_id"].rsplit("_rule_", 1)[1] for f in summary["findings"]]
        self.assertEqual(ids, ["accounts_umask_etc_profile", "audit_owner_change_success"])
        self.assertEqual(summary["evaluated"], 3)
        self.assertEqual(summary["counts"]["not_evaluated_ownership"], 2)
        self.assertEqual(len(summary["not_evaluated"]), 2)

    def test_ownership_rule_ids(self):
        for rule in ("file_owner_etc_passwd", "file_groupownership_sshd_pub_key",
                     "dir_ownership_library_dirs", "directory_group_ownership_var_log_audit",
                     "file_audit_tools_group_ownership", "rpm_verify_ownership",
                     "no_files_unowned_by_user", "file_permissions_ungroupowned",
                     "dir_perms_world_writable_root_owned",
                     "accounts_users_home_files_groupownership",
                     "file_etc_security_opasswd"):
            self.assertTrue(w.is_ownership_rule("xccdf_org.ssgproject.content_rule_" + rule), rule)
        for rule in ("audit_owner_change_failed", "audit_rules_dac_modification_chown",
                     "file_permissions_etc_shadow", "sshd_disable_user_known_hosts"):
            self.assertFalse(w.is_ownership_rule("xccdf_org.ssgproject.content_rule_" + rule), rule)

    def test_all_notapplicable_counts_nothing_evaluated(self):
        summary = w.summarize_results([self.rr("a", "notapplicable"), self.rr("b", "notselected")])
        self.assertEqual(summary["evaluated"], 0)


class Isolation(unittest.TestCase):
    """How oscap's probes get CAP_SYS_CHROOT: user namespace, or opt-in root."""

    def test_default_is_user_namespace_even_as_root(self):
        # Running as root without the opt-in never runs oscap outside a user
        # namespace.
        self.assertEqual(w.isolation_plan(0, False, False), ("userns", None))
        mode, reason = w.isolation_plan(0, False, True)
        self.assertIsNone(mode)
        self.assertIn(w.RUN_AS_ROOT_ENV, reason)
        self.assertIn("rootless Podman", reason)

    def test_root_mode_needs_opt_in_and_root(self):
        self.assertEqual(w.isolation_plan(0, True, True), ("root", None))
        self.assertEqual(w.isolation_plan(0, True, False), ("root", None))
        # Opted in but not root: user namespace if it works, else explain.
        self.assertEqual(w.isolation_plan(1001, True, False), ("userns", None))
        mode, reason = w.isolation_plan(1001, True, True)
        self.assertIsNone(mode)
        self.assertIn('user "0"', reason)

    def test_opt_in_values(self):
        for v in ("1", "true", "TRUE", " yes ", "on"):
            self.assertTrue(w.run_as_root_requested({w.RUN_AS_ROOT_ENV: v}), v)
        for v in ("", "0", "false", "no", "root"):
            self.assertFalse(w.run_as_root_requested({w.RUN_AS_ROOT_ENV: v}), v)
        self.assertFalse(w.run_as_root_requested({}))

    def test_root_mode_keeps_only_chroot_and_read_search(self):
        docker_default = "CapBnd:\t00000000a80425fb\n"  # Docker's default set
        bnd = w.bounding_caps(docker_default)
        self.assertIn(w.CAP_SYS_CHROOT, bnd)
        self.assertNotIn(w.CAP_DAC_READ_SEARCH, bnd)
        self.assertEqual(w.root_mode_caps(bnd), (w.CAP_SYS_CHROOT,))
        self.assertEqual(w.root_mode_caps(bnd | {w.CAP_DAC_READ_SEARCH}),
                         (w.CAP_SYS_CHROOT, w.CAP_DAC_READ_SEARCH))
        self.assertIsNone(w.root_mode_caps({w.CAP_DAC_READ_SEARCH}))
        self.assertEqual(w.cap_mask((w.CAP_SYS_CHROOT, w.CAP_DAC_READ_SEARCH)), (0x40004, 0))

    def test_root_path_runs_without_user_namespace(self):
        from unittest import mock
        calls = []

        def fake_run(cmd, **kw):
            calls.append(kw["preexec_fn"])
            self.assertEqual(kw["env"]["OSCAP_PROBE_ROOT"], "/scan-workspace/x/rootfs")
            return mock.Mock(returncode=0, stderr="")

        sentinel = object()
        with mock.patch.object(w, "RUN_AS_ROOT", True), \
             mock.patch.object(w.os, "geteuid", return_value=0), \
             mock.patch.object(w, "bounding_caps", return_value={w.CAP_SYS_CHROOT}), \
             mock.patch.object(w, "_root_mode_preexec", return_value=sentinel) as root_pre, \
             mock.patch.object(w, "_userns_preexec") as userns_pre, \
             mock.patch.object(w.subprocess, "run", side_effect=fake_run):
            _, mode = w._run_oscap_offline(["oscap"], "/scan-workspace/x/rootfs", 5)
        self.assertEqual(mode, "root")
        self.assertEqual(calls, [sentinel])
        root_pre.assert_called_once_with(w.SCAN_UID, (w.CAP_SYS_CHROOT,))
        userns_pre.assert_not_called()

    def test_root_path_without_chroot_capability_is_refused(self):
        from unittest import mock
        with mock.patch.object(w, "RUN_AS_ROOT", True), \
             mock.patch.object(w.os, "geteuid", return_value=0), \
             mock.patch.object(w, "bounding_caps", return_value=set()), \
             mock.patch.object(w.subprocess, "run") as run:
            with self.assertRaises(w.OfflineUnsupported) as ctx:
                w._run_oscap_offline(["oscap"], "/scan-workspace/x/rootfs", 5)
        run.assert_not_called()
        self.assertIn("CAP_SYS_CHROOT", str(ctx.exception))

    def test_blocked_user_namespace_without_opt_in_never_runs_unconfined(self):
        import subprocess as sp
        from unittest import mock
        old = dict(w._ISOLATION)
        try:
            w._ISOLATION["userns_blocked"] = False
            with mock.patch.object(w, "RUN_AS_ROOT", False), \
                 mock.patch.object(w.os, "geteuid", return_value=0), \
                 mock.patch.object(w.subprocess, "run",
                                   side_effect=sp.SubprocessError("preexec")) as run:
                with self.assertRaises(w.OfflineUnsupported):
                    w._run_oscap_offline(["oscap"], "/scan-workspace/x/rootfs", 5)
            self.assertEqual(run.call_count, 1, "one userns attempt, no unconfined retry")
        finally:
            w._ISOLATION.update(old)


class Paths(unittest.TestCase):
    def test_sibling_prefix_is_not_allowed(self):
        old = w.ALLOWED_SCAN_DIRS
        try:
            base = tempfile.mkdtemp()
            sibling = base + "-evil"
            os.makedirs(sibling)
            w.ALLOWED_SCAN_DIRS = [base + "/"]
            self.assertIsNone(w.validate_scan_path(sibling))
            self.assertEqual(w.validate_scan_path(base), os.path.realpath(base))
        finally:
            w.ALLOWED_SCAN_DIRS = old


if __name__ == "__main__":
    unittest.main(verbosity=1)
