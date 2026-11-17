"""Isolated stdlib tests; never opens real user configs or starts VMs/services."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "runtime_shares.py"
spec = importlib.util.spec_from_file_location("isolated_runtime_shares", str(SOURCE))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RuntimeSharesTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="gold-runtime-shares-test-", dir="/tmp")).resolve(strict=True)
        self.expected_root = self.root
        self.root.chmod(0o700)
        self.home = self.root / "home"
        self.project = self.home / "projects" / "normal"
        self.state = self.home / "manager-state"
        self.network = self.home / "Applications" / "GoldNetwork"
        self.manager_source = self.home / "projects" / "manager"
        self.manager_install = self.home / "Applications" / "Manager.app"
        self.system = self.root / "system-protected"
        for p in (self.project, self.state, self.network, self.manager_source,
                  self.manager_install, self.system, self.home / ".ssh",
                  self.home / ".tart", self.home / "Library/Keychains"):
            p.mkdir(parents=True, mode=0o700, exist_ok=True)
            p.chmod(0o700)
        self.constants = patch.multiple(m, HOST_HOME=self.home, CONFIG_PATH=self.state / "config.json",
            STATE_DIR=self.state, MANAGER_SOURCE_DIR=self.manager_source,
            MANAGER_INSTALL_DIR=self.manager_install, MANAGER_EXTRA_DIRS=(),
            NETWORK_CONTROLLER_DIRS=(self.network,), PROTECTED_ROOTS=(Path("/"), self.home),
            PROTECTED_SUBTREES=(self.system,))
        self.constants.start()

    def tearDown(self):
        self.constants.stop()
        # Verify the resolved absolute deletion target before removing fixtures.
        self.assertFalse(self.root.is_symlink())
        self.assertEqual(self.root.resolve(strict=True), self.expected_root)
        self.assertEqual(self.root.parent, Path("/tmp").resolve(strict=True))
        self.assertTrue(self.root.name.startswith("gold-runtime-shares-test-"))
        shutil.rmtree(str(self.root))

    def share(self, **changes):
        result = {"id": "project-1", "name": "project", "path": str(self.project),
                  "read_only": False, "enabled": True}
        result.update(changes)
        return result

    def write_json(self, path, value):
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    def desired(self, shares=None, vm="gold"):
        self.write_json(m.CONFIG_PATH, {"version": 1, "vms": {vm: {"shares": shares if shares is not None else [self.share()]}}})

    def manifest(self, shares=None, vm="gold", **updates):
        shares = [self.share()] if shares is None else shares
        data = {"version": 1, "vm_id": vm, "pid": 12345, "shares": shares,
                "fingerprint": m.shares_fingerprint(shares), "suspendable": not shares,
                "started_at": "2026-11-12T00:00:00+00:00"}
        data.update(updates)
        self.write_json(self.network / m.LAST_LAUNCH_NAME, data)
        return data

    def denied(self, fn, *args, **kwargs):
        with self.assertRaises(m.ShareValidationError):
            fn(*args, **kwargs)

    def test_absent_config_and_manifest_are_empty_without_mutation(self):
        self.assertEqual(m.load_desired("gold"), [])
        self.assertEqual(m.read_last_launch(self.network), {})
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        self.assertEqual(p.arguments, [])
        self.assertTrue(p.suspendable)
        self.assertFalse(p.pending_changes)
        self.assertFalse(m.CONFIG_PATH.exists())
        self.assertFalse((self.network / m.LAST_LAUNCH_NAME).exists())

    def test_absent_config_parent_is_empty_without_directory_creation(self):
        absent = self.root / "not-created" / "config.json"
        with patch.object(m, "CONFIG_PATH", absent):
            self.assertEqual(m.load_desired("gold"), [])
        self.assertFalse(absent.parent.exists())

    def test_named_rw_and_ro_arguments(self):
        self.desired([self.share(), self.share(id="second", name="readonly", read_only=True)])
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        self.assertEqual(p.arguments, ["--dir=project:" + str(self.project), "--dir=readonly:" + str(self.project) + ":ro"])
        self.assertFalse(p.suspendable)
        self.assertFalse(p.pending_changes)

    def test_disabled_rows_not_attached(self):
        self.desired([self.share(enabled=False)])
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        self.assertEqual(p.shares, [])
        self.assertTrue(p.suspendable)

    def test_spaces_unicode_quotes_and_dedicated_sibling_project_allowed(self):
        p = self.home / "projects" / "ordinary 项目 '$` folder"
        p.mkdir()
        result = m.validate_shares([self.share(path=str(p))])
        self.assertEqual(result[0]["path"], str(p))

    def test_missing_id_generated_but_persisted_config_requires_id(self):
        s = self.share()
        del s["id"]
        got = m.validate_shares([s])
        self.assertRegex(got[0]["id"], r"^[0-9a-f-]{36}$")
        self.desired([s])
        self.denied(m.load_desired, "gold")

    def test_uuid_normalized_and_duplicate_normalized_ids_rejected(self):
        first = self.share(id="{12345678-1234-4ABC-8DEF-1234567890AB}")
        got = m.validate_shares([first])
        self.assertEqual(got[0]["id"], "12345678-1234-4abc-8def-1234567890ab")
        self.denied(m.validate_shares, [first, self.share(id=got[0]["id"], name="other")])

    def test_invalid_ids(self):
        for value in ("", "../key", "a:b", "ümlaut", 7, True, "x" * 65):
            with self.subTest(value=value):
                self.denied(m.validate_shares, [self.share(id=value)])

    def test_invalid_names_and_duplicate_casefold(self):
        for value in ("", ".", "../a", "a:ro", "tag=x", "a b", "项目", "a\n", "-x", "x" * 41):
            with self.subTest(value=value):
                self.denied(m.validate_shares, [self.share(name=value)])
        self.denied(m.validate_shares, [self.share(name="Project"), self.share(id="other", name="project")])

    def test_exact_boolean_fields_required(self):
        for key in ("read_only", "enabled"):
            for value in (0, 1, "true", "false", None):
                with self.subTest(key=key, value=value):
                    self.denied(m.validate_shares, [self.share(**{key: value})])
            s = self.share()
            del s[key]
            self.denied(m.validate_shares, [s])

    def test_unknown_share_fields_rejected(self):
        self.denied(m.validate_shares, [self.share(options="tag=evil")])

    def test_limit_and_input_types(self):
        good = [self.share(id="id%d" % i, name="name%d" % i) for i in range(16)]
        self.assertEqual(len(m.validate_shares(good)), 16)
        self.denied(m.validate_shares, good + [self.share(id="extra", name="extra")])
        for value in (None, {}, "[]", [None], [True]):
            self.denied(m.validate_shares, value)

    def test_relative_colon_comma_controls_and_parent_traversal_denied(self):
        for p in ("relative", "~/project", "//server/path", str(self.project) + ":ro",
                  str(self.project) + ",ro", str(self.project) + "\n", str(self.project) + "\t",
                  str(self.project) + "\x00", str(self.project) + "\x7f", str(self.project / ".." / "normal")):
            self.denied(m.validate_shares, [self.share(path=p)])

    def test_nonexistent_file_and_nonowner_denied_even_disabled(self):
        self.denied(m.validate_shares, [self.share(path=str(self.root / "absent"), enabled=False)])
        regular = self.root / "file"
        regular.write_text("not inspected")
        self.denied(m.validate_shares, [self.share(path=str(regular))])
        with patch.object(m.os, "getuid", return_value=os.getuid() + 1):
            self.denied(m.validate_shares, [self.share()])

    def test_selected_and_parent_symlinks_denied(self):
        alias = self.root / "alias"
        alias.symlink_to(self.project, target_is_directory=True)
        self.denied(m.validate_shares, [self.share(path=str(alias))])
        nested = self.project / "nested"
        nested.mkdir()
        self.denied(m.validate_shares, [self.share(path=str(alias / "nested"))])

    def test_sensitive_roots_descendants_and_ancestors_denied(self):
        targets = [self.home, self.home / ".ssh", self.home / ".tart", self.home / "Library",
                   self.home / "Library/Keychains", self.state, self.network,
                   self.manager_source, self.manager_install, self.system, self.home / "projects"]
        for p in targets:
            with self.subTest(path=p):
                self.denied(m.validate_shares, [self.share(path=str(p), read_only=True)])
        nested = self.network / "nested"
        nested.mkdir()
        self.denied(m.validate_shares, [self.share(path=str(nested))])
        # Protecting manager source must NOT block its ordinary sibling project.
        self.assertEqual(m.validate_shares([self.share()])[0]["path"], str(self.project))

    def test_root_and_home_roots_cannot_be_shared(self):
        self.denied(m.validate_shares, [self.share(path="/")])
        self.denied(m.validate_shares, [self.share(path=str(self.home))])

    def test_config_schema_versions_and_unknown_vm_ids(self):
        for data in ({}, [], {"version": True, "vms": {}}, {"version": 2, "vms": {}},
                     {"version": 1, "vms": []}, {"version": 1, "vms": {"other": {}}},
                     {"version": 1, "vms": {}, "extra": 1}):
            self.write_json(m.CONFIG_PATH, data)
            self.denied(m.load_desired, "gold")

    def test_malformed_other_vm_scoped_to_that_vm(self):
        self.write_json(m.CONFIG_PATH, {"version": 1, "vms": {"gold": {"shares": []}, "gold-backup": "bad"}})
        self.assertEqual(m.load_desired("gold"), [])
        self.assertEqual(m.load_desired("gold-fresh"), [])
        self.denied(m.load_desired, "gold-backup")

    def test_invalid_json_empty_duplicate_keys_nonfinite_and_oversize(self):
        for text in ("", "{", '{"version":1,"version":1,"vms":{}}',
                     '{"version":NaN,"vms":{}}', " " * (m.MAX_JSON_BYTES + 1)):
            m.CONFIG_PATH.write_text(text)
            m.CONFIG_PATH.chmod(0o600)
            self.denied(m.load_desired, "gold")

    def test_deeply_nested_json_is_safe_validation_error(self):
        m.CONFIG_PATH.write_text("[" * 1100 + "]" * 1100)
        m.CONFIG_PATH.chmod(0o600)
        self.denied(m.load_desired, "gold")

    def test_private_file_permissions_owner_and_symlink_checks(self):
        self.desired([])
        m.CONFIG_PATH.chmod(0o644)
        self.denied(m.load_desired, "gold")
        m.CONFIG_PATH.chmod(0o600)
        with patch.object(m.os, "getuid", return_value=os.getuid() + 1):
            self.denied(m.load_desired, "gold")
        target = self.root / "fake-private-config"
        self.write_json(target, {"version": 1, "vms": {}})
        with patch.object(m, "CONFIG_PATH", self.state / "link.json"):
            m.CONFIG_PATH.symlink_to(target)
            self.denied(m.load_desired, "gold")

    def test_dangling_config_symlink_not_treated_missing(self):
        m.CONFIG_PATH.symlink_to(self.root / "does-not-exist")
        self.denied(m.load_desired, "gold")

    def test_hardlinked_config_and_fifo_rejected_without_blocking(self):
        target = self.state / "original"
        self.write_json(target, {"version": 1, "vms": {}})
        os.link(str(target), str(m.CONFIG_PATH))
        self.denied(m.load_desired, "gold")
        fifo = self.state / "fifo"
        os.mkfifo(str(fifo), 0o600)
        with patch.object(m, "CONFIG_PATH", fifo):
            self.denied(m.load_desired, "gold")

    def test_unknown_vm_and_unknown_state_fail(self):
        for vm in ("other", "../gold", 1, None):
            self.denied(m.load_desired, vm)
        for state_value in ("missing", "unknown", None, True):
            self.denied(m.prepare_vm_shares, "gold", self.network, state_value)

    def test_legacy_suspended_no_manifest_uses_no_shares_pending(self):
        self.desired()
        p = m.prepare_vm_shares("gold", self.network, "suspended")
        self.assertEqual(p.shares, [])
        self.assertEqual(p.arguments, [])
        self.assertTrue(p.suspendable)
        self.assertTrue(p.pending_changes)
        self.assertFalse((self.network / m.LAST_LAUNCH_NAME).exists())

    def test_suspended_uses_actual_saved_shares_not_changed_desired(self):
        old = self.share(read_only=True)
        self.manifest([old])
        new = self.share(name="renamed", read_only=False)
        self.desired([new])
        p = m.prepare_vm_shares("gold", self.network, "suspended")
        self.assertEqual(p.shares, [old])
        self.assertEqual(p.arguments, ["--dir=project:" + str(self.project) + ":ro"])
        self.assertFalse(p.suspendable)
        self.assertTrue(p.pending_changes)

    def test_removal_or_disabling_waits_for_cold_boot(self):
        self.manifest()
        self.desired([self.share(enabled=False)])
        suspended = m.prepare_vm_shares("gold", self.network, "suspended")
        self.assertEqual(len(suspended.shares), 1)
        self.assertTrue(suspended.pending_changes)
        cold = m.prepare_vm_shares("gold", self.network, "stopped")
        self.assertEqual(cold.shares, [])
        self.assertFalse(cold.pending_changes)
        self.assertTrue(cold.suspendable)

    def test_unchanged_resume_and_running_state(self):
        self.manifest()
        self.desired()
        for state_value in ("suspended", "running"):
            p = m.prepare_vm_shares("gold", self.network, state_value)
            self.assertEqual(p.shares, [self.share()])
            self.assertFalse(p.pending_changes)

    def test_reordering_is_pending_and_prior_argv_order_preserved(self):
        first = self.share()
        second = self.share(id="two", name="two", read_only=True)
        self.manifest([first, second])
        self.desired([second, first])
        p = m.prepare_vm_shares("gold", self.network, "suspended")
        self.assertEqual(p.shares, [first, second])
        self.assertTrue(p.pending_changes)

    def test_manifest_other_vm_rejected(self):
        self.manifest(vm="gold-backup")
        self.denied(m.prepare_vm_shares, "gold", self.network, "stopped")

    def test_manifest_schema_fingerprint_and_boolean_tamper_rejected(self):
        for updates in ({"version": True}, {"pid": True}, {"pid": 0}, {"fingerprint": "0" * 64},
                        {"suspendable": True}, {"started_at": None}, {"extra": 1},
                        {"shares": [], "fingerprint": m.shares_fingerprint([self.share()])}):
            self.manifest(**updates)
            self.denied(m.read_last_launch, self.network)

    def test_malformed_or_nonprivate_manifest_not_empty_even_cold(self):
        p = self.network / m.LAST_LAUNCH_NAME
        p.write_text("not json")
        p.chmod(0o600)
        self.denied(m.prepare_vm_shares, "gold", self.network, "stopped")
        self.manifest([])
        p.chmod(0o644)
        self.denied(m.read_last_launch, self.network)

    def test_saved_active_path_missing_or_protected_rejected(self):
        self.manifest([self.share(path=str(self.root / "gone"))])
        self.denied(m.prepare_vm_shares, "gold", self.network, "suspended")
        self.manifest([self.share(path=str(self.home / ".ssh"))])
        self.denied(m.read_last_launch, self.network)

    def test_invalid_desired_still_rejected_on_resume(self):
        self.manifest([])
        self.desired([self.share(path=str(self.home / ".ssh"))])
        self.denied(m.prepare_vm_shares, "gold", self.network, "suspended")

    def test_disabled_actual_manifest_rejected(self):
        self.manifest([self.share(enabled=False)])
        self.denied(m.read_last_launch, self.network)

    def test_plan_returns_defensive_lists(self):
        self.desired()
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        p.arguments.append("--dir=evil:/")
        p.shares[0]["path"] = "/"
        self.assertEqual(p.arguments, ["--dir=project:" + str(self.project)])
        self.assertEqual(p.shares[0]["path"], str(self.project))

    def test_record_launch_atomic_private_and_roundtrips(self):
        self.desired()
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        data = p.record_launch(12345)
        path = self.network / m.LAST_LAUNCH_NAME
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(m.read_last_launch(self.network), data)
        self.assertEqual(data["shares"], [self.share()])
        self.assertEqual(data["pid"], 12345)
        self.assertFalse(data["suspendable"])
        self.assertEqual(list(self.network.glob(".shares.last-start-*.tmp")), [])

    def test_record_empty_plan_and_resume_new_pid_preserves_actual(self):
        self.desired()
        p = m.prepare_vm_shares("gold", self.network, "suspended")
        p.record_launch(12345)
        got = m.read_last_launch(self.network)
        self.assertEqual(got["shares"], [])
        self.assertTrue(got["suspendable"])
        self.assertTrue(p.pending_changes)

    def test_record_invalid_pid_no_mutation(self):
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        for pid in (True, 0, -1, "123", 2 ** 31):
            self.denied(p.record_launch, pid)
        self.assertFalse((self.network / m.LAST_LAUNCH_NAME).exists())

    def test_record_revalidates_share_symlink_replacement(self):
        self.desired()
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        # Exact fixture move paths checked before replacing the selected folder.
        moved = self.project.parent / "original-project"
        self.assertEqual(self.project.resolve(strict=True), self.project)
        self.assertEqual(moved.parent.resolve(strict=True), self.project.parent)
        self.project.rename(moved)
        self.project.symlink_to(moved, target_is_directory=True)
        self.denied(p.record_launch, 12345)
        self.assertFalse((self.network / m.LAST_LAUNCH_NAME).exists())

    def test_record_rejects_same_path_new_directory_inode(self):
        self.desired()
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        moved = self.project.parent / "old-project"
        self.assertEqual(self.project.resolve(strict=True), self.project)
        self.assertEqual(moved.parent.resolve(strict=True), self.project.parent)
        self.project.rename(moved)
        self.project.mkdir()
        self.denied(p.record_launch, 12345)

    def test_network_base_private_real_directory_required(self):
        self.network.chmod(0o755)
        self.denied(m.prepare_vm_shares, "gold", self.network, "stopped")
        alias = self.root / "network-alias"
        alias.symlink_to(self.network, target_is_directory=True)
        self.denied(m.read_last_launch, alias)

    def test_atomic_replace_failure_cleans_verified_staging_preserves_previous(self):
        original = self.manifest([])
        self.desired()
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        with patch.object(m.os, "replace", side_effect=OSError("injected")):
            self.denied(p.record_launch, 12346)
        self.assertEqual(m.read_last_launch(self.network), original)
        self.assertEqual(list(self.network.glob(".shares.last-start-*.tmp")), [])

    def test_staging_fsync_failure_cleans_only_owned_temp(self):
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        unrelated = self.network / "unrelated.tmp"
        unrelated.write_text("keep")
        with patch.object(m.os, "fsync", side_effect=OSError("injected")):
            self.denied(p.record_launch, 12345)
        self.assertEqual(unrelated.read_text(), "keep")
        self.assertEqual(list(self.network.glob(".shares.last-start-*.tmp")), [])
        self.assertFalse((self.network / m.LAST_LAUNCH_NAME).exists())

    def test_record_does_not_overwrite_new_corrupt_or_symlink_manifest(self):
        p = m.prepare_vm_shares("gold", self.network, "stopped")
        target = self.network / m.LAST_LAUNCH_NAME
        target.write_text("broken")
        target.chmod(0o600)
        self.denied(p.record_launch, 12345)
        self.assertEqual(target.read_text(), "broken")
        link = self.root / "other-network"
        link.mkdir(mode=0o700)
        path = link / m.LAST_LAUNCH_NAME
        path.symlink_to(target)
        self.denied(m.read_last_launch, link)

    def test_errors_do_not_include_input_payload_or_path(self):
        secret_path = str(self.root / "private-payload-secret")
        try:
            m.validate_shares([self.share(path=secret_path)])
        except m.ShareValidationError as error:
            self.assertNotIn(secret_path, str(error))
            self.assertNotIn("private-payload-secret", str(error))
            self.assertTrue(error.code)
        else:
            self.fail("Expected validation error")


if __name__ == "__main__":
    unittest.main()
