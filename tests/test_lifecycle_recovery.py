"""Crash-boundary tests using tiny text fixtures, never real VMs or helpers.

Exceptions model an interruption at a filesystem operation, not actual APFS power
loss. Every lifecycle filesystem root is patched; subprocess calls are forbidden.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lifecycle as lifecycle
import managed_registry as registry


class InjectedCrash(BaseException):
    """Bypass normal application exception handling, like an abrupt interruption."""


class LifecycleRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="gold-recovery-unit-", dir="/private/tmp")).resolve(strict=True)
        self.expected_root = self.root
        self.state = self.root / "state"
        self.tart = self.root / "synthetic-tart"
        self.vms = self.tart / "vms"
        self.code = self.root / "fake-code"
        for directory in (self.state, self.tart, self.vms, self.code):
            directory.mkdir(mode=0o700)
        self.helper = self.code / "CleanVMInstaller"
        self.helper.write_text("Not executable. Never run this test fixture.")
        (self.code / "provisioning.py").write_text("# existence check fixture only\n")
        self.stack = ExitStack()
        for module, key, value in (
            (lifecycle, "STATE", self.state), (lifecycle, "TART_HOME", self.tart),
            (lifecycle, "VM_ROOT", self.vms), (lifecycle, "HERE", self.code),
            (lifecycle, "HELPER", self.helper), (registry, "STATE_DIR", self.state),
            (registry, "REGISTRY_PATH", self.state / "registry.json"),
        ):
            self.stack.enter_context(patch.object(module, key, value))
        self.stack.enter_context(patch.object(lifecycle.subprocess, "run", side_effect=AssertionError("No real subprocess is allowed")))
        self.spawn = self.stack.enter_context(patch.object(lifecycle.subprocess, "Popen", side_effect=AssertionError("Never start a worker or VM in recovery tests")))
        self.stack.enter_context(patch.object(lifecycle, "job_alive", return_value=False))
        self.jid = "c" * 32
        self.old = self.vms / "old-vm"
        self.old.mkdir(mode=0o700)
        registry.write_private(self.old / "config.json", {"os": "darwin", "ecid": "synthetic-old-identity"})
        (self.old / "disk.img").write_bytes(b"OLD SYNTHETIC TEXT; NOT A VIRTUAL DISK")
        (self.old / "nvram.bin").write_bytes(b"OLD SYNTHETIC NVRAM")
        self.stage = self.tart / ".gold-manager-staging" / self.jid / "new-environment"
        self.stage.mkdir(mode=0o700, parents=True)
        registry.write_private(self.stage / "config.json", {"os": "darwin", "ecid": "synthetic-new-identity"})
        (self.stage / "disk.img").write_bytes(b"NEW SYNTHETIC TEXT; NOT A VIRTUAL DISK")
        self.base = self.state / "environments" / self.jid
        self.base.mkdir(mode=0o700, parents=True)
        self.jobdir = self.state / "build-jobs" / self.jid
        registry.private_dir(self.jobdir)
        self.journal = self.jobdir / "commit.json"
        self.tombstone = self.stage.parent / "old-environment"
        self.target = self.vms / "replacement-vm"
        self.request = {
            "mode": "rebuild", "name": self.target.name, "source_vm": self.old.name,
            "id": self.jid, "source_identity": lifecycle.source_identity(self.old.name),
            "acknowledge_setup": True, "acknowledge_erase": True, "confirm_name": self.old.name,
        }
        registry.write_private(self.state / "config.json", {"version": 1, "vms": {self.old.name: {"shares": []}, "unrelated-vm": {"shares": [{"name": "keep"}]}}})
        self.current = {"id": self.jid, "phase": "failed", "pid": 123,
                        "source_vm": self.old.name, "name": self.target.name, "old_deleted": False}
        registry.write_private(self.state / "build-current.json", self.current)

    def tearDown(self):
        self.stack.close()
        # Verify exact disposable target before removing any fixtures.
        self.assertEqual(self.root.resolve(strict=True), self.expected_root)
        self.assertEqual(self.root.parent, Path("/private/tmp"))
        self.assertTrue(self.root.name.startswith("gold-recovery-unit-"))
        self.assertFalse(self.root.is_symlink())
        shutil.rmtree(str(self.root))

    def update(self, phase, message, progress=None):
        self.current.update(phase=phase, message=message, progress=progress)
        registry.write_private(self.state / "build-current.json", self.current)

    def commit(self):
        lifecycle.commit(self.request, self.stage, self.base, self.update)

    def assert_old_preserved(self, directory):
        self.assertEqual((directory / "disk.img").read_bytes(), b"OLD SYNTHETIC TEXT; NOT A VIRTUAL DISK")
        self.assertEqual((directory / "nvram.bin").read_bytes(), b"OLD SYNTHETIC NVRAM")

    def assert_recovery_blocks_next_job(self):
        status = lifecycle.status()
        self.assertTrue(status.get("recovery_required"), status)
        # Mock host checks; do not call sysctl, Tart, installer, or a worker process.
        with patch.object(lifecycle.subprocess, "run", return_value=SimpleNamespace(stdout=str(64 * 1024**3))), \
             patch.object(lifecycle, "inventory", return_value={}):
            with self.assertRaisesRegex(ValueError, "人工恢复"):
                lifecycle.start({"mode": "create", "name": "another-vm", "acknowledge_setup": True}, set())
        self.spawn.assert_not_called()
        self.assertEqual(registry.read_private(self.state / "build-current.json")["id"], self.jid)

    def test_initial_journal_write_failure_never_moves_old(self):
        original = registry.write_private
        def fail(path, data):
            if Path(path) == self.journal:
                raise InjectedCrash("before durable journal")
            return original(path, data)
        with patch.object(registry, "write_private", side_effect=fail), self.assertRaises(InjectedCrash):
            self.commit()
        self.assert_old_preserved(self.old)
        self.assertTrue(self.stage.exists())
        self.assertFalse(self.tombstone.exists())
        self.assertFalse(self.target.exists())

    def test_first_rename_failure_is_conservatively_quarantined(self):
        with patch.object(lifecycle.os, "rename", side_effect=InjectedCrash("first rename")), self.assertRaises(InjectedCrash):
            self.commit()
        self.assert_old_preserved(self.old)
        self.assertTrue(self.stage.exists())
        self.assert_recovery_blocks_next_job()

    def test_second_rename_failure_preserves_both_environments(self):
        original = os.rename
        def fail(src, dst):
            if Path(src) == self.stage:
                raise InjectedCrash("stage publication")
            return original(src, dst)
        with patch.object(lifecycle.os, "rename", side_effect=fail), self.assertRaises(InjectedCrash):
            self.commit()
        self.assertFalse(self.old.exists())
        self.assert_old_preserved(self.tombstone)
        self.assertTrue(self.stage.exists())
        self.assertFalse(self.target.exists())
        self.assert_recovery_blocks_next_job()

    def test_registry_write_failure_after_publish_retains_tombstone(self):
        original = registry.write_private
        def fail(path, data):
            if Path(path) == registry.REGISTRY_PATH:
                raise InjectedCrash("registry publication")
            return original(path, data)
        with patch.object(registry, "write_private", side_effect=fail), self.assertRaises(InjectedCrash):
            self.commit()
        self.assertTrue(self.target.exists())
        self.assert_old_preserved(self.tombstone)
        self.assertEqual(registry.read_private(self.journal)["phase"], "new_published")
        self.assert_recovery_blocks_next_job()

    def test_share_write_failure_after_registry_retains_tombstone(self):
        original = registry.write_private
        def fail(path, data):
            if Path(path) == self.state / "config.json":
                raise InjectedCrash("shares publication")
            return original(path, data)
        with patch.object(registry, "write_private", side_effect=fail), self.assertRaises(InjectedCrash):
            self.commit()
        self.assertIn(self.target.name, registry.load_registry()["vms"])
        self.assert_old_preserved(self.tombstone)
        self.assert_recovery_blocks_next_job()

    def test_pre_rmtree_failure_preserves_tombstone_and_blocks_restart(self):
        def fail(path, *args, **kwargs):
            # Confirm every attempted delete is exactly the disposable old fixture.
            self.assertEqual(Path(path).resolve(strict=True), self.tombstone)
            self.assertTrue(Path(path).is_relative_to(self.root))
            raise InjectedCrash("before deleting old contents")
        with patch.object(lifecycle.shutil, "rmtree", side_effect=fail), self.assertRaises(InjectedCrash):
            self.commit()
        self.assertTrue(self.target.exists())
        self.assert_old_preserved(self.tombstone)
        self.assertEqual(registry.read_private(self.journal)["phase"], "new_published")
        self.assert_recovery_blocks_next_job()

    def test_post_publish_directory_sync_failure_never_deletes_old(self):
        original = registry.sync_directory
        def fail(path):
            if Path(path) == self.vms and self.target.exists():
                raise InjectedCrash("publication directory fsync")
            return original(path)
        with patch.object(registry, "sync_directory", side_effect=fail), self.assertRaises(InjectedCrash):
            self.commit()
        self.assert_old_preserved(self.tombstone)
        self.assertTrue(self.target.exists())
        self.assert_recovery_blocks_next_job()

    def test_final_journal_failure_quarantines_even_after_old_removal(self):
        original = registry.write_private
        def fail(path, data):
            if Path(path) == self.journal and data.get("phase") == "committed_old_removed":
                raise InjectedCrash("final journal publication")
            return original(path, data)
        with patch.object(registry, "write_private", side_effect=fail), self.assertRaises(InjectedCrash):
            self.commit()
        self.assertFalse(self.tombstone.exists())
        self.assertTrue(self.target.exists())
        self.assertIn(self.target.name, registry.load_registry()["vms"])
        self.assert_recovery_blocks_next_job()

    def test_registry_size_limit_rejected_before_first_rename(self):
        registry.write_private(registry.REGISTRY_PATH, {"version": 1, "retired": [], "vms": {
            "existing-" + str(i): {"environment_id": format(i, "032x")} for i in range(128)
        }})
        with patch.object(lifecycle.os, "rename") as rename, self.assertRaises(ValueError):
            self.commit()
        rename.assert_not_called()
        self.assert_old_preserved(self.old)
        self.assertTrue(self.stage.exists())
        self.assertFalse(self.journal.exists())

    def test_successful_synthetic_commit_clears_recovery_and_preserves_unrelated_shares(self):
        self.commit()
        self.assertEqual(registry.read_private(self.journal)["phase"], "committed_old_removed")
        self.assertFalse(lifecycle.status().get("recovery_required", False))
        self.assertFalse(self.old.exists())
        self.assertFalse(self.tombstone.exists())
        self.assertEqual((self.target / "disk.img").read_bytes(), b"NEW SYNTHETIC TEXT; NOT A VIRTUAL DISK")
        shares = registry.read_private(self.state / "config.json")
        self.assertEqual(shares["vms"]["unrelated-vm"]["shares"], [{"name": "keep"}])

    def test_private_json_fsyncs_parent_after_atomic_replace(self):
        events = []
        replace = os.replace
        sync = registry.sync_directory
        target = self.state / "durability-test.json"
        def record_replace(src, dst):
            events.append(("replace", Path(dst)))
            return replace(src, dst)
        def record_sync(path):
            events.append(("sync", Path(path)))
            return sync(path)
        with patch.object(registry.os, "replace", side_effect=record_replace), \
             patch.object(registry, "sync_directory", side_effect=record_sync):
            registry.write_private(target, {"test": True})
        self.assertIn(("replace", target), events)
        self.assertIn(("sync", target.parent), events)
        self.assertLess(events.index(("replace", target)), len(events) - 1)
        self.assertEqual(events[-1], ("sync", target.parent))


if __name__ == "__main__":
    unittest.main()
