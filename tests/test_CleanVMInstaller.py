"""Non-destructive helper tests. Never invoke --create or any Tart command."""
import json
import os
from pathlib import Path
import platform
import plistlib
import stat
import subprocess
import tempfile
import unittest

import host_tools

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "CleanVMInstaller.swift").read_text(encoding="utf-8")


@unittest.skipUnless((platform.system(), platform.machine(), platform.mac_ver()[0]) ==
                     ("Darwin", "arm64", "26.6.2"), "Reviewed Apple Silicon test host required")
class CleanVMInstallerReadOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = Path(tempfile.gettempdir()).resolve(strict=True)
        temporary = tempfile.TemporaryDirectory(prefix="gold-clean-installer-tests-", dir=parent)
        cls.build = Path(temporary.name)
        created = cls.build.lstat()

        def cleanup():
            current = cls.build.lstat()
            assert cls.build.resolve(strict=True) == cls.build
            assert cls.build.parent == parent and cls.build.name.startswith("gold-clean-installer-tests-")
            assert stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid()
            assert (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)
            temporary.cleanup()

        cls.addClassCleanup(cleanup)
        (cls.helper,) = host_tools.compile_helpers(cls.build)

    def invoke(self, *args):
        # Positive allowlist prevents future tests accidentally running create/latest.
        self.assertIn(args[0], ("--help", "--inspect"))
        result = subprocess.run([str(self.helper), *args], capture_output=True, text=True,
                                timeout=30, check=False)
        self.assertGreaterEqual(result.returncode, 0, result.stderr)
        return result

    def error(self, *args, code):
        result = self.invoke(*args)
        self.assertNotEqual(result.returncode, 0)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout)
        message = json.loads(lines[0])
        self.assertEqual(message["event"], "error")
        self.assertEqual(message["code"], code)
        return result

    def test_help(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--latest", result.stdout)
        self.assertIn("--inspect", result.stdout)
        self.assertIn("--cpu 2", result.stdout)
        self.assertIn("zero NICs", result.stdout)

    def test_missing_input(self):
        self.error("--inspect", code="usage")

    def test_duplicate_input(self):
        self.error("--inspect", "--ipsw", "/missing", "--ipsw", "/other", code="usage")

    def test_unknown_input(self):
        self.error("--inspect", "--network", "nat", code="usage")

    def test_remote_input_rejected(self):
        result = self.error("--inspect", "--ipsw", "https://example.invalid/private-token.ipsw", code="unsafe_path")
        self.assertNotIn("private-token", result.stdout)

    def test_relative_input_rejected(self):
        self.error("--inspect", "--ipsw", "relative.ipsw", code="unsafe_path")

    def test_noncanonical_input_rejected(self):
        self.error("--inspect", "--ipsw", "/Users/../private.ipsw", code="unsafe_path")

    def test_invalid_media_async_and_symlink_rejections(self):
        temporary = tempfile.TemporaryDirectory(prefix="CleanVMInstaller-tests-", dir=self.build)
        directory = Path(temporary.name)
        # Verify the absolute cleanup target before TemporaryDirectory removes test fixtures.
        self.assertEqual(directory.resolve().parent, self.build)
        self.assertTrue(directory.name.startswith("CleanVMInstaller-tests-"))
        try:
            invalid = directory / "CleanVMInstaller-invalid.ipsw"
            invalid.write_bytes(b"This is intentionally not an IPSW archive.\n")
            invalid.chmod(0o600)
            before = invalid.stat()
            result = self.error("--inspect", "--ipsw", str(invalid), code="framework_failure")
            self.assertNotIn(str(invalid), result.stdout)
            self.assertEqual(invalid.read_bytes(), b"This is intentionally not an IPSW archive.\n")
            self.assertEqual(before.st_mtime_ns, invalid.stat().st_mtime_ns)
            link = directory / "CleanVMInstaller-symlink.ipsw"
            link.symlink_to(invalid)
            self.error("--inspect", "--ipsw", str(link), code="unsafe_ipsw")
            parent_link = directory / "CleanVMInstaller-parent-link"
            parent_link.symlink_to(directory, target_is_directory=True)
            self.error("--inspect", "--ipsw", str(parent_link / invalid.name), code="unsafe_path")
            invalid.chmod(0o666)
            self.error("--inspect", "--ipsw", str(invalid), code="unsafe_ipsw")
        finally:
            self.assertEqual(directory.resolve().parent, self.build)
            self.assertTrue(directory.name.startswith("CleanVMInstaller-tests-"))
            temporary.cleanup()


class CleanVMInstallerSourceContractTests(unittest.TestCase):
    """Static guardrails, not claims that the create path was executed."""

    def test_no_network_shares_sockets_or_console(self):
        for name in ("networkDevices", "directorySharingDevices", "socketDevices", "serialPorts", "consoleDevices", "audioDevices"):
            self.assertIn(f"configuration.{name} = []", SOURCE)
        for forbidden in ("VZNATNetworkDeviceAttachment", "VZBridgedNetworkDeviceAttachment", "VZVirtioNetworkDeviceConfiguration", "VZVirtioSocketDeviceConfiguration", "VZSharedDirectory", "VZSpiceAgentPortAttachment"):
            self.assertNotIn(forbidden, SOURCE)

    def test_fresh_identity_and_exclusive_output(self):
        self.assertIn("let identifier = VZMacMachineIdentifier()", SOURCE)
        self.assertIn("VZMACAddress.randomLocallyAdministered()", SOURCE)
        self.assertIn("O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW", SOURCE)
        self.assertIn("O_DIRECTORY | O_NOFOLLOW", SOURCE)
        self.assertIn("options: []", SOURCE)
        self.assertNotIn(".allowOverwrite", SOURCE)
        self.assertNotIn("O_TRUNC", SOURCE)
        self.assertNotIn("removeItem", SOURCE)
        self.assertNotIn("unlink(", SOURCE)
        self.assertNotIn("Process()", SOURCE)

    def test_resources_checked_before_first_stage_write(self):
        create = SOURCE[SOURCE.index("private func create("):]
        claim = create.index("try stage.claim()")
        for required in ("cpu_out_of_range", "memory_out_of_range", "disk_too_small", "try stage.checkEmpty()", "try stage.checkCapacity(", "try local.verifyUnchanged()"):
            self.assertLess(create.index(required), claim)
        self.assertIn("configuration.cpuCount = options.cpu", create)
        self.assertNotIn("max(4,", create)

    def test_config_and_receipt_only_after_install(self):
        create = SOURCE[SOURCE.index("private func create("):]
        install = create.index("installer.install { result")
        self.assertGreater(create.index('stage.writeNew("config.json"'), install)
        self.assertGreater(create.index('stage.writeNew(".clean-vm-installer.complete.json"'), install)
        for field in ("cpuCountMin", "memorySizeMin", "ecid", "hardwareModel", "macAddress", "diskFormat"):
            self.assertIn(f'"{field}"', create)
        self.assertIn('"arch": "arm64"', create)
        self.assertIn('"os": "darwin"', create)

    def test_nonblocking_async_main_and_readonly_latest(self):
        self.assertIn("static func main() async", SOURCE)
        self.assertIn("@MainActor", SOURCE)
        self.assertIn("VZMacOSRestoreImage.fetchLatestSupported", SOURCE)
        self.assertIn("VZMacOSRestoreImage.load(from:", SOURCE)
        self.assertNotIn("DispatchSemaphore", SOURCE)
        self.assertNotIn("URLSession", SOURCE)
        self.assertIn('"macOSVersion"', SOURCE)
        self.assertIn('"minimumCPUCount"', SOURCE)
        self.assertIn('"minimumMemorySize"', SOURCE)

    def test_minimal_entitlement(self):
        entitlements = plistlib.loads((ROOT / "CleanVMInstaller.entitlements.plist").read_bytes())
        self.assertEqual(entitlements, {"com.apple.security.virtualization": True})


if __name__ == "__main__":
    unittest.main()
