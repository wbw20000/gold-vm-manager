"""Protected launcher status-file handling with private temporary fixtures only.

No VM, Tart, backend, socket or network is started; only write_status and the
locked stale-staging cleanup run against a disposable private directory.
"""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import protected_launcher as launcher


class StatusFileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-launcher-test-', dir='/tmp')).resolve(strict=True)
        self.root.chmod(0o700)
        self.addCleanup(self.clean_fixture)
        patcher = patch.object(launcher, 'BASE', self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.status = self.root / 'status.json'

    def clean_fixture(self):
        self.assertFalse(self.root.is_symlink())
        self.assertEqual(self.root.parent, Path('/tmp').resolve(strict=True))
        self.assertTrue(self.root.name.startswith('gold-launcher-test-'))
        shutil.rmtree(str(self.root))

    def staging_files(self):
        return sorted(p.name for p in self.root.iterdir() if p.name.endswith('.pending'))

    def test_stale_fixed_staging_file_from_a_crash_does_not_block_status_updates(self):
        stale = self.root / 'status.pending'
        stale.write_text('{"state": "half-written')
        stale.chmod(0o600)
        launcher.write_status(self.status, {'state': 'validating', 'launcher_pid': 1})
        self.assertEqual(json.loads(self.status.read_text()), {'launcher_pid': 1, 'state': 'validating'})
        # The leftover is never adopted as status; only the locked cleanup removes it.
        self.assertEqual(stale.read_text(), '{"state": "half-written')

    def test_repeated_writes_leave_no_staging_files_and_stay_private(self):
        for number in range(3):
            launcher.write_status(self.status, {'n': number})
        self.assertEqual(json.loads(self.status.read_text()), {'n': 2})
        self.assertEqual(self.staging_files(), [])
        self.assertEqual(self.status.stat().st_mode & 0o777, 0o600)

    def test_failed_serialization_keeps_previous_status_and_removes_staging(self):
        launcher.write_status(self.status, {'state': 'running'})
        before = self.status.read_bytes()
        with self.assertRaises(TypeError):
            launcher.write_status(self.status, {'unserializable': object()})
        self.assertEqual(self.status.read_bytes(), before)
        self.assertEqual(self.staging_files(), [])

    def test_symlinked_or_foreign_status_path_is_refused(self):
        target = self.root / 'elsewhere.json'
        target.write_text('{}')
        self.status.symlink_to(target)
        with self.assertRaises(RuntimeError):
            launcher.write_status(self.status, {'state': 'x'})
        self.assertEqual(target.read_text(), '{}')
        self.status.unlink()
        with self.assertRaises(RuntimeError):
            launcher.write_status(self.root / 'other.json', {})
        self.assertEqual(self.staging_files(), [])

    def test_locked_cleanup_removes_only_the_legacy_regular_staging_file(self):
        launcher.remove_stale_status_staging()  # Absent: nothing to do.
        stale = self.root / 'status.pending'
        stale.write_text('partial')
        stale.chmod(0o600)
        launcher.remove_stale_status_staging()
        self.assertFalse(stale.exists())
        keep = self.root / 'keep.txt'
        keep.write_text('keep')
        stale.symlink_to(keep)
        with self.assertRaises(RuntimeError):
            launcher.remove_stale_status_staging()
        self.assertTrue(stale.is_symlink())
        self.assertEqual(keep.read_text(), 'keep')

    def test_cleanup_runs_after_the_run_lock_and_before_the_first_status_write(self):
        source = Path(launcher.__file__).read_text(encoding='utf-8')
        lock = source.index('fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)')
        cleanup = source.index('remove_stale_status_staging()', lock)
        first_write = source.index("write_status(BASE/'status.json',{'state':'validating'", lock)
        self.assertLess(cleanup, first_write)


if __name__ == '__main__':
    unittest.main()
