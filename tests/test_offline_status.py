"""State-only fixtures, no VM/process operations and no production registry."""
import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import lifecycle
import managed_registry as r


class OfflineStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='offline-status-test-')
        self.root=Path(self.tmp.name).resolve();self.addCleanup(self.cleanup)
        (self.root/'build-jobs'/('a'*32)).mkdir(parents=True)
        self.patch=patch.object(lifecycle,'STATE',self.root);self.patch.start();self.addCleanup(self.patch.stop)
        self.process=patch.object(lifecycle.subprocess,'run',side_effect=AssertionError('no processes'))
        self.process.start();self.addCleanup(self.process.stop)
        self.initial={'id':'a'*32,'mode':'offline_validate','name':'gg1','phase':'awaiting_offline_preinstall',
                      'offline_preinstall':{'operation_id':'b'*32,'active':True,'phase':'copying_complete_apps'},
                      'applications_preinstalled':False,'desktop_verified':False,'guest_started':False}
        r.write_private(self.root/'build-current.json',self.initial)

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(),self.root)
        self.assertTrue(self.root.name.startswith('offline-status-test-'))
        self.tmp.cleanup()

    def test_missing_lock_marks_stale_operation_recovery_required(self):
        value=lifecycle.status()
        self.assertEqual(value['phase'],'interrupted')
        self.assertTrue(value['recovery_required'])
        self.assertFalse(value['offline_preinstall']['active'])
        self.assertFalse(value['applications_preinstalled'])
        self.assertEqual(r.read_private(self.root/'build-current.json'),self.initial)

    def test_unheld_existing_lock_is_not_evidence_of_running_worker(self):
        (self.root/'build.lock').write_bytes(b'')
        self.assertTrue(lifecycle.status()['recovery_required'])

    def test_lifecycle_lock_held_keeps_actual_inflight_status(self):
        path=self.root/'build.lock';path.write_bytes(b'')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            value=lifecycle.status()
            self.assertEqual(value['phase'],'awaiting_offline_preinstall')
            self.assertTrue(value['offline_preinstall']['active'])
            self.assertFalse(value.get('recovery_required',False))
        finally:os.close(fd)

    def test_verified_apps_remain_unbooted_and_not_desktop_accepted(self):
        value=dict(self.initial,phase='awaiting_first_desktop_acceptance',applications_preinstalled=True,
                   offline_preinstall={'active':False,'phase':'verified_awaiting_first_desktop'})
        r.write_private(self.root/'build-current.json',value)
        self.assertEqual(lifecycle.status(),value)
        self.assertIn(value['phase'],lifecycle.TERMINAL)
        self.assertNotIn(value['phase'],lifecycle.ACTIVE)
        self.assertFalse(value['desktop_verified']);self.assertFalse(value['guest_started'])


if __name__=='__main__':unittest.main()
