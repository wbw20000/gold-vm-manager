"""Lifecycle and cleanup fixtures only; every system command is forbidden/mocked."""
import dataclasses
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import managed_registry as r
import offline_disk as d


class WritableOwnershipRecheckTests(unittest.TestCase):
    def test_requested_mode_must_still_match_on_each_check(self):
        from offline_writable import WritableDiskSession
        for mode, expected in [('on', True), ('off', False)]:
            with self.subTest(mode=mode):
                session = object.__new__(WritableDiskSession)
                session.mountpoint, session.attribution, session.ownership_mode = '/dummy', object(), mode
                for changed in ({'GlobalPermissionsEnabled': not expected}, {}, {'GlobalPermissionsEnabled': int(expected)}):
                    records = [plistlib.dumps({'GlobalPermissionsEnabled': expected}), plistlib.dumps(changed)]
                    with patch.object(session, '_check_mounted_write_metadata', side_effect=records), patch('offline_writable.volume.validate_mounted_writable') as verify:
                        session.check_mounted_writable()
                        with self.assertRaises(d.OfflineDiskError):
                            session.check_mounted_writable()
                        verify.assert_called_once()


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='offline-stage-test-')
        self.root=Path(self.tmp.name).resolve()
        self.addCleanup(self.cleanup)
        self.mask=os.umask(0o077);self.addCleanup(os.umask,self.mask)
        self.state=self.root/'state';self.tart=self.root/'tart'
        self.jid='a'*32
        self.stage=self.tart/'.gold-manager-staging'/self.jid/'new-environment'
        for p in (self.state/'build-jobs'/self.jid,self.stage):p.mkdir(parents=True,mode=0o700)
        self.current={'id':self.jid,'name':'new-fixture','mode':'offline_validate','source_vm':None,
            'phase':'awaiting_offline_preinstall','system_restored':True,'guest_started':False,
            'applications_preinstalled':False,'desktop_verified':False,'credentials_copied':False,
            'stage_path':str(self.stage)}
        r.write_private(self.state/'build-current.json',self.current)
        r.write_private(self.state/'build-jobs'/self.jid/'request.json',
            {'id':self.jid,'name':'new-fixture','mode':'offline_validate','source_vm':None,'disk_gib':1})
        r.write_private(self.stage/'.clean-vm-installer.complete.json',
            {'installer':'CleanVMInstaller','status':'complete','schemaVersion':1,
             'networkDeviceCount':0,'directorySharingDeviceCount':0,'socketDeviceCount':0})
        for name in ('config.json','nvram.bin','disk.img'):(self.stage/name).write_bytes(b'fixture')
        with (self.stage/'disk.img').open('r+b') as f:f.truncate(1024**3)
        (self.state/'build.lock').write_bytes(b'')
        self.runner=patch.object(d.subprocess,'run',side_effect=AssertionError('real command forbidden'))
        self.runner.start();self.addCleanup(self.runner.stop)

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(),self.root)
        self.assertTrue(self.root.name.startswith('offline-stage-test-'))
        self.tmp.cleanup()

    def load(self):return d.StageTarget.load(self.state,self.tart,self.jid,'new-fixture')

    def test_only_never_booted_private_restore_target(self):
        target=self.load()
        self.assertEqual(target.image,self.stage/'disk.img')
        with target.locked():target.verify_unchanged()

    def test_unsafe_stage_states_are_rejected_before_subprocess(self):
        for key,value in (('phase','awaiting_user_setup'),('mode','create'),('source_vm','google1'),
                          ('guest_started',True),('applications_preinstalled',True),
                          ('system_restored',False),('credentials_copied',True),
                          ('stage_path',str(self.root))):
            with self.subTest(key=key):
                r.write_private(self.state/'build-current.json',dict(self.current,**{key:value}))
                with self.assertRaises(d.OfflineDiskError):self.load()

    def test_published_stage_rejected(self):
        (self.tart/'vms'/'new-fixture').mkdir(parents=True)
        with self.assertRaises(d.OfflineDiskError):self.load()

    def test_savedstate_rejected(self):
        (self.stage/'state.vzvmsave').write_bytes(b'no')
        with self.assertRaises(d.OfflineDiskError):self.load()

    def test_failed_operation_review_is_explicit_and_readonly(self):
        op='b'*32
        value=dict(self.current,phase='failed',recovery_required=True,
                   offline_preinstall={'operation_id':op,'active':False,'phase':'failed_quarantined'})
        r.write_private(self.state/'build-current.json',value)
        with self.assertRaises(d.OfflineDiskError):self.load()
        with self.assertRaises(d.OfflineDiskError):
            d.StageTarget.load(self.state,self.tart,self.jid,'new-fixture',review_failed_operation_id='c'*32)
        target=d.StageTarget.load(self.state,self.tart,self.jid,'new-fixture',review_failed_operation_id=op)
        self.assertTrue(target.readonly_review)
        with self.assertRaises(d.OfflineDiskError):
            d.DiskSession(target,self.root/'forbidden-write',lock_held=True,probe_writable_attachment=True)
        self.assertFalse((self.root/'forbidden-write').exists())
        readonly=d.DiskSession(target,self.root/'readonly-review',lock_held=True)
        self.assertTrue(readonly.target.readonly_review)

    def test_failed_review_cannot_relax_booted_or_published_guards(self):
        op='b'*32
        value=dict(self.current,phase='failed',recovery_required=True,guest_started=True,
                   offline_preinstall={'operation_id':op,'active':False})
        r.write_private(self.state/'build-current.json',value)
        with self.assertRaises(d.OfflineDiskError):
            d.StageTarget.load(self.state,self.tart,self.jid,'new-fixture',review_failed_operation_id=op)

    def test_image_changed_after_binding_is_rejected(self):
        target=self.load()
        with target.image.open('r+b') as f:f.write(b'changed')
        with self.assertRaises(d.OfflineDiskError):target.verify_unchanged()

    def test_wrong_receipt_rejected(self):
        r.write_private(self.stage/'.clean-vm-installer.complete.json',{'status':'complete'})
        with self.assertRaises(d.OfflineDiskError):self.load()

    def test_missing_lock_claim_and_reused_evidence_refused(self):
        target=self.load()
        with self.assertRaises(d.OfflineDiskError):d.DiskSession(target,self.root/'evidence')
        session=d.DiskSession(target,self.root/'evidence',lock_held=True)
        with self.assertRaises(FileExistsError):d.DiskSession(target,self.root/'evidence',lock_held=True)
        with self.assertRaises(d.OfflineDiskError):session.mount_readonly_for_probe()

    def test_existing_attachment_is_not_adopted_or_detached(self):
        target=self.load();calls=[]
        def fake(argv,**kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0,stdout=plistlib.dumps({'images':[{'image-path':str(target.image)}]}),stderr=b'')
        session=d.DiskSession(target,self.root/'evidence',lock_held=True,run=fake)
        with self.assertRaises(d.OfflineDiskError):session.__enter__()
        self.assertEqual(calls,[['/usr/bin/hdiutil','info','-plist']])

    def test_cleanup_never_adopts_replacement_attachment(self):
        target=self.load();calls=[]
        original={'image-path':str(target.image),'writeable':False,'owner-uid':os.getuid(),'hdid-pid':123,
                  'system-entities':[{'dev-entry':'/dev/disk9','content-hint':'GUID_partition_scheme'}]}
        current=[original]
        def fake(argv,**kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0,stdout=plistlib.dumps({'images':current}),stderr=b'')
        session=d.DiskSession(target,self.root/'evidence',lock_held=True,run=fake)
        session.attach_started=True;session.attach_devices=frozenset(('/dev/disk9',))
        session.owned();calls.clear()
        current[0]=dict(original,**{'hdid-pid':124})
        with self.assertRaises(d.OfflineDiskError):session.cleanup()
        self.assertTrue(session.summary['manual_review_required'])
        self.assertTrue(all('detach' not in argv and 'unmount' not in argv for argv in calls))
        for change in ({'writeable':True},{'owner-uid':os.getuid()+1},
                       {'system-entities':[{'dev-entry':'/dev/disk908','content-hint':'GUID_partition_scheme'}]}):
            current[0]=dict(original,**change)
            with self.subTest(change=change),self.assertRaises(d.OfflineDiskError):session.owned()
        self.assertTrue(all('detach' not in argv for argv in calls))

    def test_unknown_failed_attach_is_never_adopted_for_cleanup(self):
        target=self.load()
        mapping={'image-path':str(target.image),'writeable':False,'owner-uid':os.getuid(),'hdid-pid':123,
                 'system-entities':[{'dev-entry':'/dev/disk9','content-hint':'GUID_partition_scheme'}]}
        calls=[]
        def fake(argv,**kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0,stdout=plistlib.dumps({'images':[mapping]}),stderr=b'')
        session=d.DiskSession(target,self.root/'evidence',lock_held=True,run=fake)
        session.attach_started=True
        with self.assertRaises(d.OfflineDiskError):session.cleanup()
        self.assertTrue(all('detach' not in argv for argv in calls))

    def test_duplicate_metadata_keys_are_not_normalized_away(self):
        raw=b'<?xml version="1.0"?><plist version="1.0"><dict><key>images</key><array/><key>images</key><array/></dict></plist>'
        with self.assertRaises(d.OfflineDiskError):d.decode(raw)

    def test_device_identifiers_cannot_inject_commands(self):
        for value in ('/dev/disk3','disk3;rm','disk03','disk3s0','disk3s1/../disk0','disk0\n'):
            with self.subTest(value=value),self.assertRaises(d.OfflineDiskError):d.node(value)
        self.assertEqual(d.node('disk12s5'),'/dev/disk12s5')


if __name__=='__main__':unittest.main()
