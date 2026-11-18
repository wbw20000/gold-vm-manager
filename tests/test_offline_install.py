"""Private-directory transaction fixtures. No real apps, tools, mounts, or VMs."""
from pathlib import Path
import json
import os
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import guest_app_artifacts as a
import offline_install as i


class WriteAttribution:
    data_uuid='fixture-data'
    volume_group_uuid='fixture-group'


class ReadAttribution(WriteAttribution):pass


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='offline-install-test-')
        self.root=Path(self.tmp.name).resolve();self.addCleanup(self.cleanup)
        self.mask=os.umask(0o077);self.addCleanup(os.umask,self.mask)
        self.mount=self.root/'mount';self.apps=self.mount/'Applications'
        self.apps.mkdir(parents=True);(self.mount/'Users'/'Shared').mkdir(parents=True)
        self.session=SimpleNamespace(attribution=WriteAttribution(),mountpoint=self.mount,summary={},
            check_mounted_writable=lambda:None,check_mounted_readonly=lambda:None)
        self.patch(patch.object(i.offline_volume,'WritableAttribution',WriteAttribution,create=True))
        self.patch(patch.object(i.offline_volume,'OfflineAttribution',ReadAttribution))
        self.patch(patch.object(i.os.path,'ismount',side_effect=lambda p:Path(p)==self.mount))
        self.patch(patch.object(i.quarantine_policy,'read',return_value=b'0083;fixture'))
        self.propagate=self.patch(patch.object(i.quarantine_policy,'propagate',return_value=b'0083;fixture'))
        self.patch(patch.object(i.os,'statvfs',return_value=SimpleNamespace(f_bavail=100*1024**3,f_frsize=1)))
        self.materials=[];self.receipts=[]
        urls={
          'ccbaga':'https://github.com/liseami/CCBaga/releases/download/v1.2.3/CCBaga-1.2.3-macos-arm64.dmg',
          'clashVergeRev':'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v1.2.3/Clash.Verge_1.2.3_aarch64.dmg',
          'claudeDesktop':'https://downloads.claude.ai/releases/darwin/universal/1.2.3/Claude-'+('a'*40)+'.zip'}
        for product in i.PRODUCTS:
            root=self.root/product;root.mkdir()
            manifest=a.freeze_manifest(product=product,version='1.2.3',artifact_url=urls[product],known_sha256='b'*64)
            apps=[];proof=[]
            for app in manifest.expected_apps:
                path=root/app.name;(path/'Contents').mkdir(parents=True)
                (path/'Contents'/'fixture').write_bytes(b'not an application; never executed')
                tree=a._tree_snapshot(path,manifest)
                proof.append({'name':app.name,'bundle_tree_sha256':tree[0],'bundle_bytes':tree[1],'bundle_entries':tree[2]})
                apps.append(path)
            self.materials.append(i.Material(manifest,SimpleNamespace(),root,tuple(apps)))
            self.receipts.append(SimpleNamespace(apps=tuple(proof)))
        self.materials=tuple(self.materials);self.receipts=tuple(self.receipts)
        def verify(manifest,root,paths,receipt):
            return self.receipts[i.PRODUCTS.index(manifest.product)]
        self.verify=self.patch(patch.object(i.artifacts,'verify_app_bundles',side_effect=verify))
        self.calls=[]

    def patch(self,p):
        result=p.start();self.addCleanup(p.stop);return result

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(),self.root)
        self.assertTrue(self.root.name.startswith('offline-install-test-'))
        self.tmp.cleanup()

    def copier(self,argv,**kwargs):
        self.calls.append(argv)
        self.assertEqual(argv[0],'/usr/bin/ditto')
        source,target=Path(argv[1]),Path(argv[2])
        self.assertEqual(target.parent,self.apps)
        self.assertEqual(list(target.iterdir()),[])
        shutil.copytree(source,target,dirs_exist_ok=True,symlinks=True)
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')

    def install(self,run=None,ack=True,retained=()):
        return i.write_applications(self.session,self.materials,self.root/'evidence',
                                    acknowledge_write=ack,verified_existing=retained,run=run or self.copier)

    def status(self):return json.loads((self.root/'evidence/transaction.json').read_text())

    def test_complete_copy_is_still_not_preinstalled_until_readonly_remount(self):
        self.install()
        self.assertEqual(set(p.name for p in self.apps.iterdir()),set(i.APP_NAMES))
        self.assertTrue(all((p.stat().st_mode & 0o7777) == 0o755 for p in self.apps.iterdir()))
        self.assertEqual(len(self.calls),4)
        self.assertEqual(self.status()['phase'],'copied_requires_detach_and_readonly_verification')
        self.assertFalse(self.status()['applications_preinstalled'])
        self.assertFalse(self.status()['guest_started'])
        self.assertFalse((self.mount/'private/var/db/.AppleSetupDone').exists())

    def test_write_ack_and_distinct_attribution_are_mandatory(self):
        with self.assertRaises(i.InstallError):self.install(ack=False)
        self.verify.assert_not_called()
        self.session.attribution=ReadAttribution()
        with self.assertRaises(i.InstallError):self.install()
        self.verify.assert_not_called();self.assertEqual(self.calls,[])

    def test_failed_source_signature_never_claims_guest_paths(self):
        self.verify.side_effect=a.ArtifactError('signature-rejected')
        with self.assertRaises(a.ArtifactError):self.install()
        self.assertEqual(list(self.apps.iterdir()),[])
        self.assertFalse((self.root/'evidence').exists())

    def test_existing_app_never_overwritten_or_deleted(self):
        existing=self.apps/'Claude.app';existing.mkdir();(existing/'sentinel').write_text('keep')
        with self.assertRaises(i.InstallError):self.install()
        self.assertEqual((existing/'sentinel').read_text(),'keep')
        self.assertEqual(self.calls,[])

    def test_partial_copy_failure_is_durable_and_not_retried(self):
        def fail_second(argv,**kw):
            if len(self.calls)==1:
                self.calls.append(argv)
                return SimpleNamespace(returncode=1,stdout=b'',stderr=b'fixture failure')
            return self.copier(argv,**kw)
        with self.assertRaises(i.InstallError):self.install(run=fail_second)
        self.assertEqual(self.status()['phase'],'failed_quarantined')
        self.assertFalse(self.status()['applications_preinstalled'])
        self.assertEqual(self.status()['completed_apps'],['CCBaga-A.app'])
        self.assertTrue((self.apps/'CCBaga-A.app').exists())
        self.assertTrue((self.apps/'CCBaga-B.app').exists())
        self.assertFalse((self.apps/'Claude.app').exists())
        with self.assertRaises(FileExistsError):self.install()

    def test_tampered_copy_not_accepted(self):
        def mutate(argv,**kw):
            result=self.copier(argv,**kw)
            (Path(argv[2])/'Contents'/'fixture').write_bytes(b'tampered')
            return result
        with self.assertRaises(i.InstallError):self.install(run=mutate)
        self.assertEqual(self.status()['phase'],'failed_quarantined')
        self.assertEqual(self.status()['completed_apps'],[])

    def test_existing_home_and_completed_setup_refused(self):
        (self.mount/'Users'/'existing-person').mkdir()
        with self.assertRaises(i.InstallError):self.install()
        self.assertEqual(self.calls,[])

    def test_insufficient_guest_space_refused_before_copy(self):
        with patch.object(i.os,'statvfs',return_value=SimpleNamespace(f_bavail=1,f_frsize=1)):
            with self.assertRaises(i.InstallError):self.install()
        self.assertEqual(self.calls,[])

    def test_readonly_reverification_requires_new_mode_and_same_uuid(self):
        self.install()
        with self.assertRaises(i.InstallError):
            i.verify_installed_readonly(self.session,self.materials,self.receipts,expected_data_uuid='fixture-data',expected_group_uuid='fixture-group')
        self.session.attribution=ReadAttribution()
        with self.assertRaises(i.InstallError):
            i.verify_installed_readonly(self.session,self.materials,self.receipts,expected_data_uuid='wrong',expected_group_uuid='fixture-group')
        result=i.verify_installed_readonly(self.session,self.materials,self.receipts,expected_data_uuid='fixture-data',expected_group_uuid='fixture-group')
        self.assertEqual(len(result),3)

    def test_verified_complete_prefix_is_retained_never_recopied(self):
        source=self.materials[0].app_paths[0];target=self.apps/source.name
        shutil.copytree(source,target,symlinks=True)
        before=a._tree_snapshot(target,self.materials[0].manifest)
        self.install(retained=('CCBaga-A.app',))
        self.assertEqual(len(self.calls),3)
        self.assertTrue(all(Path(call[2]).name!='CCBaga-A.app' for call in self.calls))
        self.assertEqual(a._tree_snapshot(target,self.materials[0].manifest),before)
        self.propagate.assert_any_call(source,target)
        self.assertEqual(self.propagate.call_count,4)
        self.assertFalse(self.status()['applications_preinstalled'])
        self.assertEqual(self.status()['completed_apps'],list(i.APP_NAMES))
        retained=json.loads((self.root/'evidence/CCBaga-A.app.retained.json').read_text())
        self.assertFalse(retained['application_bytes_overwritten'])

    def test_changed_prefix_is_never_overwritten_or_repaired(self):
        source=self.materials[0].app_paths[0];target=self.apps/source.name
        shutil.copytree(source,target,symlinks=True)
        (target/'Contents/fixture').write_bytes(b'changed partial copy')
        with self.assertRaises(i.InstallError):self.install(retained=('CCBaga-A.app',))
        self.assertEqual((target/'Contents/fixture').read_bytes(),b'changed partial copy')
        self.assertEqual(self.calls,[]);self.propagate.assert_not_called()

    def test_nonprefix_or_unprovided_retained_copy_is_rejected(self):
        for prefix in (('Clash Verge.app',),('CCBaga-B.app',),('CCBaga-A.app','Claude.app')):
            with self.subTest(prefix=prefix),self.assertRaises(i.InstallError):self.install(retained=prefix)
        self.assertEqual(self.calls,[])

    def test_origin_failure_on_retained_copy_never_runs_ditto(self):
        source=self.materials[0].app_paths[0];target=self.apps/source.name
        shutil.copytree(source,target,symlinks=True)
        self.propagate.side_effect=i.quarantine_policy.QuarantineError('different origin')
        with self.assertRaises(i.quarantine_policy.QuarantineError):self.install(retained=('CCBaga-A.app',))
        self.assertEqual(self.calls,[])
        self.assertEqual(self.status()['phase'],'failed_quarantined')
        self.assertFalse(self.status()['applications_preinstalled'])
        self.assertEqual((target/'Contents/fixture').read_bytes(),b'not an application; never executed')

    def test_partial_product_set_rejected(self):
        with self.assertRaises(i.InstallError):i.validate_material_set(self.materials[:2])


if __name__=='__main__':unittest.main()
