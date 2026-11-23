"""Isolated synthetic filesystem tests. Never create/delete/boot a real VM."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import lifecycle as l
import managed_registry as r


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-lifecycle-unit-', dir='/private/tmp')).resolve(strict=True)
        self.expected_root = self.root
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.tart = self.root / 'tart'; self.tart.mkdir(mode=0o700)
        self.vms = self.tart / 'vms'; self.vms.mkdir(mode=0o700)
        self.patches = [patch.object(l, 'STATE', self.state), patch.object(l, 'TART_HOME', self.tart),
            patch.object(l, 'VM_ROOT', self.vms), patch.object(r, 'STATE_DIR', self.state),
            patch.object(r, 'REGISTRY_PATH', self.state / 'registry.json')]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.assertEqual(self.root.resolve(strict=True), self.expected_root)
        self.assertEqual(self.root.parent, Path('/private/tmp'))
        self.assertTrue(self.root.name.startswith('gold-lifecycle-unit-'))
        self.assertFalse(self.root.is_symlink())
        shutil.rmtree(str(self.root))

    def payload(self, **changes):
        d = {'mode':'create','name':'用户的新 VM','acknowledge_setup':True}
        d.update(changes); return d

    def fake_vm(self, name, ecid='old-id', mac='a2:00:00:00:00:01'):
        p = self.vms / name; p.mkdir(mode=0o700)
        r.write_private(p/'config.json', {'os':'darwin','ecid':ecid,'macAddress':mac})
        (p/'disk.img').write_bytes(b'fake disk not a real VM')
        (p/'nvram.bin').write_bytes(b'fake nvram')
        return p

    def commit_fixture(self, rename=False):
        old = self.fake_vm('gold')
        jid = 'a'*32
        stage = self.tart / '.gold-manager-staging' / jid / 'new-environment'
        stage.mkdir(mode=0o700, parents=True)
        r.write_private(stage/'config.json', {'os':'darwin','ecid':'fresh-id','macAddress':'a2:00:00:00:00:02'})
        (stage/'disk.img').write_bytes(b'fresh synthetic data')
        base = self.state / 'environments' / jid; base.mkdir(mode=0o700, parents=True)
        r.private_dir(self.state/'build-jobs'/jid)
        r.write_private(self.state/'config.json', {'version':1,'vms':{'gold':{'shares':[]},'gold-fresh':{'shares':[]}}})
        d = self.payload(mode='rebuild', source_vm='gold', name='新环境' if rename else 'gold',
             confirm_name='gold', acknowledge_erase=True, source_identity=l.source_identity('gold'), id=jid)
        return old, stage, base, d

    def test_defaults_are_two_cpu_four_gib(self):
        d=l.validated_request(self.payload(), set(), host_cpu=10,host_memory=64)
        self.assertEqual((d['cpu'],d['memory_gib'],d['disk_gib']),(2,4,50))
        self.assertEqual(d['name'],'用户的新 VM')

    def test_resources_are_editable_but_strict(self):
        d=l.validated_request(self.payload(cpu=4,memory_gib=6,disk_gib=80),set(),host_cpu=10,host_memory=64)
        self.assertEqual((d['cpu'],d['memory_gib'],d['disk_gib']),(4,6,80))
        for key,value in [('cpu',True),('cpu',1),('cpu',11),('memory_gib',3),('memory_gib',65),('disk_gib',-1),('cpu',2.0)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                l.validated_request(self.payload(**{key:value}),set(),host_cpu=10,host_memory=64)

    def test_new_disk_range_for_create_rebuild_and_offline(self):
        image = self.root / 'synthetic.ipsw'
        image.write_bytes(b'fixture only')
        for payload in (self.payload(), self.payload(mode='rebuild', source_vm='gold', confirm_name='gold', acknowledge_erase=True),
                        self.payload(mode=l.OFFLINE_MODE, ipsw=str(image), acknowledge_offline=True)):
            for size in (30, 31, 49, 50, 137, 1024):
                with self.subTest(mode=payload['mode'], size=size):
                    self.assertEqual(l.validated_request(dict(payload, disk_gib=size), {'gold'})['disk_gib'], size)
            for size in (29, 1025, True, 30.0, 30.5, '30', None):
                with self.subTest(mode=payload['mode'], size=size), self.assertRaises(ValueError):
                    l.validated_request(dict(payload, disk_gib=size), {'gold'})

    def test_names_reject_paths_and_unsafe_characters(self):
        for name in ['', '../gold', '.hidden','-flag','a/b','a\\b','a:b','a,b','a\n',' gold','gold ','a"b','a\x00b','x'*65]:
            with self.subTest(name=name),self.assertRaises(ValueError):r.validate_name(name)
        for name in ['gold','中文 VM','new_vm-2']:self.assertEqual(r.validate_name(name),name)

    def test_rebuild_requires_explicit_exact_confirmation(self):
        d=self.payload(mode='rebuild',source_vm='gold',confirm_name='gold',acknowledge_erase=True)
        l.validated_request(d,{'gold'})
        for change in [{'confirm_name':'gold-backup'},{'acknowledge_erase':1},{'acknowledge_erase':False},{'source_vm':'unknown'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):l.validated_request(dict(d,**change),{'gold'})

    def test_no_implicit_user_setup_consent(self):
        for value in [None,False,1,'true']:
            with self.assertRaises(ValueError):l.validated_request(self.payload(acknowledge_setup=value),set())

    def test_create_never_accepts_delete_target(self):
        with self.assertRaises(ValueError):l.validated_request(self.payload(source_vm='gold'),{'gold'})

    def test_local_ipsw_symlink_rejected(self):
        image=self.root/'test.ipsw';image.write_bytes(b'not an actual ipsw')
        link=self.root/'link.ipsw';link.symlink_to(image)
        with self.assertRaises(ValueError):l.validated_request(self.payload(ipsw=str(link)),set())
        self.assertEqual(l.validated_request(self.payload(ipsw=str(image)),set())['ipsw'],str(image))

    def test_apple_download_url_allowlist(self):
        for u in ['https://updates.cdn-apple.com/a.ipsw','https://updates.apple.com/a.ipsw']:self.assertTrue(l.apple_url(u))
        for u in ['http://updates.apple.com/a','https://evil.invalid/a','https://updates.apple.com.evil.invalid/a','https://x:secret@updates.apple.com/a','https://127.0.0.1/a','file:///tmp/a']:
            self.assertFalse(l.apple_url(u))

    def test_destination_collision_is_case_insensitive(self):
        with self.assertRaises(ValueError):l.validate_destination({'name':'GOLD','source_vm':None},{'gold':{'State':'stopped'}})

    def test_running_predecessor_rejected(self):
        with self.assertRaises(ValueError):l.validate_destination({'name':'gold','source_vm':'gold'},{'gold':{'State':'running'}})

    def test_linux_predecessor_not_silently_replaced(self):
        p=self.fake_vm('linux')
        r.write_private(p/'config.json',{'os':'linux'})
        with self.assertRaises(ValueError):l.source_identity('linux')

    def test_identity_comparison_rejects_mac_and_ecid_reuse(self):
        self.fake_vm('gold')
        stage=self.root/'stage';stage.mkdir(mode=0o700)
        for ecid,mac in [('old-id','a2:00:00:00:00:02'),('new-id','a2:00:00:00:00:01')]:
            r.write_private(stage/'config.json',{'ecid':ecid,'macAddress':mac})
            with self.assertRaises(ValueError):l.new_identity_check(stage)

    def test_commit_same_name_replaces_only_synthetic_vm(self):
        old,stage,base,d=self.commit_fixture()
        shared=self.root/'host-user-files';shared.mkdir();(shared/'keep.txt').write_text('keep')
        other=self.fake_vm('gold-fresh','different','a2:00:00:00:00:03')
        other_before=(other/'config.json').read_bytes()
        l.commit(d,stage,base,lambda *args:None)
        self.assertEqual((old/'disk.img').read_bytes(),b'fresh synthetic data')
        self.assertFalse((stage.parent/'old-environment').exists())
        self.assertEqual((shared/'keep.txt').read_text(),'keep')
        self.assertEqual((other/'config.json').read_bytes(),other_before)
        self.assertEqual(r.load_registry()['vms']['gold']['environment_id'],'a'*32)
        self.assertEqual(r.read_private(self.state/'config.json')['vms']['gold']['shares'],[])

    def test_commit_new_name_retires_old_registration(self):
        old,stage,base,d=self.commit_fixture(rename=True)
        l.commit(d,stage,base,lambda *args:None)
        self.assertFalse(old.exists())
        self.assertTrue((self.vms/'新环境'/'disk.img').is_file())
        self.assertIn('gold',r.load_registry()['retired'])
        self.assertNotIn('gold',r.registered_bases({'gold':self.root/'old-launcher'}))

    def test_commit_changed_config_never_deletes(self):
        old,stage,base,d=self.commit_fixture()
        r.write_private(old/'config.json',{'os':'darwin','ecid':'changed'})
        with self.assertRaises(ValueError):l.commit(d,stage,base,lambda *args:None)
        self.assertTrue((old/'disk.img').exists());self.assertTrue(stage.exists())

    def test_commit_symlink_inside_old_vm_rejected(self):
        old,stage,base,d=self.commit_fixture()
        external=self.root/'keep';external.write_text('untouched')
        (old/'link').symlink_to(external)
        with self.assertRaises(ValueError):l.commit(d,stage,base,lambda *args:None)
        self.assertEqual(external.read_text(),'untouched');self.assertTrue(stage.exists())

    def test_tart_posix_lock_prevents_delete(self):
        old,stage,base,d=self.commit_fixture()
        code='import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.lockf(f,fcntl.LOCK_EX); print("ready",flush=True); sys.stdin.read(1)'
        child=subprocess.Popen([sys.executable,'-c',code,str(old/'config.json')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'ready')
            with self.assertRaises(BlockingIOError):l.commit(d,stage,base,lambda *args:None)
            self.assertEqual((old/'disk.img').read_bytes(),b'fake disk not a real VM')
        finally:
            child.stdin.write('x');child.stdin.flush();child.wait(timeout=5)
            child.stdin.close();child.stdout.close()

    def test_registry_rejects_unsafe_permissions_duplicates_and_path_ids(self):
        p=self.state/'registry.json'
        for entry in [{'version':1,'vms':{'name':{'environment_id':'../escape'}},'retired':[]}, {'version':True,'vms':{},'retired':[]}]:
            r.write_private(p,entry)
            with self.assertRaises(ValueError):r.load_registry()
        r.write_private(p,{'version':1,'vms':{},'retired':[]});p.chmod(0o644)
        with self.assertRaises(ValueError):r.load_registry()

    def valid_install_output(self, disk_gib=50):
        stage=self.root/'install-output';stage.mkdir(mode=0o700)
        for name in ('disk.img','nvram.bin'):
            fd=os.open(str(stage/name),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try:os.ftruncate(fd,disk_gib*1024**3 if name=='disk.img' else 1)
            finally:os.close(fd)
        r.write_private(stage/'.clean-vm-installer.complete.json',{'schemaVersion':1,'status':'complete','installer':'CleanVMInstaller','networkDeviceCount':0,'directorySharingDeviceCount':0,'socketDeviceCount':0})
        r.write_private(stage/'config.json',{'version':1,'os':'darwin','arch':'arm64','diskFormat':'raw','cpuCountMin':2,'cpuCount':2,'memorySizeMin':4*1024**3,'memorySize':4*1024**3,'ecid':'bmV3LWlk','hardwareModel':'bW9kZWw=','macAddress':'a2:00:00:00:00:02','display':{'width':1024,'height':768,'unit':'px'}})
        return stage,{'cpu':2,'memory_gib':4,'disk_gib':disk_gib}

    def test_verify_custom_disk_size_never_repairs_mismatch(self):
        stage, request = self.valid_install_output(disk_gib=30)
        l.verify_install_output(stage, request)
        with self.assertRaisesRegex(ValueError, '新磁盘容量不匹配'):
            l.verify_install_output(stage, dict(request, disk_gib=31))
        self.assertEqual((stage/'disk.img').stat().st_size, 30 * 1024**3)

    def test_complete_receipt_and_private_outputs_required(self):
        stage,request=self.valid_install_output()
        self.assertEqual(l.verify_install_output(stage,request)['cpuCount'],2)
        r.write_private(stage/'.clean-vm-installer.complete.json',{'schemaVersion':1,'status':'complete','installer':'CleanVMInstaller','networkDeviceCount':1,'directorySharingDeviceCount':0,'socketDeviceCount':0})
        with self.assertRaises(ValueError):l.verify_install_output(stage,request)

    def test_invalid_resource_schema_is_rejected(self):
        stage,request=self.valid_install_output()
        c=r.read_private(stage/'config.json');c['cpuCountMin']=None
        r.write_private(stage/'config.json',c)
        with self.assertRaises(ValueError):l.verify_install_output(stage,request)

    def test_symlink_output_cannot_be_published(self):
        stage,request=self.valid_install_output()
        target=stage/'nvram.bin';self.assertEqual(target.resolve(strict=True),target);target.unlink()
        target.symlink_to(stage/'config.json')
        with self.assertRaises(ValueError):l.verify_install_output(stage,request)

    def assert_legacy_worker(self, mode, disk_gib):
        import provisioning
        import io
        from types import SimpleNamespace
        jid='c'*32;jobdir=self.state/'build-jobs'/jid;r.private_dir(jobdir)
        request=self.payload(mode=mode,id=jid,source_vm=None,source_identity=None,cpu=2,memory_gib=4,disk_gib=disk_gib,ipsw='latest')
        values={}
        if mode=='rebuild':
            self.fake_vm('gold')
            values={'gold':{'State':'stopped'}}
            request.update(source_vm='gold',source_identity=l.source_identity('gold'),confirm_name='gold',acknowledge_erase=True)
        r.write_private(jobdir/'request.json',request)
        r.write_private(self.state/'build-current.json',{'id':jid,'mode':mode,'name':request['name'],'phase':'queued'})
        fd=os.open(str(self.state/'build.lock'),os.O_CREAT|os.O_RDWR,0o600)
        def prepare(name,config,base,artifacts):
            self.assertTrue(base.parent.is_dir())
            self.assertEqual(base.parent.stat().st_mode&0o777,0o700)
            base.mkdir(mode=0o700);(base/'setup').mkdir(mode=0o700)
            # Match prepare_environment's metadata contract used by setup profiles.
            r.write_private(base/'environment.json',{'setup_sha256':{}})
            return {'status':'awaiting_user_setup'}
        child=SimpleNamespace(stdout=io.StringIO('{"event":"complete","schemaVersion":1}\n'),wait=lambda:0)
        try:
            with patch.object(l,'inventory',return_value=values),patch.object(l.shutil,'disk_usage',return_value=SimpleNamespace(free=(disk_gib+20)*1024**3)),patch.object(provisioning,'preflight') as preflight,patch.object(provisioning,'prepare_environment',side_effect=prepare) as provision,patch.object(l,'offline_image',return_value=self.root/'fake.ipsw'),patch.object(l,'helper_json',return_value={'supported':True,'minimumCPUCount':2,'minimumMemorySize':4*1024**3}),patch.object(l.subprocess,'Popen',return_value=child) as install,patch.object(l,'verify_install_output') as verify,patch.object(l,'new_identity_check',return_value={'cpuCount':2,'memorySize':4*1024**3}),patch.object(l,'commit') as commit:
                l.worker(jid,fd)
                stage = self.tart/'.gold-manager-staging'/jid/'new-environment'
                self.assertEqual(install.call_args.args[0], [str(l.HELPER), '--create', '--directory', str(stage),
                    '--ipsw', str(self.root/'fake.ipsw'), '--cpu', '2', '--memory-gib', '4', '--disk-gib', str(disk_gib)])
                verify.assert_called_once_with(stage, request);commit.assert_called_once()
                if mode == 'rebuild':
                    self.assertEqual((self.vms/'gold'/'disk.img').stat().st_size, len(b'fake disk not a real VM'))
                preflight.assert_called_once();provision.assert_called_once()
            current=r.read_private(self.state/'build-current.json')
            self.assertEqual(current['phase'],'awaiting_user_setup')
            self.assertEqual(current['old_deleted'],mode=='rebuild')
            self.assertEqual(commit.call_args.args[0]['source_vm'],request['source_vm'])
            self.assertNotIn('system_restored',current)
            base=self.state/'environments'/jid
            metadata=r.read_private(base/'environment.json')
            self.assertEqual(metadata['setup_sha256']['profile.json'],l.fingerprint(base/'setup/profile.json'))
            self.assertEqual(set(p.name for p in self.vms.iterdir()),set(values))
        finally:os.close(fd)

    def test_first_create_makes_private_environment_parent(self):
        self.assert_legacy_worker('create', 30)

    def test_legacy_rebuild_still_provisions_and_commits(self):
        self.assert_legacy_worker('rebuild', 1024)

    def test_interrupted_job_never_auto_resumes(self):
        r.write_private(self.state/'build-current.json',{'id':'b'*32,'phase':'installing','pid':123,'name':'new'})
        with patch.object(l,'job_alive',return_value=False):self.assertEqual(l.status()['phase'],'interrupted')
        self.assertEqual(list(self.vms.iterdir()),[])

if __name__=='__main__':unittest.main()
