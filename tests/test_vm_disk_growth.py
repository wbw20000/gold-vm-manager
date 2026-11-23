"""Only inert ordinary sparse files below temporary roots. No Tart, guest or hdiutil invocation."""
from contextlib import redirect_stdout
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import vm_disk_growth as growth


class DiskGrowthTest(unittest.TestCase):
    vm = '新机 A'
    jid = 'a' * 32
    old = 30 * growth.GIB + 512  # Sector-aligned, not an integer GiB.
    first = b'fixture head\x00\xff'
    last = b'fixture tail\xff\x00'

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.state = self.home / 'manager'
        self.root = self.home / 'storage' / 'vms'
        self.folder = self.root / self.vm
        self.job = self.state / 'build-jobs' / self.jid
        self.base = self.state / 'environments' / self.jid
        for path in (self.state, self.root.parent, self.root, self.folder,
                     self.job.parent, self.job, self.base.parent, self.base):
            path.mkdir(mode=0o700)
        self.disk = self.folder / 'disk.img'
        self.create_sparse(self.disk)
        self.before = self.contents(self.disk)
        for name in ('build.lock', 'configuration.lock'):
            (self.state / name).touch(mode=0o600)
        self.config = {'version': 1, 'os': 'darwin', 'arch': 'arm64', 'diskFormat': 'raw',
                       'cpuCountMin': 2, 'cpuCount': 2, 'memorySizeMin': 4294967296,
                       'memorySize': 4294967296, 'ecid': 'Zml4dHVyZQ==', 'hardwareModel': 'eA==',
                       'macAddress': '02:00:00:00:00:03', 'display': {'width': 1024, 'height': 768, 'unit': 'px'}}
        self.cfg = self.folder / 'config.json'; self.put(self.cfg, self.config)
        s = self.cfg.stat()
        self.meta = {'version': 3, 'tart_home': str(self.root.parent), 'vm_name': self.vm,
                     'vm_config': str(self.cfg), 'vm_config_identity': [s.st_dev, s.st_ino],
                     'vm_config_sha256': hashlib.sha256(self.cfg.read_bytes()).hexdigest(),
                     'guest_mac': self.config['macAddress'], 'ecid': self.config['ecid']}
        self.put(self.base / 'environment.json', self.meta)
        self.reg = {'version': 1, 'vms': {self.vm: {'environment_id': self.jid}}, 'retired': []}
        self.put(self.state / 'registry.json', self.reg)
        self.commit = {'version': 1, 'mode': 'preinstall', 'id': self.jid, 'environment_id': self.jid,
                       'source_vm': None, 'name': self.vm, 'phase': 'committed_new_registered', 'target': str(self.folder)}
        self.put(self.job / 'commit.json', self.commit)
        self.status = {'id': self.jid, 'mode': 'preinstall', 'name': self.vm, 'source_vm': None,
                       'phase': 'awaiting_first_desktop_acceptance', 'published': True, 'stage_path': None}
        self.put(self.job / 'status.json', self.status)
        self.put(self.state / 'build-current.json', self.status)
        self.row = {'Source': 'local', 'Name': self.vm, 'State': 'stopped', 'Disk': 0, 'Size': 0}
        self.options = {'vm_root': self.root, 'state_dir': self.state, 'known_names': lambda: {self.vm},
                        'inventory': lambda: {self.vm: self.row}, 'expected_environment_id': self.jid}
        self.free = self.patched(growth, '_free', return_value=2048 * growth.GIB)
        self.hdi = self.patched(growth.subprocess, 'run', return_value=self.plist({'images': []}))
        if sys.platform != 'darwin':
            # Non-Darwin production never falls back. These are the only host-specific checks.
            self.patched(growth, '_only_open', return_value=None)
            self.patched(growth, '_require_local', return_value=None)

    def create_sparse(self, path):
        with path.open('xb') as f:
            f.write(self.first); f.seek(self.old - len(self.last)); f.write(self.last)
        path.chmod(0o600)

    @staticmethod
    def contents(path, limit=None):
        # Compare every data extent and the position/size of every zero hole,
        # without reading tens of GiB of known zeros or relying on spot checks.
        size = min(path.stat().st_size, limit) if limit is not None else path.stat().st_size
        spans = []; pos = 0
        with path.open('rb') as f:
            while pos < size:
                try:
                    start = os.lseek(f.fileno(), pos, os.SEEK_DATA)
                except OSError as e:
                    if e.errno == errno.ENXIO: break
                    raise
                if start >= size: break
                end = min(size, os.lseek(f.fileno(), start, os.SEEK_HOLE))
                assert start < end <= start + 1024**2, 'fixture lost sparse storage'
                spans.append((start, os.pread(f.fileno(), end-start, start)))
                pos = end
        return size, spans

    def patched(self, obj, key, **kw):
        p = patch.object(obj, key, **kw); self.addCleanup(p.stop); return p.start()

    @staticmethod
    def put(path, obj):
        path.write_text(json.dumps(obj)); path.chmod(0o600)

    @staticmethod
    def plist(data):
        return SimpleNamespace(returncode=0, stdout=plistlib.dumps(data))

    def grow(self, gib=31, expected=None, **changes):
        return growth.grow(self.vm, gib, self.old if expected is None else expected,
                           **dict(self.options, **changes))

    def reject(self, gib=31, expected=None, **changes):
        # Check *all* original bytes, not only a size assertion or a mocked syscall.
        with patch.object(os, 'ftruncate', side_effect=AssertionError('unexpected mutation')) as mutate:
            with self.assertRaises(growth.GrowthRejected) as caught:
                self.grow(gib, expected, **changes)
            self.assertNotIsInstance(caught.exception, growth.GrowthUncertain)
            self.assertNotIn(str(self.home), str(caught.exception))
            mutate.assert_not_called()
        self.assertEqual(self.contents(self.disk), self.before)

    def test_apparent_size_and_sparse_extension_exact_including_old_last_byte(self):
        self.assertEqual(growth.inspect(self.vm, vm_root=self.root), self.old)
        original = self.disk.stat()
        self.free.return_value = 31 * growth.GIB - self.old + 2 * growth.GIB  # exact threshold
        self.assertEqual(self.grow(), {'ok': True, 'virtual_capacity_bytes': 31 * 1024**3})
        self.assertEqual(self.hdi.call_args.args, (['/usr/bin/hdiutil', 'info', '-plist'],))
        self.assertEqual(growth.inspect(self.vm, vm_root=self.root), 31 * growth.GIB)
        new = self.disk.stat()
        self.assertEqual((new.st_ino, new.st_dev), (original.st_ino, original.st_dev))
        self.assertLess(new.st_blocks * 512, 1024**2)
        with self.disk.open('rb') as f:
            self.assertEqual(self.contents(self.disk, self.old), self.before)
            f.seek(self.old); self.assertEqual(f.read(64), bytes(64)); f.seek(-64, 2); self.assertEqual(f.read(), bytes(64))
        self.free.return_value = 3 * growth.GIB
        self.assertEqual(self.grow(32, 31 * growth.GIB)['virtual_capacity_bytes'], 32 * growth.GIB)

    def test_stale_confirmation_shrink_and_policy_bounds(self):
        for gib, expected in ((29, self.old), (1025, self.old), ('31', self.old), (30.0, self.old),
                              (True, self.old), (30, True), (30, -1), (30, self.old - 1),
                              (30, 30 * growth.GIB), (30, 31 * growth.GIB)):
            with self.subTest(gib=gib, expected=expected): self.reject(gib, expected)

    def test_truncated_or_unaligned_published_image(self):
        # This specific publisher could never have produced a 1 GiB image.
        for size in (growth.GIB, self.old + 1):
            with self.disk.open('rb+') as f: os.ftruncate(f.fileno(), size)
            self.before = self.contents(self.disk)
            self.reject(expected=size)

    def test_replaced_publication_identity_during_inventory(self):
        def inventory():
            self.put(self.state / 'registry.json', {'version': 1, 'vms': {}, 'retired': [self.vm]})
            return {self.vm: self.row}
        self.reject(inventory=inventory)

    def test_unexpected_owner_on_image_descriptor(self):
        real = os.fstat
        inode = self.disk.stat().st_ino
        def fstat(fd):
            info = real(fd)
            if info.st_ino == inode:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid+1, st_nlink=1)
            return info
        with patch.object(os, 'fstat', fstat): self.reject()

    def test_insufficient_real_delta_plus_margin(self):
        self.free.return_value = (31 + 2) * growth.GIB - self.old - 1
        self.reject()

    def test_unsafe_names_and_noncanonical_root(self):
        for bad in ('../else', '/tmp/another.img', '-path', '.hidden', self.vm.lower(), self.vm + '/disk.img'):
            with self.subTest(vm=bad):
                with self.assertRaises(growth.GrowthRejected): growth.inspect(bad, vm_root=self.root)
                with self.assertRaises(growth.GrowthRejected): growth.grow(bad, 30, self.old, **self.options)
        alias = self.home / 'alias'; alias.symlink_to(self.root.parent, target_is_directory=True)
        self.reject(vm_root=alias / 'vms')
        self.reject(known_names=set()); self.reject(expected_environment_id='b' * 32)

    def test_missing_and_retired_registry_not_authorized_by_controller(self):
        self.put(self.state / 'registry.json', {'version': 1, 'vms': {}, 'retired': [self.vm]})
        self.reject()

    def test_config_and_publication_misbindings(self):
        for change in ({'vm_name': 'another'}, {'vm_config': '/secret/other'}, {'guest_mac': 'broken'},
                       {'vm_config_identity': [0, 0]}, {'vm_config_sha256': '0' * 64}, {'version': 1}):
            with self.subTest(change=change):
                self.put(self.base / 'environment.json', dict(self.meta, **change)); self.reject()
        self.put(self.base / 'environment.json', self.meta)
        for change in ({'target': str(self.root / 'other')}, {'phase': 'new_published'}, {'source_vm': self.vm}):
            self.put(self.job / 'commit.json', dict(self.commit, **change)); self.reject()
        self.put(self.job / 'commit.json', self.commit)
        for change in ({'diskFormat': 'asif'}, {'diskPath': '/tmp/another.img'}, {'os': 'linux'}):
            self.put(self.cfg, dict(self.config, **change))
            self.put(self.base / 'environment.json', dict(self.meta, vm_config_sha256=hashlib.sha256(self.cfg.read_bytes()).hexdigest()))
            self.reject()

    def test_symlink_hardlink_file_and_folder(self):
        for file in (self.disk, self.cfg, self.state / 'build.lock', self.state / 'configuration.lock'):
            original = file.with_name(file.name + '.fixture')
            with self.subTest(name=file.name):
                file.rename(original); file.symlink_to(original); self.reject()
                file.unlink(); original.rename(file)
                os.link(file, original); self.reject(); original.unlink()
                file.chmod(0o644); self.reject(); file.chmod(0o600)
        moved = self.root / 'moved'; self.folder.rename(moved); self.folder.symlink_to(moved, target_is_directory=True)
        self.reject()

    def test_fifo_not_opened(self):
        saved = self.folder / 'original'; self.disk.rename(saved); os.mkfifo(self.disk, 0o600)
        with self.assertRaises(growth.GrowthRejected): self.grow()
        self.assertEqual(self.contents(saved), self.before)

    def test_bad_inventory_and_saved_state(self):
        for change in ({'State': 'running'}, {'State': 'suspended'}, {'State': None}, {'Source': 'oci'}, {'Name': 'other'}):
            with self.subTest(change=change):
                self.reject(inventory=lambda: {self.vm: dict(self.row, **change)})
        for name in growth._SAVED + ('control.sock',):
            marker = self.folder / name
            marker.symlink_to(self.folder / 'absent')  # even dangling markers are not proof of offline
            self.reject(); marker.unlink()
        self.reject(inventory=Mock(side_effect=ValueError('secret-auth-info')))

    def test_current_and_retained_busy_journals(self):
        for change in ({'phase': 'publishing'}, {'phase': 'awaiting_vpn_configuration'},
                       {'phase': 'not-recognized'}, {'recovery_required': True},
                       {'stage_path': '/temp/stage'}, {'offline_preinstall': {'active': True}},
                       {'vpn_configuration': {'active': True}}):
            self.put(self.state / 'build-current.json', dict(self.status, **change)); self.reject()
        self.put(self.state / 'build-current.json', self.status)
        other = self.job.parent / ('b' * 32); other.mkdir(mode=0o700)
        self.put(other / 'commit.json', {'phase': 'before_delete', 'source_vm': self.vm}); self.reject()
        (other / 'commit.json').unlink()
        self.put(other / 'status.json', dict(self.status, id=other.name, phase='committing')); self.reject()

    def test_busy_build_registry_and_storage_locks(self):
        for path in (self.state / 'build.lock', self.state / 'configuration.lock', self.root.parent):
            fd = os.open(path, os.O_RDONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); self.reject()
            finally: os.close(fd)
        self.hdi.assert_not_called()

    @staticmethod
    def lock_child(path):
        proc = subprocess.Popen([sys.executable, '-B', '-c',
            "import fcntl,sys; f=open(sys.argv[1],'rb+'); fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('ready',flush=True); sys.stdin.read(1)", str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return proc

    def test_posix_lock_held_in_another_process(self):
        for file in (self.cfg, self.disk):
            with self.lock_child(file) as proc:
                try:
                    self.assertEqual(proc.stdout.readline(), b'ready\n'); self.reject()
                finally: proc.stdin.close(); proc.wait(timeout=5)

    def test_detached_attachment_alias_shadow_malformed_failure_and_timeout(self):
        alias = self.home / 'disk-alias'; alias.symlink_to(self.disk)
        for data in ({'images': [{'image-path': str(alias)}]}, {'images': [{'image-path': str(self.disk)}]},
                     {'images': [{'image-path': str(self.cfg), 'shadow-path': str(alias)}]},
                     {'images': [{'image-path': 'not a path'}]}, {'images': [{}]}, {'images': {}}, {}):
            self.hdi.return_value = self.plist(data); self.reject()
        self.hdi.return_value = SimpleNamespace(returncode=1, stdout=b'secret'); self.reject()
        self.hdi.return_value = SimpleNamespace(returncode=0, stdout=b'not a plist'); self.reject()
        self.hdi.side_effect = subprocess.TimeoutExpired('secret', 1); self.reject()

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin vnode-use check')
    def test_kernel_refuses_even_unlocked_second_open(self):
        with self.disk.open('rb'):
            self.reject()

    def test_substitution_while_querying_detached_state(self):
        saved = self.folder / 'pinned'
        def replace(*args, **kwargs):
            self.disk.rename(saved); self.create_sparse(self.disk)
            return self.plist({'images': []})
        self.hdi.side_effect = replace; self.reject()
        self.assertEqual(self.contents(saved), self.before)

    def test_fsync_failure_after_mutation_never_shrinks(self):
        with patch.object(os, 'fsync', side_effect=OSError('credential fake-text-not-for-client')):
            with self.assertRaises(growth.GrowthUncertain) as caught: self.grow()
        self.assertNotIn('fake-text', str(caught.exception)); self.assertEqual(self.disk.stat().st_size, 31 * growth.GIB)
        self.assertEqual(self.contents(self.disk, self.old), self.before)

    def test_readback_mismatch_is_uncertain_and_not_retried(self):
        with patch.object(os, 'ftruncate', return_value=None) as mutate:
            with self.assertRaises(growth.GrowthUncertain): self.grow()
        mutate.assert_called_once(); self.assertEqual(self.contents(self.disk), self.before)

    def test_worker_schema_and_no_user_controlled_paths(self):
        for argv in (['--grow', '/secret', '30', '1', self.jid], ['--other', 'secret'],
                     ['--grow', self.vm, '30', '1', '/unknown'], ['--grow', self.vm, '30', '1']):
            out = io.StringIO()
            with patch.object(growth, 'grow') as writer, redirect_stdout(out): growth.main(argv)
            writer.assert_not_called(); result = json.loads(out.getvalue())
            self.assertEqual(set(result), {'ok', 'uncertain', 'error'}); self.assertFalse(result['ok'])
            self.assertFalse(result['uncertain']); self.assertNotIn('secret', result['error'])
        out = io.StringIO()
        with patch.object(growth, 'grow', side_effect=growth.GrowthUncertain(growth._PARTIAL)), redirect_stdout(out):
            growth.main(['--grow', self.vm, '30', str(self.old), self.jid])
        self.assertTrue(json.loads(out.getvalue())['uncertain'])


if __name__ == '__main__':
    unittest.main()
