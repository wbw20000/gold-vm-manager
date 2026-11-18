"""Offline lifecycle fixtures only: no real helper, Tart, credentials or state.

The 50 GiB disk is a sparse synthetic file; subprocesses are mocked, and imports
of provisioning are explicitly forbidden even if another test already loaded it.
"""
import builtins
from contextlib import ExitStack
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lifecycle as l
import managed_registry as r


class OfflineValidationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-offline-unit-', dir='/private/tmp')).resolve(strict=True)
        self.expected_root = self.root
        self.umask = os.umask(0o077)
        self.state = self.root / 'state'
        self.tart = self.root / 'synthetic-tart'
        self.vms = self.tart / 'vms'
        self.code = self.root / 'code'
        for path in (self.state, self.tart, self.vms, self.code): path.mkdir(mode=0o700)
        self.helper = self.code / 'CleanVMInstaller'
        self.helper.write_text('NONEXECUTABLE TEST FIXTURE')
        self.image = self.root / 'fixture.ipsw'
        self.image.write_bytes(b'SYNTHETIC IMAGE; NOT A RESTORE IMAGE')
        self.old = self.vms / 'google1'
        self.old.mkdir(mode=0o700)
        r.write_private(self.old / 'config.json', {'os': 'darwin', 'ecid': 'b2xkLWlk', 'macAddress': 'a2:00:00:00:00:01'})
        (self.old / 'disk.img').write_bytes(b'untouched existing VM fixture')
        (self.old / 'nvram.bin').write_bytes(b'untouched existing NVRAM fixture')
        r.write_private(self.state / 'registry.json', {'version': 1, 'vms': {}, 'retired': []})
        r.write_private(self.state / 'config.json', {'version': 1, 'vms': {'google1': {'shares': []}}})
        self.protected = {p: p.read_bytes() for p in (
            self.old / 'config.json', self.old / 'disk.img', self.old / 'nvram.bin',
            self.state / 'registry.json', self.state / 'config.json')}
        self.stack = ExitStack()
        for module, key, value in (
            (l, 'HOME', self.root), (l, 'STATE', self.state), (l, 'TART_HOME', self.tart),
            (l, 'VM_ROOT', self.vms), (l, 'HERE', self.code), (l, 'HELPER', self.helper),
            (l, 'TART', self.code / 'never-run-tart'),
            (l, 'ENV', {'HOME': str(self.root), 'TART_HOME': str(self.tart)}),
            (r, 'HOME', self.root), (r, 'STATE_DIR', self.state),
            (r, 'REGISTRY_PATH', self.state / 'registry.json'),
        ): self.stack.enter_context(patch.object(module, key, value))
        self.values = {'google1': {'State': 'stopped'}}
        self.inventory = self.stack.enter_context(patch.object(l, 'inventory', return_value=self.values))
        self.run = self.stack.enter_context(patch.object(l.subprocess, 'run', side_effect=self.sysctl_only))
        self.spawn = self.stack.enter_context(patch.object(l.subprocess, 'Popen', side_effect=self.fake_restore))
        self.stack.enter_context(patch.object(l.shutil, 'disk_usage', return_value=SimpleNamespace(free=200 * 1024**3)))
        self.info = {'schemaVersion': 1, 'supported': True, 'minimumCPUCount': 2, 'minimumMemorySize': 4 * 1024**3}
        self.inspect = self.stack.enter_context(patch.object(l, 'helper_json', return_value=self.info))
        self.forbidden = []
        for module, key in ((l, 'commit'), (l, 'offline_image'), (l, 'build_opener'),
                            (l, 'source_identity'), (l.setup_profile, 'validate'),
                            (r, 'load_registry'), (r, 'state_lock')):
            self.forbidden.append(self.stack.enter_context(patch.object(module, key, side_effect=AssertionError('Forbidden offline operation: ' + key))))
        self.provisioning_imports = []
        original_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name == 'provisioning' or name.startswith('provisioning.'):
                self.provisioning_imports.append(name)
                raise AssertionError('Offline mode must not even import provisioning')
            return original_import(name, *args, **kwargs)
        self.stack.enter_context(patch('builtins.__import__', side_effect=guarded_import))
        self.jid = 'd' * 32
        self.exit_code = 0
        self.events = '{"event":"progress","percent":25}\n{"event":"complete","schemaVersion":1}\n'
        self.emit_receipt = True
        self.mutate_output = lambda stage: None

    def tearDown(self):
        try:
            for guard in self.forbidden: guard.assert_not_called()
            self.assertEqual(self.provisioning_imports, [])
            for path, content in self.protected.items(): self.assertEqual(path.read_bytes(), content)
            self.assertFalse((self.vms / 'gg1').exists())
            self.assertFalse((self.state / 'environments').exists())
        finally:
            self.stack.close()
            os.umask(self.umask)
            self.assertEqual(self.root.resolve(strict=True), self.expected_root)
            self.assertEqual(self.root.parent, Path('/private/tmp'))
            self.assertTrue(self.root.name.startswith('gold-offline-unit-'))
            self.assertFalse(self.root.is_symlink())
            shutil.rmtree(str(self.root))

    def sysctl_only(self, command, **kwargs):
        self.assertEqual(command, ['/usr/sbin/sysctl', '-n', 'hw.memsize'])
        return SimpleNamespace(stdout=str(64 * 1024**3), returncode=0)

    def payload(self, **changes):
        result = {'mode': 'offline_validate', 'name': 'gg1', 'ipsw': str(self.image), 'acknowledge_offline': True}
        result.update(changes)
        return result

    @property
    def jobdir(self): return self.state / 'build-jobs' / self.jid

    @property
    def stage(self): return self.tart / '.gold-manager-staging' / self.jid / 'new-environment'

    def make_job(self, changes=None, jid=None):
        if jid is not None: self.jid = jid
        request = l.validated_request(self.payload(), self.values, host_cpu=10, host_memory=64)
        request.update(id=self.jid, source_identity=None)
        if changes: request.update(changes)
        r.write_private(self.jobdir / 'request.json', request)
        current = {'id': self.jid, 'mode': 'offline_validate', 'name': 'gg1', 'source_vm': None,
                   'phase': 'queued', 'pid': None, 'started_at': l.timestamp(), 'old_deleted': False}
        current.update(l.offline_status_fields())
        r.write_private(self.state / 'build-current.json', current)
        fd = os.open(str(self.state / 'build.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        self.stack.callback(os.close, fd)
        return fd

    def fake_restore(self, command, **kwargs):
        self.assertEqual(command, [str(self.helper), '--create', '--directory', str(self.stage),
            '--ipsw', str(self.image), '--cpu', '2', '--memory-gib', '4', '--disk-gib', '50'])
        self.assertEqual(list(self.stage.iterdir()), [])
        self.assertEqual(self.stage.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(kwargs['pass_fds']), 1)
        for name, size in (('disk.img', 50 * 1024**3), ('nvram.bin', 1)):
            fd = os.open(str(self.stage / name), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try: os.ftruncate(fd, size)
            finally: os.close(fd)
        r.write_private(self.stage / 'config.json', {
            'version': 1, 'os': 'darwin', 'arch': 'arm64', 'diskFormat': 'raw',
            'cpuCountMin': 2, 'cpuCount': 2, 'memorySizeMin': 4 * 1024**3, 'memorySize': 4 * 1024**3,
            'ecid': 'bmV3LWlk', 'hardwareModel': 'bW9kZWw=', 'macAddress': 'a2:00:00:00:00:02',
            'display': {'width': 1024, 'height': 768, 'unit': 'px'}})
        if self.emit_receipt:
            r.write_private(self.stage / '.clean-vm-installer.complete.json', {
                'schemaVersion': 1, 'status': 'complete', 'installer': 'CleanVMInstaller',
                'networkDeviceCount': 0, 'directorySharingDeviceCount': 0, 'socketDeviceCount': 0})
        self.mutate_output(self.stage)
        return SimpleNamespace(stdout=io.StringIO(self.events), wait=lambda: self.exit_code)

    def assert_failed(self):
        current = l.status()
        self.assertEqual(current['phase'], 'failed', current)
        for key in ('system_restored', 'applications_preinstalled', 'desktop_verified', 'guest_started', 'credentials_copied', 'old_deleted'):
            self.assertIs(current[key], False)
        self.assertEqual(r.read_private(self.jobdir / 'status.json'), current)
        self.assertFalse((self.jobdir / 'commit.json').exists())
        return current

    def test_request_defaults_and_no_setup_consent(self):
        d = l.validated_request(self.payload(), self.values, host_cpu=10, host_memory=64)
        self.assertEqual((d['cpu'], d['memory_gib'], d['disk_gib']), (2, 4, 50))
        self.assertIsNone(d['source_vm'])
        self.assertNotIn('setup_profile', d)
        self.assertNotIn('acknowledge_setup', d)
        l.validated_request(self.payload(acknowledge_setup=False), self.values)

    def test_forbidden_source_erase_and_setup_fields_rejected_even_when_empty(self):
        for key in ('source_vm', 'confirm_name', 'acknowledge_erase', 'setup_profile', 'erase'):
            for value in (None, False, '', 'google1', {}):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    l.validated_request(self.payload(**{key: value}), self.values)

    def test_explicit_offline_acknowledgement_required(self):
        for value in (None, False, 1, 'true'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                l.validated_request(self.payload(acknowledge_offline=value), self.values)
        payload = self.payload(); payload.pop('acknowledge_offline')
        with self.assertRaises(ValueError): l.validated_request(payload, self.values)

    def test_only_new_names_and_nonempty_local_ipsw_are_accepted(self):
        for name in ('google1', 'GOOGLE1'):
            with self.assertRaises(ValueError): l.validated_request(self.payload(name=name), self.values)
        link = self.root / 'linked.ipsw'; link.symlink_to(self.image)
        empty = self.root / 'empty.ipsw'; empty.touch()
        for image in ('latest', 'https://updates.apple.com/a.ipsw', 'relative.ipsw', str(link), str(empty)):
            with self.subTest(image=image), self.assertRaises(ValueError):
                l.validated_request(self.payload(ipsw=image), self.values)
        payload = self.payload(); payload.pop('ipsw')
        with self.assertRaises(ValueError): l.validated_request(payload, self.values)
        self.inspect.assert_not_called(); self.spawn.assert_not_called()

    def test_start_without_provisioning_component_initializes_truthful_status(self):
        self.assertFalse((self.code / 'provisioning.py').exists())
        self.spawn.side_effect = None
        with patch.object(l.uuid, 'uuid4', return_value=SimpleNamespace(hex=self.jid)):
            result = l.start(self.payload(), self.values)
        self.assertTrue(result['ok'])
        request = r.read_private(self.jobdir / 'request.json')
        self.assertIsNone(request['source_vm']); self.assertIsNone(request['source_identity'])
        self.assertNotIn('setup_profile', request)
        current = l.status()
        self.assertEqual(current['phase'], 'queued')
        self.assertEqual(current['mode'], 'offline_validate')
        for key, expected in l.offline_status_fields().items(): self.assertEqual(current[key], expected)
        self.assertEqual(r.read_private(self.jobdir / 'status.json'), current)
        self.inspect.assert_not_called()
        self.assertEqual(self.spawn.call_args.args[0][0:2], ['/usr/bin/python3', '-B'])

    def test_worker_only_restores_checks_and_leaves_staging(self):
        fd = self.make_job()
        old_stage = self.tart / '.gold-manager-staging' / ('e' * 32) / 'new-environment'
        old_stage.mkdir(mode=0o700, parents=True)
        (old_stage / 'keep').write_bytes(b'never reuse previous jobs')
        l.worker(self.jid, fd)
        current = l.status()
        self.assertEqual(current['phase'], 'awaiting_offline_preinstall')
        self.assertIn(current['phase'], l.TERMINAL); self.assertNotIn(current['phase'], l.ACTIVE)
        self.assertIs(current['system_restored'], True)
        for key in ('applications_preinstalled', 'desktop_verified', 'guest_started', 'credentials_copied', 'old_deleted'):
            self.assertIs(current[key], False)
        self.assertEqual(current['stage_path'], str(self.stage))
        self.assertTrue(self.stage.is_dir())
        self.assertEqual((old_stage / 'keep').read_bytes(), b'never reuse previous jobs')
        self.assertEqual(r.read_private(self.jobdir / 'status.json'), current)
        self.assertFalse((self.jobdir / 'commit.json').exists())
        self.inspect.assert_called_once_with(['--inspect', '--ipsw', str(self.image)])
        self.spawn.assert_called_once()
        self.assertEqual(self.spawn.call_args.kwargs['pass_fds'], (fd,))
        self.assertEqual(self.inventory.call_count, 2)
        with patch.object(l, 'job_alive', side_effect=AssertionError('Terminal jobs need no live process')):
            self.assertEqual(l.status()['phase'], 'awaiting_offline_preinstall')

    def test_worker_revalidates_stored_request_before_any_restore(self):
        changes = ({'source_vm': 'google1'}, {'source_identity': {}}, {'confirm_name': None},
                   {'acknowledge_erase': False}, {'setup_profile': None}, {'ipsw': 'latest'},
                   {'acknowledge_offline': False}, {'cpu': True}, {'name': 'different'},
                   {'mode': 'create'}, {'id': '0' * 32}, {'unknown_field': True})
        for index, change in enumerate(changes, 1):
            with self.subTest(change=change):
                fd = self.make_job(change, jid=format(index, '032x'))
                l.worker(self.jid, fd)
                self.assert_failed()
                self.assertFalse(self.stage.exists())
                # Release this completed fixture's lock before the next synthetic job.
                fcntl.flock(fd, fcntl.LOCK_UN)
        self.inspect.assert_not_called(); self.spawn.assert_not_called()

    def test_corrupt_request_records_durable_failure(self):
        fd = self.make_job()
        (self.jobdir / 'request.json').write_text('{ invalid json')
        l.worker(self.jid, fd)
        self.assert_failed(); self.spawn.assert_not_called()

    def test_helper_nonzero_exit_is_never_success_even_with_receipt(self):
        fd = self.make_job(); self.exit_code = 9
        l.worker(self.jid, fd)
        self.assertEqual(self.assert_failed()['stage_path'], str(self.stage))
        self.assertTrue(self.stage.exists())

    def test_helper_spawn_failure_is_sanitized_and_preserves_failed_stage(self):
        fd = self.make_job()
        self.spawn.side_effect = OSError('SECRET HELPER DETAILS')
        l.worker(self.jid, fd)
        current = self.assert_failed()
        self.assertNotIn('SECRET', current['message'])
        self.assertEqual(current['stage_path'], str(self.stage))
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_final_status_write_failure_never_leaves_success_claim(self):
        fd = self.make_job()
        original_write = r.write_private
        def fail_final_status(path, data):
            if path == self.jobdir / 'status.json' and data.get('phase') == 'awaiting_offline_preinstall':
                raise OSError('SECRET STATUS DETAILS')
            return original_write(path, data)
        with patch.object(r, 'write_private', side_effect=fail_final_status):
            l.worker(self.jid, fd)
        current = self.assert_failed()
        self.assertNotIn('SECRET', current['message'])
        self.assertEqual(current['stage_path'], str(self.stage))
        self.assertTrue((self.stage / '.clean-vm-installer.complete.json').exists())

    def test_missing_or_boolean_complete_event_is_not_success(self):
        for index, events in enumerate(('', '{"event":"complete","schemaVersion":true}\n'), 1):
            with self.subTest(events=events):
                fd = self.make_job(jid=format(index, '032x')); self.events = events
                l.worker(self.jid, fd); self.assert_failed()
                fcntl.flock(fd, fcntl.LOCK_UN)

    def test_non_object_helper_events_are_ignored_safely(self):
        fd = self.make_job(); self.events = 'null\n[]\n123\nnot-json\n' + self.events
        l.worker(self.jid, fd)
        self.assertEqual(l.status()['phase'], 'awaiting_offline_preinstall')

    def test_helper_complete_event_without_receipt_is_not_success(self):
        fd = self.make_job(); self.emit_receipt = False
        l.worker(self.jid, fd); self.assert_failed()

    def test_receipt_resource_and_identity_failures_do_not_mark_restored(self):
        cases = (('receipt', 'networkDeviceCount', 1), ('receipt', 'directorySharingDeviceCount', 1),
                 ('receipt', 'socketDeviceCount', 1), ('config', 'cpuCount', 4),
                 ('config', 'memorySize', 8 * 1024**3), ('config', 'ecid', 'b2xkLWlk'),
                 ('config', 'macAddress', 'a2:00:00:00:00:01'))
        for index, (kind, key, value) in enumerate(cases, 1):
            with self.subTest(kind=kind, key=key):
                def mutate(stage):
                    path = stage / ('.clean-vm-installer.complete.json' if kind == 'receipt' else 'config.json')
                    data = r.read_private(path); data[key] = value; r.write_private(path, data)
                self.mutate_output = mutate
                fd = self.make_job(jid=format(index, '032x'))
                l.worker(self.jid, fd); self.assert_failed()
                fcntl.flock(fd, fcntl.LOCK_UN)

    def test_inspection_failure_precedes_staging_or_restore(self):
        fd = self.make_job(); self.inspect.side_effect = ValueError('Compatibility inspection failed')
        l.worker(self.jid, fd); self.assert_failed()
        self.assertFalse(self.stage.exists()); self.spawn.assert_not_called()

    def test_inspection_rejects_unsupported_and_insufficient_resources(self):
        for index, change in enumerate(({'supported': False}, {'minimumCPUCount': 4}, {'minimumMemorySize': 8 * 1024**3}, {'minimumCPUCount': True}), 1):
            with self.subTest(change=change):
                self.inspect.return_value = dict(self.info, **change)
                fd = self.make_job(jid=format(index, '032x'))
                l.worker(self.jid, fd); self.assert_failed()
                self.assertFalse(self.stage.exists())
                fcntl.flock(fd, fcntl.LOCK_UN)
        self.spawn.assert_not_called()

    def test_image_changed_during_inspection_never_starts_restore(self):
        fd = self.make_job()
        def inspect(args):
            self.image.write_bytes(b'changed fixture image')
            return self.info
        self.inspect.side_effect = inspect
        l.worker(self.jid, fd); self.assert_failed(); self.spawn.assert_not_called()

    def test_new_destination_collision_during_restore_fails_closed(self):
        fd = self.make_job()
        self.inventory.side_effect = [self.values, dict(self.values, gg1={'State': 'stopped'})]
        l.worker(self.jid, fd); self.assert_failed()
        self.assertTrue(self.stage.exists())

    def test_existing_stage_is_not_reused_or_overwritten(self):
        fd = self.make_job(); self.stage.mkdir(mode=0o700, parents=True)
        marker = self.stage / 'keep'; marker.write_bytes(b'existing staging evidence')
        l.worker(self.jid, fd); self.assert_failed(); self.spawn.assert_not_called()
        self.assertEqual(marker.read_bytes(), b'existing staging evidence')

    def test_terminal_job_is_not_restarted(self):
        fd = self.make_job(); l.worker(self.jid, fd)
        before = r.read_private(self.state / 'build-current.json')
        with self.assertRaises(ValueError): l.worker(self.jid, fd)
        self.assertEqual(r.read_private(self.state / 'build-current.json'), before)
        self.spawn.assert_called_once()

    def test_start_respects_active_job_and_held_build_lock(self):
        fd = self.make_job()
        with self.assertRaisesRegex(ValueError, '任务正在运行'): l.start(self.payload(), self.values)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaisesRegex(ValueError, '任务进行中'): l.start(self.payload(), self.values)
        self.spawn.assert_not_called()
        self.assertEqual(l.status()['id'], self.jid)

    def test_worker_rejects_wrong_lock_without_changing_current_status(self):
        self.make_job()
        wrong = os.open(str(self.state / 'wrong.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            before = r.read_private(self.state / 'build-current.json')
            with self.assertRaisesRegex(ValueError, '任务锁无效'): l.worker(self.jid, wrong)
            self.assertEqual(r.read_private(self.state / 'build-current.json'), before)
            self.spawn.assert_not_called()
        finally: os.close(wrong)

    def test_spawn_failure_records_failed_status_and_releases_lock(self):
        self.spawn.side_effect = OSError('DO NOT EXPOSE SECRET PROCESS OUTPUT')
        with patch.object(l.uuid, 'uuid4', return_value=SimpleNamespace(hex=self.jid)):
            with self.assertRaisesRegex(ValueError, '未能启动'): l.start(self.payload(), self.values)
        current = self.assert_failed()
        self.assertNotIn('SECRET', current['message'])
        fd = os.open(str(self.state / 'build.lock'), os.O_RDWR)
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally: os.close(fd)

    def test_status_interrupted_is_not_offline_success(self):
        self.make_job()
        current = r.read_private(self.state / 'build-current.json')
        current.update(phase='installing', pid=123)
        r.write_private(self.state / 'build-current.json', current)
        with patch.object(l, 'job_alive', return_value=False):
            current = l.status()
        self.assertEqual(current['phase'], 'interrupted')
        self.assertIs(current['system_restored'], False)
        self.assertIs(current['guest_started'], False)
        self.spawn.assert_not_called()


if __name__ == '__main__': unittest.main()
