"""Orphan acquisition reconciliation, using private temporary metadata and inert workers."""
from contextlib import ExitStack
import errno
import fcntl
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lifecycle as lc
import managed_registry as registry
import oneclick
import vm_deletion as deletion


class OrphanDownloads(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve(strict=True)
        self.state, self.home = root / 'state', root / 'tart'
        self.jid = '7' * 32
        self.dir = self.state / 'build-jobs' / self.jid
        self.current, self.saved = self.state / 'build-current.json', self.dir / 'status.json'
        for p in (self.state, self.state / 'build-jobs', self.dir, self.home, self.home / 'vms'):
            p.mkdir(mode=0o700)
        self.lock = self.state / 'build.lock'
        self.lock.touch(mode=0o600)
        self.raw = dict(id=self.jid, mode='preinstall', phase='acquiring', name='Fixture', pid=12345,
                        source_vm=None, stage_path=None, published=False, guest_started=False,
                        system_restored=False, applications_preinstalled=False, vpn_configuration_staged=False,
                        old_deleted=False, started_at='2026-01-01T01:00:00+00:00',
                        updated_at='2026-01-01T02:00:00+00:00', progress=0.15, message='Downloading')
        self.pair(self.raw, self.raw)
        self.cache = self.state / 'host-materials' / 'bytes'
        self.ticket = self.state / 'tickets' / 'bound'
        for p in (self.cache, self.ticket):
            registry.write_private(p, {'kept': self.jid})
        self.before = self.untouched()
        self.kill = self.stack.enter_context(patch.object(os, 'kill', side_effect=OSError(errno.ESRCH, 'fixture')))
        self.argv = self.stack.enter_context(patch.object(lc.process_identity, 'arguments', return_value=[]))
        self.stack.enter_context(patch.object(lc.subprocess, 'run', side_effect=AssertionError('No host tools')))
        self.spawn = self.stack.enter_context(patch.object(lc.subprocess, 'Popen', side_effect=AssertionError('No workers')))

    def untouched(self):
        return [(p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in (self.cache, self.ticket)]

    def pair(self, raw, saved):
        registry.write_private(self.current, raw)
        registry.write_private(self.saved, saved)

    def eligible(self, raw):
        return lc.dead_pre_disk_download(raw, job_id=self.jid, state_dir=self.state, tart_home=self.home)

    def run_locked(self):
        with self.lock.open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lc.finalize_replaced_download(self.state, self.home)

    def test_exact_read_only_proof_for_old_same_name_job(self):
        (self.home / 'vms' / 'Fixture').mkdir(mode=0o700)  # Different, newer generation.
        registry.write_private(self.state / 'registry.json', {'version': 1, 'retired': [],
                               'vms': {'Fixture': {'environment_id': '8' * 32}}})
        before = [p.read_bytes() for p in (self.current, self.saved)]
        self.assertTrue(self.eligible(self.raw))
        view = lc.status(state_dir=self.state, tart_home=self.home)
        self.assertIs(view['interrupted_download_archivable'], True)
        self.assertEqual(view['phase'], 'interrupted')
        self.assertEqual(before, [p.read_bytes() for p in (self.current, self.saved)])
        self.assertEqual(self.before, self.untouched())

    def test_missing_malformed_and_unsafe_fields_are_not_proof(self):
        for k in ('id', 'mode', 'name', 'pid', 'stage_path', 'source_vm', 'phase', *lc._DOWNLOAD_FLAGS):
            with self.subTest(missing=k):
                self.assertFalse(self.eligible({n: v for n, v in self.raw.items() if n != k}))
        for k, v in [('id', '6' * 32), ('mode', 'rebuild'), ('phase', 'preflight'), ('phase', 'interrupted'),
                     ('name', '../Fixture'), ('name', 'GOLD'), ('source_vm', 'old'), ('pid', True),
                     ('pid', '12345'), ('pid', 0), ('pid', 2**63), ('stage_path', ''),
                     ('published_path', 'target'), ('desktop_verified', True), ('recovery_required', 0),
                     ('offline_preinstall', {}), ('vpn_configuration', {'active': 0}),
                     ('offline_preinstall', {'active': True}), ('vpn_configuration', 'inactive')]:
            with self.subTest(field=k, value=v):
                self.assertFalse(self.eligible(dict(self.raw, **{k: v})))
        for flag in lc._DOWNLOAD_FLAGS:
            for bad in (True, 0, None):
                self.assertFalse(self.eligible(dict(self.raw, **{flag: bad})))
        self.assertTrue(self.eligible(dict(self.raw, recovery_required=False, vpn_configuration={'active': False})))
        self.assertFalse(self.eligible(type('D', (dict,), {})(self.raw)))

    def test_markers_empty_generation_roots_and_dangling_ancestors(self):
        paths = [self.dir / n for n in ('commit.json', 'vpn-wait.json', 'vpn-resume.json', 'archived-current.json',
                                         'image-inspection.json', 'runtime-preparation.json')]
        for parent in (self.state / 'environments', self.home / '.gold-manager-staging'):
            parent.symlink_to(self.home / 'absent')
            self.assertFalse(self.eligible(self.raw))
            parent.unlink()
            parent.mkdir(mode=0o700)
            paths.append(parent / self.jid)
        for path in paths:
            with self.subTest(path=path):
                path.symlink_to(self.home / 'absent')
                self.assertFalse(self.eligible(self.raw))
                path.unlink()
                path.mkdir(mode=0o700)
                self.assertFalse(self.eligible(self.raw))
                path.rmdir()
        self.assertTrue(self.eligible(self.raw))

    def test_pid_death_requires_esrch_or_positive_unrelated_argv(self):
        for error in (errno.EPERM, errno.EACCES, errno.EINVAL):
            self.kill.side_effect = OSError(error, 'fixture')
            self.assertFalse(self.eligible(self.raw))
        self.kill.side_effect = None
        for argv in ([], None, ['python3', '-B', '/Different.app/Resources/app/oneclick.py', '--worker', self.jid],
                     ['', 'unavailable'], ['python3', '-m', 'oneclick', '--worker=' + self.jid]):
            self.argv.return_value = argv
            self.assertFalse(self.eligible(self.raw))
        self.argv.return_value = ['/bin/sleep', '42']
        self.assertTrue(self.eligible(self.raw))

    def test_half_writes_retry_in_both_orders_without_changing_generation(self):
        write = registry.write_private
        def crash(path, value):
            if path == self.current:
                raise OSError('simulated crash')
            write(path, value)
        with patch.object(registry, 'write_private', side_effect=crash), self.assertRaises(OSError):
            self.run_locked()
        terminal = registry.read_private(self.saved)
        self.assertEqual(terminal['phase'], 'interrupted')
        self.assertEqual(terminal['failed_phase'], 'acquiring')
        for k in ('pid', 'progress'):
            self.assertIsNone(terminal[k])
        self.assertIs(terminal['recovery_required'], False)
        self.assertEqual(registry.read_private(self.current), self.raw)
        for current, history in ((self.raw, terminal), (terminal, self.raw), (terminal, terminal)):
            self.pair(current, history)
            self.assertEqual(self.run_locked(), terminal)
            self.assertEqual(registry.read_private(self.current), terminal)
            self.assertEqual(registry.read_private(self.saved), terminal)
            with patch.object(registry, 'write_private', side_effect=AssertionError('not idempotent')):
                self.assertEqual(self.run_locked(), terminal)
        self.assertFalse((self.dir / 'archived-current.json').exists())
        self.assertEqual(self.before, self.untouched())

    def test_unmatched_status_refuses_replacement_in_either_order(self):
        terminal = self.run_locked()
        for a, b in ((self.raw, None), (self.raw, dict(self.raw, pid=12346)),
                     (self.raw, dict(self.raw, name='Other')), (self.raw, dict(self.raw, id='9' * 32)),
                     (self.raw, dict(self.raw, started_at='another generation')),
                     (self.raw, dict(self.raw, phase='inspecting')), (dict(self.raw, phase='preflight'), self.raw),
                     (self.raw, dict(terminal, old_deleted=0)), (dict(terminal, started_at='different'), self.raw),
                     (terminal, dict(terminal, name='Other')), (self.raw, dict(terminal, pid=12345))):
            with self.subTest(current=a.get('phase'), saved=b):
                self.pair(a, b)
                before = [p.read_bytes() for p in (self.current, self.saved)]
                with self.assertRaises(ValueError):
                    self.run_locked()
                self.assertEqual(before, [p.read_bytes() for p in (self.current, self.saved)])

    def test_every_replacement_path_finalizes_before_publishing_new_generation(self):
        for module in (lc, deletion):
            self.stack.enter_context(patch.multiple(module, STATE=self.state, TART_HOME=self.home, VM_ROOT=self.home / 'vms'))
        self.stack.enter_context(patch.object(lc, 'HELPER', Path(__file__).resolve()))
        self.stack.enter_context(patch.object(lc, 'inventory', return_value={'Previous VM': {'State': 'stopped'}}))
        self.stack.enter_context(patch.object(lc, 'source_identity', return_value={'test': True}))
        self.stack.enter_context(patch.object(deletion, 'source_identity', return_value={'test': True}))
        self.stack.enter_context(patch.object(oneclick, 'capabilities', return_value={'ready': True}))
        self.stack.enter_context(patch.object(oneclick, '_host_memory', return_value=16))
        self.stack.enter_context(patch.object(lc.subprocess, 'run', return_value=SimpleNamespace(stdout=str(16 * 2**30))))
        self.spawn.side_effect = None
        self.spawn.return_value = SimpleNamespace(pid=54321)
        calls = [lambda: oneclick.start({'name': 'Other', 'defer_vpn': True, 'acknowledge_preinstall': True},
                                       state_dir=self.state, tart_home=self.home),
                 lambda: lc.start({'mode': 'create', 'name': 'Other', 'acknowledge_setup': True}, set()),
                 lambda: lc.start({'mode': 'rebuild', 'name': 'Other', 'source_vm': 'Previous VM',
                                   'confirm_name': 'Previous VM', 'acknowledge_erase': True,
                                   'acknowledge_setup': True}, {'Previous VM'}),
                 lambda: deletion.start('Previous VM', 'Previous VM', True, {'Previous VM'})]
        write = registry.write_private
        for i, start in enumerate(calls):
            self.pair(self.raw, self.raw)
            def check(path, value):
                if path == self.current and value['id'] != self.jid:
                    saved = registry.read_private(self.saved)
                    self.assertEqual(saved['phase'], 'interrupted')
                    self.assertEqual(registry.read_private(self.current), saved)
                if path == self.saved:
                    with self.lock.open('rb') as other, self.assertRaises(BlockingIOError):
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                write(path, value)
            with self.subTest(start=i), patch.object(registry, 'write_private', side_effect=check):
                start()
                self.assertNotEqual(registry.read_private(self.current)['id'], self.jid)
                self.assertFalse((self.dir / 'archived-current.json').exists())
            self.pair(self.raw, dict(self.raw, pid=None))
            with self.assertRaises(ValueError):
                start()
            self.assertEqual(registry.read_private(self.current), self.raw)
        self.assertEqual(self.before, self.untouched())

    def archive(self, **override):
        return oneclick.archive_failed(dict({'confirm_name': self.raw['name'], 'job_id': self.jid}, **override),
                                       state_dir=self.state, tart_home=self.home)

    def test_archive_requires_exact_confirmation_no_markers_and_known_dead_worker(self):
        with self.assertRaises(ValueError):
            self.archive(confirm_name='wrong')
        self.kill.side_effect = None
        for argv in ([], ['/other/Resources/oneclick.py', '--worker', self.jid]):
            self.argv.return_value = argv
            with self.assertRaises(ValueError):
                self.archive()
            self.assertNotIn('interrupted_download_archivable', lc.status(state_dir=self.state, tart_home=self.home))
        self.kill.side_effect = OSError(errno.ESRCH, 'fixture')
        (self.dir / 'vpn-wait.json').touch()
        with self.assertRaises(ValueError):
            self.archive()
        self.assertEqual(registry.read_private(self.current), self.raw)
        self.assertEqual(registry.read_private(self.saved), self.raw)
        self.assertFalse((self.dir / 'archived-current.json').exists())

    def test_explicit_archive_records_terminal_snapshot_and_retries_after_crash(self):
        with patch.object(os, 'unlink', side_effect=OSError('fixture crash')), self.assertRaises(OSError):
            self.archive()
        terminal = registry.read_private(self.saved)
        self.assertEqual(terminal['phase'], 'interrupted')
        self.assertEqual(registry.read_private(self.current), terminal)
        archived = registry.read_private(self.dir / 'archived-current.json')
        self.assertEqual(archived, dict(terminal, archived_at=archived['archived_at']))
        self.assertTrue(self.archive()['ok'])
        self.assertFalse(self.current.exists())
        self.assertEqual(self.before, self.untouched())


if __name__ == '__main__':
    unittest.main()
