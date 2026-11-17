"""Deletion tests authored for future approval; NOT RUN for UI-only acceptance.

All destructive/VM interactions below are mocked. Do not substitute executing
this module for the user's explicitly requested front-panel acceptance.
"""
from contextlib import ExitStack, nullcontext
import hashlib
import io
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vm_deletion as deletion


VM = '中文 VM 1'
JID = 'a' * 32
ROOT_INFO = SimpleNamespace(st_dev=10, st_ino=100, st_uid=501,
                            st_mode=stat.S_IFDIR | 0o700, st_nlink=2)
CONFIG_INFO = SimpleNamespace(st_dev=10, st_ino=101, st_uid=501,
                              st_mode=stat.S_IFREG | 0o600, st_nlink=1,
                              st_size=16)
IDENTITY = {'root': deletion._metadata(ROOT_INFO),
            'config': deletion._metadata(CONFIG_INFO), 'config_sha256': 'digest'}


def request():
    return {'id': JID, 'mode': 'delete', 'source_vm': VM, 'name': VM,
            'confirm_name': VM, 'acknowledge_erase': True,
            'source_identity': IDENTITY}


class RequestTests(unittest.TestCase):
    def test_chinese_and_spaces_are_preserved(self):
        value = deletion.validated_request(VM, VM, True, {VM})
        self.assertEqual(value['source_vm'], VM)
        self.assertEqual(value['name'], VM)
        self.assertEqual(value['mode'], 'delete')

    def test_unknown_name_is_rejected(self):
        with self.assertRaises(deletion.DeletionRejected):
            deletion.validated_request(VM, VM, True, {'another VM'})

    def test_non_nfc_and_path_names_are_rejected(self):
        for vm in ('e\u0301', '../VM', '-VM', ' VM', 'VM/', 'VM;touch'):
            with self.subTest(vm=vm), self.assertRaises(deletion.DeletionRejected):
                deletion.validated_request(vm, vm, True, {vm})

    def test_confirmation_is_exact_and_ack_is_literal(self):
        for confirm, ack in ((VM + ' ', True), (VM.lower(), True),
                             (VM, 1), (VM, 'true'), (VM, False)):
            with self.subTest(confirm=confirm, ack=ack), self.assertRaises(deletion.DeletionRejected):
                deletion.validated_request(VM, confirm, ack, {VM})

    def test_running_and_missing_vm_rejected_without_stop(self):
        for values in ({}, {VM: {'State': 'running'}}, {VM: {'State': 'unknown'}}):
            with self.assertRaises(deletion.DeletionRejected):
                deletion._stopped(VM, values)

    def test_stopped_and_suspended_are_accepted(self):
        for state in ('stopped', 'suspended'):
            deletion._stopped(VM, {VM: {'State': state}})


class SourceTests(unittest.TestCase):
    def test_snapshot_is_os_neutral_and_hashes_only_config_fd(self):
        linux_config = b'{"os":"linux"}'
        with ExitStack() as stack:
            stack.enter_context(patch.object(deletion, '_root', return_value=ROOT_INFO))
            stack.enter_context(patch.object(deletion.registry, 'safe_path', side_effect=lambda p, *a: p))
            opened = stack.enter_context(patch.object(deletion.os, 'open', return_value=71))
            stack.enter_context(patch.object(deletion, '_config_info', return_value=CONFIG_INFO))
            stack.enter_context(patch.object(deletion.os, 'fstat', return_value=CONFIG_INFO))
            stack.enter_context(patch.object(deletion.os, 'lseek'))
            stack.enter_context(patch.object(deletion.os, 'read', side_effect=[linux_config, b'']))
            stack.enter_context(patch.object(Path, 'lstat', return_value=CONFIG_INFO))
            closed = stack.enter_context(patch.object(deletion.os, 'close'))
            result = deletion.source_identity(VM)
        self.assertEqual(result['config_sha256'], hashlib.sha256(linux_config).hexdigest())
        self.assertEqual(result['root']['owner'], 501)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(opened.call_args.args[0], str(deletion.VM_ROOT / VM / 'config.json'))
        closed.assert_called_once_with(71)

    def test_mount_is_rejected_before_any_descent_or_generic_walk(self):
        path = deletion.VM_ROOT / VM
        def walk(*args, **kwargs):
            yield str(path), ['mounted-share'], []
            raise AssertionError('must not descend into mounted host data')
        with patch.object(deletion, '_root', return_value=ROOT_INFO), \
             patch.object(deletion.os, 'walk', side_effect=walk), \
             patch.object(Path, 'lstat', return_value=ROOT_INFO), \
             patch.object(deletion.os, 'getuid', return_value=501), \
             patch.object(deletion.os.path, 'ismount', return_value=True), \
             patch.object(deletion.lifecycle, 'check_tree') as generic:
            with self.assertRaises(deletion.DeletionRejected):
                deletion._check_tree(path, None)
        generic.assert_not_called()

    def test_share_configuration_removes_target_entry_only(self):
        reg = {'version': 1, 'vms': {VM: {'environment_id': JID},
                                  'other': {'environment_id': 'b' * 32}}, 'retired': []}
        host_path = '/DO-NOT-RESOLVE/host-private-share'
        shares = {'version': 1, 'vms': {VM: {'shares': [{'path': host_path}]},
                                      'other': {'shares': [{'path': host_path}]}}}
        with patch.object(deletion.registry, 'load_registry', return_value=reg), \
             patch.object(deletion.registry, 'read_private', return_value=shares), \
             patch.object(Path, 'stat', side_effect=AssertionError('must not inspect host shares')):
            updated, _, updated_shares = deletion._load_target_configuration(VM)
        self.assertNotIn(VM, updated['vms'])
        self.assertIn(VM, updated['retired'])
        self.assertEqual(updated['vms']['other'], {'environment_id': 'b' * 32})
        self.assertNotIn(VM, updated_shares['vms'])
        self.assertEqual(updated_shares['vms']['other']['shares'][0]['path'], host_path)


class StatusTests(unittest.TestCase):
    def test_incomplete_journal_requires_recovery(self):
        current = {'id': JID, 'mode': 'delete', 'phase': 'failed'}
        with patch.object(deletion.registry, 'read_private', return_value={'phase': 'configuration_removed'}):
            result = deletion._status_with_journal(current)
        self.assertTrue(result['recovery_required'])
        self.assertNotIn('recovery_required', current)

    def test_empty_or_unrelated_journal_fails_closed(self):
        current = {'id': JID, 'mode': 'delete', 'source_vm': VM, 'phase': 'failed'}
        for journal in ({}, [], {'phase': 'committed_old_removed'},
                        {'version': 1, 'id': 'b' * 32, 'mode': 'delete',
                         'source_vm': VM, 'phase': 'committed_old_removed'}):
            with self.subTest(journal=journal), patch.object(
                    deletion.registry, 'read_private', return_value=journal):
                self.assertTrue(deletion._status_with_journal(current)['recovery_required'])

    def test_committed_journal_reconciles_final_status(self):
        current = {'id': JID, 'mode': 'delete', 'source_vm': VM, 'phase': 'interrupted'}
        completed = {'version': 1, 'id': JID, 'mode': 'delete', 'source_vm': VM,
                     'phase': 'committed_old_removed'}
        with patch.object(deletion.registry, 'read_private', return_value=completed):
            result = deletion._status_with_journal(current)
        self.assertEqual(result['phase'], 'deleted')
        self.assertEqual(result['result'], 'deleted')
        self.assertTrue(result['old_deleted'])
        self.assertFalse(result['recovery_required'])
        self.assertIn('restore_images', result['retained_private_artifacts'])

    def test_non_deletion_job_is_untouched(self):
        current = {'id': JID, 'mode': 'rebuild', 'phase': 'preflight'}
        with patch.object(deletion.registry, 'read_private') as read:
            self.assertIs(deletion._status_with_journal(current), current)
        read.assert_not_called()


class SpawnTests(unittest.TestCase):
    def test_detached_argv_and_inherited_global_flock(self):
        writes = []
        with ExitStack() as stack:
            stack.enter_context(patch.object(deletion.lifecycle, 'inventory', return_value={VM: {'State': 'stopped'}}))
            stack.enter_context(patch.object(deletion, 'source_identity', return_value=IDENTITY))
            stack.enter_context(patch.object(deletion.registry, 'private_dir'))
            stack.enter_context(patch.object(deletion.registry, 'safe_path', side_effect=lambda p, *a: p))
            stack.enter_context(patch.object(deletion.os, 'open', side_effect=[70, 72]))
            stack.enter_context(patch.object(deletion, '_lock_metadata'))
            flock = stack.enter_context(patch.object(deletion.fcntl, 'flock'))
            stack.enter_context(patch.object(deletion, 'status', return_value=None))
            stack.enter_context(patch.object(deletion.registry, 'write_private', side_effect=lambda p, d: writes.append((p, dict(d)))))
            stack.enter_context(patch.object(deletion.os, 'fdopen', return_value=io.StringIO()))
            spawn = stack.enter_context(patch.object(deletion.subprocess, 'Popen', return_value=SimpleNamespace(pid=1234)))
            closed = stack.enter_context(patch.object(deletion.os, 'close'))
            result = deletion.start(VM, VM, True, {VM})
        self.assertEqual(result['pid'], 1234)
        self.assertEqual(result['mode'], 'delete')
        argv = spawn.call_args.args[0]
        self.assertEqual(argv[2], str(deletion.HERE / 'vm_deletion.py'))
        self.assertEqual(argv[3:5], ['--worker', result['job_id']])
        self.assertNotIn('shell', spawn.call_args.kwargs)
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        self.assertEqual(spawn.call_args.kwargs['pass_fds'], (70,))
        closed.assert_called_once_with(70)
        self.assertEqual(flock.call_count, 1)  # no parent LOCK_UN
        self.assertEqual(writes[-1][1]['phase'], 'queued')  # no post-spawn overwrite

    def test_inventory_error_is_sanitized(self):
        with patch.object(deletion.lifecycle, 'inventory', side_effect=ValueError('secret credential')):
            with self.assertRaises(deletion.DeletionRejected) as caught:
                deletion.start(VM, VM, True, {VM})
        self.assertNotIn('secret', str(caught.exception))


class CommitTests(unittest.TestCase):
    def mocked_commit(self, stack, *, tree_failure=None, remove_failure=None):
        events = []
        stack.enter_context(patch.object(deletion.registry, 'state_lock', return_value=nullcontext()))
        stack.enter_context(patch.object(deletion.lifecycle, 'inventory', return_value={VM: {'State': 'suspended'}}))
        stack.enter_context(patch.object(deletion.registry, 'safe_path', side_effect=lambda p, *a: p))
        opened = stack.enter_context(patch.object(deletion.os, 'open', side_effect=[70, 71]))
        stack.enter_context(patch.object(deletion.fcntl, 'flock', side_effect=lambda *a: events.append(('storage_lock',))))
        stack.enter_context(patch.object(deletion.fcntl, 'lockf', side_effect=lambda *a: events.append(('config_lock',))))
        stack.enter_context(patch.object(deletion, '_root', return_value=ROOT_INFO))
        stack.enter_context(patch.object(deletion, '_config_info', return_value=CONFIG_INFO))
        stack.enter_context(patch.object(deletion, '_config_digest', return_value='digest'))
        stack.enter_context(patch.object(Path, 'lstat', return_value=CONFIG_INFO))
        stack.enter_context(patch.object(Path, 'stat', return_value=ROOT_INFO))
        stack.enter_context(patch.object(Path, 'exists', return_value=False))
        stack.enter_context(patch.object(Path, 'resolve', lambda self, strict=False: self))
        stale = stack.enter_context(patch.object(deletion.lifecycle, 'stale_control_socket', return_value=(10, 300)))
        tree = stack.enter_context(patch.object(deletion, '_check_tree', side_effect=tree_failure))
        stack.enter_context(patch.object(deletion, '_load_target_configuration', return_value=(
            {'version': 1, 'vms': {}, 'retired': [VM]}, deletion.STATE / 'config.json',
            {'version': 1, 'vms': {}})))
        stack.enter_context(patch.object(deletion.registry, 'private_dir'))
        stack.enter_context(patch.object(deletion.registry, 'write_private',
            side_effect=lambda p, d: events.append(('write', p.name, d.get('phase')))))
        stack.enter_context(patch.object(deletion.registry, 'sync_directory',
            side_effect=lambda p: events.append(('sync', p))))
        renamed = stack.enter_context(patch.object(deletion.os, 'rename',
            side_effect=lambda a, b: events.append(('rename', a, b))))
        def remove(path):
            events.append(('rmtree', path))
            if remove_failure:
                raise remove_failure
        removed = stack.enter_context(patch.object(deletion.shutil, 'rmtree', side_effect=remove))
        closed = stack.enter_context(patch.object(deletion.os, 'close',
            side_effect=lambda fd: events.append(('close', fd))))
        return events, opened, renamed, removed, closed, stale, tree

    def test_durable_commit_order_and_single_config_fd(self):
        with ExitStack() as stack:
            events, opened, renamed, removed, closed, stale, tree = self.mocked_commit(stack)
            deletion._commit(request(), Mock())
        before = events.index(('write', 'commit.json', 'before_delete'))
        rename = next(i for i, item in enumerate(events) if item[0] == 'rename')
        config_removed = events.index(('write', 'commit.json', 'configuration_removed'))
        remove = next(i for i, item in enumerate(events) if item[0] == 'rmtree')
        complete = events.index(('write', 'commit.json', 'committed_old_removed'))
        self.assertLess(before, rename)
        self.assertLess(rename, config_removed)
        self.assertLess(config_removed, remove)
        self.assertLess(remove, complete)
        self.assertTrue(any(item[0] == 'sync' for item in events[config_removed + 1:remove]))
        self.assertEqual(opened.call_count, 2)  # storage + exactly one config inode
        self.assertEqual(closed.call_args_list[0].args, (71,))
        self.assertEqual(closed.call_args_list[1].args, (70,))
        tombstone = deletion.TART_HOME / '.gold-manager-deletions' / JID / 'old-environment'
        renamed.assert_called_once_with(str(deletion.VM_ROOT / VM), str(tombstone))
        removed.assert_called_once_with(str(tombstone))
        stale.assert_called_once_with(deletion.VM_ROOT / VM)  # never re-probe after rename
        self.assertEqual(tree.call_args_list[0].args[1], (10, 300))
        self.assertEqual(tree.call_args_list[1].args[1], (10, 300))

    def test_validation_failure_never_moves_original(self):
        with ExitStack() as stack:
            events, _, renamed, removed, _, _, _ = self.mocked_commit(
                stack, tree_failure=deletion.DeletionRejected('unsafe tree'))
            with self.assertRaises(deletion.DeletionRejected):
                deletion._commit(request(), Mock())
        renamed.assert_not_called()
        removed.assert_not_called()
        self.assertFalse(any(item[:2] == ('write', 'commit.json') for item in events))

    def test_partial_remove_has_no_completion_journal(self):
        with ExitStack() as stack:
            events, _, _, removed, closed, _, _ = self.mocked_commit(
                stack, remove_failure=OSError('do not expose private paths'))
            with self.assertRaises(OSError):
                deletion._commit(request(), Mock())
        removed.assert_called_once()
        self.assertIn(('write', 'commit.json', 'configuration_removed'), events)
        self.assertNotIn(('write', 'commit.json', 'committed_old_removed'), events)
        self.assertEqual(closed.call_count, 2)


class WorkerFailureTests(unittest.TestCase):
    def test_incomplete_commit_is_persistently_locked_and_sanitized(self):
        writes = []
        current = {'id': JID, 'mode': 'delete', 'source_vm': VM, 'name': VM,
                   'phase': 'queued', 'old_deleted': False}
        with ExitStack() as stack:
            stack.enter_context(patch.object(deletion, '_lock_metadata'))
            stack.enter_context(patch.object(deletion.fcntl, 'flock'))
            stack.enter_context(patch.object(deletion.os, 'umask'))
            stack.enter_context(patch.object(deletion.registry, 'safe_path', side_effect=lambda p, *a: p))
            stack.enter_context(patch.object(deletion.registry, 'read_private', side_effect=[
                request(), current, {'phase': 'configuration_removed'}]))
            stack.enter_context(patch.object(deletion.registry, 'write_private',
                side_effect=lambda p, d: writes.append(dict(d))))
            stack.enter_context(patch.object(deletion, '_commit', side_effect=ValueError('secret password')))
            stack.enter_context(patch('builtins.print'))
            deletion.worker(JID, 70)
        self.assertEqual(writes[-1]['phase'], 'failed')
        self.assertTrue(writes[-1]['recovery_required'])
        self.assertFalse(writes[-1]['old_deleted'])
        self.assertNotIn('secret', writes[-1]['message'])


if __name__ == '__main__':
    unittest.main()
