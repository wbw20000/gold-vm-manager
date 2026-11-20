"""Isolated controller/bootstrap/HTTP security regression tests.

Run: python3 -B -m unittest discover -s tests -p test_manager.py -v
No real Tart, launcher, picker, GUI, process signal, or user config is used.
Only HTTP tests bind ephemeral loopback ports with a fake controller; all
fixtures are private temporary directories, checked before recursive cleanup.
"""
import copy
import importlib.util
import http.client
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / filename))
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


m = load_module('isolated_gold_manager', 'manager.py')
b = load_module('isolated_gold_bootstrap', 'bootstrap.py')


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-manager-test-', dir='/tmp')).resolve(strict=True)
        self.expected_root = self.root
        self.root.chmod(0o700)
        self.addCleanup(self.clean_fixture)

    def clean_fixture(self):
        # Never delete a computed or unverified location.
        self.assertFalse(self.root.is_symlink())
        self.assertEqual(self.root.resolve(strict=True), self.expected_root)
        self.assertEqual(self.root.parent, Path('/tmp').resolve(strict=True))
        self.assertTrue(self.root.name.startswith('gold-manager-test-'))
        shutil.rmtree(str(self.root))

    def write_json(self, path, data):
        path.write_text(json.dumps(data), encoding='utf-8')
        path.chmod(0o600)

    def start_patch(self, replacement):
        value = replacement.start()
        self.addCleanup(replacement.stop)
        return value


class ControllerTests(PrivateFixture):
    def setUp(self):
        super().setUp()
        self.home = self.root / 'home'
        self.state_dir = self.home / 'state'
        self.project = self.home / 'projects' / 'project'
        self.other_project = self.home / 'projects' / 'other'
        self.vm_root = self.home / '.tart' / 'vms'
        self.bases = {vm: self.home / 'networks' / vm for vm in ('gold', 'gold-backup', 'gold-fresh')}
        for directory in (self.home, self.state_dir, self.project, self.other_project, self.vm_root, *self.bases.values()):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        self.config_path = self.state_dir / 'config.json'
        self.start_patch(patch.multiple(m, HOME=self.home, STATE_DIR=self.state_dir,
            CONFIG_PATH=self.config_path, VM_ROOT=self.vm_root, VM_BASES=self.bases,
            TART=self.root / 'fake-tart'))
        self.start_patch(patch.multiple(m.shares_lib, HOST_HOME=self.home, STATE_DIR=self.state_dir,
            CONFIG_PATH=self.config_path, MANAGER_SOURCE_DIR=self.home / 'manager-source',
            MANAGER_INSTALL_DIR=self.home / 'Manager.app', MANAGER_EXTRA_DIRS=(),
            NETWORK_CONTROLLER_DIRS=tuple(self.bases.values()),
            PROTECTED_ROOTS=(Path('/'), self.home), PROTECTED_SUBTREES=()))
        self.run = self.start_patch(patch.object(m.subprocess, 'run', side_effect=AssertionError('Real subprocess forbidden')))
        self.popen = self.start_patch(patch.object(m.subprocess, 'Popen', side_effect=AssertionError('Real launcher forbidden')))
        self.kill = self.start_patch(patch.object(m.os, 'kill', side_effect=AssertionError('Real signal forbidden')))
        self.worker = self.start_patch(patch.object(m.threading, 'Thread'))
        self.controller = m.Controller()
        self.inventory = {vm: {'Name': vm, 'State': 'stopped', 'Disk': 50, 'Size': 20, 'Source': 'local'} for vm in self.bases}
        self.controller.inventory = Mock(side_effect=lambda fresh=False: copy.deepcopy(self.inventory))
        self.controller._run = Mock(side_effect=self.fake_run)
        for vm, base in self.bases.items():
            (base / 'launcher.py').write_text('# GOLD_VM_MANAGER_SHARES_V1\n', encoding='utf-8')
            folder = self.vm_root / vm
            folder.mkdir(mode=0o700)
            self.write_json(folder / 'config.json', {'cpuCount': 4, 'memorySize': 6 * 1024 ** 3})
        self.controller._pid = Mock(return_value=(12345, str(m.TART) + ' run gold --suspendable'))

    def fake_run(self, args, **kwargs):
        if args == ['/usr/sbin/sysctl', '-n', 'hw.memsize']:
            return SimpleNamespace(returncode=0, stdout=str(32 * 1024 ** 3), stderr='')
        raise AssertionError('Unmocked command: ' + repr(args))

    def share(self, **updates):
        result = {'id': 'project-1', 'name': 'project', 'path': str(self.project), 'read_only': True, 'enabled': True}
        result.update(updates)
        return result

    def configured(self, vm='gold', shares=None):
        data = {'version': 1, 'vms': {vm: {'shares': [self.share()] if shares is None else shares}}}
        self.write_json(self.config_path, data)
        return data

    def manifest(self, vm='gold', shares=None):
        shares = [self.share()] if shares is None else shares
        value = {'version': 1, 'vm_id': vm, 'pid': 12345, 'shares': shares,
                 'fingerprint': m.shares_lib.shares_fingerprint(shares),
                 'suspendable': not shares, 'started_at': '2026-11-12T00:00:00+00:00'}
        self.write_json(self.bases[vm] / m.shares_lib.LAST_LAUNCH_NAME, value)
        return value

    def denied(self, call, *args, code=None):
        with self.assertRaises(m.AppError) as caught:
            call(*args)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_empty_state_is_real_and_configuration_is_not_created(self):
        result = self.controller.state()
        self.assertTrue(result['ok'])
        self.assertEqual([vm['id'] for vm in result['vms']], list(self.bases))
        self.assertTrue(all(vm['shares'] == [] and vm['active_shares'] == [] for vm in result['vms']))
        self.assertEqual(result['host']['memory_gib'], 32)
        self.assertTrue(result['capabilities']['offline_validate'])
        self.assertFalse(self.config_path.exists())
        self.run.assert_not_called()
        self.popen.assert_not_called()
        self.kill.assert_not_called()

    def test_only_fixed_vm_ids_are_accepted(self):
        for vm in ('other', '../gold', 'gold/../../etc', '', None, [], True):
            with self.subTest(vm=vm):
                self.denied(self.controller.action, vm, {'action': 'start'}, code='unknown_vm')
                self.denied(self.controller.save_shares, vm, {'shares': []}, code='unknown_vm')
        self.worker.assert_not_called()
        self.assertFalse(self.config_path.exists())

    def test_no_delete_or_arbitrary_action_is_supported(self):
        for action in ('delete', 'remove', 'unblock', 'exec', None, [], {'action': 'start'}):
            with self.subTest(action=action):
                self.denied(self.controller.action, 'gold', {'action': action})
        self.worker.assert_not_called()
        self.kill.assert_not_called()

    def test_readonly_save_needs_no_write_consent_and_persists_per_vm(self):
        first = self.share()
        first.pop('id')
        a = self.controller.save_shares('gold', {'shares': [first]})
        self.assertTrue(a['shares'][0]['read_only'])
        self.assertTrue(a['shares'][0]['id'])
        self.controller.save_shares('gold-backup', {'shares': [self.share(id='backup-1', name='backup')]})
        restored = m.Controller()
        self.assertEqual(restored._configured('gold'), a['shares'])
        self.assertEqual(restored._configured('gold-backup')[0]['name'], 'backup')
        self.assertEqual(restored._configured('gold-fresh'), [])
        self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)
        self.worker.assert_not_called()

    def test_missing_access_booleans_never_default_to_writable(self):
        for key in ('read_only', 'enabled'):
            value = self.share()
            value.pop(key)
            with self.subTest(key=key):
                self.denied(self.controller.save_shares, 'gold', {'shares': [value]}, code='invalid_shares')
        self.assertFalse(self.config_path.exists())

    def test_write_access_requires_literal_true_acknowledgement(self):
        for ack in (None, False, 1, 'true'):
            with self.subTest(ack=ack):
                self.denied(self.controller.save_shares, 'gold', {'shares': [self.share(read_only=False)], 'acknowledge_write': ack}, code='write_ack_required')
        self.assertFalse(self.config_path.exists())
        result = self.controller.save_shares('gold', {'shares': [self.share(read_only=False)], 'acknowledge_write': True})
        self.assertFalse(result['shares'][0]['read_only'])
        self.worker.assert_not_called()

    def test_new_path_or_ro_to_rw_requires_new_ack(self):
        self.configured()
        self.denied(self.controller.save_shares, 'gold', {'shares': [self.share(read_only=False)]}, code='write_ack_required')
        self.controller.save_shares('gold', {'shares': [self.share(read_only=False)], 'acknowledge_write': True})
        self.controller.save_shares('gold', {'shares': [self.share(read_only=False)]})
        self.denied(self.controller.save_shares, 'gold', {'shares': [self.share(path=str(self.other_project), read_only=False)]}, code='write_ack_required')

    def test_renaming_rw_share_requires_new_acknowledgement(self):
        self.configured(shares=[self.share(read_only=False)])
        self.denied(self.controller.save_shares, 'gold', {'shares': [self.share(name='renamed', read_only=False)]}, code='write_ack_required')
        result = self.controller.save_shares('gold', {'shares': [self.share(name='renamed', read_only=False)], 'acknowledge_write': True})
        self.assertEqual(result['shares'][0]['name'], 'renamed')

    def test_reenable_rw_requires_ack_but_disabling_and_removing_do_not(self):
        self.configured(shares=[self.share(read_only=False)])
        self.controller.save_shares('gold', {'shares': [self.share(read_only=False, enabled=False)]})
        self.denied(self.controller.save_shares, 'gold', {'shares': [self.share(read_only=False)]}, code='write_ack_required')
        self.controller.save_shares('gold', {'shares': []})
        self.assertTrue(self.project.is_dir())
        self.assertEqual(self.controller._configured('gold'), [])

    def test_sensitive_and_noncanonical_paths_are_rejected(self):
        for path in ('/', str(self.home), str(self.state_dir), str(self.bases['gold']), str(self.vm_root), str(self.root / 'missing'), 'relative/path', str(self.project) + ':rw', str(self.project) + '\n'):
            with self.subTest(path=path):
                self.denied(self.controller.save_shares, 'gold', {'shares': [self.share(path=path)]}, code='invalid_shares')
        self.assertFalse(self.config_path.exists())

    def test_paused_changes_remain_pending_and_preserve_actual_mounts(self):
        self.inventory['gold']['State'] = 'suspended'
        active = self.share()
        self.manifest(shares=[active])
        changed = self.share(path=str(self.other_project))
        result = self.controller.save_shares('gold', {'shares': [changed]})
        self.assertTrue(result['pending_share_changes'])
        vm = next(vm for vm in self.controller.state()['vms'] if vm['id'] == 'gold')
        self.assertEqual(vm['active_shares'], [active])
        self.assertEqual(vm['shares'], [changed])
        self.assertTrue(vm['pending_share_changes'])
        self.assertFalse(vm['pause_supported'])
        self.assertEqual(m.shares_lib.read_last_launch(self.bases['gold'])['shares'], [active])
        self.worker.assert_not_called()

    def test_suspended_start_uses_saved_mount_plan_not_new_desired(self):
        self.inventory['gold']['State'] = 'suspended'
        self.manifest(shares=[self.share()])
        self.configured(shares=[self.share(path=str(self.other_project))])
        plans = []
        original = m.shares_lib.prepare_vm_shares
        def capture(*args):
            plan = original(*args)
            plans.append(plan)
            return plan
        with patch.object(m.shares_lib, 'prepare_vm_shares', side_effect=capture):
            result = self.controller.action('gold', {'action': 'start'})
        self.assertTrue(result['ok'])
        self.assertEqual(plans[0].shares, [self.share()])
        self.assertTrue(plans[0].pending_changes)
        self.worker.return_value.start.assert_called_once()
        self.popen.assert_not_called()

    def test_running_start_is_idempotent(self):
        self.inventory['gold']['State'] = 'running'
        result = self.controller.action('gold', {'action': 'start'})
        self.assertTrue(result['ok'])
        self.worker.assert_not_called()

    def test_busy_vm_rejects_mutations(self):
        self.controller.operations['gold'] = {'action': 'start'}
        self.denied(self.controller.action, 'gold', {'action': 'shutdown'}, code='busy')
        self.denied(self.controller.save_shares, 'gold', {'shares': []}, code='busy')
        self.assertFalse(self.config_path.exists())

    def test_pause_with_active_shares_is_rejected(self):
        self.inventory['gold']['State'] = 'running'
        self.manifest(shares=[self.share()])
        self.denied(self.controller.action, 'gold', {'action': 'pause'}, code='pause_with_shares')
        self.worker.assert_not_called()

    def test_pause_with_unrecorded_dir_or_non_suspendable_process_is_rejected(self):
        self.inventory['gold']['State'] = 'running'
        self.manifest(shares=[])
        for command in (str(m.TART) + ' run gold', str(m.TART) + ' run gold --suspendable --dir=project:/safe'):
            self.controller._pid.return_value = (12345, command)
            with self.subTest(command=command):
                self.denied(self.controller.action, 'gold', {'action': 'pause'}, code='pause_unsupported')
        self.worker.assert_not_called()

    def test_pause_supported_dispatches_only_mocked_worker(self):
        self.inventory['gold']['State'] = 'running'
        self.manifest(shares=[])
        self.assertTrue(self.controller.action('gold', {'action': 'pause'})['ok'])
        self.worker.return_value.start.assert_called_once()
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_force_and_discard_require_exact_typed_vm_before_dispatch(self):
        for action, state in (('force-stop', 'running'), ('discard-state', 'suspended')):
            self.inventory['gold']['State'] = state
            for value in (None, '', 'Gold', 'gold ', 'gold-backup', ['gold']):
                with self.subTest(action=action, value=value):
                    self.denied(self.controller.action, 'gold', {'action': action, 'confirm_name': value}, code='confirmation_required')
        self.worker.assert_not_called()
        self.kill.assert_not_called()

    def test_confirmed_dangerous_actions_only_dispatch_mocked_workers(self):
        for action, state in (('force-stop', 'running'), ('discard-state', 'suspended')):
            self.inventory['gold']['State'] = state
            self.controller.operations.clear()
            self.worker.reset_mock()
            with self.subTest(action=action):
                self.assertTrue(self.controller.action('gold', {'action': action, 'confirm_name': 'gold'})['ok'])
                self.assertEqual(self.worker.call_args.kwargs['args'], ('gold', action))
                self.worker.return_value.start.assert_called_once()
        self.run.assert_not_called()
        self.popen.assert_not_called()
        self.kill.assert_not_called()

    def test_confirmed_dangerous_actions_still_enforce_state(self):
        self.inventory['gold']['State'] = 'stopped'
        for action in ('force-stop', 'discard-state'):
            self.denied(self.controller.action, 'gold', {'action': action, 'confirm_name': 'gold'}, code='wrong_state')
        self.worker.assert_not_called()

    def test_normal_shutdown_never_automatically_dispatches_force_stop(self):
        self.inventory['gold']['State'] = 'running'
        result = self.controller.action('gold', {'action': 'shutdown'})
        self.assertIn('macOS', result['message'])
        self.assertEqual(self.worker.call_args.kwargs['args'], ('gold', 'shutdown'))
        self.run.assert_not_called()
        self.kill.assert_not_called()

    def test_failed_preinstall_job_exposes_only_public_failure_details(self):
        self.assertTrue({'failed_step', 'failure_reason'} <= m.PREINSTALL_PHASE_FIELDS)
        job = {'id': 'a' * 32, 'mode': 'preinstall', 'name': 'failed fixture', 'phase': 'failed',
               'failed_phase': 'failed_retained', 'failure_code': 'offline-vpn-failed-retained',
               'failed_step': 'authorized-ownership-apply',
               'failure_reason': 'system-authorization-interaction-not-allowed', 'recovery_required': True,
               'stage_path': '/private/stage/fixture', 'vpn_configuration': {'operation_id': 'b' * 32,
               'created_parent_paths': ['Library/LaunchAgents'], 'active': False}}
        self.controller.build_status = Mock(return_value=job)
        build = self.controller.state()['build_job']
        self.assertEqual((build['failed_step'], build['failure_reason'], build['failure_code']),
                         ('authorized-ownership-apply', 'system-authorization-interaction-not-allowed',
                          'offline-vpn-failed-retained'))
        self.assertNotIn('vpn_configuration', build)
        self.assertNotIn('stage_path', build)

    def test_material_failure_and_source_are_public_fixed_fields(self):
        self.assertTrue({'failed_product', 'materials_source'} <= m.PREINSTALL_PHASE_FIELDS)
        job = {'id': 'a' * 32, 'mode': 'preinstall', 'name': 'material fixture', 'phase': 'failed',
               'failed_phase': 'acquiring', 'failure_code': 'download-timeout', 'failed_product': 'ccbaga',
               'materials_source': 'downloaded', 'system_restored': False}
        self.controller.build_status = Mock(return_value=job)
        build = self.controller.state()['build_job']
        self.assertEqual((build['failure_code'], build['failed_product'], build['materials_source']),
                         ('download-timeout', 'ccbaga', 'downloaded'))

    def test_retired_authorization_pause_never_reaches_the_ui(self):
        job = {'id': 'a' * 32, 'mode': 'preinstall', 'name': 'old fixture', 'phase': 'awaiting_system_authorization',
               'authorization_retry': {'operation': 'apply', 'attempt': 1}, 'stage_path': '/private/stage/fixture',
               'vpn_configuration': {'operation_id': 'b' * 32, 'active': True}}
        self.controller.build_status = Mock(return_value=job)
        build = self.controller.state()['build_job']
        self.assertNotIn('authorization_retry', build)
        self.assertNotIn('vpn_configuration', build)
        self.assertFalse(hasattr(self.controller, 'decide_preinstall_authorization'))
        self.assertFalse(hasattr(m.oneclick, 'authorization_decision'))

    def test_archive_preinstall_delegates_and_hides_internal_reasons(self):
        archive = self.start_patch(patch.object(m.oneclick, 'archive_failed', return_value={
            'ok': True, 'job_id': 'a' * 32, 'name': 'failed fixture', 'stage_retained': True}))
        value = {'job_id': 'a' * 32, 'confirm_name': 'failed fixture'}
        self.assertEqual(self.controller.archive_preinstall(value)['stage_retained'], True)
        archive.assert_called_once_with(value, state_dir=self.state_dir, tart_home=self.vm_root.parent)
        archive.side_effect = m.oneclick.OneClickError('inert-internal-reason-not-for-ui')
        with self.assertRaises(m.AppError) as raised:
            self.controller.archive_preinstall(value)
        self.assertEqual((raised.exception.code, raised.exception.status), ('archive_rejected', 409))
        self.assertNotIn('inert-internal-reason', str(raised.exception))
        self.controller.operations['gold'] = {'action': 'start'}
        archive.reset_mock()
        with self.assertRaises(m.AppError) as busy:
            self.controller.archive_preinstall(value)
        self.assertEqual(busy.exception.status, 409)
        archive.assert_not_called()

    def preinstalled(self, vm='gold', version=2):
        base = self.bases[vm]
        self.write_json(base / 'environment.json', {'version': version})
        return base

    def test_preinstalled_start_requires_own_named_execution_consent(self):
        import preinstall_runtime
        base = self.preinstalled()
        preinstall_runtime.finish_first_setup(base)
        original = self.controller._require_preinstall_publication
        with patch.object(self.controller, '_require_preinstall_publication', wraps=original) as fence:
            self.denied(self.controller.action, 'gold', {'action': 'start'}, code='host_authorization_required')
            self.denied(self.controller.action, 'gold', {'action': 'start', 'confirm_name': 'gold',
                        'acknowledge_reviewed_unsigned_backend': 1}, code='host_authorization_required')
            self.denied(self.controller.action, 'gold', {'action': 'start', 'confirm_name': 'gold-backup',
                        'acknowledge_reviewed_unsigned_backend': True}, code='host_authorization_required')
            fence.assert_not_called()
            self.denied(self.controller.action, 'gold', {'action': 'start', 'confirm_name': 'gold',
                        'acknowledge_reviewed_unsigned_backend': True}, code='preinstall_start_rejected')
            fence.assert_called_once_with('gold', base)
        self.worker.assert_not_called()
        with patch.object(self.controller, '_require_preinstall_publication') as fence, patch.object(m.shares_lib, 'prepare_vm_shares'):
            result = self.controller.action('gold', {'action': 'start', 'confirm_name': 'gold',
                            'acknowledge_reviewed_unsigned_backend': True})
            self.assertTrue(result['ok'])
            fence.assert_called_once_with('gold', base)
            self.assertEqual(self.worker.call_args.kwargs['args'], ('gold', 'start', True))
        self.popen.assert_not_called()

    def test_first_setup_start_needs_its_own_named_consent_and_no_backend_consent(self):
        base = self.preinstalled()
        with patch.object(self.controller, '_require_preinstall_publication') as fence, \
                patch.object(m.shares_lib, 'prepare_vm_shares'):
            for payload in ({'action': 'start'}, {'action': 'start', 'confirm_name': 'gold'},
                            {'action': 'start', 'confirm_name': 'gold', 'first_setup_normal_network': 1},
                            {'action': 'start', 'confirm_name': 'gold-backup', 'first_setup_normal_network': True},
                            {'action': 'start', 'confirm_name': 'gold', 'acknowledge_reviewed_unsigned_backend': True},
                            {'action': 'start', 'confirm_name': 'gold', 'first_setup_normal_network': True,
                             'acknowledge_reviewed_unsigned_backend': True}):
                with self.subTest(payload=payload):
                    self.denied(self.controller.action, 'gold', payload, code='first_setup_confirmation_required')
            fence.assert_not_called()
            self.worker.assert_not_called()
            result = self.controller.action('gold', {'action': 'start', 'confirm_name': 'gold',
                                                     'first_setup_normal_network': True})
            self.assertTrue(result['ok'])
            self.assertIn('普通网络', result['message'])
            self.assertNotIn('gold-installers', result['message'], 'v2 VMs have no installers folder')
            fence.assert_called_once_with('gold', base)
            self.assertEqual(self.worker.call_args.kwargs['args'], ('gold', 'start', True, True))
        self.popen.assert_not_called()

    def test_v3_first_setup_names_the_installers_folder_and_writes_nothing_into_the_guest(self):
        base = self.preinstalled(version=3)
        with patch.object(self.controller, '_require_preinstall_publication'), \
                patch.object(m.shares_lib, 'prepare_vm_shares'):
            result = self.controller.action('gold', {'action': 'start', 'confirm_name': 'gold',
                                                     'first_setup_normal_network': True})
        self.assertIn('gold-installers', result['message'])
        self.assertEqual(self.worker.call_args.kwargs['args'], ('gold', 'start', True, True))
        gold = next(vm for vm in self.controller.state()['vms'] if vm['id'] == 'gold')
        self.assertIs(gold['preinstalled']['installers_share'], True)
        self.assertIs(gold['preinstalled']['configuration_staged'], False)
        self.assertNotIn('evidence', gold['preinstalled'])
        self.assertTrue(gold['preinstalled']['first_setup_pending'])
        self.assertFalse(gold['rebuild_supported'])
        self.write_json(self.bases['gold'] / 'environment.json', {'version': 4})
        gold = next(vm for vm in self.controller.state()['vms'] if vm['id'] == 'gold')
        self.assertIsNone(gold['preinstalled'], 'unknown layouts are not treated as preinstalled')

    def test_finished_first_setup_refuses_the_normal_network(self):
        import preinstall_runtime
        base = self.preinstalled()
        preinstall_runtime.finish_first_setup(base)
        for payload in ({'action': 'start', 'confirm_name': 'gold', 'first_setup_normal_network': True},
                        {'action': 'start', 'confirm_name': 'gold', 'first_setup_normal_network': True,
                         'acknowledge_reviewed_unsigned_backend': True}):
            with self.subTest(payload=payload):
                self.denied(self.controller.action, 'gold', payload, code='first_setup_finished')
        (base / preinstall_runtime.NETWORK_MODE_NAME).write_text('{"version":1,"mode":"first-setup"}')
        self.denied(self.controller.action, 'gold', {'action': 'start', 'confirm_name': 'gold',
                    'first_setup_normal_network': True}, code='invalid_network_mode')
        self.worker.assert_not_called()

    def test_first_setup_flag_and_finish_action_belong_to_preinstalled_vms_only(self):
        self.denied(self.controller.action, 'gold', {'action': 'start', 'first_setup_normal_network': True},
                    code='invalid_execution_consent')
        self.denied(self.controller.action, 'gold', {'action': 'finish-first-setup'}, code='first_setup_unavailable')
        self.preinstalled()
        self.denied(self.controller.action, 'gold', {'action': 'shutdown', 'first_setup_normal_network': True},
                    code='invalid_execution_consent')
        self.worker.assert_not_called()

    def test_finishing_first_setup_is_recorded_once_and_never_reverts(self):
        import preinstall_runtime
        base = self.preinstalled()
        self.controller.operations['gold'] = {'action': 'start'}
        self.denied(self.controller.action, 'gold', {'action': 'finish-first-setup'}, code='busy')
        self.assertTrue(preinstall_runtime.first_setup_pending(base))
        self.controller.operations.clear()
        result = self.controller.action('gold', {'action': 'finish-first-setup'})
        self.assertTrue(result['ok'])
        self.assertFalse(preinstall_runtime.first_setup_pending(base))
        self.assertEqual(self.controller.events[0]['action'], 'finish-first-setup')
        self.inventory['gold']['State'] = 'running'
        again = self.controller.action('gold', {'action': 'finish-first-setup'})
        self.assertTrue(again['ok'])
        self.assertFalse(preinstall_runtime.first_setup_pending(base))
        self.worker.assert_not_called()
        self.popen.assert_not_called()

    def test_launch_passes_the_normal_network_flag_only_for_first_setup(self):
        (self.state_dir / 'logs').mkdir(mode=0o700, exist_ok=True)
        proc = Mock()
        proc.poll.return_value = None
        self.popen.side_effect = None
        self.popen.return_value = proc
        for vm in self.bases:
            self.inventory[vm]['State'] = 'running'
        with patch.object(self.controller, '_refresh_runtime') as refresh:
            self.controller._perform('gold', 'start', True, True)
            refresh.assert_called_once_with('gold')
            first = self.popen.call_args[0][0]
            self.controller._perform('gold-backup', 'start', True)
            protected = self.popen.call_args[0][0]
        self.assertEqual(first[-1], '--first-setup-normal-network')
        self.assertFalse({'--acknowledge-reviewed-unsigned-backend', '--enable-reviewed-backend-owner-execute'} & set(first))
        self.assertEqual(protected[-2:], ['--acknowledge-reviewed-unsigned-backend', '--enable-reviewed-backend-owner-execute'])
        self.assertNotIn('--first-setup-normal-network', protected)
        self.assertEqual(self.controller.errors, {})
        messages = [e['message'] for e in self.controller.events]
        self.assertIn('普通网络', messages[1])
        self.assertNotIn('普通网络', messages[0])

    def test_state_reports_first_setup_and_a_normal_network_run(self):
        import preinstall_runtime
        base = self.preinstalled()
        def gold():
            return next(vm for vm in self.controller.state()['vms'] if vm['id'] == 'gold')
        self.assertTrue(gold()['preinstalled']['first_setup_pending'])
        self.assertFalse(gold()['network']['normal_network'])
        self.inventory['gold']['State'] = 'running'
        self.write_json(base / 'status.json', {'state': 'running', 'tart_pid': 12345,
                                               'network_mode': preinstall_runtime.FIRST_SETUP_NETWORK})
        self.assertTrue(gold()['network']['normal_network'])
        self.assertFalse(gold()['network']['protected'])
        preinstall_runtime.finish_first_setup(base)
        self.assertFalse(gold()['preinstalled']['first_setup_pending'])
        self.assertTrue(gold()['network']['normal_network'], 'this run stays on the normal network until shutdown')
        self.inventory['gold']['State'] = 'stopped'
        self.assertFalse(gold()['network']['normal_network'])

    def test_confirmed_start_moves_an_older_environment_to_the_signed_backend_first(self):
        import host_artifacts
        import host_tools
        import preinstall_runtime
        base = self.bases['gold']
        package = SimpleNamespace(artifact_path='package-fixture')
        backend = SimpleNamespace(executable_path=self.state_dir / 'tools' / 'gvproxy-tool-fixture' / 'gvproxy')
        steps = []
        with patch.object(preinstall_runtime, 'environment_needs_refresh', side_effect=lambda b: steps.append(('check', b)) or True), \
                patch.object(host_artifacts, 'acquire', side_effect=lambda key, root: steps.append(('acquire', key, root)) or package), \
                patch.object(host_tools, 'ensure_gvproxy', side_effect=lambda root, artifact_receipt: steps.append(
                    ('extract', root, artifact_receipt)) or backend), \
                patch.object(preinstall_runtime, 'refresh_environment', side_effect=lambda b, p: steps.append(('refresh', b, p)) or True), \
                patch.object(preinstall_runtime, 'refresh_sources', side_effect=AssertionError('backend refresh already wrote the code')):
            self.controller._refresh_runtime('gold')
        self.assertEqual(steps, [('check', base), ('acquire', 'podman-installer', self.state_dir / 'host-materials'),
                                 ('extract', self.state_dir / 'tools', package), ('refresh', base, backend.executable_path)])
        with patch.object(preinstall_runtime, 'environment_needs_refresh', return_value=False), \
                patch.object(preinstall_runtime, 'refresh_sources', return_value=False), \
                patch.object(host_artifacts, 'acquire', side_effect=AssertionError('no download for a current environment')):
            self.controller._refresh_runtime('gold')
        for module, name, error in ((host_artifacts, 'acquire', host_artifacts.ArtifactError('download-timeout')),
                                    (host_tools, 'ensure_gvproxy', host_tools.HostToolError('gvproxy-notarization-required')),
                                    (preinstall_runtime, 'refresh_environment',
                                     preinstall_runtime.RuntimePreparationError('environment-source-integrity-mismatch'))):
            with self.subTest(code=error.code), patch.object(preinstall_runtime, 'environment_needs_refresh', return_value=True), \
                    patch.object(host_artifacts, 'acquire', return_value=package), \
                    patch.object(host_tools, 'ensure_gvproxy', return_value=backend), \
                    patch.object(preinstall_runtime, 'refresh_environment', return_value=True), \
                    patch.object(module, name, side_effect=error), self.assertRaises(m.AppError) as raised:
                self.controller._refresh_runtime('gold')
            self.assertEqual((raised.exception.code, raised.exception.status), ('backend_refresh_failed', 409))
            self.assertIn(error.code, str(raised.exception))

    def test_confirmed_start_gives_a_signed_environment_the_current_launcher_code(self):
        import host_artifacts
        import preinstall_runtime
        base = self.bases['gold']
        steps = []
        with patch.object(preinstall_runtime, 'environment_needs_refresh', return_value=False), \
                patch.object(host_artifacts, 'acquire', side_effect=AssertionError('no download for code only')), \
                patch.object(preinstall_runtime, 'refresh_sources', side_effect=lambda b: steps.append(b) or True):
            self.controller._refresh_runtime('gold')
        self.assertEqual(steps, [base])
        self.assertIn('受保护启动文件', self.controller.events[0]['message'])
        error = preinstall_runtime.RuntimePreparationError('environment-source-integrity-mismatch')
        with patch.object(preinstall_runtime, 'environment_needs_refresh', return_value=False), \
                patch.object(preinstall_runtime, 'refresh_sources', side_effect=error), \
                self.assertRaises(m.AppError) as raised:
            self.controller._refresh_runtime('gold')
        self.assertEqual((raised.exception.code, raised.exception.status), ('backend_refresh_failed', 409))
        self.assertIn(error.code, str(raised.exception))

    def test_runtime_refresh_failure_never_launches(self):
        (self.state_dir / 'logs').mkdir(mode=0o700, exist_ok=True)
        refusal = m.AppError('fixture refresh refusal', 'backend_refresh_failed', 409)
        with patch.object(self.controller, '_refresh_runtime', side_effect=refusal) as refresh:
            self.controller._perform('gold', 'start', True)
        refresh.assert_called_once_with('gold')
        self.popen.assert_not_called()
        self.assertEqual(self.controller.errors['gold'], 'fixture refresh refusal')
        with patch.object(self.controller, '_refresh_runtime') as refresh:
            self.controller._perform('gold', 'start')  # Only a confirmed preinstalled start refreshes.
        refresh.assert_not_called()

    def test_publication_check_accepts_an_environment_that_still_needs_refresh(self):
        import preinstall_runtime
        base = self.bases['gold']
        jid = 'c' * 32
        base = base.parent / jid
        base.mkdir(mode=0o700)
        (self.state_dir / 'build-jobs' / jid).mkdir(mode=0o700, parents=True)
        self.write_json(self.state_dir / 'build-jobs' / jid / 'commit.json', {
            'version': 1, 'phase': 'committed_new_registered', 'id': jid, 'mode': 'preinstall', 'name': 'gold',
            'source_vm': None, 'environment_id': jid, 'target': str(self.vm_root / 'gold')})
        meta = {'vm_name': 'gold', 'vm_config': str(self.vm_root / 'gold' / 'config.json')}
        with patch.object(preinstall_runtime, 'validate_environment_for_refresh', return_value=meta) as kept, \
                patch.object(preinstall_runtime, 'validate_environment', side_effect=AssertionError('backend not yet current')):
            self.controller._require_preinstall_publication('gold', base)
        kept.assert_called_once_with(base)

    def test_validation_binds_only_an_explicit_submission_without_resolving(self):
        payload = {'submission': {'input_mode': 'fields', 'nodes': [{'type': 'trojan',
            'server': '8.8.8.8', 'port': 443, 'password': 'fixture-only', 'sni': 'example.com'}]},
            'allow_resolve': False}
        result = self.controller.validate_vpn(payload)
        self.assertTrue(result['configuration_stored_privately'])
        self.assertFalse(result['vpn_connected'])
        self.assertNotIn('fixture-only', repr(result))
        self.assertNotIn('8.8.8.8', repr(result))
        self.run.assert_not_called()
        self.denied(self.controller.validate_vpn, dict(payload, allow_resolve=1), code='vpn_validation_failed')

    def test_picker_requires_explicit_controller_call_and_valid_vm(self):
        self.denied(self.controller.pick_directory, {'vm': 'other'}, code='unknown_vm')
        self.controller._run.assert_not_called()
        self.controller._run.return_value = SimpleNamespace(returncode=1, stdout='', stderr='execution error: User canceled. (-128)')
        self.controller._run.side_effect = None
        self.assertEqual(self.controller.pick_directory({'vm': 'gold'}), {'ok': True, 'cancelled': True})
        self.assertEqual(self.controller._run.call_args.args[0][0], '/usr/bin/osascript')

    def test_reveal_cannot_open_unconfigured_arbitrary_path(self):
        self.configured()
        self.denied(self.controller.reveal, {'vm': 'gold', 'share_id': 'missing'}, code='share_missing')
        self.denied(self.controller.reveal, {'vm': 'gold', 'share_id': 'project-1', 'path': '/etc'})
        self.controller._run.assert_not_called()
        self.controller._run.side_effect = None
        self.controller._run.return_value = SimpleNamespace(returncode=0, stdout='', stderr='')
        self.assertTrue(self.controller.reveal({'vm': 'gold', 'share_id': 'project-1'})['ok'])
        self.controller._run.assert_called_once_with(['/usr/bin/open', str(self.project)])

    def test_malformed_global_config_fails_closed_without_overwrite(self):
        malformed = ('{', '{"version":1,"version":1,"vms":{}}', '{"version":NaN,"vms":{}}', '[]', '{"version":true,"vms":{}}', '{"version":1,"vms":{"other":{"shares":[]}}}', '{"version":1,"vms":{},"unknown":true}')
        for raw in malformed:
            with self.subTest(raw=raw):
                self.config_path.write_text(raw, encoding='utf-8')
                self.config_path.chmod(0o600)
                self.denied(m.Controller)
                self.denied(self.controller.save_shares, 'gold', {'shares': []})
                self.assertEqual(self.config_path.read_text(), raw)

    def test_malformed_nested_config_is_not_silently_normalized_or_overwritten(self):
        malformed_entries = [
            {'shares': [] , 'unknown': True},
            {'shares': [self.share(read_only='false')]},
            {'shares': [self.share(enabled=1)]},
            {'shares': [{k: v for k, v in self.share().items() if k != 'id'}]},
            {'shares': [self.share(path='/')]},
            {'shares': [self.share(), self.share(id='other', name='PROJECT')]},
        ]
        for entry in malformed_entries:
            with self.subTest(entry=entry):
                self.write_json(self.config_path, {'version': 1, 'vms': {'gold': entry}})
                before = self.config_path.read_bytes()
                self.denied(self.controller._configured, 'gold')
                self.denied(self.controller.save_shares, 'gold', {'shares': []})
                self.assertEqual(self.config_path.read_bytes(), before)

    def test_hardlinked_private_config_is_rejected(self):
        self.configured()
        os.link(str(self.config_path), str(self.root / 'linked-config.json'))
        self.denied(m.Controller, code='unsafe_config')

    def test_symlink_and_world_readable_config_fail_closed(self):
        other = self.root / 'external.json'
        self.write_json(other, {'version': 1, 'vms': {}})
        self.config_path.symlink_to(other)
        self.denied(m.Controller, code='unsafe_config')
        # This fixture path was explicitly resolved and identified before unlink.
        self.assertTrue(self.config_path.is_symlink())
        self.assertEqual(self.config_path.parent.resolve(), self.state_dir.resolve())
        self.config_path.unlink()
        self.write_json(self.config_path, {'version': 1, 'vms': {}})
        self.config_path.chmod(0o644)
        self.denied(m.Controller, code='unsafe_config')


class FakeController:
    def __init__(self):
        self.calls = []

    def state(self):
        self.calls.append(('state',))
        return {'ok': True, 'app': {'name': 'Gold VM Manager'}, 'vms': []}

    def action(self, vm, value):
        if vm not in m.VM_BASES:
            raise m.AppError('未知虚拟机', 'unknown_vm', 404)
        self.calls.append(('action', vm, value))
        return {'ok': True, 'message': 'queued'}

    def delete_vm(self, vm, value):
        if value != {'confirm_name': vm, 'acknowledge_erase': True}:
            raise m.AppError('删除确认无效', 'delete_rejected', 409)
        self.calls.append(('delete', vm, value))
        return {'ok': True, 'job_id': 'unit-only-delete'}

    def save_shares(self, vm, value):
        self.calls.append(('shares', vm, value))
        return {'ok': True, 'shares': value.get('shares', [])}

    def create_build(self, value):
        self.calls.append(('build', value))
        return {'ok': True, 'job_id': 'unit-only-job'}

    def preinstall_capabilities(self):
        self.calls.append(('preinstall-capabilities',))
        return {'ok': True, 'ready': False}

    def preinstall_examples(self):
        self.calls.append(('preinstall-examples',))
        return {'ok': True, 'yaml': 'sample only', 'fields': {'input_mode': 'fields'}}

    def validate_vpn(self, value):
        self.calls.append(('validate-vpn', value))
        return {'ok': True, 'configuration_id': '1' * 32, 'vpn_connected': False}

    def create_preinstall(self, value):
        self.calls.append(('create-preinstall', value))
        return {'ok': True, 'job': {'id': '2' * 32, 'phase': 'queued'}}

    def resume_preinstall(self, value):
        self.calls.append(('resume-preinstall', value))
        return {'ok': True, 'job': {'id': '2' * 32, 'phase': 'vpn_resume_queued'}}

    def archive_preinstall(self, value):
        self.calls.append(('archive-preinstall', value))
        return {'ok': True, 'job_id': '2' * 32, 'name': 'fixture', 'stage_retained': True}

    def pick_ipsw(self, value):
        self.calls.append(('ipsw', value))
        return {'ok': True, 'cancelled': True}

    def pick_directory(self, value):
        self.calls.append(('pick', value))
        return {'ok': True, 'cancelled': True}

    def reveal(self, value):
        self.calls.append(('reveal', value))
        return {'ok': True}


class HTTPSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeController()
        cls.server = m.AppServer(('127.0.0.1', 0), cls.fake, 'unit-test-token-not-a-secret', 'unit-test-instance')
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        if cls.thread.is_alive():
            raise AssertionError('Test HTTP thread did not terminate')

    def setUp(self):
        self.fake.calls.clear()
        self.port = self.server.server_address[1]
        self.origin = 'http://127.0.0.1:' + str(self.port)

    def request(self, path='/api/state', method='GET', value=None, headers=None, raw=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        self.addCleanup(conn.close)
        body = raw if raw is not None else json.dumps(value).encode() if value is not None else None
        fields = {'Host': '127.0.0.1:' + str(self.port), 'Connection': 'close'}
        if headers:
            fields.update(headers)
        conn.request(method, path, body=body, headers=fields)
        response = conn.getresponse()
        raw_response = response.read()
        content_type = response.getheader('Content-Type', '')
        result = json.loads(raw_response) if content_type.startswith('application/json') else raw_response
        return response.status, result, dict(response.getheaders())

    def auth(self):
        return {'Authorization': 'Bearer unit-test-token-not-a-secret'}

    def mutation_headers(self):
        return {**self.auth(), 'Origin': self.origin, 'Content-Type': 'application/json'}

    def test_health_without_auth_exposes_no_token_or_host_paths(self):
        status, result, _ = self.request('/api/health')
        self.assertEqual(status, 200)
        self.assertTrue(result['ok'])
        self.assertNotIn('token', result)
        self.assertNotIn('path', result)
        self.assertEqual(self.fake.calls, [])

    def test_state_requires_exact_bearer_token(self):
        for value in ('', 'unit-test-token-not-a-secret', 'bearer unit-test-token-not-a-secret', 'Bearer wrong'):
            with self.subTest(value=value):
                status, result, _ = self.request(headers={'Authorization': value})
                self.assertEqual((status, result['code']), (401, 'unauthorized'))
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.request(headers=self.auth())[0], 200)
        self.assertEqual(self.fake.calls, [('state',)])

    def test_host_rebinding_and_cross_origin_reads_are_blocked(self):
        for host in ('localhost:' + str(self.port), 'evil.example', '127.0.0.1', '127.0.0.1:' + str(self.port + 1)):
            with self.subTest(host=host):
                status, result, _ = self.request(headers={**self.auth(), 'Host': host})
                self.assertEqual((status, result['code']), (403, 'invalid_host'))
        status, result, _ = self.request(headers={**self.auth(), 'Origin': 'http://evil.example'})
        self.assertEqual((status, result['code']), (403, 'invalid_origin'))
        self.assertEqual(self.fake.calls, [])

    def test_mutations_need_auth_and_exact_same_origin(self):
        headers = self.mutation_headers()
        for missing, code, status_code in (('Authorization', 'unauthorized', 401), ('Origin', 'origin_required', 403)):
            fields = {k: v for k, v in headers.items() if k != missing}
            with self.subTest(missing=missing):
                status, result, _ = self.request('/api/vms/gold/action', 'POST', {'action': 'start'}, fields)
                self.assertEqual((status, result['code']), (status_code, code))
        status, result, _ = self.request('/api/vms/gold/action', 'POST', {'action': 'start'}, {**headers, 'Origin': 'null'})
        self.assertEqual((status, result['code']), (403, 'invalid_origin'))
        self.assertEqual(self.fake.calls, [])

    def test_json_content_type_length_and_syntax_are_checked(self):
        headers = self.mutation_headers()
        cases = [
            ({**headers, 'Content-Type': 'text/plain'}, b'{}', 415),
            ({**headers, 'Content-Length': '65537'}, b'', 413),
            ({**headers, 'Content-Length': '-1'}, b'', 413),
            ({**headers, 'Content-Length': 'bad'}, b'', 400),
            ({**headers, 'Transfer-Encoding': 'chunked'}, b'{}', 400),
            (headers, b'{', 400),
            (headers, b'{"action":NaN}', 400),
            (headers, b'\xff', 400),
        ]
        for fields, body, expected in cases:
            with self.subTest(fields=fields, body=body):
                status, result, _ = self.request('/api/vms/gold/action', 'POST', headers=fields, raw=body)
                self.assertEqual(status, expected)
                self.assertFalse(result['ok'])
        self.assertEqual(self.fake.calls, [])

    def test_routes_accept_registered_names_and_never_expose_raw_delete(self):
        unknown = self.request('/api/vms/other/action', 'POST', {'action': 'start'}, self.mutation_headers())
        self.assertEqual((unknown[0], unknown[1]['code']), (404, 'unknown_vm'))
        # A dedicated confirmed-delete endpoint now exists; raw deletion still does not.
        rejected = self.request('/api/vms/gold/delete', 'POST', {'action': 'start'}, self.mutation_headers())
        self.assertEqual((rejected[0], rejected[1]['code']), (409, 'delete_rejected'))
        for path in ('/api/vms/gold/../gold/action', '/api/vms/gold/action/', '/api/exec', '/api/delete'):
            with self.subTest(path=path):
                status, result, _ = self.request(path, 'POST', {'action': 'start'}, self.mutation_headers())
                self.assertEqual((status, result['code']), (404, 'not_found'))
        self.assertEqual(self.fake.calls, [])
        for vm in ('gold', 'gold-backup', 'gold-fresh'):
            self.assertEqual(self.request('/api/vms/' + vm + '/action', 'POST', {'action': 'start'}, self.mutation_headers())[0], 202)
            self.assertEqual(self.request('/api/vms/' + vm + '/shares', 'POST', {'shares': []}, self.mutation_headers())[0], 200)
        self.assertEqual(len(self.fake.calls), 6)

    def test_query_tokens_and_static_traversal_are_not_accepted(self):
        for path in ('/api/state?token=unit-test-token-not-a-secret', '/api/state#token=secret'):
            with self.subTest(path=path):
                status, _, _ = self.request(path, headers=self.auth())
                self.assertEqual(status, 400)
        for path in ('/../manager.py', '/static/../manager.py', '/%2e%2e/manager.py', '/manager.py', '/API_CONTRACT.md'):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.fake.calls, [])

    def test_create_route_is_authenticated_and_origin_checked(self):
        status, result, _ = self.request('/api/build', 'POST', {'mode':'create'}, {'Content-Type':'application/json','Origin':self.origin})
        self.assertEqual(status,401)
        headers=self.mutation_headers();headers['Origin']='https://untrusted.invalid'
        status, result, _ = self.request('/api/build', 'POST', {'mode':'create'}, headers)
        self.assertEqual(status,403)
        self.assertEqual(self.fake.calls,[])
        status, result, _ = self.request('/api/build','POST',{'mode':'create'},self.mutation_headers())
        self.assertEqual(status,202)
        self.assertEqual(self.fake.calls,[('build',{'mode':'create'})])

    def test_offline_build_route_keeps_auth_origin_and_payload_contract(self):
        payload = {'mode': 'offline_validate', 'name': 'gg1', 'ipsw': '/fixture/local.ipsw',
                   'acknowledge_offline': True}
        for headers, expected in (({'Content-Type': 'application/json', 'Origin': self.origin}, 401),
                                  ({**self.mutation_headers(), 'Origin': 'https://untrusted.invalid'}, 403)):
            self.assertEqual(self.request('/api/build', 'POST', payload, headers)[0], expected)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.request('/api/build', 'POST', payload, self.mutation_headers())[0], 202)
        self.assertEqual(self.fake.calls, [('build', payload)])

    def test_destructive_duplicate_fields_rejected_before_dispatch(self):
        status, result, _ = self.request('/api/build','POST',headers=self.mutation_headers(),raw=b'{"mode":"create","mode":"rebuild"}')
        self.assertEqual(status,400)
        self.assertEqual(self.fake.calls,[])

    def test_preinstall_requires_authentication_and_same_origin(self):
        for route in ('/api/preinstall/capabilities', '/api/preinstall/examples'):
            self.assertEqual(self.request(route)[0], 401)
            self.assertEqual(self.request(route, headers=self.auth())[0], 200)
        vpn = '/api/preinstall/vpn/validate'
        create = '/api/preinstall/create'
        resume = '/api/preinstall/resume'
        for route in (vpn, create, resume):
            self.assertEqual(self.request(route, 'POST', {}, {**self.auth(), 'Content-Type': 'application/json'})[0], 403)
        payload = {'submission': {'input_mode': 'yaml', 'yaml_text': 'fixture only'}, 'allow_resolve': False}
        self.assertEqual(self.request(vpn, 'POST', payload, self.mutation_headers())[0], 200)
        request = {'name': 'New fixture VM', 'vpn_configuration_id': '1' * 32}
        status, result, _ = self.request(create, 'POST', request, self.mutation_headers())
        self.assertEqual((status, result['job']['phase']), (202, 'queued'))
        resume_data = {'job_id': '2' * 32, 'vpn_configuration_id': '1' * 32,
                       'acknowledge_network_policy': True, 'acknowledge_guest_autoconfigure': True}
        status, result, _ = self.request(resume, 'POST', resume_data, self.mutation_headers())
        self.assertEqual((status, result['job']['phase']), (202, 'vpn_resume_queued'))
        self.assertEqual(self.fake.calls, [('preinstall-capabilities',), ('preinstall-examples',),
                                          ('validate-vpn', payload), ('create-preinstall', request),
                                          ('resume-preinstall', resume_data)])

    def test_archive_route_requires_authentication_and_same_origin(self):
        route = '/api/preinstall/archive'
        value = {'job_id': '2' * 32, 'confirm_name': 'fixture'}
        self.assertEqual(self.request(route, 'POST', value, {'Content-Type': 'application/json'})[0], 403)
        self.assertEqual(self.request(route, 'POST', value, {**self.auth(), 'Content-Type': 'application/json'})[0], 403)
        self.assertEqual(self.request(route, 'POST', value, {'Origin': self.origin, 'Content-Type': 'application/json'})[0], 401)
        self.assertEqual(self.fake.calls, [])
        status, result, _ = self.request(route, 'POST', value, self.mutation_headers())
        self.assertEqual((status, result['stage_retained']), (200, True))
        self.assertEqual(self.fake.calls, [('archive-preinstall', value)])

    def test_retired_authorization_decision_route_is_gone(self):
        route = '/api/preinstall/authorization'
        value = {'job_id': '2' * 32, 'attempt': 1, 'decision': 'retry'}
        self.assertEqual(self.request(route, 'POST', value, self.mutation_headers())[0], 404)
        self.assertEqual(self.fake.calls, [])

    def test_only_vpn_validation_has_a_larger_request_limit(self):
        payload = {'submission': {'input_mode': 'yaml', 'yaml_text': '柴' * 30000}, 'allow_resolve': False}
        vpn = '/api/preinstall/vpn/validate'
        create = '/api/preinstall/create'
        self.assertEqual(self.request(vpn, 'POST', payload, self.mutation_headers())[0], 200)
        self.assertEqual(self.request(create, 'POST', payload, self.mutation_headers())[0], 413)
        headers = {**self.mutation_headers(), 'Content-Length': str(m.VPN_VALIDATE_MAX_WIRE + 1)}
        self.assertEqual(self.request(vpn, 'POST', headers=headers, raw=b'{}')[0], 413)
        self.assertEqual(self.fake.calls, [('validate-vpn', payload)])

    def test_native_restore_picker_route(self):
        status,result,_=self.request('/api/pick-ipsw','POST',{},self.mutation_headers())
        self.assertEqual(status,200)
        self.assertTrue(result['cancelled'])
        self.assertEqual(self.fake.calls,[('ipsw',{})])

    def test_static_assets_and_security_headers_integrate_with_frontend(self):
        for path, content_type in (('/', 'text/html'), ('/index.html', 'text/html'), ('/app.js', 'text/javascript'), ('/style.css', 'text/css'), ('/preinstall.js', 'text/javascript'), ('/preinstall.css', 'text/css')):
            with self.subTest(path=path):
                status, raw, headers = self.request(path)
                self.assertEqual(status, 200)
                self.assertIn(content_type, headers['Content-Type'])
                self.assertTrue(raw)
                self.assertEqual(headers['Cache-Control'], 'no-store')
                self.assertEqual(headers['X-Frame-Options'], 'DENY')
                self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                self.assertIn("script-src 'self'", headers['Content-Security-Policy'])
                self.assertNotIn('unsafe-inline', headers['Content-Security-Policy'])
        self.assertEqual(self.fake.calls, [])

    def test_native_picker_and_reveal_routes_dispatch_only_fake_controller(self):
        self.assertEqual(self.request('/api/pick-directory', 'POST', {'vm': 'gold'}, self.mutation_headers())[0], 200)
        self.assertEqual(self.request('/api/reveal-directory', 'POST', {'vm': 'gold', 'share_id': 'project-1'}, self.mutation_headers())[0], 200)
        self.assertEqual(self.fake.calls[0], ('pick', {'vm': 'gold'}))
        self.assertEqual(self.fake.calls[1][0], 'reveal')

    def test_options_does_not_enable_cors(self):
        status, result, headers = self.request('/api/state', 'OPTIONS', headers={'Origin': 'http://evil.example'})
        self.assertEqual((status, result['code']), (403, 'cors_denied'))
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.assertEqual(self.fake.calls, [])


class BootstrapTests(PrivateFixture):
    def setUp(self):
        super().setUp()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.start_patch(patch.object(b, 'STATE', self.state))
        self.kill = self.start_patch(patch.object(b.os, 'kill', side_effect=AssertionError('Real process checks forbidden')))
        self.popen = self.start_patch(patch.object(b.subprocess, 'Popen', side_effect=AssertionError('Real launcher forbidden')))
        self.run = self.start_patch(patch.object(b.subprocess, 'run', side_effect=AssertionError('Real GUI forbidden')))
        self.opener = self.start_patch(patch.object(b, 'OPENER'))

    def info(self, **changes):
        data = {'app': 'gold-vm-manager', 'port': b.PORT, 'pid': 12345,
                'token': 'bootstrap-unit-test-token', 'instance': 'isolated-test'}
        data.update(changes)
        self.write_json(self.state / 'server.json', data)
        return data

    def response(self, value):
        import io
        self.opener.open.return_value.__enter__.return_value = io.BytesIO(json.dumps(value).encode())

    def test_bootstrap_requires_the_packaged_controller_version(self):
        self.assertEqual(b.CONTROLLER_VERSION, m.VERSION)
        info = self.info()
        self.kill.side_effect = None
        self.response({'ok': True, 'app': {'name': 'Gold VM Manager', 'version': m.VERSION}})
        self.assertEqual(b.running_info(required_version=b.CONTROLLER_VERSION), info)
        self.response({'ok': True, 'app': {'name': 'Gold VM Manager', 'version': '1.3.0'}})
        self.assertIsNone(b.running_info(required_version=b.CONTROLLER_VERSION))

    def test_absent_or_unsafe_server_info_does_not_contact_any_process(self):
        self.assertIsNone(b.running_info())
        self.info()
        (self.state / 'server.json').chmod(0o644)
        self.assertIsNone(b.running_info())
        self.kill.assert_not_called()
        self.opener.open.assert_not_called()
        self.popen.assert_not_called()
        self.run.assert_not_called()

    def test_running_info_verifies_authenticated_state_without_proxy(self):
        info = self.info()
        self.kill.side_effect = None
        self.response({'ok': True, 'app': {'name': 'Gold VM Manager'}})
        self.assertEqual(b.running_info(), info)
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'http://127.0.0.1:' + str(b.PORT) + '/api/state')
        self.assertEqual(request.get_header('Authorization'), 'Bearer bootstrap-unit-test-token')
        self.assertEqual(request.get_header('Origin'), 'http://127.0.0.1:' + str(b.PORT))
        self.kill.assert_called_once_with(12345, 0)
        self.popen.assert_not_called()
        self.run.assert_not_called()

    def test_malformed_server_info_is_rejected_without_crashing_or_starting(self):
        for value in ([], None, 'bad', {'app': 'gold-vm-manager', 'port': True}, {'app': 'different', 'port': b.PORT}):
            with self.subTest(value=value):
                self.write_json(self.state / 'server.json', value)
                self.assertIsNone(b.running_info())
        self.opener.open.assert_not_called()
        self.popen.assert_not_called()
        self.run.assert_not_called()

    def test_malformed_or_wrong_http_identity_fails_closed(self):
        self.info()
        self.kill.side_effect = None
        for value in ([], {'ok': True, 'app': []}, {'ok': True, 'app': {'name': 'Unverified app'}}, {'ok': False}):
            with self.subTest(value=value):
                self.response(value)
                self.assertIsNone(b.running_info())
        self.popen.assert_not_called()
        self.run.assert_not_called()

    def test_fixed_port_and_real_integer_pid_are_required(self):
        for changes in ({'port': b.PORT + 1}, {'port': str(b.PORT)}, {'pid': True}, {'pid': 1}, {'token': None}):
            with self.subTest(changes=changes):
                self.info(**changes)
                self.assertIsNone(b.running_info())
        self.kill.assert_not_called()
        self.opener.open.assert_not_called()


if __name__ == '__main__':
    unittest.main()
