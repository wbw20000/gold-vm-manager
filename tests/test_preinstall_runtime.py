"""Tiny private fixtures only. Never execute native tools, backend, Tart or VMs."""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import preinstall_runtime as runtime
import protected_launcher as launcher
import runtime_shares
from vpn_config import parse_submission

SECRET = 'fixture-secret-never-log'
BACKEND = b'inert fixture backend; not a program'
Q = b'0083;0;Fixture;preserve-this-exactly'
TOKEN = 'a' * 64
REAL_VERIFY_BACKEND = runtime._verified_backend
REAL_PRESERVE_QUARANTINE = runtime._preserve_quarantine


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-preinstall-runtime-')).resolve()
        self.root.chmod(0o700)
        self.expected_root = self.root
        self.stack = ExitStack()
        self.name = 'fixture-vm'
        self.tart_home = self.root / 'explicit-tart-home'
        self.vm_directory = self.tart_home / 'vms' / self.name
        self.vm_directory.mkdir(mode=0o700, parents=True)
        self.config = self.vm_directory / 'config.json'
        self.put(self.config, {'macAddress': '02:aa:bb:cc:dd:ee', 'ecid': 'FIXTURE_ECID=', 'cpuCount': 2})
        self.base = self.root / 'environment'
        self.backend = self.root / 'backend.fixture'
        self.backend.write_bytes(BACKEND)
        self.backend.chmod(0o600)
        self.tart = self.root / 'tart.fixture'
        self.tart.write_bytes(b'inert fixture tart; never executed')
        self.tart.chmod(0o700)
        self.preinstall = self.root / 'preinstall.json'
        self.seed_receipt = self.root / 'seed.json'
        self.put(self.preinstall, {'schema': 1, 'stage_digest': 'b' * 64, 'private': SECRET})
        self.put(self.seed_receipt, {'schema': 1, 'receipt_token': TOKEN, 'private': SECRET})
        self.vpn = parse_submission({'input_mode': 'fields', 'nodes': [{
            'type': 'trojan', 'server': '8.8.8.8', 'port': 443,
            'password': SECRET, 'sni': 'vpn.example.com'}]})
        self.quarantines = {str(self.backend): Q}
        # Scoped source helper injection only. Production digest constants stay intact.
        self.pin = self.stack.enter_context(mock.patch.object(runtime, '_verified_backend', side_effect=self.fixture_backend))
        self.stack.enter_context(mock.patch.object(runtime, '_quarantine', side_effect=lambda p: self.quarantines.get(str(p))))
        self.preserve = self.stack.enter_context(mock.patch.object(runtime, '_preserve_quarantine', side_effect=self.fixture_quarantine))
        self.run = self.stack.enter_context(mock.patch('subprocess.run', side_effect=AssertionError('native forbidden')))
        self.spawn = self.stack.enter_context(mock.patch('subprocess.Popen', side_effect=AssertionError('process forbidden')))
        self.stack.enter_context(mock.patch.dict(sys.modules, {'share_support': runtime_shares}))
        self.original_umask = os.umask(0o077)

    def tearDown(self):
        os.umask(self.original_umask)
        self.stack.close()
        self.assertEqual(self.root.resolve(strict=True), self.expected_root)
        self.assertTrue(self.root.name.startswith('gold-preinstall-runtime-'))
        self.assertFalse(self.root.is_symlink())
        self.assertEqual(self.root.stat().st_uid, os.getuid())
        shutil.rmtree(str(self.root))

    def put(self, path, data):
        path.write_text(json.dumps(data))
        path.chmod(0o600)

    def fixture_backend(self, path):
        raw, info = runtime._read(path, private=False, cap=1024)
        runtime._need(raw == BACKEND, 'reviewed-backend-digest-mismatch')
        return raw, info

    def fixture_quarantine(self, source, target, expected):
        self.assertEqual(self.quarantines.get(str(source)), expected)
        if expected is not None:
            self.quarantines[str(target)] = expected

    def prepare(self, **changes):
        values = dict(vm_name=self.name, vm_config=self.config, published_vm_config=self.config,
                      destination_private_base=self.base,
                      private_config=self.vpn.private_config, endpoints=self.vpn.endpoints,
                      gvproxy_path=self.backend, tart_path=self.tart,
                      preinstall_receipt=self.preinstall, vpn_seed_receipt=self.seed_receipt)
        values.update(changes)
        return runtime.prepare_environment(**values)

    def meta(self):
        return json.loads((self.base / 'environment.json').read_text())

    def command(self, shares=(), arguments=(), **options):
        plan = SimpleNamespace(shares=list(shares), arguments=list(arguments))
        with mock.patch.object(launcher, 'BASE', self.base):
            return launcher.build_tart_command(self.name, 42, plan, environment=self.meta(), **options)

    def test_prepare_public_result_no_credentials_no_process_and_v2_validation(self):
        result = self.prepare()
        self.assertEqual(result['version'], 2)
        self.assertEqual(result['status'], 'awaiting_host_authorization')
        self.assertTrue(result['needs_host_security_authorization'])
        self.assertFalse(result['native_execution_approved'])
        self.assertFalse(result['desktop_verified'])
        self.assertFalse(result['network_independently_verified'])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn('8.8.8.8', json.dumps(result))
        with mock.patch.object(launcher, 'BASE', self.base):
            self.assertEqual(launcher.validate_environment()['version'], 2)
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_no_legacy_setup_material_or_raw_private_config(self):
        self.prepare()
        names = {p.name for p in self.base.iterdir()}
        for forbidden in ('setup', 'mihomo', 'config.json', 'profile.json', 'Install.command'):
            self.assertNotIn(forbidden, names)
        self.assertFalse(any(p.suffix == '.dmg' for p in self.base.iterdir()))
        meta = self.meta()
        self.assertFalse(meta['setup_active'])
        self.assertEqual(set(meta['source_sha256']), runtime._MANIFEST)
        self.assertNotIn(SECRET, json.dumps(meta))
        self.assertEqual(meta['private_config_sha256'], runtime._sha(runtime._json(self.vpn.private_config)))
        policy = json.loads((self.base / 'policy.json').read_text())
        self.assertEqual(policy, {'guest_mac': '02:aa:bb:cc:dd:ee', 'endpoints': [list(v) for v in self.vpn.endpoints]})

    def test_files_and_mailbox_are_private_and_source_exec_not_added(self):
        self.prepare()
        for path in self.base.iterdir():
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertIn(mode, (0o600, 0o700))
            self.assertEqual(mode & 0o077, 0)
        self.assertEqual(stat.S_IMODE((self.base / 'guest-status').stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.base / 'gvproxy-darwin').stat().st_mode), 0o600)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'backend-not-executable'):
            runtime.backend_is_executable(self.base)

    def test_existing_owner_execute_bit_is_preserved_but_not_approval(self):
        self.backend.chmod(0o700)
        self.prepare()
        self.assertEqual(stat.S_IMODE((self.base / 'gvproxy-darwin').stat().st_mode), 0o700)
        runtime.backend_is_executable(self.base)
        self.assertFalse(self.meta()['native_execution_approved'])

    def test_source_and_copy_backend_pinned_without_modifying_production_constant(self):
        original = runtime.GV_SHA256
        self.prepare()
        # Podman 6.2.0's Red Hat-signed, notarized gvproxy v0.9.0, not the bare release.
        self.assertEqual(original, '45881c33400a14c4c50d4ed7e814b69a60248aa0d78e9b541e879edc05346a85')
        self.assertEqual(runtime.GV_SHA256, original)
        self.assertEqual(self.meta()['backend_assessment'], runtime.BACKEND_ASSESSMENT)
        self.assertIn(mock.call(self.backend), self.pin.call_args_list)
        self.assertIn(mock.call(self.base / 'gvproxy-darwin'), self.pin.call_args_list)
        self.assertEqual((self.base / 'gvproxy-darwin').read_bytes(), BACKEND)

    def test_source_quarantine_preserved_exactly_and_removal_fails(self):
        self.prepare()
        self.assertEqual(self.quarantines[str(self.base / 'gvproxy-darwin')], Q)
        self.assertEqual(self.meta()['backend_quarantine_sha256'], hashlib.sha256(Q).hexdigest())
        self.quarantines[str(self.base / 'gvproxy-darwin')] = None
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'backend-quarantine-changed'):
            runtime.validate_environment(self.base)

    def test_gatekeeper_may_update_the_backend_quarantine_but_never_remove_it(self):
        self.prepare()
        copy = str(self.base / 'gvproxy-darwin')
        self.quarantines[copy] = b'00c3;0;Fixture;assessed-by-gatekeeper'
        self.assertEqual(runtime.validate_environment(self.base)['backend_quarantine_sha256'],
                         hashlib.sha256(Q).hexdigest())
        self.quarantines[copy] = None
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'backend-quarantine-changed'):
            runtime.validate_environment(self.base)

    def inode_quarantines(self):
        """Quarantine that follows a file across renames, as a real xattr does."""
        by_inode = {os.lstat(path).st_ino: value for path, value in self.quarantines.items()
                    if value is not None and os.path.lexists(path)}

        def lookup(path):
            return by_inode.get(os.lstat(str(path)).st_ino) if os.path.lexists(str(path)) else None

        def preserve(source, target, expected):
            self.assertEqual(lookup(source), expected)
            if expected is not None:
                by_inode[os.lstat(str(target)).st_ino] = expected
        return lookup, preserve

    def older_environment(self, backend_present=False):
        """As left by builds that pinned the unnotarized gvproxy (bb1's case: copy gone)."""
        self.prepare()
        meta = self.meta()
        launcher_copy = b'# GOLD_VM_MANAGER_SHARES_V1\n# GOLD_VM_MANAGER_RECOVERY_V1\n# older launcher copy\n'
        (self.base / 'launcher.py').write_bytes(launcher_copy)
        meta['source_sha256']['launcher.py'] = hashlib.sha256(launcher_copy).hexdigest()
        meta['backend_assessment'] = 'reviewed-sha256-only-adhoc-no-usable-native-signature'
        meta['source_sha256']['gvproxy-darwin'] = runtime._LEGACY_GV_SHA256
        if not backend_present:
            copy = self.base / 'gvproxy-darwin'
            self.assertEqual(copy.resolve(strict=True), self.expected_root / 'environment/gvproxy-darwin')
            copy.unlink()
        (self.base / 'environment.json').write_bytes(runtime._json(meta))
        return meta

    def test_refresh_moves_an_older_environment_to_the_signed_backend(self):
        old = self.older_environment()
        kept = {name: (self.base / name).read_bytes() for name in runtime._KEPT}
        mailbox = (self.base / 'guest-status').stat().st_ino
        lookup, preserve = self.inode_quarantines()
        with mock.patch.object(runtime, '_quarantine', side_effect=lookup), \
                mock.patch.object(runtime, '_preserve_quarantine', side_effect=preserve):
            with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-backend-authorization-contract'):
                runtime.validate_environment(self.base)
            self.assertEqual(runtime.validate_environment_for_refresh(self.base), old)
            self.assertTrue(runtime.environment_needs_refresh(self.base))
            self.assertTrue(runtime.refresh_environment(self.base, self.backend))
            meta = runtime.validate_environment(self.base)
            self.assertEqual(lookup(self.base / 'gvproxy-darwin'), Q)  # macOS still assesses it.
            self.assertFalse(runtime.environment_needs_refresh(self.base))
            self.assertFalse(runtime.refresh_environment(self.base, self.backend))
        self.assertEqual({key for key in meta if meta[key] != old[key]}, {'source_sha256', 'backend_assessment'})
        self.assertEqual(meta['backend_assessment'], runtime.BACKEND_ASSESSMENT)
        self.assertEqual((self.base / 'launcher.py').read_bytes(), (runtime.HERE / 'protected_launcher.py').read_bytes())
        self.assertEqual({name: (self.base / name).read_bytes() for name in runtime._KEPT}, kept)
        self.assertEqual((self.base / 'guest-status').stat().st_ino, mailbox)
        self.assertEqual(stat.S_IMODE((self.base / 'gvproxy-darwin').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.base / 'launcher.py').stat().st_mode), 0o700)
        self.assertFalse([p.name for p in self.base.iterdir() if p.name.startswith('.')])
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_refresh_never_repairs_what_it_keeps_or_takes_other_backend_bytes(self):
        self.older_environment()
        launcher_copy = (self.base / 'launcher.py').read_bytes()
        other = self.root / 'other-backend.fixture'
        other.write_bytes(b'other bytes')
        other.chmod(0o600)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'reviewed-backend-digest-mismatch'):
            runtime.refresh_environment(self.base, other)
        for name in runtime._KEPT:
            path = self.base / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_bytes(original + b' ')
                for call in (runtime.environment_needs_refresh, lambda base: runtime.refresh_environment(base, self.backend)):
                    with self.assertRaisesRegex(runtime.RuntimePreparationError, 'environment-source-integrity-mismatch'):
                        call(self.base)
                path.write_bytes(original)
        self.assertEqual((self.base / 'launcher.py').read_bytes(), launcher_copy)
        self.assertFalse(os.path.lexists(self.base / 'gvproxy-darwin'))
        self.assertFalse([p.name for p in self.base.iterdir() if p.name.startswith('.')])

    def test_absent_source_quarantine_blocks_preparation(self):
        self.quarantines[str(self.backend)] = None
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'backend-source-quarantine-required'):
            self.prepare()
        self.assertFalse(self.base.exists())

    def test_current_signed_environment_missing_quarantine_is_not_migrated(self):
        self.prepare()
        copy = self.base / 'gvproxy-darwin'
        self.quarantines[str(copy)] = None
        before = (self.base / 'environment.json').read_bytes()
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'backend-quarantine-changed'):
            runtime.refresh_environment(self.base, self.backend)
        self.assertEqual((self.base / 'environment.json').read_bytes(), before)
        self.assertIsNone(self.quarantines[str(copy)])

    def test_exact_explicit_tart_and_config_binding_not_home_defaults(self):
        self.prepare()
        meta = self.meta()
        self.assertEqual(meta['vm_config'], str(self.config))
        self.assertEqual(meta['tart_home'], str(self.tart_home))
        self.assertEqual(meta['tart_binding']['path'], str(self.tart))
        self.assertEqual(meta['vm_config_sha256'], hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.assertEqual(meta['ecid'], 'FIXTURE_ECID=')

    def test_existing_destination_never_overwritten(self):
        self.prepare()
        before = (self.base / 'environment.json').read_bytes()
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'destination-must-be-new'):
            self.prepare()
        self.assertEqual((self.base / 'environment.json').read_bytes(), before)

    def test_names_mac_and_config_location_fail_before_output(self):
        for name in ('../bad', '-flag', ' bad', 'with.dot'):
            with self.subTest(name=name), self.assertRaises(runtime.RuntimePreparationError):
                self.prepare(vm_name=name)
        wrong = self.root / 'config.json'
        self.put(wrong, {'macAddress': '02:aa:bb:cc:dd:ee', 'ecid': 'x'})
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'explicit-vm-config'):
            self.prepare(published_vm_config=wrong)
        for mac in ('01:00:00:00:00:01', '00:00:00:00:00:00', '5a:94:ef:e4:0c:dd', SECRET):
            self.put(self.config, {'macAddress': mac, 'ecid': 'x'})
            with self.subTest(mac=mac), self.assertRaises(runtime.RuntimePreparationError):
                self.prepare()
        self.assertFalse(self.base.exists())

    def test_changed_private_policy_or_endpoint_mismatch_refused(self):
        config = copy.deepcopy(self.vpn.private_config)
        config['rules'] = ['MATCH,DIRECT']
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'private-config-changed'):
            self.prepare(private_config=config)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'endpoint-config-mismatch'):
            self.prepare(endpoints=[('tcp', '1.1.1.1', 443)])
        for endpoint in [('tcp', '127.0.0.1', 443), ('udp', '8.8.8.8', 53), ('tcp', '8.8.8.8', True)]:
            with self.subTest(endpoint=endpoint), self.assertRaises(runtime.RuntimePreparationError):
                self.prepare(endpoints=[endpoint])
        self.assertFalse(self.base.exists())

    def test_private_receipts_are_copied_and_hashed_not_semantically_trusted(self):
        self.prepare()
        meta = self.meta()
        self.assertEqual((self.base / 'preinstall-receipt.json').read_bytes(), self.preinstall.read_bytes())
        self.assertEqual(meta['preinstall_receipt_sha256'], hashlib.sha256(self.preinstall.read_bytes()).hexdigest())
        self.assertEqual(meta['vpn_seed_receipt_sha256'], hashlib.sha256(self.seed_receipt.read_bytes()).hexdigest())
        self.assertFalse(meta['native_execution_approved'])

    def test_nonprivate_or_symlink_receipt_refused(self):
        self.preinstall.chmod(0o644)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'private-file-required'):
            self.prepare()
        self.preinstall.chmod(0o600)
        alias = self.root / 'alias.json'
        alias.symlink_to(self.preinstall)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'symlink'):
            self.prepare(preinstall_receipt=alias)
        self.assertFalse(self.base.exists())

    def test_tampered_source_copy_manifest_or_private_receipt_refused(self):
        self.prepare()
        (self.base / 'preinstall-receipt.json').write_bytes(b'{}')
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'integrity'):
            runtime.validate_environment(self.base)

    def test_missing_manifest_member_refused_even_if_other_hashes_match(self):
        self.prepare()
        meta = self.meta()
        del meta['source_sha256']['share_support.py']
        self.put(self.base / 'environment.json', meta)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'incomplete-v2-source-manifest'):
            runtime.validate_environment(self.base)

    def test_config_and_tart_changes_refused(self):
        self.prepare()
        original = self.config.read_bytes()
        changed = json.loads(original)
        changed['cpuCount'] = 4
        self.put(self.config, changed)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'vm-config-binding-changed'):
            runtime.validate_environment(self.base)
        self.config.write_bytes(original)
        self.tart.write_bytes(b'changed inert fixture')
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'tart-binding-changed'):
            runtime.validate_environment(self.base)

    def test_metadata_cannot_turn_unsigned_backend_into_approved_backend(self):
        self.prepare()
        meta = self.meta()
        meta['needs_host_security_authorization'] = False
        self.put(self.base / 'environment.json', meta)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-backend-authorization-contract'):
            runtime.validate_environment(self.base)

    def test_legacy_setup_directory_refused_in_v2(self):
        self.prepare()
        (self.base / 'setup').mkdir(mode=0o700)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'legacy-setup-refused'):
            runtime.validate_environment(self.base)

    def test_v2_command_has_only_owned_rw_mailbox_and_validated_user_shares(self):
        self.prepare()
        command = self.command(shares=[{'name': 'data'}], arguments=['--dir=data:/fixture/user-data:ro'], no_graphics=True)
        self.assertEqual(command[:4], [str(self.tart), 'run', self.name, '--net-fd=42'])
        self.assertIn('--dir=gold-status:' + str(self.base / 'guest-status'), command)
        self.assertIn('--dir=data:/fixture/user-data:ro', command)
        self.assertIn('--no-graphics', command)
        self.assertIn('--no-clipboard', command)
        self.assertFalse(any('setup:' in arg or 'nat' in arg.lower() or 'suspendable' in arg for arg in command))

    def test_reserved_mailbox_and_setup_names_casefolded(self):
        self.prepare()
        for name in ('gold-status', 'GoLd-StAtUs', 'setup', 'SETUP'):
            with self.subTest(name=name), self.assertRaisesRegex(runtime.RuntimePreparationError, 'reserved-share-name'):
                self.command(shares=[{'name': name}])

    def test_recovery_never_shares_mailbox_setup_or_user_directory(self):
        self.prepare()
        command = self.command(shares=[{'name': 'data'}], arguments=['--dir=data:/fixture'], recovery=True)
        self.assertIn('--recovery', command)
        self.assertIn('--no-clipboard', command)
        self.assertFalse(any(arg.startswith('--dir=') for arg in command))
        self.assertIn('--net-fd=42', command)

    def test_mailbox_permission_change_fails_closed(self):
        self.prepare()
        (self.base / 'guest-status').chmod(0o755)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'private-directory-required'):
            self.command()

    def test_default_v2_launch_refuses_before_any_native_execution(self):
        self.prepare()
        with mock.patch.object(launcher, 'BASE', self.base), mock.patch.object(sys, 'argv', ['launcher.py']):
            with self.assertRaisesRegex(runtime.RuntimePreparationError, 'awaiting-host-authorization'):
                launcher.main()
        status = json.loads((self.base / 'status.json').read_text())
        self.assertEqual(status['state'], 'awaiting_host_authorization')
        self.assertFalse(status['native_execution_approved'])
        self.assertFalse(status['vm_started'])
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_acknowledgement_is_not_a_native_signature_success(self):
        self.prepare()
        meta = self.meta()
        runtime.require_backend_authorization(meta, True)
        self.assertFalse(meta['native_execution_approved'])
        self.assertTrue(meta['needs_host_security_authorization'])
        for value in (1, 'yes', None):
            with self.assertRaises(runtime.RuntimePreparationError):
                runtime.require_backend_authorization(meta, value)

    def test_acknowledged_nonexecutable_backend_still_fails_without_chmod(self):
        self.prepare()
        with mock.patch.object(launcher, 'BASE', self.base), mock.patch.object(sys, 'argv', [
                'launcher.py', '--acknowledge-reviewed-unsigned-backend']):
            with self.assertRaisesRegex(runtime.RuntimePreparationError, 'backend-not-executable'):
                launcher.main()
        self.assertEqual(stat.S_IMODE((self.base / 'gvproxy-darwin').stat().st_mode), 0o600)
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_os_refusal_is_not_retried_or_fallen_back_and_keeps_authorization_state(self):
        self.backend.chmod(0o700)
        self.prepare()
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(stdout=json.dumps([
            {'Name': self.name, 'Source': 'local', 'Running': False, 'State': 'stopped'}]))
        self.spawn.side_effect = PermissionError('synthetic OS denial; no native invocation')
        runtime_dir = self.root / 'run'
        runtime_dir.mkdir(mode=0o700)
        plan = SimpleNamespace(shares=[], arguments=[])
        with mock.patch.object(launcher, 'BASE', self.base), mock.patch.object(sys, 'argv', [
                'launcher.py', '--acknowledge-reviewed-unsigned-backend']), \
                mock.patch.object(runtime_shares, 'prepare_vm_shares', return_value=plan), \
                mock.patch.object(launcher.tempfile, 'mkdtemp', return_value=str(runtime_dir)), \
                mock.patch.object(launcher.signal, 'signal'):
            with self.assertRaises(PermissionError):
                launcher.main()
        self.assertEqual(self.spawn.call_count, 1)
        argv = self.spawn.call_args[0][0]
        self.assertEqual(argv[0], str(self.base / 'gvproxy-darwin'))
        self.assertNotIn('spctl', ' '.join(argv))
        env = self.spawn.call_args[1]['env']
        self.assertEqual(env['TART_HOME'], str(self.tart_home))
        self.assertEqual(set(env), {'HOME', 'TART_HOME', 'PATH', 'LANG', 'PYTHONNOUSERSITE',
                                    'PYTHONDONTWRITEBYTECODE', 'TART_NO_AUTO_PRUNE'})
        for key in ('PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE', 'TART_NO_AUTO_PRUNE'):
            self.assertEqual(env[key], '1')
        self.assertNotIn('DYLD_INSERT_LIBRARIES', env)
        self.assertEqual(self.run.call_args[1]['env'], env)
        status = json.loads((self.base / 'status.json').read_text())
        self.assertEqual(status['state'], 'awaiting_host_authorization')
        self.assertFalse(status['native_execution_approved'])
        self.assertEqual(self.quarantines[str(self.base / 'gvproxy-darwin')], Q)

    def test_real_local_datagram_path_filters_and_disconnects_on_backend_loss(self):
        # Run the actual launcher and its selector on Unix datagram sockets only.
        # Subprocesses are inert fixtures; addresses appear in Ethernet bytes,
        # never in AF_INET sockets, DNS, a VM, or an external request.
        vpn = parse_submission({'input_mode': 'fields', 'nodes': [{
            'type': 'hysteria2', 'server': '8.8.8.8', 'port': 443,
            'password': SECRET, 'sni': 'vpn.example.com'}]})
        self.backend.chmod(0o700)
        self.prepare(private_config=vpn.private_config, endpoints=vpn.endpoints)
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(stdout=json.dumps([
            {'Name': self.name, 'Source': 'local', 'Running': False, 'State': 'stopped'}]))
        plan = SimpleNamespace(shares=[], arguments=[], record_launch=mock.Mock())
        # Darwin Unix socket path length is short. Allocate a private short root.
        temp_parent = Path('/tmp').resolve(strict=True)
        directory = Path(tempfile.mkdtemp(prefix='goldnet-test-', dir=str(temp_parent)))
        def cleanup_directory():
            self.assertEqual(directory.resolve(strict=True), directory)
            self.assertEqual(directory.parent, temp_parent)
            self.assertTrue(directory.name.startswith('goldnet-test-'))
            self.assertFalse(directory.is_symlink())
            self.assertEqual(directory.stat().st_uid, os.getuid())
            shutil.rmtree(str(directory))
        self.addCleanup(cleanup_directory)
        mac_guest = bytes.fromhex('02aabbccddee')
        mac_gateway = bytes.fromhex('5a94efe40cdd')
        def frame(out, address='8.8.8.8', remote_port=443):
            guest, remote = socket.inet_aton('192.168.127.2'), socket.inet_aton(address)
            src, dst = (guest, remote) if out else (remote, guest)
            ports = (43123, remote_port) if out else (remote_port, 43123)
            payload = b'local datagram fixture'
            udp = struct.pack('!HHHH', *ports, 8 + len(payload), 0) + payload
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0, src, dst)
            checksum = sum(struct.unpack('!10H', ip))
            checksum = (checksum & 0xffff) + (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16)
            complete = ip[:10] + struct.pack('!H', 0xffff ^ checksum) + ip[12:]
            eth = mac_gateway + mac_guest if out else mac_guest + mac_gateway
            return eth + b'\x08\x00' + complete + udp
        request, reply = frame(True), frame(False)
        steps = [
            ('in', reply, None),                              # unsolicited reply
            ('out', frame(True, remote_port=53), None),        # direct DNS
            ('out', frame(True, address='192.168.127.59'), None),  # local address
            ('out', frame(True, remote_port=8443), None),      # wrong tuple
            ('out', request, request),
            ('in', reply, reply),
            ('in', reply, None),                              # backend dies in select
        ]
        processes = {'backend_rc': None, 'children_stopped': []}
        backend = SimpleNamespace(pid=8001, poll=lambda: processes['backend_rc'])
        child = SimpleNamespace(pid=8002, poll=lambda: None)
        with ExitStack() as local:
            backend_peer = local.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
            backend_peer.settimeout(1)
            real_selector = local.enter_context(selectors.DefaultSelector())
            registered = []
            peers = {}
            def spawn(argv, **kwargs):
                if argv[0] == str(self.base / 'gvproxy-darwin'):
                    self.assertEqual(argv[argv.index('--listen-vfkit') + 1], 'unixgram://' + str(directory / 'gv.sock'))
                    self.assertNotIn('pass_fds', kwargs)
                    backend_peer.bind(str(directory / 'gv.sock'))
                    return backend
                self.assertEqual(argv[:3], [str(self.tart), 'run', self.name])
                (vm_fd,) = kwargs['pass_fds']
                self.assertEqual(argv[3], '--net-fd=' + str(vm_fd))
                self.assertNotIn('--net-softnet', argv)
                peer = local.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, fileno=os.dup(vm_fd)))
                marker, endpoint = backend_peer.recvfrom(32)
                self.assertEqual(marker, b'VFKT')
                self.assertEqual(endpoint, str(directory / 'filter.sock'))
                peers.update(guest=peer, filter=endpoint)
                peer.setblocking(False)
                backend_peer.setblocking(False)
                return child
            def check(step):
                direction, _, want = step
                receiver = backend_peer if direction == 'out' else peers['guest']
                if want is None:
                    with self.assertRaises(BlockingIOError):
                        receiver.recv(2048)
                else:
                    self.assertEqual(receiver.recv(2048), want)
            test = self
            class ObserveSelector:
                index = 0
                closed = False
                def register(self, fileobj, events, data):
                    registered.append(fileobj)
                    return real_selector.register(fileobj, events, data)
                def select(self, timeout):
                    if self.index:
                        check(steps[self.index - 1])
                    test.assertLess(self.index, len(steps))
                    direction, packet, _ = steps[self.index]
                    if direction == 'out':
                        test.assertEqual(peers['guest'].send(packet), len(packet))
                    else:
                        test.assertEqual(backend_peer.sendto(packet, peers['filter']), len(packet))
                    self.index += 1
                    ready = real_selector.select(timeout)
                    test.assertEqual([key.data for key, _ in ready], [direction])
                    if self.index == len(steps):
                        processes['backend_rc'] = 1
                    return ready
                def close(self):
                    real_selector.close()
                    self.closed = True
            selector = ObserveSelector()
            def stop(proc, _signal):
                self.assertEqual(len(registered), 2)
                self.assertTrue(all(s.fileno() == -1 for s in registered))
                processes['children_stopped'].append(proc)
            self.spawn.side_effect = spawn
            with mock.patch.object(launcher, 'BASE', self.base), mock.patch.object(sys, 'argv', [
                    'launcher.py', '--acknowledge-reviewed-unsigned-backend']), \
                    mock.patch.object(runtime_shares, 'prepare_vm_shares', return_value=plan), \
                    mock.patch.object(launcher.tempfile, 'mkdtemp', return_value=str(directory)), \
                    mock.patch.object(launcher.signal, 'signal'), \
                    mock.patch.object(launcher.selectors, 'DefaultSelector', return_value=selector), \
                    mock.patch.object(launcher, 'stop_process', side_effect=stop):
                with self.assertRaisesRegex(RuntimeError, 'Network backend exited'):
                    launcher.main()
            self.assertEqual(selector.index, len(steps))
            # Darwin can report reset once the other socketpair end is closed;
            # neither outcome can deliver the data already queued by the peer.
            with self.assertRaises((BlockingIOError, ConnectionResetError)):
                peers['guest'].recv(2048)
            self.assertTrue(selector.closed)
        self.assertEqual(self.spawn.call_count, 2)
        self.assertEqual(processes['children_stopped'], [child, backend])
        plan.record_launch.assert_called_once_with(child.pid)
        status = json.loads((self.base / 'status.json').read_text())
        self.assertEqual(status['state'], 'failed-closed')
        self.assertEqual(status['cleanup_errors'], [])
        self.assertFalse(status['native_execution_approved'])
        self.assertFalse(status['network_independently_verified'])
        self.assertFalse(status['desktop_verified'])

    def test_guest_report_never_becomes_independent_desktop_or_network_proof(self):
        self.prepare()
        value = {'schema_version': 1, 'evidence': 'guest_reported', 'configuration': 'imported',
                 'application': 'opened', 'system_authorization': 'user_action_may_be_required',
                 'connection_check': 'not_run', 'host_independently_verified': False}
        self.put(self.base / 'guest-status' / (TOKEN + '.json'), value)
        result = runtime.read_guest_status(self.base, TOKEN)
        self.assertEqual(result['evidence'], 'guest_reported')
        self.assertFalse(result['desktop_verified'])
        self.assertFalse(result['network_independently_verified'])
        self.assertFalse(result['host_independently_verified'])
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_guest_report_absent_and_forged_success(self):
        self.prepare()
        self.assertEqual(runtime.read_guest_status(self.base, TOKEN)['evidence'], 'not_observed')
        self.put(self.base / 'guest-status' / (TOKEN + '.json'), {'host_independently_verified': True})
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-guest-self-report'):
            runtime.read_guest_status(self.base, TOKEN)
        for token in ('../secret', 'b' * 65, SECRET):
            with self.assertRaises(runtime.RuntimePreparationError):
                runtime.read_guest_status(self.base, token)

    def test_guest_report_symlink_not_followed(self):
        self.prepare()
        (self.base / 'guest-status' / (TOKEN + '.json')).symlink_to(self.seed_receipt)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'symlink'):
            runtime.read_guest_status(self.base, TOKEN)

    def test_production_backend_pin_rejects_inert_fixture_without_mutating_pin(self):
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'reviewed-backend-digest-mismatch'):
            REAL_VERIFY_BACKEND(self.backend)
        self.assertEqual(self.backend.read_bytes(), BACKEND)

    def test_quarantine_copy_policy_never_ensures_or_clears_absent_attribute(self):
        import quarantine_policy
        with mock.patch.object(quarantine_policy, 'propagate') as propagate, \
                mock.patch.object(quarantine_policy, 'ensure') as ensure, \
                mock.patch.object(runtime, '_quarantine', side_effect=[Q, Q]):
            REAL_PRESERVE_QUARANTINE(self.backend, self.root / 'copy.fixture', Q)
        propagate.assert_called_once_with(self.backend, self.root / 'copy.fixture')
        ensure.assert_not_called()
        with mock.patch.object(quarantine_policy, 'propagate') as propagate, \
                mock.patch.object(quarantine_policy, 'ensure') as ensure, \
                mock.patch.object(runtime, '_quarantine', side_effect=[None, None]):
            REAL_PRESERVE_QUARANTINE(self.backend, self.root / 'copy.fixture', None)
        propagate.assert_not_called()
        ensure.assert_not_called()

    def test_early_backend_exit_keeps_authorization_pending_without_vm(self):
        self.backend.chmod(0o700)
        self.prepare()
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(stdout=json.dumps([
            {'Name': self.name, 'Source': 'local', 'Running': False, 'State': 'stopped'}]))
        backend = mock.Mock()
        backend.poll.return_value = 126
        self.spawn.side_effect = None
        self.spawn.return_value = backend
        runtime_dir = self.root / 'early-exit-run'
        runtime_dir.mkdir(mode=0o700)
        with mock.patch.object(launcher, 'BASE', self.base), mock.patch.object(sys, 'argv', [
                'launcher.py', '--acknowledge-reviewed-unsigned-backend']), \
                mock.patch.object(runtime_shares, 'prepare_vm_shares',
                                  return_value=SimpleNamespace(shares=[], arguments=[])), \
                mock.patch.object(launcher.tempfile, 'mkdtemp', return_value=str(runtime_dir)), \
                mock.patch.object(launcher.signal, 'signal'):
            with self.assertRaisesRegex(RuntimeError, 'Network backend unavailable'):
                launcher.main()
        self.assertEqual(self.spawn.call_count, 1)
        self.assertEqual(json.loads((self.base / 'status.json').read_text())['state'],
                         'awaiting_host_authorization')
        backend.send_signal.assert_not_called()

    def test_host_authorization_gate_still_holds_per_vm_flock(self):
        import fcntl
        self.prepare()
        lock_path = self.base / 'run.lock'
        with lock_path.open('a+') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with mock.patch.object(launcher, 'BASE', self.base), mock.patch.object(sys, 'argv', ['launcher.py']):
                self.assertEqual(launcher.main(), 0)
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def staged_inputs(self):
        stage = self.root / 'new-stage'
        stage.mkdir(mode=0o700)
        source = stage / 'config.json'
        source.write_bytes(self.config.read_bytes())
        source.chmod(0o600)
        name = 'new-staged-vm'
        destination = self.tart_home / 'vms' / name / 'config.json'
        return source, destination, name

    def test_prepare_before_publication_then_same_filesystem_rename_validates(self):
        source, published, name = self.staged_inputs()
        before = source.stat()
        result = self.prepare(vm_name=name, vm_config=source, published_vm_config=published)
        self.assertFalse(published.exists())
        self.assertTrue(source.exists())
        self.assertEqual(result['status'], 'awaiting_host_authorization')
        meta = self.meta()
        self.assertEqual(meta['vm_config'], str(published))
        self.assertEqual(meta['vm_config_identity'], [before.st_dev, before.st_ino])
        with self.assertRaises(runtime.RuntimePreparationError):
            runtime.validate_environment(self.base)
        # Verify both exact owned disposable paths before the fixture directory move.
        self.assertEqual(source.parent.resolve(strict=True), self.root / 'new-stage')
        self.assertEqual(published.parent.resolve(strict=False), self.tart_home / 'vms' / name)
        self.assertFalse(published.parent.exists())
        os.rename(str(source.parent), str(published.parent))
        self.assertEqual(published.stat().st_ino, before.st_ino)
        self.assertEqual(runtime.validate_environment(self.base)['vm_name'], name)
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_copy_instead_of_atomic_publication_fails_config_inode_pin(self):
        source, published, name = self.staged_inputs()
        self.prepare(vm_name=name, vm_config=source, published_vm_config=published)
        published.parent.mkdir(mode=0o700)
        published.write_bytes(source.read_bytes())
        published.chmod(0o600)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'vm-config-binding-changed'):
            runtime.validate_environment(self.base)

    def test_existing_published_config_cannot_be_rebound_to_stage(self):
        source, _, _ = self.staged_inputs()
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'published-config-already-exists'):
            self.prepare(vm_config=source, published_vm_config=self.config)
        self.assertFalse(self.base.exists())

    def test_published_vm_config_is_mandatory_keyword(self):
        with self.assertRaises(TypeError):
            runtime.prepare_environment(self.name, self.config, self.base,
                private_config=self.vpn.private_config, endpoints=self.vpn.endpoints,
                gvproxy_path=self.backend, tart_path=self.tart,
                preinstall_receipt=self.preinstall, vpn_seed_receipt=self.seed_receipt)

    def test_errors_do_not_return_private_input_or_exception_text(self):
        with mock.patch.object(runtime, '_quarantine', side_effect=ValueError(SECRET)):
            with self.assertRaises(runtime.RuntimePreparationError) as raised:
                self.prepare()
        self.assertNotIn(SECRET, repr(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)


if __name__ == '__main__':
    unittest.main()
