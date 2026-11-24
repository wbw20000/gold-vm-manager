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
        self.jobs = 0
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

    def new_installers(self):
        """A folder as oneclick.build_installers leaves it: 0755 inside a private job directory."""
        self.jobs += 1
        job = self.root / ('job-%d' % self.jobs)
        job.mkdir(mode=0o700)
        folder = job / 'installers'
        folder.mkdir(mode=0o700)
        (folder / 'inert.fixture').write_text('inert fixture; never a real app')
        folder.chmod(0o755)
        return folder

    def prepare(self, **changes):
        values = dict(vm_name=self.name, vm_config=self.config, published_vm_config=self.config,
                      destination_private_base=self.base,
                      private_config=self.vpn.private_config, endpoints=self.vpn.endpoints,
                      gvproxy_path=self.backend, tart_path=self.tart)
        values.update(changes)
        if 'installers' not in values:
            values['installers'] = self.new_installers()
        return runtime.prepare_environment(**values)

    def prepare_v2(self, **changes):
        """The v2 layout that builds before 2026-11-20 published (bb1): private receipts
        and a guest mailbox, no installers folder."""
        result = self.prepare(**changes)
        meta = self.meta()
        installers = self.base / runtime.INSTALLERS_NAME
        self.assertEqual(installers.resolve(strict=True), self.expected_root / 'environment' / 'installers')
        shutil.rmtree(str(installers))
        mailbox = self.base / 'guest-status'
        mailbox.mkdir(mode=0o700)
        for name, source in (('preinstall-receipt.json', self.preinstall), ('vpn-seed-receipt.json', self.seed_receipt)):
            (self.base / name).write_bytes(source.read_bytes())
            (self.base / name).chmod(0o600)
            meta['source_sha256'][name] = hashlib.sha256(source.read_bytes()).hexdigest()
        del meta['installers_identity']
        meta.update(version=2, preinstall_receipt_sha256=meta['source_sha256']['preinstall-receipt.json'],
                    vpn_seed_receipt_sha256=meta['source_sha256']['vpn-seed-receipt.json'],
                    guest_status_identity=[mailbox.stat().st_dev, mailbox.stat().st_ino],
                    guest_status_share='gold-status')
        (self.base / 'environment.json').write_bytes(runtime._json(meta))
        runtime.validate_environment(self.base)
        return result

    def meta(self):
        return json.loads((self.base / 'environment.json').read_text())

    def command(self, shares=(), arguments=(), **options):
        plan = SimpleNamespace(shares=list(shares), arguments=list(arguments))
        with mock.patch.object(launcher, 'BASE', self.base):
            return launcher.build_tart_command(self.name, 42, plan, environment=self.meta(), **options)

    def test_prepare_public_result_no_credentials_no_process_and_v3_validation(self):
        result = self.prepare()
        self.assertEqual(result['version'], 3)
        self.assertEqual(result['status'], 'awaiting_first_setup')
        self.assertTrue(result['needs_host_security_authorization'])
        self.assertFalse(result['native_execution_approved'])
        self.assertFalse(result['desktop_verified'])
        self.assertFalse(result['network_independently_verified'])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn('8.8.8.8', json.dumps(result))
        with mock.patch.object(launcher, 'BASE', self.base):
            self.assertEqual(launcher.validate_environment()['version'], 3)
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_published_v2_environment_still_validates_through_the_same_launcher(self):
        self.prepare_v2()
        with mock.patch.object(launcher, 'BASE', self.base):
            meta = launcher.validate_environment()
        self.assertEqual(meta['version'], 2)
        self.assertEqual(set(meta['source_sha256']), runtime._LAYOUTS[2][0])
        self.assertEqual(runtime.status_directory(self.base, meta), self.base / 'guest-status')
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'installers-unavailable'):
            runtime.installers_directory(self.base, meta)
        for version in (1, 4, True):
            changed = dict(meta, version=version)
            self.put(self.base / 'environment.json', changed)
            with self.subTest(version=version), self.assertRaises(runtime.RuntimePreparationError):
                runtime.validate_environment(self.base)

    def test_no_legacy_setup_material_or_raw_private_config(self):
        self.prepare()
        names = {p.name for p in self.base.iterdir()}
        for forbidden in ('setup', 'mihomo', 'config.json', 'profile.json', 'Install.command'):
            self.assertNotIn(forbidden, names)
        self.assertFalse(any(p.suffix == '.dmg' for p in self.base.iterdir()))
        meta = self.meta()
        self.assertFalse(meta['setup_active'])
        self.assertEqual(set(meta['source_sha256']), runtime._LAYOUTS[3][0])
        self.assertNotIn('guest-status', names)
        self.assertNotIn('preinstall-receipt.json', names)
        self.assertIn('installers', names)
        self.assertNotIn(SECRET, json.dumps(meta))
        self.assertEqual(meta['private_config_sha256'], runtime._sha(runtime._json(self.vpn.private_config)))
        policy = json.loads((self.base / 'policy.json').read_text())
        self.assertEqual(policy, {'guest_mac': '02:aa:bb:cc:dd:ee', 'endpoints': [list(v) for v in self.vpn.endpoints]})

    def test_files_are_private_installers_readable_and_source_exec_not_added(self):
        self.prepare()
        for path in self.base.iterdir():
            if path.name == runtime.INSTALLERS_NAME:
                continue
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertIn(mode, (0o600, 0o700))
            self.assertEqual(mode & 0o077, 0)
        self.assertEqual(stat.S_IMODE(self.base.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.base / 'installers').stat().st_mode), 0o755)
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
        self.prepare_v2()
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
        kept = {name: (self.base / name).read_bytes() for name in runtime._LAYOUTS[2][2]}
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
        self.assertEqual({name: (self.base / name).read_bytes() for name in runtime._LAYOUTS[2][2]}, kept)
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
        for name in runtime._LAYOUTS[2][2]:
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

    def signed_environment_with_older_code(self, v2=True):
        """A current signed environment whose launcher copy predates this build (bb1 after 602adc1)."""
        self.prepare_v2() if v2 else self.prepare()
        meta = self.meta()
        older = b'# GOLD_VM_MANAGER_SHARES_V1\n# GOLD_VM_MANAGER_RECOVERY_V1\n# launcher before first-setup support\n'
        (self.base / 'launcher.py').write_bytes(older)
        meta['source_sha256']['launcher.py'] = hashlib.sha256(older).hexdigest()
        (self.base / 'environment.json').write_bytes(runtime._json(meta))
        return meta

    def test_source_refresh_gives_an_intact_environment_only_this_builds_code(self):
        old = self.signed_environment_with_older_code()
        kept = {name: (self.base / name).read_bytes() for name in ('gvproxy-darwin',) + runtime._LAYOUTS[2][2]}
        backend_inode = (self.base / 'gvproxy-darwin').stat().st_ino
        mailbox = (self.base / 'guest-status').stat().st_ino
        self.assertTrue(runtime.environment_sources_outdated(self.base))
        self.assertTrue(runtime.refresh_sources(self.base))
        meta = runtime.validate_environment(self.base)
        self.assertEqual((self.base / 'launcher.py').read_bytes(), (runtime.HERE / 'protected_launcher.py').read_bytes())
        self.assertEqual(stat.S_IMODE((self.base / 'launcher.py').stat().st_mode), 0o700)
        self.assertEqual({key for key in meta if meta[key] != old[key]}, {'source_sha256'})
        self.assertEqual({name for name, digest in meta['source_sha256'].items()
                          if digest != old['source_sha256'][name]}, {'launcher.py'})
        self.assertEqual({name: (self.base / name).read_bytes() for name in kept}, kept)
        self.assertEqual((self.base / 'gvproxy-darwin').stat().st_ino, backend_inode)
        self.assertEqual(self.quarantines[str(self.base / 'gvproxy-darwin')], Q)
        self.assertEqual((self.base / 'guest-status').stat().st_ino, mailbox)
        self.assertFalse(runtime.environment_sources_outdated(self.base))
        self.assertFalse(runtime.refresh_sources(self.base))
        self.assertFalse([p.name for p in self.base.iterdir() if p.name.startswith('.')])
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_source_refresh_keeps_a_v3_installers_folder(self):
        old = self.signed_environment_with_older_code(v2=False)
        installers = (self.base / 'installers').stat().st_ino
        self.assertFalse(runtime.environment_needs_refresh(self.base))
        self.assertTrue(runtime.refresh_sources(self.base))
        meta = runtime.validate_environment(self.base)
        self.assertEqual({key for key in meta if meta[key] != old[key]}, {'source_sha256'})
        self.assertEqual((self.base / 'installers').stat().st_ino, installers)
        self.assertEqual(meta['installers_identity'], old['installers_identity'])
        self.assertFalse(runtime.refresh_environment(self.base, self.backend))

    def test_source_refresh_never_repairs_a_changed_or_legacy_environment(self):
        self.signed_environment_with_older_code()
        launcher_copy = self.base / 'launcher.py'
        original = launcher_copy.read_bytes()
        record = (self.base / 'environment.json').read_bytes()
        launcher_copy.write_bytes(original + b'# changed after preparation\n')
        for call in (runtime.environment_sources_outdated, runtime.refresh_sources):
            with self.subTest(call=call.__name__), \
                    self.assertRaisesRegex(runtime.RuntimePreparationError, 'environment-source-integrity-mismatch'):
                call(self.base)
        launcher_copy.write_bytes(original)
        self.quarantines[str(self.base / 'gvproxy-darwin')] = None
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'backend-quarantine-changed'):
            runtime.refresh_sources(self.base)
        self.quarantines[str(self.base / 'gvproxy-darwin')] = Q
        meta = self.meta()
        meta['backend_assessment'] = runtime._UNNOTARIZED_ASSESSMENT
        (self.base / 'environment.json').write_bytes(runtime._json(meta))
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-backend-authorization-contract'):
            runtime.refresh_sources(self.base)  # Legacy environments take refresh_environment instead.
        (self.base / 'environment.json').write_bytes(record)
        self.assertEqual(launcher_copy.read_bytes(), original)
        self.assertFalse([p.name for p in self.base.iterdir() if p.name.startswith('.')])

    def test_first_setup_runs_until_marked_finished_and_never_reverts(self):
        self.prepare()
        record = self.base / 'network-mode.json'
        self.assertTrue(runtime.first_setup_pending(self.base))
        runtime.require_first_setup(self.base)
        self.assertTrue(runtime.finish_first_setup(self.base))
        self.assertEqual(json.loads(record.read_text()), {'version': 1, 'mode': 'protected'})
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertFalse(runtime.first_setup_pending(self.base))
        self.assertFalse(runtime.finish_first_setup(self.base))
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'first-setup-finished'):
            runtime.require_first_setup(self.base)
        runtime.validate_environment(self.base)  # A host-only record outside the reviewed manifest.
        finished = record.read_bytes()
        for raw in (b'{"mode":"protected","version":true}', b'{"mode":"first-setup","version":1}',
                    b'{"mode":"protected","version":1,"extra":1}', b'[]', b'not json'):
            record.write_bytes(raw)
            for call in (runtime.first_setup_pending, runtime.finish_first_setup):
                with self.subTest(raw=raw, call=call.__name__), \
                        self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-network-mode'):
                    call(self.base)
            self.assertEqual(record.read_bytes(), raw)  # Never overwritten or repaired.
        record.write_bytes(finished)
        record.chmod(0o644)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-network-mode'):
            runtime.first_setup_pending(self.base)
        record.unlink()
        other = self.root / 'finished-elsewhere.json'
        other.write_bytes(finished)
        other.chmod(0o600)
        record.symlink_to(other)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-network-mode'):
            runtime.first_setup_pending(self.base)
        self.assertFalse([p.name for p in self.base.iterdir() if p.name.startswith('.')])

    def test_first_setup_command_uses_normal_network_with_mailbox_and_user_shares(self):
        self.prepare_v2()
        plan = SimpleNamespace(shares=[{'name': 'data'}], arguments=['--dir=data:/fixture/user-data:ro'])
        with mock.patch.object(launcher, 'BASE', self.base):
            command = launcher.build_tart_command(self.name, None, plan, environment=self.meta(), first_setup=True)
            self.assertEqual(command[:4], [str(self.tart), 'run', self.name, '--no-clipboard'])
            self.assertFalse(any(arg.startswith('--net') for arg in command))
            self.assertIn('--dir=gold-status:' + str(self.base / 'guest-status'), command)
            self.assertIn('--dir=data:/fixture/user-data:ro', command)
            for fd, recovery in ((42, False), (None, True)):
                with self.subTest(fd=fd, recovery=recovery), \
                        self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-v2-launch-binding'):
                    launcher.build_tart_command(self.name, fd, plan, recovery=recovery, environment=self.meta(),
                                                first_setup=True)
            with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-v2-launch-binding'):
                launcher.build_tart_command(self.name, None, plan, environment=self.meta())

    def test_v3_first_setup_shares_installers_read_only_and_protected_starts_never_do(self):
        self.prepare()
        plan = SimpleNamespace(shares=[{'name': 'data'}], arguments=['--dir=data:/fixture/user-data:ro'])
        with mock.patch.object(launcher, 'BASE', self.base):
            command = launcher.build_tart_command(self.name, None, plan, environment=self.meta(), first_setup=True)
            protected = launcher.build_tart_command(self.name, 42, plan, environment=self.meta())
        self.assertEqual(command[:4], [str(self.tart), 'run', self.name, '--no-clipboard'])
        self.assertFalse(any(arg.startswith('--net') for arg in command))
        self.assertEqual([arg for arg in command if arg.startswith('--dir=')],
                         ['--dir=gold-installers:' + str(self.base / 'installers') + ':ro', '--dir=data:/fixture/user-data:ro'])
        self.assertEqual([arg for arg in protected if arg.startswith('--dir=')], ['--dir=data:/fixture/user-data:ro'])
        self.assertIn('--net-fd=42', protected)
        self.assertFalse(any('gold-status' in arg or 'guest-status' in arg for arg in command + protected))

    def test_vms_prepared_before_the_clipboard_agent_keep_no_clipboard_everywhere(self):
        result = self.prepare()
        self.assertIs(result['clipboard_shared'], False)
        self.assertFalse((self.base / runtime.CLIPBOARD_NAME).exists())
        self.assertFalse(runtime.clipboard_shared(self.base))
        plan = SimpleNamespace(shares=[], arguments=[])
        with mock.patch.object(launcher, 'BASE', self.base):
            commands = [launcher.build_tart_command(self.name, None, plan, environment=self.meta(), first_setup=True),
                        launcher.build_tart_command(self.name, 42, plan, environment=self.meta()),
                        launcher.build_tart_command(self.name, 42, plan, recovery=True, environment=self.meta())]
        for command in commands:
            self.assertEqual(command.count('--no-clipboard'), 1)

    def test_new_vm_shares_the_clipboard_on_normal_and_first_setup_starts_but_never_in_recovery(self):
        result = self.prepare(share_clipboard=True)
        self.assertIs(result['clipboard_shared'], True)
        record = self.base / runtime.CLIPBOARD_NAME
        self.assertEqual(json.loads(record.read_bytes()), {'version': 1, 'clipboard': 'shared'})
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertNotIn(runtime.CLIPBOARD_NAME, self.meta()['source_sha256'])  # Host-only record.
        runtime.validate_environment(self.base)
        plan = SimpleNamespace(shares=[{'name': 'data'}], arguments=['--dir=data:/fixture/user-data:ro'])
        with mock.patch.object(launcher, 'BASE', self.base):
            first = launcher.build_tart_command(self.name, None, plan, environment=self.meta(), first_setup=True)
            protected = launcher.build_tart_command(self.name, 42, plan, environment=self.meta())
            recovery = launcher.build_tart_command(self.name, 42, plan, recovery=True, environment=self.meta())
        self.assertEqual(first[:3], [str(self.tart), 'run', self.name])
        self.assertNotIn('--no-clipboard', first)
        self.assertFalse(any(arg.startswith('--net') for arg in first))
        self.assertEqual(protected[:4], [str(self.tart), 'run', self.name, '--net-fd=42'])
        self.assertNotIn('--no-clipboard', protected)
        self.assertIn('--dir=data:/fixture/user-data:ro', protected)
        self.assertIn('--recovery', recovery)
        self.assertIn('--no-clipboard', recovery)
        self.assertFalse(any(arg.startswith('--dir=') for arg in recovery))
        # Marking first setup finished changes the network, not the clipboard.
        self.assertTrue(runtime.finish_first_setup(self.base))
        self.assertTrue(runtime.clipboard_shared(self.base))

    def test_any_other_clipboard_record_fails_closed_and_is_never_repaired(self):
        self.prepare(share_clipboard=True)
        record = self.base / runtime.CLIPBOARD_NAME
        plan = SimpleNamespace(shares=[], arguments=[])
        for raw in (b'{"version":1,"clipboard":"off"}', b'{"version":2,"clipboard":"shared"}', b'',
                    b'{"version":1,"clipboard":"shared","x":1}', b'{"version":1,"version":1,"clipboard":"shared"}'):
            with self.subTest(raw=raw):
                record.chmod(0o600)
                record.write_bytes(raw)
                with self.assertRaisesRegex(runtime.RuntimePreparationError, '^invalid-clipboard-record$'):
                    runtime.clipboard_shared(self.base)
                with mock.patch.object(launcher, 'BASE', self.base), \
                        self.assertRaisesRegex(runtime.RuntimePreparationError, '^invalid-clipboard-record$'):
                    launcher.build_tart_command(self.name, 42, plan, environment=self.meta())
                self.assertEqual(record.read_bytes(), raw)
        record.write_bytes(b'{"version":1,"clipboard":"shared"}')
        record.chmod(0o644)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, '^invalid-clipboard-record$'):
            runtime.clipboard_shared(self.base)
        record.unlink()
        other = self.root / 'shared-elsewhere.json'
        other.write_bytes(b'{"version":1,"clipboard":"shared"}')
        other.chmod(0o600)
        record.symlink_to(other)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, '^invalid-clipboard-record$'):
            runtime.clipboard_shared(self.base)
        shutil.rmtree(str(self.base))
        for bad in (1, 'yes', None):
            with self.subTest(choice=bad), \
                    self.assertRaisesRegex(runtime.RuntimePreparationError, '^invalid-clipboard-choice$'):
                self.prepare(share_clipboard=bad)
            self.assertFalse(self.base.exists())  # Refused before anything is created.

    def first_setup_launch(self, *flags):
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(stdout=json.dumps([
            {'Name': self.name, 'Source': 'local', 'Running': False, 'State': 'stopped'}]))
        plan = SimpleNamespace(shares=[], arguments=[], record_launch=mock.Mock())
        child = SimpleNamespace(pid=8002, poll=lambda: 0)
        stopped = []
        self.spawn.side_effect = None
        self.spawn.return_value = child
        with mock.patch.object(launcher, 'BASE', self.base), \
                mock.patch.object(sys, 'argv', ['launcher.py', '--first-setup-normal-network', *flags]), \
                mock.patch.object(runtime_shares, 'prepare_vm_shares', return_value=plan), \
                mock.patch.object(launcher.tempfile, 'mkdtemp', side_effect=AssertionError('no backend runtime')), \
                mock.patch.object(launcher.signal, 'signal'), \
                mock.patch.object(launcher, 'stop_process', side_effect=lambda proc, signum: stopped.append(proc)):
            result = launcher.main()
        return result, plan, child, stopped

    def test_first_setup_launch_runs_tart_on_its_normal_network_and_never_the_backend(self):
        self.prepare_v2()
        result, plan, child, stopped = self.first_setup_launch()
        self.assertEqual(result, 0)
        self.assertEqual(self.spawn.call_count, 1)  # Tart only; the backend is never executed.
        argv = self.spawn.call_args[0][0]
        self.assertEqual(argv[:4], [str(self.tart), 'run', self.name, '--no-clipboard'])
        self.assertFalse(any(arg.startswith('--net') for arg in argv))
        self.assertIn('--dir=gold-status:' + str(self.base / 'guest-status'), argv)
        self.assertNotIn('pass_fds', self.spawn.call_args[1])
        self.assertEqual(self.spawn.call_args[1]['env']['TART_HOME'], str(self.tart_home))
        plan.record_launch.assert_called_once_with(child.pid)
        self.assertEqual(stopped, [child])
        status = json.loads((self.base / 'status.json').read_text())
        self.assertEqual((status['state'], status['network_mode'], status['tart_pid']),
                         ('guest-exited', 'first-setup-normal-network', child.pid))
        self.assertFalse(status['native_execution_approved'])
        self.assertFalse(status['network_independently_verified'])
        self.assertEqual(stat.S_IMODE((self.base / 'gvproxy-darwin').stat().st_mode), 0o600)
        self.assertEqual(self.quarantines[str(self.base / 'gvproxy-darwin')], Q)
        self.assertTrue(runtime.first_setup_pending(self.base))  # Only the person marks it finished.

    def test_v3_first_setup_launch_mounts_the_installers_folder_and_never_the_backend(self):
        self.prepare()
        result, plan, child, stopped = self.first_setup_launch()
        self.assertEqual(result, 0)
        self.assertEqual(self.spawn.call_count, 1)
        argv = self.spawn.call_args[0][0]
        self.assertIn('--dir=gold-installers:' + str(self.base / 'installers') + ':ro', argv)
        self.assertFalse(any('gold-status' in arg for arg in argv))
        status = json.loads((self.base / 'status.json').read_text())
        self.assertEqual((status['state'], status['installers_share'], status['shared_directory_count']),
                         ('guest-exited', 'gold-installers', 1))
        self.assertNotIn('guest_bootstrap_evidence', status)
        self.assertEqual(stopped, [child])

    def test_first_setup_launch_refused_once_finished_or_mixed_with_backend_or_recovery(self):
        self.prepare()
        for flags in (('--acknowledge-reviewed-unsigned-backend',), ('--recovery',),
                      ('--acknowledge-reviewed-unsigned-backend', '--enable-reviewed-backend-owner-execute')):
            with self.subTest(flags=flags), self.assertRaisesRegex(RuntimeError, 'First-setup normal network'):
                self.first_setup_launch(*flags)
        self.assertFalse((self.base / 'status.json').exists())
        runtime.finish_first_setup(self.base)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'first-setup-finished'):
            self.first_setup_launch()
        status = json.loads((self.base / 'status.json').read_text())
        self.assertEqual((status['state'], status['reason'], status['vm_started']),
                         ('failed-closed', 'first-setup-finished', False))
        self.spawn.assert_not_called()

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

    def test_installers_folder_is_moved_in_and_bound_not_copied(self):
        folder = self.new_installers()
        before = folder.stat()
        self.prepare(installers=folder)
        moved = self.base / 'installers'
        self.assertFalse(os.path.lexists(str(folder)))
        self.assertEqual(moved.stat().st_ino, before.st_ino)
        self.assertEqual((moved / 'inert.fixture').read_text(), 'inert fixture; never a real app')
        meta = self.meta()
        self.assertEqual(meta['installers_identity'], [before.st_dev, before.st_ino])
        self.assertNotIn('preinstall_receipt_sha256', meta)
        self.assertNotIn('guest_status_share', meta)
        self.assertFalse(meta['native_execution_approved'])
        self.assertEqual(runtime.installers_directory(self.base, meta), moved)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'guest-status-unavailable'):
            runtime.status_directory(self.base, meta)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'guest-status-unavailable'):
            runtime.read_guest_status(self.base, TOKEN)

    def test_changed_or_private_installers_folder_fails_closed(self):
        self.prepare()
        meta = self.meta()
        folder = self.base / 'installers'
        folder.chmod(0o700)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'installers-directory-required'):
            runtime.validate_bindings(self.base, meta)
        folder.chmod(0o755)
        self.assertEqual(folder.resolve(strict=True), self.expected_root / 'environment' / 'installers')
        shutil.rmtree(str(folder))
        folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'installers-directory-changed'):
            runtime.validate_environment(self.base)

    PROFILE = 'Clash 节点配置.yaml'

    def profile_installers(self, config=None):
        """As oneclick.build_installers writes it: the validated configuration as readable JSON, 0644."""
        folder = self.new_installers()
        profile = folder / self.PROFILE
        profile.write_text(json.dumps(self.vpn.private_config if config is None else config,
                                      ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        profile.chmod(0o644)
        return folder

    def read_saved_profile(self, profile_name=PROFILE):
        return runtime.saved_private_config(self.base, profile_name, expected_vm_name=self.name,
                                            expected_vm_config=self.config)

    def test_saved_private_config_is_exactly_what_the_environment_was_prepared_with(self):
        self.prepare(installers=self.profile_installers())
        before = {path.name: (path.stat().st_ino, path.stat().st_mtime_ns) for path in self.base.iterdir()}
        config, endpoints = self.read_saved_profile()
        self.assertEqual(config, self.vpn.private_config)
        self.assertEqual(tuple(endpoints), self.vpn.endpoints)
        self.assertEqual(runtime._private_config(config, endpoints), self.meta()['private_config_sha256'])
        self.assertEqual({path.name: (path.stat().st_ino, path.stat().st_mtime_ns) for path in self.base.iterdir()}, before)
        # First setup finished, sources due for a refresh: the nodes can still be read back.
        self.assertTrue(runtime.finish_first_setup(self.base))
        with mock.patch.object(runtime, 'validate_environment', side_effect=AssertionError('the launch check is stricter')):
            self.assertEqual(self.read_saved_profile()[0], self.vpn.private_config)
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_saved_private_config_refuses_misassociated_environment_before_profile_read(self):
        self.prepare(installers=self.profile_installers())
        profile = self.base / runtime.INSTALLERS_NAME / self.PROFILE
        # The environment itself validates. Neither a different selected name nor
        # the same name under a different controller Tart home grants access.
        for name, config in (('other-vm', self.config),
                             (self.name, self.root / 'other-home' / 'vms' / self.name / 'config.json')):
            with self.subTest(name=name), mock.patch.object(runtime, '_read', wraps=runtime._read) as read:
                with self.assertRaisesRegex(runtime.RuntimePreparationError, '^saved-source-vm-mismatch$'):
                    runtime.saved_private_config(self.base, self.PROFILE, expected_vm_name=name,
                                                 expected_vm_config=config)
                self.assertNotIn(profile, [call.args[0] for call in read.call_args_list])

    def test_saved_private_config_rechecks_the_policy_bytes_used_for_endpoints(self):
        self.prepare(installers=self.profile_installers())
        validate = runtime.validate_environment_for_refresh

        def change_after_validation(base):
            meta = validate(base)
            policy = base / 'policy.json'
            policy.write_bytes(policy.read_bytes() + b'\n')  # Same endpoints, no longer the pinned bytes.
            return meta

        with mock.patch.object(runtime, 'validate_environment_for_refresh', side_effect=change_after_validation), \
                self.assertRaisesRegex(runtime.RuntimePreparationError, '^policy-binding-changed$'):
            self.read_saved_profile()

    def test_saved_private_config_fails_closed_on_any_difference(self):
        self.prepare(installers=self.profile_installers())
        profile = self.base / 'installers' / self.PROFILE
        original = profile.read_bytes()
        other = parse_submission({'input_mode': 'fields', 'nodes': [{
            'type': 'trojan', 'server': '8.8.8.8', 'port': 443, 'password': 'another-fixture-secret', 'sni': 'vpn.example.com'}]})
        moved = parse_submission({'input_mode': 'fields', 'nodes': [{
            'type': 'trojan', 'server': '9.9.9.9', 'port': 443, 'password': SECRET, 'sni': 'vpn.example.com'}]})

        def refused(code, name=None):
            with self.assertRaises(runtime.RuntimePreparationError) as caught:
                self.read_saved_profile(self.PROFILE if name is None else name)
            self.assertEqual(str(caught.exception), code)
            self.assertNotIn(SECRET, repr(caught.exception))
        for config, code in ((other.private_config, 'saved-private-config-changed'),
                             (moved.private_config, 'endpoint-config-mismatch'),
                             ({'proxies': self.vpn.private_config['proxies']}, 'private-config-changed'),
                             ([], 'validated-private-config-required')):
            with self.subTest(code=code):
                profile.write_text(json.dumps(config), encoding='utf-8')
                refused(code)
        profile.write_text('proxies: []\n', encoding='utf-8')
        refused('saved-private-config-unavailable')
        profile.write_bytes(original)
        self.read_saved_profile()
        for mode in (0o664, 0o646):
            profile.chmod(mode)
            refused('unsafe-source-file')
        profile.chmod(0o644)
        for name in ('', '.', '..', 'a/' + self.PROFILE, '../policy.json', 7):
            with self.subTest(name=name):
                refused('invalid-profile-name', name)
        refused('missing-parent', 'missing.yaml')
        elsewhere = self.root / 'elsewhere.yaml'
        elsewhere.write_bytes(original)
        profile.unlink()
        profile.symlink_to(elsewhere)
        refused('symlink-path-refused')
        profile.unlink()
        os.link(str(elsewhere), str(profile))
        refused('unsafe-source-file')
        profile.unlink()
        profile.write_bytes(original)
        profile.chmod(0o644)
        self.read_saved_profile()
        policy = self.base / 'policy.json'
        kept = policy.read_bytes()
        policy.write_bytes(kept.replace(b'8.8.8.8', b'9.9.9.9'))
        refused('environment-source-integrity-mismatch')
        policy.write_bytes(kept)
        self.read_saved_profile()
        self.run.assert_not_called()

    def test_an_older_environment_has_no_saved_private_config(self):
        self.prepare_v2()
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'installers-unavailable'):
            self.read_saved_profile()
        with self.assertRaises(runtime.RuntimePreparationError):
            runtime.saved_private_config(self.root / 'missing-environment', self.PROFILE,
                                         expected_vm_name=self.name, expected_vm_config=self.config)

    def test_unshareable_private_or_symlinked_installers_refused(self):
        folder = self.new_installers()
        for mode in (0o700, 0o775, 0o777):
            folder.chmod(mode)
            with self.subTest(mode=oct(mode)), \
                    self.assertRaisesRegex(runtime.RuntimePreparationError, 'installers-directory-required'):
                self.prepare(installers=folder)
        folder.chmod(0o755)
        alias = self.root / 'alias-installers'
        alias.symlink_to(folder)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'symlink'):
            self.prepare(installers=alias)
        with self.assertRaises(runtime.RuntimePreparationError):
            self.prepare(installers=self.root / 'absent-installers')
        folder.parent.chmod(0o755)
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'private-directory-required'):
            self.prepare(installers=folder)
        self.assertFalse(self.base.exists())

    def test_tampered_source_copy_manifest_or_private_receipt_refused(self):
        self.prepare_v2()
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
        self.prepare_v2()
        command = self.command(shares=[{'name': 'data'}], arguments=['--dir=data:/fixture/user-data:ro'], no_graphics=True)
        self.assertEqual(command[:4], [str(self.tart), 'run', self.name, '--net-fd=42'])
        self.assertIn('--dir=gold-status:' + str(self.base / 'guest-status'), command)
        self.assertIn('--dir=data:/fixture/user-data:ro', command)
        self.assertIn('--no-graphics', command)
        self.assertIn('--no-clipboard', command)
        self.assertFalse(any('setup:' in arg or 'nat' in arg.lower() or 'suspendable' in arg for arg in command))

    def test_reserved_mailbox_and_setup_names_casefolded(self):
        self.prepare()
        for name in ('gold-status', 'GoLd-StAtUs', 'setup', 'SETUP', 'gold-installers', 'Gold-Installers'):
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
        self.prepare_v2()
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
        self.prepare_v2()
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
        self.prepare_v2()
        self.assertEqual(runtime.read_guest_status(self.base, TOKEN)['evidence'], 'not_observed')
        self.put(self.base / 'guest-status' / (TOKEN + '.json'), {'host_independently_verified': True})
        with self.assertRaisesRegex(runtime.RuntimePreparationError, 'invalid-guest-self-report'):
            runtime.read_guest_status(self.base, TOKEN)
        for token in ('../secret', 'b' * 65, SECRET):
            with self.assertRaises(runtime.RuntimePreparationError):
                runtime.read_guest_status(self.base, token)

    def test_guest_report_symlink_not_followed(self):
        self.prepare_v2()
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
        self.assertEqual(result['status'], 'awaiting_first_setup')
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
                gvproxy_path=self.backend, tart_path=self.tart, installers=self.new_installers())

    def test_errors_do_not_return_private_input_or_exception_text(self):
        with mock.patch.object(runtime, '_quarantine', side_effect=ValueError(SECRET)):
            with self.assertRaises(runtime.RuntimePreparationError) as raised:
                self.prepare()
        self.assertNotIn(SECRET, repr(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)


if __name__ == '__main__':
    unittest.main()
