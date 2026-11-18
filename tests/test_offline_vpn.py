"""Tiny ordinary-file fixtures only. Native sessions, trust and root prompts mocked.

No app execution, mount/device access, VM, network, real authorization or chown.
Fixture directory renames preserve inode identity across simulated remounts only.
"""
from dataclasses import asdict, replace, fields
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import uuid

import guest_app_artifacts as artifacts
from guest_app_pins import reviewed_manifests
import guest_ownership as ownership
import guest_vpn_seed
import managed_registry as registry
import offline_disk
import offline_install
import offline_volume as volume
import offline_vpn as vpn
from vpn_config import parse_submission


def uid(value):
    return str(uuid.UUID(int=value)).upper()


class OfflineVPNTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='offline-vpn-fixture-')
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.cleanup)
        self.job_id = '1' * 32
        self.name = '新环境 fixture'
        self.state = self.mkdir(self.root / 'state')
        self.tart = self.mkdir(self.root / 'tart')
        self.mkdir(self.tart / 'vms')
        self.jobdir = self.mkdir(self.state / 'build-jobs' / self.job_id)
        self.stage = self.mkdir(self.tart / '.gold-manager-staging' / self.job_id / 'new-environment')
        self.file(self.state / 'build.lock', b'')
        self.file(self.stage / 'disk.img', b'fixture-not-a-disk'.ljust(1024, b'\0'))
        self.file(self.stage / 'config.json', b'{"fixture":true}\n')
        self.file(self.stage / 'nvram.bin', b'fixture NVRAM')
        self.storage = self.mkdir(self.root / 'simulated-data')
        self.mkdir(self.storage / 'Applications', mode=0o755)
        self.mkdir(self.storage / 'Users/Shared', mode=0o755)
        self.mkdir(self.storage / 'private/var/db', mode=0o755)
        for name in vpn._PARENTS:
            self.mkdir(self.storage / name, mode=0o755)
        self.materials, self.receipts = self.material_fixture()
        self.request = {'id': self.job_id, 'name': self.name, 'mode': 'preinstall', 'source_vm': None,
                        'disk_gib': 1, 'vpn_configuration_id': '3' * 32,
                        'acknowledge_preinstall': True, 'acknowledge_network_policy': True,
                        'acknowledge_guest_autoconfigure': True}
        self.current = dict(self.request, phase='awaiting_first_desktop_acceptance', system_restored=True,
                            applications_preinstalled=True, stage_path=str(self.stage), credentials_copied=False,
                            host_credentials_copied=False, published=False, guest_started=False, desktop_verified=False,
                            offline_preinstall={'operation_id': '2' * 32, 'active': False,
                                                'phase': 'verified_awaiting_first_desktop'})
        self.complete = {'schema': 1, 'job_id': self.job_id, 'name': self.name, 'operation_id': '2' * 32,
                         'stage_path': str(self.stage), 'applications_preinstalled': True,
                         'guest_started': False, 'desktop_verified': False, 'published': False, 'credentials_copied': False,
                         'vm_config_and_nvram_unchanged': True, 'image_file_identity_and_size_unchanged': True,
                         'readonly_remount_verified': True, 'final_detach_confirmed': True,
                         'data_uuid': uid(50), 'volume_group_uuid': uid(51), 'applications': vpn._rows(self.receipts)}
        self.record(self.jobdir / 'request.json', self.request)
        self.record(self.state / 'build-current.json', self.current)
        self.record(self.jobdir / 'status.json', self.current)
        self.record(self.stage / '.offline-preinstall.complete.json', self.complete)
        self.record(self.stage / '.clean-vm-installer.complete.json', {
            'schemaVersion': 1, 'status': 'complete', 'installer': 'CleanVMInstaller',
            'networkDeviceCount': 0, 'directorySharingDeviceCount': 0, 'socketDeviceCount': 0})
        header = b'\xcf\xfa\xed\xfe' + struct.pack('<I', 0x0100000c) + b'fixture-only-not-executed'
        self.bootstrap = self.file(self.root / 'GuestVPNBootstrap', header, mode=0o700)
        self.root_helper = self.file(self.root / 'GuestOwnershipHelper', header, mode=0o700)
        self.configuration = parse_submission({'input_mode': 'fields', 'nodes': [{
            'type': 'trojan', 'server': '8.8.8.8', 'port': 443, 'password': 'PRIVATE-node-password',
            'sni': 'example.com', 'network': 'tcp', 'tls': True}]}).private_config
        self.sessions, self.auth_calls, self.events = [], [], []
        self.active_session = None
        self.entry_snapshots = None
        self.hooks = {}
        self.receipt_mutation = lambda operation, receipt: None
        self.patch(patch.object(vpn, 'GIB', 1024))
        self.patch(patch.object(vpn, 'DiskSession', side_effect=self.readonly_session))
        self.patch(patch.object(vpn, 'WritableDiskSession', side_effect=self.writable_session))
        self.source_verifier = self.patch(patch.object(vpn, 'verify_materials', side_effect=self.verify_sources))
        self.guest_verifier = self.patch(patch.object(vpn, 'verify_installed_readonly', side_effect=self.verify_guest))
        self.patch(patch.object(vpn.os.path, 'ismount', side_effect=lambda p: self.active_session is not None
                                and Path(p) == self.active_session.mountpoint))
        self.patch(patch.object(ownership, 'deploy_helper', side_effect=self.deploy, create=True))
        self.patch(patch.object(ownership, 'prepare_ticket', side_effect=self.ticket))
        self.authorization = self.patch(patch.object(ownership, 'request_authorization', side_effect=self.authorize))
        # Any attempted external/native action is a test failure, including if a
        # production catch-all would otherwise hide the raised assertion.
        for owner, name in ((subprocess, 'run'), (subprocess, 'Popen'), (os, 'system'), (os, 'chown'),
                            (os, 'fchown'), (socket, 'create_connection'), (socket.socket, 'connect'),
                            (urllib.request, 'urlopen')):
            guard = self.patch(patch.object(owner, name, side_effect=AssertionError('External I/O forbidden')))
            self.addCleanup(guard.assert_not_called)

    def patch(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(), self.root)
        self.assertTrue(self.root.name.startswith('offline-vpn-fixture-'))
        self.tmp.cleanup()

    def mkdir(self, path, mode=0o700):
        pending = []
        p = path
        while not p.exists():
            pending.append(p)
            p = p.parent
        for p in reversed(pending):
            p.mkdir(mode=mode)
            p.chmod(mode)  # Fixture modes must not depend on the runner's umask.
        return path

    def file(self, path, data, mode=0o600):
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(mode)
        return path

    def record(self, path, data):
        registry.write_private(path, data)

    def checked_move(self, source, target):
        # Only our ordinary dummy tree, never an image/device/VM. Verify both
        # canonical absolute endpoints BEFORE every test-fixture rename.
        self.assertEqual(source.resolve(strict=True), source)
        self.assertEqual(target.parent.resolve(strict=True) / target.name, target)
        self.assertTrue(source.is_relative_to(self.root))
        self.assertTrue(target.is_relative_to(self.root))
        self.assertFalse(target.exists())
        os.rename(str(source), str(target))

    def material_fixture(self):
        materials, receipts = [], []
        for manifest in reviewed_manifests():
            source = self.mkdir(self.root / 'source' / manifest.product)
            cache = self.mkdir(self.root / 'cache' / manifest.product)
            raw = self.file(cache / 'fixture-original.dmg', b'fixture original')
            apps, app_records = [], []
            for expected in manifest.expected_apps:
                app = self.mkdir(source / expected.name, mode=0o755)
                self.mkdir(app / 'Contents/Resources', mode=0o755)
                self.file(app / 'Contents/Resources/fixture', expected.name.encode(), mode=0o644)
                shutil.copytree(app, self.storage / 'Applications' / app.name)
                digest, total, count = artifacts._tree_snapshot(app, manifest)
                apps.append(app)
                app_records.append({'name': app.name, 'bundle_identifier': expected.bundle_identifiers[0],
                                    'short_version': expected.short_versions[0], 'bundle_version': expected.bundle_versions[0],
                                    'team_id': manifest.vendor_team_ids[0], 'bundle_tree_sha256': digest,
                                    'bundle_bytes': total, 'bundle_entries': count})
            receipt = artifacts.DownloadReceipt(manifest.artifact_key, str(raw), manifest.known_sha256,
                                                manifest.declared_size_bytes or 100, True, 'github.com')
            materials.append(offline_install.Material(manifest, receipt, source, tuple(apps)))
            receipts.append(artifacts.VerificationReceipt(manifest.manifest_sha256, asdict(manifest),
                            manifest.known_sha256, receipt.size_bytes, tuple(app_records)))
        return tuple(materials), tuple(receipts)

    def attribution(self, target, writable):
        parts, containers = [], []
        next_uuid = 100
        group = uid(51)
        for index, content in enumerate((volume.CONTAINER_HINT, 'Apple_APFS_ISC', 'Apple_APFS_Recovery')):
            # CONTAINER_HINT is not the pure parser's content key.
            content = 'Apple_APFS' if index == 0 else content
            part = volume.PartitionAttribution('disk9s' + str(index + 1), uid(next_uuid), content, 200)
            next_uuid += 1
            container_device, container_uuid = 'disk' + str(index + 10), uid(next_uuid)
            next_uuid += 1
            values = []
            for offset, role in enumerate(sorted(volume.ROLE_LAYOUT[content]), 1):
                volume_uuid = uid(50) if role == 'Data' else uid(next_uuid)
                next_uuid += 1
                values.append(volume.VolumeAttribution(container_device + 's' + str(offset), volume_uuid, role,
                    container_device, container_uuid, part.device, part.uuid, group if role in ('System', 'Data') else None))
            parts.append(part)
            containers.append(volume.ContainerAttribution(container_device, container_uuid, part, tuple(values)))
        main = containers[0]
        data = next(v for v in main.volumes if v.role == 'Data')
        system = next(v for v in main.volumes if v.role == 'System')
        cls = volume.WritableAttribution if writable else volume.OfflineAttribution
        return cls(volume.SCHEMA, volume.WRITABLE_MODE if writable else volume.MODE, str(target.image), os.getuid(),
                   'disk9', None, 1024, tuple(parts), tuple(containers), main.device, main.uuid,
                   data.device, data.uuid, system.device, system.uuid, group)

    def new_session(self, target, directory, writable, ownership_mode, lock_held):
        test = self
        self.assertTrue(lock_held)
        self.assertIn(ownership_mode, ('on', 'off'))
        class Session:
            def __init__(self):
                self.target, self.directory = target, directory
                self.writable, self.ownership_mode = writable, ownership_mode
                self.attribution = test.attribution(target, writable)
                self.attachment_generation = ('/dev/disk9', frozenset(('/dev/disk9', '/dev/disk9s1')),
                                              1000 + len(test.sessions), os.getuid(), writable, target.baseline[:3])
                self.summary = {'cleanup_confirmed': False}
                self.mountpoint = None
                directory.mkdir(mode=0o700)
            def __enter__(self):
                self.target.verify_unchanged()
                test.assertIsNone(test.active_session)
                test.active_session = self
                test.events.append(('attach', self.directory.name, self.ownership_mode))
                test.hooks.get(self.directory.name + ':enter', lambda session: None)(self)
                return self
            def mount(self):
                test.assertIsNone(self.mountpoint)
                self.mountpoint = self.directory / 'data-mount'
                test.checked_move(test.storage, self.mountpoint)
                return self.mountpoint
            def mount_readonly_for_probe(self):
                test.assertFalse(self.writable)
                return self.mount()
            def mount_writable(self):
                test.assertTrue(self.writable)
                return self.mount()
            def check_mounted_readonly(self):
                test.assertFalse(self.writable)
                test.assertIs(test.active_session, self)
                test.assertIsNotNone(self.mountpoint)
                return {}
            def check_mounted_writable(self):
                test.assertTrue(self.writable)
                test.assertIs(test.active_session, self)
                test.assertIsNotNone(self.mountpoint)
                return {}
            def __exit__(self, kind, value, trace):
                test.hooks.get(self.directory.name + ':cleanup', lambda session: None)(self)
                if self.mountpoint is not None:
                    test.checked_move(self.mountpoint, test.storage)
                    self.mountpoint = None
                self.summary['cleanup_confirmed'] = True
                test.events.append(('detach', self.directory.name, self.ownership_mode))
                test.active_session = None
                return False
        session = Session()
        self.sessions.append(session)
        return session

    def readonly_session(self, target, directory, *, lock_held, ownership_mode):
        return self.new_session(target, directory, False, ownership_mode, lock_held)

    def writable_session(self, target, directory, baseline, *, acknowledge_write, lock_held, ownership_mode):
        self.assertIs(acknowledge_write, True)
        self.assertIs(type(baseline), volume.OfflineAttribution)
        return self.new_session(target, directory, True, ownership_mode, lock_held)

    def verify_sources(self, materials):
        self.assertEqual(materials, self.materials)
        self.events.append(('source-verification',))
        return self.receipts

    def verify_guest(self, session, materials, source, *, expected_data_uuid, expected_group_uuid):
        session.check_mounted_readonly()
        self.assertEqual(session.ownership_mode, 'off')
        vpn._need(session.attribution.data_uuid == expected_data_uuid and
                  session.attribution.volume_group_uuid == expected_group_uuid, 'fixture-volume-mismatch')
        self.assertEqual(materials, self.materials)
        for material, receipt in zip(materials, source):
            for app in receipt.apps:
                path = session.mountpoint / 'Applications' / app['name']
                actual = artifacts._tree_snapshot(path, material.manifest)
                vpn._need(actual == (app['bundle_tree_sha256'], app['bundle_bytes'], app['bundle_entries']), 'fixture-app-changed')
        self.events.append(('guest-verification', session.directory.name))
        return source

    def deploy(self, state_dir, binary):
        self.assertEqual(state_dir, self.state)
        self.assertEqual(binary, self.root_helper)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        destination = self.mkdir(self.state / 'ownership-helper' / digest)
        self.file(destination / 'GuestOwnershipHelper', binary.read_bytes(), mode=0o700)
        return digest

    def ticket(self, **kwargs):
        self.assertTrue(kwargs['verify_mount'].parent.parent.is_dir())
        self.assertFalse(kwargs['verify_mount'].parent.exists())
        config_fd = kwargs['config_lock_fd']
        self.assertEqual(os.fstat(config_fd).st_ino, (self.stage / 'config.json').stat().st_ino)
        self.assertEqual(os.pread(config_fd, 4096, 0), b'{"fixture":true}\n')
        current = registry.read_private(self.state / 'build-current.json')
        self.assertEqual(current['phase'], 'awaiting_system_authorization')
        self.assertTrue(current['vpn_configuration']['active'])
        self.assertFalse(current['host_credentials_copied'])
        paths = ownership.operation_paths(self.tart, self.job_id, kwargs['operation_id'], state_dir=self.state)
        self.assertTrue(paths['directory'].is_dir())
        self.record(paths['ticket'], {'fixture': True, 'operation_id': kwargs['operation_id']})
        digest = hashlib.sha256(paths['ticket'].read_bytes()).hexdigest()
        self.entry_snapshots = kwargs['entries']
        return ownership.OwnershipTicket(paths['ticket'], digest, kwargs['operation_id'],
            self.state / 'ownership-helper' / kwargs['helper_sha256'] / 'GuestOwnershipHelper', os.getuid())

    def authorize(self, ticket, operation, *, acknowledge_authorization):
        self.assertIs(acknowledge_authorization, True)
        session = self.active_session
        self.assertEqual(session.ownership_mode, 'off' if operation == 'apply' else 'on')
        self.assertEqual(session.writable, operation == 'apply')
        self.auth_calls.append(operation)
        self.events.append(('authorization', operation))
        self.hooks.get('authorization:' + operation, lambda session: None)(session)
        receipt = {'schema': 1, 'operation_id': ticket.operation_id, 'ticket_sha256': ticket.digest,
                   'operation': operation, 'attachment_generation': session.attachment_generation[2],
                   'entry_count': len(self.entry_snapshots), 'fixture_only': False,
                   'metadata_applied': operation == 'apply', 'persistent_ownership_verified': operation == 'verify',
                   'readonly_owners_on': operation == 'verify', 'guest_started': False, 'published': False,
                   'authorization': 'macos_system_administrator', 'helper_contract': ownership.PRODUCTION_CONTRACT}
        self.receipt_mutation(operation, receipt)
        self.record(ticket.path.parent / (operation + '.receipt.json'), receipt)
        return ownership.AuthorizationResult('helper_completed_receipt_required', operation, True, operation == 'verify')

    def run_configure(self, **changes):
        kwargs = dict(state_dir=self.state, tart_home=self.tart, job_id=self.job_id, name=self.name,
                      private_config=self.configuration, bootstrap_helper_path=self.bootstrap,
                      ownership_helper_path=self.root_helper, materials=self.materials,
                      acknowledge_write=True, acknowledge_system_authorization=True)
        kwargs.update(changes)
        return vpn.configure_preinstalled_stage(**kwargs)

    def assert_retained(self):
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        current = registry.read_private(self.state / 'build-current.json')
        self.assertEqual(current['phase'], 'failed')
        self.assertTrue(current['recovery_required'])
        self.assertFalse(current['guest_started'])
        self.assertFalse(current['published'])
        self.assertTrue(current['applications_preinstalled'])
        self.assertFalse(current['vpn_configuration']['active'])
        self.assertFalse((self.stage / vpn._COMPLETE).exists())
        return current

    def test_complete_fixed_order_and_private_receipt_no_public_secret(self):
        config_before = offline_disk.signature(self.stage / 'config.json')
        nvram_before = offline_disk.signature(self.stage / 'nvram.bin')
        result = self.run_configure()
        self.assertEqual([s.directory.name for s in self.sessions],
                         ['baseline-readonly', 'write-session', 'bytes-readonly', 'owner-readonly'])
        self.assertEqual([s.ownership_mode for s in self.sessions], ['off', 'off', 'off', 'on'])
        self.assertTrue(all(s.summary['cleanup_confirmed'] for s in self.sessions))
        self.assertEqual(self.auth_calls, ['apply', 'verify'])
        self.assertEqual(self.source_verifier.call_count, 1)
        self.assertEqual(self.guest_verifier.call_count, 2)
        self.assertTrue(result['persistent_ownership_verified'])
        self.assertTrue(result['readonly_payload_verified'])
        self.assertTrue(result['final_detach_confirmed'])
        self.assertFalse(result['vpn_connected'])
        self.assertFalse(result['guest_started'])
        self.assertNotIn('receipt_token', result)
        self.assertNotIn('PRIVATE-node-password', json.dumps(result))
        private = registry.read_private(self.stage / vpn._COMPLETE)
        self.assertEqual(len(private['receipt_token']), 64)
        self.assertEqual(private['job_id'], self.job_id)
        self.assertEqual(private['name'], self.name)
        self.assertEqual(private['image_file_stamp'], list(offline_disk.signature(self.stage / 'disk.img')))
        self.assertNotIn('image_file_stamp', result)
        self.assertTrue(private['ownership_verify']['readonly_owners_on'])
        self.assertEqual(stat.S_IMODE((self.stage / vpn._COMPLETE).stat().st_mode), 0o600)
        state = registry.read_private(self.state / 'build-current.json')
        self.assertTrue(state['vpn_configuration_staged'])
        self.assertTrue(state['system_restored'])
        self.assertNotIn(private['receipt_token'], json.dumps(state))
        self.assertEqual(state['phase'], 'awaiting_first_desktop_acceptance')
        self.assertEqual(offline_disk.signature(self.stage / 'config.json'), config_before)
        self.assertEqual(offline_disk.signature(self.stage / 'nvram.bin'), nvram_before)
        self.assertFalse((self.tart / 'vms' / self.name).exists())

    def test_loader_never_calls_restore_only_loader_or_changes_status(self):
        before = (self.state / 'build-current.json').read_bytes()
        with patch.object(offline_disk.StageTarget, 'load', side_effect=AssertionError('No fake restore-only state')):
            target = vpn.load_completed_stage(self.state, self.tart, self.job_id, self.name)
        self.assertIs(type(target), offline_disk.StageTarget)
        self.assertEqual((self.state / 'build-current.json').read_bytes(), before)
        self.assertFalse(self.sessions)

    def test_safe_existing_0755_tart_roots_supported_without_chmod(self):
        self.tart.chmod(0o755)
        (self.tart / 'vms').chmod(0o755)
        self.run_configure()
        self.assertEqual(stat.S_IMODE(self.tart.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.tart / 'vms').stat().st_mode), 0o755)

    def test_nonprivate_stage_and_writable_tart_roots_rejected(self):
        for path, mode in ((self.stage, 0o755), (self.tart, 0o777), (self.tart / 'vms', 0o775)):
            old = stat.S_IMODE(path.stat().st_mode)
            path.chmod(mode)
            try:
                with self.assertRaises(vpn.OfflineVPNError):
                    self.run_configure()
            finally:
                path.chmod(old)
        self.assertFalse(self.sessions)

    def test_both_explicit_consents_required_before_any_session(self):
        for key in ('acknowledge_write', 'acknowledge_system_authorization'):
            with self.assertRaises(vpn.OfflineVPNError):
                self.run_configure(**{key: False})
        self.assertFalse(self.sessions)
        self.assertFalse(self.auth_calls)

    def test_incomplete_or_changed_reviewed_materials_rejected(self):
        with self.assertRaises(offline_install.InstallError):
            self.run_configure(materials=self.materials[:2])
        changed = replace(self.materials[0], manifest=replace(self.materials[0].manifest, vendor_team_ids=('AAAAAAAAAA',)))
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure(materials=(changed,) + self.materials[1:])
        self.assertFalse(self.sessions)

    def test_wrong_mode_started_published_and_false_app_completion_rejected(self):
        cases = ({'mode': 'offline_validate'}, {'source_vm': 'existing'}, {'guest_started': True},
                 {'desktop_verified': True}, {'published': True}, {'applications_preinstalled': False},
                 {'system_restored': False}, {'host_credentials_copied': True}, {'recovery_required': True})
        for changes in cases:
            self.record(self.state / 'build-current.json', dict(self.current, **changes))
            with self.assertRaises(vpn.OfflineVPNError):
                self.run_configure()
        self.assertFalse(self.sessions)

    def test_missing_app_or_modified_record_and_wrong_isolation_fail_closed(self):
        bad = dict(self.complete, applications=self.complete['applications'][:3])
        self.record(self.stage / '.offline-preinstall.complete.json', bad)
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        self.record(self.stage / '.offline-preinstall.complete.json', self.complete)
        restore = registry.read_private(self.stage / '.clean-vm-installer.complete.json')
        restore['networkDeviceCount'] = 1
        self.record(self.stage / '.clean-vm-installer.complete.json', restore)
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        self.assertFalse(self.sessions)

    def test_existing_published_path_or_saved_state_refused(self):
        self.mkdir(self.tart / 'vms' / self.name)
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        self.file(self.stage / 'state.vzvmsave', b'not a saved VM')
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        self.assertFalse(self.sessions)

    def test_host_control_hardlinks_symlinks_and_helper_scripts_rejected(self):
        alias = self.root / 'state-alias'
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure(state_dir=alias)
        os.link(str(self.stage / 'nvram.bin'), str(self.root / 'nvram-hardlink'))
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        script = self.file(self.root / 'not-compiled', b'#!/bin/sh\nexit 0\n', mode=0o700)
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure(bootstrap_helper_path=script)
        self.assertFalse(self.sessions)

    def test_existing_seed_paths_are_never_replaced_or_adopted(self):
        existing = self.mkdir(self.storage / guest_vpn_seed.BASE, mode=0o755)
        before = existing.stat().st_ino
        self.assert_retained()
        self.assertEqual((self.storage / guest_vpn_seed.BASE).stat().st_ino, before)
        self.assertEqual(len(self.sessions), 1)
        self.assertFalse(self.auth_calls)

    def test_missing_system_parent_refused_without_creating_or_chmod(self):
        source = self.storage / 'Library/LaunchAgents'
        self.checked_move(source, self.storage / 'Library/fixture-preserved-LaunchAgents')
        self.assert_retained()
        self.assertFalse(source.exists())
        self.assertEqual(len(self.sessions), 1)
        self.assertFalse(self.auth_calls)

    def test_group_writable_existing_parent_refused_unchanged(self):
        parent = self.storage / 'Library/Application Support'
        parent.chmod(0o777)
        self.assert_retained()
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o777)
        self.assertEqual(len(self.sessions), 1)

    def test_failed_baseline_app_verification_never_opens_writable(self):
        (self.storage / 'Applications/CCBaga-A.app/Contents/Resources/fixture').write_bytes(b'corrupted')
        self.assert_retained()
        self.assertEqual(len(self.sessions), 1)
        self.assertFalse(self.auth_calls)

    def test_wrong_data_group_identity_rejected_before_write(self):
        self.hooks['baseline-readonly:enter'] = lambda s: setattr(s, 'attribution', replace(s.attribution, volume_group_uuid=uid(900)))
        self.assert_retained()
        self.assertEqual(len(self.sessions), 1)
        self.assertFalse(self.auth_calls)

    def test_user_denial_retains_seed_no_false_completion_or_second_authorization(self):
        self.authorization.side_effect = lambda *a, **k: ownership.AuthorizationResult('denied', 'apply', False)
        self.assert_retained()
        self.assertEqual(len(self.sessions), 2)
        self.assertTrue((self.storage / guest_vpn_seed.SEED_PATH).exists())
        self.assertFalse((self.stage / vpn._COMPLETE).exists())

    def test_helper_success_without_private_receipt_is_not_acceptance(self):
        self.authorization.side_effect = lambda *a, **k: ownership.AuthorizationResult('completed', 'apply', True)
        self.assert_retained()
        self.assertEqual(len(self.sessions), 2)

    def test_fixture_receipt_is_never_treated_as_real_administrator_proof(self):
        self.receipt_mutation = lambda operation, receipt: receipt.update(fixture_only=True)
        self.assert_retained()
        self.assertEqual(self.auth_calls, ['apply'])

    def test_incorrect_persistent_owners_receipt_never_completes(self):
        def bad_verify(operation, receipt):
            if operation == 'verify':
                receipt['persistent_ownership_verified'] = False
        self.receipt_mutation = bad_verify
        self.assert_retained()
        self.assertEqual(self.auth_calls, ['apply', 'verify'])
        self.assertEqual(len(self.sessions), 4)

    def test_apply_metadata_does_not_substitute_for_independent_ro_seed_bytes(self):
        self.hooks['write-session:cleanup'] = lambda s: (s.mountpoint / guest_vpn_seed.SEED_PATH).write_bytes(b'changed private bytes')
        self.assert_retained()
        self.assertEqual(len(self.sessions), 3)
        self.assertEqual(self.auth_calls, ['apply'])

    def test_replaced_seed_inode_rejected_even_if_bytes_and_modes_match(self):
        def replace_seed(session):
            source = session.mountpoint / guest_vpn_seed.SEED_PATH
            content = source.read_bytes()
            self.checked_move(source, self.root / 'preserved-old-seed-fixture')
            self.file(source, content, mode=0o600)
        self.hooks['write-session:cleanup'] = replace_seed
        self.assert_retained()
        self.assertEqual(len(self.sessions), 3)
        self.assertEqual(self.auth_calls, ['apply'])

    def test_saved_state_alone_and_no_published_vm_refused(self):
        self.file(self.stage / 'state.vzvmsave', b'fixture-saved-state')
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        self.assertFalse((self.tart / 'vms' / self.name).exists())
        self.assertFalse(self.sessions)

    def test_guest_parent_symlink_never_traversed(self):
        original = self.storage / 'Library/LaunchAgents'
        self.checked_move(original, self.storage / 'Library/preserved-launchagents')
        original.symlink_to(self.root, target_is_directory=True)
        self.assert_retained()
        self.assertEqual(len(self.sessions), 1)
        self.assertFalse((self.root / 'org.goldvmmanager.first-login.plist').exists())

    def test_modified_apps_after_seed_write_rejected(self):
        self.hooks['write-session:cleanup'] = lambda s: (s.mountpoint / 'Applications/Claude.app/Contents/Resources/fixture').write_bytes(b'changed app')
        self.assert_retained()
        self.assertEqual(len(self.sessions), 3)

    def test_vm_config_or_nvram_change_is_not_rebased_away(self):
        self.hooks['authorization:apply'] = lambda s: (self.stage / 'nvram.bin').write_bytes(b'changed NVRAM')
        self.assert_retained()
        self.assertEqual(len(self.sessions), 2)

    def test_fresh_attachment_generation_is_required(self):
        self.hooks['bytes-readonly:enter'] = lambda s: setattr(s, 'attachment_generation', self.sessions[1].attachment_generation)
        self.assert_retained()
        self.assertEqual(len(self.sessions), 3)
        self.assertEqual(self.auth_calls, ['apply'])

    def test_no_python_private_seed_read_on_owners_on_mount(self):
        original = vpn._seed_snapshot
        def checked(session, *args, **kwargs):
            self.assertEqual(session.ownership_mode, 'off')
            return original(session, *args, **kwargs)
        with patch.object(vpn, '_seed_snapshot', side_effect=checked):
            self.run_configure()
        self.assertEqual(self.auth_calls, ['apply', 'verify'])

    def test_borrowed_lifecycle_fd_survives_full_operation(self):
        fd = os.open(str(self.state / 'build.lock'), os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_configure(lifecycle_lock_fd=fd)
            self.assertEqual(os.fstat(fd).st_ino, (self.state / 'build.lock').stat().st_ino)
        finally:
            os.close(fd)

    def test_second_call_cannot_rewrite_completed_stage_or_reuse_outputs(self):
        self.run_configure()
        receipt = self.stage / vpn._COMPLETE
        before = receipt.stat().st_ino, receipt.read_bytes()
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure()
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
        self.assertEqual(len(self.sessions), 4)

    def test_arbitrary_evidence_directory_not_accepted(self):
        other = self.mkdir(self.root / 'unrelated-evidence')
        with self.assertRaises(vpn.OfflineVPNError):
            self.run_configure(evidence_dir=other)
        self.assertEqual(list(other.iterdir()), [])
        self.assertFalse(self.sessions)


if __name__ == '__main__':
    unittest.main()
