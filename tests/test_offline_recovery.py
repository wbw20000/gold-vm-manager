"""Reviewed-prefix recovery contracts; only checked private temporary fixtures.

Real StageTarget, locks, state/evidence persistence and tiny bundle-tree hashes;
fake disk sessions, copy boundary and signature verifiers. No real apps, network,
subprocess, mounts, VM operations or quarantine changes are performed here.
"""
import dataclasses
import fcntl
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import guest_app_artifacts as artifacts
import managed_registry as registry
import offline_disk as disk
import offline_install as install
import offline_recovery as recovery
from offline_preinstall import PreinstallError
import test_offline_preinstall as fixtures


class RecoverySession(fixtures.FakeSession):
    def mount_readonly_for_probe(self):
        self.case.assertIn(self.label, ('before', 'after'))
        self.case.assertIs(self.target.readonly_review, True)
        self.mounted = True
        self.case.record(self.label + ':mount')
        return self.case.guest_apps.parent


class RecoveryTests(fixtures.NoExternalIOTests):
    # Reuse fixture utilities, not PreinstallTests itself: discovery must not run
    # its unrelated test methods against a failed-stage recovery fixture.
    checked = fixtures.PreinstallTests.checked
    make_materials = fixtures.PreinstallTests.make_materials
    assert_locks_held = fixtures.PreinstallTests.assert_locks_held
    record = fixtures.PreinstallTests.record
    tracked_lock = fixtures.PreinstallTests.tracked_lock
    load_target = fixtures.PreinstallTests.load_target
    verify_bundle = fixtures.PreinstallTests.verify_bundle
    verify_sources = fixtures.PreinstallTests.verify_sources
    change_image_contents = fixtures.PreinstallTests.change_image_contents
    assert_not_accepted = fixtures.PreinstallTests.assert_not_accepted
    assert_quarantined = fixtures.PreinstallTests.assert_quarantined

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory(prefix='offline-recovery-test-')
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.cleanup)
        self.addCleanup(os.umask, os.umask(0o077))
        self.state = self.root / 'state'
        self.tart = self.root / 'tart'
        self.jid = 'b' * 32
        self.operation_id = 'c' * 32
        self.name = 'gg1'
        self.stage = self.tart / '.gold-manager-staging' / self.jid / 'new-environment'
        self.evidence = self.root / 'recovery-evidence'
        self.previous = self.root / 'failed-evidence'
        self.guest_apps = self.root / 'fake-data' / 'Applications'
        for path in (self.state / 'build-jobs' / self.jid, self.stage, self.guest_apps,
                     self.previous / 'write-session', self.previous / 'copy-transaction'):
            path.mkdir(parents=True, mode=0o700)
        self.current = {
            'id': self.jid, 'name': self.name, 'mode': 'offline_validate', 'source_vm': None,
            'phase': 'failed', 'system_restored': True, 'recovery_required': True,
            'guest_started': False, 'applications_preinstalled': False,
            'desktop_verified': False, 'credentials_copied': False, 'published': False,
            'stage_path': str(self.stage),
            'offline_preinstall': {'operation_id': self.operation_id,
                                   'phase': 'failed_quarantined', 'active': False},
        }
        for path in (self.state / 'build-current.json', self.state / 'build-jobs' / self.jid / 'status.json'):
            registry.write_private(path, self.current)
        registry.write_private(self.state / 'build-jobs' / self.jid / 'request.json', {
            'id': self.jid, 'name': self.name, 'mode': 'offline_validate',
            'source_vm': None, 'disk_gib': 1,
        })
        registry.write_private(self.stage / '.clean-vm-installer.complete.json', {
            'installer': 'CleanVMInstaller', 'status': 'complete', 'schemaVersion': 1,
            'networkDeviceCount': 0, 'directorySharingDeviceCount': 0, 'socketDeviceCount': 0,
        })
        for name in ('config.json', 'nvram.bin', 'disk.img'):
            (self.stage / name).write_bytes(b'private non-executable recovery fixture')
        with (self.stage / 'disk.img').open('r+b') as stream:
            stream.truncate(1024**3)
        self.config_identity = disk.signature(self.stage / 'config.json')[:2]
        self.external_lock = self.root / 'lifecycle.lock'
        for path in (self.external_lock, self.state / 'build.lock'):
            path.write_bytes(b'')
        self.failed = {
            'schema': 1, 'operation_id': self.operation_id, 'job_id': self.jid,
            'name': self.name, 'stage_path': str(self.stage), 'applications_preinstalled': False,
            'guest_started': False, 'desktop_verified': False, 'credentials_copied': False,
            'published': False, 'manual_review_required': True,
        }
        self.prior_cleanup = {'cleanup_confirmed': True, 'operation_failed': True, 'guest_started': False}
        self.transaction = {
            'phase': 'failed_quarantined', 'applications_preinstalled': False,
            'data_uuid': 'fixture-data', 'volume_group_uuid': 'fixture-group',
            # Complete bytes can exist even when a subsequent quarantine check
            # failed before completed_apps was advanced. Trust fresh trees only.
            'completed_apps': [],
        }
        registry.write_private(self.previous / 'preinstall-failed.json', self.failed)
        registry.write_private(self.previous / 'write-session' / 'session-summary.json', self.prior_cleanup)
        registry.write_private(self.previous / 'copy-transaction' / 'transaction.json', self.transaction)
        self.materials, receipts = self.make_materials()
        self.sources = {path.name: (path, material.manifest)
                        for material in self.materials for path in material.app_paths}
        self.receipts = []
        for receipt in receipts:
            apps = []
            for app in receipt.apps:
                path, manifest = self.sources[app['name']]
                digest, size, entries = artifacts._tree_snapshot(path, manifest)
                apps.append(dict(app, bundle_tree_sha256=digest, bundle_bytes=size, bundle_entries=entries))
            self.receipts.append(dataclasses.replace(receipt, apps=tuple(apps)))
        self.receipts = tuple(self.receipts)
        self.copy_receipts = tuple(dataclasses.replace(r) for r in self.receipts)
        self.seed_app(install.APP_NAMES[0])
        self.retained_before = self.retained_identity()
        self.events = []
        self.lock_held = False
        self.fail_copy = False
        self.fail_readback = False
        self.fail_detach = None
        self.fail_commit = None
        self.copied_names = []
        self.after_write = self.change_image_contents
        self.loaded_targets = []
        self.sessions = []
        self.real_load = disk.StageTarget.load
        self.real_locked = disk.StageTarget.locked
        self.real_write_private = registry.write_private
        self.load_mock = self.patch(patch.object(disk.StageTarget, 'load', side_effect=self.load_target))
        self.patch(patch.object(disk.StageTarget, 'locked', self.tracked_lock()))
        self.lockf_mock = self.patch(patch.object(disk.fcntl, 'lockf', wraps=fcntl.lockf))
        self.patch(patch.object(registry, 'write_private', side_effect=self.write_private))
        self.bundle_verifier = self.patch(patch.object(artifacts, 'verify_app_bundles', side_effect=self.verify_bundle))
        self.source_verifier = self.patch(patch.object(recovery, 'verify_materials', side_effect=self.verify_sources))
        self.readonly_factory = self.patch(patch.object(recovery, 'DiskSession', side_effect=self.readonly_session))
        self.writable_factory = self.patch(patch.object(recovery, 'WritableDiskSession', side_effect=self.writable_session))
        self.root_getter = self.patch(patch.object(recovery, 'application_root', side_effect=self.application_root))
        self.copier = self.patch(patch.object(recovery, 'write_applications', side_effect=self.copy_apps))
        self.readback = self.patch(patch.object(recovery, 'verify_installed_readonly', side_effect=self.verify_readback))

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(), self.root)
        self.assertTrue(self.root.name.startswith('offline-recovery-test-'))
        self.tmp.cleanup()

    def seed_app(self, name):
        source, _ = self.sources[name]
        target = self.checked(self.guest_apps / name)
        self.checked(source)
        self.assertFalse(target.exists())
        shutil.copytree(source, target, symlinks=True)
        return target

    def retained_identity(self):
        root = self.checked(self.guest_apps / install.APP_NAMES[0])
        content = self.checked(root / 'Contents' / 'fixture')
        return (root.stat().st_ino, content.stat().st_ino, content.read_bytes(),
                artifacts._tree_snapshot(root, self.materials[0].manifest))

    def move_first_app_aside(self):
        source = self.checked(self.guest_apps / install.APP_NAMES[0])
        destination = self.checked(self.root / 'retained-away-fixture')
        self.assertFalse(destination.exists())
        source.rename(destination)

    def write_private(self, path, data):
        self.checked(path)
        if Path(path) == self.evidence / 'readonly-prefix-review.json':
            self.record('review:prefix')
        if Path(path) in (self.state / 'build-current.json', self.state / 'build-jobs' / self.jid / 'status.json'):
            self.assert_locks_held()
            if data.get('applications_preinstalled') is not True:
                self.assertEqual(data['phase'], 'failed', 'recovery must not forge an untouched phase')
                self.assertIs(data['recovery_required'], True)
        if data.get('applications_preinstalled') is True and Path(path).name == self.fail_commit:
            raise OSError('fixture completion persistence failure')
        return fixtures.PreinstallTests.write_private(self, path, data)

    def readonly_session(self, target, directory, *, lock_held=False):
        self.assertIs(lock_held, True)
        self.assertIs(target.readonly_review, True)
        self.assertEqual(directory.parent, self.evidence)
        label = {'before-recovery-readonly': 'before', 'after-write-readonly': 'after'}[directory.name]
        if label == 'after':
            self.assertIn('write:detach', self.events)
            self.assertIn('stage:rebase', self.events)
            self.assertIs(target, self.loaded_targets[-1])
            self.assertEqual(target.baseline[:3], self.loaded_targets[0].baseline[:3])
        session = RecoverySession(self, target, directory, label,
            SimpleNamespace(data_uuid='fixture-data', volume_group_uuid='fixture-group'))
        self.sessions.append(session)
        return session

    def application_root(self, session, writable=False):
        self.assertIs(writable, False)
        self.assertEqual(session.label, 'before')
        self.assertTrue(session.mounted)
        self.record('root:readonly')
        return self.checked(self.guest_apps)

    def writable_session(self, target, directory, baseline, *, acknowledge_write=False, lock_held=False):
        self.assertIs(acknowledge_write, True)
        self.assertIs(lock_held, True)
        self.assertIn('before:detach', self.events)
        self.assertIn('review:prefix', self.events)
        original = self.loaded_targets[0]
        self.assertIs(original.readonly_review, True)
        self.assertIs(target.readonly_review, False)
        self.assertEqual(target, dataclasses.replace(original, readonly_review=False))
        self.assertIs(baseline, self.sessions[0].attribution)
        self.assertEqual(directory, self.evidence / 'write-session')
        current = registry.read_private(self.state / 'build-current.json')
        self.assertEqual(current['phase'], 'failed')
        self.assertIs(current['recovery_required'], True)
        self.assertEqual(current['offline_preinstall']['phase'], 'resuming_verified_prefix')
        session = RecoverySession(self, target, directory, 'write',
            SimpleNamespace(data_uuid='fixture-data', volume_group_uuid='fixture-group'))
        self.sessions.append(session)
        return session

    def copy_apps(self, session, materials, evidence_dir, *, acknowledge_write=False, verified_existing=()):
        self.record('copy:missing-apps')
        self.assertIs(acknowledge_write, True)
        self.assertTrue(session.mounted)
        self.assertEqual(materials, self.materials)
        self.assertEqual(evidence_dir, self.evidence / 'copy-transaction')
        review = registry.read_private(self.evidence / 'readonly-prefix-review.json')
        self.assertEqual(verified_existing, tuple(review['verified_existing_apps']))
        self.assertEqual(verified_existing, install.APP_NAMES[:len(verified_existing)])
        self.assertTrue(verified_existing)
        self.assert_not_accepted()
        expected = install._tree_map(self.copy_receipts)
        for name in verified_existing:
            _, manifest = self.sources[name]
            self.assertEqual(artifacts._tree_snapshot(self.guest_apps / name, manifest), expected[name])
        for name in install.APP_NAMES:
            if name in verified_existing:
                continue  # Existing bytes must never reach a copying operation.
            self.seed_app(name)
            self.copied_names.append(name)
            if self.fail_copy:
                raise install.InstallError('fixture missing-app copy failure')
        self.assertEqual(self.retained_identity(), self.retained_before)
        return self.copy_receipts

    def verify_readback(self, session, materials, receipts, *, expected_data_uuid, expected_group_uuid):
        self.record('readonly:verify')
        self.assertEqual(session.label, 'after')
        self.assertTrue(session.mounted)
        self.assertEqual(materials, self.materials)
        self.assertIs(receipts, self.copy_receipts)
        self.assertEqual((expected_data_uuid, expected_group_uuid), ('fixture-data', 'fixture-group'))
        self.assert_not_accepted()
        for name, expected in install._tree_map(self.receipts).items():
            _, manifest = self.sources[name]
            self.assertEqual(artifacts._tree_snapshot(self.guest_apps / name, manifest), expected)
        if self.fail_readback:
            raise artifacts.ArtifactError('fixture final readonly verification failure')
        return self.receipts

    def run_recovery(self, **changes):
        kwargs = dict(state_dir=self.state, tart_home=self.tart, job_id=self.jid, name=self.name,
            materials=self.materials, failed_evidence_dir=self.previous, operation_id=self.operation_id,
            evidence_dir=self.evidence, acknowledge_recovery=True, external_lock=self.external_lock)
        kwargs.update(changes)
        return recovery.resume_verified_prefix(**kwargs)

    def assert_no_write(self):
        self.writable_factory.assert_not_called()
        self.copier.assert_not_called()
        self.readback.assert_not_called()
        self.assert_not_accepted()

    def assert_recovery_failure(self, expected_exception):
        with self.assertRaises(expected_exception):
            self.run_recovery()
        self.assert_quarantined()
        self.assertEqual(self.retained_identity(), self.retained_before)

    def test_success_retains_original_bytes_and_requires_final_readonly_detach(self):
        previous = {p: p.read_bytes() for p in self.previous.rglob('*.json')}
        config_before = disk.signature(self.stage / 'config.json')
        nvram_before = disk.signature(self.stage / 'nvram.bin')
        outcome = self.run_recovery()
        self.assertEqual(self.events, [
            'stage:load', 'lock:acquired', 'sources:verify', 'before:open', 'before:enter',
            'before:mount', 'root:readonly', 'review:prefix', 'before:detach',
            'write:open', 'write:enter', 'write:mount', 'copy:missing-apps', 'write:detach',
            'stage:rebase', 'after:open', 'after:enter', 'after:mount', 'readonly:verify',
            'after:detach', 'receipt:sidecar', 'state:complete', 'receipt:complete', 'lock:released',
        ])
        self.assertEqual(self.copied_names, list(install.APP_NAMES[1:]))
        self.assertEqual(self.retained_identity(), self.retained_before)
        self.assertEqual(outcome['retained_without_application_byte_overwrite'], [install.APP_NAMES[0]])
        self.assertEqual(tuple(a['name'] for a in outcome['applications']), install.APP_NAMES)
        self.assertEqual(outcome['operation_id'], self.operation_id)
        self.assertEqual(outcome['recovered_from'], str(self.previous))
        self.assertEqual(previous, {p: p.read_bytes() for p in previous})
        self.assertEqual(disk.signature(self.stage / 'config.json'), config_before)
        self.assertEqual(disk.signature(self.stage / 'nvram.bin'), nvram_before)
        self.assertEqual(self.loaded_targets[0].baseline[:3], self.loaded_targets[1].baseline[:3])
        self.assertNotEqual(self.loaded_targets[0].baseline, self.loaded_targets[1].baseline)
        for call in self.load_mock.call_args_list:
            self.assertEqual(call.kwargs, {'review_failed_operation_id': self.operation_id})
        current = registry.read_private(self.state / 'build-current.json')
        self.assertEqual(current['phase'], 'awaiting_first_desktop_acceptance')
        self.assertIs(current['applications_preinstalled'], True)
        self.assertFalse(current.get('recovery_required', False))
        self.assertIs(current['offline_preinstall']['active'], False)
        for key in ('desktop_verified', 'guest_started', 'published', 'credentials_copied'):
            self.assertIs(current[key], False)
            self.assertIs(outcome[key], False)
        for key in ('applications_preinstalled', 'readonly_remount_verified', 'final_detach_confirmed',
                    'image_file_identity_and_size_unchanged', 'vm_config_and_nvram_unchanged'):
            self.assertIs(outcome[key], True)
        for path in (self.stage / '.offline-preinstall.complete.json', self.evidence / 'preinstall-complete.json'):
            self.assertEqual(registry.read_private(path), outcome)
        self.assertEqual(current, registry.read_private(self.state / 'build-jobs' / self.jid / 'status.json'))
        self.assertFalse((self.tart / 'vms' / self.name).exists())
        self.assertFalse((self.evidence / 'preinstall-failed.json').exists())

    def test_all_four_existing_complete_apps_can_be_reviewed_without_any_recopy(self):
        for name in install.APP_NAMES[1:]:
            self.seed_app(name)
        outcome = self.run_recovery()
        self.assertEqual(self.copied_names, [])
        self.assertEqual(outcome['retained_without_application_byte_overwrite'], list(install.APP_NAMES))
        self.assertEqual(self.retained_identity(), self.retained_before)

    def test_explicit_true_recovery_ack_is_mandatory_before_evidence_access(self):
        with patch.object(recovery.registry, 'read_private', side_effect=AssertionError('premature evidence read')) as reader:
            for ack in (False, None, 0, 1, 'yes'):
                with self.subTest(ack=ack), self.assertRaises(PreinstallError):
                    self.run_recovery(acknowledge_recovery=ack)
            reader.assert_not_called()
        self.load_mock.assert_not_called()
        self.source_verifier.assert_not_called()
        self.assert_no_write()
        self.assertFalse(self.evidence.exists())

    def test_incomplete_or_unreviewed_catalog_rejected_before_evidence_or_sessions(self):
        first = dataclasses.replace(self.materials[0],
            manifest=dataclasses.replace(self.materials[0].manifest, vendor_team_ids=()))
        for materials in (self.materials[:2], (first,) + self.materials[1:]):
            with self.subTest(count=len(materials)), self.assertRaises(ValueError):
                self.run_recovery(materials=materials)
        self.load_mock.assert_not_called()
        self.source_verifier.assert_not_called()
        self.assert_no_write()

    def test_exact_failed_operation_job_name_stage_and_negative_flags_required(self):
        variants = (('operation_id', 'd' * 32), ('job_id', 'e' * 32), ('name', 'different-vm'),
                    ('stage_path', str(self.root)), ('applications_preinstalled', True),
                    ('guest_started', True), ('desktop_verified', True),
                    ('credentials_copied', True), ('published', True))
        for key, value in variants:
            self.real_write_private(self.previous / 'preinstall-failed.json', dict(self.failed, **{key: value}))
            with self.subTest(key=key), self.assertRaises(PreinstallError):
                self.run_recovery()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.assert_no_write()
        self.assertFalse(self.evidence.exists())

    def test_current_failed_operation_must_match_review_request(self):
        changed = dict(self.current, offline_preinstall=dict(self.current['offline_preinstall'], operation_id='e' * 32))
        self.real_write_private(self.state / 'build-current.json', changed)
        with self.assertRaises(disk.OfflineDiskError):
            self.run_recovery()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.assert_no_write()

    def test_confirmed_prior_failed_session_cleanup_is_required(self):
        for key, value in (('cleanup_confirmed', False), ('operation_failed', False),
                           ('guest_started', True), ('cleanup_confirmed', 1)):
            self.real_write_private(self.previous / 'write-session' / 'session-summary.json',
                                    dict(self.prior_cleanup, **{key: value}))
            with self.subTest(key=key, value=value), self.assertRaises(PreinstallError):
                self.run_recovery()
        self.load_mock.assert_not_called()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.assert_no_write()

    def test_prior_transaction_must_be_failed_and_not_preinstalled(self):
        for change in ({'phase': 'copying'}, {'applications_preinstalled': True}):
            self.real_write_private(self.previous / 'copy-transaction' / 'transaction.json', dict(self.transaction, **change))
            with self.subTest(change=change), self.assertRaises(PreinstallError):
                self.run_recovery()
        self.load_mock.assert_not_called()
        self.assert_no_write()

    def test_source_signature_failure_never_opens_a_session(self):
        self.bundle_verifier.side_effect = artifacts.ArtifactError('fixture source signature failure')
        self.assert_recovery_failure(artifacts.ArtifactError)
        self.readonly_factory.assert_not_called()
        self.assert_no_write()

    def test_changed_data_uuid_refused_before_writable_attach(self):
        self.real_write_private(self.previous / 'copy-transaction' / 'transaction.json',
                                dict(self.transaction, data_uuid='other-data'))
        self.assert_recovery_failure(PreinstallError)
        self.assertIn('before:detach', self.events)
        self.assert_no_write()

    def test_changed_volume_group_uuid_refused_before_writable_attach(self):
        self.real_write_private(self.previous / 'copy-transaction' / 'transaction.json',
                                dict(self.transaction, volume_group_uuid='other-group'))
        self.assert_recovery_failure(PreinstallError)
        self.assert_no_write()

    def test_empty_prefix_refused_before_writable_attach(self):
        self.move_first_app_aside()
        with self.assertRaises(PreinstallError):
            self.run_recovery()
        self.assert_quarantined()
        self.assert_no_write()

    def test_noncontiguous_existing_apps_refused_before_writable_attach(self):
        self.seed_app('Claude.app')
        self.assert_recovery_failure(PreinstallError)
        self.assert_no_write()

    def test_unknown_app_refused_without_touching_it_or_opening_rw(self):
        unknown = self.checked(self.guest_apps / 'Unknown.app')
        unknown.mkdir(mode=0o700)
        sentinel = unknown / 'keep'
        sentinel.write_bytes(b'not authorized for modification')
        before = (sentinel.stat().st_ino, sentinel.read_bytes())
        self.assert_recovery_failure(PreinstallError)
        self.assertEqual(before, (sentinel.stat().st_ino, sentinel.read_bytes()))
        self.assert_no_write()

    def test_unknown_application_root_file_also_refused(self):
        self.checked(self.guest_apps / 'unexpected-file').write_bytes(b'keep')
        self.assert_recovery_failure(PreinstallError)
        self.assert_no_write()

    def test_changed_existing_tree_rejected_before_rw_not_repaired(self):
        path = self.checked(self.guest_apps / install.APP_NAMES[0] / 'Contents' / 'fixture')
        path.write_bytes(b'tampered existing app bytes must never be repaired')
        changed = (path.stat().st_ino, path.read_bytes())
        with self.assertRaises(PreinstallError):
            self.run_recovery()
        self.assertEqual(changed, (path.stat().st_ino, path.read_bytes()))
        self.assert_quarantined()
        self.assert_no_write()

    def test_existing_bundle_mode_change_also_refused_before_rw(self):
        path = self.checked(self.guest_apps / install.APP_NAMES[0] / 'Contents' / 'fixture')
        path.chmod(0o700)
        with self.assertRaises(PreinstallError):
            self.run_recovery()
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assert_quarantined()
        self.assert_no_write()

    def test_partial_existing_bundle_is_not_accepted_as_complete_prefix(self):
        partial = self.checked(self.guest_apps / install.APP_NAMES[1])
        partial.mkdir(mode=0o700)
        (partial / 'Contents').mkdir(mode=0o700)
        self.assert_recovery_failure(PreinstallError)
        self.assert_no_write()

    def test_initial_readonly_detach_failure_never_grants_write_permission(self):
        self.fail_detach = 'before'
        self.assert_recovery_failure(disk.OfflineDiskError)
        self.assertIn('review:prefix', self.events)
        self.assertNotIn('before:detach', self.events)
        self.assert_no_write()

    def test_missing_app_copy_failure_leaves_recovery_required_and_existing_bytes(self):
        self.fail_copy = True
        self.assert_recovery_failure(install.InstallError)
        self.assertEqual(self.copied_names, [install.APP_NAMES[1]])
        self.assertIn('write:detach', self.events)
        self.assertNotIn('stage:rebase', self.events)
        self.readback.assert_not_called()

    def test_writable_detach_failure_prevents_rebase_and_fresh_verification(self):
        self.fail_detach = 'write'
        self.assert_recovery_failure(disk.OfflineDiskError)
        self.assertNotIn('stage:rebase', self.events)
        self.readback.assert_not_called()

    def test_final_readonly_verification_failure_never_marks_complete(self):
        self.fail_readback = True
        self.assert_recovery_failure(artifacts.ArtifactError)
        self.assertIn('after:detach', self.events)
        self.readback.assert_called_once()

    def test_final_readonly_detach_failure_never_marks_complete(self):
        self.fail_detach = 'after'
        self.assert_recovery_failure(disk.OfflineDiskError)
        self.assertIn('after:detach-failed', self.events)
        self.assertNotIn('after:detach', self.events)
        self.readback.assert_called_once()

    def assert_postwrite_rejected(self, expected_exception=PreinstallError):
        self.assert_recovery_failure(expected_exception)
        self.assertIn('write:detach', self.events)
        self.assertIn('stage:rebase', self.events)
        self.readonly_factory.assert_called_once()
        self.readback.assert_not_called()

    def test_replaced_same_size_postwrite_image_cannot_rebase_or_verify(self):
        def replace_image():
            image = self.checked(self.stage / 'disk.img')
            replacement = self.checked(self.stage / 'replacement-fixture.img')
            before = disk.signature(image)
            with replacement.open('xb') as stream:
                stream.truncate(before[2])
            self.checked(image)
            self.checked(replacement)
            os.replace(replacement, image)
            self.assertEqual(image.stat().st_size, before[2])
            self.assertNotEqual(image.stat().st_ino, before[1])
        self.after_write = replace_image
        self.assert_postwrite_rejected()

    def test_resized_postwrite_image_cannot_rebase_or_verify(self):
        def resize_image():
            with self.checked(self.stage / 'disk.img').open('r+b') as stream:
                stream.truncate(1024**3 + 1)
        self.after_write = resize_image
        self.assert_postwrite_rejected(disk.OfflineDiskError)

    def test_postwrite_config_change_forbids_readonly_acceptance(self):
        self.after_write = lambda: self.checked(self.stage / 'config.json').write_bytes(b'changed config')
        self.assert_postwrite_rejected()

    def test_postwrite_nvram_change_forbids_readonly_acceptance(self):
        self.after_write = lambda: self.checked(self.stage / 'nvram.bin').write_bytes(b'changed nvram')
        self.assert_postwrite_rejected()

    def test_sidecar_persistence_failure_must_not_leave_true_completion_evidence(self):
        self.fail_commit = '.offline-preinstall.complete.json'
        self.assert_recovery_failure(OSError)

    def assert_commit_failure(self, filename):
        self.fail_commit = filename
        with self.assertRaises(OSError):
            self.run_recovery()
        self.assertFalse((self.evidence / 'preinstall-complete.json').exists())
        current = registry.read_private(self.state / 'build-current.json')
        self.assertEqual(current['phase'], 'failed')
        self.assertIs(current['recovery_required'], True)
        self.assertIs(current['applications_preinstalled'], False)
        self.assertIs(current['offline_preinstall']['active'], False)
        failed = registry.read_private(self.evidence / 'preinstall-failed.json')
        self.assertIs(failed['applications_preinstalled'], False)
        self.assertIs(failed['manual_review_required'], True)
        for key in ('desktop_verified', 'guest_started', 'published', 'credentials_copied'):
            self.assertIs(current[key], False)
            self.assertIs(failed[key], False)
        self.assertEqual(current, registry.read_private(self.state / 'build-jobs' / self.jid / 'status.json'))
        self.assertEqual(self.retained_identity(), self.retained_before)
        # The private sidecar records completed physical-disk verification, NOT
        # operation commit. It cannot substitute for current state + final receipt.
        sidecar = registry.read_private(self.stage / '.offline-preinstall.complete.json')
        self.assertIs(sidecar['final_detach_confirmed'], True)
        self.assertIs(sidecar['readonly_remount_verified'], True)
        self.assertIn('after:detach', self.events)

    def test_final_state_persistence_failure_must_not_commit_success(self):
        self.assert_commit_failure('status.json')

    def test_final_evidence_persistence_failure_returns_state_to_failed(self):
        self.assert_commit_failure('preinstall-complete.json')


if __name__ == '__main__':
    unittest.main()
