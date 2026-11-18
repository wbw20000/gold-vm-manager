"""Offline orchestration contracts, not real application/signature acceptance.

Only private, checked temporary paths are touched. Sessions, bundle verifiers,
and copying are fakes; network, subprocesses, mounts, VMs and app execution are
forbidden. Real StageTarget loading, lifecycle locks and receipt/state writes
exercise the orchestration boundary independently of disk-tool fixtures.
"""
from contextlib import contextmanager
import dataclasses
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request

import guest_app_artifacts as artifacts
import guest_app_pins as pins
import managed_registry as registry
import offline_disk as disk
import offline_install as install
import offline_preinstall as preinstall


APP_NAMES = ('CCBaga-A.app', 'CCBaga-B.app', 'Clash Verge.app', 'Claude.app')


class NoExternalIOTests(unittest.TestCase):
    def setUp(self):
        super().setUp()
        for owner, name in ((subprocess, 'run'), (subprocess, 'Popen'),
                            (socket, 'create_connection'), (socket.socket, 'connect'),
                            (urllib.request, 'urlopen'), (urllib.request, 'build_opener'),
                            (os, 'system')):
            guard = self.patch(patch.object(owner, name,
                side_effect=AssertionError('External I/O forbidden: ' + name)))
            # A production catch-all must not hide an attempted real operation.
            self.addCleanup(guard.assert_not_called)

    def patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value


class CatalogTests(NoExternalIOTests):
    def test_exact_reviewed_versions_archives_hashes_and_signers(self):
        expected = (
            ('ccbaga', '0.2.50',
             'https://github.com/liseami/CCBaga/releases/download/v0.2.50/CCBaga-0.2.50-macos-arm64.dmg',
             '0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b',
             ('6UB6WM6VQR',), 333449374),
            ('clashVergeRev', '2.5.10',
             'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.10/Clash.Verge_2.5.10_aarch64.dmg',
             '40d4a7da4543d75f573a5cfcc31543b0b4bf7e02caa122a9ca50654859585839',
             ('JPH3Z7PPBB',), 80769307),
            ('claudeDesktop', '6.6395.0',
             'https://downloads.claude.ai/releases/darwin/universal/6.6395.0/Claude-d71a20056be3b25708751e98bef60759ea1f441b.zip',
             '88c7b43039e77529930eda386a21141232bf2acb6762d04e6fbc2d028813847a',
             ('Q6L2SF6YDW',), None),
        )
        manifests = pins.reviewed_manifests()
        self.assertIs(type(manifests), tuple)
        self.assertEqual(tuple((m.product, m.version, m.artifact_url, m.known_sha256,
                                m.vendor_team_ids, m.declared_size_bytes)
                               for m in manifests), expected)
        for manifest in manifests:
            with self.subTest(product=manifest.product):
                self.assertIs(manifest.allow_unpinned_sha256, False)
                self.assertTrue(manifest.identity_review_sources)
                artifacts._require_review(manifest)

    def test_original_complete_gui_bundle_identities_and_resources(self):
        apps = tuple(app for m in pins.reviewed_manifests() for app in m.expected_apps)
        self.assertEqual(tuple(app.name for app in apps), APP_NAMES)
        self.assertEqual(tuple(app.bundle_names for app in apps),
                         (('CCBaga-A',), ('CCBaga-B',), ('Clash Verge',), ('Claude',)))
        self.assertEqual(tuple(app.bundle_identifiers for app in apps), (
            ('ai.local.requirement-french',), ('ai.local.requirement-french.browser',),
            ('io.github.clash-verge-rev.clash-verge-rev',), ('com.anthropic.claudefordesktop',)))
        self.assertEqual(tuple(app.executable_names for app in apps),
                         (('requirement-french',), ('CCBrowser',), ('clash-verge',), ('Claude',)))
        for app in apps:
            self.assertIn('Contents/Resources', app.required_paths)
            self.assertIn('Contents/MacOS/' + app.executable_names[0], app.required_paths)
        self.assertIn('Contents/MacOS/Chromium', apps[1].required_paths)
        self.assertIn('Contents/Frameworks/Chromium Framework.framework', apps[1].required_paths)
        self.assertIn('Contents/MacOS/verge-mihomo', apps[2].required_paths)
        self.assertIn('Contents/Resources/app.asar', apps[3].required_paths)
        self.assertIn('Contents/Frameworks/Electron Framework.framework', apps[3].required_paths)

    def test_ccbaga_browser_version_is_not_replaced_by_a_version(self):
        a, b = pins.reviewed_manifests()[0].expected_apps
        self.assertEqual((a.short_versions, a.bundle_versions), (('0.2.50',), ('0.2.50',)))
        self.assertEqual((b.short_versions, b.bundle_versions), (('148.0.7778.215',), ('7778.215',)))
        self.assertNotEqual(a.short_versions, b.short_versions)
        self.assertNotEqual(a.bundle_versions, b.bundle_versions)

    def test_claude_has_explicit_secondary_digest_review(self):
        claude = pins.reviewed_manifests()[2]
        self.assertEqual(pins.CLAUDE_DIGEST_SOURCE,
            'https://raw.githubusercontent.com/Homebrew/homebrew-cask/master/Casks/c/claude.rb')
        self.assertIn(pins.CLAUDE_DIGEST_SOURCE, claude.identity_review_sources)
        self.assertIn('https://downloads.claude.ai/releases/darwin/universal/RELEASES.json',
                      claude.identity_review_sources)
        self.assertIn('https://support.claude.com/en/articles/12611117-deploy-claude-desktop-for-macos',
                      claude.identity_review_sources)
        self.assertIsNotNone(claude.known_sha256)
        self.assertFalse(claude.allow_unpinned_sha256)

    def test_catalog_is_frozen_repeatable_and_does_not_autoupdate(self):
        first = pins.reviewed_manifests()
        second = pins.reviewed_manifests()
        self.assertEqual(first, second)
        self.assertEqual(tuple(m.manifest_sha256 for m in first),
                         tuple(m.manifest_sha256 for m in second))
        for manifest in first:
            self.assertNotIn('/latest/', manifest.artifact_url)
            self.assertIn(manifest.version, manifest.artifact_url)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                manifest.version = '99.0.0'
            with self.assertRaises(dataclasses.FrozenInstanceError):
                manifest.expected_apps[0].name = 'replacement.app'


class FakeSession:
    """No devices, commands or mounts; every boundary checks the real locks."""
    def __init__(self, case, target, directory, label, attribution):
        self.case = case
        self.target = target
        self.directory = directory
        self.label = label
        self.attribution = attribution
        self.mounted = False
        case.record(label + ':open')

    def __enter__(self):
        self.target.verify_unchanged()
        self.case.record(self.label + ':enter')
        self.case.assert_not_accepted()
        return self

    def mount_writable(self):
        self.case.assertEqual(self.label, 'write')
        self.mounted = True
        self.case.record('write:mount')
        return self.case.guest_apps.parent

    def mount_readonly_for_probe(self):
        self.case.assertEqual(self.label, 'after')
        self.mounted = True
        self.case.record('after:mount')
        return self.case.guest_apps.parent

    def __exit__(self, kind, value, trace):
        self.case.assert_not_accepted()
        if self.label == self.case.fail_detach:
            self.case.record(self.label + ':detach-failed')
            raise disk.OfflineDiskError('fixture detach failure')
        if self.label == 'write' and kind is None:
            self.case.after_write()
        self.case.record(self.label + ':detach')
        return False


class PreinstallTests(NoExternalIOTests):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory(prefix='offline-preinstall-test-')
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.cleanup)
        self.addCleanup(os.umask, os.umask(0o077))
        self.state = self.root / 'state'
        self.tart = self.root / 'tart'
        self.jid = 'b' * 32
        self.name = 'gg1'
        self.stage = self.tart / '.gold-manager-staging' / self.jid / 'new-environment'
        self.evidence = self.root / 'evidence'
        self.guest_apps = self.root / 'fake-data' / 'Applications'
        for path in (self.state / 'build-jobs' / self.jid, self.stage, self.guest_apps):
            path.mkdir(parents=True, mode=0o700)
        self.current = {
            'id': self.jid, 'name': self.name, 'mode': 'offline_validate', 'source_vm': None,
            'phase': 'awaiting_offline_preinstall', 'system_restored': True,
            'guest_started': False, 'applications_preinstalled': False,
            'desktop_verified': False, 'credentials_copied': False, 'published': False,
            'stage_path': str(self.stage),
        }
        registry.write_private(self.state / 'build-current.json', self.current)
        registry.write_private(self.state / 'build-jobs' / self.jid / 'status.json', self.current)
        registry.write_private(self.state / 'build-jobs' / self.jid / 'request.json', {
            'id': self.jid, 'name': self.name, 'mode': 'offline_validate',
            'source_vm': None, 'disk_gib': 1,
        })
        registry.write_private(self.stage / '.clean-vm-installer.complete.json', {
            'installer': 'CleanVMInstaller', 'status': 'complete', 'schemaVersion': 1,
            'networkDeviceCount': 0, 'directorySharingDeviceCount': 0, 'socketDeviceCount': 0,
        })
        for name in ('config.json', 'nvram.bin', 'disk.img'):
            (self.stage / name).write_bytes(b'private non-executable fixture')
        with (self.stage / 'disk.img').open('r+b') as stream:
            stream.truncate(1024**3)  # Sparse fixture, never a usable VM image.
        self.config_identity = disk.signature(self.stage / 'config.json')[:2]
        self.external_lock = self.root / 'lifecycle.lock'
        for path in (self.external_lock, self.state / 'build.lock'):
            path.write_bytes(b'')
        self.materials, self.receipts = self.make_materials()
        # A distinct writer return proves readback is bound to the copy receipts,
        # not to a stale preflight success flag or the first verifier's tuple.
        self.copy_receipts = tuple(dataclasses.replace(r) for r in self.receipts)
        self.events = []
        self.lock_held = False
        self.fail_copy = False
        self.fail_readback = False
        self.fail_detach = None
        self.after_write = self.change_image_contents
        self.loaded_targets = []
        self.sessions = []
        self.real_load = disk.StageTarget.load
        self.real_locked = disk.StageTarget.locked
        self.real_write_private = registry.write_private
        self.load_mock = self.patch(patch.object(disk.StageTarget, 'load', side_effect=self.load_target))
        self.patch(patch.object(disk.StageTarget, 'locked', self.tracked_lock()))
        self.lockf_mock = self.patch(patch.object(disk.fcntl, 'lockf', wraps=fcntl.lockf))
        self.state_writer = self.patch(patch.object(registry, 'write_private', side_effect=self.write_private))
        self.bundle_verifier = self.patch(patch.object(artifacts, 'verify_app_bundles',
                                                      side_effect=self.verify_bundle))
        self.source_verifier = self.patch(patch.object(preinstall, 'verify_materials',
                                                      side_effect=self.verify_sources))
        self.readonly_factory = self.patch(patch.object(preinstall, 'DiskSession',
                                                       side_effect=self.readonly_session))
        self.writable_factory = self.patch(patch.object(preinstall, 'WritableDiskSession',
                                                       side_effect=self.writable_session))
        self.copier = self.patch(patch.object(preinstall, 'write_applications', side_effect=self.copy_apps))
        self.readback = self.patch(patch.object(preinstall, 'verify_installed_readonly',
                                               side_effect=self.verify_readback))

    def checked(self, path):
        path = Path(path)
        self.assertEqual(path.resolve(), path)
        self.assertIn(self.root, path.parents)
        self.assertFalse(path.is_symlink())
        return path

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(), self.root)
        self.assertTrue(self.root.name.startswith('offline-preinstall-test-'))
        self.tmp.cleanup()

    def make_materials(self):
        materials, receipts = [], []
        for manifest in pins.reviewed_manifests():
            root = self.root / manifest.product
            root.mkdir(mode=0o700)
            paths, apps = [], []
            for app in manifest.expected_apps:
                path = root / app.name
                (path / 'Contents').mkdir(parents=True, mode=0o700)
                (path / 'Contents' / 'fixture').write_bytes(b'NOT a real application; never execute')
                paths.append(path)
                apps.append({
                    'name': app.name, 'bundle_identifier': app.bundle_identifiers[0],
                    'short_version': app.short_versions[0], 'bundle_version': app.bundle_versions[0],
                    'team_id': manifest.vendor_team_ids[0], 'bundle_bytes': 35,
                    'bundle_entries': 2,
                    'bundle_tree_sha256': hashlib.sha256(app.name.encode()).hexdigest(),
                })
            archive = root / 'fixture-archive'
            archive.write_bytes(b'not a downloaded archive')
            download = artifacts.DownloadReceipt(manifest.artifact_key, str(archive),
                manifest.known_sha256, archive.stat().st_size, True, 'fixture.invalid')
            materials.append(install.Material(manifest, download, root, tuple(paths)))
            receipts.append(artifacts.VerificationReceipt(manifest.manifest_sha256,
                dataclasses.asdict(manifest), manifest.known_sha256, download.size_bytes, tuple(apps)))
        return tuple(materials), tuple(receipts)

    def assert_locks_held(self):
        self.assertTrue(self.lock_held, 'lifecycle context released too early')
        # POSIX locks are process-scoped, so a same-process competing lock would
        # not test exclusion. Check the real LOCK_EX call and that its exact
        # config descriptor remains open at every orchestration boundary.
        self.lockf_mock.assert_called_once()
        fd, operation = self.lockf_mock.call_args.args[:2]
        self.assertEqual(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(fd)
        self.assertEqual((info.st_dev, info.st_ino), self.config_identity)
        for path in (self.external_lock, self.state / 'build.lock'):
            fd = os.open(str(self.checked(path)), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BlockingIOError, msg='lifecycle lock is not held'):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    def record(self, event):
        self.assert_locks_held()
        self.events.append(event)

    def tracked_lock(self):
        case = self

        @contextmanager
        def locked(target, external_lock=None):
            case.assertEqual(external_lock, case.external_lock)
            with case.real_locked(target, external_lock):
                case.lock_held = True
                case.record('lock:acquired')
                try:
                    yield
                finally:
                    case.assert_locks_held()
                    case.lock_held = False
            case.events.append('lock:released')
        return locked

    def load_target(self, *args, **kwargs):
        if self.lock_held:
            self.record('stage:rebase')
            self.assertIn('write:detach', self.events)
        else:
            self.events.append('stage:load')
        target = self.real_load(*args, **kwargs)
        self.loaded_targets.append(target)
        return target

    def write_private(self, path, data):
        self.checked(path)
        if data.get('applications_preinstalled') is True:
            self.assert_locks_held()
            self.assertIn('after:detach', self.events, 'success was written before final RO detach')
            if Path(path).name == 'preinstall-complete.json':
                self.events.append('receipt:complete')
            elif Path(path).name == '.offline-preinstall.complete.json':
                self.events.append('receipt:sidecar')
            elif Path(path).name == 'build-current.json':
                self.events.append('state:complete')
        return self.real_write_private(path, data)

    def verify_bundle(self, manifest, root, paths, download):
        self.assert_locks_held()
        material = self.materials[install.PRODUCTS.index(manifest.product)]
        self.assertEqual((manifest, root, paths, download),
                         (material.manifest, material.staging_root, material.app_paths, material.download))
        self.assertEqual(tuple(p.name for p in paths), tuple(a.name for a in manifest.expected_apps))
        return self.receipts[install.PRODUCTS.index(manifest.product)]

    def verify_sources(self, materials):
        self.record('sources:verify')
        return install.verify_materials(materials)

    def readonly_session(self, target, directory, *, lock_held=False):
        self.assertIs(lock_held, True)
        self.assertEqual(directory.parent, self.evidence)
        label = {'before-write-readonly': 'before', 'after-write-readonly': 'after'}[directory.name]
        if label == 'after':
            self.assertIn('write:detach', self.events)
            self.assertIn('stage:rebase', self.events)
            self.assertIs(target, self.loaded_targets[-1])
            self.assertIsNot(target, self.loaded_targets[0])
            self.assertEqual(target.baseline[:3], self.loaded_targets[0].baseline[:3])
        session = FakeSession(self, target, directory, label,
            SimpleNamespace(data_uuid='fixture-data', volume_group_uuid='fixture-group'))
        self.sessions.append(session)
        return session

    def writable_session(self, target, directory, baseline, *, acknowledge_write=False, lock_held=False):
        self.assertIs(acknowledge_write, True)
        self.assertIs(lock_held, True)
        self.assertIn('before:detach', self.events)
        self.assertIs(baseline, self.sessions[0].attribution)
        self.assertEqual(directory, self.evidence / 'write-session')
        session = FakeSession(self, target, directory, 'write',
            SimpleNamespace(data_uuid='fixture-data', volume_group_uuid='fixture-group'))
        self.sessions.append(session)
        return session

    def copy_apps(self, session, materials, evidence_dir, *, acknowledge_write=False):
        self.record('copy:apps')
        self.assertIs(acknowledge_write, True)
        self.assertTrue(session.mounted)
        self.assertIs(session, self.sessions[1])
        self.assertEqual(materials, self.materials)
        self.assertEqual(evidence_dir, self.evidence / 'copy-transaction')
        self.assert_not_accepted()
        for index, name in enumerate(APP_NAMES):
            target = self.checked(self.guest_apps / name)
            target.mkdir(mode=0o700)  # No merge, overwrite or execution.
            (target / 'fixture').write_text('copied fixture ' + name, encoding='utf-8')
            if self.fail_copy and index == 1:
                raise install.InstallError('fixture partial copy failure')
        return self.copy_receipts

    def verify_readback(self, session, materials, receipts, *, expected_data_uuid, expected_group_uuid):
        self.record('readonly:verify')
        self.assertIs(session, self.sessions[-1])
        self.assertEqual(session.label, 'after')
        self.assertTrue(session.mounted)
        self.assertEqual(materials, self.materials)
        self.assertIs(receipts, self.copy_receipts)
        self.assertEqual((expected_data_uuid, expected_group_uuid), ('fixture-data', 'fixture-group'))
        self.assertEqual(set(p.name for p in self.guest_apps.iterdir()), set(APP_NAMES))
        self.assert_not_accepted()
        if self.fail_readback:
            raise artifacts.ArtifactError('fixture fresh readonly signature failure')
        return self.receipts

    def change_image_contents(self):
        path = self.checked(self.stage / 'disk.img')
        original = disk.signature(path)
        with path.open('r+b') as stream:
            stream.write(b'changed only fixture image contents')
        os.utime(path, ns=(path.stat().st_atime_ns, original[3] + 1_000_000_000))
        self.assertEqual(disk.signature(path)[:3], original[:3])
        self.assertNotEqual(disk.signature(path), original)

    def run_preinstall(self, **changes):
        kwargs = dict(state_dir=self.state, tart_home=self.tart, job_id=self.jid, name=self.name,
            materials=self.materials, evidence_dir=self.evidence, acknowledge_write=True,
            external_lock=self.external_lock)
        kwargs.update(changes)
        return preinstall.preinstall_stage(**kwargs)

    def assert_not_accepted(self):
        current = registry.read_private(self.state / 'build-current.json')
        self.assertIs(current['applications_preinstalled'], False)
        for key in ('desktop_verified', 'guest_started', 'published', 'credentials_copied'):
            self.assertIs(current[key], False)
        self.assertFalse((self.evidence / 'preinstall-complete.json').exists())
        self.assertFalse((self.stage / '.offline-preinstall.complete.json').exists())
        self.assertFalse((self.tart / 'vms' / self.name).exists())

    def assert_quarantined(self):
        self.assert_not_accepted()
        current = registry.read_private(self.state / 'build-current.json')
        self.assertEqual(current['phase'], 'failed')
        self.assertIs(current['recovery_required'], True)
        self.assertEqual(current['offline_preinstall']['phase'], 'failed_quarantined')
        self.assertIs(current['offline_preinstall']['active'], False)
        self.assertEqual(current, registry.read_private(self.state / 'build-jobs' / self.jid / 'status.json'))
        failed = registry.read_private(self.evidence / 'preinstall-failed.json')
        self.assertIs(failed['applications_preinstalled'], False)
        self.assertIs(failed['manual_review_required'], True)
        for key in ('desktop_verified', 'guest_started', 'published', 'credentials_copied'):
            self.assertIs(failed[key], False)

    def assert_retry_refused_without_overwrite(self):
        before = {p: (p.stat().st_ino, p.read_bytes()) for p in self.guest_apps.glob('*/fixture')}
        failed = (self.evidence / 'preinstall-failed.json').read_bytes()
        calls = (self.readonly_factory.call_count, self.writable_factory.call_count,
                 self.copier.call_count, self.source_verifier.call_count)
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall(evidence_dir=self.root / 'retry-evidence')
        self.assertFalse((self.root / 'retry-evidence').exists())
        self.assertEqual(calls, (self.readonly_factory.call_count, self.writable_factory.call_count,
                                self.copier.call_count, self.source_verifier.call_count))
        self.assertEqual(before, {p: (p.stat().st_ino, p.read_bytes()) for p in before})
        self.assertEqual((self.evidence / 'preinstall-failed.json').read_bytes(), failed)

    def test_success_holds_locks_through_fresh_readonly_detach_before_acceptance(self):
        config_before = disk.signature(self.stage / 'config.json')
        nvram_before = disk.signature(self.stage / 'nvram.bin')
        result = self.run_preinstall()
        self.assertEqual(self.events, [
            'stage:load', 'lock:acquired', 'sources:verify',
            'before:open', 'before:enter', 'before:detach',
            'write:open', 'write:enter', 'write:mount', 'copy:apps', 'write:detach',
            'stage:rebase', 'after:open', 'after:enter', 'after:mount', 'readonly:verify',
            'after:detach', 'receipt:sidecar', 'state:complete', 'receipt:complete', 'lock:released',
        ])
        self.lockf_mock.assert_called_once()
        self.assertEqual(self.lockf_mock.call_args.args[1], fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(disk.signature(self.stage / 'config.json'), config_before)
        self.assertEqual(disk.signature(self.stage / 'nvram.bin'), nvram_before)
        self.assertEqual(self.loaded_targets[0].baseline[:3], self.loaded_targets[1].baseline[:3])
        self.assertNotEqual(self.loaded_targets[0].baseline, self.loaded_targets[1].baseline)
        self.assertEqual(tuple(a['name'] for a in result['applications']), APP_NAMES)
        self.assertEqual(result['name'], 'gg1')
        self.assertEqual(result['stage_path'], str(self.stage))
        for key in ('applications_preinstalled', 'readonly_remount_verified', 'final_detach_confirmed',
                    'vm_config_and_nvram_unchanged', 'image_file_identity_and_size_unchanged'):
            self.assertIs(result[key], True)
        current = registry.read_private(self.state / 'build-current.json')
        self.assertEqual(current['phase'], 'awaiting_first_desktop_acceptance')
        self.assertIs(current['applications_preinstalled'], True)
        self.assertEqual(current['offline_preinstall']['phase'], 'verified_awaiting_first_desktop')
        self.assertIs(current['offline_preinstall']['active'], False)
        self.assertEqual(current['offline_preinstall']['operation_id'], result['operation_id'])
        for key in ('desktop_verified', 'guest_started', 'published', 'credentials_copied'):
            self.assertIs(current[key], False)
            self.assertIs(result[key], False)
        self.assertEqual(current, registry.read_private(self.state / 'build-jobs' / self.jid / 'status.json'))
        for path in (self.evidence / 'preinstall-complete.json', self.stage / '.offline-preinstall.complete.json'):
            self.assertEqual(registry.read_private(path), result)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for material in self.materials:
            for suffix in ('-source.json', '-guest-readonly.json'):
                proof = registry.read_private(self.evidence / (material.manifest.product + suffix))
                self.assertEqual(proof['manifest_sha256'], material.manifest.manifest_sha256)
                self.assertEqual(tuple(a['name'] for a in proof['apps']),
                                 tuple(a.name for a in material.manifest.expected_apps))
        self.assertFalse((self.tart / 'vms' / 'gg1').exists())
        self.assertFalse((self.evidence / 'preinstall-failed.json').exists())
        for name in ('state.vzvmsave', 'state.bin', 'savedstate'):
            self.assertFalse((self.stage / name).exists())
        for path in (self.external_lock, self.state / 'build.lock'):
            with path.open('rb') as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_explicit_true_ack_is_required_before_any_stage_or_source_access(self):
        for ack in (False, None, 0, 1, 'yes'):
            with self.subTest(ack=ack), self.assertRaises(preinstall.PreinstallError):
                self.run_preinstall(acknowledge_write=ack)
        self.load_mock.assert_not_called()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.assertFalse(self.evidence.exists())

    def test_incomplete_reordered_or_non_tuple_materials_are_rejected_early(self):
        variants = ((), self.materials[:2], self.materials[::-1], list(self.materials))
        for materials in variants:
            with self.subTest(materials=type(materials).__name__), self.assertRaises(install.InstallError):
                self.run_preinstall(materials=materials)
        self.load_mock.assert_not_called()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.assertFalse(self.evidence.exists())

    def test_unreviewed_or_changed_catalog_is_rejected_before_source_or_disk_access(self):
        original = self.materials[0]
        variants = (
            dataclasses.replace(original.manifest, vendor_team_ids=()),
            dataclasses.replace(original.manifest, vendor_team_ids=('AAAAAAAAAA',)),
            dataclasses.replace(original.manifest, identity_review_sources=()),
            dataclasses.replace(original.manifest, known_sha256='f' * 64),
            dataclasses.replace(original.manifest, expected_apps=tuple(
                dataclasses.replace(a, bundle_identifiers=()) for a in original.manifest.expected_apps)),
        )
        for manifest in variants:
            with self.subTest(manifest=manifest.manifest_sha256), self.assertRaises(preinstall.PreinstallError):
                self.run_preinstall(materials=(dataclasses.replace(original, manifest=manifest),) + self.materials[1:])
        self.load_mock.assert_not_called()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.assertFalse(self.evidence.exists())

    def test_incomplete_four_bundle_catalog_is_rejected_before_stage_access(self):
        manifest = dataclasses.replace(self.materials[0].manifest)
        # Simulate malformed deserialized input without weakening production's
        # frozen constructor: the orchestration must still reject a missing B.
        object.__setattr__(manifest, 'expected_apps', manifest.expected_apps[:1])
        materials = (dataclasses.replace(self.materials[0], manifest=manifest),) + self.materials[1:]
        with self.assertRaises(install.InstallError):
            self.run_preinstall(materials=materials)
        self.load_mock.assert_not_called()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()

    def test_existing_evidence_is_never_reused_or_overwritten(self):
        self.evidence.mkdir(mode=0o700)
        sentinel = self.evidence / 'sentinel'
        sentinel.write_bytes(b'preserve prior evidence')
        before = (sentinel.stat().st_ino, sentinel.read_bytes())
        with self.assertRaises(FileExistsError):
            self.run_preinstall()
        self.assertEqual(before, (sentinel.stat().st_ino, sentinel.read_bytes()))
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.assertEqual(registry.read_private(self.state / 'build-current.json'), self.current)

    def test_contended_lifecycle_locks_prevent_source_and_session_operations(self):
        for index, path in enumerate((self.external_lock, self.state / 'build.lock')):
            with self.subTest(path=path.name), self.checked(path).open('rb') as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    self.run_preinstall(evidence_dir=self.root / ('lock-contention-%d' % index))
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.assertEqual(registry.read_private(self.state / 'build-current.json'), self.current)

    def test_source_signature_failure_never_opens_any_session(self):
        self.bundle_verifier.side_effect = artifacts.ArtifactError('fixture signature rejected')
        with self.assertRaises(artifacts.ArtifactError):
            self.run_preinstall()
        self.source_verifier.assert_called_once_with(self.materials)
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.copier.assert_not_called()
        self.readback.assert_not_called()
        self.assertEqual(list(self.guest_apps.iterdir()), [])
        self.assert_quarantined()
        self.assert_retry_refused_without_overwrite()

    def test_only_untouched_never_booted_restore_state_is_eligible(self):
        changes = (('phase', 'awaiting_first_desktop_acceptance'), ('phase', 'failed'),
                   ('mode', 'create'), ('source_vm', 'existing-vm'), ('name', 'different-name'),
                   ('guest_started', True), ('desktop_verified', True),
                   ('applications_preinstalled', True), ('credentials_copied', True),
                   ('system_restored', False), ('stage_path', str(self.root)))
        for key, value in changes:
            self.real_write_private(self.state / 'build-current.json', dict(self.current, **{key: value}))
            with self.subTest(key=key, value=value), self.assertRaises(disk.OfflineDiskError):
                self.run_preinstall()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.assertFalse(self.evidence.exists())

    def test_published_vm_is_rejected_before_source_or_session_access(self):
        (self.tart / 'vms' / self.name).mkdir(parents=True, mode=0o700)
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()
        self.assertFalse(self.evidence.exists())

    def test_saved_state_is_rejected_before_source_or_session_access(self):
        (self.stage / 'state.vzvmsave').write_bytes(b'fixture saved state')
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()

    def test_invalid_restore_isolation_receipt_is_rejected_before_sessions(self):
        self.real_write_private(self.stage / '.clean-vm-installer.complete.json', {
            'installer': 'CleanVMInstaller', 'status': 'complete', 'schemaVersion': 1,
            'networkDeviceCount': 1, 'directorySharingDeviceCount': 0, 'socketDeviceCount': 0,
        })
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall()
        self.source_verifier.assert_not_called()
        self.readonly_factory.assert_not_called()
        self.writable_factory.assert_not_called()

    def test_partial_copy_failure_quarantines_and_never_overwrites_on_retry(self):
        self.fail_copy = True
        with self.assertRaises(install.InstallError):
            self.run_preinstall()
        self.assertEqual(set(p.name for p in self.guest_apps.iterdir()), set(APP_NAMES[:2]))
        self.assertIn('write:detach', self.events)
        self.assertNotIn('stage:rebase', self.events)
        self.readonly_factory.assert_called_once()
        self.readback.assert_not_called()
        self.assert_quarantined()
        self.assert_retry_refused_without_overwrite()

    def test_fresh_readonly_verification_failure_quarantines_and_forbids_retry(self):
        self.fail_readback = True
        with self.assertRaises(artifacts.ArtifactError):
            self.run_preinstall()
        self.assertEqual(set(p.name for p in self.guest_apps.iterdir()), set(APP_NAMES))
        self.assertIn('after:detach', self.events)
        self.assertEqual(self.readonly_factory.call_count, 2)
        self.readback.assert_called_once()
        self.assert_quarantined()
        self.assert_retry_refused_without_overwrite()

    def test_initial_readonly_detach_failure_prevents_any_writable_session(self):
        self.fail_detach = 'before'
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall()
        self.readonly_factory.assert_called_once()
        self.writable_factory.assert_not_called()
        self.copier.assert_not_called()
        self.readback.assert_not_called()
        self.assertEqual(list(self.guest_apps.iterdir()), [])
        self.assert_quarantined()
        self.assert_retry_refused_without_overwrite()

    def test_writable_detach_failure_prevents_rebase_and_readback(self):
        self.fail_detach = 'write'
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall()
        self.assertNotIn('stage:rebase', self.events)
        self.readonly_factory.assert_called_once()
        self.readback.assert_not_called()
        self.assert_quarantined()
        self.assert_retry_refused_without_overwrite()

    def test_final_readonly_detach_failure_cannot_create_success_state_or_receipt(self):
        self.fail_detach = 'after'
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall()
        self.readback.assert_called_once()
        self.assertIn('after:detach-failed', self.events)
        self.assertNotIn('after:detach', self.events)
        self.assert_quarantined()
        self.assert_retry_refused_without_overwrite()

    def assert_postwrite_rejected(self):
        with self.assertRaises(disk.OfflineDiskError if self.resize else preinstall.PreinstallError):
            self.run_preinstall()
        self.assertIn('write:detach', self.events)
        self.assertIn('stage:rebase', self.events)
        self.readonly_factory.assert_called_once()
        self.readback.assert_not_called()
        self.assert_quarantined()
        self.assert_retry_refused_without_overwrite()

    def test_replaced_same_size_postwrite_image_cannot_rebase_or_verify(self):
        self.resize = False

        def replace_image():
            image = self.checked(self.stage / 'disk.img')
            replacement = self.checked(self.stage / 'replacement-fixture.img')
            before = disk.signature(image)
            with replacement.open('xb') as stream:
                stream.truncate(before[2])
            # Both source and destination are verified private fixture paths.
            self.checked(image)
            self.checked(replacement)
            os.replace(replacement, image)
            self.assertEqual(image.stat().st_size, before[2])
            self.assertNotEqual(image.stat().st_ino, before[1])

        self.after_write = replace_image
        self.assert_postwrite_rejected()

    def test_resized_postwrite_image_cannot_rebase_or_verify(self):
        self.resize = True

        def resize_image():
            image = self.checked(self.stage / 'disk.img')
            with image.open('r+b') as stream:
                stream.truncate(1024**3 + 1)

        self.after_write = resize_image
        self.assert_postwrite_rejected()

    def test_postwrite_config_change_cannot_rebase_or_verify(self):
        self.resize = False
        self.after_write = lambda: self.checked(self.stage / 'config.json').write_bytes(b'changed config fixture')
        self.assert_postwrite_rejected()

    def test_postwrite_nvram_change_cannot_rebase_or_verify(self):
        self.resize = False
        self.after_write = lambda: self.checked(self.stage / 'nvram.bin').write_bytes(b'changed NVRAM fixture')
        self.assert_postwrite_rejected()

    def test_successful_stage_cannot_be_preinstalled_again(self):
        self.run_preinstall()
        sidecar = self.stage / '.offline-preinstall.complete.json'
        before = (sidecar.stat().st_ino, sidecar.read_bytes())
        calls = (self.copier.call_count, self.readonly_factory.call_count)
        with self.assertRaises(disk.OfflineDiskError):
            self.run_preinstall(evidence_dir=self.root / 'second-evidence')
        self.assertEqual(before, (sidecar.stat().st_ino, sidecar.read_bytes()))
        self.assertEqual(calls, (self.copier.call_count, self.readonly_factory.call_count))
        self.assertFalse((self.root / 'second-evidence').exists())


if __name__ == '__main__':
    unittest.main()
