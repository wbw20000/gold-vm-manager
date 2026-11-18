"""Source-only tiny fixtures: no network, native commands, real apps, disks or VMs."""
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import guest_app_artifacts as artifacts
from guest_app_pins import reviewed_manifests
import preinstall_materials as m


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='material-source-test-')
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.cleanup)
        self.root = self.base / 'materials'
        self.root.mkdir(mode=0o700)
        self.raw = {p: ('tiny-original-' + p).encode() for p in m.PRODUCTS}
        self.manifests = tuple(dataclasses.replace(v, known_sha256=hashlib.sha256(self.raw[v.product]).hexdigest(),
                                                  declared_size_bytes=len(self.raw[v.product]))
                               for v in reviewed_manifests())
        self.quarantine = {}
        self.events = []
        self.downloads = []
        self.extracts = []
        self.tool_calls = []
        for target, name, replacement in ((m, 'capability_report', lambda: {'ready': True}),
                                          (artifacts, 'download_artifact', self.download),
                                          (artifacts, '_tool', self.tool),
                                          (m.offline_payload, 'extract_dmg', self.extract),
                                          (m.offline_payload, 'extract_zip', self.extract),
                                          (m.quarantine, 'ensure', self.ensure),
                                          (m.quarantine, 'read', self.read_quarantine)):
            patcher = patch.object(target, name, side_effect=replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def cleanup(self):
        self.assertEqual(Path(self.tmp.name).resolve(), self.base)
        self.assertTrue(self.base.name.startswith('material-source-test-'))
        self.tmp.cleanup()

    def manager(self, **kwargs):
        return m.MaterialManager(self.root, manifests=self.manifests, **kwargs)

    def private_file(self, path, data):
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o600)
        return path

    def download(self, manifest, cache, **kwargs):
        self.downloads.append((manifest.product, cache, kwargs))
        suffix = '.zip' if manifest.product == 'claudeDesktop' else '.dmg'
        raw = self.private_file(cache / (uuid.uuid4().hex + suffix), self.raw[manifest.product])
        host = 'downloads.claude.ai' if suffix == '.zip' else 'release-assets.githubusercontent.com'
        return artifacts.DownloadReceipt(manifest.artifact_key, str(raw), manifest.known_sha256,
                                         len(self.raw[manifest.product]), True, host)

    def ensure(self, path):
        path = Path(path)
        if path.suffix in ('.dmg', '.zip'):
            evidence = path.parents[2] / 'evidence' / path.parent.name
            # Regression: native quarantine can fail AFTER a completed download;
            # that must never lose its original receipt or invent final_host.
            self.assertTrue((evidence / 'download.json').is_file())
            self.assertEqual(json.loads((evidence / 'download.json').read_text())['artifact_path'], str(path))
        self.quarantine.setdefault(str(path), b'0083;fixture;GoldVMManager;fixture-id')
        return self.quarantine[str(path)]

    def read_quarantine(self, path):
        if str(path) not in self.quarantine:
            raise m.quarantine.QuarantineError('Missing quarantine')
        return self.quarantine[str(path)]

    def bundle(self, app, expectation):
        app.mkdir(mode=0o755)
        (app / 'Contents').mkdir(mode=0o755)
        for directory in ('Resources', 'MacOS', 'Frameworks'):
            (app / 'Contents' / directory).mkdir(mode=0o755)
        values = {'CFBundleIdentifier': expectation.bundle_identifiers[0],
                  'CFBundleName': expectation.bundle_names[0],
                  'CFBundleExecutable': expectation.executable_names[0],
                  'CFBundleShortVersionString': expectation.short_versions[0],
                  'CFBundleVersion': expectation.bundle_versions[0], 'CFBundlePackageType': 'APPL'}
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(values))
        (app / 'Contents/Resources/fixture.txt').write_bytes(b'complete tiny fixture')
        executable = app / 'Contents/MacOS' / expectation.executable_names[0]
        executable.write_bytes(b'not executable machine code; native tools mocked')
        executable.chmod(0o755)
        for relative in expectation.required_paths:
            target = app / relative
            if target.exists():
                continue
            if target.suffix == '.framework':
                target.mkdir(mode=0o755)
                (target / 'fixture').write_bytes(b'framework bytes')
            else:
                target.write_bytes(b'required resource')
        return app

    def extract(self, manifest, receipt, destination, evidence):
        self.extracts.append((manifest.product, destination, evidence))
        self.assertFalse(destination.exists())
        self.assertFalse(evidence.exists())
        destination.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        return tuple(self.bundle(destination / app.name, app) for app in manifest.expected_apps)

    def tool(self, argv, cwd):
        self.tool_calls.append(argv)
        stdout, stderr = '', ''
        if argv[0] == '/usr/bin/lipo':
            stdout = 'arm64 x86_64\n'
        else:
            name = Path(argv[-1]).name
            manifest, app = next((manifest, app) for manifest in self.manifests
                                 for app in manifest.expected_apps if app.name == name)
            if '--display' in argv:
                stderr = 'TeamIdentifier=%s\nIdentifier=%s\n' % (manifest.vendor_team_ids[0], app.bundle_identifiers[0])
            elif argv[0] == '/usr/sbin/spctl':
                stderr = '%s: accepted\nsource=Notarized Developer ID\n' % name
        return {'argv': argv, 'returncode': 0, 'stdout': stdout, 'stderr': stderr}

    def prepared(self):
        manager = self.manager(progress=self.events.append)
        materials = manager.prepare()
        attempt = self.root / 'attempts' / manager.last_attempt_id
        return manager, materials, attempt

    def assert_rejected_load(self, manager):
        with self.assertRaises(m.MaterialPreparationError):
            manager.load(manager.last_attempt_id)

    def test_complete_preparation_and_durable_reload_reverify_sources(self):
        manager, materials, attempt = self.prepared()
        self.assertEqual(tuple(v.manifest.product for v in materials), m.PRODUCTS)
        self.assertEqual(tuple(p.name for v in materials for p in v.app_paths), m.APP_NAMES)
        self.assertEqual(len(self.downloads), 3)
        self.assertEqual(len(self.extracts), 3)
        # All four apps have architecture/signing/notarization checked twice.
        self.assertEqual(len(self.tool_calls), 4 * 4 * 2)
        calls = len(self.tool_calls)
        reloaded = self.manager().load(manager.last_attempt_id)
        self.assertEqual(materials, reloaded)
        self.assertEqual(len(self.tool_calls), calls + 4 * 4)
        self.assertEqual(len(self.downloads), 3)
        self.assertEqual(manager.summary(attempt.name)['status'], 'prepared')
        self.assertFalse(manager.summary(attempt.name)['guest_installation_performed'])
        self.assertEqual(self.events[-1]['stage'], 'prepared')
        for product in m.PRODUCTS:
            evidence = attempt / 'evidence' / product
            self.assertEqual(stat.S_IMODE((evidence / 'download.json').stat().st_mode), 0o600)
            self.assertTrue((evidence / 'material.json').is_file())

    def test_default_manifests_are_reviewed_catalog_not_latest_discovery(self):
        manager = m.MaterialManager(self.root)
        self.assertEqual(manager.manifests, reviewed_manifests())
        self.assertFalse(self.downloads)

    def test_receipt_durable_before_quarantine_failure_and_no_lost_host(self):
        manager = self.manager()
        with patch.object(m.quarantine, 'ensure', side_effect=RuntimeError('https://signed.invalid/?token=secret')):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^quarantining-failed$'):
                manager.prepare()
        attempt = self.root / 'attempts' / manager.last_attempt_id
        receipt = json.loads((attempt / 'evidence/ccbaga/download.json').read_text())
        self.assertEqual(receipt['final_host'], 'release-assets.githubusercontent.com')
        self.assertEqual(manager.summary(manager.last_attempt_id)['status'], 'failed-retained')
        self.assertTrue(Path(receipt['artifact_path']).is_file())
        self.assertFalse(self.extracts)
        self.assert_rejected_load(manager)

    def test_failed_partial_is_retained_not_adopted_or_resumed(self):
        manager = self.manager(progress=self.events.append)
        def fail(manifest, cache, **kwargs):
            self.private_file(cache / ('a' * 32 + '.partial'), b'prefix')
            raise RuntimeError('https://user:password@cdn.invalid/?signed=SECRET')
        with patch.object(artifacts, 'download_artifact', side_effect=fail):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^downloading-failed$') as caught:
                manager.prepare()
        attempt_id = manager.last_attempt_id
        self.assertEqual(caught.exception.attempt_id, attempt_id)
        self.assertFalse(manager.summary(attempt_id)['resume_supported'])
        with self.assertRaisesRegex(m.MaterialPreparationError, '^resume-unavailable-retained-attempt$'):
            manager.resume(attempt_id)
        serialized = json.dumps(self.events) + json.dumps(manager.summary(attempt_id))
        self.assertNotIn('SECRET', serialized)
        self.assertNotIn('password', serialized)
        old = self.root / 'attempts' / attempt_id / 'cache/ccbaga' / ('a' * 32 + '.partial')
        self.assertEqual(old.read_bytes(), b'prefix')
        # A new explicit prepare is a fresh complete attempt, not partial adoption.
        manager.prepare()
        self.assertNotEqual(manager.last_attempt_id, attempt_id)
        self.assertEqual(old.read_bytes(), b'prefix')

    def test_cancellation_after_download_preserves_receipt_and_stops_extraction(self):
        current = {'stage': ''}
        def progress(event):
            current['stage'] = event['stage']
        manager = self.manager(progress=progress, cancelled=lambda: current['stage'] == 'quarantining')
        with self.assertRaisesRegex(m.MaterialPreparationError, '^preparation-cancelled$'):
            manager.prepare()
        self.assertEqual(len(self.downloads), 1)
        self.assertFalse(self.extracts)
        self.assertEqual(manager.summary(manager.last_attempt_id)['status'], 'cancelled-retained')
        self.assertTrue((self.root / 'attempts' / manager.last_attempt_id / 'evidence/ccbaga/download.json').exists())

    def test_cancelled_reload_does_not_rewrite_completed_attempt(self):
        manager, _, attempt = self.prepared()
        before = (attempt / 'complete.json').read_bytes()
        calls = len(self.tool_calls)
        reader = self.manager(cancelled=lambda: True, progress=self.events.append)
        with self.assertRaisesRegex(m.MaterialPreparationError, '^preparation-cancelled$'):
            reader.load(manager.last_attempt_id)
        self.assertEqual(len(self.tool_calls), calls)
        self.assertEqual((attempt / 'complete.json').read_bytes(), before)
        self.assertEqual(reader.summary(attempt.name)['status'], 'prepared')
        self.assertEqual(self.events[-1]['attempt_id'], attempt.name)
        self.assertFalse((attempt / 'failure.json').exists())

    def test_cancellation_before_network_and_observer_errors_are_sanitized(self):
        def observer(event):
            raise RuntimeError('private credentials')
        manager = self.manager(progress=observer, cancelled=lambda: True)
        with self.assertRaisesRegex(m.MaterialPreparationError, '^preparation-cancelled$'):
            manager.prepare()
        self.assertFalse(self.downloads)

    def test_explicit_credential_free_loopback_is_forwarded_not_recorded(self):
        manager = self.manager(loopback_proxy='http://127.0.0.1:19080', deadline_seconds=99)
        manager.prepare()
        self.assertTrue(all(call[2] == {'loopback_proxy': 'http://127.0.0.1:19080', 'deadline_seconds': 99}
                            for call in self.downloads))
        self.assertNotIn('19080', json.dumps(manager.summary(manager.last_attempt_id)))

    def test_untrusted_proxy_inputs_rejected_without_downloads(self):
        for proxy in ('http://localhost:19080', 'http://user:pass@127.0.0.1:19080',
                      'http://127.0.0.1:19080/path', 'https://127.0.0.1:19080', 'http://example.com:80'):
            with self.subTest(proxy=proxy), self.assertRaises(m.MaterialPreparationError):
                self.manager(loopback_proxy=proxy)
        self.assertFalse(self.downloads)

    def test_incomplete_unreviewed_or_unpinned_manifest_sets_rejected(self):
        cases = (self.manifests[:2], self.manifests[::-1], self.manifests + self.manifests[:1],
                 (dataclasses.replace(self.manifests[0], vendor_team_ids=()),) + self.manifests[1:],
                 self.manifests[:2] + (dataclasses.replace(self.manifests[2], known_sha256=None,
                                                                         allow_unpinned_sha256=True),))
        for values in cases:
            with self.subTest(values=len(values)), self.assertRaises(m.MaterialPreparationError):
                m.MaterialManager(self.root, manifests=values)
        self.assertFalse(self.downloads)

    def test_missing_relative_nonprivate_symlink_and_foreign_root_rejected(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for root in ('relative', self.base / 'missing', alias):
            with self.subTest(root=str(root)), self.assertRaises(m.MaterialPreparationError):
                m.MaterialManager(root, manifests=self.manifests)
        self.root.chmod(0o755)
        with self.assertRaises(m.MaterialPreparationError):
            self.manager()
        self.root.chmod(0o700)
        uid = os.getuid()
        with patch.object(m.os, 'getuid', return_value=uid + 1), self.assertRaises(m.MaterialPreparationError):
            self.manager()

    def test_arbitrary_cache_or_receipts_never_adopted(self):
        self.private_file(self.root / 'old-cache.dmg', b'bytes')
        with self.assertRaises(m.MaterialPreparationError):
            self.manager()
        self.assertFalse(self.downloads)

    def test_concurrent_manager_operation_refused(self):
        manager = self.manager()
        other = self.manager()
        with manager._lock(), self.assertRaisesRegex(m.MaterialPreparationError, '^material-manager-busy$'):
            other.prepare()
        self.assertFalse(self.downloads)

    def test_reused_attempt_output_is_never_overwritten(self):
        manager, _, attempt = self.prepared()
        before = (attempt / 'complete.json').read_bytes()
        with patch.object(m.uuid, 'uuid4', return_value=SimpleNamespace(hex=attempt.name)):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^attempt-output-already-exists-or-unsafe$'):
                manager.prepare()
        self.assertEqual((attempt / 'complete.json').read_bytes(), before)
        self.assertFalse((attempt / 'failure.json').exists())

    def test_modified_raw_file_rejected_even_with_valid_saved_records(self):
        manager, materials, _ = self.prepared()
        Path(materials[0].download.artifact_path).write_bytes(b'changed raw bytes')
        self.assert_rejected_load(manager)

    def test_modified_bundle_bytes_rejected_even_if_native_checks_accept(self):
        manager, materials, _ = self.prepared()
        (materials[0].app_paths[0] / 'Contents/Resources/fixture.txt').write_bytes(b'changed source')
        self.assert_rejected_load(manager)

    def test_modified_manifest_and_receipt_records_refused(self):
        manager, _, attempt = self.prepared()
        receipt = attempt / 'evidence/ccbaga/download.json'
        value = json.loads(receipt.read_text())
        value['final_host'] = 'https://cdn.invalid/?signed=secret'
        receipt.write_text(json.dumps(value))
        self.assert_rejected_load(manager)

    def test_signed_binding_edit_is_detected(self):
        manager, _, attempt = self.prepared()
        record = attempt / 'evidence/ccbaga/material.json'
        value = json.loads(record.read_text())
        value['data']['trees'][0]['sha256'] = 'a' * 64
        record.write_text(json.dumps(value))
        self.assert_rejected_load(manager)

    def test_quarantine_changes_are_rejected_not_repaired_on_reload(self):
        manager, materials, _ = self.prepared()
        self.quarantine[str(materials[0].app_paths[0])] = b'altered-quarantine'
        with patch.object(m.quarantine, 'ensure', side_effect=AssertionError('must never repair')):
            self.assert_rejected_load(manager)

    def test_download_symlink_and_signed_host_never_reach_quarantine(self):
        manager = self.manager()
        outside = self.private_file(self.base / 'foreign.dmg', self.raw['ccbaga'])
        def linked(manifest, cache, **kwargs):
            target = cache / ('b' * 32 + '.dmg')
            target.symlink_to(outside)
            return artifacts.DownloadReceipt(manifest.artifact_key, str(target), manifest.known_sha256,
                                             len(self.raw[manifest.product]), True, 'github.com')
        with patch.object(artifacts, 'download_artifact', side_effect=linked):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^symlink-path-refused$'):
                manager.prepare()
        self.assertFalse(self.quarantine)
        def signed_host(manifest, cache, **kwargs):
            return dataclasses.replace(self.download(manifest, cache, **kwargs),
                                       final_host='https://cdn.invalid/?signature=secret')
        with patch.object(artifacts, 'download_artifact', side_effect=signed_host):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^unbound-download-receipt$'):
                manager.prepare()
        self.assertFalse(self.quarantine)

    def test_record_symlink_and_unsafe_parent_modes_rejected(self):
        manager = self.manager()
        alias = self.base / 'lock-alias'
        alias.symlink_to(self.root / 'manager.lock')
        with self.assertRaisesRegex(m.MaterialPreparationError, '^symlink-path-refused$'):
            m._read(alias)
        self.base.chmod(0o777)
        try:
            with self.assertRaises(m.MaterialPreparationError):
                manager.prepare()
        finally:
            self.base.chmod(0o700)
        self.assertFalse(self.downloads)

    def test_partial_initialization_is_retained_not_unreportable(self):
        manager = self.manager()
        mkdir = m._mkdir
        def fail_staging(path):
            if path.name == 'staging':
                raise OSError('private error details')
            return mkdir(path)
        with patch.object(m, '_mkdir', side_effect=fail_staging):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^initializing-failed$'):
                manager.prepare()
        self.assertEqual(manager.summary(manager.last_attempt_id)['status'], 'failed-retained')
        self.assert_rejected_load(manager)

    def test_raw_hardlinks_and_permissions_rejected(self):
        manager, materials, _ = self.prepared()
        raw = Path(materials[0].download.artifact_path)
        raw.chmod(0o644)
        self.assert_rejected_load(manager)
        raw.chmod(0o600)
        os.link(str(raw), str(self.base / 'raw-hardlink'))
        self.assert_rejected_load(manager)

    def test_metadata_hardlinks_and_symlinks_rejected(self):
        manager, _, attempt = self.prepared()
        record = attempt / 'complete.json'
        os.link(str(record), str(self.base / 'record-hardlink'))
        self.assert_rejected_load(manager)
        # A path outside the owned store is never an attempt selector.
        with self.assertRaises(m.MaterialPreparationError):
            manager.load(str(attempt))

    def test_bundle_hardlinks_and_group_writable_paths_rejected(self):
        manager, materials, _ = self.prepared()
        source = materials[0].app_paths[0] / 'Contents/Resources/fixture.txt'
        source.chmod(0o666)
        self.assert_rejected_load(manager)
        source.chmod(0o644)
        os.link(str(source), str(self.base / 'source-hardlink'))
        self.assert_rejected_load(manager)

    def test_bundle_escaping_links_and_incomplete_sets_rejected(self):
        manager, materials, _ = self.prepared()
        (materials[0].app_paths[0] / 'Contents/escape').symlink_to('/etc/passwd')
        self.assert_rejected_load(manager)

    def test_internal_framework_links_preserved_and_verified(self):
        def with_link(manifest, receipt, destination, evidence):
            apps = self.extract(manifest, receipt, destination, evidence)
            for app in apps:
                (app / 'Contents/Resources/link').symlink_to('fixture.txt')
            return apps
        with patch.object(m.offline_payload, 'extract_dmg', side_effect=with_link), \
                patch.object(m.offline_payload, 'extract_zip', side_effect=with_link):
            manager, materials, _ = self.prepared()
        self.assertEqual(manager.load(manager.last_attempt_id), materials)

    def test_reused_extraction_destination_refused(self):
        manager = self.manager()
        def poison(event):
            if event['stage'] == 'extracting':
                (self.root / 'attempts' / event['attempt_id'] / 'staging' / event['product']).mkdir(mode=0o700)
        manager.progress = poison
        with self.assertRaisesRegex(m.MaterialPreparationError, '^reused-extraction-output$'):
            manager.prepare()
        self.assertFalse(self.extracts)

    def test_wrong_or_incomplete_extraction_paths_never_accepted(self):
        def missing(manifest, receipt, destination, evidence):
            return self.extract(manifest, receipt, destination, evidence)[:1]
        with patch.object(m.offline_payload, 'extract_dmg', side_effect=missing):
            manager = self.manager()
            with self.assertRaisesRegex(m.MaterialPreparationError, '^incomplete-or-unexpected-source-set$'):
                manager.prepare()
        self.assert_rejected_load(manager)

    def test_unexpected_extra_staged_bundle_rejected(self):
        manager, materials, _ = self.prepared()
        (materials[0].staging_root / 'Extra.app').mkdir()
        self.assert_rejected_load(manager)

    def test_pending_attempt_never_automatically_promoted(self):
        manager = self.manager()
        attempt_id = uuid.uuid4().hex
        attempt = m._mkdir(self.root / 'attempts' / attempt_id)
        for name in ('cache', 'staging', 'evidence'):
            m._mkdir(attempt / name)
        manager._record(attempt / 'attempt.json', manager._start(attempt_id))
        self.assertEqual(manager.summary(attempt_id)['status'], 'interrupted-retained')
        with self.assertRaisesRegex(m.MaterialPreparationError, '^retained-attempt-not-installable$'):
            manager.load(attempt_id)

    def test_changed_review_catalog_does_not_load_old_materials(self):
        manager, _, _ = self.prepared()
        changed = (dataclasses.replace(self.manifests[0], vendor_team_ids=('AAAAAAAAAA',)),) + self.manifests[1:]
        other = m.MaterialManager(self.root, manifests=changed)
        with self.assertRaisesRegex(m.MaterialPreparationError, '^attempt-manifest-or-store-mismatch$'):
            other.load(manager.last_attempt_id)

    def test_native_signature_rejection_retains_failure(self):
        manager = self.manager()
        with patch.object(artifacts, '_tool', side_effect=artifacts.ArtifactError('verification-tool-rejected')):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^verifying-failed$'):
                manager.prepare()
        self.assert_rejected_load(manager)

    def test_full_set_recheck_catches_changes_to_earlier_product(self):
        manager = self.manager()
        def corrupt(event):
            if event['stage'] == 'verifying-complete-set':
                source = self.root / 'attempts' / event['attempt_id'] / 'staging/ccbaga/CCBaga-A.app/Contents/Resources/fixture.txt'
                source.write_bytes(b'changed during later product processing')
        manager.progress = corrupt
        with self.assertRaisesRegex(m.MaterialPreparationError, '^modified-source-or-evidence$'):
            manager.prepare()
        self.assert_rejected_load(manager)

    def test_capability_gate_blocks_before_any_download(self):
        manager = self.manager()
        with patch.object(m, 'capability_report', return_value={'ready': False}):
            with self.assertRaisesRegex(m.MaterialPreparationError, '^unsupported-material-capability$'):
                manager.prepare()
        self.assertIsNone(manager.last_attempt_id)
        self.assertFalse(self.downloads)


class CapabilitiesTests(unittest.TestCase):
    def report(self, system='Darwin', machine='arm64', version='26.6.2', schema='macos-26.6.2', available=True):
        with patch.object(m.platform, 'system', return_value=system), \
                patch.object(m.platform, 'machine', return_value=machine), \
                patch.object(m.platform, 'mac_ver', return_value=(version, (), '')), \
                patch.object(m.offline_volume, 'SCHEMA', schema), \
                patch.object(m, '_tool_ready', return_value=available):
            return m.capability_report()

    def test_only_explicit_tested_apple_silicon_schema_tuple_is_supported(self):
        self.assertTrue(self.report()['ready'])
        for changes in ({'system': 'Linux'}, {'machine': 'x86_64'}, {'version': '26.6.3'},
                        {'version': '15.0'}, {'schema': 'unknown'}, {'available': False}):
            with self.subTest(changes=changes):
                self.assertFalse(self.report(**changes)['ready'])

    def test_unknown_environment_values_cannot_leak_credentials(self):
        report = self.report(version='https://user:pass@host/?signed=SECRET')
        self.assertFalse(report['ready'])
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertIn('verified_gvproxy_runtime', report['parent_interfaces_not_assessed'])
        self.assertIn('reviewed_ipsw_restore_input', report['parent_interfaces_not_assessed'])


if __name__ == '__main__':
    unittest.main()
