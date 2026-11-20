"""Offline tar/package fixtures only; tools mocked, never run third-party code."""
from contextlib import contextmanager, ExitStack
import dataclasses
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import host_artifacts
import host_tools as tools
import install_app

REAL_TOOL = tools._tool


class HostToolFixtures(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-host-tools-fixture-')).resolve()
        self.root.chmod(0o700)
        self.expected = self.root
        self.stack = ExitStack()
        self.addCleanup(self.cleanup)
        self.native = self.stack.enter_context(mock.patch.object(tools, '_tool', side_effect=self.tool))
        self.no_run = self.stack.enter_context(mock.patch('subprocess.run', side_effect=AssertionError('real native forbidden')))
        self.no_spawn = self.stack.enter_context(mock.patch('subprocess.Popen', side_effect=AssertionError('no process launch')))
        self.quarantine = self.stack.enter_context(mock.patch.object(tools.quarantine_policy, 'propagate'))
        self.sdk = self.root / 'sdk'
        self.sdk.mkdir(mode=0o700)
        self.os_temp = self.root / 'fixture-os-user-temp'
        self.os_temp.mkdir(mode=0o700)
        self.system_temp = self.stack.enter_context(
            mock.patch.object(tools, '_system_compiler_temp', return_value=self.os_temp))

    def cleanup(self):
        self.stack.close()
        self.assertEqual(self.root.resolve(strict=True), self.expected)
        self.assertTrue(self.root.name.startswith('gold-host-tools-fixture-'))
        self.assertFalse(self.root.is_symlink())
        self.assertEqual(self.root.stat().st_uid, os.getuid())
        shutil.rmtree(str(self.root))

    def tool(self, argv, timeout=120, build_directory=None):
        self.assertIn(argv[0], ('/usr/bin/xcrun', '/usr/bin/xcode-select', '/usr/bin/python3',
                               '/usr/bin/ruby', '/usr/bin/codesign', '/usr/bin/lipo', '/usr/sbin/spctl'))
        out, err = b'', b''
        if argv[0] == '/usr/bin/xcrun' and 'swiftc' in argv:
            target = Path(argv[argv.index('-o') + 1])
            self.assertFalse(target.exists())
            target.write_bytes(b'inert compiled-project fixture; never execute')
            target.chmod(0o700)
            self.assertNotIn('GOLD_VPN_BOOTSTRAP_FIXTURE', argv)
        elif argv[0] == '/usr/bin/xcrun':
            out = (str(self.sdk) + '\n').encode()
        elif argv[0] == '/usr/bin/xcode-select':
            out = (str(self.sdk) + '\n').encode()
        elif argv[0] == '/usr/bin/lipo':
            out = b'arm64\n'
        elif '--entitlements' in argv and '--display' in argv:
            out = plistlib.dumps({'com.apple.security.virtualization': True}) if Path(argv[-1]).name == 'CleanVMInstaller' else b''
        elif '--display' in argv:
            if Path(argv[-1]).name in ('tart.app', 'Explicit Tart.app'):
                err = (f'Identifier={tools.TART_IDENTIFIER}\nTeamIdentifier={tools.TART_TEAM}\n'
                       f'Authority=Developer ID Application: Cirrus Labs, Inc. ({tools.TART_TEAM})\n').encode()
            else:
                err = b'Signature=adhoc\nTeamIdentifier=not set\n'
        elif argv[0] == '/usr/sbin/spctl':
            err = (argv[-1] + ': accepted\nsource=Notarized Developer ID\n').encode()
        return SimpleNamespace(returncode=0, stdout=out, stderr=err)

    def bundle(self, name='Explicit Tart.app'):
        app = self.root / name
        (app / 'Contents' / 'MacOS').mkdir(mode=0o700, parents=True)
        (app / 'Contents' / '_CodeSignature').mkdir(mode=0o700)
        info = {'CFBundleIdentifier': tools.TART_IDENTIFIER, 'CFBundleExecutable': 'tart',
                'CFBundleShortVersionString': tools.TART_VERSION, 'CFBundlePackageType': 'APPL'}
        (app / 'Contents' / 'Info.plist').write_bytes(plistlib.dumps(info))
        (app / 'Contents' / '_CodeSignature' / 'CodeResources').write_bytes(b'inert sealed resource fixture')
        binary = app / 'Contents' / 'MacOS' / 'tart'
        binary.write_bytes(b'inert Tart fixture; never execute')
        binary.chmod(0o700)
        return app

    def tar(self, entries):
        path = self.root / ('archive-' + str(len(list(self.root.glob('archive-*')))) + '.tar.gz')
        with tarfile.open(str(path), 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            for name, kind, content in entries:
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if kind in ('dir', 'symlink') or name.endswith('/MacOS/tart') else 0o644
                if kind == 'dir':
                    member.type = tarfile.DIRTYPE
                elif kind == 'symlink':
                    member.type, member.linkname, member.mode = tarfile.SYMTYPE, content, 0o777
                elif kind == 'hardlink':
                    member.type, member.linkname = tarfile.LNKTYPE, content
                elif kind == 'device':
                    member.type = tarfile.CHRTYPE
                else:
                    member.size = len(content)
                archive.addfile(member, io.BytesIO(content) if kind == 'file' else None)
        path.chmod(0o600)
        return path

    def valid_entries(self):
        info = {'CFBundleIdentifier': tools.TART_IDENTIFIER, 'CFBundleExecutable': 'tart',
                'CFBundleShortVersionString': tools.TART_VERSION, 'CFBundlePackageType': 'APPL'}
        return [('tart.app', 'dir', None), ('tart.app/Contents', 'dir', None),
                ('tart.app/Contents/Info.plist', 'file', plistlib.dumps(info)),
                ('tart.app/Contents/MacOS/tart', 'file', b'inert binary fixture'),
                ('tart.app/Contents/_CodeSignature/CodeResources', 'file', b'inert sealed signature fixture')]

    def use_archive(self, path):
        @contextmanager
        def fixture_source(receipt):
            # One scoped trusted-source seam; immutable production pins unchanged.
            with path.open('rb') as stream:
                yield path, stream, hashlib.sha256(path.read_bytes()).hexdigest()
        return mock.patch.object(tools, '_archive_source', side_effect=fixture_source)

    def ensure_archive(self, entries):
        archive = self.tar(entries)
        with self.use_archive(archive):
            return tools.ensure_tart(self.root / 'tools', artifact_receipt=object())

    def test_existing_tart_is_explicit_and_native_verified_without_execution(self):
        app = self.bundle()
        receipt = tools.ensure_tart(self.root / 'tools', existing_tart=app / 'Contents' / 'MacOS' / 'tart')
        self.assertEqual(receipt.app_path, app)
        self.assertEqual(receipt.version, '2.41.1')
        self.assertEqual(receipt.team_id, '9M2P8L4D89')
        self.assertTrue(receipt.notarized)
        self.assertFalse(receipt.execution_performed)
        self.assertEqual(receipt.source_kind, 'explicit-existing-native-verified')
        self.assertEqual(receipt.archive_sha256, '')
        self.assertTrue(receipt.receipt_path.is_file())
        self.quarantine.assert_not_called()
        self.no_run.assert_not_called()
        self.no_spawn.assert_not_called()
        commands = [call[0][0] for call in self.native.call_args_list]
        verification = [a for a in commands if a[0].endswith('codesign') and '--verify' in a][0]
        requirement = verification[verification.index('-R') + 1]
        self.assertIn('anchor apple generic', requirement)
        self.assertIn('certificate leaf[subject.OU] = "9M2P8L4D89"', requirement)
        self.assertIn('--deep', verification)
        self.assertIn('--strict', verification)
        self.assertFalse(any('--sign' in a or '--add' in a for a in commands))

    def test_official_tart_authority_comma_and_exact_legacy_variant(self):
        app = self.bundle()
        # Default fixture uses the actual observed Cirrus Labs, Inc. authority.
        tools.ensure_tart(self.root / 'tools', existing_tart=app)
        def legacy(argv, timeout=120):
            result = self.tool(argv, timeout)
            result.stderr = result.stderr.replace(b'Cirrus Labs, Inc.', b'Cirrus Labs Inc.')
            return result
        self.native.side_effect = legacy
        tools.ensure_tart(self.root / 'tools', existing_tart=app)
        def wrong_suffix(argv, timeout=120):
            result = self.tool(argv, timeout)
            result.stderr = result.stderr.replace(b'Cirrus Labs, Inc.', b'Cirrus Labs, Inc. Unreviewed')
            return result
        self.native.side_effect = wrong_suffix
        with self.assertRaisesRegex(tools.HostToolError, 'tart-signing-identity-mismatch'):
            tools.ensure_tart(self.root / 'tools', existing_tart=app)
        self.no_run.assert_not_called()
        self.no_spawn.assert_not_called()

    def test_exactly_one_explicit_tart_source_required(self):
        for kwargs in ({}, {'existing_tart': self.root, 'artifact_receipt': object()}):
            with self.assertRaisesRegex(tools.HostToolError, 'choose-exactly-one'):
                tools.ensure_tart(self.root / 'tools', **kwargs)
        self.native.assert_not_called()

    def test_wrong_tart_version_arch_team_and_notarization_fail(self):
        app = self.bundle()
        plist = app / 'Contents' / 'Info.plist'
        original = plist.read_bytes()
        value = plistlib.loads(original)
        value['CFBundleShortVersionString'] = '2.41.0'
        plist.write_bytes(plistlib.dumps(value))
        with self.assertRaisesRegex(tools.HostToolError, 'unexpected-tart-bundle'):
            tools.ensure_tart(self.root / 'tools', existing_tart=app)
        plist.write_bytes(original)
        def wrong(argv, timeout=120):
            result = self.tool(argv, timeout)
            if argv[0].endswith('lipo'):
                result.stdout = b'x86_64\n'
            return result
        self.native.side_effect = wrong
        with self.assertRaisesRegex(tools.HostToolError, 'arm64-required'):
            tools.ensure_tart(self.root / 'tools', existing_tart=app)
        def unsigned(argv, timeout=120):
            result = self.tool(argv, timeout)
            if '--display' in argv:
                result.stderr = b'Identifier=com.github.cirruslabs.tart\nTeamIdentifier=WRONGTEAM0\n'
            return result
        self.native.side_effect = unsigned
        with self.assertRaisesRegex(tools.HostToolError, 'signing-identity'):
            tools.ensure_tart(self.root / 'tools', existing_tart=app)
        def unnotarized(argv, timeout=120):
            result = self.tool(argv, timeout)
            if argv[0].endswith('spctl'):
                result.stderr = b'fixture: accepted\nsource=Developer ID\n'
            return result
        self.native.side_effect = unnotarized
        with self.assertRaisesRegex(tools.HostToolError, 'notarization-required'):
            tools.ensure_tart(self.root / 'tools', existing_tart=app)

    def test_controlled_archive_extraction_preserves_signature_files_and_quarantine(self):
        receipt = self.ensure_archive(self.valid_entries())
        self.assertEqual(receipt.source_kind, 'pinned-public-archive')
        self.assertEqual((receipt.app_path / 'Contents' / '_CodeSignature' / 'CodeResources').read_bytes(),
                         b'inert sealed signature fixture')
        self.quarantine.assert_called_once()
        self.assertEqual(self.quarantine.call_args[0][1], receipt.app_path)
        self.assertTrue((receipt.app_path.parent / 'extraction.json').exists())

    def test_reviewed_archive_accepts_only_a_plain_bounded_license_sibling(self):
        receipt = self.ensure_archive(self.valid_entries() + [('LICENSE', 'file', b'public license fixture')])
        license_path = receipt.app_path.parent / 'LICENSE'
        self.assertEqual(license_path.read_bytes(), b'public license fixture')
        self.assertFalse(license_path.stat().st_mode & 0o111)
        self.assertFalse((receipt.app_path / 'LICENSE').exists())
        self.assertFalse(receipt.execution_performed)

    def test_license_exception_does_not_accept_links_directories_aliases_or_other_siblings(self):
        refused = [
            [('LICENSE', 'dir', None)], [('LICENSE', 'symlink', 'tart.app')],
            [('LICENSE', 'hardlink', 'tart.app/Contents/Info.plist')],
            [('LICENSE', 'file', b'')], [('LICENSE', 'file', b'x' * (128 * 1024 + 1))],
            [('LICENSE', 'file', b'x'), ('LICENSE', 'file', b'y')],
            [('LICENSE/file', 'file', b'x')], [('license', 'file', b'x')],
            [('NOTICE', 'file', b'x')],
        ]
        for items in refused:
            with self.subTest(name=items[0][0], kind=items[0][1]), self.assertRaises(tools.HostToolError):
                self.ensure_archive(self.valid_entries() + items)
        self.assertFalse(list((self.root / 'tools').glob('*/tart.json')))
        self.quarantine.assert_not_called()

    def test_internal_framework_symlinks_preserved_not_followed_during_writes(self):
        entries = self.valid_entries() + [
            ('tart.app/Contents/Frameworks/F.framework/Versions/A/Resources/item', 'file', b'resource'),
            ('tart.app/Contents/Frameworks/F.framework/Versions/Current', 'symlink', 'A'),
            ('tart.app/Contents/Frameworks/F.framework/Resources', 'symlink', 'Versions/Current/Resources')]
        receipt = self.ensure_archive(entries)
        link = receipt.app_path / 'Contents' / 'Frameworks' / 'F.framework' / 'Resources'
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(str(link)), 'Versions/Current/Resources')

    def test_tar_traversal_alias_multi_root_special_hardlink_and_external_links_refused(self):
        bad = [('../outside', 'file', b'x'), ('/absolute', 'file', b'x'),
               ('./tart.app/file', 'file', b'x'), ('tart.app//file', 'file', b'x'),
               ('other.app/file', 'file', b'x'), ('tart.app/device', 'device', None),
               ('tart.app/hard', 'hardlink', 'tart.app/Contents/Info.plist'),
               ('tart.app/outside', 'symlink', '../../outside'),
               ('tart.app/absolute', 'symlink', '/private/secret'),
               ('tart.app/e\u0301', 'file', b'x')]
        for entry in bad:
            with self.subTest(entry=entry), self.assertRaises(tools.HostToolError):
                self.ensure_archive(self.valid_entries() + [entry])
        self.assertFalse(list((self.root / 'tools').glob('*/tart.json')))
        self.quarantine.assert_not_called()
        self.assertFalse((self.root / 'outside').exists())

    def test_tar_case_collision_duplicate_symlink_parent_and_cycle_refused(self):
        cases = [[('tart.app/contents/new', 'file', b'x')],
                 [('tart.app/Contents/Info.plist', 'file', b'other')],
                 [('tart.app/link', 'symlink', 'Contents'), ('tart.app/link/file', 'file', b'x')],
                 [('tart.app/a', 'symlink', 'b'), ('tart.app/b', 'symlink', 'a')]]
        for extra in cases:
            with self.subTest(extra=extra), self.assertRaises(tools.HostToolError):
                self.ensure_archive(self.valid_entries() + extra)
        self.quarantine.assert_not_called()

    def test_tar_limits_are_enforced_before_extraction(self):
        with mock.patch.object(tools, 'MAX_ENTRIES', 2):
            with self.assertRaisesRegex(tools.HostToolError, 'too-many-tar-entries'):
                self.ensure_archive(self.valid_entries())
        with mock.patch.object(tools, 'MAX_FILE_BYTES', 2):
            with self.assertRaisesRegex(tools.HostToolError, 'tar-file-too-large'):
                self.ensure_archive(self.valid_entries())
        for attempt in (self.root / 'tools').iterdir():
            self.assertFalse((attempt / 'tart.app').exists())

    def test_unreviewed_receipt_refused_without_native_trust_or_extraction(self):
        with self.assertRaisesRegex(tools.HostToolError, 'host-artifact-receipt-required'):
            tools.ensure_tart(self.root / 'tools', artifact_receipt={})
        self.native.assert_not_called()
        self.quarantine.assert_not_called()
        self.assertEqual(host_artifacts.SPECS['tart'].sha256,
                         'e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2')

    def test_partial_failed_extractions_retained_and_no_retry_or_overwrite(self):
        archive = self.tar(self.valid_entries())
        self.quarantine.side_effect = RuntimeError('secret-native-details')
        with self.use_archive(archive):
            with self.assertRaisesRegex(tools.HostToolError, '^tart-preparation-failed$'):
                tools.ensure_tart(self.root / 'tools', artifact_receipt=object())
        app = next((self.root / 'tools').glob('*/tart.app'))
        before = (app / 'Contents' / 'MacOS' / 'tart').stat()
        self.quarantine.side_effect = None
        with self.use_archive(archive):
            result = tools.ensure_tart(self.root / 'tools', artifact_receipt=object())
        self.assertNotEqual(app, result.app_path)
        self.assertEqual((app / 'Contents' / 'MacOS' / 'tart').stat().st_ino, before.st_ino)

    def test_compiler_outputs_only_the_restore_helper_with_its_exact_entitlement(self):
        with mock.patch.object(tools, 'source_prerequisites', return_value={'sdk_path': str(self.sdk)}):
            (clean,) = tools.compile_helpers(self.root / 'build')
        self.assertEqual(clean.name, 'CleanVMInstaller')
        self.assertEqual(stat.S_IMODE(clean.stat().st_mode), 0o700)
        self.assertEqual(sorted(p.name for p in clean.parent.iterdir() if not p.name.startswith(('module-cache', '.'))),
                         ['CleanVMInstaller', 'CleanVMInstaller.entitlements.plist', 'CleanVMInstaller.swift',
                          'helpers.json', tools.HELPERS_PORTABLE_RECEIPT])
        receipt = json.loads((clean.parent / 'helpers.json').read_text())
        self.assertFalse(receipt['notarized'])
        self.assertFalse(receipt['developer_id_signed'])
        self.assertFalse(receipt['executed'])
        self.assertEqual(set(receipt['artifacts']), {'CleanVMInstaller'})
        compile_commands = [c[0][0] for c in self.native.call_args_list if 'swiftc' in c[0][0]]
        self.assertEqual(len(compile_commands), 1)
        self.assertFalse(any('-D' in command for command in compile_commands))
        self.assertEqual(receipt['clean_installer_entitlements'], {'com.apple.security.virtualization': True})

    def test_compiler_retries_have_distinct_owned_directories(self):
        with mock.patch.object(tools, 'source_prerequisites', return_value={'sdk_path': str(self.sdk)}):
            first = tools.compile_helpers(self.root / 'build')
            second = tools.compile_helpers(self.root / 'build')
        self.assertNotEqual(first[0].parent, second[0].parent)
        self.assertTrue(first[0].exists())

    def test_wrong_local_entitlements_fail_not_silently_accepted(self):
        path = self.root / 'own.fixture'
        path.write_bytes(b'own inert fixture')
        with self.assertRaisesRegex(tools.HostToolError, 'unexpected-local-entitlements'):
            tools.verify_local_signature(path, {'com.apple.security.virtualization': True})

    def test_no_global_installs_or_unsupported_platform_fallback(self):
        with mock.patch.object(tools.platform, 'system', return_value='Darwin'), \
             mock.patch.object(tools.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(tools.platform, 'mac_ver', return_value=('26.6.2', (), '')):
            with self.assertRaisesRegex(tools.HostToolError, 'unsupported-host-platform'):
                tools.source_prerequisites()
        self.native.assert_not_called()

    def source_fixture(self):
        root = self.root / 'source 含空格'
        root.mkdir(mode=0o700)
        for name in install_app.FILES:
            (root / name).write_text('# inert Python source fixture\n')
        for name in install_app.SOURCE_FILES:
            raw = plistlib.dumps({'com.apple.security.virtualization': True}) if name.endswith('.plist') else b'// inert own Swift fixture\n'
            (root / name).write_bytes(raw)
        for folder, names in (('static', install_app.STATIC_FILES),
                              ('guest_setup', install_app.GUEST_SETUP_FILES),
                              ('examples', install_app.EXAMPLE_FILES)):
            for name in names:
                path = root / folder / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_text('inert reviewed source/example fixture\n')
        return root

    def test_package_full_closure_helper_signatures_receipt_and_no_launch(self):
        source = self.source_fixture()
        output = self.root / 'new 包装.app'
        with mock.patch.object(install_app, 'ROOT', source), \
             mock.patch.object(tools, 'source_prerequisites', return_value={'sdk_path': str(self.sdk)}):
            result = install_app.package_app(output, self.root / 'build')
        payload = output / 'Contents' / 'Resources' / 'app'
        for name in install_app.FILES + install_app.SOURCE_FILES:
            self.assertTrue((payload / name).is_file(), name)
        for name in install_app.STATIC_FILES:
            self.assertTrue((payload / 'static' / name).is_file())
        for name in install_app.EXAMPLE_FILES:
            self.assertTrue((payload / 'examples' / name).is_file())
        self.assertTrue((payload / 'CleanVMInstaller').exists())
        # Nothing is built for, or copied into, the guest any more.
        for name in ('GuestVPNBootstrap', 'GuestOwnershipHelper', 'GuestVPNBootstrap.swift', 'GuestOwnershipHelper.swift',
                     'guest_ownership.py', 'guest_vpn_seed.py', 'offline_vpn.py', 'offline_preinstall.py'):
            self.assertFalse((payload / name).exists(), name)
        self.assertEqual(set(result['helper_entitlements']), {'CleanVMInstaller'})
        self.assertEqual(set(result['portable_helper_receipts']), {tools.HELPERS_PORTABLE_RECEIPT})
        for name, expected_hash in result['portable_helper_receipts'].items():
            self.assertEqual(hashlib.sha256((payload / name).read_bytes()).hexdigest(), expected_hash)
            self.assertNotIn(str(self.root), (payload / name).read_text())
        self.assertFalse(result['notarized'])
        self.assertFalse(result['launched'])
        info = plistlib.loads((output / 'Contents' / 'Info.plist').read_bytes())
        self.assertEqual(info['CFBundleShortVersionString'], '1.4.0')
        self.assertEqual(info['CFBundleVersion'], '7')
        self.assertTrue(Path(result['package_receipt']).is_file())
        self.assertNotIn('evidence', str(result['package_receipt']))
        commands = [c[0][0] for c in self.native.call_args_list]
        sign_commands = [c for c in commands if '--sign' in c]
        self.assertEqual(sign_commands[-1][-1], str(output))
        native = [c for c in commands if 'swiftc' in c and any('NativeApp.swift' in a for a in c)][0]
        self.assertTrue(any('GuestInitialization.swift' in a for a in native))
        self.assertIn('ScreenCaptureKit', native)
        self.no_spawn.assert_not_called()
        self.no_run.assert_not_called()

    def test_missing_parent_owned_module_fails_before_output_or_build(self):
        source = self.source_fixture()
        # Use an unpopulated fixture source rather than skipping closure members.
        incomplete = self.root / 'incomplete'
        incomplete.mkdir(mode=0o700)
        with mock.patch.object(install_app, 'ROOT', incomplete):
            with self.assertRaises(Exception):
                install_app.package_app(self.root / 'new.app', self.root / 'build')
        self.assertIn('oneclick.py', install_app.FILES)
        self.assertIn('preinstall_runtime.py', install_app.FILES)
        self.assertFalse((self.root / 'new.app').exists())
        self.assertFalse((self.root / 'build').exists())

    def test_existing_app_never_overwritten_even_before_source_checks(self):
        app = self.root / 'existing.app'
        app.mkdir(mode=0o700)
        original = app / 'keep'
        original.write_bytes(b'preserve existing app')
        with self.assertRaisesRegex(tools.HostToolError, 'existing-app-will-not-be-overwritten'):
            install_app.package_app(app, self.root / 'build')
        self.assertEqual(original.read_bytes(), b'preserve existing app')
        self.native.assert_not_called()
        self.assertFalse((self.root / 'build').exists())

    def test_unlisted_local_python_dependency_rejects_incomplete_closure(self):
        source = self.source_fixture()
        (source / 'manager.py').write_text('import new_runtime_dependency\n')
        (source / 'new_runtime_dependency.py').write_text('# new dependency\n')
        with mock.patch.object(install_app, 'ROOT', source):
            with self.assertRaisesRegex(tools.HostToolError, 'incomplete-python-package-closure'):
                install_app.source_snapshot()

    def receipt_fixture(self):
        archive = self.tar(self.valid_entries())
        body = archive.read_bytes()
        spec = dataclasses.replace(host_artifacts.SPECS['tart'], size_bytes=len(body),
                                   sha256=hashlib.sha256(body).hexdigest())
        directory = self.root / ('tart-' + 'b' * 32)
        directory.mkdir(mode=0o700)
        path = directory / spec.filename
        path.write_bytes(body)
        path.chmod(0o600)
        info = path.stat()
        receipt = host_artifacts.Receipt(
            spec_key='tart', spec_sha256=spec.spec_sha256, version=spec.version,
            artifact_path=str(path), receipt_path=str(directory / 'receipt.json'),
            acceptance_path=str(directory / 'accepted.json'), attempt_id=directory.name,
            size_bytes=spec.size_bytes, sha256=spec.sha256, source_kind='download',
            source_url=spec.url, final_host='github.com', hash_provenance=spec.hash_provenance,
            device=info.st_dev, inode=info.st_ino, mtime_ns=info.st_mtime_ns,
            quarantine_ensured=True)
        for name, value in (('accepted.json', receipt), ('receipt.json', dataclasses.replace(receipt, quarantine_ensured=False))):
            record = directory / name
            record.write_bytes(tools._json(dataclasses.asdict(value)))
            record.chmod(0o600)
        return spec, receipt

    def test_durable_host_receipts_and_fresh_archive_digest_are_required(self):
        spec, receipt = self.receipt_fixture()
        with mock.patch.object(tools, '_reviewed_tart_spec', return_value=spec), \
             mock.patch.object(tools.quarantine_policy, 'read', return_value=b'fixture-q'):
            result = tools.ensure_tart(self.root / 'tools', artifact_receipt=receipt)
        self.assertEqual(result.archive_sha256, spec.sha256)
        path = Path(receipt.artifact_path)
        info = path.stat()
        path.write_bytes(b'x' * spec.size_bytes)
        os.utime(str(path), ns=(info.st_atime_ns, info.st_mtime_ns))
        with mock.patch.object(tools, '_reviewed_tart_spec', return_value=spec), \
             mock.patch.object(tools.quarantine_policy, 'read', return_value=b'fixture-q'):
            with self.assertRaisesRegex(tools.HostToolError, 'archive-digest-mismatch'):
                tools.ensure_tart(self.root / 'tools', artifact_receipt=receipt)
        self.assertEqual(host_artifacts.SPECS['tart'].sha256,
                         'e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2')

    def test_tampered_acceptance_proof_is_not_adopted(self):
        spec, receipt = self.receipt_fixture()
        Path(receipt.acceptance_path).write_bytes(b'{}')
        with mock.patch.object(tools, '_reviewed_tart_spec', return_value=spec):
            with self.assertRaisesRegex(tools.HostToolError, 'durable-receipt-mismatch'):
                tools.ensure_tart(self.root / 'tools', artifact_receipt=receipt)
        self.native.assert_not_called()

    def test_compressed_parser_metadata_allocations_are_bounded(self):
        wrapped = tools._BoundedTarIO(io.BytesIO(b''), float('inf'))
        with self.assertRaisesRegex(tools.HostToolError, 'expanded-tar-limit'):
            wrapped.read(5 * 1024 * 1024)
        with self.assertRaisesRegex(tools.HostToolError, 'expanded-tar-limit'):
            wrapped.seek(tools.MAX_TAR_BYTES + 1)

    def test_compiler_system_temp_requires_os_location_owner_and_exact_private_mode(self):
        path = Path('/private/var/folders/ab/fixture-uid-root/T')
        valid = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=os.getuid())
        self.assertEqual(tools._validate_system_compiler_temp(path, valid), path)
        cases = [(self.root / 'T', valid),
                 (path, SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=os.getuid())),
                 (path, SimpleNamespace(st_mode=stat.S_IFDIR | 0o770, st_uid=os.getuid())),
                 (path, SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=os.getuid() + 1)),
                 (path, SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_uid=os.getuid())),
                 (path, SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=os.getuid()))]
        for candidate, info in cases:
            with self.subTest(candidate=candidate, info=info), self.assertRaisesRegex(
                    tools.HostToolError, 'trusted-os-compiler-temp-required'):
                tools._validate_system_compiler_temp(candidate, info)

    def test_native_compiler_environment_is_owned_and_credential_free(self):
        build = self.root / 'compiler-environment'
        build.mkdir(mode=0o700)
        self.no_run.side_effect = None
        self.no_run.return_value = SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://user:secret@bad',
                                         'RUBYOPT': 'secret', 'DYLD_INSERT_LIBRARIES': 'secret'}), \
             mock.patch.object(tools.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(self.root / 'os-home'))):
            REAL_TOOL(['/usr/bin/xcrun', 'swiftc', '--version'], build_directory=build)
        env = self.no_run.call_args[1]['env']
        self.assertEqual(env['HOME'], str(self.root / 'os-home'))
        self.assertNotIn('CFFIXED_USER_HOME', env)
        self.assertEqual(env['TMPDIR'], str(self.os_temp) + '/')
        self.assertEqual(env['LANG'], 'en_US.UTF-8')
        self.assertEqual(env['LC_ALL'], 'en_US.UTF-8')
        self.assertEqual(env['CLANG_MODULE_CACHE_PATH'], str(build / 'module-cache'))
        self.system_temp.assert_called_once_with()
        self.assertFalse((build / 'compiler-tmp').exists())
        for forbidden in ('HTTPS_PROXY', 'RUBYOPT', 'DYLD_INSERT_LIBRARIES'):
            self.assertNotIn(forbidden, env)

    def portable_fixture(self, packaged=False):
        source = self.source_fixture()
        with mock.patch.object(tools, 'source_prerequisites', return_value={'sdk_path': str(self.sdk)}):
            (clean,) = tools._compile_helpers(self.root / 'build', source)
        resource = self.root / 'portable'
        if packaged:
            resource = self.root / 'Portable.app' / 'Contents' / 'Resources' / 'app'
        resource.mkdir(mode=0o700, parents=True)
        target = resource / clean.name
        target.write_bytes(clean.read_bytes())
        target.chmod(0o700)
        name = tools.HELPERS_PORTABLE_RECEIPT
        (resource / name).write_bytes((clean.parent / name).read_bytes())
        (resource / name).chmod(0o600)
        self.native.reset_mock()
        return resource

    def test_resolve_portable_helpers_without_sources_or_sdk_compilation(self):
        resource = self.portable_fixture(packaged=True)
        with mock.patch.object(tools, 'source_prerequisites', side_effect=AssertionError('no SDK lookup')), \
             mock.patch.object(tools, '_compile_helpers', side_effect=AssertionError('no runtime compile')):
            clean = tools.resolve_helpers(resource, self.root / 'unused-build')
        self.assertEqual(clean, resource / 'CleanVMInstaller')
        self.assertFalse((self.root / 'unused-build').exists())
        self.assertFalse(list(resource.glob('*.swift')))
        self.assertTrue(all(call[0][0][0] in ('/usr/bin/codesign', '/usr/bin/lipo')
                            for call in self.native.call_args_list))
        verified = [call[0][0][-1] for call in self.native.call_args_list if '--verify' in call[0][0]]
        self.assertIn(str(resource.parents[2]), verified)
        for name in (tools.HELPERS_PORTABLE_RECEIPT,):
            record = (resource / name).read_text()
            self.assertNotIn(str(self.root), record)
            self.assertNotIn('sdk_path', record)
            self.assertNotIn('artifact_path', record)

    def test_resolve_source_checkout_compiles_without_global_here_override(self):
        source = self.source_fixture()
        with mock.patch.object(tools, 'source_prerequisites', return_value={'sdk_path': str(self.sdk)}):
            clean = tools.resolve_helpers(source, self.root / 'build')
        self.assertEqual(clean.name, 'CleanVMInstaller')
        self.assertTrue((clean.parent / tools.HELPERS_PORTABLE_RECEIPT).is_file())

    def test_resolve_refuses_unreceipted_binary_even_with_complete_sources(self):
        source = self.source_fixture()
        (source / 'CleanVMInstaller').write_bytes(b'inert unreceipted binary')
        with mock.patch.object(tools, '_compile_helpers', side_effect=AssertionError('must not fallback')):
            with self.assertRaisesRegex(tools.HostToolError, 'complete-helper-binaries-and-portable-receipt-required'):
                tools.resolve_helpers(source, self.root / 'build')
        self.assertFalse((self.root / 'build').exists())

    def test_resolve_rejects_changed_binary_instead_of_adopting_or_compiling(self):
        resource = self.portable_fixture()
        (resource / 'CleanVMInstaller').write_bytes(b'changed binary')
        with mock.patch.object(tools, '_compile_helpers', side_effect=AssertionError('must not fallback')):
            with self.assertRaisesRegex(tools.HostToolError, 'packaged-helper-hash-mismatch'):
                tools.resolve_helpers(resource, self.root / 'unused')
        self.native.assert_not_called()

    def test_portable_receipt_requires_exact_production_recipe_and_unique_keys(self):
        resource = self.portable_fixture()
        path = resource / tools.HELPERS_PORTABLE_RECEIPT
        value = json.loads(path.read_text())
        value['recipes']['CleanVMInstaller']['defines'] = ['FIXTURE_DEFINE']
        path.write_bytes(tools._json(value))
        with self.assertRaisesRegex(tools.HostToolError, 'portable-helper-build-recipe-mismatch'):
            tools.resolve_helpers(resource, self.root / 'unused')
        path.write_text('{"schema":1,"schema":1}')
        with self.assertRaisesRegex(tools.HostToolError, 'duplicate-portable-receipt-key'):
            tools.resolve_helpers(resource, self.root / 'unused')

    def test_portable_receipt_crosschecks_any_present_source(self):
        resource = self.portable_fixture()
        (resource / 'CleanVMInstaller.swift').write_bytes(b'changed source')
        with self.assertRaisesRegex(tools.HostToolError, 'packaged-helper-source-mismatch'):
            tools.resolve_helpers(resource, self.root / 'unused')

    def test_packaged_app_missing_helpers_never_compiles_even_if_sources_present(self):
        source = self.source_fixture()
        resource = self.root / 'Incomplete.app' / 'Contents' / 'Resources' / 'app'
        resource.mkdir(mode=0o700, parents=True)
        for name in install_app.SOURCE_FILES:
            (resource / name).write_bytes((source / name).read_bytes())
        with mock.patch.object(tools, '_compile_helpers', side_effect=AssertionError('no packaged compile')):
            with self.assertRaisesRegex(tools.HostToolError, 'packaged-helpers-missing-no-runtime-compilation'):
                tools.resolve_helpers(resource, self.root / 'unused')
        self.assertFalse(hasattr(tools, 'resolve_ownership_helper'))
        self.assertFalse(hasattr(tools, 'compile_ownership_helper'))

    def test_native_failure_keeps_exact_private_compiler_diagnostic(self):
        build = self.root / 'diagnostic-build'
        build.mkdir(mode=0o700)
        self.no_run.side_effect = None
        self.no_run.return_value = SimpleNamespace(returncode=-5, stdout=b'', stderr=b'fixture native startup trap')
        with self.assertRaisesRegex(tools.HostToolError, '^native-tool-rejected$') as caught:
            REAL_TOOL(['/usr/bin/xcrun', 'swiftc', '--version'], build_directory=build)
        error = caught.exception
        self.assertEqual(error.returncode, -5)
        self.assertEqual(error.diagnostic_path.parent, build)
        self.assertEqual(error.diagnostic_path.read_bytes(), b'fixture native startup trap')
        self.assertEqual(stat.S_IMODE(error.diagnostic_path.stat().st_mode), 0o600)
        self.assertNotIn('fixture native startup trap', str(error))

    def test_entrypoint_has_no_launch_or_gatekeeper_commands(self):
        source = (tools.HERE / 'Install.command').read_text()
        self.assertIn('/usr/bin/xcode-select -p', source)
        self.assertIn('/usr/bin/env -i', source)
        self.assertIn('"$SOURCE_DIR/install_app.py" "$@"', source)
        self.assertIn('Gold VM 管理器.app', source)
        for forbidden in ('spctl', 'xattr', 'sudo ', 'pip ', 'npm ', '/usr/bin/open', 'bootstrap.py'):
            self.assertNotIn(forbidden, source)



class GvproxyToolTests(unittest.TestCase):
    """Podman's installer is only expanded and assessed with mocked native tools."""

    BINARY = b'inert gvproxy fixture; never execute'
    TEAM = tools.GVPROXY_TEAM

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-host-tools-fixture-')).resolve()
        self.root.chmod(0o700)
        self.addCleanup(shutil.rmtree, str(self.root))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.package = self.root / 'podman-installer-macos-arm64.pkg'
        self.package.write_bytes(b'inert package fixture')
        self.package.chmod(0o600)
        self.payload = self.BINARY
        self.signature = ('Package "podman-installer-macos-arm64.pkg":\n'
                          '   Status: signed by a developer certificate issued by Apple for distribution\n'
                          '   Notarization: trusted by the Apple notary service\n'
                          '   Certificate Chain:\n'
                          '    1. Developer ID Installer: Red Hat, Inc. (%s)\n' % self.TEAM)
        self.install_verdict = ': accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: Red Hat, Inc. (%s)\n' % self.TEAM
        self.display = 'Identifier=gvproxy\nTeamIdentifier=%s\nAuthority=Developer ID Application: Red Hat, Inc. (%s)\n' % (self.TEAM, self.TEAM)
        self.open_verdict = ': accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Red Hat, Inc. (%s)\n' % self.TEAM
        self.calls = []
        self.stack.enter_context(mock.patch.object(tools, 'GVPROXY_SHA256', hashlib.sha256(self.BINARY).hexdigest()))
        self.stack.enter_context(mock.patch.object(tools, 'GVPROXY_SIZE', len(self.BINARY)))
        self.stack.enter_context(mock.patch.object(tools, '_tool', side_effect=self.tool))
        self.stack.enter_context(mock.patch.object(tools, '_archive_source', side_effect=self.source))
        self.propagate = self.stack.enter_context(mock.patch.object(tools.quarantine_policy, 'propagate'))
        self.stack.enter_context(mock.patch('subprocess.run', side_effect=AssertionError('real native forbidden')))
        self.stack.enter_context(mock.patch('subprocess.Popen', side_effect=AssertionError('no process launch')))

    @contextmanager
    def source(self, receipt, key='tart'):
        self.assertEqual(key, 'podman-installer')
        with self.package.open('rb') as stream:
            yield self.package, stream, 'f' * 64

    def tool(self, argv, timeout=120, build_directory=None):
        self.calls.append(list(argv))
        out = err = ''
        if argv[:2] == ['/usr/sbin/pkgutil', '--check-signature']:
            out = self.signature
        elif argv[:2] == ['/usr/sbin/pkgutil', '--expand-full']:
            destination = Path(argv[3])
            self.assertFalse(destination.exists())
            binary = destination / 'podman.pkg' / 'Payload' / 'podman' / 'bin' / 'gvproxy'
            binary.parent.mkdir(mode=0o755, parents=True)
            binary.write_bytes(self.payload)
            binary.chmod(0o755)
            (binary.parent / 'podman').write_bytes(b'inert podman fixture; never installed')
        elif argv[0] == '/usr/sbin/spctl' and '--type' in argv and argv[argv.index('--type') + 1] == 'install':
            err = argv[-1] + self.install_verdict
        elif argv[0] == '/usr/sbin/spctl':
            self.assertEqual(argv[argv.index('--type') + 1], 'open')
            self.assertIn('context:primary-signature', argv)
            err = argv[-1] + self.open_verdict
        elif argv[0] == '/usr/bin/codesign' and '--display' in argv:
            err = self.display
        elif argv[0] == '/usr/bin/codesign':
            self.assertIn('--verify', argv)
        else:
            self.fail('unexpected native tool')
        return SimpleNamespace(returncode=0, stdout=out.encode(), stderr=err.encode())

    def ensure(self):
        return tools.ensure_gvproxy(self.root / 'tools', artifact_receipt=object())

    def test_only_gvproxy_is_taken_from_the_signed_package_without_installing(self):
        result = self.ensure()
        binary = Path(result.executable_path)
        self.assertEqual(binary.read_bytes(), self.BINARY)
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o600)  # Executable only after confirmation.
        self.assertEqual(sorted(p.name for p in binary.parent.iterdir()), ['gvproxy', 'gvproxy.json'])
        self.assertEqual((result.team_id, result.version, result.notarized, result.execution_performed),
                         (self.TEAM, '0.9.0', True, False))
        self.assertEqual(json.loads(Path(result.receipt_path).read_text())['executable_sha256'],
                         hashlib.sha256(self.BINARY).hexdigest())
        self.propagate.assert_called_once_with(self.package, binary)
        steps = [c[:2] for c in self.calls]
        self.assertEqual(steps[:3], [['/usr/sbin/pkgutil', '--check-signature'], ['/usr/sbin/spctl', '--assess'],
                                     ['/usr/sbin/pkgutil', '--expand-full']])
        requirement = next(c[c.index('-R') + 1] for c in self.calls if '-R' in c)
        self.assertIn('certificate leaf[subject.OU] = "%s" and identifier "gvproxy"' % self.TEAM, requirement)

    def test_package_without_red_hat_signature_or_notarization_is_never_expanded(self):
        good_signature, good_verdict = self.signature, self.install_verdict
        for signature, verdict, code in (
                (good_signature.replace('   Notarization: trusted by the Apple notary service\n', ''), good_verdict,
                 'podman-package-signature-required'),
                (good_signature.replace('Red Hat, Inc. (%s)' % self.TEAM, 'Someone Else (ABCDE12345)'), good_verdict,
                 'podman-package-signature-required'),
                (good_signature, good_verdict.replace('Notarized Developer ID', 'Developer ID'),
                 'podman-package-notarization-required'),
                (good_signature, good_verdict.replace('Red Hat, Inc.', 'Other, Inc.'), 'podman-package-notarization-required')):
            with self.subTest(code=code):
                self.signature, self.install_verdict, self.calls = signature, verdict, []
                with self.assertRaisesRegex(tools.HostToolError, '^' + code + '$'):
                    self.ensure()
                self.assertNotIn(['/usr/sbin/pkgutil', '--expand-full'], [c[:2] for c in self.calls])
        self.assertFalse(list((self.root / 'tools').glob('*/gvproxy')))

    def test_other_bytes_identity_or_unnotarized_binary_is_refused(self):
        cases = (('payload', self.BINARY[:-1] + b'X', 'reviewed-gvproxy-digest-mismatch'),
                 ('payload', self.BINARY + b'X', 'reviewed-gvproxy-size-mismatch'),
                 ('display', self.display.replace('TeamIdentifier=' + self.TEAM, 'TeamIdentifier=ABCDE12345'),
                  'gvproxy-signing-identity-mismatch'),
                 ('display', self.display.replace('Identifier=gvproxy\n', 'Identifier=other\n'), 'gvproxy-signing-identity-mismatch'),
                 ('open_verdict', self.open_verdict.replace('Notarized Developer ID', 'Developer ID'),
                  'gvproxy-notarization-required'))
        for attribute, value, code in cases:
            with self.subTest(code=code, attribute=attribute):
                original = getattr(self, attribute)
                setattr(self, attribute, value)
                try:
                    with self.assertRaisesRegex(tools.HostToolError, '^' + code + '$'):
                        self.ensure()
                finally:
                    setattr(self, attribute, original)
        self.assertFalse(list((self.root / 'tools').glob('*/expanded')))  # Never retained.
        self.assertFalse(list((self.root / 'tools').glob('*/gvproxy.json')))

    def test_only_the_reviewed_podman_receipt_is_accepted(self):
        self.stack.close()  # Real _archive_source and pins; nothing native may run.
        tart = host_artifacts.SPECS['tart']
        receipt = host_artifacts.Receipt(
            spec_key='tart', spec_sha256=tart.spec_sha256, version=tart.version, artifact_path=str(self.package),
            receipt_path='', acceptance_path='', attempt_id='tart-' + 'a' * 32, size_bytes=tart.size_bytes,
            sha256=tart.sha256, source_kind='download', source_url=tart.url, final_host='github.com',
            hash_provenance=tart.hash_provenance, device=0, inode=0, mtime_ns=0, quarantine_ensured=True)
        with mock.patch.object(tools, '_tool', side_effect=AssertionError('no native tool')):
            for value in (receipt, object()):
                with self.subTest(value=type(value).__name__), self.assertRaises(tools.HostToolError) as raised:
                    tools.ensure_gvproxy(self.root / 'tools', artifact_receipt=value)
                self.assertIn(raised.exception.code, ('reviewed-podman-receipt-required', 'host-artifact-receipt-required'))
        self.assertEqual((tools.GVPROXY_TEAM, tools.GVPROXY_SHA256),
                         ('HYSCB8KRL2', '45881c33400a14c4c50d4ed7e814b69a60248aa0d78e9b541e879edc05346a85'))


if __name__ == '__main__':
    unittest.main()
