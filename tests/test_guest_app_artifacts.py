"""Offline fixtures only: every subprocess/network call is mocked.

Temporary synthetic app/cache files are not signed executables or real packages.
Never download binaries, invoke Apple tools, inspect host apps, mount or launch.
"""
import dataclasses
from email.message import Message
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error

import guest_app_artifacts as artifacts


BODY = b'fixture artifact bytes -- not a real disk image or executable'
SHA = hashlib.sha256(BODY).hexdigest()
TEAM = 'TESTTEAM01'  # Deliberately fictitious; never a production trust constant.
REVIEW = 'https://example.invalid/review/fixture-only'
URLS = {
    'ccbaga': 'https://github.com/liseami/CCBaga/releases/download/v1.2.3/CCBaga-1.2.3-macos-arm64.dmg',
    'clashVergeRev': 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v1.2.3/Clash.Verge_1.2.3_aarch64.dmg',
    'claudeDesktop': 'https://downloads.claude.ai/releases/darwin/universal/1.2.3/Claude-' + 'a' * 40 + '.zip',
}
CDN = 'https://release-assets.githubusercontent.com/github-production-release-asset/1413898431/12345678-1234-1234-1234-123456789abc'


def expectation(name):
    stem = name[:-4]
    return artifacts.AppExpectation(
        name, ('org.fixture.' + stem.replace(' ', ''),), (stem,), (stem,),
        ('1.2.3',), ('123',), ('Contents/Resources',))


def manifest(product='ccbaga', reviewed=True, **changes):
    names = artifacts._PRODUCTS[product][2]
    data = dict(product=product, version='1.2.3', artifact_url=URLS[product],
                known_sha256=SHA, expected_apps=tuple(expectation(n) for n in names),
                vendor_team_ids=(TEAM,) if reviewed else (),
                identity_review_sources=(REVIEW,) if reviewed else (),
                maximum_download_bytes=4096, maximum_bundle_bytes=65536,
                maximum_bundle_entries=1000)
    data.update(changes)
    return artifacts.freeze_manifest(**data)


class Response(io.BytesIO):
    def __init__(self, url, payload=BODY, code=200, headers=()):
        super().__init__(payload)
        self.url, self.code = url, code
        self.headers = Message()
        for key, value in headers:
            self.headers.add_header(key, value)

    def geturl(self):
        return self.url


class ArtifactFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gold-artifact-fixtures-')
        self.root = Path(self.temp.name).resolve()
        self.cache = self.root / 'cache'
        self.cache.mkdir(mode=0o700)
        self.stage = self.root / 'staging'
        self.stage.mkdir(mode=0o700)
        self.run = self.enterContext(mock.patch.object(
            artifacts.subprocess, 'run', side_effect=AssertionError('real subprocess prohibited')))
        self.opener = mock.Mock()
        self.opener.open.side_effect = AssertionError('unconfigured network prohibited')
        self.build = self.enterContext(mock.patch.object(artifacts, '_build_opener', return_value=self.opener))
        self.addCleanup(self.temp.cleanup)

    # unittest.TestCase.enterContext is not present in Python 3.9.
    def enterContext(self, context):
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def acquire(self, selected=None, response=None):
        selected = selected or manifest()
        self.opener.open.side_effect = None
        self.opener.open.return_value = response or Response(selected.artifact_url)
        return artifacts.download_artifact(selected, self.cache)

    def make_apps(self, selected):
        paths = []
        for expected in selected.expected_apps:
            app = self.stage / expected.name
            (app / 'Contents' / 'MacOS').mkdir(parents=True)
            (app / 'Contents' / 'Resources').mkdir()
            (app / 'Contents' / 'Resources' / 'fixture.txt').write_bytes(b'signed resource fixture')
            executable = app / 'Contents' / 'MacOS' / expected.executable_names[0]
            executable.write_bytes(b'not a real Mach-O')
            executable.chmod(0o755)
            info = dict(CFBundleIdentifier=expected.bundle_identifiers[0],
                        CFBundleName=expected.bundle_names[0],
                        CFBundleExecutable=expected.executable_names[0],
                        CFBundleShortVersionString=expected.short_versions[0],
                        CFBundleVersion=expected.bundle_versions[0], CFBundlePackageType='APPL')
            with (app / 'Contents' / 'Info.plist').open('wb') as stream:
                plistlib.dump(info, stream)
            paths.append(app)
        return paths

    def good_tool(self, argv, **kwargs):
        self.assertIn(argv[0], ('/usr/bin/lipo', '/usr/bin/codesign', '/usr/sbin/spctl'))
        self.assertFalse(kwargs.get('shell', False))
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['env'], {
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/var/empty'})
        self.assertEqual(kwargs['timeout'], 120)
        stdout, stderr = b'', b''
        if argv[0].endswith('lipo'):
            stdout = b'x86_64 arm64\n'
        elif '--display' in argv:
            stem = Path(argv[-1]).name[:-4]
            stderr = ('Identifier=org.fixture.%s\nTeamIdentifier=%s\nAuthority=Developer ID Application: Fixture\n'
                      % (stem.replace(' ', ''), TEAM)).encode()
        elif argv[0].endswith('spctl'):
            stderr = (argv[-1] + ': accepted\nsource=Notarized Developer ID\n').encode()
        return subprocess.CompletedProcess(argv, 0, stdout, stderr)

    def verified(self, selected=None):
        selected = selected or manifest()
        receipt = self.acquire(selected)
        paths = self.make_apps(selected)
        self.run.side_effect = self.good_tool
        return selected, receipt, paths

    def test_import_has_no_network_or_subprocess_activity(self):
        # Execute source in an isolated module name without replacing class types.
        source = Path(artifacts.__file__).read_text()
        with mock.patch('urllib.request.build_opener') as network:
            namespace = {'__name__': 'guest_app_artifacts'}
            exec(compile(source, artifacts.__file__, 'exec'), namespace)
            network.assert_not_called()
        self.run.assert_not_called()

    def test_manifest_is_frozen_and_complete(self):
        selected = manifest()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            selected.version = '2.0.0'
        with self.assertRaisesRegex(artifacts.ArtifactError, 'incomplete-gui'):
            manifest(expected_apps=(expectation('CCBaga-A.app'),))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'incomplete-gui'):
            manifest('clashVergeRev', expected_apps=(expectation('mihomo.app'),))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'incomplete-gui'):
            manifest('claudeDesktop', expected_apps=(expectation('Claude Code.app'),))

    def test_pending_manifest_has_no_invented_identity_or_plist(self):
        selected = artifacts.freeze_manifest(product='ccbaga', version='1.2.3',
                                             artifact_url=URLS['ccbaga'], known_sha256=SHA)
        self.assertEqual(selected.vendor_team_ids, ())
        self.assertEqual(selected.expected_apps[1].short_versions, ())
        with self.assertRaises(artifacts.PendingReview):
            artifacts.verify_app_bundles(selected, self.stage, [], None)
        self.run.assert_not_called()

    def test_origin_urls_are_exact_publisher_artifact_paths(self):
        original = URLS['ccbaga']
        for invalid in (original.replace('https:', 'http:'), original + '?mirror=true',
                        original + '#a', original.replace('github.com/', 'github.com:443/'),
                        original.replace('github.com/', 'github.com.evil/'),
                        original.replace('github.com/', 'user:secret@github.com/'),
                        original.replace('/liseami/', '/other/'), original.replace('v1.2.3/', 'latest/'),
                        original.replace('CCBaga-1', '%43CBaga-1'), original.replace('.dmg', '.app.tar.gz'),
                        original.replace('/download/', '/download/../download/')):
            with self.subTest(url=invalid), self.assertRaises(artifacts.ArtifactError):
                manifest(artifact_url=invalid)
        with self.assertRaises(artifacts.ArtifactError):
            manifest('claudeDesktop', artifact_url=URLS['claudeDesktop'].replace('downloads.claude.ai', 'claude.ai'))

    def test_checksum_size_and_review_values_are_strict(self):
        for kwargs in ({'known_sha256': None}, {'known_sha256': 'f' * 40},
                       {'version': 'latest'}, {'maximum_download_bytes': True},
                       {'maximum_download_bytes': artifacts.MAX_DOWNLOAD_BYTES + 1},
                       {'declared_size_bytes': -1}, {'vendor_team_ids': ('bad" injection',)},
                       {'identity_review_sources': ('file:///private/secret',)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(artifacts.ArtifactError):
                manifest(**kwargs)

    def test_app_expectations_refuse_paths_and_mutable_values(self):
        for kwargs in ({'executable_names': ('../bad',)}, {'required_paths': ('../host',)},
                       {'required_paths': ('/Applications',)}, {'short_versions': ['1.2.3']},
                       {'bundle_identifiers': ('org.bad" injection',)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(artifacts.ArtifactError):
                artifacts.AppExpectation('Fixture.app', **kwargs)

    def test_redirects_are_repository_scoped_and_https(self):
        selected = manifest()
        artifacts.validate_artifact_redirect(selected, selected.artifact_url, CDN + '?jwt=not-retained')
        for bad in (CDN.replace('1413898431', '721767116'), CDN.replace('https:', 'http:'),
                    CDN.replace('release-assets.githubusercontent.com', 'evil.example'),
                    CDN.replace('/12345678-', '/../../12345678-'), CDN + '#fragment',
                    CDN.replace('release-assets.', 'user:pass@release-assets.'),
                    CDN.replace('/github-production-', '/%67ithub-production-')):
            with self.subTest(bad=bad), self.assertRaises(artifacts.ArtifactError):
                artifacts.validate_artifact_redirect(selected, selected.artifact_url, bad)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_artifact_redirect(manifest('claudeDesktop'), URLS['claudeDesktop'], CDN)

    def test_download_success_private_hash_and_metadata_distinction(self):
        receipt = self.acquire()
        path = Path(receipt.artifact_path)
        self.assertEqual(path.read_bytes(), BODY)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(receipt.sha256, SHA)
        self.assertTrue(receipt.expected_sha256_matched)
        self.assertFalse(receipt.binary_verification_performed)
        self.assertFalse(list(self.cache.glob('*.partial')))
        request = self.opener.open.call_args[0][0]
        self.assertFalse(request.has_header('Cookie'))
        self.assertFalse(request.has_header('Authorization'))
        self.build.assert_called_once_with(None)
        self.run.assert_not_called()

    def test_missing_publisher_checksum_is_not_authenticated(self):
        receipt = self.acquire(manifest('claudeDesktop', known_sha256=None))
        self.assertFalse(receipt.expected_sha256_matched)
        self.assertFalse(receipt.binary_verification_performed)
        self.assertEqual(receipt.sha256, SHA)

    def test_actual_http_error_redirect_is_checked_before_following(self):
        selected = manifest()
        headers = Message()
        headers.add_header('Location', CDN + '?jwt=secret-temporary-token')
        redirection = urllib.error.HTTPError(selected.artifact_url, 302, 'found', headers, io.BytesIO(b''))
        self.opener.open.side_effect = [redirection, Response(CDN + '?jwt=secret-temporary-token')]
        receipt = artifacts.download_artifact(selected, self.cache)
        self.assertEqual(receipt.final_host, 'release-assets.githubusercontent.com')
        self.assertNotIn('secret-temporary-token', repr(receipt))
        self.assertEqual(self.opener.open.call_count, 2)

    def test_untrusted_redirect_never_requested(self):
        selected = manifest()
        self.opener.open.side_effect = None
        self.opener.open.return_value = Response(selected.artifact_url, code=302, headers=[('Location', 'https://evil.invalid/payload')])
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.download_artifact(selected, self.cache)
        self.assertEqual(self.opener.open.call_count, 1)
        self.assertEqual(len(list(self.cache.glob('*.partial'))), 1)
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_checksum_failure_stays_partial(self):
        with self.assertRaisesRegex(artifacts.ArtifactError, 'checksum-mismatch'):
            self.acquire(manifest(known_sha256='0' * 64))
        self.assertEqual(len(list(self.cache.glob('*.partial'))), 1)
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_stream_cap_is_enforced_without_header(self):
        with self.assertRaisesRegex(artifacts.ArtifactError, 'download-too-large'):
            self.acquire(manifest(maximum_download_bytes=8))
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_invalid_headers_and_short_responses_never_finalize(self):
        cases = [([('Content-Length', '999999999')], 'download-too-large'),
                 ([('Content-Length', '1'), ('Content-Length', '2')], 'invalid-content-length'),
                 ([('Content-Length', str(len(BODY) + 1))], 'truncated-download'),
                 ([('Content-Length', '-1')], 'invalid-content-length'),
                 ([('Content-Encoding', 'gzip')], 'unsupported-content-encoding'),
                 ([('Content-Range', 'bytes 0-1/100')], 'partial-response-refused')]
        for headers, code in cases:
            with self.subTest(headers=headers), self.assertRaisesRegex(artifacts.ArtifactError, code):
                self.acquire(response=Response(URLS['ccbaga'], headers=headers))
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_declared_size_and_empty_bytes_fail(self):
        with self.assertRaisesRegex(artifacts.ArtifactError, 'declared-size-mismatch'):
            self.acquire(manifest(declared_size_bytes=len(BODY) + 1))
        self.opener.open.return_value = Response(URLS['ccbaga'], payload=b'')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'truncated-download'):
            artifacts.download_artifact(manifest(), self.cache)

    def test_implicit_redirect_and_non_success_fail(self):
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unexpected-implicit-redirect'):
            self.acquire(response=Response(CDN))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unexpected-http-status'):
            self.acquire(response=Response(URLS['ccbaga'], code=206))

    def test_transport_errors_do_not_leak_details(self):
        self.opener.open.side_effect = urllib.error.URLError('secret-user:password@host')
        with self.assertRaisesRegex(artifacts.ArtifactError, '^download-failed$'):
            artifacts.download_artifact(manifest(), self.cache)
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_cache_rejects_public_or_symlink_directory(self):
        self.cache.chmod(0o755)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'not-private'):
            artifacts.download_artifact(manifest(), self.cache)
        alias = self.root / 'alias'
        alias.symlink_to(self.cache, target_is_directory=True)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.download_artifact(manifest(), alias)
        self.opener.open.assert_not_called()

    def test_partial_and_final_files_are_never_overwritten(self):
        token = mock.Mock(hex='a' * 32)
        partial = self.cache / (token.hex + '.partial')
        partial.write_bytes(b'existing partial')
        with mock.patch.object(artifacts.uuid, 'uuid4', return_value=token):
            with self.assertRaises(FileExistsError):
                self.acquire()
        self.assertEqual(partial.read_bytes(), b'existing partial')
        token.hex = 'b' * 32
        final = self.cache / (token.hex + '.dmg')
        final.write_bytes(b'existing artifact')
        with mock.patch.object(artifacts.uuid, 'uuid4', return_value=token):
            with self.assertRaisesRegex(artifacts.ArtifactError, 'download-failed'):
                self.acquire()
        self.assertEqual(final.read_bytes(), b'existing artifact')

    def make_partial(self, payload=BODY[:10]):
        partial = self.cache / ('c' * 32 + '.partial')
        partial.write_bytes(payload)
        partial.chmod(0o600)
        return partial

    def range_response(self, selected=None, offset=10, payload=None, headers=None, code=206):
        selected = selected or manifest()
        if headers is None:
            headers = [('Content-Range', 'bytes %d-%d/%d' % (offset, len(BODY) - 1, len(BODY))),
                       ('Content-Length', str(len(BODY) - offset))]
        return Response(selected.artifact_url, payload=BODY[offset:] if payload is None else payload,
                        code=code, headers=headers)

    def resume(self, partial, selected=None, response=None, **kwargs):
        selected = selected or manifest()
        self.opener.open.side_effect = None
        self.opener.open.return_value = response if response is not None else self.range_response(selected)
        return artifacts.resume_artifact(selected, self.cache, partial, **kwargs)

    def test_bounded_deadline_is_explicit_and_checked_before_side_effects(self):
        for bad in (0, -1, True, 1.5, 10801):
            with self.subTest(deadline=bad), self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-download-deadline'):
                artifacts.download_artifact(manifest(), self.cache, deadline_seconds=bad)
        self.opener.open.assert_not_called()
        self.assertFalse(list(self.cache.iterdir()))
        self.opener.open.side_effect = None
        self.opener.open.return_value = Response(URLS['ccbaga'])
        with mock.patch.object(artifacts.time, 'monotonic', return_value=0):
            receipt = artifacts.download_artifact(manifest(), self.cache, deadline_seconds=10800)
        self.assertEqual(receipt.sha256, SHA)

    def test_resume_success_hashes_whole_file_and_requests_only_suffix(self):
        partial = self.make_partial()
        receipt = self.resume(partial)
        self.assertFalse(partial.exists())
        self.assertEqual(Path(receipt.artifact_path).read_bytes(), BODY)
        self.assertEqual(receipt.sha256, SHA)
        self.assertTrue(receipt.expected_sha256_matched)
        self.assertFalse(receipt.binary_verification_performed)
        request = self.opener.open.call_args[0][0]
        self.assertEqual(request.get_header('Range'), 'bytes=10-')
        self.assertFalse(request.has_header('Cookie'))
        self.assertIsNone(request.data)
        self.run.assert_not_called()

    def test_resume_without_pinned_sha_never_opens_partial_or_network(self):
        partial = self.make_partial()
        with self.assertRaisesRegex(artifacts.ArtifactError, 'resume-requires-pinned'):
            artifacts.resume_artifact(manifest('claudeDesktop', known_sha256=None), self.cache, partial)
        self.opener.open.assert_not_called()
        self.assertEqual(partial.read_bytes(), BODY[:10])

    def test_resume_never_searches_cache_or_accepts_external_path(self):
        partial = self.make_partial()
        for bad in (self.root / partial.name, self.cache / 'guess.partial', self.cache / ('d' * 32 + '.partial')):
            with self.subTest(path=bad), self.assertRaises(artifacts.ArtifactError):
                artifacts.resume_artifact(manifest(), self.cache, bad)
        self.opener.open.assert_not_called()
        self.assertEqual(partial.read_bytes(), BODY[:10])

    def test_resume_refuses_public_symlink_hardlinked_or_empty_partial(self):
        partial = self.make_partial()
        partial.chmod(0o644)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-partial-file'):
            artifacts.resume_artifact(manifest(), self.cache, partial)
        partial.chmod(0o600)
        alias = self.cache / ('d' * 32 + '.partial')
        alias.symlink_to(partial)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.resume_artifact(manifest(), self.cache, alias)
        alias.unlink()
        os.link(partial, alias)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-partial-file'):
            artifacts.resume_artifact(manifest(), self.cache, partial)
        alias.unlink()
        partial.write_bytes(b'')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-partial-size'):
            artifacts.resume_artifact(manifest(), self.cache, partial)
        self.opener.open.assert_not_called()

    def test_resume_refuses_special_file_before_opening_it(self):
        partial = self.cache / ('c' * 32 + '.partial')
        os.mkfifo(partial, 0o600)
        with mock.patch.object(artifacts.os, 'open') as opened:
            with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-partial-file'):
                artifacts.resume_artifact(manifest(), self.cache, partial)
            opened.assert_not_called()
        self.opener.open.assert_not_called()

    def test_resume_untrusted_redirect_does_not_receive_range_request(self):
        partial = self.make_partial()
        response = Response(URLS['ccbaga'], code=302,
                            headers=[('Location', 'https://evil.invalid/artifact')])
        with self.assertRaisesRegex(artifacts.ArtifactError, 'untrusted-redirect'):
            self.resume(partial, response=response)
        self.assertEqual(self.opener.open.call_count, 1)
        self.assertEqual(partial.read_bytes(), BODY[:10])

    def test_resume_refuses_another_cooperating_writer(self):
        partial = self.make_partial()
        with partial.open('r+b') as owner:
            artifacts.fcntl.flock(owner.fileno(), artifacts.fcntl.LOCK_EX | artifacts.fcntl.LOCK_NB)
            with self.assertRaisesRegex(artifacts.ArtifactError, 'partial-in-use'):
                artifacts.resume_artifact(manifest(), self.cache, partial)
        self.opener.open.assert_not_called()
        self.assertEqual(partial.read_bytes(), BODY[:10])

    def test_fresh_download_holds_lock_while_requesting_and_publishing(self):
        def observe_request(request, **kwargs):
            partial = next(self.cache.glob('*.partial'))
            with partial.open('r+b') as other:
                with self.assertRaisesRegex(artifacts.ArtifactError, 'partial-in-use'):
                    artifacts._lock_partial(other.fileno())
            return Response(request.full_url)
        self.opener.open.side_effect = observe_request
        receipt = artifacts.download_artifact(manifest(), self.cache)
        self.assertEqual(receipt.sha256, SHA)

    def test_resume_does_not_accept_200_or_416_or_restart_download(self):
        partial = self.make_partial()
        for code in (200, 416):
            with self.subTest(code=code), self.assertRaisesRegex(artifacts.ArtifactError, 'resume-requires-http-206'):
                self.resume(partial, response=self.range_response(code=code))
            self.assertEqual(partial.read_bytes(), BODY[:10])
        self.assertEqual(self.opener.open.call_count, 2)

    def test_resume_validates_entire_content_range_contract_before_writing(self):
        partial = self.make_partial()
        for value in ('bytes 0-58/59', 'bytes 11-58/59', 'bytes 10-50/59',
                      'bytes 10-58/*', 'bytes */59', 'bytes 10-4096/4097', 'items 10-58/59',
                      'bytes 10-8/9', 'bytes 10-58/0'):
            response = self.range_response(headers=[('Content-Range', value)])
            with self.subTest(value=value), self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-content-range'):
                self.resume(partial, response=response)
            self.assertEqual(partial.read_bytes(), BODY[:10])
        response = self.range_response(headers=[('Content-Range', 'bytes 10-58/59')] * 2)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-content-range'):
            self.resume(partial, response=response)

    def test_resume_length_encoding_declared_size_and_multipart_are_checked(self):
        partial = self.make_partial()
        range_header = ('Content-Range', 'bytes 10-%d/%d' % (len(BODY) - 1, len(BODY)))
        for extra, code in (([('Content-Length', '1')], 'range-length-mismatch'),
                            ([('Content-Encoding', 'gzip')], 'unsupported-content-encoding'),
                            ([('Content-Encoding', 'identity')] * 2, 'unsupported-content-encoding'),
                            ([('Content-Type', 'multipart/byteranges; boundary=example')], 'multipart-range-refused')):
            with self.subTest(extra=extra), self.assertRaisesRegex(artifacts.ArtifactError, code):
                self.resume(partial, response=self.range_response(headers=[range_header] + extra))
            self.assertEqual(partial.read_bytes(), BODY[:10])
        with self.assertRaisesRegex(artifacts.ArtifactError, 'declared-size-mismatch'):
            self.resume(partial, selected=manifest(declared_size_bytes=len(BODY) + 1))

    def test_resume_strong_etag_if_available_is_sent_and_must_match(self):
        partial = self.make_partial()
        headers = [('Content-Range', 'bytes 10-%d/%d' % (len(BODY) - 1, len(BODY))), ('ETag', '"fixture-tag"')]
        receipt = self.resume(partial, response=self.range_response(headers=headers), expected_etag='"fixture-tag"')
        self.assertEqual(receipt.etag, '"fixture-tag"')
        request = self.opener.open.call_args[0][0]
        self.assertEqual(request.get_header('If-range'), '"fixture-tag"')

    def test_resume_etag_mismatch_weak_duplicates_or_missing_are_refused(self):
        partial = self.make_partial()
        base = [('Content-Range', 'bytes 10-%d/%d' % (len(BODY) - 1, len(BODY)))]
        for tags, code in (([('ETag', '"other"')], 'etag-mismatch'),
                           ([], 'etag-mismatch'), ([('ETag', 'W/"weak"')], 'invalid-strong-etag'),
                           ([('ETag', '"a"'), ('ETag', '"b"')], 'invalid-strong-etag')):
            with self.subTest(tags=tags), self.assertRaisesRegex(artifacts.ArtifactError, code):
                self.resume(partial, response=self.range_response(headers=base + tags), expected_etag='"original"')
            self.assertEqual(partial.read_bytes(), BODY[:10])
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-strong-etag'):
            artifacts.resume_artifact(manifest(), self.cache, partial, expected_etag='bad\r\nInjected: x')

    def test_resume_corrupted_prefix_never_finalizes(self):
        partial = self.make_partial(b'XXXXXXXXXX')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'checksum-mismatch'):
            self.resume(partial)
        self.assertTrue(partial.exists())
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_resume_truncated_or_oversized_range_stays_partial(self):
        partial = self.make_partial()
        with self.assertRaisesRegex(artifacts.ArtifactError, 'truncated-range-response'):
            self.resume(partial, response=self.range_response(payload=BODY[10:-1]))
        self.assertEqual(partial.read_bytes(), BODY[:-1])
        partial.write_bytes(BODY[:10])
        with self.assertRaisesRegex(artifacts.ArtifactError, 'range-response-too-large'):
            self.resume(partial, response=self.range_response(payload=BODY[10:] + b'extra'))
        self.assertEqual(partial.read_bytes(), BODY[:10])
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_resume_deadline_does_not_discard_previous_bytes(self):
        partial = self.make_partial()
        with mock.patch.object(artifacts.time, 'monotonic', side_effect=[0, 0, 10801]):
            with self.assertRaisesRegex(artifacts.ArtifactError, 'download-deadline-exceeded'):
                self.resume(partial)
        self.assertEqual(partial.read_bytes(), BODY[:10])
        self.assertFalse(list(self.cache.glob('*.dmg')))

    def test_resume_preserves_range_through_same_publisher_redirect_boundary(self):
        partial = self.make_partial()
        self.opener.open.side_effect = [
            Response(URLS['ccbaga'], code=302, headers=[('Location', CDN + '?signed=secret')]),
            Response(CDN + '?signed=secret', payload=BODY[10:], code=206,
                     headers=[('Content-Range', 'bytes 10-%d/%d' % (len(BODY) - 1, len(BODY)))])]
        receipt = artifacts.resume_artifact(manifest(), self.cache, partial, loopback_proxy='http://127.0.0.1:7897')
        self.assertEqual(receipt.sha256, SHA)
        self.assertNotIn('secret', repr(receipt))
        for call in self.opener.open.call_args_list:
            self.assertEqual(call[0][0].get_header('Range'), 'bytes=10-')
        self.build.assert_called_once_with('http://127.0.0.1:7897')

    def test_resume_rechecks_inode_and_size_after_network_wait(self):
        partial = self.make_partial()
        def mutate(request, **kwargs):
            partial.write_bytes(b'changed-size')
            return self.range_response()
        self.opener.open.side_effect = mutate
        with self.assertRaisesRegex(artifacts.ArtifactError, 'partial-changed'):
            artifacts.resume_artifact(manifest(), self.cache, partial)
        self.assertEqual(partial.read_bytes(), b'changed-size')

    def test_resume_cannot_overwrite_final_or_auto_promote_complete_partial(self):
        partial = self.make_partial()
        final = self.cache / (partial.stem + '.dmg')
        final.write_bytes(b'preexisting-final')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'resume-failed'):
            self.resume(partial)
        self.assertEqual(final.read_bytes(), b'preexisting-final')
        self.assertEqual(partial.read_bytes(), BODY)
        self.opener.open.reset_mock()
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-partial-size'):
            artifacts.resume_artifact(manifest(declared_size_bytes=len(BODY)), self.cache, partial)
        self.opener.open.assert_not_called()

    def test_review_upgrade_preserves_artifact_key(self):
        selected = manifest(reviewed=False)
        receipt = self.acquire(selected)
        reviewed = dataclasses.replace(selected, vendor_team_ids=(TEAM,), identity_review_sources=(REVIEW,))
        self.assertEqual(selected.artifact_key, reviewed.artifact_key)
        self.assertNotEqual(selected.manifest_sha256, reviewed.manifest_sha256)
        paths = self.make_apps(reviewed)
        self.run.side_effect = self.good_tool
        self.assertTrue(artifacts.verify_app_bundles(reviewed, self.stage, paths, receipt).binary_verification_performed)

    def test_complete_bundles_verify_without_running_apps(self):
        selected, receipt, paths = self.verified()
        result = artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.assertTrue(result.binary_verification_performed)
        self.assertFalse(result.installation_performed)
        self.assertFalse(result.extraction_proven_by_this_module)
        self.assertEqual(len(result.apps), 2)
        self.assertEqual(self.run.call_count, 8)
        requirement = self.run.call_args_list[1][0][0]
        self.assertIn('--deep', requirement)
        self.assertIn('--strict', requirement)
        self.assertEqual(requirement[requirement.index('-R') + 1], requirement[-2])
        self.assertTrue(requirement[-2].startswith('=anchor apple generic and '))
        self.assertIn('certificate leaf[subject.OU] = "' + TEAM + '"', requirement[-2])
        self.assertIn('certificate 1[field.1.2.840.113635.100.6.2.6] exists', requirement[-2])
        self.assertIn('certificate leaf[field.1.2.840.113635.100.6.1.13] exists', requirement[-2])
        self.assertTrue(requirement[-2].endswith('and identifier "org.fixture.CCBaga-A"'))
        for call in self.run.call_args_list:
            self.assertNotIn('--force', call[0][0])
            self.assertNotIn('--sign', call[0][0])
            self.assertNotIn('xattr', call[0][0])

    def test_claude_unpinned_verification_requires_explicit_review(self):
        selected = manifest('claudeDesktop', known_sha256=None)
        receipt = self.acquire(selected)
        paths = self.make_apps(selected)
        self.run.side_effect = self.good_tool
        with self.assertRaisesRegex(artifacts.PendingReview, 'checksum-policy'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        reviewed = dataclasses.replace(selected, allow_unpinned_sha256=True)
        self.assertTrue(artifacts.verify_app_bundles(reviewed, self.stage, paths, receipt).binary_verification_performed)

    def test_framework_relative_symlinks_are_preserved_and_accepted(self):
        selected, receipt, paths = self.verified()
        framework = paths[0] / 'Contents' / 'Frameworks' / 'Fixture.framework'
        version = framework / 'Versions' / 'A'
        (version / 'Resources').mkdir(parents=True)
        (version / 'Resources' / 'Info.plist').write_bytes(b'framework resource')
        (version / 'Fixture').write_bytes(b'framework fixture')
        (framework / 'Versions' / 'Current').symlink_to('A', target_is_directory=True)
        (framework / 'Resources').symlink_to('Versions/Current/Resources', target_is_directory=True)
        (framework / 'Fixture').symlink_to('Versions/Current/Fixture')
        result = artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.assertTrue(result.binary_verification_performed)
        self.assertEqual(os.readlink(framework / 'Resources'), 'Versions/Current/Resources')

    def test_escaping_broken_absolute_cyclic_links_fail_before_tools(self):
        selected, receipt, paths = self.verified()
        link = paths[0] / 'Contents' / 'Resources' / 'bad'
        for target in ('../../../../outside', '/Applications', 'nonexistent', 'bad'):
            with self.subTest(target=target):
                link.symlink_to(target)
                with self.assertRaises(artifacts.ArtifactError):
                    artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
                self.run.assert_not_called()
                link.unlink()

    def test_escape_then_reentry_is_rejected(self):
        selected, receipt, paths = self.verified()
        outside = self.stage / 'outside-link'
        outside.symlink_to(paths[0] / 'Contents' / 'Resources', target_is_directory=True)
        (paths[0] / 'Contents' / 'Resources' / 'reentry').symlink_to('../../../outside-link')
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.run.assert_not_called()

    def test_host_hardlinks_and_special_files_are_rejected(self):
        selected, receipt, paths = self.verified()
        resource = paths[0] / 'Contents' / 'Resources' / 'hardlink'
        outside = self.root / 'outside-fixture'
        outside.write_bytes(b'not a host credential')
        os.link(outside, resource)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        resource.unlink()
        os.mkfifo(resource)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.run.assert_not_called()

    def test_missing_app_or_duplicate_paths_fail(self):
        selected, receipt, paths = self.verified()
        for supplied in (paths[:1], paths + paths[:1], (paths[0], paths[0])):
            with self.assertRaisesRegex(artifacts.ArtifactError, 'incomplete-gui'):
                artifacts.verify_app_bundles(selected, self.stage, supplied, receipt)
        self.run.assert_not_called()

    def test_bundle_outside_staging_and_root_symlink_fail(self):
        selected, receipt, paths = self.verified()
        other = self.root / 'other'
        other.mkdir()
        with self.assertRaisesRegex(artifacts.ArtifactError, 'outside-staging'):
            artifacts.verify_app_bundles(selected, other, paths, receipt)
        alias = self.root / 'staging-alias'
        alias.symlink_to(self.stage, target_is_directory=True)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.verify_app_bundles(selected, alias, paths, receipt)
        self.run.assert_not_called()

    def test_plist_version_and_executable_values_are_not_guessed(self):
        selected, receipt, paths = self.verified()
        path = paths[0] / 'Contents' / 'Info.plist'
        info = plistlib.loads(path.read_bytes())
        info['CFBundleVersion'] = 'unexpected-build'
        path.write_bytes(plistlib.dumps(info))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unexpected-bundle-plist'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.run.assert_not_called()
        reviewed_app = dataclasses.replace(selected.expected_apps[0], bundle_versions=('unexpected-build',))
        selected = dataclasses.replace(selected, expected_apps=(reviewed_app, selected.expected_apps[1]))
        self.assertTrue(artifacts.verify_app_bundles(selected, self.stage, paths, receipt).binary_verification_performed)

    def test_arm64_signature_identity_and_gatekeeper_are_independent_checks(self):
        selected, receipt, paths = self.verified()
        for tool, replacement, code in (
            ('lipo', (b'x86_64\n', b''), 'arm64-required'),
            ('display', (b'', b'Identifier=org.fixture.CCBaga-A\nTeamIdentifier=WRONGTEAM1\n'), 'signing-identity-mismatch'),
            ('spctl', (b'', b'app: accepted\nsource=Developer ID\n'), 'notarized-gatekeeper'),
            ('spctl', (b'', b'assessments disabled\n'), 'notarized-gatekeeper')):
            def replaced(argv, _tool=tool, _replacement=replacement, **kwargs):
                result = self.good_tool(argv, **kwargs)
                if _tool in argv[0] or (_tool == 'display' and '--display' in argv):
                    return subprocess.CompletedProcess(argv, 0, *_replacement)
                return result
            self.run.side_effect = replaced
            with self.subTest(tool=tool), self.assertRaisesRegex(artifacts.ArtifactError, code):
                artifacts.verify_app_bundles(selected, self.stage, paths, receipt)

    def test_signature_failure_and_missing_tool_fail_closed(self):
        selected, receipt, paths = self.verified()
        self.run.side_effect = OSError('tool absent')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'tool-unavailable'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.run.side_effect = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, b'', b'rejected')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'tool-rejected'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)

    def test_mutated_artifact_is_not_trusted_from_receipt_metadata(self):
        selected, receipt, paths = self.verified()
        Path(receipt.artifact_path).write_bytes(b'changed')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'artifact-receipt-mismatch'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.run.assert_not_called()

    def test_bundle_mutation_during_tool_checks_fails(self):
        selected, receipt, paths = self.verified()
        def mutate(argv, **kwargs):
            result = self.good_tool(argv, **kwargs)
            if 'spctl' in argv[0]:
                (paths[0] / 'Contents' / 'Resources' / 'fixture.txt').write_bytes(b'tampered')
            return result
        self.run.side_effect = mutate
        with self.assertRaisesRegex(artifacts.ArtifactError, 'bundle-changed'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)

    def test_size_and_entry_limits_fail_before_tools(self):
        selected, receipt, paths = self.verified()
        for changed in (dataclasses.replace(selected, maximum_bundle_bytes=8),
                        dataclasses.replace(selected, maximum_bundle_entries=2)):
            with self.assertRaises(artifacts.ArtifactError):
                artifacts.verify_app_bundles(changed, self.stage, paths, receipt)
        self.run.assert_not_called()

    def test_caps_apply_to_the_complete_set_not_each_app_independently(self):
        selected, receipt, paths = self.verified()
        sizes = [artifacts._tree_snapshot(path, selected)[1] for path in paths]
        limited = dataclasses.replace(selected, maximum_bundle_bytes=max(sizes) + 1)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'complete-app-set-too-large'):
            artifacts.verify_app_bundles(limited, self.stage, paths, receipt)

    def test_earlier_app_cannot_change_while_later_app_is_assessed(self):
        selected, receipt, paths = self.verified()
        def mutate_previous(argv, **kwargs):
            result = self.good_tool(argv, **kwargs)
            if 'spctl' in argv[0] and argv[-1].endswith('CCBaga-B.app'):
                (paths[0] / 'Contents' / 'Resources' / 'fixture.txt').write_bytes(b'late tamper')
            return result
        self.run.side_effect = mutate_previous
        with self.assertRaisesRegex(artifacts.ArtifactError, 'bundle-changed'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)

    def test_artifact_cannot_change_during_app_assessment(self):
        selected, receipt, paths = self.verified()
        def mutate_artifact(argv, **kwargs):
            result = self.good_tool(argv, **kwargs)
            if 'spctl' in argv[0]:
                Path(receipt.artifact_path).write_bytes(b'artifact replaced')
            return result
        self.run.side_effect = mutate_artifact
        with self.assertRaisesRegex(artifacts.ArtifactError, 'artifact-changed'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)

    def test_malformed_plist_is_refused_before_tools(self):
        selected, receipt, paths = self.verified()
        (paths[0] / 'Contents' / 'Info.plist').write_bytes(b'<?xml version="1.0"?><plist><dict>')
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-info-plist'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        self.run.assert_not_called()

    def test_executable_bit_and_gui_resources_are_required(self):
        selected, receipt, paths = self.verified()
        executable = paths[0] / 'Contents' / 'MacOS' / 'CCBaga-A'
        executable.chmod(0o644)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-bundle-executable'):
            artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'gui-resources-required'):
            artifacts.AppExpectation('Fixture.app', required_paths=())
        self.run.assert_not_called()

    def test_evidence_is_private_exclusive_and_contains_static_checks(self):
        selected, receipt, paths = self.verified()
        result = artifacts.verify_app_bundles(selected, self.stage, paths, receipt)
        path = artifacts.write_evidence(result, self.cache / 'verified.json')
        saved = json.loads(path.read_text())
        self.assertEqual(saved['artifact_sha256'], SHA)
        self.assertEqual(saved['apps'][0]['team_id'], TEAM)
        self.assertIn('commands', saved['apps'][0])
        self.assertFalse(saved['installation_performed'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            artifacts.write_evidence(result, path)

    def test_extraction_plan_does_not_mount_or_extract(self):
        plan = artifacts.extraction_plan(manifest())
        self.assertEqual(plan['format'], 'dmg')
        self.assertEqual(plan['expected_apps'], ['CCBaga-A.app', 'CCBaga-B.app'])
        self.assertFalse(plan['execution_permitted'])
        self.run.assert_not_called()
        self.opener.open.assert_not_called()


class ProxyPolicyTests(unittest.TestCase):
    def test_only_explicit_credential_free_loopback_http_proxy(self):
        with mock.patch.object(artifacts.urllib.request, 'build_opener') as build:
            artifacts._build_opener()
            self.assertEqual(build.call_args[0][0].proxies, {})
            for proxy in ('http://127.0.0.1:7897', 'http://[::1]:7897'):
                artifacts._build_opener(proxy)
                self.assertEqual(build.call_args[0][0].proxies, {'https': proxy})
            for invalid in ('http://localhost:7897', 'http://user:pass@127.0.0.1:7897',
                            'http://127.0.0.1:7897/', 'http://127.0.0.1:7897?token=x',
                            'https://127.0.0.1:7897', 'http://192.168.1.1:7897',
                            'http://127.0.0.1:0', 'http://127.0.0.1:65536',
                            'http://127.0.0.1:7897#x'):
                with self.subTest(invalid=invalid), self.assertRaises(artifacts.ArtifactError):
                    artifacts._build_opener(invalid)


if __name__ == '__main__':
    unittest.main()
