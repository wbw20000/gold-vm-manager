"""Offline tiny fixtures only; no real downloads, native tools or VM operations."""
import dataclasses
from email.message import Message
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
from types import MappingProxyType
import unittest
from unittest import mock
import urllib.error
import urllib.request

import host_artifacts as artifacts


BODY = b'tiny inert host artifact fixture; never executable\n'
SHA = hashlib.sha256(BODY).hexdigest()
REAL_SPECS = artifacts.SPECS
REAL_BUILD_OPENER = artifacts._build_opener
SPEC = dataclasses.replace(REAL_SPECS['podman-installer'], size_bytes=len(BODY), sha256=SHA)
CDN = ('https://release-assets.githubusercontent.com/github-production-release-asset/'
       '123456/12345678-1234-1234-1234-123456789abc')


class Response(io.BytesIO):
    def __init__(self, payload=BODY, url=SPEC.url, code=200, headers=()):
        super().__init__(payload)
        self.url, self.code = url, code
        self.headers = Message()
        for name, value in headers:
            self.headers.add_header(name, value)

    def geturl(self):
        return self.url


class HostArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='host-artifact-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cache = self.root / 'cache'
        self.opener = mock.Mock()
        self.opener.open.side_effect = lambda *args, **kw: Response()
        # Only tests replace the immutable registry with tiny size/hash fixtures.
        self.patch(mock.patch.object(artifacts, 'SPECS', MappingProxyType({'podman-installer': SPEC})))
        self.build = self.patch(mock.patch.object(artifacts, '_build_opener', return_value=self.opener))
        self.quarantine = self.patch(mock.patch.object(artifacts.quarantine_policy, 'ensure',
                                                       side_effect=self.ensure_fixture))
        self.native = self.patch(mock.patch('subprocess.run', side_effect=AssertionError('native forbidden')))

    def patch(self, context):
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def ensure_fixture(self, path):
        path = Path(path)
        data = json.loads((path.parent / 'receipt.json').read_text())
        self.assertEqual(data['sha256'], SHA)
        self.assertTrue(data['digest_verified'])
        self.assertFalse(data['quarantine_ensured'])
        self.assertFalse(data['native_execution_approved'])
        self.assertEqual(path.read_bytes(), BODY)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        return b'0083;0;Fixture;not-native'

    def acquire(self, response=None, **kwargs):
        if response is not None:
            self.opener.open.side_effect = None
            self.opener.open.return_value = response
        return artifacts.acquire('podman-installer', self.cache, **kwargs)

    def attempts(self):
        return sorted(self.cache.glob('podman-installer-*')) if self.cache.exists() else []

    def source(self, payload=BODY):
        path = self.root / 'local.fixture'
        path.write_bytes(payload)
        return path

    def assert_not_accepted(self):
        self.assertFalse(list(self.cache.glob('*/accepted.json')))
        self.quarantine.assert_not_called()

    def test_public_registry_pins_and_immutable_types(self):
        self.assertEqual(set(REAL_SPECS), {'podman-installer', 'tart', 'ipsw'})
        podman = REAL_SPECS['podman-installer']
        self.assertEqual((podman.version, podman.size_bytes), ('6.2.0', 76730429))
        self.assertEqual(podman.sha256, 'b4628a29a4c70bbec757a84d0e429882d358cab18956a0017f99df74b37201a7')
        self.assertEqual(podman.url, 'https://github.com/podman-container-tools/podman/releases/download/'
                                     'v6.2.0/podman-installer-macos-arm64.pkg')
        self.assertNotIn('gvisor-tap-vsock', ' '.join(spec.url for spec in REAL_SPECS.values()))
        self.assertEqual(REAL_SPECS['tart'].version, '2.41.1')
        self.assertEqual(REAL_SPECS['tart'].size_bytes, 22959557)
        self.assertEqual(REAL_SPECS['tart'].sha256,
                         'e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2')
        ipsw = REAL_SPECS['ipsw']
        self.assertEqual(ipsw.size_bytes, 19772231540)
        self.assertEqual(ipsw.sha256,
                         '885503b7f4b06609e9a512f2befd40f59730640a3f1233e3892d60affdd51c95')
        self.assertEqual(ipsw.hash_provenance, 'reviewed-local-digest-of-official-https-acquisition')
        with self.assertRaises(TypeError):
            REAL_SPECS['other'] = SPEC
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ipsw.size_bytes = 1

    def test_unknown_key_and_spec_object_are_not_arbitrary_url_api(self):
        for key in ('https://example.invalid/a', SPEC, None, [], 'other'):
            with self.subTest(key=key), self.assertRaises(artifacts.ArtifactError):
                artifacts.acquire(key, self.cache)
        self.build.assert_not_called()
        self.assertFalse(self.cache.exists())

    def test_import_module_has_no_io_or_native_activity(self):
        source = Path(artifacts.__file__).read_text()
        with mock.patch('urllib.request.build_opener') as build, mock.patch('os.open') as opened:
            exec(compile(source, artifacts.__file__, 'exec'), {'__name__': 'host_artifacts'})
        build.assert_not_called()
        opened.assert_not_called()
        self.native.assert_not_called()
        self.quarantine.assert_not_called()

    def test_success_receipt_order_permissions_and_no_execution_approval(self):
        receipt = self.acquire(Response(headers=[('Content-Length', str(len(BODY)))]))
        self.assertEqual(Path(receipt.artifact_path).read_bytes(), BODY)
        self.assertEqual(receipt.sha256, SHA)
        self.assertEqual(receipt.source_kind, 'download')
        self.assertTrue(receipt.quarantine_ensured)
        self.assertTrue(receipt.digest_verified)
        self.assertFalse(receipt.native_execution_approved)
        self.assertFalse(receipt.binary_verification_performed)
        self.assertFalse(receipt.apple_restore_validation_performed)
        self.assertEqual(receipt.final_host, 'github.com')
        self.assertEqual(json.loads(Path(receipt.acceptance_path).read_text()), dataclasses.asdict(receipt))
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(Path(receipt.artifact_path).parent.stat().st_mode), 0o700)
        for path in Path(receipt.artifact_path).parent.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.quarantine.assert_called_once()
        self.native.assert_not_called()
        request = self.opener.open.call_args[0][0]
        self.assertEqual(request.full_url, SPEC.url)
        self.assertEqual(request.get_header('Accept-encoding'), 'identity')
        for header in ('Cookie', 'Authorization', 'Proxy-authorization', 'Range', 'If-range'):
            self.assertIsNone(request.get_header(header))

    def test_progress_covers_network_full_disk_hash_and_acceptance(self):
        events = []
        self.acquire(progress=events.append)
        self.assertEqual({e.phase for e in events}, {'download', 'verify', 'accepted'})
        self.assertTrue(all(e.total_bytes == len(BODY) and e.spec_key == 'podman-installer' for e in events))
        self.assertEqual(events[-1].completed_bytes, len(BODY))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            events[-1].phase = 'executed'

    def test_redirect_signed_query_is_not_persisted(self):
        secret = '?jwt=do-not-save-signed-credential'
        first = Response(b'', code=302, headers=[('Location', CDN + secret)])
        last = Response(url=CDN + secret)
        self.opener.open.side_effect = [first, last]
        receipt = self.acquire()
        self.assertTrue(first.closed)
        self.assertTrue(last.closed)
        self.assertEqual(receipt.final_host, 'release-assets.githubusercontent.com')
        self.assertNotIn('do-not-save', repr(receipt))
        for path in Path(receipt.artifact_path).parent.glob('*.json'):
            self.assertNotIn('do-not-save', path.read_text())
        second = self.opener.open.call_args_list[1][0][0]
        self.assertIsNone(second.get_header('Referer'))

    def test_real_urllib_http_error_redirect_is_supported(self):
        headers = Message()
        headers['Location'] = CDN
        error = urllib.error.HTTPError(SPEC.url, 302, 'found', headers, io.BytesIO())
        self.opener.open.side_effect = [error, Response(url=CDN)]
        self.assertEqual(self.acquire().final_host, 'release-assets.githubusercontent.com')

    def test_redirect_boundaries_reject_unreviewed_hosts_and_paths(self):
        invalid = [CDN.replace('https:', 'http:'), CDN.replace('release-assets.', 'evil.'),
                   CDN.replace('githubusercontent.com', 'githubusercontent.com.evil'),
                   CDN.replace('https://', 'https://u:secret@'), CDN + '#fragment',
                   CDN.replace('.com/', '.com:443/'), CDN.replace('/123456/', '/../../123456/'),
                   CDN.replace('/github-', '/%67ithub-'), SPEC.url + '?mirror=true',
                   'https://updates.cdn-apple.com/another-file', CDN + '\n']
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(artifacts.ArtifactError):
                artifacts._redirect(SPEC, SPEC.url, url)
        artifacts._redirect(SPEC, SPEC.url, CDN)
        artifacts._redirect(SPEC, CDN, CDN + '?refreshed=transport-only')
        with self.assertRaises(artifacts.ArtifactError):
            artifacts._redirect(SPEC, CDN, CDN.replace('123456789abc', '123456789abd'))
        with self.assertRaises(artifacts.ArtifactError):
            artifacts._redirect(REAL_SPECS['ipsw'], REAL_SPECS['ipsw'].url, CDN)

    def test_invalid_redirect_is_not_followed(self):
        with self.assertRaisesRegex(artifacts.ArtifactError, 'untrusted-redirect'):
            self.acquire(Response(code=302, headers=[('Location', 'https://evil.invalid/private')]))
        self.assertEqual(self.opener.open.call_count, 1)
        self.assert_not_accepted()

    def test_implicit_redirect_rejected(self):
        with self.assertRaisesRegex(artifacts.ArtifactError, 'implicit-redirect'):
            self.acquire(Response(url=CDN))
        self.assert_not_accepted()

    def test_redirect_loop_is_finite(self):
        self.opener.open.side_effect = lambda *a, **k: Response(code=302, headers=[('Location', SPEC.url)])
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-redirect'):
            self.acquire()
        self.assertEqual(self.opener.open.call_count, 5)

    def test_http_206_416_auth_errors_and_500_are_not_retries(self):
        for status in (206, 416, 401, 403, 500):
            with self.subTest(status=status), self.assertRaisesRegex(artifacts.ArtifactError, 'unexpected-http'):
                self.acquire(Response(code=status))
        self.assertEqual(len(self.attempts()), 5)
        self.assertEqual(self.opener.open.call_count, 5)
        self.assert_not_accepted()

    def test_headers_size_encoding_and_duplicate_values_are_strict(self):
        invalid = [[('Content-Length', str(len(BODY) + 1))], [('Content-Length', '-1')],
                   [('Content-Length', '2'), ('Content-Length', '2')],
                   [('Content-Length', str(len(BODY))), ('Transfer-Encoding', 'chunked')],
                   [('Content-Encoding', 'gzip')], [('Content-Encoding', 'identity'), ('Content-Encoding', 'identity')],
                   [('Content-Range', 'bytes 0-1/2')], [('Transfer-Encoding', 'gzip')]]
        for headers in invalid:
            with self.subTest(headers=headers), self.assertRaises(artifacts.ArtifactError):
                self.acquire(Response(headers=headers))
        self.assert_not_accepted()

    def test_chunked_and_no_length_still_require_exact_whole_pin(self):
        self.acquire(Response(headers=[('Transfer-Encoding', 'chunked')]))
        self.quarantine.assert_called_once()

    def test_truncated_overlong_and_bad_hash_leave_failed_attempts(self):
        for payload in (BODY[:-1], BODY + b'!', b'X' * len(BODY)):
            with self.subTest(payload=payload), self.assertRaises(artifacts.ArtifactError) as raised:
                self.acquire(Response(payload=payload))
            attempt = self.cache / raised.exception.attempt_id
            self.assertTrue((attempt / SPEC.filename).exists())
            self.assertTrue((attempt / 'attempt.json').exists())
            self.assertFalse((attempt / 'receipt.json').exists())
        self.assertEqual(len(self.attempts()), 3)
        self.assert_not_accepted()

    def test_partial_is_not_automatically_resumed_or_overwritten(self):
        with self.assertRaises(artifacts.ArtifactError) as raised:
            self.acquire(Response(payload=BODY[:3]))
        first = self.cache / raised.exception.attempt_id / SPEC.filename
        before = first.stat()
        receipt = self.acquire(Response())
        self.assertNotEqual(first, Path(receipt.artifact_path))
        self.assertEqual(first.read_bytes(), BODY[:3])
        self.assertEqual(before.st_ino, first.stat().st_ino)
        for call in self.opener.open.call_args_list:
            self.assertIsNone(call[0][0].get_header('Range'))

    def test_cache_reuse_fresh_hash_no_network_and_quarantine_recheck(self):
        first = self.acquire()
        self.build.reset_mock()
        events = []
        with mock.patch.object(artifacts, '_hash_file', wraps=artifacts._hash_file) as hashed:
            second = self.acquire(progress=events.append)
        self.assertEqual(first, second)
        self.build.assert_not_called()
        self.assertEqual(len(self.attempts()), 1)
        self.assertEqual(hashed.call_count, 1)
        self.assertEqual(self.quarantine.call_count, 2)
        self.assertEqual({e.phase for e in events}, {'cache-verify'})

    def test_cache_content_mutation_with_restored_mtime_fails_digest(self):
        receipt = self.acquire()
        path = Path(receipt.artifact_path)
        info = path.stat()
        path.write_bytes(b'X' * len(BODY))
        os.utime(str(path), ns=(info.st_atime_ns, info.st_mtime_ns))
        self.build.reset_mock()
        with self.assertRaisesRegex(artifacts.ArtifactError, 'checksum-mismatch'):
            self.acquire()
        self.build.assert_not_called()
        self.assertEqual(path.read_bytes(), b'X' * len(BODY))

    def test_cache_receipt_mismatch_fails_closed_without_replacement(self):
        receipt = self.acquire()
        path = Path(receipt.receipt_path)
        data = json.loads(path.read_text())
        data['native_execution_approved'] = True
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-cache-receipt'):
            self.acquire()
        self.assertEqual(len(self.attempts()), 1)

    def test_cache_receipt_boolean_integer_confusion_is_refused(self):
        receipt = self.acquire()
        path = Path(receipt.receipt_path)
        data = json.loads(path.read_text())
        data['digest_verified'] = 1
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'invalid-cache-receipt'):
            self.acquire()

    def test_quarantine_failure_retains_durable_receipt_but_not_acceptance(self):
        self.quarantine.side_effect = RuntimeError('secret-native-error')
        with self.assertRaisesRegex(artifacts.ArtifactError, '^quarantine-failed$') as raised:
            self.acquire()
        self.assertNotIn('secret', repr(raised.exception))
        attempt = self.cache / raised.exception.attempt_id
        self.assertTrue((attempt / 'receipt.json').exists())
        self.assertFalse((attempt / 'accepted.json').exists())
        self.assertEqual((attempt / SPEC.filename).read_bytes(), BODY)
        self.quarantine.side_effect = self.ensure_fixture
        self.acquire()
        self.assertEqual(len(self.attempts()), 2)

    def test_receipt_fsync_failure_does_not_reach_quarantine(self):
        original = artifacts._save_json
        def fail(directory_fd, name, value):
            if name == 'receipt.json':
                raise OSError('secret-fsync-error')
            return original(directory_fd, name, value)
        with mock.patch.object(artifacts, '_save_json', side_effect=fail):
            with self.assertRaises(artifacts.ArtifactError):
                self.acquire()
        self.assert_not_accepted()

    def test_transfer_failure_cause_is_a_fixed_code(self):
        for error, code in ((urllib.error.URLError(socket.timeout('SECRET')), 'download-timeout'),
                            (urllib.error.URLError(ConnectionRefusedError(61, 'SECRET')), 'download-connect-failed')):
            with self.subTest(code=code):
                self.opener.open.side_effect = error
                with self.assertRaises(artifacts.ArtifactError) as raised:
                    self.acquire()
                self.assertEqual(str(raised.exception), code)
                self.assertTrue(raised.exception.__suppress_context__)
                self.assertIsNotNone(raised.exception.attempt_id)

    def test_public_error_does_not_include_signed_url_or_credentials(self):
        self.opener.open.side_effect = urllib.error.URLError('https://user:password@host/?jwt=secret')
        with self.assertRaises(artifacts.ArtifactError) as raised:
            self.acquire()
        self.assertEqual(str(raised.exception), 'artifact-io-failed')
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertIsNotNone(raised.exception.attempt_id)

    def test_bad_proxy_is_rejected_before_any_cache_io(self):
        for proxy in ('http://user:pass@127.0.0.1:8', 'http://localhost:8', 'https://127.0.0.1:8',
                      'socks5://127.0.0.1:8', 'http://127.1:8', 'http://127.0.0.1:08',
                      'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://127.0.0.1:8/',
                      'http://127.0.0.1:8?auth=secret', 'http://[::1]:8#x', 8):
            with self.subTest(proxy=proxy), self.assertRaises(artifacts.ArtifactError):
                self.acquire(loopback_proxy=proxy)
        self.assertFalse(self.cache.exists())
        self.build.assert_not_called()

    def test_proxy_handler_ignores_ambient_bypass_and_credentials(self):
        for proxy in ('http://127.0.0.1:8080', 'http://[::1]:8080'):
            handler = artifacts._ExplicitProxyHandler(artifacts._proxy(proxy))
            request = urllib.request.Request(SPEC.url)
            with mock.patch('urllib.request.proxy_bypass', side_effect=AssertionError('ambient forbidden')):
                handler.proxy_open(request, proxy, 'https')
            self.assertEqual(request.host, urllib.parse.urlsplit(proxy).netloc)
            self.assertIsNone(request.get_header('Proxy-authorization'))
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://user:secret@bad:8', 'ALL_PROXY': 'bad'}):
            empty = artifacts._ExplicitProxyHandler(artifacts._proxy(None))
        self.assertEqual(empty.proxies, {})

    def test_deadline_and_callbacks_are_validated(self):
        for seconds in (True, 0, -1, 0.5, float('inf'), artifacts.MAX_DEADLINE_SECONDS + 1):
            with self.subTest(seconds=seconds), self.assertRaises(artifacts.ArtifactError):
                self.acquire(deadline_seconds=seconds)
        for kwargs in ({'progress': 3}, {'cancelled': False}, {'cancelled': lambda: 1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(artifacts.ArtifactError):
                self.acquire(**kwargs)
        self.build.assert_not_called()

    def test_cancel_before_attempt_has_no_io(self):
        with self.assertRaisesRegex(artifacts.ArtifactError, '^cancelled$'):
            self.acquire(cancelled=lambda: True)
        self.assertFalse(self.cache.exists())

    def test_cancel_mid_download_retains_partial_and_closes_response(self):
        stop = [False]
        def progress(event):
            if event.phase == 'download' and event.completed_bytes:
                stop[0] = True
        response = Response()
        with self.assertRaisesRegex(artifacts.ArtifactError, '^cancelled$'):
            self.acquire(response, progress=progress, cancelled=lambda: stop[0])
        self.assertTrue(response.closed)
        self.assertEqual(len(self.attempts()), 1)
        self.assert_not_accepted()

    def test_deadline_expiry_during_network_closes_and_retains(self):
        clock = [1.0]
        def response(*args, **kwargs):
            clock[0] = 20.0
            return Response()
        self.opener.open.side_effect = response
        with mock.patch.object(artifacts.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(artifacts.ArtifactError, 'deadline-exceeded'):
                self.acquire(deadline_seconds=1)
        self.assert_not_accepted()

    def test_callback_exception_is_sanitized(self):
        def bad(event):
            raise RuntimeError('credentials=do-not-print')
        with self.assertRaisesRegex(artifacts.ArtifactError, '^progress-callback-failed$'):
            self.acquire(progress=bad)
        self.assert_not_accepted()

    def test_symlink_cache_root_or_component_refused(self):
        actual = self.root / 'actual'
        actual.mkdir(mode=0o700)
        self.cache.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(artifacts.ArtifactError):
            self.acquire()
        self.assertFalse(list(actual.iterdir()))
        self.build.assert_not_called()

    def test_world_readable_cache_root_refused(self):
        self.cache.mkdir(mode=0o755)
        self.cache.chmod(0o755)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-private-directory'):
            self.acquire()
        self.build.assert_not_called()

    def test_symlink_or_hardlink_accepted_artifact_refused(self):
        receipt = self.acquire()
        path = Path(receipt.artifact_path)
        # Create a link only inside this fixture's private temporary tree.
        os.link(str(path), str(self.root / 'alias.fixture'))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-file'):
            self.acquire()

    def test_cache_flock_is_nonblocking(self):
        receipt = self.acquire()
        with open(receipt.artifact_path, 'rb') as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(artifacts.ArtifactError, 'artifact-in-use'):
                self.acquire()

    def test_local_import_copies_new_inode_and_never_mutates_source(self):
        source = self.source()
        before = source.stat()
        receipt = artifacts.import_local('podman-installer', source, self.cache)
        after = source.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_mode),
                         (after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_mode))
        self.assertNotEqual(before.st_ino, Path(receipt.artifact_path).stat().st_ino)
        self.assertEqual(receipt.source_kind, 'local-import')
        self.assertEqual(receipt.final_host, '')
        self.assertNotIn(str(source), Path(receipt.receipt_path).read_text())
        self.build.assert_not_called()
        self.quarantine.assert_called_once_with(Path(receipt.artifact_path))

    def test_import_verifies_source_even_if_cache_already_accepted(self):
        self.acquire()
        with self.assertRaisesRegex(artifacts.ArtifactError, 'checksum-mismatch'):
            artifacts.import_local('podman-installer', self.source(b'X' * len(BODY)), self.cache)
        self.assertEqual(len(self.attempts()), 2)

    def test_local_import_rejects_symlink_hardlink_fifo_and_directory(self):
        source = self.source()
        alias = self.root / 'alias'
        alias.symlink_to(source)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.import_local('podman-installer', alias, self.cache)
        hardlink = self.root / 'hardlink'
        os.link(str(source), str(hardlink))
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.import_local('podman-installer', source, self.cache)
        fifo = self.root / 'fifo'
        os.mkfifo(str(fifo))
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.import_local('podman-installer', fifo, self.cache)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.import_local('podman-installer', self.root, self.cache)
        self.assert_not_accepted()
        self.build.assert_not_called()

    def test_import_source_change_during_copy_is_refused(self):
        source = self.source()
        def changed(event):
            if event.phase == 'import' and event.completed_bytes:
                source.write_bytes(b'X' * len(BODY))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'source-changed'):
            artifacts.import_local('podman-installer', source, self.cache, progress=changed)
        self.assert_not_accepted()

    def test_owner_mismatch_and_private_file_modes_fail_closed(self):
        receipt = self.acquire()
        path = Path(receipt.artifact_path)
        path.chmod(0o644)
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-file-mode'):
            self.acquire()
        with mock.patch.object(artifacts.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-private-directory'):
                self.acquire()

    def test_opener_has_explicit_proxy_and_no_custom_tls_or_cookie_handlers(self):
        with mock.patch('urllib.request.build_opener') as constructor:
            REAL_BUILD_OPENER(None)
        args, kwargs = constructor.call_args
        self.assertEqual(kwargs, {})
        self.assertEqual(len(args), 2)
        self.assertIsInstance(args[0], artifacts._ExplicitProxyHandler)
        self.assertEqual(args[0].proxies, {})
        self.assertIsInstance(args[1], artifacts._NoRedirect)

    def test_symlink_attempt_directory_is_not_traversed(self):
        self.cache.mkdir(mode=0o700)
        target = self.root / 'external'
        target.mkdir(mode=0o700)
        (self.cache / ('podman-installer-' + 'a' * 32)).symlink_to(target, target_is_directory=True)
        with self.assertRaises(artifacts.ArtifactError):
            self.acquire()
        self.build.assert_not_called()
        self.assertFalse(list(target.iterdir()))

    def test_hardlinked_metadata_is_not_trusted(self):
        receipt = self.acquire()
        os.link(receipt.receipt_path, str(self.root / 'receipt-alias.fixture'))
        with self.assertRaisesRegex(artifacts.ArtifactError, 'unsafe-file'):
            self.acquire()

    def test_destination_bytes_are_rehashed_not_only_source_digest(self):
        def bad_copy(fd, source, spec, attempt, budget):
            os.write(fd, b'X' * len(BODY))
        with mock.patch.object(artifacts, '_copy_source', side_effect=bad_copy):
            with self.assertRaisesRegex(artifacts.ArtifactError, 'checksum-mismatch'):
                artifacts.import_local('podman-installer', self.source(), self.cache)
        self.assert_not_accepted()

    def test_quarantine_byte_mutation_prevents_acceptance(self):
        def mutate(path):
            self.ensure_fixture(path)
            Path(path).write_bytes(BODY + b'mutated')
        self.quarantine.side_effect = mutate
        with self.assertRaisesRegex(artifacts.ArtifactError, 'file-changed'):
            self.acquire()
        self.assertFalse(list(self.cache.glob('*/accepted.json')))
        self.assertEqual(len(list(self.cache.glob('*/receipt.json'))), 1)

    def test_fsync_durability_precedes_quarantine(self):
        fsynced = []
        real_fsync = os.fsync
        def tracked(fd):
            real_fsync(fd)
            fsynced.append((os.fstat(fd).st_dev, os.fstat(fd).st_ino))
        def ensure(path):
            info = (Path(path).parent / 'receipt.json').stat()
            self.assertIn((info.st_dev, info.st_ino), fsynced)
            directory = Path(path).parent.stat()
            self.assertIn((directory.st_dev, directory.st_ino), fsynced)
            return self.ensure_fixture(path)
        self.quarantine.side_effect = ensure
        with mock.patch.object(artifacts.os, 'fsync', side_effect=tracked):
            self.acquire()

    def test_progress_throttles_tiny_network_chunks_but_keeps_boundaries(self):
        class TinyResponse(Response):
            def read1(self, size):
                return super().read1(min(size, 1))
        events = []
        with mock.patch.object(artifacts.time, 'monotonic', return_value=1.0):
            self.acquire(TinyResponse(), progress=events.append)
        network = [event.completed_bytes for event in events if event.phase == 'download']
        self.assertEqual(network, [0, len(BODY)])
        self.assertEqual(events[-1].phase, 'accepted')

    def test_no_resume_api_is_advertised(self):
        self.assertFalse(hasattr(artifacts, 'resume'))
        self.assertFalse(hasattr(artifacts, 'resume_artifact'))


if __name__ == '__main__':
    unittest.main()
