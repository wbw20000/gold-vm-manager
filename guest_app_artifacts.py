"""Python 3.9 stdlib-only, explicit artifact acquisition and static GUI verification.

No import-time I/O, app execution, mounting, extraction, installation, host-profile
access, xattr modification or signature mutation. A DownloadReceipt authenticates
neither an application nor its publisher. The caller owns safe extraction from
that artifact, exclusive staging, preserving signatures/quarantine, and verifying
again after copying. Trust and plist allow-values come from external review, never
from the binary under examination. See GUEST_APP_ARTIFACTS.md.
"""

import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import subprocess
import time
from typing import Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request
import unicodedata
import uuid
from xml.parsers.expat import ExpatError


MAX_DOWNLOAD_BYTES = 2 * 1024 ** 3
MAX_BUNDLE_BYTES = 8 * 1024 ** 3
MAX_BUNDLE_ENTRIES = 100000
MAX_PLIST_BYTES = 1024 ** 2
MAX_TOOL_OUTPUT = 1024 ** 2
CHUNK_BYTES = 1024 ** 2
DEFAULT_DOWNLOAD_DEADLINE_SECONDS = 2700
MAX_DOWNLOAD_DEADLINE_SECONDS = 10800
# Repository IDs verified using the public GitHub repository APIs, 2026-11-17.
_PRODUCTS = {
    'ccbaga': ('liseami/CCBaga', '1413898431', ('CCBaga-A.app', 'CCBaga-B.app')),
    'clashVergeRev': ('clash-verge-rev/clash-verge-rev', '721767116', ('Clash Verge.app',)),
    'claudeDesktop': (None, None, ('Claude.app',)),
}
_VERSION = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
_SHA256 = r'[0-9a-f]{64}'


class ArtifactError(Exception):
    """Stable error codes; never include network bodies, signed URLs or secrets."""


class PendingReview(ArtifactError):
    """A missing trust decision is not a verification success."""


def _need(condition, code):
    if not condition:
        raise ArtifactError(code)


def _text(value, max_length=200):
    return (isinstance(value, str) and 0 < len(value) <= max_length
            and all(ord(c) >= 32 and ord(c) != 127 for c in value))


def _allow_values(values, pattern=None):
    _need(isinstance(values, tuple) and len(values) <= 32, 'invalid-allow-values')
    _need(len(set(values)) == len(values), 'duplicate-allow-value')
    for value in values:
        _need(_text(value), 'invalid-allow-value')
        if pattern:
            _need(re.fullmatch(pattern, value) is not None, 'invalid-allow-value')


@dataclasses.dataclass(frozen=True)
class AppExpectation:
    name: str
    bundle_identifiers: Tuple[str, ...] = ()
    bundle_names: Tuple[str, ...] = ()
    executable_names: Tuple[str, ...] = ()
    short_versions: Tuple[str, ...] = ()
    bundle_versions: Tuple[str, ...] = ()
    required_paths: Tuple[str, ...] = ('Contents/Resources',)

    def __post_init__(self):
        _need(_text(self.name) and '/' not in self.name and '\\' not in self.name
              and self.name.endswith('.app'), 'invalid-app-name')
        for values in (self.bundle_identifiers, self.bundle_names, self.executable_names,
                       self.short_versions, self.bundle_versions, self.required_paths):
            _allow_values(values)
        for value in self.bundle_identifiers:
            _need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', value) is not None,
                  'invalid-bundle-identifier')
        for value in self.executable_names:
            _need(value not in ('.', '..') and '/' not in value and '\\' not in value,
                  'invalid-executable-name')
        _need('Contents/Resources' in self.required_paths, 'gui-resources-required')
        for value in self.required_paths:
            parts = PurePosixPath(value).parts
            _need(not value.startswith('/') and '\\' not in value and '..' not in parts
                  and parts and parts[0] == 'Contents' and str(PurePosixPath(value)) == value,
                  'invalid-required-path')


@dataclasses.dataclass(frozen=True)
class ArtifactManifest:
    product: str
    version: str
    artifact_url: str
    known_sha256: Optional[str]
    expected_apps: Tuple[AppExpectation, ...]
    vendor_team_ids: Tuple[str, ...] = ()
    identity_review_sources: Tuple[str, ...] = ()
    declared_size_bytes: Optional[int] = None
    maximum_download_bytes: int = MAX_DOWNLOAD_BYTES
    maximum_bundle_bytes: int = MAX_BUNDLE_BYTES
    maximum_bundle_entries: int = MAX_BUNDLE_ENTRIES
    allow_unpinned_sha256: bool = False

    def __post_init__(self):
        _need(self.product in _PRODUCTS, 'unsupported-product')
        _need(isinstance(self.version, str) and len(self.version) <= 48
              and re.fullmatch(_VERSION, self.version) is not None, 'invalid-version')
        _need(self.known_sha256 is None or (isinstance(self.known_sha256, str)
              and re.fullmatch(_SHA256, self.known_sha256) is not None), 'invalid-sha256')
        _need(self.product == 'claudeDesktop' or self.known_sha256 is not None,
              'publisher-checksum-required')
        _need(isinstance(self.expected_apps, tuple)
              and all(isinstance(a, AppExpectation) for a in self.expected_apps)
              and tuple(a.name for a in self.expected_apps) == _PRODUCTS[self.product][2],
              'incomplete-gui-app-set')
        _allow_values(self.vendor_team_ids, r'[A-Z0-9]{10}')
        _allow_values(self.identity_review_sources)
        for source in self.identity_review_sources:
            parsed = _https_url(source)
            _need(not parsed.query, 'invalid-review-source')
        for value, cap in ((self.maximum_download_bytes, MAX_DOWNLOAD_BYTES),
                           (self.maximum_bundle_bytes, MAX_BUNDLE_BYTES),
                           (self.maximum_bundle_entries, MAX_BUNDLE_ENTRIES)):
            _need(type(value) is int and 0 < value <= cap, 'invalid-size-cap')
        _need(self.declared_size_bytes is None or (type(self.declared_size_bytes) is int
              and 0 < self.declared_size_bytes <= self.maximum_download_bytes),
              'invalid-declared-size')
        _need(type(self.allow_unpinned_sha256) is bool, 'invalid-hash-policy')
        _validate_origin(self)

    @property
    def artifact_key(self):
        # Review fields may be filled after downloading without changing bytes.
        return _json_hash({k: getattr(self, k) for k in (
            'product', 'version', 'artifact_url', 'known_sha256',
            'declared_size_bytes', 'maximum_download_bytes')})

    @property
    def manifest_sha256(self):
        return _json_hash(dataclasses.asdict(self))


def freeze_manifest(*, product, version, artifact_url, known_sha256,
                    expected_apps=None, vendor_team_ids=(), identity_review_sources=(),
                    declared_size_bytes=None, maximum_download_bytes=MAX_DOWNLOAD_BYTES,
                    maximum_bundle_bytes=MAX_BUNDLE_BYTES,
                    maximum_bundle_entries=MAX_BUNDLE_ENTRIES,
                    allow_unpinned_sha256=False):
    """Freeze reviewed inputs; absent identity/plist values stay pending.

    Expected application names are fixed, including BOTH CCBaga bundles. Explicit
    plist allow-values may differ from the product version (e.g. Chromium B).
    """
    _need(product in _PRODUCTS, 'unsupported-product')
    apps = (tuple(AppExpectation(name) for name in _PRODUCTS[product][2])
            if expected_apps is None else tuple(expected_apps))
    return ArtifactManifest(product, version, artifact_url, known_sha256, apps,
                            tuple(vendor_team_ids), tuple(identity_review_sources),
                            declared_size_bytes, maximum_download_bytes,
                            maximum_bundle_bytes, maximum_bundle_entries,
                            allow_unpinned_sha256)


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def _json_hash(value):
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _https_url(url):
    _need(_text(url, 16384) and url.isascii() and not any(c.isspace() for c in url)
          and '\\' not in url, 'untrusted-url')
    try:
        parsed = urllib.parse.urlsplit(url)
        _need(parsed.scheme == 'https' and parsed.hostname
              and parsed.netloc == parsed.hostname and not parsed.fragment
              and not parsed.username and not parsed.password and parsed.port is None,
              'untrusted-url')
    except ValueError:
        raise ArtifactError('untrusted-url') from None
    return parsed


def _validate_origin(manifest):
    parsed = _https_url(manifest.artifact_url)
    repo = _PRODUCTS[manifest.product][0]
    if repo:
        name = ('CCBaga-%s-macos-arm64.dmg' % manifest.version if manifest.product == 'ccbaga'
                else 'Clash.Verge_%s_aarch64.dmg' % manifest.version)
        expected = 'https://github.com/%s/releases/download/v%s/%s' % (repo, manifest.version, name)
        _need(manifest.artifact_url == expected, 'untrusted-artifact-origin')
    else:
        prefix = '/releases/darwin/universal/%s/' % manifest.version
        _need(parsed.hostname == 'downloads.claude.ai' and not parsed.query
              and parsed.path.startswith(prefix)
              and re.fullmatch(r'Claude-[0-9a-f]{40}\.zip', parsed.path[len(prefix):]) is not None,
              'untrusted-artifact-origin')


def validate_artifact_redirect(manifest, previous_url, next_url):
    """Only the exact publisher URL -> repository-scoped GitHub CDN path.

    CDN signed query strings are transport data, never saved in receipts. Claude
    has no reviewed cross-host redirect boundary and therefore allows none.
    """
    previous = _https_url(previous_url)
    target = _https_url(next_url)
    if next_url == manifest.artifact_url and previous_url == manifest.artifact_url:
        return
    repo_id = _PRODUCTS[manifest.product][1]
    _need(repo_id is not None, 'untrusted-redirect')
    pattern = (r'/github-production-release-asset/%s/' % repo_id
               + r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    _need(target.hostname == 'release-assets.githubusercontent.com'
          and re.fullmatch(pattern, target.path) is not None, 'untrusted-redirect')
    _need(previous_url == manifest.artifact_url or (
        previous.hostname == target.hostname and previous.path == target.path),
        'untrusted-redirect')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener(loopback_proxy=None):
    # Never inspect ambient proxies, cookies, profiles or credentials. A caller
    # may explicitly use an existing credential-free local HTTP CONNECT proxy;
    # HTTPS certificate verification remains the urllib default.
    proxies = {}
    if loopback_proxy is not None:
        _need(_text(loopback_proxy, 100) and '\\' not in loopback_proxy
              and not any(c.isspace() for c in loopback_proxy), 'unsafe-loopback-proxy')
        try:
            parsed = urllib.parse.urlsplit(loopback_proxy)
            _need(parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', '::1')
                  and parsed.username is None and parsed.password is None
                  and parsed.path == '' and not parsed.query and not parsed.fragment
                  and parsed.port is not None and 0 < parsed.port < 65536,
                  'unsafe-loopback-proxy')
            expected_host = '[::1]' if parsed.hostname == '::1' else '127.0.0.1'
            _need(parsed.netloc == '%s:%s' % (expected_host, parsed.port), 'unsafe-loopback-proxy')
        except ValueError:
            raise ArtifactError('unsafe-loopback-proxy') from None
        proxies = {'https': loopback_proxy}
    return urllib.request.build_opener(urllib.request.ProxyHandler(proxies), _NoRedirect())


def _checked_directory(path, private=False, create=False):
    path = Path(os.path.abspath(os.fspath(path)))
    # Reject aliases, including intermediate symlinks; callers can explicitly pass
    # a previously canonicalized trusted staging/cache root on macOS.
    for part in reversed((path,) + tuple(path.parents)):
        if part == path and create and not part.exists():
            try:
                part.mkdir(mode=0o700)
            except FileExistsError:
                pass
        info = part.lstat()
        _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'unsafe-directory')
    if private:
        info = path.stat()
        _need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0,
              'cache-or-evidence-directory-not-private')
    return path


def _new_private_file(path):
    return os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


@dataclasses.dataclass(frozen=True)
class DownloadReceipt:
    artifact_key: str
    artifact_path: str
    sha256: str
    size_bytes: int
    expected_sha256_matched: bool
    final_host: str
    binary_verification_performed: bool = False
    etag: Optional[str] = None


def _deadline(deadline_seconds):
    _need(type(deadline_seconds) is int
          and 0 < deadline_seconds <= MAX_DOWNLOAD_DEADLINE_SECONDS,
          'invalid-download-deadline')
    return time.monotonic() + deadline_seconds


def _lock_partial(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise ArtifactError('partial-in-use') from None


def _owned_partial(fd, partial, cache):
    info = os.fstat(fd)
    _need(partial.parent == cache and partial.resolve(strict=True) == partial
          and re.fullmatch(r'[0-9a-f]{32}\.partial', partial.name) is not None,
          'unsafe-partial-path')
    entry = partial.lstat()
    _need(stat.S_ISREG(info.st_mode) and stat.S_ISREG(entry.st_mode)
          and info.st_uid == os.getuid() and info.st_nlink == 1
          and stat.S_IMODE(info.st_mode) & 0o7077 == 0
          and (entry.st_dev, entry.st_ino) == (info.st_dev, info.st_ino),
          'unsafe-partial-file')
    return info


def _open_artifact_response(manifest, loopback_proxy, deadline, extra_headers=None):
    opener = _build_opener(loopback_proxy)
    current_url, response = manifest.artifact_url, None
    try:
        for hop in range(5):
            _need(time.monotonic() < deadline, 'download-deadline-exceeded')
            headers = {'User-Agent': 'GoldVMManager-Artifact/1',
                       'Accept': 'application/octet-stream', 'Accept-Encoding': 'identity'}
            headers.update(extra_headers or {})
            request = urllib.request.Request(current_url, headers=headers, method='GET')
            try:
                response = opener.open(request, timeout=30)
            except urllib.error.HTTPError as error:
                response = error
            _need(response.geturl() == current_url, 'unexpected-implicit-redirect')
            if response.code in (301, 302, 303, 307, 308):
                locations = response.headers.get_all('Location', [])
                _need(len(locations) == 1 and hop < 4, 'invalid-redirect')
                next_url = urllib.parse.urljoin(current_url, locations[0])
                validate_artifact_redirect(manifest, current_url, next_url)
                response.close()
                response = None
                current_url = next_url
                continue
            return response, current_url
        raise ArtifactError('invalid-response')
    except BaseException:
        if response is not None:
            response.close()
        raise


def _identity_encoding(response):
    encodings = response.headers.get_all('Content-Encoding', [])
    _need(len(encodings) <= 1 and (not encodings or encodings[0].lower() == 'identity'),
          'unsupported-content-encoding')


def _response_length(response):
    lengths = response.headers.get_all('Content-Length', [])
    _need(len(lengths) <= 1, 'invalid-content-length')
    if not lengths:
        return None
    _need(re.fullmatch(r'[0-9]{1,12}', lengths[0]) is not None, 'invalid-content-length')
    return int(lengths[0])


def _publish_partial(manifest, cache, partial, fd, value, size, final_host, etag=None):
    # Keep the inode lock until publication/unlink completes. No rename-overwrite.
    info = _owned_partial(fd, partial, cache)
    _need(info.st_size == size, 'partial-changed')
    final = cache / (partial.stem + ('.zip' if manifest.product == 'claudeDesktop' else '.dmg'))
    os.link(str(partial), str(final), follow_symlinks=False)
    # Verify this exact absolute unlink target and inode after creating the link.
    entry = partial.lstat()
    _need(partial.resolve(strict=True) == partial
          and (entry.st_dev, entry.st_ino) == (info.st_dev, info.st_ino), 'cache-changed')
    partial.unlink()
    return DownloadReceipt(manifest.artifact_key, str(final), value, size,
                           manifest.known_sha256 is not None, final_host, etag=etag)


def download_artifact(manifest, cache_dir, *, loopback_proxy=None,
                      deadline_seconds=DEFAULT_DOWNLOAD_DEADLINE_SECONDS):
    """Explicit bounded raw download; no download happens on import.

    Failing attempts retain a 0600 random .partial (no automatic resume/reuse). Only complete
    size/hash-checked bytes are atomically published without overwriting a file.
    Missing official hash is recorded, NOT silently turned into publisher trust.
    This operation does not read or change quarantine; caller must preserve it
    during extraction/copy and apply its download quarantine policy as needed.
    """
    _need(isinstance(manifest, ArtifactManifest), 'invalid-manifest')
    manifest.__post_init__()
    deadline = _deadline(deadline_seconds)
    cache = _checked_directory(cache_dir, private=True, create=True)
    token = uuid.uuid4().hex
    partial = cache / (token + '.partial')
    fd = _new_private_file(partial)
    digest, total = hashlib.sha256(), 0
    response = None
    try:
        with os.fdopen(fd, 'wb') as output:
            _lock_partial(fd)
            response, current_url = _open_artifact_response(manifest, loopback_proxy, deadline)
            _need(response.code == 200, 'unexpected-http-status')
            _identity_encoding(response)
            _need(response.headers.get('Content-Range') is None, 'partial-response-refused')
            length = _response_length(response)
            if length is not None:
                _need(0 < length <= manifest.maximum_download_bytes, 'download-too-large')
            while True:
                _need(time.monotonic() < deadline, 'download-deadline-exceeded')
                chunk = response.read(min(CHUNK_BYTES, manifest.maximum_download_bytes - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                _need(total <= manifest.maximum_download_bytes, 'download-too-large')
                output.write(chunk)
                digest.update(chunk)
            _need(total > 0 and (length is None or total == length), 'truncated-download')
            _need(manifest.declared_size_bytes is None or total == manifest.declared_size_bytes,
                  'declared-size-mismatch')
            value = digest.hexdigest()
            _need(manifest.known_sha256 is None or value == manifest.known_sha256, 'checksum-mismatch')
            output.flush()
            os.fsync(output.fileno())
            return _publish_partial(manifest, cache, partial, fd, value, total,
                                    _https_url(current_url).hostname)
    except ArtifactError:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise ArtifactError('download-failed') from None
    finally:
        if response is not None:
            response.close()


def _strong_etag(value):
    _need(isinstance(value, str) and re.fullmatch(r'"[\x21\x23-\x7e]{0,200}"', value) is not None,
          'invalid-strong-etag')
    return value


def _hash_open_partial(stream, cap, deadline):
    before = os.fstat(stream.fileno())
    stream.seek(0)
    digest, size = hashlib.sha256(), 0
    while True:
        _need(time.monotonic() < deadline, 'download-deadline-exceeded')
        data = stream.read(min(CHUNK_BYTES, cap - size + 1))
        if not data:
            break
        size += len(data)
        _need(size <= cap, 'download-too-large')
        digest.update(data)
    after = os.fstat(stream.fileno())
    _need((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
          == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
          and size == before.st_size, 'partial-changed')
    return digest.hexdigest(), size


def resume_artifact(manifest, cache_dir, partial_path, *, loopback_proxy=None,
                    deadline_seconds=MAX_DOWNLOAD_DEADLINE_SECONDS, expected_etag=None):
    """Explicit resume of a stopped attempt; requires a trusted pinned SHA-256.

    Never searches for partials, retries automatically, or promotes existing bytes
    offline. Caller MUST establish the previous attempt ended, especially attempts
    from older module versions without advisory flock. Only the explicitly named
    private, owned, single-link inode is opened and locked. A new request starts at
    the exact publisher URL and must return the complete remaining range as 206.
    If a prior strong ETag is known, pass it; If-Range and exact equality enforce it.
    Without one, only the final whole-file pinned digest authenticates continuity.
    No partial's content is transmitted. Failure leaves a non-installable partial.
    """
    _need(isinstance(manifest, ArtifactManifest), 'invalid-manifest')
    manifest.__post_init__()
    _need(manifest.known_sha256 is not None, 'resume-requires-pinned-sha256')
    deadline = _deadline(deadline_seconds)
    if expected_etag is not None:
        _strong_etag(expected_etag)
    cache = _checked_directory(cache_dir, private=True)
    partial = Path(os.path.abspath(os.fspath(partial_path)))
    _need(partial.parent == cache
          and re.fullmatch(r'[0-9a-f]{32}\.partial', partial.name) is not None,
          'unsafe-partial-path')
    response = None
    try:
        # Inspect type before opening: even opening a device/FIFO may have effects.
        # O_NOFOLLOW plus the subsequent fstat/inode checks defend link swaps;
        # the caller's exclusive cache remains necessary against other writers.
        entry = partial.lstat()
        _need(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid()
              and entry.st_nlink == 1 and stat.S_IMODE(entry.st_mode) & 0o7077 == 0,
              'unsafe-partial-file')
        fd = os.open(str(partial), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'r+b', buffering=0) as output:
            _lock_partial(fd)
            initial = _owned_partial(fd, partial, cache)
            offset = initial.st_size
            _need(0 < offset < manifest.maximum_download_bytes
                  and (manifest.declared_size_bytes is None or offset < manifest.declared_size_bytes),
                  'invalid-partial-size')
            headers = {'Range': 'bytes=%d-' % offset}
            if expected_etag is not None:
                headers['If-Range'] = expected_etag
            response, current_url = _open_artifact_response(manifest, loopback_proxy, deadline, headers)
            _need(response.code == 206, 'resume-requires-http-206')
            _identity_encoding(response)
            _need(not response.headers.get('Content-Type', '').lower().startswith('multipart/'),
                  'multipart-range-refused')
            ranges = response.headers.get_all('Content-Range', [])
            _need(len(ranges) == 1, 'invalid-content-range')
            match = re.fullmatch(r'bytes ([0-9]{1,12})-([0-9]{1,12})/([0-9]{1,12})', ranges[0])
            _need(match is not None, 'invalid-content-range')
            start, end, total = (int(value) for value in match.groups())
            _need(start == offset and start <= end and end == total - 1
                  and total <= manifest.maximum_download_bytes, 'invalid-content-range')
            _need(manifest.declared_size_bytes is None or total == manifest.declared_size_bytes,
                  'declared-size-mismatch')
            length = _response_length(response)
            _need(length is None or length == total - offset, 'range-length-mismatch')
            etags = response.headers.get_all('ETag', [])
            _need(len(etags) <= 1, 'invalid-strong-etag')
            etag = _strong_etag(etags[0]) if etags else None
            _need(expected_etag is None or etag == expected_etag, 'etag-mismatch')
            current = _owned_partial(fd, partial, cache)
            _need((current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                  == (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns), 'partial-changed')
            output.seek(offset)
            written = offset
            while True:
                _need(time.monotonic() < deadline, 'download-deadline-exceeded')
                chunk = response.read(min(CHUNK_BYTES, total - written + 1))
                if not chunk:
                    break
                _need(written + len(chunk) <= total, 'range-response-too-large')
                _need(os.fstat(fd).st_size == written, 'partial-changed')
                _need(output.write(chunk) == len(chunk), 'partial-write-failed')
                written += len(chunk)
            _need(written == total, 'truncated-range-response')
            output.flush()
            os.fsync(fd)
            # Hash the entire on-disk prefix+suffix, not response metadata or only
            # the received suffix. A mismatched/mutated prefix never finalizes.
            value, size = _hash_open_partial(output, manifest.maximum_download_bytes, deadline)
            _need(size == total and value == manifest.known_sha256, 'checksum-mismatch')
            return _publish_partial(manifest, cache, partial, fd, value, size,
                                    _https_url(current_url).hostname, etag)
    except ArtifactError:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise ArtifactError('resume-failed') from None
    finally:
        if response is not None:
            response.close()


def extraction_plan(manifest):
    """Non-executable requirements, NOT a safe extractor or mounted-volume proof."""
    return {
        'format': 'zip' if manifest.product == 'claudeDesktop' else 'dmg',
        'expected_apps': [app.name for app in manifest.expected_apps],
        'maximum_expanded_bytes': manifest.maximum_bundle_bytes,
        'maximum_entries': manifest.maximum_bundle_entries,
        'execution_permitted': False,
        'requirements': [
            'Use only the acquired artifact, never host-installed applications.',
            'DMG: parent mounts readonly, nobrowse, noautoopen; inspect no arbitrary volumes.',
            'ZIP: parent preflights every member; reject absolute/dotdot/duplicate/casefold '
            'collisions, special files, encryption, zip bombs and escaping links before writing.',
            'Use a new exclusive private staging directory; never follow archive-created '
            'symlinks while extracting; enforce actual expanded bytes and entry limits.',
            'Keep complete bundles and internal Framework symlinks, signatures and quarantine.',
            'Do not execute applications, installer, scripts or launch services.',
            'Verify bundles before and after copying; no xattr removal or re-signing.',
        ],
    }


def _require_review(manifest):
    if not manifest.vendor_team_ids or not manifest.identity_review_sources:
        raise PendingReview('publisher-signing-identity-pending-review')
    if manifest.known_sha256 is None and not manifest.allow_unpinned_sha256:
        raise PendingReview('unpublished-checksum-policy-pending-review')
    for app in manifest.expected_apps:
        if not all((app.bundle_identifiers, app.bundle_names, app.executable_names,
                    app.short_versions, app.bundle_versions)):
            raise PendingReview('bundle-plist-allow-values-pending-review')


def _within(path, root):
    try:
        path.relative_to(root)
        return path != root
    except ValueError:
        return False


def _regular_hash(path, cap):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and before.st_size <= cap, 'unsafe-or-oversize-file')
        digest, size = hashlib.sha256(), 0
        while True:
            data = stream.read(min(CHUNK_BYTES, cap - size + 1))
            if not data:
                break
            size += len(data)
            _need(size <= cap, 'file-too-large')
            digest.update(data)
        after = os.fstat(stream.fileno())
        _need((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
              == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
              and size == before.st_size, 'file-changed-during-verification')
        return digest.hexdigest(), size


def _tree_snapshot(app, manifest):
    """Hash content/layout without traversing links; reject all escaping links."""
    records, total, seen = [], 0, set()
    stack = [app]
    while stack:
        directory = stack.pop()
        for path in sorted(directory.iterdir(), key=lambda p: p.name):
            rel = path.relative_to(app).as_posix()
            _need(_text(rel, 4096), 'unsafe-bundle-name')
            normalized = unicodedata.normalize('NFC', rel).casefold()
            _need(normalized not in seen, 'case-colliding-bundle-path')
            seen.add(normalized)
            _need(len(seen) <= manifest.maximum_bundle_entries, 'too-many-bundle-entries')
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            _need(not mode & (stat.S_ISUID | stat.S_ISGID), 'setid-bundle-entry')
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(str(path))
                _need(_text(target, 4096) and not os.path.isabs(target) and '\\' not in target,
                      'unsafe-bundle-symlink')
                # Check every intermediate link, even one leading out and back in.
                _resolve_internal_link(path, app)
                record = (rel, 'symlink', mode, target)
            elif stat.S_ISDIR(info.st_mode):
                stack.append(path)
                record = (rel, 'directory', mode)
            elif stat.S_ISREG(info.st_mode):
                digest, size = _regular_hash(path, manifest.maximum_bundle_bytes - total)
                total += size
                record = (rel, 'file', mode, size, digest)
            else:
                raise ArtifactError('special-file-in-bundle')
            records.append(record)
    return _json_hash(sorted(records)), total, len(records)


def _resolve_internal_link(path, root):
    # Resolve component-wise, so no symlink can briefly escape to a host path.
    pending = list(path.relative_to(root).parts)
    current, links = root, 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            current = current.parent
            _need(current == root or _within(current, root), 'escaping-bundle-symlink')
            continue
        current = current / part
        info = current.lstat()  # broken links fail before reading their target
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(str(current))
            _need(_text(target, 4096) and not os.path.isabs(target) and '\\' not in target,
                  'unsafe-bundle-symlink')
            links += 1
            _need(links <= 40, 'cyclic-bundle-symlink')
            current = current.parent
            pending = target.split('/') + pending
        elif pending:
            _need(stat.S_ISDIR(info.st_mode), 'invalid-bundle-link-target')
    _need(_within(current, root), 'escaping-bundle-symlink')
    return current


def _tool(argv, cwd):
    """Fixed Apple tools only; clean environment and no executable app invocation."""
    try:
        result = subprocess.run(argv, cwd=str(cwd), env={
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C',
            'HOME': '/var/empty',
        }, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ArtifactError('verification-tool-unavailable') from None
    _need(len(result.stdout) + len(result.stderr) <= MAX_TOOL_OUTPUT, 'verification-output-too-large')
    evidence = {'argv': list(argv), 'returncode': result.returncode,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr': result.stderr.decode('utf-8', errors='replace')}
    _need(result.returncode == 0, 'verification-tool-rejected')
    return evidence


def _read_plist(path):
    _need(path.lstat().st_size <= MAX_PLIST_BYTES and path.is_file() and not path.is_symlink(),
          'invalid-info-plist')
    with path.open('rb') as source:
        payload = source.read(MAX_PLIST_BYTES + 1)
    _need(len(payload) <= MAX_PLIST_BYTES, 'invalid-info-plist')
    try:
        result = plistlib.loads(payload)
    except (ValueError, TypeError, OverflowError, plistlib.InvalidFileException, ExpatError):
        raise ArtifactError('invalid-info-plist') from None
    _need(isinstance(result, dict), 'invalid-info-plist')
    return result


@dataclasses.dataclass(frozen=True)
class VerificationReceipt:
    manifest_sha256: str
    manifest: dict
    artifact_sha256: str
    artifact_size_bytes: int
    apps: tuple
    binary_verification_performed: bool = True
    installation_performed: bool = False
    extraction_proven_by_this_module: bool = False


def verify_app_bundles(manifest, staging_root, app_paths, download_receipt):
    """Static checks of the exact complete bundle set, never app execution.

    staging_root must be exclusive and controlled by the caller, not /Applications
    or a host profile. Paths must be canonical real directories below that root.
    The caller attests extraction lineage; this module does not extract/mount and
    cannot prove that a staged bundle originated inside the supplied archive.
    Tool failures/unavailable trust or notarization checks are hard failures.
    """
    _need(isinstance(manifest, ArtifactManifest), 'invalid-manifest')
    manifest.__post_init__()
    _require_review(manifest)
    _need(isinstance(download_receipt, DownloadReceipt)
          and download_receipt.artifact_key == manifest.artifact_key
          and not download_receipt.binary_verification_performed, 'invalid-download-receipt')
    try:
        artifact = Path(download_receipt.artifact_path)
        _checked_directory(artifact.parent, private=True)
        digest, size = _regular_hash(artifact, manifest.maximum_download_bytes)
        _need(digest == download_receipt.sha256 and size == download_receipt.size_bytes
              and (manifest.known_sha256 is None or digest == manifest.known_sha256)
              and (manifest.declared_size_bytes is None or size == manifest.declared_size_bytes),
              'artifact-receipt-mismatch')
        root = _checked_directory(staging_root)
        _need(root != Path('/') and root != Path('/Applications')
              and root != Path('/System/Applications'), 'host-app-root-refused')
        paths = tuple(Path(os.path.abspath(os.fspath(p))) for p in app_paths)
        _need(len(paths) == len(manifest.expected_apps)
              and len(set(paths)) == len(paths)
              and {p.name for p in paths} == {a.name for a in manifest.expected_apps},
              'incomplete-gui-app-set')
        by_name = {p.name: p for p in paths}
        results = []
        total_bundle_bytes, total_bundle_entries = 0, 0
        for expectation in manifest.expected_apps:
            app = by_name[expectation.name]
            _need(_within(app, root), 'app-outside-staging-root')
            _checked_directory(app)
            before = _tree_snapshot(app, manifest)
            total_bundle_bytes += before[1]
            total_bundle_entries += before[2]
            _need(total_bundle_bytes <= manifest.maximum_bundle_bytes
                  and total_bundle_entries <= manifest.maximum_bundle_entries,
                  'complete-app-set-too-large')
            contents = app / 'Contents'
            _need(contents.is_dir() and not contents.is_symlink(), 'invalid-app-layout')
            plist = _read_plist(contents / 'Info.plist')
            for key, allowed in (
                ('CFBundleIdentifier', expectation.bundle_identifiers),
                ('CFBundleName', expectation.bundle_names),
                ('CFBundleExecutable', expectation.executable_names),
                ('CFBundleShortVersionString', expectation.short_versions),
                ('CFBundleVersion', expectation.bundle_versions),
            ):
                _need(isinstance(plist.get(key), str) and plist[key] in allowed,
                      'unexpected-bundle-plist-value')
            _need(plist.get('CFBundlePackageType') == 'APPL', 'not-an-application-bundle')
            for relative in expectation.required_paths:
                required = _resolve_internal_link(app / relative, app)
                _need(required.exists(), 'incomplete-app-resources')
                if relative == 'Contents/Resources':
                    _need(required.is_dir(), 'invalid-gui-resources-directory')
                if required.is_dir():
                    _need(next(required.iterdir(), None) is not None, 'empty-app-resources')
            macos = contents / 'MacOS'
            _need(macos.is_dir() and not macos.is_symlink(), 'invalid-executable-directory')
            executable = macos / plist['CFBundleExecutable']
            info = executable.lstat()
            _need(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111
                  and info.st_size > 0, 'invalid-bundle-executable')
            executable_hash, _ = _regular_hash(executable, manifest.maximum_bundle_bytes)
            commands = []
            arch = _tool(['/usr/bin/lipo', '-archs', str(executable)], root)
            commands.append(arch)
            architectures = arch['stdout'].split()
            _need('arm64' in architectures and set(architectures) <= {'arm64', 'x86_64', 'arm64e'},
                  'arm64-required')
            teams = ' or '.join('certificate leaf[subject.OU] = "%s"' % team
                                for team in manifest.vendor_team_ids)
            # codesign interprets -R values without '=' as filenames, not source.
            requirement = ('=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] '
                           'exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                           'and (%s) and identifier "%s"' % (teams, plist['CFBundleIdentifier']))
            commands.append(_tool(['/usr/bin/codesign', '--verify', '--deep', '--strict',
                                   '--verbose=2', '-R', requirement, str(app)], root))
            signature = _tool(['/usr/bin/codesign', '--display', '--verbose=4', str(app)], root)
            commands.append(signature)
            signature_text = signature['stdout'] + '\n' + signature['stderr']
            observed = re.findall(r'^TeamIdentifier=([A-Z0-9]{10})$', signature_text, re.MULTILINE)
            identifiers = re.findall(r'^Identifier=(.+)$', signature_text, re.MULTILINE)
            _need(len(observed) == 1 and observed[0] in manifest.vendor_team_ids
                  and identifiers == [plist['CFBundleIdentifier']], 'signing-identity-mismatch')
            assessment = _tool(['/usr/sbin/spctl', '--assess', '--type', 'execute',
                                '--verbose=4', str(app)], root)
            commands.append(assessment)
            text = assessment['stdout'] + '\n' + assessment['stderr']
            _need(re.search(r'^source=Notarized Developer ID\s*$', text, re.MULTILINE) is not None
                  and re.search(r': accepted\s*$', text, re.MULTILINE) is not None,
                  'notarized-gatekeeper-acceptance-required')
            after = _tree_snapshot(app, manifest)
            _need(before == after, 'bundle-changed-during-verification')
            results.append({'name': app.name, 'bundle_path': str(app),
                            'bundle_tree_sha256': after[0], 'bundle_bytes': after[1],
                            'bundle_entries': after[2], 'executable_sha256': executable_hash,
                            'bundle_identifier': plist['CFBundleIdentifier'],
                            'short_version': plist['CFBundleShortVersionString'],
                            'bundle_version': plist['CFBundleVersion'], 'team_id': observed[0],
                            'architectures': architectures, 'commands': commands})
        # Recheck the whole set, not just the last app: an earlier app must not
        # change while a later app is being assessed. The caller must still keep
        # staging exclusive and repeat verification after copying to the guest.
        for result in results:
            snapshot = _tree_snapshot(Path(result['bundle_path']), manifest)
            _need(snapshot == (result['bundle_tree_sha256'], result['bundle_bytes'],
                               result['bundle_entries']), 'bundle-changed-during-verification')
        _need(_regular_hash(artifact, manifest.maximum_download_bytes) == (digest, size),
              'artifact-changed-during-verification')
        return VerificationReceipt(manifest.manifest_sha256, dataclasses.asdict(manifest),
                                   digest, size, tuple(results))
    except ArtifactError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise ArtifactError('unsafe-or-unreadable-bundle') from None


def write_evidence(receipt, path):
    """Save immutable-by-convention receipt JSON in a private directory, no replace.

    Tool output is untrusted evidence, not instructions. Successful evidence is
    not an installation receipt and carries the unproven extraction boundary.
    """
    _need(isinstance(receipt, (DownloadReceipt, VerificationReceipt)), 'invalid-evidence')
    path = Path(os.path.abspath(os.fspath(path)))
    _checked_directory(path.parent, private=True)
    fd = _new_private_file(path)
    with os.fdopen(fd, 'wb') as output:
        output.write(_json_bytes(dataclasses.asdict(receipt)) + b'\n')
        output.flush()
        os.fsync(output.fileno())
    return path
