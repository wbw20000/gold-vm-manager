"""Pinned, credential-free host material acquisition; Python 3.9 stdlib only.

Only bytes are accepted. Nothing is extracted, installed, mounted or executed.
SHA-256 is NOT native signature approval. See HOST_ARTIFACTS.md for trust limits.
"""

import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType
import urllib.error
import urllib.parse
import urllib.request
import uuid

import error_codes
import quarantine_policy


DEFAULT_DEADLINE_SECONDS = 24 * 60 * 60
MAX_DEADLINE_SECONDS = 72 * 60 * 60
CHUNK_BYTES = 1024 * 1024
_MAX_METADATA_BYTES = 16384
_MAX_ATTEMPTS = 10000
_REDIRECT_CODES = (301, 302, 303, 307, 308)


class ArtifactError(Exception):
    """Only stable codes and an optional locally generated attempt ID; no URLs."""

    def __init__(self, code, attempt_id=None):
        self.code = code
        self.attempt_id = attempt_id
        super().__init__(code)


def _need(condition, code):
    if not condition:
        raise ArtifactError(code)


@dataclasses.dataclass(frozen=True)
class Spec:
    key: str
    version: str
    url: str
    size_bytes: int
    sha256: str
    filename: str
    hash_provenance: str
    review_source: str
    redirect_hosts: tuple = ()

    @property
    def spec_sha256(self):
        return hashlib.sha256(_json_bytes(dataclasses.asdict(self))).hexdigest()


# These are reviewed pins, not a runtime manifest or arbitrary URL API.
SPECS = MappingProxyType({
    # Podman's official installer carries gvproxy v0.9.0 (the same upstream tag
    # commit as the bare release) signed with Red Hat's Developer ID and notarized.
    # The bare release binary is not notarized, so macOS refuses to run it.
    'podman-installer': Spec(
        'podman-installer', '6.2.0',
        'https://github.com/podman-container-tools/podman/releases/download/v6.2.0/podman-installer-macos-arm64.pkg',
        76730429, 'b4628a29a4c70bbec757a84d0e429882d358cab18956a0017f99df74b37201a7',
        'podman-installer-macos-arm64.pkg', 'publisher-github-release-digest',
        'https://api.github.com/repos/podman-container-tools/podman/releases/tags/v6.2.0',
        ('release-assets.githubusercontent.com',)),
    'tart': Spec(
        'tart', '2.41.1',
        'https://github.com/openai/tart/releases/download/2.41.1/tart.tar.gz',
        22959557, 'e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2',
        'tart.tar.gz', 'publisher-github-release-digest',
        'https://api.github.com/repos/openai/tart/releases/tags/2.41.1',
        ('release-assets.githubusercontent.com',)),
    'ipsw': Spec(
        'ipsw', '26.6.2/25G83',
        'https://updates.cdn-apple.com/2026SummerFCS/fullrestores/140-75212/'
        'A2A24B94-1FC1-45A3-93F7-C51B02AF1F4D/UniversalMac_26.6.2_25G83_Restore.ipsw',
        19772231540, '885503b7f4b06609e9a512f2befd40f59730640a3f1233e3892d60affdd51c95',
        'UniversalMac_26.6.2_25G83_Restore.ipsw',
        'reviewed-local-digest-of-official-https-acquisition',
        'https://updates.cdn-apple.com/2026SummerFCS/fullrestores/140-75212/'
        'A2A24B94-1FC1-45A3-93F7-C51B02AF1F4D/UniversalMac_26.6.2_25G83_Restore.ipsw'),
})


@dataclasses.dataclass(frozen=True)
class Progress:
    spec_key: str
    attempt_id: str
    phase: str
    completed_bytes: int
    total_bytes: int


@dataclasses.dataclass(frozen=True)
class Receipt:
    spec_key: str
    spec_sha256: str
    version: str
    artifact_path: str
    receipt_path: str
    acceptance_path: str
    attempt_id: str
    size_bytes: int
    sha256: str
    source_kind: str
    source_url: str
    final_host: str
    hash_provenance: str
    device: int
    inode: int
    mtime_ns: int
    schema: int = 1
    digest_verified: bool = True
    quarantine_ensured: bool = False
    native_execution_approved: bool = False
    binary_verification_performed: bool = False
    apple_restore_validation_performed: bool = False


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _spec(key):
    _need(isinstance(key, str) and key in SPECS, 'unknown-spec-key')
    return SPECS[key]


def _https_url(value):
    _need(isinstance(value, str) and 0 < len(value) <= 16384
          and value.isascii() and not any(ord(c) <= 32 or ord(c) == 127 for c in value)
          and '\\' not in value, 'untrusted-url')
    try:
        parts = urllib.parse.urlsplit(value)
        _need(parts.scheme == 'https' and parts.hostname and parts.netloc == parts.hostname
              and not parts.username and not parts.password and parts.port is None
              and not parts.fragment, 'untrusted-url')
    except ValueError:
        raise ArtifactError('untrusted-url') from None
    return parts


def _redirect(spec, previous, target):
    old, new = _https_url(previous), _https_url(target)
    if target == spec.url and previous == spec.url:
        return
    # No unreviewed Apple mirror or same-origin alternate path. GitHub's signed
    # CDN query is transport-only; no host wildcards, ports, encoded paths, auth.
    _need(new.hostname in spec.redirect_hosts
          and new.hostname == 'release-assets.githubusercontent.com'
          and re.fullmatch(r'/github-production-release-asset/[0-9]{1,20}/'
                           r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',
                           new.path) is not None, 'untrusted-redirect')
    _need(previous == spec.url or (old.hostname == new.hostname and old.path == new.path),
          'untrusted-redirect')


def _proxy(value):
    if value is None:
        return {}
    _need(isinstance(value, str) and len(value) <= 100, 'unsafe-loopback-proxy')
    # Reject localhost DNS, alternate numeric encodings, credentials, paths,
    # leading zero ports, environment values, SOCKS, TLS weakening, etc.
    match = re.fullmatch(r'http://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})', value)
    _need(match is not None and int(match.group(2)) <= 65535, 'unsafe-loopback-proxy')
    return {'https': value}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _ExplicitProxyHandler(urllib.request.ProxyHandler):
    def proxy_open(self, req, proxy, protocol):
        # ProxyHandler otherwise consults ambient NO_PROXY/system bypass rules.
        # Only our already validated literal loopback endpoint reaches here.
        _proxy(proxy)
        _need(req.type == 'https' and protocol == 'https', 'untrusted-proxy-request')
        req.set_proxy(urllib.parse.urlsplit(proxy).netloc, 'http')
        return None


def _build_opener(loopback_proxy):
    # An explicit empty handler suppresses ambient HTTP(S)/ALL_PROXY settings.
    # No cookie/auth handlers, .netrc access, custom TLS context or credential API.
    return urllib.request.build_opener(_ExplicitProxyHandler(_proxy(loopback_proxy)),
                                       _NoRedirect())


class _Budget:
    def __init__(self, seconds, progress, cancelled):
        _need(type(seconds) is int and 0 < seconds <= MAX_DEADLINE_SECONDS,
              'invalid-deadline')
        _need(progress is None or callable(progress), 'invalid-progress-callback')
        _need(cancelled is None or callable(cancelled), 'invalid-cancelled-callback')
        self.end = time.monotonic() + seconds
        self.progress, self.cancelled = progress, cancelled
        self.last_event = None
        self.last_event_time = 0.0

    def check(self):
        if self.cancelled is not None:
            try:
                stop = self.cancelled()
            except Exception:
                raise ArtifactError('cancelled-callback-failed') from None
            _need(type(stop) is bool, 'invalid-cancelled-result')
            _need(not stop, 'cancelled')
        _need(time.monotonic() < self.end, 'deadline-exceeded')

    def notify(self, spec, attempt, phase, size):
        self.check()
        now = time.monotonic()
        event_key = (attempt, phase)
        # read1 can return a single TLS record. A 20GB IPSW must not flood the
        # parent UI with a million progress events; always report boundaries.
        if self.progress is not None and (event_key != self.last_event
                or size == spec.size_bytes or now - self.last_event_time >= 0.25):
            try:
                self.progress(Progress(spec.key, attempt, phase, size, spec.size_bytes))
            except Exception:
                raise ArtifactError('progress-callback-failed') from None
            self.last_event, self.last_event_time = event_key, now
        self.check()


def _identity(info):
    return (info.st_dev, info.st_ino)


def _unchanged(info):
    return (_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _regular(info, private):
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
          and info.st_nlink == 1, 'unsafe-file')
    if private:
        _need(stat.S_IMODE(info.st_mode) == 0o600, 'unsafe-file-mode')


def _directory(info):
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe-private-directory')


def _absolute(path):
    value = os.fspath(path)
    _need(isinstance(value, str) and '\x00' not in value, 'invalid-path')
    # Never silently resolve symlinks or parent traversals on callers' behalf.
    _need('..' not in Path(value).parts, 'unsafe-path')
    return Path(os.path.abspath(value))


def _open_directory(path, create=False):
    """Open each component relative to its predecessor; never follow symlinks."""
    path = _absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, component in enumerate(path.parts[1:]):
            if create and index == len(path.parts) - 2:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        _directory(os.fstat(fd))
        return path, fd
    except BaseException:
        os.close(fd)
        raise


def _directory_still(path, fd):
    _, check = _open_directory(path)
    try:
        _need(_identity(os.fstat(check)) == _identity(os.fstat(fd)), 'directory-changed')
    finally:
        os.close(check)


def _file_at(directory_fd, name, create=False, private=True):
    entry = None
    if not create:
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _regular(entry, private)
    flags = os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= (os.O_RDWR | os.O_CREAT | os.O_EXCL) if create else os.O_RDONLY
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        current = os.fstat(fd)
        _regular(current, private)
        if entry is not None:
            _need(_identity(entry) == _identity(current), 'file-changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _same_file(directory_fd, name, fd, private=True):
    entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    current = os.fstat(fd)
    _regular(entry, private)
    _regular(current, private)
    _need(_identity(entry) == _identity(current), 'file-changed')
    return current


def _lock(fd, shared=False):
    try:
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
    except OSError:
        raise ArtifactError('artifact-in-use') from None


def _write_all(fd, data):
    while data:
        size = os.write(fd, data)
        _need(size > 0, 'write-failed')
        data = data[size:]


def _save_json(directory_fd, name, value):
    fd = _file_at(directory_fd, name, create=True)
    try:
        _write_all(fd, _json_bytes(value))
        os.fsync(fd)
        _same_file(directory_fd, name, fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'invalid-cache-receipt')
        result[key] = value
    return result


def _read_json(directory_fd, name):
    fd = _file_at(directory_fd, name)
    try:
        before = os.fstat(fd)
        _need(0 < before.st_size <= _MAX_METADATA_BYTES, 'invalid-cache-receipt')
        data = os.read(fd, _MAX_METADATA_BYTES + 1)
        after = _same_file(directory_fd, name, fd)
        _need(len(data) == before.st_size and _unchanged(before) == _unchanged(after),
              'invalid-cache-receipt')
        value = json.loads(data, object_pairs_hook=_unique_pairs)
        # A previous interrupted fsync may have left a readable but non-durable
        # record. Reuse must make its byte proof durable before native ensure.
        os.fsync(fd)
        return value
    finally:
        os.close(fd)


def _hash_file(fd, spec, attempt, budget, phase):
    before = os.fstat(fd)
    _need(before.st_size == spec.size_bytes, 'size-mismatch')
    os.lseek(fd, 0, os.SEEK_SET)
    digest, total = hashlib.sha256(), 0
    budget.notify(spec, attempt, phase, total)
    while True:
        budget.check()
        data = os.read(fd, min(CHUNK_BYTES, spec.size_bytes - total + 1))
        if not data:
            break
        total += len(data)
        _need(total <= spec.size_bytes, 'size-mismatch')
        digest.update(data)
        budget.notify(spec, attempt, phase, total)
    _need(_unchanged(before) == _unchanged(os.fstat(fd)), 'file-changed')
    _need(total == spec.size_bytes, 'size-mismatch')
    _need(digest.hexdigest() == spec.sha256, 'checksum-mismatch')
    return before


def _header(response, name):
    values = response.headers.get_all(name, [])
    _need(len(values) <= 1, 'invalid-response-headers')
    return values[0] if values else None


def _open_response(spec, proxy, budget):
    opener = _build_opener(proxy)
    current, response = spec.url, None
    try:
        for hop in range(5):
            budget.check()
            request = urllib.request.Request(current, method='GET', headers={
                'User-Agent': 'GoldVMManager-HostArtifacts/1',
                'Accept': 'application/octet-stream', 'Accept-Encoding': 'identity'})
            try:
                response = opener.open(request, timeout=min(30, max(0.001, budget.end - time.monotonic())))
            except urllib.error.HTTPError as error:
                response = error
            budget.check()
            _need(response.geturl() == current, 'implicit-redirect-refused')
            if response.code in _REDIRECT_CODES:
                location = _header(response, 'Location')
                _need(isinstance(location, str) and hop < 4, 'invalid-redirect')
                _need(not any(ord(c) <= 32 or ord(c) == 127 for c in location), 'untrusted-redirect')
                target = urllib.parse.urljoin(current, location)
                _redirect(spec, current, target)
                response.close()
                response = None
                current = target
                continue
            return response, _https_url(current).hostname
        raise ArtifactError('invalid-redirect')
    except BaseException:
        if response is not None:
            response.close()
        raise


def _download(fd, spec, attempt, proxy, budget):
    response = None
    try:
        response, host = _open_response(spec, proxy, budget)
        _need(response.code == 200, 'unexpected-http-status')
        _need(_header(response, 'Content-Range') is None, 'partial-response-refused')
        encoding = _header(response, 'Content-Encoding')
        _need(encoding is None or encoding.lower() == 'identity', 'unsupported-content-encoding')
        length = _header(response, 'Content-Length')
        transfer = _header(response, 'Transfer-Encoding')
        _need(transfer is None or (transfer.lower() == 'chunked' and length is None),
              'unsupported-transfer-encoding')
        if length is not None:
            _need(re.fullmatch(r'[0-9]{1,12}', length) is not None
                  and int(length) == spec.size_bytes, 'content-length-mismatch')
        total = 0
        budget.notify(spec, attempt, 'download', total)
        # HTTPResponse.read1 avoids read(size)'s unbounded slow-trickle fill loop.
        reader = response.read1
        while True:
            budget.check()
            data = reader(min(CHUNK_BYTES, spec.size_bytes - total + 1))
            budget.check()
            if not data:
                break
            _need(total + len(data) <= spec.size_bytes, 'size-mismatch')
            _write_all(fd, data)
            total += len(data)
            budget.notify(spec, attempt, 'download', total)
        _need(total == spec.size_bytes, 'size-mismatch')
        return host
    finally:
        if response is not None:
            response.close()


def _copy_source(fd, source, spec, attempt, budget):
    source = _absolute(source)
    # Source parents need not be 0700; open them without imposing cache ownership.
    parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source_fd = None
    try:
        for component in source.parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        source_fd = _file_at(parent_fd, source.name, private=False)
        _lock(source_fd, shared=True)
        before = os.fstat(source_fd)
        _need(before.st_size == spec.size_bytes, 'size-mismatch')
        total, digest = 0, hashlib.sha256()
        budget.notify(spec, attempt, 'import', total)
        while True:
            budget.check()
            data = os.read(source_fd, min(CHUNK_BYTES, spec.size_bytes - total + 1))
            if not data:
                break
            total += len(data)
            _need(total <= spec.size_bytes, 'size-mismatch')
            digest.update(data)
            _write_all(fd, data)
            budget.notify(spec, attempt, 'import', total)
        after = _same_file(parent_fd, source.name, source_fd, private=False)
        _need(_unchanged(before) == _unchanged(after), 'source-changed')
        _need(total == spec.size_bytes and digest.hexdigest() == spec.sha256, 'checksum-mismatch')
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(parent_fd)


def _receipt(spec, attempt, path, info, source_kind, host):
    return Receipt(spec.key, spec.spec_sha256, spec.version,
                   str(path / spec.filename), str(path / 'receipt.json'),
                   str(path / 'accepted.json'), attempt, spec.size_bytes, spec.sha256,
                   source_kind, spec.url, host, spec.hash_provenance,
                   info.st_dev, info.st_ino, info.st_mtime_ns)


def _ensure_quarantine(root, root_fd, path, directory_fd, spec, fd, budget):
    budget.check()
    _directory_still(root, root_fd)
    _directory_still(path, directory_fd)
    before = _same_file(directory_fd, spec.filename, fd)
    try:
        # The durable byte-verification receipt MUST already exist. No executable
        # permission is added; ensure preserves existing xattrs and only adds q.
        quarantine_policy.ensure(path / spec.filename)
    except Exception:
        raise ArtifactError('quarantine-failed') from None
    budget.check()
    after = _same_file(directory_fd, spec.filename, fd)
    _need((_identity(before), before.st_size, before.st_mtime_ns)
          == (_identity(after), after.st_size, after.st_mtime_ns), 'file-changed')
    os.fsync(fd)
    _directory_still(root, root_fd)
    _directory_still(path, directory_fd)


def _recorded(spec, path, name, info, data, accepted):
    """The receipt that both of an entry's records must spell out for its file as it is now."""
    _need(isinstance(data, dict) and data.get('source_kind') in ('download', 'local-import'),
          'invalid-cache-receipt')
    host = data.get('final_host')
    allowed = ('', _https_url(spec.url).hostname) + spec.redirect_hosts
    _need(host in allowed and ((data['source_kind'] == 'local-import') == (host == '')),
          'invalid-cache-receipt')
    expected = _receipt(spec, name, path, info, data['source_kind'], host)
    # Compare canonical JSON, not Python equality (True must not equal 1).
    _need(_json_bytes(data) == _json_bytes(dataclasses.asdict(expected))
          and _json_bytes(accepted) == _json_bytes(dataclasses.asdict(
              dataclasses.replace(expected, quarantine_ensured=True))), 'invalid-cache-receipt')
    return expected


def _reuse(spec, root, root_fd, budget):
    names = os.listdir(root_fd)
    _need(len(names) <= _MAX_ATTEMPTS, 'too-many-cache-attempts')
    for name in sorted(names):
        budget.check()
        if re.fullmatch(re.escape(spec.key) + r'-[0-9a-f]{32}', name) is None:
            continue
        directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=root_fd)
        fd = None
        try:
            _directory(os.fstat(directory_fd))
            entries = os.listdir(directory_fd)
            if 'accepted.json' not in entries:
                continue  # Never infer acceptance from existing bytes or partial receipts.
            data = _read_json(directory_fd, 'receipt.json')
            accepted = _read_json(directory_fd, 'accepted.json')
            fd = _file_at(directory_fd, spec.filename)
            _lock(fd)
            info = _same_file(directory_fd, spec.filename, fd)
            expected = _recorded(spec, root / name, name, info, data, accepted)
            verified = _hash_file(fd, spec, name, budget, 'cache-verify')
            _need(_unchanged(verified) == _unchanged(_same_file(directory_fd, spec.filename, fd)),
                  'file-changed')
            os.fsync(directory_fd)
            _ensure_quarantine(root, root_fd, root / name, directory_fd, spec, fd, budget)
            return dataclasses.replace(expected, quarantine_ensured=True)
        except ArtifactError as error:
            raise ArtifactError(error.code, name) from None
        except Exception:
            raise ArtifactError('cache-io-failed', name) from None
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory_fd)
    return None


def cached(spec_key, private_cache_root):
    """Whether acquire() would find an accepted copy of this pinned artifact in the cache.

    A hint for the interface only. It looks at the first accepted entry, the
    one reuse would pick, and checks its records against the file's current
    identity and size exactly as reuse does. Nothing is hashed, locked or
    created here; acquire() still verifies the whole file before any use.
    """
    spec = _spec(spec_key)
    root_fd = directory_fd = None
    try:
        root, root_fd = _open_directory(private_cache_root)
        names = os.listdir(root_fd)
        _need(len(names) <= _MAX_ATTEMPTS, 'too-many-cache-attempts')
        for name in sorted(names):
            if re.fullmatch(re.escape(spec.key) + r'-[0-9a-f]{32}', name) is None:
                continue
            directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            _directory(os.fstat(directory_fd))
            if 'accepted.json' in os.listdir(directory_fd):
                data = _read_json(directory_fd, 'receipt.json')
                accepted = _read_json(directory_fd, 'accepted.json')
                info = os.stat(spec.filename, dir_fd=directory_fd, follow_symlinks=False)
                _regular(info, True)
                _recorded(spec, root / name, name, info, data, accepted)
                return info.st_size == spec.size_bytes
            os.close(directory_fd)
            directory_fd = None
        return False
    except Exception:
        return False
    finally:
        for fd in (directory_fd, root_fd):
            if fd is not None:
                os.close(fd)


def _acquire(spec_key, private_cache_root, *, source=None, loopback_proxy=None,
             progress=None, cancelled=None, deadline_seconds=DEFAULT_DEADLINE_SECONDS):
    spec = _spec(spec_key)
    _proxy(loopback_proxy)  # Validate even if a matching accepted cache entry exists.
    budget = _Budget(deadline_seconds, progress, cancelled)
    root_fd = directory_fd = fd = None
    attempt = None
    try:
        budget.check()
        root, root_fd = _open_directory(private_cache_root, create=True)
        # Import always verifies/copies the explicitly supplied source. It must
        # not silently succeed via cache without inspecting that user's file.
        if source is None:
            reused = _reuse(spec, root, root_fd, budget)
            if reused is not None:
                return reused
        attempt = spec.key + '-' + uuid.uuid4().hex
        os.mkdir(attempt, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        path = root / attempt
        directory_fd = os.open(attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=root_fd)
        _directory(os.fstat(directory_fd))
        _directory_still(root, root_fd)
        fd = _file_at(directory_fd, spec.filename, create=True)
        _lock(fd)
        # The artifact filename alone never denotes acceptance. Partial attempts
        # retain this same inode; no link, rename, deletion or overwrite occurs.
        _save_json(directory_fd, 'attempt.json', {
            'schema': 1, 'attempt_id': attempt, 'spec_key': spec.key,
            'spec_sha256': spec.spec_sha256, 'native_execution_approved': False})
        if source is None:
            host = _download(fd, spec, attempt, loopback_proxy, budget)
            source_kind = 'download'
        else:
            _copy_source(fd, source, spec, attempt, budget)
            host, source_kind = '', 'local-import'
        os.fsync(fd)
        info = _hash_file(fd, spec, attempt, budget, 'verify')
        _need(_unchanged(info) == _unchanged(_same_file(directory_fd, spec.filename, fd)),
              'file-changed')
        _directory_still(root, root_fd)
        _directory_still(path, directory_fd)
        receipt = _receipt(spec, attempt, path, info, source_kind, host)
        _save_json(directory_fd, 'receipt.json', dataclasses.asdict(receipt))
        _ensure_quarantine(root, root_fd, path, directory_fd, spec, fd, budget)
        receipt = dataclasses.replace(receipt, quarantine_ensured=True)
        _save_json(directory_fd, 'accepted.json', dataclasses.asdict(receipt))
        budget.notify(spec, attempt, 'accepted', spec.size_bytes)
        return receipt
    except ArtifactError as error:
        raise ArtifactError(error.code, attempt or error.attempt_id) from None
    except Exception as error:
        # urllib/OS/JSON exceptions can contain private paths, credentials or CDN
        # signed queries. Never return their text or an exception cause; only a
        # fixed transfer category (timeout, dropped connection, DNS, TLS...).
        raise ArtifactError(error_codes.network_failure_code(error, 'artifact-io-failed'), attempt) from None
    finally:
        if fd is not None:
            try:
                os.fsync(fd)  # Retain failed partials, including cancellations.
            except OSError:
                pass
            os.close(fd)
        if directory_fd is not None:
            os.close(directory_fd)
        if root_fd is not None:
            os.close(root_fd)


def acquire(spec_key, private_cache_root, *, loopback_proxy=None, progress=None,
            cancelled=None, deadline_seconds=DEFAULT_DEADLINE_SECONDS):
    """Download a fixed registry key, or freshly hash an owned accepted receipt.

    Progress receives a frozen Progress value; cancelled() must return bool.
    A returned Receipt is material verification ONLY, never execution approval.
    Failed attempts are retained. Resume is intentionally NOT implemented.
    """
    return _acquire(spec_key, private_cache_root, loopback_proxy=loopback_proxy,
                    progress=progress, cancelled=cancelled, deadline_seconds=deadline_seconds)


def import_local(spec_key, path, private_cache_root, *, progress=None,
                 cancelled=None, deadline_seconds=DEFAULT_DEADLINE_SECONDS):
    """Verify and copy a caller-owned regular file to a new private cache inode.

    Never mutate the source, persist its path, or trust its original quarantine.
    Uses a shared source flock plus before/after identity and metadata checks;
    acceptance always requires a whole-file pin match on the new cache inode.
    """
    _need(path is not None, 'invalid-path')
    return _acquire(spec_key, private_cache_root, source=path, progress=progress,
                    cancelled=cancelled, deadline_seconds=deadline_seconds)
