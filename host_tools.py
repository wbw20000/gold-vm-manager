"""Reviewed host tools and local-source builds; never run Tart, gvproxy or a VM.

Third-party Tart is only statically assessed, never re-signed. Local project code
may be compiled/ad-hoc signed; that is not Developer ID or notarization.
"""
from contextlib import contextmanager
import dataclasses
import fcntl
import gzip
import grp
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import tarfile
import time
import unicodedata
import uuid

import host_artifacts
import quarantine_policy

HERE = Path(__file__).absolute().parent
TART_VERSION = '2.41.1'
TART_TEAM = '9M2P8L4D89'
TART_IDENTIFIER = 'com.github.cirruslabs.tart'
MAX_ENTRIES = 20000
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TAR_BYTES = MAX_EXPANDED_BYTES + 64 * 1024 * 1024
_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
        'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8',
        'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}


class HostToolError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _need(ok, code):
    if not ok:
        raise HostToolError(code)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _path(value, missing=False):
    text = os.fspath(value)
    _need(type(text) is str and Path(text).is_absolute() and str(Path(text)) == text
          and '..' not in Path(text).parts and not text.startswith('//')
          and not any(ord(c) < 32 or ord(c) == 127 for c in text), 'unsafe-path')
    path = Path(text)
    for part in reversed((path,) + tuple(path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            _need(missing and part == path, 'missing-parent')
            continue
        _need(not stat.S_ISLNK(info.st_mode), 'symlink-path')
        if part != path:
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            # macOS /Applications is normally root:admin 0775. Treat only that
            # exact system-admin directory as trusted, never arbitrary group- or
            # world-writable ancestors. This grants no write privilege itself.
            applications = (part == Path('/Applications') and info.st_uid == 0
                            and stat.S_IMODE(info.st_mode) == 0o775
                            and info.st_gid == grp.getgrnam('admin').gr_gid)
            _need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                  and (not info.st_mode & 0o022 or sticky or applications), 'unsafe-parent')
    return path


def _regular(info, private=False):
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
          and info.st_uid in ((os.getuid(),) if private else (0, os.getuid()))
          and not stat.S_IMODE(info.st_mode) & 0o7022, 'unsafe-file')
    if private:
        _need(not stat.S_IMODE(info.st_mode) & 0o077, 'file-not-private')


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(path, cap=4 * 1024 * 1024, private=False):
    path = _path(path)
    before = path.lstat()
    _regular(before, private)
    _need(before.st_size <= cap, 'file-too-large')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _need(_stamp(before) == _stamp(os.fstat(fd)), 'file-changed')
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, cap - size + 1))
            if not chunk:
                break
            size += len(chunk)
            _need(size <= cap, 'file-too-large')
            chunks.append(chunk)
        _need(size == before.st_size and _stamp(before) == _stamp(os.fstat(fd))
              == _stamp(path.lstat()), 'file-changed')
        return b''.join(chunks)
    finally:
        os.close(fd)


def _digest(path, cap=MAX_FILE_BYTES):
    path = _path(path)
    info = path.lstat()
    _regular(info)
    _need(info.st_size <= cap, 'file-too-large')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _need(_stamp(info) == _stamp(os.fstat(fd)), 'file-changed')
        digest, size = hashlib.sha256(), 0
        while True:
            raw = os.read(fd, min(1024 * 1024, cap - size + 1))
            if not raw:
                break
            size += len(raw)
            _need(size <= cap, 'file-too-large')
            digest.update(raw)
        _need(size == info.st_size and _stamp(info) == _stamp(os.fstat(fd)) == _stamp(path.lstat()),
              'file-changed')
        return digest.hexdigest()
    finally:
        os.close(fd)


def _private_root(path):
    path = _path(path, missing=True)
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.stat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, 'private-root-required')
    return path


def _sync(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _attempt(root, prefix):
    root = _private_root(root)
    result = root / (prefix + '-' + uuid.uuid4().hex)
    result.mkdir(mode=0o700)
    _sync(root)
    return result


def _write(path, raw, mode=0o600):
    _path(path.parent)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _need(count > 0, 'write-failed')
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        _need(_stamp(os.fstat(fd)) == _stamp(path.lstat()), 'destination-changed')
    finally:
        os.close(fd)
    _sync(path.parent)


def _validate_system_compiler_temp(path, info):
    # getconf, not an inherited TMPDIR or a caller-controlled location, selects
    # the standard OS per-user temporary directory. Inspect metadata only.
    _need(path.is_absolute() and path.name == 'T'
          and str(path).startswith('/private/var/folders/')
          and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, 'trusted-os-compiler-temp-required')
    return path


def _system_compiler_temp():
    result = _tool(['/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR'])
    text = result.stdout.decode('utf-8', 'strict').strip()
    _need(0 < len(text) <= 4096 and Path(text).is_absolute()
          and not any(ord(c) < 32 or ord(c) == 127 for c in text), 'invalid-os-compiler-temp')
    # Canonicalizing this trusted OS result is intentional: /var is Apple's
    # standard alias to /private/var. No caller artifact path gains this exception.
    path = _path(Path(text).resolve(strict=True))
    return _validate_system_compiler_temp(path, path.lstat())


def _tool(argv, timeout=120, build_directory=None):
    _need(argv[0] in ('/usr/bin/xcrun', '/usr/bin/xcode-select', '/usr/bin/python3', '/usr/bin/ruby',
                     '/usr/bin/codesign', '/usr/bin/lipo', '/usr/bin/getconf', '/usr/sbin/spctl'), 'unsupported-native-tool')
    # The native SDK driver requires a legitimate OS account HOME. Looking up
    # that account field is not profile/keychain harvesting; no home files are
    # read/copied by this module and no ambient auth/proxy/loader env is retained.
    env = dict(_ENV, HOME=pwd.getpwuid(os.getuid()).pw_dir)
    if build_directory is not None:
        _need(argv[0] == '/usr/bin/xcrun' and 'swiftc' in argv, 'compiler-environment-only')
        build_directory = _private_root(build_directory)
        temporary = _system_compiler_temp()
        env.update(TMPDIR=str(temporary) + '/', CLANG_MODULE_CACHE_PATH=str(build_directory / 'module-cache'))
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise HostToolError('native-tool-timeout') from None
    except Exception:
        raise HostToolError('native-tool-unavailable') from None
    _need(len(result.stdout) + len(result.stderr) <= 2 * 1024 * 1024, 'native-output-too-large')
    if result.returncode != 0:
        error = HostToolError('native-tool-rejected')
        error.returncode = result.returncode
        # Exact compiler diagnostics stay in this caller-owned private build,
        # never an unsanitized UI error or an inherited environment dump.
        if build_directory is not None:
            error.diagnostic_path = build_directory / ('compiler-error-' + uuid.uuid4().hex + '.txt')
            _write(error.diagnostic_path, result.stdout + result.stderr)
        raise error
    return result


def source_prerequisites():
    """Read-only checks; no installs, global packages, host profiles or keychains."""
    _need(sys.version_info >= (3, 9), 'python39-required')
    _need((platform.system(), platform.machine(), platform.mac_ver()[0])
          == ('Darwin', 'arm64', '26.6.2'), 'unsupported-host-platform')
    developer = _tool(['/usr/bin/xcode-select', '-p']).stdout.decode('utf-8').strip()
    _path(developer)
    _tool(['/usr/bin/python3', '-I', '-c', 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'])
    _tool(['/usr/bin/ruby', '-e', "require 'psych'; abort unless Psych.respond_to?(:safe_load)"])
    sdk = _tool(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).stdout.decode('utf-8').strip()
    # xcrun commonly returns Apple's MacOSX.sdk symlink. Canonicalize only this
    # trusted tool-selected SDK, never caller-supplied artifact/output paths.
    sdk = _path(Path(sdk).resolve(strict=True))
    _need(sdk.is_dir(), 'sdk-directory-required')
    return {'platform': 'Darwin-arm64-26.6.2', 'sdk_path': str(sdk), 'notarized': False}


def verify_local_signature(path, entitlements):
    """Verify only an explicitly locally built artifact, never a third-party app."""
    _path(path)
    _tool(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(path)])
    displayed = _tool(['/usr/bin/codesign', '--display', '--verbose=4', str(path)])
    text = (displayed.stdout + displayed.stderr).decode('utf-8', 'replace')
    _need(re.search(r'^Signature=adhoc\s*$', text, re.M) is not None,
          'local-adhoc-signature-required')
    result = _tool(['/usr/bin/codesign', '--display', '--entitlements', ':-', '--xml', str(path)])
    actual = plistlib.loads(result.stdout) if result.stdout.strip() else {}
    _need(type(actual) is dict and _json(actual) == _json(entitlements), 'unexpected-local-entitlements')


def _sign_local(path, entitlements_path=None, expected_entitlements=None):
    argv = ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none']
    if entitlements_path is not None:
        argv.extend(['--entitlements', str(entitlements_path)])
    _tool(argv + [str(path)])
    verify_local_signature(path, expected_entitlements or {})


HELPERS_PORTABLE_RECEIPT = 'helpers.portable.json'
OWNERSHIP_PORTABLE_RECEIPT = 'ownership-helper.portable.json'


def _helper_group(group):
    _need(group in ('runtime', 'ownership'), 'unknown-helper-group')
    if group == 'runtime':
        return (('CleanVMInstaller', 'GuestVPNBootstrap'),
                ('CleanVMInstaller.swift', 'CleanVMInstaller.entitlements.plist', 'GuestVPNBootstrap.swift'),
                HELPERS_PORTABLE_RECEIPT)
    return (('GuestOwnershipHelper',), ('GuestOwnershipHelper.swift',), OWNERSHIP_PORTABLE_RECEIPT)


def _portable_header(group):
    names, _, _ = _helper_group(group)
    recipes = {}
    for name in names:
        clean = name == 'CleanVMInstaller'
        recipes[name] = {
            'source': name + '.swift', 'compiler': 'apple-sdk-swiftc', 'sdk': 'macosx',
            'target': 'arm64-apple-macos13.0', 'swift_version': '6' if clean else '5',
            'parse_as_library': True, 'optimization': '-O', 'defines': [],
            'frameworks': ['Virtualization'] if clean else [],
            'entitlements': {'com.apple.security.virtualization': True} if clean else {},
            'signature': 'local-ad-hoc', 'timestamp': 'none',
        }
    return {'schema': 1, 'kind': 'gold-local-helper-build', 'group': group,
            'recipes': recipes, 'notarized': False, 'developer_id_signed': False,
            'executed': False, 'administrator_authorization_requested': False}


def _emit_portable_receipt(root, group, source_hashes):
    names, sources, receipt_name = _helper_group(group)
    _need(set(source_hashes) == set(sources), 'portable-source-set-mismatch')
    value = _portable_header(group)
    value.update(source_sha256=dict(source_hashes),
                 artifact_sha256={name: _digest(root / name) for name in names})
    _write(root / receipt_name, _json(value))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'duplicate-portable-receipt-key')
        result[key] = value
    return result


def _present(path):
    return os.path.lexists(str(path))


def _enclosing_local_app(root):
    if root.name == 'app' and root.parent.name == 'Resources' and root.parent.parent.name == 'Contents':
        app = root.parents[2]
        _need(app.suffix == '.app', 'invalid-packaged-resource-root')
        return app
    return None


def _verify_portable_helpers(resource_root, group):
    names, sources, receipt_name = _helper_group(group)
    root = _path(resource_root)
    _need(root.is_dir(), 'helper-resource-directory-required')
    _need(all(_present(root / name) for name in names + (receipt_name,)),
          'complete-helper-binaries-and-portable-receipt-required')
    receipt_path = root / receipt_name
    raw = _read(receipt_path, cap=65536)
    document = json.loads(raw, object_pairs_hook=_unique_object)
    header = _portable_header(group)
    _need(type(document) is dict and set(document) == set(header) | {'source_sha256', 'artifact_sha256'},
          'invalid-portable-helper-receipt')
    _need(_json({key: document[key] for key in header}) == _json(header),
          'portable-helper-build-recipe-mismatch')
    for key, expected_names in (('source_sha256', sources), ('artifact_sha256', names)):
        values = document[key]
        _need(type(values) is dict and set(values) == set(expected_names)
              and all(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) for value in values.values()),
              'invalid-portable-helper-hashes')
    paths = tuple(root / name for name in names)
    before = {receipt_path: _stamp(receipt_path.lstat())}
    for path in paths:
        _regular(path.lstat())
        _need(bool(path.stat().st_mode & 0o100), 'packaged-helper-not-executable')
        _need(_digest(path) == document['artifact_sha256'][path.name], 'packaged-helper-hash-mismatch')
        before[path] = _stamp(path.lstat())
    # Sources are optional for a binary package; if present, they must match the
    # full recorded source closure. Absence never causes a packaged recompile.
    for name in sources:
        path = root / name
        if _present(path):
            _need(_digest(path, cap=4 * 1024 * 1024) == document['source_sha256'][name],
                  'packaged-helper-source-mismatch')
            before[path] = _stamp(path.lstat())
    app = _enclosing_local_app(root)
    if app is not None:
        verify_local_signature(app, {})  # Also verify the wrapper seal over the receipt.
    for path in paths:
        verify_local_signature(path, header['recipes'][path.name]['entitlements'])
        architectures = _tool(['/usr/bin/lipo', '-archs', str(path)]).stdout.decode('ascii').split()
        _need(architectures == ['arm64'], 'packaged-helper-arm64-required')
    _need(_read(receipt_path, cap=65536) == raw, 'portable-helper-receipt-changed')
    for path in paths:
        _need(_digest(path) == document['artifact_sha256'][path.name], 'packaged-helper-changed')
    _need(all(_stamp(path.lstat()) == stamp for path, stamp in before.items()), 'packaged-helper-changed')
    return paths


def _resolve_helper_group(resource_root, private_build_root, group):
    try:
        root = _path(resource_root)
        _need(root.is_dir(), 'helper-resource-directory-required')
        names, sources, receipt_name = _helper_group(group)
        if any(_present(root / name) for name in names + (receipt_name,)):
            # An incomplete, unreceipted or altered binary set is an error, not
            # permission to adopt it, erase it or silently rebuild around it.
            return _verify_portable_helpers(root, group)
        _need(_enclosing_local_app(root) is None, 'packaged-helpers-missing-no-runtime-compilation')
        for source in sources:
            _read(root / source)
        if group == 'runtime':
            return _compile_helpers(private_build_root, root)
        return (_compile_ownership_helper(private_build_root, root),)
    except HostToolError:
        raise
    except Exception:
        raise HostToolError('helper-resolution-failed') from None


def resolve_helpers(resource_root, private_build_root):
    """Reuse two verified receipt-bound binaries, or compile an explicit source checkout.

    Binary packages need no Swift sources/SDK invocation. An app missing its
    packaged helpers is rejected rather than compiling at runtime.
    """
    return _resolve_helper_group(resource_root, private_build_root, 'runtime')


def resolve_ownership_helper(resource_root, private_build_root):
    """Return the separately verified metadata helper; never request privileges."""
    return _resolve_helper_group(resource_root, private_build_root, 'ownership')[0]


def compile_helpers(private_build_root):
    """Return (CleanVMInstaller Path, production GuestVPNBootstrap Path).

    Outputs and durable helpers.json live under a NEW unique private directory.
    No helper is executed. No GOLD_VPN_BOOTSTRAP_FIXTURE compiler define is used.
    """
    return _compile_helpers(private_build_root, HERE)


def _compile_helpers(private_build_root, source_root):
    try:
        prerequisites = source_prerequisites()
        root = _attempt(private_build_root, 'helpers')
        sources = {}
        for name in ('CleanVMInstaller.swift', 'GuestVPNBootstrap.swift', 'CleanVMInstaller.entitlements.plist'):
            raw = _read(Path(source_root) / name)
            sources[name] = _sha(raw)
            _write(root / name, raw)
        entitlement = {'com.apple.security.virtualization': True}
        _need(plistlib.loads(_read(root / 'CleanVMInstaller.entitlements.plist')) == entitlement,
              'unexpected-source-entitlements')
        common = ['/usr/bin/xcrun', '--sdk', 'macosx', 'swiftc', '-parse-as-library', '-O',
                  '-target', 'arm64-apple-macos13.0', '-sdk', prerequisites['sdk_path'],
                  '-module-cache-path', str(root / 'module-cache')]
        clean, guest = root / 'CleanVMInstaller', root / 'GuestVPNBootstrap'
        _tool(common + ['-swift-version', '6', str(root / 'CleanVMInstaller.swift'),
                        '-framework', 'Virtualization', '-o', str(clean)], timeout=600, build_directory=root)
        _tool(common + ['-swift-version', '5', str(root / 'GuestVPNBootstrap.swift'),
                        '-o', str(guest)], timeout=600, build_directory=root)
        for path in (clean, guest):
            _regular(path.lstat())
            _need(path.stat().st_uid == os.getuid() and bool(path.stat().st_mode & 0o100),
                  'compiled-helper-not-executable')
            path.chmod(0o700)  # Restrict only this newly compiled project artifact.
            _regular(path.lstat(), private=True)
        _sign_local(clean, root / 'CleanVMInstaller.entitlements.plist', entitlement)
        _sign_local(guest)
        for name, digest in sources.items():
            _need(_digest(root / name) == digest, 'build-source-changed')
        _write(root / 'helpers.json', _json({
            'schema': 1, 'source_sha256': sources, 'signature': 'local-ad-hoc',
            'notarized': False, 'developer_id_signed': False, 'executed': False,
            'production_guest_bootstrap': True,
            'artifacts': {p.name: {'path': str(p), 'sha256': _digest(p)} for p in (clean, guest)},
            'clean_installer_entitlements': entitlement,
        }))
        _emit_portable_receipt(root, 'runtime', sources)
        return clean, guest
    except HostToolError:
        raise
    except Exception:
        raise HostToolError('helper-build-failed') from None


def compile_ownership_helper(private_build_root):
    """Compile/sign a separate local metadata helper; NEVER authorize or run it.

    OS administrator consent and the helper's restricted operation protocol are
    parent responsibilities. This API does not request privileges or set set-ID.
    """
    return _compile_ownership_helper(private_build_root, HERE)


def _compile_ownership_helper(private_build_root, source_root):
    try:
        raw = _read(Path(source_root) / 'GuestOwnershipHelper.swift')
        prerequisites = source_prerequisites()
        root = _attempt(private_build_root, 'ownership-helper')
        source, binary = root / 'GuestOwnershipHelper.swift', root / 'GuestOwnershipHelper'
        _write(source, raw)
        _tool(['/usr/bin/xcrun', '--sdk', 'macosx', 'swiftc', '-parse-as-library', '-O',
               '-swift-version', '5', '-target', 'arm64-apple-macos13.0',
               '-sdk', prerequisites['sdk_path'], '-module-cache-path', str(root / 'module-cache'),
               str(source), '-o', str(binary)], timeout=600, build_directory=root)
        _regular(binary.lstat())
        _need(binary.stat().st_uid == os.getuid() and bool(binary.stat().st_mode & 0o100),
              'compiled-helper-not-executable')
        binary.chmod(0o700)  # Never setuid/setgid; ordinary owned project executable.
        _sign_local(binary)
        _need(_digest(source) == _sha(raw), 'build-source-changed')
        _write(root / 'ownership-helper.json', _json({
            'schema': 1, 'source_sha256': _sha(raw), 'path': str(binary),
            'sha256': _digest(binary), 'signature': 'local-ad-hoc', 'notarized': False,
            'entitlements': {}, 'executed': False, 'administrator_authorization_requested': False,
        }))
        _emit_portable_receipt(root, 'ownership', {'GuestOwnershipHelper.swift': _sha(raw)})
        return binary
    except HostToolError:
        raise
    except Exception:
        raise HostToolError('ownership-helper-build-failed') from None


@dataclasses.dataclass(frozen=True)
class TartReceipt:
    app_path: Path
    executable_path: Path
    receipt_path: Path
    version: str
    team_id: str
    executable_sha256: str
    bundle_tree_sha256: str
    notarized: bool
    source_kind: str
    archive_sha256: str = ''
    execution_performed: bool = False


def _text(value):
    return type(value) is str and 0 < len(value) <= 4096 and '\\' not in value \
        and not any(ord(c) < 32 or ord(c) == 127 for c in value) \
        and unicodedata.normalize('NFC', value) == value


def _tar_name(name):
    _need(_text(name) and not name.startswith('/') and ':' not in name, 'unsafe-tar-path')
    # A single standard directory trailing slash is not a pathname alias.
    value = name[:-1] if name.endswith('/') else name
    parts = value.split('/')
    _need(1 <= len(parts) <= 32 and all(p not in ('', '.', '..') for p in parts)
          and parts[0] == 'tart.app', 'unsafe-tar-path')
    return '/'.join(parts)


def _resolve_virtual(path, nodes):
    pending, current, links = path.split('/'), [] , 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            _need(len(current) > 1, 'escaping-tar-link')
            current.pop()
            continue
        current.append(part)
        key = '/'.join(current)
        _need(key in nodes, 'broken-tar-link')
        node = nodes[key]
        if node['kind'] == 'symlink':
            links += 1
            _need(links <= 40, 'cyclic-tar-link')
            current.pop()
            pending = node['target'].split('/') + pending
        elif pending:
            _need(node['kind'] == 'directory', 'invalid-tar-link-parent')
    _need(len(current) > 1 and current[0] == 'tart.app', 'escaping-tar-link')
    return '/'.join(current)


class _BoundedTarIO:
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline

    def check(self):
        _need(time.monotonic() < self.deadline, 'tar-deadline-exceeded')

    def tell(self):
        return self.stream.tell()

    def seek(self, offset, whence=0):
        self.check()
        _need(whence in (0, 1), 'unsupported-tar-seek')
        destination = offset + (self.tell() if whence == 1 else 0)
        _need(0 <= destination <= MAX_TAR_BYTES, 'expanded-tar-limit')
        value = self.stream.seek(destination)
        self.check()
        return value

    def read(self, size=-1):
        self.check()
        remaining = MAX_TAR_BYTES - self.tell()
        # Ordinary extraction reads <=1MiB. Large parser metadata allocations
        # (e.g. a bomb-sized PAX header) are refused before gzip expands them.
        _need(0 <= size <= min(remaining, 4 * 1024 * 1024), 'expanded-tar-limit')
        data = self.stream.read(size)
        self.check()
        return data


def _tar_plan(archive, deadline):
    nodes, aliases, total, count = {}, {}, 0, 0
    for member in archive:
        _need(time.monotonic() < deadline, 'tar-deadline-exceeded')
        count += 1
        _need(count <= MAX_ENTRIES, 'too-many-tar-entries')
        _need(not member.name.endswith('/') or member.isdir(), 'unsafe-tar-path')
        if member.name == 'LICENSE':
            # The exact reviewed Tart release places its license beside the app.
            # This is the only allowed sibling, and is retained solely as data.
            _need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                  and 0 < member.size <= 128 * 1024 and not member.mode & 0o111,
                  'invalid-tart-license-member')
            name = 'LICENSE'
        else:
            name = _tar_name(member.name)
        _need(not member.sparse and not any(k.startswith('GNU.sparse') for k in member.pax_headers),
              'sparse-tar-refused')
        _need(set(member.pax_headers) <= {'path', 'linkpath', 'mtime', 'atime', 'ctime', 'size'},
              'unsupported-tar-metadata')
        _need(not member.mode & 0o7000 and (member.issym() or not member.mode & 0o022),
              'unsafe-tar-mode')
        if member.isdir():
            kind = 'directory'
        elif member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
            kind = 'file'
            _need(0 <= member.size <= MAX_FILE_BYTES, 'tar-file-too-large')
            total += member.size
            _need(total <= MAX_EXPANDED_BYTES, 'expanded-tar-limit')
        elif member.issym():
            kind = 'symlink'
            _need(_text(member.linkname) and not member.linkname.startswith('/')
                  and ':' not in member.linkname, 'unsafe-tar-link')
        else:
            raise HostToolError('unsupported-tar-member')
        _need(name not in nodes or nodes[name].get('implicit') and kind == 'directory',
              'duplicate-tar-path')
        parts = name.split('/')
        for index in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:index])
            folded = prefix.casefold()
            _need(folded not in aliases or aliases[folded] == prefix, 'unicode-or-case-tar-alias')
            aliases[folded] = prefix
            if index < len(parts):
                _need(prefix not in nodes or nodes[prefix]['kind'] == 'directory', 'tar-link-parent')
                nodes.setdefault(prefix, {'kind': 'directory', 'implicit': True, 'mode': 0o755})
        nodes[name] = {'kind': kind, 'member': member, 'mode': member.mode,
                       'target': member.linkname if kind == 'symlink' else None}
        _need(len(nodes) <= MAX_ENTRIES, 'too-many-tar-entries')
    _need(nodes and nodes.get('tart.app', {}).get('kind') == 'directory', 'single-tart-app-required')
    for name, node in nodes.items():
        if node['kind'] == 'symlink':
            _resolve_virtual(name, nodes)
    return nodes


def _extract(archive, nodes, root, deadline):
    for name in sorted(nodes, key=lambda n: (n.count('/'), n)):
        node = nodes[name]
        if node['kind'] == 'directory':
            path = root / name
            _path(path.parent)
            path.mkdir(mode=0o700)
    for name, node in nodes.items():
        _need(time.monotonic() < deadline, 'tar-deadline-exceeded')
        if node['kind'] != 'file':
            continue
        path = root / name
        _path(path.parent)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            source = archive.extractfile(node['member'])
            _need(source is not None, 'tar-file-missing')
            with source:
                total = 0
                while True:
                    _need(time.monotonic() < deadline, 'tar-deadline-exceeded')
                    chunk = source.read(min(1024 * 1024, node['member'].size - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    _need(total <= node['member'].size, 'tar-size-mismatch')
                    view = memoryview(chunk)
                    while view:
                        written = os.write(fd, view)
                        _need(written > 0, 'write-failed')
                        view = view[written:]
                _need(total == node['member'].size, 'tar-size-mismatch')
            os.fchmod(fd, node['mode'] & 0o777)
            os.fsync(fd)
        finally:
            os.close(fd)
    # No archive-created symlink exists while files/directories are written.
    for name, node in nodes.items():
        if node['kind'] == 'symlink':
            path = root / name
            _path(path.parent)
            os.symlink(node['target'], str(path))
    for name in sorted(nodes, key=lambda n: -n.count('/')):
        node = nodes[name]
        if node['kind'] == 'directory':
            path = root / name
            path.chmod(node['mode'] & 0o777)
            _sync(path)
    _sync(root)


def _reviewed_tart_spec():
    return host_artifacts.SPECS['tart']


@contextmanager
def _archive_source(receipt):
    _need(type(receipt) is host_artifacts.Receipt, 'host-artifact-receipt-required')
    spec = _reviewed_tart_spec()
    _need(receipt.spec_key == 'tart' and receipt.spec_sha256 == spec.spec_sha256
          and receipt.version == spec.version and receipt.sha256 == spec.sha256
          and receipt.size_bytes == spec.size_bytes and receipt.digest_verified is True
          and receipt.quarantine_ensured is True and receipt.native_execution_approved is False,
          'reviewed-tart-receipt-required')
    path = _path(receipt.artifact_path)
    _private_root(path.parent)
    _need(path.name == spec.filename and path.parent.name == receipt.attempt_id
          and re.fullmatch(r'tart-[0-9a-f]{32}', receipt.attempt_id)
          and receipt.receipt_path == str(path.parent / 'receipt.json')
          and receipt.acceptance_path == str(path.parent / 'accepted.json'), 'invalid-receipt-path')
    accepted = _read(Path(receipt.acceptance_path), private=True)
    proof = _read(Path(receipt.receipt_path), private=True)
    _need(_json(json.loads(accepted)) == _json(dataclasses.asdict(receipt))
          and _json(json.loads(proof)) == _json(dataclasses.asdict(
              dataclasses.replace(receipt, quarantine_ensured=False))), 'durable-receipt-mismatch')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = os.fstat(fd)
        _regular(before, True)
        _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
              == (receipt.device, receipt.inode, spec.size_bytes, receipt.mtime_ns), 'archive-identity-mismatch')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            digest, size, deadline = hashlib.sha256(), 0, time.monotonic() + 900
            while True:
                _need(time.monotonic() < deadline, 'archive-hash-deadline')
                data = stream.read(min(1024 * 1024, spec.size_bytes - size + 1))
                if not data:
                    break
                size += len(data)
                _need(size <= spec.size_bytes, 'archive-size-mismatch')
                digest.update(data)
            _need(digest.hexdigest() == spec.sha256 and _stamp(before) == _stamp(os.fstat(fd))
                  == _stamp(path.lstat()), 'archive-digest-mismatch')
            quarantine_policy.read(path)  # Require preserved origin; do not add/clear it here.
            stream.seek(0)
            yield path, stream, spec.sha256
            _need(_stamp(before) == _stamp(os.fstat(fd)) == _stamp(path.lstat()), 'archive-changed')
    finally:
        os.close(fd)


def _tree(app):
    # Reuse the reviewed component-wise internal-link resolver, not the guest
    # three-product manifest or its product-specific verification entry point.
    from guest_app_artifacts import _resolve_internal_link
    records, seen, total = [], set(), 0
    stack = [app]
    while stack:
        directory = stack.pop()
        for path in sorted(directory.iterdir()):
            rel = path.relative_to(app).as_posix()
            _need(_text(rel), 'unsafe-bundle-path')
            folded = rel.casefold()
            _need(folded not in seen, 'bundle-alias')
            seen.add(folded)
            _need(len(seen) <= MAX_ENTRIES, 'too-many-bundle-entries')
            info = path.lstat()
            _need(info.st_uid in (0, os.getuid()), 'unsafe-bundle-owner')
            if stat.S_ISLNK(info.st_mode):
                _resolve_internal_link(path, app)
                records.append((rel, 'symlink', os.readlink(str(path))))
            elif stat.S_ISDIR(info.st_mode):
                _need(not info.st_mode & 0o7022, 'unsafe-bundle-directory')
                stack.append(path)
                records.append((rel, 'directory', stat.S_IMODE(info.st_mode)))
            else:
                _regular(info)
                total += info.st_size
                _need(total <= MAX_EXPANDED_BYTES, 'bundle-too-large')
                records.append((rel, 'file', stat.S_IMODE(info.st_mode), info.st_size, _digest(path)))
    return _sha(_json(sorted(records)))


def _verify_tart(app):
    app = _path(app)
    _need(app.suffix == '.app' and app.is_dir(), 'tart-app-required')
    before = _tree(app)
    info = plistlib.loads(_read(app / 'Contents' / 'Info.plist', cap=1024 * 1024))
    _need(type(info) is dict and info.get('CFBundleIdentifier') == TART_IDENTIFIER
          and info.get('CFBundleExecutable') == 'tart' and info.get('CFBundlePackageType') == 'APPL'
          and info.get('CFBundleShortVersionString', info.get('CFBundleVersion')) == TART_VERSION,
          'unexpected-tart-bundle')
    executable = app / 'Contents' / 'MacOS' / 'tart'
    _need(bool(executable.stat().st_mode & 0o100), 'tart-not-executable')
    architectures = _tool(['/usr/bin/lipo', '-archs', str(executable)]).stdout.decode('ascii').split()
    _need('arm64' in architectures and set(architectures) <= {'arm64', 'arm64e', 'x86_64'}, 'arm64-required')
    requirement = ('=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                   'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                   'and certificate leaf[subject.OU] = "%s" and identifier "%s"'
                   % (TART_TEAM, TART_IDENTIFIER))
    _tool(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', requirement, str(app)])
    display = _tool(['/usr/bin/codesign', '--display', '--verbose=4', str(app)])
    signature = (display.stdout + display.stderr).decode('utf-8', 'replace')
    _need(re.findall(r'^TeamIdentifier=(.+)$', signature, re.M) == [TART_TEAM]
          and re.findall(r'^Identifier=(.+)$', signature, re.M) == [TART_IDENTIFIER]
          and re.findall(r'^Authority=Developer ID Application: (.+)$', signature, re.M)
          in ([f'Cirrus Labs, Inc. ({TART_TEAM})'], [f'Cirrus Labs Inc. ({TART_TEAM})']),
          'tart-signing-identity-mismatch')
    assessment = _tool(['/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=4', str(app)])
    verdict = (assessment.stdout + assessment.stderr).decode('utf-8', 'replace')
    _need(re.search(r'^source=Notarized Developer ID\s*$', verdict, re.M)
          and re.search(r': accepted\s*$', verdict, re.M), 'tart-notarization-required')
    _need(_tree(app) == before, 'tart-changed-during-verification')
    return executable, _digest(executable), before


def ensure_tart(private_tools_root, *, artifact_receipt=None, existing_tart=None):
    """Statically verify an explicit existing app OR extract a pinned receipt.

    Returns a frozen TartReceipt. No downloading, CLI invocation, VM operation,
    installation, third-party signing or executable launch occurs.
    """
    try:
        _need((artifact_receipt is None) != (existing_tart is None), 'choose-exactly-one-tart-source')
        root = _attempt(private_tools_root, 'tart-tool')
        archive_sha = ''
        if existing_tart is not None:
            supplied = _path(existing_tart)
            app = supplied.parents[2] if supplied.name == 'tart' and supplied.parent.name == 'MacOS' else supplied
            _need(supplied == app or supplied == app / 'Contents' / 'MacOS' / 'tart', 'invalid-tart-path')
            source_kind = 'explicit-existing-native-verified'
        else:
            with _archive_source(artifact_receipt) as (artifact, stream, archive_sha):
                deadline = time.monotonic() + 900
                with gzip.GzipFile(fileobj=stream, mode='rb') as expanded:
                    bounded = _BoundedTarIO(expanded, deadline)
                    with tarfile.open(fileobj=bounded, mode='r:') as archive:
                        plan = _tar_plan(archive, deadline)
                        _extract(archive, plan, root, deadline)
                app = root / 'tart.app'
                _write(root / 'extraction.json', _json({'schema': 1, 'archive_sha256': archive_sha,
                       'complete_members': len(plan), 'native_verification_performed': False}))
                quarantine_policy.propagate(artifact, app)
            source_kind = 'pinned-public-archive'
        executable, digest, tree = _verify_tart(app)
        receipt = TartReceipt(app, executable, root / 'tart.json', TART_VERSION, TART_TEAM,
                              digest, tree, True, source_kind, archive_sha)
        value = dataclasses.asdict(receipt)
        for key in ('app_path', 'executable_path', 'receipt_path'):
            value[key] = str(value[key])
        _write(receipt.receipt_path, _json(value))
        return receipt
    except HostToolError:
        raise
    except Exception:
        raise HostToolError('tart-preparation-failed') from None
