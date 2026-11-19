"""Explicit, one-shot macOS administrator bridge for NEW guest ownership only.

No mount, detach, VM start, password reading, sudo, authorization caching or
implicit approval. Parent owns the locked stage and both independently verified
mount sessions. Production root enforcement is in GuestOwnershipHelper.swift.
"""
from dataclasses import dataclass, asdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
from typing import Optional
import unicodedata

import host_tools
import quarantine_policy

APP_NAMES = ('CCBaga-A.app', 'CCBaga-B.app', 'Clash Verge.app', 'Claude.app')
BASE = 'Library/Application Support/GoldVMManager'
SEED_RULES = {
    BASE: ('directory', 0, 0, 0o755),
    BASE + '/FirstLogin': ('directory', 501, 20, 0o700),
    BASE + '/FirstLogin/GuestVPNBootstrap': ('file', 0, 0, 0o755),
    BASE + '/FirstLogin/seed.json': ('file', 501, 20, 0o600),
    'Library/LaunchAgents/org.goldvmmanager.first-login.plist': ('file', 0, 0, 0o644),
}
TICKET_SCHEMA = 2
MAX_ENTRIES = 200000
MAX_TICKET_BYTES = 64 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 ** 3
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\Z')


class OwnershipError(ValueError):
    """Only constant sanitized messages cross the API."""


@dataclass(frozen=True, repr=False)
class OwnershipEntry:
    path: str
    kind: str
    device: int
    inode: int
    size: int
    mode: int
    observed_uid: int
    observed_gid: int
    ctime_ns: int
    sha256: str = ''
    link_target: str = ''

    def __repr__(self):
        return 'OwnershipEntry(<private metadata>)'


@dataclass(frozen=True, repr=False)
class OwnershipTicket:
    path: Path
    digest: str
    operation_id: str
    helper_path: Path
    caller_uid: int

    def __repr__(self):
        return 'OwnershipTicket(<private metadata>)'


@dataclass(frozen=True)
class AuthorizationResult:
    phase: str
    operation: str
    authorized_helper_completed: bool
    independent_readonly_acceptance: bool = False
    # Fixed category only; never native text. failure_status is set only for
    # 'helper-exit' (helper exit status) and 'authorization-error' (OSStatus).
    failure_reason: Optional[str] = None
    failure_status: Optional[int] = None


# osascript reports `... execution error: <text> (<number>)`; only the number is used.
_OSASCRIPT_STATUS = re.compile(r'\((-?\d{1,6})\)\s*\Z')
_AUTHORIZATION_STATUS = {-128: 'user-cancelled', -60006: 'user-cancelled',
                         -60005: 'authorization-denied', -60007: 'interaction-not-allowed'}


def _classify_osascript_failure(stderr):
    """Return (reason, status) from the trailing number only; the text is discarded."""
    try:
        lines = [line for line in (stderr or b'').decode('utf-8', 'replace').splitlines() if line.strip()]
    except (AttributeError, TypeError):
        lines = []
    match = _OSASCRIPT_STATUS.search(lines[-1]) if lines else None
    if match is None:
        return 'unknown-failure', None
    status = int(match.group(1))
    if status in _AUTHORIZATION_STATUS:
        return _AUTHORIZATION_STATUS[status], None
    if 0 < status <= 255:
        return 'helper-exit', status
    if status < 0:
        return 'authorization-error', status
    return 'unknown-failure', None


def _authorization_failure(operation, reason, status=None):
    return AuthorizationResult('authorization_or_helper_failed_retained', operation, False,
                               failure_reason=reason, failure_status=status)


def _need(ok, message='Guest ownership validation failed; retain the unpublished stage'):
    if not ok:
        raise OwnershipError(message) from None


def _canonical(path):
    path = Path(path)
    _need(path.is_absolute() and '..' not in path.parts and '.' not in path.parts
          and not any(ord(c) < 32 or ord(c) == 127 for c in str(path)))
    _need(path.resolve(strict=True) == path)
    # resolve equality alone misses a lexical alias which returns to the same
    # inode; inspect every component and reject any link explicitly.
    cursor = Path('/')
    for part in path.parts[1:]:
        cursor /= part
        _need(not stat.S_ISLNK(cursor.lstat().st_mode))
    return path


def operation_paths(tart_home, job_id, operation_id, *, state_dir):
    """Pure fixed layout. Parent creates private dirs before its mount sessions."""
    _need(type(job_id) is str and HEX32.fullmatch(job_id) is not None)
    _need(type(operation_id) is str and HEX32.fullmatch(operation_id) is not None)
    root = Path(tart_home)
    _need(root.is_absolute() and '..' not in root.parts)
    directory = root / '.gold-manager-staging' / job_id / 'new-environment' / '.guest-ownership' / operation_id
    state = Path(state_dir)
    _need(state.is_absolute() and '..' not in state.parts)
    evidence = state / 'build-jobs' / job_id / ('offline-vpn-' + operation_id)
    return {'directory': directory, 'ticket': directory / 'ticket.json',
            'apply_mount': evidence / 'write-session' / 'data-mount',
            'verify_mount': evidence / 'owner-readonly' / 'data-mount'}


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _file_hash(fd, size):
    _need(0 <= size <= MAX_TREE_BYTES)
    before = os.fstat(fd)
    digest = hashlib.sha256()
    count = 0
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        count += len(block)
        _need(count <= size)
        digest.update(block)
    after = os.fstat(fd)
    _need(count == size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
          == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return digest.hexdigest()


def _identity(path, owner, *, digest=False, executable=False):
    path = _canonical(path)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner
              and stat.S_IMODE(info.st_mode) == (0o755 if executable else 0o600))
        result = {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
                  'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        if digest:
            # A previously deployed helper may predate this ticket schema. Bind
            # the bytes carrying the production contract to the very same hash.
            result['sha256'] = (hashlib.sha256(_read_production_helper(fd, info)).hexdigest()
                                if executable else _file_hash(fd, info.st_size))
        return result
    finally:
        os.close(fd)


def _locked_config_identity(path, fd, owner):
    # POSIX locks are dropped if this process closes ANY descriptor for the
    # locked inode. Never open/close this file; hash via pread on caller's fd.
    _need(type(fd) is int and fd >= 0)
    path = _canonical(path)
    info = os.fstat(fd)
    actual = path.lstat()
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
          and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1024 * 1024
          and (info.st_dev, info.st_ino) == (actual.st_dev, actual.st_ino))
    digest, offset = hashlib.sha256(), 0
    while offset < info.st_size:
        chunk = os.pread(fd, min(65536, info.st_size - offset), offset)
        _need(bool(chunk))
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(fd)
    _need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
          == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
            'mode': 0o600, 'uid': info.st_uid, 'gid': info.st_gid, 'sha256': digest.hexdigest()}


def _private_json(path, owner, *, limit=1024 * 1024):
    identity = _identity(path, owner, digest=True)
    _need(identity['size'] <= limit)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, 'rb') as stream:
            value = json.load(stream)
    except Exception:
        _need(False)
    _need(type(value) is dict)
    _need(_identity(path, owner, digest=True) == identity)
    return value, identity


def _valid_ctime_ns(value):
    return type(value) is int and 0 < value < 2 ** 63


def desired_ownership(entry):
    """Whitelist-derived uid/gid; no caller-specified destination identities."""
    _need(type(entry) is OwnershipEntry and type(entry.path) is str and type(entry.kind) is str)
    _need(all(type(getattr(entry, key)) is int and 0 <= getattr(entry, key) < 2 ** 63
              for key in ('device', 'inode', 'size', 'mode', 'observed_uid', 'observed_gid')))
    _need(entry.device > 0 and entry.inode > 0 and entry.mode <= 0o7777 and entry.size <= MAX_TREE_BYTES
          and entry.observed_uid <= 0xffffffff and entry.observed_gid <= 0xffffffff
          and _valid_ctime_ns(entry.ctime_ns))
    _need((type(entry.sha256) is str and HEX64.fullmatch(entry.sha256)) if entry.kind == 'file' else entry.sha256 == '')
    _need(type(entry.link_target) is str and (entry.kind == 'symlink' or entry.link_target == ''))
    parts = PurePosixPath(entry.path).parts
    _need(parts and not entry.path.startswith('/') and all(p not in ('', '.', '..') for p in parts)
          and str(PurePosixPath(entry.path)) == entry.path and '\\' not in entry.path
          and len(entry.path.encode()) <= 4096 and not any(ord(c) < 32 or ord(c) == 127 for c in entry.path))
    if entry.path in SEED_RULES:
        kind, uid, gid, mode = SEED_RULES[entry.path]
        _need(entry.kind == kind and entry.mode == mode)
        return uid, gid
    _need(len(parts) >= 2 and parts[0] == 'Applications' and parts[1] in APP_NAMES)
    _need(entry.kind in ('directory', 'file', 'symlink'))
    if len(parts) == 2:
        _need(entry.kind == 'directory' and entry.mode == 0o755)
        return 0, 0
    if entry.kind == 'symlink':
        _need(entry.mode & 0o7000 == 0 and 0 <= entry.mode <= 0o777 and type(entry.link_target) is str and entry.link_target
              and not entry.link_target.startswith('/') and '\\' not in entry.link_target
              and not any(ord(c) < 32 or ord(c) == 127 for c in entry.link_target))
        pending = list(parts[:-1])
        for part in entry.link_target.split('/'):
            if part in ('', '.'):
                continue
            if part == '..':
                _need(len(pending) > 2)
                pending.pop()
            else:
                pending.append(part)
    else:
        _need(entry.mode & 0o7022 == 0)
    return 501, 20


def _validate_links(entries):
    by_path = {entry.path: entry for entry in entries}
    for entry in entries:
        if entry.kind != 'symlink':
            continue
        parts = entry.path.split('/')
        resolved, pending, hops = parts[:2], parts[2:], 0
        while pending:
            part, pending = pending[0], pending[1:]
            if part in ('', '.'):
                continue
            if part == '..':
                _need(len(resolved) > 2)
                resolved.pop()
                continue
            resolved.append(part)
            target = by_path.get('/'.join(resolved))
            _need(target is not None)
            if target.kind == 'symlink':
                desired_ownership(target)
                hops += 1
                _need(hops <= 40)
                resolved.pop()
                pending = target.link_target.split('/') + pending
            elif pending:
                _need(target.kind == 'directory')
        _need('/'.join(resolved) in by_path)


def collect_entries(data_root):
    """Read/hash only fixed seed roots and four app trees, using no-follow dirfds.

    This is not mount attribution; the root helper independently re-derives that.
    Caller has already verified/locked its new guest writable Data mount.
    """
    try:
        root = _canonical(data_root)
        root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_device = os.fstat(root_fd).st_dev
        result = []
        total = 0

        def observation(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
                    info.st_uid, info.st_gid, info.st_ctime_ns, info.st_mtime_ns)

        def visit(parent_fd, name, relative):
            nonlocal total
            _need(len(result) < MAX_ENTRIES)
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _need(info.st_dev == root_device)
            mode = stat.S_IMODE(info.st_mode)
            kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'symlink' if stat.S_ISLNK(info.st_mode) else None
            _need(kind is not None and (kind == 'directory' or info.st_nlink == 1))
            digest, target = '', ''
            if kind == 'file':
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                try:
                    actual = os.fstat(fd)
                    _need(observation(actual) == observation(info))
                    digest = _file_hash(fd, info.st_size)
                    _need(observation(os.fstat(fd)) == observation(info))
                finally:
                    os.close(fd)
                total += info.st_size
                _need(total <= MAX_TREE_BYTES)
            elif kind == 'symlink':
                target = os.readlink(name, dir_fd=parent_fd)
            entry = OwnershipEntry(relative, kind, info.st_dev, info.st_ino, info.st_size, mode,
                                   info.st_uid, info.st_gid, info.st_ctime_ns, digest, target)
            desired_ownership(entry)
            result.append(entry)
            if kind == 'directory':
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                try:
                    _need(observation(os.fstat(fd)) == observation(info))
                    for child in sorted(os.listdir(fd)):
                        visit(fd, child, relative + '/' + child)
                    _need(observation(os.fstat(fd)) == observation(info))
                finally:
                    os.close(fd)
            _need(observation(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == observation(info))

        try:
            roots = [BASE, 'Library/LaunchAgents/org.goldvmmanager.first-login.plist']
            roots += ['Applications/' + name for name in APP_NAMES]
            for relative in roots:
                parts = PurePosixPath(relative).parts
                parent_fd = os.dup(root_fd)
                try:
                    for part in parts[:-1]:
                        next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                        os.close(parent_fd)
                        parent_fd = next_fd
                        _need(os.fstat(parent_fd).st_dev == root_device)
                    visit(parent_fd, parts[-1], relative)
                finally:
                    os.close(parent_fd)
        finally:
            os.close(root_fd)
        _validate_links(result)
        return tuple(sorted(result, key=lambda entry: entry.path))
    except OwnershipError:
        raise
    except Exception:
        _need(False)


def _app_tree(entries, app):
    prefix = 'Applications/' + app + '/'
    records, total = [], 0
    for entry in entries:
        if not entry.path.startswith(prefix):
            continue
        path = entry.path[len(prefix):]
        if entry.kind == 'directory':
            records.append((path, 'directory', entry.mode))
        elif entry.kind == 'symlink':
            records.append((path, 'symlink', entry.mode, entry.link_target))
        else:
            records.append((path, 'file', entry.mode, entry.size, entry.sha256))
            total += entry.size
    _need(records)
    return hashlib.sha256(_json(sorted(records))).hexdigest(), total


def prepare_ticket(*, state_dir, tart_home, job_id, name, operation_id, apply_mount,
                   verify_mount, data_uuid, group_uuid, entries, helper_sha256, config_lock_fd):
    """EXCL-write the fixed private ticket after parent creates/mounts its layout.

    Keep the worker's POSIX config.json write lock across BOTH authorization
    requests and remount. The ticket records this process as the lock holder.
    Immutable restore/app/request/config/NVRAM/helper identities are hashed.
    """
    try:
        caller = os.getuid()
        _need(caller >= 501 and caller == os.geteuid())
        _need(type(name) is str and 1 <= len(name) <= 64 and name == name.strip()
              and not name.startswith(('.', '-')) and not name.endswith('.')
              and all(c.isalnum() or c in ' _-' for c in name)
              and unicodedata.normalize('NFC', name) == name)
        _need(type(data_uuid) is str and UUID.fullmatch(data_uuid) and type(group_uuid) is str and UUID.fullmatch(group_uuid))
        state = _canonical(state_dir)
        tart = _canonical(tart_home)
        paths = operation_paths(tart, job_id, operation_id, state_dir=state)
        directory = _canonical(paths['directory'])
        _need(set(p.name for p in directory.parent.iterdir()) == {operation_id})
        _need(not any(directory.iterdir()), 'Ownership operation directory must be new and empty')
        _need(Path(apply_mount) == paths['apply_mount'] and Path(verify_mount) == paths['verify_mount'])
        _canonical(apply_mount)
        # The fresh owners-on verification session does not exist yet. Its path
        # is derived, not caller-selected; root validates it when --verify runs.
        stage = tart / '.gold-manager-staging' / job_id / 'new-environment'
        for path in (tart, tart / 'vms'):
            info = _canonical(path).stat()
            _need(stat.S_ISDIR(info.st_mode) and info.st_uid == caller and stat.S_IMODE(info.st_mode) in (0o700, 0o755))
        for path in (state, tart / '.gold-manager-staging', stage.parent, stage,
                     state / 'build-jobs', state / 'build-jobs' / job_id,
                     paths['apply_mount'].parent.parent, paths['apply_mount'].parent,
                     directory.parent, directory):
            info = _canonical(path).stat()
            _need(stat.S_ISDIR(info.st_mode) and info.st_uid == caller and stat.S_IMODE(info.st_mode) == 0o700)
        for path in (tart / 'vms' / name, stage / 'state.vzvmsave', stage / 'state.bin', stage / 'savedstate'):
            _need(not os.path.lexists(str(path)))
        current, _ = _private_json(state / 'build-current.json', caller)
        request, request_id = _private_json(state / 'build-jobs' / job_id / 'request.json', caller)
        restore, restore_id = _private_json(stage / '.clean-vm-installer.complete.json', caller)
        apps, apps_id = _private_json(stage / '.offline-preinstall.complete.json', caller)
        for value in (current, request):
            _need(value.get('id') == job_id and value.get('name') == name and value.get('mode') == 'preinstall' and value.get('source_vm') is None)
        _need(current.get('stage_path') == str(stage) and current.get('system_restored') is True
              and current.get('applications_preinstalled') is True and current.get('guest_started') is False
              and current.get('published') is False and current.get('credentials_copied') is False
              and current.get('desktop_verified') is False and current.get('host_credentials_copied') is False
              and current.get('phase') in ('configuring_vpn', 'awaiting_system_authorization'))
        vpn_state = current.get('vpn_configuration')
        _need(type(vpn_state) is dict and vpn_state.get('operation_id') == operation_id and vpn_state.get('active') is True)
        _need(all(request.get(k) is True for k in ('acknowledge_preinstall', 'acknowledge_network_policy', 'acknowledge_guest_autoconfigure')))
        _need(restore.get('installer') == 'CleanVMInstaller' and restore.get('status') == 'complete'
              and restore.get('schemaVersion') == 1 and all(type(restore.get(k)) is int and restore[k] == 0 for k in
              ('networkDeviceCount', 'directorySharingDeviceCount', 'socketDeviceCount')))
        _need(apps.get('job_id') == job_id and apps.get('name') == name and apps.get('stage_path') == str(stage)
              and apps.get('applications_preinstalled') is True and apps.get('readonly_remount_verified') is True
              and apps.get('final_detach_confirmed') is True and apps.get('guest_started') is False
              and apps.get('published') is False and apps.get('data_uuid', '').upper() == data_uuid.upper()
              and apps.get('volume_group_uuid', '').upper() == group_uuid.upper())
        _need(type(entries) is tuple and 9 <= len(entries) <= MAX_ENTRIES and all(type(e) is OwnershipEntry for e in entries))
        _need(len({e.path for e in entries}) == len(entries))
        _need(set(SEED_RULES).issubset({e.path for e in entries}))
        root_stat = Path(apply_mount).stat()
        for entry in entries:
            desired_ownership(entry)
            _need(entry.device == root_stat.st_dev and entry.inode > 0 and entry.size >= 0
                  and (entry.kind != 'file' or HEX64.fullmatch(entry.sha256)))
        _validate_links(entries)
        actual_apps = apps.get('applications')
        _need(type(actual_apps) is list and {v.get('name') for v in actual_apps if type(v) is dict} == set(APP_NAMES) and len(actual_apps) == 4)
        for app in APP_NAMES:
            _need(any(e.path == 'Applications/' + app and e.kind == 'directory' for e in entries))
            recorded = next(v for v in actual_apps if v['name'] == app)
            digest, size = _app_tree(entries, app)
            _need(recorded.get('bundle_tree_sha256') == digest and recorded.get('bundle_bytes') == size)
        _need(type(helper_sha256) is str and HEX64.fullmatch(helper_sha256))
        helper = state / 'ownership-helper' / helper_sha256 / 'GuestOwnershipHelper'
        image_id = _identity(stage / 'disk.img', caller)
        _need(type(request.get('disk_gib')) is int and image_id['size'] == request['disk_gib'] * 1024 ** 3)
        metadata = {
            'request': request_id, 'restore': restore_id, 'applications': apps_id,
            'config': _locked_config_identity(stage / 'config.json', config_lock_fd, caller),
            'nvram': _identity(stage / 'nvram.bin', caller, digest=True),
            'root_helper': _identity(helper, caller, digest=True, executable=True),
        }
        _need(metadata['root_helper']['sha256'] == helper_sha256)
        value = {'schema': TICKET_SCHEMA, 'operation_id': operation_id, 'job_id': job_id, 'name': name,
                 'state_dir': str(state), 'tart_home': str(tart), 'caller_pid': os.getpid(),
                 'image': image_id, 'metadata': metadata, 'data_uuid': data_uuid.upper(),
                 'group_uuid': group_uuid.upper(), 'apply_mount': str(apply_mount),
                 'verify_mount': str(verify_mount), 'apply_device': root_stat.st_dev,
                 'apply_root_inode': root_stat.st_ino,
                 'entries': [asdict(entry) for entry in sorted(entries, key=lambda e: e.path)]}
        content = _json(value)
        _need(len(content) <= MAX_TICKET_BYTES)
        fd = os.open(str(paths['ticket']), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            _need(False)
        return OwnershipTicket(paths['ticket'], hashlib.sha256(content).hexdigest(), operation_id, helper, caller)
    except OwnershipError:
        raise
    except Exception:
        _need(False)


PRODUCTION_CONTRACT = 'GOLD_OWNERSHIP_PRODUCTION_ROOT_ONLY_V2'
_FIXTURE_CONTRACT_PREFIX = 'GOLD_OWNERSHIP_FIXTURE_SIMULATION_ONLY_'
FIXTURE_CONTRACT = _FIXTURE_CONTRACT_PREFIX + 'V2'


def _private_directory(path, owner, *, create=False):
    path = Path(path)
    if create and not os.path.lexists(str(path)):
        _canonical(path.parent)
        path.mkdir(mode=0o700)
    path = _canonical(path)
    info = path.stat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and stat.S_IMODE(info.st_mode) == 0o700)
    return path


def _read_production_helper(fd, before):
    _need(0 < before.st_size <= 64 * 1024 * 1024)
    data = bytearray()
    while len(data) <= before.st_size:
        block = os.read(fd, min(1024 * 1024, before.st_size - len(data) + 1))
        if not block:
            break
        data.extend(block)
    after = os.fstat(fd)
    _need(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
          == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    _need(PRODUCTION_CONTRACT.encode() in data and _FIXTURE_CONTRACT_PREFIX.encode() not in data)
    return data


def deploy_helper(state_dir, binary_path):
    """Freshly verify a production portable local helper; EXCL private deployment.

    Returns its SHA256. Compilation is exclusively host_tools' responsibility.
    Existing version directories are never overwritten or silently repaired.
    Local ad-hoc signatures are not Developer ID signatures or notarization.
    """
    try:
        owner = os.getuid()
        _need(owner >= 501 and os.geteuid() == owner)
        state = _private_directory(state_dir, owner)
        source = _canonical(binary_path)
        _need(source.name == 'GuestOwnershipHelper')
        # A binary is present, so this API's contract verifies portable metadata;
        # it cannot take the source-only compile branch.
        checked = host_tools.resolve_ownership_helper(source.parent, state / 'unused-ownership-build')
        _need(Path(checked) == source)
        fd = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, owner)
                  and stat.S_IMODE(before.st_mode) & 0o7022 == 0 and before.st_mode & 0o100)
            data = _read_production_helper(fd, before)
        finally:
            os.close(fd)
        digest = hashlib.sha256(data).hexdigest()
        attributes = quarantine_policy._run([str(source)]).decode('utf-8', errors='strict').splitlines()
        quarantined = quarantine_policy.NAME in attributes
        versions = _private_directory(state / 'ownership-helper', owner, create=True)
        version = versions / digest
        target = version / 'GuestOwnershipHelper'
        if os.path.lexists(str(version)):
            _private_directory(version, owner)
            _need(set(p.name for p in version.iterdir()) == {'GuestOwnershipHelper'})
            _need(_identity(target, owner, digest=True, executable=True)['sha256'] == digest)
            host_tools.verify_local_signature(target, {})
            if quarantined:
                _need(quarantine_policy.read(target) == quarantine_policy.read(source))
            return digest
        version.mkdir(mode=0o700)  # EXCL: failed/partial versions remain for review.
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                _need(count > 0)
                view = view[count:]
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        finally:
            os.close(fd)
        # Apple's Python 3.9 has no os.*xattr API. Use the project's fixed native
        # xattr wrapper; only propagate an existing value onto this new copy.
        if quarantined:
            quarantine_policy.propagate(source, target)
        _need(_identity(target, owner, digest=True, executable=True)['sha256'] == digest)
        host_tools.verify_local_signature(target, {})
        directory_fd = os.open(str(version), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return digest
    except OwnershipError:
        raise
    except Exception:
        _need(False)


def _ticket_document(ticket):
    value, identity = _private_json(ticket.path, ticket.caller_uid, limit=MAX_TICKET_BYTES)
    _need(identity['sha256'] == ticket.digest and type(value.get('schema')) is int and value['schema'] == TICKET_SCHEMA)
    entries = value.get('entries')
    _need(type(entries) is list and 9 <= len(entries) <= MAX_ENTRIES
          and all(type(entry) is dict and _valid_ctime_ns(entry.get('ctime_ns')) for entry in entries))
    return value


def verify_receipt(ticket, operation):
    """Validate root helper's exact private receipt; fixture receipts never pass."""
    try:
        _need(type(ticket) is OwnershipTicket and operation in ('apply', 'verify'))
        value = _ticket_document(ticket)
        path = ticket.path.parent / (operation + '.receipt.json')
        receipt, _ = _private_json(path, ticket.caller_uid)
        expected_keys = {'schema', 'operation_id', 'ticket_sha256', 'operation', 'attachment_generation',
                         'entry_count', 'fixture_only', 'metadata_applied', 'persistent_ownership_verified',
                         'readonly_owners_on', 'guest_started', 'published', 'authorization', 'helper_contract'}
        _need(set(receipt) == expected_keys and type(receipt['schema']) is int and receipt['schema'] == 1
              and receipt['operation_id'] == ticket.operation_id and receipt['ticket_sha256'] == ticket.digest
              and receipt['operation'] == operation and receipt['helper_contract'] == PRODUCTION_CONTRACT
              and receipt['authorization'] == 'macos_system_administrator')
        _need(type(receipt['attachment_generation']) is int and receipt['attachment_generation'] > 0
              and type(receipt['entry_count']) is int and receipt['entry_count'] == len(value['entries']))
        _need(receipt['fixture_only'] is False and receipt['guest_started'] is False and receipt['published'] is False
              and receipt['metadata_applied'] is (operation == 'apply')
              and receipt['persistent_ownership_verified'] is (operation == 'verify')
              and receipt['readonly_owners_on'] is (operation == 'verify'))
        if operation == 'verify':
            prior, _ = _private_json(ticket.path.parent / 'apply.receipt.json', ticket.caller_uid)
            verify_receipt(ticket, 'apply')
            _need(prior['attachment_generation'] != receipt['attachment_generation'])
        return AuthorizationResult('persistent_ownership_verified' if operation == 'verify'
                                   else 'ownership_applied_awaiting_readonly', operation, True, operation == 'verify')
    except OwnershipError:
        raise
    except Exception:
        _need(False)


def _apple_string(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def request_authorization(ticket, operation, *, acknowledge_authorization=False, run=None):
    """Request real macOS system authorization; never call from an implicit API.

    Call separately for apply and verify. macOS may reuse its own authorization,
    or display a second genuine prompt. Never promise zero/two fixed dialogs.
    No password is requested by this module. stdout is discarded; stderr is read
    only for osascript's trailing numeric status and then dropped, so the result
    distinguishes "never prompted" (preflight/launch), "prompt refused or not
    allowed", "helper ran and refused" and "timed out" without native text.
    """
    _need(type(ticket) is OwnershipTicket and operation in ('apply', 'verify'))
    if acknowledge_authorization is not True:
        return AuthorizationResult('awaiting_system_authorization', operation, False)
    try:
        value = _ticket_document(ticket)
        _need(os.getuid() == ticket.caller_uid)
        expected_paths = operation_paths(value['tart_home'], value['job_id'], value['operation_id'], state_dir=value['state_dir'])
        helper_hash = value['metadata']['root_helper']['sha256']
        _need(type(helper_hash) is str and HEX64.fullmatch(helper_hash)
              and ticket.path == expected_paths['ticket'] and ticket.operation_id == value['operation_id']
              and ticket.helper_path == Path(value['state_dir']) / 'ownership-helper' / helper_hash / 'GuestOwnershipHelper')
        _need(_identity(ticket.helper_path, ticket.caller_uid, digest=True, executable=True) == value['metadata']['root_helper'])
        host_tools.verify_local_signature(ticket.helper_path, {})
        command = ' '.join(shlex.quote(str(value)) for value in (ticket.helper_path, ticket.path, '--' + operation))
        script = 'do shell script ' + _apple_string(command) + ' with administrator privileges\n'
    except Exception:
        # Local checks failed before any prompt could be shown.
        return _authorization_failure(operation, 'preflight-rejected')
    runner = subprocess.run if run is None else run
    try:
        result = runner(['/usr/bin/osascript', '-'], input=script.encode(),
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=1800,
                        env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8'}, cwd='/')
    except subprocess.TimeoutExpired:
        return _authorization_failure(operation, 'timeout')
    except OSError:
        return _authorization_failure(operation, 'launch-failed')
    except Exception:
        return _authorization_failure(operation, 'unknown-failure')
    try:
        returncode = result.returncode
        if returncode:
            reason, status = _classify_osascript_failure(getattr(result, 'stderr', None))
            return _authorization_failure(operation, reason, status)
    except Exception:
        return _authorization_failure(operation, 'unknown-failure')
    finally:
        result = None  # Drop any captured native text promptly.
    try:
        # Exit 0 alone is never acceptance: validate the private root receipt.
        return verify_receipt(ticket, operation)
    except OwnershipError:
        raise
    except Exception:
        return _authorization_failure(operation, 'unknown-failure')
