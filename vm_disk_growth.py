"""Offline virtual capacity growth for a published, locally managed raw macOS VM.

Run the writer in its own process. Tart uses process-associated POSIX locks:
closing *any* descriptor for config.json in the holder would release its lock.
The controller serializes its operations; this worker independently fences the
manager journals, publication, Tart and DiskImages. As with Tart itself, the
owner must not bypass advisory locks to concurrently edit the private VM files.
This never opens a guest filesystem, edits a partition or launches a guest.
"""
from contextlib import ExitStack
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import sys

import lifecycle
import managed_registry as registry

GIB = 1024 ** 3
_MAX_JSON = 1024 ** 2
_UUID = re.compile(r'[0-9a-f]{32}')
_BUSY = 'VM、存储或管理任务正忙，或存在未完成事务；未扩容。'
_UNSAFE = '无法安全核对本地私有原始磁盘及其发布身份；未扩容。'
_OFFLINE = '无法确认磁盘已关机、无暂停状态、未挂载且未被其他程序打开；未扩容。'
_SPACE = '宿主可用空间不足：需要扩容量加 2 GiB 余量；未扩容。'
_STALE = '原始磁盘容量已变化或目标不是扩容；请重新核对。'
_TARGET = '目标容量必须是 30–1024 GiB 的整数；不会缩小磁盘。'
_PARTIAL = '磁盘可能已经扩容，未能完整确认；不回滚、不自动重试。请先重新核对磁盘容量。'
PUBLIC_REJECTIONS = frozenset((_BUSY, _UNSAFE, _OFFLINE, _SPACE, _STALE, _TARGET))
_CONFIG_KEYS = {'version', 'os', 'arch', 'diskFormat', 'cpuCountMin', 'cpuCount',
                'memorySizeMin', 'memorySize', 'ecid', 'hardwareModel', 'macAddress', 'display'}
_SAVED = ('state.vzvmsave', 'state.bin', 'savedstate', 'saved-state.bin', 'suspend.bin')


class GrowthRejected(ValueError):
    """Fixed public refusal; no client values, filesystem paths or tool output."""


class GrowthUncertain(GrowthRejected):
    """The mutation may already have committed. Never try to shrink it back."""


def _need(condition, message=_UNSAFE):
    if not condition:
        raise GrowthRejected(message)


def _identity(s):
    return s.st_dev, s.st_ino


def _stamp(s):
    return (_identity(s), s.st_uid, s.st_mode, s.st_nlink, s.st_size, s.st_ctime_ns, s.st_mtime_ns)


def _dir_info(s, private):
    _need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid()
          and not s.st_mode & (0o7077 if private else 0o7022))


def _file_info(s):
    _need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1
          and not s.st_mode & 0o7077)


def _fd(stack, name, flags, *, parent=None):
    fd = os.open(name, flags | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
    stack.callback(os.close, fd)
    return fd


def _directory(stack, path, *, private=False, parent=None):
    registry.safe_path(path)
    fd = _fd(stack, path if parent is None else path.name, os.O_RDONLY | os.O_DIRECTORY, parent=parent)
    _dir_info(os.fstat(fd), private)
    _same_path(fd, path)
    if parent is not None:
        _need(os.fstat(parent).st_dev == os.fstat(fd).st_dev and not os.path.ismount(path))
    return fd


def _same_path(fd, path):
    # No reopening of pinned inodes. Check canonical components, not just the leaf.
    registry.safe_path(path)
    _need(_identity(os.fstat(fd)) == _identity(os.lstat(path)))


def _regular(stack, parent, name, flags):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _file_info(before)
    _need(before.st_dev == os.fstat(parent).st_dev)
    fd = _fd(stack, name, flags, parent=parent)
    opened = os.fstat(fd)
    _file_info(opened)
    _need(_stamp(before) == _stamp(opened))
    return fd


def _storage_path(vm, vm_root):
    registry.validate_name(vm)
    root = registry.safe_path(Path(vm_root))
    _need(root.name == 'vms')
    return root / vm


def _vm_directory(stack, path, home_fd):
    root_fd = _directory(stack, path.parent, parent=home_fd)
    _need(path.name in os.listdir(root_fd))  # No case-insensitive aliases.
    return root_fd, _directory(stack, path, parent=root_fd, private=True)


def inspect(vm, *, vm_root):
    """Exact apparent byte size, not allocated bytes or guest free space.

    The caller selects vm from its managed registry. Inspection opens no image
    or config descriptor, so it cannot interfere with an offline writer's locks.
    This display-only observation is not authority to mutate anything.
    """
    try:
        path = _storage_path(vm, vm_root)
        with ExitStack() as stack:
            home_fd = _directory(stack, path.parent.parent)
            _, folder = _vm_directory(stack, path, home_fd)
            s = os.stat('disk.img', dir_fd=folder, follow_symlinks=False)
            _file_info(s)
            _need(s.st_dev == os.fstat(folder).st_dev and s.st_size > 0)
            _same_path(folder, path)
            _need(_stamp(s) == _stamp(os.lstat(path / 'disk.img')))
            return s.st_size
    except GrowthRejected:
        raise
    except Exception:
        raise GrowthRejected(_UNSAFE) from None


def _lock(fd, *, posix=False):
    try:
        (fcntl.lockf if posix else fcntl.flock)(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise GrowthRejected(_BUSY) from None


def _parse_json(raw):
    def object_pairs(pairs):
        value = dict(pairs)
        _need(len(value) == len(pairs))
        return value
    return json.loads(raw, object_pairs_hook=object_pairs)


def _read_state(path, pins, *, optional=False):
    registry.safe_path(path, False)
    try:
        s = path.lstat()
    except FileNotFoundError:
        if optional:
            pins[path] = None
            return None
        raise
    _file_info(s)
    _need(0 < s.st_size <= _MAX_JSON)
    with ExitStack() as stack:
        fd = _fd(stack, path, os.O_RDONLY)
        _need(_stamp(s) == _stamp(os.fstat(fd)))
        raw = os.pread(fd, _MAX_JSON + 1, 0)
        _need(0 < len(raw) == s.st_size and _stamp(s) == _stamp(path.lstat()))
    value = _parse_json(raw)
    _need(type(value) is dict)
    pins[path] = _stamp(s)
    return value


def _unchanged(pins):
    # Under the config lock, recheck the registry, publication and journal pins
    # by metadata only. Do not trigger a callback or reopen a protected inode.
    for path, stamp in pins.items():
        try:
            observed = _stamp(path.lstat())
        except FileNotFoundError:
            observed = None
        _need(observed == stamp, _BUSY)


def _idle(status):
    if status is None:
        return
    _need(_UUID.fullmatch(str(status.get('id', ''))) and not status.get('recovery_required')
          and status.get('phase') in ('awaiting_user_setup', 'awaiting_first_desktop_acceptance',
                                      'deleted', 'failed', 'interrupted')
          and not lifecycle.is_active(status) and not lifecycle.waiting_for_vpn(status)
          and not status.get('stage_path'), _BUSY)
    if status['phase'] == 'awaiting_first_desktop_acceptance':
        _need(status.get('published') is True, _BUSY)
    for key in ('offline_preinstall', 'vpn_configuration'):
        operation = status.get(key)
        _need(operation is None or (type(operation) is dict and not operation.get('active')), _BUSY)


def _binding(state, vm, path, environment_id):
    pins = {}
    def read(path, *, optional=False):
        return _read_state(path, pins, optional=optional)
    reg = registry.validate_registry(read(state / 'registry.json'))
    _need(vm in reg['vms'] and vm not in reg['retired'] and vm not in registry.LEGACY_NAMES)
    jid = reg['vms'][vm]['environment_id']
    _need(environment_id is None or jid == environment_id)
    _idle(read(state / 'build-current.json', optional=True))
    jobs = registry.safe_path(state / 'build-jobs')
    _dir_info(jobs.lstat(), True)
    pins[jobs] = _stamp(jobs.lstat())
    # A newer current job does not retire an older incomplete commit journal.
    # No request.json, VPN files, worker logs or guest material are consumed.
    selected = None
    for job in jobs.iterdir():
        _need(_UUID.fullmatch(job.name) and not job.is_symlink(), _BUSY)
        _dir_info(job.lstat(), True)
        record = read(job / 'commit.json', optional=True)
        if record is not None:
            if record.get('mode') == 'preinstall':
                _need(type(record.get('version')) is int and record['version'] == 1
                      and record.get('phase') == 'committed_new_registered'
                      and record.get('id') == record.get('environment_id') == job.name
                      and record.get('source_vm', False) is None, _BUSY)
                if job.name == jid:
                    selected = record
            else:
                _need(record.get('phase') == 'committed_old_removed', _BUSY)
        status = read(job / 'status.json', optional=True)
        if job.name == jid:
            _need(status and status.get('mode') == 'preinstall' and status.get('name') == vm
                  and status.get('source_vm', False) is None and status.get('published') is True
                  and status.get('phase') == 'awaiting_first_desktop_acceptance', _BUSY)
        if status is not None and (job.name == jid or vm in (status.get('name'), status.get('source_vm'))):
            # Archiving without publishing never creates a usable published VM.
            archived = read(job / 'archived-current.json', optional=True)
            if archived is None:
                _need(status.get('id') == job.name, _BUSY)
                _idle(status)
            else:
                _need(record is None and archived.get('id') == job.name
                      and archived.get('name') == status.get('name')
                      and not archived.get('published') and archived.get('archived_at'), _BUSY)
    _need(selected is not None and selected.get('name') == vm and selected.get('target') == str(path))
    base = registry.safe_path(state / 'environments' / jid)
    _dir_info(base.parent.lstat(), True)
    _dir_info(base.lstat(), True)
    meta = read(base / 'environment.json')
    _need(type(meta.get('version')) is int and meta['version'] in (2, 3) and meta.get('vm_name') == vm
          and meta.get('vm_config') == str(path / 'config.json') and meta.get('tart_home') == str(path.parent.parent))
    return meta, pins


def _config(fd, meta):
    s = os.fstat(fd)
    _need(0 < s.st_size <= _MAX_JSON)
    raw = os.pread(fd, _MAX_JSON + 1, 0)
    _need(len(raw) == s.st_size and list(_identity(s)) == meta.get('vm_config_identity')
          and hashlib.sha256(raw).hexdigest() == meta.get('vm_config_sha256'))
    cfg = _parse_json(raw)
    _need(type(cfg) is dict and set(cfg) == _CONFIG_KEYS and type(cfg['version']) is int
          and cfg['version'] == 1 and (cfg['os'], cfg['arch'], cfg['diskFormat']) == ('darwin', 'arm64', 'raw')
          and type(cfg['ecid']) is str and cfg['ecid'] and cfg['ecid'] == meta.get('ecid')
          and type(cfg['macAddress']) is str and re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', cfg['macAddress'])
          and cfg['macAddress'].lower() == meta.get('guest_mac'))


def _detached(image, fd):
    result = subprocess.run(['/usr/bin/hdiutil', 'info', '-plist'], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15,
                            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C'})
    _need(result.returncode == 0 and 0 < len(result.stdout) <= 4 * _MAX_JSON, _OFFLINE)
    class StrictDict(dict):
        def __setitem__(self, key, value):
            _need(key not in self, _OFFLINE)
            super().__setitem__(key, value)
    data = plistlib.loads(result.stdout, fmt=plistlib.FMT_XML, dict_type=StrictDict)
    rows = data.get('images') if isinstance(data, dict) else None
    _need(type(rows) is list, _OFFLINE)
    for row in rows:
        _need(isinstance(row, dict) and 'image-path' in row, _OFFLINE)
        for key in ('image-path', 'shadow-path'):
            if key not in row:
                continue
            p = row[key]
            _need(type(p) is str and p.startswith('/') and p != str(image), _OFFLINE)
            # Covers alternate symlink/case/firmlink spellings of this same inode.
            _need(_identity(os.stat(p)) != _identity(os.fstat(fd)), _OFFLINE)


def _only_open(fd):
    """Darwin's vnode-use check, unlike lsof, isn't limited by process visibility.

    [XNU fsctl.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fsctl.h):
    FSIOC_FD_ONLY_OPEN_ONCE = _IOWR('A',21,uint32_t).
    It is a *check*, not a lock. Hold the actual Tart and image locks across it
    AND the mutation. Unsupported system/filesystem is never a pass.
    """
    _need(sys.platform == 'darwin', _OFFLINE)
    lib = ctypes.CDLL(None, use_errno=True)
    ctl = lib.ffsctl
    ctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_uint)
    ctl.restype = ctypes.c_int
    arg = ctypes.c_uint32()
    _need(ctl(fd, 0xc0044115, ctypes.byref(arg), 0) == 0, _OFFLINE)


def _require_local(dir_fd):
    # Darwin getattrlist(2): reject remote filesystem lock/size semantics.
    _need(sys.platform == 'darwin', _OFFLINE)
    f = ctypes.CDLL(None, use_errno=True).fgetattrlist
    f.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong)
    f.restype = ctypes.c_int
    attrs = struct.pack('=HHIIIII', 5, 0, 0, 0x80040000, 0, 0, 0)  # ATTR_VOL_INFO | ATTR_VOL_MOUNTFLAGS
    out = ctypes.create_string_buffer(8)
    _need(f(dir_fd, attrs, out, len(out), 0) == 0)
    length, flags = struct.unpack('=II', out.raw)
    _need(length == 8 and flags & 0x1000)  # MNT_LOCAL


def _free(fd):
    fs = os.fstatvfs(fd)
    _need(fs.f_bavail >= 0 and fs.f_frsize > 0, _SPACE)
    return fs.f_bavail * fs.f_frsize


def grow(vm, target_gib, expected_bytes, *, vm_root, state_dir, inventory, known_names,
         expected_environment_id=None):
    """Dedicated worker entry. Arguments after * come from the controller, never HTTP paths.

    inventory() is a fresh Tart inventory and known_names() (or a set) is the
    controller allowlist. The registry and existing durable publication binding
    remain mandatory. The production worker requires the confirmed environment ID.
    Success only after fsync/readback; an ambiguous commit is NOT retried.
    """
    attempted = False
    try:
        registry.validate_name(vm)
        _need(type(target_gib) is int and lifecycle.DISK_GIB_MIN <= target_gib <= lifecycle.DISK_GIB_MAX, _TARGET)
        target = target_gib * GIB
        _need(type(expected_bytes) is int and 0 < expected_bytes < target, _STALE)
        _need(expected_environment_id is None or type(expected_environment_id) is str and _UUID.fullmatch(expected_environment_id))
        state = Path(state_dir)
        with ExitStack() as stack:
            state_fd = _directory(stack, state, private=True)
            # All published managed VMs already have both locks. Never create a
            # missing/replaced lock or let the UI block behind an active worker.
            build = _regular(stack, state_fd, 'build.lock', os.O_RDWR)
            _lock(build)
            conf_lock = _regular(stack, state_fd, 'configuration.lock', os.O_RDWR)
            _lock(conf_lock)
            _need(vm in (known_names() if callable(known_names) else known_names))
            path = _storage_path(vm, vm_root)
            meta, pins = _binding(state, vm, path, expected_environment_id)
            item = inventory().get(vm)  # Never ask Tart to reacquire its own storage flock.
            _need(isinstance(item, dict) and (item.get('Name'), item.get('Source'), item.get('State'))
                  == (vm, 'local', 'stopped'), _OFFLINE)
            home = _directory(stack, path.parent.parent)
            _lock(home)
            root, folder = _vm_directory(stack, path, home)
            _require_local(folder)
            cfg = _regular(stack, folder, 'config.json', os.O_RDWR)
            _lock(cfg, posix=True)
            cfg_stamp = _stamp(os.fstat(cfg))
            _config(cfg, meta)  # pread the locked FD, never reopen via pathname.
            # Tart can leave a stale control socket after a clean shutdown. Only
            # accept ECONNREFUSED on its pinned owned socket (dedicated process).
            socket_identity = lifecycle.stale_control_socket(path)
            _need(not any(os.path.lexists(path / name) for name in _SAVED), _OFFLINE)
            disk = _regular(stack, folder, 'disk.img', os.O_RDWR)
            _lock(disk, posix=True)  # DiskImages documents shared/exclusive image locks (hdiutil(1)).
            disk_info = os.fstat(disk)
            disk_stamp = _stamp(disk_info)
            _need(disk_info.st_size == expected_bytes, _STALE)
            # These specific v2/v3 publications were created at >=30 GiB. A
            # shorter file is evidence of truncation, not an older supported size.
            _need(30 * GIB <= disk_info.st_size <= lifecycle.DISK_GIB_MAX * GIB
                  and disk_info.st_size % 512 == 0)
            _detached(path / 'disk.img', disk)
            _need(_free(disk) >= target - expected_bytes + 2 * GIB, _SPACE)

            def check_bindings():
                _unchanged(pins)
                for fd, p in ((state_fd, state), (build, state / 'build.lock'),
                              (conf_lock, state / 'configuration.lock'), (home, path.parent.parent),
                              (root, path.parent), (folder, path), (cfg, path / 'config.json'),
                              (disk, path / 'disk.img')):
                    _same_path(fd, p)
                for directory, private in ((home, False), (root, False), (folder, True), (state_fd, True)):
                    _dir_info(os.fstat(directory), private)
                for fd in (build, conf_lock, cfg, disk):
                    _file_info(os.fstat(fd))
                _need(cfg_stamp == _stamp(os.fstat(cfg)))
                _need(not any(os.path.lexists(path / name) for name in _SAVED), _OFFLINE)
                _need(socket_identity == lifecycle.stale_control_socket(path), _OFFLINE)

            check_bindings()
            _need(disk_stamp == _stamp(os.fstat(disk)), _STALE)
            _only_open(disk)
            # The sole mutation: no truncate rollback, irrespective of outcome.
            attempted = True
            os.ftruncate(disk, target)
            os.fsync(disk)
            check_bindings()
            _need(os.fstat(disk).st_size == target)
        return {'ok': True, 'virtual_capacity_bytes': target}
    except Exception as exc:
        if attempted:
            raise GrowthUncertain(_PARTIAL) from None
        if type(exc) is GrowthRejected:
            raise
        raise GrowthRejected(_UNSAFE) from None


def main(argv):
    try:
        _need(len(argv) == 5 and argv[0] == '--grow')
        _, vm, gib, expected, environment = argv
        registry.validate_name(vm)
        _need(re.fullmatch(r'[1-9][0-9]{0,3}', gib) and re.fullmatch(r'[1-9][0-9]{0,12}', expected)
              and _UUID.fullmatch(environment))
        result = grow(vm, int(gib), int(expected), vm_root=lifecycle.VM_ROOT, state_dir=registry.STATE_DIR,
                      inventory=lifecycle.inventory, known_names=registry.allowed_vm_ids,
                      expected_environment_id=environment)
    except GrowthUncertain:
        result = {'ok': False, 'uncertain': True, 'error': _PARTIAL}
    except GrowthRejected as exc:
        result = {'ok': False, 'uncertain': False, 'error': str(exc)}
    except Exception:
        result = {'ok': False, 'uncertain': False, 'error': _UNSAFE}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main(sys.argv[1:])
