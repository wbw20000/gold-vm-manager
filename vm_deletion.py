"""Explicit, durable VM deletion in a dedicated process; importing does no work.

Call start only following an exact-name confirmation and erase acknowledgement.
This module never stops a VM, follows host shares, reads credentials, or retries
an incomplete transaction. See VM_DELETION.md for caller and recovery contracts.
"""
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

import lifecycle
import managed_registry as registry

STATE = lifecycle.STATE
TART_HOME = lifecycle.TART_HOME
VM_ROOT = lifecycle.VM_ROOT
HERE = Path(__file__).resolve().parent
RETAINED_PRIVATE_ARTIFACTS = ['private_logs', 'environment_setup', 'restore_images', 'staging_caches']
RETAINED_MESSAGE = '仅删除所选 VM 目录及其注册/共享配置项；保留宿主共享目录、私有日志、setup 材料、IPSW 和暂存缓存。'
MAX_CONFIG_BYTES = 1024 * 1024


class DeletionRejected(ValueError):
    """Only this module's fixed, credential-free messages may reach the caller."""


def _reject(message):
    raise DeletionRejected(message)


def validated_request(vm, confirm_name, acknowledge_erase, known_names):
    try:
        registry.validate_name(vm)
    except (TypeError, ValueError):
        _reject('VM 名称无效；必须使用列表中的规范 NFC 名称')
    if vm not in known_names:
        _reject('只能删除列表中明确选中的 VM')
    if type(confirm_name) is not str or confirm_name != vm or acknowledge_erase is not True:
        _reject('请完整输入 VM 名称并确认永久删除磁盘和暂停状态')
    return {'mode': 'delete', 'source_vm': vm, 'name': vm,
            'confirm_name': confirm_name, 'acknowledge_erase': True}


def _metadata(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'owner': info.st_uid,
            'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink}


def _root(path):
    registry.safe_path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or os.path.ismount(str(path))):
        _reject('VM 目录归属、类型或挂载状态异常；未删除')
    return info


def _config_info(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or not 0 < info.st_size <= MAX_CONFIG_BYTES):
        _reject('VM 配置类型、归属或大小异常；未删除')
    return info


def _config_digest(fd):
    # Read only the already-open config inode. Never reopen/close another FD for
    # this inode while holding its process-associated POSIX lock.
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    size = 0
    while True:
        chunk = os.read(fd, min(65536, MAX_CONFIG_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_CONFIG_BYTES:
            _reject('VM 配置大小发生变化；未删除')
    return hashlib.sha256(b''.join(chunks)).hexdigest()


def source_identity(vm):
    """OS-neutral snapshot; config bytes are hashed, not parsed for credentials.

    Called before the worker's POSIX lock. Unlike lifecycle.source_identity, this
    deliberately accepts both Linux and macOS Tart VM configuration formats.
    """
    registry.validate_name(vm)
    path = VM_ROOT / vm
    root_info = _root(path)
    config = registry.safe_path(path / 'config.json')
    fd = os.open(str(config), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        config_info = _config_info(fd)
        digest = _config_digest(fd)
        if _metadata(config_info) != _metadata(os.fstat(fd)):
            _reject('VM 配置在检查期间发生变化；未删除')
        if (config.lstat().st_dev, config.lstat().st_ino) != (config_info.st_dev, config_info.st_ino):
            _reject('VM 配置路径发生变化；未删除')
    finally:
        os.close(fd)
    if _metadata(_root(path)) != _metadata(root_info):
        _reject('VM 目录在检查期间发生变化；未删除')
    return {'root': _metadata(root_info), 'config': _metadata(config_info), 'config_sha256': digest}


def _stopped(vm, values):
    if values.get(vm, {}).get('State') not in ('stopped', 'suspended'):
        _reject('请先正常关机或暂停 VM 再删除；不会自动停止运行中的 VM')


def _check_tree(path, socket_identity):
    root_info = _root(path)
    def unreadable(_error):
        _reject('无法完整检查 VM 目录；未删除')
    # Check each directory entry BEFORE os.walk can descend into it. In
    # particular, even same-device mounts must not be traversed first by a
    # subsequent generic tree checker.
    for folder, dirs, files in os.walk(str(path), topdown=True, followlinks=False, onerror=unreadable):
        for name in dirs + files:
            child = Path(folder) / name
            info = child.lstat()
            allowed_socket = (child == path / 'control.sock' and stat.S_ISSOCK(info.st_mode)
                              and socket_identity == (info.st_dev, info.st_ino) and info.st_nlink == 1)
            if (info.st_dev != root_info.st_dev or info.st_uid != os.getuid()
                    or stat.S_ISLNK(info.st_mode)
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or allowed_socket)
                    or os.path.ismount(str(child))
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                _reject('VM 目录含链接、挂载、多重硬链接或异常文件；未删除')
    # The lifecycle helper permits ONLY the pinned, proven-stale top-level
    # socket and verifies that the previously observed socket is still present.
    lifecycle.check_tree(path, control_socket_identity=socket_identity)


def _journal_complete(journal, jid, vm):
    return (type(journal) is dict and type(journal.get('version')) is int
            and journal['version'] == 1 and journal.get('id') == jid
            and journal.get('mode') == 'delete' and journal.get('source_vm') == vm
            and journal.get('phase') == 'committed_old_removed')


def _status_with_journal(current):
    if not current or current.get('mode') != 'delete':
        return current
    current = dict(current)
    journal = registry.read_private(STATE / 'build-jobs' / current['id'] / 'commit.json', None)
    complete = _journal_complete(journal, current['id'], current.get('source_vm'))
    if journal is not None and not complete:
        current['recovery_required'] = True
        current['message'] = '删除事务未完整结束，已锁定相关 VM 和后续任务；请人工核对事务记录，不会自动重试。'
    elif complete:
        # A crash after the durable completion record but before final status is
        # not an incomplete deletion. No filesystem mutation is performed here.
        current.update(phase='deleted', result='deleted', old_deleted=True,
                       recovery_required=False, progress=1,
                       message='所选 VM 已删除。' + RETAINED_MESSAGE)
    current['retained_private_artifacts'] = list(RETAINED_PRIVATE_ARTIFACTS)
    return current


def status():
    """Return the shared lifecycle job, with deletion journal reconciliation.

    Callers must fail closed on ValueError/OSError and block operations whenever
    recovery_required is true. Reading status never starts/retries deletion.
    """
    try:
        return _status_with_journal(lifecycle.status())
    except DeletionRejected:
        raise
    except Exception:
        raise DeletionRejected('任务状态或事务记录不可读；相关操作必须保持锁定，请人工检查私有记录') from None


def _lock_metadata(fd, path):
    info = os.fstat(fd)
    registry.safe_path(path)
    expected = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino)):
        _reject('删除任务锁无效')


def start(vm, confirm_name, acknowledge_erase, known_names):
    """Validate, publish a queued job, spawn, return immediately (never wait).

    Return: {ok, job_id, pid, mode, message}. Raises sanitized ValueError on
    rejection. known_names must be the controller's current allowed VM names,
    never a client-provided list. No shell is used for names or worker commands.
    """
    try:
        request = validated_request(vm, confirm_name, acknowledge_erase, known_names)
        _stopped(vm, lifecycle.inventory())
        expected = source_identity(vm)
        registry.private_dir(STATE)
        lockpath = registry.safe_path(STATE / 'build.lock', False)
        fd = os.open(str(lockpath), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            _lock_metadata(fd, lockpath)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _reject('已有新建、重建或删除任务进行中，请等待完成')
            previous = status()
            if previous and previous.get('recovery_required'):
                _reject('上次事务需要人工恢复，未开始删除任务')
            if previous and previous.get('phase') in lifecycle.ACTIVE:
                _reject('已有任务正在运行，未开始删除任务')
            jid = uuid.uuid4().hex
            jobdir = STATE / 'build-jobs' / jid
            registry.private_dir(jobdir)
            request.update(id=jid, source_identity=expected)
            registry.write_private(jobdir / 'request.json', request)
            current = {'id': jid, 'mode': 'delete', 'source_vm': vm, 'name': vm,
                       'phase': 'queued', 'result': None, 'message': '已接收删除请求；正在检查，尚未删除 VM。',
                       'pid': None, 'progress': None, 'old_deleted': False,
                       'recovery_required': False, 'started_at': lifecycle.timestamp(),
                       'updated_at': lifecycle.timestamp(),
                       'retained_private_artifacts': list(RETAINED_PRIVATE_ARTIFACTS)}
            registry.write_private(jobdir / 'status.json', current)
            registry.write_private(STATE / 'build-current.json', current)
            try:
                logpath = registry.safe_path(jobdir / 'worker.log', False)
                log_fd = os.open(str(logpath), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(log_fd, 'w') as log:
                    process = subprocess.Popen(
                        [sys.executable, '-B', str(HERE / 'vm_deletion.py'), '--worker', jid, '--lock-fd', str(fd)],
                        env=lifecycle.ENV, stdin=subprocess.DEVNULL, stdout=log,
                        stderr=subprocess.STDOUT, start_new_session=True,
                        close_fds=True, pass_fds=(fd,))
            except Exception:
                current.update(phase='failed', message='删除工作进程未启动；未删除任何 VM。',
                               updated_at=lifecycle.timestamp())
                registry.write_private(jobdir / 'status.json', current)
                registry.write_private(STATE / 'build-current.json', current)
                _reject('删除工作进程未启动；未删除任何 VM')
            # Do not write current after spawn: it could overwrite worker progress.
            # The child owns the inherited flock until it exits, even if UI closes.
            return {'ok': True, 'job_id': jid, 'pid': process.pid, 'mode': 'delete',
                    'message': '删除任务已提交；可关闭窗口，重新打开后查看进度。'}
        finally:
            os.close(fd)  # Never LOCK_UN: the child shares this open description.
    except DeletionRejected:
        raise
    except Exception:
        raise DeletionRejected('删除前置检查失败；未删除任何 VM，请检查私有任务记录') from None


def _load_target_configuration(vm):
    reg = registry.load_registry()
    shares_path = STATE / 'config.json'
    shares = registry.read_private(shares_path, {'version': 1, 'vms': {}})
    if (type(shares) is not dict or set(shares) != {'version', 'vms'}
            or type(shares['version']) is not int or shares['version'] != 1
            or type(shares['vms']) is not dict):
        _reject('共享配置无效，未删除 VM')
    # Never interpret, resolve, stat, walk, or delete ANY host-share path.
    reg['vms'].pop(vm, None)
    if vm not in reg['retired']:
        reg['retired'].append(vm)
    shares['vms'].pop(vm, None)
    registry.validate_registry(reg)
    return reg, shares_path, shares


def _commit(request, update):
    """Worker-only commit. All VM/config descriptors remain in this process."""
    vm = request['source_vm']
    expected = request['source_identity']
    old = VM_ROOT / vm
    journal_path = STATE / 'build-jobs' / request['id'] / 'commit.json'
    with registry.state_lock(STATE):
        # Inventory before storage flock: do not ask Tart to reacquire that lock.
        _stopped(vm, lifecycle.inventory())
        registry.safe_path(TART_HOME)
        registry.safe_path(VM_ROOT)
        storage_fd = os.open(str(TART_HOME), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        config_fd = None
        try:
            try:
                fcntl.flock(storage_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _reject('Tart 存储正忙；未删除 VM')
            if _metadata(_root(old)) != expected['root']:
                _reject('VM 目录身份已变化；未删除')
            config = registry.safe_path(old / 'config.json')
            config_fd = os.open(str(config), os.O_RDWR | os.O_NOFOLLOW)
            try:
                fcntl.lockf(config_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _reject('VM 正在运行或配置正忙；未删除')
            config_info = _config_info(config_fd)
            if (_metadata(config_info) != expected['config']
                    or _config_digest(config_fd) != expected['config_sha256']):
                _reject('VM 配置身份已变化；未删除')
            path_info = config.lstat()
            if (path_info.st_dev, path_info.st_ino) != (config_info.st_dev, config_info.st_ino):
                _reject('VM 配置路径已变化；未删除')
            socket_identity = lifecycle.stale_control_socket(old)
            _check_tree(old, socket_identity)
            reg, shares_path, shares = _load_target_configuration(vm)
            tomb_parent = TART_HOME / '.gold-manager-deletions' / request['id']
            registry.private_dir(tomb_parent)
            tombstone = tomb_parent / 'old-environment'
            registry.safe_path(tombstone, False)
            if tombstone.exists():
                _reject('删除暂存目录已存在；未删除 VM')
            if tomb_parent.stat().st_dev != expected['root']['device']:
                _reject('删除暂存目录跨文件系统；未删除 VM')
            if _metadata(_root(old)) != expected['root']:
                _reject('VM 目录身份已变化；未删除')
            update('committing', '正在永久删除所选 VM；请勿退出宿主或断电。')
            journal = {'version': 1, 'id': request['id'], 'mode': 'delete', 'source_vm': vm,
                       'old': str(old), 'target': str(old), 'tombstone': str(tombstone),
                       'source_identity': expected, 'phase': 'before_delete',
                       'retained_private_artifacts': list(RETAINED_PRIVATE_ARTIFACTS)}
            # write_private fsyncs journal and job directory BEFORE moving old.
            registry.write_private(journal_path, journal)
            registry.sync_directory(VM_ROOT)
            registry.sync_directory(tomb_parent)
            # Absolute source/destination are derived, validated and pinned above.
            if old.resolve(strict=True) != VM_ROOT / vm or tombstone.resolve(strict=False) != tomb_parent / 'old-environment':
                _reject('删除源或暂存路径身份不符')
            os.rename(str(old), str(tombstone))
            registry.sync_directory(VM_ROOT)
            registry.sync_directory(tomb_parent)
            journal['phase'] = 'old_tombstoned'
            registry.write_private(journal_path, journal)
            registry.write_private(registry.REGISTRY_PATH, reg)
            registry.write_private(shares_path, shares)
            journal['phase'] = 'configuration_removed'
            registry.write_private(journal_path, journal)
            # Durable registry/share removals and parent rename MUST precede
            # physical deletion. Any partial outcome is manual-recovery-only.
            registry.sync_directory(STATE)
            registry.sync_directory(VM_ROOT)
            registry.sync_directory(tomb_parent)
            registry.safe_path(tombstone)
            if tombstone.resolve(strict=True) != tomb_parent / 'old-environment':
                _reject('删除暂存路径身份不符，必须人工恢复')
            if _metadata(_root(tombstone)) != expected['root']:
                _reject('删除暂存目录身份已变化，必须人工恢复')
            _check_tree(tombstone, socket_identity)
            shutil.rmtree(str(tombstone))
            registry.sync_directory(tomb_parent)
            journal['phase'] = 'committed_old_removed'
            registry.write_private(journal_path, journal)
        finally:
            # First/only close of the locked config inode in this process.
            if config_fd is not None:
                os.close(config_fd)
            os.close(storage_fd)


def worker(jid, lock_fd):
    if not re.fullmatch('[0-9a-f]{32}', jid):
        _reject('删除任务标识无效')
    _lock_metadata(lock_fd, STATE / 'build.lock')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.umask(0o077)
    jobdir = registry.safe_path(STATE / 'build-jobs' / jid)
    request = registry.read_private(jobdir / 'request.json')
    current = registry.read_private(STATE / 'build-current.json')
    if (type(request) is not dict or type(current) is not dict
            or request.get('id') != jid or current.get('id') != jid
            or request.get('mode') != 'delete' or current.get('mode') != 'delete'):
        _reject('删除任务状态冲突')
    current['pid'] = os.getpid()
    def update(phase, message, progress=None):
        current.update(phase=phase, message=message, progress=progress, updated_at=lifecycle.timestamp())
        registry.write_private(jobdir / 'status.json', current)
        registry.write_private(STATE / 'build-current.json', current)
    try:
        update('preflight', '检查 VM 状态和目录身份；尚未删除任何 VM。')
        validated_request(request['source_vm'], request.get('confirm_name'),
                          request.get('acknowledge_erase'), {request['source_vm']})
        if request.get('name') != request['source_vm']:
            _reject('删除任务名称不一致')
        _commit(request, update)
        current.update(result='deleted', old_deleted=True, recovery_required=False)
        update('deleted', '所选 VM 已删除。' + RETAINED_MESSAGE, 1)
    except Exception as error:
        # Never render arbitrary ValueError text: JSON/Tart errors can include
        # private source content. Only our own controlled messages are allowed.
        message = str(error) if isinstance(error, DeletionRejected) else '删除任务未完成；请检查私有事务记录。'
        try:
            journal = registry.read_private(jobdir / 'commit.json', None)
            if _journal_complete(journal, jid, request.get('source_vm')):
                current.update(result='deleted', old_deleted=True, recovery_required=False)
                update('deleted', '所选 VM 已删除。' + RETAINED_MESSAGE, 1)
                return
            current['recovery_required'] = journal is not None
        except Exception:
            current['recovery_required'] = True
        if current['recovery_required']:
            message = '删除事务未完整结束，已锁定相关 VM 和后续任务；必须人工恢复，不会自动重试。'
        update('failed', message)
        print('Deletion job stopped:', type(error).__name__, flush=True)


def main():
    parser = argparse.ArgumentParser(description='Dedicated explicit VM deletion worker')
    parser.add_argument('--worker', required=True)
    parser.add_argument('--lock-fd', type=int, required=True)
    args = parser.parse_args()
    try:
        worker(args.worker, args.lock_fd)
    except Exception:
        # Avoid traceback contents/paths in logs on malformed startup state.
        print('Deletion worker startup rejected; inspect private job state.', flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
