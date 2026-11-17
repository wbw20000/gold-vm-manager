#!/usr/bin/env python3
"""Local-only, authenticated controller for fixed, protected Tart VMs."""
import argparse
from collections import deque
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit, unquote
import uuid

import runtime_shares as shares_lib
import managed_registry
import lifecycle
import process_identity
import vm_deletion
import setup_profile

APP = 'gold-vm-manager'
VERSION = '1.2.0'
HOME = Path.home()
STATE_DIR = HOME / 'Library/Application Support/GoldVMManager'
CONFIG_PATH = STATE_DIR / 'config.json'
TART = HOME / 'Applications/tart.app/Contents/MacOS/tart'
VM_ROOT = HOME / '.tart/vms'
VM_BASES = {
    'gold': HOME / 'Applications/GoldNetwork',
    'gold-backup': HOME / 'Applications/GoldBackupNetwork',
    'gold-fresh': HOME / 'Applications/GoldFreshNetwork',
    'dsh purge测试': HOME / 'Applications/DSHPurgeVM',
}
ISOLATED_VMS = frozenset({'dsh purge测试'})
STATIC = Path(__file__).resolve().parent / 'static'
ENV = {
    'HOME': str(HOME), 'TART_HOME': str(HOME / '.tart'),
    'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin',
    'LANG': 'en_US.UTF-8', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
    'TART_NO_AUTO_PRUNE': '1',
}


class AppError(Exception):
    def __init__(self, message, code='invalid_request', status=400):
        super().__init__(message)
        self.code = code
        self.status = status


def strict_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def now():
    return datetime.now(timezone.utc).isoformat()


def private_dir(path):
    if path.is_symlink():
        raise AppError('应用状态目录不能是符号链接', 'unsafe_state', 500)
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise AppError('应用状态目录必须仅当前用户可访问', 'unsafe_state', 500)


def private_json(path, default=None):
    if path.is_symlink():
        raise AppError('拒绝读取符号链接配置', 'unsafe_config', 500)
    if not path.exists():
        return default
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
        raise AppError('配置文件权限不安全', 'unsafe_config', 500)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError()))
    except (ValueError, OSError):
        raise AppError('配置文件损坏，请勿覆盖原文件', 'invalid_config', 500) from None


def atomic_json(path, value):
    private_dir(path.parent)
    if path.is_symlink():
        raise AppError('拒绝覆盖符号链接配置', 'unsafe_config', 500)
    fd, name = tempfile.mkstemp(prefix=path.name + '-', suffix='.pending', dir=str(path.parent))
    pending = Path(name)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2, allow_nan=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        # Both absolute replacement targets are fixed/validated, not user paths.
        if pending.parent.resolve() != path.parent.resolve() or path.is_symlink():
            raise AppError('配置路径在写入时发生变化', 'unsafe_config', 500)
        os.replace(str(pending), str(path))
    finally:
        if pending.exists() or pending.is_symlink():
            s = pending.lstat()
            if (pending.is_symlink() or pending.resolve() != path.parent.resolve() / pending.name
                    or (s.st_dev, s.st_ino) != (identity.st_dev, identity.st_ino)):
                raise AppError('暂存配置路径身份不符', 'unsafe_config', 500)
            pending.unlink()


def effective_shares(items):
    return sorted([
        {'name': x['name'], 'path': x['path'], 'read_only': x['read_only']}
        for x in items if x.get('enabled', True)
    ], key=lambda x: x['name'])


class Controller:
    def __init__(self):
        private_dir(STATE_DIR)
        private_dir(STATE_DIR / 'logs')
        self.lock = threading.RLock()
        self.operations = {}
        self.errors = {}
        self.events = deque(maxlen=80)
        self.children = {}
        self.picker_lock = threading.Lock()
        self._cache = None
        self._cache_at = 0.0
        try:
            self._load_config()
        except AppError:
            # An interrupted multi-file commit must remain visible for recovery,
            # rather than making the native window unable to connect at all.
            if not (self.build_status() or {}).get('recovery_required'):
                raise

    def bases(self):
        try:
            return managed_registry.registered_bases(VM_BASES)
        except ValueError as e:
            raise AppError(str(e), 'invalid_registry', 500) from None

    def build_status(self):
        try:
            return vm_deletion.status()
        except (ValueError, OSError):
            return {'phase': 'failed', 'message': '创建任务记录不可读；为避免不完整替换，所有 VM 操作已锁定，请先检查私有任务记录', 'name': None, 'recovery_required': True}

    def build_busy(self, vm):
        job = self.build_status()
        return bool(job and (job.get('phase') in lifecycle.ACTIVE or job.get('recovery_required'))
                    and ((job.get('recovery_required') and not job.get('name'))
                         or vm in (job.get('source_vm'), job.get('name'))))

    def delete_vm(self, vm, payload):
        self._vm(vm)
        if type(payload) is not dict or set(payload) != {'confirm_name', 'acknowledge_erase'}:
            raise AppError('删除请求格式错误')
        with self.lock:
            if self.operations or self.build_busy(vm):
                raise AppError('请先等待当前操作完成', 'busy', 409)
            try:
                return vm_deletion.start(vm, payload['confirm_name'], payload['acknowledge_erase'], set(self.bases()))
            except (ValueError, OSError) as error:
                raise AppError(str(error) if isinstance(error, ValueError) else '删除前置检查失败，未删除 VM', 'delete_rejected', 409) from None

    def create_build(self, payload):
        with self.lock:
            if self.operations:
                raise AppError('请先等待当前 VM 操作完成', 'busy', 409)
            try:
                return lifecycle.start(payload, set(self.bases()) - set(ISOLATED_VMS))
            except (ValueError, OSError) as e:
                raise AppError(str(e) if isinstance(e, ValueError) else '创建任务前置检查失败', 'build_rejected', 409) from None

    def pick_ipsw(self, payload):
        if payload != {}:
            raise AppError('镜像选择请求格式错误')
        if not self.picker_lock.acquire(blocking=False):
            raise AppError('已有选择器打开', 'picker_busy', 409)
        try:
            script = 'POSIX path of (choose file with prompt "选择 Apple macOS IPSW 恢复镜像" of type {"ipsw"})'
            r = self._run(['/usr/bin/osascript', '-e', script], timeout=180)
            if r.returncode:
                if '-128' in r.stderr: return {'ok': True, 'cancelled': True}
                raise AppError('镜像选择失败；可以填写绝对路径')
            return {'ok': True, 'path': r.stdout.rstrip('\r\n')}
        finally:
            self.picker_lock.release()

    def _vm(self, vm):
        if type(vm) is not str or vm not in self.bases():
            raise AppError('未知虚拟机', 'unknown_vm', 404)
        return self.bases()[vm]

    def _load_config(self):
        d = private_json(CONFIG_PATH, {'version': 1, 'vms': {}})
        if (not isinstance(d, dict) or set(d) != {'version', 'vms'} or type(d.get('version')) is not int or d.get('version') != 1
                or not isinstance(d.get('vms'), dict) or set(d['vms']) - set(self.bases())):
            raise AppError('共享配置格式不受支持', 'invalid_config', 500)
        return d

    def _configured(self, vm):
        entry = self._load_config()['vms'].get(vm, {'shares': []})
        if type(entry) is not dict or set(entry) != {'shares'}:
            raise AppError('共享配置格式错误', 'invalid_config', 500)
        try:
            return shares_lib.validate_shares(entry['shares'], allow_missing_ids=False)
        except (ValueError, RuntimeError, OSError) as error:
            raise AppError('已保存的共享配置无效：' + str(error)[:160], 'invalid_config', 500) from None

    def _run(self, args, timeout=12):
        try:
            return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, env=ENV, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise AppError('操作超时；没有自动强制停止 VM', 'command_timeout', 504) from None
        except OSError:
            raise AppError('无法调用本机 Tart，请检查安装', 'tart_unavailable', 500) from None

    def inventory(self, fresh=False):
        with self.lock:
            if not fresh and self._cache is not None and time.monotonic() - self._cache_at < 1.0:
                return dict(self._cache)
            r = self._run([str(TART), 'list', '--format', 'json'])
            if r.returncode:
                raise AppError('读取 VM 列表失败', 'inventory_failed', 500)
            try:
                entries = json.loads(r.stdout)
                if not isinstance(entries, list):
                    raise ValueError()
                values = {x['Name']: x for x in entries
                          if x.get('Source') == 'local' and x.get('Name') in self.bases()}
            except (ValueError, KeyError, TypeError, AttributeError):
                raise AppError('Tart 返回了无法识别的状态', 'inventory_failed', 500) from None
            self._cache = values
            self._cache_at = time.monotonic()
            return dict(values)

    def event(self, vm, action, message, level='info'):
        item = {'time': now(), 'vm': vm, 'action': action, 'message': message, 'level': level}
        with self.lock:
            self.events.appendleft(item)
            path = STATE_DIR / 'events.jsonl'
            if path.is_symlink():
                raise AppError('审计日志不能是符号链接', 'unsafe_state', 500)
            fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as f:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')

    def _runtime(self, vm):
        base = self._vm(vm)
        try:
            d = private_json(base / 'status.json', {})
            return d if isinstance(d, dict) else {}
        except AppError:
            return {}

    def _pid(self, vm):
        d = self._runtime(vm)
        pid = d.get('tart_pid')
        if type(pid) is not int or pid <= 1:
            raise AppError('无法安全定位 VM 进程；请通过受保护入口启动', 'unmanaged_process', 409)
        r = self._run(['/bin/ps', '-p', str(pid), '-o', 'args='])
        command = r.stdout.strip()
        argv = process_identity.arguments(pid)
        if r.returncode or len(argv) < 3 or argv[:3] != [str(TART), 'run', vm]:
            raise AppError('VM 进程身份未通过核对，未发送控制信号', 'unmanaged_process', 409)
        return pid, command

    def _active(self, vm, state):
        if vm in ISOLATED_VMS:
            return []
        if state not in ('running', 'suspended') or self._runtime(vm).get('recovery_mode') is True:
            return []
        try:
            d = shares_lib.read_last_launch(self._vm(vm))
            return [x for x in d.get('shares', []) if x.get('enabled', True)]
        except (ValueError, OSError, RuntimeError) as error:
            raise AppError('上次共享挂载记录不可读：' + str(error)[:160], 'invalid_launch_record', 409) from None

    def state(self):
        inventory = self.inventory()
        build = self.build_status()
        vms = []
        with self.lock:
            for child_vm, process in list(self.children.items()):
                if process.poll() is not None:
                    self.children.pop(child_vm, None)
            for vm, base in self.bases().items():
                item = inventory.get(vm, {})
                vm_state = item.get('State', 'missing')
                error = self.errors.get(vm)
                settings = {}
                try:
                    p = VM_ROOT / vm / 'config.json'
                    if p.is_symlink():
                        raise ValueError()
                    settings = json.loads(p.read_text()) if item else {}
                except (OSError, ValueError):
                    error = '无法读取虚拟机配置'
                desired = []
                active = []
                try:
                    desired = self._configured(vm)
                    active = self._active(vm, vm_state)
                except AppError as e:
                    error = str(e)
                try:
                    control = private_json(base / 'control.json', {})
                    if not isinstance(control, dict):
                        raise ValueError()
                except (AppError, ValueError):
                    control = {}
                    error = '网络控制配置异常，启动器会拒绝不安全配置'
                runtime = self._runtime(vm)
                setup_active = (base / 'environment.json').is_file()
                environment = private_json(base / 'environment.json', {}) if setup_active else {}
                try:
                    profile = setup_profile.validate(environment.get('setup_profile'))
                except (ValueError, AttributeError):
                    profile = setup_profile.validate()
                    error = '初始化模板无效，请重新选择，不自动执行'
                recovery_mode = runtime.get('recovery_mode') is True and vm_state == 'running'
                pause_supported = vm not in ISOLATED_VMS and not setup_active and not effective_shares(active)
                protected_ready = (base / 'launcher.py').is_file()
                if vm_state == 'running':
                    try:
                        _, command = self._pid(vm)
                        protected_ready = '--net-fd=' in command and runtime.get('state') in ('starting', 'running')
                        if vm in ISOLATED_VMS:
                            protected_ready = protected_ready and '--no-clipboard' in command and not any(flag in command for flag in ('--dir', '--disk', '--rosetta', '--vnc'))
                        if '--dir=' in command or ' --dir ' in command:
                            pause_supported = False
                    except AppError:
                        pause_supported = False
                        protected_ready = False
                pending = vm_state in ('running', 'suspended') and effective_shares(desired) != effective_shares(active)
                latest = next((e for e in self.events if e['vm'] == vm), None)
                vms.append({
                    'id': vm, 'name': vm, 'state': vm_state,
                    'cpu': settings.get('cpuCount'),
                    'memory_gib': round(settings.get('memorySize', 0) / (1024 ** 3), 1),
                    'disk_gb': item.get('Disk'), 'allocated_gb': item.get('Size'),
                    'network': {'protected': protected_ready,
                                'blocked': control.get('drop_proxy') is True,
                                'management_enabled': runtime.get('management_enabled') is True and vm_state == 'running'},
                    'shares': desired, 'active_shares': active, 'shares_locked': vm in ISOLATED_VMS, 'pending_share_changes': pending,
                    'pause_supported': pause_supported, 'busy': vm in self.operations or self.build_busy(vm),
                    'rebuild_supported': vm not in ISOLATED_VMS and settings.get('os', 'darwin') == 'darwin',
                    'setup_required': setup_active, 'setup_profile': profile,
                    'recovery_supported': setup_active and vm not in ISOLATED_VMS,
                    'recovery_mode': recovery_mode,
                    'operation': self.operations.get(vm), 'last_error': error, 'last_event': latest,
                })
            usage = os.statvfs(str(HOME))
            mem = self._run(['/usr/sbin/sysctl', '-n', 'hw.memsize'])
            try:
                memory = round(int(mem.stdout.strip()) / (1024 ** 3))
            except ValueError:
                memory = None
            return {'ok': True, 'app': {'name': 'Gold VM Manager', 'version': VERSION},
                    'host': {'cpu_count': os.cpu_count(), 'memory_gib': memory,
                             'free_disk_gib': round(usage.f_bavail * usage.f_frsize / (1024 ** 3), 1)},
                    'vms': vms, 'events': list(self.events), 'build_job': build,
                    'capabilities': {'native_picker': True, 'create_vm': True, 'rebuild_vm': True}}

    def save_shares(self, vm, payload):
        self._vm(vm)
        if vm in ISOLATED_VMS:
            raise AppError('Purge 测试虚拟机禁止共享宿主目录', 'shares_disabled', 403)
        if not isinstance(payload, dict) or set(payload) - {'shares', 'acknowledge_write'}:
            raise AppError('共享目录请求格式错误')
        try:
            values = shares_lib.validate_shares(payload.get('shares'))
        except (ValueError, RuntimeError, OSError) as e:
            raise AppError(str(e), 'invalid_shares') from None
        with self.lock, managed_registry.state_lock(STATE_DIR):
            self._vm(vm)  # Recheck after waiting for a concurrent commit/retirement.
            if vm in self.operations or self.build_busy(vm):
                raise AppError('此 VM 正在执行操作，请稍后保存', 'busy', 409)
            current = self._configured(vm)
            old_rw = {(x['path'], x['name']) for x in current if x.get('enabled', True) and x.get('read_only') is False}
            new_rw = {(x['path'], x['name']) for x in values if x.get('enabled', True) and x.get('read_only') is False}
            if new_rw - old_rw and payload.get('acknowledge_write') is not True:
                raise AppError('启用读写会允许 VM 修改或删除宿主原目录中的文件，请明确确认', 'write_ack_required')
            d = self._load_config()
            d['vms'][vm] = {'shares': values}
            atomic_json(CONFIG_PATH, d)
            state = self.inventory(fresh=True).get(vm, {}).get('State', 'missing')
            active = self._active(vm, state)
            pending = state in ('running', 'suspended') and effective_shares(values) != effective_shares(active)
            message = '共享配置已保存；完整关机后的下次启动生效' if pending else '共享配置已保存，下次冷启动时应用'
            self.event(vm, 'shares', '已保存共享目录配置（未重启 VM）')
            return {'ok': True, 'shares': values, 'pending_share_changes': pending, 'message': message}

    def pick_directory(self, payload):
        if not isinstance(payload, dict) or set(payload) != {'vm'}:
            raise AppError('请选择目标 VM')
        vm = payload['vm']
        self._vm(vm)
        if vm in ISOLATED_VMS:
            raise AppError('Purge 测试虚拟机禁止共享宿主目录', 'shares_disabled', 403)
        if not self.picker_lock.acquire(blocking=False):
            raise AppError('已有目录选择窗口，请先完成或取消', 'picker_busy', 409)
        try:
            script = 'POSIX path of (choose folder with prompt "选择要共享的宿主目录")'
            r = self._run(['/usr/bin/osascript', '-e', script], timeout=180)
            if r.returncode:
                if '-128' in r.stderr:
                    return {'ok': True, 'cancelled': True}
                raise AppError('目录选择已取消或无法打开；也可以手动填写路径', 'picker_failed')
            path = r.stdout.rstrip('\r\n')
            if not path:
                return {'ok': True, 'cancelled': True}
            return {'ok': True, 'path': path}
        finally:
            self.picker_lock.release()

    def reveal(self, payload):
        if not isinstance(payload, dict) or set(payload) != {'vm', 'share_id'}:
            raise AppError('打开目录请求格式错误')
        vm = payload['vm']
        self._vm(vm)
        share = next((x for x in self._configured(vm) if x.get('id') == payload['share_id']), None)
        if not share:
            raise AppError('共享目录不存在', 'share_missing', 404)
        try:
            validated = shares_lib.validate_shares([share])[0]
        except (ValueError, RuntimeError, OSError) as error:
            raise AppError(str(error), 'invalid_shares') from None
        r = self._run(['/usr/bin/open', validated['path']])
        if r.returncode:
            raise AppError('无法在 Finder 中打开目录', 'reveal_failed')
        return {'ok': True}

    def action(self, vm, payload):
        self._vm(vm)
        if not isinstance(payload, dict) or set(payload) - {'action', 'confirm_name'}:
            raise AppError('操作请求格式错误')
        action = payload.get('action')
        if action not in ('start', 'pause', 'shutdown', 'force-stop', 'discard-state', 'focus', 'recovery-start'):
            raise AppError('不支持此 VM 操作')
        if action in ('force-stop', 'discard-state', 'recovery-start') and payload.get('confirm_name') != vm:
            raise AppError('请输入完整 VM 名称以确认可能丢失未保存内容的操作', 'confirmation_required')
        with self.lock:
            if vm in self.operations or self.build_busy(vm):
                raise AppError('此 VM 正在执行操作', 'busy', 409)
            item = self.inventory(fresh=True).get(vm)
            if not item:
                raise AppError('VM 不存在', 'missing_vm', 404)
            state = item['State']
            if action == 'recovery-start':
                if state != 'stopped':
                    raise AppError('恢复模式仅用于已关机 VM；请先正常关机，不会自动强制停止', 'wrong_state', 409)
                code = (self._vm(vm) / 'launcher.py').read_text()
                if not (self._vm(vm) / 'environment.json').is_file() or '# GOLD_VM_MANAGER_RECOVERY_V1' not in code:
                    raise AppError('此 VM 的受保护恢复启动器尚未就绪', 'recovery_unavailable', 409)
            if action == 'start' and state == 'running':
                return {'ok': True, 'message': '此 VM 已在运行；没有重复启动'}
            if action in ('pause', 'shutdown', 'focus') and state != 'running':
                raise AppError('此操作需要 VM 正在运行', 'wrong_state', 409)
            if action == 'pause':
                if (self._vm(vm) / 'environment.json').is_file():
                    raise AppError('当前新环境带只读安装共享，不支持暂停，请正常关机', 'pause_with_setup', 409)
                if effective_shares(self._active(vm, state)):
                    raise AppError('当前挂载共享目录，暂不支持安全暂停；请在 guest 内正常关机', 'pause_with_shares', 409)
                _, command = self._pid(vm)
                if '--suspendable' not in command or '--dir' in command:
                    raise AppError('此启动配置未确认可暂停；请正常关机', 'pause_unsupported', 409)
            if action == 'discard-state' and state != 'suspended':
                raise AppError('只有已暂停 VM 才有可丢弃的状态', 'wrong_state', 409)
            if action == 'force-stop' and state != 'running':
                raise AppError('强制停止仅用于运行中的 VM；暂停状态请单独选择丢弃', 'wrong_state', 409)
            if action == 'start' and vm in ISOLATED_VMS:
                code = (self.bases()[vm] / 'launcher.py').read_text()
                if '# GOLD_VM_MANAGER_ISOLATED_V1' not in code or self._configured(vm):
                    raise AppError('专用隔离启动器或禁止共享配置未通过核对', 'integration_missing', 409)
            if action == 'start' and vm not in ISOLATED_VMS:
                code = (self.bases()[vm] / 'launcher.py').read_text()
                if '# GOLD_VM_MANAGER_SHARES_V1' not in code:
                    raise AppError('共享目录安全集成未安装，拒绝忽略配置启动', 'integration_missing', 409)
                try:
                    shares_lib.prepare_vm_shares(vm, self.bases()[vm], state)
                except (ValueError, RuntimeError, OSError) as e:
                    raise AppError(str(e), 'share_preflight_failed', 409) from None
            self.operations[vm] = {'action': action, 'started_at': now()}
            self.errors.pop(vm, None)
            worker = threading.Thread(target=self._perform, args=(vm, action), daemon=True)
            worker.start()
            return {'ok': True, 'message': {'start': '正在启动或恢复 VM', 'pause': '正在保存暂停状态',
                    'shutdown': '已请求正常关机，请留意客机提示（macOS 可能需要确认）',
                    'force-stop': '正在强制停止 VM', 'discard-state': '正在丢弃已确认的暂停状态',
                    'focus': '正在打开 VM 窗口', 'recovery-start': '正在以受保护恢复模式启动；未抹盘或更改密码'}[action]}

    def _perform(self, vm, action):
        try:
            if action in ('start', 'recovery-start'):
                logfile = STATE_DIR / 'logs' / (vm + '-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.log')
                if logfile.is_symlink():
                    raise AppError('启动日志路径异常', 'unsafe_log', 500)
                with logfile.open('x', encoding='utf-8') as log:
                    proc = subprocess.Popen(['/usr/bin/python3', str(self.bases()[vm] / 'launcher.py')] + (['--recovery'] if action == 'recovery-start' else []),
                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        env=ENV, cwd=str(self.bases()[vm]), start_new_session=True, close_fds=True)
                with self.lock:
                    self.children[vm] = proc
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise AppError('受保护启动器提前退出；没有使用无保护网络回退。请查看应用日志。', 'launcher_exited', 500)
                    if self.inventory(fresh=True).get(vm, {}).get('State') == 'running':
                        self.event(vm, action, '恢复模式已启动，未附加宿主共享目录' if action == 'recovery-start' else 'VM 已运行，保留原网络防护')
                        return
                    time.sleep(0.3)
                raise AppError('VM 启动仍未确认；不会自动重试或重复启动，请刷新状态', 'startup_unconfirmed', 504)
            elif action == 'pause':
                r = self._run([str(TART), 'suspend', vm])
                if r.returncode:
                    raise AppError('暂停请求失败，没有自动强制停止', 'suspend_failed', 500)
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    state = self.inventory(fresh=True).get(vm, {}).get('State')
                    if state == 'suspended':
                        self.event(vm, action, 'VM 已暂停，运行状态已保存')
                        return
                    if state == 'stopped':
                        raise AppError('VM 已停止但没有生成暂停状态；请检查启动器日志', 'suspend_failed', 500)
                    time.sleep(0.4)
                raise AppError('暂停仍未完成，请检查 VM 状态；没有强制停止', 'suspend_timeout', 504)
            elif action == 'shutdown':
                pid, _ = self._pid(vm)
                os.kill(pid, signal.SIGUSR2)
                self.event(vm, action, '已发送正常关机请求；客机可能需要确认')
            elif action in ('force-stop', 'discard-state'):
                current = self.inventory(fresh=True).get(vm, {}).get('State')
                expected = 'running' if action == 'force-stop' else 'suspended'
                if current != expected:
                    raise AppError('VM 状态已变化，已取消危险操作，请重新确认', 'state_changed', 409)
                if action == 'discard-state':
                    # Dedicated single-thread process holds the same config POSIX lock
                    # as Tart and deletes ONLY the verified saved-RAM file, never a live VM.
                    helper = Path(__file__).resolve().parent / 'discard_state.py'
                    r = self._run(['/usr/bin/python3', str(helper), vm])
                else:
                    r = self._run([str(TART), 'stop', vm, '--timeout', '10'], timeout=18)
                if r.returncode:
                    raise AppError('停止/丢弃未成功或状态已变化，请刷新后重新确认', 'stop_failed', 409)
                self.event(vm, action, 'VM 已停止（用户明确确认）' if action == 'force-stop' else '已丢弃用户确认的暂停状态；下次冷启动')
            elif action == 'focus':
                pid, _ = self._pid(vm)
                script = ('import AppKit; import Foundation; let p:pid_t=' + str(pid)
                          + '; guard let a=NSRunningApplication(processIdentifier:p),'
                          + 'a.bundleIdentifier=="com.github.cirruslabs.tart" else{exit(2)};'
                          + '_=a.activate(options:[.activateAllWindows])')
                r = self._run(['/usr/bin/swift', '-e', script], timeout=20)
                if r.returncode:
                    raise AppError('无法切换 VM 窗口，但 VM 仍可能正常运行', 'focus_failed')
                self.event(vm, action, '已请求显示 VM 窗口')
        except Exception as error:
            message = str(error) if isinstance(error, AppError) else '操作失败：' + type(error).__name__
            with self.lock:
                self.errors[vm] = message
            self.event(vm, action, message, 'error')
        finally:
            with self.lock:
                self.operations.pop(vm, None)
                self._cache_at = 0


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, controller, token, instance):
        self.controller = controller
        self.token = token
        self.instance = instance
        super().__init__(address, Handler)
        self.origin = 'http://127.0.0.1:' + str(self.server_address[1])


class Handler(BaseHTTPRequestHandler):
    server_version = 'GoldVMManager/1.0'
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        # Do not log URLs, tokens, user paths or HTTP headers.
        return

    def _headers(self, status, content_type, length):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(length))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
        self.end_headers()

    def _json(self, status, value):
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
        self._headers(status, 'application/json; charset=utf-8', len(raw))
        self.wfile.write(raw)

    def _guard(self, authenticated=True, mutation=False):
        expected = '127.0.0.1:' + str(self.server.server_address[1])
        if self.headers.get('Host') != expected:
            raise AppError('不接受此 Host 地址', 'invalid_host', 403)
        origin = self.headers.get('Origin')
        if origin is not None and origin != self.server.origin:
            raise AppError('跨站请求已拒绝', 'invalid_origin', 403)
        if mutation and origin != self.server.origin:
            raise AppError('写操作必须由本机界面发起', 'origin_required', 403)
        if authenticated:
            value = self.headers.get('Authorization', '')
            if not hmac.compare_digest(value, 'Bearer ' + self.server.token):
                raise AppError('请从 Gold VM Manager App 重新打开界面以授权', 'unauthorized', 401)

    def do_GET(self):
        try:
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment:
                raise AppError('请求不能携带查询参数', 'invalid_url')
            path = parsed.path
            self._guard(authenticated=path.startswith('/api/') and path != '/api/health')
            if path == '/api/health':
                self._json(200, {'ok': True, 'app': APP, 'version': VERSION, 'instance': self.server.instance})
            elif path == '/api/state':
                self._json(200, self.server.controller.state())
            elif path in ('/', '/index.html', '/app.js', '/style.css'):
                name = 'index.html' if path in ('/', '/index.html') else path[1:]
                asset = STATIC / name
                if asset.is_symlink() or asset.resolve() != STATIC.resolve() / name:
                    raise AppError('资源不可用', 'asset_not_found', 404)
                raw = asset.read_bytes()
                types = {'index.html': 'text/html; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8', 'style.css': 'text/css; charset=utf-8'}
                self._headers(200, types[name], len(raw))
                self.wfile.write(raw)
            elif path == '/favicon.ico':
                self._headers(204, 'image/x-icon', 0)
            else:
                raise AppError('未找到资源', 'not_found', 404)
        except AppError as e:
            self._json(e.status, {'ok': False, 'error': str(e), 'code': e.code})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._json(500, {'ok': False, 'error': '读取失败，原配置未被覆盖', 'code': 'internal_error'})

    def do_POST(self):
        try:
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment:
                raise AppError('不接受查询参数')
            self._guard(mutation=True)
            if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
                raise AppError('只接受 JSON 请求', 'invalid_content_type', 415)
            if self.headers.get('Transfer-Encoding'):
                raise AppError('不接受分块请求')
            try:
                length = int(self.headers.get('Content-Length', '-1'))
            except ValueError:
                raise AppError('请求长度错误') from None
            if not 0 <= length <= 65536:
                raise AppError('请求过大或没有长度', 'invalid_length', 413)
            try:
                payload = json.loads(self.rfile.read(length).decode('utf-8'), object_pairs_hook=strict_pairs,
                                     parse_constant=lambda x: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeError):
                raise AppError('JSON 格式错误') from None
            path = parsed.path
            if path == '/api/build':
                value = self.server.controller.create_build(payload)
            elif path == '/api/pick-ipsw':
                value = self.server.controller.pick_ipsw(payload)
            elif path == '/api/pick-directory':
                value = self.server.controller.pick_directory(payload)
            elif path == '/api/reveal-directory':
                value = self.server.controller.reveal(payload)
            else:
                match = re.fullmatch(r'/api/vms/([^/]+)/(action|shares|delete)', unquote(path, errors='strict'))
                if not match:
                    raise AppError('未找到操作', 'not_found', 404)
                vm, route = match.groups()
                if route == 'delete':
                    value = self.server.controller.delete_vm(vm, payload)
                elif route == 'action':
                    value = self.server.controller.action(vm, payload)
                else:
                    value = self.server.controller.save_shares(vm, payload)
            self._json(202 if path.endswith(('/action','/delete')) or path == '/api/build' else 200, value)
        except AppError as e:
            self.close_connection = True
            self._json(e.status, {'ok': False, 'error': str(e), 'code': e.code})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.close_connection = True
            self._json(500, {'ok': False, 'error': '操作失败，没有自动重试或删除数据', 'code': 'internal_error'})

    def do_OPTIONS(self):
        self._json(403, {'ok': False, 'error': '跨站访问不受支持', 'code': 'cors_denied'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=18765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit('Port must be an unprivileged local port')
    os.umask(0o077)
    private_dir(STATE_DIR)
    lockpath = STATE_DIR / 'server.lock'
    if lockpath.is_symlink():
        raise SystemExit('Refusing symlinked server lock')
    lock = lockpath.open('a+')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('Gold VM Manager is already running')
    token = secrets.token_urlsafe(32)
    instance = uuid.uuid4().hex
    controller = Controller()
    server = AppServer(('127.0.0.1', args.port), controller, token, instance)
    info_path = STATE_DIR / 'server.json'
    atomic_json(info_path, {'version': 1, 'app': APP, 'pid': os.getpid(),
                           'port': server.server_address[1], 'token': token,
                           'instance': instance, 'started_at': now()})
    def stop(signum, frame):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print('Gold VM Manager listening on ' + server.origin + ' (authentication required)', flush=True)
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        server.server_close()
        # Manager shutdown does not implicitly stop running VMs.
        try:
            value = private_json(info_path, {})
            if value.get('instance') == instance:
                if info_path.resolve(strict=True) != STATE_DIR.resolve() / 'server.json' or info_path.is_symlink():
                    raise RuntimeError('Unexpected server-info cleanup path')
                info_path.unlink()
        finally:
            lock.close()

if __name__ == '__main__':
    main()
