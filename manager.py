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
import vm_disk_growth
import setup_profile
import oneclick
import vpn_store

APP = 'gold-vm-manager'
VERSION = '1.5.2'
VPN_VALIDATE_PATH = '/api/preinstall/vpn/validate'
# Cover JSON escaping for the 256 KiB input limit without raising other routes' caps.
VPN_VALIDATE_MAX_WIRE = 6 * 256 * 1024 + 16384
PREINSTALL_PHASE_FIELDS = frozenset(('id', 'mode', 'name', 'phase', 'pid', 'progress', 'started_at',
    'updated_at', 'message', 'source_vm', 'old_deleted', 'system_restored', 'applications_preinstalled',
    'guest_started', 'desktop_verified', 'host_credentials_copied', 'user_vpn_configuration_supplied',
    'vpn_configuration_staged', 'vpn_connected', 'network_independently_verified', 'published',
    'needs_host_security_authorization', 'recovery_required', 'failure_code', 'failed_phase',
    'failed_step', 'failure_reason', 'failed_product', 'materials_source', 'interrupted_download_archivable'))
# Preinstalled protected environments: v2 wrote apps and a first-login seed into
# the guest disk; v3 writes nothing there and shares installers during first setup.
PROTECTED_VERSIONS = (2, 3)
HOME = Path.home()
STATE_DIR = HOME / 'Library/Application Support/GoldVMManager'
CONFIG_PATH = STATE_DIR / 'config.json'
TART = HOME / 'Applications/tart.app/Contents/MacOS/tart'
VM_ROOT = HOME / '.tart/vms'
VM_BASES = {
    'gold': HOME / 'Applications/GoldNetwork',
    'gold-backup': HOME / 'Applications/GoldBackupNetwork',
    'gold-fresh': HOME / 'Applications/GoldFreshNetwork',
}
# Dedicated local test-VM bindings are not distributed with the public source.
ISOLATED_VMS = frozenset()
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
            return managed_registry.registered_bases(VM_BASES, state_dir=STATE_DIR)
        except ValueError as e:
            raise AppError(str(e), 'invalid_registry', 500) from None

    def build_status(self):
        try:
            return vm_deletion.status(state_dir=STATE_DIR)
        except (ValueError, OSError):
            return {'phase': 'failed', 'message': '创建任务记录不可读；为避免不完整替换，所有 VM 操作已锁定，请先检查私有任务记录', 'name': None, 'recovery_required': True}

    def build_busy(self, vm):
        job = self.build_status()
        return bool(job and (lifecycle.is_active(job) or job.get('recovery_required'))
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

    def preinstall_capabilities(self):
        # restore_image_cached only shapes the dialog's wording; every build still
        # hashes the whole cached image before using it.
        import host_artifacts
        return {'ok': True, **oneclick.capabilities(),
                'restore_image_cached': host_artifacts.cached('ipsw', STATE_DIR / 'host-materials')}

    def preinstall_examples(self):
        return {'ok': True, **oneclick.examples()}

    def validate_vpn(self, payload):
        from vpn_config import VPNConfigurationError
        if type(payload) is not dict or set(payload) != {'submission', 'allow_resolve'} or type(payload['allow_resolve']) is not bool:
            raise AppError('节点校验请求无效', 'vpn_validation_failed')
        submission = payload['submission']
        if type(submission) is dict and submission.get('input_mode') == 'vm':
            return {'ok': True, **self._reuse_vpn(submission, payload['allow_resolve'])}
        try:
            stored = vpn_store.store_submission(STATE_DIR, submission, allow_resolve=payload['allow_resolve'])
        except (VPNConfigurationError, vpn_store.VPNStoreError):
            # No submitted value or underlying parser/OS output crosses the API boundary.
            raise AppError('节点或 YAML 未通过校验；请检查本地文件路径、权限及模板中的协议和节点字段。', 'vpn_validation_failed') from None
        return {'ok': True, **stored}

    def _reuse_vpn(self, submission, allow_resolve):
        # The nodes one of this manager's own v3 VMs was built with: read back from
        # that VM's private environment, rechecked against its pins, and issued as
        # a new one-hour ticket. The source VM is only read, running or not.
        import preinstall_runtime
        from vpn_config import VPNConfigurationError
        if set(submission) != {'input_mode', 'vm'} or allow_resolve:
            raise AppError('节点校验请求无效', 'vpn_validation_failed')
        vm = submission['vm']
        try:
            base = self._vm(vm)
            config, endpoints = preinstall_runtime.saved_private_config(
                base, oneclick.INSTALLERS_PROFILE, expected_vm_name=vm,
                expected_vm_config=VM_ROOT / vm / 'config.json')
            return vpn_store.store_saved(STATE_DIR, config, endpoints)
        except (AppError, OSError, preinstall_runtime.RuntimePreparationError, VPNConfigurationError, vpn_store.VPNStoreError):
            # One answer for unknown VMs, older VMs and changed files alike.
            raise AppError('无法沿用这台 VM 的节点：它没有保存节点配置，或配置已被改动。请改用本地 YAML 路径。',
                           'vpn_validation_failed') from None

    def create_preinstall(self, payload):
        with self.lock:
            if self.operations:
                raise AppError('请先等待当前 VM 操作完成', 'busy', 409)
            try:
                job = oneclick.start(payload, state_dir=STATE_DIR, tart_home=VM_ROOT.parent)
            except (ValueError, OSError, subprocess.SubprocessError):
                raise AppError('预装请求未受理。请检查全新名称、前置条件、有效的节点校验以及是否有任务待处理。', 'preinstall_rejected', 409) from None
            return {'ok': True, 'job': {k: v for k, v in job.items() if k in PREINSTALL_PHASE_FIELDS}}

    def resume_preinstall(self, payload):
        with self.lock:
            if self.operations:
                raise AppError('请先等待当前 VM 操作完成', 'busy', 409)
            try:
                job = oneclick.resume(payload, state_dir=STATE_DIR, tart_home=VM_ROOT.parent)
            except (ValueError, OSError, subprocess.SubprocessError):
                raise AppError('无法继续 VPN 配置。请确认任务仍在等待、节点已重新校验，且暂存盘未被改动。', 'vpn_resume_rejected', 409) from None
            return {'ok': True, 'job': {k: v for k, v in job.items() if k in PREINSTALL_PHASE_FIELDS}}

    def archive_preinstall(self, payload):
        with self.lock:
            if self.operations:
                raise AppError('请先等待当前 VM 操作完成', 'busy', 409)
            try:
                return oneclick.archive_failed(payload, state_dir=STATE_DIR, tart_home=VM_ROOT.parent)
            except (ValueError, OSError, subprocess.SubprocessError):
                raise AppError('未归档。只能归档已结束、未发布、未挂载且名称完全一致的失败预装任务；暂存盘未改动。',
                               'archive_rejected', 409) from None

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
        base = self.bases().get(vm) if type(vm) is str else None
        if base is None:
            raise AppError('未知虚拟机', 'unknown_vm', 404)
        return base

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

    def _inventory_tart(self):
        try:
            return lifecycle.inventory_tool(state_dir=STATE_DIR, legacy=TART)
        except (OSError, ValueError, RuntimeError, TypeError):
            raise AppError('受审查的 Tart 工具记录未通过核对', 'tart_unavailable', 409) from None

    def _environment(self, vm):
        meta = private_json(self._vm(vm) / 'environment.json', {})
        if type(meta) is not dict:
            raise AppError('启动环境记录不受支持', 'invalid_environment', 409)
        return meta

    def inventory(self, fresh=False):
        with self.lock:
            if not fresh and self._cache is not None and time.monotonic() - self._cache_at < 1.0:
                return dict(self._cache)
            tool = self._inventory_tart()
            if tool is None:
                return {}  # No programs run and the first-install UI is still available.
            r = self._run([str(tool), 'list', '--format', 'json'])
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
        meta = self._environment(vm)
        if meta.get('version') in PROTECTED_VERSIONS:
            binding = meta.get('tart_binding')
            tart = binding.get('path') if type(binding) is dict and meta.get('vm_name') == vm else None
        else:
            tart = str(TART)
        if not tart or r.returncode or len(argv) < 3 or argv[:3] != [tart, 'run', vm]:
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

    def _preinstalled_status(self, base, runtime, environment):
        # v3 writes nothing into the guest: the person installs from the read-only
        # installers share. v2's guest mailbox is untrusted evidence from one
        # purpose-built private share; it never elevates guest claims to a
        # verified connection or desktop.
        from preinstall_runtime import read_guest_status, first_setup_pending, RuntimePreparationError
        try:
            pending = first_setup_pending(base)
        except RuntimePreparationError:
            pending = None  # Reported as an error; no start chooses a network for it.
        installers = environment.get('version') == 3
        result = {'first_setup_pending': pending, 'installers_share': installers,
                  'configuration_staged': not installers, 'configuration': 'not_observed',
                  'application': 'not_observed', 'system_authorization': 'user_action_may_be_required',
                  'host_authorization_pending': runtime.get('state') in (None, 'awaiting_host_authorization'),
                  'desktop_verified': False, 'vpn_connected': False, 'network_independently_verified': False}
        if installers:
            return result
        try:
            seed = private_json(base / 'vpn-seed-receipt.json', {})
            report = read_guest_status(base, seed.get('receipt_token'))
            if report.get('evidence') == 'guest_reported':
                result.update(evidence='guest_reported', configuration=report['configuration'],
                              application=report['application'], connection_check=report['connection_check'])
        except (ValueError, OSError, RuntimeError, TypeError, AttributeError, AppError):
            pass
        return result

    def _check_publication_journal(self, vm, base):
        jid = base.name
        if not re.fullmatch(r'[0-9a-f]{32}', jid):
            raise ValueError('uncommitted')
        journal = managed_registry.read_private(STATE_DIR / 'build-jobs' / jid / 'commit.json')
        if (type(journal) is not dict or type(journal.get('version')) is not int or journal['version'] != 1
                or journal.get('phase') != 'committed_new_registered' or journal.get('id') != jid
                or journal.get('mode') != 'preinstall' or journal.get('name') != vm
                or journal.get('source_vm') is not None or journal.get('environment_id') != jid
                or journal.get('target') != str(VM_ROOT / vm)):
            raise ValueError('uncommitted')

    def _require_preinstall_publication(self, vm, base):
        # Launcher code and backend may still be the older unnotarized set here;
        # _refresh_runtime replaces them before launch, then the launcher validates all.
        from preinstall_runtime import validate_environment_for_refresh as validate_environment
        try:
            self._check_publication_journal(vm, base)
            meta = validate_environment(base)
            if meta['vm_name'] != vm or meta['vm_config'] != str(VM_ROOT / vm / 'config.json'):
                raise ValueError('binding')
        except (ValueError, OSError, RuntimeError, TypeError, KeyError):
            raise AppError('预装发布记录或受保护启动文件未通过核对，不会启动或回退到普通网络。', 'preinstall_start_rejected', 409) from None

    @staticmethod
    def _disk_growth_busy(job):
        # Growth shares the build lock with publication, deletion and recovery.
        return bool(job and (job.get('recovery_required') or lifecycle.is_active(job) or lifecycle.waiting_for_vpn(job)))

    @staticmethod
    def _vm_settings(vm):
        # A poll must never follow a substituted path, block on a FIFO, or read
        # disk.img as configuration. Use the bounded/rechecked config FD for
        # both the existing hardware display and the preinstalled config pin.
        from preinstall_runtime import _read
        raw, info = _read(VM_ROOT / vm / 'config.json', private=False, cap=1024 * 1024)
        config = json.loads(raw, object_pairs_hook=strict_pairs)
        if type(config) is not dict:
            raise ValueError('invalid config')
        pin = ([info.st_dev, info.st_ino], hashlib.sha256(raw).hexdigest()) if (
            info.st_uid == os.getuid() and not info.st_mode & 0o077) else None
        return config, pin

    def _disk_capacity(self, vm, base, item, meta, config, config_pin):
        # base is from registered_bases(), never from a client. Legacy VMs and
        # partial/unpublished environments have no disk-growth capability.
        if (base.parent != STATE_DIR / 'environments' or vm in managed_registry.LEGACY_NAMES or vm in ISOLATED_VMS
                or item.get('Name') != vm or item.get('Source') != 'local'
                or type(meta.get('version')) is not int or meta['version'] not in PROTECTED_VERSIONS
                or meta.get('vm_name') != vm or meta.get('vm_config') != str(VM_ROOT / vm / 'config.json')
                or meta.get('tart_home') != str(VM_ROOT.parent) or config_pin is None
                or (meta.get('vm_config_identity'), meta.get('vm_config_sha256')) != config_pin
                or type(config.get('version')) is not int or config['version'] != 1 or config.get('os') != 'darwin'
                or config.get('diskFormat') != 'raw' or config.get('arch') != 'arm64'):
            return None
        try:
            self._check_publication_journal(vm, base)
            size = vm_disk_growth.inspect(vm, vm_root=VM_ROOT)
            return size if (type(size) is int and lifecycle.DISK_GIB_MIN * 1024**3 <= size
                            <= lifecycle.DISK_GIB_MAX * 1024**3 and size % 512 == 0) else None
        except Exception:
            # A single unsafe/replaced target never breaks polling, and native
            # diagnostics and internal paths do not cross the API boundary.
            return None

    def expand_disk(self, vm, payload):
        if (type(payload) is not dict or set(payload) != {'target_gib', 'expected_bytes', 'acknowledge_growth'}
                or payload['acknowledge_growth'] is not True or type(payload['target_gib']) is not int
                or type(payload['expected_bytes']) is not int or payload['expected_bytes'] <= 0
                or not lifecycle.DISK_GIB_MIN <= payload['target_gib'] <= lifecycle.DISK_GIB_MAX):
            raise AppError('扩容请求需要有效的整数容量和明确确认。')
        target, expected = payload['target_gib'], payload['expected_bytes']
        with self.lock:
            base = self._vm(vm)
            if self.operations or self._disk_growth_busy(self.build_status()):
                raise AppError('有操作进行中或任务待恢复，暂不能扩容。', 'busy', 409)
            item = self.inventory(fresh=True).get(vm)
            if not item:
                raise AppError('VM 不存在', 'missing_vm', 404)
            if item.get('State') != 'stopped':
                raise AppError('扩容前请先正常关机；暂停不等于关机。', 'wrong_state', 409)
            try:
                config, pin = self._vm_settings(vm)
                capacity = self._disk_capacity(vm, base, item, self._environment(vm), config, pin)
                if capacity is None:
                    raise ValueError('unbound')
                self._require_preinstall_publication(vm, base)
            except Exception:
                raise AppError('仅支持已发布、配置和磁盘通过核对的本机预装 macOS VM。', 'disk_growth_rejected', 409) from None
            if capacity != expected or target * 1024**3 <= capacity:
                raise AppError('当前容量已变化或目标不大于当前磁盘；请刷新后重新确认。', 'disk_growth_rejected', 409)
            self.operations[vm] = {'action': 'expand-disk', 'started_at': now()}
        # Reserve this VM without holding the server lock across fsync. A
        # single-threaded child owns Tart's process-wide POSIX config lock; an
        # unrelated config FD close in this server cannot drop it. The child
        # rechecks publication, fresh inventory (before storage flock), and size.
        try:
            return self._grow_disk_worker(vm, target, expected, base.name)
        finally:
            with self.lock:
                self.operations.pop(vm, None)
                self._cache = None

    @staticmethod
    def _grow_disk_worker(vm, target, expected, environment_id):
        helper = Path(__file__).resolve().with_name('vm_disk_growth.py')
        try:
            child = subprocess.Popen(['/usr/bin/python3', '-B', '-E', '-s', str(helper), '--grow', vm,
                                      str(target), str(expected), environment_id], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, cwd=str(helper.parent),
                                     close_fds=True)
        except OSError:
            raise AppError('磁盘扩容程序未能启动。', 'disk_growth_unavailable', 503) from None
        try:
            with child, child.stdout as stream:
                # Never render private output or buffer an unbounded traceback.
                raw = stream.read(513)
            if child.returncode == 0 and len(raw) <= 512:
                result = json.loads(raw, object_pairs_hook=strict_pairs)
                if (type(result) is dict and set(result) == {'ok', 'virtual_capacity_bytes'} and result['ok'] is True
                        and type(result['virtual_capacity_bytes']) is int and result['virtual_capacity_bytes'] == target * 1024**3):
                    return {'ok': True, 'virtual_capacity_bytes': result['virtual_capacity_bytes']}
                if (type(result) is dict and set(result) == {'ok', 'uncertain', 'error'} and result['ok'] is False
                        and result['uncertain'] is False and type(result['error']) is str):
                    reason = result['error']
                    if reason not in vm_disk_growth.PUBLIC_REJECTIONS:
                        reason = '当前状态或磁盘未通过扩容核对；请刷新状态。'
                    raise AppError(reason, 'disk_growth_rejected', 409)
        except AppError:
            raise
        except Exception:
            pass
        # Broken pipe, killed child, fsync/readback failure, malformed/wrong
        # capacity response: growth may already have happened. Never auto-retry.
        raise AppError('无法确认扩容是否已持久完成；请先核对磁盘状态，不要直接重试。', 'growth_outcome_uncertain', 500)

    def state(self):
        inventory = self.inventory()
        build = self.build_status()
        if build and build.get('mode') == 'preinstall':
            build = {k: v for k, v in build.items() if k in PREINSTALL_PHASE_FIELDS}
        vms = []
        with self.lock:
            for child_vm, process in list(self.children.items()):
                if process.poll() is not None:
                    self.children.pop(child_vm, None)
            for vm, base in self.bases().items():
                item = inventory.get(vm, {})
                vm_state = item.get('State', 'missing')
                error = self.errors.get(vm)
                settings, config_pin = {}, None
                try:
                    if item:
                        settings, config_pin = self._vm_settings(vm)
                except (OSError, ValueError, RuntimeError):
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
                managed_environment = (base / 'environment.json').is_file()
                try:
                    environment = self._environment(vm) if managed_environment else {}
                except AppError:
                    environment = {}
                    error = '启动环境记录不可读；不会自动启动。'
                preinstalled = environment.get('version') in PROTECTED_VERSIONS
                setup_active = managed_environment and not preinstalled
                try:
                    profile = setup_profile.validate(environment.get('setup_profile'))
                except (ValueError, AttributeError):
                    profile = setup_profile.validate()
                    error = '初始化模板无效，请重新选择，不自动执行'
                recovery_mode = runtime.get('recovery_mode') is True and vm_state == 'running'
                preinstall_status = self._preinstalled_status(base, runtime, environment) if preinstalled else None
                if preinstall_status is not None and preinstall_status['first_setup_pending'] is None:
                    error = '首次设置记录（network-mode.json）异常；不会启动，请检查私有运行目录。'
                pause_supported = vm not in ISOLATED_VMS and not managed_environment and not effective_shares(active)
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
                capacity = self._disk_capacity(vm, base, item, environment, settings, config_pin)
                vms.append({
                    'id': vm, 'name': vm, 'state': vm_state,
                    'cpu': settings.get('cpuCount'),
                    'memory_gib': round(settings.get('memorySize', 0) / (1024 ** 3), 1),
                    'disk_gb': item.get('Disk'), 'allocated_gb': item.get('Size'),
                    'disk_capacity_bytes': capacity,
                    'disk_growth_supported': (capacity is not None and capacity < lifecycle.DISK_GIB_MAX * 1024**3
                                              and vm_state == 'stopped' and not self.operations and not self._disk_growth_busy(build)),
                    'network': {'protected': protected_ready,
                                'blocked': control.get('drop_proxy') is True,
                                'management_enabled': runtime.get('management_enabled') is True and vm_state == 'running',
                                'normal_network': vm_state == 'running' and runtime.get('network_mode') == 'first-setup-normal-network'},
                    'shares': desired, 'active_shares': active, 'shares_locked': vm in ISOLATED_VMS, 'pending_share_changes': pending,
                    'pause_supported': pause_supported, 'busy': vm in self.operations or self.build_busy(vm),
                    'rebuild_supported': not preinstalled and vm not in ISOLATED_VMS and settings.get('os', 'darwin') == 'darwin',
                    'setup_required': setup_active, 'setup_profile': profile,
                    'preinstalled': preinstall_status,
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
                    'capabilities': {'native_picker': True, 'create_vm': True, 'rebuild_vm': True, 'offline_validate': True, 'preinstall': True}}

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
        if not isinstance(payload, dict) or set(payload) - {'action', 'confirm_name', 'acknowledge_reviewed_unsigned_backend',
                                                            'first_setup_normal_network'}:
            raise AppError('操作请求格式错误')
        action = payload.get('action')
        if action not in ('start', 'pause', 'shutdown', 'force-stop', 'discard-state', 'focus', 'recovery-start',
                          'finish-first-setup'):
            raise AppError('不支持此 VM 操作')
        if action in ('force-stop', 'discard-state', 'recovery-start') and payload.get('confirm_name') != vm:
            raise AppError('请在对话框里确认可能丢失未保存内容的操作', 'confirmation_required')
        with self.lock:
            if vm in self.operations or self.build_busy(vm):
                raise AppError('此 VM 正在执行操作', 'busy', 409)
            item = self.inventory(fresh=True).get(vm)
            if not item:
                raise AppError('VM 不存在', 'missing_vm', 404)
            state = item['State']
            base = self._vm(vm)
            environment = self._environment(vm)
            preinstalled = environment.get('version') in PROTECTED_VERSIONS
            launch_ack = False
            first_setup = False
            if 'acknowledge_reviewed_unsigned_backend' in payload and (not preinstalled or action != 'start'):
                raise AppError('此操作不接受后端授权字段', 'invalid_execution_consent')
            if 'first_setup_normal_network' in payload and (not preinstalled or action != 'start'):
                raise AppError('此操作不接受首次设置字段', 'invalid_execution_consent')
            if action == 'finish-first-setup':
                return self._finish_first_setup(vm, base, preinstalled, state)
            if preinstalled and action == 'start' and state != 'running':
                # First setup runs on Tart's normal network until the person marks it
                # finished (owner's decision, 2026-11-19); after that only protected starts.
                if self._first_setup_pending(base):
                    if (state != 'stopped' or payload.get('confirm_name') != vm
                            or payload.get('first_setup_normal_network') is not True
                            or 'acknowledge_reviewed_unsigned_backend' in payload):
                        raise AppError('首次设置使用普通网络：请在对话框里确认；不会自动启动。',
                                       'first_setup_confirmation_required', 409)
                    first_setup = True
                else:
                    if 'first_setup_normal_network' in payload:
                        raise AppError('首次设置已完成，之后只走受保护启动，不再使用普通网络。', 'first_setup_finished', 409)
                    if (state != 'stopped' or payload.get('confirm_name') != vm
                            or payload.get('acknowledge_reviewed_unsigned_backend') is not True):
                        raise AppError('请在对话框里确认这台 VM 的后端执行提示；不会自动启动。', 'host_authorization_required', 409)
                self._require_preinstall_publication(vm, base)
                launch_ack = True
            if action == 'recovery-start':
                if preinstalled:
                    raise AppError('预装环境目前只支持明确授权的受保护普通启动。', 'recovery_unavailable', 409)
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
            worker = threading.Thread(target=self._perform, daemon=True, args=(
                (vm, action, True, True) if first_setup else (vm, action, True) if launch_ack else (vm, action)))
            worker.start()
            if first_setup:
                return {'ok': True, 'message': '正在用普通网络启动首次设置；这次不经过网络过滤'
                        + ('，并挂只读安装文件夹 gold-installers' if environment.get('version') == 3 else '')}
            return {'ok': True, 'message': {'start': '正在启动或恢复 VM', 'pause': '正在保存暂停状态',
                    'shutdown': '已请求正常关机，请留意客机提示（macOS 可能需要确认）',
                    'force-stop': '正在强制停止 VM', 'discard-state': '正在丢弃已确认的暂停状态',
                    'focus': '正在打开 VM 窗口', 'recovery-start': '正在以受保护恢复模式启动；未抹盘或更改密码'}[action]}

    def _first_setup_pending(self, base):
        import preinstall_runtime
        try:
            return preinstall_runtime.first_setup_pending(base)
        except preinstall_runtime.RuntimePreparationError:
            raise AppError('首次设置记录（network-mode.json）未通过核对；不会启动，也不会自动选择网络方式。',
                           'invalid_network_mode', 409) from None

    def _finish_first_setup(self, vm, base, preinstalled, state):
        import preinstall_runtime
        if not preinstalled:
            raise AppError('只有预装的 VM 有首次设置。', 'first_setup_unavailable', 409)
        try:
            changed = preinstall_runtime.finish_first_setup(base)
        except preinstall_runtime.RuntimePreparationError as error:
            raise AppError('首次设置记录未通过核对（' + error.code + '）；没有更改。', 'invalid_network_mode', 409) from None
        if not changed:
            return {'ok': True, 'message': '首次设置早已标记完成；之后都走受保护启动。'}
        message = '已记录首次设置完成：之后每次启动都走受保护启动，客机只能连到你的 VPN 节点。'
        if state == 'running':
            message += '当前这次运行仍是普通网络，关机后生效。'
        self.event(vm, 'finish-first-setup', message)
        return {'ok': True, 'message': message}

    def _refresh_runtime(self, vm):
        """Before a confirmed preinstalled start, move an older environment to the signed backend.

        Environments prepared before 2026-11-19 pinned the unnotarized gvproxy,
        which macOS refuses to run. Their launcher code and backend are replaced
        with the current ones and Red Hat's notarized gvproxy (quarantine kept).
        The VM, its packet-filter policy and receipts are kept and rechecked.
        """
        import host_artifacts
        import host_tools
        import preinstall_runtime
        base = self.bases()[vm]
        try:
            if preinstall_runtime.environment_needs_refresh(base):
                self.event(vm, 'start', '正在获取 Red Hat 签名并经公证的网络后端（Podman 官方安装包，约 77 MB）；不安装 Podman')
                package = host_artifacts.acquire('podman-installer', STATE_DIR / 'host-materials')
                backend = host_tools.ensure_gvproxy(STATE_DIR / 'tools', artifact_receipt=package)
                if preinstall_runtime.refresh_environment(base, backend.executable_path):
                    self.event(vm, 'start', '已换用签名版网络后端并更新受保护启动文件；VM 磁盘和网络过滤规则未改动')
            elif preinstall_runtime.refresh_sources(base):
                # An intact signed environment takes this build's launcher code only.
                self.event(vm, 'start', '已把受保护启动文件更新到当前版本；网络后端、VM 磁盘和网络过滤规则未改动')
        except host_artifacts.ArtifactError as error:
            raise AppError('无法获取签名版网络后端（' + error.code + '）；未启动 VM。', 'backend_refresh_failed', 409) from None
        except host_tools.HostToolError as error:
            raise AppError('签名版网络后端未通过签名或公证核对（' + error.code + '）；未启动 VM。', 'backend_refresh_failed', 409) from None
        except preinstall_runtime.RuntimePreparationError as error:
            raise AppError('受保护启动文件未通过核对（' + error.code + '）；未启动 VM。', 'backend_refresh_failed', 409) from None

    def _perform(self, vm, action, launch_ack=False, first_setup=False):
        try:
            if launch_ack:
                self._refresh_runtime(vm)
            if action in ('start', 'recovery-start'):
                logfile = STATE_DIR / 'logs' / (vm + '-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.log')
                if logfile.is_symlink():
                    raise AppError('启动日志路径异常', 'unsafe_log', 500)
                with logfile.open('x', encoding='utf-8') as log:
                    argv = ['/usr/bin/python3', '-B', str(self.bases()[vm] / 'launcher.py')]
                    if action == 'recovery-start':
                        argv.append('--recovery')
                    if launch_ack and first_setup:
                        argv.append('--first-setup-normal-network')
                    elif launch_ack:
                        argv += ['--acknowledge-reviewed-unsigned-backend', '--enable-reviewed-backend-owner-execute']
                    proc = subprocess.Popen(argv,
                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        env=ENV, cwd=str(self.bases()[vm]), start_new_session=True, close_fds=True)
                with self.lock:
                    self.children[vm] = proc
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        if first_setup and self._runtime(vm).get('reason') == 'first-setup-finished':
                            raise AppError('首次设置已标记完成；没有用普通网络启动。', 'first_setup_finished', 409)
                        if launch_ack and not first_setup and self._runtime(vm).get('state') == 'awaiting_host_authorization':
                            raise AppError('后端未获得本机执行许可或启动未就绪；未启动 VM，也不会重试、移除隔离属性或改用普通网络。', 'host_authorization_required', 409)
                        raise AppError('受保护启动器提前退出；没有使用无保护网络回退。请查看应用日志。', 'launcher_exited', 500)
                    if self.inventory(fresh=True).get(vm, {}).get('State') == 'running':
                        self.event(vm, action, '恢复模式已启动，未附加宿主共享目录' if action == 'recovery-start'
                                   else 'VM 已运行：首次设置使用普通网络，未经过网络过滤' + (
                                       '；安装文件夹在客机「My Shared Files」里的 gold-installers'
                                       if self._environment(vm).get('version') == 3 else '') if first_setup
                                   else 'VM 已运行，保留原网络防护')
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
                    tool = self._inventory_tart()
                    if tool is None:
                        raise AppError('Tart 工具未就绪；未发送停止请求', 'tart_unavailable', 409)
                    r = self._run([str(tool), 'stop', vm, '--timeout', '10'], timeout=18)
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
            elif path == '/api/preinstall/capabilities':
                self._json(200, self.server.controller.preinstall_capabilities())
            elif path == '/api/preinstall/examples':
                self._json(200, self.server.controller.preinstall_examples())
            elif path in ('/', '/index.html', '/app.js', '/style.css', '/preinstall.js', '/preinstall.css'):
                name = 'index.html' if path in ('/', '/index.html') else path[1:]
                asset = STATIC / name
                if asset.is_symlink() or asset.resolve() != STATIC.resolve() / name:
                    raise AppError('资源不可用', 'asset_not_found', 404)
                raw = asset.read_bytes()
                mime = {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css'}[asset.suffix]
                self._headers(200, mime + '; charset=utf-8', len(raw))
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
            path = parsed.path
            max_wire = VPN_VALIDATE_MAX_WIRE if path == VPN_VALIDATE_PATH else 65536
            if not 0 <= length <= max_wire:
                raise AppError('请求过大或没有长度', 'invalid_length', 413)
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError('incomplete request')
                payload = json.loads(raw.decode('utf-8'), object_pairs_hook=strict_pairs,
                                     parse_constant=lambda x: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeError, RecursionError):
                raise AppError('JSON 格式错误') from None
            if path == VPN_VALIDATE_PATH:
                value = self.server.controller.validate_vpn(payload)
            elif path == '/api/preinstall/create':
                value = self.server.controller.create_preinstall(payload)
            elif path == '/api/preinstall/resume':
                value = self.server.controller.resume_preinstall(payload)
            elif path == '/api/preinstall/archive':
                value = self.server.controller.archive_preinstall(payload)
            elif path == '/api/build':
                value = self.server.controller.create_build(payload)
            elif path == '/api/pick-ipsw':
                value = self.server.controller.pick_ipsw(payload)
            elif path == '/api/pick-directory':
                value = self.server.controller.pick_directory(payload)
            elif path == '/api/reveal-directory':
                value = self.server.controller.reveal(payload)
            else:
                match = re.fullmatch(r'/api/vms/([^/]+)/(action|shares|delete|expand-disk)', unquote(path, errors='strict'))
                if not match:
                    raise AppError('未找到操作', 'not_found', 404)
                vm, route = match.groups()
                if route == 'expand-disk':
                    value = self.server.controller.expand_disk(vm, payload)
                elif route == 'delete':
                    value = self.server.controller.delete_vm(vm, payload)
                elif route == 'action':
                    value = self.server.controller.action(vm, payload)
                else:
                    value = self.server.controller.save_shares(vm, payload)
            self._json(202 if path.endswith(('/action','/delete')) or path in ('/api/build', '/api/preinstall/create', '/api/preinstall/resume') else 200, value)
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
