"""Explicit, durable new/rebuild jobs. Importing this module performs no VM work.

Each job is a separate process. A stopped/suspended predecessor is held by Tart's
storage flock and config POSIX lock at replacement. Installation is offline and
occurs BEFORE the predecessor is removed. No automatic retry of destructive work.
"""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import errno
import socket
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
import uuid

import managed_registry as registry
import process_identity
import setup_profile

HOME = registry.HOME
STATE = registry.STATE_DIR
TART_HOME = HOME / '.tart'
VM_ROOT = TART_HOME / 'vms'
TART = HOME / 'Applications/tart.app/Contents/MacOS/tart'
HERE = Path(__file__).resolve().parent
HELPER = HERE / 'CleanVMInstaller'
ENV = {'HOME': str(HOME), 'TART_HOME': str(TART_HOME), 'TART_NO_AUTO_PRUNE': '1',
       'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin', 'LANG': 'en_US.UTF-8',
       'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
ACTIVE = ('queued', 'preflight', 'downloading', 'inspecting', 'installing', 'provisioning', 'committing', 'deleting')
TERMINAL = ('awaiting_user_setup', 'awaiting_offline_preinstall', 'awaiting_first_desktop_acceptance', 'failed', 'interrupted', 'deleted')
OFFLINE_MODE = 'offline_validate'
PREINSTALL_MODE = 'preinstall'
DISK_GIB_MIN, DISK_GIB_MAX, DISK_GIB_DEFAULT = 30, 1024, 50
PREINSTALL_ACTIVE = ('queued', 'preflight', 'acquiring', 'inspecting', 'installing',
                     'awaiting_offline_preinstall', 'preinstalling', 'configuring_vpn',
                     'awaiting_system_authorization', 'verifying', 'preparing_runtime', 'publishing',
                     'vpn_resume_queued', 'resuming_vpn')


def is_active(job):
    return bool(job and (job.get('phase') in (PREINSTALL_ACTIVE if job.get('mode') == PREINSTALL_MODE else ACTIVE)
                or (job.get('mode') == PREINSTALL_MODE and job.get('phase') == 'awaiting_first_desktop_acceptance'
                    and not job.get('published') and job.get('pid'))))


def waiting_for_vpn(job):
    return bool(job and job.get('mode') == PREINSTALL_MODE and job.get('phase') == 'awaiting_vpn_configuration')


def offline_status_fields():
    """Restoration is not application preinstallation or delivery acceptance."""
    return {'system_restored': False, 'applications_preinstalled': False,
            'desktop_verified': False, 'guest_started': False,
            'credentials_copied': False, 'stage_path': None}


def timestamp(): return datetime.now(timezone.utc).isoformat()


def fingerprint(path):
    path = registry.safe_path(path)
    with path.open('rb') as f:
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()


def inventory_tool(*, state_dir=None, legacy=None):
    """Use the private, verified local Tart receipt, or the unchanged legacy path.

    A clean checkout can serve its authenticated UI before Tart is acquired.
    An invalid registered portable tool never silently falls back.
    """
    state = STATE if state_dir is None else Path(state_dir)
    existing = TART if legacy is None else Path(legacy)
    selected = registry.read_private(state / 'tart-tool.json')
    if selected is None:
        return existing if existing.is_file() and not existing.is_symlink() else None
    from preinstall_runtime import _tart_binding
    from host_artifacts import SPECS
    if type(selected) is not dict or set(selected) != {'version', 'executable_path', 'executable_sha256', 'receipt_path'} or type(selected.get('version')) is not int or selected['version'] != 1:
        raise ValueError('受审查的 Tart 工具记录无效')
    path = registry.safe_path(Path(selected['executable_path']))
    receipt_path = registry.safe_path(Path(selected['receipt_path']))
    attempt = receipt_path.parent
    if (attempt.parent != state / 'tools' or not re.fullmatch(r'tart-tool-[0-9a-f]{32}', attempt.name)
            or receipt_path.name != 'tart.json' or path != attempt / 'tart.app/Contents/MacOS/tart'):
        raise ValueError('Tart 工具路径与私有材料记录不匹配')
    receipt = registry.read_private(receipt_path)
    if (type(receipt) is not dict or receipt.get('executable_path') != str(path)
            or receipt.get('executable_sha256') != selected['executable_sha256']
            or receipt.get('notarized') is not True or receipt.get('source_kind') != 'pinned-public-archive'
            or receipt.get('archive_sha256') != SPECS['tart'].sha256 or receipt.get('version') != SPECS['tart'].version
            or receipt.get('team_id') != '9M2P8L4D89' or _tart_binding(path)['sha256'] != selected['executable_sha256']):
        raise ValueError('Tart 工具与受审查记录不一致')
    return path


def inventory():
    tool = inventory_tool()
    if tool is None:
        return {}
    r = subprocess.run([str(tool), 'list', '--format', 'json'], env=ENV, capture_output=True, text=True, timeout=20)
    if r.returncode: raise ValueError('无法读取当前 VM 清单，操作已取消')
    return {v['Name']: v for v in json.loads(r.stdout) if v.get('Source') == 'local'}


def validate_disk_gib(value):
    if type(value) is not int or not DISK_GIB_MIN <= value <= DISK_GIB_MAX:
        raise ValueError(f'新磁盘容量必须是 {DISK_GIB_MIN} 到 {DISK_GIB_MAX} GiB 的整数')
    return value


def validated_request(payload, known_names, host_cpu=None, host_memory=None):
    keys = {'mode', 'source_vm', 'name', 'cpu', 'memory_gib', 'disk_gib', 'ipsw', 'confirm_name', 'acknowledge_erase', 'acknowledge_setup', 'setup_profile', 'acknowledge_offline'}
    if type(payload) is not dict or set(payload) - keys: raise ValueError('新建请求格式错误')
    d = dict(payload)
    if d.get('mode') not in ('create', 'rebuild', OFFLINE_MODE): raise ValueError('请选择新建、彻底重建或离线验证')
    offline = d['mode'] == OFFLINE_MODE
    registry.validate_name(d.get('name'))
    if offline:
        if {'source_vm', 'confirm_name', 'acknowledge_erase', 'setup_profile'} & set(d):
            raise ValueError('离线验证仅限全新名称，不能指定旧 VM、删除确认或设置资料')
        if d.get('acknowledge_offline') is not True:
            raise ValueError('请确认仅恢复暂存系统，不开机、不迁移凭据，软件预装与桌面验收尚未完成')
        if any(existing.casefold() == d['name'].casefold() for existing in known_names):
            raise ValueError('此名称已存在；离线验证只能使用全新名称')
    d['disk_gib'] = validate_disk_gib(d.get('disk_gib', DISK_GIB_DEFAULT))
    for key, low, high, default in [('cpu', 2, host_cpu or os.cpu_count() or 2, 2),
                                    ('memory_gib', 4, host_memory or 64, 4)]:
        value = d.get(key, default)
        if type(value) is not int or not low <= value <= high: raise ValueError('CPU 或内存大小超出允许范围')
        d[key] = value
    if not offline and d.get('acknowledge_setup') is not True: raise ValueError('请确认首次 macOS 设置、客机安装及本地代理配置迁移说明')
    if d['mode'] == 'rebuild':
        old = d.get('source_vm')
        if type(old) is not str or old not in known_names: raise ValueError('只能重建列表中明确选中的 VM')
        registry.validate_name(old)
        if d.get('confirm_name') != old or d.get('acknowledge_erase') is not True:
            raise ValueError('重建请求必须对应所选旧 VM 并确认永久丢弃旧磁盘和暂停状态')
    elif d.get('source_vm') or d.get('confirm_name') or d.get('acknowledge_erase'):
        raise ValueError('新建操作不能指定待删除的 VM')
    else: d['source_vm'] = None
    ipsw = d.get('ipsw', 'latest')
    if type(ipsw) is not str: raise ValueError('恢复镜像路径无效')
    if offline and ipsw == 'latest': raise ValueError('离线验证仅接受已取得并核验的本地 IPSW，不自动下载 latest')
    if ipsw != 'latest':
        path = registry.safe_path(Path(ipsw))
        if not path.is_file() or path.suffix.lower() != '.ipsw': raise ValueError('请选择 Apple macOS IPSW 恢复镜像')
        if offline and path.stat().st_size <= 0: raise ValueError('本地 IPSW 为空，不能进行离线验证')
    d['ipsw'] = ipsw
    if not offline: d['setup_profile'] = setup_profile.validate(d.get('setup_profile'))
    return d


def source_identity(name):
    p = registry.safe_path(VM_ROOT / name)
    if not p.is_dir() or p.stat().st_uid != os.getuid(): raise ValueError('旧 VM 目录归属无效')
    cfg = registry.safe_path(p / 'config.json')
    c = json.loads(cfg.read_text())
    if c.get('os', 'darwin') != 'darwin': raise ValueError('此重建流程仅用于 macOS；不会把其他系统静默替换为 macOS')
    return {'device': p.stat().st_dev, 'inode': p.stat().st_ino, 'config_sha256': fingerprint(cfg)}


def validate_destination(d, values):
    name, old = d['name'], d['source_vm']
    for existing in values:
        if existing.casefold() == name.casefold() and existing != old:
            raise ValueError('此名称已存在；不会覆盖其他 VM')
    target = VM_ROOT / name
    registry.safe_path(target, False)
    if target.exists() and name != old: raise ValueError('目标目录已经存在')
    if old:
        if values.get(old, {}).get('State') not in ('stopped', 'suspended'):
            raise ValueError('请先正常关机或暂停旧 VM，再执行重建；不会自动强制停止')
        source_identity(old)


def job_alive(job):
    pid = job.get('pid')
    if type(pid) is not int or pid <= 1: return False
    args = process_identity.arguments(pid)
    entry = 'oneclick.py' if job.get('mode') == PREINSTALL_MODE else ('vm_deletion.py' if job.get('mode') == 'delete' else 'lifecycle.py')
    paths = {str(HERE / entry)}
    if not args or not any(p in args for p in paths): return False
    return any(args[i:i+2] == ['--worker', job.get('id')] for i in range(len(args)-1))


def status(*, state_dir=None):
    state = STATE if state_dir is None else Path(state_dir)
    path = state / 'build-current.json'
    d = registry.read_private(path, None)
    if not d: return None
    if type(d) is not dict or not re.fullmatch('[0-9a-f]{32}', str(d.get('id', ''))): raise ValueError('创建任务状态异常')
    queued_grace = False
    if d.get('phase') in ('queued', 'vpn_resume_queued') and d.get('pid') is None:
        try:
            stamp = d['updated_at'] if d['phase'] == 'vpn_resume_queued' else d['started_at']
            queued_grace = (datetime.now(timezone.utc) - datetime.fromisoformat(stamp)).total_seconds() < 10
        except (KeyError, TypeError, ValueError):
            pass
    persisted_recovery_required = d.get('recovery_required') is True
    if is_active(d) and not queued_grace and not job_alive(d):
        d = dict(d, phase='interrupted', message='上次任务进程已退出；没有自动重试或再次删除。请保留任务目录并检查日志。')
        if d.get('mode') == PREINSTALL_MODE and d.get('stage_path'):
            d.update(recovery_required=True, message='预装进程已退出；暂存内容需要人工核对，不自动重做或发布。')
    preinstall = d.get('offline_preinstall')
    if isinstance(preinstall, dict) and preinstall.get('active') is True:
        # This opt-in operation holds the lifecycle lock across all disk access.
        # A stale active flag must not permit a new job or an overwrite retry.
        offline_lock_held = False
        lock_fd = None
        try:
            lock_fd = os.open(str(registry.safe_path(state / 'build.lock')), os.O_RDONLY | os.O_NOFOLLOW)
            try: fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: offline_lock_held = True
        except (OSError, ValueError):
            pass
        finally:
            if lock_fd is not None: os.close(lock_fd)
        if not offline_lock_held:
            d = dict(d, phase='interrupted', recovery_required=True,
                     offline_preinstall=dict(preinstall, active=False),
                     message='离线预装进程已退出；暂存磁盘未发布、未启动。请检查复制及重挂验收证据，禁止自动覆盖重试。')
    if waiting_for_vpn(d) and os.path.lexists(state / 'build-jobs' / d['id'] / 'vpn-resume.json'):
        d = dict(d, phase='interrupted', recovery_required=True,
                 message='VPN 续接记录已存在但未排队；保留暂存盘，需核对任务记录，不自动重试。')
    journal = registry.read_private(state / 'build-jobs' / d['id'] / 'commit.json', None)
    complete = (type(journal) is dict and journal.get('phase') == 'committed_old_removed')
    if d.get('mode') == PREINSTALL_MODE:
        complete = (type(journal) is dict and type(journal.get('version')) is int and journal['version'] == 1
                    and journal.get('phase') == 'committed_new_registered' and journal.get('id') == d['id']
                    and journal.get('mode') == PREINSTALL_MODE and journal.get('name') == d.get('name')
                    and journal.get('environment_id') == d['id'] and journal.get('source_vm') is None)
        if complete and not persisted_recovery_required and d.get('published') is not True:
            d = dict(d, phase='awaiting_first_desktop_acceptance', published=True, stage_path=None,
                     progress=1, recovery_required=False, needs_host_security_authorization=True,
                     message='发布完成；首次启动和桌面/VPN 验收仍需另行进行。')
        if d.get('published') is True and not complete:
            d = dict(d, recovery_required=True, message='缺少完整发布记录；禁止启动或覆盖该 VM。')
    if d.get('mode') == 'delete':
        complete = (complete and type(journal.get('version')) is int and journal['version'] == 1
                    and journal.get('id') == d['id'] and journal.get('mode') == 'delete'
                    and journal.get('source_vm') == d.get('source_vm'))
    if journal is not None and not complete:
        d = dict(d, recovery_required=True)
        if not is_active(d):
            d['message'] = '事务未完整结束，已锁定相关 VM 和后续操作。请保留任务记录，核对目录和注册状态；不会自动重试。'
    return d


def start(payload, known_names):
    mem = subprocess.run(['/usr/sbin/sysctl', '-n', 'hw.memsize'], capture_output=True, text=True, check=True)
    d = validated_request(payload, known_names, host_memory=int(mem.stdout) // 1024**3)
    values = inventory(); validate_destination(d, values)
    if not HELPER.is_file(): raise ValueError('离线 macOS 安装组件未就绪，未删除任何 VM')
    if d['mode'] != OFFLINE_MODE and not (HERE / 'provisioning.py').is_file(): raise ValueError('网络与软件配置组件未就绪')
    registry.private_dir(STATE)
    lockpath = registry.safe_path(STATE / 'build.lock', False)
    fd = os.open(str(lockpath), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('已有新建/重建任务进行中，请等待完成') from None
        old = status()
        if old and old.get('recovery_required'): raise ValueError('上次替换事务需要人工恢复，未开始新任务')
        if waiting_for_vpn(old): raise ValueError('请先完成已暂存 VM 的 VPN 配置')
        if is_active(old): raise ValueError('已有任务正在运行')
        jid = uuid.uuid4().hex
        jobdir = STATE / 'build-jobs' / jid; registry.private_dir(jobdir)
        d['source_identity'] = source_identity(d['source_vm']) if d['source_vm'] else None
        d['id'] = jid
        registry.write_private(jobdir / 'request.json', d)
        initial = {'id': jid, 'mode': d['mode'], 'source_vm': d['source_vm'], 'name': d['name'],
                   'phase': 'queued', 'message': '已接收请求，先检查镜像和软件材料；尚未删除旧 VM',
                   'progress': None, 'pid': None, 'started_at': timestamp(), 'updated_at': timestamp(),
                   'old_deleted': False}
        if d['mode'] == OFFLINE_MODE:
            initial.update(offline_status_fields())
            initial['message'] = '已接收离线验证请求；仅恢复全新暂存磁盘，不开机、不预装软件、不迁移凭据'
        registry.write_private(STATE / 'build-current.json', initial)
        registry.write_private(jobdir / 'status.json', initial)
        try:
            with (jobdir / 'worker.log').open('x') as log:
                process = subprocess.Popen(['/usr/bin/python3', '-B', str(HERE / 'lifecycle.py'), '--worker', jid, '--lock-fd', str(fd)],
                    env=ENV, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    start_new_session=True, close_fds=True, pass_fds=(fd,))
        except Exception:
            initial.update(phase='failed', message='任务进程未能启动；未恢复或发布系统，请检查任务日志。', updated_at=timestamp())
            registry.write_private(STATE / 'build-current.json', initial)
            registry.write_private(jobdir / 'status.json', initial)
            raise ValueError('任务进程未能启动，未修改任何 VM') from None
        # The child inherits the flock; parent only closes its descriptor.
        return {'ok': True, 'job_id': jid, 'message': '任务已开始；可关闭窗口，重新打开后查看进度'}
    finally: os.close(fd)


def apple_url(url):
    p = urlsplit(url)
    return p.scheme == 'https' and p.port in (None, 443) and not p.username and not p.password and bool(p.hostname) and (p.hostname.endswith('.apple.com') or p.hostname.endswith('.cdn-apple.com'))


class AppleRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not apple_url(newurl): raise ValueError('Apple 镜像下载跳转到未批准地址，已拒绝')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def helper_json(args):
    r = subprocess.run([str(HELPER)] + args, env=ENV, capture_output=True, text=True, timeout=120)
    if r.returncode: raise ValueError('Apple 恢复镜像检查失败；未删除旧 VM')
    for line in reversed(r.stdout.splitlines()):
        try:
            d = json.loads(line)
            if isinstance(d, dict): return d
        except ValueError: pass
    raise ValueError('安装组件没有返回有效镜像信息')


def offline_image(d, update):
    if d['ipsw'] != 'latest': return registry.safe_path(Path(d['ipsw']))
    info = helper_json(['--latest']); url = info.get('url')
    if type(url) is not str or not apple_url(url): raise ValueError('未取得受信任的 Apple 恢复镜像地址')
    cache = STATE / 'restore-images'; registry.private_dir(cache)
    path = cache / (hashlib.sha256(url.encode()).hexdigest() + '.ipsw')
    if path.exists():
        registry.safe_path(path)
        return path
    update('downloading', '下载 Apple macOS 恢复镜像；不会删除旧 VM', None)
    partial = cache / (d['id'] + '.download')
    registry.safe_path(partial, False)
    if partial.exists(): raise ValueError('下载暂存文件已存在，拒绝覆盖')
    opener = build_opener(AppleRedirect())
    with opener.open(Request(url, headers={'User-Agent': 'GoldVMManager/1.1'}), timeout=60) as r, partial.open('xb') as f:
        if not apple_url(r.url): raise ValueError('恢复镜像来源未通过检查')
        total = int(r.headers.get('Content-Length', '0'))
        if not 0 < total <= 40 * 1024**3: raise ValueError('镜像大小缺失或超过允许范围')
        downloaded = 0; last = 0
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk: break
            downloaded += len(chunk)
            if downloaded > total: raise ValueError('下载大小与声明不符')
            f.write(chunk)
            if time.monotonic() - last > 2:
                update('downloading', '正在下载 Apple 恢复镜像', round(downloaded / total, 4)); last = time.monotonic()
        f.flush(); os.fsync(f.fileno())
    if downloaded != total: raise ValueError('恢复镜像下载不完整；旧 VM 未删除')
    registry.safe_path(partial); registry.safe_path(path, False)
    if path.exists(): raise ValueError('恢复镜像缓存发生变化')
    os.rename(str(partial), str(path))
    return path


def verify_install_output(stage, request):
    registry.safe_path(stage)
    for name in ('disk.img', 'nvram.bin', 'config.json', '.clean-vm-installer.complete.json'):
        p = registry.safe_path(stage / name)
        s = p.stat()
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_size <= 0:
            raise ValueError('新系统输出文件权限或类型不正确，旧 VM 未删除')
    receipt = registry.read_private(stage / '.clean-vm-installer.complete.json')
    if (type(receipt) is not dict or receipt.get('status') != 'complete' or type(receipt.get('schemaVersion')) is not int
            or receipt['schemaVersion'] != 1 or receipt.get('installer') != 'CleanVMInstaller'
            or any(type(receipt.get(k)) is not int or receipt[k] != 0 for k in ('networkDeviceCount','directorySharingDeviceCount','socketDeviceCount'))):
        raise ValueError('安装完成凭据无效，旧 VM 未删除')
    c = registry.read_private(stage / 'config.json')
    if c.get('os') != 'darwin' or c.get('arch') != 'arm64' or c.get('diskFormat') != 'raw' or type(c.get('version')) is not int or c['version'] != 1:
        raise ValueError('新系统磁盘配置不兼容')
    for key in ('cpuCountMin', 'cpuCount', 'memorySizeMin', 'memorySize'):
        if type(c.get(key)) is not int or c[key] <= 0:
            raise ValueError('新系统资源字段不完整')
    if c['cpuCount'] < c['cpuCountMin'] or c['memorySize'] < c['memorySizeMin']:
        raise ValueError('新系统资源低于镜像要求')
    display = c.get('display')
    if type(display) is not dict or display.get('unit') != 'px' or type(display.get('width')) is not int or type(display.get('height')) is not int or min(display['width'], display['height']) <= 0:
        raise ValueError('新系统显示器配置无效')
    for key in ('ecid','hardwareModel'):
        try:
            if type(c[key]) is not str or not base64.b64decode(c[key], validate=True): raise ValueError()
        except (KeyError, ValueError): raise ValueError('新系统机器标识无效') from None
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', c.get('macAddress','')):
        raise ValueError('新系统 MAC 格式无效')
    if (int(c['macAddress'][:2],16) & 3) != 2: raise ValueError('新 MAC 必须为随机本地管理单播地址')
    if c.get('cpuCount') != request['cpu'] or c.get('memorySize') != request['memory_gib'] * 1024**3:
        raise ValueError('新系统资源大小不匹配')
    if (stage / 'disk.img').stat().st_size != validate_disk_gib(request.get('disk_gib')) * 1024**3: raise ValueError('新磁盘容量不匹配')
    return c


def new_identity_check(stage):
    config = json.loads(registry.safe_path(stage / 'config.json').read_text())
    if not isinstance(config.get('ecid'), str) or not isinstance(config.get('macAddress'), str): raise ValueError('新机器身份缺失')
    for entry in VM_ROOT.iterdir():
        if not entry.is_dir() or entry.is_symlink(): continue
        p = entry / 'config.json'
        if not p.is_file() or p.is_symlink(): continue
        old = json.loads(p.read_text())
        if old.get('ecid') == config['ecid'] or str(old.get('macAddress', '')).lower() == config['macAddress'].lower():
            raise ValueError('新机器身份与现有 VM 重复，拒绝发布')
    return config


def stale_control_socket(path):
    """Called ONLY under Tart storage/config locks, before moving the old VM.

    Tart leaves a stream control.sock after exit. A live listener or ambiguous
    failure must block replacement. No control protocol bytes are transmitted.
    Use a relative address in this dedicated worker to respect Darwin sun_path,
    including long Unicode VM names. Never probe again after moving the old VM.
    """
    target = path / 'control.sock'
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or info.st_dev != path.stat().st_dev or info.st_nlink != 1):
        raise ValueError('旧 VM 控制套接字类型或归属异常；未替换')
    identity = (info.st_dev, info.st_ino)
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    cwd_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
    old_dir_fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchdir(old_dir_fd)
        try:
            probe.connect('control.sock')
        except OSError as error:
            if error.errno != errno.ECONNREFUSED:
                raise ValueError('无法确认旧 VM 控制套接字已停止；未替换') from None
        else:
            raise ValueError('旧 VM 控制服务仍在监听；请先正常关闭后再重建')
    finally:
        os.fchdir(cwd_fd)
        os.close(old_dir_fd)
        os.close(cwd_fd)
        probe.close()
    current = target.lstat()
    if ((current.st_dev, current.st_ino) != identity or not stat.S_ISSOCK(current.st_mode)
            or current.st_uid != os.getuid() or current.st_nlink != 1):
        raise ValueError('旧 VM 控制套接字已变化；未替换')
    return identity


def legacy_ownership_marker(root, path, info):
    """True only for a root-owned start marker of the retired guest-ownership helper.

    VMs published before 2026-11-20 keep .guest-ownership/<32 hex>/apply.started
    and verify.started, written by that root helper with owner 0. Their user-owned
    directory lets the user remove them; no other foreign-owned entry is accepted.
    """
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    return (len(parts) == 3 and parts[0] == '.guest-ownership' and re.fullmatch(r'[0-9a-f]{32}', parts[1]) is not None
            and parts[2] in ('apply.started', 'verify.started') and info.st_uid == 0
            and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536)


def check_tree(path, *, control_socket_identity=None, legacy_ownership_markers=False):
    registry.safe_path(path)
    device = path.stat().st_dev
    seen_socket = False
    def unreadable(_error):
        raise ValueError('无法完整检查旧 VM 目录；拒绝递归删除')
    for folder, dirs, files in os.walk(str(path), followlinks=False, onerror=unreadable):
        for name in dirs + files:
            p = Path(folder) / name; s = p.lstat()
            allowed_socket = (p == path / 'control.sock' and stat.S_ISSOCK(s.st_mode)
                              and control_socket_identity is not None
                              and (s.st_dev, s.st_ino) == control_socket_identity and s.st_nlink == 1)
            if allowed_socket:
                seen_socket = True
            owned = s.st_uid == os.getuid() or (legacy_ownership_markers and legacy_ownership_marker(path, p, s))
            if s.st_dev != device or not owned or stat.S_ISLNK(s.st_mode) or not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) or allowed_socket):
                raise ValueError('旧 VM 目录含链接、挂载或异常文件；拒绝递归删除')
    if control_socket_identity is not None and not seen_socket:
        raise ValueError('已确认的旧 VM 控制套接字已变化；拒绝清理')


def commit(d, stage, base, update):
    if d.get('mode') == OFFLINE_MODE: raise ValueError('离线验证只保留暂存磁盘，禁止发布或注册 VM')
    with registry.state_lock(STATE):
        return _commit_locked(d, stage, base, update)


def _commit_locked(d, stage, base, update):
    """Runs only in a dedicated worker; never close another old config FD while locked."""
    registry.safe_path(TART_HOME); registry.safe_path(VM_ROOT)
    storage_fd = os.open(str(TART_HOME), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    config_fd = None
    control_socket_identity = None
    try:
        fcntl.flock(storage_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = VM_ROOT / d['source_vm'] if d['source_vm'] else None
        target = VM_ROOT / d['name']
        registry.safe_path(stage); registry.safe_path(target, False)
        if old:
            registry.safe_path(old)
            expected = d['source_identity']; s = old.stat()
            if (s.st_dev, s.st_ino) != (expected['device'], expected['inode']): raise ValueError('旧 VM 目录已经变化，未删除')
            config_fd = os.open(str(registry.safe_path(old / 'config.json')), os.O_RDWR | os.O_NOFOLLOW)
            fcntl.lockf(config_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            raw = os.read(config_fd, 1024 * 1024)
            if hashlib.sha256(raw).hexdigest() != expected['config_sha256']: raise ValueError('旧 VM 配置已经变化，未删除')
            control_socket_identity = stale_control_socket(old)
            check_tree(old, control_socket_identity=control_socket_identity)
        if target.exists() and target != old: raise ValueError('目标名称已被占用，未覆盖')
        reg = registry.load_registry()
        shares_path = STATE / 'config.json'
        shares = registry.read_private(shares_path, {'version': 1, 'vms': {}})
        if type(shares) is not dict or set(shares) != {'version', 'vms'} or shares['version'] != 1 or type(shares['vms']) is not dict:
            raise ValueError('共享配置无效，拒绝替换')
        tombstone = stage.parent / 'old-environment'
        registry.safe_path(tombstone, False)
        if tombstone.exists(): raise ValueError('清理暂存目标已存在')
        if d['source_vm']:
            reg['vms'].pop(d['source_vm'], None)
            shares['vms'].pop(d['source_vm'], None)
            if d['source_vm'] != d['name'] and d['source_vm'] not in reg['retired']: reg['retired'].append(d['source_vm'])
        reg['retired'] = [x for x in reg['retired'] if x != d['name']]
        reg['vms'][d['name']] = {'environment_id': base.name}
        shares['vms'][d['name']] = {'shares': []}
        registry.validate_registry(reg)
        update('committing', '新系统已安装，正在按确认替换；请勿退出宿主或断电', None)
        journal = {'new': str(stage), 'target': str(target), 'old': str(old) if old else None,
                   'tombstone': str(tombstone), 'environment_id': base.name, 'phase': 'before_replace'}
        journal_path = STATE / 'build-jobs' / d['id'] / 'commit.json'
        registry.write_private(journal_path, journal)
        for filename in ('disk.img', 'nvram.bin', 'config.json', '.clean-vm-installer.complete.json'):
            output = stage / filename
            if output.exists():
                registry.safe_path(output)
                new_fd = os.open(str(output), os.O_RDWR | os.O_NOFOLLOW)
                try:
                    os.fsync(new_fd)
                finally:
                    os.close(new_fd)
        registry.sync_directory(stage)
        registry.sync_directory(stage.parent)
        if old:
            # Every absolute source/destination has been verified above, with old config locked.
            os.rename(str(old), str(tombstone))
            registry.sync_directory(VM_ROOT)
            registry.sync_directory(stage.parent)
        os.rename(str(stage), str(target))
        registry.sync_directory(VM_ROOT)
        registry.sync_directory(stage.parent)
        journal['phase'] = 'new_published'; registry.write_private(journal_path, journal)
        registry.write_private(registry.REGISTRY_PATH, reg)
        registry.write_private(shares_path, shares)
        if old:
            if tombstone.resolve(strict=True) != stage.parent / 'old-environment' or tombstone.is_symlink(): raise ValueError('旧磁盘清理路径身份不符')
            s = tombstone.stat()
            if (s.st_dev, s.st_ino) != (expected['device'], expected['inode']): raise ValueError('旧磁盘清理对象变化')
            check_tree(tombstone, control_socket_identity=control_socket_identity)
            shutil.rmtree(str(tombstone))
            registry.sync_directory(stage.parent)
        journal['phase'] = 'committed_old_removed'; registry.write_private(journal_path, journal)
    finally:
        if config_fd is not None: os.close(config_fd)
        os.close(storage_fd)


def revalidate_offline_request(d, current, values):
    """Recheck the stored request, distinguishing internal nulls from API inputs."""
    if (current.get('phase') != 'queued'
            or any(current.get(key) != d.get(key) for key in ('id', 'mode', 'name', 'source_vm'))
            or d.get('source_vm') is not None or d.get('source_identity') is not None):
        raise ValueError('离线验证任务状态或源输入已变化，拒绝恢复或重试')
    payload = dict(d)
    for key in ('id', 'source_vm', 'source_identity'): payload.pop(key, None)
    mem = subprocess.run(['/usr/sbin/sysctl', '-n', 'hw.memsize'], capture_output=True, text=True, check=True)
    checked = validated_request(payload, values, host_memory=int(mem.stdout) // 1024**3)
    return dict(checked, id=d['id'], source_identity=None)


def worker(jid, lock_fd):
    if not re.fullmatch('[0-9a-f]{32}', jid): raise ValueError('任务标识无效')
    # Validate inherited lock descriptor (a private regular file), keep alive to exit.
    s = os.fstat(lock_fd)
    expected_lock = registry.safe_path(STATE / 'build.lock').stat()
    if (s.st_dev, s.st_ino) != (expected_lock.st_dev, expected_lock.st_ino) or not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_nlink != 1: raise ValueError('任务锁无效')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.umask(0o077)
    jobdir = registry.safe_path(STATE / 'build-jobs' / jid)
    current = registry.read_private(STATE / 'build-current.json')
    if type(current) is not dict or current.get('id') != jid: raise ValueError('任务状态冲突')
    offline = current.get('mode') == OFFLINE_MODE
    if offline:
        if current.get('phase') != 'queued': raise ValueError('离线验证不能自动恢复或重复执行已有任务')
        current.update(offline_status_fields())
        current['old_deleted'] = False
    current['pid'] = os.getpid()
    def update(phase, message, progress=None):
        current.update(phase=phase, message=message, progress=progress, updated_at=timestamp())
        registry.write_private(STATE / 'build-current.json', current)
        registry.write_private(jobdir / 'status.json', current)
    try:
        d = registry.read_private(jobdir / 'request.json')
        if type(d) is not dict or d.get('id') != jid: raise ValueError('任务请求无效或状态冲突')
        if current.get('mode', d.get('mode')) != d.get('mode'): raise ValueError('任务模式已变化，拒绝执行')
        validate_disk_gib(d.get('disk_gib'))  # Recheck the persisted size before any installer work.
        offline = d.get('mode') == OFFLINE_MODE
        values = inventory()
        if offline:
            d = revalidate_offline_request(d, current, values)
        update('preflight', '检查本地镜像、暂存空间和全新名称；不准备软件或迁移凭据' if offline else '检查软件材料、磁盘空间和旧 VM 状态；尚未删除任何 VM')
        validate_destination(d, values)
        if d['source_vm'] and source_identity(d['source_vm']) != d['source_identity']: raise ValueError('旧 VM 身份已变化，操作取消')
        free = shutil.disk_usage(str(TART_HOME)).free
        if free < (d['disk_gib'] + 20) * 1024**3: raise ValueError('可用空间不足以安全暂存新系统与恢复镜像；未删除旧 VM')
        if offline:
            # No downloader, provisioning import, host credentials or environment setup.
            image = registry.safe_path(Path(d['ipsw']))
            image_stat = image.stat()
        else:
            import provisioning
            provisioning.preflight()
            image = offline_image(d, update)
        update('inspecting', '检查 Apple 镜像兼容性及所选 CPU／内存；不自动调高配置')
        info = helper_json(['--inspect', '--ipsw', str(image)])
        registry.write_private(jobdir / 'image-inspection.json', info)
        if (type(info) is not dict or info.get('supported') is not True
                or any(type(info.get(k)) is not int or info[k] <= 0 for k in ('minimumCPUCount', 'minimumMemorySize'))):
            raise ValueError('此 Apple 恢复镜像不支持当前宿主，旧环境未删除')
        if d['cpu'] < info['minimumCPUCount'] or d['memory_gib'] * 1024**3 < info['minimumMemorySize']:
            raise ValueError('所选 CPU 或内存低于此 macOS 镜像要求；请手动调整后重试')
        if offline:
            # Compatibility inspection is not provenance/signature verification.
            now = registry.safe_path(image).stat()
            if any(getattr(now, key) != getattr(image_stat, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                raise ValueError('本地 IPSW 在兼容性检查期间已变化，拒绝恢复')
        stage_parent = TART_HOME / '.gold-manager-staging' / jid; registry.private_dir(stage_parent)
        stage = registry.safe_path(stage_parent / 'new-environment', False); stage.mkdir(mode=0o700)
        if offline: current['stage_path'] = str(stage)
        base = STATE / 'environments' / jid
        update('installing', '离线安装全新 macOS：无网卡、无共享、独立磁盘和机器身份', 0)
        command = [str(HELPER), '--create', '--directory', str(stage), '--ipsw', str(image), '--cpu', str(d['cpu']), '--memory-gib', str(d['memory_gib']), '--disk-gib', str(d['disk_gib'])]
        saw_complete = False
        with (jobdir / 'installer.log').open('x') as err:
            proc = subprocess.Popen(command, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err, text=True, pass_fds=(lock_fd,))
            for line in proc.stdout:
                try: event = json.loads(line)
                except ValueError: continue
                if type(event) is not dict: continue
                if event.get('event') == 'complete' and type(event.get('schemaVersion')) is int and event['schemaVersion'] == 1:
                    saw_complete = True
                percent = event.get('percent')
                progress = percent / 100 if type(percent) in (int, float) else None
                if isinstance(progress, (int, float)) and 0 <= progress <= 1:
                    update('installing', '正在离线安装 macOS；旧环境尚未删除', progress)
            result = proc.wait()
        if result or not saw_complete:
            raise ValueError('全新 macOS 安装未确认完成；旧 VM 未删除。请检查安装日志')
        verify_install_output(stage, d)
        new = new_identity_check(stage)
        if new.get('cpuCount') != d['cpu'] or new.get('memorySize') != d['memory_gib'] * 1024**3: raise ValueError('安装后资源设置不匹配，未发布 VM')
        if offline:
            # Recheck concurrent name use, but never move, register, share or boot.
            validate_destination(d, inventory())
            current['system_restored'] = True
            update('awaiting_offline_preinstall', '仅全新系统恢复及隔离输出验证完成；磁盘留在暂存区。尚未预装应用、未开机、未验收桌面、未复制凭据；这不是交付。', 1)
            return
        update('provisioning', '准备专属网络防护和只读安装材料，不导入旧身份库')
        registry.private_dir(base.parent)
        prepared = provisioning.prepare_environment(d['name'], stage / 'config.json', base, None)
        metadata = registry.read_private(base / 'environment.json')
        metadata['setup_profile'] = setup_profile.validate(d.get('setup_profile'))
        registry.write_private(base / 'setup/profile.json', metadata['setup_profile'])
        metadata['setup_sha256']['profile.json'] = fingerprint(base / 'setup/profile.json')
        registry.write_private(base / 'environment.json', metadata)
        registry.sync_directory(base / 'setup')
        registry.sync_directory(base)
        registry.sync_directory(base.parent)
        registry.write_private(jobdir / 'preparation.json', prepared)
        # Recheck predecessor immediately before commit; locks cover final replacement.
        validate_destination(d, inventory())
        commit(d, stage, base, update)
        current['old_deleted'] = bool(d['source_vm'])
        update('awaiting_user_setup', '新 VM 已创建。请启动，完成 macOS 初始设置，再运行只读 setup 目录中的安装向导。软件/代理验收尚未完成。', 1)
    except Exception as error:
        if offline:
            current.update({key: value for key, value in offline_status_fields().items() if key != 'stage_path'})
            current.setdefault('stage_path', None)
            current['old_deleted'] = False
        # Only controlled ValueErrors may be rendered; subprocess output/credentials never pass through.
        message = str(error) if isinstance(error, ValueError) else '任务失败（' + type(error).__name__ + '）；没有自动重试。请检查任务日志和提交记录。'
        update('failed', message[:450])
        print('Job stopped:', type(error).__name__, flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--worker', required=True)
    p.add_argument('--lock-fd', type=int, required=True)
    a = p.parse_args()
    worker(a.worker, a.lock_fd)
