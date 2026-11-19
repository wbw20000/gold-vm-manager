"""Fresh-only user-driven preinstallation. No host profile import or auto first boot.

A single inherited lifecycle flock covers acquisition through publication. Disk
writers retain their own generation/config locks. Failures keep their artifacts;
neither a failed job nor a half-published transaction is automatically replayed.
"""
import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import unicodedata
import uuid

import error_codes
import managed_registry as registry
import lifecycle
import vpn_store

HERE = Path(__file__).resolve().parent
MODE = 'preinstall'
ID = re.compile(r'[0-9a-f]{32}\Z')
ACTIVE = lifecycle.PREINSTALL_ACTIVE
ACKS = ('acknowledge_preinstall', 'acknowledge_network_policy', 'acknowledge_guest_autoconfigure')
KEYS = frozenset(('name', 'cpu', 'memory_gib', 'disk_gib', 'ipsw', 'vpn_configuration_id',
                  'download_loopback_proxy', 'acknowledge_normalization', 'defer_vpn') + ACKS)
RESUME_KEYS = frozenset(('job_id', 'vpn_configuration_id', 'acknowledge_normalization') + ACKS[1:])
PAUSE_PHASE = 'awaiting_vpn_configuration'
RESUME_QUEUED = 'vpn_resume_queued'
MIB = 1024 ** 2
# Fixed product keys of the reviewed application materials and their UI names.
MATERIAL_LABELS = {'ccbaga': 'CCBaga', 'clashVergeRev': 'Clash Verge', 'claudeDesktop': 'Claude Desktop'}
_MATERIAL_STAGES = {'quarantining': '正在为 {} 标记下载来源', 'extracting': '正在解包 {}',
                    'verifying': '正在校验 {} 的签名与公证', 'revalidating': '正在重新校验已缓存的 {}'}
STAGE_FILES = ('disk.img', 'config.json', 'nvram.bin', '.clean-vm-installer.complete.json', '.offline-preinstall.complete.json')


class OneClickError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _need(value, code):
    if not value:
        raise OneClickError(code)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _env(home, tart_home):
    return {'HOME': str(home), 'TART_HOME': str(tart_home), 'TART_NO_AUTO_PRUNE': '1',
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8',
            'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}


def _regular(path):
    path = registry.safe_path(Path(path))
    s = path.stat()
    _need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1
          and not s.st_mode & 0o077, 'unsafe-private-file')
    return s


def _stamp(path):
    s = _regular(path)
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _lock(fd, state_dir):
    _need(type(fd) is int and fd >= 0, 'invalid-lifecycle-lock')
    expected = _regular(state_dir / 'build.lock')
    actual = os.fstat(fd)
    _need(stat.S_ISREG(actual.st_mode) and actual.st_uid == os.getuid()
          and not actual.st_mode & 0o077 and actual.st_nlink == 1
          and (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
          'lifecycle-lock-identity-mismatch')
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _name_key(value):
    return unicodedata.normalize('NFC', value).casefold()


def _safe_tart_root(path, *, create=False):
    path = registry.safe_path(path, not create)
    if create and not path.exists():
        registry.private_dir(path)
    s = path.lstat()
    _need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid()
          and stat.S_IMODE(s.st_mode) in (0o700, 0o755), 'unsafe-tart-storage-root')
    return path


def _host_memory():
    memory = subprocess.run(['/usr/sbin/sysctl', '-n', 'hw.memsize'], capture_output=True,
                            text=True, check=True, timeout=10)
    return int(memory.stdout) // 1024**3


def names_on_disk(tart_home):
    """Bootstrap-safe name inventory; no Tart binary or old disk access required."""
    root = registry.safe_path(Path(tart_home) / 'vms', False)
    if not root.exists():
        return set()
    _safe_tart_root(root)
    return {p.name for p in root.iterdir()}


def validated_request(payload, known_names, *, host_cpu=None, host_memory=64):
    _need(type(payload) is dict and not set(payload) - KEYS, 'invalid-preinstall-request')
    d = dict(payload)
    registry.validate_name(d.get('name'))
    defer = d.get('defer_vpn', False)
    _need(type(defer) is bool, 'invalid-defer-vpn-choice')
    if defer:
        _need(d.get(ACKS[0]) is True and not any(k in d for k in ACKS[1:] +
              ('vpn_configuration_id', 'acknowledge_normalization')), 'exclusive-deferred-preinstall-consent-required')
    else:
        _need(all(d.get(k) is True for k in ACKS), 'explicit-preinstall-consent-required')
    _need(not any(_name_key(n) == _name_key(d['name']) for n in set(known_names) | set(registry.LEGACY_NAMES)), 'fresh-name-required')
    _need(type(d.get('acknowledge_normalization', False)) is bool, 'invalid-normalization-consent')
    for key, low, high, default in (
            ('cpu', 2, host_cpu or os.cpu_count() or 2, 2),
            ('memory_gib', 4, host_memory, 4), ('disk_gib', 50, 1024, 50)):
        value = d.get(key, default)
        _need(type(value) is int and low <= value <= high, 'invalid-resource-size')
        d[key] = value
    ident = d.get('vpn_configuration_id')
    _need(defer or (type(ident) is str and ID.fullmatch(ident)), 'validated-vpn-configuration-required')
    image = d.get('ipsw', 'reviewed')
    _need(type(image) is str, 'invalid-restore-image')
    if image != 'reviewed':
        path = registry.safe_path(Path(image))
        s = path.stat()
        _need(str(path) == image and not any(ord(x) < 32 or ord(x) == 127 for x in image)
              and path.suffix.lower() == '.ipsw' and stat.S_ISREG(s.st_mode)
              and s.st_nlink == 1 and s.st_size > 0, 'invalid-restore-image')
    d['ipsw'] = image
    proxy = d.get('download_loopback_proxy')
    _need(proxy is None or (type(proxy) is str and re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}', proxy)
                           and 1 <= int(proxy.rsplit(':', 1)[1]) <= 65535), 'invalid-explicit-download-proxy')
    d['download_loopback_proxy'] = proxy
    return dict(d, mode=MODE, source_vm=None, source_identity=None)


def capabilities():
    import host_tools
    from preinstall_materials import capability_report
    from guest_app_pins import reviewed_manifests
    platform = capability_report()
    try:
        prerequisites = host_tools.source_prerequisites()
        prerequisites_ready = True
    except Exception:
        prerequisites = {'status': 'missing-or-unavailable', 'notarized': False}
        prerequisites_ready = False
    required = ('offline_vpn.py', 'guest_ownership.py', 'vpn_store.py', 'preinstall_runtime.py')
    complete = all((HERE / name).is_file() for name in required)
    # Compiled app resources are checked again by resolve_helpers at use, not trusted here.
    source_or_bundle = all((HERE / name).is_file() for name in
                           ('CleanVMInstaller', 'GuestVPNBootstrap', 'GuestOwnershipHelper')) or all(
                           (HERE / name).is_file() for name in
                           ('CleanVMInstaller.swift', 'GuestVPNBootstrap.swift', 'GuestOwnershipHelper.swift'))
    checks = [
        {'id': 'platform', 'ready': platform['ready'], 'message': '仅支持已审查的 Apple Silicon / macOS 26.6.2 磁盘格式'},
        {'id': 'implementation', 'ready': complete and source_or_bundle, 'message': '完整预装与首次登录组件必须齐备'},
        {'id': 'prerequisites', 'ready': prerequisites_ready, 'message': '需可用的系统 Python、Ruby/Psych 与 Apple 命令行开发工具'},
        {'id': 'system-authorizations', 'ready': True, 'message': '需本人完成宿主文件归属授权、首次系统设置及客机服务授权'},
    ]
    # source_prerequisites is a diagnostic report, not authorization to execute downloaded tools.
    return {'ready': all(c['ready'] for c in checks), 'checks': checks,
            'supported_tuples': platform['supported_tuples'],
            'applications': [{'name': a.name, 'version': a.short_versions[0] if a.short_versions else m.version}
                             for m in reviewed_manifests() for a in m.expected_apps],
            'source_prerequisites': prerequisites,
            'limitations': ['下载/复制失败保留材料，不自动续传或覆盖重试。',
                            '首次启动另行确认；原版 gvproxy 未公证，默认禁止启动，需单独安全确认。',
                            '配置导入、系统授权、桌面验收和 VPN 连通分别记录；未提供真实节点不能验收连通。']}


def examples():
    directory = HERE / 'examples' / 'vpn'
    yaml = registry.safe_path(directory / 'clash.yaml').read_text(encoding='utf-8')
    fields = json.loads(registry.safe_path(directory / 'fields.json').read_text(encoding='utf-8'))
    return {'yaml': yaml, 'fields': fields}


def start(payload, *, state_dir=None, tart_home=None):
    state = Path(state_dir) if state_dir is not None else registry.STATE_DIR
    home = Path(tart_home) if tart_home is not None else registry.HOME / '.tart'
    registry.private_dir(state)
    _safe_tart_root(home, create=True)
    _safe_tart_root(home / 'vms', create=True)
    known = names_on_disk(home) | set(registry.load_registry(state / 'registry.json')['vms'])
    d = validated_request(payload, known, host_memory=_host_memory())
    _need(capabilities()['ready'], 'preinstall-capabilities-unavailable')
    defer = d.get('defer_vpn') is True
    if not defer:
        stored = vpn_store.load_configuration(state, d['vpn_configuration_id'])
        _need(stored.bound_job is None, 'configuration-already-bound')
        _need(not stored.summary['normalization_required'] or d.get('acknowledge_normalization') is True,
              'explicit-normalization-consent-required')
    fd = os.open(str(registry.safe_path(state / 'build.lock', False)), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        _lock(fd, state)
        old = lifecycle.status(state_dir=state)
        _need(not old or (not old.get('recovery_required') and not lifecycle.is_active(old)
                         and not lifecycle.waiting_for_vpn(old)
                         and not (old.get('offline_preinstall') or {}).get('active')),
              'existing-job-requires-completion-or-review')
        known = names_on_disk(home) | set(registry.load_registry(state / 'registry.json')['vms'])
        _need(_name_key(d['name']) not in {_name_key(n) for n in known}, 'fresh-name-required')
        jid = uuid.uuid4().hex
        jobdir = state / 'build-jobs' / jid
        registry.private_dir(jobdir)
        d['id'] = jid
        if not defer:
            vpn_store.claim_configuration(state, d['vpn_configuration_id'], jid)
        registry.write_private(jobdir / 'request.json', d)
        initial = {'id': jid, 'mode': MODE, 'name': d['name'], 'source_vm': None,
                   'phase': 'queued', 'pid': None, 'progress': None, 'started_at': _now(), 'updated_at': _now(),
                   'message': '已接收完整预装请求；不会读取宿主节点资料、替换旧 VM 或自动首次启动。',
                   'old_deleted': False, 'system_restored': False, 'applications_preinstalled': False,
                   'credentials_copied': False, 'host_credentials_copied': False,
                   'user_vpn_configuration_supplied': not defer, 'vpn_configuration_staged': False,
                   'guest_started': False, 'desktop_verified': False, 'vpn_connected': False,
                   'network_independently_verified': False, 'published': False, 'stage_path': None}
        registry.write_private(jobdir / 'status.json', initial)
        registry.write_private(state / 'build-current.json', initial)
        try:
            with (jobdir / 'worker.log').open('x') as log:
                subprocess.Popen(['/usr/bin/python3', '-B', str(HERE / 'oneclick.py'), '--worker', jid,
                                  '--lock-fd', str(fd), '--state-dir', str(state), '--tart-home', str(home)],
                                 env=_env(registry.HOME, home), stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True, close_fds=True, pass_fds=(fd,))
        except Exception:
            initial.update(phase='failed', message='后台任务未启动；配置已绑定，不会自动重试。', updated_at=_now())
            registry.write_private(jobdir / 'status.json', initial)
            registry.write_private(state / 'build-current.json', initial)
            raise OneClickError('worker-start-failed') from None
        return initial
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Context:
    state: Path
    tart_home: Path
    job_id: str
    lock_fd: int

    @property
    def jobdir(self):
        return self.state / 'build-jobs' / self.job_id

    @property
    def stage(self):
        return self.tart_home / '.gold-manager-staging' / self.job_id / 'new-environment'

    @property
    def base(self):
        return self.state / 'environments' / self.job_id

    @property
    def env(self):
        return _env(registry.HOME, self.tart_home)


def _job_update(c, phase, message, progress=None, *, worker_pid=None, **fields):
    value = registry.read_private(c.state / 'build-current.json')
    _need(type(value) is dict and value.get('id') == c.job_id and value.get('mode') == MODE,
          'current-job-identity-changed')
    value.update(phase=phase, message=message, progress=progress, pid=worker_pid, updated_at=_now(), **fields)
    registry.write_private(c.jobdir / 'status.json', value)
    registry.write_private(c.state / 'build-current.json', value)
    return value


def _stage_stamps(c):
    return {name: list(_stamp(c.stage / name)) for name in STAGE_FILES}


def _deferred_checkpoint(c, record, current):
    checkpoint = registry.read_private(c.jobdir / 'vpn-wait.json')
    _need(type(checkpoint) is dict and set(checkpoint) == {'schema', 'id', 'request', 'stage_stamps', 'materials'}
          and type(checkpoint['schema']) is int and checkpoint['schema'] == 1 and checkpoint['id'] == c.job_id
          and checkpoint['request'] == record and type(checkpoint['materials']) is dict
          and record.get('defer_vpn') is True and record.get(ACKS[0]) is True
          and record.get('id') == current.get('id') == c.job_id
          and record.get('mode') == current.get('mode') == MODE and record.get('source_vm') is None
          and record.get('source_identity') is None and record.get('name') == current.get('name')
          and current.get('stage_path') == str(c.stage) and current.get('system_restored') is True
          and current.get('applications_preinstalled') is True
          and all(current.get(k) is False for k in ('published', 'guest_started', 'desktop_verified',
                  'host_credentials_copied', 'credentials_copied', 'vpn_configuration_staged', 'vpn_connected'))
          and not current.get('recovery_required') and not current.get('vpn_configuration')
          and not (current.get('offline_preinstall') or {}).get('active')
          and not os.path.lexists(c.jobdir / 'commit.json') and not os.path.lexists(c.base)
          and not os.path.lexists(c.stage / '.offline-vpn.complete.json') and not os.path.lexists(c.stage / '.guest-ownership')
          and not os.path.lexists(c.stage / 'state.vzvmsave') and not os.path.lexists(c.stage / 'state.bin')
          and not os.path.lexists(c.stage / 'savedstate') and not os.path.lexists(c.stage / 'saved-state.bin')
          and not os.path.lexists(c.stage / 'suspend.bin') and not os.path.lexists(c.stage / 'control.sock'),
          'invalid-deferred-stage-checkpoint')
    name = registry.validate_name(record['name'])
    known = names_on_disk(c.tart_home) | set(registry.load_registry(c.state / 'registry.json')['vms'])
    _need(_name_key(name) not in {_name_key(v) for v in known}, 'fresh-name-required')
    _need(checkpoint['stage_stamps'] == _stage_stamps(c), 'deferred-stage-changed')
    return checkpoint


def _resume_fields(payload):
    _need(type(payload) is dict and not set(payload) - RESUME_KEYS and all(payload.get(k) is True for k in ACKS[1:])
          and type(payload.get('acknowledge_normalization', False)) is bool
          and all(type(payload.get(k)) is str and ID.fullmatch(payload[k]) for k in ('job_id', 'vpn_configuration_id')),
          'explicit-vpn-resume-consent-required')
    return dict(payload)


def resume(payload, *, state_dir=None, tart_home=None):
    """Bind an explicitly validated ticket to exactly one completed paused disk."""
    details = _resume_fields(payload)
    state = registry.safe_path(Path(state_dir) if state_dir is not None else registry.STATE_DIR)
    home = _safe_tart_root(Path(tart_home) if tart_home is not None else registry.HOME / '.tart')
    _need(capabilities()['ready'], 'preinstall-capabilities-unavailable')
    fd = os.open(str(registry.safe_path(state / 'build.lock')), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _lock(fd, state)
        c = Context(state, home, details['job_id'], fd)
        current = registry.read_private(state / 'build-current.json')
        _need(lifecycle.waiting_for_vpn(current) and current.get('id') == c.job_id,
              'exact-waiting-vpn-job-required')
        request = registry.read_private(c.jobdir / 'request.json')
        _need(type(request) is dict, 'invalid-deferred-request')
        _deferred_checkpoint(c, request, current)
        marker = c.jobdir / 'vpn-resume.json'
        _need(not os.path.lexists(marker), 'vpn-resume-already-requested')
        stored = vpn_store.load_configuration(c.state, details['vpn_configuration_id'])
        _need(stored.bound_job is None, 'configuration-already-bound')
        _need(not stored.summary['normalization_required'] or details.get('acknowledge_normalization') is True,
              'explicit-normalization-consent-required')
        vpn_store.claim_configuration(c.state, details['vpn_configuration_id'], c.job_id)
        registry.write_private(marker, details)
        result = _job_update(c, RESUME_QUEUED, '已接收 VPN 配置；重新核验同一暂存盘，不再安装系统或软件。',
                             user_vpn_configuration_supplied=True)
        try:
            with (c.jobdir / 'vpn-worker.log').open('x') as log:
                subprocess.Popen(['/usr/bin/python3', '-B', str(HERE / 'oneclick.py'), '--worker', c.job_id,
                                  '--lock-fd', str(fd), '--state-dir', str(c.state), '--tart-home', str(c.tart_home), '--resume-vpn'],
                                 env=c.env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True, close_fds=True, pass_fds=(fd,))
        except Exception:
            _job_update(c, 'failed', 'VPN 续接未能启动；暂存盘保留，不会自动重试。',
                        recovery_required=True, failed_phase=RESUME_QUEUED, failure_code='vpn-worker-start-failed')
            raise OneClickError('vpn-worker-start-failed') from None
        return result
    finally:
        os.close(fd)


def _require_reviewed_restore_build(value):
    """An Apple-supported image is not necessarily this reviewed build."""
    from host_artifacts import SPECS
    version, build = SPECS['ipsw'].version.split('/')
    _need(type(value) is dict and value.get('macOSVersion') == version
          and value.get('buildVersion') == build, 'reviewed-restore-build-mismatch')


class NativeServices:
    """Real adapters; tests replace this boundary, never execute a VM implicitly."""
    def __init__(self, context):
        self.context = context

    def prepare(self, request, update):
        import host_artifacts
        import host_tools
        from preinstall_materials import MaterialManager, MaterialPreparationError
        c = self.context
        registry.private_dir(c.state / 'host-materials')
        registry.private_dir(c.state / 'tools')
        registry.private_dir(c.jobdir / 'build')
        self.installer, self.bootstrap = host_tools.resolve_helpers(HERE, c.jobdir / 'build')
        self.ownership = host_tools.resolve_ownership_helper(HERE, c.jobdir / 'build')
        def progress(value):
            fraction = value.completed_bytes / value.total_bytes if value.total_bytes else None
            update('acquiring', '正在获取固定版本公开材料（' + value.spec_key + '）；不连接 VPN 节点。', fraction)
        options = {'loopback_proxy': request['download_loopback_proxy'], 'progress': progress}
        tart_archive = host_artifacts.acquire('tart', c.state / 'host-materials', **options)
        self.tart = host_tools.ensure_tart(c.state / 'tools', artifact_receipt=tart_archive)
        self.backend = host_artifacts.acquire('gvproxy', c.state / 'host-materials', **options)
        if request['ipsw'] == 'reviewed':
            self.ipsw = host_artifacts.acquire('ipsw', c.state / 'host-materials', **options)
        else:
            self.ipsw = host_artifacts.import_local('ipsw', Path(request['ipsw']), c.state / 'host-materials', progress=progress)
        registry.private_dir(c.state / 'application-materials')
        def material_progress(event):
            # Observer data is untrusted: only fixed product keys and integers are shown.
            label = MATERIAL_LABELS.get(event.get('product')) if type(event) is dict and type(event.get('product')) is str else None
            if label is None:
                if type(event) is dict and event.get('stage') == 'verifying-complete-set':
                    update('acquiring', '正在整体复核全部应用；不连接 VPN 节点。', None)
                return
            stage, done, total = event.get('stage'), event.get('completed_bytes'), event.get('total_bytes')
            if stage == 'downloading' and type(done) is int and done >= 0:
                if type(total) is int and total > 0:
                    update('acquiring', '正在下载 %s（%d/%d MiB）；不连接 VPN 节点。' % (label, done // MIB, total // MIB),
                           min(done / total, 1.0))
                else:
                    update('acquiring', '正在下载 %s（%d MiB）；不连接 VPN 节点。' % (label, done // MIB), None)
            elif stage in _MATERIAL_STAGES:
                update('acquiring', _MATERIAL_STAGES[stage].format(label) + '；不连接 VPN 节点。', None)
        manager = MaterialManager(c.state / 'application-materials', loopback_proxy=request['download_loopback_proxy'],
                                  progress=material_progress)
        try:
            # This store's own completed download, fully re-verified; otherwise download afresh.
            self.materials, source = manager.load_reusable(), 'reused'
        except MaterialPreparationError:
            self.materials, source = manager.prepare(), 'downloaded'
        self.material_attempt_id = manager.last_attempt_id
        update('acquiring', '应用材料已就绪（%s）；尚未创建或启动客机。' %
               ('复用本机已校验的缓存，已重新完整校验' if source == 'reused' else '本次重新下载'),
               None, materials_source=source)
        # The controller may use only this explicit statically verified Tart binding.
        registry.write_private(c.state / 'tart-tool.json', {
            'version': 1, 'executable_path': str(self.tart.executable_path),
            'executable_sha256': self.tart.executable_sha256,
            'receipt_path': str(self.tart.receipt_path)})

    def deferred_materials(self):
        import host_artifacts
        from preinstall_runtime import _qhash, _quarantine
        c = self.context
        attempt = self.backend.attempt_id
        _need(type(attempt) is str and re.fullmatch(r'gvproxy-[0-9a-f]{32}', attempt), 'invalid-backend-attempt')
        path = c.state / 'host-materials' / attempt / host_artifacts.SPECS['gvproxy'].filename
        _need(Path(self.backend.artifact_path) == path, 'backend-path-mismatch')
        quarantine = _quarantine(path)
        _need(quarantine is not None, 'deferred-backend-quarantine-missing')
        return {'applications': self.material_attempt_id, 'backend': attempt, 'backend_stamp': list(_stamp(path)),
                'backend_quarantine': _qhash(quarantine), 'tart': registry.read_private(c.state / 'tart-tool.json')}

    def load_deferred_materials(self, value):
        import host_artifacts
        import host_tools
        from preinstall_materials import MaterialManager
        from preinstall_runtime import _verified_backend, _qhash, _quarantine
        from types import SimpleNamespace
        c = self.context
        _need(type(value) is dict and set(value) == {'applications','backend','backend_stamp','backend_quarantine','tart'}
              and type(value['tart']) is dict and value['tart'] == registry.read_private(c.state / 'tart-tool.json')
              and type(value['backend']) is str and re.fullmatch(r'gvproxy-[0-9a-f]{32}', value['backend']),
              'deferred-material-record-mismatch')
        tart = lifecycle.inventory_tool(state_dir=c.state)
        _need(tart is not None and str(tart) == value['tart'].get('executable_path'), 'deferred-tart-changed')
        self.tart = SimpleNamespace(executable_path=tart)
        path = c.state / 'host-materials' / value['backend'] / host_artifacts.SPECS['gvproxy'].filename
        _need(list(_stamp(path)) == value['backend_stamp'], 'deferred-backend-changed')
        _verified_backend(path)
        q = _quarantine(path)
        _need(q is not None and _qhash(q) == value['backend_quarantine'] and list(_stamp(path)) == value['backend_stamp'],
              'deferred-backend-quarantine-changed')
        self.backend = SimpleNamespace(artifact_path=path)
        _, self.bootstrap = host_tools.resolve_helpers(HERE, c.jobdir / 'build')
        self.ownership = host_tools.resolve_ownership_helper(HERE, c.jobdir / 'build')
        self.materials = MaterialManager(c.state / 'application-materials').load(value['applications'])

    def restore(self, request, update):
        c = self.context
        image = Path(self.ipsw.artifact_path)
        before = _stamp(image)
        _need((self.ipsw.device, self.ipsw.inode, self.ipsw.size_bytes, self.ipsw.mtime_ns) == before[:4]
              and self.ipsw.digest_verified is True and self.ipsw.quarantine_ensured is True,
              'ipsw-receipt-identity-mismatch')
        inspected = subprocess.run([str(self.installer), '--inspect', '--ipsw', str(image)],
                                   env=c.env, capture_output=True, text=True, timeout=120)
        _need(inspected.returncode == 0, 'apple-restore-inspection-failed')
        info = None
        for line in inspected.stdout.splitlines():
            try:
                candidate = json.loads(line)
                if type(candidate) is dict:
                    info = candidate
            except ValueError:
                pass
        _need(type(info) is dict and type(info.get('schemaVersion')) is int and info['schemaVersion'] == 1
              and info.get('event') == 'inspect' and info.get('supported') is True
              and all(type(info.get(k)) is int and info[k] > 0 for k in ('minimumCPUCount', 'minimumMemorySize')),
              'unsupported-apple-restore-image')
        _require_reviewed_restore_build(info)
        _need(request['cpu'] >= info['minimumCPUCount']
              and request['memory_gib'] * 1024**3 >= info['minimumMemorySize'], 'selected-resources-below-image-minimum')
        _need(_stamp(image) == before, 'ipsw-changed-during-inspection')
        registry.write_private(c.jobdir / 'image-inspection.json', info)
        registry.private_dir(c.stage.parent.parent)
        registry.safe_path(c.stage.parent, False).mkdir(mode=0o700)
        registry.safe_path(c.stage, False).mkdir(mode=0o700)
        registry.sync_directory(c.stage.parent.parent)
        update('installing', '恢复全新系统：零网卡、零共享、零 socket；不创建账号或跳过首次设置。', 0,
               stage_path=str(c.stage))
        command = [str(self.installer), '--create', '--directory', str(c.stage), '--ipsw', str(image),
                   '--cpu', str(request['cpu']), '--memory-gib', str(request['memory_gib']),
                   '--disk-gib', str(request['disk_gib'])]
        complete = False
        with (c.jobdir / 'installer.log').open('x') as log:
            proc = subprocess.Popen(command, env=c.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=log, text=True, pass_fds=(c.lock_fd,))
            for line in proc.stdout:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if type(event) is not dict:
                    continue
                if event.get('event') == 'complete' and type(event.get('schemaVersion')) is int and event['schemaVersion'] == 1:
                    complete = True
                percent = event.get('percent')
                if type(percent) in (int, float) and math.isfinite(percent) and 0 <= percent <= 100:
                    update('installing', '正在恢复全新 macOS；尚未普通开机。', percent / 100)
            _need(proc.wait() == 0 and complete, 'apple-restore-not-complete')
        _need(_stamp(image) == before, 'ipsw-changed-during-restore')
        lifecycle.verify_install_output(c.stage, request)
        _require_reviewed_restore_build(registry.read_private(c.stage / '.clean-vm-installer.complete.json'))
        _new_identity(c.stage, c.tart_home / 'vms')

    def preinstall(self, request, update):
        from offline_preinstall import preinstall_stage
        c = self.context
        return preinstall_stage(state_dir=c.state, tart_home=c.tart_home, job_id=c.job_id,
                                name=request['name'], materials=self.materials,
                                evidence_dir=c.jobdir / 'application-preinstall', acknowledge_write=True,
                                lifecycle_lock_fd=c.lock_fd)

    def configure(self, request, stored, update):
        from offline_vpn import configure_preinstalled_stage
        c = self.context
        return configure_preinstalled_stage(state_dir=c.state, tart_home=c.tart_home, job_id=c.job_id,
                                            name=request['name'], private_config=stored.private_config,
                                            bootstrap_helper_path=self.bootstrap, ownership_helper_path=self.ownership,
                                            materials=self.materials, acknowledge_write=True,
                                            acknowledge_system_authorization=True, lifecycle_lock_fd=c.lock_fd)

    def runtime(self, request, stored, update):
        from preinstall_runtime import prepare_environment
        c = self.context
        registry.private_dir(c.base.parent)
        return prepare_environment(request['name'], c.stage / 'config.json', c.base,
                                   published_vm_config=c.tart_home / 'vms' / request['name'] / 'config.json',
                                   private_config=stored.private_config, endpoints=stored.endpoints,
                                   gvproxy_path=Path(self.backend.artifact_path), tart_path=self.tart.executable_path,
                                   preinstall_receipt=c.stage / '.offline-preinstall.complete.json',
                                   vpn_seed_receipt=c.stage / '.offline-vpn.complete.json')

    def publish(self, request, update):
        return publish_fresh(self.context, request, update)


def _new_identity(stage, vm_root):
    config = registry.read_private(stage / 'config.json')
    _need(type(config) is dict and type(config.get('ecid')) is str and type(config.get('macAddress')) is str,
          'invalid-new-vm-identity')
    for entry in vm_root.iterdir():
        if not entry.is_dir():
            continue
        peer = registry.safe_path(entry / 'config.json', False)
        if not peer.exists():
            continue
        # Standard Tart configs may be 0644. Read only bounded owned metadata,
        # never the predecessor disk, host profile or arbitrary referenced files.
        fd = os.open(str(peer), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            _need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
                  and not st.st_mode & 0o7022 and 0 < st.st_size <= 1048576, 'unsafe-peer-config')
            old = json.loads(os.read(fd, 1048577))
            _need(type(old) is dict and old.get('ecid') != config['ecid']
                  and str(old.get('macAddress', '')).lower() != config['macAddress'].lower(), 'duplicate-vm-identity')
        finally:
            os.close(fd)
    return config


def _rename_exclusive(source, destination):
    """Darwin's no-replacement directory rename; never falls back to os.rename."""
    source = registry.safe_path(source)
    destination = registry.safe_path(destination, False)
    _need(source.name == 'new-environment' and destination.parent.name == 'vms'
          and source.is_dir() and not destination.exists(), 'unsafe-publication-path')
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, 'renameatx_np', None)
    _need(function is not None, 'exclusive-rename-unavailable')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    src = os.open(str(source.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        dst = os.open(str(destination.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _need(os.fstat(src).st_dev == os.fstat(dst).st_dev, 'publication-requires-same-filesystem')
            # RENAME_EXCL: even a newly created empty target cannot be replaced.
            if function(src, os.fsencode(source.name), dst, os.fsencode(destination.name), 4):
                raise OneClickError('exclusive-publication-rename-failed')
        finally:
            os.close(dst)
    finally:
        os.close(src)


def _require_detached(image):
    from offline_disk import decode
    r = subprocess.run(['/usr/bin/hdiutil', 'info', '-plist'], stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=30, env=_env(registry.HOME, image.parents[3]))
    _need(r.returncode == 0, 'disk-detach-could-not-be-confirmed')
    rows = decode(r.stdout).get('images')
    _need(type(rows) is list and all(type(row) is dict and type(row.get('image-path')) is str for row in rows),
          'invalid-disk-attachment-inventory')
    _need(all(Path(row['image-path']).resolve() != image for row in rows), 'publication-disk-still-attached')


def _publication_acceptance(c, request, meta):
    from offline_vpn import _recorded_rows
    state = registry.read_private(c.state / 'build-current.json')
    _need(type(state) is dict and state.get('id') == c.job_id and state.get('name') == request['name']
          and state.get('mode') == MODE and state.get('phase') == 'publishing'
          and state.get('source_vm') is None and state.get('stage_path') == str(c.stage)
          and all(state.get(k) is True for k in ('system_restored', 'applications_preinstalled', 'vpn_configuration_staged'))
          and all(state.get(k) is False for k in ('guest_started', 'desktop_verified', 'published')),
          'publication-acceptance-missing')
    for filename, key, yes, no in (
        ('.offline-preinstall.complete.json', 'preinstall_receipt_sha256',
         ('applications_preinstalled', 'readonly_remount_verified', 'final_detach_confirmed',
          'vm_config_and_nvram_unchanged', 'image_file_identity_and_size_unchanged'),
         ('guest_started', 'desktop_verified', 'published', 'credentials_copied')),
        ('.offline-vpn.complete.json', 'vpn_seed_receipt_sha256',
         ('applications_preinstalled', 'vpn_configuration_staged', 'persistent_ownership_verified', 'readonly_payload_verified',
          'readonly_remount_verified', 'final_detach_confirmed', 'config_unchanged', 'nvram_unchanged'),
         ('guest_started', 'desktop_verified', 'published', 'host_credentials_copied', 'vpn_connected')),
    ):
        path = c.stage / filename
        record = registry.read_private(path)
        _need(type(record) is dict and type(record.get('schema')) is int and record['schema'] == 1
              and record.get('job_id') == c.job_id and record.get('name') == request['name']
              and record.get('stage_path') == str(c.stage)
              and type(record.get('operation_id')) is str and ID.fullmatch(record['operation_id'])
              and all(record.get(k) is True for k in yes) and all(record.get(k) is False for k in no)
              and lifecycle.fingerprint(path) == meta[key], 'independent-readonly-acceptance-required')
        if filename == '.offline-preinstall.complete.json':
            _recorded_rows(record)
        else:
            _need(type(record.get('receipt_token')) is str and re.fullmatch('[0-9a-f]{64}', record['receipt_token'])
                  and record.get('image_file_stamp') == list(_stamp(c.stage / 'disk.img')),
                  'vpn-acceptance-disk-binding-mismatch')
    for name in ('state.vzvmsave', 'state.bin', 'savedstate', 'saved-state.bin', 'suspend.bin', 'control.sock'):
        _need(not os.path.lexists(c.stage / name), 'previously-started-stage')


def publish_fresh(c, request, update):
    import preinstall_runtime
    _need(request['mode'] == MODE and request['source_vm'] is None and request['source_identity'] is None,
          'fresh-publication-only')
    registry.validate_name(request['name'])
    _lock(c.lock_fd, c.state)
    target = _safe_tart_root(c.tart_home / 'vms') / request['name']
    _need(not os.path.lexists(target), 'fresh-name-required')
    lifecycle.verify_install_output(c.stage, request)
    meta = preinstall_runtime._validate_environment(c.base, staged_vm_config=c.stage / 'config.json')
    _need(meta['vm_name'] == request['name'] and meta['vm_config'] == str(target / 'config.json'),
          'runtime-publication-binding-mismatch')
    storage_fd = os.open(str(_safe_tart_root(c.tart_home)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    config_fd = None
    try:
        with registry.state_lock(c.state):
            fcntl.flock(storage_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _new_identity(c.stage, target.parent)  # Before lockf: reads the config inode.
            config_fd = os.open(str(registry.safe_path(c.stage / 'config.json')), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            fcntl.lockf(config_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            pinned = os.fstat(config_fd)
            raw = os.pread(config_fd, 1048577, 0)
            _need([pinned.st_dev, pinned.st_ino] == meta['vm_config_identity']
                  and 0 < len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == meta['vm_config_sha256'],
                  'config-changed-before-publish')
            _require_reviewed_restore_build(registry.read_private(c.stage / '.clean-vm-installer.complete.json'))
            _publication_acceptance(c, request, meta)
            _require_detached(c.stage / 'disk.img')
            key = _name_key(request['name'])
            _need(key not in {_name_key(n) for n in names_on_disk(c.tart_home)}, 'fresh-name-required')
            reg_path = c.state / 'registry.json'
            reg = registry.load_registry(reg_path)
            shares_path = c.state / 'config.json'
            shares = registry.read_private(shares_path, {'version': 1, 'vms': {}})
            _need(type(shares) is dict and set(shares) == {'version', 'vms'} and type(shares['version']) is int
                  and shares['version'] == 1 and type(shares['vms']) is dict, 'invalid-share-registry')
            _need(not any(_name_key(n) == key for n in set(registry.LEGACY_NAMES) | set(reg['vms']) | set(shares['vms'])),
                  'registered-name-exists')
            reg['vms'][request['name']] = {'environment_id': c.job_id}
            reg['retired'] = [n for n in reg['retired'] if n != request['name']]
            shares['vms'][request['name']] = {'shares': []}
            registry.validate_registry(reg)
            journal_path = c.jobdir / 'commit.json'
            _need(not os.path.lexists(journal_path), 'publication-journal-already-exists')
            journal = {'version': 1, 'id': c.job_id, 'mode': MODE, 'name': request['name'], 'source_vm': None,
                       'new': str(c.stage), 'target': str(target), 'environment_id': c.job_id, 'phase': 'before_publish'}
            registry.write_private(journal_path, journal)
            # Do not reopen/close config.json while holding its POSIX lock.
            os.fsync(config_fd)
            for filename in ('disk.img', 'nvram.bin', '.clean-vm-installer.complete.json',
                             '.offline-preinstall.complete.json', '.offline-vpn.complete.json'):
                fd = os.open(str(registry.safe_path(c.stage / filename)), os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            registry.sync_directory(c.stage)
            _rename_exclusive(c.stage, target)
            registry.sync_directory(target.parent)
            registry.sync_directory(c.stage.parent)
            journal['phase'] = 'new_published'
            registry.write_private(journal_path, journal)
            registry.write_private(reg_path, reg)
            registry.write_private(shares_path, shares)
            # Release only the per-config POSIX lock before using the full path
            # validator; the lifecycle/storage/state locks still fence publication.
            os.close(config_fd)
            config_fd = None
            preinstall_runtime.validate_environment(c.base, meta)
            _need(registry.load_registry(reg_path) == reg and registry.read_private(shares_path) == shares,
                  'publication-registry-readback-failed')
            journal['phase'] = 'committed_new_registered'
            registry.write_private(journal_path, journal)
    finally:
        if config_fd is not None:
            os.close(config_fd)
        os.close(storage_fd)
    return target


def _worker_updates(c):
    def update(phase, message, progress=None, **fields):
        return _job_update(c, phase, message, progress, worker_pid=os.getpid(), **fields)
    return update


def _finish_preinstall(c, d, stored, service, update):
    service.configure(d, stored, update)
    value = registry.read_private(c.state / 'build-current.json')
    _need(value.get('vpn_configuration_staged') is True, 'vpn-seed-readback-not-accepted')
    update('preparing_runtime', '绑定独立网络保护与首次登录回执；不启动网络后端或 VM。')
    prepared = service.runtime(d, stored, update)
    registry.write_private(c.jobdir / 'runtime-preparation.json', prepared)
    update('publishing', '独立只读核验完成；仅发布这个新 VM，不覆盖或删除旧 VM。')
    target = service.publish(d, update)
    return update('awaiting_first_desktop_acceptance',
                  '系统、四个完整应用与私有配置已预装。首次启动需单独确认后端安全提示，并由本人完成系统设置和授权；未验收桌面或 VPN 连通。',
                  1, published=True, stage_path=None, published_path=str(target),
                  needs_host_security_authorization=True, guest_started=False,
                  desktop_verified=False, vpn_connected=False, network_independently_verified=False)


def _worker_failure(c, update, error):
    value = registry.read_private(c.state / 'build-current.json', {})
    phase = value.get('phase')
    if phase == 'failed':
        operation = value.get('vpn_configuration') or value.get('offline_preinstall') or {}
        phase = operation.get('phase', 'preinstalling')
    code = error_codes.public_code(error, 'preinstall-step-failed')
    # The VPN workflow records its own inner step and a sanitized reason.
    inner = value.get('vpn_configuration')
    inner = inner if type(inner) is dict else {}
    failed_step = inner.get('failed_step') if error_codes.is_step(inner.get('failed_step')) else None
    failure_reason = inner.get('failure_code') if error_codes.is_code(inner.get('failure_code')) else None
    product = getattr(error, 'product', None)
    failed_product = product if type(product) is str and product in MATERIAL_LABELS else None
    message = ('原始材料下载或校验未完成，尚未创建虚拟磁盘；已保留下载，不会自动重试。'
               if phase == 'acquiring' and not value.get('stage_path') else
               '预装未完成；保留所有暂存文件，不自动覆盖重试。请查看失败步骤。')
    return update('failed', message, failure_code=code, failed_phase=phase,
                  failed_step=failed_step, failure_reason=failure_reason, failed_product=failed_product,
                  recovery_required=bool(value.get('stage_path')) or (c.jobdir / 'commit.json').exists(),
                  desktop_verified=False, vpn_connected=False, network_independently_verified=False)


def execute(context, *, services=None):
    c = context
    _need(type(c.job_id) is str and ID.fullmatch(c.job_id), 'invalid-job-id')
    _lock(c.lock_fd, c.state)
    current = registry.read_private(c.state / 'build-current.json')
    d = registry.read_private(c.jobdir / 'request.json')
    _need(type(current) is dict and type(d) is dict and current.get('id') == d.get('id') == c.job_id
          and current.get('mode') == d.get('mode') == MODE and current.get('phase') == 'queued'
          and current.get('name') == d.get('name') and d.get('source_vm') is None
          and d.get('source_identity') is None, 'queued-fresh-job-required')
    update = _worker_updates(c)
    service = services if services is not None else NativeServices(c)
    try:
        defer = d.get('defer_vpn') is True
        if not defer:
            stored = vpn_store.load_configuration(c.state, d['vpn_configuration_id'], job_id=c.job_id)
            _need(stored.bound_job == c.job_id, 'unclaimed-vpn-configuration')
            _need(not stored.summary['normalization_required'] or d.get('acknowledge_normalization') is True,
                  'explicit-normalization-consent-required')
        known = names_on_disk(c.tart_home) | set(registry.load_registry(c.state / 'registry.json')['vms'])
        checked = validated_request({k: v for k, v in d.items() if k in KEYS}, known, host_memory=_host_memory())
        _need(dict(checked, id=c.job_id) == d, 'stored-request-changed')
        update('preflight', '核对全新名称、空间与显式配置；不读取宿主 VPN 资料。')
        _need(shutil.disk_usage(c.tart_home).free >= (d['disk_gib'] + 32) * 1024**3, 'insufficient-safe-staging-space')
        update('acquiring', '准备固定版本系统、完整应用及工具；尚未创建或启动客机。')
        service.prepare(d, update)
        update('inspecting', '验证 Apple 恢复兼容性。')
        service.restore(d, update)
        update('awaiting_offline_preinstall', '全新隔离恢复完成，开始完整应用离线预装。',
               system_restored=True, stage_path=str(c.stage))
        service.preinstall(d, update)
        value = registry.read_private(c.state / 'build-current.json')
        _need(value.get('applications_preinstalled') is True, 'application-readback-not-accepted')
        if defer:
            _require_detached(c.stage / 'disk.img')
            checkpoint = {'schema': 1, 'id': c.job_id, 'request': d, 'stage_stamps': _stage_stamps(c),
                          'materials': service.deferred_materials()}
            marker = c.jobdir / 'vpn-wait.json'
            _need(not os.path.lexists(marker), 'deferred-checkpoint-already-exists')
            registry.write_private(marker, checkpoint)
            _deferred_checkpoint(c, d, value)
            return update(PAUSE_PHASE, '系统和软件已安装到暂存盘。请补充 VPN 配置后继续；未发布、未开机。',
                          1, user_vpn_configuration_supplied=False)
        return _finish_preinstall(c, d, stored, service, update)
    except Exception as error:
        return _worker_failure(c, update, error)


def execute_resume(context, *, services=None):
    c = context
    _need(type(c.job_id) is str and ID.fullmatch(c.job_id), 'invalid-job-id')
    _lock(c.lock_fd, c.state)
    current = registry.read_private(c.state / 'build-current.json')
    _need(type(current) is dict and current.get('id') == c.job_id and current.get('mode') == MODE
          and current.get('phase') == RESUME_QUEUED and current.get('user_vpn_configuration_supplied') is True,
          'queued-vpn-resume-required')
    update = _worker_updates(c)
    service = services if services is not None else NativeServices(c)
    try:
        initial = registry.read_private(c.jobdir / 'request.json')
        _need(type(initial) is dict, 'invalid-deferred-request')
        checkpoint = _deferred_checkpoint(c, initial, current)
        details = _resume_fields(registry.read_private(c.jobdir / 'vpn-resume.json'))
        _need(details.pop('job_id') == c.job_id, 'resume-job-id-mismatch')
        stored = vpn_store.load_configuration(c.state, details['vpn_configuration_id'], job_id=c.job_id)
        _need(stored.bound_job == c.job_id and (not stored.summary['normalization_required']
              or details.get('acknowledge_normalization') is True), 'unconfirmed-vpn-resume-configuration')
        update('resuming_vpn', '正在复核用于此 VM 的配置和同一批已审查材料；不重新恢复系统或重新预装。')
        service.load_deferred_materials(checkpoint['materials'])
        _require_detached(c.stage / 'disk.img')
        _deferred_checkpoint(c, initial, registry.read_private(c.state / 'build-current.json'))
        # The immutable original request remains in vpn-wait.json. The effective
        # request is written once under lock, only after this explicit VPN bind.
        d = dict(initial, **details)
        del d['defer_vpn']
        registry.write_private(c.jobdir / 'request.json', d)
        update('awaiting_first_desktop_acceptance', '同一暂存盘已通过续接检查，准备独立验证并写入 VPN。')
        return _finish_preinstall(c, d, stored, service, update)
    except Exception as error:
        return _worker_failure(c, update, error)


ARCHIVE_KEYS = frozenset(('job_id', 'confirm_name'))


def archive_failed(payload, *, state_dir=None, tart_home=None):
    """Explicitly unlock a dead, failed, unpublished preinstall job; keep its stage.

    Moves only the current-job record into the job's own directory. The stage,
    its disk image, evidence and bound VPN ticket are left exactly as they are;
    nothing is resumed, deleted, published or started.
    """
    state = Path(state_dir) if state_dir is not None else registry.STATE_DIR
    home = Path(tart_home) if tart_home is not None else registry.HOME / '.tart'
    _need(type(payload) is dict and set(payload) == ARCHIVE_KEYS
          and type(payload['job_id']) is str and ID.fullmatch(payload['job_id'])
          and type(payload['confirm_name']) is str, 'invalid-archive-request')
    registry.private_dir(state)
    fd = os.open(str(registry.safe_path(state / 'build.lock', False)), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            _lock(fd, state)
        except BlockingIOError:
            # A live worker inherits build.lock; never archive under it.
            raise OneClickError('lifecycle-lock-busy') from None
        current_path = state / 'build-current.json'
        raw = registry.read_private(current_path)
        job = lifecycle.status(state_dir=state)
        _need(type(raw) is dict and type(job) is dict and raw.get('id') == job.get('id') == payload['job_id'],
              'archive-job-not-current')
        _need(raw.get('mode') == MODE and job.get('mode') == MODE, 'archive-preinstall-only')
        _need(job.get('name') == payload['confirm_name'], 'archive-name-confirmation-mismatch')
        # With build.lock held no worker is alive, so a derived 'interrupted'
        # job is as dead as a 'failed' one. Anything else is still in progress.
        _need(job.get('phase') in ('failed', 'interrupted') and not lifecycle.is_active(job)
              and not lifecycle.waiting_for_vpn(job), 'archive-job-not-failed')
        _need(job.get('published') is not True and raw.get('published') is not True, 'archive-published-job-refused')
        for key in ('offline_preinstall', 'vpn_configuration'):
            operation = raw.get(key)
            _need(operation is None or (type(operation) is dict and operation.get('active') is not True),
                  'archive-operation-still-active')
        jobdir = state / 'build-jobs' / payload['job_id']
        _need(not os.path.lexists(jobdir / 'commit.json'), 'archive-publication-journal-present')
        archived = jobdir / 'archived-current.json'
        _need(not os.path.lexists(archived), 'archive-record-already-exists')
        stage = home / '.gold-manager-staging' / payload['job_id'] / 'new-environment'
        image = stage / 'disk.img'
        if os.path.lexists(image):
            _require_detached(image)
        record = dict(raw, archived_at=_now())
        registry.write_private(archived, record)
        _need(registry.read_private(archived) == record, 'archive-record-readback-failed')
        os.unlink(str(registry.safe_path(current_path)))
        registry.sync_directory(state)
        return {'ok': True, 'job_id': payload['job_id'], 'name': job['name'], 'stage_retained': os.path.lexists(stage)}
    finally:
        os.close(fd)


AUTHORIZATION_DECISION_KEYS = frozenset(('job_id', 'attempt', 'decision'))


def authorization_decision(payload, *, state_dir=None):
    """Pass the user's explicit retry/abandon choice to a paused, live worker.

    Only a preinstall job whose worker is alive and paused on a refused macOS
    prompt (phase awaiting_system_authorization, checked by lifecycle.status)
    can receive it. Writes one private decision file; nothing else changes.
    """
    state = Path(state_dir) if state_dir is not None else registry.STATE_DIR
    _need(type(payload) is dict and set(payload) == AUTHORIZATION_DECISION_KEYS
          and type(payload['job_id']) is str and ID.fullmatch(payload['job_id'])
          and type(payload['attempt']) is int and type(payload['decision']) is str
          and payload['decision'] in ('retry', 'abandon'), 'invalid-authorization-decision')
    job = lifecycle.status(state_dir=state)
    _need(type(job) is dict and job.get('id') == payload['job_id'] and job.get('mode') == MODE
          and job.get('phase') == 'awaiting_system_authorization', 'authorization-decision-not-pending')
    from offline_vpn import submit_authorization_decision
    result = submit_authorization_decision(state, payload['job_id'], payload['attempt'], payload['decision'])
    return dict(result, ok=True, job_id=payload['job_id'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', required=True)
    parser.add_argument('--lock-fd', type=int, required=True)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--tart-home', type=Path, required=True)
    parser.add_argument('--resume-vpn', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    registry.private_dir(args.state_dir)
    _safe_tart_root(args.tart_home)
    run = execute_resume if args.resume_vpn else execute
    result = run(Context(args.state_dir, args.tart_home, args.worker, args.lock_fd))
    if result['phase'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
