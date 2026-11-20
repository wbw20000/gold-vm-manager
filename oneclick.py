"""Fresh-only user-driven VM creation. No host profile import or auto first boot.

Restores a clean macOS and never writes into the guest disk. The verified apps
and the Clash profile go into a read-only folder that is shared only while first
setup is pending; the person installs them in the guest with Finder and the GUI
(owner's decision, 2026-11-20: copying apps in from the host made macOS run them
from a temporary translocated path, which Clash Verge refuses).

A single inherited lifecycle flock covers acquisition through publication.
Failures keep their artifacts; neither a failed job nor a half-published
transaction is automatically replayed.
"""
import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
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
ACKS = ('acknowledge_preinstall', 'acknowledge_network_policy')
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
STAGE_FILES = ('disk.img', 'config.json', 'nvram.bin', '.clean-vm-installer.complete.json')
# The read-only first-setup folder (see build_installers).
INSTALLERS_PROFILE = 'Clash 节点配置.yaml'
INSTALLERS_README = '先读我.txt'
INSTALLERS_NOTE = """首次设置用的安装文件（只读，只在首次设置期间出现）

1. 安装应用：在客机 Finder 里，把这里的 4 个应用（CCBaga-A、CCBaga-B、Clash Verge、Claude）
   一个一个拖到客机桌面，再从桌面一个一个拖进「应用程序」。
   不要从这个共享文件夹直接拖进「应用程序」，也不要在共享文件夹里打开应用。
   安装完后，只打开「应用程序」里的副本。
2. 打开「应用程序」里的 Clash Verge。macOS 提示这是从互联网下载的应用时，选「打开」。
3. 导入节点：在 Clash Verge 左侧点「订阅」，点「新建」，类型选「本地」，点「选择文件」，
   选这个文件夹里的「Clash 节点配置.yaml」，再点「保存」。然后点一下新出现的订阅，让它处于使用中。
4. 在 Clash Verge 的「设置」里打开「虚拟网卡模式」，按提示安装系统服务并输入你的管理员密码。
5. 确认代理已启用后，从「应用程序」打开 CCBaga A，点「浏览器环境」进行检测。
   点「电脑环境」可快速对齐时区；如不需要定位，可在客机的「系统设置 → 隐私与安全性 → 定位服务」中关闭定位。
6. 调整后重新检测，直到 CCBaga A 的检测项全部变绿。再用客机浏览器打开 https://ip.net.coffee/claude/，
   确认评分达到 70 分或以上，且本次检测未报告 IP 或 DNS 泄露。这是第三方自检，不代表 Claude 官方准入或账户资格。
   不要在检测网页输入账户密码、节点凭据或支付信息。
7. 自检通过后可打开 Claude Code，按提示在 Claude 官方页面注册或登录；免费账户、Claude Code 使用权限和套餐升级以官方页面显示为准。
8. 确认 Clash 已通过节点联网后，在客机里正常关机，回到 Gold VM 管理器，点「标记首次设置完成…」。
   之后每次启动都受保护，客机只能连到你的节点，这个文件夹也不再出现。
"""


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
    required = ('vpn_store.py', 'preinstall_runtime.py', 'preinstall_materials.py')
    complete = all((HERE / name).is_file() for name in required)
    # Compiled app resources are checked again by resolve_helpers at use, not trusted here.
    source_or_bundle = (HERE / 'CleanVMInstaller').is_file() or (HERE / 'CleanVMInstaller.swift').is_file()
    checks = [
        {'id': 'platform', 'ready': platform['ready'], 'message': '仅支持已审查的 Apple Silicon / macOS 26.6.2 磁盘格式'},
        {'id': 'implementation', 'ready': complete and source_or_bundle, 'message': '系统恢复与受保护启动组件必须齐备'},
        {'id': 'prerequisites', 'ready': prerequisites_ready, 'message': '需可用的系统 Python、Ruby/Psych 与 Apple 命令行开发工具'},
        {'id': 'system-authorizations', 'ready': True, 'message': '需本人在客机里完成首次系统设置、安装应用、导入节点和服务授权'},
    ]
    # source_prerequisites is a diagnostic report, not authorization to execute downloaded tools.
    return {'ready': all(c['ready'] for c in checks), 'checks': checks,
            'supported_tuples': platform['supported_tuples'],
            'applications': [{'name': a.name, 'version': a.short_versions[0] if a.short_versions else m.version}
                             for m in reviewed_manifests() for a in m.expected_apps],
            'source_prerequisites': prerequisites,
            'limitations': ['下载/复制失败保留材料，不自动续传或覆盖重试。',
                            '不往客机磁盘写任何东西。首次设置另行确认，使用普通网络（不经过滤），并挂一个只读文件夹，里面是核验过的 4 个应用和节点配置，由你在客机里用 Finder 安装、在 Clash 里导入。',
                            '确认 Clash 连上节点后由你标记首次设置完成；之后每次启动都受保护，网络后端 gvproxy 取自 Podman 官方安装包（Red Hat 签名、已公证，不安装 Podman），保留隔离属性，由 macOS 自行核验。',
                            '系统设置、应用安装、节点导入和 VPN 连通都没有自动验收；未提供真实节点不能验收连通。']}


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
                   'message': '已接收预装请求；不会读取宿主节点资料、替换旧 VM 或自动首次启动。',
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
        result = _job_update(c, RESUME_QUEUED, '已接收 VPN 配置；重新核验同一暂存盘，不再恢复系统或下载。',
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
        self.installer = host_tools.resolve_helpers(HERE, c.jobdir / 'build')
        def progress(value):
            fraction = value.completed_bytes / value.total_bytes if value.total_bytes else None
            update('acquiring', '正在获取固定版本公开材料（' + value.spec_key + '）；不连接 VPN 节点。', fraction)
        options = {'loopback_proxy': request['download_loopback_proxy'], 'progress': progress}
        tart_archive = host_artifacts.acquire('tart', c.state / 'host-materials', **options)
        self.tart = host_tools.ensure_tart(c.state / 'tools', artifact_receipt=tart_archive)
        # Only gvproxy is taken from Podman's notarized installer; Podman itself is never installed.
        backend_package = host_artifacts.acquire('podman-installer', c.state / 'host-materials', **options)
        self.backend = host_tools.ensure_gvproxy(c.state / 'tools', artifact_receipt=backend_package)
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
        from preinstall_runtime import _qhash, _quarantine
        c = self.context
        path = Path(self.backend.executable_path)
        tool = path.parent.name
        _need(re.fullmatch(r'gvproxy-tool-[0-9a-f]{32}', tool) and path == c.state / 'tools' / tool / 'gvproxy',
              'backend-path-mismatch')
        quarantine = _quarantine(path)
        _need(quarantine is not None, 'deferred-backend-quarantine-missing')
        return {'applications': self.material_attempt_id, 'backend': tool, 'backend_stamp': list(_stamp(path)),
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
              and type(value['backend']) is str and re.fullmatch(r'gvproxy-(tool-)?[0-9a-f]{32}', value['backend']),
              'deferred-material-record-mismatch')
        tart = lifecycle.inventory_tool(state_dir=c.state)
        _need(tart is not None and str(tart) == value['tart'].get('executable_path'), 'deferred-tart-changed')
        self.tart = SimpleNamespace(executable_path=tart)
        if not value['backend'].startswith('gvproxy-tool-'):
            # Recorded by an older build with the unnotarized release gvproxy, which
            # macOS refuses to run. Take the same upstream v0.9.0, signed and notarized.
            package = host_artifacts.acquire('podman-installer', c.state / 'host-materials')
            self.backend = host_tools.ensure_gvproxy(c.state / 'tools', artifact_receipt=package)
        else:
            path = c.state / 'tools' / value['backend'] / 'gvproxy'
            _need(list(_stamp(path)) == value['backend_stamp'], 'deferred-backend-changed')
            _verified_backend(path)
            q = _quarantine(path)
            _need(q is not None and _qhash(q) == value['backend_quarantine'] and list(_stamp(path)) == value['backend_stamp'],
                  'deferred-backend-quarantine-changed')
            self.backend = SimpleNamespace(executable_path=path)
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

    def runtime(self, request, stored, update):
        from preinstall_runtime import prepare_environment
        c = self.context
        registry.private_dir(c.base.parent)
        installers = c.jobdir / 'installers'
        update('preparing_runtime', '正在准备首次设置用的只读文件夹：复核 4 个应用并复制，写入节点配置；不往客机磁盘写入。')
        build_installers(installers, self.materials, stored.private_config)
        update('preparing_runtime', '绑定受保护启动环境；不启动网络后端或 VM。')
        return prepare_environment(request['name'], c.stage / 'config.json', c.base,
                                   published_vm_config=c.tart_home / 'vms' / request['name'] / 'config.json',
                                   private_config=stored.private_config, endpoints=stored.endpoints,
                                   gvproxy_path=Path(self.backend.executable_path), tart_path=self.tart.executable_path,
                                   installers=installers)

    def publish(self, request, update):
        return publish_fresh(self.context, request, update)


def _clone(source, target):
    """APFS clone of a whole bundle: bytes, modes, internal links and extended
    attributes (the download quarantine included). ditto only where cloning is
    unavailable; the caller compares the result either way."""
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, 'clonefile', None)
    if function is not None:
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
        function.restype = ctypes.c_int
        if function(os.fsencode(str(source)), os.fsencode(str(target)), 1) == 0:  # CLONE_NOFOLLOW
            return
        _need(ctypes.get_errno() in (errno.EXDEV, errno.ENOTSUP, errno.EOPNOTSUPP)
              and not os.path.lexists(target), 'installer-copy-failed')
    result = subprocess.run(['/usr/bin/ditto', str(source), str(target)], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=1800, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    _need(result.returncode == 0, 'installer-copy-failed')


def _write_shared(path, raw):
    """A new 0644 file: readable by the guest user whatever its UID."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)


def build_installers(target, materials, private_config):
    """Build the read-only first-setup folder at a new path: the 4 verified apps,
    the Clash profile and a short note. Nothing is installed or executed.

    The sources are verified again here (signature, notarization, quarantine and
    tree digest); each copy must match its source's verified tree and quarantine.
    The profile is the unchanged validated private configuration as JSON, which
    is also YAML. The finished folder is 0755 for the read-only guest share.
    """
    import guest_app_artifacts as artifacts
    import quarantine_policy
    from preinstall_materials import verify_materials
    target = registry.safe_path(Path(target), False)
    _need(type(private_config) is dict and type(private_config.get('proxies')) is list, 'validated-private-config-required')
    receipts = verify_materials(materials)
    trees = {app['name']: (app['bundle_tree_sha256'], app['bundle_bytes'], app['bundle_entries'])
             for receipt in receipts for app in receipt.apps}
    target.mkdir(mode=0o700)
    for material in materials:
        for app in material.app_paths:
            copy = target / app.name
            _clone(app, copy)
            _need(artifacts._tree_snapshot(copy, material.manifest) == trees[app.name], 'installer-copy-mismatch')
            _need(quarantine_policy.read(copy) == quarantine_policy.read(app), 'installer-quarantine-mismatch')
    profile = json.dumps(private_config, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    _write_shared(target / INSTALLERS_PROFILE, profile.encode('utf-8'))
    _write_shared(target / INSTALLERS_README, INSTALLERS_NOTE.encode('utf-8'))
    registry.sync_directory(target)
    os.chmod(str(target), 0o755)
    return target


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
    from offline_volume import parse_plist
    r = subprocess.run(['/usr/bin/hdiutil', 'info', '-plist'], stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=30, env=_env(registry.HOME, image.parents[3]))
    _need(r.returncode == 0 and len(r.stdout) <= 4 * MIB, 'disk-detach-could-not-be-confirmed')
    inventory = parse_plist(r.stdout)
    _need(type(inventory) is dict, 'invalid-disk-attachment-inventory')
    rows = inventory.get('images')
    _need(type(rows) is list and all(type(row) is dict and type(row.get('image-path')) is str for row in rows),
          'invalid-disk-attachment-inventory')
    _need(all(Path(row['image-path']).resolve() != image for row in rows), 'publication-disk-still-attached')


def _publication_acceptance(c, request):
    state = registry.read_private(c.state / 'build-current.json')
    _need(type(state) is dict and state.get('id') == c.job_id and state.get('name') == request['name']
          and state.get('mode') == MODE and state.get('phase') == 'publishing'
          and state.get('source_vm') is None and state.get('stage_path') == str(c.stage)
          and state.get('system_restored') is True
          and all(state.get(k) is False for k in ('guest_started', 'desktop_verified', 'published')),
          'publication-acceptance-missing')
    # Never written into: the restored disk must not have been started either.
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
            _publication_acceptance(c, request)
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
            for filename in ('disk.img', 'nvram.bin', '.clean-vm-installer.complete.json'):
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
    update('preparing_runtime', '准备首次设置文件夹并绑定受保护启动环境；不启动网络后端或 VM。')
    prepared = service.runtime(d, stored, update)
    registry.write_private(c.jobdir / 'runtime-preparation.json', prepared)
    update('publishing', '核对完成；仅发布这个新 VM，不覆盖或删除旧 VM。')
    target = service.publish(d, update)
    return update('awaiting_first_desktop_acceptance',
                  '全新 macOS 已发布，客机磁盘未写入任何东西。首次设置需单独确认，使用普通网络并挂只读安装文件夹：由你完成系统设置、用 Finder 安装 4 个应用、在 Clash 导入节点并授权，确认连上节点后标记完成；未验收桌面或 VPN 连通。',
                  1, published=True, stage_path=None, published_path=str(target),
                  needs_host_security_authorization=True, guest_started=False,
                  desktop_verified=False, vpn_connected=False, network_independently_verified=False)


def _worker_failure(c, update, error):
    value = registry.read_private(c.state / 'build-current.json', {})
    phase = value.get('phase')
    code = error_codes.public_code(error, 'preinstall-step-failed')
    product = getattr(error, 'product', None)
    failed_product = product if type(product) is str and product in MATERIAL_LABELS else None
    message = ('原始材料下载或校验未完成，尚未创建虚拟磁盘；已保留下载，不会自动重试。'
               if phase == 'acquiring' and not value.get('stage_path') else
               '预装未完成；保留所有暂存文件，不自动覆盖重试。请查看失败步骤。')
    return update('failed', message, failure_code=code, failed_phase=phase, failed_product=failed_product,
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
        value = update('installing', '全新 macOS 已恢复到暂存盘；不往客机磁盘写入任何东西。', 1,
                       system_restored=True, stage_path=str(c.stage))
        if defer:
            _require_detached(c.stage / 'disk.img')
            checkpoint = {'schema': 1, 'id': c.job_id, 'request': d, 'stage_stamps': _stage_stamps(c),
                          'materials': service.deferred_materials()}
            marker = c.jobdir / 'vpn-wait.json'
            _need(not os.path.lexists(marker), 'deferred-checkpoint-already-exists')
            registry.write_private(marker, checkpoint)
            _deferred_checkpoint(c, d, value)
            return update(PAUSE_PHASE, '系统已恢复到暂存盘，应用已下载核验。请补充 VPN 配置后继续；未发布、未开机。',
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
        update('resuming_vpn', '正在复核用于此 VM 的配置和同一批已审查材料；不重新恢复系统或重新下载。')
        service.load_deferred_materials(checkpoint['materials'])
        _require_detached(c.stage / 'disk.img')
        _deferred_checkpoint(c, initial, registry.read_private(c.state / 'build-current.json'))
        # The immutable original request remains in vpn-wait.json. The effective
        # request is written once under lock, only after this explicit VPN bind.
        d = dict(initial, **details)
        del d['defer_vpn']
        registry.write_private(c.jobdir / 'request.json', d)
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
