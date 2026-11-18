"""Offline preparation of a NEW private per-VM fence and user-run guest setup.

No VM/process lifecycle operations, downloads, mounting, package execution, host
settings or login-data copying. Never log the parsed profile or exception payloads.
The parent owns fresh VM/ECID/MAC creation and atomic publish/rollback. A prepared
environment is NOT an installed or verified guest. Python 3.9+, system Ruby/Psych.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
from managed_registry import validate_name

HERE = Path(__file__).resolve().parent
HOME = Path.home()
VM_ROOT = HOME / '.tart/vms'
CLASH_ROOT = HOME / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
NETWORK_SOURCE = HOME / 'Applications/GoldNetwork'
# The reviewed policy is project source, never a dependency on a private controller.
PACKET_SOURCE = HERE / 'packet_policy.py'
MIHOMO_SOURCE = Path('/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo')
CCBAGA_NAME = 'CCBaga-0.2.50-macos-arm64.dmg'
CCBAGA_SHA256 = '0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b'
PACKET_SHA256 = '3feded0b8521c8c1f71b880731c18b53f00df64162e114b7c6936474851da10a'
GV_SHA256 = 'e2a6825ba789fe588828b418c09aaf16525dec6d8cb2d16c94e72535dd4606be'
MIHOMO_SHA256 = '94c6fe434317ae5c00c6bc3dd6761fe0734edbd78ae205910108be186b0d968c'
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z', re.ASCII)
MAX_YAML_BYTES = 4 * 1024 * 1024
# Input is sent on stdin, not argv; Ruby error output is ALWAYS discarded. Psych
# safe_load prevents object construction/aliases. Duplicate keys are rejected by
# an AST pass rather than silently selecting a last value.
_RUBY_YAML = r'''
require 'yaml'; require 'json'
begin
  text = STDIN.read
  tree = Psych.parse_stream(text)
  walk = lambda do |n|
    if n.is_a?(Psych::Nodes::Mapping)
      keys = n.children.each_slice(2).map { |k,v| raise 'key' unless k.is_a?(Psych::Nodes::Scalar); k.value }
      raise 'duplicate' unless keys.uniq.length == keys.length
    end
    (n.children || []).each { |child| walk.call(child) }
  end
  walk.call(tree)
  obj = YAML.safe_load(text, permitted_classes: [], permitted_symbols: [], aliases: false)
  STDOUT.write(JSON.generate(obj))
rescue Exception
  exit 2
end
'''


class ProvisioningError(ValueError):
    """Only constant, non-secret error messages may cross the API boundary."""


def _fail(message):
    raise ProvisioningError(message) from None


def _canonical(path, *, exists=True):
    p = Path(path)
    if (not p.is_absolute() or '..' in p.parts or
            any(ord(c) < 32 or ord(c) == 127 or c in ':,' for c in str(p))):
        _fail('Unsafe provisioning path')
    if p.resolve(strict=exists) != p:
        _fail('Symlinked or noncanonical provisioning path')
    return p


def _regular(path):
    p = _canonical(path)
    info = p.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022):
        _fail('Source must be an owned, non-writable regular file')
    return p


def _digest(path):
    h = hashlib.sha256()
    with _regular(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _pin(path, digest):
    if _digest(path) != digest:
        _fail('Reviewed source digest mismatch; review the new version explicitly')
    return Path(path)


def _safe_yaml(path):
    p = _regular(path)
    if p.stat().st_size > MAX_YAML_BYTES:
        _fail('Clash YAML exceeds safety limit')
    result = subprocess.run(['/usr/bin/ruby', '-e', _RUBY_YAML], input=p.read_bytes(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15,
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'})
    if result.returncode or len(result.stdout) > MAX_YAML_BYTES * 2:
        _fail('Clash YAML could not be safely parsed')
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        _fail('Clash YAML produced invalid data')


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 4096 and not any(ord(c) < 32 for c in value)


def build_guest_profile(profile):
    """Return (private config, endpoint tuples, non-secret warnings).

    Deliberately supports only reviewed TUIC and TCP VLESS/Reality nodes with
    literal global IPv4 endpoints. No providers, scripts, host rules, host DNS,
    external UI, profile selection/history or controller credentials are copied.
    """
    if not isinstance(profile, dict) or not isinstance(profile.get('proxies'), list):
        _fail('Active local profile must contain explicit proxy nodes')
    raw_nodes = profile['proxies']
    if not 1 <= len(raw_nodes) <= 16:
        _fail('Active profile node count is unsupported')
    nodes, endpoints, warnings = [], [], []
    common = {'name', 'type', 'server', 'port', 'uuid', 'udp'}
    tuic = {'password', 'sni', 'alpn', 'congestion-controller', 'skip-cert-verify',
            'reduce-rtt', 'request-timeout', 'heartbeat-interval', 'disable-sni',
            'udp-relay-mode', 'max-udp-relay-packet-size'}
    vless = {'network', 'tls', 'flow', 'servername', 'client-fingerprint', 'reality-opts',
             'skip-cert-verify', 'packet-encoding'}
    for index, raw in enumerate(raw_nodes, 1):
        if not isinstance(raw, dict) or raw.get('type') not in ('tuic', 'vless'):
            _fail('Unsupported proxy node type; no permissive fallback')
        kind = raw['type']
        if set(raw) - common - (tuic if kind == 'tuic' else vless):
            _fail('Unsupported proxy options; manual review required')
        try:
            ip = ipaddress.IPv4Address(raw.get('server'))
        except (ValueError, TypeError, ipaddress.AddressValueError):
            _fail('Proxy server must be a literal global IPv4 address')
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            _fail('Proxy endpoint is not globally routable unicast IPv4')
        port = raw.get('port')
        if type(port) is not int or not 1 <= port <= 65535 or port == 53:
            _fail('Proxy endpoint port is invalid')
        if not _text(raw.get('uuid')):
            _fail('Proxy identity is missing')
        for key in ('udp', 'skip-cert-verify', 'tls', 'reduce-rtt', 'disable-sni'):
            if key in raw and type(raw[key]) is not bool:
                _fail('Proxy boolean option has invalid type')
        for key, value in raw.items():
            if key in ('alpn', 'reality-opts'):
                continue
            if not isinstance(value, (str, int, bool)) or isinstance(value, str) and not _text(value):
                _fail('Proxy scalar option has invalid type')
        if kind == 'tuic':
            if not _text(raw.get('password')) or not _text(raw.get('sni')):
                _fail('TUIC credentials or TLS server name are missing')
            if 'alpn' in raw and (not isinstance(raw['alpn'], list) or
                                  not all(_text(v) for v in raw['alpn'])):
                _fail('TUIC ALPN is invalid')
        else:
            if raw.get('network', 'tcp') != 'tcp' or raw.get('tls') is not True:
                _fail('Only TLS TCP VLESS is supported')
            reality = raw.get('reality-opts')
            if (not isinstance(reality, dict) or set(reality) != {'public-key', 'short-id'} or
                    not _text(reality['public-key']) or not isinstance(reality['short-id'], str) or
                    not re.fullmatch(r'[0-9a-fA-F]{0,16}', reality['short-id']) or len(reality['short-id']) % 2):
                _fail('Only explicit VLESS Reality options are supported')
        if raw.get('skip-cert-verify') is True:
            warnings.append('A copied node disables TLS certificate verification in the host profile')
        node = json.loads(json.dumps(raw))
        node['name'] = 'proxy-' + str(index)
        nodes.append(node)
        endpoints.append(('udp' if kind == 'tuic' else 'tcp', str(ip), port))
    config = {
        'mixed-port': 7890, 'allow-lan': False, 'bind-address': '127.0.0.1',
        'mode': 'rule', 'log-level': 'silent', 'ipv6': False,
        'external-controller': '127.0.0.1:9090', 'secret': secrets.token_urlsafe(32),
        'profile': {'store-selected': False, 'store-fake-ip': False},
        'tun': {'enable': True, 'stack': 'gvisor', 'auto-route': True,
                'strict-route': True, 'auto-detect-interface': True,
                'dns-hijack': ['any:53', 'tcp://any:53'], 'mtu': 1500},
        'dns': {'enable': True, 'listen': '127.0.0.1:1053', 'ipv6': False,
                'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'fake-ip-filter': [], 'use-hosts': False, 'use-system-hosts': False,
                'respect-rules': True,
                'nameserver': ['https://1.1.1.1/dns-query#PROXY'],
                'default-nameserver': ['1.1.1.1'], 'proxy-server-nameserver': []},
        'proxies': nodes,
        'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': [n['name'] for n in nodes]}],
        'rules': ['MATCH,PROXY'],
    }
    return config, sorted(set(endpoints)), sorted(set(warnings))


def _active_profile():
    index = _safe_yaml(CLASH_ROOT / 'profiles.yaml')
    if not isinstance(index, dict) or not isinstance(index.get('items'), list):
        _fail('Invalid Clash profile index')
    active = [p for p in index['items'] if isinstance(p, dict) and p.get('uid') == index.get('current')]
    if len(active) != 1 or active[0].get('type') != 'local':
        _fail('Exactly one active local Clash profile is required')
    filename = active[0].get('file')
    if (not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+\.ya?ml', filename)
            or filename.startswith('.')):
        _fail('Unsafe Clash profile filename')
    return build_guest_profile(_safe_yaml(CLASH_ROOT / 'profiles' / filename))


def _artifacts(artifact_dir):
    # artifact_dir is an optional EXISTING cache, never an output/log directory.
    cache = _canonical(artifact_dir if artifact_dir is not None else HOME / 'Downloads')
    dmg = _pin(cache / CCBAGA_NAME, CCBAGA_SHA256)
    core = _pin(MIHOMO_SOURCE, MIHOMO_SHA256)
    signature = subprocess.run([
        '/usr/bin/codesign', '--verify', '--strict', '-R',
        '=anchor apple generic and certificate leaf[subject.OU] = "JPH3Z7PPBB"', str(core)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if signature.returncode:
        _fail('Clash core code signature failed validation')
    return {'CCBaga-0.2.50-macos-arm64.dmg': dmg, 'mihomo': core}


def preflight(artifact_dir=None):
    """Read-only readiness check, safe to call BEFORE destructive lifecycle work.

    Returns no node names/endpoints/credentials. Does not cache private node data;
    prepare revalidates everything. Failure text is intentionally sanitized.
    """
    try:
        _, endpoints, warnings = _active_profile()
        _artifacts(artifact_dir)
        _pin(PACKET_SOURCE, PACKET_SHA256)
        _pin(NETWORK_SOURCE / 'gvproxy-darwin', GV_SHA256)
        for name in ('protected_launcher.py', 'runtime_shares.py', 'managed_registry.py',
                     'guest_setup/Install.command', 'guest_setup/install_guest.rb', 'guest_setup/README.txt'):
            _regular(HERE / name)
        return {'ready': True, 'endpoint_count': len(endpoints), 'warnings': warnings,
                'guest_setup_required': True, 'ccbaga_version': '0.2.50',
                'claude_strategy': 'guest-confirmed official native download with digest and Apple signing checks'}
    except ProvisioningError:
        raise
    except Exception:
        _fail('Provisioning prerequisites unavailable; no VM operation performed')


def _private_directory(path):
    p = _canonical(path)
    st = p.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        _fail('Destination parent must be a private owned directory')
    return p


def _write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _copy(source, target, mode=0o600):
    _regular(source)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as out, Path(source).open('rb') as src:
        os.fchmod(out.fileno(), mode)
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())


def prepare_environment(vm_name, vm_config, destination_private_base, artifact_dir=None):
    """Create an environment only; never run/stop/delete a VM or execute payloads.

    vm_config: Path of newly created Tart config.json (staging is acceptable).
    Its MAC/ECID are pinned, but future launch reads VM_ROOT/vm_name/config.json.
    Parent must ensure both identities are NEW/unique; no host inventory is mutated.
    destination_private_base: absent path, or an EMPTY private owned directory,
    within an existing private parent. Never point at an existing environment.
    artifact_dir: existing cache directory containing the pinned official CCBaga
    DMG; None uses ~/Downloads. No credentials may be placed in artifact_dir.
    On error incomplete private output is retained; caller owns exact rollback.
    """
    try:
        try:
            validate_name(vm_name)
        except ValueError:
            _fail('VM name does not satisfy the managed registry naming rules')
        preflight(artifact_dir)
        cfg_path = _regular(vm_config)
        if cfg_path.stat().st_size > 1024 * 1024:
            _fail('VM config exceeds safety limit')
        vm = json.loads(cfg_path.read_bytes())
        mac = vm.get('macAddress')
        if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            _fail('VM MAC address is invalid')
        octets = bytes.fromhex(mac.replace(':', ''))
        if octets == bytes(6) or octets[0] & 1 or mac.lower() == '5a:94:ef:e4:0c:dd':
            _fail('VM MAC must be a distinct unicast address')
        ecid = vm.get('ecid')
        if not isinstance(ecid, (str, int)) or isinstance(ecid, bool) or not re.fullmatch(r'[A-Za-z0-9+/=_-]{1,4096}', str(ecid)):
            _fail('VM ECID is missing or invalid')
        guest, endpoints, warnings = _active_profile()
        artifacts = _artifacts(artifact_dir)
        base = _canonical(destination_private_base, exists=False)
        _private_directory(base.parent)
        if base.exists():
            _private_directory(base)
            if any(base.iterdir()):
                _fail('Refusing to overwrite an existing environment')
        else:
            base.mkdir(mode=0o700)
        setup = base / 'setup'
        setup.mkdir(mode=0o700)
        copies = {'launcher.py': HERE / 'protected_launcher.py',
                  'packet_policy.py': PACKET_SOURCE,
                  'gvproxy-darwin': NETWORK_SOURCE / 'gvproxy-darwin',
                  'share_support.py': HERE / 'runtime_shares.py',
                  'managed_registry.py': HERE / 'managed_registry.py'}
        for name, source in copies.items():
            _copy(source, base / name, 0o700 if name in ('launcher.py', 'gvproxy-darwin') else 0o600)
        # Revalidate copied bytes, not only a source checked before copying.
        _pin(base / 'packet_policy.py', PACKET_SHA256)
        _pin(base / 'gvproxy-darwin', GV_SHA256)
        _write(base / 'policy.json', json.dumps({'guest_mac': mac.lower(), 'endpoints': endpoints}, sort_keys=True).encode())
        for name, source in artifacts.items():
            _copy(source, setup / name, 0o700 if name == 'mihomo' else 0o600)
        _pin(setup / CCBAGA_NAME, CCBAGA_SHA256)
        _pin(setup / 'mihomo', MIHOMO_SHA256)
        for name in ('Install.command', 'install_guest.rb', 'README.txt'):
            _copy(HERE / 'guest_setup' / name, setup / name, 0o700 if name == 'Install.command' else 0o600)
        _write(setup / 'config.json', json.dumps(guest, ensure_ascii=True, sort_keys=True).encode())
        meta = {'version': 1, 'vm_name': vm_name, 'vm_config': str(VM_ROOT / vm_name / 'config.json'),
                'guest_mac': mac.lower(), 'ecid': str(ecid), 'setup_active': True,
                'setup_status': 'awaiting_user_setup',
                'source_sha256': {p.name: _digest(p) for p in base.iterdir() if p.is_file()},
                'setup_sha256': {p.name: _digest(p) for p in setup.iterdir()}}
        _write(base / 'environment.json', json.dumps(meta, sort_keys=True).encode())
        return {'base': str(base), 'launcher': str(base / 'launcher.py'), 'setup_dir': str(setup),
                'metadata_path': str(base / 'environment.json'), 'status': 'awaiting_user_setup',
                'endpoint_count': len(endpoints), 'warnings': warnings,
                'software': {'clash': 'signed pinned core staged; user authorization required',
                             'ccbaga': 'official 0.2.50 A+B DMG staged',
                             'claude': 'guest-confirmed signed native download pending'}}
    except ProvisioningError:
        raise
    except Exception:
        _fail('Environment preparation failed; private incomplete output may remain')
