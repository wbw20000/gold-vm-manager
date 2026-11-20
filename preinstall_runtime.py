"""Explicit v2 preparation: no backend/Tart/VM execution, only native xattr policy.

No host profiles, legacy setup payload, downloaded execution, NAT fallback, native
signature override or import-time I/O. Parent owns material/native trust and guest
installation; receipts here bind bytes, not semantic or independent verification.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import unicodedata
import uuid

# gvproxy v0.9.0 from Podman 6.2.0's installer: Red Hat Developer ID, notarized
# (host_tools.ensure_gvproxy). Environments prepared before 2026-11-19 pinned the
# bare, unnotarized release binary, which macOS refuses to run while quarantined;
# refresh_environment moves them to this one.
GV_SHA256 = '45881c33400a14c4c50d4ed7e814b69a60248aa0d78e9b541e879edc05346a85'
_LEGACY_GV_SHA256 = 'e2a6825ba789fe588828b418c09aaf16525dec6d8cb2d16c94e72535dd4606be'
BACKEND_ASSESSMENT = 'developer-id-notarized-HYSCB8KRL2'
_UNNOTARIZED_ASSESSMENT = 'reviewed-sha256-only-adhoc-no-usable-native-signature'
# What a refresh keeps and still requires intact; everything else in the
# manifest is replaced from the current checkout and the pinned backend.
_KEPT = ('policy.json', 'preinstall-receipt.json', 'vpn-seed-receipt.json')
PACKET_SHA256 = '3feded0b8521c8c1f71b880731c18b53f00df64162e114b7c6936474851da10a'
HERE = Path(__file__).absolute().parent
_SOURCE_NAMES = {
    'launcher.py': 'protected_launcher.py', 'packet_policy.py': 'packet_policy.py',
    'share_support.py': 'runtime_shares.py', 'managed_registry.py': 'managed_registry.py',
    'preinstall_runtime.py': 'preinstall_runtime.py', 'quarantine_policy.py': 'quarantine_policy.py',
}
_MANIFEST = frozenset(_SOURCE_NAMES) | {
    'gvproxy-darwin', 'policy.json', 'preinstall-receipt.json', 'vpn-seed-receipt.json'}
_META_KEYS = frozenset({
    'version', 'vm_name', 'vm_config', 'vm_config_sha256', 'vm_config_identity', 'tart_home', 'ecid', 'guest_mac',
    'source_sha256', 'tart_binding', 'backend_quarantine_sha256',
    'needs_host_security_authorization', 'native_execution_approved', 'backend_assessment',
    'private_config_sha256', 'preinstall_receipt_sha256', 'vpn_seed_receipt_sha256',
    'guest_status_identity', 'guest_status_share', 'setup_active',
})
_MAX_RECORD = 4 * 1024 * 1024
# Host-only record outside the reviewed manifest. Absent: first setup is still
# pending and runs on Tart's normal network (owner's decision, 2026-11-19), so
# Setup Assistant can reach Apple before Clash exists. Once the person marks it
# finished, every later start is protected; the record never reverts.
NETWORK_MODE_NAME = 'network-mode.json'
_FINISHED_MODE = {'version': 1, 'mode': 'protected'}
FIRST_SETUP_NETWORK = 'first-setup-normal-network'


class RuntimePreparationError(RuntimeError):
    """Constant error codes only, never private payloads/paths/native output."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _need(value, code):
    if not value:
        raise RuntimePreparationError(code)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _name(value):
    _need(type(value) is str and 1 <= len(value) <= 64 and value == value.strip()
          and not value.startswith(('.', '-')) and not value.endswith('.')
          and all(c.isalnum() or c in ' _-' for c in value)
          and unicodedata.normalize('NFC', value) == value, 'invalid-vm-name')
    return value


def _path(value, missing=False):
    raw = os.fspath(value)
    _need(type(raw) is str and raw == str(Path(raw)) and Path(raw).is_absolute()
          and '..' not in Path(raw).parts and not raw.startswith('//')
          and not any(ord(c) < 32 or ord(c) == 127 or c in ':,' for c in raw), 'unsafe-path')
    path = Path(raw)
    for part in reversed((path,) + tuple(path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            _need(missing, 'missing-parent')
            continue
        _need(not stat.S_ISLNK(info.st_mode), 'symlink-path-refused')
        if part != path:
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            _need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                  and (not info.st_mode & 0o022 or sticky), 'unsafe-parent')
    return path


def _directory(path):
    path = _path(path)
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, 'private-directory-required')
    return path


def _identity(info):
    return [info.st_dev, info.st_ino]


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _regular(info, private):
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
          and info.st_uid in ((os.getuid(),) if private else (0, os.getuid()))
          and not stat.S_IMODE(info.st_mode) & 0o7022, 'unsafe-source-file')
    if private:
        _need(not stat.S_IMODE(info.st_mode) & 0o077, 'private-file-required')


def _read(path, private=True, cap=_MAX_RECORD):
    path = _path(path)
    before = path.lstat()
    _regular(before, private)
    _need(before.st_size <= cap, 'file-too-large')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        _regular(opened, private)
        _need(_stamp(before) == _stamp(opened), 'source-changed')
        chunks, total = [], 0
        while True:
            data = os.read(fd, min(1024 * 1024, cap - total + 1))
            if not data:
                break
            total += len(data)
            _need(total <= cap, 'file-too-large')
            chunks.append(data)
        _need(_stamp(opened) == _stamp(os.fstat(fd)) == _stamp(path.lstat())
              and total == opened.st_size, 'source-changed')
        return b''.join(chunks), opened
    finally:
        os.close(fd)


def _parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: _need(False, 'invalid-json-number'))


def _write(path, raw, mode=0o600):
    _directory(path.parent)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _need(count > 0, 'write-failed')
            view = view[count:]
        os.fsync(fd)
        info = os.fstat(fd)
        _regular(info, True)
        _need(_identity(info) == _identity(path.lstat()), 'destination-changed')
    finally:
        os.close(fd)
    _sync(path.parent)
    copied, _ = _read(path, cap=max(_MAX_RECORD, len(raw)))
    _need(_sha(copied) == _sha(raw), 'copied-digest-mismatch')


def _sync(path):
    fd = os.open(str(_directory(path)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _endpoints(values):
    _need(type(values) in (list, tuple) and 1 <= len(values) <= 128, 'invalid-endpoints')
    result = []
    for value in values:
        _need(type(value) in (list, tuple) and len(value) == 3, 'invalid-endpoints')
        protocol, address, port = value
        _need(protocol in ('tcp', 'udp') and type(address) is str
              and type(port) is int and 1 <= port <= 65535 and port != 53, 'invalid-endpoints')
        ip = ipaddress.IPv4Address(address)
        _need(str(ip) == address and ip.is_global and not ip.is_multicast and not ip.is_reserved,
              'invalid-endpoints')
        result.append((protocol, address, port))
    _need(len(set(result)) == len(result), 'duplicate-endpoints')
    return sorted(result)


def _private_config(private_config, endpoints):
    # Preparation-only dependency. Never calls legacy provisioning/_active_profile.
    from vpn_config import parse_submission
    _need(type(private_config) is dict and type(private_config.get('proxies')) is list,
          'validated-private-config-required')
    checked = parse_submission({'input_mode': 'fields', 'nodes': private_config['proxies']})
    _need(_json(private_config) == _json(checked.private_config), 'private-config-changed')
    _need(_endpoints(endpoints) == list(checked.endpoints), 'endpoint-config-mismatch')
    return _sha(_json(private_config))


def _vm_identity(raw):
    value = _parse(raw)
    _need(type(value) is dict, 'invalid-vm-config')
    mac, ecid = value.get('macAddress'), value.get('ecid')
    _need(type(mac) is str and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac),
          'invalid-vm-mac')
    octets = bytes.fromhex(mac.replace(':', ''))
    _need(octets != bytes(6) and not octets[0] & 1
          and mac.lower() != '5a:94:ef:e4:0c:dd', 'invalid-vm-mac')
    _need(type(ecid) in (str, int) and re.fullmatch(r'[A-Za-z0-9+/=_-]{1,4096}', str(ecid)),
          'invalid-vm-ecid')
    return mac.lower(), str(ecid)


def _vm_location(vm_name, vm_config, missing=False):
    path = _path(vm_config, missing=missing)
    _need(path.name == 'config.json' and path.parent.name == vm_name
          and path.parent.parent.name == 'vms', 'explicit-vm-config-binding-required')
    vm_root = _path(path.parent.parent)
    info = vm_root.stat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and not info.st_mode & 0o022, 'unsafe-published-vm-root')
    return path, path.parent.parent.parent


def _verified_backend(path):
    """Single scoped pin-verification seam for inert fixtures; never runtime config."""
    raw, info = _read(path, private=False, cap=64 * 1024 * 1024)
    _need(_sha(raw) == GV_SHA256, 'reviewed-backend-digest-mismatch')
    return raw, info


def _tart_binding(path):
    path = _path(path)
    raw, info = _read(path, private=False, cap=128 * 1024 * 1024)
    _need(bool(info.st_mode & stat.S_IXUSR), 'tart-not-executable')
    # Native signatures were checked by the parent. We bind that exact supplied
    # inode and content, not a default app path, command lookup or native approval.
    return {'path': str(path), 'sha256': _sha(raw), 'identity': _identity(info),
            'size_bytes': info.st_size}


def _quarantine(path):
    import quarantine_policy
    names = quarantine_policy._run([str(path)]).decode('utf-8', errors='strict').splitlines()
    return quarantine_policy.read(path) if quarantine_policy.NAME in names else None


def _preserve_quarantine(source, target, expected):
    import quarantine_policy
    _need(_quarantine(source) == expected, 'source-quarantine-changed')
    if expected is not None:
        quarantine_policy.propagate(source, target)
    _need(_quarantine(target) == expected, 'copied-quarantine-mismatch')


def _qhash(value):
    return None if value is None else _sha(value)


def _quarantine_kept(path, meta):
    # Gatekeeper may update the flags once it has assessed the notarized backend.
    # The signed backend must retain quarantine. Record the original digest,
    # but let macOS update the flags without forcing another download or refresh.
    digest = meta['backend_quarantine_sha256']
    return (type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None
            and _quarantine(path) is not None)


def _receipt_bytes(path):
    raw, _ = _read(path)
    _need(type(_parse(raw)) is dict, 'private-receipt-object-required')
    return raw


def prepare_environment(vm_name, vm_config, destination_private_base, *, published_vm_config,
                        private_config, endpoints, gvproxy_path, tart_path,
                        preinstall_receipt, vpn_seed_receipt):
    """Prepare before publication, never launch or grant host authorization.

    vm_config is the existing staged private config. published_vm_config is the
    explicit future <Tart home>/vms/<vm_name>/config.json, absent unless identical
    to vm_config. Same-filesystem directory publication must retain its inode.
    Call BEFORE acquiring a POSIX config publication lock: reading/closing the
    config here must never release a lock already held by the parent process.
    Receipts are explicit private JSON paths; private_config is the unchanged
    vpn_config dictionary, never a host profile or implicit source selector.
    """
    try:
        vm_name = _name(vm_name)
        vm_config = _path(vm_config)
        _need(vm_config.name == 'config.json', 'invalid-staged-config-name')
        published, tart_home = _vm_location(vm_name, published_vm_config, missing=True)
        _need(published == vm_config or not published.exists(), 'published-config-already-exists')
        vm_raw, vm_info = _read(vm_config)
        mac, ecid = _vm_identity(vm_raw)
        endpoints = _endpoints(endpoints)
        config_sha = _private_config(private_config, endpoints)
        receipts = {'preinstall-receipt.json': _receipt_bytes(preinstall_receipt),
                    'vpn-seed-receipt.json': _receipt_bytes(vpn_seed_receipt)}
        backend, backend_info = _verified_backend(gvproxy_path)
        source_q = _quarantine(_path(gvproxy_path))
        _need(bool(source_q), 'backend-source-quarantine-required')
        tart = _tart_binding(tart_path)
        sources = {name: _read(HERE / source, private=False)[0]
                   for name, source in _SOURCE_NAMES.items()}
        _need(_sha(sources['packet_policy.py']) == PACKET_SHA256, 'reviewed-policy-digest-mismatch')
        base = _path(destination_private_base, missing=True)
        _directory(base.parent)
        _need(not base.exists(), 'destination-must-be-new')
        base.mkdir(mode=0o700)
        _sync(base.parent)
        mailbox = base / 'guest-status'
        mailbox.mkdir(mode=0o700)
        _sync(base)
        for name, raw in sources.items():
            _write(base / name, raw, 0o700 if name == 'launcher.py' else 0o600)
        # Preserve only an already-present owner execute bit. Preparing material
        # never newly marks an unsigned download executable or authorizes it.
        backend_mode = 0o700 if backend_info.st_mode & stat.S_IXUSR else 0o600
        _write(base / 'gvproxy-darwin', backend, backend_mode)
        copied_backend, _ = _verified_backend(base / 'gvproxy-darwin')
        _need(_sha(copied_backend) == _sha(backend), 'copied-backend-mismatch')
        _preserve_quarantine(_path(gvproxy_path), base / 'gvproxy-darwin', source_q)
        _write(base / 'policy.json', _json({'guest_mac': mac, 'endpoints': endpoints}))
        for name, raw in receipts.items():
            _write(base / name, raw)
        manifest = {name: _sha(_read(base / name, cap=64 * 1024 * 1024)[0]) for name in _MANIFEST}
        meta = {
            'version': 2, 'vm_name': vm_name, 'vm_config': str(published),
            'vm_config_sha256': _sha(vm_raw), 'vm_config_identity': _identity(vm_info),
            'tart_home': str(tart_home),
            'ecid': ecid, 'guest_mac': mac, 'source_sha256': manifest,
            'tart_binding': tart, 'backend_quarantine_sha256': _qhash(source_q),
            'needs_host_security_authorization': True, 'native_execution_approved': False,
            'backend_assessment': BACKEND_ASSESSMENT,
            'private_config_sha256': config_sha,
            'preinstall_receipt_sha256': manifest['preinstall-receipt.json'],
            'vpn_seed_receipt_sha256': manifest['vpn-seed-receipt.json'],
            'guest_status_identity': _identity(mailbox.stat()),
            'guest_status_share': 'gold-status', 'setup_active': False,
        }
        _write(base / 'environment.json', _json(meta))
        _validate_environment(base, meta, staged_vm_config=vm_config)
        _need(published == vm_config or not published.exists(), 'published-config-appeared')
        return {'version': 2, 'base': str(base), 'launcher': str(base / 'launcher.py'),
                'metadata_path': str(base / 'environment.json'),
                'status': 'awaiting_host_authorization', 'endpoint_count': len(endpoints),
                'needs_host_security_authorization': True, 'native_execution_approved': False,
                'backend_requires_executable_permission': not bool(backend_info.st_mode & stat.S_IXUSR),
                'guest_bootstrap_evidence': 'not_observed', 'desktop_verified': False,
                'network_independently_verified': False}
    except RuntimePreparationError:
        raise
    except Exception:
        raise RuntimePreparationError('runtime-preparation-failed') from None


def validate_environment(base, meta=None):
    """Validate a published v2 only; no staging override at the launch boundary."""
    return _validate_environment(base, meta)


def _validate_environment(base, meta=None, staged_vm_config=None, *, refreshable=False):
    try:
        base = _directory(base)
        stored = _parse(_read(base / 'environment.json')[0])
        _need(meta is None or _json(meta) == _json(stored), 'environment-metadata-changed')
        meta = stored
        _need(type(meta) is dict and set(meta) == _META_KEYS and type(meta['version']) is int
              and meta['version'] == 2 and meta['setup_active'] is False,
              'invalid-v2-environment')
        name = _name(meta['vm_name'])
        _need(meta['needs_host_security_authorization'] is True
              and meta['native_execution_approved'] is False
              and meta['backend_assessment'] in ((BACKEND_ASSESSMENT, _UNNOTARIZED_ASSESSMENT)
                                                 if refreshable else (BACKEND_ASSESSMENT,)),
              'invalid-backend-authorization-contract')
        _need(type(meta['source_sha256']) is dict and set(meta['source_sha256']) == _MANIFEST,
              'incomplete-v2-source-manifest')
        _need(not (base / 'setup').exists() and not (base / 'setup').is_symlink(),
              'legacy-setup-refused')
        for name, expected in meta['source_sha256'].items():
            if refreshable and name not in _KEPT:
                continue
            raw, _ = _read(base / name, cap=64 * 1024 * 1024)
            _need(_sha(raw) == expected, 'environment-source-integrity-mismatch')
        _need(meta['source_sha256']['packet_policy.py'] == PACKET_SHA256,
              'reviewed-policy-digest-mismatch')
        _need(meta['preinstall_receipt_sha256'] == meta['source_sha256']['preinstall-receipt.json']
              and meta['vpn_seed_receipt_sha256'] == meta['source_sha256']['vpn-seed-receipt.json']
              and type(meta['private_config_sha256']) is str
              and re.fullmatch('[0-9a-f]{64}', meta['private_config_sha256']), 'invalid-private-receipt-pins')
        _validate_bindings(base, meta, staged_vm_config, backend=not refreshable)
        return meta
    except RuntimePreparationError:
        raise
    except Exception:
        raise RuntimePreparationError('invalid-v2-environment') from None


def validate_bindings(base, meta):
    """Recheck published Tart/config, pinned backend/quarantine and owned mailbox."""
    try:
        return _validate_bindings(base, meta)
    except RuntimePreparationError:
        raise
    except Exception:
        raise RuntimePreparationError('runtime-binding-validation-failed') from None


def _validate_bindings(base, meta, staged_vm_config=None, *, backend=True):
    base = _directory(base)
    path, tart_home = _vm_location(meta['vm_name'], meta['vm_config'],
                                   missing=staged_vm_config is not None)
    raw, info = _read(path if staged_vm_config is None else staged_vm_config)
    mac, ecid = _vm_identity(raw)
    _need(_sha(raw) == meta['vm_config_sha256'] and _identity(info) == meta['vm_config_identity']
          and str(tart_home) == meta['tart_home'] and mac == meta['guest_mac']
          and ecid == meta['ecid'], 'vm-config-binding-changed')
    policy_raw, _ = _read(base / 'policy.json')
    _need(_sha(policy_raw) == meta['source_sha256']['policy.json'], 'policy-binding-changed')
    policy = _parse(policy_raw)
    _need(type(policy) is dict and set(policy) == {'guest_mac', 'endpoints'}
          and policy['guest_mac'] == mac, 'invalid-v2-policy')
    _endpoints(policy['endpoints'])
    _need(_tart_binding(meta['tart_binding']['path']) == meta['tart_binding'], 'tart-binding-changed')
    if backend:
        raw, _ = _verified_backend(base / 'gvproxy-darwin')
        _need(_sha(raw) == meta['source_sha256']['gvproxy-darwin'], 'backend-binding-changed')
        _need(_quarantine_kept(base / 'gvproxy-darwin', meta), 'backend-quarantine-changed')
    status_directory(base, meta)


def validate_environment_for_refresh(base):
    """Only what refresh_environment keeps: VM/Tart bindings, policy, receipts, mailbox."""
    return _validate_environment(base, refreshable=True)


def first_setup_pending(base):
    """True until the person marks first setup finished; then always False.

    Only the exact private record {"version":1,"mode":"protected"} ends first
    setup. Anything else at that name fails closed and is never overwritten.
    """
    try:
        base = _directory(base)
        record = base / NETWORK_MODE_NAME
        if not os.path.lexists(str(record)):
            return True
        raw, _ = _read(record, cap=4096)
        _need(_json(_parse(raw)) == _json(_FINISHED_MODE), 'invalid-network-mode')
        return False
    except Exception:
        raise RuntimePreparationError('invalid-network-mode') from None


def require_first_setup(base):
    _need(first_setup_pending(base), 'first-setup-finished')


def finish_first_setup(base):
    """Record, once, that every later start is protected. Returns False if already recorded."""
    staged = None
    try:
        base = _directory(base)
        if not first_setup_pending(base):
            return False
        staged = base / ('.' + NETWORK_MODE_NAME + '-' + uuid.uuid4().hex)
        _write(staged, _json(_FINISHED_MODE))
        os.replace(str(staged), str(base / NETWORK_MODE_NAME))
        staged = None
        _sync(base)
        _need(not first_setup_pending(base), 'network-mode-write-failed')
        return True
    except RuntimePreparationError:
        raise
    except Exception:
        raise RuntimePreparationError('network-mode-write-failed') from None
    finally:
        if staged is not None:
            try:
                os.unlink(str(staged))  # Only this call's own unpublished temporary file.
            except OSError:
                pass


def _current_sources():
    files = {name: _read(HERE / source, private=False)[0] for name, source in _SOURCE_NAMES.items()}
    _need(_sha(files['packet_policy.py']) == PACKET_SHA256, 'reviewed-policy-digest-mismatch')
    return files


def _publish_files(base, meta, files, staged, *, backend_source=None, source_q=None, **updates):
    """Write each file as a new private temporary, atomically replace, then rewrite the record."""
    manifest = dict(meta['source_sha256'])
    pending = []
    for name, raw in files.items():
        temporary = base / ('.' + name + '-' + uuid.uuid4().hex)
        staged.append(temporary)
        _write(temporary, raw, 0o700 if name == 'launcher.py' else 0o600)
        if name == 'gvproxy-darwin':
            _preserve_quarantine(backend_source, temporary, source_q)
        manifest[name] = _sha(raw)
        pending.append((temporary, name))
    for temporary, name in pending:
        os.replace(str(temporary), str(base / name))
        staged.remove(temporary)
    _sync(base)
    record = base / ('.environment-' + uuid.uuid4().hex)
    staged.append(record)
    _write(record, _json(dict(meta, source_sha256=manifest, **updates)))
    os.replace(str(record), str(base / 'environment.json'))
    staged.remove(record)
    _sync(base)


def _discard(staged):
    for path in staged:
        try:
            os.unlink(str(path))  # Only this call's own unpublished temporary files.
        except OSError:
            pass


def environment_sources_outdated(base):
    """True if an intact, signed environment holds older launcher code than this build.

    Raises if anything in the environment changed; that is never repaired.
    """
    meta = validate_environment(base)
    return any(meta['source_sha256'][name] != _sha(raw) for name, raw in _current_sources().items())


def refresh_sources(base):
    """Give an intact, signed environment this build's reviewed code; nothing else.

    The backend copy and its quarantine, packet-filter policy, receipts, VM and
    Tart bindings and the mailbox are kept and must validate before and after.
    Returns True if any code file was replaced.
    """
    staged = []
    try:
        base = _directory(base)
        meta = validate_environment(base)
        files = {name: raw for name, raw in _current_sources().items()
                 if _sha(raw) != meta['source_sha256'][name]}
        if not files:
            return False
        _publish_files(base, meta, files, staged)
        _validate_environment(base)
        return True
    except RuntimePreparationError:
        raise
    except Exception:
        raise RuntimePreparationError('environment-refresh-failed') from None
    finally:
        _discard(staged)


def environment_needs_refresh(base):
    """True if a published environment must take the current launcher code and backend.

    Raises if anything a refresh keeps has changed; that is never repaired.
    """
    meta = validate_environment_for_refresh(base)
    if meta['backend_assessment'] == _UNNOTARIZED_ASSESSMENT:
        _need(meta['source_sha256']['gvproxy-darwin'] == _LEGACY_GV_SHA256,
              'unknown-legacy-backend-pin')
        return True
    # A current signed environment that lost quarantine or has modified files
    # must fail closed, not be silently repaired by the legacy migration.
    validate_environment(base, meta)
    return False


def refresh_environment(base, gvproxy_path):
    """Give a published environment the current sources and the signed backend.

    For environments that pinned the unnotarized backend, or whose backend copy
    is gone. The VM and Tart bindings, packet-filter policy, both private
    receipts and the status mailbox are kept and must still validate. The new
    backend copy is 0600 and carries its source's quarantine, so macOS still
    assesses it at launch. Returns True if anything was replaced.
    """
    staged = []
    try:
        base = _directory(base)
        if not environment_needs_refresh(base):
            return False
        meta = validate_environment_for_refresh(base)
        backend, _ = _verified_backend(gvproxy_path)
        source_q = _quarantine(_path(gvproxy_path))
        _need(bool(source_q), 'backend-source-quarantine-required')
        files = _current_sources()
        files['gvproxy-darwin'] = backend
        _publish_files(base, meta, files, staged, backend_source=_path(gvproxy_path), source_q=source_q,
                       backend_assessment=BACKEND_ASSESSMENT, backend_quarantine_sha256=_qhash(source_q))
        _validate_environment(base)
        return True
    except RuntimePreparationError:
        raise
    except Exception:
        raise RuntimePreparationError('environment-refresh-failed') from None
    finally:
        _discard(staged)


def status_directory(base, meta):
    base = _directory(base)
    mailbox = _directory(base / 'guest-status')
    _need(meta['guest_status_share'] == 'gold-status'
          and _identity(mailbox.stat()) == meta['guest_status_identity'], 'guest-status-directory-changed')
    return mailbox


def require_backend_authorization(meta, acknowledged):
    _need(type(acknowledged) is bool, 'invalid-authorization-acknowledgement')
    _need(meta.get('needs_host_security_authorization') is True
          and meta.get('native_execution_approved') is False, 'invalid-backend-authorization-contract')
    _need(acknowledged, 'awaiting-host-authorization')
    # An acknowledgement authorizes only requesting normal platform execution;
    # it is neither a signature pass nor a Gatekeeper policy change.


def backend_is_executable(base):
    _, info = _verified_backend(_directory(base) / 'gvproxy-darwin')
    _need(bool(info.st_mode & stat.S_IXUSR), 'backend-not-executable')


def authorize_backend_execution_bit(base, meta, *, acknowledged=False):
    """Only the reviewed private copy, under the launcher lock and fresh consent.

    Never change quarantine flags, claim native approval or invoke Gatekeeper
    controls. The subsequent normal OS launch can still be refused.
    """
    require_backend_authorization(meta, acknowledged)
    path = _directory(base) / 'gvproxy-darwin'
    _, before = _verified_backend(path)
    _need(_quarantine_kept(path, meta), 'backend-quarantine-changed')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        _regular(opened, private=True)
        _need(_stamp(opened) == _stamp(before) and _identity(path.lstat()) == _identity(opened), 'backend-binding-changed')
        mode = stat.S_IMODE(opened.st_mode)
        _need(mode in (0o600, 0o700), 'unexpected-backend-mode')
        if mode == 0o600:
            os.fchmod(fd, 0o700)
            os.fsync(fd)
    finally:
        os.close(fd)
    backend_is_executable(base)
    _need(_quarantine_kept(path, meta), 'backend-quarantine-changed')


def build_tart_command(base, meta, vm_name, network_fd, share_plan, no_graphics=False, recovery=False,
                       *, first_setup=False):
    _need(vm_name == meta['vm_name'], 'invalid-v2-launch-binding')
    if first_setup:
        # Tart's own normal network for first setup only: no fenced NIC, no filter.
        _need(network_fd is None and not recovery, 'invalid-v2-launch-binding')
        command = [meta['tart_binding']['path'], 'run', vm_name, '--no-clipboard']
    else:
        _need(type(network_fd) is int and network_fd >= 0, 'invalid-v2-launch-binding')
        command = [meta['tart_binding']['path'], 'run', vm_name, '--net-fd=' + str(network_fd), '--no-clipboard']
    if recovery:
        command.append('--recovery')
    else:
        _need(share_plan is not None, 'user-share-plan-required')
        _need(not any(s['name'].casefold() in ('setup', 'gold-status') for s in share_plan.shares),
              'reserved-share-name')
        mailbox = status_directory(base, meta)
        command.append('--dir=gold-status:' + str(mailbox))  # The only special RW share.
        command.extend(share_plan.arguments)
    if no_graphics:
        command.append('--no-graphics')
    return command


def read_guest_status(base, receipt_token):
    """Bounded constant-only untrusted self-report; NEVER independent success."""
    try:
        _need(type(receipt_token) is str and re.fullmatch('[0-9a-f]{64}', receipt_token),
              'invalid-receipt-token')
        base = _directory(base)
        meta = _parse(_read(base / 'environment.json')[0])
        mailbox = status_directory(base, meta)
        path = _path(mailbox / (receipt_token + '.json'), missing=True)
        if not path.exists():
            return {'evidence': 'not_observed', 'desktop_verified': False,
                    'network_independently_verified': False}
        raw, _ = _read(path, cap=4096)
        value = _parse(raw)
        _need(type(value) is dict and set(value) == {
            'schema_version', 'evidence', 'configuration', 'application',
            'system_authorization', 'connection_check', 'host_independently_verified'},
            'invalid-guest-self-report')
        _need(type(value['schema_version']) is int and value['schema_version'] == 1
              and value['evidence'] == 'guest_reported'
              and value['configuration'] in ('imported', 'manual_recovery_required')
              and value['application'] in ('not_started', 'opened', 'launch_request_pending',
                                           'launch_failed_or_authorization_pending')
              and value['system_authorization'] == 'user_action_may_be_required'
              and value['connection_check'] == 'not_run'
              and value['host_independently_verified'] is False, 'invalid-guest-self-report')
        return dict(value, desktop_verified=False, network_independently_verified=False)
    except RuntimePreparationError:
        raise
    except Exception:
        raise RuntimePreparationError('invalid-guest-self-report') from None
