"""Private tickets for explicit VPN submissions; never discovers host VPN profiles.

Only opaque IDs and fixed summaries are public. Unclaimed tickets expire;
claimed tickets can only be retrieved for the job that claimed them. A ticket
can also be issued again for a configuration kept with one of the manager's
own VMs (store_saved); that is still the person's explicit choice.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Optional
import time
import unicodedata
import uuid

from vpn_config import (MAX_INPUT_BYTES, SUPPORTED_TYPES, VPNConfigurationError,
                        _hostname, _NAME_WARNING, _PIN_WARNING, _POLICY_WARNING,
                        _public_ipv4, _WARNINGS, parse_submission)

MAX_AGE_SECONDS = 3600
MAX_CONFIG_BYTES = MAX_INPUT_BYTES
# Space beyond the parser's input limit for generated policy, fence and metadata.
_MAX_RECORD_BYTES = MAX_CONFIG_BYTES + 16 * 1024
_MAX_YAML_PATH_BYTES = 4096
_ID = re.compile(r'[0-9a-f]{32}\Z')
_HEX256 = re.compile(r'[0-9a-f]{64}\Z')
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_VERSION = 2
_CONSENT = 'explicit_user_submission'
_RECORD_KEYS = {'version', 'configuration_id', 'created_unix', 'consent',
                'private_config', 'endpoints', 'summary', 'digest', 'bound_job', 'record_digest'}
_SUMMARY_KEYS = {'node_count', 'endpoint_count', 'protocols', 'warnings', 'normalization_required'}
_SAFE_WARNINGS = frozenset((*_WARNINGS.values(), _NAME_WARNING, _PIN_WARNING, _POLICY_WARNING))
_DEFAULT_RESOLVER = object()

_INVALID_RECORD = '网络配置记录无效；请重新校验上传'
_INTEGRITY = '网络配置完整性不匹配；请重新校验上传'
_UNSAFE_DIR = 'VPN 存储目录必须为当前用户的私有目录'
_UNSAFE_FILE = 'VPN 存储文件的身份、权限或大小无效'
_MISSING = '未找到网络配置；请重新校验上传'
_IO_ERROR = '无法访问私有网络配置存储'
_TIME = '网络配置时间无效'
_EXPIRY = '网络配置确认已过期，请重新校验上传'
_BINDING = '网络配置已用于另一任务，请重新确认上传'
_DNS_ERROR = 'VPN 服务器 DNS 查询失败；未连接任何节点'
_COLLISION = '网络配置编号冲突；未覆盖原文件'
_YAML_PATH = '请指定规范的本地 YAML 绝对路径（.yaml 或 .yml）'
_UNSAFE_YAML = '无法安全读取指定的 YAML 文件；请检查文件类型、身份、权限、大小和编码'

_RESOLVE = r'''
import json,socket,sys
try:
 host=json.loads(sys.stdin.read(1024))
 answers=sorted({row[4][0] for row in socket.getaddrinfo(host+'.',None,socket.AF_INET,socket.SOCK_STREAM)})
 if not answers or len(answers)>16:raise ValueError()
 sys.stdout.write(json.dumps(answers))
except BaseException:
 sys.exit(2)
'''


class VPNStoreError(ValueError):
    """Errors suitable for display: messages never include inputs or paths."""


def _need(value, message):
    if not value:
        raise VPNStoreError(message) from None


@contextmanager
def _private_io():
    try:
        yield
    except (VPNStoreError, VPNConfigurationError):
        raise
    except FileNotFoundError:
        raise VPNStoreError(_MISSING) from None
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        raise VPNStoreError(_IO_ERROR) from None


def resolve_public_hostname(host):
    """Opt-in DNS only; query a fully qualified hostname in a bounded helper."""
    _need(_hostname(host), 'VPN 服务器域名无效')
    try:
        result = subprocess.run(
            ['/usr/bin/python3', '-I', '-B', '-c', _RESOLVE],
            input=json.dumps(host.lower()).encode('ascii'), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=12, cwd='/',
            env={'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'},
        )
        _need(result.returncode == 0 and len(result.stdout) <= 4096, _DNS_ERROR)
        answers = json.loads(result.stdout)
        _need(type(answers) is list and 1 <= len(answers) <= 16, _DNS_ERROR)
        return tuple(_public_ipv4(answer) for answer in answers)
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        raise VPNStoreError(_DNS_ERROR) from None


@dataclass(frozen=True, repr=False)
class StoredVPN:
    configuration_id: str
    private_config: dict = field(repr=False)
    endpoints: tuple[tuple[str, str, int], ...] = field(repr=False)
    summary: dict
    digest: str = field(repr=False)
    bound_job: Optional[str] = None

    def __repr__(self):
        return 'StoredVPN(<private configuration>)'


def _opaque_id(value):
    return type(value) is str and _ID.fullmatch(value) is not None


def _ticket_name(configuration_id):
    _need(_opaque_id(configuration_id), '网络配置编号无效')
    return configuration_id + '.json'


def _job_id(job_id):
    _need(_opaque_id(job_id), '创建任务编号无效')


def _timestamp(value):
    # Excludes booleans, nonfinite numbers and integers outside exact JSON range.
    _need(type(value) in (int, float) and 0 <= value <= (1 << 53) - 1, _TIME)
    return value


def _clock(now):
    return _timestamp(time.time() if now is None else now)


def _private_directory(info):
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, _UNSAFE_DIR)


def _private_file(info):
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
          and 0 <= info.st_size <= _MAX_RECORD_BYTES, _UNSAFE_FILE)


def _inode(info):
    return info.st_dev, info.st_ino


def _snapshot(info):
    return (_inode(info), info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_root(state, *, create=False):
    # Pin the directory chain using openat, not a check-then-follow path lookup.
    fd = os.open('/', _DIR_FLAGS)
    try:
        for component in state.parts[1:]:
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _private_directory(os.fstat(fd))
        if create:
            try:
                os.mkdir('vpn-inputs', 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            else:
                os.fsync(fd)
        root = os.open('vpn-inputs', _DIR_FLAGS, dir_fd=fd)
        try:
            _private_directory(os.fstat(root))
        except BaseException:
            os.close(root)
            raise
        return root
    finally:
        os.close(fd)


def _same_root(state, fd):
    current = _open_root(state)
    try:
        _need(_inode(os.fstat(current)) == _inode(os.fstat(fd)), _UNSAFE_DIR)
    finally:
        os.close(current)


@contextmanager
def _locked_root(state_dir, *, create=False, exclusive=False):
    state = Path(state_dir)
    _need(state.anchor == '/' and state.name and '..' not in state.parts, _UNSAFE_DIR)
    fd = _open_root(state, create=create)
    try:
        # Lock the store itself: no writable lock pathname or second lock inode.
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        _same_root(state, fd)
        yield state, fd
    finally:
        os.close(fd)


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('utf-8')


def _digest(config, endpoints):
    return hashlib.sha256(_json_bytes({'config': config, 'endpoints': endpoints})).hexdigest()


def _record_digest(record):
    # A corruption check, not authentication against another same-UID writer.
    return hashlib.sha256(_json_bytes({k: v for k, v in record.items() if k != 'record_digest'})).hexdigest()


def _strict_pairs(items):
    value = {}
    for key, child in items:
        _need(key not in value, _INVALID_RECORD)
        value[key] = child
    return value


def _parse_int(value):
    _need(len(value) <= 20, _INVALID_RECORD)
    return int(value)


def _parse_float(value):
    _need(len(value) <= 64, _INVALID_RECORD)
    result = float(value)
    _need(math.isfinite(result), _INVALID_RECORD)
    return result


def _invalid_constant(_):
    raise VPNStoreError(_INVALID_RECORD) from None


def _entry(fd, name):
    return os.stat(name, dir_fd=fd, follow_symlinks=False)


def _yaml_path_parts(path):
    _need(type(path) is str and path.startswith('/') and len(path) <= _MAX_YAML_PATH_BYTES, _YAML_PATH)
    _need(not any(unicodedata.category(c) in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp'} for c in path)
          and len(path.encode('utf-8')) <= _MAX_YAML_PATH_BYTES, _YAML_PATH)
    # Split without normalization: duplicate or trailing slashes and dot
    # components must not silently change the user's specified path.
    parts = path[1:].split('/')
    _need(all(part not in {'', '.', '..'} for part in parts)
          and Path(parts[-1]).suffix.lower() in {'.yaml', '.yml'}, _YAML_PATH)
    return parts


@contextmanager
def _yaml_parent(parts):
    fd = os.open('/', _DIR_FLAGS)
    try:
        ancestry = [_inode(os.fstat(fd))]
        for component in parts[:-1]:
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
            ancestry.append(_inode(os.fstat(fd)))
        yield fd, ancestry
    finally:
        os.close(fd)


def _same_yaml_path(parts, ancestry, expected):
    with _yaml_parent(parts) as (parent, current_ancestry):
        _need(current_ancestry == ancestry and _snapshot(_entry(parent, parts[-1])) == expected,
              _UNSAFE_YAML)


def _read_yaml_path(path):
    parts = _yaml_path_parts(path)
    name = parts[-1]
    try:
        with _yaml_parent(parts) as (parent, ancestry):
            initial = _entry(parent, name)
            _need(stat.S_ISREG(initial.st_mode) and initial.st_uid == os.getuid()
                  and initial.st_nlink == 1 and not initial.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                  and 0 <= initial.st_size <= MAX_INPUT_BYTES, _UNSAFE_YAML)
            expected = _snapshot(initial)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                _need(_snapshot(os.fstat(fd)) == expected, _UNSAFE_YAML)
                # Rewalk from / to detect a renamed or replaced ancestor; the
                # pinned parent alone could still refer to the old path.
                _same_yaml_path(parts, ancestry, expected)
                raw = os.pread(fd, initial.st_size, 0)
                _need(len(raw) == initial.st_size and _snapshot(os.fstat(fd)) == expected, _UNSAFE_YAML)
                _same_yaml_path(parts, ancestry, expected)
            finally:
                os.close(fd)
        return raw.decode('utf-8')
    except (OSError, UnicodeError):
        raise VPNStoreError(_UNSAFE_YAML) from None


def _read_record(fd, name):
    initial = _entry(fd, name)
    _private_file(initial)
    current = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        _need(_snapshot(os.fstat(current)) == _snapshot(initial), _UNSAFE_FILE)
        raw = os.pread(current, _MAX_RECORD_BYTES + 1, 0)
        _need(len(raw) == initial.st_size and _snapshot(os.fstat(current)) == _snapshot(initial)
              and _snapshot(_entry(fd, name)) == _snapshot(initial), _UNSAFE_FILE)
    finally:
        os.close(current)
    try:
        record = json.loads(raw.decode('utf-8'), object_pairs_hook=_strict_pairs,
                            parse_int=_parse_int, parse_float=_parse_float, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise VPNStoreError(_INVALID_RECORD) from None
    return record, initial


def _check_digest(value, expected):
    _need(type(value) is str and _HEX256.fullmatch(value) and hmac.compare_digest(value, expected), _INTEGRITY)


def _check_summary(summary, normalized):
    _need(type(summary) is dict and set(summary) == _SUMMARY_KEYS, _INVALID_RECORD)
    for key in ('node_count', 'endpoint_count'):
        _need(type(summary[key]) is int and summary[key] == normalized[key], _INVALID_RECORD)
    protocols = summary['protocols']
    _need(type(protocols) is list and protocols == normalized['protocols']
          and all(type(p) is str and p in SUPPORTED_TYPES for p in protocols), _INVALID_RECORD)
    warnings = summary['warnings']
    _need(type(warnings) is list and len(warnings) <= len(_SAFE_WARNINGS)
          and all(type(w) is str and w in _SAFE_WARNINGS for w in warnings)
          and warnings == sorted(set(warnings)), _INVALID_RECORD)
    _need(summary['normalization_required'] is bool(warnings), _INVALID_RECORD)


def _check_policy(config, endpoints):
    _need(type(config) is dict and type(endpoints) in (list, tuple), _INVALID_RECORD)
    # Reparse pinned nodes without DNS. Compare exact JSON (bool != int) so a
    # changed record cannot alter guest policy or widen the endpoint set.
    normalized = parse_submission({'input_mode': 'fields', 'nodes': config.get('proxies')})
    _need(_json_bytes(config) == _json_bytes(normalized.private_config)
          and _json_bytes(endpoints) == _json_bytes(normalized.endpoints), _INVALID_RECORD)
    return normalized


def _decode_ticket(record, configuration_id, now):
    _need(type(record) is dict and set(record) == _RECORD_KEYS, _INVALID_RECORD)
    _need(type(record['version']) is int and record['version'] == _VERSION
          and record['configuration_id'] == configuration_id and record['consent'] == _CONSENT,
          _INVALID_RECORD)
    bound = record['bound_job']
    _need(bound is None or _opaque_id(bound), _INVALID_RECORD)
    age = _clock(now) - _timestamp(record['created_unix'])
    _need(age >= 0, _TIME)
    _check_digest(record['record_digest'], _record_digest(record))
    if bound is None:
        _need(age <= MAX_AGE_SECONDS, _EXPIRY)
    config, endpoints = record['private_config'], record['endpoints']
    _check_digest(record['digest'], _digest(config, endpoints))
    try:
        normalized = _check_policy(config, endpoints)
    except VPNConfigurationError:
        raise VPNStoreError(_INVALID_RECORD) from None
    _check_summary(record['summary'], normalized.summary)
    return StoredVPN(configuration_id, config, normalized.endpoints, record['summary'], record['digest'], bound)


def _publish_record(state, fd, name, record, *, previous=None):
    record['record_digest'] = _record_digest(record)
    raw = _json_bytes(record) + b'\n'
    _need(len(raw) <= _MAX_RECORD_BYTES, '网络配置过大')
    temp_id = uuid.uuid4().hex
    _need(_opaque_id(temp_id), _UNSAFE_FILE)
    temporary = '.ticket-' + temp_id + '.tmp'
    stage = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        identity = _inode(os.fstat(stage))
        links = 1
        try:
            os.fchmod(stage, 0o600)
            _private_file(os.fstat(stage))
            with os.fdopen(stage, 'wb', closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stage)
            _same_root(state, fd)
            staged = _entry(fd, temporary)
            _private_file(staged)
            _need(_snapshot(staged) == _snapshot(os.fstat(stage)), _UNSAFE_FILE)
            if previous is None:
                # Exclusive publication: unlike replace, this cannot clobber a
                # collision, including a dangling symlink at the final name.
                try:
                    os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                except FileExistsError:
                    raise VPNStoreError(_COLLISION) from None
                links = 2
            else:
                _need(_snapshot(_entry(fd, name)) == _snapshot(previous), _UNSAFE_FILE)
                os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                links = 0  # Renamed, so there is no temporary entry to remove.
        finally:
            if links:
                # Resolve the directory and verify the exact owned temp inode
                # again just before unlink. Never delete a ticket or unknown file.
                _same_root(state, fd)
                entry = _entry(fd, temporary)
                _need(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid()
                      and _inode(entry) == identity and entry.st_nlink == links, _UNSAFE_FILE)
                os.unlink(temporary, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(stage)


def store_submission(state_dir, payload, *, allow_resolve=False, resolver=_DEFAULT_RESOLVER, now=None):
    """Store only after authenticated user submission; no DNS unless opted in."""
    _need(type(allow_resolve) is bool, '域名解析确认无效')
    if now is not None:
        _timestamp(now)
    selected = (resolve_public_hostname if resolver is _DEFAULT_RESOLVER else resolver) if allow_resolve else None
    _need(selected is None or callable(selected), '域名解析器无效')
    if type(payload) is dict and type(payload.get('input_mode')) is str and payload['input_mode'] == 'yaml_path':
        _need(set(payload) == {'input_mode', 'path'}, _YAML_PATH)
        payload = {'input_mode': 'yaml', 'yaml_text': _read_yaml_path(payload['path'])}
    # The parser applies structural and byte limits before DNS or storage.
    parsed = parse_submission(payload, resolver=selected)
    with _private_io():
        # Generated defaults can grow near-limit input. Replay the same check
        # that the offline seed and runtime validators apply before publishing.
        normalized = _check_policy(parsed.private_config, parsed.endpoints)
        _check_summary(parsed.summary, normalized.summary)
    return _issue(state_dir, parsed.private_config, parsed.endpoints, parsed.summary, now)


def store_saved(state_dir, private_config, endpoints, *, now=None):
    """Issue a ticket for a configuration this manager validated earlier and kept with one of its own VMs.

    The person asks for it by VM name; the caller reads it from that VM's
    private environment. Nothing is read from the host here and no name is
    resolved. It is accepted only if reparsing it without DNS changes nothing,
    so the ticket carries exactly the nodes and endpoints already in use. With
    nothing replaced, there is no normalization to report or to consent to.
    """
    if now is not None:
        _timestamp(now)
    with _private_io():
        normalized = _check_policy(private_config, endpoints)
        summary = dict(normalized.summary, warnings=[], normalization_required=False)
        _check_summary(summary, normalized.summary)
    return _issue(state_dir, normalized.private_config, normalized.endpoints, summary, now)


def _issue(state_dir, private_config, endpoints, summary, now):
    with _private_io(), _locked_root(state_dir, create=True, exclusive=True) as (state, fd):
        ident = uuid.uuid4().hex
        record = {'version': _VERSION, 'configuration_id': ident, 'created_unix': _clock(now),
                  'consent': _CONSENT, 'private_config': private_config, 'endpoints': endpoints,
                  'summary': summary, 'digest': _digest(private_config, endpoints), 'bound_job': None}
        _publish_record(state, fd, _ticket_name(ident), record)
    return {'configuration_id': ident, 'summary': summary, 'expires_in_seconds': MAX_AGE_SECONDS,
            'configuration_stored_privately': True, 'vpn_connected': False}


def load_configuration(state_dir, configuration_id, *, job_id=None, now=None):
    """Read an unclaimed ticket, or an already-claimed ticket for this job."""
    name = _ticket_name(configuration_id)
    if job_id is not None:
        _job_id(job_id)
    with _private_io(), _locked_root(state_dir) as (state, fd):
        record, _ = _read_record(fd, name)
        value = _decode_ticket(record, configuration_id, now)
        _need(value.bound_job == job_id, _BINDING if value.bound_job else '网络配置尚未绑定任务')
        _same_root(state, fd)
        return value


def claim_configuration(state_dir, configuration_id, job_id, *, now=None):
    """Bind a valid ticket once, before any restoration or guest writes."""
    name = _ticket_name(configuration_id)
    _job_id(job_id)
    with _private_io(), _locked_root(state_dir, exclusive=True) as (state, fd):
        record, previous = _read_record(fd, name)
        value = _decode_ticket(record, configuration_id, now)
        _need(value.bound_job in (None, job_id), _BINDING)
        if value.bound_job == job_id:
            _same_root(state, fd)
            return value
        record['bound_job'] = job_id
        _publish_record(state, fd, name, record, previous=previous)
        return replace(value, bound_job=job_id)
