"""Private registry for user-named, protected macOS VMs; no import side effects."""
import json
import fcntl
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import tempfile
import unicodedata

HOME = Path.home()
STATE_DIR = HOME / 'Library/Application Support/GoldVMManager'
REGISTRY_PATH = STATE_DIR / 'registry.json'
LEGACY_NAMES = ('gold', 'gold-backup', 'gold-fresh', 'dsh purge测试')


def validate_name(value):
    if (type(value) is not str or not 1 <= len(value) <= 64 or value != value.strip()
            or value.startswith(('.', '-')) or value.endswith('.')
            or any(not (c.isalnum() or c in ' _-') for c in value)
            or unicodedata.normalize('NFC', value) != value):
        raise ValueError('名称须为1–64个字母、数字、中文、空格、短横线或下划线，不能以点或短横线开头')
    return value


def safe_path(path, must_exist=True):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or str(path).startswith('//'):
        raise ValueError('路径必须是规范绝对路径')
    for parent in reversed((path,) + tuple(path.parents)):
        if parent.is_symlink():
            raise ValueError('不接受符号链接路径')
    if path.resolve(strict=must_exist) != path:
        raise ValueError('路径身份不匹配')
    return path


def private_dir(path):
    safe_path(path, False)
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for created in reversed(missing):
        sync_directory(created)
        sync_directory(created.parent)
    s = path.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise ValueError('状态目录必须为当前用户的私有目录')


def read_private(path, default=None):
    safe_path(path, False)
    if not path.exists():
        return default
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_nlink != 1 or s.st_size > 1048576:
            raise ValueError('私有配置权限或大小不正确')
        with os.fdopen(fd, 'r', encoding='utf-8', closefd=False) as f:
            def pairs(items):
                result = {}
                for k, v in items:
                    if k in result: raise ValueError('配置存在重复字段')
                    result[k] = v
                return result
            return json.load(f, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('配置数值无效')))
    finally:
        os.close(fd)


def sync_directory(path):
    safe_path(path)
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_private(path, data):
    private_dir(path.parent)
    safe_path(path, False)
    fd, filename = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    tmp = Path(filename)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, allow_nan=False, indent=2)
        f.write('\n'); f.flush(); os.fsync(f.fileno())
    if tmp.resolve(strict=True) != path.parent.resolve() / tmp.name or path.is_symlink():
        raise ValueError('配置写入路径发生变化')
    os.replace(str(tmp), str(path))
    sync_directory(path.parent)


@contextmanager
def state_lock(directory=None):
    directory = directory or STATE_DIR
    private_dir(directory)
    path = safe_path(directory / 'configuration.lock', False)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def load_registry(path=None):
    data = read_private(path or REGISTRY_PATH, {'version': 1, 'vms': {}, 'retired': []})
    return validate_registry(data)


def validate_registry(data):
    if type(data) is not dict or set(data) != {'version', 'vms', 'retired'} or type(data['version']) is not int or data['version'] != 1 or type(data['vms']) is not dict or type(data['retired']) is not list:
        raise ValueError('虚拟机注册表格式无效')
    for name, entry in data['vms'].items():
        validate_name(name)
        if type(entry) is not dict or set(entry) != {'environment_id'} or type(entry['environment_id']) is not str or not re.fullmatch('[0-9a-f]{32}', entry['environment_id']):
            raise ValueError('虚拟机注册项无效')
    for name in data['retired']: validate_name(name)
    if len(data['vms']) > 128 or len(data['retired']) > 1024 or set(data['vms']) & set(data['retired']):
        raise ValueError('虚拟机注册表冲突或过大')
    return data


def allowed_vm_ids():
    d = load_registry()
    return (set(LEGACY_NAMES) | set(d['vms'])) - set(d['retired'])


def registered_bases(legacy):
    d = load_registry()
    result = {name: base for name, base in legacy.items() if name not in d['retired']}
    result.update({name: STATE_DIR / 'environments' / entry['environment_id'] for name, entry in d['vms'].items()})
    return result
