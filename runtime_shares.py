"""Fail-closed directory-share planning for Tart 2.41.1 (Python 3.9+).

No VM operations, shell invocation, directory creation, or share-content reads.
The launcher must pass arguments as argv, retain its existing per-VM launch lock,
call prepare immediately before Popen, and call record_launch(child.pid) AFTER
Popen. Any validation/manifest error must abort launch, not fall back to no shares.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

VM_IDS = ("gold", "gold-backup", "gold-fresh")


def allowed_vm_ids():
    # Older launchers remain compatible only when their private registry adapter is present.
    try:
        import managed_registry
    except ImportError:
        return set(VM_IDS)
    return managed_registry.allowed_vm_ids()
HOST_HOME = Path.home()
CONFIG_PATH = HOST_HOME / "Library/Application Support/GoldVMManager/config.json"
STATE_DIR = CONFIG_PATH.parent
# Protect the active module's source/deployment directory, not an unrelated checkout.
MANAGER_SOURCE_DIR = Path(__file__).resolve().parent
MANAGER_INSTALL_DIR = HOST_HOME / "Applications/Gold VM Manager.app"
MANAGER_EXTRA_DIRS = (HOST_HOME / "Applications/GoldVMManager",
                      HOST_HOME / "Applications/Gold VM 管理器.app")
# Inside ~/Library only these cloud-document roots may hold shareable project
# folders, and only strictly below the root itself.
CLOUD_DOCUMENT_ROOTS = ("Library/Mobile Documents", "Library/CloudStorage")
NETWORK_CONTROLLER_DIRS = tuple(HOST_HOME / "Applications" / name for name in (
    "GoldNetwork", "GoldBackupNetwork", "GoldFreshNetwork"))
# Exact roots differ from entire sensitive subtrees: /Users and home must not
# forbid every dedicated project directory below them.
PROTECTED_ROOTS = (Path("/"), Path("/Users"), Path("/Library"),
                   Path("/System"), Path("/Applications"))
PROTECTED_SUBTREES = (Path("/Library"), Path("/System"), Path("/Applications"))
MAX_SHARES = 16
MAX_JSON_BYTES = 1024 * 1024
LAST_LAUNCH_NAME = "shares.last-start.json"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z", re.ASCII)
_STABLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_HEX256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SHARE_KEYS = {"id", "name", "path", "read_only", "enabled"}
_MANIFEST_KEYS = {"version", "vm_id", "pid", "shares", "fingerprint", "suspendable", "started_at"}


class ShareValidationError(ValueError):
    """Safe error text contains no input payload, paths, or JSON contents."""
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _fail(code, message):
    raise ShareValidationError(code, message)


def _vm_id(value):
    if type(value) is not str or value not in allowed_vm_ids():
        _fail("invalid_vm", "虚拟机标识无效")
    return value


def _clean_path(value):
    if type(value) is not str or not value or len(value) > 4096:
        _fail("invalid_path", "共享目录路径无效")
    if not value.startswith("/") or value.startswith("//"):
        _fail("absolute_path_required", "必须使用绝对目录路径")
    if any(ord(c) < 32 or ord(c) == 127 or c in ":," for c in value):
        _fail("unsafe_path_syntax", "路径包含 Tart 不兼容的分隔符或控制字符")
    path = Path(value)
    if ".." in path.parts:
        _fail("noncanonical_path", "请使用规范的绝对目录路径")
    return path


def _no_symlink_components(path, missing_ok=False):
    """Reject even parent-component symlinks; do not follow /tmp aliases etc."""
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing_ok:
                return False
            _fail("path_missing", "目录或配置路径不存在")
        except OSError:
            _fail("path_unreadable", "无法安全检查目录或配置路径")
        if stat.S_ISLNK(info.st_mode):
            _fail("symlink_not_allowed", "不能使用符号链接路径")
    return True


def _is_within(path, root):
    return path == root or root in path.parents


def _protected_paths():
    home = Path(HOST_HOME)
    roots = {Path(os.path.normpath(str(p))) for p in PROTECTED_ROOTS}
    roots.add(home)
    trees = list(PROTECTED_SUBTREES) + list(NETWORK_CONTROLLER_DIRS) + list(MANAGER_EXTRA_DIRS)
    trees += [home / ".ssh", home / ".tart", home / "Library/Keychains",
              home / "Applications/tart.app",
              Path(STATE_DIR), Path(CONFIG_PATH).parent, Path(MANAGER_SOURCE_DIR),
              Path(MANAGER_INSTALL_DIR)]
    return roots, [Path(os.path.normpath(str(p))) for p in trees]


def _host_private_location(path):
    """Home locations a guest must never write to or read from.

    A read-write share of ~/Library (LaunchAgents, Application Support,
    Preferences) or of a home dot-directory (shell/tool configs, credentials)
    lets guest software plant code that the host user later runs.
    """
    home = Path(os.path.normpath(str(HOST_HOME)))
    if path == home or home not in path.parents:
        return False
    relative = path.relative_to(home).parts
    if relative[0].startswith("."):
        return True
    if relative[0] != "Library":
        return False
    for root in CLOUD_DOCUMENT_ROOTS:
        parts = Path(root).parts
        if relative[:len(parts)] == parts and len(relative) > len(parts):
            return False
    return True


def _share_directory(value):
    path = _clean_path(value)
    _no_symlink_components(path)
    try:
        canonical = path.resolve(strict=True)
        info = path.stat()
    except OSError:
        _fail("directory_unreadable", "无法读取共享目录信息")
    if canonical != path:
        _fail("noncanonical_path", "请使用规范的绝对目录路径")
    if not stat.S_ISDIR(info.st_mode):
        _fail("directory_required", "共享目标必须是目录")
    if info.st_uid != os.getuid():
        _fail("directory_owner", "共享目录必须属于当前宿主用户")
    roots, trees = _protected_paths()
    # Reject ancestors too: sharing a parent exposes its protected descendants.
    if (path in roots or _host_private_location(path)
            or any(_is_within(path, p) or _is_within(p, path) for p in trees)):
        _fail("protected_directory", "不能共享系统、密钥、~/Library、家目录下的隐藏配置目录、虚拟机或管理控制目录及其上级目录；"
                                     "iCloud 云盘或 CloudStorage 内的项目子目录除外")
    return str(canonical)


def _normal_id(value, allow_missing):
    if value is None:
        if not allow_missing:
            _fail("missing_share_id", "已保存共享配置缺少标识")
        return str(uuid.uuid4())
    if type(value) is not str or not value or len(value) > 64 or not value.isascii():
        _fail("invalid_share_id", "共享标识无效")
    try:
        return str(uuid.UUID(value))
    except ValueError:
        if not _STABLE_ID.fullmatch(value):
            _fail("invalid_share_id", "共享标识无效")
        return value


def validate_shares(raw, *, allow_missing_ids=True):
    """Normalize an untrusted share list; no filesystem writes.

    id may be omitted for a NEW backend POST (a UUID is generated). Existing
    config/manifest readers require it. read_only/enabled must be exact booleans,
    including for disabled rows; no implicit writable or enabled defaults.
    """
    if type(raw) is not list or len(raw) > MAX_SHARES:
        _fail("invalid_share_list", "共享列表无效或超过 16 项")
    result, names, ids = [], set(), set()
    for item in raw:
        if type(item) is not dict or set(item) - _SHARE_KEYS or not {"name", "path", "read_only", "enabled"}.issubset(item):
            _fail("invalid_share", "共享配置字段无效")
        name = item["name"]
        if type(name) is not str or not _NAME.fullmatch(name):
            _fail("invalid_share_name", "共享名称须为 1–40 个 ASCII 字母、数字、下划线或连字符")
        if name.casefold() in names:
            _fail("duplicate_share_name", "共享名称不能重复（不区分大小写）")
        sid = _normal_id(item.get("id"), allow_missing_ids)
        if sid in ids:
            _fail("duplicate_share_id", "共享标识不能重复")
        if type(item["read_only"]) is not bool or type(item["enabled"]) is not bool:
            _fail("invalid_share_boolean", "只读和启用设置必须是布尔值")
        path = _share_directory(item["path"])
        names.add(name.casefold())
        ids.add(sid)
        result.append({"id": sid, "name": name, "path": path,
                       "read_only": item["read_only"], "enabled": item["enabled"]})
    return result


def _private_stat(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        _fail("unsafe_config_file", "配置必须是当前用户独占的私有普通文件")


def _reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key", "配置存在重复 JSON 字段")
        result[key] = value
    return result


def _invalid_constant(value):
    _fail("invalid_json", "配置含有无效 JSON 数值")


def _private_json(path):
    """None only for an actually absent path; invalid JSON never becomes {}."""
    path = _clean_path(str(path))
    if not _no_symlink_components(path, missing_ok=True):
        return None
    fd = None
    try:
        before = path.lstat()
        _private_stat(before)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(str(path), flags)
        opened = os.fstat(fd)
        _private_stat(opened)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            _fail("config_changed", "配置文件检查时发生变化")
        if opened.st_size > MAX_JSON_BYTES:
            _fail("config_too_large", "配置文件过大")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            payload = stream.read(MAX_JSON_BYTES + 1)
        if len(payload) > MAX_JSON_BYTES:
            _fail("config_too_large", "配置文件过大")
        current = path.lstat()
        _private_stat(current)
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            _fail("config_changed", "配置文件读取时发生变化")
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_pairs,
                          parse_constant=_invalid_constant)
    except ShareValidationError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        _fail("invalid_config", "无法安全读取配置，或 JSON 格式无效")
    finally:
        if fd is not None:
            os.close(fd)


def load_desired(vm_id):
    """Return this VM's normalized desired list, [] only when absent/unconfigured.

    A malformed other VM entry is reported when that VM is read, permitting the
    backend to report per-VM errors instead of discarding all state.
    """
    _vm_id(vm_id)
    data = _private_json(Path(CONFIG_PATH))
    if data is None:
        return []
    if (type(data) is not dict or set(data) != {"version", "vms"}
            or type(data["version"]) is not int or data["version"] != 1
            or type(data["vms"]) is not dict or set(data["vms"]) - allowed_vm_ids()):
        _fail("invalid_config_schema", "共享配置版本或结构无效")
    if vm_id not in data["vms"]:
        return []
    entry = data["vms"][vm_id]
    if type(entry) is not dict or set(entry) != {"shares"}:
        _fail("invalid_vm_shares", "此虚拟机的共享配置结构无效")
    return validate_shares(entry["shares"], allow_missing_ids=False)


def _network_directory(network_base):
    path = _clean_path(str(network_base))
    _no_symlink_components(path)
    try:
        info = path.stat()
        canonical = path.resolve(strict=True)
    except OSError:
        _fail("invalid_network_base", "网络控制目录不可用")
    if (canonical != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or info.st_mode & 0o077):
        _fail("invalid_network_base", "网络控制目录必须为当前用户的私有真实目录")
    return path, info


def shares_fingerprint(shares):
    """Canonical, order-sensitive integrity fingerprint (not authentication)."""
    payload = json.dumps(shares, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def read_last_launch(network_base):
    base, _ = _network_directory(network_base)
    data = _private_json(base / LAST_LAUNCH_NAME)
    if data is None:
        return {}
    if (type(data) is not dict or set(data) != _MANIFEST_KEYS
            or type(data["version"]) is not int or data["version"] != 1):
        _fail("invalid_launch_manifest", "上次启动共享清单结构无效")
    _vm_id(data["vm_id"])
    _validate_pid(data["pid"])
    shares = validate_shares(data["shares"], allow_missing_ids=False)
    if any(not s["enabled"] for s in shares):
        _fail("invalid_launch_manifest", "实际启动清单不能包含禁用的共享")
    if (type(data["fingerprint"]) is not str or not _HEX256.fullmatch(data["fingerprint"])
            or data["fingerprint"] != shares_fingerprint(shares)
            or type(data["suspendable"]) is not bool or data["suspendable"] != (not shares)
            or type(data["started_at"]) is not str or not data["started_at"]
            or len(data["started_at"]) > 64):
        _fail("invalid_launch_manifest", "上次启动清单指纹或状态无效")
    result = dict(data)
    result["shares"] = shares
    return result


def _validate_pid(pid):
    if type(pid) is not int or not 0 < pid < 2 ** 31:
        _fail("invalid_launch_pid", "启动进程标识无效")


def _dir_identity(base, expected):
    actual, info = _network_directory(base)
    if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
        _fail("network_base_changed", "网络控制目录发生变化")
    return actual


def _atomic_manifest(base, data):
    base, info = _network_directory(base)
    # Reject an existing corrupt/foreign manifest before replacing anything.
    old = read_last_launch(base)
    if old and old["vm_id"] != data["vm_id"]:
        _fail("manifest_vm_mismatch", "启动清单属于其他虚拟机")
    directory_fd = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staging = ".shares.last-start-" + uuid.uuid4().hex + ".tmp"
    staging_identity = None
    fd = None
    try:
        opened = os.fstat(directory_fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            _fail("network_base_changed", "网络控制目录发生变化")
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        staging_identity = os.fstat(fd)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            json.dump(data, stream, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        _dir_identity(base, info)
        # lstat both resolved target paths immediately before rename; replace
        # replaces a directory entry and never follows a target symlink.
        staging_path = base / staging
        if staging_path.is_symlink() or staging_path.resolve(strict=True) != staging_path:
            _fail("staging_changed", "启动清单临时文件路径异常")
        actual = os.stat(staging, dir_fd=directory_fd, follow_symlinks=False)
        if (actual.st_dev, actual.st_ino) != (staging_identity.st_dev, staging_identity.st_ino):
            _fail("staging_changed", "启动清单临时文件发生变化")
        target = base / LAST_LAUNCH_NAME
        if target.is_symlink() or target.resolve(strict=False) != target:
            _fail("unsafe_config_file", "启动清单目标路径异常")
        if target.exists():
            _private_stat(target.lstat())
        os.replace(staging, LAST_LAUNCH_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if staging_identity is not None:
                try:
                    actual = os.stat(staging, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    actual = None
                if actual is not None:
                    # Delete ONLY the verified absolute path/inode we created.
                    _dir_identity(base, info)
                    candidate = base / staging
                    if (candidate.is_symlink() or candidate.resolve(strict=True) != candidate
                            or candidate.parent != base or not staging.startswith(".shares.last-start-")
                            or not stat.S_ISREG(actual.st_mode)
                            or (actual.st_dev, actual.st_ino) != (staging_identity.st_dev, staging_identity.st_ino)):
                        _fail("unsafe_staging_cleanup", "拒绝清理身份不明的临时文件")
                    os.unlink(staging, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)


class SharePlan:
    """Immutable-by-copy plan; .shares/.arguments return defensive lists."""
    def __init__(self, vm_id, network_base, shares, pending_changes):
        self._vm_id = vm_id
        self._base, self._base_info = _network_directory(network_base)
        self._shares = tuple(dict(s) for s in shares)
        self._pending = bool(pending_changes)
        self._directory_ids = {}
        for share in self._shares:
            info = Path(share["path"]).stat()
            self._directory_ids[share["path"]] = (info.st_dev, info.st_ino)

    @property
    def arguments(self):
        return ["--dir={}:{}{}".format(s["name"], s["path"], ":ro" if s["read_only"] else "")
                for s in self._shares]

    @property
    def suspendable(self):
        return not self._shares

    @property
    def shares(self):
        return [dict(s) for s in self._shares]

    @property
    def pending_changes(self):
        return self._pending

    def record_launch(self, pid):
        _validate_pid(pid)
        _dir_identity(self._base, self._base_info)
        shares = validate_shares(self.shares, allow_missing_ids=False)
        for share in shares:
            info = Path(share["path"]).stat()
            if self._directory_ids[share["path"]] != (info.st_dev, info.st_ino):
                _fail("share_directory_changed", "启动前共享目录发生替换")
        manifest = {"version": 1, "vm_id": self._vm_id, "pid": pid, "shares": shares,
                    "fingerprint": shares_fingerprint(shares), "suspendable": self.suspendable,
                    "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        try:
            _atomic_manifest(self._base, manifest)
        except ShareValidationError:
            raise
        except OSError:
            _fail("manifest_write_failed", "无法安全记录启动共享清单")
        return manifest


def prepare_vm_shares(vm_id, network_base, vm_state):
    _vm_id(vm_id)
    if type(vm_state) is not str or vm_state not in ("stopped", "suspended", "running"):
        _fail("invalid_vm_state", "虚拟机状态无效")
    desired = load_desired(vm_id)
    last = read_last_launch(network_base)
    if last and last["vm_id"] != vm_id:
        _fail("manifest_vm_mismatch", "启动清单属于其他虚拟机")
    requested = [s for s in desired if s["enabled"]]
    if vm_state in ("suspended", "running"):
        actual = last.get("shares", [])
        pending = shares_fingerprint(requested) != shares_fingerprint(actual)
    else:
        actual, pending = requested, False
    return SharePlan(vm_id, network_base, actual, pending)
