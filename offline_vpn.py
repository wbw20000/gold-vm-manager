"""Fresh completed-app stage ONLY: private guest seed + authorized ownership.

Never publishes, boots, reads host VPN profiles, repairs disks, overwrites seed
paths, impersonates root, or treats noowners as persistent ownership evidence.
Native authorization and all disk operations must be explicitly caller-approved.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import uuid

import guest_app_artifacts as artifacts
from guest_app_pins import reviewed_manifests
import guest_ownership as ownership
import guest_vpn_seed as seed_builder
import managed_registry as registry
from offline_disk import StageTarget, DiskSession, signature, private_regular
from offline_writable import WritableDiskSession
from offline_install import (APP_NAMES, validate_material_set, verify_materials,
                             verify_installed_readonly, application_root)
import offline_volume

GIB = 1024 ** 3
_MAX_HELPER = 16 * 1024 ** 2
_PARENTS = ('Library', 'Library/Application Support', 'Library/LaunchAgents')
_COMPLETE = '.offline-vpn.complete.json'
_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')


class OfflineVPNError(ValueError):
    """Constant public codes only; never secrets, native output or exception text."""


def _need(value, code):
    if not value:
        raise OfflineVPNError(code)


def _time():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _owned_directory(path, private=False):
    path = registry.safe_path(Path(path))
    info = path.stat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and not stat.S_IMODE(info.st_mode) & 0o7022, 'unsafe-owned-directory')
    if private:
        _need(stat.S_IMODE(info.st_mode) == 0o700, 'unsafe-private-directory')
    return path


def _private_directory(path):
    return _owned_directory(path, private=True)


def _new_private(path, value):
    _private_directory(path.parent)
    path = registry.safe_path(path, False)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(_json(value) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    registry.sync_directory(path.parent)


def _safe_record(path):
    private_regular(path)
    value = registry.read_private(path)
    _need(type(value) is dict, 'invalid-private-stage-record')
    return value


def _rows(receipts):
    keys = ('name', 'bundle_identifier', 'short_version', 'bundle_version', 'team_id',
            'bundle_bytes', 'bundle_tree_sha256')
    return [{key: app[key] for key in keys} for receipt in receipts for app in receipt.apps]


def _recorded_rows(receipt):
    rows = receipt.get('applications')
    _need(type(rows) is list and len(rows) == 4
          and tuple(row.get('name') for row in rows if type(row) is dict) == APP_NAMES,
          'complete-application-receipt-required')
    expectations = [(manifest, app) for manifest in reviewed_manifests() for app in manifest.expected_apps]
    for row, (manifest, expected) in zip(rows, expectations):
        _need(set(row) == {'name', 'bundle_identifier', 'short_version', 'bundle_version',
                          'team_id', 'bundle_bytes', 'bundle_tree_sha256'}
              and type(row['bundle_tree_sha256']) is str and _HEX64.fullmatch(row['bundle_tree_sha256'])
              and type(row['bundle_bytes']) is int and row['bundle_bytes'] > 0
              and row['bundle_identifier'] in expected.bundle_identifiers
              and row['short_version'] in expected.short_versions
              and row['bundle_version'] in expected.bundle_versions
              and row['team_id'] in manifest.vendor_team_ids,
              'invalid-reviewed-application-tree-binding')
    return rows


def load_completed_stage(state_dir, tart_home, job_id, name):
    """Narrow real completed-app loader, NOT StageTarget.load's restore-only gate.

    No status rewriting to masquerade as applications_preinstalled=False. Caller
    must revalidate this target after obtaining StageTarget.locked's actual locks.
    """
    try:
        _need(type(job_id) is str and _HEX32.fullmatch(job_id), 'invalid-preinstall-job')
        registry.validate_name(name)
        state_dir, tart_home = _private_directory(state_dir), _owned_directory(tart_home)
        job_dir = _private_directory(state_dir / 'build-jobs' / job_id)
        current = _safe_record(state_dir / 'build-current.json')
        request = _safe_record(job_dir / 'request.json')
        for value in (current, request):
            _need(value.get('id') == job_id and value.get('name') == name
                  and value.get('mode') == 'preinstall' and 'source_vm' in value
                  and value['source_vm'] is None, 'new-preinstall-job-only')
        _need(current.get('phase') == 'awaiting_first_desktop_acceptance'
              and current.get('system_restored') is True and current.get('applications_preinstalled') is True
              and all(current.get(k) is False for k in ('guest_started', 'desktop_verified', 'published'))
              and current.get('credentials_copied') is False
              and current.get('host_credentials_copied') is False
              and not current.get('recovery_required') and not current.get('vpn_configuration'),
              'completed-unpublished-unstarted-stage-required')
        for flag in ('acknowledge_preinstall', 'acknowledge_network_policy', 'acknowledge_guest_autoconfigure'):
            _need(request.get(flag) is True, 'explicit-preinstall-and-network-consent-required')
        _need(type(request.get('disk_gib')) is int and request['disk_gib'] > 0,
              'invalid-stage-disk-size')
        _need(type(request.get('vpn_configuration_id')) is str and _HEX32.fullmatch(request['vpn_configuration_id']),
              'validated-private-configuration-id-required')
        staging = _private_directory(tart_home / '.gold-manager-staging')
        job_root = _private_directory(staging / job_id)
        stage = _private_directory(job_root / 'new-environment')
        _need(current.get('stage_path') == str(stage), 'wrong-preinstall-stage-path')
        vms = _owned_directory(tart_home / 'vms')
        _need(not os.path.lexists(vms / name), 'existing-vm-never-eligible')
        for filename in ('state.vzvmsave', 'state.bin', 'savedstate', 'saved-state.bin', 'suspend.bin', _COMPLETE, '.guest-ownership'):
            _need(not os.path.lexists(stage / filename), 'used-or-suspended-stage-refused')
        restore = _safe_record(stage / '.clean-vm-installer.complete.json')
        _need(restore.get('installer') == 'CleanVMInstaller' and restore.get('status') == 'complete'
              and type(restore.get('schemaVersion')) is int and restore['schemaVersion'] == 1
              and all(type(restore.get(k)) is int and restore[k] == 0 for k in
                      ('networkDeviceCount', 'directorySharingDeviceCount', 'socketDeviceCount')),
              'restore-isolation-receipt-mismatch')
        complete = _safe_record(stage / '.offline-preinstall.complete.json')
        operation = current.get('offline_preinstall')
        _need(type(complete.get('operation_id')) is str and _HEX32.fullmatch(complete['operation_id'])
              and type(operation) is dict and operation.get('operation_id') == complete['operation_id']
              and operation.get('active') is False
              and operation.get('phase') == 'verified_awaiting_first_desktop'
              and type(complete.get('schema')) is int and complete['schema'] == 1
              and complete.get('job_id') == job_id and complete.get('name') == name
              and complete.get('stage_path') == str(stage)
              and complete.get('applications_preinstalled') is True
              and all(complete.get(k) is False for k in ('guest_started', 'desktop_verified', 'published', 'credentials_copied'))
              and complete.get('vm_config_and_nvram_unchanged') is True
              and complete.get('image_file_identity_and_size_unchanged') is True
              and complete.get('readonly_remount_verified') is True and complete.get('final_detach_confirmed') is True,
              'application-completion-record-mismatch')
        _recorded_rows(complete)
        for key in ('data_uuid', 'volume_group_uuid'):
            _need(type(complete.get(key)) is str and ownership.UUID.fullmatch(complete[key]),
                  'completed-app-volume-identity-required')
        config = private_regular(stage / 'config.json')
        private_regular(stage / 'nvram.bin')
        _need(not config.stat().st_flags & 0x2, 'immutable-stage-config')
        image = private_regular(stage / 'disk.img')
        baseline = signature(image)
        _need(baseline[2] == request['disk_gib'] * GIB, 'stage-image-size-mismatch')
        return StageTarget(state_dir, tart_home, job_id, name, stage, image, baseline)
    except OfflineVPNError:
        raise
    except Exception:
        raise OfflineVPNError('unsafe-or-incomplete-preinstall-stage') from None


def _state(target, operation_id, operation_phase, *, failed=False, complete=False, authorization=False,
           created_parent_paths=()):
    current = _safe_record(target.state_dir / 'build-current.json')
    _need(current.get('id') == target.job_id and current.get('mode') == 'preinstall'
          and current.get('name') == target.name and current.get('source_vm') is None
          and current.get('stage_path') == str(target.stage)
          and all(current.get(k) is False for k in ('guest_started', 'desktop_verified', 'published')),
          'preinstall-job-identity-changed')
    prior = current.get('vpn_configuration')
    _need(prior is None or type(prior) is dict and prior.get('operation_id') == operation_id,
          'another-vpn-operation-present')
    current = dict(current)
    current.update({'host_credentials_copied': False, 'credentials_copied': False, 'vpn_connected': False,
                    'vpn_configuration_staged': complete,
                    'phase': 'failed' if failed else 'awaiting_first_desktop_acceptance' if complete else
                             'awaiting_system_authorization' if authorization else 'configuring_vpn'})
    current['vpn_configuration'] = {'operation_id': operation_id, 'phase': operation_phase,
        'active': not (complete or failed), 'updated_at': _time(),
        'created_parent_paths': list(created_parent_paths), 'vpn_connected': False}
    if failed:
        current['recovery_required'] = True
        current['message'] = '客机网络配置未完成，已保留未发布暂存盘与私有证据；禁止自动覆盖、重试或启动，需人工核对。'
    elif complete:
        current.pop('recovery_required', None)
        current['message'] = '原始完整应用与私有首次登录配置已独立只读核验，持久属主经系统管理员授权核验。尚未发布或启动，VPN 未连接，需真人首次登录与授权。'
    elif authorization:
        current['message'] = '等待你在 macOS 标准管理员对话框中确认客机文件属主操作；拒绝后会保留失败暂存盘，不绕过权限。'
    else:
        current['message'] = '正在全新未启动客机中准备私有首次登录配置；不读取宿主节点、不启动 VM、不表示 VPN 已连通。'
    registry.write_private(target.state_dir / 'build-jobs' / target.job_id / 'status.json', current)
    registry.write_private(target.state_dir / 'build-current.json', current)


def _host_helper(path):
    path = registry.safe_path(Path(path))
    before = path.stat()
    _need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid()) and before.st_nlink == 1
          and not before.st_mode & 0o7022 and before.st_mode & 0o111
          and 8 <= before.st_size <= _MAX_HELPER, 'unsafe-bootstrap-helper')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        data = stream.read(_MAX_HELPER + 1)
        after = os.fstat(stream.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    _need(identity(before) == identity(after) and len(data) == before.st_size,
          'bootstrap-helper-changed')
    _need(data[:4] == b'\xcf\xfa\xed\xfe' and struct.unpack('<I', data[4:8])[0] == 0x0100000c,
          'compiled-arm64-bootstrap-helper-required')
    return data


def _root(session, writable=False):
    # Reuses freshness, Setup Assistant, user-home and Applications attribution
    # checks even when ONLY the fixed Library seed paths are about to be written.
    application_root(session, writable=writable)
    root = registry.safe_path(session.mountpoint)
    _need(os.path.ismount(root), 'attributed-data-mount-required')
    info = root.stat()
    _need(stat.S_ISDIR(info.st_mode), 'invalid-data-mount-root')
    return root, info.st_dev


def _open_parent(root_fd, relative, device):
    parts = PurePosixPath(relative).parts
    _need(parts and relative == '/'.join(parts) and all(p not in ('.', '..') for p in parts)
          and not relative.startswith('/'), 'unsafe-seed-relative-path')
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = following
            info = os.fstat(fd)
            _need(stat.S_ISDIR(info.st_mode) and info.st_dev == device, 'seed-parent-left-data-volume')
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def _absent_outputs(root):
    for relative in (seed_builder.BASE, seed_builder.AGENT_PATH):
        path = registry.safe_path(root / relative, False)
        _need(not os.path.lexists(path), 'existing-seed-output-refused')


def _existing_parents(root, device):
    for relative in _PARENTS:
        path = registry.safe_path(root / relative)
        info = path.lstat()
        _need(stat.S_ISDIR(info.st_mode) and info.st_dev == device
              and not stat.S_IMODE(info.st_mode) & 0o7022, 'reviewed-existing-system-parents-required')


def _write_seed(session, seed, helper_bytes):
    root, device = _root(session, writable=True)
    _absent_outputs(root)
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = []
    try:
        for relative in _PARENTS:
            session.check_mounted_writable()
            parent_fd, name = _open_parent(root_fd, relative, device)
            try:
                # Existing reviewed system parents only. Creating one would need
                # a separate Root whitelist; never leave a caller-owned parent.
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                _need(stat.S_ISDIR(info.st_mode) and info.st_dev == device
                      and not stat.S_IMODE(info.st_mode) & 0o7022, 'unsafe-existing-seed-parent')
            finally:
                os.close(parent_fd)
        for entry in seed.entries:
            session.check_mounted_writable()
            parent_fd, name = _open_parent(root_fd, entry.relative_path, device)
            try:
                if entry.kind == 'directory':
                    os.mkdir(name, entry.mode, dir_fd=parent_fd)
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    try:
                        os.fchmod(fd, entry.mode)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                else:
                    payload = helper_bytes if entry.kind == 'compiled_helper' else entry.content
                    _need(type(payload) is bytes, 'invalid-seed-plan')
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent_fd)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fchmod(stream.fileno(), entry.mode)
                        os.fsync(stream.fileno())
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    finally:
        os.close(root_fd)
    session.check_mounted_writable()
    return tuple(created)


def _seed_snapshot(session, seed, helper_bytes, created_parents, *, writable=False):
    root, device = _root(session, writable=writable)
    expected = [(p, 'directory', 0o755, None) for p in created_parents]
    expected += [(e.relative_path, 'directory' if e.kind == 'directory' else 'file', e.mode,
                  helper_bytes if e.kind == 'compiled_helper' else e.content) for e in seed.entries]
    result = []
    for relative, kind, mode, data in expected:
        path = registry.safe_path(root / relative)
        before = path.lstat()
        _need(before.st_dev == device and stat.S_IMODE(before.st_mode) == mode
              and (stat.S_ISDIR(before.st_mode) if kind == 'directory' else
                   stat.S_ISREG(before.st_mode) and before.st_nlink == 1), 'seed-node-kind-or-mode-changed')
        if kind == 'file':
            _need(before.st_size == len(data), 'seed-file-size-changed')
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                actual = stream.read(max(_MAX_HELPER, seed_builder.MAX_SEED_BYTES) + 1)
                after = os.fstat(stream.fileno())
            _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                  and actual == data, 'seed-file-bytes-changed')
        result.append({'path': relative, 'kind': kind, 'inode': before.st_ino, 'mode': mode,
                       'size': len(data) if data is not None else 0,
                       'sha256': _digest(data) if data is not None else ''})
    _need({p.name for p in (root / seed_builder.BASE).iterdir()} == {'FirstLogin'}
          and {p.name for p in (root / seed_builder.FIRST_LOGIN).iterdir()} == {'GuestVPNBootstrap', 'seed.json'},
          'unexpected-private-seed-content')
    return result


def _generation(session, previous):
    # Exact DiskSession.owned generation: whole, devices, hdid PID, owner,
    # writable flag, pinned image dev/inode/size. Device numbers alone expire.
    value = session.attachment_generation
    _need(type(value) is tuple and len(value) == 6
          and type(value[0]) is str and re.fullmatch(r'/dev/disk[0-9]+', value[0])
          and type(value[1]) is frozenset and value[0] in value[1]
          and type(value[2]) is int and value[2] > 0
          and type(value[3]) is int and value[3] == os.getuid()
          and value[4] is (type(session.attribution) is offline_volume.WritableAttribution)
          and value[5] == session.target.baseline[:3]
          and value not in previous and all(v[2] != value[2] for v in previous),
          'independent-fresh-attachment-required')
    previous.append(value)
    return value[2]


def _generation_records(generations):
    return [{'whole_device': v[0], 'devices': sorted(v[1]), 'hdid_pid': v[2],
             'owner_uid': v[3], 'writable': v[4], 'image_identity': list(v[5])}
            for v in generations]


def _ownership_receipt(ticket, operation, result, generation, count):
    _need(type(result) is ownership.AuthorizationResult and result.authorized_helper_completed is True
          and result.operation == operation and result.independent_readonly_acceptance is (operation == 'verify'),
          'system-authorization-or-helper-not-completed')
    record = _safe_record(ticket.path.parent / (operation + '.receipt.json'))
    _need(record.get('schema') == 1 and type(record.get('schema')) is int
          and record.get('operation_id') == ticket.operation_id
          and record.get('ticket_sha256') == ticket.digest and record.get('operation') == operation
          and record.get('entry_count') == count and record.get('attachment_generation') == generation
          and record.get('fixture_only') is False
          and record.get('authorization') == 'macos_system_administrator'
          and record.get('helper_contract') == ownership.PRODUCTION_CONTRACT
          and record.get('guest_started') is False and record.get('published') is False
          and record.get('metadata_applied') is (operation == 'apply')
          and record.get('persistent_ownership_verified') is (operation == 'verify')
          and record.get('readonly_owners_on') is (operation == 'verify'),
          'authorized-ownership-receipt-required')
    return record


def configure_preinstalled_stage(*, state_dir, tart_home, job_id, name, private_config,
                                 bootstrap_helper_path, ownership_helper_path, materials,
                                 evidence_dir=None, acknowledge_write=False,
                                 acknowledge_system_authorization=False, lifecycle_lock_fd=None):
    """Return ONLY a public sanitized completion summary, never seed/token/config.

    Private receipt_token and byte/ownership bindings live in the private stage
    sidecar .offline-vpn.complete.json. evidence_dir, if supplied, must be the
    exact private state_dir/build-jobs/job_id parent, not an arbitrary output.
    Two explicit OS authorization requests are made: apply and fresh RO verify.
    macOS controls dialog display/caching; this module never collects passwords.
    """
    _need(acknowledge_write is True, 'explicit-guest-seed-write-authorization-required')
    _need(acknowledge_system_authorization is True, 'explicit-system-administrator-authorization-required')
    validate_material_set(materials)
    _need(tuple(m.manifest for m in materials) == reviewed_manifests(), 'exact-reviewed-complete-materials-required')
    seed = seed_builder.build_seed(private_config, receipt_enabled=True)
    helper_bytes = _host_helper(bootstrap_helper_path)
    target = load_completed_stage(state_dir, tart_home, job_id, name)
    operation_id = uuid.uuid4().hex
    paths = ownership.operation_paths(target.tart_home, job_id, operation_id, state_dir=target.state_dir)
    job_dir = target.state_dir / 'build-jobs' / job_id
    if evidence_dir is not None:
        _need(registry.safe_path(Path(evidence_dir)) == job_dir, 'fixed-vpn-evidence-parent-required')
    evidence = job_dir / ('offline-vpn-' + operation_id)
    _need(paths['apply_mount'] == evidence / 'write-session' / 'data-mount'
          and paths['verify_mount'] == evidence / 'owner-readonly' / 'data-mount', 'ownership-operation-layout-mismatch')
    public = {'schema': 1, 'operation_id': operation_id, 'job_id': job_id, 'name': name,
              'vpn_configuration_staged': False, 'persistent_ownership_verified': False,
              'applications_preinstalled': True, 'guest_started': False, 'desktop_verified': False,
              'published': False, 'host_credentials_copied': False, 'vpn_connected': False,
              'first_login_acceptance_required': True}
    lock_options = {} if lifecycle_lock_fd is None else {'lifecycle_lock_fd': lifecycle_lock_fd}
    with target.locked(**lock_options) as config_lock_fd:
        # Re-read every completed-stage gate under both lifecycle locks. Never
        # close/open config.json during this scope: POSIX locks are per inode/PID.
        reloaded = load_completed_stage(state_dir, tart_home, job_id, name)
        _need(reloaded == target, 'stage-changed-before-lock')
        _need(type(config_lock_fd) is int and os.fstat(config_lock_fd).st_ino == target.stage.joinpath('config.json').stat().st_ino,
              'borrowed-config-posix-lock-required')
        evidence.mkdir(mode=0o700)
        _private_directory(evidence)
        registry.sync_directory(job_dir)
        immutable = {p: signature(target.stage / p) for p in
                     ('config.json', 'nvram.bin', '.clean-vm-installer.complete.json', '.offline-preinstall.complete.json')}
        request_identity = signature(job_dir / 'request.json')
        complete_apps = _safe_record(target.stage / '.offline-preinstall.complete.json')
        expected_rows = _recorded_rows(complete_apps)
        generations, created_parents = [], ()
        phase = 'preflight'
        def identities():
            _need(all(signature(target.stage / p) == value for p, value in immutable.items())
                  and signature(job_dir / 'request.json') == request_identity,
                  'vm-config-nvram-or-source-receipt-changed')
            _need(signature(target.image)[:3] == target.baseline[:3], 'stage-image-identity-or-size-changed')
            _need(not os.path.lexists(target.tart_home / 'vms' / target.name)
                  and not any(os.path.lexists(target.stage / p) for p in
                              ('state.vzvmsave', 'state.bin', 'savedstate', 'saved-state.bin', 'suspend.bin')),
                  'stage-published-or-started')
        try:
            _state(target, operation_id, phase)
            helper_sha256 = ownership.deploy_helper(target.state_dir, Path(ownership_helper_path))
            _need(type(helper_sha256) is str and _HEX64.fullmatch(helper_sha256), 'invalid-deployed-ownership-helper')
            source = verify_materials(materials)
            _need(_rows(source) == expected_rows, 'reviewed-source-differs-from-completed-apps')
            _new_private(evidence / 'source-verification.json', [asdict(v) for v in source])
            _new_private(evidence / 'private-seed-binding.json', {
                'operation_id': operation_id, 'receipt_token': seed.receipt_token,
                'seed_sha256': _digest(seed.seed_json), 'launch_agent_sha256': _digest(seed.launch_agent_plist),
                'bootstrap_sha256': _digest(helper_bytes), 'ownership_helper_sha256': helper_sha256})
            phase = 'readonly-app-baseline'
            _state(target, operation_id, phase)
            with DiskSession(target, evidence / 'baseline-readonly', lock_held=True, ownership_mode='off') as baseline_session:
                _generation(baseline_session, generations)
                baseline = baseline_session.attribution
                persistent = offline_volume._persistent_identity(baseline)
                baseline_session.mount_readonly_for_probe()
                baseline_verification = verify_installed_readonly(baseline_session, materials, source,
                    expected_data_uuid=complete_apps['data_uuid'], expected_group_uuid=complete_apps['volume_group_uuid'])
                _need(_rows(baseline_verification) == expected_rows, 'installed-complete-apps-mismatch')
                root, device = _root(baseline_session)
                _absent_outputs(root)
                _existing_parents(root, device)
            _need(baseline_session.summary.get('cleanup_confirmed') is True, 'baseline-detach-unconfirmed')
            identities()
            phase = 'writing-private-seed'
            _state(target, operation_id, phase)
            with WritableDiskSession(target, evidence / 'write-session', baseline,
                                     acknowledge_write=True, lock_held=True, ownership_mode='off') as writable:
                apply_generation = _generation(writable, generations)
                _need(offline_volume._persistent_identity(writable.attribution) == persistent, 'writable-data-identity-changed')
                writable.mount_writable()
                _need(writable.mountpoint == paths['apply_mount'], 'wrong-ownership-apply-mount')
                created_parents = _write_seed(writable, seed, helper_bytes)
                seed_snapshot = _seed_snapshot(writable, seed, helper_bytes, created_parents, writable=True)
                identities()
                _state(target, operation_id, 'awaiting_owner_apply', authorization=True,
                       created_parent_paths=created_parents)
                # Ticket directories are new private host outputs, not guest paths.
                paths['directory'].parent.mkdir(mode=0o700)
                paths['directory'].mkdir(mode=0o700)
                _private_directory(paths['directory'].parent)
                _private_directory(paths['directory'])
                registry.sync_directory(target.stage)
                registry.sync_directory(paths['directory'].parent)
                entries = ownership.collect_entries(writable.mountpoint)
                ticket = ownership.prepare_ticket(state_dir=target.state_dir, tart_home=target.tart_home,
                    job_id=job_id, name=name, operation_id=operation_id,
                    apply_mount=paths['apply_mount'], verify_mount=paths['verify_mount'],
                    data_uuid=baseline.data_uuid, group_uuid=baseline.volume_group_uuid,
                    entries=entries, helper_sha256=helper_sha256, config_lock_fd=config_lock_fd)
                phase = 'authorized-ownership-apply'
                result = ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True)
                apply_receipt = _ownership_receipt(ticket, 'apply', result, apply_generation, len(entries))
                writable.check_mounted_writable()
                identities()
            _need(writable.summary.get('cleanup_confirmed') is True, 'writable-detach-unconfirmed')
            identities()
            after_write = signature(target.image)
            refreshed = StageTarget(target.state_dir, target.tart_home, job_id, name, target.stage, target.image, after_write)
            phase = 'independent-readonly-bytes'
            _state(target, operation_id, phase, created_parent_paths=created_parents)
            with DiskSession(refreshed, evidence / 'bytes-readonly', lock_held=True, ownership_mode='off') as readonly:
                _generation(readonly, generations)
                _need(offline_volume._persistent_identity(readonly.attribution) == persistent, 'readonly-data-identity-changed')
                readonly.mount_readonly_for_probe()
                readback = verify_installed_readonly(readonly, materials, source,
                    expected_data_uuid=baseline.data_uuid, expected_group_uuid=baseline.volume_group_uuid)
                _need(_rows(readback) == expected_rows, 'readonly-app-bytes-changed')
                _need(_seed_snapshot(readonly, seed, helper_bytes, created_parents) == seed_snapshot,
                      'readonly-seed-bytes-mode-or-inode-changed')
                identities()
            _need(readonly.summary.get('cleanup_confirmed') is True, 'byte-verification-detach-unconfirmed')
            phase = 'authorized-readonly-persistent-owners'
            _state(target, operation_id, 'awaiting_owner_verify', authorization=True,
                   created_parent_paths=created_parents)
            with DiskSession(refreshed, evidence / 'owner-readonly', lock_held=True, ownership_mode='on') as owner_session:
                verify_generation = _generation(owner_session, generations)
                _need(offline_volume._persistent_identity(owner_session.attribution) == persistent,
                      'owner-readonly-data-identity-changed')
                owner_session.mount_readonly_for_probe()
                _need(owner_session.mountpoint == paths['verify_mount'], 'wrong-ownership-verify-mount')
                # Do NOT read UID501's private files as the host account here.
                # Root's independent owners-on verifier must inspect actual uid/gid.
                result = ownership.request_authorization(ticket, 'verify', acknowledge_authorization=True)
                verify_receipt = _ownership_receipt(ticket, 'verify', result, verify_generation, len(entries))
                _need(verify_receipt['attachment_generation'] != apply_receipt['attachment_generation'],
                      'independent-owner-attachment-required')
                owner_session.check_mounted_readonly()
                identities()
            _need(owner_session.summary.get('cleanup_confirmed') is True, 'owner-verification-detach-unconfirmed')
            identities()
            _need(signature(target.image) == after_write, 'image-changed-during-readonly-verification')
            public.update({'phase': 'awaiting_first_desktop_acceptance', 'vpn_configuration_staged': True,
                           'persistent_ownership_verified': True, 'readonly_payload_verified': True,
                           'readonly_remount_verified': True, 'final_detach_confirmed': True,
                           'config_unchanged': True, 'nvram_unchanged': True})
            private = dict(public, stage_path=str(target.stage), completed_at=_time(),
                           image_file_stamp=list(signature(target.image)),
                           receipt_token=seed.receipt_token, seed_sha256=_digest(seed.seed_json),
                           bootstrap_sha256=_digest(helper_bytes), ownership_helper_sha256=helper_sha256,
                           seed_entries=seed_snapshot, created_parent_paths=list(created_parents),
                           persistent_volume_identity=persistent, attachment_generations=_generation_records(generations),
                           source_verification=[asdict(v) for v in source],
                           readonly_verification=[asdict(v) for v in readback],
                           ownership_ticket_sha256=ticket.digest,
                           ownership_apply=apply_receipt, ownership_verify=verify_receipt)
            _new_private(evidence / 'vpn-complete.json', private)
            _new_private(target.stage / _COMPLETE, private)
            _state(target, operation_id, 'verified_awaiting_first_login', complete=True,
                   created_parent_paths=created_parents)
            return public
        except BaseException as error:
            failure = dict(public, phase='failed', failed_phase=phase, recovery_required=True,
                           manual_review_required=True, error_code='offline-vpn-failed-retained')
            failure.update({'vpn_configuration_staged': False, 'persistent_ownership_verified': False})
            try:
                _new_private(evidence / 'vpn-failed.json', failure)
                _state(target, operation_id, 'failed_retained', failed=True,
                       created_parent_paths=created_parents)
            except Exception:
                pass  # Never overwrite foreign/new state to fabricate recovery.
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise OfflineVPNError('offline-vpn-failed-retained') from None
