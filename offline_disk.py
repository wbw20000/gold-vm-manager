"""Restricted, explicitly invoked access to an unpublished restore-only stage.

No import side effects. No Tart start, publication, credentials, unlock, repair,
force-unmount or generic disk discovery fallback. Image ownership is re-derived
from hdiutil before every device action. Read-only is the only validated filesystem-access mode. An explicit writable
attachment probe can capture metadata without mounting or yielding attribution;
actual writes require a separately reviewed writable contract.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess

import managed_registry as registry
import offline_volume

MAX_OUTPUT = 4 * 1024 * 1024
CONTAINER_HINT = 'EF57347C-0000-11AA-AA11-00306543ECAC'
DEVICE = re.compile(r'disk(?:0|[1-9][0-9]*)(?:s[1-9][0-9]*)?\Z', re.ASCII)
WHOLE = re.compile(r'disk(?:0|[1-9][0-9]*)\Z', re.ASCII)
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8'}


class OfflineDiskError(ValueError):
    pass


def private_regular(path):
    path = registry.safe_path(Path(path))
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise OfflineDiskError('Unsafe private stage file')
    return path


def signature(path):
    info = private_regular(path).stat()
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def node(identifier, whole=False):
    if not isinstance(identifier, str) or not (WHOLE if whole else DEVICE).fullmatch(identifier):
        raise OfflineDiskError('Invalid device identifier')
    return '/dev/' + identifier


def decode(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        raise OfflineDiskError('Oversized system metadata')
    try:
        result = offline_volume.parse_plist(raw)
    except Exception:
        raise OfflineDiskError('Unsupported system metadata') from None
    if type(result) is not dict:
        raise OfflineDiskError('Unsupported system metadata')
    return result


@dataclass(frozen=True)
class StageTarget:
    state_dir: Path
    tart_home: Path
    job_id: str
    name: str
    stage: Path
    image: Path
    baseline: tuple
    readonly_review: bool = False

    @classmethod
    def load(cls, state_dir, tart_home, job_id, name, *, review_failed_operation_id=None):
        if not isinstance(job_id, str) or not re.fullmatch('[0-9a-f]{32}', job_id):
            raise OfflineDiskError('Invalid restore job id')
        registry.validate_name(name)
        state_dir = registry.safe_path(Path(state_dir))
        tart_home = registry.safe_path(Path(tart_home))
        current = registry.read_private(state_dir / 'build-current.json')
        mode = current.get('mode') if type(current) is dict else None
        for directory in (state_dir, tart_home):
            info = directory.stat()
            modes = (0o700, 0o755) if mode == 'preinstall' and directory == tart_home else (0o700,)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in modes:
                raise OfflineDiskError('Unsafe stage root')
        request = registry.read_private(state_dir / 'build-jobs' / job_id / 'request.json')
        phase_ok = type(current) is dict and current.get('phase') == 'awaiting_offline_preinstall'
        if review_failed_operation_id is not None:
            if not isinstance(review_failed_operation_id, str) or not re.fullmatch('[0-9a-f]{32}', review_failed_operation_id):
                raise OfflineDiskError('Explicit failed-operation identity required for readonly review')
            operation = current.get('offline_preinstall', {}) if type(current) is dict else {}
            phase_ok = (type(current) is dict and current.get('phase') == 'failed'
                        and current.get('recovery_required') is True and type(operation) is dict
                        and operation.get('operation_id') == review_failed_operation_id)
        mode_ok = mode in ('offline_validate', 'preinstall')
        if mode == 'preinstall':
            vpn_flags = ('acknowledge_network_policy', 'acknowledge_guest_autoconfigure')
            mode_ok = (type(request) is dict and current.get('published') is False
                       and request.get('acknowledge_preinstall') is True
                       and ((request.get('defer_vpn') is True
                             and not any(key in request for key in ('vpn_configuration_id', 'acknowledge_normalization') + vpn_flags)
                             and current.get('user_vpn_configuration_supplied') is False)
                            or (request.get('defer_vpn', False) is False
                                and all(request.get(key) is True for key in vpn_flags)
                                and type(request.get('vpn_configuration_id')) is str
                                and re.fullmatch('[0-9a-f]{32}', request['vpn_configuration_id']) is not None)))
        if (type(current) is not dict or type(request) is not dict or not mode_ok
                or any(current.get(k) != v or request.get(k) != v for k, v in
                       (('id', job_id), ('name', name), ('mode', mode), ('source_vm', None)))
                or not phase_ok
                or current.get('system_restored') is not True
                or any(current.get(k) is not False for k in
                       ('guest_started', 'applications_preinstalled', 'desktop_verified', 'credentials_copied'))):
            raise OfflineDiskError('Only an untouched restore-only stage is eligible')
        stage = registry.safe_path(tart_home / '.gold-manager-staging' / job_id / 'new-environment')
        if current.get('stage_path') != str(stage):
            raise OfflineDiskError('Stage path does not match the exact restore job')
        if mode == 'preinstall':
            for path in (stage, stage.parent, stage.parent.parent):
                info = path.stat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OfflineDiskError('The new restore stage must remain private')
        for candidate in (tart_home / 'vms' / name, stage / 'state.vzvmsave', stage / 'state.bin', stage / 'savedstate'):
            if candidate.exists() or candidate.is_symlink():
                raise OfflineDiskError('Published or previously started stage rejected')
        receipt = registry.read_private(stage / '.clean-vm-installer.complete.json')
        if (type(receipt) is not dict or receipt.get('installer') != 'CleanVMInstaller'
                or receipt.get('status') != 'complete' or type(receipt.get('schemaVersion')) is not int
                or receipt['schemaVersion'] != 1
                or any(type(receipt.get(k)) is not int or receipt[k] != 0 for k in
                       ('networkDeviceCount', 'directorySharingDeviceCount', 'socketDeviceCount'))):
            raise OfflineDiskError('Restore isolation receipt is missing or unsupported')
        image = private_regular(stage / 'disk.img')
        if image.stat().st_size != request['disk_gib'] * 1024**3:
            raise OfflineDiskError('Disk size differs from the authorized restore')
        private_regular(stage / 'config.json')
        private_regular(stage / 'nvram.bin')
        return cls(state_dir, tart_home, job_id, name, stage, image, signature(image),
                   readonly_review=review_failed_operation_id is not None)

    def verify_unchanged(self):
        if signature(self.image) != self.baseline:
            raise OfflineDiskError('Restored image identity or contents metadata changed')

    @contextmanager
    def locked(self, external_lock=None, *, lifecycle_lock_fd=None):
        """Acquire config lock; optionally reuse the worker's exact inherited flock.

        Opening a second descriptor and flocking it is NOT reentrant, even in the
        same process. Never close the caller-owned inherited descriptor here.
        """
        fds = []
        try:
            primary = self.state_dir / 'build.lock'
            paths = [Path(external_lock)] if external_lock is not None else []
            if lifecycle_lock_fd is None:
                paths.append(primary)
            else:
                if type(lifecycle_lock_fd) is not int or lifecycle_lock_fd < 0:
                    raise OfflineDiskError('Invalid inherited lifecycle lock')
                expected = private_regular(primary).stat()
                actual = os.fstat(lifecycle_lock_fd)
                if (not stat.S_ISREG(actual.st_mode) or actual.st_uid != os.getuid()
                        or actual.st_mode & 0o077 or actual.st_nlink != 1
                        or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)):
                    raise OfflineDiskError('Inherited lifecycle lock identity mismatch')
                fcntl.flock(lifecycle_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if primary in paths:
                    raise OfflineDiskError('Duplicate inherited lifecycle lock path')
            for path in paths:
                fd = os.open(str(private_regular(path)), os.O_RDONLY | os.O_NOFOLLOW)
                fds.append(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Tart's configuration POSIX lock is an additional independent guard.
            fd = os.open(str(private_regular(self.stage / 'config.json')), os.O_RDWR | os.O_NOFOLLOW)
            fds.append(fd)
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.verify_unchanged()
            yield fd  # Borrowed config lock FD; callers must never close/reopen it.
        finally:
            for fd in reversed(fds): os.close(fd)


class DiskSession:
    """One private readonly attachment, full capture and guarded cleanup.

    Caller MUST hold StageTarget.locked for this entire session. A claimed lock
    flag alone never makes this class a privilege/security boundary against the
    same OS user. The pure validator treats lifecycle facts as caller assertions.
    """
    def __init__(self, target, evidence_dir, *, lock_held=False, probe_writable_attachment=False, ownership_mode=None, run=subprocess.run):
        if not isinstance(target, StageTarget) or lock_held is not True:
            raise OfflineDiskError('Explicit locked new-stage context required')
        if type(probe_writable_attachment) is not bool:
            raise OfflineDiskError('Explicit boolean required for write-access probe')
        if target.readonly_review and probe_writable_attachment:
            raise OfflineDiskError('Failed-stage review is strictly readonly, not write authorization')
        if ownership_mode not in (None, 'on', 'off'):
            raise OfflineDiskError('Unsupported explicit ownership mount mode')
        self.ownership_mode = ownership_mode
        self.probe_writable_attachment = probe_writable_attachment
        self.target = target
        self.directory = registry.safe_path(Path(evidence_dir), False)
        self.directory.mkdir(mode=0o700)  # no reuse, overwrite, or recursive cleanup
        self.run_process = run
        self.sequence = 0
        self.before_devices = set()
        self.attach_started = False
        self.attach_devices = None
        self.attachment_generation = None
        self.mountpoint = None
        self.mount_identity = None
        self.data_device = None
        self.attribution = None
        self.summary = {'readonly_requested': not probe_writable_attachment, 'writable_attachment_probe': probe_writable_attachment,
                        'mount_requested': False, 'apps_written': False, 'guest_started': False,
                        'capture_verified': False, 'cleanup_confirmed': False, 'manual_review_required': False}

    def command(self, args, label):
        if args[0] not in ('/usr/bin/hdiutil', '/usr/sbin/diskutil'):
            raise OfflineDiskError('Unreviewed command')
        self.sequence += 1
        stem = '%03d-%s' % (self.sequence, label)
        try:
            completed = self.run_process(args, stdin=subprocess.DEVNULL, capture_output=True,
                                         env=ENV, timeout=120)
        except Exception as error:
            registry.write_private(self.directory / (stem + '.error.json'), {'error_type': type(error).__name__})
            raise OfflineDiskError('System operation interrupted; cleanup must be checked') from None
        if len(completed.stdout) > MAX_OUTPUT or len(completed.stderr) > MAX_OUTPUT:
            raise OfflineDiskError('System operation output exceeded limit')
        for suffix, data in (('stdout', completed.stdout), ('stderr', completed.stderr)):
            with (self.directory / (stem + '.' + suffix)).open('xb') as f: f.write(data)
        registry.write_private(self.directory / (stem + '.json'), {'argv': args, 'exit_code': completed.returncode})
        if completed.returncode:
            raise OfflineDiskError('System operation failed: ' + label + '; no fallback')
        return completed.stdout

    def images(self):
        result = decode(self.command(['/usr/bin/hdiutil', 'info', '-plist'], 'images'))
        images = result.get('images')
        if type(images) is not list or any(type(i) is not dict for i in images):
            raise OfflineDiskError('Unsupported image inventory')
        return images

    def owned(self, required=None, allow_absent=False):
        file_identity = signature(self.target.image)[:3]
        if file_identity != self.target.baseline[:3]:
            raise OfflineDiskError('Image file identity/size changed; no device operation permitted')
        inventory = self.images()
        matches = [i for i in inventory if i.get('image-path') == str(self.target.image)]
        if not matches and allow_absent:
            if self.attach_devices and any(e.get('dev-entry') in self.attach_devices
                    for image in inventory for e in image.get('system-entities', [])):
                raise OfflineDiskError('Original device mapping changed image ownership')
            return None, None
        if len(matches) != 1:
            raise OfflineDiskError('Image not uniquely attributed; never guess a device')
        mapping = matches[0]
        entries = mapping.get('system-entities', [])
        if type(entries) is not list or any(type(e) is not dict for e in entries):
            raise OfflineDiskError('Unsupported image device list')
        identifiers = [e.get('dev-entry') for e in entries]
        if (any(not isinstance(value, str) or not value.startswith('/dev/')
                or not DEVICE.fullmatch(value[5:]) for value in identifiers)
                or len(set(identifiers)) != len(identifiers)):
            raise OfflineDiskError('Invalid or duplicate owned device')
        if (self.attach_devices is None or frozenset(identifiers) != self.attach_devices
                or type(mapping.get('owner-uid')) is not int or mapping['owner-uid'] != os.getuid()
                or mapping.get('writeable') is not self.probe_writable_attachment
                or type(mapping.get('hdid-pid')) is not int or mapping['hdid-pid'] <= 0):
            raise OfflineDiskError('Image attachment owner/access/generation cannot be attributed')
        wholes = [e.get('dev-entry') for e in entries if e.get('content-hint') == 'GUID_partition_scheme']
        if len(wholes) != 1 or not isinstance(wholes[0], str) or not wholes[0].startswith('/dev/'):
            raise OfflineDiskError('Image whole device is ambiguous')
        whole = node(wholes[0][5:], True)
        if self.before_devices.intersection(identifiers) or (required is not None and required not in identifiers):
            raise OfflineDiskError('Device is not uniquely owned by this new attachment')
        generation = (whole, frozenset(identifiers), mapping['hdid-pid'], mapping['owner-uid'],
                      mapping['writeable'], file_identity)
        if self.attachment_generation is None:
            self.attachment_generation = generation
        elif generation != self.attachment_generation:
            raise OfflineDiskError('Attachment was replaced; never adopt or detach a new generation')
        return mapping, whole

    def __enter__(self):
        self.target.verify_unchanged()
        before = self.images()
        if any(i.get('image-path') == str(self.target.image) for i in before):
            raise OfflineDiskError('Image already attached; do not adopt existing attachment')
        self.before_devices = {e.get('dev-entry') for i in before for e in i.get('system-entities', [])}
        self.attach_started = True
        try:
            raw_attach = self.command(['/usr/bin/hdiutil', 'attach',
                '-readwrite' if self.probe_writable_attachment else '-readonly', '-nomount', '-nobrowse',
                '-noautoopen', '-noautofsck', '-imagekey', 'diskimage-class=CRawDiskImage', '-plist']
                + ([] if self.ownership_mode is None else ['-owners', self.ownership_mode])
                + [str(self.target.image)], 'attach')
            entities = decode(raw_attach).get('system-entities')
            if (type(entities) is not list or not entities or any(type(e) is not dict for e in entities)
                    or any(not isinstance(e.get('dev-entry'), str) or not e['dev-entry'].startswith('/dev/')
                           or not DEVICE.fullmatch(e['dev-entry'][5:]) for e in entities)
                    or len({e['dev-entry'] for e in entities}) != len(entities)):
                raise OfflineDiskError('Successful attach did not supply unique device identity')
            self.attach_devices = frozenset(e['dev-entry'] for e in entities)
            mapping, whole = self.owned()
            raw_owned = plistlib.dumps(mapping)
            raw_list = self.command(['/usr/sbin/diskutil', 'list', '-plist', whole], 'whole-list')
            self.owned(whole)
            raw_whole = self.command(['/usr/sbin/diskutil', 'info', '-plist', whole], 'whole-info')
            containers = [e['dev-entry'][5:] for e in mapping.get('system-entities', [])
                          if e.get('content-hint') == CONTAINER_HINT and isinstance(e.get('dev-entry'), str)
                          and e['dev-entry'].startswith('/dev/') and WHOLE.fullmatch(e['dev-entry'][5:])]
            if not containers or len(containers) != len(set(containers)):
                raise OfflineDiskError('Unsupported or duplicate APFS container inventory')
            apfs, groups, infos = {}, {}, {}
            for identifier in containers:
                self.owned(node(identifier, True))
                raw = self.command(['/usr/sbin/diskutil', 'apfs', 'list', '-plist', node(identifier, True)], identifier + '-apfs')
                entries = decode(raw).get('Containers', [])
                if len(entries) != 1 or entries[0].get('ContainerReference') != identifier:
                    raise OfflineDiskError('Restricted APFS output mismatch')
                stores = entries[0].get('PhysicalStores', [])
                if len(stores) != 1 or not re.fullmatch(re.escape(whole[5:]) + r's[1-9][0-9]*', stores[0].get('DeviceIdentifier', '')):
                    raise OfflineDiskError('Foreign physical store')
                apfs[identifier] = raw
                self.owned(node(identifier, True))
                groups[identifier] = self.command(['/usr/sbin/diskutil', 'apfs', 'listVolumeGroups', '-plist',
                                                  node(identifier, True)], identifier + '-groups')
                for volume in entries[0].get('Volumes', []):
                    volume_id = volume.get('DeviceIdentifier')
                    if not isinstance(volume_id, str) or not re.fullmatch(re.escape(identifier) + r's[1-9][0-9]*', volume_id):
                        raise OfflineDiskError('Foreign APFS volume')
                    self.owned(node(volume_id))
                    if volume_id in infos: raise OfflineDiskError('Duplicate APFS volume')
                    infos[volume_id] = self.command(['/usr/sbin/diskutil', 'info', '-plist', node(volume_id)], volume_id + '-info')
            context = offline_volume.ValidationContext(image_path=str(self.target.image), owner_uid=os.getuid(),
                image_is_new=True, unpublished=True, never_booted=True, lock_held=True, installer_exited=True)
            self.capture = {'context': context, 'attach_plist': raw_attach, 'owned_image_plist': raw_owned,
                'disk_list_plist': raw_list, 'whole_info_plist': raw_whole, 'apfs_plists': apfs,
                'groups_plists': groups, 'volume_info_plists': infos}
            if self.probe_writable_attachment:
                # Metadata capture ONLY. Never call the readonly parser on changed
                # access flags, never issue a mount, and return NO attribution.
                self.summary['raw_writable_metadata_captured'] = True
            else:
                self.attribution = offline_volume.validate_readonly(**self.capture)
                self.summary['capture_verified'] = True
            return self
        except BaseException:
            self.cleanup()
            raise

    def check_mount_for_cleanup(self):
        return self.check_mounted_readonly()

    def verify_image_after_cleanup(self):
        self.target.verify_unchanged()

    def cleanup(self):
        if not self.attach_started: return
        try:
            mapping, whole = self.owned(allow_absent=True)
            if mapping is not None:
                if self.mountpoint is not None:
                    # If the mount command failed, detach the attributed readonly image
                    # rather than guessing a volume or forcing an unmount elsewhere.
                    if os.path.ismount(self.mountpoint):
                        self.check_mount_for_cleanup()
                        self.command(['/usr/sbin/diskutil', 'unmount', node(self.data_device)], 'unmount-data')
                    self.mountpoint = None
                self.owned(whole)
                self.command(['/usr/bin/hdiutil', 'detach', whole], 'detach')
            if any(i.get('image-path') == str(self.target.image) for i in self.images()):
                raise OfflineDiskError('Image remained attached after detach')
            self.verify_image_after_cleanup()
            self.summary['cleanup_confirmed'] = True
        except BaseException:
            self.summary['manual_review_required'] = True
            raise
        finally:
            registry.write_private(self.directory / 'session-summary.json', self.summary)

    def __exit__(self, kind, value, trace):
        if kind is not None: self.summary['operation_failed'] = True
        self.cleanup()
        return False

    def mount_readonly_for_probe(self):
        """Only readonly schema capture; this is not an application write API."""
        if self.attribution is None or not self.summary['capture_verified'] or self.mountpoint is not None:
            raise OfflineDiskError('Fresh validated attachment required before mount probe')
        self.data_device = self.attribution.data_device
        self.owned(node(self.data_device))
        self.mountpoint = self.directory / 'data-mount'
        self.mountpoint.mkdir(mode=0o700)
        # Readonly attachment makes all image sectors non-writable even if mount fails.
        options = [] if self.ownership_mode is None else ['-mountOptions', 'owners' if self.ownership_mode == 'on' else 'noowners']
        self.command(['/usr/sbin/diskutil', 'mount', 'readOnly', 'nobrowse'] + options + ['-mountPoint',
                      str(self.mountpoint), node(self.data_device)], 'mount-readonly-data')
        info = self.check_mounted_readonly()
        if self.ownership_mode is not None and info.get('GlobalPermissionsEnabled') is not (self.ownership_mode == 'on'):
            raise OfflineDiskError('Explicit readonly ownership mode not applied by macOS')
        self.summary['mount_requested'] = True
        self.summary['readonly_data_mount_verified'] = True
        return self.mountpoint

    def check_mounted_readonly(self):
        if self.mountpoint is None or self.attribution is None or self.data_device != self.attribution.data_device:
            raise OfflineDiskError('No attributed readonly Data mount')
        mapping, _ = self.owned(node(self.data_device))
        mounts = [(e.get('dev-entry'), e.get('mount-point')) for e in mapping['system-entities'] if e.get('mount-point')]
        if mounts != [(node(self.data_device), str(self.mountpoint))] or mapping.get('writeable') is not False:
            raise OfflineDiskError('Only the attributed readonly Data mount is allowed')
        raw = self.command(['/usr/sbin/diskutil', 'info', '-plist', node(self.data_device)], 'mounted-data-info')
        offline_volume.validate_mounted_readonly(self.attribution, str(self.mountpoint), raw)
        if registry.safe_path(self.mountpoint) != self.mountpoint or not os.path.ismount(self.mountpoint):
            raise OfflineDiskError('Readonly Data mountpoint changed')
        current = self.mountpoint.stat()
        identity = (current.st_dev, current.st_ino)
        if self.mount_identity is not None and self.mount_identity != identity:
            raise OfflineDiskError('Readonly Data filesystem identity changed')
        self.mount_identity = identity
        self.mounted_info = raw
        return decode(raw)
