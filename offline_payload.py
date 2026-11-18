"""Explicit extraction of acquired GUI artifacts into fresh private staging.

No application/installer execution, host application copying, credentials,
quarantine removal or re-signing. ZIP members are preflighted and extracted by
the same restricted parser, without external archive execution. DMG access is readonly, attributed to the exact acquired file,
and never accepts a software licence automatically. Outputs still require the
separate signature, complete-bundle and publisher verification step.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import re
import stat
import subprocess
import time
import unicodedata
import uuid
import zipfile

import guest_app_artifacts as artifacts
import managed_registry as registry
import quarantine_policy
from offline_volume import parse_plist


class PayloadError(ValueError):
    pass


def _require(ok, message):
    if not ok: raise PayloadError(message)


def _canonical(path, exists=True):
    return registry.safe_path(Path(path), exists)


def _new_directory(path):
    path = _canonical(path, False)
    _require(path.parent.is_dir() and not path.parent.is_symlink(), 'Missing extraction parent')
    path.mkdir(mode=0o700)
    return path


def _hash(path):
    path = _canonical(path)
    s = path.stat()
    _require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and not s.st_mode & 0o022, 'Unsafe artifact file')
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''): h.update(block)
    after = path.stat()
    _require((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Artifact changed during hash')
    return h.hexdigest()


def _bind(manifest, receipt):
    _require(isinstance(manifest, artifacts.ArtifactManifest)
             and isinstance(receipt, artifacts.DownloadReceipt)
             and receipt.artifact_key == manifest.artifact_key, 'Unbound download receipt')
    artifact = _canonical(receipt.artifact_path)
    _require(_hash(artifact) == receipt.sha256 and artifact.stat().st_size == receipt.size_bytes
             and (manifest.known_sha256 is None or receipt.sha256 == manifest.known_sha256), 'Artifact changed after acquisition')
    return artifact


def _quarantine(path):
    # Use native macOS support; Python os.*xattr is not available on this host.
    return quarantine_policy.ensure(path)


def _zip_inventory_hash(entries):
    values = [(e.filename, e.header_offset, e.CRC, e.file_size, e.compress_size,
               e.compress_type, e.external_attr, e.flag_bits) for e in entries]
    return hashlib.sha256(json.dumps(values, ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()


def inspect_zip(archive_path, expected_app='Claude.app', *, maximum_bytes=8*1024**3, maximum_entries=100000):
    """Pure archive inspection, no extraction. Complete inventory before writes."""
    _require(expected_app == 'Claude.app', 'Unsupported ZIP product')
    inventory, aliases, total, keys = {}, {}, 0, set()
    with zipfile.ZipFile(archive_path) as z:
        entries = z.infolist()
        _require(0 < len(entries) <= maximum_entries, 'ZIP entry count limit')
        for entry in entries:
            name = entry.filename
            _require(isinstance(name, str) and 0 < len(name) <= 4096
                     and all(ord(c) >= 32 and ord(c) != 127 for c in name)
                     and not name.startswith('/') and '\\' not in name and '\x00' not in name,
                     'Unsafe ZIP path')
            directory = entry.is_dir()
            clean = name[:-1] if directory else name
            path = PurePosixPath(clean)
            _require(clean == path.as_posix() and '..' not in path.parts and '.' not in path.parts
                     and path.parts[0] in (expected_app, '__MACOSX'), 'ZIP path outside expected bundle')
            key = unicodedata.normalize('NFD', clean).casefold()
            _require(key not in keys, 'Duplicate or case/Unicode-colliding ZIP entry')
            keys.add(key)
            _require(not entry.flag_bits & 1 and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                     'Unsupported encrypted/compressed ZIP entry')
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            _require(not mode & (stat.S_ISUID | stat.S_ISGID), 'Set-id ZIP entry')
            if directory:
                _require(kind in (0, stat.S_IFDIR) and entry.file_size == 0, 'Invalid ZIP directory')
                typename = 'directory'
            elif kind == stat.S_IFLNK:
                _require(path.parts[0] == expected_app and 0 < entry.file_size <= 4096, 'Unsafe ZIP symlink')
                try: link = z.read(entry).decode('utf-8')
                except (UnicodeError, zipfile.BadZipFile): raise PayloadError('Invalid ZIP link') from None
                _require(link and not link.startswith('/') and '\\' not in link
                         and all(ord(c) >= 32 and ord(c) != 127 for c in link), 'Unsafe ZIP symlink target')
                aliases[clean] = link
                typename = 'symlink'
            else:
                _require(kind in (0, stat.S_IFREG), 'Special file in ZIP')
                if path.parts[0] == '__MACOSX':
                    _require(entry.file_size <= 16*1024**2, 'Oversized AppleDouble metadata')
                typename = 'file'
            total += entry.file_size
            _require(total <= maximum_bytes and entry.file_size <= maximum_bytes,
                     'Expanded ZIP byte limit')
            inventory[clean] = typename
        _require(expected_app in inventory and inventory[expected_app] == 'directory', 'Missing ZIP application root')
        # APFS/HFS may be case-insensitive and Unicode-normalizing. Model every
        # explicit AND implicit parent in the same namespace before resolving
        # symlinks; checking complete entry strings alone is insufficient.
        namespace = {}
        for name in inventory:
            parts = PurePosixPath(name).parts
            for length in range(1, len(parts) + 1):
                prefix = '/'.join(parts[:length])
                normalized = unicodedata.normalize('NFD', prefix).casefold()
                _require(normalized not in namespace or namespace[normalized] == prefix,
                         'ZIP parent case/Unicode alias')
                namespace[normalized] = prefix
        for name in inventory:
            for parent in PurePosixPath(name).parents:
                if str(parent) == '.': continue
                _require(inventory.get(str(parent), 'directory') == 'directory', 'ZIP entry traverses file or link')
        for name in aliases:
            # Resolve against the complete archive inventory; never host filesystem.
            pending = list(PurePosixPath(name).parts)
            current, count = [], 0
            while pending:
                part = pending.pop(0)
                if part in ('', '.'): continue
                if part == '..':
                    _require(len(current) > 1, 'ZIP symlink escapes application')
                    current.pop(); continue
                current.append(part)
                _require(current[0] == expected_app, 'ZIP symlink escapes application')
                candidate = '/'.join(current)
                normalized = unicodedata.normalize('NFD', candidate).casefold()
                _require(normalized in namespace and namespace[normalized] == candidate,
                         'ZIP link crosses missing or case/Unicode-aliased path')
                if candidate in aliases:
                    count += 1
                    _require(count <= 40, 'Cyclic ZIP symlink')
                    target = aliases[candidate]
                    current.pop()
                    pending = target.split('/') + pending
                elif pending:
                    _require(inventory.get(candidate, 'directory') == 'directory', 'ZIP link crosses regular file')
            _require(len(current) > 1 and '/'.join(current) in inventory,
                     'Broken ZIP symlink or link to application root')
        # Use the same parser as extraction. Reading every member checks local
        # header names, actual stream lengths and CRC, not just central metadata.
        actual_total = 0
        try:
            for entry in entries:
                actual = 0
                with z.open(entry) as stream:
                    while True:
                        block = stream.read(1024*1024)
                        if not block: break
                        actual += len(block); actual_total += len(block)
                        _require(actual <= entry.file_size and actual_total <= maximum_bytes,
                                 'Actual ZIP expansion exceeds declared bounds')
                _require(actual == entry.file_size, 'ZIP expanded length mismatch')
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError):
            raise PayloadError('ZIP local header, stream or CRC disagrees with inventory') from None
        fingerprint = _zip_inventory_hash(entries)
    return {'member_count': len(inventory), 'declared_expanded_bytes': total,
            'symlink_count': len(aliases), 'expected_app': expected_app, 'extraction_performed': False,
            'inventory_sha256': fingerprint,
            'appledouble_entries': sum(name == '__MACOSX' or name.startswith('__MACOSX/') for name in inventory)}


class Recorder:
    def __init__(self, directory, run=subprocess.run):
        self.directory = _new_directory(directory)
        self.run = run
        self.sequence = 0

    def command(self, argv, label, timeout=120):
        _require(argv[0] in ('/usr/bin/ditto','/usr/bin/hdiutil','/usr/sbin/diskutil'), 'Unreviewed extraction tool')
        self.sequence += 1
        stem = '%03d-%s' % (self.sequence, label)
        result = self.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                          env={'HOME':'/var/empty','PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'en_US.UTF-8'})
        _require(len(result.stdout)+len(result.stderr) <= 4*1024**2, 'Excessive tool output')
        for suffix, raw in (('stdout',result.stdout),('stderr',result.stderr)):
            with (self.directory/(stem+'.'+suffix)).open('xb') as f:f.write(raw)
        registry.write_private(self.directory/(stem+'.json'),{'argv':argv,'exit_code':result.returncode})
        _require(result.returncode == 0, 'Extraction operation failed: '+label)
        return result.stdout


def extract_zip(manifest, receipt, destination, evidence_dir, *, run=subprocess.run):
    _require(manifest.product == 'claudeDesktop', 'Only official Claude ZIP supported')
    artifact = _bind(manifest, receipt)
    preflight = inspect_zip(artifact, maximum_bytes=manifest.maximum_bundle_bytes,
                            maximum_entries=manifest.maximum_bundle_entries)
    recorder = Recorder(evidence_dir, run)
    registry.write_private(recorder.directory/'zip-preflight.json', preflight)
    # Do not silently drop AppleDouble/resource-fork metadata. The observed
    # ordinary Electron ZIP layout can be extracted by the exact same parser;
    # an archive requiring native metadata restoration needs a separate review.
    _require(preflight['appledouble_entries'] == 0, 'ZIP AppleDouble metadata restoration not supported')
    destination = _new_directory(destination)
    with zipfile.ZipFile(artifact) as archive:
        entries = archive.infolist()
        _require(_zip_inventory_hash(entries) == preflight['inventory_sha256'], 'ZIP inventory changed after preflight')
        directories = {}
        links = []
        def directory(path):
            _require(path == destination or destination in path.parents, 'Extraction directory escaped staging')
            if path == destination: return
            directory(path.parent)
            if not path.exists(): path.mkdir(mode=0o700)
            _require(path.is_dir() and not path.is_symlink() and _canonical(path) == path,
                     'Extraction parent is not a controlled directory')
            directories.setdefault(path, 0o755)
        # No symlink is created until ALL regular files and directories are done.
        # Unreferenced local ZIP headers are never interpreted or extracted.
        for entry in entries:
            target = destination / entry.filename.rstrip('/')
            mode = entry.external_attr >> 16
            if entry.is_dir():
                directory(target); directories[target] = (mode & 0o777) or 0o755
            elif stat.S_IFMT(mode) == stat.S_IFLNK:
                directory(target.parent); links.append((entry,target))
            else:
                directory(target.parent)
                fd = os.open(str(target), os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd,'wb') as output, archive.open(entry) as stream:
                    written = 0
                    while True:
                        block = stream.read(1024*1024)
                        if not block: break
                        written += len(block)
                        _require(written <= entry.file_size, 'ZIP member expanded beyond inventory')
                        output.write(block)
                    _require(written == entry.file_size, 'ZIP member truncated during extraction')
                    output.flush(); os.fsync(output.fileno())
                    os.fchmod(output.fileno(), (mode & 0o777) or 0o644)
        for entry,target in links:
            _require(not target.exists() and not target.is_symlink(), 'ZIP link would replace a filesystem entry')
            os.symlink(archive.read(entry).decode('utf-8'),str(target))
        for path,mode in sorted(directories.items(),key=lambda item:len(item[0].parts),reverse=True):
            _require(_canonical(path) == path and path.is_dir(), 'ZIP directory identity changed')
            os.chmod(path,mode)
    registry.write_private(recorder.directory/'extraction-engine.json',{
        'engine':'Python zipfile, same parser as preflight','unreferenced_local_headers_ignored':True,
        'symlinks_created_after_all_regular_members':True,'AppleDouble_metadata_silently_dropped':False})
    _require(_hash(artifact) == receipt.sha256, 'Archive changed during extraction')
    app = _canonical(destination/'Claude.app')
    _require(app.is_dir(), 'Expected application not extracted')
    _quarantine(app)
    return (app,)


@contextmanager
def mounted_dmg(manifest, receipt, mountpoint, recorder):
    _require(manifest.product in ('ccbaga','clashVergeRev'), 'Unsupported DMG product')
    image = _bind(manifest, receipt)
    mountpoint = _new_directory(mountpoint)
    def file_identity():
        current = _canonical(image).stat()
        return (current.st_dev,current.st_ino,current.st_size)
    original_file = file_identity()
    attach_devices = None
    generation = None
    def images():
        raw = recorder.command(['/usr/bin/hdiutil','info','-plist'],'images')
        value = parse_plist(raw).get('images')
        _require(type(value) is list, 'Unsupported image inventory')
        return value
    before = images()
    _require(not any(i.get('image-path') == str(image) for i in before), 'Artifact already attached')
    before_devices = {e.get('dev-entry') for i in before for e in i.get('system-entities',[])}
    def owned(allow_absent=False):
        nonlocal generation
        _require(file_identity()==original_file, 'Artifact file identity changed')
        inventory = images()
        matches = [i for i in inventory if i.get('image-path')==str(image)]
        if not matches and allow_absent:
            _require(not attach_devices or not any(e.get('dev-entry') in attach_devices
                      for i in inventory for e in i.get('system-entities',[])), 'Artifact device ownership changed')
            return None,None
        _require(len(matches)==1, 'Artifact not uniquely attached')
        mapping=matches[0]
        _require(mapping.get('writeable') is False and mapping.get('owner-uid')==os.getuid(), 'Artifact attachment not readonly/owned')
        entries=mapping.get('system-entities',[])
        _require(type(entries) is list and all(type(e) is dict for e in entries), 'Unsupported artifact entities')
        devices=[e.get('dev-entry') for e in entries]
        _require(attach_devices is not None and all(isinstance(d,str) and re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)?',d) for d in devices)
                 and len(devices)==len(set(devices)) and frozenset(devices)==attach_devices
                 and not before_devices.intersection(devices)
                 and type(mapping.get('hdid-pid')) is int and mapping['hdid-pid']>0,
                 'Artifact attachment generation is not proven')
        roots=[e.get('dev-entry') for e in entries if e.get('content-hint') in
               ('GUID_partition_scheme','Apple_partition_scheme','Apple_HFS','Apple_APFS')
               and re.fullmatch(r'/dev/disk[0-9]+',e.get('dev-entry',''))]
        _require(len(roots)==1 and roots[0] not in before_devices, 'Ambiguous artifact whole device')
        observed=(roots[0],frozenset(devices),mapping['hdid-pid'],mapping['owner-uid'],mapping['writeable'])
        if generation is None:generation=observed
        else:_require(generation==observed, 'Artifact attachment replaced; no detach of new generation')
        return mapping,roots[0]
    try:
        # No -acceptlicense, input is /dev/null: SLA prompts must fail, not be consented.
        raw=recorder.command(['/usr/bin/hdiutil','attach','-readonly','-nobrowse','-noautoopen','-noautofsck',
                              '-mountpoint',str(mountpoint),'-plist',str(image)],'attach-dmg')
        attached=parse_plist(raw)
        entities=attached.get('system-entities')
        _require(type(entities) is list and entities and all(type(e) is dict
                 and isinstance(e.get('dev-entry'),str) for e in entities), 'Artifact attach lacks device identities')
        attach_devices=frozenset(e['dev-entry'] for e in entities)
        _require(len(attach_devices)==len(entities), 'Duplicate artifact attach device')
        mapping,whole=owned()
        mounts=[e for e in attached.get('system-entities',[]) if e.get('mount-point')]
        _require(len(mounts)==1 and mounts[0]['mount-point']==str(mountpoint)
                 and mounts[0].get('dev-entry') in {e.get('dev-entry') for e in mapping['system-entities']},
                 'Artifact mounted at unexpected location')
        device=mounts[0]['dev-entry']
        _require(re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)?',device) is not None, 'Invalid artifact device')
        info=parse_plist(recorder.command(['/usr/sbin/diskutil','info','-plist',device],'dmg-volume-info'))
        _require(info.get('MountPoint')==str(mountpoint) and info.get('WritableMedia') is False
                 and info.get('WritableVolume') is False and info.get('DeviceNode')==device
                 and os.path.ismount(mountpoint), 'Readonly artifact filesystem not confirmed')
        yield mountpoint
    finally:
        mapping,whole=owned(allow_absent=True)
        if mapping is not None:recorder.command(['/usr/bin/hdiutil','detach',whole],'detach-dmg')
        _require(not any(i.get('image-path')==str(image) for i in images()), 'Artifact remained attached')
        _require(_hash(image)==receipt.sha256, 'Artifact changed during readonly access')


def extract_dmg(manifest, receipt, destination, evidence_dir, *, run=subprocess.run):
    recorder=Recorder(evidence_dir,run)
    destination=_new_directory(destination)
    result=[]
    with mounted_dmg(manifest,receipt,recorder.directory/'mount',recorder) as mount:
        for expected in manifest.expected_apps:
            source=_canonical(mount/expected.name)
            _require(source.is_dir() and source.parent==mount, 'Expected complete app missing from artifact')
            # Inspect links/layout before ditto can follow or reproduce them.
            artifacts._tree_snapshot(source,manifest)
            target=_canonical(destination/expected.name,False)
            _require(not target.exists() and not target.is_symlink(), 'Extraction target exists')
            recorder.command(['/usr/bin/ditto',str(source),str(target)],'copy-complete-app',timeout=600)
            _quarantine(target)
            result.append(target)
    return tuple(result)
