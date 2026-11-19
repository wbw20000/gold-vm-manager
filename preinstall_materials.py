"""Owned, durable preparation of the complete reviewed original GUI material set.

No VM lifecycle, server, app execution, automatic retry, adoption of foreign or
partial caches, or import side effects. Only this store's own completed attempts
can be reused, and only after full native revalidation (load_reusable). Caller keeps the lifecycle lock and private root exclusive through
subsequent installation. Native trust checks are mandatory, including on reload.
"""
from contextlib import contextmanager
import dataclasses
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import stat
import uuid

import error_codes
import guest_app_artifacts as artifacts
from guest_app_pins import reviewed_manifests
from offline_install import Material, PRODUCTS, APP_NAMES, validate_material_set
import offline_payload
import offline_volume
import quarantine_policy as quarantine

SCHEMA = 1
SUPPORTED_SCHEMA_TUPLES = (('Darwin', 'arm64', '26.6.2', 'macos-26.6.2'),)
NATIVE_TOOLS = ('/usr/bin/hdiutil', '/usr/bin/ditto', '/usr/sbin/diskutil',
                '/usr/bin/xattr', '/usr/bin/lipo', '/usr/bin/codesign', '/usr/sbin/spctl')
_REQUIRED_INTERFACES = ('exclusive_lifecycle_lock', 'reviewed_ipsw_restore_input',
                        'verified_tart_runtime', 'verified_gvproxy_runtime',
                        'fresh_guest_disk_lifecycle')
_ID = re.compile(r'[0-9a-f]{32}\Z')


class MaterialPreparationError(ValueError):
    """Stable, credential-free code; retained files are never installation success."""
    def __init__(self, code, attempt_id=None):
        super().__init__(code)
        self.code = code
        self.attempt_id = attempt_id


def _need(ok, code):
    if not ok:
        raise MaterialPreparationError(code)


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _identity(path):
    info = path.lstat()
    return [info.st_dev, info.st_ino]


def _canonical(path):
    raw = os.fspath(path)
    _need(isinstance(raw, str) and raw == str(Path(raw)) and Path(raw).is_absolute()
          and '..' not in Path(raw).parts, 'noncanonical-path')
    path = Path(raw)
    for part in reversed((path,) + tuple(path.parents)):
        info = part.lstat()
        _need(not stat.S_ISLNK(info.st_mode), 'symlink-path-refused')
        if part != path:
            trusted_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            _need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                  and (not info.st_mode & 0o022 or trusted_sticky), 'unsafe-parent-directory')
    _need(path.resolve(strict=True) == path, 'noncanonical-path')
    return path


def _directory(path, private=True):
    path = _canonical(path)
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and not stat.S_IMODE(info.st_mode) & 0o7022, 'unsafe-directory')
    if private:
        _need(stat.S_IMODE(info.st_mode) == 0o700, 'directory-not-private')
    return path


def _regular(path, private=True):
    path = _canonical(path)
    info = path.lstat()
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
          and info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o7022,
          'unsafe-regular-file')
    if private:
        _need(stat.S_IMODE(info.st_mode) == 0o600, 'file-not-private')
    return info


def _sync(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir(path):
    _directory(path.parent)
    path.mkdir(mode=0o700)  # exclusive; never adopt even an empty preexisting output
    _directory(path)
    _sync(path.parent)
    return path


def _write(path, data):
    _directory(path.parent)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(_json(data) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


def _read(path):
    before = _regular(path)
    _need(before.st_size <= 8 * 1024**2, 'record-too-large')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        _need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), 'record-changed')
        raw = stream.read(8 * 1024**2 + 1)
        after = os.fstat(stream.fileno())
    _need((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
          (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'record-changed')
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'duplicate-record-key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: _need(False, 'invalid-record'))
    except (ValueError, UnicodeError):
        raise MaterialPreparationError('invalid-record') from None


def _file_hash(path):
    _regular(path)
    return artifacts._regular_hash(path, 8 * 1024**2)[0]


def _tool_ready(path):
    try:
        info = Path(path).stat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022 and os.access(path, os.X_OK))
    except OSError:
        return False


def capability_report():
    """Sanitized local readiness only; never probes network, disks, apps or VMs.

    Unknown OS/schema tuples fail closed, not 'all Apple Silicon macOS supported'.
    Required parent interfaces are NOT assessed or acquired by this module.
    """
    def clean(value):
        return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value) else 'unknown'
    try:
        observed = tuple(clean(v) for v in (platform.system(), platform.machine(),
                                          platform.mac_ver()[0], offline_volume.SCHEMA))
    except Exception:
        observed = ('unknown', 'unknown', 'unknown', 'unknown')
    tools = {Path(path).name: _tool_ready(path) for path in NATIVE_TOOLS}
    supported = observed in SUPPORTED_SCHEMA_TUPLES
    return {'schema': SCHEMA, 'ready': supported and all(tools.values()),
            'supported_platform': supported, 'observed_tuple': list(observed),
            'supported_tuples': [list(v) for v in SUPPORTED_SCHEMA_TUPLES],
            'native_tools': tools, 'resume_supported': False,
            'parent_interfaces_not_assessed': list(_REQUIRED_INTERFACES)}


def _manifest_set(manifests):
    values = tuple(reviewed_manifests() if manifests is None else manifests)
    _need(len(values) == 3 and all(type(m) is artifacts.ArtifactManifest for m in values)
          and tuple(m.product for m in values) == PRODUCTS, 'complete-reviewed-set-required')
    _need(tuple(a.name for m in values for a in m.expected_apps) == APP_NAMES,
          'complete-reviewed-set-required')
    for manifest in values:
        manifest.__post_init__()
        artifacts._require_review(manifest)
        _need(manifest.known_sha256 is not None and not manifest.allow_unpinned_sha256,
              'pinned-reviewed-originals-required')
    return values


def _bundle_permissions(app, manifest):
    _directory(app, private=False)
    stack = [app]
    count = 0
    while stack:
        for path in stack.pop().iterdir():
            count += 1
            _need(count <= manifest.maximum_bundle_entries, 'too-many-bundle-entries')
            info = path.lstat()
            _need(info.st_uid == os.getuid(), 'foreign-owned-bundle-entry')
            if stat.S_ISLNK(info.st_mode):
                # Complete originals NEED internal Framework links. Never allow
                # a symlink for cache/control paths or an escaping bundle link.
                artifacts._resolve_internal_link(path, app)
            elif stat.S_ISDIR(info.st_mode):
                _need(not stat.S_IMODE(info.st_mode) & 0o7022, 'unsafe-bundle-mode')
                stack.append(path)
            else:
                _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                      and not stat.S_IMODE(info.st_mode) & 0o7022, 'unsafe-bundle-file')


def _trees(receipt):
    return [{'name': app['name'], 'sha256': app['bundle_tree_sha256'],
             'bytes': app['bundle_bytes'], 'entries': app['bundle_entries']}
            for app in receipt.apps]


class MaterialManager:
    """Dedicated existing canonical 0700 root, created by the trusted caller.

    manifests=None uses reviewed_manifests(); overrides are explicit reviewed
    inputs, not network discovery. progress(dict) gets allowlisted summaries.
    cancelled() is cooperative BETWEEN bounded download/native operations.
    Parent must hold its lifecycle lock; this store also refuses concurrent use.
    """
    def __init__(self, root, *, manifests=None, loopback_proxy=None,
                 cancelled=None, progress=None,
                 deadline_seconds=artifacts.DEFAULT_DOWNLOAD_DEADLINE_SECONDS):
        try:
            self.root = _directory(root)
            self.manifests = _manifest_set(manifests)
            artifacts._build_opener(loopback_proxy)  # validates explicit credential-free loopback only
            artifacts._deadline(deadline_seconds)
            _need(cancelled is None or callable(cancelled), 'invalid-cancellation-callback')
            _need(progress is None or callable(progress), 'invalid-progress-callback')
            self.loopback_proxy = loopback_proxy
            self.cancelled, self.progress = cancelled, progress
            self.deadline_seconds = deadline_seconds
            self.last_attempt_id = None
            marker = self.root / 'store.json'
            if not list(self.root.iterdir()):
                # A nonempty unowned root is NEVER a source/cache import interface.
                _write(self.root / 'manager.lock', {})
                with self._lock():
                    _mkdir(self.root / 'attempts')
                    _write(marker, {'schema': SCHEMA, 'store_id': uuid.uuid4().hex,
                                    'root_identity': _identity(self.root),
                                    'record_key': os.urandom(32).hex()})
            _need({p.name for p in self.root.iterdir()} == {'store.json', 'manager.lock', 'attempts'},
                  'unowned-material-root')
            self.store = _read(marker)
            _need(type(self.store) is dict and set(self.store) ==
                  {'schema', 'store_id', 'root_identity', 'record_key'}
                  and type(self.store['schema']) is int and self.store['schema'] == SCHEMA
                  and _ID.fullmatch(self.store['store_id']) is not None
                  and re.fullmatch(r'[0-9a-f]{64}', self.store['record_key']) is not None
                  and self.store['root_identity'] == _identity(self.root), 'unowned-material-root')
            _directory(self.root / 'attempts')
            _regular(self.root / 'manager.lock')
            self.key = bytes.fromhex(self.store['record_key'])
        except MaterialPreparationError:
            raise
        except Exception:
            raise MaterialPreparationError('invalid-material-manager-input') from None

    @contextmanager
    def _lock(self):
        _directory(self.root)
        path = self.root / 'manager.lock'
        before = _regular(path)
        fd = os.open(str(path), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            _need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), 'lock-changed')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise MaterialPreparationError('material-manager-busy') from None
            if hasattr(self, 'store'):
                _need(_read(self.root / 'store.json') == self.store
                      and _identity(self.root) == self.store['root_identity'], 'material-store-changed')
            yield
        finally:
            os.close(fd)

    def _record(self, path, data):
        envelope = {'data': data, 'hmac_sha256': hmac.new(self.key, _json(data), hashlib.sha256).hexdigest()}
        _write(path, envelope)

    def _record_read(self, path):
        envelope = _read(path)
        _need(type(envelope) is dict and set(envelope) == {'data', 'hmac_sha256'}
              and type(envelope['hmac_sha256']) is str, 'unowned-material-record')
        expected = hmac.new(self.key, _json(envelope['data']), hashlib.sha256).hexdigest()
        _need(hmac.compare_digest(expected, envelope['hmac_sha256']), 'material-record-modified')
        return envelope['data']

    def _attempt(self, attempt_id):
        _need(type(attempt_id) is str and _ID.fullmatch(attempt_id) is not None, 'invalid-attempt-id')
        _directory(self.root / 'attempts')
        attempt = _directory(self.root / 'attempts' / attempt_id)
        start = self._record_read(attempt / 'attempt.json')
        _need(start == self._start(attempt_id), 'attempt-manifest-or-store-mismatch')
        return attempt

    def _start(self, attempt_id):
        return {'schema': SCHEMA, 'store_id': self.store['store_id'], 'attempt_id': attempt_id,
                'manifest_sha256': [m.manifest_sha256 for m in self.manifests]}

    def _notify(self, stage, product=None, completed_bytes=None, total_bytes=None):
        if self.progress is not None:
            event = {'attempt_id': self.last_attempt_id, 'stage': stage,
                     'product': product, 'resume_supported': False}
            if completed_bytes is not None:
                event.update(completed_bytes=completed_bytes, total_bytes=total_bytes)
            try:
                self.progress(event)
            except Exception:
                # Observers do not control transaction success or inject diagnostics.
                pass

    def _checkpoint(self, stage, product=None):
        self._notify(stage, product)
        if self.cancelled is not None:
            try:
                stop = bool(self.cancelled())
            except Exception:
                raise MaterialPreparationError('cancellation-callback-failed') from None
            _need(not stop, 'preparation-cancelled')

    def _receipt(self, manifest, cache, receipt):
        _directory(cache)
        _need(type(receipt) is artifacts.DownloadReceipt, 'invalid-download-receipt')
        path = Path(receipt.artifact_path)
        suffix = 'zip' if manifest.product == 'claudeDesktop' else 'dmg'
        hosts = ('downloads.claude.ai',) if suffix == 'zip' else ('github.com', 'release-assets.githubusercontent.com')
        _need(path.parent == cache and re.fullmatch(r'[0-9a-f]{32}\.' + suffix, path.name) is not None
              and receipt.artifact_key == manifest.artifact_key
              and receipt.sha256 == manifest.known_sha256
              and receipt.expected_sha256_matched is True and receipt.binary_verification_performed is False
              and type(receipt.size_bytes) is int and 0 < receipt.size_bytes <= manifest.maximum_download_bytes
              and receipt.final_host in hosts and receipt.etag is None, 'unbound-download-receipt')
        _regular(path)
        _need(set(cache.iterdir()) == {path}, 'unexpected-cache-content')
        digest, size = artifacts._regular_hash(path, manifest.maximum_download_bytes)
        _need((digest, size) == (receipt.sha256, receipt.size_bytes)
              and (manifest.declared_size_bytes is None or size == manifest.declared_size_bytes),
              'modified-raw-artifact')
        return path

    def _sources(self, manifest, stage, paths):
        _directory(stage)
        expected = tuple(stage / app.name for app in manifest.expected_apps)
        _need(type(paths) is tuple and paths == expected and set(stage.iterdir()) == set(expected),
              'incomplete-or-unexpected-source-set')
        for app in expected:
            _bundle_permissions(app, manifest)
        return expected

    def _evidence(self, receipt, path):
        artifacts.write_evidence(receipt, path)
        _sync(path.parent)  # make receipt name durable BEFORE any quarantine operation

    def _binding(self, manifest, receipt, stage, apps, verification, evidence):
        raw = Path(receipt.artifact_path)
        return {'manifest_sha256': manifest.manifest_sha256,
                'raw_identity': _identity(raw), 'stage_identity': _identity(stage),
                'app_identities': [_identity(app) for app in apps],
                'trees': _trees(verification),
                'quarantine_sha256': [_digest(quarantine.read(p)) for p in (raw,) + apps],
                'evidence_sha256': {name: _file_hash(evidence / name) for name in
                                    ('manifest.json', 'download.json', 'verification.json')}}

    def _byte_progress(self, product):
        """Throttled byte progress for one download: about every 2%, plus the end."""
        last = [None]
        def report(done, total):
            if type(done) is not int or done < 0 or not (total is None or (type(total) is int and total > 0)):
                return
            step = max(total // 50, 1) if total else 8 * 1024 ** 2
            if last[0] is not None and done - last[0] < step and done != total:
                return
            last[0] = done
            self._notify('downloading', product, done, total)
        return report

    def load_reusable(self) -> tuple[Material, ...]:
        """Newest completed attempt of THIS store for the current manifests, revalidated.

        Candidates are attempts whose signed start record matches this store and
        the current reviewed manifests, with a signed completion record and no
        failure record. Each is rebuilt by load(): full hashing plus native
        signature, notarization and quarantine checks, every time. A candidate
        that fails is skipped and left exactly as found (never repaired). Raises
        'material-cache-miss' when none passes; callers then download afresh.
        """
        scan_limit, tries = 256, 3
        _need(capability_report()['ready'], 'unsupported-material-capability')
        candidates = []
        try:
            with self._lock():
                with os.scandir(_directory(self.root / 'attempts')) as entries:
                    for index, entry in enumerate(entries):
                        _need(index < scan_limit, 'too-many-material-attempts')
                        if _ID.fullmatch(entry.name) is None or not entry.is_dir(follow_symlinks=False):
                            continue
                        try:
                            attempt = self._attempt(entry.name)
                            if (os.path.lexists(attempt / 'failure.json')
                                    or not os.path.lexists(attempt / 'complete.json')):
                                continue  # Failed or interrupted: never adopted.
                            candidates.append((_regular(attempt / 'complete.json').st_mtime_ns, entry.name))
                        except Exception:
                            continue  # Other manifests/store or unreadable: not a candidate.
        except MaterialPreparationError:
            raise
        except Exception:
            raise MaterialPreparationError('material-cache-miss') from None
        for _, attempt_id in sorted(candidates, reverse=True)[:tries]:
            try:
                return self.load(attempt_id)
            except MaterialPreparationError:
                continue
        self.last_attempt_id = None
        raise MaterialPreparationError('material-cache-miss')

    def prepare(self) -> tuple[Material, ...]:
        """Fresh attempt only. Returns the exact complete tuple[Material, ...].

        Failures/cancellation retain private evidence and raw/partial bytes. They
        are NOT resumable or installable. last_attempt_id identifies the attempt.
        """
        _need(capability_report()['ready'], 'unsupported-material-capability')
        with self._lock():
            attempt_id = uuid.uuid4().hex
            attempt = self.root / 'attempts' / attempt_id
            # Never write failure records into a preexisting/reused attempt.
            try:
                _mkdir(attempt)
            except Exception:
                raise MaterialPreparationError('attempt-output-already-exists-or-unsafe') from None
            self.last_attempt_id = attempt_id
            stage_name, product = 'initializing', None
            try:
                self._record(attempt / 'attempt.json', self._start(attempt_id))
                for name in ('cache', 'staging', 'evidence'):
                    _mkdir(attempt / name)
                for manifest in self.manifests:
                    product = manifest.product
                    cache = _mkdir(attempt / 'cache' / product)
                    evidence = _mkdir(attempt / 'evidence' / product)
                    stage = attempt / 'staging' / product
                    _write(evidence / 'manifest.json', dataclasses.asdict(manifest))
                    stage_name = 'downloading'
                    self._checkpoint(stage_name, product)
                    receipt = artifacts.download_artifact(manifest, cache, loopback_proxy=self.loopback_proxy,
                                                          deadline_seconds=self.deadline_seconds,
                                                          progress=self._byte_progress(product))
                    raw = self._receipt(manifest, cache, receipt)
                    self._evidence(receipt, evidence / 'download.json')
                    stage_name = 'quarantining'
                    self._checkpoint(stage_name, product)
                    quarantine.ensure(raw)
                    stage_name = 'extracting'
                    self._checkpoint(stage_name, product)
                    _need(not os.path.lexists(stage) and not os.path.lexists(evidence / 'extraction'),
                          'reused-extraction-output')
                    extractor = offline_payload.extract_zip if product == 'claudeDesktop' else offline_payload.extract_dmg
                    apps = extractor(manifest, receipt, stage, evidence / 'extraction')
                    apps = self._sources(manifest, stage, apps)
                    for app in apps:
                        quarantine.ensure(app)
                    stage_name = 'verifying'
                    self._checkpoint(stage_name, product)
                    verified = artifacts.verify_app_bundles(manifest, stage, apps, receipt)
                    self._evidence(verified, evidence / 'verification.json')
                    self._record(evidence / 'material.json',
                                 self._binding(manifest, receipt, stage, apps, verified, evidence))
                stage_name, product = 'verifying-complete-set', None
                self._checkpoint(stage_name)
                complete = dict(self._start(attempt_id), status='prepared',
                                material_sha256=[_file_hash(attempt / 'evidence' / m.product / 'material.json')
                                                 for m in self.manifests])
                # Reverify the WHOLE set after every product has finished; no stale
                # earlier success can become the final transaction's acceptance.
                materials = self._reconstruct(attempt, complete)
                self._checkpoint('committing')
                self._record(attempt / 'complete.json', complete)
                self._notify('prepared')
                return materials
            except BaseException as error:
                if isinstance(error, MaterialPreparationError):
                    code = error.code
                elif isinstance(error, artifacts.ArtifactError) and error.args and error_codes.is_code(error.args[0]):
                    code = error.args[0]  # Fixed artifact cause, e.g. download-timeout.
                else:
                    code = stage_name + '-failed'
                failure = dict(self._start(attempt_id), status='cancelled-retained' if code ==
                               'preparation-cancelled' else 'failed-retained', stage=stage_name,
                               code=code, product=product, resume_supported=False)
                try:
                    self._record(attempt / 'failure.json', failure)
                except Exception:
                    pass  # absent terminal record is interrupted-retained, NEVER success
                self._notify(failure['status'])
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                failed = MaterialPreparationError(code, attempt_id)
                failed.product = product  # Which material failed; a fixed product key.
                raise failed from None

    def _reconstruct(self, attempt, complete):
        for name in ('cache', 'staging', 'evidence'):
            _directory(attempt / name)
        _need(complete == dict(self._start(attempt.name), status='prepared',
                              material_sha256=[_file_hash(attempt / 'evidence' / m.product / 'material.json')
                                               for m in self.manifests]), 'incomplete-material-record')
        materials = []
        for manifest in self.manifests:
            self._checkpoint('revalidating', manifest.product)
            evidence = _directory(attempt / 'evidence' / manifest.product)
            binding = self._record_read(evidence / 'material.json')
            _need(_read(evidence / 'manifest.json') == json.loads(_json(dataclasses.asdict(manifest))),
                  'manifest-record-mismatch')
            receipt = artifacts.DownloadReceipt(**_read(evidence / 'download.json'))
            raw = self._receipt(manifest, attempt / 'cache' / manifest.product, receipt)
            stage = attempt / 'staging' / manifest.product
            apps = self._sources(manifest, stage, tuple(stage / a.name for a in manifest.expected_apps))
            # Only read quarantine on reload: missing/changed attributes fail, not repair.
            verified = artifacts.verify_app_bundles(manifest, stage, apps, receipt)
            _need(binding == self._binding(manifest, receipt, stage, apps, verified, evidence),
                  'modified-source-or-evidence')
            materials.append(Material(manifest, receipt, stage, apps))
        return validate_material_set(tuple(materials))

    def load(self, attempt_id) -> tuple[Material, ...]:
        """Reconstruct only THIS store's completed records, with native revalidation.

        There is intentionally no cache_path, receipt_path or app_path import API.
        """
        _need(capability_report()['ready'], 'unsupported-material-capability')
        try:
            with self._lock():
                attempt = self._attempt(attempt_id)
                _need(not os.path.lexists(attempt / 'failure.json'), 'retained-attempt-not-installable')
                _need(os.path.lexists(attempt / 'complete.json'), 'retained-attempt-not-installable')
                self.last_attempt_id = attempt_id
                return self._reconstruct(attempt, self._record_read(attempt / 'complete.json'))
        except MaterialPreparationError:
            raise
        except Exception:
            raise MaterialPreparationError('material-revalidation-failed', attempt_id) from None

    def summary(self, attempt_id):
        """Public status only, not current trust verification; no tool text/paths/proxy."""
        try:
            with self._lock():
                attempt = self._attempt(attempt_id)
                status = 'interrupted-retained'
                for name in ('failure.json', 'complete.json'):
                    if os.path.lexists(attempt / name):
                        record = self._record_read(attempt / name)
                        _need(all(record.get(k) == v for k, v in self._start(attempt_id).items()),
                              'unowned-material-record')
                        _need(record.get('status') in ('prepared', 'failed-retained', 'cancelled-retained'),
                              'invalid-attempt-status')
                        _need(status == 'interrupted-retained', 'conflicting-attempt-status')
                        status = record['status']
                return {'attempt_id': attempt_id, 'status': status, 'resume_supported': False,
                        'requires_reverification': True, 'guest_installation_performed': False,
                        'products': [{'product': m.product, 'version': m.version,
                                      'artifact_url': m.artifact_url,
                                      'apps': [a.name for a in m.expected_apps]} for m in self.manifests]}
        except MaterialPreparationError:
            raise
        except Exception:
            raise MaterialPreparationError('invalid-material-record', attempt_id) from None

    def resume(self, attempt_id):
        """Explicit fail-closed interface; no guessed partial discovery/adoption."""
        self.summary(attempt_id)
        raise MaterialPreparationError('resume-unavailable-retained-attempt', attempt_id)
