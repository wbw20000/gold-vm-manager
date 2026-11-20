"""One-click orchestration with inert fixtures; no native tool, mount, or VM runs."""
import builtins
from contextlib import ExitStack
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from guest_app_pins import reviewed_manifests
import host_artifacts
import host_tools
import lifecycle
import managed_registry as registry
import oneclick
import preinstall_materials
import preinstall_runtime
import provisioning
import quarantine_policy
import setup_profile
import vpn_store


GIB = 1024 ** 3
NAME = 'Fresh fixture'
SECRET = 'inert-explicit-user-password-do-not-log'
UNSELECTED = 'inert-unselected-password-do-not-use'
ENDPOINT = '8.8.4.4'  # Numeric only, never contacted.
SNI = 'fixture.example.com'
RECEIPT_TOKEN = 'e' * 64
ACKS = ('acknowledge_preinstall', 'acknowledge_network_policy')
UNVERIFIED = ('old_deleted', 'credentials_copied', 'host_credentials_copied', 'guest_started',
              'desktop_verified', 'vpn_connected', 'network_independently_verified')


def payload(configuration_id='a' * 32, **fields):
    return dict({key: True for key in ACKS}, name=NAME, vpn_configuration_id=configuration_id, **fields)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp_parent = Path('/tmp').resolve(strict=True)
        self.root = Path(tempfile.mkdtemp(prefix='gold-oneclick-test-', dir=str(self.tmp_parent)))
        self.addCleanup(self.clean_fixture)
        self.addCleanup(os.umask, os.umask(0o077))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.home = self.root / 'home'
        self.state = self.home / 'state'
        self.tart_home = self.home / '.tart'
        self.vms = self.tart_home / 'vms'
        for directory in (self.home, self.state, self.tart_home, self.vms):
            directory.mkdir(mode=0o700)
        self.stack.enter_context(mock.patch.dict(os.environ, {'HOME': str(self.home), 'TART_HOME': str(self.tart_home)}))
        self.target = self.vms / NAME
        self.stack.enter_context(mock.patch.multiple(
            registry, HOME=self.home, STATE_DIR=self.state, REGISTRY_PATH=self.state / 'registry.json'))
        self.stack.enter_context(mock.patch.multiple(
            lifecycle, HOME=self.home, STATE=self.state, TART_HOME=self.tart_home, VM_ROOT=self.vms,
            TART=self.root / 'forbidden-tart'))
        self.run = self.patch(subprocess, 'run', side_effect=self.host_query)
        self.spawn = self.patch(subprocess, 'Popen', side_effect=self.worker_spawn)
        self.dns = self.patch(socket, 'getaddrinfo', side_effect=AssertionError('No network resolution'))
        self.patch(lifecycle.process_identity, 'arguments', side_effect=AssertionError('No native process inspection'))
        self.caps = self.patch(oneclick, 'capabilities', return_value={'ready': True})
        self.legacy = [self.patch(module, attribute, side_effect=AssertionError('Legacy path forbidden'))
                       for module, attribute in ((lifecycle, 'inventory'), (lifecycle, 'start'),
                                                 (lifecycle, 'commit'), (provisioning, 'preflight'),
                                                 (provisioning, 'prepare_environment'),
                                                 (provisioning, '_active_profile'), (setup_profile, 'validate'))]
        self.keep_worker_lock = False
        self.worker_fd = None

    def clean_fixture(self):
        self.assertFalse(self.root.is_symlink())
        self.assertEqual(self.root.resolve(strict=True), self.root)
        self.assertEqual(self.root.parent, self.tmp_parent)
        self.assertTrue(self.root.name.startswith('gold-oneclick-test-'))
        self.assertEqual(self.root.stat().st_uid, os.getuid())
        shutil.rmtree(str(self.root))

    def patch(self, module, attribute, **kwargs):
        return self.stack.enter_context(mock.patch.object(module, attribute, **kwargs))

    def host_query(self, command, **kwargs):
        self.assertEqual(command, ['/usr/sbin/sysctl', '-n', 'hw.memsize'])
        return SimpleNamespace(returncode=0, stdout=str(32 * GIB), stderr='')

    def assert_clean_env(self, env):
        self.assertEqual(env, {
            'HOME': str(self.home), 'TART_HOME': str(self.tart_home), 'TART_NO_AUTO_PRUNE': '1',
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8',
            'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
        })

    def worker_spawn(self, command, **kwargs):
        job = self.job()
        fd, = kwargs['pass_fds']
        self.assertEqual(command, ['/usr/bin/python3', '-B', str(oneclick.HERE / 'oneclick.py'),
                                   '--worker', job['id'], '--lock-fd', str(fd),
                                   '--state-dir', str(self.state), '--tart-home', str(self.tart_home)])
        self.assertEqual((os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                         self.identity(self.state / 'build.lock'))
        self.assertIs(kwargs['close_fds'], True)
        self.assertIs(kwargs['start_new_session'], True)
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'], subprocess.STDOUT)
        self.assertEqual(Path(kwargs['stdout'].name), self.jobdir() / 'worker.log')
        self.assert_clean_env(kwargs['env'])
        self.assertEqual(job['phase'], 'queued')
        request = registry.read_private(self.jobdir() / 'request.json')
        stored = vpn_store.load_configuration(self.state, request['vpn_configuration_id'], job_id=job['id'])
        self.assertEqual(stored.bound_job, job['id'])  # Binding is durable before the child can start.
        if self.keep_worker_lock:
            self.worker_fd = os.dup(fd)  # Same open file description as inherited via pass_fds.
            self.addCleanup(self.release_worker_lock)
        return SimpleNamespace(pid=98765)

    def release_worker_lock(self):
        if self.worker_fd is not None:
            os.close(self.worker_fd)
            self.worker_fd = None

    def submission(self, password=SECRET, **overrides):
        node = dict({'type': 'trojan', 'server': ENDPOINT, 'port': 443, 'sni': SNI, 'password': password}, **overrides)
        return vpn_store.store_submission(self.state, {'input_mode': 'fields', 'nodes': [node]})['configuration_id']

    def start(self, request):
        return oneclick.start(request, state_dir=self.state, tart_home=self.tart_home)

    def job(self):
        return registry.read_private(self.state / 'build-current.json')

    def jobdir(self):
        return self.state / 'build-jobs' / self.job()['id']

    @staticmethod
    def identity(path):
        info = path.stat()
        return info.st_dev, info.st_ino

    def assert_no_legacy_or_dns(self):
        for call in self.legacy + [self.dns]:
            call.assert_not_called()

    def assert_unverified(self, status):
        for flag in UNVERIFIED:
            self.assertIs(status[flag], False, flag)

    def assert_redacted(self, *records):
        serial = json.dumps(records, ensure_ascii=False)
        for value in (SECRET, UNSELECTED, ENDPOINT, SNI, RECEIPT_TOKEN):
            self.assertNotIn(value, serial)

    def validate(self, request, known=()):
        return oneclick.validated_request(request, known, host_cpu=8, host_memory=32)


class ValidationAndStartTests(Fixture):
    def test_validation_normalizes_defaults_but_requires_fresh_name_and_literal_consent(self):
        request = payload()
        self.assertEqual(self.validate(request), dict(request, mode='preinstall', source_vm=None,
            source_identity=None, cpu=2, memory_gib=4, disk_gib=50, ipsw='reviewed', download_loopback_proxy=None))
        for key in ACKS:
            for invalid in (None, False, 1, 'true'):
                with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(
                        oneclick.OneClickError, 'explicit-preinstall-consent-required'):
                    self.validate(dict(request, **{key: invalid}))
            with self.assertRaisesRegex(oneclick.OneClickError, 'explicit-preinstall-consent-required'):
                self.validate({k: v for k, v in request.items() if k != key})
        with self.assertRaisesRegex(oneclick.OneClickError, 'fresh-name-required'):
            self.validate(request, {NAME.swapcase()})
        for invalid in ('../other', '-flag', ' trailing ', 'e\u0301'):
            with self.subTest(name=invalid), self.assertRaises(ValueError):
                self.validate(dict(request, name=invalid))
        for key in ('mode', 'source_vm', 'source_identity', 'confirm_name', 'acknowledge_erase',
                    'setup_profile', 'private_config', 'allow_resolve', 'start_after_install'):
            with self.subTest(key=key), self.assertRaisesRegex(oneclick.OneClickError, 'invalid-preinstall-request'):
                self.validate(dict(request, **{key: True}))

    def test_sizes_opaque_vpn_id_and_explicit_download_proxy_are_strict(self):
        for key, values in (('cpu', (True, 1, 9)), ('memory_gib', ('4', 3, 33)), ('disk_gib', (50.0, 49, 1025))):
            for invalid in values:
                with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(
                        oneclick.OneClickError, 'invalid-resource-size'):
                    self.validate(payload(**{key: invalid}))
        for invalid in (None, True, 'A' * 32, 'a' * 31, '../' + 'a' * 32):
            with self.subTest(id=invalid), self.assertRaisesRegex(
                    oneclick.OneClickError, 'validated-vpn-configuration-required'):
                self.validate(payload(invalid))
        for invalid in ('http://localhost:7890', 'https://127.0.0.1:7890', 'http://127.0.0.1:0',
                        'http://127.0.0.1:65536', 'http://127.0.0.1:7890/', 'http://user@127.0.0.1:7890'):
            with self.subTest(proxy=invalid), self.assertRaisesRegex(
                    oneclick.OneClickError, 'invalid-explicit-download-proxy'):
                self.validate(payload(download_loopback_proxy=invalid))
        self.assertEqual(self.validate(payload(download_loopback_proxy='http://127.0.0.1:65535'))[
            'download_loopback_proxy'], 'http://127.0.0.1:65535')

    def test_local_ipsw_must_be_a_nonempty_unaliased_fixture_file(self):
        image = self.root / 'trusted.ipsw'
        image.write_bytes(b'inert restore material')
        self.assertEqual(self.validate(payload(ipsw=str(image)))['ipsw'], str(image))
        alias = self.root / 'alias.ipsw'
        alias.symlink_to(image)
        empty = self.root / 'empty.ipsw'
        empty.touch()
        linked = self.root / 'linked.ipsw'
        os.link(image, linked)
        for invalid in ('latest', 'relative.ipsw', str(alias), str(empty), str(linked)):
            with self.subTest(ipsw=invalid), self.assertRaises((ValueError, OSError)):
                self.validate(payload(ipsw=invalid))

    def test_start_claims_only_chosen_configuration_and_hands_off_lock(self):
        selected = self.submission()
        other = self.submission(UNSELECTED)
        self.keep_worker_lock = True
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://invalid.invalid', 'DYLD_INSERT_LIBRARIES': SECRET}):
            queued = self.start(payload(selected))
        self.assertEqual(queued, self.job())
        self.assertEqual(queued, registry.read_private(self.jobdir() / 'status.json'))
        self.assertEqual(queued['mode'], 'preinstall')
        self.assertIsNone(queued['stage_path'])
        self.assertIsNone(queued['source_vm'])
        self.assertIs(queued['user_vpn_configuration_supplied'], True)
        for flag in ('system_restored', 'applications_preinstalled', 'vpn_configuration_staged', 'published'):
            self.assertIs(queued[flag], False)
        self.assert_unverified(queued)
        request = registry.read_private(self.jobdir() / 'request.json')
        self.assertEqual(request['vpn_configuration_id'], selected)
        self.assertIsNone(request['source_identity'])
        self.assert_redacted(queued, request, self.spawn.call_args[0][0])
        self.assertIsNone(vpn_store.load_configuration(self.state, other).bound_job)
        for name in ('status.json', 'request.json', 'worker.log'):
            self.assertEqual(stat.S_IMODE((self.jobdir() / name).stat().st_mode), 0o600)
        self.spawn.assert_called_once()
        self.assertFalse(self.target.exists())
        self.assertFalse((self.tart_home / '.gold-manager-staging').exists())
        contender = os.open(str(self.state / 'build.lock'), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.release_worker_lock()
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)
        self.assert_no_legacy_or_dns()

    def test_missing_capability_or_casefold_collision_never_claims_or_spawns(self):
        ident = self.submission()
        self.caps.return_value = {'ready': False}
        with self.assertRaisesRegex(oneclick.OneClickError, 'preinstall-capabilities-unavailable'):
            self.start(payload(ident))
        self.caps.return_value = {'ready': True}
        for existing in ('registry', 'disk'):
            with self.subTest(existing=existing):
                if existing == 'registry':
                    registry.write_private(self.state / 'registry.json', {'version': 1,
                        'vms': {NAME.swapcase(): {'environment_id': 'a' * 32}}, 'retired': []})
                else:
                    registry.write_private(self.state / 'registry.json', {'version': 1, 'vms': {}, 'retired': []})
                    (self.vms / NAME.swapcase()).mkdir(mode=0o700)
                with self.assertRaisesRegex(oneclick.OneClickError, 'fresh-name-required'):
                    self.start(payload(ident))
                self.assertIsNone(vpn_store.load_configuration(self.state, ident).bound_job)
                self.assertIsNone(self.job())
        self.spawn.assert_not_called()

    def test_owned_standard_tart_roots_are_accepted_without_chmod(self):
        self.tart_home.chmod(0o755)
        self.vms.chmod(0o755)
        queued = self.start(payload(self.submission()))
        self.assertEqual(queued['phase'], 'queued')
        for path in (self.tart_home, self.vms):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
        self.spawn.assert_called_once()

    def test_normalized_ticket_needs_extra_literal_consent_before_claim(self):
        ident = self.submission(name='Fixture custom label')
        stored = vpn_store.load_configuration(self.state, ident)
        self.assertIs(stored.summary['normalization_required'], True)
        for request in (payload(ident), *(payload(ident, acknowledge_normalization=value)
                                          for value in (False, 1, 'true'))):
            with self.assertRaises(ValueError):
                self.start(request)
            self.assertIsNone(vpn_store.load_configuration(self.state, ident).bound_job)
        self.spawn.assert_not_called()
        accepted = self.start(payload(ident, acknowledge_normalization=True))
        self.assertEqual(vpn_store.load_configuration(self.state, ident, job_id=accepted['id']).bound_job, accepted['id'])
        self.spawn.assert_called_once()

    def test_unknown_id_is_not_replaced_by_any_other_valid_configuration(self):
        other = self.submission(UNSELECTED)
        with self.assertRaises(ValueError):
            self.start(payload('b' * 32))
        self.assertIsNone(vpn_store.load_configuration(self.state, other).bound_job)
        self.assertIsNone(self.job())
        self.spawn.assert_not_called()

    def test_worker_spawn_failure_keeps_single_job_binding_and_does_not_retry(self):
        ident = self.submission()
        self.spawn.side_effect = OSError(SECRET)
        with self.assertRaisesRegex(oneclick.OneClickError, 'worker-start-failed'):
            self.start(payload(ident))
        failed = self.job()
        self.assertEqual(failed['phase'], 'failed')
        self.assertEqual(vpn_store.load_configuration(self.state, ident, job_id=failed['id']).bound_job, failed['id'])
        with self.assertRaises(ValueError):
            self.start(dict(payload(ident), name='Another fixture'))
        self.assertEqual(self.job(), failed)
        self.assertEqual(registry.read_private(self.jobdir() / 'status.json'), failed)
        self.assert_redacted(failed, (self.jobdir() / 'worker.log').read_text(encoding='utf-8'))
        self.spawn.assert_called_once()
        self.assertFalse(self.target.exists())


class WorkerTests(Fixture):
    def setUp(self):
        super().setUp()
        self.selected = self.submission()
        self.other = self.submission(UNSELECTED)
        self.keep_worker_lock = True
        self.restore_source = self.fixture_file('local.ipsw', b'explicit local fixture')
        self.proxy = 'http://127.0.0.1:17890'
        self.queued = self.start(payload(self.selected, ipsw=str(self.restore_source),
                                         download_loopback_proxy=self.proxy))
        self.context = oneclick.Context(self.state, self.tart_home, self.queued['id'], self.worker_fd)
        self.journal_path = self.context.jobdir / 'commit.json'
        self.trace = []
        self.config_locked = None
        self.config_before = None
        self.install_events = [{'percent': 50}, {'event': 'complete', 'schemaVersion': 1}]
        self.restore_version = {'macOSVersion': '26.6.2', 'buildVersion': '25G83'}
        self.completed_version = dict(self.restore_version)
        self.inspection = dict(self.restore_version, schemaVersion=1, event='inspect', supported=True,
                               minimumCPUCount=2, minimumMemorySize=4 * GIB)
        self.installer = self.fixture_file('installer.fixture', b'not executable')
        self.tart = self.fixture_file('tart.fixture', b'not a program', mode=0o700)
        self.backend = self.fixture_file('gvproxy.fixture', b'not a backend')
        self.image = self.fixture_file('pinned.ipsw.fixture', b'not a restore image')
        self.tools = SimpleNamespace(executable_path=self.tart, executable_sha256='1' * 64,
                                     receipt_path=self.root / 'tart-receipt.fixture')
        self.tart_archive = SimpleNamespace(artifact_path=self.root / 'tart-archive.fixture')
        self.resolve_helpers = self.patch(host_tools, 'resolve_helpers', return_value=self.installer)
        self.ensure_tart = self.patch(host_tools, 'ensure_tart', return_value=self.tools)
        self.podman_package = SimpleNamespace(artifact_path=self.root / 'podman-installer.fixture')
        self.ensure_gvproxy = self.patch(host_tools, 'ensure_gvproxy',
                                         return_value=SimpleNamespace(executable_path=self.backend))
        self.acquire = self.patch(host_artifacts, 'acquire', side_effect=self.acquire_fixture)
        image_info = self.image.stat()
        self.image_receipt = SimpleNamespace(artifact_path=self.image, device=image_info.st_dev,
            inode=image_info.st_ino, size_bytes=image_info.st_size, mtime_ns=image_info.st_mtime_ns,
            digest_verified=True, quarantine_ensured=True)
        self.import_local = self.patch(host_artifacts, 'import_local', return_value=self.image_receipt)
        self.materials = object()
        self.material_manager = self.patch(preinstall_materials, 'MaterialManager')
        self.material_manager.return_value.prepare.return_value = self.materials
        # No verified cache by default: every fixture job downloads fresh materials.
        self.material_manager.return_value.load_reusable.side_effect = \
            preinstall_materials.MaterialPreparationError('material-cache-miss')
        self.installers = self.patch(oneclick, 'build_installers', side_effect=self.installers_fixture)
        self.patch(preinstall_runtime, '_verified_backend', side_effect=self.verify_inert_backend)
        self.patch(preinstall_runtime, '_quarantine', return_value=b'0083;0;Fixture;package-origin')
        self.patch(preinstall_runtime, '_preserve_quarantine')  # Simulated xattr; never invoke native tools.
        self.runtime_prepare = self.patch(preinstall_runtime, 'prepare_environment', wraps=preinstall_runtime.prepare_environment)
        self.published_readback = self.patch(preinstall_runtime, 'validate_environment',
                                             side_effect=self.verify_published_environment)
        self.rename = mock.Mock(side_effect=self.rename_fixture)
        self.patch(oneclick.ctypes, 'CDLL', return_value=SimpleNamespace(renameatx_np=self.rename))
        self.detached = self.patch(oneclick, '_require_detached')
        self.disk_usage = self.patch(shutil, 'disk_usage', return_value=SimpleNamespace(free=100 * GIB))
        self.run.reset_mock(side_effect=True)
        self.run.side_effect = self.inspect_fixture
        self.spawn.reset_mock(side_effect=True)
        self.spawn.side_effect = self.create_fixture
        self.write = registry.write_private
        self.write_hook = lambda path, data: self.write(path, data)
        self.patch(registry, 'write_private', side_effect=self.record_write)

    def fixture_file(self, name, content, mode=0o600):
        p = self.root / name
        p.write_bytes(content)
        p.chmod(mode)
        return p

    def record_write(self, path, data):
        if path == self.state / 'build-current.json':
            self.trace.append(('status', data['phase']))
        if path == self.journal_path:
            self.trace.append(('journal', data['phase']))
        self.write_hook(path, data)

    def acquire_fixture(self, key, cache, *, loopback_proxy, progress):
        self.assertEqual(cache, self.state / 'host-materials')
        self.assertEqual(loopback_proxy, self.proxy)
        progress(SimpleNamespace(spec_key=key, completed_bytes=1, total_bytes=2))
        return {'tart': self.tart_archive, 'podman-installer': self.podman_package}[key]

    def inspect_fixture(self, command, **kwargs):
        if command == ['/usr/sbin/sysctl', '-n', 'hw.memsize']:
            return self.host_query(command, **kwargs)
        self.assertEqual(command, [str(self.installer), '--inspect', '--ipsw', str(self.image)])
        self.assert_clean_env(kwargs['env'])
        self.trace.append(('installer', 'inspect'))
        return SimpleNamespace(returncode=0, stdout='installer progress\n' + json.dumps(self.inspection), stderr='')

    def create_fixture(self, command, **kwargs):
        c = self.context
        self.assertEqual(command, [str(self.installer), '--create', '--directory', str(c.stage),
            '--ipsw', str(self.image), '--cpu', '2', '--memory-gib', '4', '--disk-gib', '50'])
        self.assertEqual(kwargs['pass_fds'], (c.lock_fd,))
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(Path(kwargs['stderr'].name), c.jobdir / 'installer.log')
        self.assert_clean_env(kwargs['env'])
        self.trace.append(('installer', 'create'))
        self.assertEqual(c.stage.resolve(strict=True), self.tart_home / '.gold-manager-staging' / c.job_id / 'new-environment')
        # Sparse metadata-only extent for verify_install_output's exact size check, not a usable image.
        with (c.stage / 'disk.img').open('xb') as stream:
            stream.write(b'fixture-only, cannot mount')
            stream.truncate(50 * GIB)
        (c.stage / 'nvram.bin').write_bytes(b'fixture-only NVRAM')
        registry.write_private(c.stage / 'config.json', {'os': 'darwin', 'arch': 'arm64', 'diskFormat': 'raw',
            'version': 1, 'cpuCountMin': 2, 'cpuCount': 2, 'memorySizeMin': 4 * GIB, 'memorySize': 4 * GIB,
            'display': {'unit': 'px', 'width': 1024, 'height': 768},
            'ecid': 'Zml4dHVyZS1lY2lk', 'hardwareModel': 'Zml4dHVyZS1tb2RlbA==', 'macAddress': '02:aa:bb:cc:dd:ee'})
        registry.write_private(c.stage / '.clean-vm-installer.complete.json', dict(self.completed_version,
            status='complete', schemaVersion=1, installer='CleanVMInstaller', networkDeviceCount=0,
            directorySharingDeviceCount=0, socketDeviceCount=0))
        self.config_before = self.identity(c.stage / 'config.json')
        return SimpleNamespace(stdout=iter(['unstructured log\n'] + [json.dumps(e) for e in self.install_events]),
                               wait=mock.Mock(return_value=0))

    def installers_fixture(self, target, materials, private_config):
        c = self.context
        self.assertEqual(target, c.jobdir / 'installers')
        self.assertIs(materials, self.materials)
        selected = vpn_store.load_configuration(self.state, self.selected, job_id=c.job_id)
        self.assertEqual(selected.bound_job, c.job_id)
        self.assertEqual(private_config, selected.private_config)
        self.assertEqual(self.job()['phase'], 'preparing_runtime')
        self.assertIs(self.job()['system_restored'], True)
        self.trace.append(('installers', 'built'))
        target.mkdir(mode=0o700)
        (target / 'inert.fixture').write_bytes(b'inert fixture; not an app')
        target.chmod(0o755)
        return target

    def verify_inert_backend(self, path):
        self.assertIn(path, (self.backend, self.context.base / 'gvproxy-darwin'))
        data, info = preinstall_runtime._read(path, private=False, cap=1024)
        self.assertEqual(data, b'not a backend')
        return data, info

    def verify_published_environment(self, *args, **kwargs):
        self.trace.append(('readback', 'environment'))
        self.assertIsNone(self.config_locked, 'do not reopen/close the same inode under a POSIX lock')
        self.assertEqual(self.identity(self.target / 'config.json'), self.config_before)
        return ORIGINAL_RUNTIME_VALIDATION(*args, **kwargs)

    def check_rename_call(self, src, source, dst, destination, flags):
        self.assertEqual((source, destination, flags), (b'new-environment', os.fsencode(NAME), 4))  # RENAME_EXCL.
        self.assertEqual((os.fstat(src).st_dev, os.fstat(src).st_ino), self.identity(self.context.stage.parent))
        self.assertEqual((os.fstat(dst).st_dev, os.fstat(dst).st_ino), self.identity(self.vms))
        self.assertIsNotNone(self.config_locked)
        self.assertEqual(registry.read_private(self.journal_path)['phase'], 'before_publish')

    def rename_fixture(self, src, source, dst, destination, flags):
        self.check_rename_call(src, source, dst, destination, flags)
        stage = self.context.stage
        self.assertEqual(stage.resolve(strict=True), self.tart_home / '.gold-manager-staging' / self.context.job_id / 'new-environment')
        self.assertEqual(self.target.resolve(strict=False), self.root / 'home' / '.tart' / 'vms' / NAME)
        self.assertFalse(os.path.lexists(self.target))
        os.rename(str(stage), str(self.target))  # Verified, absent scratch destination only.
        return 0

    def execute(self):
        # A POSIX lock belongs to the process, not the FD. Closing any FD for
        # the same inode releases it, even if the original lock FD stays open.
        c = self.context
        real_lock, real_close = fcntl.lockf, os.close
        configs = (c.stage / 'config.json', self.target / 'config.json')

        def fd_identity(fd):
            info = os.fstat(fd)
            return info.st_dev, info.st_ino

        def track_lock(fd, operation, *args):
            result = real_lock(fd, operation, *args)
            if fd_identity(fd) == self.config_before:
                if operation & fcntl.LOCK_EX:
                    self.assertIsNone(self.config_locked)
                    self.config_locked = fd
                elif operation == fcntl.LOCK_UN:
                    self.config_locked = None
            return result

        def checked_open(opener):
            def call(path, *args, **kwargs):
                if self.config_locked is not None and not isinstance(path, int):
                    opened = Path(os.fsdecode(path))
                    self.assertNotIn(opened, configs)
                    if kwargs.get('dir_fd') is not None and opened == Path('config.json'):
                        parents = [self.identity(p.parent) for p in configs if p.parent.exists()]
                        self.assertNotIn(fd_identity(kwargs['dir_fd']), parents)
                return opener(path, *args, **kwargs)
            return call

        def track_close(fd):
            if fd == self.config_locked:
                self.config_locked = None
            elif self.config_locked is not None:
                self.assertNotEqual(fd_identity(fd), self.config_before)
            real_close(fd)

        with ExitStack() as watchers:
            watchers.enter_context(mock.patch.object(fcntl, 'lockf', side_effect=track_lock))
            watchers.enter_context(mock.patch.object(os, 'close', side_effect=track_close))
            for module in (os, builtins, io):
                watchers.enter_context(mock.patch.object(module, 'open', side_effect=checked_open(module.open)))
            return oneclick.execute(c)

    def assert_failed(self, status, phase, code, *, recovery):
        self.assertEqual((status['phase'], status['failed_phase'], status['failure_code']), ('failed', phase, code))
        self.assertIs(status['recovery_required'], recovery)
        self.assertIs(status['published'], False)
        self.assert_unverified(status)
        self.assertEqual(status, self.job())
        self.assertEqual(status, registry.read_private(self.context.jobdir / 'status.json'))
        self.assert_redacted(status)
        self.assert_no_legacy_or_dns()

    def test_worker_consumes_only_its_config_then_journals_verified_publication_without_boot(self):
        old = self.vms / 'Unrelated fixture'
        old.mkdir(mode=0o700)
        old_config = old / 'config.json'
        registry.write_private(old_config, {'ecid': 'b2xk', 'macAddress': '02:00:00:00:00:11'})
        old_bytes = old_config.read_bytes()
        old_inode = self.identity(old_config)
        old_environment = {'environment_id': 'b' * 32}
        old_shares = {'shares': [{'name': 'old-share-fixture'}]}
        registry.write_private(self.state / 'registry.json', {'version': 1,
            'vms': {old.name: old_environment}, 'retired': ['retired fixture']})
        registry.write_private(self.state / 'config.json', {'version': 1, 'vms': {old.name: old_shares}})
        status = self.execute()
        self.assertEqual(status['phase'], 'awaiting_first_desktop_acceptance', status)
        self.assertEqual(status['published_path'], str(self.target))
        self.assertIsNone(status['stage_path'])
        for flag in ('system_restored', 'user_vpn_configuration_supplied', 'published', 'needs_host_security_authorization'):
            self.assertIs(status[flag], True, flag)
        # Nothing is written into the guest disk any more.
        for flag in ('applications_preinstalled', 'vpn_configuration_staged'):
            self.assertIs(status[flag], False, flag)
        self.assert_unverified(status)
        self.assertEqual(status, self.job())
        self.assertEqual(status, registry.read_private(self.context.jobdir / 'status.json'))
        self.assert_redacted(status)
        self.assertEqual(self.trace.count(('installers', 'built')), 1)
        # Only gvproxy, from Podman's notarized installer; never the bare release binary.
        self.assertIn('podman-installer', [c.args[0] for c in self.acquire.call_args_list])
        self.ensure_gvproxy.assert_called_once_with(self.state / 'tools', artifact_receipt=self.podman_package)
        self.assertEqual(self.runtime_prepare.call_args.kwargs['gvproxy_path'], self.backend)
        self.assertLess(self.trace.index(('installer', 'inspect')), self.trace.index(('installer', 'create')))
        self.assertLess(self.trace.index(('installer', 'create')), self.trace.index(('installers', 'built')))
        self.assertLess(self.trace.index(('installers', 'built')), self.trace.index(('status', 'publishing')))
        self.assertNotIn(('status', 'awaiting_system_authorization'), self.trace)
        self.assertEqual(self.runtime_prepare.call_args.kwargs['installers'], self.context.jobdir / 'installers')
        meta = preinstall_runtime.validate_environment(self.context.base)
        self.assertEqual(meta['version'], 3)
        self.assertEqual((self.context.base / 'installers' / 'inert.fixture').read_bytes(), b'inert fixture; not an app')
        self.assertFalse((self.context.jobdir / 'installers').exists())
        for name in ('.offline-preinstall.complete.json', '.offline-vpn.complete.json', '.guest-ownership'):
            self.assertFalse((self.target / name).exists(), name)
        self.assertLess(self.trace.index(('readback', 'environment')), self.trace.index(('journal', 'committed_new_registered')))
        self.assertEqual(registry.read_private(self.journal_path)['phase'], 'committed_new_registered')
        self.assertEqual(lifecycle.status(state_dir=self.state), status)
        self.detached.assert_any_call(self.context.stage / 'disk.img')
        self.assertEqual(registry.load_registry(self.state / 'registry.json'), {'version': 1,
            'vms': {old.name: old_environment, NAME: {'environment_id': self.context.job_id}}, 'retired': ['retired fixture']})
        self.assertEqual(registry.read_private(self.state / 'config.json'), {'version': 1,
            'vms': {old.name: old_shares, NAME: {'shares': []}}})
        self.assertEqual(self.identity(old_config), old_inode)
        self.assertEqual(old_config.read_bytes(), old_bytes)
        self.assertEqual(self.identity(self.target / 'config.json'), self.config_before)
        self.assertFalse(self.context.stage.exists())
        self.assertFalse((self.context.base / 'setup').exists())
        self.assertFalse((self.target / 'state.vzvmsave').exists())
        self.assertIsNone(vpn_store.load_configuration(self.state, self.other).bound_job)
        self.assertEqual(self.import_local.call_args[0], ('ipsw', self.restore_source, self.state / 'host-materials'))
        self.assertNotIn('loopback_proxy', self.import_local.call_args[1])
        self.material_manager.assert_called_once_with(self.state / 'application-materials', loopback_proxy=self.proxy,
                                                      progress=mock.ANY)
        self.material_manager.return_value.load_reusable.assert_called_once_with()
        self.material_manager.return_value.prepare.assert_called_once_with()
        self.assertEqual(status['materials_source'], 'downloaded')
        self.assertEqual(self.runtime_prepare.call_args[1]['endpoints'], (('tcp', ENDPOINT, 443),))
        self.spawn.assert_called_once()  # Only the mocked isolated restore, no Tart/backend/boot.
        self.rename.assert_called_once()
        self.assert_no_legacy_or_dns()

    def assert_reject_unavailable_ticket(self):
        request_path = self.context.jobdir / 'request.json'
        request = registry.read_private(request_path)
        registry.write_private(request_path, dict(request, vpn_configuration_id=self.other))
        # The display-only store message never crosses; its class maps to a fixed category.
        self.assert_failed(self.execute(), 'queued', 'vpn-configuration-unavailable', recovery=False)
        self.acquire.assert_not_called()
        self.spawn.assert_not_called()
        self.rename.assert_not_called()

    def test_worker_refuses_unclaimed_vpn_configuration(self):
        self.assert_reject_unavailable_ticket()
        self.assertIsNone(vpn_store.load_configuration(self.state, self.other).bound_job)

    def test_worker_cannot_borrow_another_jobs_vpn_configuration(self):
        vpn_store.claim_configuration(self.state, self.other, 'b' * 32)
        self.assert_reject_unavailable_ticket()
        self.assertEqual(vpn_store.load_configuration(self.state, self.other, job_id='b' * 32).bound_job, 'b' * 32)

    def test_worker_refuses_different_lock_inode_before_any_acquisition(self):
        alien = self.fixture_file('wrong.lock', b'')
        with alien.open('r+b') as lock, self.assertRaisesRegex(oneclick.OneClickError, 'lifecycle-lock-identity-mismatch'):
            oneclick.execute(oneclick.Context(self.state, self.tart_home, self.queued['id'], lock.fileno()))
        self.acquire.assert_not_called()
        self.spawn.assert_not_called()
        self.assertEqual(self.job(), self.queued)

    def test_insufficient_staging_space_stops_before_acquiring_materials(self):
        self.disk_usage.return_value = SimpleNamespace(free=81 * GIB)
        self.assert_failed(self.execute(), 'preflight', 'insufficient-safe-staging-space', recovery=False)
        self.resolve_helpers.assert_not_called()
        self.acquire.assert_not_called()
        self.spawn.assert_not_called()
        self.assertFalse(self.context.stage.exists())

    def test_acquisition_failure_records_phase_without_leaking_native_error(self):
        self.acquire.side_effect = RuntimeError(SECRET)
        self.assert_failed(self.execute(), 'acquiring', 'preinstall-step-failed', recovery=False)
        self.assertFalse(self.context.stage.exists())
        self.spawn.assert_not_called()
        self.installers.assert_not_called()
        self.rename.assert_not_called()

    def test_image_minimum_failure_never_creates_stage(self):
        self.inspection['minimumMemorySize'] = 8 * GIB
        self.assert_failed(self.execute(), 'inspecting', 'selected-resources-below-image-minimum', recovery=False)
        self.assertFalse(self.context.stage.exists())
        self.spawn.assert_not_called()
        self.installers.assert_not_called()
        self.rename.assert_not_called()

    def test_apple_compatibility_does_not_accept_an_unreviewed_build(self):
        self.inspection['buildVersion'] = '25G82'
        self.assert_failed(self.execute(), 'inspecting', 'reviewed-restore-build-mismatch', recovery=False)
        self.assertFalse(self.context.stage.exists())
        self.spawn.assert_not_called()
        self.installers.assert_not_called()
        self.rename.assert_not_called()

    def test_unreviewed_completion_build_does_not_advance_to_installers(self):
        self.completed_version['macOSVersion'] = '26.6.1'
        status = self.execute()
        self.assert_failed(status, 'installing', 'reviewed-restore-build-mismatch', recovery=True)
        self.assertIs(status['system_restored'], False)
        self.assertTrue((self.context.stage / 'disk.img').is_file())
        self.installers.assert_not_called()
        self.rename.assert_not_called()

    def test_incomplete_restore_retains_stage_but_does_not_claim_system_restored(self):
        self.install_events = [{'percent': 100}, {'event': 'complete', 'schemaVersion': True}]
        status = self.execute()
        self.assert_failed(status, 'installing', 'apple-restore-not-complete', recovery=True)
        self.assertIs(status['system_restored'], False)
        self.assertTrue((self.context.stage / 'disk.img').is_file())
        self.assertFalse(self.journal_path.exists())
        self.installers.assert_not_called()
        self.rename.assert_not_called()

    def test_installer_folder_failure_keeps_the_stage_and_never_publishes(self):
        self.installers.side_effect = oneclick.OneClickError('installer-copy-mismatch')
        status = self.execute()
        self.assert_failed(status, 'preparing_runtime', 'installer-copy-mismatch', recovery=True)
        self.assertIs(status['system_restored'], True)
        self.runtime_prepare.assert_not_called()
        self.assertFalse(self.context.base.exists())
        self.assert_rejected_before_rename(status)

    def test_constant_code_in_project_error_args_is_reported(self):
        self.installers.side_effect = preinstall_materials.MaterialPreparationError('modified-source-or-evidence')
        self.assert_failed(self.execute(), 'preparing_runtime', 'modified-source-or-evidence', recovery=True)

    def test_project_error_sentence_maps_to_fixed_class_category(self):
        self.installers.side_effect = quarantine_policy.QuarantineError('Missing or malformed quarantine')
        status = self.execute()
        self.assert_failed(status, 'preparing_runtime', 'quarantine-check-failed', recovery=True)
        self.assertNotIn('malformed', json.dumps(status))

    def test_verified_cached_materials_are_reused_before_any_download(self):
        manager = self.material_manager.return_value
        manager.load_reusable.side_effect = None
        manager.load_reusable.return_value = self.materials
        status = self.execute()
        self.assertEqual(status['phase'], 'awaiting_first_desktop_acceptance', status)
        self.assertEqual(status['materials_source'], 'reused')
        manager.prepare.assert_not_called()

    def test_material_progress_names_the_product_and_mebibytes(self):
        seen = []
        def prepare():
            progress = self.material_manager.call_args.kwargs['progress']
            mib = 1024 ** 2
            for event in ({'attempt_id': 'a' * 32, 'stage': 'downloading', 'product': 'ccbaga',
                           'resume_supported': False, 'completed_bytes': 101 * mib, 'total_bytes': 318 * mib},
                          {'attempt_id': 'a' * 32, 'stage': 'verifying', 'product': 'clashVergeRev',
                           'resume_supported': False},
                          {'stage': 'downloading', 'product': '../' + SECRET, 'completed_bytes': 'x'}):
                progress(event)
                seen.append(self.job())
            return self.materials
        self.material_manager.return_value.prepare.side_effect = prepare
        self.execute()
        self.assertIn('正在下载 CCBaga（101/318 MiB）', seen[0]['message'])
        self.assertAlmostEqual(seen[0]['progress'], 101 / 318)
        self.assertIn('Clash Verge', seen[1]['message'])
        self.assertIn('校验', seen[1]['message'])
        self.assertNotIn('ipsw', seen[0]['message'] + seen[1]['message'])
        self.assertNotIn(SECRET, json.dumps(seen))  # Untrusted observer data is never echoed.

    def material_failure(self, product):
        error = preinstall_materials.MaterialPreparationError('download-timeout', 'a' * 32)
        error.product = product
        self.material_manager.return_value.prepare.side_effect = error
        status = self.execute()
        self.assert_failed(status, 'acquiring', 'download-timeout', recovery=False)
        return status

    def test_material_failure_records_the_failed_product(self):
        self.assertEqual(self.material_failure('clashVergeRev')['failed_product'], 'clashVergeRev')

    def test_material_failure_never_records_an_unknown_product(self):
        self.assertIsNone(self.material_failure('../' + SECRET)['failed_product'])

    def test_builtin_exception_text_is_never_a_failure_code(self):
        self.installers.side_effect = ValueError(SECRET)
        self.assert_failed(self.execute(), 'preparing_runtime', 'preinstall-step-failed', recovery=True)

    def test_non_value_error_code_shaped_text_is_ignored(self):
        self.installers.side_effect = RuntimeError('installer-copy-mismatch')
        self.assert_failed(self.execute(), 'preparing_runtime', 'preinstall-step-failed', recovery=True)

    # --- Archiving a failed job: explicit unlock that retains the stage. ---

    def failed_job(self):
        self.installers.side_effect = oneclick.OneClickError('installer-copy-mismatch')
        status = self.execute()
        self.release_worker_lock()
        return status

    def archive(self, **overrides):
        value = dict({'job_id': self.context.job_id, 'confirm_name': NAME}, **overrides)
        return oneclick.archive_failed(value, state_dir=self.state, tart_home=self.tart_home)

    def test_archive_failed_job_unlocks_new_fresh_job(self):
        status = self.failed_job()
        self.assertIs(status['recovery_required'], True)
        disk = self.context.stage / 'disk.img'
        before = disk.stat()
        self.detached.reset_mock()
        result = self.archive()
        self.assertEqual(result, {'ok': True, 'job_id': self.context.job_id, 'name': NAME, 'stage_retained': True})
        self.assertFalse((self.state / 'build-current.json').exists())
        archived = registry.read_private(self.context.jobdir / 'archived-current.json')
        self.assertIsInstance(archived.pop('archived_at'), str)
        self.assertEqual(archived, status)
        after = disk.stat()
        self.assertEqual((after.st_ino, after.st_size), (before.st_ino, before.st_size))
        self.detached.assert_called_once_with(disk)
        self.assertIsNone(lifecycle.status(state_dir=self.state))
        self.spawn.side_effect = self.worker_spawn
        queued = self.start(dict(payload(self.other), name='Second fixture'))
        self.assertEqual((queued['phase'], queued['name']), ('queued', 'Second fixture'))

    def test_archive_rejects_unsafe_jobs_without_changing_records(self):
        status = self.failed_job()
        current_path = self.state / 'build-current.json'
        archived_path = self.context.jobdir / 'archived-current.json'
        journal = self.context.jobdir / 'commit.json'
        now = oneclick._now()
        record_cases = {
            'queued-active': dict(status, phase='queued', pid=None, started_at=now),
            'waiting-for-vpn': dict(status, phase='awaiting_vpn_configuration', recovery_required=False),
            'published': dict(status, published=True),
            'offline-preinstall-active': dict(status, offline_preinstall={'operation_id': '1' * 32, 'active': True}),
            'vpn-configuration-active': dict(status, vpn_configuration={'operation_id': '2' * 32, 'active': True}),
            'other-mode': dict(status, mode='create'),
        }
        for label, record in record_cases.items():
            with self.subTest(label):
                self.write(current_path, record)
                before = current_path.read_bytes()
                with self.assertRaises(oneclick.OneClickError):
                    self.archive()
                self.assertEqual(current_path.read_bytes(), before)
                self.assertFalse(archived_path.exists())
        self.write(current_path, status)
        before = current_path.read_bytes()
        payload_cases = {
            'wrong-name': {'confirm_name': 'Fresh fixture '},
            'wrong-job': {'job_id': 'c' * 32},
            'extra-field': {'force': True},
        }
        for label, change in payload_cases.items():
            with self.subTest(label):
                with self.assertRaises(oneclick.OneClickError):
                    self.archive(**change)
                self.assertEqual(current_path.read_bytes(), before)
        for value in (None, [], {'job_id': self.context.job_id}):
            with self.subTest(payload=value), self.assertRaises(oneclick.OneClickError):
                oneclick.archive_failed(value, state_dir=self.state, tart_home=self.tart_home)
        with self.subTest('commit-journal'):
            self.write(journal, {'version': 1, 'id': self.context.job_id, 'phase': 'before_publish'})
            with self.assertRaises(oneclick.OneClickError):
                self.archive()
            journal.unlink()
        with self.subTest('still-attached'):
            self.detached.side_effect = oneclick.OneClickError('publication-disk-still-attached')
            with self.assertRaises(oneclick.OneClickError):
                self.archive()
            self.detached.side_effect = None
        self.assertEqual(current_path.read_bytes(), before)
        self.assertFalse(archived_path.exists())
        self.assertTrue((self.context.stage / 'disk.img').is_file())

    def test_archive_requires_the_lifecycle_lock(self):
        self.installers.side_effect = oneclick.OneClickError('installer-copy-mismatch')
        self.execute()  # The fixture worker still holds build.lock.
        with self.assertRaisesRegex(oneclick.OneClickError, 'lifecycle-lock-busy'):
            self.archive()
        self.assertTrue((self.state / 'build-current.json').exists())

    def assert_rejected_before_rename(self, result):
        self.assertEqual(result['phase'], 'failed', result)
        self.assertIs(result['published'], False)
        self.assertIs(result['recovery_required'], True)
        self.assert_unverified(result)
        self.assertTrue(self.context.stage.is_dir())
        self.assertFalse(self.target.exists())
        self.assertFalse(self.journal_path.exists())
        self.rename.assert_not_called()

    def test_a_started_stage_is_never_published(self):
        build = self.installers.side_effect
        def started(*args):
            (self.context.stage / 'state.vzvmsave').write_bytes(b'inert saved-state fixture')
            return build(*args)
        self.installers.side_effect = started
        status = self.execute()
        self.assert_failed(status, 'publishing', 'previously-started-stage', recovery=True)
        self.assert_rejected_before_rename(status)

    def test_the_authorization_pause_no_longer_exists(self):
        self.assertFalse(hasattr(oneclick, 'authorization_decision'))
        self.assertFalse(hasattr(oneclick.NativeServices, 'preinstall'))
        self.assertFalse(hasattr(oneclick.NativeServices, 'configure'))

    def test_completion_build_is_rechecked_before_exclusive_publication(self):
        build = self.installers.side_effect
        def changed_receipt(*args):
            result = build(*args)
            path = self.context.stage / '.clean-vm-installer.complete.json'
            receipt = registry.read_private(path)
            self.write(path, dict(receipt, buildVersion='25G82'))
            return result
        self.installers.side_effect = changed_receipt
        status = self.execute()
        self.assert_failed(status, 'publishing', 'reviewed-restore-build-mismatch', recovery=True)
        self.assert_rejected_before_rename(status)

    def test_detach_gate_refuses_publication_and_keeps_stage(self):
        self.detached.side_effect = oneclick.OneClickError('fixture-image-still-attached')
        status = self.execute()
        self.assert_rejected_before_rename(status)
        self.assertEqual(status['failure_code'], 'fixture-image-still-attached')

    def test_config_changed_after_staged_manifest_validation_cannot_be_published(self):
        validate = preinstall_runtime._validate_environment
        config = self.context.stage / 'config.json'

        def change_after_read(*args, **kwargs):
            value = validate(*args, **kwargs)
            if kwargs.get('staged_vm_config') == config and self.job()['phase'] == 'publishing':
                with config.open('ab') as stream:
                    stream.write(b' ')  # Same inode and semantics, different pinned bytes.
            return value

        with mock.patch.object(preinstall_runtime, '_validate_environment', side_effect=change_after_read):
            self.assert_rejected_before_rename(self.execute())

    def test_duplicate_mac_even_with_different_ecid_cannot_be_published(self):
        old = self.vms / 'Unrelated fixture'
        old.mkdir(mode=0o700)
        old_config = old / 'config.json'
        registry.write_private(old_config, {'ecid': 'b2xk', 'macAddress': '02:AA:BB:CC:DD:EE'})
        before = old_config.read_bytes()
        self.assert_rejected_before_rename(self.execute())
        self.assertEqual(old_config.read_bytes(), before)
        self.installers.assert_not_called()

    def test_same_name_racing_exclusive_rename_retains_both_inodes_without_registration(self):
        def race(src, source, dst, dest, flags):
            self.check_rename_call(src, source, dst, dest, flags)
            self.target.mkdir(mode=0o700)  # An empty dir plain rename could replace.
            self.racing_target = self.identity(self.target)
            oneclick.ctypes.set_errno(errno.EEXIST)
            return -1

        self.rename.side_effect = race
        status = self.execute()
        self.assert_failed(status, 'publishing', 'exclusive-publication-rename-failed', recovery=True)
        self.rename.assert_called_once()
        self.assertEqual(self.identity(self.target), self.racing_target)
        self.assertEqual(list(self.target.iterdir()), [])
        self.assertEqual(self.identity(self.context.stage / 'config.json'), self.config_before)
        self.assertEqual(registry.read_private(self.journal_path)['phase'], 'before_publish')
        self.assertFalse((self.state / 'registry.json').exists())
        self.assertFalse((self.state / 'config.json').exists())
        self.release_worker_lock()
        with self.assertRaises(ValueError):
            self.start(dict(payload(self.other), name='Retry with different name'))
        self.assertIsNone(vpn_store.load_configuration(self.state, self.other).bound_job)
        self.assertEqual(self.job(), status)
        self.spawn.assert_called_once()

    def test_postrename_runtime_readback_failure_leaves_journal_incomplete(self):
        self.published_readback.side_effect = preinstall_runtime.RuntimePreparationError('fixture-readback-denied')
        status = self.execute()
        self.assert_failed(status, 'publishing', 'fixture-readback-denied', recovery=True)
        self.assertTrue(self.target.is_dir())
        self.assertFalse(self.context.stage.exists())
        self.assertNotEqual(registry.read_private(self.journal_path)['phase'], 'committed_new_registered')
        self.assertNotIn(('journal', 'committed_new_registered'), self.trace)

    def assert_unpersisted_index_blocks_commit(self, name):
        self.write_hook = lambda path, value: None if path == self.state / name else self.write(path, value)
        status = self.execute()
        self.assertEqual(status['phase'], 'failed', status)
        self.assertEqual(status['failed_phase'], 'publishing')
        self.assertIs(status['recovery_required'], True)
        self.assertIs(status['published'], False)
        self.assertTrue(self.target.is_dir())
        self.assertNotIn(('journal', 'committed_new_registered'), self.trace)

    def test_share_write_that_does_not_stick_cannot_finalize_publication(self):
        self.assert_unpersisted_index_blocks_commit('config.json')

    def test_registry_write_that_does_not_stick_cannot_finalize_publication(self):
        self.assert_unpersisted_index_blocks_commit('registry.json')


ORIGINAL_RUNTIME_VALIDATION = preinstall_runtime.validate_environment


class DeferredWorkerTests(Fixture):
    def pause(self):
        def inherit(command, **kwargs):
            self.worker_fd = os.dup(kwargs['pass_fds'][0])
            return SimpleNamespace(pid=98765)
        self.spawn.side_effect = inherit
        self.addCleanup(self.release_worker_lock)
        with mock.patch.object(vpn_store, 'load_configuration', side_effect=AssertionError('no VPN in deferred start')):
            initial = self.start({'name': NAME, 'defer_vpn': True, 'acknowledge_preinstall': True})
            ctx = oneclick.Context(self.state, self.tart_home, initial['id'], self.worker_fd)
            self.context = ctx
            self.service = mock.Mock()
            self.service.deferred_materials.return_value = {'fixture': 'reviewed'}
            def restore(_, update):
                ctx.stage.mkdir(mode=0o700, parents=True)
                for item in oneclick.STAGE_FILES:
                    (ctx.stage / item).write_bytes(b'inert stage fixture')
            self.service.restore.side_effect = restore
            with mock.patch.object(shutil, 'disk_usage', return_value=SimpleNamespace(free=100*GIB)), \
                 mock.patch.object(oneclick, '_require_detached'):
                result = oneclick.execute(ctx, services=self.service)
        self.release_worker_lock()
        self.assertEqual(result['phase'], oneclick.PAUSE_PHASE, result)
        self.assertIs(result['system_restored'], True)
        self.assertFalse(result['published'] or result['user_vpn_configuration_supplied'] or result['vpn_configuration_staged']
                         or result['applications_preinstalled'])
        self.assert_unverified(result)
        self.assertFalse(self.target.exists())
        self.service.runtime.assert_not_called()
        self.service.publish.assert_not_called()
        self.assertTrue(lifecycle.waiting_for_vpn(lifecycle.status(state_dir=self.state)))
        return result

    def queue_resume(self, ticket, **changes):
        data={'job_id':self.context.job_id,'vpn_configuration_id':ticket,'acknowledge_network_policy':True}
        return oneclick.resume(dict(data,**changes),state_dir=self.state,tart_home=self.tart_home)

    def test_deferral_rejects_implicit_or_mixed_consent(self):
        base = {'name': NAME, 'defer_vpn': True, 'acknowledge_preinstall': True}
        for changes in ({'defer_vpn': 1}, {'acknowledge_preinstall': False},
                        {'vpn_configuration_id': 'a'*32}, {'acknowledge_network_policy': True},
                        {'acknowledge_guest_autoconfigure': True}, {'acknowledge_normalization': True}):
            with self.subTest(changes=changes), self.assertRaises(oneclick.OneClickError):
                self.validate(dict(base, **changes))

    def test_pause_does_not_claim_ticket_or_publish_and_blocks_new_job(self):
        self.pause()
        ticket=self.submission()
        with self.assertRaisesRegex(oneclick.OneClickError,'existing-job'):
            self.start(dict(payload(ticket),name='Another VM'))
        self.assertIsNone(vpn_store.load_configuration(self.state,ticket).bound_job)
        self.assert_no_legacy_or_dns()

    def test_resume_only_same_disk_preserves_original_request_and_does_not_reinstall(self):
        self.pause(); ticket=self.submission()
        original=registry.read_private(self.jobdir()/'request.json')
        stamp=oneclick._stage_stamps(self.context)
        queued=self.queue_resume(ticket)
        self.assertEqual(queued['phase'],oneclick.RESUME_QUEUED)
        self.assertIn('--resume-vpn',self.spawn.call_args.args[0]);self.assertNotIn(ticket,self.spawn.call_args.args[0])
        ctx=oneclick.Context(self.state,self.tart_home,self.context.job_id,self.worker_fd)
        def runtime(d, stored, update):
            self.assertNotIn('defer_vpn',d)
            self.assertEqual(stored.bound_job,ctx.job_id)
            self.assertEqual(oneclick._stage_stamps(ctx),stamp)
            return {'fixture':True}
        self.service.runtime.side_effect=runtime
        self.service.publish.return_value=self.target
        with mock.patch.object(oneclick, '_require_detached'):
            done=oneclick.execute_resume(ctx,services=self.service)
        self.assertTrue(done['published'],done)
        self.assertFalse(done['guest_started'] or done['vpn_connected'])
        self.service.prepare.assert_called_once()
        self.service.restore.assert_called_once()
        self.service.load_deferred_materials.assert_called_once_with({'fixture':'reviewed'})
        self.service.runtime.assert_called_once()
        self.assertEqual(registry.read_private(self.jobdir()/'vpn-wait.json')['request'],original)
        self.assertEqual(registry.read_private(self.jobdir()/'request.json')['vpn_configuration_id'],ticket)
        self.assert_redacted(done)
        self.assert_no_legacy_or_dns()

    def test_wrong_job_missing_consent_or_changed_disk_never_claims_ticket(self):
        self.pause(); ticket=self.submission()
        for changes in ({'job_id':'a'*32},{'acknowledge_network_policy':False},{'acknowledge_guest_autoconfigure':True}):
            with self.assertRaises(oneclick.OneClickError):self.queue_resume(ticket,**changes)
        with (self.context.stage/'disk.img').open('r+b') as f:f.write(b'changed fixture')
        with self.assertRaisesRegex(oneclick.OneClickError,'deferred-stage-changed'):
            self.queue_resume(ticket)
        self.assertIsNone(vpn_store.load_configuration(self.state,ticket).bound_job)
        self.assertFalse((self.jobdir()/'vpn-resume.json').exists())
        self.service.runtime.assert_not_called()

    def test_file_changed_after_queue_fails_without_configuration_or_publish(self):
        self.pause(); ticket=self.submission();self.queue_resume(ticket)
        with (self.context.stage/'disk.img').open('r+b') as f:f.write(b'late change')
        ctx=oneclick.Context(self.state,self.tart_home,self.context.job_id,self.worker_fd)
        done=oneclick.execute_resume(ctx,services=self.service)
        self.assertEqual(done['phase'],'failed')
        self.assertTrue(done['recovery_required'])
        self.service.runtime.assert_not_called()
        self.service.publish.assert_not_called()


class DeferredBackendTests(unittest.TestCase):
    """The deferred-VPN checkpoint binds the extracted, signed gvproxy copy."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-deferred-backend-')).resolve()
        self.addCleanup(shutil.rmtree, str(self.root))
        self.state = self.root / 'state'
        self.tool = 'gvproxy-tool-' + 'a' * 32
        self.path = self.state / 'tools' / self.tool / 'gvproxy'
        self.path.parent.mkdir(mode=0o700, parents=True)
        self.path.write_bytes(b'inert fixture backend')
        self.path.chmod(0o600)
        self.tart = {'version': 1, 'executable_path': str(self.root / 'tart'), 'executable_sha256': '1' * 64,
                     'receipt_path': str(self.root / 'receipt')}
        self.quarantine = b'0083;0;Fixture;package-origin'
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        patch = lambda *a, **k: self.stack.enter_context(mock.patch.object(*a, **k))
        patch(preinstall_runtime, '_quarantine', side_effect=lambda path: self.quarantine)
        patch(preinstall_runtime, '_verified_backend', return_value=(b'', None))
        patch(registry, 'read_private', return_value=self.tart)
        patch(lifecycle, 'inventory_tool', return_value=Path(self.tart['executable_path']))
        patch(host_tools, 'resolve_helpers', return_value=None)
        patch(preinstall_materials, 'MaterialManager')
        self.acquire = patch(host_artifacts, 'acquire', side_effect=AssertionError('no download'))
        self.extract = patch(host_tools, 'ensure_gvproxy', side_effect=AssertionError('no extraction'))
        self.service = oneclick.NativeServices(SimpleNamespace(state=self.state, jobdir=self.root / 'job'))

    def record(self):
        self.service.backend = SimpleNamespace(executable_path=self.path)
        self.service.material_attempt_id = 'materials-fixture'
        return self.service.deferred_materials()

    def test_checkpoint_binds_the_signed_copy_and_its_quarantine(self):
        record = self.record()
        self.assertEqual(record['backend'], self.tool)
        self.service.load_deferred_materials(record)
        self.assertEqual(self.service.backend.executable_path, self.path)
        self.quarantine = b'0083;0;Fixture;changed'
        with self.assertRaisesRegex(oneclick.OneClickError, '^deferred-backend-quarantine-changed$'):
            self.service.load_deferred_materials(record)
        self.quarantine = None
        with self.assertRaisesRegex(oneclick.OneClickError, '^deferred-backend-quarantine-missing$'):
            self.record()
        self.service.backend = SimpleNamespace(executable_path=self.root / 'elsewhere' / 'gvproxy')
        with self.assertRaisesRegex(oneclick.OneClickError, '^backend-path-mismatch$'):
            self.service.deferred_materials()
        self.acquire.assert_not_called()
        self.extract.assert_not_called()

    def test_older_checkpoint_with_the_unnotarized_backend_takes_the_signed_one(self):
        record = dict(self.record(), backend='gvproxy-' + 'b' * 32)  # As written by an older build.
        package, signed = object(), SimpleNamespace(executable_path=self.root / 'signed' / 'gvproxy')
        self.acquire.side_effect, self.acquire.return_value = None, package
        self.extract.side_effect, self.extract.return_value = None, signed
        self.service.load_deferred_materials(record)
        self.acquire.assert_called_once_with('podman-installer', self.state / 'host-materials')
        self.extract.assert_called_once_with(self.state / 'tools', artifact_receipt=package)
        self.assertIs(self.service.backend, signed)
        for bad in ('gvproxy-tool-x', 'other-' + 'a' * 32, 7):
            with self.subTest(bad=bad), self.assertRaisesRegex(oneclick.OneClickError, '^deferred-material-record-mismatch$'):
                self.service.load_deferred_materials(dict(record, backend=bad))


class BuildInstallersTests(unittest.TestCase):
    """The read-only first-setup folder: real APFS clones of inert fixture bundles only."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gold-installers-test-')).resolve()
        self.addCleanup(self.cleanup)
        self.addCleanup(os.umask, os.umask(0o077))
        self.sources = self.root / 'staging'
        self.sources.mkdir(mode=0o700)
        self.apps = []
        for name in ('One.app', 'Two.app'):
            app = self.sources / name
            (app / 'Contents' / 'MacOS').mkdir(parents=True, mode=0o755)
            (app / 'Contents' / 'MacOS' / 'binary').write_bytes(b'inert fixture bytes for ' + name.encode())
            (app / 'Contents' / 'Current').symlink_to('MacOS')
            self.apps.append(app)
        self.materials = (SimpleNamespace(manifest='m1', app_paths=(self.apps[0],)),
                          SimpleNamespace(manifest='m2', app_paths=(self.apps[1],)))
        self.config = {'proxies': [{'name': '节点', 'type': 'trojan', 'server': ENDPOINT, 'password': SECRET}],
                       'rules': ['MATCH,PROXY']}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        patch = lambda *a, **k: self.stack.enter_context(mock.patch.object(*a, **k))
        self.verify = patch(preinstall_materials, 'verify_materials', side_effect=self.verified)
        self.quarantine = {}
        patch(quarantine_policy, 'read', side_effect=lambda path: self.quarantine.get(Path(path).name, b'0083;0;Fixture;origin'))
        self.target = self.root / 'job' / 'installers'
        self.target.parent.mkdir(mode=0o700)

    def cleanup(self):
        self.assertTrue(self.root.name.startswith('gold-installers-test-'))
        shutil.rmtree(str(self.root))

    @staticmethod
    def tree(app):
        records = []
        for folder, dirs, files in os.walk(str(app)):
            for name in sorted(dirs + files):
                path = Path(folder) / name
                info = path.lstat()
                records.append((str(path.relative_to(app)), stat.S_IMODE(info.st_mode),
                                os.readlink(str(path)) if path.is_symlink() else
                                path.read_bytes() if path.is_file() else None))
        return (json.dumps(sorted(records, key=lambda r: r[0]), default=repr), 1, len(records))

    def verified(self, materials):
        self.assertIs(materials, self.materials)
        return tuple(SimpleNamespace(apps=[{'name': app.name, 'bundle_tree_sha256': self.tree(app)[0],
                                             'bundle_bytes': 1, 'bundle_entries': self.tree(app)[2]}])
                     for m in materials for app in m.app_paths)

    def build(self):
        with mock.patch('guest_app_artifacts._tree_snapshot', side_effect=lambda app, manifest: self.tree(app)):
            return oneclick.build_installers(self.target, self.materials, self.config)

    def test_folder_holds_verified_copies_profile_and_note_readable_by_the_guest(self):
        self.assertEqual(self.build(), self.target)
        self.verify.assert_called_once()
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
        self.assertEqual(sorted(p.name for p in self.target.iterdir()),
                         sorted(['One.app', 'Two.app', oneclick.INSTALLERS_PROFILE, oneclick.INSTALLERS_README]))
        for app in self.apps:
            copy = self.target / app.name
            self.assertEqual(self.tree(copy), self.tree(app))
            self.assertTrue((copy / 'Contents' / 'Current').is_symlink())
            self.assertNotEqual(copy.stat().st_ino, app.stat().st_ino)
        profile = self.target / oneclick.INSTALLERS_PROFILE
        self.assertEqual(json.loads(profile.read_text(encoding='utf-8')), self.config)
        self.assertIn('节点', profile.read_text(encoding='utf-8'))  # Readable names, not escapes.
        note = (self.target / oneclick.INSTALLERS_README).read_text(encoding='utf-8')
        for words in ('Finder', '应用程序', '订阅', '本地', '虚拟网卡模式', '标记首次设置完成'):
            self.assertIn(words, note)
        for path in (profile, self.target / oneclick.INSTALLERS_README):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertNotIn(SECRET, note)

    def test_copy_mismatch_or_lost_quarantine_stops(self):
        real = self.verified
        self.verify.side_effect = lambda materials: tuple(
            SimpleNamespace(apps=[dict(app, bundle_tree_sha256='0' * 64) for app in r.apps]) for r in real(materials))
        with self.assertRaisesRegex(oneclick.OneClickError, '^installer-copy-mismatch$'):
            self.build()
        self.assertNotEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)  # Never finished.
        shutil.rmtree(str(self.target))
        self.verify.side_effect = self.verified
        reads = []
        def read(path):
            reads.append(Path(path))
            return b'0083;0;Fixture;origin' if Path(path).parent == self.sources else b'0083;0;Fixture;other'
        with mock.patch.object(quarantine_policy, 'read', side_effect=read), \
                self.assertRaisesRegex(oneclick.OneClickError, '^installer-quarantine-mismatch$'):
            self.build()

    def test_existing_target_and_unvalidated_profile_are_refused(self):
        self.target.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(list(self.target.iterdir()), [])
        self.verify.reset_mock()
        with self.assertRaisesRegex(oneclick.OneClickError, 'validated-private-config-required'):
            oneclick.build_installers(self.root / 'job' / 'other', self.materials, {'rules': []})
        self.verify.assert_not_called()

    def test_ditto_only_where_cloning_is_unavailable(self):
        def unsupported(source, target, flags):
            oneclick.ctypes.set_errno(errno.ENOTSUP)
            return -1
        library = SimpleNamespace(clonefile=unsupported)
        copies = []
        def ditto(command, **kwargs):
            self.assertEqual(command[0], '/usr/bin/ditto')
            copies.append(command[1:])
            shutil.copytree(command[1], command[2], symlinks=True)
            return SimpleNamespace(returncode=0)
        with mock.patch.object(oneclick.ctypes, 'CDLL', return_value=library), \
                mock.patch.object(oneclick.subprocess, 'run', side_effect=ditto):
            self.build()
        self.assertEqual(copies, [[str(app), str(self.target / app.name)] for app in self.apps])
        def denied(source, target, flags):
            oneclick.ctypes.set_errno(errno.EACCES)
            return -1
        shutil.rmtree(str(self.target))
        with mock.patch.object(oneclick.ctypes, 'CDLL', return_value=SimpleNamespace(clonefile=denied)), \
                mock.patch.object(oneclick.subprocess, 'run', side_effect=AssertionError('no fallback')), \
                self.assertRaisesRegex(oneclick.OneClickError, '^installer-copy-failed$'):
            self.build()


class ExclusiveRenameTests(Fixture):
    def test_unavailable_exclusive_rename_does_not_fall_back(self):
        old = self.root / 'new-environment'
        old.mkdir(mode=0o700)
        self.patch(oneclick.ctypes, 'CDLL', return_value=SimpleNamespace())
        fallback = self.patch(os, 'rename', side_effect=AssertionError('Unsafe fallback'))
        with self.assertRaisesRegex(oneclick.OneClickError, 'exclusive-rename-unavailable'):
            oneclick._rename_exclusive(old, self.target)
        fallback.assert_not_called()
        self.assertTrue(old.is_dir())
        self.assertFalse(self.target.exists())


if __name__ == '__main__':
    unittest.main()
