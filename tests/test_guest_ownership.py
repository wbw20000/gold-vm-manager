"""Only own regular-file fixtures and compile-gated metadata simulation.

No authorization dialogs, actual root helper execution, disk images mounted,
VM commands, guest apps, password input, host configs or network. The dummy
'disk.img' is merely a sparse regular file, never formatted or attached.
"""
from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import guest_ownership as ownership

SOURCE = Path(__file__).resolve().parents[1]
JOB = 'a' * 32
OP = 'b' * 32
DATA_UUID = '11111111-2222-4333-8444-555555555555'
GROUP_UUID = '66666666-7777-4888-8999-AAAAAAAAAAAA'
SECRET = 'dummy-fixture-secret-never-real'


def new_root():
    path = Path(tempfile.mkdtemp(prefix='gold-ownership-tests-', dir='/private/tmp'))
    assert path.resolve() == path and path.parent == Path('/private/tmp')
    path.chmod(0o700)
    return path


def cleanup_root(root):
    expected = Path('/private/tmp') / root.name
    if (not root.name.startswith('gold-ownership-tests-') or root != expected
            or root.is_symlink() or root.resolve() != expected
            or root.lstat().st_uid != os.getuid() or not root.is_dir()):
        raise AssertionError('Unsafe ownership-test cleanup refused')
    shutil.rmtree(str(expected))


def mkdir(path, mode=0o700):
    # Only within a freshly allocated own fixture; create missing parents 0700,
    # rather than pathlib's intermediate 0755 default under the test umask.
    if not path.parent.exists():
        mkdir(path.parent, 0o700)
    path.mkdir(mode=mode, exist_ok=True)
    path.chmod(mode)
    return path


def write(path, value, mode=0o600):
    raw = ownership._json(value) if isinstance(value, (dict, list)) else value
    with path.open('wb') as stream:
        stream.write(raw)
    path.chmod(mode)


class Fixture:
    def __init__(self, root, *, name='中文 新环境 1', helper_bytes=None):
        self.root = root
        self.state = mkdir(root / 'state')
        self.tart = mkdir(root / 'tart')
        mkdir(self.tart / 'vms')
        self.stage = mkdir(self.tart / '.gold-manager-staging' / JOB / 'new-environment')
        self.paths = ownership.operation_paths(self.tart, JOB, OP, state_dir=self.state)
        mkdir(self.paths['directory'])
        self.mount = mkdir(self.paths['apply_mount'])
        self.name = name
        mkdir(self.mount / 'Library' / 'Application Support')
        mkdir(self.mount / 'Library' / 'LaunchAgents')
        mkdir(self.mount / 'Applications')
        mkdir(self.mount / 'Users' / 'Shared')
        mkdir(self.mount / 'private' / 'var' / 'db')
        for relative, (kind, uid, gid, mode) in ownership.SEED_RULES.items():
            path = self.mount / relative
            if kind == 'directory':
                mkdir(path, mode)
            else:
                write(path, (SECRET if relative.endswith('seed.json') else 'dummy-fixed-payload').encode(), mode)
        for app in ownership.APP_NAMES:
            app_root = mkdir(self.mount / 'Applications' / app, 0o755)
            mkdir(app_root / 'Contents', 0o755)
            write(app_root / 'Contents' / 'dummy', b'dummy-app-content', 0o755)
            write(app_root / 'Contents' / 'Unicode-中文-🙂', b'dummy-unicode', 0o644)
            (app_root / 'Current').symlink_to('Contents/dummy')
        self.entries = ownership.collect_entries(self.mount)
        self.request = {'id': JOB, 'name': name, 'mode': 'preinstall', 'source_vm': None,
                        'disk_gib': 1, 'acknowledge_preinstall': True,
                        'acknowledge_network_policy': True, 'acknowledge_guest_autoconfigure': True}
        self.current = dict(self.request, stage_path=str(self.stage), phase='configuring_vpn',
                            system_restored=True, applications_preinstalled=True, guest_started=False,
                            desktop_verified=False, published=False, credentials_copied=False,
                            host_credentials_copied=False, vpn_configuration={'operation_id': OP, 'active': True})
        write(self.state / 'build-current.json', self.current)
        write(self.state / 'build-jobs' / JOB / 'request.json', self.request)
        write(self.stage / '.clean-vm-installer.complete.json', {
            'installer': 'CleanVMInstaller', 'status': 'complete', 'schemaVersion': 1,
            'networkDeviceCount': 0, 'directorySharingDeviceCount': 0, 'socketDeviceCount': 0})
        apps = []
        for name in ownership.APP_NAMES:
            digest, size = ownership._app_tree(self.entries, name)
            apps.append({'name': name, 'bundle_tree_sha256': digest, 'bundle_bytes': size})
        self.apps = {'job_id': JOB, 'name': self.name, 'stage_path': str(self.stage),
                     'applications_preinstalled': True, 'readonly_remount_verified': True,
                     'final_detach_confirmed': True, 'guest_started': False, 'published': False,
                     'credentials_copied': False, 'desktop_verified': False,
                     'data_uuid': DATA_UUID, 'volume_group_uuid': GROUP_UUID, 'applications': apps}
        write(self.stage / '.offline-preinstall.complete.json', self.apps)
        write(self.stage / 'config.json', {'fixture': True})
        write(self.stage / 'nvram.bin', b'dummy-nvram')
        image = self.stage / 'disk.img'
        with image.open('wb') as stream:
            stream.truncate(1024 ** 3)  # Sparse ordinary dummy file, NOT an APFS image.
        image.chmod(0o600)
        helper_bytes = helper_bytes or b'dummy-local-helper-' + ownership.PRODUCTION_CONTRACT.encode()
        self.helper_hash = hashlib.sha256(helper_bytes).hexdigest()
        helper_dir = mkdir(self.state / 'ownership-helper' / self.helper_hash)
        self.helper = helper_dir / 'GuestOwnershipHelper'
        write(self.helper, helper_bytes, 0o755)
        self.config_fd = os.open(str(self.stage / 'config.json'), os.O_RDWR | os.O_NOFOLLOW)
        fcntl.lockf(self.config_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.ticket = None

    def close(self):
        if self.config_fd is not None:
            os.close(self.config_fd)
            self.config_fd = None

    def prepare(self, **overrides):
        args = dict(state_dir=self.state, tart_home=self.tart, job_id=JOB, name=self.name,
                    operation_id=OP, apply_mount=self.paths['apply_mount'], verify_mount=self.paths['verify_mount'],
                    data_uuid=DATA_UUID, group_uuid=GROUP_UUID, entries=self.entries,
                    helper_sha256=self.helper_hash, config_lock_fd=self.config_fd)
        args.update(overrides)
        self.ticket = ownership.prepare_ticket(**args)
        return self.ticket

    def native_documents(self):
        directory = self.paths['directory']
        for operation, generation in (('apply', 111), ('verify', 222)):
            readonly = operation == 'verify'
            mount = self.paths['verify_mount' if readonly else 'apply_mount']
            image = {'image-path': str(self.stage / 'disk.img'), 'owner-uid': os.getuid(),
                     'image-type': 'read/write', 'writeable': not readonly, 'image-encrypted': False,
                     'autodiskmount': False, 'blockcount': 2097152, 'blocksize': 512, 'hdid-pid': generation,
                     'system-entities': [{'dev-entry': '/dev/disk76'}, {'dev-entry': '/dev/disk76s2'},
                                         {'dev-entry': '/dev/disk77'},
                                         {'dev-entry': '/dev/disk77s1', 'mount-point': str(mount)}]}
            disk = {'DeviceIdentifier': 'disk77s1', 'DeviceNode': '/dev/disk77s1',
                    'APFSContainerReference': 'disk77', 'ParentWholeDisk': 'disk77',
                    'APFSPhysicalStores': [{'APFSPhysicalStore': 'disk76s2'}],
                    'MountPoint': str(mount), 'FilesystemType': 'apfs', 'BusProtocol': 'Disk Image',
                    'VolumeUUID': DATA_UUID, 'DiskUUID': DATA_UUID, 'APFSVolumeGroupID': GROUP_UUID,
                    'GlobalPermissionsEnabled': True, 'ReadOnly': readonly}
            disk.update({key: False for key in ('WholeDisk', 'Internal', 'OSInternalMedia', 'APFSSnapshot',
                        'Encryption', 'EncryptionThisVolumeProper', 'FileVault', 'Locked')})
            disk.update({key: not readonly for key in ('Writable', 'WritableMedia', 'WritableVolume')})
            write(directory / ('fixture-hdi-' + operation + '.json'), {'images': [image]})
            write(directory / ('fixture-disk-' + operation + '.json'), disk)
        write(directory / 'fixture-apfs.json', {'Containers': [{
            'ContainerReference': 'disk77', 'PhysicalStores': [{'DeviceIdentifier': 'disk76s2'}],
            'Volumes': [{'APFSVolumeUUID': DATA_UUID, 'DeviceIdentifier': 'disk77s1', 'Roles': ['Data'],
                         'Encryption': False, 'FileVault': False, 'Locked': False}]}]})

    def simulate_remount(self):
        source = self.paths['apply_mount']
        target = self.paths['verify_mount']
        mkdir(target.parent)
        # Verify exact owned absolute source/destination BEFORE this fixture move.
        assert source.resolve() == source and target.parent.resolve() == target.parent
        assert source.is_relative_to(self.root) if hasattr(source, 'is_relative_to') else str(source).startswith(str(self.root) + '/')
        assert str(target).startswith(str(self.root) + '/') and not target.exists()
        source.rename(target)  # Keeps inodes: no disk tools, mount or ownership changes.


def receipt(fixture, operation, *, generation=None):
    return {'schema': 1, 'operation_id': OP, 'ticket_sha256': fixture.ticket.digest,
            'operation': operation, 'attachment_generation': generation or (111 if operation == 'apply' else 222),
            'entry_count': len(fixture.entries), 'fixture_only': False,
            'metadata_applied': operation == 'apply', 'persistent_ownership_verified': operation == 'verify',
            'readonly_owners_on': operation == 'verify', 'guest_started': False, 'published': False,
            'authorization': 'macos_system_administrator', 'helper_contract': ownership.PRODUCTION_CONTRACT}


class PythonOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.root = new_root()
        self.addCleanup(cleanup_root, self.root)
        self.fixture = Fixture(self.root)
        self.addCleanup(self.fixture.close)

    def test_ticket_contract_private_no_payload_and_future_verify_mount(self):
        f = self.fixture
        self.assertFalse(f.paths['verify_mount'].exists())
        ticket = f.prepare()
        self.assertEqual(repr(ticket), 'OwnershipTicket(<private metadata>)')
        value = json.loads(ticket.path.read_bytes())
        self.assertNotIn(SECRET, ticket.path.read_text())
        self.assertEqual(value['name'], '中文 新环境 1')
        self.assertEqual(value['caller_pid'], os.getpid())
        self.assertEqual(stat.S_IMODE(ticket.path.stat().st_mode), 0o600)
        self.assertEqual(ticket.path.stat().st_nlink, 1)
        self.assertEqual(ticket.digest, hashlib.sha256(ticket.path.read_bytes()).hexdigest())
        self.assertEqual(value['schema'], 2)
        for entry, encoded in zip(f.entries, value['entries']):
            self.assertNotIn('target_uid', encoded)
            self.assertEqual(encoded['ctime_ns'], (f.mount / entry.path).lstat().st_ctime_ns)
            self.assertIn(ownership.desired_ownership(entry), ((0, 0), (501, 20)))

    def test_prepare_preserves_config_posix_lock_and_offset(self):
        f = self.fixture
        os.lseek(f.config_fd, 3, os.SEEK_SET)
        f.prepare()
        self.assertEqual(os.lseek(f.config_fd, 0, os.SEEK_CUR), 3)
        # This child only tests a lock on the explicit owned dummy config file.
        script = "import fcntl,os,sys;f=os.open(sys.argv[1],os.O_RDWR)\ntry: fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(0)\nelse: sys.exit(9)"
        result = subprocess.run(['/usr/bin/python3', '-B', '-c', script, str(f.stage / 'config.json')],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0)

    def test_tart_0755_allowed_without_permission_changes(self):
        f = self.fixture
        f.tart.chmod(0o755)
        (f.tart / 'vms').chmod(0o755)
        f.prepare()
        self.assertEqual(stat.S_IMODE(f.tart.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((f.tart / 'vms').stat().st_mode), 0o755)

    def test_writable_tart_and_nonprivate_stage_rejected(self):
        f = self.fixture
        for path in (f.tart, f.tart / 'vms', f.stage, f.stage.parent):
            with self.subTest(path=path.name):
                old = stat.S_IMODE(path.stat().st_mode)
                path.chmod(0o775)
                with self.assertRaises(ownership.OwnershipError):
                    f.prepare()
                path.chmod(old)

    def test_ticket_reuse_and_second_operation_refused(self):
        f = self.fixture
        f.prepare()
        with self.assertRaises(ownership.OwnershipError):
            f.prepare()
        other = mkdir(f.paths['directory'].parent / ('c' * 32))
        self.assertTrue(other.is_dir())
        with self.assertRaises(ownership.OwnershipError):
            f.prepare()

    def test_invalid_names_and_mount_overrides_are_rejected(self):
        for name in ('../escape', '/escape', ' leading', 'trailing ', '-leading', 'bad.name', 'e\u0301', 'a' * 65):
            with self.subTest(name=name), self.assertRaises(ownership.OwnershipError):
                self.fixture.prepare(name=name)
        with self.assertRaises(ownership.OwnershipError):
            self.fixture.prepare(verify_mount=self.root / 'arbitrary')

    def test_scope_modes_and_escaping_symlinks_rejected(self):
        regular = next(e for e in self.fixture.entries if e.kind == 'file' and e.path.startswith('Applications/'))
        link = next(e for e in self.fixture.entries if e.kind == 'symlink')
        for entry in (replace(regular, path='/etc/passwd'), replace(regular, path='Applications/Other.app/file'),
                      replace(regular, path='Applications/CCBaga-A.app/../escape'), replace(regular, mode=0o4755),
                      replace(regular, mode=0o666), replace(link, link_target='/etc/passwd'),
                      replace(link, link_target='../../escape'), replace(regular, path=ownership.BASE + '/arbitrary')):
            with self.subTest(path=entry.path), self.assertRaises(ownership.OwnershipError):
                ownership.desired_ownership(entry)

    def test_broken_cyclic_and_composed_escape_links_rejected(self):
        entries = self.fixture.entries
        link = next(e for e in entries if e.kind == 'symlink')
        for target in ('Current', 'missing-file'):
            altered = tuple(replace(e, link_target=target) if e == link else e for e in entries)
            with self.subTest(target=target), self.assertRaises(ownership.OwnershipError):
                ownership._validate_links(altered)
        prefix = link.path.rsplit('/', 1)[0]
        alias = replace(link, path=prefix + '/Alias', link_target='.')
        escape = replace(link, path=prefix + '/Escape', link_target='Alias/../Contents/dummy')
        ownership.desired_ownership(alias)
        ownership.desired_ownership(escape)  # Lexical checks alone are not enough.
        with self.assertRaises(ownership.OwnershipError):
            ownership._validate_links(entries + (alias, escape))

    def test_entry_types_and_unused_secret_fields_rejected(self):
        entry = next(e for e in self.fixture.entries if e.kind == 'directory')
        for changed in (replace(entry, mode=True), replace(entry, inode=-1), replace(entry, sha256=SECRET),
                        replace(entry, link_target=SECRET), replace(entry, observed_uid=2**32),
                        replace(entry, size=2**63 - 1)):
            with self.assertRaises(ownership.OwnershipError):
                ownership.desired_ownership(changed)

    def test_no_implicit_authorization_and_no_secret_argv(self):
        f = self.fixture
        ticket = f.prepare()
        run = Mock()
        result = ownership.request_authorization(ticket, 'apply', run=run)
        self.assertEqual(result.phase, 'awaiting_system_authorization')
        run.assert_not_called()
        def fake_run(argv, **kwargs):
            self.assertEqual(argv, ['/usr/bin/osascript', '-'])
            self.assertIn(b'with administrator privileges', kwargs['input'])
            self.assertNotIn(SECRET.encode(), kwargs['input'])
            # stderr is captured only to extract the trailing numeric status.
            self.assertIs(kwargs['stderr'], subprocess.PIPE)
            self.assertIs(kwargs['stdout'], subprocess.DEVNULL)
            write(ticket.path.parent / 'apply.receipt.json', receipt(f, 'apply'))
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(ownership.host_tools, 'verify_local_signature'):
            result = ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True, run=fake_run)
        self.assertTrue(result.authorized_helper_completed)
        self.assertFalse(result.independent_readonly_acceptance)

    def test_shell_and_applescript_quoting_roundtrip(self):
        values = ["/private/tmp/quoted ' \" 中文/helper", "/private/tmp/space name/ticket.json", '--apply']
        command = ' '.join(ownership.shlex.quote(value) for value in values)
        decoded = json.loads(ownership._apple_string(command))
        self.assertEqual(ownership.shlex.split(decoded), values)

    def test_exit_zero_without_receipt_is_not_success(self):
        ticket = self.fixture.prepare()
        with patch.object(ownership.host_tools, 'verify_local_signature'), self.assertRaises(ownership.OwnershipError):
            ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True,
                                            run=lambda *args, **kwargs: subprocess.CompletedProcess([], 0))

    def test_denied_and_timeout_authorization_are_sanitized(self):
        ticket = self.fixture.prepare()
        with patch.object(ownership.host_tools, 'verify_local_signature'):
            for runner in (lambda *a, **k: subprocess.CompletedProcess([], 1), Mock(side_effect=RuntimeError(SECRET))):
                result = ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True, run=runner)
                self.assertFalse(result.authorized_helper_completed)
                self.assertNotIn(SECRET, repr(result))

    def authorization_failure(self, runner):
        ticket = self.fixture.ticket if getattr(self.fixture, 'ticket', None) else self.fixture.prepare()
        with patch.object(ownership.host_tools, 'verify_local_signature'):
            result = ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True, run=runner)
        self.assertFalse(result.authorized_helper_completed)
        self.assertEqual((result.phase, result.operation), ('authorization_or_helper_failed_retained', 'apply'))
        self.assertNotIn(SECRET, repr(result))
        self.assertFalse((ticket.path.parent / 'apply.receipt.json').exists())
        return result

    def test_osascript_status_is_classified_without_retaining_native_text(self):
        prefix = b'-:93:220: execution error: '
        cases = (
            (prefix + b'User canceled. (-128)\n', 'user-cancelled', None),
            (prefix + b'The authorization was cancelled by the user. (-60006)\n', 'user-cancelled', None),
            (prefix + b'The administrator user name or password was incorrect. (-60005)\n', 'authorization-denied', None),
            (prefix + b'The authorization was denied since no user interaction was possible. (-60007)\n',
             'interaction-not-allowed', None),
            (prefix + b'Internal error. (-60008)\n', 'authorization-error', -60008),
            (prefix + SECRET.encode() + b' /private/ticket path (3)\n', 'helper-exit', 3),
            (b'garbage without a status ' + SECRET.encode(), 'unknown-failure', None),
            (None, 'unknown-failure', None),
        )
        for stderr, reason, status in cases:
            with self.subTest(reason=reason, stderr=stderr):
                runner = lambda argv, _native=stderr, **kwargs: subprocess.CompletedProcess(argv, 1, None, _native)
                result = self.authorization_failure(runner)
                self.assertEqual((result.failure_reason, result.failure_status), (reason, status))

    def test_osascript_timeout_and_launch_failure_are_distinct(self):
        def timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'], stderr=SECRET.encode())
        def missing(argv, **kwargs):
            raise FileNotFoundError(2, SECRET)
        self.assertEqual(self.authorization_failure(timeout).failure_reason, 'timeout')
        self.assertEqual(self.authorization_failure(missing).failure_reason, 'launch-failed')

    def test_local_preflight_rejection_never_prompts(self):
        ticket = self.fixture.prepare()
        run = Mock()
        with patch.object(ownership.host_tools, 'verify_local_signature', side_effect=RuntimeError(SECRET)):
            result = ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True, run=run)
        run.assert_not_called()
        self.assertFalse(result.authorized_helper_completed)
        self.assertEqual((result.failure_reason, result.failure_status), ('preflight-rejected', None))
        self.assertNotIn(SECRET, repr(result))
        with patch.object(ownership.host_tools, 'verify_local_signature'), \
                patch.object(ownership, '_identity', side_effect=ownership.OwnershipError(SECRET)):
            result = ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True, run=run)
        run.assert_not_called()
        self.assertEqual(result.failure_reason, 'preflight-rejected')

    def test_successful_authorization_has_no_failure_fields(self):
        f = self.fixture
        ticket = f.prepare()
        def fake_run(argv, **kwargs):
            write(ticket.path.parent / 'apply.receipt.json', receipt(f, 'apply'))
            return subprocess.CompletedProcess(argv, 0, None, b'')
        with patch.object(ownership.host_tools, 'verify_local_signature'):
            result = ownership.request_authorization(ticket, 'apply', acknowledge_authorization=True, run=fake_run)
        self.assertTrue(result.authorized_helper_completed)
        self.assertEqual((result.failure_reason, result.failure_status), (None, None))

    def test_fixture_receipt_and_same_generation_never_accepted(self):
        f = self.fixture
        ticket = f.prepare()
        write(ticket.path.parent / 'apply.receipt.json', receipt(f, 'apply'))
        write(ticket.path.parent / 'verify.receipt.json', receipt(f, 'verify', generation=111))
        with self.assertRaises(ownership.OwnershipError):
            ownership.verify_receipt(ticket, 'verify')
        value = receipt(f, 'verify')
        value['fixture_only'] = True
        write(ticket.path.parent / 'verify.receipt.json', value)
        with self.assertRaises(ownership.OwnershipError):
            ownership.verify_receipt(ticket, 'verify')
        write(ticket.path.parent / 'verify.receipt.json', receipt(f, 'verify'))
        self.assertTrue(ownership.verify_receipt(ticket, 'verify').independent_readonly_acceptance)

    def test_deploy_uses_verified_portable_binary_and_never_overwrites(self):
        f = self.fixture
        source_dir = mkdir(self.root / 'portable')
        source = source_dir / 'GuestOwnershipHelper'
        payload = b'not-executed-dummy-fixture-' + ownership.PRODUCTION_CONTRACT.encode()
        write(source, payload, 0o700)
        with patch.object(ownership.host_tools, 'resolve_ownership_helper', return_value=source) as verify, \
                patch.object(ownership.host_tools, 'verify_local_signature'):
            digest = ownership.deploy_helper(f.state, source)
            target = f.state / 'ownership-helper' / digest / 'GuestOwnershipHelper'
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual(ownership.deploy_helper(f.state, source), digest)
            self.assertEqual(verify.call_count, 2)
            write(target, b'changed', 0o755)
            with self.assertRaises(ownership.OwnershipError):
                ownership.deploy_helper(f.state, source)
            self.assertEqual(target.read_bytes(), b'changed')

    def test_deploy_preserves_quarantine_on_new_and_reused_copy(self):
        source = mkdir(self.root / 'portable') / 'GuestOwnershipHelper'
        write(source, b'dummy-with-quarantine-' + ownership.PRODUCTION_CONTRACT.encode(), 0o700)
        quarantine = '0083;00000000;GoldOwnershipFixture;11111111-2222-4333-8444-555555555555'
        result = subprocess.run(['/usr/bin/xattr', '-w', 'com.apple.quarantine', quarantine, str(source)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        with patch.object(ownership.host_tools, 'resolve_ownership_helper', return_value=source), \
                patch.object(ownership.host_tools, 'verify_local_signature'):
            digest = ownership.deploy_helper(self.fixture.state, source)
            target = self.fixture.state / 'ownership-helper' / digest / 'GuestOwnershipHelper'
            self.assertEqual(ownership.quarantine_policy.read(target), quarantine.encode())
            self.assertEqual(ownership.deploy_helper(self.fixture.state, source), digest)
            self.assertEqual(ownership.quarantine_policy.read(source), quarantine.encode())
            self.assertEqual(ownership.quarantine_policy.read(target), quarantine.encode())

    def test_deploy_rejects_fixture_contract(self):
        source = mkdir(self.root / 'portable') / 'GuestOwnershipHelper'
        write(source, ownership.FIXTURE_CONTRACT.encode(), 0o700)
        with patch.object(ownership.host_tools, 'resolve_ownership_helper', return_value=source), self.assertRaises(ownership.OwnershipError):
            ownership.deploy_helper(self.fixture.state, source)


@unittest.skipUnless(os.path.isfile('/usr/bin/xcrun'), 'macOS Swift compiler required')
class SwiftOwnershipFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = new_root()
        cls.addClassCleanup(cleanup_root, cls.build)
        cls.fixture_binary = cls.build / 'fixture-helper'
        cls.production_binary = cls.build / 'GuestOwnershipHelper'
        common = ['/usr/bin/xcrun', 'swiftc', '-parse-as-library', '-swift-version', '5',
                  '-module-cache-path', str(cls.build / 'module-cache'), str(SOURCE / 'GuestOwnershipHelper.swift')]
        for flags, binary in ((['-D', 'GOLD_OWNERSHIP_FIXTURE'], cls.fixture_binary), ([], cls.production_binary)):
            result = subprocess.run(common + flags + ['-o', str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            if result.returncode:
                raise AssertionError('Swift compile failed:\n' + result.stderr.decode(errors='replace'))
        # Standalone no-I/O test main. It invokes the same compiled pure rules as
        # production, not the helper CLI and never a pretend-root mutation path.
        driver = cls.build / 'Predicates.swift'
        driver.write_text('''
import Darwin
@main struct Predicates {
    static func main() {
        typealias G = GuestOwnership
        let a = CommandLine.arguments
        func owner(_ i: Int) -> G.Owner { G.Owner(uid: UInt32(a[i])!, gid: UInt32(a[i+1])!) }
        func stamp(_ i: Int) -> G.RawStamp { G.RawStamp(owner: owner(i), ctime_ns: Int64(a[i+2])!) }
        let ok: Bool
        switch a[1] {
        case "apply": ok = G.applyObservationMatches(stamp(2), observed: owner(5), ctime_ns: Int64(a[7])!, caller: owner(8))
        case "raw": ok = G.rawStampMatches(stamp(2), prevalidated: stamp(5))
        case "final": ok = G.finalOwnerMatches(owner(2), desired: owner(4))
        default: exit(2)
        }
        exit(ok ? 0 : 1)
    }
}
''')
        cls.predicates = cls.build / 'predicates'
        result = subprocess.run(common + ['-D', 'GOLD_OWNERSHIP_FIXTURE', '-D', 'GOLD_OWNERSHIP_PREDICATE_TEST',
                                str(driver), '-o', str(cls.predicates)], capture_output=True, timeout=180)
        if result.returncode:
            raise AssertionError('Swift predicate compile failed:\n' + result.stderr.decode(errors='replace'))
        # Only fixture_binary and this pure driver are executed, never production.

    def setUp(self):
        self.root = new_root()
        self.addCleanup(cleanup_root, self.root)
        self.fixture = Fixture(self.root, helper_bytes=self.production_binary.read_bytes())
        self.addCleanup(self.fixture.close)
        self.fixture.prepare()
        self.fixture.native_documents()

    def run_helper(self, operation='apply', expected=0):
        result = subprocess.run([str(self.fixture_binary), str(self.fixture.ticket.path), '--' + operation],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        # All failure channels are numeric only, including native/decoding errors.
        self.assertEqual(len(result.stderr), 0)
        self.assertEqual(result.returncode, expected)
        if expected:
            self.assertEqual(len(result.stdout), 0)
        else:
            self.assertEqual(result.stdout, b'fixture_metadata_simulation_completed\n')
        return result

    def edit_document(self, name, change):
        path = self.fixture.paths['directory'] / name
        value = json.loads(path.read_bytes())
        change(value)
        write(path, value)

    def predicate(self, mode, fields, accepted):
        result = subprocess.run([str(self.predicates), mode, *map(str, fields)], capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0 if accepted else 1, b'', b''))

    def test_compiled_apply_comparison_is_not_a_wildcard(self):
        ts, unknown, interactive = 1795100000000000987, (99, 99), (501, 20)
        # (raw root view, ticket ordinary view, verified lock-holder principal).
        for raw, observed, caller, accepted in (
            (unknown, interactive, interactive, True),       # actual root-probe sample
            (unknown, (504, 42), (504, 42), True),          # not derived from guest target
            ((0, 0), (0, 0), interactive, True),            # exact path remains first
            (unknown, unknown, interactive, True),
            ((99, 42), (99, 42), interactive, True),
            ((501, 99), interactive, interactive, False),    # neither partial match is enough
            ((99, 20), interactive, interactive, False),
            ((502, 21), interactive, interactive, False),    # wrong known pair
            (unknown, interactive, (504, 20), False),        # unverified UID/GID/guest target
            (unknown, interactive, (501, 80), False),
            (unknown, (0, 0), interactive, False),
            (unknown, (99, 20), (99, 20), False),
            (unknown, (501, 99), (501, 99), False),
            (unknown, (501, 0), (501, 0), False),
            (unknown, (501, 2**32-1), (501, 2**32-1), False),
            (unknown, (2**32-1, 20), (2**32-1, 20), False),
        ):
            with self.subTest(raw=raw, observed=observed, caller=caller):
                self.predicate('apply', (*raw, ts, *observed, ts, *caller), accepted)
        for raw in (unknown, interactive):  # projected AND exact require the ticket ctime
            self.predicate('apply', (*raw, ts, *interactive, ts+1, *interactive), False)

    def test_compiled_second_pass_requires_unchanged_raw_stamp(self):
        original = (99, 99, 1795100000000000987)
        self.predicate('raw', original + original, True)
        for current in ((501, 20, original[2]), (99, 20, original[2]),
                        (501, 99, original[2]), (99, 99, original[2]+1)):
            # A projected->exact change could pass both ticket comparisons but
            # must NOT pass the second, raw-to-raw pre-mutation comparison.
            self.predicate('raw', current + original, False)

    def test_compiled_post_chown_and_readonly_compare_are_exact(self):
        for desired in ((0, 0), (501, 20)):
            self.predicate('final', desired + desired, True)
            for raw in ((99, 99), (99, desired[1]), (desired[0], 99), (502, 20)):
                self.predicate('final', raw + desired, False)

    def test_build_contracts_and_no_mutation_calls_in_fixture(self):
        prod, fixture = self.production_binary.read_bytes(), self.fixture_binary.read_bytes()
        self.assertTrue(ownership.PRODUCTION_CONTRACT.encode() in prod)
        self.assertFalse(ownership.FIXTURE_CONTRACT.encode() in prod)
        self.assertTrue(ownership.FIXTURE_CONTRACT.encode() in fixture)
        self.assertFalse(ownership.PRODUCTION_CONTRACT.encode() in fixture)
        # Mach-O external symbol names; unlike an owner-only before/after test,
        # this also rules out a successful same-IDs chown in the fixture helper.
        self.assertTrue(b'_fchown' in prod)
        for call in (b'_chown', b'_lchown', b'_fchown', b'_fchownat'):
            self.assertFalse(call in fixture)

    def test_apply_and_fresh_verify_only_simulate_metadata(self):
        f = self.fixture
        def raw_stamps():
            return [(s.st_uid, s.st_gid, s.st_ctime_ns) for s in ((f.mount / e.path).lstat() for e in f.entries)]
        original = raw_stamps()
        self.run_helper()
        apply = json.loads((f.paths['directory'] / 'apply.receipt.json').read_bytes())
        self.assertTrue(apply['fixture_only'])
        self.assertFalse(apply['metadata_applied'])
        self.assertFalse(apply['persistent_ownership_verified'])
        self.assertEqual(original, raw_stamps())
        self.assertEqual(set(apply), set(receipt(f, 'apply')))  # no entry/owner/path diagnostics
        f.simulate_remount()
        # A real apply changes ctime. Change only metadata in this owned dummy
        # file to prove the fresh verification does not require pre-apply ctime.
        entry = next(e for e in f.entries if e.kind == 'file')
        path = f.paths['verify_mount'] / entry.path
        st = path.lstat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns - 1), follow_symlinks=False)
        self.assertNotEqual(path.lstat().st_ctime_ns, entry.ctime_ns)
        self.run_helper('verify')
        result = json.loads((f.paths['directory'] / 'verify.receipt.json').read_bytes())
        self.assertFalse(result['persistent_ownership_verified'])
        self.assertEqual(result['helper_contract'], ownership.FIXTURE_CONTRACT)
        with self.assertRaises(ownership.OwnershipError):
            ownership.verify_receipt(f.ticket, 'verify')

    def test_tart_0755_and_chinese_name_supported(self):
        self.fixture.tart.chmod(0o755)
        (self.fixture.tart / 'vms').chmod(0o755)
        self.run_helper()

    def test_owners_off_apply_refused_even_with_matching_observed_ids(self):
        self.edit_document('fixture-disk-apply.json', lambda v: v.update(GlobalPermissionsEnabled=False))
        self.run_helper(expected=24)
        self.assertFalse((self.fixture.paths['directory'] / 'apply.started').exists())

    def test_owners_on_apply_rejects_observed_owner_change(self):
        path = self.fixture.ticket.path
        value = json.loads(path.read_bytes())
        value['entries'][0]['observed_uid'] = os.getuid() + 1
        write(path, value)
        self.run_helper(expected=28)
        self.assertFalse((self.fixture.paths['directory'] / 'apply.started').exists())

    def test_stale_ctime_on_each_entry_kind_fails_before_marker(self):
        path = self.fixture.ticket.path
        original = path.read_bytes()
        for kind in ('file', 'symlink', 'directory'):
            with self.subTest(kind=kind):
                ticket = json.loads(original)
                entry = next(e for e in ticket['entries'] if e['kind'] == kind)
                entry['ctime_ns'] -= 1   # one nanosecond, with identical owner/identity/content
                write(path, ticket)
                self.run_helper(expected=28)
                self.assertFalse((path.parent / 'apply.started').exists())
                self.assertFalse((path.parent / 'apply.receipt.json').exists())

    def test_schema2_requires_positive_int64_ctime_on_every_entry(self):
        path = self.fixture.ticket.path
        original = path.read_bytes()
        for schema, ctime in ((1, None), (1, 'keep'), (2, None), (2, False), (2, -1),
                              (2, 0), (2, 2**63), (2, 'not-an-integer')):
            with self.subTest(schema=schema, ctime=ctime):
                ticket = json.loads(original)
                ticket['schema'] = schema
                if ctime is None:
                    del ticket['entries'][-1]['ctime_ns']
                elif ctime != 'keep':
                    ticket['entries'][-1]['ctime_ns'] = ctime
                write(path, ticket)
                self.run_helper(expected=21)
                self.assertFalse((path.parent / 'apply.started').exists())

    def test_extended_acl_on_private_target_is_refused_not_removed(self):
        seed = self.fixture.mount / ownership.BASE / 'FirstLogin' / 'seed.json'
        self.assertTrue(str(seed.resolve()).startswith(str(self.root) + '/'))
        result = subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(seed)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.run_helper(expected=29)
        self.assertEqual(seed.read_bytes(), SECRET.encode())

    def test_invalid_invocation_and_malformed_ticket_have_no_text_output(self):
        # Both the caller's argument and an undecodable private document must be
        # discarded; run_helper asserts byte-empty stdout and stderr on failure.
        self.run_helper(operation=SECRET, expected=20)
        write(self.fixture.ticket.path, ('{"unclosed":"' + SECRET).encode())
        self.run_helper(expected=21)
        self.assertFalse((self.fixture.paths['directory'] / 'apply.started').exists())

    def test_lock_checked_before_stage_state_or_mount(self):
        f = self.fixture
        f.close()  # Drop the real POSIX lock only on this fixture's dummy config.
        write(f.state / 'build-current.json', dict(f.current, guest_started=True))
        self.edit_document('fixture-disk-apply.json', lambda v: v.update(GlobalPermissionsEnabled=False))
        self.run_helper(expected=22)
        self.assertFalse((f.paths['directory'] / 'apply.started').exists())
        self.assertFalse((f.paths['directory'] / 'apply.receipt.json').exists())

    def test_immutable_input_hash_precedes_interpreted_receipt(self):
        f = self.fixture
        path = f.stage / '.offline-preinstall.complete.json'
        # Keep size, inode and mode. A bound receipt edited in place fails 21,
        # not the later bundle-manifest comparison (26).
        record = f.apps['applications'][0]
        record['bundle_tree_sha256'] = '0' * 64
        write(path, f.apps)
        self.run_helper(expected=21)
        self.assertFalse((f.paths['directory'] / 'apply.started').exists())

    def test_bundle_tree_receipt_precedes_bad_guest_bytes(self):
        f = self.fixture
        path = f.stage / '.offline-preinstall.complete.json'
        f.apps['applications'][0]['bundle_tree_sha256'] = '0' * 64
        write(path, f.apps)
        self.edit_document('ticket.json', lambda v: v['metadata'].update(
            applications=ownership._identity(path, os.getuid(), digest=True)))
        write(f.mount / ownership.BASE / 'FirstLogin/seed.json', b'x' * len(SECRET))
        self.run_helper(expected=26)
        self.assertFalse((f.paths['directory'] / 'apply.started').exists())

    def test_bad_guest_digest_precedes_one_shot_marker(self):
        f = self.fixture
        marker = f.paths['directory'] / 'apply.started'
        write(marker, b'dummy-existing-marker')
        # Same inode, mode, owner and bytes count. Only the digest is wrong.
        write(f.mount / ownership.BASE / 'FirstLogin/seed.json', b'x' * len(SECRET))
        self.run_helper(expected=30)
        self.assertEqual(marker.read_bytes(), b'dummy-existing-marker')
        self.assertFalse((f.paths['directory'] / 'apply.receipt.json').exists())

    def test_replay_apply_refused(self):
        self.run_helper()
        self.run_helper(expected=31)

    def test_readonly_noowners_rejected(self):
        self.run_helper()
        self.fixture.simulate_remount()
        self.edit_document('fixture-disk-verify.json', lambda v: v.update(GlobalPermissionsEnabled=False))
        self.run_helper('verify', expected=24)

    def test_readwrite_verify_and_same_generation_rejected(self):
        self.run_helper()
        self.fixture.simulate_remount()
        self.edit_document('fixture-hdi-verify.json', lambda v: v['images'][0].update({'hdid-pid': 111}))
        self.run_helper('verify', expected=31)
        self.edit_document('fixture-hdi-verify.json', lambda v: v['images'][0].update({'hdid-pid': 222, 'writeable': True}))
        self.run_helper('verify', expected=24)

    def test_wrong_image_owner_uuid_and_role_rejected(self):
        f = self.fixture
        cases = [ ('fixture-hdi-apply.json', lambda v: v['images'][0].update({'owner-uid': os.getuid() + 1})),
                  ('fixture-hdi-apply.json', lambda v: v['images'][0].update({'image-path': '/dummy/not-the-image'})),
                  ('fixture-disk-apply.json', lambda v: v.update(VolumeUUID=GROUP_UUID)),
                  ('fixture-disk-apply.json', lambda v: v.update(Internal=True)),
                  ('fixture-apfs.json', lambda v: v['Containers'][0]['Volumes'][0].update(Roles=['System'])) ]
        for name, change in cases:
            with self.subTest(name=name):
                f.native_documents()
                self.edit_document(name, change)
                self.run_helper(expected=24)
        self.assertFalse((f.paths['directory'] / 'apply.started').exists())

    def test_payload_hash_extra_file_and_hardlink_refused(self):
        f = self.fixture
        seed = f.mount / ownership.BASE / 'FirstLogin' / 'seed.json'
        write(seed, b'tampered-payload')
        self.run_helper(expected=30)
        write(seed, SECRET.encode())
        extra = f.mount / ownership.BASE / 'FirstLogin' / 'unexpected'
        write(extra, b'dummy')
        self.run_helper(expected=25)
        # Do not delete evidence to retry; separate hardlink fixture is covered
        # by adding a link, which independently violates both nlink and inventory.
        os.link(seed, f.root / 'hardlinked-seed')
        self.run_helper(expected=25)

    def test_hardlinked_payload_rejected_without_inventory_change(self):
        f = self.fixture
        seed = f.mount / ownership.BASE / 'FirstLogin' / 'seed.json'
        os.link(seed, f.root / 'outside-inventory-dummy-link')
        self.run_helper(expected=27)
        self.assertFalse((f.paths['directory'] / 'apply.started').exists())

    def test_cyclic_link_rejected_even_with_consistent_fixture_receipt(self):
        f = self.fixture
        link_path = f.mount / 'Applications' / ownership.APP_NAMES[0] / 'Cycle'
        link_path.symlink_to('Cycle')
        st = link_path.lstat()
        entry = ownership.OwnershipEntry('Applications/' + ownership.APP_NAMES[0] + '/Cycle', 'symlink',
                st.st_dev, st.st_ino, st.st_size, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_ctime_ns, '', 'Cycle')
        entries = f.entries + (entry,)
        for app in f.apps['applications']:
            app['bundle_tree_sha256'], app['bundle_bytes'] = ownership._app_tree(entries, app['name'])
        app_path = f.stage / '.offline-preinstall.complete.json'
        write(app_path, f.apps)
        ticket = json.loads(f.ticket.path.read_bytes())
        ticket['entries'].append(ownership.asdict(entry))
        ticket['entries'].sort(key=lambda value: value['path'])
        ticket['metadata']['applications'] = ownership._identity(app_path, os.getuid(), digest=True)
        write(f.ticket.path, ticket)
        self.run_helper(expected=26)
        self.assertFalse((f.paths['directory'] / 'apply.started').exists())

    def test_stage_state_and_published_vm_guards(self):
        f = self.fixture
        for patch_value in ({'guest_started': True}, {'phase': 'running'}, {'host_credentials_copied': True},
                            {'vpn_configuration': {'operation_id': OP, 'active': False}}):
            value = dict(f.current, **patch_value)
            write(f.state / 'build-current.json', value)
            self.run_helper(expected=23)
        write(f.state / 'build-current.json', f.current)
        mkdir(f.tart / 'vms' / f.name)
        self.run_helper(expected=23)

    def test_existing_user_or_setup_complete_refused(self):
        f = self.fixture
        mkdir(f.mount / 'Users' / 'existing-user')
        self.run_helper(expected=23)
        write(f.mount / 'private' / 'var' / 'db' / '.AppleSetupDone', b'dummy')
        self.run_helper(expected=23)

    def test_seed_symlink_to_outside_is_not_followed(self):
        f = self.fixture
        seed = f.mount / ownership.BASE / 'FirstLogin' / 'seed.json'
        held = f.root / 'held-private-fixture'
        assert seed.resolve() == seed and not held.exists() and held.parent.resolve() == f.root
        seed.rename(held)
        seed.symlink_to(held)
        self.run_helper(expected=27)
        self.assertEqual(held.read_bytes(), SECRET.encode())

    def test_ticket_modes_unknown_keys_and_duplicate_keys_rejected(self):
        f = self.fixture
        f.ticket.path.chmod(0o644)
        self.run_helper(expected=21)
        f.ticket.path.chmod(0o600)
        original = f.ticket.path.read_bytes()
        value = json.loads(original)
        value['entries'][0]['size'] = 2**63 - 1
        write(f.ticket.path, value)
        self.run_helper(expected=30)
        value = json.loads(original)
        value['entries'][0]['target_uid'] = 0
        write(f.ticket.path, value)
        self.run_helper(expected=21)
        write(f.ticket.path, b'{"schema":1,' + original[1:])
        self.run_helper(expected=21)

    def test_second_operation_directory_and_writable_tart_refused(self):
        self.fixture.tart.chmod(0o775)
        self.run_helper(expected=21)
        self.fixture.tart.chmod(0o700)
        mkdir(self.fixture.paths['directory'].parent / ('c' * 32))
        self.run_helper(expected=21)


if __name__ == '__main__':
    unittest.main()
