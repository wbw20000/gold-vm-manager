"""Only pure seed generation, Swift compilation and compile-gated file fixtures.

Never executes the production helper, GUI, disk/VM tools, real seed paths, host
profiles or a network request. Every destructive cleanup verifies its exact own
absolute temporary root first. No subprocess argument contains VPN secrets.
"""
import copy
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from guest_vpn_seed import (AGENT_PATH, APP_ID, APP_TEAM, APP_VERSION, BASE,
                            FIRST_LOGIN, HELPER_PATH, PROFILE_FILE, PROFILE_UID,
                            SEED_PATH, GuestVPNSeedError, build_seed)
from vpn_config import parse_submission

ROOT = Path(__file__).resolve().parents[1]
DUMMY_SECRET = 'dummy-fixture-password-not-a-credential'


def fixture_config():
    return parse_submission({'input_mode': 'fields', 'nodes': [{
        'type': 'trojan', 'server': '8.8.8.8', 'port': 443,
        'password': DUMMY_SECRET, 'sni': 'vpn.example.com',
    }]})


def own_root():
    path = Path(tempfile.mkdtemp(prefix='gold-vpn-bootstrap-tests-', dir='/private/tmp'))
    assert path.is_absolute() and path.resolve() == path
    assert path.parent == Path('/private/tmp') and path.name.startswith('gold-vpn-bootstrap-tests-')
    os.chmod(path, 0o700)
    return path


def cleanup_own_root(path):
    # Verify the resolved absolute target immediately before any deletion.
    expected = Path('/private/tmp') / path.name
    if (not path.name.startswith('gold-vpn-bootstrap-tests-') or path != expected
            or path.is_symlink() or path.resolve() != expected
            or path.lstat().st_uid != os.getuid() or not path.is_dir()):
        raise AssertionError('Refusing unsafe test cleanup')
    shutil.rmtree(str(expected))


class PureSeedTests(unittest.TestCase):
    def test_contract_private_repr_and_fixed_layout(self):
        config = fixture_config()
        result = build_seed(config)
        self.assertEqual(repr(result), 'GuestVPNSeed(<redacted>)')
        self.assertNotIn(DUMMY_SECRET, repr(result.entries))
        self.assertEqual(len(result.receipt_token), 64)
        manifest = {entry.relative_path: entry for entry in result.entries}
        self.assertEqual(set(manifest), {BASE, FIRST_LOGIN, HELPER_PATH, SEED_PATH, AGENT_PATH})
        self.assertEqual((manifest[FIRST_LOGIN].uid, manifest[FIRST_LOGIN].gid, manifest[FIRST_LOGIN].mode), (501, 20, 0o700))
        self.assertEqual((manifest[SEED_PATH].uid, manifest[SEED_PATH].mode), (501, 0o600))
        self.assertEqual((manifest[HELPER_PATH].uid, manifest[HELPER_PATH].mode, manifest[HELPER_PATH].kind), (0, 0o755, 'compiled_helper'))
        self.assertIsNone(manifest[HELPER_PATH].content)
        self.assertEqual((manifest[AGENT_PATH].uid, manifest[AGENT_PATH].mode), (0, 0o644))
        self.assertEqual(manifest[SEED_PATH].content, result.seed_json)
        self.assertEqual(manifest[AGENT_PATH].content, result.launch_agent_plist)
        for path in manifest:
            self.assertFalse(path.startswith('/'))
            self.assertNotIn('..', Path(path).parts)

    def test_launch_agent_no_shell_no_secrets_no_privilege_escalation(self):
        plan = build_seed(fixture_config())
        agent = plistlib.loads(plan.launch_agent_plist)
        self.assertEqual(agent['ProgramArguments'], ['/' + HELPER_PATH])
        self.assertTrue(agent['RunAtLoad'])
        self.assertFalse(agent['KeepAlive'])
        self.assertEqual(agent['LimitLoadToSessionType'], 'Aqua')
        self.assertEqual(agent['Umask'], 0o077)
        self.assertEqual(agent['StandardOutPath'], '/dev/null')
        self.assertEqual(agent['StandardErrorPath'], '/dev/null')
        for forbidden in ('UserName', 'EnvironmentVariables', 'RootDirectory', 'WorkingDirectory'):
            self.assertNotIn(forbidden, agent)
        self.assertNotIn(DUMMY_SECRET.encode(), plan.launch_agent_plist)
        self.assertNotIn(plan.receipt_token.encode(), plan.launch_agent_plist)

    def test_pinned_identity_and_clash_documents(self):
        result = build_seed(fixture_config())
        seed = json.loads(result.seed_json)
        self.assertEqual((seed['expected_uid'], seed['app_id'], seed['app_version'], seed['app_team']), (501, APP_ID, APP_VERSION, APP_TEAM))
        self.assertEqual(set(seed['documents']), {'config.yaml', 'verge.yaml', 'profiles.yaml', 'profiles/' + PROFILE_FILE})
        documents = {key: json.loads(value) for key, value in seed['documents'].items()}
        self.assertEqual(documents['profiles/' + PROFILE_FILE], fixture_config().private_config)
        profile_list = documents['profiles.yaml']
        self.assertEqual(profile_list['current'], PROFILE_UID)
        self.assertEqual(profile_list['items'], [{'uid': PROFILE_UID, 'type': 'local', 'name': 'Guest VPN', 'file': PROFILE_FILE, 'updated': 0, 'option': {'allow_auto_update': False}}])
        self.assertEqual(documents['config.yaml']['mixed-port'], 7897)
        self.assertEqual(documents['config.yaml']['dns'], fixture_config().private_config['dns'])
        self.assertEqual(documents['config.yaml']['external-controller'], '')
        self.assertFalse(documents['config.yaml']['allow-lan'])
        self.assertFalse(documents['config.yaml']['ipv6'])
        self.assertEqual(documents['config.yaml']['log-level'], 'silent')
        self.assertNotIn('proxies', documents['config.yaml'])
        self.assertNotIn('external-controller-unix', documents['config.yaml'])
        self.assertEqual(documents['profiles/' + PROFILE_FILE]['rules'], ['MATCH,PROXY'])
        verge = documents['verge.yaml']
        self.assertTrue(verge['enable_tun_mode'])
        self.assertTrue(verge['enable_system_proxy'])
        for key in ('enable_dns_settings', 'enable_external_controller', 'enable_builtin_enhanced', 'enable_auto_launch', 'auto_check_update', 'auto_backup_on_change'):
            self.assertFalse(verge[key])
        self.assertEqual(verge['profile_dns_settings'], {PROFILE_UID: {'enabled': False}})

    def test_receipts_opt_in_random_and_independent_of_credentials(self):
        one = build_seed(fixture_config())
        two = build_seed(fixture_config(), receipt_enabled=True)
        self.assertFalse(json.loads(one.seed_json)['receipt_enabled'])
        self.assertTrue(json.loads(two.seed_json)['receipt_enabled'])
        self.assertNotEqual(one.receipt_token, two.receipt_token)
        self.assertNotEqual(json.loads(one.seed_json)['seed_id'], json.loads(two.seed_json)['seed_id'])
        for invalid in (1, 'true', None, []):
            with self.assertRaises(GuestVPNSeedError):
                build_seed(fixture_config(), receipt_enabled=invalid)

    def test_unchanged_private_dictionary_accepted_without_mutation(self):
        config = fixture_config().private_config
        before = copy.deepcopy(config)
        with patch('builtins.open', side_effect=AssertionError('no file access')), patch('subprocess.run', side_effect=AssertionError('no process')):
            seed = build_seed(config)
        self.assertEqual(config, before)
        self.assertEqual(json.loads(json.loads(seed.seed_json)['documents']['profiles/' + PROFILE_FILE]), before)

    def test_rejects_mutated_config_and_arbitrary_payloads_sanitized(self):
        mutations = [lambda c: c.update({'rules': ['MATCH,DIRECT']}),
                     lambda c: c['dns'].update({'nameserver': ['8.8.8.8']}),
                     lambda c: c.update({'mixed-port': 7897}),
                     lambda c: c.update({'external-controller': '0.0.0.0:9090'}),
                     lambda c: c['proxies'][0].update({'skip-cert-verify': True}),
                     lambda c: c['proxies'][0].update({'server': '127.0.0.1'}),
                     lambda c: c.update({'script': DUMMY_SECRET})]
        for mutate in mutations:
            config = fixture_config().private_config
            mutate(config)
            with self.assertRaises(GuestVPNSeedError) as caught:
                build_seed(config)
            self.assertNotIn(DUMMY_SECRET, str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
        for value in (None, [], 'private', {}, {'input_mode': 'fields'}):
            with self.assertRaises(GuestVPNSeedError):
                build_seed(value)


@unittest.skipUnless(os.path.isfile('/usr/bin/xcrun'), 'macOS Swift compiler required for fixture tests')
class SwiftFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_root = own_root()
        cls.addClassCleanup(cleanup_own_root, cls.build_root)
        cls.fixture_binary = cls.build_root / 'helper-fixture'
        cls.production_binary = cls.build_root / 'helper-production'
        common = ['/usr/bin/xcrun', 'swiftc', '-parse-as-library', '-module-cache-path', str(cls.build_root / 'module-cache'), str(ROOT / 'GuestVPNBootstrap.swift')]
        for extra, output in ((['-D', 'GOLD_VPN_BOOTSTRAP_FIXTURE'], cls.fixture_binary), ([], cls.production_binary)):
            result = subprocess.run(common + extra + ['-o', str(output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            if result.returncode:
                raise AssertionError('Swift compilation failed:\n' + result.stderr.decode('utf-8', errors='replace'))
        # The production executable is COMPILED ONLY, never executed.

    def setUp(self):
        self.root = own_root()
        self.addCleanup(cleanup_own_root, self.root)
        (self.root / 'home').mkdir(mode=0o700)
        self.plan = build_seed(fixture_config())
        self.seed_path = self.root / 'seed.json'
        self.seed_path.write_bytes(self.plan.seed_json)
        self.seed_path.chmod(0o600)

    def run_fixture(self, success=True, mode='--fixture'):
        result = subprocess.run([str(self.fixture_binary), mode, str(self.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, 0 if success else 2, (result.stdout + result.stderr).decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        self.assertNotIn(DUMMY_SECRET.encode(), result.stdout)
        self.assertNotIn(self.plan.receipt_token.encode(), result.stdout)
        return result

    def rewrite_seed(self, value):
        self.seed_path.write_text(json.dumps(value), encoding='utf-8')
        self.seed_path.chmod(0o600)

    def test_exclusive_import_private_modes_and_json_yaml(self):
        result = self.run_fixture()
        self.assertEqual(result.stdout, b'fixture_imported\n')
        directory = self.root / 'home' / APP_ID
        documents = json.loads(self.plan.seed_json)['documents']
        for name, content in documents.items():
            path = directory / name
            self.assertEqual(path.read_text(), content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertIsInstance(json.loads(path.read_text()), dict)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / 'profiles').stat().st_mode), 0o700)
        status = json.loads((self.root / 'status.json').read_text())
        self.assertEqual(status['configuration'], 'imported')
        self.assertEqual(status['application'], 'not_started_fixture')
        self.assertEqual(status['connection_check'], 'not_run')
        self.assertEqual(status['evidence'], 'guest_reported')
        self.assertFalse(status['host_independently_verified'])

    def test_all_parser_protocols_import_as_private_local_profile(self):
        nodes = []
        for kind in ('tuic', 'vless', 'trojan', 'ss', 'hysteria2'):
            node = {'type': kind, 'server': '8.8.8.8', 'port': 443}
            if kind in ('tuic', 'vless'):
                node['uuid'] = '11111111-2222-4333-8444-555555555555'
            if kind != 'vless':
                node['password'] = DUMMY_SECRET
            if kind == 'vless':
                node.update(tls=True, network='tcp', servername='vpn.example.com')
            elif kind == 'ss':
                node['cipher'] = 'aes-256-gcm'
            else:
                node['sni'] = 'vpn.example.com'
            nodes.append(node)
        config = parse_submission({'input_mode': 'fields', 'nodes': nodes})
        self.plan = build_seed(config)
        self.seed_path.write_bytes(self.plan.seed_json)
        self.run_fixture()
        written = json.loads((self.root / 'home' / APP_ID / 'profiles' / PROFILE_FILE).read_text())
        self.assertEqual(written, config.private_config)

    def test_same_exact_seed_noop_preserves_user_edits_and_status(self):
        self.run_fixture()
        directory = self.root / 'home' / APP_ID
        profile = directory / 'profiles' / PROFILE_FILE
        profile.write_text('user changed their own config')
        status = (self.root / 'status.json').read_bytes()
        result = self.run_fixture()
        self.assertEqual(result.stdout, b'fixture_same_seed_noop\n')
        self.assertEqual(profile.read_text(), 'user changed their own config')
        self.assertEqual((self.root / 'status.json').read_bytes(), status)

    def test_different_seed_never_overwrites_existing_clash(self):
        self.run_fixture()
        profile = self.root / 'home' / APP_ID / 'profiles' / PROFILE_FILE
        previous = profile.read_bytes()
        self.seed_path.write_bytes(build_seed(fixture_config()).seed_json)
        self.run_fixture(success=False)
        self.assertEqual(profile.read_bytes(), previous)

    def test_existing_directory_without_marker_refused(self):
        existing = self.root / 'home' / APP_ID
        existing.mkdir(mode=0o700)
        (existing / 'user-data').write_text('preserve')
        self.run_fixture(success=False)
        self.assertEqual((existing / 'user-data').read_text(), 'preserve')
        self.assertEqual(sorted(path.name for path in existing.iterdir()), ['user-data'])

    def test_existing_symlink_never_followed(self):
        victim = self.root / 'victim'
        victim.mkdir(mode=0o700)
        (victim / 'preserve').write_text('preserve')
        (self.root / 'home' / APP_ID).symlink_to(victim, target_is_directory=True)
        self.run_fixture(success=False)
        self.assertEqual([path.name for path in victim.iterdir()], ['preserve'])

    def test_partial_staging_directory_retained_for_manual_recovery(self):
        seed = json.loads(self.plan.seed_json)
        stage = self.root / 'home' / ('.gold-vpn-import-' + seed['seed_id'])
        stage.mkdir(mode=0o700)
        (stage / 'partial').write_text('preserve')
        self.run_fixture(success=False)
        self.assertEqual((stage / 'partial').read_text(), 'preserve')
        self.assertFalse((self.root / 'home' / APP_ID).exists())

    def test_seed_permissions_and_hardlinks_refused(self):
        self.seed_path.chmod(0o644)
        self.run_fixture(success=False)
        self.seed_path.chmod(0o600)
        os.link(self.seed_path, self.root / 'linked-seed')
        self.run_fixture(success=False)
        self.assertFalse((self.root / 'home' / APP_ID).exists())

    def test_extended_acl_on_own_fixture_seed_is_refused(self):
        # macOS chmod changes ONLY this newly created fixture file's ACL.
        self.assertEqual(self.seed_path.resolve(), self.root / 'seed.json')
        result = subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(self.seed_path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, 'Fixture ACL creation failed')
        self.run_fixture(success=False)
        self.assertFalse((self.root / 'home' / APP_ID).exists())

    def test_seed_symlink_refused_without_reading_target(self):
        # Verify the exact own fixture target before moving it.
        expected = self.root / 'seed.json'
        self.assertEqual(self.seed_path.resolve(), expected)
        target = self.root / 'held-seed'
        self.assertEqual(target.resolve(), self.root / 'held-seed')
        self.assertFalse(target.exists())
        self.seed_path.rename(target)
        self.seed_path.symlink_to(target)
        self.run_fixture(success=False)
        self.assertEqual(target.read_bytes(), self.plan.seed_json)

    def test_wrong_uid_identity_and_unknown_documents_refused(self):
        for key, value in (('expected_uid', 502), ('app_team', 'WRONG'), ('app_version', '9.9.9'),
                           ('app_id', 'wrong.bundle'), ('receipt_token', '../escape'), ('seed_id', '../escape')):
            with self.subTest(key=key):
                seed = json.loads(self.plan.seed_json)
                seed[key] = value
                self.rewrite_seed(seed)
                self.run_fixture(success=False)
        seed = json.loads(self.plan.seed_json)
        seed['documents']['../../escape'] = '{}'
        self.rewrite_seed(seed)
        self.run_fixture(success=False)
        self.assertFalse((self.root / 'home' / APP_ID).exists())

    def test_tampered_policy_controller_dns_and_nodes_refused(self):
        changes = [('profiles/' + PROFILE_FILE, lambda value: value.update({'rules': ['MATCH,DIRECT']})),
                   ('profiles/' + PROFILE_FILE, lambda value: value['proxies'][0].update({'server': '127.0.0.1'})),
                   ('profiles/' + PROFILE_FILE, lambda value: value['proxies'][0].update({'skip-cert-verify': True})),
                   ('profiles/' + PROFILE_FILE, lambda value: value['proxies'][0].update({'plugin': 'dummy'})),
                   ('config.yaml', lambda value: value.update({'external-controller': '0.0.0.0:9090'})),
                   ('config.yaml', lambda value: value['dns'].update({'nameserver': ['8.8.8.8']})),
                   ('verge.yaml', lambda value: value.update({'enable_dns_settings': True})),
                   ('profiles.yaml', lambda value: value['items'][0].update({'url': 'https://example.com/dummy'}))]
        for filename, change in changes:
            with self.subTest(filename=filename):
                seed = json.loads(self.plan.seed_json)
                document = json.loads(seed['documents'][filename])
                change(document)
                seed['documents'][filename] = json.dumps(document)
                self.rewrite_seed(seed)
                self.run_fixture(success=False)
        self.assertFalse((self.root / 'home' / APP_ID).exists())

    def test_private_receipt_contains_only_constant_fields(self):
        (self.root / 'receipt').mkdir(mode=0o700)
        self.plan = build_seed(fixture_config(), receipt_enabled=True)
        self.seed_path.write_bytes(self.plan.seed_json)
        self.run_fixture()
        path = self.root / 'receipt' / (self.plan.receipt_token + '.json')
        value = json.loads(path.read_text())
        self.assertEqual(set(value), {'schema_version', 'evidence', 'configuration', 'application', 'system_authorization', 'connection_check', 'host_independently_verified'})
        for private in (DUMMY_SECRET, '8.8.8.8', 'vpn.example.com', self.plan.receipt_token, json.loads(self.plan.seed_json)['seed_id']):
            self.assertNotIn(private, path.read_text())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(value['connection_check'], 'not_run')

    def test_receipt_share_not_created_or_written_without_opt_in(self):
        (self.root / 'receipt').mkdir(mode=0o700)
        self.run_fixture()
        self.assertEqual(list((self.root / 'receipt').iterdir()), [])

    def test_standard_applications_exception_uses_synthetic_metadata_only(self):
        result = self.run_fixture(mode='--fixture-applications-policy')
        self.assertEqual(result.stdout, b'fixture_applications_policy_ok\n')
        # Swift checks exact path/root/admin80/0775 plus wrong path, owners,
        # groups, other-write, special bits and symlink type without host reads.
        self.assertEqual(list((self.root / 'home').iterdir()), [])
        self.assertFalse((self.root / 'status.json').exists())

    def test_missing_fixed_application_support_is_created_privately(self):
        library = self.root / 'home' / 'Library'
        library.mkdir(mode=0o755)
        before = stat.S_IMODE(library.stat().st_mode)
        self.run_fixture(mode='--fixture-user-library')
        support = library / 'Application Support'
        self.assertEqual(stat.S_IMODE(support.stat().st_mode), 0o700)
        self.assertEqual(support.stat().st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(library.stat().st_mode), before)
        self.assertTrue((support / APP_ID / 'profiles' / PROFILE_FILE).is_file())
        self.assertEqual([path.name for path in library.iterdir()], ['Application Support'])

    def test_existing_trusted_application_support_keeps_its_mode(self):
        library = self.root / 'home' / 'Library'
        library.mkdir(mode=0o755)
        support = library / 'Application Support'
        support.mkdir(mode=0o755)
        support.chmod(0o755)
        (support / 'unrelated').write_text('preserve')
        self.run_fixture(mode='--fixture-user-library')
        self.assertEqual(stat.S_IMODE(support.stat().st_mode), 0o755)
        self.assertEqual((support / 'unrelated').read_text(), 'preserve')
        self.assertTrue((support / APP_ID).is_dir())

    def test_existing_writable_application_support_is_not_repaired(self):
        library = self.root / 'home' / 'Library'
        library.mkdir(mode=0o700)
        support = library / 'Application Support'
        support.mkdir(mode=0o700)
        support.chmod(0o775)
        self.run_fixture(success=False, mode='--fixture-user-library')
        self.assertEqual(stat.S_IMODE(support.stat().st_mode), 0o775)
        self.assertEqual(list(support.iterdir()), [])

    def test_application_support_symlink_is_not_followed_or_replaced(self):
        library = self.root / 'home' / 'Library'
        library.mkdir(mode=0o700)
        victim = self.root / 'victim'
        victim.mkdir(mode=0o700)
        (victim / 'preserve').write_text('preserve')
        support = library / 'Application Support'
        support.symlink_to(victim, target_is_directory=True)
        self.run_fixture(success=False, mode='--fixture-user-library')
        self.assertTrue(support.is_symlink())
        self.assertEqual([path.name for path in victim.iterdir()], ['preserve'])

    def test_application_support_regular_file_is_not_replaced(self):
        library = self.root / 'home' / 'Library'
        library.mkdir(mode=0o700)
        support = library / 'Application Support'
        support.write_text('preserve')
        self.run_fixture(success=False, mode='--fixture-user-library')
        self.assertEqual(support.read_text(), 'preserve')

    def test_missing_library_parent_is_never_created(self):
        self.run_fixture(success=False, mode='--fixture-user-library')
        self.assertFalse((self.root / 'home' / 'Library').exists())
        self.assertEqual(list((self.root / 'home').iterdir()), [])

    def test_writable_library_parent_is_not_repaired(self):
        library = self.root / 'home' / 'Library'
        library.mkdir(mode=0o700)
        library.chmod(0o775)
        self.run_fixture(success=False, mode='--fixture-user-library')
        self.assertEqual(stat.S_IMODE(library.stat().st_mode), 0o775)
        self.assertFalse((library / 'Application Support').exists())

    def test_library_parent_symlink_is_never_followed(self):
        victim = self.root / 'victim'
        victim.mkdir(mode=0o700)
        library = self.root / 'home' / 'Library'
        library.symlink_to(victim, target_is_directory=True)
        self.run_fixture(success=False, mode='--fixture-user-library')
        self.assertTrue(library.is_symlink())
        self.assertEqual(list(victim.iterdir()), [])

    def test_fixture_cli_refuses_arbitrary_root(self):
        result = subprocess.run([str(self.fixture_binary), '--fixture', '/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'fixture_failure:unsafe_path_or_permissions\n')
        self.assertEqual(result.stderr, b'')


if __name__ == '__main__':
    unittest.main()
