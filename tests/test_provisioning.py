"""Isolated synthetic data only. Never invoke Tart, network, mount, or install."""
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import provisioning as p
import protected_launcher as launcher


SECRET = 'SYNTHETIC-SECRET-NEVER-LOG'


def profile():
    return {'secret': 'host-controller-secret', 'rules': ['MATCH,DIRECT'],
            'proxy-providers': {'untrusted': {'url': 'https://invalid.invalid'}},
            'proxies': [
                {'name': 'host-private-name', 'type': 'tuic', 'server': '8.8.8.8', 'port': 443,
                 'uuid': SECRET, 'password': SECRET, 'sni': 'example.com', 'alpn': ['h3'],
                 'udp': True, 'skip-cert-verify': True},
                {'name': 'vless', 'type': 'vless', 'server': '1.1.1.1', 'port': 8443,
                 'uuid': SECRET, 'network': 'tcp', 'tls': True, 'udp': True,
                 'servername': 'example.com', 'reality-opts': {'public-key': SECRET, 'short-id': ''}},
            ]}


class ProfileTests(unittest.TestCase):
    def test_minimal_config_no_host_preferences_or_direct_fallback(self):
        config, endpoints, warnings = p.build_guest_profile(profile())
        self.assertEqual(config['rules'], ['MATCH,PROXY'])
        self.assertNotIn('proxy-providers', config)
        self.assertTrue(config['tun']['strict-route'])
        self.assertTrue(config['tun']['dns-hijack'])
        self.assertFalse(config['ipv6'])
        self.assertEqual(config['dns']['nameserver'], ['https://1.1.1.1/dns-query#PROXY'])
        self.assertEqual(config['external-controller'], '127.0.0.1:9090')
        self.assertNotIn('host-private-name', json.dumps(config))
        self.assertNotEqual(config['secret'], 'host-controller-secret')
        self.assertEqual(endpoints, [('tcp', '1.1.1.1', 8443), ('udp', '8.8.8.8', 443)])
        self.assertEqual(len(warnings), 1)
        self.assertNotIn(SECRET, json.dumps(warnings))

    def test_controller_secret_fresh_every_time(self):
        self.assertNotEqual(p.build_guest_profile(profile())[0]['secret'],
                            p.build_guest_profile(profile())[0]['secret'])

    def test_unreviewed_options_and_endpoints_fail_without_secrets(self):
        edits = [('server', 'localhost'), ('server', '127.0.0.1'), ('server', '192.168.1.1'),
                 ('server', '224.0.0.1'), ('server', '::1'), ('port', 53), ('port', True),
                 ('dialer-proxy', SECRET), ('type', 'http'), ('udp', SECRET)]
        for key, value in edits:
            with self.subTest(key=key, value=value):
                bad = profile()
                bad['proxies'][0][key] = value
                with self.assertRaises(p.ProvisioningError) as caught:
                    p.build_guest_profile(bad)
                self.assertNotIn(SECRET, str(caught.exception))

    def test_vless_only_tls_tcp(self):
        for field, value in [('tls', False), ('network', 'ws'), ('reality-opts', {'evil': SECRET})]:
            bad = profile()
            bad['proxies'][1][field] = value
            with self.assertRaises(p.ProvisioningError):
                p.build_guest_profile(bad)


class YamlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()

    def yaml(self, text):
        path = self.base / 'input.yaml'
        path.write_text(text)
        path.chmod(0o600)
        return p._safe_yaml(path)

    def test_ruby_safe_load_supports_plain_yaml(self):
        self.assertEqual(self.yaml('a: 1\nb: [true, text]\n'), {'a': 1, 'b': [True, 'text']})

    def test_alias_duplicate_and_object_tags_rejected_without_payload(self):
        for text in ('a: &a [1]\nb: *a\n', 'a: first\na: ' + SECRET,
                     '--- !ruby/object:Object\nx: ' + SECRET, 'a: [invalid ' + SECRET):
            with self.subTest(text=text):
                with self.assertRaises(p.ProvisioningError) as caught:
                    self.yaml(text)
                self.assertNotIn(SECRET, str(caught.exception))

    def test_yaml_symlink_rejected(self):
        source = self.base / 'real.yaml'
        source.write_text('a: 1')
        link = self.base / 'link.yaml'
        link.symlink_to(source)
        with self.assertRaises(p.ProvisioningError):
            p._safe_yaml(link)

    def test_active_profile_path_traversal_rejected(self):
        with mock.patch.object(p, '_safe_yaml', return_value={'current': 'x', 'items': [
                {'uid': 'x', 'type': 'local', 'file': '../../secret.yaml'}]}):
            with self.assertRaises(p.ProvisioningError):
                p._active_profile()


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.source = self.root / 'network'
        self.source.mkdir(mode=0o700)
        self.cache = self.root / 'cache'
        self.cache.mkdir(mode=0o700)
        self.core = self.root / 'mihomo'
        self.core.write_bytes(b'synthetic-core-not-executable')
        self.dmg = self.cache / p.CCBAGA_NAME
        self.dmg.write_bytes(b'synthetic-dmg-not-mountable')
        for name in ('packet_policy.py', 'gvproxy-darwin'):
            (self.source / name).write_bytes(('synthetic-' + name).encode())
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'macAddress': '02:aa:bb:cc:dd:ee', 'ecid': 'FAKE_BASE64='}))
        self.config.chmod(0o600)
        self.base = self.root / 'environment'
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for key, value in {
            'NETWORK_SOURCE': self.source,
            'PACKET_SHA256': hashlib.sha256((self.source / 'packet_policy.py').read_bytes()).hexdigest(),
            'GV_SHA256': hashlib.sha256((self.source / 'gvproxy-darwin').read_bytes()).hexdigest(),
            'MIHOMO_SHA256': hashlib.sha256(self.core.read_bytes()).hexdigest(),
            'CCBAGA_SHA256': hashlib.sha256(self.dmg.read_bytes()).hexdigest(),
        }.items():
            self.stack.enter_context(mock.patch.object(p, key, value))
        self.stack.enter_context(mock.patch.object(p, 'preflight', return_value={'ready': True}))
        self.stack.enter_context(mock.patch.object(p, '_active_profile', side_effect=lambda: p.build_guest_profile(profile())))
        self.stack.enter_context(mock.patch.object(p, '_artifacts', return_value={p.CCBAGA_NAME: self.dmg, 'mihomo': self.core}))
        # A guard against accidentally introducing process/network lifecycle work.
        self.no_process = self.stack.enter_context(mock.patch.object(p.subprocess, 'Popen', side_effect=AssertionError('No process may launch')))

    def prepare(self, name='新机 测试'):
        return p.prepare_environment(name, self.config, self.base, self.cache)

    def test_private_payload_and_sanitized_return(self):
        result = self.prepare()
        self.assertEqual(result['status'], 'awaiting_user_setup')
        self.assertNotIn(SECRET, json.dumps(result))
        meta = json.loads((self.base / 'environment.json').read_text())
        self.assertEqual(meta['vm_config'], str(p.VM_ROOT / '新机 测试' / 'config.json'))
        self.assertNotEqual(meta['vm_config'], str(self.config))
        self.assertNotIn(SECRET, json.dumps(meta))
        self.assertEqual(meta['ecid'], 'FAKE_BASE64=')
        self.assertEqual(json.loads((self.base / 'policy.json').read_text())['guest_mac'], '02:aa:bb:cc:dd:ee')
        for path in self.base.rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
        private_payload = json.loads((self.base / 'setup/config.json').read_text())
        self.assertEqual(private_payload['proxies'][0]['password'], SECRET)
        self.no_process.assert_not_called()
        with mock.patch.object(launcher, 'BASE', self.base):
            self.assertEqual(launcher.validate_environment()['vm_name'], '新机 测试')

    def test_never_overwrites_existing_environment(self):
        self.prepare()
        before = (self.base / 'setup/config.json').read_bytes()
        with self.assertRaises(p.ProvisioningError):
            self.prepare()
        self.assertEqual((self.base / 'setup/config.json').read_bytes(), before)

    def test_invalid_name_and_identity_fail_before_output(self):
        for name in ('../escape', '-flag', 'bad:name', 'with.dot', ' name'):
            with self.assertRaises(p.ProvisioningError):
                self.prepare(name)
            self.assertFalse(self.base.exists())
        for mac in ('01:00:00:00:00:01', '00:00:00:00:00:00', '5a:94:ef:e4:0c:dd', SECRET):
            self.config.write_text(json.dumps({'macAddress': mac, 'ecid': 'x'}))
            with self.assertRaises(p.ProvisioningError) as caught:
                self.prepare()
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertFalse(self.base.exists())

    def test_symlink_and_nonprivate_destination_rejected(self):
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        self.base.symlink_to(target)
        with self.assertRaises(p.ProvisioningError):
            self.prepare()
        self.assertEqual(list(target.iterdir()), [])

    def test_tampered_payload_fails_launcher_validation(self):
        self.prepare()
        payload = self.base / 'setup/config.json'
        payload.write_text('{}')
        with mock.patch.object(launcher, 'BASE', self.base):
            with self.assertRaisesRegex(RuntimeError, 'integrity'):
                launcher.validate_environment()

    def test_wrong_source_digest_fails_closed(self):
        with mock.patch.object(p, 'PACKET_SHA256', '0' * 64):
            with self.assertRaisesRegex(p.ProvisioningError, 'digest'):
                self.prepare()
        self.no_process.assert_not_called()

    def test_policy_permissions_fail_launcher_validation(self):
        self.prepare()
        (self.base / 'policy.json').chmod(0o644)
        with mock.patch.object(launcher, 'BASE', self.base):
            with self.assertRaisesRegex(RuntimeError, 'private'):
                launcher.validate_environment()


class LauncherTests(unittest.TestCase):
    def test_argv_always_has_fence_and_readonly_setup_never_suspend(self):
        plan = mock.Mock(shares=[], arguments=['--dir=data:/safe/path:ro'], suspendable=True)
        command = launcher.build_tart_command('新机 测试', 42, plan, True)
        self.assertEqual(command[2], '新机 测试')
        self.assertIn('--net-fd=42', command)
        self.assertIn('--dir=setup:' + str(launcher.BASE / 'setup') + ':ro', command)
        self.assertIn('--dir=data:/safe/path:ro', command)
        self.assertIn('--no-graphics', command)
        self.assertNotIn('--suspendable', command)
        self.assertFalse(any('nat' in word.lower() for word in command))

    def test_setup_share_name_is_reserved(self):
        with self.assertRaises(RuntimeError):
            launcher.build_tart_command('vm', 42, mock.Mock(shares=[{'name': 'SETUP'}], arguments=[]))


if __name__ == '__main__':
    unittest.main()
