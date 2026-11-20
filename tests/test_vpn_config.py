"""Fixture-only tests: no real resolver, host profiles, VM, disk or app actions.

The only unmocked executable is system Ruby on explicit dummy YAML strings.
No temporary directory is created or destructively cleaned up.
"""
import base64
import copy
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import Mock, patch

import vpn_config as vpn

DUMMY_UUID = '11111111-2222-4333-8444-555555555555'
DUMMY_PASSWORD = 'dummy-test-secret-not-a-real-credential'
DUMMY_KEY = base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip('=')


def node(kind='trojan', **overrides):
    value = {'type': kind, 'server': '8.8.8.8', 'port': 443}
    if kind in ('tuic', 'trojan', 'hysteria2'):
        value.update(password=DUMMY_PASSWORD, sni='vpn.example.com')
    if kind in ('tuic', 'vless'):
        value['uuid'] = DUMMY_UUID
    if kind == 'vless':
        value.update(tls=True, network='tcp', servername='vpn.example.com')
    if kind == 'ss':
        value.update(cipher='aes-128-gcm', password=DUMMY_PASSWORD)
    value.update(overrides)
    return value


def fields(*nodes, resolver=None):
    return vpn.parse_submission({'input_mode': 'fields', 'nodes': list(nodes)}, resolver=resolver)


def imported(profile, resolver=None):
    result = subprocess.CompletedProcess([], 0, json.dumps(profile).encode(), None)
    with patch.object(vpn.subprocess, 'run', return_value=result):
        return vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': '# explicit dummy YAML'}, resolver=resolver)


class FieldContractTests(unittest.TestCase):
    def assertInvalid(self, raw, text=None):
        with self.assertRaises(vpn.VPNConfigurationError) as caught:
            fields(raw)
        if text:
            self.assertIn(text, str(caught.exception))
        self.assertNotIn(DUMMY_PASSWORD, str(caught.exception))
        return caught.exception

    def test_all_supported_protocols_and_transports(self):
        config = fields(*(node(kind) for kind in vpn.SUPPORTED_TYPES))
        self.assertEqual(config.summary['node_count'], 5)
        self.assertEqual(config.summary['protocols'], list(vpn.SUPPORTED_TYPES))
        self.assertEqual(config.endpoints, (('tcp', '8.8.8.8', 443), ('udp', '8.8.8.8', 443)))
        self.assertEqual(config.summary['endpoint_count'], 2)
        self.assertEqual(len(config.private_config['proxies']), 5)

    def test_fields_never_launch_ruby_read_files_or_resolve_implicitly(self):
        with patch.object(vpn.subprocess, 'run', side_effect=AssertionError('no executable')) as run, \
                patch('builtins.open', side_effect=AssertionError('no files')) as opened, \
                patch.object(socket, 'getaddrinfo', side_effect=AssertionError('no DNS')) as dns:
            self.assertEqual(fields(node()).summary['node_count'], 1)
            self.assertInvalid(node(server='vpn.example.com'), 'caller-supplied resolver')
        run.assert_not_called()
        opened.assert_not_called()
        dns.assert_not_called()

    def test_result_frozen_and_repr_redacted(self):
        result = fields(node(name='secret-user-node'))
        self.assertEqual(repr(result), 'VPNConfiguration(<redacted>)')
        self.assertEqual(str(result), 'VPNConfiguration(<redacted>)')
        with self.assertRaises(FrozenInstanceError):
            result.private_config = {}
        with self.assertRaises(FrozenInstanceError):
            result.endpoints = ()
        summary = json.dumps(result.summary)
        for secret in ('secret-user-node', DUMMY_PASSWORD, '8.8.8.8', 'vpn.example.com', DUMMY_UUID):
            self.assertNotIn(secret, summary)
        self.assertEqual(set(result.summary), {'node_count', 'endpoint_count', 'protocols', 'warnings', 'normalization_required'})

    def test_canonical_private_json_and_determinism(self):
        result = fields(node('tuic'))
        self.assertEqual(json.loads(result.private_json), result.private_config)
        self.assertEqual(result.private_json, fields(node('tuic')).private_json)
        self.assertEqual(result.private_json, json.dumps(result.private_config, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
        self.assertIn(DUMMY_PASSWORD, result.private_json)

    def test_owned_policy_has_no_direct_route_or_controller(self):
        result = fields(node())
        config = result.private_config
        self.assertEqual(config['external-controller'], '')
        self.assertNotIn('secret', config)
        self.assertFalse(config['allow-lan'])
        self.assertFalse(config['ipv6'])
        self.assertEqual(config['bind-address'], '127.0.0.1')
        self.assertEqual(config['log-level'], 'silent')
        self.assertEqual(config['rules'], ['MATCH,PROXY'])
        self.assertEqual(config['proxy-groups'], [{'name': 'PROXY', 'type': 'select', 'proxies': ['proxy-1']}])
        self.assertTrue(config['tun']['enable'])
        self.assertTrue(config['tun']['strict-route'])
        self.assertEqual(config['tun']['dns-hijack'], ['any:53', 'tcp://any:53'])
        self.assertEqual(config['profile'], {'store-selected': False, 'store-fake-ip': False})
        dns = config['dns']
        self.assertFalse(dns['use-hosts'])
        self.assertFalse(dns['use-system-hosts'])
        self.assertFalse(dns['ipv6'])
        for key in ('nameserver', 'default-nameserver', 'proxy-server-nameserver'):
            self.assertEqual(dns[key], ['https://1.1.1.1/dns-query#PROXY'])
        self.assertEqual(dns['fallback'], [])
        self.assertEqual(dns['direct-nameserver'], [])

    def test_input_is_not_mutated_or_referenced(self):
        raw = node('vless', **{'reality-opts': {'public-key': DUMMY_KEY, 'short-id': 'Ab01'}, 'alpn': ['h2']})
        original = copy.deepcopy(raw)
        result = fields(raw)
        self.assertEqual(raw, original)
        raw['alpn'].append('http/1.1')
        raw['reality-opts']['short-id'] = 'ff'
        self.assertEqual(result.private_config['proxies'][0]['alpn'], ['h2'])
        self.assertEqual(result.private_config['proxies'][0]['reality-opts']['short-id'], 'ab01')

    def test_payload_shape_and_mode_are_strict(self):
        payloads = [None, [], {}, {'input_mode': []}, {'input_mode': 'url'},
                    {'input_mode': 'fields', 'nodes': [node()], 'secret': 'dummy'},
                    {'input_mode': 'fields'}, {'input_mode': 'yaml'},
                    {'input_mode': 'yaml', 'yaml_text': 'dummy', 'path': '/dummy'},
                    {'input_mode': 'fields', 'nodes': node()}]
        for payload in payloads:
            with self.subTest(payload_type=type(payload).__name__), self.assertRaises(vpn.VPNConfigurationError):
                vpn.parse_submission(payload)

    def test_one_to_sixteen_nodes(self):
        for count in (0, 17):
            with self.subTest(count=count), self.assertRaises(vpn.VPNConfigurationError):
                fields(*(node() for _ in range(count)))
        self.assertEqual(fields(*(node() for _ in range(16))).summary['node_count'], 16)

    def test_protocol_names_are_explicit(self):
        for kind in ('vmess', 'hysteria', 'ssr', 'socks5', 'wireguard', 'TUIC', '', None, [], 1):
            with self.subTest(kind=kind):
                self.assertInvalid(node(type=kind))

    def test_names_rewritten_and_warning_contains_no_name(self):
        result = fields(node(name='private-name'))
        self.assertEqual(result.private_config['proxies'][0]['name'], 'proxy-1')
        self.assertTrue(result.summary['normalization_required'])
        self.assertNotIn('private-name', json.dumps(result.summary))
        self.assertFalse(fields(node()).summary['normalization_required'])

    def test_unknown_node_options_rejected(self):
        for option in ('plugin', 'ws-opts', 'grpc-opts', 'dialer-proxy', 'interface-name', 'routing-mark', 'fingerprint', 'ports'):
            with self.subTest(option=option):
                self.assertInvalid(node(**{option: 'dummy'}))

    def test_ports_must_be_typed_non_dns_ports(self):
        for port in (None, '443', True, 0, -1, 53, 65536, 1.5):
            with self.subTest(port=port):
                self.assertInvalid(node(port=port))
        for port in (1, 65535):
            self.assertEqual(fields(node(port=port)).endpoints[0][2], port)

    def test_private_special_and_non_ipv4_endpoints_rejected(self):
        addresses = ['0.0.0.0', '0.1.2.3', '10.0.0.1', '127.0.0.1', '169.254.169.254',
                     '172.16.0.1', '192.168.1.1', '100.64.1.1', '192.0.0.9', '192.88.99.1',
                     '192.0.2.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1',
                     '240.0.0.1', '255.255.255.255', '::1', '2001:4860:4860::8888',
                     '::ffff:8.8.8.8', '008.008.008.008', '8.8.8.999', '134744072', '0x08080808']
        for address in addresses:
            with self.subTest(address=address):
                self.assertInvalid(node(server=address))

    def test_boolean_options_are_not_truthy_strings_or_numbers(self):
        for key in ('udp', 'skip-cert-verify'):
            for value in ('false', 'true', 0, 1, None):
                with self.subTest(key=key, value=value):
                    self.assertInvalid(node(**{key: value}))
        for value in (1, 'false', None):
            self.assertInvalid(node('tuic', **{'reduce-rtt': value}))
            self.assertInvalid(node('tuic', **{'disable-sni': value}))

    def test_no_insecure_tls_or_disabled_sni(self):
        for kind in ('tuic', 'trojan', 'vless', 'hysteria2'):
            with self.subTest(kind=kind):
                self.assertInvalid(node(kind, **{'skip-cert-verify': True}), 'Insecure TLS')
                self.assertFalse(fields(node(kind)).private_config['proxies'][0]['skip-cert-verify'])
        self.assertInvalid(node('tuic', **{'disable-sni': True}), 'Insecure TLS')

    def test_tls_required_and_only_tcp_for_vless_trojan(self):
        for kind in ('vless', 'trojan'):
            for value in (False, 'true', 1, None):
                with self.subTest(kind=kind, tls=value):
                    self.assertInvalid(node(kind, tls=value))
            for transport in ('ws', 'grpc', 'h2', 'udp', None, 1):
                self.assertInvalid(node(kind, network=transport), 'Only TCP')
        raw = node('vless')
        del raw['tls']
        self.assertInvalid(raw, 'TLS is required')

    def test_uuid_validation(self):
        for kind in ('tuic', 'vless'):
            for value in ('', 'placeholder', DUMMY_UUID.replace('-', ''), '{' + DUMMY_UUID + '}',
                          '00000000-0000-0000-0000-000000000000', 12, None):
                with self.subTest(kind=kind, value=value):
                    self.assertInvalid(node(kind, uuid=value))
        raw = node('vless', uuid=DUMMY_UUID.upper())
        self.assertEqual(fields(raw).private_config['proxies'][0]['uuid'], DUMMY_UUID)

    def test_passwords_require_nonempty_plain_text(self):
        for kind in ('tuic', 'trojan', 'ss', 'hysteria2'):
            for value in ('', None, 123, False, ['dummy'], 'bad\nline', 'bad\x00', 'x' * 4097):
                with self.subTest(kind=kind, value_type=type(value).__name__):
                    self.assertInvalid(node(kind, password=value))
        self.assertEqual(fields(node(password='dummy Unicode 密码')).summary['node_count'], 1)

    def test_alpn_and_browser_fingerprints_are_typed(self):
        raw = node('vless', alpn=['h2', 'http/1.1'], **{'client-fingerprint': 'chrome'})
        self.assertEqual(fields(raw).private_config['proxies'][0]['alpn'], ['h2', 'http/1.1'])
        for alpn in ('h2', [], [1], [''], ['h2'] * 9, ['a b'], ['x' * 33]):
            self.assertInvalid(node(alpn=alpn))
        for value in ('random', 'unknown', 1, None, []):
            self.assertInvalid(node(**{'client-fingerprint': value}))

    def test_tls_names_are_safe_names_or_public_ipv4(self):
        for value in ('localhost', 'x.local', 'bad name.example.com', 'https://example.com',
                      'example.com/path', '*.example.com', '127.0.0.1', '::1', '', None):
            with self.subTest(value=value):
                self.assertInvalid(node(sni=value))
        raw = node()
        del raw['sni']
        self.assertEqual(fields(raw).private_config['proxies'][0]['sni'], '8.8.8.8')

    def test_tuic_typed_options(self):
        raw = node('tuic', **{'congestion-controller': 'bbr', 'udp-relay-mode': 'native',
                             'reduce-rtt': False, 'request-timeout': 8000,
                             'heartbeat-interval': 10000, 'max-udp-relay-packet-size': 1500})
        self.assertEqual(fields(raw).endpoints, (('udp', '8.8.8.8', 443),))
        for key, value in (('congestion-controller', 'invalid'), ('udp-relay-mode', 'invalid'),
                           ('request-timeout', '8000'), ('request-timeout', 999),
                           ('heartbeat-interval', 120001), ('max-udp-relay-packet-size', 65508)):
            self.assertInvalid(node('tuic', **{key: value}))

    def test_vless_reality_strict_key_short_id_and_defaults(self):
        for short_id in ('', '00', 'abcdef0123456789'):
            raw = node('vless', **{'reality-opts': {'public-key': DUMMY_KEY, 'short-id': short_id}})
            config = fields(raw).private_config['proxies'][0]
            self.assertEqual(config['client-fingerprint'], 'chrome')
            self.assertEqual(config['reality-opts']['short-id'], short_id)
        invalid = [None, {}, {'public-key': DUMMY_KEY},
                   {'public-key': DUMMY_KEY, 'short-id': '0'},
                   {'public-key': DUMMY_KEY, 'short-id': 'gg'},
                   {'public-key': DUMMY_KEY, 'short-id': 'ab' * 9},
                   {'public-key': DUMMY_KEY, 'short-id': 12},
                   {'public-key': DUMMY_KEY + '=', 'short-id': ''},
                   {'public-key': 'A' * 43, 'short-id': ''},
                   {'public-key': DUMMY_KEY, 'short-id': '', 'extra': 'dummy'}]
        for reality in invalid:
            with self.subTest(reality_type=type(reality).__name__):
                self.assertInvalid(node('vless', **{'reality-opts': reality}))

    def test_vless_flow_and_packet_encoding(self):
        raw = node('vless', flow='xtls-rprx-vision', **{'packet-encoding': 'xudp'})
        self.assertEqual(fields(raw).private_config['proxies'][0]['flow'], 'xtls-rprx-vision')
        self.assertInvalid(node('vless', flow='xtls-rprx-direct'))
        self.assertInvalid(node('vless', **{'packet-encoding': 'packetaddr'}))

    def test_shadowsocks_only_reviewed_aead_and_explicit_udp_fence(self):
        for cipher in vpn.SUPPORTED_SS_CIPHERS:
            self.assertEqual(len(fields(node('ss', cipher=cipher)).endpoints), 2)
        self.assertEqual(fields(node('ss', udp=False)).endpoints, (('tcp', '8.8.8.8', 443),))
        for cipher in ('none', 'rc4-md5', 'aes-256-cfb', '2022-blake3-aes-128-gcm', '', None):
            self.assertInvalid(node('ss', cipher=cipher))

    def test_hysteria2_obfs_and_bandwidth(self):
        raw = node('hysteria2', up=100, down=200, obfs='salamander', **{'obfs-password': 'dummy-obfs'})
        self.assertEqual(fields(raw).endpoints, (('udp', '8.8.8.8', 443),))
        for options in ({'up': '100 Mbps'}, {'down': True}, {'up': 0}, {'down': 100001},
                        {'obfs': 'salamander'}, {'obfs-password': 'dummy'},
                        {'obfs': 'unknown', 'obfs-password': 'dummy'}):
            self.assertInvalid(node('hysteria2', **options))

    def test_plain_json_only_and_bounded_structure(self):
        for extra in (1.5, float('nan'), b'dummy', set(), object(), 2 ** 64):
            self.assertInvalid(node(password=extra))
        cyclical = []
        cyclical.append(cyclical)
        with self.assertRaises(vpn.VPNConfigurationError):
            vpn.parse_submission({'input_mode': 'fields', 'nodes': cyclical})
        shared = node()
        with self.assertRaises(vpn.VPNConfigurationError):
            fields(shared, shared)
        deep = {}
        for _ in range(20):
            deep = {'nested': deep}
        self.assertInvalid(node(extra=deep))
        self.assertInvalid(node(extra=[None] * 8193))
        huge = {str(i): 'x' * 4096 for i in range(70)}
        self.assertInvalid(node(extra=huge))
        self.assertInvalid(node(password='\ud800'))
        self.assertInvalid(node(**{'<<': 'dummy'}))
        with self.assertRaises(vpn.VPNConfigurationError):
            fields({1: 'dummy'})


class ResolverTests(unittest.TestCase):
    def test_domains_pin_deterministically_and_preserve_default_sni(self):
        resolve = Mock(return_value=['8.8.8.8', '1.1.1.1'])
        raw = node(server='VPN.Example.com')
        del raw['sni']
        result = fields(raw, resolver=resolve)
        resolve.assert_called_once_with('vpn.example.com')
        config = result.private_config['proxies'][0]
        self.assertEqual(config['server'], '1.1.1.1')
        self.assertEqual(config['sni'], 'vpn.example.com')
        self.assertEqual(result.endpoints, (('tcp', '1.1.1.1', 443),))
        self.assertTrue(result.summary['normalization_required'])
        self.assertNotIn('vpn.example.com', json.dumps(result.summary))

    def test_domains_preserve_explicit_sni_all_tls_types(self):
        for kind in ('tuic', 'vless', 'trojan', 'hysteria2'):
            with self.subTest(kind=kind):
                result = fields(node(kind, server='endpoint.example.com'), resolver=lambda _: ['1.1.1.1'])
                key = 'servername' if kind == 'vless' else 'sni'
                self.assertEqual(result.private_config['proxies'][0][key], 'vpn.example.com')

    def test_resolver_cached_per_submission_not_globally(self):
        resolve = Mock(return_value=['8.8.8.8'])
        fields(node(server='vpn.example.com'), node('tuic', server='VPN.example.com'), resolver=resolve)
        self.assertEqual(resolve.call_count, 1)
        fields(node(server='vpn.example.com'), resolver=resolve)
        self.assertEqual(resolve.call_count, 2)

    def test_literal_endpoint_never_calls_resolver(self):
        resolve = Mock(side_effect=AssertionError('unexpected'))
        fields(node(), resolver=resolve)
        resolve.assert_not_called()

    def test_mixed_private_invalid_and_unbounded_answers_rejected(self):
        answers = [['8.8.8.8', '10.0.0.1'], ['8.8.8.8', '::1'], ['8.8.8.8', '192.0.2.1'],
                   ['8.8.8.8', 134744072], ['vpn.example.com'], [], ['8.8.8.8'] * 17,
                   '8.8.8.8', None, {'8.8.8.8'}, iter(['8.8.8.8'])]
        for response in answers:
            with self.subTest(response_type=type(response).__name__), self.assertRaises(vpn.VPNConfigurationError):
                fields(node(server='vpn.example.com'), resolver=lambda _: response)

    def test_resolver_errors_are_constant_and_secret_free(self):
        resolve = Mock(side_effect=RuntimeError(DUMMY_PASSWORD))
        with self.assertRaises(vpn.VPNConfigurationError) as caught:
            fields(node(server='vpn.example.com'), resolver=resolve)
        self.assertEqual(str(caught.exception), 'Proxy hostname resolution failed')
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_hostname_validation_precedes_resolver(self):
        for hostname in ('localhost', 'foo.local', 'foo.test', 'foo.invalid', 'foo.onion',
                         '-bad.example.com', 'bad-.example.com', 'bad..example.com',
                         'user@example.com', 'https://example.com', 'example.com.',
                         '☃.example.com', 'a' * 64 + '.example.com'):
            resolve = Mock(return_value=['8.8.8.8'])
            with self.subTest(hostname=hostname), self.assertRaises(vpn.VPNConfigurationError):
                fields(node(server=hostname), resolver=resolve)
            resolve.assert_not_called()


class YAMLAdapterTests(unittest.TestCase):
    def test_equivalence_of_fields_and_yaml_nodes(self):
        raw = node('tuic')
        self.assertEqual(fields(raw), imported({'proxies': [raw]}))

    def test_full_upload_is_normalized_with_fixed_warnings(self):
        profile = {'proxies': [node(name='do-not-disclose')],
                   'rules': ['MATCH,DIRECT'], 'dns': {'nameserver': ['8.8.4.4']},
                   'tun': {'enable': False}, 'external-controller': '0.0.0.0:9090',
                   'secret': DUMMY_PASSWORD, 'proxy-groups': [{'name': 'private-group', 'type': 'select', 'proxies': ['DIRECT']}],
                   'allow-lan': True, 'ipv6': True, 'log-level': 'debug',
                   'profile': {'store-selected': True}}
        original = copy.deepcopy(profile)
        result = imported(profile)
        self.assertEqual(profile, original)
        self.assertEqual(result.private_config, fields(node()).private_config)
        self.assertEqual(len(result.summary['warnings']), 7)
        self.assertTrue(result.summary['normalization_required'])
        for value in ('do-not-disclose', 'private-group', DUMMY_PASSWORD, '0.0.0.0', '8.8.4.4'):
            self.assertNotIn(value, json.dumps(result.summary))

    def test_each_owned_section_warns_even_when_empty(self):
        sections = {'rules': [], 'dns': {}, 'tun': {}, 'proxy-groups': [], 'external-controller': '', 'secret': ''}
        for key, value in sections.items():
            with self.subTest(section=key):
                result = imported({'proxies': [node()], key: value})
                self.assertEqual(len(result.summary['warnings']), 1)
                self.assertTrue(result.summary['normalization_required'])

    def test_unknown_root_and_wrong_ignored_types_rejected(self):
        for key, value in (('unknown', {}), ('dns', []), ('rules', {}), ('tun', 'false'),
                           ('allow-lan', 1), ('mixed-port', True), ('secret', 1)):
            with self.subTest(key=key), self.assertRaises(vpn.VPNConfigurationError):
                imported({'proxies': [node()], key: value})
        for profile in (None, [], {}, {'proxies': {}}, {'proxies': []}):
            with self.subTest(profile_type=type(profile).__name__), self.assertRaises(vpn.VPNConfigurationError):
                imported(profile)

    def test_dangerous_directives_fail_even_inside_discarded_settings(self):
        for key in ('script', 'proxy-providers', 'rule-providers', 'external-ui',
                    'external-controller-unix', 'external-controller-tls', 'secret-file',
                    'ca', 'certificate', 'private-key', 'url', 'listeners', 'authentication', 'geox-url'):
            for profile in ({'proxies': [node()], key: {}},
                            {'proxies': [node()], 'dns': {key: '/dummy-not-read'}}):
                with self.subTest(key=key), self.assertRaises(vpn.VPNConfigurationError) as caught:
                    imported(profile)
                self.assertIn('directives', str(caught.exception))
        with self.assertRaises(vpn.VPNConfigurationError):
            imported({'proxies': [node()], 'proxy-groups': [{'use': ['provider']} ]})

    def test_ruby_stdin_only_bounded_minimal_env_discarded_stderr(self):
        text = '# explicit dummy secret: ' + DUMMY_PASSWORD
        completed = subprocess.CompletedProcess([], 0, json.dumps({'proxies': [node()]}).encode())
        with patch.object(vpn.subprocess, 'run', return_value=completed) as run:
            vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': text})
        args, kwargs = run.call_args
        self.assertEqual(args[0][:3], ['/usr/bin/ruby', '--disable-gems', '-e'])
        self.assertEqual(args[0][3], vpn._RUBY_YAML)
        self.assertNotIn(DUMMY_PASSWORD, repr(args))
        self.assertEqual(kwargs['input'], text.encode())
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertIs(kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(kwargs['timeout'], 5)
        self.assertEqual(kwargs['cwd'], '/')
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'})
        self.assertNotIn('shell', kwargs)

    def test_subprocess_errors_do_not_expose_stderr_or_input(self):
        failures = [FileNotFoundError(DUMMY_PASSWORD), PermissionError(DUMMY_PASSWORD),
                    subprocess.TimeoutExpired(['dummy'], 5, output=DUMMY_PASSWORD, stderr=DUMMY_PASSWORD),
                    RuntimeError(DUMMY_PASSWORD)]
        for failure in failures:
            with patch.object(vpn.subprocess, 'run', side_effect=failure), self.assertRaises(vpn.VPNConfigurationError) as caught:
                vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': 'dummy'})
            self.assertNotIn(DUMMY_PASSWORD, str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
            if isinstance(failure, FileNotFoundError):
                self.assertIn('parameter form', str(caught.exception))

    def test_bad_bounded_parser_output_is_rejected(self):
        outputs = [(2, b'private-secret'), (0, b'not json'), (0, b'\xff'),
                   (0, b'x' * (vpn.MAX_OUTPUT_BYTES + 1)), (0, b'NaN')]
        for code, output in outputs:
            result = subprocess.CompletedProcess([], code, output, DUMMY_PASSWORD)
            with self.subTest(code=code, size=len(output)), patch.object(vpn.subprocess, 'run', return_value=result), self.assertRaises(vpn.VPNConfigurationError) as caught:
                vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': 'dummy'})
            self.assertNotIn('private-secret', str(caught.exception))
            self.assertNotIn(DUMMY_PASSWORD, str(caught.exception))

    def test_input_size_checked_before_subprocess_including_utf8(self):
        for text in ('', None, b'dummy', 'x' * (vpn.MAX_INPUT_BYTES + 1), '密' * 100000, '\ud800'):
            with patch.object(vpn.subprocess, 'run') as run, self.assertRaises(vpn.VPNConfigurationError):
                vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': text})
            run.assert_not_called()

    def test_size_limit_is_applied_after_parser(self):
        profile = {'proxies': [node()], 'rules': ['x' * 4096 for _ in range(65)]}
        with self.assertRaises(vpn.VPNConfigurationError):
            imported(profile)


@unittest.skipUnless(os.path.isfile('/usr/bin/ruby'), 'System Ruby is not available')
class NativeRubyDummyTests(unittest.TestCase):
    # Only these literal dummy inputs reach native Ruby. Never read a host YAML.
    def test_plain_dummy_yaml_and_json(self):
        self.assertEqual(vpn._safe_yaml('dummy: [one, two]\nenabled: false\nport: 443\n'),
                         {'dummy': ['one', 'two'], 'enabled': False, 'port': 443})
        self.assertEqual(vpn._safe_yaml('{"dummy": "only", "nested": {"n": 1}}'),
                         {'dummy': 'only', 'nested': {'n': 1}})

    def test_duplicate_keys_and_multidoc_rejected(self):
        for text in ('dummy: one\ndummy: two\n', '{"dummy": 1, "dummy": 2}',
                     'dummy: {nested: 1, nested: 2}', '---\ndummy: one\n---\ndummy: two\n',
                     '---\ndummy: one\n---\n', ''):
            with self.subTest(dummy_input=text), self.assertRaises(vpn.VPNConfigurationError):
                vpn._safe_yaml(text)

    def test_aliases_anchors_merges_tags_and_objects_rejected(self):
        inputs = ['dummy: &alias value\nother: *alias', 'dummy: &unused value',
                  'dummy: !!str value', 'dummy: !custom value',
                  'dummy: !ruby/object:Object {}', 'dummy: !!binary ZHVtbXk=',
                  'dummy: {<<: {key: value}}', '? [a, b]\n: dummy',
                  'dummy: 2020-01-01', 'true: dummy', '1: dummy', 'null: dummy',
                  'dummy: {yes: one, true: two}']
        for text in inputs:
            with self.subTest(dummy_input=text), self.assertRaises(vpn.VPNConfigurationError):
                vpn._safe_yaml(text)

    def test_depth_node_limits_and_non_json_types(self):
        inputs = ['dummy: ' + '[' * 24 + '0' + ']' * 24,
                  'dummy: [' + ','.join('0' for _ in range(8200)) + ']',
                  'dummy: .nan', 'dummy: 1.5', 'dummy: "unterminated']
        for text in inputs:
            with self.subTest(size=len(text)), self.assertRaises(vpn.VPNConfigurationError):
                vpn._safe_yaml(text)

    def test_dummy_end_to_end_does_not_connect(self):
        text = ('proxies:\n  - type: trojan\n    server: 8.8.8.8\n    port: 443\n'
                '    password: dummy-not-a-real-password\n    sni: vpn.example.com\n')
        with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('no network')) as dns:
            result = vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': text})
        dns.assert_not_called()
        self.assertEqual(result.endpoints, (('tcp', '8.8.8.8', 443),))
        self.assertEqual(result.summary['protocols'], ['trojan'])


class TemplateTests(unittest.TestCase):
    @staticmethod
    def upload_template():
        return (Path(__file__).resolve().parents[1] / 'examples' / 'vpn' / 'clash.yaml').read_text(encoding='utf-8')

    @unittest.skipUnless(os.path.isfile('/usr/bin/ruby'), 'System Ruby is not available')
    def test_public_upload_template_has_no_enabled_nodes(self):
        text = self.upload_template()
        self.assertEqual(vpn._safe_yaml(text), {'proxies': []})
        resolver = Mock(side_effect=AssertionError('no DNS'))
        with self.assertRaises(vpn.VPNConfigurationError):
            vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': text}, resolver=resolver)
        resolver.assert_not_called()

    @unittest.skipUnless(os.path.isfile('/usr/bin/ruby'), 'System Ruby is not available')
    def test_filling_each_documented_node_block_is_accepted_by_the_upload_parser(self):
        template = self.upload_template()
        lines = template.splitlines()
        variants = []
        start = '#   - type: '
        for index, line in enumerate(lines):
            if not line.startswith(start):
                continue
            block = ['proxies:', line[2:]]  # Uncomment exactly as documented.
            for item in lines[index + 1:]:
                if not item.startswith('#     '):
                    break
                block.append(item[2:])
            variants.append((line[len(start):], '\n'.join(block) + '\n'))
        self.assertEqual([kind for kind, _ in variants], ['trojan', 'tuic', 'vless', 'vless', 'ss', 'hysteria2'])
        for kind, text in variants:
            with self.subTest(protocol=kind), patch.object(socket, 'getaddrinfo', side_effect=AssertionError('no DNS')):
                filled = (text.replace('192.0.2.10', '8.8.8.8')
                          .replace('00000000-0000-0000-0000-000000000000', DUMMY_UUID)
                          .replace('REPLACE_WITH_REALITY_PUBLIC_KEY', DUMMY_KEY)
                          .replace('REPLACE_WITH_REALITY_SHORT_ID', '0a'))
                for protocol in ('TROJAN', 'TUIC', 'SHADOWSOCKS', 'HYSTERIA2'):
                    filled = filled.replace(f'REPLACE_WITH_{protocol}_PASSWORD', DUMMY_PASSWORD)
                result = vpn.parse_submission({'input_mode': 'yaml', 'yaml_text': filled})
                self.assertEqual(result.summary['node_count'], 1)
                self.assertEqual(result.summary['protocols'], [kind])

    def test_json_template_has_no_nodes(self):
        path = Path(__file__).resolve().parents[1] / 'examples' / 'vpn' / 'fields.json'
        # Only the committed template is read; no host/user configuration files.
        payload = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(payload, {'input_mode': 'fields', 'nodes': []})
        with self.assertRaises(vpn.VPNConfigurationError):
            vpn.parse_submission(payload)


if __name__ == '__main__':
    unittest.main()
