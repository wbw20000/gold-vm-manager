"""Pure, fail-closed normalization of user-submitted explicit Mihomo nodes.

Never reads host profiles, resolves names implicitly, installs anything, or calls
legacy provisioning. The caller owns consent, private storage and guest runtime.
Only YAML mode starts a bounded system Ruby/Psych parser, with input on stdin.
"""
from dataclasses import dataclass, field
import base64
import ipaddress
import json
import re
import subprocess
import uuid

MAX_INPUT_BYTES = 256 * 1024
MAX_NODES = 16
MAX_TREE_NODES = 8192
MAX_DEPTH = 16
MAX_OUTPUT_BYTES = MAX_INPUT_BYTES * 8
SUPPORTED_TYPES = ('hysteria2', 'ss', 'trojan', 'tuic', 'vless')
SUPPORTED_SS_CIPHERS = ('aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305')

# This is the existing system Ruby/Psych safe_load pattern, with stricter
# preflight limits and no file argument. No exception or secret goes to stderr.
_RUBY_YAML = r'''
require 'yaml'; require 'json'
begin
  text = STDIN.read(262145)
  raise 'size' if text.bytesize > 262144
  tree = Psych.parse_stream(text)
  raise 'documents' unless tree.children.length == 1
  todo = [[tree, 0]]; count = 0
  until todo.empty?
    n, depth = todo.pop
    count += 1
    raise 'limit' if count > 8192 || depth > 18
    raise 'alias' if n.is_a?(Psych::Nodes::Alias)
    raise 'anchor' if n.respond_to?(:anchor) && n.anchor
    raise 'tag' if n.respond_to?(:tag) && n.tag
    if n.is_a?(Psych::Nodes::Mapping)
      keys = n.children.each_slice(2).map do |k,v|
        raise 'key' unless k.is_a?(Psych::Nodes::Scalar)
        raise 'key' if k.value == '<<' || k.value.bytesize > 256
        k.value
      end
      raise 'duplicate' unless keys.uniq.length == keys.length
    end
    (n.children || []).each { |child| todo << [child, depth + 1] }
  end
  obj = YAML.safe_load(text, permitted_classes: [], permitted_symbols: [], aliases: false)
  # JSON.generate would silently stringify boolean/numeric/null mapping keys.
  # Validate actual safe_load types before that lossy conversion.
  values = [obj]
  until values.empty?
    value = values.pop
    case value
    when Hash
      raise 'key' unless value.keys.all? { |key| key.is_a?(String) }
      values.concat(value.values)
    when Array
      values.concat(value)
    when String, Integer, TrueClass, FalseClass, NilClass
    else
      raise 'type'
    end
  end
  output = JSON.generate(obj)
  raise 'size' if output.bytesize > 2097152
  STDOUT.write(output)
rescue Exception
  exit 2
end
'''


class VPNConfigurationError(ValueError):
    """Public errors have constant text; never interpolate submitted values."""


@dataclass(frozen=True, repr=False)
class VPNConfiguration:
    """Private fields are intentionally redacted from repr.

    Frozen attributes, JSON-compatible dictionaries. Nested dictionaries are not
    immutable: callers must not mutate them between validation and publication.
    Neither private_config nor endpoints may enter logs, public API or UI state.
    """
    private_config: dict = field(repr=False)
    endpoints: tuple[tuple[str, str, int], ...] = field(repr=False)
    summary: dict = field(repr=False)

    def __repr__(self):
        return 'VPNConfiguration(<redacted>)'

    @property
    def private_json(self):
        """Canonical private JSON (also valid YAML); contains credentials."""
        return json.dumps(self.private_config, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _fail(message):
    raise VPNConfigurationError(message) from None


def _bounded_tree(value):
    """Accept only bounded plain JSON containers/scalars, without object hooks."""
    todo, seen, count, size = [(value, 0)], set(), 0, 0
    while todo:
        item, depth = todo.pop()
        count += 1
        if count > MAX_TREE_NODES or depth > MAX_DEPTH:
            _fail('VPN input exceeds structural safety limits')
        kind = type(item)
        if kind in (dict, list):
            if id(item) in seen:
                _fail('VPN input must not contain shared or recursive containers')
            seen.add(id(item))
            if len(item) > MAX_TREE_NODES:
                _fail('VPN input exceeds structural safety limits')
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str or not 1 <= len(key) <= 256 or key == '<<':
                        _fail('VPN mapping keys are invalid')
                    todo.append((key, depth + 1))
                    todo.append((child, depth + 1))
            else:
                todo.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in item):
                _fail('VPN text values are invalid')
            size += len(item.encode('utf-8'))
        elif kind is int:
            if not -(2 ** 63) <= item < 2 ** 63:
                _fail('VPN integer values are invalid')
        elif item is not None and kind is not bool:
            _fail('VPN input contains unsupported value types')
        if size > MAX_INPUT_BYTES:
            _fail('VPN input exceeds size limit')
    if len(json.dumps(value, ensure_ascii=False).encode('utf-8')) > MAX_INPUT_BYTES:
        _fail('VPN input exceeds size limit')


def _safe_yaml(text):
    if type(text) is not str or not text or len(text) > MAX_INPUT_BYTES:
        _fail('Clash YAML is empty or exceeds size limit')
    data = text.encode('utf-8')
    if len(data) > MAX_INPUT_BYTES:
        _fail('Clash YAML is empty or exceeds size limit')
    try:
        result = subprocess.run(
            ['/usr/bin/ruby', '--disable-gems', '-e', _RUBY_YAML], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
            cwd='/', env={'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'},
        )
    except FileNotFoundError:
        _fail('System Ruby/Psych is required to import Clash YAML; use the parameter form or install the prerequisite')
    except Exception:
        _fail('Clash YAML could not be safely parsed')
    if result.returncode or len(result.stdout) > MAX_OUTPUT_BYTES:
        _fail('Clash YAML could not be safely parsed')
    try:
        value = json.loads(result.stdout)
    except Exception:
        _fail('Clash YAML could not be safely parsed')
    _bounded_tree(value)
    return value


# Full uploads may have these settings, but none are copied. Unknown root keys
# fail closed instead of trying to infer their semantics across Mihomo versions.
_IGNORED_TYPES = {
    'rules': list, 'dns': dict, 'tun': dict, 'proxy-groups': list,
    'external-controller': str, 'secret': str, 'profile': dict, 'hosts': dict,
    'mixed-port': int, 'port': int, 'socks-port': int, 'redir-port': int,
    'tproxy-port': int, 'allow-lan': bool, 'bind-address': str, 'mode': str,
    'log-level': str, 'ipv6': bool, 'sniffer': dict, 'tcp-concurrent': bool,
    'unified-delay': bool, 'find-process-mode': str,
}
_WARNINGS = {
    'rules': 'Uploaded routing rules were replaced by MATCH,PROXY.',
    'dns': 'Uploaded DNS settings were replaced by tunneled guest DNS.',
    'tun': 'Uploaded TUN settings were replaced by owned guest TUN settings.',
    'proxy-groups': 'Uploaded proxy groups were replaced by the owned PROXY selector.',
    'external-controller': 'Uploaded controller settings and credentials were not adopted.',
    'secret': 'Uploaded controller settings and credentials were not adopted.',
}
_POLICY_WARNING = 'Uploaded general settings were replaced by owned guest policy.'
_PIN_WARNING = 'Domain endpoints were pinned to validated public IPv4 addresses.'
_NAME_WARNING = 'Submitted node names were replaced by generated private identifiers.'
_DANGEROUS_KEYS = {
    'script', 'scripts', 'proxy-providers', 'rule-providers', 'providers',
    'use', 'url', 'path', 'file', 'external-ui', 'external-ui-url',
    'external-ui-name', 'external-controller-unix', 'external-controller-pipe',
    'external-controller-tls', 'certificate', 'private-key', 'ca', 'ca-str',
    'geox-url', 'geodata-loader', 'geodata-mode', 'geodata-auto-update',
    'geo-auto-update', 'geo-update-interval', 'authentication', 'listeners',
}


def _reject_directives(value):
    todo = [value]
    while todo:
        item = todo.pop()
        if type(item) is dict:
            for key, child in item.items():
                words = set(key.lower().replace('_', '-').split('-'))
                if (key.lower() in _DANGEROUS_KEYS or
                        words & {'script', 'scripts', 'provider', 'providers', 'path', 'file'}):
                    _fail('Scripts, providers, downloads and file directives are not supported')
                todo.append(child)
        elif type(item) is list:
            todo.extend(item)


def _text(value, maximum=4096):
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _fail('Proxy text option is invalid')
    return value


def _boolean(raw, key, default):
    value = raw.get(key, default)
    if type(value) is not bool:
        _fail('Proxy boolean option has invalid type')
    return value


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _fail('Proxy integer option is invalid')
    return value


def _hostname(value):
    if type(value) is not str or not 1 <= len(value) <= 253 or value.endswith('.'):
        return False
    labels = value.split('.')
    return (len(labels) >= 2 and not all(label.isdigit() for label in labels) and
            all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in labels) and
            labels[-1].lower() not in ('local', 'localhost', 'internal', 'lan', 'home', 'onion', 'invalid', 'test'))


def _public_ipv4(value):
    if type(value) is not str:
        _fail('Proxy endpoints must be globally routable unicast IPv4')
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        _fail('Proxy endpoints must be globally routable unicast IPv4')
    # Explicit exclusions also guard older system Python ipaddress tables.
    blocked = ('0.0.0.0/8', '100.64.0.0/10', '192.0.0.0/24', '192.0.2.0/24',
               '192.88.99.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24')
    if (not address.is_global or address.is_multicast or address.is_reserved or
            address.is_loopback or address.is_link_local or address.is_unspecified or
            any(address in ipaddress.IPv4Network(network) for network in blocked)):
        _fail('Proxy endpoints must be globally routable unicast IPv4')
    return str(address)


def _endpoint(raw, resolver, cache, warnings):
    server = _text(raw.get('server'), 253)
    port = _integer(raw.get('port'), 1, 65535)
    if port == 53:
        _fail('Proxy endpoint port 53 is not allowed by the guest fence')
    try:
        ipaddress.IPv4Address(server)
    except ValueError:
        if not _hostname(server):
            _fail('Proxy server must be a public IPv4 address or a valid DNS hostname')
        if resolver is None:
            _fail('Domain endpoints require a caller-supplied resolver; enter a public IPv4 address and explicit TLS server name')
        domain = server.lower()
        if domain not in cache:
            try:
                answers = resolver(domain)
            except Exception:
                _fail('Proxy hostname resolution failed')
            if type(answers) not in (list, tuple) or not 1 <= len(answers) <= 16:
                _fail('Resolver must return one to sixteen public IPv4 strings')
            checked = [_public_ipv4(answer) for answer in answers]
            cache[domain] = min(checked, key=lambda ip: int(ipaddress.IPv4Address(ip)))
        warnings.add(_PIN_WARNING)
        return cache[domain], port, domain
    return _public_ipv4(server), port, server


def _tls(raw, node, key, default_name):
    if _boolean(raw, 'skip-cert-verify', False) or _boolean(raw, 'disable-sni', False):
        _fail('Insecure TLS or disabled SNI is not supported')
    servername = raw.get(key, default_name)
    if not _hostname(servername):
        _public_ipv4(servername)
    node[key] = servername
    node['skip-cert-verify'] = False
    if 'alpn' in raw:
        alpn = raw['alpn']
        if (type(alpn) is not list or not 1 <= len(alpn) <= 8 or
                any(type(v) is not str or not re.fullmatch(r'[A-Za-z0-9./_-]{1,32}', v) for v in alpn)):
            _fail('Proxy ALPN option is invalid')
        node['alpn'] = list(alpn)
    if 'client-fingerprint' in raw:
        if raw['client-fingerprint'] not in ('chrome', 'firefox', 'safari', 'ios', 'android', 'edge'):
            _fail('Proxy TLS fingerprint is unsupported')
        node['client-fingerprint'] = raw['client-fingerprint']


def _identity(value):
    if type(value) is not str or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', value):
        _fail('Proxy UUID must be a canonical nonzero UUID')
    parsed = uuid.UUID(value)
    if not parsed.int:
        _fail('Proxy UUID must be a canonical nonzero UUID')
    return str(parsed)


_COMMON = {'name', 'type', 'server', 'port', 'udp'}
_TLS = {'skip-cert-verify', 'alpn', 'client-fingerprint'}
_OPTIONS = {
    'tuic': _COMMON | {'uuid', 'password', 'sni', 'disable-sni', 'reduce-rtt',
                       'congestion-controller', 'udp-relay-mode', 'request-timeout',
                       'heartbeat-interval', 'max-udp-relay-packet-size', 'alpn', 'skip-cert-verify'},
    'vless': _COMMON | _TLS | {'uuid', 'tls', 'network', 'servername', 'flow', 'reality-opts', 'packet-encoding'},
    'trojan': _COMMON | _TLS | {'password', 'sni', 'network', 'tls'},
    'ss': _COMMON | {'cipher', 'password'},
    'hysteria2': _COMMON | {'password', 'sni', 'skip-cert-verify', 'alpn', 'up', 'down', 'obfs', 'obfs-password'},
}


def _node(raw, index, resolver, cache, warnings):
    if type(raw) is not dict or type(raw.get('type')) is not str or raw['type'] not in SUPPORTED_TYPES:
        _fail('Unsupported proxy type; supported types are tuic, vless, trojan, ss and hysteria2')
    kind = raw['type']
    if set(raw) - _OPTIONS[kind]:
        _fail('Unsupported proxy options; no permissive fallback')
    if 'name' in raw:
        _text(raw['name'], 256)
        warnings.add(_NAME_WARNING)
    server, port, default_name = _endpoint(raw, resolver, cache, warnings)
    node = {'name': 'proxy-' + str(index), 'type': kind, 'server': server,
            'port': port, 'udp': _boolean(raw, 'udp', True)}
    transports = ['udp'] if kind in ('tuic', 'hysteria2') else ['tcp']
    if kind == 'ss':
        if raw.get('cipher') not in SUPPORTED_SS_CIPHERS:
            _fail('Unsupported Shadowsocks cipher; only reviewed AEAD ciphers are supported')
        node.update(cipher=raw['cipher'], password=_text(raw.get('password')))
        if node['udp']:
            transports.append('udp')
    else:
        _tls(raw, node, 'servername' if kind == 'vless' else 'sni', default_name)
    if kind in ('tuic', 'vless'):
        node['uuid'] = _identity(raw.get('uuid'))
    if kind in ('tuic', 'trojan', 'hysteria2'):
        node['password'] = _text(raw.get('password'))
    if kind == 'tuic':
        node['disable-sni'] = False
        for key, choices in (('congestion-controller', ('cubic', 'new_reno', 'bbr')),
                             ('udp-relay-mode', ('native', 'quic'))):
            if key in raw:
                if raw[key] not in choices:
                    _fail('TUIC enumeration option is invalid')
                node[key] = raw[key]
        if 'reduce-rtt' in raw:
            node['reduce-rtt'] = _boolean(raw, 'reduce-rtt', False)
        for key in ('request-timeout', 'heartbeat-interval'):
            if key in raw:
                node[key] = _integer(raw[key], 1000, 120000)
        if 'max-udp-relay-packet-size' in raw:
            node['max-udp-relay-packet-size'] = _integer(raw['max-udp-relay-packet-size'], 1200, 65507)
    if kind in ('vless', 'trojan'):
        if raw.get('network', 'tcp') != 'tcp':
            _fail('Only TCP transport is supported for VLESS and Trojan')
        if not _boolean(raw, 'tls', kind == 'trojan'):
            _fail('TLS is required for VLESS and Trojan')
        node['network'] = 'tcp'
        if kind == 'vless':
            node['tls'] = True
            if raw.get('flow', '') not in ('', 'xtls-rprx-vision'):
                _fail('Unsupported VLESS flow')
            if 'flow' in raw:
                node['flow'] = raw['flow']
            if 'packet-encoding' in raw:
                if raw['packet-encoding'] != 'xudp':
                    _fail('Unsupported VLESS packet encoding')
                node['packet-encoding'] = 'xudp'
            if 'reality-opts' in raw:
                reality = raw['reality-opts']
                if type(reality) is not dict or set(reality) != {'public-key', 'short-id'}:
                    _fail('VLESS Reality requires an explicit public key and short ID')
                key, short_id = reality['public-key'], reality['short-id']
                if type(key) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{43}', key):
                    _fail('VLESS Reality public key is invalid')
                decoded = base64.urlsafe_b64decode(key + '=')
                if len(decoded) != 32 or not any(decoded) or base64.urlsafe_b64encode(decoded).decode().rstrip('=') != key:
                    _fail('VLESS Reality public key is invalid')
                if type(short_id) is not str or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', short_id):
                    _fail('VLESS Reality short ID is invalid')
                node['reality-opts'] = {'public-key': key, 'short-id': short_id.lower()}
                node.setdefault('client-fingerprint', 'chrome')
    if kind == 'hysteria2':
        for key in ('up', 'down'):
            if key in raw:
                node[key] = _integer(raw[key], 1, 100000)
        if 'obfs' in raw or 'obfs-password' in raw:
            if raw.get('obfs') != 'salamander':
                _fail('Hysteria2 obfuscation requires salamander and a password')
            node['obfs'] = 'salamander'
            node['obfs-password'] = _text(raw.get('obfs-password'))
    return node, [(transport, server, port) for transport in transports]


def _guest_policy(nodes):
    return {
        'mixed-port': 7890, 'allow-lan': False, 'bind-address': '127.0.0.1',
        'mode': 'rule', 'log-level': 'silent', 'ipv6': False,
        # An empty controller address disables the API; no controller secret.
        'external-controller': '',
        'profile': {'store-selected': False, 'store-fake-ip': False},
        'tun': {'enable': True, 'stack': 'gvisor', 'auto-route': True,
                'strict-route': True, 'auto-detect-interface': True,
                'dns-hijack': ['any:53', 'tcp://any:53'], 'mtu': 1500},
        'dns': {'enable': True, 'listen': '127.0.0.1:1053', 'ipv6': False,
                'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'fake-ip-filter': [], 'use-hosts': False, 'use-system-hosts': False,
                'respect-rules': True,
                'nameserver': ['https://1.1.1.1/dns-query#PROXY'],
                # Explicit IP-literal DoH bootstrap avoids core default resolvers.
                # Proxy servers are pinned, so bootstrap cannot recurse on them.
                'default-nameserver': ['https://1.1.1.1/dns-query#PROXY'],
                'proxy-server-nameserver': ['https://1.1.1.1/dns-query#PROXY'],
                'direct-nameserver': [], 'fallback': []},
        'proxies': nodes,
        'proxy-groups': [{'name': 'PROXY', 'type': 'select',
                          'proxies': [node['name'] for node in nodes]}],
        'rules': ['MATCH,PROXY'],
    }


def parse_submission(payload, *, resolver=None):
    """Validate fields or Clash YAML and return a redacted frozen result.

    resolver, when supplied, is called with an ASCII lowercase hostname and must
    return a list/tuple of 1..16 global IPv4 strings. EVERY answer is validated;
    the smallest address is pinned, with the original/explicit TLS name retained.
    This module does not create a resolver or perform any network operations.
    All external exceptions are converted to constant sanitized public errors.
    """
    try:
        return _parse_submission(payload, resolver)
    except VPNConfigurationError:
        raise
    except Exception:
        _fail('VPN submission is invalid or could not be safely processed')


def _parse_submission(payload, resolver):
    if type(payload) is not dict or type(payload.get('input_mode')) is not str:
        _fail('VPN submission must choose fields or yaml input mode')
    mode = payload['input_mode']
    warnings = set()
    if mode == 'fields':
        if set(payload) != {'input_mode', 'nodes'}:
            _fail('Fields submission must contain only input_mode and nodes')
        _bounded_tree(payload)
        raw_nodes = payload['nodes']
        _reject_directives(raw_nodes)
    elif mode == 'yaml':
        if set(payload) != {'input_mode', 'yaml_text'}:
            _fail('YAML submission must contain only input_mode and yaml_text')
        profile = _safe_yaml(payload['yaml_text'])
        if type(profile) is not dict:
            _fail('Clash YAML must contain an explicit proxies mapping')
        _reject_directives(profile)
        if set(profile) - {'proxies'} - set(_IGNORED_TYPES):
            _fail('Unsupported Clash top-level settings; submit explicit nodes only')
        for key, value in profile.items():
            if key != 'proxies':
                if type(value) is not _IGNORED_TYPES[key]:
                    _fail('Uploaded Clash settings have invalid types')
                warnings.add(_WARNINGS.get(key, _POLICY_WARNING))
        raw_nodes = profile.get('proxies')
    else:
        _fail('VPN submission must choose fields or yaml input mode')
    if type(raw_nodes) is not list or not 1 <= len(raw_nodes) <= MAX_NODES:
        _fail('VPN submission requires one to sixteen explicit proxy nodes')
    nodes, endpoints, cache = [], set(), {}
    for index, raw in enumerate(raw_nodes, 1):
        node, node_endpoints = _node(raw, index, resolver, cache, warnings)
        nodes.append(node)
        endpoints.update(node_endpoints)
    summary = {'node_count': len(nodes), 'endpoint_count': len(endpoints),
               'protocols': sorted({node['type'] for node in nodes}),
               'warnings': sorted(warnings),
               'normalization_required': bool(warnings)}
    return VPNConfiguration(_guest_policy(nodes), tuple(sorted(endpoints)), summary)
