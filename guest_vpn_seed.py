"""Pure private first-login seed construction; no filesystem, account or VM work.

The parent securely installs this plan onto the NEW guest Data volume, verifies
persistent ownership/read-only acceptance, and preserves the original GUI app.
"""
from dataclasses import dataclass, field
import json
import plistlib
import secrets

from vpn_config import VPNConfiguration, parse_submission

APP_ID = 'io.github.clash-verge-rev.clash-verge-rev'
APP_VERSION = '2.5.10'
APP_TEAM = 'JPH3Z7PPBB'
EXPECTED_UID = 501
EXPECTED_GID = 20
BASE = 'Library/Application Support/GoldVMManager'
FIRST_LOGIN = BASE + '/FirstLogin'
HELPER_PATH = FIRST_LOGIN + '/GuestVPNBootstrap'
SEED_PATH = FIRST_LOGIN + '/seed.json'
AGENT_PATH = 'Library/LaunchAgents/org.goldvmmanager.first-login.plist'
PROFILE_UID = 'GoldVMVPN'
PROFILE_FILE = 'gold-vm-vpn.yaml'
STATUS_SHARE = '/Volumes/My Shared Files/gold-status'
MAX_SEED_BYTES = 1024 * 1024


class GuestVPNSeedError(ValueError):
    """Constant public messages only."""


@dataclass(frozen=True)
class DataEntry:
    relative_path: str
    kind: str
    uid: int
    gid: int
    mode: int
    content: bytes = field(default=None, repr=False)


@dataclass(frozen=True, repr=False)
class GuestVPNSeed:
    seed_json: bytes = field(repr=False)
    launch_agent_plist: bytes = field(repr=False)
    entries: tuple = field(repr=False)
    receipt_token: str = field(repr=False)

    def __repr__(self):
        return 'GuestVPNSeed(<redacted>)'


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _fail():
    raise GuestVPNSeedError('Guest VPN seed requires an unchanged validated private VPN configuration') from None


def _validated_config(configuration):
    if type(configuration) is VPNConfiguration:
        config = configuration.private_config
    elif type(configuration) is dict:
        config = configuration
    else:
        _fail()
    if type(config) is not dict or type(config.get('proxies')) is not list:
        _fail()
    # Re-derive the entire owned policy, not merely a few flags. No Ruby or DNS.
    checked = parse_submission({'input_mode': 'fields', 'nodes': config['proxies']})
    if _json(config) != checked.private_json:
        _fail()
    return json.loads(checked.private_json)


def build_seed(configuration, *, receipt_enabled=False):
    """Return a private seed/plist and relative Data-volume installation plan.

    Accepts VPNConfiguration or its unchanged private_config dictionary. The
    UID501/paths/app version are fixed, never caller-controlled. Helper bytes are
    supplied by the parent for the entry with kind='compiled_helper'. No writes
    or app execution occur here. receipt_enabled is explicit per-VM authorization
    for ONLY STATUS_SHARE; it does not create/share a host directory.
    """
    try:
        if type(receipt_enabled) is not bool:
            _fail()
        profile = _validated_config(configuration)
        seed_id = secrets.token_hex(16)
        receipt_token = secrets.token_hex(32)
        controller_secret = secrets.token_hex(32)
        owned = {key: value for key, value in profile.items()
                 if key not in ('proxies', 'proxy-groups', 'rules')}
        owned['mixed-port'] = 7897
        # The GUI owns its private Unix IPC. Its external TCP controller is OFF.
        owned['secret'] = controller_secret
        owned['external-controller-cors'] = {'allow-origins': [], 'allow-private-network': False}
        verge = {
            'clash_core': 'verge-mihomo', 'app_log_level': 'silent',
            'enable_tun_mode': True, 'enable_system_proxy': True,
            'enable_dns_settings': False,
            'profile_dns_settings': {PROFILE_UID: {'enabled': False}},
            'enable_external_controller': False, 'enable_builtin_enhanced': False,
            'enable_auto_launch': False, 'enable_silent_start': False,
            'verge_mixed_port': 7897, 'verge_socks_enabled': False,
            'verge_http_enabled': False, 'verge_redir_enabled': False,
            'proxy_host': '127.0.0.1', 'proxy_auto_config': False,
            'enable_proxy_guard': False, 'enable_bypass_check': False,
            'use_default_bypass': False, 'system_proxy_bypass': '',
            'auto_check_update': False, 'enable_auto_delay_detection': False,
            'enable_auto_backup_schedule': False, 'auto_backup_on_change': False,
        }
        profiles = {'current': PROFILE_UID, 'items': [{
            'uid': PROFILE_UID, 'type': 'local', 'name': 'Guest VPN',
            'file': PROFILE_FILE, 'updated': 0,
            'option': {'allow_auto_update': False},
        }]}
        documents = {'config.yaml': _json(owned), 'verge.yaml': _json(verge),
                     'profiles.yaml': _json(profiles), 'profiles/' + PROFILE_FILE: _json(profile)}
        envelope = {
            'schema_version': 1, 'expected_uid': EXPECTED_UID, 'seed_id': seed_id,
            'app_id': APP_ID, 'app_version': APP_VERSION, 'app_team': APP_TEAM,
            'receipt_enabled': receipt_enabled, 'receipt_token': receipt_token,
            'documents': documents,
        }
        seed_json = (_json(envelope) + '\n').encode('utf-8')
        if len(seed_json) > MAX_SEED_BYTES:
            _fail()
        agent = {
            'Label': 'org.goldvmmanager.first-login',
            'ProgramArguments': ['/' + HELPER_PATH], 'RunAtLoad': True,
            'KeepAlive': False, 'LimitLoadToSessionType': 'Aqua',
            'ProcessType': 'Interactive', 'Umask': 0o077,
            'StandardOutPath': '/dev/null', 'StandardErrorPath': '/dev/null',
        }
        launch_agent_plist = plistlib.dumps(agent, fmt=plistlib.FMT_XML, sort_keys=True)
        entries = (
            DataEntry(BASE, 'directory', 0, 0, 0o755),
            DataEntry(FIRST_LOGIN, 'directory', EXPECTED_UID, EXPECTED_GID, 0o700),
            DataEntry(HELPER_PATH, 'compiled_helper', 0, 0, 0o755),
            DataEntry(SEED_PATH, 'file', EXPECTED_UID, EXPECTED_GID, 0o600, seed_json),
            DataEntry(AGENT_PATH, 'file', 0, 0, 0o644, launch_agent_plist),
        )
        return GuestVPNSeed(seed_json, launch_agent_plist, entries, receipt_token)
    except GuestVPNSeedError:
        raise
    except Exception:
        _fail()
