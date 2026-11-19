"""Map failures to constant, public failure codes. Never returns exception text.

Codes are shown in the local UI and kept in private job records. They must not
carry paths, node data, credentials or native tool output, so only three kinds
of value are accepted:

1. an explicit ``code`` attribute that is already a constant slug;
2. the first argument of a project-defined ValueError whose message is a
   hyphenated constant slug (the established ``_need(value, 'some-code')`` style);
3. a fixed category derived from the exception class name.

Anything else becomes the caller's default.
"""
import errno
import http.client
import re
import socket
import ssl
import subprocess
import urllib.error

# Existing ``.code`` attributes are constant slugs, some without hyphens.
_ATTRIBUTE_CODE = re.compile(r'[a-z][a-z0-9-]{0,100}\Z')
# Messages must look like a deliberate slug: lowercase words joined by hyphens.
_MESSAGE_CODE = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)+\Z')

_CLASS_CODES = {
    'OfflineDiskError': 'offline-disk-error',
    'InstallError': 'offline-install-error',
    'PayloadError': 'offline-payload-error',
    'ValidationError': 'apfs-layout-validation-error',
    'PreinstallError': 'offline-preinstall-error',
    'OwnershipError': 'guest-ownership-validation-failed',
    'QuarantineError': 'quarantine-check-failed',
    'GuestVPNSeedError': 'guest-vpn-seed-error',
    'VPNStoreError': 'vpn-configuration-unavailable',
    'VPNConfigurationError': 'vpn-configuration-invalid',
}


def is_code(value):
    """True for a hyphenated constant slug such as ``internal-error``."""
    return type(value) is str and len(value) <= 101 and _MESSAGE_CODE.match(value) is not None


def is_step(value):
    """True for a constant step/phase token such as ``preflight`` or ``readonly-app-baseline``."""
    return type(value) is str and _ATTRIBUTE_CODE.match(value) is not None


def public_code(error, default):
    code = getattr(error, 'code', None)
    if is_step(code):
        return code
    project_defined = type(error).__module__ != 'builtins'
    if (isinstance(error, ValueError) and project_defined and error.args
            and is_code(error.args[0])):
        return error.args[0]
    if isinstance(error, subprocess.TimeoutExpired):
        return 'native-tool-timeout'
    mapped = _CLASS_CODES.get(type(error).__name__)
    if mapped is not None and project_defined:
        return mapped
    return default


_UNREACHABLE = (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.EHOSTDOWN)


def network_failure_code(error, default):
    """Fixed category for a failed transfer; the exception text is never used.

    Distinguishes "no data for the socket timeout" from "connection dropped",
    "could not connect", DNS, TLS, unreachable network and a full host disk.
    Anything else, including text-only URLError and HTTP status errors, keeps
    the caller's default.
    """
    if (isinstance(error, urllib.error.URLError) and not isinstance(error, urllib.error.HTTPError)
            and isinstance(getattr(error, 'reason', None), BaseException)):
        error = error.reason
    if isinstance(error, (socket.timeout, TimeoutError)):
        return 'download-timeout'
    if isinstance(error, ssl.SSLError):
        return 'download-tls-failed'
    if isinstance(error, socket.gaierror):
        return 'download-dns-failed'
    if isinstance(error, ConnectionRefusedError):
        return 'download-connect-failed'
    if isinstance(error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                          http.client.IncompleteRead, http.client.RemoteDisconnected)):
        return 'download-connection-lost'
    if isinstance(error, OSError) and error.errno in _UNREACHABLE:
        return 'download-network-unreachable'
    if isinstance(error, OSError) and error.errno == errno.ENOSPC:
        return 'host-disk-full'
    if isinstance(error, http.client.HTTPException):
        return 'download-protocol-error'
    return default
