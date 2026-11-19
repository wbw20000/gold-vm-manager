"""Fixed transfer-failure categories only; exception text is never used."""
import errno
import http.client
import socket
import ssl
import unittest
import urllib.error

import error_codes


class NetworkFailureCodeTests(unittest.TestCase):
    def test_transfer_exceptions_map_to_fixed_categories(self):
        cases = (
            (socket.timeout('timed out SECRET'), 'download-timeout'),
            (TimeoutError(errno.ETIMEDOUT, 'SECRET'), 'download-timeout'),
            (urllib.error.URLError(socket.timeout('SECRET')), 'download-timeout'),
            (ConnectionResetError(errno.ECONNRESET, 'SECRET'), 'download-connection-lost'),
            (ConnectionAbortedError(errno.ECONNABORTED, 'SECRET'), 'download-connection-lost'),
            (BrokenPipeError(errno.EPIPE, 'SECRET'), 'download-connection-lost'),
            (http.client.RemoteDisconnected('SECRET'), 'download-connection-lost'),
            (http.client.IncompleteRead(b'SECRET', 10), 'download-connection-lost'),
            (urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, 'SECRET')), 'download-connect-failed'),
            (urllib.error.URLError(socket.gaierror(8, 'nodename SECRET')), 'download-dns-failed'),
            (urllib.error.URLError(ssl.SSLError(1, 'SECRET')), 'download-tls-failed'),
            (ssl.SSLCertVerificationError(1, 'SECRET'), 'download-tls-failed'),
            (OSError(errno.ENETUNREACH, 'SECRET'), 'download-network-unreachable'),
            (urllib.error.URLError(OSError(errno.EHOSTUNREACH, 'SECRET')), 'download-network-unreachable'),
            (OSError(errno.ENOSPC, 'SECRET'), 'host-disk-full'),
            (http.client.BadStatusLine('SECRET'), 'download-protocol-error'),
        )
        for error, code in cases:
            with self.subTest(error=type(error).__name__, code=code):
                self.assertEqual(error_codes.network_failure_code(error, 'fallback-code'), code)
                self.assertTrue(error_codes.is_code(code))

    def test_unknown_or_text_only_errors_keep_the_callers_default(self):
        for error in (urllib.error.URLError('https://user:password@host/?SECRET'),
                      urllib.error.HTTPError('https://host/', 500, 'SECRET', {}, None),
                      OSError(errno.EACCES, 'SECRET'), FileExistsError(errno.EEXIST, 'SECRET'),
                      ValueError('download-timeout'), RuntimeError('download-timeout'), None):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(error_codes.network_failure_code(error, 'fallback-code'), 'fallback-code')


if __name__ == '__main__':
    unittest.main()
