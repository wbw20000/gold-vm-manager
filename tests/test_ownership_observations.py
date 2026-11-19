"""Ticket v2: own ordinary file fixtures only. Never authorize or change owners."""
from dataclasses import replace
import hashlib
import json
import os
import unittest
from unittest.mock import Mock, patch

import guest_ownership as ownership
from tests.test_guest_ownership import Fixture, cleanup_root, new_root, write


class ChangedStat:
    """Inject one metadata change while retaining every other real stat field."""
    def __init__(self, info, **changes):
        self.original = info
        self.__dict__.update(changes)

    def __getattr__(self, name):
        return getattr(self.original, name)


class OwnershipObservationTests(unittest.TestCase):
    def setUp(self):
        root = new_root()
        self.addCleanup(cleanup_root, root)
        self.fixture = Fixture(root)
        self.addCleanup(self.fixture.close)

    def test_schema_two_binds_each_kind_to_its_own_lstat(self):
        f = self.fixture
        ticket = json.loads(f.prepare().path.read_bytes())
        self.assertIs(type(ticket['schema']), int)
        self.assertEqual(ticket['schema'], 2)
        self.assertEqual({e['kind'] for e in ticket['entries']}, {'directory', 'symlink', 'file'})
        for entry in ticket['entries']:
            info = (f.mount / entry['path']).lstat()
            self.assertIs(type(entry['ctime_ns']), int)
            self.assertEqual((entry['observed_uid'], entry['observed_gid'], entry['ctime_ns']),
                             (info.st_uid, info.st_gid, info.st_ctime_ns))

    def test_required_positive_int64_ctime_before_writing_ticket(self):
        f = self.fixture
        entry = f.entries[0]
        ownership.desired_ownership(replace(entry, ctime_ns=2 ** 63 - 1))
        for bad in (0, -1, True, 1.0, '1', None, 2 ** 63):
            with self.subTest(bad=bad), self.assertRaises(ownership.OwnershipError):
                f.prepare(entries=(replace(entry, ctime_ns=bad),) + f.entries[1:])
        self.assertFalse(f.paths['ticket'].exists())

    def test_old_schema_or_invalid_v2_entry_never_reaches_prompt(self):
        ticket = self.fixture.prepare()
        original = ticket.path.read_bytes()
        for key, bad in [('schema', v) for v in (None, 1, True, 2.0)] + [
                ('ctime_ns', v) for v in (None, 0, True, 2 ** 63)]:
            with self.subTest(key=key, bad=bad):
                value = json.loads(original)
                record = value if key == 'schema' else value['entries'][-1]
                if bad is None:
                    del record[key]
                else:
                    record[key] = bad
                write(ticket.path, value)
                # Rebind the digest so a hash mismatch cannot mask a schema failure.
                altered = replace(ticket, digest=hashlib.sha256(ticket.path.read_bytes()).hexdigest())
                run = Mock()
                with patch.object(ownership.host_tools, 'verify_local_signature') as signature:
                    result = ownership.request_authorization(altered, 'apply', acknowledge_authorization=True, run=run)
                self.assertEqual(result.failure_reason, 'preflight-rejected')
                signature.assert_not_called()
                run.assert_not_called()

    def test_already_deployed_v1_or_mixed_fixture_is_not_ticketable(self):
        f = self.fixture
        for payload in (b'GOLD_OWNERSHIP_PRODUCTION_ROOT_ONLY_V1',
                        b'GOLD_OWNERSHIP_FIXTURE_SIMULATION_ONLY_V1 ' + ownership.PRODUCTION_CONTRACT.encode()):
            digest = hashlib.sha256(payload).hexdigest()
            directory = f.helper.parent.parent / digest
            directory.mkdir(mode=0o700)
            write(directory / 'GuestOwnershipHelper', payload, mode=0o755)
            with self.assertRaises(ownership.OwnershipError):
                f.prepare(helper_sha256=digest)
        self.assertFalse(f.paths['ticket'].exists())

    def test_stale_owner_from_path_stat_cannot_be_paired_with_fd_hash(self):
        real_stat = os.stat
        stale = []

        def stat_path(name, *args, **kwargs):
            info = real_stat(name, *args, **kwargs)
            if name == 'seed.json' and kwargs.get('dir_fd') is not None:
                stale.append(name)
                return ChangedStat(info, st_uid=info.st_uid + 1)
            return info

        with patch.object(os, 'stat', stat_path), self.assertRaises(ownership.OwnershipError):
            ownership.collect_entries(self.fixture.mount)
        self.assertTrue(stale)

    def test_changed_directory_ctime_after_traversal_is_rejected(self):
        inode = (self.fixture.mount / ownership.BASE).stat().st_ino
        real_listdir, real_fstat = os.listdir, os.fstat
        visited = []

        def list_dir(fd):
            names = real_listdir(fd)
            if real_fstat(fd).st_ino == inode:
                visited.append(inode)
            return names

        def stat_fd(fd):
            info = real_fstat(fd)
            if visited and info.st_ino == inode:
                return ChangedStat(info, st_ctime_ns=info.st_ctime_ns + 1)
            return info

        with patch.object(os, 'listdir', list_dir), patch.object(os, 'fstat', stat_fd), \
                self.assertRaises(ownership.OwnershipError):
            ownership.collect_entries(self.fixture.mount)
        self.assertTrue(visited)

    def test_changed_symlink_ctime_after_readlink_is_rejected(self):
        real_stat, real_readlink = os.stat, os.readlink
        read = []

        def read_link(name, *args, **kwargs):
            target = real_readlink(name, *args, **kwargs)
            if name == 'Current':
                read.append(name)
            return target

        def stat_path(name, *args, **kwargs):
            info = real_stat(name, *args, **kwargs)
            if name == 'Current' and read:
                return ChangedStat(info, st_ctime_ns=info.st_ctime_ns + 1)
            return info

        with patch.object(os, 'readlink', read_link), patch.object(os, 'stat', stat_path), \
                self.assertRaises(ownership.OwnershipError):
            ownership.collect_entries(self.fixture.mount)
        self.assertTrue(read)
