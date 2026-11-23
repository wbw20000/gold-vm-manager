"""Synthetic private ticket tests only: no network, native processes or host profiles."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import traceback
from types import SimpleNamespace
import unittest
from unittest import mock

import vpn_store as store
from vpn_config import VPNConfigurationError


NOW = 1700000000.0
JOB = 'a' * 32
OTHER_JOB = 'b' * 32
SECRET = 'synthetic-password-do-not-expose'
PROFILE_SECRET = 'synthetic-unused-upload-secret'
NODE_NAME = 'synthetic uploaded name'
HOST = 'unresolved-input.example.com'
SNI = 'tls-name.example.com'
IP = '8.8.8.8'
USER_UUID = 'b51cbf07-921a-43b9-9b3f-2f4e06a0b9cb'
PREFIX = 'gold-vpn-store-tests-'


def payload(**overrides):
    return {'input_mode': 'fields', 'nodes': [dict(
        {'type': 'tuic', 'server': IP, 'port': 443, 'password': SECRET,
         'uuid': USER_UUID, 'name': NODE_NAME, 'sni': SNI}, **overrides)]}


def path_payload(path):
    return {'input_mode': 'yaml_path', 'path': str(path)}


class StoreTests(unittest.TestCase):
    def setUp(self):
        base = Path(tempfile.gettempdir()).resolve(strict=True)
        self.root = Path(tempfile.mkdtemp(prefix=PREFIX, dir=base))
        identity = self.root.lstat()
        self.addCleanup(self.cleanup_owned, base / self.root.name, identity)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.state.chmod(0o700)
        self.inputs = self.state / 'vpn-inputs'
        self.run = self.start_patch('subprocess.run', side_effect=AssertionError('no real process'))
        self.start_patch('subprocess.Popen', side_effect=AssertionError('no real process'))
        self.start_patch('socket.getaddrinfo', side_effect=AssertionError('no real DNS'))

    def cleanup_owned(self, expected, identity):
        info = self.root.lstat()
        if (self.root != expected or not expected.is_absolute() or not expected.name.startswith(PREFIX)
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or (info.st_dev, info.st_ino) != (identity.st_dev, identity.st_ino)
                or self.root.resolve(strict=True) != expected):
            raise AssertionError('Refusing unsafe fixture cleanup')
        shutil.rmtree(expected)

    def start_patch(self, target, **kwargs):
        patch = mock.patch(target, **kwargs)
        result = patch.start()
        self.addCleanup(patch.stop)
        return result

    def submit(self, submitted=None, **kwargs):
        result = store.store_submission(self.state, payload() if submitted is None else submitted, now=NOW, **kwargs)
        self.ident = result['configuration_id']
        self.path = self.inputs / (self.ident + '.json')
        return result

    def assert_redacted(self, *values):
        for value in values:
            for sensitive in (SECRET, PROFILE_SECRET, NODE_NAME, HOST, SNI, IP, USER_UUID, str(self.root)):
                self.assertNotIn(sensitive, value)

    def reject(self, fn, *args, error=store.VPNStoreError, **kwargs):
        try:
            fn(*args, **kwargs)
        except error as exc:
            self.assert_redacted(str(exc), repr(exc), ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
            return str(exc)
        self.fail('Expected a sanitized rejection')

    def read(self, **kwargs):
        return store.load_configuration(self.state, self.ident, **kwargs)

    def claim(self, job=JOB, **kwargs):
        return store.claim_configuration(self.state, self.ident, job, **kwargs)

    def test_round_trip_exposes_only_fixed_public_metadata(self):
        parsed = store.parse_submission(payload())
        result = self.submit()
        saved = self.read(now=NOW)
        self.assertEqual(set(result), {'configuration_id', 'summary', 'expires_in_seconds',
                                       'configuration_stored_privately', 'vpn_connected'})
        self.assertRegex(self.ident, r'^[0-9a-f]{32}$')
        self.assertTrue(result['configuration_stored_privately'])
        self.assertFalse(result['vpn_connected'])
        self.assertEqual(result['expires_in_seconds'], store.MAX_AGE_SECONDS)
        self.assertEqual(saved.summary, parsed.summary)
        self.assertEqual(saved.summary, result['summary'])
        self.assertEqual(saved.summary, {'node_count': 1, 'endpoint_count': 1, 'protocols': ['tuic'],
                                        'warnings': ['Submitted node names were replaced by generated private identifiers.'],
                                        'normalization_required': True})
        self.assertEqual(saved.private_config, parsed.private_config)
        self.assertEqual(saved.endpoints, (('udp', IP, 443),))
        self.assertIsNone(saved.bound_job)
        self.assert_redacted(repr(parsed), repr(saved), str(saved), json.dumps(result))
        self.assertNotIn(saved.digest, repr(saved) + repr(result))
        self.assertNotIn(NODE_NAME, self.path.read_text())
        self.assertEqual(stat.S_IMODE(self.inputs.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(self.path.stat().st_nlink, 1)
        self.assertEqual(list(self.inputs.iterdir()), [self.path])
        self.run.assert_not_called()

    def test_saved_configuration_gets_its_own_ticket_with_nothing_to_normalize(self):
        first = self.submit()
        original = self.read(now=NOW)
        later = NOW + 2 * store.MAX_AGE_SECONDS  # The first ticket has long expired; its VM keeps the nodes.
        self.reject(self.read, now=later)
        with mock.patch('vpn_store.resolve_public_hostname', side_effect=AssertionError('no DNS for a copy')):
            result = store.store_saved(self.state, copy.deepcopy(original.private_config), list(original.endpoints), now=later)
        self.assertEqual(set(result), set(first))
        self.assertNotEqual(result['configuration_id'], first['configuration_id'])
        self.assertEqual(result['summary'], {'node_count': 1, 'endpoint_count': 1, 'protocols': ['tuic'],
                                             'warnings': [], 'normalization_required': False})
        self.assertEqual(result['expires_in_seconds'], store.MAX_AGE_SECONDS)
        copied = store.load_configuration(self.state, result['configuration_id'], now=later)
        self.assertEqual(copied.private_config, original.private_config)
        self.assertEqual(copied.endpoints, original.endpoints)
        self.assertEqual(copied.digest, original.digest)
        self.assertEqual(copied.summary, result['summary'])
        self.assertIsNone(copied.bound_job)
        claimed = store.claim_configuration(self.state, result['configuration_id'], OTHER_JOB, now=later)
        self.assertEqual(claimed.bound_job, OTHER_JOB)
        self.assertEqual(len(list(self.inputs.iterdir())), 2)
        self.assert_redacted(json.dumps(result), repr(copied))
        ticket = self.inputs / (result['configuration_id'] + '.json')
        self.assertEqual(stat.S_IMODE(ticket.stat().st_mode), 0o600)
        self.reject(store.load_configuration, self.state,
                    store.store_saved(self.state, original.private_config, original.endpoints, now=later)['configuration_id'],
                    now=later + store.MAX_AGE_SECONDS + 1)
        self.run.assert_not_called()

    def test_saved_configuration_is_refused_unless_reparsing_changes_nothing(self):
        self.submit()
        original = self.read(now=NOW)
        config, endpoints = original.private_config, list(original.endpoints)

        def changed(**node):
            value = copy.deepcopy(config)
            value['proxies'][0].update(node)
            return value
        errors = (store.VPNStoreError, VPNConfigurationError)
        for label, candidate, pinned in (
                ('not yet normalized', {'proxies': payload()['nodes']}, endpoints),
                ('only the nodes', {'proxies': config['proxies']}, endpoints),
                ('unsupported option', changed(extra=SECRET), endpoints),
                ('another server', changed(server='9.9.9.9'), endpoints),
                ('another endpoint set', config, [('udp', '9.9.9.9', 443)]),
                ('no endpoints', config, []),
                ('extra policy', dict(config, extra=SECRET), endpoints),
                ('no nodes', dict(config, proxies=None), endpoints),
                ('not a mapping', [config], endpoints),
                ('endpoints not a list', config, 'udp')):
            with self.subTest(label):
                self.reject(store.store_saved, self.state, candidate, pinned, now=NOW, error=errors)
        self.reject(store.store_saved, self.state, config, endpoints, now='soon')
        self.assertEqual(list(self.inputs.iterdir()), [self.path])
        self.run.assert_not_called()

    def test_unexpected_parser_summary_is_not_exposed_or_written(self):
        parsed = store.parse_submission(payload())
        for summary in (dict(parsed.summary, extra=SECRET), dict(parsed.summary, warnings=[SECRET])):
            with self.subTest(shape=set(summary)):
                untrusted = replace(parsed, summary=summary)
                with mock.patch('vpn_store.parse_submission', side_effect=[untrusted, parsed]):
                    self.reject(self.submit)
        self.assertFalse(self.inputs.exists())

    def test_unclaimed_expiry_and_clock_validation_do_not_mutate(self):
        self.submit()
        age_boundary = NOW + store.MAX_AGE_SECONDS
        self.assertIsNone(self.read(now=age_boundary).bound_job)
        before = self.path.read_bytes()
        for operation in (self.read, self.claim):
            self.assertIn('过期', self.reject(operation, now=age_boundary + .01))
            for bad in (NOW - .01, True, '1700000000', float('nan'), float('inf'), float('-inf'), 1 << 100):
                with self.subTest(operation=operation.__name__, clock=bad):
                    self.assertIn('时间', self.reject(operation, now=bad))
        self.assertEqual(self.path.read_bytes(), before)

    def test_claim_is_exact_and_idempotent_even_past_unclaimed_expiry(self):
        self.submit()
        before = self.read(now=NOW)
        self.reject(self.read, job_id=JOB, now=NOW)
        self.reject(self.claim, job=None, now=NOW)
        self.reject(self.claim, job=SECRET, now=NOW)
        self.assertIsNone(self.read(now=NOW).bound_job)
        claimed = self.claim(now=NOW + store.MAX_AGE_SECONDS)
        self.assertEqual(claimed.bound_job, JOB)
        self.assertEqual(claimed.digest, before.digest)
        ino = self.path.stat().st_ino
        later = NOW + store.MAX_AGE_SECONDS * 2
        self.assertEqual(self.claim(now=later), claimed)
        self.assertEqual(self.read(job_id=JOB, now=later), claimed)
        self.assertEqual(self.path.stat().st_ino, ino)
        self.reject(self.read, now=later)
        self.reject(self.read, job_id=OTHER_JOB, now=later)
        self.reject(self.claim, job=OTHER_JOB, now=later)
        self.assertEqual(list(self.inputs.iterdir()), [self.path])

    def test_concurrent_claims_choose_only_one_job(self):
        self.submit()
        barrier = threading.Barrier(2, timeout=5)

        def try_claim(job_id):
            barrier.wait()
            try:
                return self.claim(job=job_id, now=NOW).bound_job
            except store.VPNStoreError as exc:
                self.assertIn('另一任务', str(exc))
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = [pool.submit(try_claim, job) for job in (JOB, OTHER_JOB)]
            results = [future.result(timeout=10) for future in outcomes]
        self.assertEqual(results.count(None), 1)
        winner = next(job for job in results if job is not None)
        self.assertEqual(self.read(job_id=winner, now=NOW).bound_job, winner)

    def test_record_schema_even_if_checksums_match(self):
        self.submit()
        valid = json.loads(self.path.read_bytes())
        cases = [
            ('identity', {'configuration_id': OTHER_JOB}), ('version type', {'version': 2.0}),
            ('v1', {'version': 1}), ('consent', {'consent': SECRET}),
            ('binding', {'bound_job': {'job_id': JOB}}), ('timestamp type', {'created_unix': True}),
            ('negative timestamp', {'created_unix': -1}), ('extra root key', {SECRET: None}),
            ('missing private field', {'private_config': {}}), ('endpoint mismatch', {'endpoints': [['udp', IP, 444]]}),
            ('wrong endpoint shape', {'endpoints': [SECRET]}),
            ('duplicate fence', {'endpoints': valid['endpoints'] * 2}),
            ('changed policy', {'private_config': dict(valid['private_config'], **{'allow-lan': True})}),
            ('numeric boolean', {'private_config': dict(valid['private_config'], **{'allow-lan': 0})}),
        ]
        summary = valid['summary']
        for key, value in (('node_count', True), ('node_count', 2), ('endpoint_count', 0),
                           ('protocols', ['tuic', 'tuic']), ('protocols', [SECRET]), ('warnings', [SECRET]),
                           ('warnings', summary['warnings'] * 2), ('warnings', SECRET),
                           ('normalization_required', 1), ('normalization_required', False), ('extra', SECRET)):
            cases.append(('summary ' + key, {'summary': dict(summary, **{key: value})}))
        for label, changes in cases:
            with self.subTest(case=label):
                record = dict(copy.deepcopy(valid), **changes)
                record['digest'] = store._digest(record['private_config'], record['endpoints'])
                record['record_digest'] = store._record_digest(record)
                self.path.write_bytes(store._json_bytes(record))
                self.reject(self.read, now=NOW)
                self.reject(self.claim, now=NOW)

    def test_checksum_covers_valid_looking_changes_to_metadata(self):
        self.submit()
        valid = json.loads(self.path.read_bytes())
        for change in ({'created_unix': NOW - 1}, {'bound_job': JOB},
                       {'summary': dict(valid['summary'], warnings=[], normalization_required=False)}):
            with self.subTest(keys=sorted(change)):
                self.path.write_bytes(store._json_bytes(dict(valid, **change)))
                self.assertIn('完整性', self.reject(self.read, now=NOW))

    def test_malformed_json_does_not_echo_private_text(self):
        self.submit()
        valid = self.path.read_bytes()
        malformed = (b'{"version":2,' + valid[1:], b'{"bad":"' + SECRET.encode() + b'"',
                     b'\xff' + SECRET.encode(), b'{"created_unix":NaN}', b'{"created_unix":1e9999}',
                     b'{"created_unix":' + b'9' * 10000 + b'}', b'[' * 5000 + b']' * 5000)
        for index, raw in enumerate(malformed):
            with self.subTest(case=index):
                self.path.write_bytes(raw)
                self.reject(self.read, now=NOW)

    def test_invalid_ids_and_missing_reads_do_not_create_storage(self):
        for ident in ('../' + SECRET, 'A' * 32, 'a' * 32 + '\n', True, None):
            self.reject(store.load_configuration, self.state, ident, now=NOW)
            self.reject(store.claim_configuration, self.state, ident, JOB, now=NOW)
        self.reject(store.load_configuration, self.state, OTHER_JOB, now=NOW)
        self.reject(store.claim_configuration, self.state, OTHER_JOB, JOB, now=NOW)
        self.assertFalse(self.inputs.exists())

    def test_directory_symlinks_at_ancestor_state_or_store_are_rejected(self):
        state_link = self.root / 'state-alias'
        state_link.symlink_to(self.state, target_is_directory=True)
        self.reject(store.store_submission, state_link, payload(), now=NOW)
        parent_link = self.root / 'parent-alias'
        parent_link.symlink_to(self.root, target_is_directory=True)
        self.reject(store.store_submission, parent_link / 'state', payload(), now=NOW)
        outside = self.root / 'elsewhere'
        outside.mkdir(mode=0o700)
        self.inputs.symlink_to(outside, target_is_directory=True)
        self.reject(store.store_submission, self.state, payload(), now=NOW)
        self.reject(store.load_configuration, self.state, OTHER_JOB, now=NOW)
        self.assertEqual(list(outside.iterdir()), [])

    def test_file_symlinks_hard_links_fifos_and_collisions_are_not_touched(self):
        self.submit()
        content = self.path.read_bytes()
        cases = [('1' * 32, lambda p: p.symlink_to(self.path)),
                 ('2' * 32, lambda p: p.symlink_to(self.root / 'not-created')),
                 ('3' * 32, lambda p: os.link(self.path, p)),
                 ('4' * 32, lambda p: os.mkfifo(p, 0o600))]
        for ident, make in cases:
            with self.subTest(ident=ident):
                path = self.inputs / (ident + '.json')
                make(path)
                expected = path.lstat()
                self.reject(store.load_configuration, self.state, ident, now=NOW)
                self.reject(store.claim_configuration, self.state, ident, JOB, now=NOW)
                with mock.patch('vpn_store.uuid.uuid4', return_value=SimpleNamespace(hex=ident)):
                    self.reject(store.store_submission, self.state, payload(), now=NOW)
                self.assertEqual((path.lstat().st_ino, path.lstat().st_mode), (expected.st_ino, expected.st_mode))
        self.reject(self.read, now=NOW)  # its hard-link count is now two
        self.assertEqual(self.path.read_bytes(), content)
        self.assertEqual(len(list(self.inputs.iterdir())), len(cases) + 1)
        self.assertFalse((self.root / 'not-created').exists())

    def test_regular_collision_does_not_replace_the_original(self):
        self.submit()
        before = self.path.stat(), self.path.read_bytes()
        with mock.patch('vpn_store.uuid.uuid4', return_value=SimpleNamespace(hex=self.ident)):
            self.assertIn('冲突', self.reject(store.store_submission, self.state, payload(), now=NOW))
        self.assertEqual(self.path.stat().st_ino, before[0].st_ino)
        self.assertEqual(self.path.read_bytes(), before[1])
        self.assertEqual(list(self.inputs.iterdir()), [self.path])

    def test_unsafe_modes_rejected_without_chmod_or_write(self):
        self.state.chmod(0o750)
        self.reject(store.store_submission, self.state, payload(), now=NOW)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o750)
        self.assertFalse(self.inputs.exists())
        self.state.chmod(0o700)
        self.submit()
        for path, safe, unsafe in ((self.inputs, 0o700, (0o750, 0o755)), (self.path, 0o600, (0o640, 0o700))):
            for mode in unsafe:
                path.chmod(mode)
                self.reject(self.read, now=NOW)
                self.reject(self.claim, now=NOW)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            path.chmod(safe)
        self.assertIsNone(self.read(now=NOW).bound_job)

    def test_record_growth_after_read_cannot_be_overwritten_by_claim(self):
        self.submit()
        real_publish = store._publish_record
        changed = self.path.read_bytes() + b' '

        def mutate_then_publish(*args, **kwargs):
            self.path.write_bytes(changed)
            return real_publish(*args, **kwargs)

        with mock.patch('vpn_store._publish_record', side_effect=mutate_then_publish):
            self.reject(self.claim, now=NOW)
        self.assertEqual(self.path.read_bytes(), changed)
        self.assertEqual(list(self.inputs.iterdir()), [self.path])

    def test_stage_write_failure_is_redacted_and_original_is_preserved(self):
        self.submit()
        before = self.path.read_bytes()
        with mock.patch('vpn_store.os.fsync', side_effect=OSError(5, SECRET, self.path)):
            self.reject(self.claim, now=NOW)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.inputs.iterdir()), [self.path])
        self.assertIsNone(self.read(now=NOW).bound_job)

    def test_oversized_record_rejected_before_reading(self):
        self.submit()
        with self.path.open('wb') as stream:
            stream.truncate(store._MAX_RECORD_BYTES + 1)
        with mock.patch('vpn_store.os.pread') as read:
            self.reject(self.read, now=NOW)
            read.assert_not_called()

    def test_submission_limits_before_storage_and_processes(self):
        invalid = [dict(input_mode='fields', nodes=[payload()['nodes'][0] for _ in range(17)]),
                   payload(password='x' * 4097), payload(password='\ud800'),
                   dict(input_mode='yaml', yaml_text='界' * (store.MAX_CONFIG_BYTES // 3 + 1))]
        for value in invalid:
            self.reject(store.store_submission, self.state, value, now=NOW, error=VPNConfigurationError)
        self.reject(store.store_submission, self.state, payload(), now=float('nan'))
        self.run.assert_not_called()
        self.assertFalse(self.inputs.exists())

    def test_generated_nodes_must_also_fit_parser_byte_limit(self):
        nodes = [{'type': 'hysteria2', 'server': IP, 'port': 443, 'password': 'p',
                  'obfs': 'salamander', 'obfs-password': 'o'} for _ in range(16)]
        value = dict(input_mode='fields', nodes=nodes)
        room = store.MAX_CONFIG_BYTES - len(json.dumps(value, ensure_ascii=False).encode())
        for node in nodes:
            for key in ('password', 'obfs-password'):
                repeat = min(room // 4, 4095)
                node[key] += '🍃' * repeat
                room -= repeat * 4
        nodes[-1]['password'] += 'x' * room
        self.assertEqual(store.parse_submission(value).summary['node_count'], 16)
        self.reject(store.store_submission, self.state, value, now=NOW, error=VPNConfigurationError)
        self.assertFalse(self.inputs.exists())

    def test_yaml_limit_is_raw_bytes_and_upload_is_not_preserved(self):
        head = '# ' + PROFILE_SECRET + '\n# '
        text = head + '\\' * (store.MAX_CONFIG_BYTES - len(head))
        normalized_input = {'proxies': payload()['nodes'], 'secret': PROFILE_SECRET}
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(normalized_input).encode())
        result = self.submit({'input_mode': 'yaml', 'yaml_text': text})
        self.assertEqual(self.run.call_args.kwargs['input'], text.encode())
        self.assertEqual(self.read(now=NOW).summary, result['summary'])
        self.assertTrue(result['summary']['normalization_required'])
        self.assertNotIn(PROFILE_SECRET, self.path.read_text())
        self.assertNotIn('yaml_text', self.path.read_text())
        self.assert_redacted(repr(result))

    def test_yaml_path_reads_only_explicit_source_and_does_not_preserve_it(self):
        profile = {'proxies': payload()['nodes'], 'secret': PROFILE_SECRET}
        header = (json.dumps(profile) + '\n# ').encode()
        raw = header + b'x' * (store.MAX_CONFIG_BYTES - len(header))
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(profile).encode())
        for suffix in ('.yaml', '.yml'):
            with self.subTest(suffix=suffix):
                source = self.root / ('合成配置 with spaces' + suffix)
                source.write_bytes(raw)
                source.chmod(0o644)
                before = store._snapshot(source.stat())
                result = self.submit(path_payload(source))
                self.assertEqual(self.run.call_args.kwargs['input'], raw)
                self.assertNotIn(str(source), ' '.join(self.run.call_args.args[0]))
                stored = self.read(now=NOW)
                self.assertEqual(stored.summary, result['summary'])
                self.assertEqual(stored.private_config, store.parse_submission(payload()).private_config)
                self.assert_redacted(repr(result), repr(stored))
                record_text = self.path.read_text()
                for private in (str(source), source.name, PROFILE_SECRET, 'yaml_path', 'yaml_text'):
                    for output in (repr(result), repr(stored), record_text):
                        self.assertNotIn(private, output)
                self.assertEqual(store._snapshot(source.stat()), before)
                self.assertEqual(source.read_bytes(), raw)
        self.assertEqual(self.run.call_count, 2)

    def test_yaml_path_requires_exact_shape_and_canonical_syntax_before_io(self):
        source = self.root / (SECRET + '.yaml')
        bad_paths = (None, 123, source, str(source.relative_to(self.root)), '~/' + source.name,
                     'file://' + str(source), 'https://example.com/' + source.name, '/' + str(source),
                     str(self.root) + '//' + source.name, str(self.root) + '/./' + source.name,
                     str(self.root) + '/sub/../' + source.name, str(source) + '/', str(source) + '.json',
                     str(source) + '\n.yml', str(source) + '\u0085.yml', str(source) + '\u202e.yml',
                     str(source) + '\x00.yml', str(source) + '\ud800.yml',
                     str(self.root) + '/' + '界' * store._MAX_YAML_PATH_BYTES + '.yml',
                     str(self.root) + '/' + '界' * (store._MAX_YAML_PATH_BYTES // 3) + '.yml')
        bad = [{'input_mode': 'yaml_path', 'path': value} for value in bad_paths]
        bad += [{'input_mode': 'yaml_path'}, dict(path_payload(source), yaml_text=PROFILE_SECRET)]
        with mock.patch('vpn_store.os.open', side_effect=AssertionError('must reject before opening')):
            for index, submitted in enumerate(bad):
                with self.subTest(case=index):
                    self.reject(self.submit, submitted)
        self.assertFalse(self.inputs.exists())
        self.run.assert_not_called()

    def test_yaml_path_rejects_unsafe_source_entries_before_read(self):
        target = self.root / 'source.yaml'
        target.write_text('# ' + PROFILE_SECRET)
        target.chmod(0o644)
        alias = self.root / 'alias.yaml'
        alias.symlink_to(target)
        dangling = self.root / 'dangling.yml'
        dangling.symlink_to(self.root / 'missing.yaml')
        parent_link = self.root / 'ancestor'
        parent_link.symlink_to(self.root, target_is_directory=True)
        fifo = self.root / 'fifo.yaml'
        os.mkfifo(fifo, 0o600)
        dir_source = self.root / 'dir.yaml'
        dir_source.mkdir()
        oversized = self.root / 'oversized.yaml'
        with oversized.open('wb') as stream:
            stream.truncate(store.MAX_CONFIG_BYTES + 1)
        writable = self.root / 'writable.yml'
        writable.write_bytes(target.read_bytes())
        hard = self.root / 'second-link.yml'
        os.link(target, hard)
        with mock.patch('vpn_store.os.pread') as read:
            for index, source in enumerate((alias, dangling, parent_link / target.name, fifo, dir_source,
                                            oversized, target, hard, self.root / 'missing.yaml')):
                with self.subTest(case=index):
                    self.reject(self.submit, path_payload(source))
            for mode in (0o664, 0o646, 0o666):
                writable.chmod(mode)
                self.reject(self.submit, path_payload(writable))
                self.assertEqual(stat.S_IMODE(writable.stat().st_mode), mode)
            writable.chmod(0o644)
            with mock.patch('vpn_store.os.getuid', return_value=os.getuid() + 1):
                self.reject(self.submit, path_payload(writable))
            read.assert_not_called()
        self.assertFalse(self.inputs.exists())
        self.run.assert_not_called()

    def test_yaml_path_read_and_decode_errors_are_sanitized(self):
        source = self.root / (SECRET + '.yaml')
        source.write_bytes(b'\xff' + PROFILE_SECRET.encode())
        self.reject(self.submit, path_payload(source))
        with mock.patch('vpn_store.os.pread', side_effect=OSError(5, PROFILE_SECRET, source)):
            self.reject(self.submit, path_payload(source))
        self.assertFalse(self.inputs.exists())
        self.run.assert_not_called()

    def test_yaml_path_rejects_changed_file_identity_before_read(self):
        source = self.root / 'source.yaml'
        alternate = self.root / 'alternate.yaml'
        for entry in (source, alternate):
            entry.write_text('# ' + PROFILE_SECRET)
        real_open = os.open

        def open_different_source(path, flags, *args, **kwargs):
            if path == source.name:
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)
                path = alternate.name
            return real_open(path, flags, *args, **kwargs)

        with mock.patch('vpn_store.os.open', side_effect=open_different_source), mock.patch('vpn_store.os.pread') as read:
            self.reject(self.submit, path_payload(source))
            read.assert_not_called()
        self.assertFalse(self.inputs.exists())
        self.run.assert_not_called()

    def test_yaml_path_rejects_file_and_ancestor_changes_during_read(self):
        original = b'# ' + PROFILE_SECRET.encode()
        for case in ('file', 'ancestor'):
            with self.subTest(case=case):
                parent = self.root / case
                parent.mkdir()
                source = parent / 'source.yaml'
                source.write_bytes(original)
                real_pread = os.pread

                def read_and_change(fd, count, offset):
                    result = real_pread(fd, count, offset)
                    self.assertEqual(count, len(original))
                    if case == 'file':
                        with source.open('ab') as stream:
                            stream.write(b'\n# changed')
                    else:
                        parent.rename(self.root / 'moved')
                        parent.mkdir()
                        source.write_bytes(original)
                    return result

                with mock.patch('vpn_store.os.pread', side_effect=read_and_change):
                    self.reject(self.submit, path_payload(source))
                self.assertFalse(self.inputs.exists())
        self.run.assert_not_called()

    def test_dns_off_by_default_even_with_supplied_resolver(self):
        resolver = mock.Mock(return_value=[IP])
        self.reject(store.store_submission, self.state, payload(server=HOST), now=NOW, resolver=resolver,
                    error=VPNConfigurationError)
        self.reject(store.store_submission, self.state, payload(server=HOST), now=NOW, allow_resolve=1,
                    resolver=resolver)
        self.reject(store.store_submission, self.state, payload(server=HOST), now=NOW, allow_resolve=True,
                    resolver=None, error=VPNConfigurationError)
        resolver.assert_not_called()
        self.run.assert_not_called()
        self.assertFalse(self.inputs.exists())

    def test_explicit_fake_resolver_pins_all_and_is_never_used_on_read(self):
        resolver = mock.Mock(return_value=['9.9.9.9', IP])
        submitted = payload(server=HOST.upper())
        del submitted['nodes'][0]['sni']
        result = self.submit(submitted, allow_resolve=True, resolver=resolver)
        resolver.assert_called_once_with(HOST)
        claim = self.claim(now=NOW)
        self.assertEqual(claim.endpoints, (('udp', IP, 443),))
        self.assertEqual(claim.private_config['proxies'][0]['sni'], HOST)
        self.assertEqual(claim.private_config['proxies'][0]['server'], IP)
        self.assertEqual(self.read(job_id=JOB, now=NOW).summary, result['summary'])
        self.assert_redacted(repr(result), repr(claim))
        resolver.assert_called_once()
        self.run.assert_not_called()

    def test_bad_resolver_answers_and_exceptions_do_not_leak(self):
        for resolver in (mock.Mock(side_effect=RuntimeError(SECRET)),
                         mock.Mock(return_value=[IP, '127.0.0.1']), mock.Mock(return_value=[IP, '224.0.0.1']),
                         mock.Mock(return_value=[IP] * 17), mock.Mock(return_value=[HOST])):
            self.reject(store.store_submission, self.state, payload(server=HOST), now=NOW, allow_resolve=True,
                        resolver=resolver, error=VPNConfigurationError)
            resolver.assert_called_once_with(HOST)
        self.run.assert_not_called()
        self.assertFalse(self.inputs.exists())

    def test_opt_in_system_resolver_contract_is_simulated(self):
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps([IP]).encode())
        self.submit(payload(server=HOST), allow_resolve=True)
        args, kwargs = self.run.call_args
        self.assertNotIn(HOST, ' '.join(args[0]))
        self.assertNotIn(SECRET, ' '.join(args[0]))
        self.assertEqual(kwargs['input'], json.dumps(HOST).encode())
        self.assertEqual(kwargs['timeout'], 12)
        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(self.read(now=NOW).endpoints, (('udp', IP, 443),))
        self.run.assert_called_once()
        self.run.side_effect = subprocess.TimeoutExpired(SECRET, 12)
        self.reject(store.resolve_public_hostname, HOST)


if __name__ == '__main__':
    unittest.main()
