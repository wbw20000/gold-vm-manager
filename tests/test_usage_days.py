"""Offline tests: only synthetic README fixtures in a temporary directory."""
from datetime import date, datetime, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import update_usage_days as counter


START = b"<!-- max-days:start -->"
END = b"<!-- max-days:end -->"


def sample_docs(days):
    marker = START + str(days).encode("ascii") + END
    zh = "人工核验：2026-11-21，第 2 天。  \r\n".encode()
    en = b"Last verified by owner: 2026-11-21, day 2.  \n"
    return (b"\xef\xbb\xbf" + zh + "Max 第 ".encode() + marker + " 天\r\n".encode(),
            b"Max day **" + marker + b"**.\n" + en)


class CalendarTests(unittest.TestCase):
    @patch.object(counter, "STOP_DATE", None)
    def test_singapore_midnight(self):
        utc = timezone.utc
        self.assertEqual(counter.elapsed_days(counter.singapore_date(
            datetime(2026, 11, 21, 15, 59, 59, 999999, tzinfo=utc))), 2)
        self.assertEqual(counter.elapsed_days(counter.singapore_date(
            datetime(2026, 11, 21, 16, 0, tzinfo=utc))), 3)
        with self.assertRaises(ValueError):
            counter.singapore_date(datetime(2026, 11, 21))


class ReadmeTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        root_patch = patch.object(counter, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        # Tests describe active counting by default, even after the owner freezes it.
        stop_patch = patch.object(counter, "STOP_DATE", None)
        stop_patch.start()
        self.addCleanup(stop_patch.stop)
        self.paths = self.root / "README.md", self.root / "README.en.md"

    def put(self, docs):
        for path, data in zip(self.paths, docs):
            path.write_bytes(data)

    def docs(self):
        return tuple(p.read_bytes() for p in self.paths)

    def test_catchup_keeps_verified_records_and_all_other_bytes(self):
        self.put(sample_docs(2))
        self.assertTrue(counter.update(date(2026, 12, 1)))
        self.assertEqual(self.docs(), sample_docs(12))  # includes unrelated literal 2s
        for path in self.paths:
            os.utime(path, (100, 100))  # catch a redundant rewrite on a fast filesystem
        self.assertFalse(counter.update(date(2026, 12, 1)))
        self.assertEqual(self.docs(), sample_docs(12))
        self.assertEqual([p.stat().st_mtime for p in self.paths], [100, 100])

    def test_only_stale_translation_is_updated(self):
        self.put((sample_docs(12)[0], sample_docs(2)[1]))
        os.utime(self.paths[0], (100, 100))
        self.assertTrue(counter.update(date(2026, 12, 1)))
        self.assertEqual(self.docs(), sample_docs(12))
        self.assertEqual(self.paths[0].stat().st_mtime, 100)

    def test_invalid_second_document_never_changes_first(self):
        good = START + b"2" + END
        for bad in (b"absent", START, END, good + good, good + START, END + good,
                    START + b"" + END, START + b"02" + END, START + b"2\n" + END,
                    START + b"-2" + END, START + b"2.0" + END,
                    START + "２".encode() + END, END + b"2" + START,
                    good + b"<!-- max-days:STOP -->"):
            with self.subTest(bad=bad):
                previous = sample_docs(2)[0], bad
                self.put(previous)
                with self.assertRaises(ValueError):
                    counter.update(date(2026, 12, 1))
                self.assertEqual(self.docs(), previous)

    def test_missing_or_symlinked_translation_does_not_touch_any_file(self):
        previous = sample_docs(2)
        self.paths[0].write_bytes(previous[0])
        with self.assertRaises(FileNotFoundError):
            counter.update(date(2026, 12, 1))
        self.assertEqual(self.paths[0].read_bytes(), previous[0])
        other = self.root / "not-a-target"
        other.write_bytes(previous[1])
        self.paths[1].symlink_to(other)
        with self.assertRaises(ValueError):
            counter.update(date(2026, 12, 1))
        self.assertEqual(self.docs(), previous)
        self.assertTrue(self.paths[1].is_symlink())
        self.assertEqual(other.read_bytes(), previous[1])

    def test_hardlink_cannot_redirect_a_write(self):
        previous = sample_docs(2)
        self.paths[0].write_bytes(previous[0])
        other = self.root / "not-a-target"
        other.write_bytes(previous[1])
        os.link(other, self.paths[1])
        with self.assertRaises(ValueError):
            counter.update(date(2026, 12, 1))
        self.assertEqual(self.docs(), previous)
        self.assertEqual(other.read_bytes(), previous[1])

    def test_before_anchor_refuses_to_invent_a_count(self):
        self.put(sample_docs(2))
        with self.assertRaises(ValueError):
            counter.update(date(2026, 11, 20))
        with patch.object(counter, "STOP_DATE", date(2026, 11, 20)):
            with self.assertRaises(ValueError):
                counter.update(date(2026, 12, 1))
        self.assertEqual(self.docs(), sample_docs(2))

    def test_inclusive_freeze_corrects_overshoot_and_stays_frozen(self):
        self.put(sample_docs(15))
        with patch.object(counter, "STOP_DATE", date(2026, 11, 23)):
            self.assertEqual(counter.elapsed_days(date(2026, 11, 22)), 3)
            self.assertEqual(counter.elapsed_days(date(2026, 11, 23)), 4)
            self.assertTrue(counter.update(date(2026, 12, 5)))
            self.assertFalse(counter.update(date(2027, 1, 5)))
        self.assertEqual(self.docs(), sample_docs(4))


if __name__ == "__main__":
    unittest.main()
