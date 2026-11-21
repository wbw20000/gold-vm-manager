"""Update only the Max elapsed-day digits; never infer or update account status.

Owner: if usage stops, set STOP_DATE below to date(year, month, day) using the
actual last counted Singapore date (inclusive). Leave it None while counting.
A later run will correct the digits to that day even if they already overshot.
Dates before the day-2 anchor are rejected without changing either document.
Keep any personal last-verified date/status outside the markers and edit it by hand.
"""
from contextlib import ExitStack
from datetime import date, datetime, timedelta, timezone
import os
from pathlib import Path
import re
import stat
import sys
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
READMES = ("README.md", "README.en.md")
SINGAPORE = timezone(timedelta(hours=8))
ANCHOR = date(2026, 11, 21)  # Max day 2, not a claim of continued verification.
STOP_DATE: Optional[date] = None

COUNTER = re.compile(rb"<!-- max-days:start -->([1-9][0-9]*)<!-- max-days:end -->")
# Reject extra/unpaired marker comments as well as a second complete pair.
MARKER_TAG = re.compile(rb"<!--\s*max-days\b|\bmax-days\s*:", re.IGNORECASE)


def singapore_date(instant: datetime) -> date:
    if instant.utcoffset() is None:
        raise ValueError("an aware instant is required")
    return instant.astimezone(SINGAPORE).date()


def elapsed_days(today: date) -> int:
    if today < ANCHOR or (STOP_DATE is not None and STOP_DATE < ANCHOR):
        raise ValueError("date before the documented day-2 anchor; leaving READMEs alone")
    last = min(today, STOP_DATE) if STOP_DATE is not None else today
    return 2 + (last - ANCHOR).days


def _open_no_follow(path, flags):
    return os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)


def update(today: date) -> bool:
    digits = str(elapsed_days(today)).encode("ascii")
    with ExitStack() as stack:
        changes = []
        for name in READMES:
            path = ROOT / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f"{name}: expected a regular file, not a link or special file")
            f = stack.enter_context(open(path, "r+b", opener=_open_no_follow))
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError(f"{name}: expected a single-link regular file")
            content = f.read()
            match = COUNTER.search(content)
            if match is None or len(MARKER_TAG.findall(content)) != 2:
                raise ValueError(f"{name}: expected exactly one inline decimal Max counter")
            if digits != match[1]:
                changes.append((f, match.start(1), match[1], content[match.end(1):]))

        # Both documents passed. Use the validated handles; no text re-encoding.
        for f, offset, old_digits, suffix in changes:
            f.seek(offset)
            f.write(digits)
            if len(old_digits) != len(digits):
                f.write(suffix)
                f.truncate()
        return bool(changes)


if __name__ == "__main__":
    if len(sys.argv) != 1:
        sys.exit("update_usage_days.py takes no arguments")
    try:
        changed = update(singapore_date(datetime.now(timezone.utc)))
    except (OSError, ValueError) as exc:
        sys.exit(f"Max day counter: {exc}")
    print("Updated Max day counter." if changed else "Max day counter is current.")
