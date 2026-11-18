"""macOS internet-origin quarantine preservation; never clear or bypass Gatekeeper.

Python's os.getxattr/setxattr are Linux-only, not available in Apple's Python3.9.
Use the fixed native xattr utility explicitly. Only add a missing attribute to
caller-owned new downloads/bundles; never overwrite an existing value.
"""
import os
from pathlib import Path
import subprocess
import time
import uuid

import managed_registry as registry

NAME='com.apple.quarantine'


class QuarantineError(ValueError):pass


def _run(argv, run=subprocess.run):
    result=run(['/usr/bin/xattr']+argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=30,
               env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'en_US.UTF-8'})
    if result.returncode or len(result.stdout)>65536 or len(result.stderr)>65536:
        raise QuarantineError('Native quarantine inspection/update failed')
    return result.stdout


def read(path, *, run=subprocess.run):
    path=registry.safe_path(Path(path))
    raw=_run(['-p',NAME,str(path)],run)
    value=raw.rstrip(b'\r\n')
    if not value or len(value)>4096 or b'\x00' in value:
        raise QuarantineError('Missing or malformed quarantine')
    return value


def ensure(path, *, run=subprocess.run):
    """Preserve existing quarantine; otherwise add it without deleting any xattrs."""
    path=registry.safe_path(Path(path))
    if path.stat().st_uid!=os.getuid():raise QuarantineError('Caller-owned new artifact required')
    names=_run([str(path)],run).decode('utf-8',errors='strict').splitlines()
    if NAME not in names:
        value='0083;%x;GoldVMManager;%s' % (int(time.time()),uuid.uuid4())
        _run(['-w',NAME,value,str(path)],run)
    return read(path,run=run)


def propagate(source, target, *, run=subprocess.run):
    """Preserve exact origin on a caller-claimed new app root without clearing it.

    ditto can merge a bundle into an existing exclusively-created directory yet
    leave its root quarantine absent. Add only that missing attribute; never
    overwrite a different existing quarantine value or alter application bytes.
    """
    source=registry.safe_path(Path(source));target=registry.safe_path(Path(target))
    if target.stat().st_uid!=os.getuid():raise QuarantineError('Caller-owned new application required')
    expected=read(source,run=run)
    names=_run([str(target)],run).decode('utf-8',errors='strict').splitlines()
    if NAME not in names:
        _run(['-w',NAME,expected.decode('utf-8',errors='strict'),str(target)],run)
    actual=read(target,run=run)
    if actual!=expected:raise QuarantineError('Existing target quarantine differs; never overwrite it')
    return actual
