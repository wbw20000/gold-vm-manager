#!/usr/bin/env python3
"""Discard one explicitly confirmed suspended state, atomically excluding Tart start.
Separate process is essential: POSIX record locks are process-wide and another
thread closing a config fd in the HTTP process could accidentally release them.
No power-off, VM disk edits, or directory deletion is performed here.
"""
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import managed_registry

VM_ROOT=Path.home()/'.tart/vms'
VM_IDS={'gold','gold-backup','gold-fresh'}


def discard(vm):
    if vm not in managed_registry.allowed_vm_ids() or vm == 'dsh purge测试':
        raise ValueError('Unknown VM')
    base=VM_ROOT/vm
    config=base/'config.json'
    target=base/'state.vzvmsave'
    if base.is_symlink() or base.resolve(strict=True)!=base or not base.is_dir():
        raise RuntimeError('Unexpected VM directory')
    if config.is_symlink() or config.resolve(strict=True)!=config or not config.is_file():
        raise RuntimeError('Unexpected VM config path')
    info=config.stat()
    if info.st_uid!=os.getuid():
        raise RuntimeError('Unexpected VM config owner')
    fd=os.open(str(config),os.O_RDWR|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):
            raise RuntimeError('VM config changed')
        # Tart PIDLock uses POSIX fcntl advisory write locks on this same file.
        # Do NOT open/read/close config again in this process while holding it.
        fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if target.is_symlink() or target.resolve(strict=True)!=base/'state.vzvmsave':
            raise RuntimeError('Unexpected saved-state deletion target')
        snapshot=target.lstat()
        if not stat.S_ISREG(snapshot.st_mode) or snapshot.st_uid!=os.getuid():
            raise RuntimeError('Unexpected saved-state file')
        target.unlink()
    finally:
        os.close(fd)
    return {'ok':True,'vm':vm,'saved_ram_discarded':True,'vm_disk_modified':False}


def main():
    if len(sys.argv)!=2:
        raise SystemExit(2)
    try:
        print(json.dumps(discard(sys.argv[1])))
    except (OSError,ValueError,RuntimeError):
        print(json.dumps({'ok':False,'error':'VM 正在运行、状态已改变或路径无法安全核对；未丢弃状态'}))
        raise SystemExit(3)

if __name__=='__main__':main()
