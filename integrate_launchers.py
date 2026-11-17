#!/usr/bin/env python3
"""Install only the reviewed share adapter; leave network policy and VM disks alone."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
HOME=Path.home()
BASES=[HOME/'Applications'/n for n in ('GoldNetwork','GoldBackupNetwork','GoldFreshNetwork')]
TART=str(HOME/'Applications/tart.app/Contents/MacOS/tart')
ENV=dict(os.environ,HOME=str(HOME),TART_HOME=str(HOME/'.tart'))
MARKER='# GOLD_VM_MANAGER_SHARES_V1'


def main():
    os.umask(0o077)
    vms=json.loads(subprocess.run([TART,'list','--format','json'],env=ENV,capture_output=True,text=True,check=True).stdout)
    if any(v.get('Running') for v in vms if v.get('Name') in ('gold','gold-backup','gold-fresh')):
        raise SystemExit('VMs must not be running while installing the share adapter')
    module=(ROOT/'runtime_shares.py').read_text()
    ast.parse(module)
    plans=[]
    for base in BASES:
        path=base/'launcher.py'
        if base.resolve(strict=True)!=base or base.is_symlink() or path.is_symlink():raise RuntimeError('Unsafe launcher path')
        code=path.read_text()
        if MARKER in code:raise RuntimeError('Already integrated; review existing version rather than blind overwrite')
        new=code
        changes={
            'from packet_policy import PacketPolicy':'from packet_policy import PacketPolicy\nfrom share_support import prepare_vm_shares\n'+MARKER,
            '    endpoints = [tuple(x) for x in cfg[\'endpoints\']]':'    share_plan = prepare_vm_shares(VM_CONFIG.parent.name, BASE, gold[0][\'State\'])\n    endpoints = [tuple(x) for x in cfg[\'endpoints\']]',
            "        # No host directory shares, no inherited default NAT NIC, no install media.":'        # Only explicitly configured named shares; no NAT fallback or extra disks.',
            '        vm_sock.close()':'        share_plan.record_launch(child.pid)\n        vm_sock.close()',
            "        status.update(state='starting',tart_pid=child.pid,backend_pid=backend.pid,vm_network_seen=False)":"        status.update(state='starting',tart_pid=child.pid,backend_pid=backend.pid,vm_network_seen=False,shared_directory_count=len(share_plan.shares),sharing_allows_suspend=share_plan.suspendable)",
        }
        for old,replacement in changes.items():
            if new.count(old)!=1:raise RuntimeError('Unexpected launcher version: '+base.name)
            new=new.replace(old,replacement)
        vm={'GoldNetwork':'gold','GoldBackupNetwork':'gold-backup','GoldFreshNetwork':'gold-fresh'}[base.name]
        old="        cmd=[TART,'run','"+vm+"','--net-fd='+str(vm_sock.fileno()),'--suspendable']"
        replacement=("        cmd=[TART,'run','"+vm+"','--net-fd='+str(vm_sock.fileno())]\n"
                     "        if share_plan.suspendable:\n            cmd.append('--suspendable')\n"
                     "        cmd.extend(share_plan.arguments)")
        if new.count(old)!=1:raise RuntimeError('Unexpected VM run command')
        new=new.replace(old,replacement)
        ast.parse(new)
        plans.append((base,path,code,new))
    backup=ROOT/'evidence/launcher-backups'
    backup.mkdir(parents=True,mode=0o700,exist_ok=False)
    for base,path,old,new in plans:
        dst=backup/(base.name+'-launcher.py')
        with dst.open('x') as f:f.write(old)
        target=base/'share_support.py'
        if target.exists() or target.is_symlink():raise RuntimeError('Share adapter already exists')
        with target.open('x') as f:f.write(module)
        target.chmod(0o600)
        # Fixed existing launcher was read and checked in full above; never writes a VM image.
        if path.resolve(strict=True)!=path or path.is_symlink():raise RuntimeError('Launcher path changed')
        path.write_text(new)
        path.chmod(0o600)
    result={'installed':True,'vms':['gold','gold-backup','gold-fresh'],'shares_default_empty':True,
            'network_policy_changed':False,'vm_disk_changed':False,'saved_state_discarded':False,
            'adapter_sha256':hashlib.sha256(module.encode()).hexdigest()}
    with (ROOT/'evidence/integration.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))

if __name__=='__main__':main()
