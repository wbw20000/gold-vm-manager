"""One-shot explicit local app upgrade. Never calls VM action/delete/create APIs."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import signal
import subprocess
from urllib.request import Request, build_opener, ProxyHandler

ROOT=Path(__file__).resolve().parent
HOME=Path.home()
APP=Path('/Applications/Gold VM 管理器.app')
PAYLOAD=APP/'Contents/Resources/app'
STATE=HOME/'Library/Application Support/GoldVMManager'
BACKUP=ROOT/'evidence/rebuild-installed-backup'
FILES=('manager.py','bootstrap.py','runtime_shares.py','discard_state.py','managed_registry.py',
       'lifecycle.py','process_identity.py','provisioning.py','protected_launcher.py',
       'static/index.html','static/app.js','static/style.css')
ENV=dict(os.environ,HOME=str(HOME),TART_HOME=str(HOME/'.tart'),TART_NO_AUTO_PRUNE='1')


def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    assert APP.resolve(strict=True)==APP and not APP.is_symlink()
    assert not BACKUP.exists()
    plist=APP/'Contents/Info.plist'
    info=plistlib.loads(plist.read_bytes())
    assert info['CFBundleIdentifier']=='local.gold.vm-manager'
    old_controller=None
    serverinfo=STATE/'server.json'
    if serverinfo.exists():
        s=json.loads(serverinfo.read_text())
        args=subprocess.run(['/bin/ps','-p',str(s['pid']),'-o','args='],capture_output=True,text=True)
        if args.returncode==0:
            assert str(PAYLOAD/'manager.py') in args.stdout
            req=Request('http://127.0.0.1:18765/api/state',headers={'Authorization':'Bearer '+s['token'],'Origin':'http://127.0.0.1:18765'})
            with build_opener(ProxyHandler({})).open(req,timeout=6) as response: state=json.load(response)
            assert not any(v['busy'] for v in state['vms'])
            assert not state.get('build_job')
            old_controller=s['pid']
    BACKUP.mkdir(mode=0o700)
    inventory=json.loads(subprocess.run([str(HOME/'Applications/tart.app/Contents/MacOS/tart'),'list','--format','json'],env=ENV,capture_output=True,text=True,check=True).stdout)
    config=STATE/'config.json'
    baseline={'vm_states':{v['Name']:v['State'] for v in inventory},'shared_config_sha256':digest(config) if config.exists() else None}
    (BACKUP/'vm-baseline.json').write_text(json.dumps(baseline,indent=2))
    shutil.copy2(str(plist),str(BACKUP/'Info.plist'))
    for name in FILES:
        src=PAYLOAD/name
        if src.exists():
            assert src.resolve(strict=True)==src and not src.is_symlink()
            dst=BACKUP/'app'/name;dst.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
            shutil.copy2(str(src),str(dst))
    # Update only reviewed share adapters. Packet policies/launchers/binaries remain untouched.
    legacy=[]
    for name in ('GoldNetwork','GoldBackupNetwork','GoldFreshNetwork'):
        base=HOME/'Applications'/name
        old=base/'share_support.py'
        assert old.resolve(strict=True)==old and digest(old)==digest(PAYLOAD/'runtime_shares.py')
        assert not (base/'managed_registry.py').exists()
        dst=BACKUP/'launchers'/name;dst.mkdir(parents=True,mode=0o700)
        shutil.copy2(str(old),str(dst/'share_support.py'))
        legacy.append(base)
    subprocess.run(['/usr/bin/swift','-e','import AppKit;import Foundation;let apps=NSRunningApplication.runningApplications(withBundleIdentifier:"local.gold.vm-manager");for a in apps{_=a.terminate()};let end=Date().addingTimeInterval(4);while Date()<end && apps.contains(where:{!$0.isTerminated}){RunLoop.current.run(until:Date().addingTimeInterval(0.05))};guard apps.allSatisfy({$0.isTerminated}) else{exit(2)}'],check=True)
    if old_controller:
        check=subprocess.run(['/bin/ps','-p',str(old_controller),'-o','args='],capture_output=True,text=True)
        assert check.returncode==0 and str(PAYLOAD/'manager.py') in check.stdout
        os.kill(old_controller,signal.SIGTERM)
    for name in FILES:
        target=PAYLOAD/name
        assert not target.is_symlink() and target.parent.resolve(strict=True)==target.parent
        shutil.copy2(str(ROOT/name),str(target));target.chmod(0o644)
    guest=PAYLOAD/'guest_setup'
    assert not guest.exists();shutil.copytree(str(ROOT/'guest_setup'),str(guest))
    for p in guest.iterdir():p.chmod(0o644)
    guest.chmod(0o755)
    helper=PAYLOAD/'CleanVMInstaller'
    assert not helper.exists()
    shutil.copy2(str(ROOT/'evidence/newbuild/CleanVMInstaller'),str(helper));helper.chmod(0o755)
    for base in legacy:
        shutil.copy2(str(ROOT/'runtime_shares.py'),str(base/'share_support.py'));(base/'share_support.py').chmod(0o600)
        shutil.copy2(str(ROOT/'managed_registry.py'),str(base/'managed_registry.py'));(base/'managed_registry.py').chmod(0o600)
    info['CFBundleShortVersionString']='1.1.0';info['CFBundleVersion']='3'
    plist.write_bytes(plistlib.dumps(info));plist.chmod(0o644)
    # Preserve the helper's explicitly signed virtualization entitlement.
    subprocess.run(['/usr/bin/codesign','--verify','--strict',str(helper)],check=True)
    subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(APP)],check=True)
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(APP)],check=True)
    final={name:digest(PAYLOAD/name) for name in FILES}
    (BACKUP/'installed-hashes.json').write_text(json.dumps(final,indent=2))
    print('Installed Gold VM Manager 1.1.0. Only app/adapters updated; no VM lifecycle action performed.')

if __name__=='__main__':main()
