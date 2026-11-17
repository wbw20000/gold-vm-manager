#!/usr/bin/env python3
"""Package a native WKWebView app and the self-contained local Python controller."""
import ast
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
APP=Path('/Applications/Gold VM 管理器.app')
FILES=('manager.py','bootstrap.py','runtime_shares.py','discard_state.py',
       'managed_registry.py','lifecycle.py','process_identity.py','provisioning.py','protected_launcher.py',
       'setup_profile.py','vm_deletion.py')


def main():
    os.umask(0o077)
    if APP.exists() or APP.is_symlink():
        raise SystemExit('Existing app will not be overwritten; review an explicit upgrade')
    for name in FILES:
        ast.parse((ROOT/name).read_text())
    for name in ('index.html','style.css','app.js'):
        assert (ROOT/'static'/name).is_file()
    helper=ROOT/'evidence/newbuild/CleanVMInstaller'
    if not helper.is_file():
        raise SystemExit('Build the signed CleanVMInstaller helper first; see CleanVMInstaller.md')
    contents=APP/'Contents'
    mac=contents/'MacOS'
    payload=contents/'Resources/app'
    mac.mkdir(parents=True,mode=0o700)
    (payload/'static').mkdir(parents=True,mode=0o700)
    for name in FILES:
        shutil.copy2(str(ROOT/name),str(payload/name))
        (payload/name).chmod(0o600)
    for name in ('index.html','style.css','app.js'):
        shutil.copy2(str(ROOT/'static'/name),str(payload/'static'/name))
        (payload/'static'/name).chmod(0o600)
    shutil.copytree(str(ROOT/'guest_setup'),str(payload/'guest_setup'))
    shutil.copy2(str(helper),str(payload/'CleanVMInstaller'))
    (payload/'CleanVMInstaller').chmod(0o755)
    icon=ROOT/'assets/AppIcon.icns'
    if icon.is_file():
        shutil.copy2(str(icon),str(contents/'Resources/AppIcon.icns'))
    info={
        'CFBundleName':'Gold VM Manager','CFBundleDisplayName':'Gold VM 管理器',
        'CFBundleIdentifier':'local.gold.vm-manager','CFBundleVersion':'5',
        'CFBundleIconFile':'AppIcon',
        'LSApplicationCategoryType':'public.app-category.developer-tools',
        'CFBundleShortVersionString':'1.2.0','CFBundleExecutable':'GoldVMManager',
        'CFBundlePackageType':'APPL','LSMinimumSystemVersion':'14.0',
        'NSHighResolutionCapable':True,
        'NSAppTransportSecurity':{'NSAllowsLocalNetworking':True},
    }
    with (contents/'Info.plist').open('xb') as f:plistlib.dump(info,f)
    subprocess.run(['/usr/bin/swiftc','-swift-version','5','-parse-as-library','-target','arm64-apple-macos14.0',str(ROOT/'NativeApp.swift'),str(ROOT/'GuestInitialization.swift'),'-framework','AppKit','-framework','WebKit','-framework','ScreenCaptureKit','-framework','Vision','-o',str(mac/'GoldVMManager')],check=True)
    (mac/'GoldVMManager').chmod(0o700)
    # Ad-hoc signing is local packaging integrity, not Developer ID notarization.
    subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(APP)],check=True)
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(APP)],check=True)
    result={'app_path':str(APP),'native_webkit_window':True,'loopback_port':18765,
            'developer_id_notarized':False,'gatekeeper_disabled':False,
            'source_hashes':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in FILES}}
    (ROOT/'evidence').mkdir(mode=0o700,exist_ok=True)
    with (ROOT/'evidence/package.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print('Packaged native Gold VM Manager app; no system security settings changed')

if __name__=='__main__':main()
