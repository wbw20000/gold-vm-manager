#!/usr/bin/env python3
"""Package a native WKWebView app and the self-contained local Python controller."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import plistlib
import sys

import host_tools

ROOT=Path(__file__).resolve().parent
APP=Path('/Applications/Gold VM 管理器.app')
FILES=('manager.py','bootstrap.py','runtime_shares.py','discard_state.py',
       'managed_registry.py','lifecycle.py','process_identity.py','provisioning.py','protected_launcher.py','packet_policy.py',
       'setup_profile.py','vm_deletion.py','vm_disk_growth.py','vpn_config.py','vpn_store.py',
       'preinstall_materials.py','host_artifacts.py','host_tools.py','preinstall_runtime.py',
       'oneclick.py','offline_volume.py','offline_payload.py',
       'guest_app_artifacts.py','guest_app_pins.py','quarantine_policy.py','error_codes.py')
STATIC_FILES=('index.html','style.css','app.js','preinstall.js','preinstall.css')
SOURCE_FILES=('CleanVMInstaller.swift','CleanVMInstaller.entitlements.plist',
              'NativeApp.swift','GuestInitialization.swift')
GUEST_SETUP_FILES=('Install.command','install_guest.rb','README.txt')
EXAMPLE_FILES=('vpn/clash.yaml','vpn/fields.json')


def source_snapshot():
    """Fixed full closure: missing parent-owned files are errors, never skipped."""
    snapshot={}
    names=list(FILES)+list(SOURCE_FILES)
    names += ['static/'+name for name in STATIC_FILES]
    names += ['guest_setup/'+name for name in GUEST_SETUP_FILES]
    names += ['examples/'+name for name in EXAMPLE_FILES]
    for name in names:
        snapshot[name]=host_tools._read(ROOT/name, cap=8*1024*1024)
    for name in FILES:
        tree=ast.parse(snapshot[name], filename=name)
        for node in ast.walk(tree):
            imports=([alias.name.split('.')[0] for alias in node.names] if isinstance(node,ast.Import)
                     else [node.module.split('.')[0]] if isinstance(node,ast.ImportFrom) and node.module else [])
            for dependency in imports:
                if (ROOT/(dependency+'.py')).exists() and dependency+'.py' not in FILES:
                    raise host_tools.HostToolError('incomplete-python-package-closure')
    icon=ROOT/'assets/AppIcon.icns'
    if icon.exists():
        snapshot['assets/AppIcon.icns']=host_tools._read(icon, cap=8*1024*1024)
    return snapshot


def package_app(output, private_build_root):
    """Create a new local ad-hoc app only; never replace, launch or start service."""
    app=host_tools._path(output, missing=True)
    if app.exists() or app.is_symlink():
        raise host_tools.HostToolError('existing-app-will-not-be-overwritten')
    if app.suffix!='.app':
        raise host_tools.HostToolError('app-output-required')
    snapshot=source_snapshot()  # Validate the complete closure before any build/output.
    build=host_tools._attempt(private_build_root, 'package')
    for name in SOURCE_FILES:
        host_tools._write(build/name, snapshot[name])
    # The restore helper is signed and verified before entering the wrapper bundle.
    # Bind compile_helpers to this owned source snapshot, not a historic build.
    clean,=host_tools._compile_helpers(build,build)
    sdk=host_tools.source_prerequisites()['sdk_path']
    app.mkdir(mode=0o700)  # Exclusive final claim; a concurrent existing app wins.
    contents=app/'Contents'
    mac=contents/'MacOS'
    payload=contents/'Resources/app'
    for directory in (contents,mac,contents/'Resources',payload,payload/'static',
                      payload/'guest_setup',payload/'examples',payload/'examples/vpn'):
        directory.mkdir(mode=0o700)
    for name,raw in snapshot.items():
        if name.startswith('assets/'):
            host_tools._write(contents/'Resources/AppIcon.icns',raw)
        else:
            host_tools._write(payload/name,raw,0o700 if name=='guest_setup/Install.command' else 0o600)
    expected_entitlements={'com.apple.security.virtualization':True}
    raw=host_tools._read(clean,cap=64*1024*1024,private=True)
    host_tools._write(payload/clean.name,raw,0o700)
    host_tools.verify_local_signature(payload/clean.name,expected_entitlements)
    raw=host_tools._read(clean.parent/host_tools.HELPERS_PORTABLE_RECEIPT,cap=65536,private=True)
    host_tools._write(payload/host_tools.HELPERS_PORTABLE_RECEIPT,raw)
    portable_receipts={host_tools.HELPERS_PORTABLE_RECEIPT:hashlib.sha256(raw).hexdigest()}
    info={
        'CFBundleName':'Gold VM Manager','CFBundleDisplayName':'Gold VM 管理器',
        'CFBundleIdentifier':'local.gold.vm-manager','CFBundleVersion':'9',
        'CFBundleIconFile':'AppIcon',
        'LSApplicationCategoryType':'public.app-category.developer-tools',
        'CFBundleShortVersionString':'1.6.0','CFBundleExecutable':'GoldVMManager',
        'CFBundlePackageType':'APPL','LSMinimumSystemVersion':'26.6.2',
        'NSHighResolutionCapable':True,
        'NSAppTransportSecurity':{'NSAllowsLocalNetworking':True},
    }
    host_tools._write(contents/'Info.plist',plistlib.dumps(info))
    # Preserve the existing NativeApp + GuestInitialization source build contract.
    host_tools._tool(['/usr/bin/xcrun','--sdk','macosx','swiftc','-swift-version','5',
        '-parse-as-library','-target','arm64-apple-macos14.0','-sdk',sdk,
        '-module-cache-path',str(build/'native-module-cache'),str(build/'NativeApp.swift'),
        str(build/'GuestInitialization.swift'),'-framework','AppKit','-framework','WebKit',
        '-framework','ScreenCaptureKit','-framework','Vision','-o',str(mac/'GoldVMManager')],
        timeout=600,build_directory=build)
    host_tools._regular((mac/'GoldVMManager').lstat())
    (mac/'GoldVMManager').chmod(0o700)
    host_tools._sign_local(app)
    # Exercise the actual installed-app resolution path after the outer seal;
    # this must verify/reuse binaries without invoking a compiler or SDK lookup.
    host_tools.resolve_helpers(payload,build)
    for name,raw in snapshot.items():
        target=contents/'Resources/AppIcon.icns' if name.startswith('assets/') else payload/name
        if host_tools._digest(target)!=hashlib.sha256(raw).hexdigest():
            raise host_tools.HostToolError('packaged-source-mismatch')
    result={'schema':1,'app_path':str(app),'native_webkit_window':True,'loopback_port':18765,
            'signature':'local-ad-hoc','notarized':False,'developer_id_notarized':False,
            'gatekeeper_disabled':False,'launched':False,
            'helper_entitlements':{'CleanVMInstaller':expected_entitlements},
            'package_receipt':str(build/'package.json'),'portable_helper_receipts':portable_receipts,
            'artifact_hashes':{name:host_tools._digest(path) for name,path in (
                ('GoldVMManager',mac/'GoldVMManager'),('CleanVMInstaller',payload/'CleanVMInstaller'))},
            'source_hashes':{name:hashlib.sha256(raw).hexdigest() for name,raw in snapshot.items()}}
    host_tools._write(build/'package.json',host_tools._json(result))
    host_tools._sync(app.parent)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=APP,help='new absent .app path; never overwritten')
    parser.add_argument('--build-root',type=Path,default=ROOT/'build',help='owned 0700 build/cache root')
    args=parser.parse_args(argv)
    os.umask(0o077)
    try:
        result=package_app(args.output,args.build_root)
    except host_tools.HostToolError as error:
        print('Source installation refused: '+error.code,file=sys.stderr)
        return 1
    except Exception:
        print('Source installation failed; incomplete owned output retained, no app replaced',file=sys.stderr)
        return 1
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
    return 0


if __name__=='__main__':
    sys.exit(main())
