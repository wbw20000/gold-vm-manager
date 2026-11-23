#!/usr/bin/env python3
"""Double-click entry: reuse the authenticated local controller, or start it."""
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen, ProxyHandler, build_opener

HERE=Path(__file__).resolve().parent
HOME=Path.home()
STATE=HOME/'Library/Application Support/GoldVMManager'
PORT=18765
CONTROLLER_VERSION='1.5.0'
OPENER=build_opener(ProxyHandler({}))


def running_info(*, required_version=None):
    path=STATE/'server.json'
    if path.is_symlink() or not path.exists():return None
    try:
        s=path.stat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077:return None
        info=json.loads(path.read_text())
        if type(info) is not dict:return None
        if info.get('app')!='gold-vm-manager' or type(info.get('port')) is not int or info['port']!=PORT:return None
        if type(info.get('pid')) is not int or info['pid']<=1 or not isinstance(info.get('token'),str):return None
        os.kill(info['pid'],0)
        base='http://127.0.0.1:'+str(PORT)
        req=Request(base+'/api/state',headers={'Authorization':'Bearer '+info['token'],'Origin':base})
        with OPENER.open(req,timeout=3) as response:data=json.load(response)
        if type(data) is not dict or type(data.get('app')) is not dict:return None
        if data.get('ok') is not True or data['app'].get('name')!='Gold VM Manager':return None
        if required_version is not None and data['app'].get('version') != required_version:return None
        return info
    except (OSError,ValueError,URLError):return None


def main():
    os.umask(0o077)
    if STATE.is_symlink():raise SystemExit('Refusing symlinked application state')
    STATE.mkdir(parents=True,mode=0o700,exist_ok=True)
    s=STATE.stat()
    if s.st_uid!=os.getuid() or s.st_mode&0o077:raise SystemExit('Application state must be private')
    info=running_info(required_version=CONTROLLER_VERSION)
    if info is None:
        test=socket.socket()
        test.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:
            test.bind(('127.0.0.1',PORT))
        except OSError:
            raise SystemExit('Port 18765 is already in use by a different controller or process; close it normally before using this version')
        finally:test.close()
        logpath=STATE/'controller.log'
        if logpath.is_symlink():raise SystemExit('Unsafe controller log path')
        with logpath.open('a',encoding='utf-8') as log:
            env={'HOME':str(HOME),'PATH':'/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin',
                 'LANG':'en_US.UTF-8','PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1'}
            subprocess.Popen(['/usr/bin/python3',str(HERE/'manager.py'),'--port',str(PORT)],
                             cwd=str(HERE),env=env,stdin=subprocess.DEVNULL,stdout=log,
                             stderr=subprocess.STDOUT,start_new_session=True,close_fds=True)
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            info=running_info(required_version=CONTROLLER_VERSION)
            if info:break
            time.sleep(.2)
        if info is None:raise SystemExit('Controller did not become ready; see private controller.log')
    url='http://127.0.0.1:'+str(PORT)+'/#token='+info['token']
    if '--emit-url' in sys.argv[1:]:
        # Only the native wrapper consumes this captured pipe; never write it to logs.
        print(url)
    else:
        subprocess.run(['/usr/bin/open','/Applications/Gold VM 管理器.app'],check=True)
        print('Opened native Gold VM Manager; no Terminal or external browser required')

if __name__=='__main__':main()
