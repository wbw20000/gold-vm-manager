#!/usr/bin/env python3
"""Per-VM protected launcher; adapted from reviewed Gold launcher, not a NAT wrapper."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import re
import unicodedata
# Copied into a new private environment only. Existing launchers are untouched.
# GOLD_VM_MANAGER_SHARES_V1
# GOLD_VM_MANAGER_RECOVERY_V1

BASE = Path(__file__).absolute().parent
# Preinstalled protected environments, validated by their own preinstall_runtime:
# v2 (apps and a first-login seed written into the disk) and v3 (nothing written;
# a read-only installers share during first setup). "v2" below means either.
PROTECTED_VERSIONS = (2, 3)
HOME = Path.home()
TART = str(HOME / 'Applications/tart.app/Contents/MacOS/tart')
VM_ROOT = HOME / '.tart/vms'
GV_SHA256 = 'e2a6825ba789fe588828b418c09aaf16525dec6d8cb2d16c94e72535dd4606be'
ENV = dict(os.environ, HOME=str(HOME), TART_HOME=str(HOME / '.tart'))


def checked_file(path, read=True):
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise RuntimeError('Unexpected file path')
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise RuntimeError('Environment file must be private and owned')
    return path.read_bytes() if read else path


def checked_digest(path):
    h = hashlib.sha256()
    with checked_file(path, read=False).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def build_tart_command(vm_name, network_fd, share_plan, no_graphics=False, recovery=False, *, environment=None,
                       first_setup=False):
    if environment is not None and environment.get('version') in PROTECTED_VERSIONS:
        from preinstall_runtime import build_tart_command as build_v2
        return build_v2(BASE, environment, vm_name, network_fd, share_plan, no_graphics, recovery,
                        first_setup=first_setup)
    if first_setup:
        raise RuntimeError('First-setup normal network is only for a preinstalled v2 environment')
    if share_plan is not None and any(s['name'].casefold() == 'setup' for s in share_plan.shares):
        raise RuntimeError('The setup share name is reserved')
    cmd = [TART, 'run', vm_name, '--net-fd=' + str(network_fd)]
    if recovery:
        cmd.extend(['--recovery', '--no-clipboard'])
    else:
        cmd.append('--dir=setup:' + str(BASE / 'setup') + ':ro')
        cmd.extend(share_plan.arguments)
    if no_graphics:
        cmd.append('--no-graphics')
    return cmd


def validate_environment():
    if BASE.resolve(strict=True) != BASE or any(c in str(BASE) for c in ':,\n\r'):
        raise RuntimeError('Unsafe private base')
    meta = json.loads(checked_file(BASE / 'environment.json'))
    if type(meta.get('version')) is int and meta['version'] in PROTECTED_VERSIONS:
        # Verify the copied v2 support module before importing its validator.
        if checked_digest(BASE / 'preinstall_runtime.py') != meta.get('source_sha256', {}).get('preinstall_runtime.py'):
            raise RuntimeError('V2 runtime source integrity mismatch')
        from preinstall_runtime import validate_environment as validate_v2
        return validate_v2(BASE, meta)
    name = meta.get('vm_name')
    if (meta.get('version') != 1 or not isinstance(name, str)
            or not 1 <= len(name) <= 64 or name != name.strip()
            or name.startswith(('.', '-')) or any(not (c.isalnum() or c in ' _-') for c in name)
            or unicodedata.normalize('NFC', name) != name or meta.get('setup_active') is not True):
        raise RuntimeError('Invalid environment metadata')
    if meta.get('vm_config') != str(VM_ROOT / name / 'config.json'):
        raise RuntimeError('Unexpected VM config location')
    expected = {'launcher.py', 'packet_policy.py', 'policy.json', 'share_support.py',
                'managed_registry.py', 'gvproxy-darwin'}
    if set(meta.get('source_sha256', {})) != expected:
        raise RuntimeError('Incomplete trusted source manifest')
    for filename, digest in meta['source_sha256'].items():
        if checked_digest(BASE / filename) != digest:
            raise RuntimeError('Environment source integrity mismatch')
    setup = BASE / 'setup'
    private_directory(setup)
    expected_setup = {'Install.command', 'install_guest.rb', 'config.json', 'mihomo',
                      'CCBaga-0.2.50-macos-arm64.dmg', 'README.txt'}
    if 'profile.json' in meta.get('setup_sha256', {}):
        expected_setup.add('profile.json')
    if set(meta.get('setup_sha256', {})) != expected_setup:
        raise RuntimeError('Incomplete setup manifest')
    for filename, digest in meta['setup_sha256'].items():
        if checked_digest(setup / filename) != digest:
            raise RuntimeError('Setup payload integrity mismatch')
    return meta


def private_directory(path):
    if path.is_symlink():
        raise RuntimeError('Refusing symlinked private directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.stat()
    if s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise RuntimeError('Private directory owner/mode mismatch')


def write_status(path, data):
    # Replace only our fixed status file, in our checked private directory.
    resolved = path.parent.resolve() / path.name
    if resolved != BASE / 'status.json' or path.is_symlink():
        raise RuntimeError('Unexpected status path')
    # A unique, exclusively created staging name: a file left behind by a crash
    # can never block later updates, and a failed write never leaves one.
    fd, name = tempfile.mkstemp(prefix='status.', suffix='.pending', dir=str(BASE))
    temp = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, sort_keys=True)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(temp), str(resolved))
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def remove_stale_status_staging():
    """Remove the legacy fixed staging file left by an older launcher crash.

    Call only while holding run.lock. Only a private regular file owned by us is
    removed; anything else (e.g. a symlink) fails closed and is left in place.
    """
    legacy = BASE / 'status.pending'
    try:
        info = os.lstat(str(legacy))
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise RuntimeError('Unexpected legacy status staging file')
    legacy.unlink()


def local_control(management_capability):
    control=BASE/'control.json'
    if control.is_symlink():
        raise RuntimeError('Symlinked local control file')
    if not control.exists():
        return management_capability, False
    info=control.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError('Local control file must be regular, owned and private')
    ctl=json.loads(control.read_text())
    if not isinstance(ctl,dict) or set(ctl)-{'management','drop_proxy'}:
        raise RuntimeError('Unexpected local control schema')
    if any(type(value) is not bool for value in ctl.values()):
        raise RuntimeError('Control settings must be exact booleans')
    return ctl.get('management',management_capability) and management_capability, ctl.get('drop_proxy',False)


def stop_process(proc, signum=signal.SIGTERM):
    if proc is not None and proc.poll() is None:
        try:
            proc.send_signal(signum)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except ProcessLookupError:
            pass


def run_first_setup(vm_name, share_plan, meta, runtime_env, no_graphics, lock):
    """First setup only: Tart on its own normal network. No backend, no filter.

    The owner decided (2026-11-19) that before Clash exists the fence only blocks
    Setup Assistant. The caller has already checked that first setup is still
    pending; once it is marked finished this path refuses and starts are protected.
    """
    import preinstall_runtime as runtime_v2
    child = None
    shutdown = False
    def request_stop(signum, frame):
        nonlocal shutdown
        shutdown = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    status = {'launcher_pid': os.getpid(), 'state': 'initializing', 'started_unix': time.time(),
              'network_mode': runtime_v2.FIRST_SETUP_NETWORK,
              'policy': 'none: Tart normal network for first setup only',
              'native_execution_approved': False,
              'desktop_verified': False, 'network_independently_verified': False}
    if meta['version'] == 2:
        status['guest_bootstrap_evidence'] = 'not_observed'
    else:
        status['installers_share'] = runtime_v2.INSTALLERS_SHARE
    try:
        runtime_v2.validate_bindings(BASE, meta)
        runtime_v2.require_first_setup(BASE)
        cmd = build_tart_command(vm_name, None, share_plan, no_graphics, environment=meta, first_setup=True)
        if shutdown:
            raise RuntimeError('Startup cancelled; VM not started')
        child = subprocess.Popen(cmd, env=runtime_env, stdin=subprocess.DEVNULL, close_fds=True)
        share_plan.record_launch(child.pid)
        # v2's status mailbox or v3's read-only installers folder.
        status.update(state='running', tart_pid=child.pid, shared_directory_count=len(share_plan.shares) + 1,
                      sharing_allows_suspend=False, recovery_mode=False, setup_status='first-setup')
        write_status(BASE/'status.json', status)
        print('First setup is running on the normal network; no packet filter.', flush=True)
        while not shutdown and child.poll() is None:
            time.sleep(0.5)
        status['state'] = 'stopping' if shutdown else 'guest-exited'
    except Exception as error:
        status['state'] = 'failed-closed'
        status['error_type'] = type(error).__name__
        print('First-setup launcher stopped (' + type(error).__name__ + ').', file=sys.stderr, flush=True)
        raise
    finally:
        cleanup_errors = []
        try:
            stop_process(child, signal.SIGINT)
        except Exception as error:
            cleanup_errors.append(type(error).__name__)
        status['ended_unix'] = time.time()
        status['cleanup_errors'] = cleanup_errors
        try:
            write_status(BASE/'status.json', status)
        finally:
            lock.close()
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-graphics', action='store_true')
    parser.add_argument('--recovery', action='store_true')
    parser.add_argument('--acknowledge-reviewed-unsigned-backend', action='store_true',
                        help='V2 only: explicitly request normal OS execution of the pinned backend '
                             '(Red Hat-signed, notarized gvproxy); macOS still decides; the legacy flag name is kept')
    parser.add_argument('--enable-reviewed-backend-owner-execute', action='store_true',
                        help='V2 only with acknowledgement: make the exact private backend owner-executable; preserve quarantine')
    parser.add_argument('--first-setup-normal-network', action='store_true',
                        help="V2/v3 only, until first setup is marked finished: run Tart on its normal network, "
                             "unfiltered, so Setup Assistant can reach Apple before Clash exists; no backend runs. "
                             "v3 also shares its installers folder read-only")
    args = parser.parse_args()
    args.management = False  # No guest management port is exposed by this launcher.
    os.umask(0o077)
    private_directory(BASE)
    meta = validate_environment()
    vm_name = meta['vm_name']
    v2 = meta.get('version') in PROTECTED_VERSIONS
    vm_config = Path(meta['vm_config']) if v2 else VM_ROOT / vm_name / 'config.json'
    tart = meta['tart_binding']['path'] if v2 else TART
    runtime_env = ({'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(HOME),
                    'TART_HOME': meta['tart_home'], 'LANG': 'C',
                    'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                    'TART_NO_AUTO_PRUNE': '1'} if v2 else ENV)
    if ((args.acknowledge_reviewed_unsigned_backend or args.enable_reviewed_backend_owner_execute) and not v2
            or args.enable_reviewed_backend_owner_execute and not args.acknowledge_reviewed_unsigned_backend):
        raise RuntimeError('Backend execute permission needs explicit v2 acknowledgement')
    first_setup = args.first_setup_normal_network
    if first_setup and (not v2 or args.recovery or args.acknowledge_reviewed_unsigned_backend
                        or args.enable_reviewed_backend_owner_execute):
        raise RuntimeError('First-setup normal network is only a plain v2 start without backend flags')
    from packet_policy import PacketPolicy
    from share_support import prepare_vm_shares
    lock_path = BASE / 'run.lock'
    if lock_path.is_symlink():
        raise RuntimeError('Refusing symlinked run lock')
    lock = (os.fdopen(os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                              0o600), 'a+') if v2 else lock_path.open('a+'))
    if v2:
        try:
            checked_file(lock_path, read=False)
            opened, entry = os.fstat(lock.fileno()), lock_path.stat()
            if (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                raise RuntimeError('Run lock identity changed')
        except BaseException:
            lock.close()
            raise
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print('Protected launcher is already running.', flush=True)
        if v2:
            lock.close()
        return 0
    remove_stale_status_staging()  # Safe only now: run.lock excludes any other writer.
    write_status(BASE/'status.json',{'state':'validating','launcher_pid':os.getpid(),'started_unix':time.time()})
    gv = BASE / 'gvproxy-darwin'
    if first_setup:
        import preinstall_runtime as runtime_v2
        try:
            runtime_v2.require_first_setup(BASE)
            runtime_v2.validate_bindings(BASE, meta)
        except runtime_v2.RuntimePreparationError as error:
            write_status(BASE/'status.json', {'state': 'failed-closed', 'launcher_pid': os.getpid(),
                         'reason': error.code, 'network_mode': runtime_v2.FIRST_SETUP_NETWORK,
                         'native_execution_approved': False, 'vm_started': False})
            lock.close()
            raise
    elif v2:
        import preinstall_runtime as runtime_v2
        try:
            runtime_v2.require_backend_authorization(meta, args.acknowledge_reviewed_unsigned_backend)
            runtime_v2.validate_bindings(BASE, meta)
            if args.enable_reviewed_backend_owner_execute:
                runtime_v2.authorize_backend_execution_bit(BASE, meta, acknowledged=True)
            runtime_v2.backend_is_executable(BASE)
        except runtime_v2.RuntimePreparationError as error:
            write_status(BASE/'status.json', {'state': 'awaiting_host_authorization',
                         'launcher_pid': os.getpid(), 'reason': error.code,
                         'native_execution_approved': False, 'vm_started': False})
            lock.close()
            raise
    elif gv.is_symlink() or hashlib.sha256(gv.read_bytes()).hexdigest() != GV_SHA256:
        raise RuntimeError('Network backend integrity mismatch; VM not started')
    cfg = json.loads((BASE / 'policy.json').read_text())
    vm = json.loads(vm_config.read_text())
    if cfg['guest_mac'].lower() != vm['macAddress'].lower() or str(vm.get('ecid')) != meta['ecid']:
        raise RuntimeError('VM identity changed; refusing network startup')
    inventory = subprocess.run([tart, 'list', '--format', 'json'], env=runtime_env, capture_output=True, text=True, check=True)
    gold = [x for x in json.loads(inventory.stdout) if x['Name'] == vm_name and x['Source'] == 'local']
    if len(gold) != 1 or gold[0]['Running'] or gold[0]['State'] != 'stopped':
        raise RuntimeError('VM must exist and be stopped; suspended setup resumes are not supported')
    share_plan = prepare_vm_shares(vm_name, BASE, gold[0]['State']) if not args.recovery else None
    reserved_names = ('setup', 'gold-status', 'gold-installers') if v2 else ('setup',)
    if share_plan is not None and any(s['name'].casefold() in reserved_names for s in share_plan.shares):
        raise RuntimeError('A protected runtime share name is reserved')
    endpoints = [tuple(x) for x in cfg['endpoints']]
    local_control(args.management)  # Validate before any VM can start.
    if first_setup:
        return run_first_setup(vm_name, share_plan, meta, runtime_env, args.no_graphics, lock)
    policy = PacketPolicy(guest_mac=cfg['guest_mac'], endpoints=endpoints, allow_management=args.management)
    run = Path(tempfile.mkdtemp(prefix='goldnet-', dir='/tmp'))
    private_directory(run)
    gv_sock, api_sock, client_sock = run/'gv.sock', run/'api.sock', run/'filter.sock'
    # Config is generated by us, not read from guest or subscription content.
    lines = [
        'stack:', '  subnet: "192.168.127.0/24"',
        '  gatewayIP: "192.168.127.1"', '  deviceIP: "192.168.127.2"',
        '  hostIP: "192.168.127.254"', '  gatewayMacAddress: "5a:94:ef:e4:0c:dd"',
        '  dhcpStaticLeases:', '    "192.168.127.2": '+json.dumps(cfg['guest_mac']),
    ]
    if args.management:
        lines += ['  forwards:', '    "127.0.0.1:22022": "192.168.127.2:22"']
    gv_config = run/'gv.yaml'
    gv_config.write_text('\n'.join(lines)+'\n')
    backend_log = (run/'backend.log').open('xb')
    vm_log = (run/'tart.log').open('xb')
    backend = child = None
    host_sock = vm_sock = backend_sock = None
    sel = None
    shutdown = False
    def request_stop(signum, frame):
        nonlocal shutdown
        shutdown = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    status = {'launcher_pid':os.getpid(),'runtime_directory':str(run),'management_enabled':args.management,
              'endpoint_count':len(endpoints),'policy':'deny except pinned proxy tuples, narrow DHCP/ARP, optional temporary SSH',
              'state':'initializing','started_unix':time.time()}
    if v2:
        status.update(native_execution_approved=False, backend_execution_acknowledged=True,
                      backend_startup_pending=True, desktop_verified=False, network_independently_verified=False)
    if meta.get('version') == 2:
        status['guest_bootstrap_evidence'] = 'not_observed'
    # v1's setup share or v2's status mailbox; v3 adds none to a protected start.
    special_shares = 0 if meta.get('version') == 3 else 1
    try:
        if v2:
            runtime_v2.validate_bindings(BASE, meta)
        backend = subprocess.Popen([str(gv),'--config',str(gv_config),'--listen-vfkit','unixgram://'+str(gv_sock),
                                    '--services','unix://'+str(api_sock),'--mtu','1500'],
                                   stdin=subprocess.DEVNULL,stdout=backend_log,stderr=subprocess.STDOUT,env=runtime_env,close_fds=True)
        deadline = time.monotonic()+15
        while not gv_sock.exists():
            if backend.poll() is not None or time.monotonic()>deadline or shutdown:
                raise RuntimeError('Network backend unavailable; VM not started')
            time.sleep(0.05)
        if not stat.S_ISSOCK(gv_sock.stat().st_mode):
            raise RuntimeError('Unexpected backend socket type')
        if v2:
            status['backend_startup_pending'] = False
        backend_sock = socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        backend_sock.bind(str(client_sock))
        backend_sock.connect(str(gv_sock))
        host_sock,vm_sock = socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        for s in (backend_sock,host_sock,vm_sock):
            s.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,1024*1024)
            s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
        backend_sock.send(b'VFKT')
        backend_sock.setblocking(False)
        host_sock.setblocking(False)
        # V1 keeps readonly setup. V2 exposes only its owned status mailbox, v3
        # nothing of its own, plus the unchanged validated user-share plan; all
        # remain non-suspendable.
        if v2:
            runtime_v2.validate_bindings(BASE, meta)
        cmd = build_tart_command(vm_name, vm_sock.fileno(), share_plan, args.no_graphics, args.recovery,
                                 environment=meta if v2 else None)
        # Only explicitly configured named shares; no NAT fallback or extra disks.
        if shutdown or backend.poll() is not None:
            raise RuntimeError('Startup cancelled or backend exited; VM not started')
        child=subprocess.Popen(cmd,env=runtime_env,pass_fds=(vm_sock.fileno(),),stdin=subprocess.DEVNULL,
                               stdout=vm_log,stderr=subprocess.STDOUT,close_fds=True)
        if share_plan is not None:
            share_plan.record_launch(child.pid)
        vm_sock.close()
        vm_sock=None
        status.update(state='starting',tart_pid=child.pid,backend_pid=backend.pid,vm_network_seen=False,shared_directory_count=0 if args.recovery else len(share_plan.shares)+special_shares,sharing_allows_suspend=False,recovery_mode=args.recovery,setup_status='recovery' if args.recovery else ('protected' if meta.get('version') == 3 else 'preinstalled-awaiting-guest-report' if v2 else 'awaiting_user_setup'))
        write_status(BASE/'status.json',status)
        print('Protected network is running; default egress is denied.',flush=True)
        sel=selectors.DefaultSelector()
        sel.register(host_sock,selectors.EVENT_READ,'out')
        sel.register(backend_sock,selectors.EVENT_READ,'in')
        last_status=time.monotonic()
        overflow=0
        while not shutdown and child.poll() is None:
            if backend.poll() is not None:
                raise RuntimeError('Network backend exited; keeping VM disconnected and stopping it')
            # Host-only control has no guest-visible API. Absence means allow configured endpoints.
            management,drop_proxy=local_control(args.management)
            policy.set_management_enabled(management)
            ready = sel.select(timeout=0.25)
            # Readiness only means a datagram is queued. The backend may have
            # exited while select was waiting; do not relay that queued batch.
            if shutdown or child.poll() is not None:
                break
            if backend.poll() is not None:
                raise RuntimeError('Network backend exited; keeping VM disconnected and stopping it')
            for key,_ in ready:
                packet,anc,flags,addr=key.fileobj.recvmsg(65536)
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    overflow+=1
                    continue
                if not packet:
                    continue
                outgoing=key.data=='out'
                if outgoing:
                    status.update(state='running',vm_network_seen=True)
                # The fault-test control can only REMOVE permission. DHCP/ARP/SSH remain for repair.
                if drop_proxy and len(packet)>=34 and packet[12:14]==b'\x08\x00':
                    dest=socket.inet_ntoa(packet[30:34])
                    src=socket.inet_ntoa(packet[26:30])
                    if any((dest if outgoing else src)==x[1] for x in endpoints):
                        continue
                allowed=policy.allow_outbound(packet) if outgoing else policy.allow_inbound(packet)
                if not allowed:
                    continue
                target=backend_sock if outgoing else host_sock
                try:
                    target.send(packet)
                except (BlockingIOError,BufferError):
                    overflow+=1
            if time.monotonic()-last_status>=2:
                status.update(management_enabled=management,last_update_unix=time.time(),overflow_drops=overflow,
                              proxy_fault_test=drop_proxy,counters=policy.snapshot())
                write_status(BASE/'status.json',status)
                last_status=time.monotonic()
        status['state']='stopping' if shutdown else 'guest-exited'
    except Exception as error:
        # A normal OS execution refusal/early backend exit is not repaired with
        # xattr removal, re-signing, a policy exception, retry or a NAT fallback.
        status['state']=('awaiting_host_authorization' if v2 and status.get('backend_startup_pending')
                         else 'failed-closed')
        status['error_type']=type(error).__name__
        print('Protected launcher failed closed ('+type(error).__name__+').',file=sys.stderr,flush=True)
        raise
    finally:
        # Close the only NIC transport BEFORE process cleanup. No fallback network is created.
        cleanup_errors=[]
        for s in (host_sock,vm_sock,backend_sock):
            if s is not None:
                try:
                    s.close()
                except Exception as error:
                    cleanup_errors.append(type(error).__name__)
        if sel is not None:
            try:
                sel.close()
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        for proc,signum in ((child,signal.SIGINT),(backend,signal.SIGTERM)):
            try:
                stop_process(proc,signum)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        status['ended_unix']=time.time()
        status['cleanup_errors']=cleanup_errors
        try:
            write_status(BASE/'status.json',status)
        finally:
            backend_log.close()
            vm_log.close()
            if v2:
                lock.close()
        # Runtime artifacts retained for diagnostics; no broad path deletion.
    return 0

if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Protected launcher refused startup; inspect private status.', file=sys.stderr)
        sys.exit(1)
