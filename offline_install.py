"""Complete GUI payload transaction for one explicitly authorized new Data volume.

This module never attaches, mounts, boots or publishes a VM, acquires credentials,
creates accounts, changes Setup Assistant state, installs services, deletes apps,
or accepts licences. The caller owns the restricted live disk session. A failure
leaves an unpublished partial stage quarantined; there is no destructive retry.
Actual acceptance requires detach followed by fresh readonly disk verification.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import subprocess

import guest_app_artifacts as artifacts
import managed_registry as registry
import offline_volume
import quarantine_policy

PRODUCTS = ('ccbaga', 'clashVergeRev', 'claudeDesktop')
APP_NAMES = ('CCBaga-A.app', 'CCBaga-B.app', 'Clash Verge.app', 'Claude.app')


class InstallError(ValueError):
    pass


def need(ok, message):
    if not ok: raise InstallError(message)


@dataclass(frozen=True)
class Material:
    manifest: artifacts.ArtifactManifest
    download: artifacts.DownloadReceipt
    staging_root: Path
    app_paths: tuple


def validate_material_set(materials):
    need(type(materials) is tuple and len(materials) == 3
         and all(type(m) is Material for m in materials), 'Exact complete material set required')
    need(tuple(m.manifest.product for m in materials) == PRODUCTS, 'Three complete GUI products required in fixed order')
    need(tuple(app.name for m in materials for app in m.manifest.expected_apps) == APP_NAMES,
         'Full CCBaga A+B, Clash GUI and Claude Desktop are mandatory')
    for m in materials:
        need(type(m.app_paths) is tuple and all(type(p) is Path or isinstance(p, Path) for p in m.app_paths),
             'Explicit source bundle paths required')
    return materials


def verify_materials(materials):
    """Do not trust a caller-provided success flag: reverify all actual source bundles."""
    validate_material_set(materials)
    return tuple(artifacts.verify_app_bundles(m.manifest, m.staging_root, m.app_paths, m.download)
                 for m in materials)


def application_root(session, writable=False):
    checker = session.check_mounted_writable if writable else session.check_mounted_readonly
    checker()
    mount = registry.safe_path(session.mountpoint)
    need(os.path.ismount(mount), 'Expected a live, attributed guest filesystem')
    root = registry.safe_path(mount / 'Applications')
    info = root.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_dev == mount.stat().st_dev, 'Guest Applications is not on the attributed Data filesystem')
    need(not (mount/'private/var/db/.AppleSetupDone').exists(), 'Setup Assistant already completed; fresh-only installation refused')
    users = registry.safe_path(mount/'Users')
    need(users.is_dir() and set(p.name for p in users.iterdir()) <= {'.localized', 'Shared'},
         'User home already present; no existing-user installation')
    return root


def _same_root(root, identity):
    root = registry.safe_path(root)
    info = root.stat()
    need((info.st_dev, info.st_ino) == identity and stat.S_ISDIR(info.st_mode), 'Guest application root changed')


def _tree_map(receipts):
    return {app['name']: (app['bundle_tree_sha256'], app['bundle_bytes'], app['bundle_entries'])
            for receipt in receipts for app in receipt.apps}


def write_applications(session, materials, evidence_dir, *, acknowledge_write=False, verified_existing=(), run=subprocess.run):
    """Copy complete verified bundles to previously absent guest paths only.

    There is no rollback/delete/overwrite. A failed copy or partial product set
    keeps the new disk unpublished and applications_preinstalled false. Each app
    directory is exclusively claimed before ditto, and never adopted from disk.
    """
    need(acknowledge_write is True, 'Explicit new-disk application-write authorization required')
    need(type(session.attribution) is offline_volume.WritableAttribution,
         'Distinct fresh writable attribution required; readonly success is not write permission')
    need(type(verified_existing) is tuple and verified_existing == APP_NAMES[:len(verified_existing)],
         'Recovery may only retain an explicitly verified complete prefix, never arbitrary existing apps')
    material_receipts = verify_materials(materials)
    evidence = registry.safe_path(Path(evidence_dir), False)
    evidence.mkdir(mode=0o700)
    root = application_root(session, writable=True)
    root_info = root.stat()
    identity = (root_info.st_dev, root_info.st_ino)
    source_trees = _tree_map(material_receipts)
    by_name = {app.name:m for m in materials for app in m.manifest.expected_apps}
    for name in APP_NAMES:
        target = registry.safe_path(root/name, False)
        if name in verified_existing:
            need(target.is_dir() and not target.is_symlink()
                 and artifacts._tree_snapshot(target,by_name[name].manifest) == source_trees[name],
                 'Previously reviewed complete copy changed; no overwrite or repair of bytes')
        else:
            need(not target.exists() and not target.is_symlink(), 'An application target already exists; never overwrite')
    required = sum(v[1] for v in source_trees.values()) + 1024**3
    usage = os.statvfs(root)
    need(usage.f_bavail*usage.f_frsize >= required, 'Insufficient guest Data space for complete GUI apps')
    state = {'schema':1, 'phase':'copying', 'completed_apps':[], 'applications_preinstalled':False,
             'guest_started':False, 'desktop_verified':False, 'credentials_copied':False,
             'data_uuid':session.attribution.data_uuid, 'volume_group_uuid':session.attribution.volume_group_uuid}
    registry.write_private(evidence/'transaction.json',state)
    fd = os.open(str(root), os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for m in materials:
            sources = {p.name:p for p in m.app_paths}
            for app in m.manifest.expected_apps:
                session.check_mounted_writable()
                _same_root(root,identity)
                source = registry.safe_path(sources[app.name])
                target = registry.safe_path(root/app.name,False)
                need(source.is_dir() and source.name == app.name and target.parent == root,
                     'Source or destination application identity mismatch')
                if app.name in verified_existing:
                    # Explicit recovery: retain byte-identical prior output. Never
                    # rerun ditto against it, never remove or replace its bytes.
                    need(artifacts._tree_snapshot(target,m.manifest) == source_trees[app.name],
                         'Retained application changed since readonly review')
                    quarantine_policy.propagate(source,target)
                    session.summary['apps_written'] = True  # possible quarantine metadata addition only
                    registry.write_private(evidence/(app.name+'.retained.json'),{
                        'action':'retained_complete_verified_bundle_quarantine_only','target':str(target),
                        'source_tree_sha256':source_trees[app.name][0],'application_bytes_overwritten':False})
                    state['completed_apps'].append(app.name)
                    registry.write_private(evidence/'transaction.json',state)
                    continue
                # Exclusive directory creation; not ditto's merge/overwrite behavior.
                os.mkdir(app.name,mode=0o755,dir_fd=fd)
                claim = target.stat()
                need(claim.st_dev == identity[0] and not target.is_symlink(), 'Application claim changed filesystem')
                session.summary['apps_written'] = True  # possible partial writes, NOT acceptance
                result = run(['/usr/bin/ditto',str(source),str(target)],stdin=subprocess.DEVNULL,capture_output=True,
                    timeout=900,env={'HOME':'/var/empty','PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'en_US.UTF-8'})
                registry.write_private(evidence/(app.name+'.copy.json'),{
                    'source':str(source),'target':str(target),'exit_code':result.returncode,
                    'stdout':result.stdout[:65536].decode('utf-8',errors='replace'),
                    'stderr':result.stderr[:65536].decode('utf-8',errors='replace')})
                need(result.returncode == 0, 'Complete bundle copy failed; stage remains quarantined')
                session.check_mounted_writable()
                _same_root(root,identity)
                # umask 077 can leave an exclusive root at 0700; ditto merges
                # into that root and does not reliably restore its mode. These
                # four public, signed bundles must be traversable after their
                # root becomes guest root-owned. Never chmod a retained app,
                # existing target, credential, or nested signed component.
                app_fd = os.open(app.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    after = os.fstat(app_fd)
                    need((after.st_dev,after.st_ino) == (claim.st_dev,claim.st_ino)
                         and after.st_uid == os.getuid() and stat.S_IMODE(after.st_mode) in (0o700, 0o755),
                         'Claimed app directory was replaced or has unsafe mode')
                    if stat.S_IMODE(after.st_mode) == 0o700:
                        os.fchmod(app_fd, 0o755)
                    os.fsync(app_fd)
                finally:
                    os.close(app_fd)
                copied = artifacts._tree_snapshot(target,m.manifest)
                need(copied == source_trees[app.name], 'Copied app content/layout differs from verified source')
                try: quarantine=quarantine_policy.propagate(source,target)
                except quarantine_policy.QuarantineError: raise InstallError('Internet quarantine was not preserved on guest copy') from None
                need(bool(quarantine), 'Guest bundle quarantine is empty')
                state['completed_apps'].append(app.name)
                registry.write_private(evidence/'transaction.json',state)
        need(tuple(state['completed_apps']) == APP_NAMES, 'Incomplete application copy set')
        state['phase']='copied_requires_detach_and_readonly_verification'
        registry.write_private(evidence/'transaction.json',state)
        return material_receipts
    except BaseException:
        state['phase']='failed_quarantined'
        registry.write_private(evidence/'transaction.json',state)
        raise
    finally:
        os.close(fd)


def verify_installed_readonly(session, materials, source_receipts, *, expected_data_uuid, expected_group_uuid):
    """Fresh readonly remount evidence, not a first-desktop or service success claim."""
    validate_material_set(materials)
    need(type(session.attribution) is offline_volume.OfflineAttribution,
         'Fresh readonly attribution is required after writable detach')
    need(session.attribution.data_uuid == expected_data_uuid
         and session.attribution.volume_group_uuid == expected_group_uuid, 'Reattached Data/group identity changed')
    root = application_root(session, writable=False)
    expected = _tree_map(source_receipts)
    need(set(expected) == set(APP_NAMES), 'Verified source receipts incomplete')
    receipts=[]
    for m in materials:
        session.check_mounted_readonly()
        apps=tuple(root/app.name for app in m.manifest.expected_apps)
        receipt=artifacts.verify_app_bundles(m.manifest,root,apps,m.download)
        for app in receipt.apps:
            actual=(app['bundle_tree_sha256'],app['bundle_bytes'],app['bundle_entries'])
            need(actual == expected[app['name']], 'Guest app differs from verified complete source')
            try: quarantine=quarantine_policy.read(root/app['name'])
            except quarantine_policy.QuarantineError: raise InstallError('Guest download quarantine missing') from None
            need(bool(quarantine) and quarantine == quarantine_policy.read(m.staging_root/app['name']),
                 'Guest download quarantine missing or differs from original source')
        receipts.append(receipt)
    session.check_mounted_readonly()
    return tuple(receipts)
