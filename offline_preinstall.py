"""Opt-in, fresh-stage-only complete GUI preinstallation orchestration.

Not a VM starter or publisher. Success means four complete signed app bundles
were independently read back from the detached/reopened readonly guest Data
volume. It NEVER means first-desktop acceptance, login, network/service setup,
permission acceptance, or product delivery. No HTTP endpoint runs this implicitly.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import os
from pathlib import Path
import uuid

import guest_app_artifacts as artifacts
from guest_app_pins import reviewed_manifests
import managed_registry as registry
from offline_disk import StageTarget, DiskSession, signature
from offline_writable import WritableDiskSession
from offline_install import validate_material_set, verify_materials, write_applications, verify_installed_readonly


class PreinstallError(ValueError):pass


def _time():return datetime.now(timezone.utc).isoformat()


def _state(target, operation_id, operation_phase, *, message, complete=False, failed=False):
    current=registry.read_private(target.state_dir/'build-current.json')
    if (current.get('id')!=target.job_id or current.get('mode') not in ('offline_validate','preinstall')
            or current.get('stage_path')!=str(target.stage) or current.get('guest_started') is not False):
        raise PreinstallError('Restore job identity changed while lifecycle lock held')
    current=dict(current)
    current['offline_preinstall']={'operation_id':operation_id,'phase':operation_phase,
        'active':not (complete or failed),'updated_at':_time()}
    current['message']=message
    current['applications_preinstalled']=complete
    current['desktop_verified']=False
    current['guest_started']=False
    current['credentials_copied']=False
    if complete:
        current.pop('recovery_required',None)
        current['phase']='awaiting_first_desktop_acceptance'
        current['progress']=1
    elif failed:
        current['phase']='failed'
        current['recovery_required']=True
    registry.write_private(target.state_dir/'build-jobs'/target.job_id/'status.json',current)
    registry.write_private(target.state_dir/'build-current.json',current)


def preinstall_stage(*,state_dir,tart_home,job_id,name,materials,evidence_dir,
                     acknowledge_write=False,external_lock=None,lifecycle_lock_fd=None):
    """Caller supplies reviewed official archive extraction results, never host apps.

    Keep both lifecycle locks and the config POSIX lock across every attachment.
    There are no destructive retry, directory replacement or arbitrary app flags.
    """
    if acknowledge_write is not True:raise PreinstallError('Explicit offline application write authorization required')
    validate_material_set(materials)
    if tuple(m.manifest for m in materials)!=reviewed_manifests():
        raise PreinstallError('Only the complete frozen reviewed application catalog is eligible')
    target=StageTarget.load(state_dir,tart_home,job_id,name)
    evidence=registry.safe_path(Path(evidence_dir),False)
    evidence.mkdir(mode=0o700)
    operation_id=uuid.uuid4().hex
    config_before=signature(target.stage/'config.json');nvram_before=signature(target.stage/'nvram.bin')
    outcome={'schema':1,'operation_id':operation_id,'job_id':job_id,'name':name,
        'stage_path':str(target.stage),'started_at':_time(),'applications_preinstalled':False,
        'desktop_verified':False,'guest_started':False,'credentials_copied':False,'published':False}
    lock_options = {} if lifecycle_lock_fd is None else {'lifecycle_lock_fd': lifecycle_lock_fd}
    with target.locked(external_lock, **lock_options):
        try:
            _state(target,operation_id,'verifying_sources',message='正在验证完整官方应用；尚未写入或启动客机。')
            before_receipts=verify_materials(materials)
            for material,receipt in zip(materials,before_receipts):
                artifacts.write_evidence(receipt,evidence/(material.manifest.product+'-source.json'))
            with DiskSession(target,evidence/'before-write-readonly',lock_held=True) as readonly:
                baseline=readonly.attribution
            _state(target,operation_id,'copying_complete_apps',message='正在对全新暂存 Data 卷预装完整应用；未发布、未启动。')
            with WritableDiskSession(target,evidence/'write-session',baseline,
                                     acknowledge_write=True,lock_held=True) as writable:
                writable.mount_writable()
                source_receipts=write_applications(writable,materials,evidence/'copy-transaction',acknowledge_write=True)
                data_uuid=writable.attribution.data_uuid;group_uuid=writable.attribution.volume_group_uuid
            # Rebase ONLY after successful unmount/detach. Accept journal/app-write
            # mtime changes, never a replaced image, changed size, config or NVRAM.
            after=StageTarget.load(state_dir,tart_home,job_id,name)
            if (after.baseline[:3]!=target.baseline[:3] or signature(after.stage/'config.json')!=config_before
                    or signature(after.stage/'nvram.bin')!=nvram_before):
                raise PreinstallError('Post-write file identity/config/NVRAM mismatch; no readonly acceptance')
            _state(target,operation_id,'verifying_fresh_readonly_mount',message='应用已复制，正在卸载后的独立只读重挂验收；尚未算预装成功。')
            with DiskSession(after,evidence/'after-write-readonly',lock_held=True) as readonly:
                readonly.mount_readonly_for_probe()
                guest_receipts=verify_installed_readonly(readonly,materials,source_receipts,
                    expected_data_uuid=data_uuid,expected_group_uuid=group_uuid)
                for material,receipt in zip(materials,guest_receipts):
                    artifacts.write_evidence(receipt,evidence/(material.manifest.product+'-guest-readonly.json'))
            # Only now: independent fresh readonly disk verification AND final detach.
            outcome.update({'finished_at':_time(),'applications_preinstalled':True,'readonly_remount_verified':True,
                'final_detach_confirmed':True,'data_uuid':data_uuid,'volume_group_uuid':group_uuid,
                'vm_config_and_nvram_unchanged':True,'image_file_identity_and_size_unchanged':True,
                'applications':[{'name':app['name'],'bundle_identifier':app['bundle_identifier'],
                    'short_version':app['short_version'],'bundle_version':app['bundle_version'],
                    'team_id':app['team_id'],'bundle_bytes':app['bundle_bytes'],
                    'bundle_tree_sha256':app['bundle_tree_sha256']} for receipt in guest_receipts for app in receipt.apps]})
            # This is a private staging verification sidecar, not a guest startup hook or profile.
            # Publish the final evidence receipt only after sidecar AND state writes succeed.
            sidecar=after.stage/'.offline-preinstall.complete.json'
            if sidecar.exists() or sidecar.is_symlink():raise PreinstallError('Existing stage preinstall receipt cannot be overwritten')
            registry.write_private(sidecar,outcome)
            _state(target,operation_id,'verified_awaiting_first_desktop',complete=True,
                message='完整 CCBaga A+B、Clash Verge GUI、Claude Desktop 已写入客机磁盘并经独立只读重挂验签。未发布、未启动、未验收首次桌面；不是产品交付。')
            registry.write_private(evidence/'preinstall-complete.json',outcome)
            return outcome
        except BaseException as error:
            outcome.update({'failed_at':_time(),'error_type':type(error).__name__,
                'applications_preinstalled':False,'manual_review_required':True})
            registry.write_private(evidence/'preinstall-failed.json',outcome)
            _state(target,operation_id,'failed_quarantined',failed=True,
                message='离线预装未完成；新暂存磁盘未发布、未启动。已保留证据并禁止自动覆盖重试，请先核对暂存状态。')
            raise
