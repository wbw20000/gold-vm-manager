"""Explicit NON-destructive recovery of an already reviewed complete copy prefix.

Never an automatic retry. No existing application bytes are overwritten/deleted:
retained apps must match every byte/mode/link of the freshly verified originals
on a new readonly attachment first, then AGAIN before any metadata-only origin
propagation. Unknown/partial/corrupt apps, changed IDs or unreconciled attachment
cleanup fail closed. Complete success still requires a fresh final readonly
four-app verification and detach; no guest boot/publication/credentials.
"""
from dataclasses import asdict, replace
from pathlib import Path

import guest_app_artifacts as artifacts
from guest_app_pins import reviewed_manifests
import managed_registry as registry
from offline_disk import StageTarget, DiskSession, signature
from offline_writable import WritableDiskSession
from offline_install import APP_NAMES, application_root, validate_material_set, verify_materials, write_applications, verify_installed_readonly
from offline_preinstall import PreinstallError, _state, _time


def _require(ok,message):
    if not ok:raise PreinstallError(message)


def resume_verified_prefix(*,state_dir,tart_home,job_id,name,materials,failed_evidence_dir,
                           operation_id,evidence_dir,acknowledge_recovery=False,external_lock=None):
    _require(acknowledge_recovery is True,'Explicit reviewed-prefix recovery authorization required')
    validate_material_set(materials)
    _require(tuple(m.manifest for m in materials)==reviewed_manifests(),'Only the complete frozen reviewed catalog is eligible')
    previous=registry.safe_path(Path(failed_evidence_dir))
    failed=registry.read_private(previous/'preinstall-failed.json')
    cleanup=registry.read_private(previous/'write-session/session-summary.json')
    transaction=registry.read_private(previous/'copy-transaction/transaction.json')
    _require(all(type(value) is dict for value in (failed,cleanup,transaction)),
             'Missing or malformed prior evidence; recovery refused')
    _require(failed.get('operation_id')==operation_id and failed.get('job_id')==job_id
        and failed.get('name')==name and failed.get('applications_preinstalled') is False
        and failed.get('guest_started') is False and failed.get('desktop_verified') is False
        and failed.get('credentials_copied') is False and failed.get('published') is False,
        'Failed-operation evidence does not match this exact fresh stage')
    _require(cleanup.get('cleanup_confirmed') is True and cleanup.get('operation_failed') is True
        and cleanup.get('guest_started') is False and transaction.get('phase')=='failed_quarantined'
        and transaction.get('applications_preinstalled') is False,'Prior disk cleanup or failure scope is unproven')
    target=StageTarget.load(state_dir,tart_home,job_id,name,review_failed_operation_id=operation_id)
    _require(failed.get('stage_path')==str(target.stage),'Failed evidence targets another staging directory')
    _require(not (target.stage/'.offline-preinstall.complete.json').exists(),'Completed stage cannot be resumed')
    evidence=registry.safe_path(Path(evidence_dir),False);evidence.mkdir(mode=0o700)
    config_before=signature(target.stage/'config.json');nvram_before=signature(target.stage/'nvram.bin')
    outcome={'schema':1,'operation_id':operation_id,'job_id':job_id,'name':name,'stage_path':str(target.stage),
        'recovered_from':str(previous),'started_at':_time(),'applications_preinstalled':False,
        'guest_started':False,'desktop_verified':False,'credentials_copied':False,'published':False}
    with target.locked(external_lock):
        try:
            source_receipts=verify_materials(materials)
            expected={app['name']:(app['bundle_tree_sha256'],app['bundle_bytes'],app['bundle_entries'])
                      for receipt in source_receipts for app in receipt.apps}
            by_name={app.name:material for material in materials for app in material.manifest.expected_apps}
            for material,receipt in zip(materials,source_receipts):
                artifacts.write_evidence(receipt,evidence/(material.manifest.product+'-source.json'))
            with DiskSession(target,evidence/'before-recovery-readonly',lock_held=True) as readonly:
                readonly.mount_readonly_for_probe();root=application_root(readonly,writable=False)
                baseline=readonly.attribution
                _require(baseline.data_uuid==transaction.get('data_uuid')
                         and baseline.volume_group_uuid==transaction.get('volume_group_uuid'),
                         'Fresh Data/group identity differs from original failed transaction')
                names=set(p.name for p in root.iterdir())
                _require(names <= set(APP_NAMES)|{'.localized','Safari.app','Utilities'},'Unknown application-root content; no recovery')
                prefix=tuple(name for name in APP_NAMES if name in names)
                _require(prefix and prefix==APP_NAMES[:len(prefix)],'Only a contiguous complete application prefix can be retained')
                for app_name in prefix:
                    path=registry.safe_path(root/app_name)
                    _require(path.is_dir() and artifacts._tree_snapshot(path,by_name[app_name].manifest)==expected[app_name],
                             'An existing app is partial/changed; never overwrite or repair its bytes')
                registry.write_private(evidence/'readonly-prefix-review.json',{
                    'operation_id':operation_id,'data_uuid':baseline.data_uuid,'volume_group_uuid':baseline.volume_group_uuid,
                    'verified_existing_apps':list(prefix),'all_existing_bundle_trees_match_verified_originals':True,
                    'application_bytes_may_be_overwritten':False,'guest_started':False})
            # Readonly review alone grants no writes. Only this explicit, checked
            # recovery decision upgrades the same pinned new-stage object while
            # holding its original lifecycle/config locks and after clean detach.
            writable_target=replace(target,readonly_review=False)
            _state(target,operation_id,'resuming_verified_prefix',message='已只读确认已复制应用完整且未变；只补缺失来源标记、保留现有应用字节，再补装缺少的应用。未启动。')
            with WritableDiskSession(writable_target,evidence/'write-session',baseline,
                                     acknowledge_write=True,lock_held=True) as writable:
                writable.mount_writable()
                source_receipts=write_applications(writable,materials,evidence/'copy-transaction',
                    acknowledge_write=True,verified_existing=prefix)
            after=StageTarget.load(state_dir,tart_home,job_id,name,review_failed_operation_id=operation_id)
            _require(after.baseline[:3]==target.baseline[:3]
                and signature(after.stage/'config.json')==config_before and signature(after.stage/'nvram.bin')==nvram_before,
                'Recovery changed image identity/size/config/NVRAM; no acceptance')
            _state(target,operation_id,'verifying_recovery_readonly',message='完整应用已补齐；正在独立只读重挂验签，尚未算预装成功。')
            with DiskSession(after,evidence/'after-write-readonly',lock_held=True) as readonly:
                readonly.mount_readonly_for_probe()
                guest_receipts=verify_installed_readonly(readonly,materials,source_receipts,
                    expected_data_uuid=baseline.data_uuid,expected_group_uuid=baseline.volume_group_uuid)
                for material,receipt in zip(materials,guest_receipts):
                    artifacts.write_evidence(receipt,evidence/(material.manifest.product+'-guest-readonly.json'))
            outcome.update({'finished_at':_time(),'applications_preinstalled':True,'readonly_remount_verified':True,
                'final_detach_confirmed':True,'data_uuid':baseline.data_uuid,'volume_group_uuid':baseline.volume_group_uuid,
                'retained_without_application_byte_overwrite':list(prefix),'vm_config_and_nvram_unchanged':True,
                'image_file_identity_and_size_unchanged':True,
                'applications':[{'name':app['name'],'bundle_identifier':app['bundle_identifier'],
                    'short_version':app['short_version'],'bundle_version':app['bundle_version'],'team_id':app['team_id'],
                    'bundle_bytes':app['bundle_bytes'],'bundle_tree_sha256':app['bundle_tree_sha256']}
                    for receipt in guest_receipts for app in receipt.apps]})
            # Final public-facing evidence receipt is last, after sidecar + state.
            sidecar=after.stage/'.offline-preinstall.complete.json'
            _require(not sidecar.exists() and not sidecar.is_symlink(),'Existing completion receipt cannot be overwritten')
            registry.write_private(sidecar,outcome)
            _state(target,operation_id,'verified_awaiting_first_desktop',complete=True,
                message='完整 CCBaga A+B、Clash Verge GUI、Claude Desktop 已写入客机并经独立只读重挂验签。已安全保留先前完整副本并补齐来源标记。未发布、未启动、首次桌面未验收。')
            registry.write_private(evidence/'preinstall-complete.json',outcome)
            return outcome
        except BaseException as error:
            outcome.update({'failed_at':_time(),'error_type':type(error).__name__,
                'applications_preinstalled':False,'manual_review_required':True})
            registry.write_private(evidence/'preinstall-failed.json',outcome)
            _state(target,operation_id,'failed_quarantined',failed=True,
                message='非破坏性续装未通过完整验收；没有删除或覆盖已有应用，暂存磁盘仍未发布、未启动。保留新旧证据，禁止盲目重试。')
            raise
