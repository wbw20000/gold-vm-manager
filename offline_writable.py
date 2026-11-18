"""Explicit new-stage Data-only writable sessions, separate from readonly trust.

A readonly baseline and a fresh full RW unmounted capture must independently
agree on every persistent image/partition/container/volume UUID. A mount probe
can capture unknown post-mount schema but CANNOT pass check_mounted_writable or
application writes until the separate strict mounted-write validator exists.
No unlock, repair, force unmount, whole-image write, user setup or guest boot.
"""
import os
from pathlib import Path

import offline_disk as disk
import offline_volume as volume
import managed_registry as registry


class WritableDiskSession(disk.DiskSession):
    def __init__(self,target,evidence_dir,readonly_baseline,*,acknowledge_write=False,lock_held=False,ownership_mode=None,run=disk.subprocess.run):
        if acknowledge_write is not True or type(readonly_baseline) is not volume.OfflineAttribution:
            raise disk.OfflineDiskError('Explicit write authorization and verified readonly baseline required')
        if readonly_baseline.image_path!=str(target.image):
            raise disk.OfflineDiskError('Readonly baseline belongs to another image')
        self.readonly_baseline=readonly_baseline
        self.filesystem_was_mounted=False
        self.config_identity=disk.signature(target.stage/'config.json')
        self.nvram_identity=disk.signature(target.stage/'nvram.bin')
        super().__init__(target,evidence_dir,lock_held=lock_held,probe_writable_attachment=True,ownership_mode=ownership_mode,run=run)

    def __enter__(self):
        try:
            super().__enter__()
            raw={key:value for key,value in self.capture.items() if key!='context'}
            context=volume.WritableContext(image_path=str(self.target.image),owner_uid=os.getuid(),
                image_is_new=True,unpublished=True,never_booted=True,lock_held=True,installer_exited=True,
                write_authorized=True)
            self.attribution=volume.validate_writable_unmounted(context,self.readonly_baseline,**raw)
            self.summary['writable_unmounted_capture_verified']=True
            return self
        except BaseException:
            if self.attach_started and not self.summary['cleanup_confirmed']:self.cleanup()
            raise

    def mount_readonly_for_probe(self):
        raise disk.OfflineDiskError('Writable attachment cannot be used as readonly verification')

    def mount_writable_for_probe(self):
        if type(self.attribution) is not volume.WritableAttribution or self.mountpoint is not None:
            raise disk.OfflineDiskError('Fresh distinct writable attribution required')
        self.data_device=self.attribution.data_device
        self.owned(disk.node(self.data_device))
        self.mountpoint=self.directory/'data-mount';self.mountpoint.mkdir(mode=0o700)
        self.summary['mount_requested']=True
        # From this point the filesystem may update journal metadata, even if the
        # command fails. This never authorizes mutations to config or NVRAM.
        self.filesystem_was_mounted=True
        options = [] if self.ownership_mode is None else ['-mountOptions', 'owners' if self.ownership_mode == 'on' else 'noowners']
        self.command(['/usr/sbin/diskutil','mount','nobrowse']+options+['-mountPoint',str(self.mountpoint),
                      disk.node(self.data_device)],'mount-writable-data')
        raw = self._check_mounted_write_metadata()
        if self.ownership_mode is not None and disk.decode(raw).get('GlobalPermissionsEnabled') is not (self.ownership_mode == 'on'):
            raise disk.OfflineDiskError('Explicit writable ownership mode not applied by macOS')
        self.summary['writable_mount_metadata_captured']=True
        return self.mountpoint

    def mount_writable(self):
        self.mount_writable_for_probe()
        self.check_mounted_writable()
        self.summary['writable_data_mount_verified']=True
        return self.mountpoint

    def _check_mounted_write_metadata(self):
        """Probe/cleanup guard only, not permission for application writes."""
        a=self.attribution
        if type(a) is not volume.WritableAttribution or self.mountpoint is None or self.data_device!=a.data_device:
            raise disk.OfflineDiskError('No attributed writable Data mount')
        mapping,_=self.owned(disk.node(self.data_device))
        mounts=[(e.get('dev-entry'),e.get('mount-point')) for e in mapping['system-entities'] if e.get('mount-point')]
        if mounts!=[(disk.node(self.data_device),str(self.mountpoint))] or mapping.get('writeable') is not True:
            raise disk.OfflineDiskError('Only the attributed new Data volume may be mounted writable')
        raw=self.command(['/usr/sbin/diskutil','info','-plist',disk.node(self.data_device)],'mounted-write-data-info')
        info=disk.decode(raw)
        v=next(v for c in a.containers for v in c.volumes if v.device==a.data_device)
        expected={'DeviceIdentifier':a.data_device,'DeviceNode':disk.node(a.data_device),
            'APFSContainerReference':a.main_container_device,'ParentWholeDisk':a.main_container_device,
            'DiskUUID':a.data_uuid,'VolumeUUID':a.data_uuid,'APFSVolumeGroupID':a.volume_group_uuid,
            'MountPoint':str(self.mountpoint),'BusProtocol':'Disk Image','FilesystemType':'apfs',
            'APFSPhysicalStores':[{'APFSPhysicalStore':v.physical_store_device}]}
        if (any(type(info.get(k)) is not type(value) or info[k]!=value for k,value in expected.items())
                or any(info.get(k) is not False for k in ('WholeDisk','Internal','APFSSnapshot',
                    'Encryption','EncryptionThisVolumeProper','FileVault','Locked'))
                or any(info.get(k) is not True for k in ('Writable','WritableMedia','WritableVolume'))):
            raise disk.OfflineDiskError('Writable Data mount identity/access mismatch')
        if registry.safe_path(self.mountpoint)!=self.mountpoint or not os.path.ismount(self.mountpoint):
            raise disk.OfflineDiskError('Writable mountpoint changed')
        s=self.mountpoint.stat();identity=(s.st_dev,s.st_ino)
        if self.mount_identity is not None and self.mount_identity!=identity:
            raise disk.OfflineDiskError('Writable filesystem identity changed')
        self.mount_identity=identity;self.mounted_info=raw
        return raw

    def check_mounted_writable(self):
        raw=self._check_mounted_write_metadata()
        validator=getattr(volume,'validate_mounted_writable',None)
        if validator is None:
            raise disk.OfflineDiskError('Mounted-write contract not integrated; application writes forbidden')
        return validator(self.attribution,str(self.mountpoint),raw)

    def check_mounted_readonly(self):
        raise disk.OfflineDiskError('Writable session cannot verify readonly installation acceptance')

    def check_mount_for_cleanup(self):
        return self._check_mounted_write_metadata()

    def verify_image_after_cleanup(self):
        after=disk.signature(self.target.image)
        if self.filesystem_was_mounted:
            if after[:3]!=self.target.baseline[:3]:raise disk.OfflineDiskError('Writable image file identity/size changed')
            self.summary['image_metadata_changed']=after!=self.target.baseline
        else:self.target.verify_unchanged()
        if disk.signature(self.target.stage/'config.json')!=self.config_identity or disk.signature(self.target.stage/'nvram.bin')!=self.nvram_identity:
            raise disk.OfflineDiskError('VM identity or NVRAM changed during application-only operation')
