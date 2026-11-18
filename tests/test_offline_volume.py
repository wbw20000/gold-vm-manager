"""Portable synthetic macOS 26.6.2 schema tests; never touch a real device/image.

All identities and paths below are invented. No test reads private evidence or
invokes system utilities. Fixture field spellings reflect captured Apple XML,
not the older Swift synthetic contract.
"""

import ast
import copy
from dataclasses import FrozenInstanceError, replace
import inspect
import plistlib
import unittest
import uuid
from unittest import mock

import offline_volume as ov


def uid(number):
    return str(uuid.UUID(int=number)).upper()


def synthetic_capture(shift=0):
    """Return context and mutable plist objects for negative mutation tests."""
    whole = "disk%d" % (80 + shift)
    specs = [
        ("Apple_APFS_ISC", "disk%d" % (91 + shift), whole + "s4",
         [(2, "Preboot"), (5, "xART"), (7, "Hardware"), (9, "Recovery")]),
        ("Apple_APFS", "disk%d" % (103 + shift), whole + "s7",
         [(3, "System"), (5, "Preboot"), (7, "Recovery"), (9, "Update"), (11, "Data")]),
        ("Apple_APFS_Recovery", "disk%d" % (95 + shift), whole + "s9", [(4, "Recovery")]),
    ]
    context = ov.ValidationContext("/synthetic/unpublished/new-image.img", 1234,
                                   True, True, True, True, True)
    image_size = 1024 * 1024 * 1024
    attached = []
    owned_entities = []

    def entity(dev, content, unmapped, mountable):
        item = {"dev-entry": "/dev/" + dev, "content-hint": content,
                "unmapped-content-hint": unmapped, "potentially-mountable": mountable}
        if mountable:
            item["volume-kind"] = "apfs"
        attached.append(item)
        owned_entities.append({"dev-entry": "/dev/" + dev, "content-hint": unmapped})

    entity(whole, ov.GUID, ov.GUID, False)
    partitions = []
    apfs = {}
    groups = {}
    infos = {}

    def common_info(dev, parent, size, is_whole):
        return {
            "Bootable": False, "BusProtocol": "Disk Image", "CanBeMadeBootable": False,
            "CanBeMadeBootableRequiresDestroy": False,
            "Content": ov.GUID if is_whole else ov.VOLUME_HINT,
            "DeviceBlockSize": 512 if is_whole else 4096,
            "DeviceIdentifier": dev, "DeviceNode": "/dev/" + dev,
            "DeviceTreePath": "IODeviceTree:/", "Ejectable": True,
            "EjectableMediaAutomaticUnderSoftwareControl": True, "EjectableOnly": True,
            "FreeSpace": 0, "GlobalPermissionsEnabled": False, "IOKitSize": size,
            "IORegistryEntryName": "synthetic metadata", "Internal": False,
            "MediaName": "", "MediaType": "Generic", "MountPoint": "",
            "OSInternalMedia": False, "ParentWholeDisk": parent, "PartitionMapPartition": False,
            "RAIDMaster": False, "RAIDSlice": False, "Removable": True, "RemovableMedia": True,
            "RemovableMediaOrExternalDevice": True,
            "SMARTDeviceSpecificKeysMayVaryNotGuaranteed": {}, "SMARTStatus": "Not Supported",
            "Size": size, "SupportsGlobalPermissionsDisable": not is_whole, "SystemImage": False,
            "TotalSize": size, "VolumeName": "untrusted repeated name", "VolumeSize": 0,
            "WholeDisk": is_whole, "Writable": False, "WritableMedia": False, "WritableVolume": False,
        }

    counter = 1000
    for index, (content, dev, store, roles) in enumerate(specs):
        size = 200 * 1024 * 1024 + index * 4096
        part = {"Content": content, "DeviceIdentifier": store, "DiskUUID": uid(100 + index), "Size": size}
        partitions.append(part)
        entity(store, content, ov.PARTITION_HINTS[content], False)
        entity(dev, ov.CONTAINER_HINT, ov.CONTAINER_HINT, False)
        container = {
            "APFSContainerUUID": uid(200 + index), "CapacityCeiling": size,
            "CapacityFree": size // 2, "ContainerReference": dev,
            "DesignatedPhysicalStore": store,
            "PhysicalStores": [{"DeviceIdentifier": store, "DiskUUID": part["DiskUUID"], "Size": size}],
            "Volumes": [],
        }
        apfs[dev] = {"Containers": [container]}
        group_container = {"APFSContainerUUID": container["APFSContainerUUID"],
                           "ContainerReference": dev, "VolumeGroups": []}
        groups[dev] = {"Containers": [group_container]}
        members = []
        for number, role in roles:
            counter += 1
            volume_dev = dev + "s%d" % number
            volume_uuid = uid(counter)
            volume = {
                "APFSVolumeUUID": volume_uuid, "CapacityInUse": 4096,
                "CapacityQuota": 0, "CapacityReserve": 0, "CryptoMigrationOn": False,
                "DeviceIdentifier": volume_dev, "Encryption": False, "FileVault": False,
                "Locked": False, "Name": "same arbitrary display name", "Roles": [role],
            }
            container["Volumes"].append(volume)
            entity(volume_dev, ov.VOLUME_HINT, ov.VOLUME_HINT, True)
            info = common_info(volume_dev, dev, size, False)
            info.update({
                "APFSContainerFree": container["CapacityFree"], "APFSContainerReference": dev,
                "APFSContainerSize": size, "APFSPhysicalStores": [{"APFSPhysicalStore": store}],
                "APFSSnapshot": False, "CapacityInUse": 4096, "DiskUUID": volume_uuid,
                "Encryption": False, "EncryptionThisVolumeProper": False, "FileVault": False,
                "FilesystemName": "APFS", "FilesystemType": "apfs", "FilesystemUserVisibleName": "APFS",
                "Locked": False, "Sealed": "Yes" if role == "System" else "No", "VolumeUUID": volume_uuid,
            })
            for ref_role, field in (("Preboot", "BooterDeviceIdentifier"), ("Recovery", "RecoveryDeviceIdentifier")):
                for ref_number, candidate in roles:
                    if candidate == ref_role:
                        info[field] = dev + "s%d" % ref_number
            infos[volume_dev] = info
            if role in {"Data", "System"}:
                members.append({"DeviceIdentifier": volume_dev, "DiskUUID": volume_uuid,
                                "NoBrowseRole": False, "Role": role})
        if content == "Apple_APFS":
            group_uuid = next(member["DiskUUID"] for member in members if member["Role"] == "Data")
            group_container["VolumeGroups"] = [{"APFSVolumeGroupUUID": group_uuid, "Volumes": members}]
            for member in members:
                infos[member["DeviceIdentifier"]]["APFSVolumeGroupID"] = group_uuid
                infos[member["DeviceIdentifier"]]["Bootable"] = True
    whole_info = common_info(whole, whole, image_size, True)
    whole_info.update({"LowLevelFormatSupported": False, "OS9DriversInstalled": False,
                       "VirtualOrPhysical": "Virtual"})
    return context, {
        "attach_plist": {"system-entities": attached},
        "owned_image_plist": {
            "autodiskmount": False, "blockcount": image_size // 512, "blocksize": 512,
            "diskimages2": False, "hdid-pid": 4321, "icon-path": "/synthetic/icon.icns",
            "image-encrypted": False, "image-path": context.image_path, "image-type": "read/write",
            "owner-uid": context.owner_uid, "removable": True,
            "system-entities": list(reversed(owned_entities)), "writeable": False,
        },
        "disk_list_plist": {"AllDisks": [whole] + [p["DeviceIdentifier"] for p in partitions],
                            "AllDisksAndPartitions": [{"Content": ov.GUID, "DeviceIdentifier": whole,
                                                       "OSInternal": False, "Partitions": partitions, "Size": image_size}],
                            "VolumesFromDisks": [], "WholeDisks": [whole]},
        "whole_info_plist": whole_info, "apfs_plists": apfs, "groups_plists": groups,
        "volume_info_plists": infos,
    }


def encoded(capture):
    return {key: ({dev: plistlib.dumps(value) for dev, value in item.items()}
                  if key in {"apfs_plists", "groups_plists", "volume_info_plists"}
                  else plistlib.dumps(item)) for key, item in capture.items()}


def validate(context, capture):
    return ov.validate_readonly(context, **encoded(capture))


def locate(capture, role="Data", content="Apple_APFS"):
    partitions = capture["disk_list_plist"]["AllDisksAndPartitions"][0]["Partitions"]
    store = next(p["DeviceIdentifier"] for p in partitions if p["Content"] == content)
    container = next(raw["Containers"][0] for raw in capture["apfs_plists"].values()
                     if raw["Containers"][0]["DesignatedPhysicalStore"] == store)
    volume = next(v for v in container["Volumes"] if v["Roles"] == [role])
    return container, volume, capture["volume_info_plists"][volume["DeviceIdentifier"]]


class ReadonlyAttributionTests(unittest.TestCase):
    def setUp(self):
        self.context, self.capture = synthetic_capture()

    def reject(self, capture=None, context=None):
        with self.assertRaises(ov.ValidationError):
            validate(context or self.context, capture or self.capture)

    def test_observed_schema_accepts_without_volume_name_selection(self):
        result = validate(self.context, self.capture)
        main, data, _ = locate(self.capture)
        _, system, _ = locate(self.capture, "System")
        self.assertEqual(result.whole_device, "disk80")
        self.assertIsNone(result.whole_disk_uuid)
        self.assertEqual(result.main_container_device, main["ContainerReference"])
        self.assertEqual(result.main_container_uuid, main["APFSContainerUUID"])
        self.assertEqual(result.data_device, data["DeviceIdentifier"])
        self.assertEqual(result.data_uuid, data["APFSVolumeUUID"])
        self.assertEqual(result.system_uuid, system["APFSVolumeUUID"])
        self.assertEqual(result.volume_group_uuid, result.data_uuid)
        self.assertEqual(len(result.partitions), 3)
        self.assertEqual(sum(len(c.volumes) for c in result.containers), 10)
        self.assertEqual(result.mode, ov.MODE)

    def test_not_tied_to_any_device_number_or_order(self):
        context, capture = synthetic_capture(187)
        capture["attach_plist"]["system-entities"].reverse()
        capture["disk_list_plist"]["AllDisks"].reverse()
        capture["disk_list_plist"]["AllDisksAndPartitions"][0]["Partitions"].reverse()
        for raw in capture["apfs_plists"].values():
            raw["Containers"][0]["Volumes"].reverse()
        result = validate(context, capture)
        self.assertEqual(result.whole_device, "disk267")
        self.assertEqual(result.data_device, "disk290s11")

    def test_inputs_unchanged_and_output_deeply_immutable(self):
        before = copy.deepcopy(self.capture)
        result = validate(self.context, self.capture)
        self.assertEqual(self.capture, before)
        with self.assertRaises(FrozenInstanceError):
            result.data_device = "disk0s1"
        with self.assertRaises(FrozenInstanceError):
            result.containers[0].volumes[0].uuid = uid(9999)
        self.assertIsInstance(result.containers, tuple)
        self.capture["whole_info_plist"]["DeviceIdentifier"] = "disk0"
        self.assertEqual(result.whole_device, "disk80")

    def test_no_io_or_command_implementations(self):
        source = inspect.getsource(ov)
        tree = ast.parse(source, feature_version=(3, 9))
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse(imports & {"os", "subprocess", "pathlib", "socket", "ctypes", "urllib"})
        args = encoded(self.capture)
        with mock.patch("builtins.open", side_effect=AssertionError("I/O forbidden")):
            result = ov.validate_readonly(self.context, **args)
        self.assertEqual(result.mode, ov.MODE)

    def test_context_guards_reject_false_missing_type_and_numeric_bool(self):
        for field in ("image_is_new", "unpublished", "never_booted", "lock_held", "installer_exited"):
            for bad in (False, 1, 0, "true", None):
                with self.subTest(field=field, bad=bad):
                    self.reject(context=replace(self.context, **{field: bad}))
        for field, bad in (("schema", "macos-27"), ("mode", "readwrite"), ("mode", "readonly_mounted"),
                           ("owner_uid", True), ("owner_uid", -1), ("owner_uid", "1234")):
            with self.subTest(field=field, bad=bad):
                self.reject(context=replace(self.context, **{field: bad}))
        with self.assertRaises(ov.ValidationError):
            ov.validate_readonly(None, **encoded(self.capture))

    def test_canonical_path_and_exact_owner(self):
        for path in ("relative.img", "/a/../b.img", "//host/a.img", "/a//b.img", "/a/./b.img", "/", "/a/b/", "/a/\n.img"):
            with self.subTest(path=path):
                self.reject(context=replace(self.context, image_path=path))
        for key, value in (("image-path", "/synthetic/other.img"), ("owner-uid", 1235), ("owner-uid", True),
                           ("image-type", "read-only"), ("blockcount", True), ("blocksize", 0)):
            with self.subTest(key=key, value=value):
                capture = copy.deepcopy(self.capture)
                capture["owned_image_plist"][key] = value
                self.reject(capture)

    def test_required_ownership_bools(self):
        for field in ("writeable", "autodiskmount", "image-encrypted"):
            for bad in (True, 0, 1, "false", [], "missing"):
                with self.subTest(field=field, bad=bad):
                    capture = copy.deepcopy(self.capture)
                    if bad == "missing":
                        del capture["owned_image_plist"][field]
                    else:
                        capture["owned_image_plist"][field] = bad
                    self.reject(capture)

    def test_all_volumes_not_just_data_require_safe_bools(self):
        for device in self.capture["volume_info_plists"]:
            for field in ("Writable", "WritableMedia", "WritableVolume", "Encryption", "EncryptionThisVolumeProper",
                          "FileVault", "Locked", "APFSSnapshot", "Internal", "RAIDMaster", "RAIDSlice"):
                for bad in (True, 0, "missing"):
                    with self.subTest(device=device, field=field, bad=bad):
                        capture = copy.deepcopy(self.capture)
                        info = capture["volume_info_plists"][device]
                        if bad == "missing":
                            del info[field]
                        else:
                            info[field] = bad
                        self.reject(capture)

    def test_apfs_encryption_and_migration_all_checked(self):
        for role, content in (("Data", "Apple_APFS"), ("System", "Apple_APFS"), ("xART", "Apple_APFS_ISC"),
                              ("Recovery", "Apple_APFS_Recovery")):
            for field in ("CryptoMigrationOn", "Encryption", "FileVault", "Locked"):
                for bad in (True, 0, "missing"):
                    with self.subTest(role=role, field=field, bad=bad):
                        capture = copy.deepcopy(self.capture)
                        _, volume, _ = locate(capture, role, content)
                        if bad == "missing":
                            del volume[field]
                        else:
                            volume[field] = bad
                        self.reject(capture)

    def test_every_mountpoint_rejected_including_whole(self):
        for key in ["whole_info_plist"] + list(self.capture["volume_info_plists"]):
            for bad in ("/Volumes/test", " ", 0, False, "missing"):
                with self.subTest(key=key, bad=bad):
                    capture = copy.deepcopy(self.capture)
                    info = capture[key] if key == "whole_info_plist" else capture["volume_info_plists"][key]
                    if bad == "missing":
                        del info["MountPoint"]
                    else:
                        info["MountPoint"] = bad
                    self.reject(capture)

    def test_whole_readonly_flags_and_identity(self):
        for key in ("Writable", "WritableMedia", "WritableVolume", "Internal", "OSInternalMedia", "RAIDMaster"):
            for bad in (True, 0, "missing"):
                with self.subTest(key=key, bad=bad):
                    capture = copy.deepcopy(self.capture)
                    if bad == "missing":
                        del capture["whole_info_plist"][key]
                    else:
                        capture["whole_info_plist"][key] = bad
                    self.reject(capture)
        for key, bad in (("DeviceIdentifier", "disk0"), ("ParentWholeDisk", "disk0"), ("DeviceNode", "/dev/rdisk80"),
                         ("Content", "Apple_APFS"), ("WholeDisk", False), ("BusProtocol", "PCI-Express"),
                         ("VirtualOrPhysical", "Physical"), ("Size", 0)):
            with self.subTest(key=key):
                capture = copy.deepcopy(self.capture)
                capture["whole_info_plist"][key] = bad
                self.reject(capture)

    def test_attach_ownership_inventory_and_hints(self):
        for field in ("attach_plist", "owned_image_plist"):
            for mutation in ("duplicate", "missing", "foreign", "wrong_hint", "mountpoint"):
                with self.subTest(field=field, mutation=mutation):
                    capture = copy.deepcopy(self.capture)
                    entries = capture[field]["system-entities"]
                    if mutation == "duplicate":
                        entries.append(copy.deepcopy(entries[0]))
                    elif mutation == "missing":
                        entries.pop()
                    elif mutation == "foreign":
                        entries[0]["dev-entry"] = "/dev/disk0"
                    elif mutation == "wrong_hint":
                        entries[0]["content-hint"] = "Apple_APFS"
                    else:
                        entries[0]["mount-point"] = "/Volumes/unexpected"
                    self.reject(capture)
        for key, value in (("potentially-mountable", 0), ("potentially-mountable", True),
                           ("unmapped-content-hint", "unknown"), ("dev-entry", "/dev/disk080")):
            capture = copy.deepcopy(self.capture)
            capture["attach_plist"]["system-entities"][0][key] = value
            self.reject(capture)

    def test_unknown_schema_and_old_contract_rejected(self):
        for mutation in ("unknown_top", "unknown_info", "old_writable", "old_encrypted", "old_roles", "old_group"):
            with self.subTest(mutation=mutation):
                capture = copy.deepcopy(self.capture)
                container, _, info = locate(capture)
                if mutation == "unknown_top":
                    capture["attach_plist"]["new-schema"] = True
                elif mutation == "unknown_info":
                    info["Mounted"] = False
                elif mutation == "old_writable":
                    info["ReadOnly"] = True
                    del info["Writable"]
                elif mutation == "old_encrypted":
                    info["Encrypted"] = info.pop("Encryption")
                elif mutation == "old_roles":
                    info["Roles"] = ["Data"]
                else:
                    group = capture["groups_plists"][container["ContainerReference"]]["Containers"][0]
                    group["Groups"] = group.pop("VolumeGroups")
                self.reject(capture)

    def test_partition_inventory_uuid_mapping_and_capacities(self):
        for mutation in ("foreign_store", "wrong_uuid", "duplicate_uuid", "duplicate_device", "unknown_content",
                         "missing_partition", "extra_whole", "duplicate_alldisks", "mounted_disklist", "wrong_size"):
            with self.subTest(mutation=mutation):
                capture = copy.deepcopy(self.capture)
                disks = capture["disk_list_plist"]
                parts = disks["AllDisksAndPartitions"][0]["Partitions"]
                container, _, _ = locate(capture)
                if mutation == "foreign_store":
                    container["PhysicalStores"][0]["DeviceIdentifier"] = "disk0s1"
                elif mutation == "wrong_uuid":
                    container["PhysicalStores"][0]["DiskUUID"] = uid(9999)
                elif mutation == "duplicate_uuid":
                    parts[1]["DiskUUID"] = parts[0]["DiskUUID"]
                elif mutation == "duplicate_device":
                    parts[1]["DeviceIdentifier"] = parts[0]["DeviceIdentifier"]
                elif mutation == "unknown_content":
                    parts[0]["Content"] = "Apple_HFS"
                elif mutation == "missing_partition":
                    parts.pop()
                elif mutation == "extra_whole":
                    disks["WholeDisks"].append("disk0")
                elif mutation == "duplicate_alldisks":
                    disks["AllDisks"].append(disks["AllDisks"][0])
                elif mutation == "mounted_disklist":
                    disks["VolumesFromDisks"] = ["disk0s1"]
                else:
                    parts[0]["Size"] += 1
                self.reject(capture)

    def test_container_ambiguity_foreign_store_and_capture_omissions(self):
        for mutation in ("multi_store", "designated", "uuid", "device", "duplicate_container", "missing_apfs",
                         "missing_groups", "extra_info", "missing_info", "wrong_info_key", "negative_free"):
            with self.subTest(mutation=mutation):
                capture = copy.deepcopy(self.capture)
                container, volume, _ = locate(capture)
                dev = container["ContainerReference"]
                if mutation == "multi_store":
                    container["PhysicalStores"].append(copy.deepcopy(container["PhysicalStores"][0]))
                elif mutation == "designated":
                    container["DesignatedPhysicalStore"] = "disk0s1"
                elif mutation == "uuid":
                    container["APFSContainerUUID"] = container["PhysicalStores"][0]["DiskUUID"]
                elif mutation == "device":
                    container["ContainerReference"] = "disk0"
                elif mutation == "duplicate_container":
                    capture["apfs_plists"][dev]["Containers"].append(copy.deepcopy(container))
                elif mutation == "missing_apfs":
                    del capture["apfs_plists"][dev]
                elif mutation == "missing_groups":
                    del capture["groups_plists"][dev]
                elif mutation == "extra_info":
                    capture["volume_info_plists"]["disk0s1"] = copy.deepcopy(locate(capture)[2])
                elif mutation == "missing_info":
                    del capture["volume_info_plists"][volume["DeviceIdentifier"]]
                elif mutation == "wrong_info_key":
                    capture["volume_info_plists"]["disk0s1"] = capture["volume_info_plists"].pop(volume["DeviceIdentifier"])
                else:
                    container["CapacityFree"] = -1
                self.reject(capture)

    def test_duplicate_volume_uuid_device_unknown_and_multiple_roles(self):
        for mutation in ("uuid", "case_uuid", "nil_uuid", "device", "role", "empty_role", "multiple_role", "second_data", "foreign_location"):
            with self.subTest(mutation=mutation):
                capture = copy.deepcopy(self.capture)
                container, volume, _ = locate(capture)
                if mutation == "uuid":
                    volume["APFSVolumeUUID"] = container["Volumes"][0]["APFSVolumeUUID"]
                elif mutation == "case_uuid":
                    volume["APFSVolumeUUID"] = "aaaaaaaa-0000-0000-0000-000000000001"
                elif mutation == "nil_uuid":
                    volume["APFSVolumeUUID"] = uid(0)
                elif mutation == "device":
                    volume["DeviceIdentifier"] = container["Volumes"][0]["DeviceIdentifier"]
                elif mutation == "role":
                    volume["Roles"] = ["VM"]
                elif mutation == "empty_role":
                    volume["Roles"] = []
                elif mutation == "multiple_role":
                    volume["Roles"] = ["Data", "System"]
                elif mutation == "second_data":
                    container["Volumes"][0]["Roles"] = ["Data"]
                else:
                    locate(capture, "xART", "Apple_APFS_ISC")[1]["Roles"] = ["Data"]
                self.reject(capture)

    def test_group_and_info_uuid_role_identity_cross_checks(self):
        mutations = ("container_uuid", "container_device", "group_uuid", "duplicate_group", "missing_member",
                     "duplicate_member", "foreign_member", "member_uuid", "member_role", "member_bool",
                     "info_group", "missing_info_group", "aux_group", "info_uuid", "volume_uuid", "foreign_info_store",
                     "foreign_parent", "wrong_node", "foreign_booter", "seal", "snapshot")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                capture = copy.deepcopy(self.capture)
                container, _, info = locate(capture)
                group_container = capture["groups_plists"][container["ContainerReference"]]["Containers"][0]
                group = group_container["VolumeGroups"][0]
                member = group["Volumes"][0]
                if mutation == "container_uuid":
                    group_container["APFSContainerUUID"] = uid(9999)
                elif mutation == "container_device":
                    group_container["ContainerReference"] = "disk0"
                elif mutation == "group_uuid":
                    group["APFSVolumeGroupUUID"] = container["APFSContainerUUID"]
                elif mutation == "duplicate_group":
                    group_container["VolumeGroups"].append(copy.deepcopy(group))
                elif mutation == "missing_member":
                    group["Volumes"].pop()
                elif mutation == "duplicate_member":
                    group["Volumes"][1] = copy.deepcopy(member)
                elif mutation == "foreign_member":
                    member["DeviceIdentifier"] = "disk0s1"
                elif mutation == "member_uuid":
                    member["DiskUUID"] = uid(9999)
                elif mutation == "member_role":
                    member["Role"] = "Data"
                elif mutation == "member_bool":
                    member["NoBrowseRole"] = 0
                elif mutation == "info_group":
                    info["APFSVolumeGroupID"] = uid(9999)
                elif mutation == "missing_info_group":
                    del info["APFSVolumeGroupID"]
                elif mutation == "aux_group":
                    locate(capture, "Preboot")[2]["APFSVolumeGroupID"] = group["APFSVolumeGroupUUID"]
                elif mutation == "info_uuid":
                    info["DiskUUID"] = uid(9999)
                elif mutation == "volume_uuid":
                    info["VolumeUUID"] = uid(9999)
                elif mutation == "foreign_info_store":
                    info["APFSPhysicalStores"][0]["APFSPhysicalStore"] = "disk0s1"
                elif mutation == "foreign_parent":
                    info["ParentWholeDisk"] = "disk0"
                elif mutation == "wrong_node":
                    info["DeviceNode"] = "/dev/rdisk103s11"
                elif mutation == "foreign_booter":
                    info["BooterDeviceIdentifier"] = "disk0s1"
                elif mutation == "seal":
                    locate(capture, "System")[2]["Sealed"] = "No"
                else:
                    info["APFSSnapshot"] = True
                self.reject(capture)

    def test_distinct_group_uuid_allowed_only_with_consistent_references(self):
        container, _, info = locate(self.capture)
        group = self.capture["groups_plists"][container["ContainerReference"]]["Containers"][0]["VolumeGroups"][0]
        group["APFSVolumeGroupUUID"] = uid(8000)
        info["APFSVolumeGroupID"] = uid(8000)
        locate(self.capture, "System")[2]["APFSVolumeGroupID"] = uid(8000)
        result = validate(self.context, self.capture)
        self.assertEqual(result.volume_group_uuid, uid(8000))
        self.assertNotEqual(result.volume_group_uuid, result.data_uuid)

    def test_every_observed_bool_rejects_numeric_substitution(self):
        # Includes otherwise informational booleans, not only safety gates.
        def walk(value, path=()):
            if type(value) is dict:
                for key, item in value.items():
                    yield from walk(item, path + (key,))
            elif type(value) is list:
                for index, item in enumerate(value):
                    yield from walk(item, path + (index,))
            elif type(value) is bool:
                yield path, value

        for path, value in walk(self.capture):
            with self.subTest(path=path):
                capture = copy.deepcopy(self.capture)
                target = capture
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = int(value)
                self.reject(capture)

    def test_all_required_volume_fields_are_fail_closed(self):
        for field in ov._VOLUME_INFO:
            with self.subTest(field=field):
                capture = copy.deepcopy(self.capture)
                del locate(capture)[2][field]
                self.reject(capture)

    def test_new_fields_rejected_at_every_schema_dictionary_level(self):
        paths = [
            ("attach_plist",), ("attach_plist", "system-entities", 0), ("owned_image_plist",),
            ("owned_image_plist", "system-entities", 0), ("disk_list_plist",),
            ("disk_list_plist", "AllDisksAndPartitions", 0),
            ("disk_list_plist", "AllDisksAndPartitions", 0, "Partitions", 0),
            ("whole_info_plist",),
        ]
        container, volume, _ = locate(self.capture)
        dev = container["ContainerReference"]
        paths.extend([
            ("apfs_plists", dev), ("apfs_plists", dev, "Containers", 0),
            ("apfs_plists", dev, "Containers", 0, "PhysicalStores", 0),
            ("apfs_plists", dev, "Containers", 0, "Volumes", 0),
            ("groups_plists", dev), ("groups_plists", dev, "Containers", 0),
            ("groups_plists", dev, "Containers", 0, "VolumeGroups", 0),
            ("groups_plists", dev, "Containers", 0, "VolumeGroups", 0, "Volumes", 0),
            ("volume_info_plists", volume["DeviceIdentifier"]),
            ("volume_info_plists", volume["DeviceIdentifier"], "APFSPhysicalStores", 0),
        ])
        for path in paths:
            with self.subTest(path=path):
                capture = copy.deepcopy(self.capture)
                target = capture
                for part in path:
                    target = target[part]
                target["UnsupportedFutureField"] = False
                self.reject(capture)

    def test_context_image_path_not_derived_from_untrusted_capture(self):
        capture = copy.deepcopy(self.capture)
        capture["owned_image_plist"]["image-path"] = self.context.image_path + ".other"
        self.reject(capture)
        result = validate(self.context, self.capture)
        self.assertEqual(result.image_path, self.context.image_path)

    def test_capture_bounds_and_mapping_types(self):
        for field, bad in (("apfs_plists", []), ("groups_plists", {}), ("volume_info_plists", {"/dev/disk1": b"x"}),
                           ("attach_plist", "not bytes"), ("attach_plist", b"x" * (ov.MAX_PLIST_BYTES + 1))):
            with self.subTest(field=field):
                args = encoded(self.capture)
                args[field] = bad
                with self.assertRaises(ov.ValidationError):
                    ov.validate_readonly(self.context, **args)
        args = encoded(self.capture)
        args["volume_info_plists"] = {"disk%ds1" % n: b"x" * ov.MAX_PLIST_BYTES for n in range(20)}
        with self.assertRaisesRegex(ov.ValidationError, "capture size limit"):
            ov.validate_readonly(self.context, **args)


def writable_capture(shift=0):
    context, capture = synthetic_capture(shift)
    context = ov.WritableContext(**{**vars(context), "mode": ov.WRITABLE_MODE, "write_authorized": True})
    capture["owned_image_plist"]["writeable"] = True
    for info in [capture["whole_info_plist"]] + list(capture["volume_info_plists"].values()):
        info["Writable"] = True
        info["WritableMedia"] = True
        # Real nomount schema retains WritableVolume=false on every device.
    return context, capture


def replace_values(value, replacements):
    """Synthetic coherent identity mutations, including every cross-reference."""
    if type(value) is dict:
        return {key: replace_values(item, replacements) for key, item in value.items()}
    if type(value) is list:
        return [replace_values(item, replacements) for item in value]
    return replacements.get(value, value)


class WritableUnmountedTests(unittest.TestCase):
    def setUp(self):
        context, capture = synthetic_capture()
        self.baseline = validate(context, capture)
        self.context, self.capture = writable_capture()

    def writable(self, capture=None, context=None, baseline=None):
        return ov.validate_writable_unmounted(
            self.context if context is None else context,
            self.baseline if baseline is None else baseline,
            **encoded(self.capture if capture is None else capture))

    def test_observed_writable_media_nomount_schema_has_distinct_result(self):
        before = copy.deepcopy(self.capture)
        result = self.writable()
        self.assertIs(type(result), ov.WritableAttribution)
        self.assertNotIsInstance(result, ov.OfflineAttribution)
        self.assertEqual(result.mode, "writable_unmounted")
        self.assertEqual(result.data_uuid, self.baseline.data_uuid)
        self.assertEqual(self.capture, before)
        self.assertTrue(all(not info["WritableVolume"] and not info["MountPoint"]
                            for info in self.capture["volume_info_plists"].values()))
        with self.assertRaises(FrozenInstanceError):
            result.mode = "readonly_unmounted"
        raw_args = encoded(self.capture)
        with mock.patch("builtins.open", side_effect=AssertionError("I/O forbidden")):
            self.assertEqual(ov.validate_writable_unmounted(self.context, self.baseline, **raw_args), result)

    def test_reattachment_device_renumbering_allowed_uuid_graph_unchanged(self):
        context, capture = writable_capture(439)
        result = self.writable(capture, context)
        self.assertNotEqual(result.whole_device, self.baseline.whole_device)
        self.assertNotEqual(result.data_device, self.baseline.data_device)
        self.assertEqual(result.data_uuid, self.baseline.data_uuid)
        self.assertEqual(result.system_uuid, self.baseline.system_uuid)
        self.assertEqual(result.main_container_uuid, self.baseline.main_container_uuid)

    def test_explicit_write_authorization_and_lifecycle_flags_required(self):
        for field in ("write_authorized", "image_is_new", "unpublished", "never_booted", "lock_held", "installer_exited"):
            for bad in (False, 0, 1, "true", None):
                with self.subTest(field=field, bad=bad), self.assertRaises(ov.ValidationError):
                    self.writable(context=replace(self.context, **{field: bad}))
        for field, bad in (("mode", ov.MODE), ("mode", "writable_mounted"), ("schema", "macos-27"),
                           ("owner_uid", 1), ("image_path", "/synthetic/other.img")):
            with self.subTest(field=field), self.assertRaises(ov.ValidationError):
                self.writable(context=replace(self.context, **{field: bad}))

    def test_public_readonly_and_writable_types_cannot_be_interchanged(self):
        readonly_context, readonly_capture = synthetic_capture()
        writable_result = self.writable()
        with self.assertRaises(ov.ValidationError):
            self.writable(context=readonly_context)
        with self.assertRaises(ov.ValidationError):
            ov.validate_readonly(self.context, **encoded(self.capture))
        with self.assertRaises(ov.ValidationError):
            ov.validate_readonly(readonly_context, **encoded(self.capture))
        with self.assertRaises(ov.ValidationError):
            self.writable(readonly_capture)
        with self.assertRaises(ov.ValidationError):
            self.writable(baseline=writable_result)
        with self.assertRaises(ov.ValidationError):
            self.writable(baseline=replace(self.baseline, mode=ov.WRITABLE_MODE))
        with self.assertRaises(ov.ValidationError):
            ov.validate_mounted_readonly(writable_result, "/synthetic/mount", plistlib.dumps(locate(self.capture)[2]))
        with self.assertRaises(ov.ValidationError):
            ov.validate_writable_unmounted(self.context, None, **encoded(self.capture))

    def test_every_device_has_exact_actual_access_flags_and_remains_unmounted(self):
        devices = ["whole_info_plist"] + list(self.capture["volume_info_plists"])
        for device in devices:
            for field, bad_values in (("Writable", [False, 1, "true"]), ("WritableMedia", [False, 1, "true"]),
                                      ("WritableVolume", [True, 0, "false"]), ("MountPoint", ["/synthetic/mounted", False])):
                for bad in bad_values:
                    with self.subTest(device=device, field=field, bad=bad):
                        capture = copy.deepcopy(self.capture)
                        info = capture[device] if device == "whole_info_plist" else capture["volume_info_plists"][device]
                        info[field] = bad
                        with self.assertRaises(ov.ValidationError):
                            self.writable(capture)
        for bad in (False, 1, "true"):
            capture = copy.deepcopy(self.capture)
            capture["owned_image_plist"]["writeable"] = bad
            with self.assertRaises(ov.ValidationError):
                self.writable(capture)

    def test_no_security_gates_weakened_for_writable_capture(self):
        for device in self.capture["volume_info_plists"]:
            for field in ("Encryption", "EncryptionThisVolumeProper", "Locked", "FileVault", "APFSSnapshot", "Internal"):
                with self.subTest(device=device, field=field):
                    capture = copy.deepcopy(self.capture)
                    capture["volume_info_plists"][device][field] = True
                    with self.assertRaises(ov.ValidationError):
                        self.writable(capture)
        for field in ("autodiskmount", "image-encrypted"):
            capture = copy.deepcopy(self.capture)
            capture["owned_image_plist"][field] = True
            with self.assertRaises(ov.ValidationError):
                self.writable(capture)
        for field in ("CryptoMigrationOn", "Encryption", "Locked", "FileVault"):
            capture = copy.deepcopy(self.capture)
            locate(capture)[1][field] = True
            with self.assertRaises(ov.ValidationError):
                self.writable(capture)
        capture = copy.deepcopy(self.capture)
        locate(capture, "System")[2]["Sealed"] = "No"
        with self.assertRaises(ov.ValidationError):
            self.writable(capture)

    def test_every_persistent_uuid_change_rejected_even_when_capture_is_consistent(self):
        uuids = [part.uuid for part in self.baseline.partitions]
        uuids += [c.uuid for c in self.baseline.containers]
        uuids += [v.uuid for c in self.baseline.containers for v in c.volumes]
        for original in uuids:
            with self.subTest(uuid=original):
                capture = replace_values(self.capture, {original: uid(9000)})
                with self.assertRaisesRegex(ov.ValidationError, "persistent baseline"):
                    self.writable(capture)
        capture = copy.deepcopy(self.capture)
        container, _, info = locate(capture)
        group = capture["groups_plists"][container["ContainerReference"]]["Containers"][0]["VolumeGroups"][0]
        group["APFSVolumeGroupUUID"] = uid(9000)
        info["APFSVolumeGroupID"] = uid(9000)
        locate(capture, "System")[2]["APFSVolumeGroupID"] = uid(9000)
        with self.assertRaisesRegex(ov.ValidationError, "persistent baseline"):
            self.writable(capture)

    def test_coherent_uuid_role_swap_and_partition_size_change_rejected(self):
        _, first, _ = locate(self.capture, "xART", "Apple_APFS_ISC")
        _, second, _ = locate(self.capture, "Hardware", "Apple_APFS_ISC")
        capture = replace_values(self.capture, {first["APFSVolumeUUID"]: second["APFSVolumeUUID"],
                                               second["APFSVolumeUUID"]: first["APFSVolumeUUID"]})
        with self.assertRaisesRegex(ov.ValidationError, "persistent baseline"):
            self.writable(capture)
        for part in self.baseline.partitions:
            with self.subTest(partition=part.content):
                capture = replace_values(self.capture, {part.size: part.size + 100 * 4096})
                with self.assertRaisesRegex(ov.ValidationError, "persistent baseline"):
                    self.writable(capture)

    def test_foreign_stores_unknown_fields_roles_and_missing_captures_rejected(self):
        for mutation in ("store", "role", "missing_info", "mounted_field", "unknown_field", "duplicate_volume"):
            with self.subTest(mutation=mutation):
                capture = copy.deepcopy(self.capture)
                container, volume, info = locate(capture)
                if mutation == "store":
                    container["PhysicalStores"][0]["DeviceIdentifier"] = "disk0s1"
                elif mutation == "role":
                    volume["Roles"] = ["Backup"]
                elif mutation == "missing_info":
                    del capture["volume_info_plists"][volume["DeviceIdentifier"]]
                elif mutation == "mounted_field":
                    info["VolumeAllocationBlockSize"] = 4096
                elif mutation == "unknown_field":
                    info["Encrypted"] = False
                else:
                    container["Volumes"].append(copy.deepcopy(volume))
                with self.assertRaises(ov.ValidationError):
                    self.writable(capture)

    def test_baseline_auxiliary_identity_graph_is_checked(self):
        auxiliary = next(c for c in self.baseline.containers if c.device != self.baseline.main_container_device)
        changed_volume = replace(auxiliary.volumes[0], physical_store_uuid=uid(9000))
        changed = replace(auxiliary, volumes=(changed_volume,) + auxiliary.volumes[1:])
        baseline = replace(self.baseline, containers=tuple(
            changed if c == auxiliary else c for c in self.baseline.containers))
        with self.assertRaises(ov.ValidationError):
            self.writable(baseline=baseline)


class MountedReadonlyTests(unittest.TestCase):
    def setUp(self):
        self.context, self.capture = synthetic_capture()
        self.attribution = validate(self.context, self.capture)
        self.mountpoint = "/synthetic/private-session/data-mount"
        self.info = copy.deepcopy(locate(self.capture)[2])
        self.info["MountPoint"] = self.mountpoint
        self.info["VolumeAllocationBlockSize"] = 4096

    def mounted(self, info=None, attribution=None, mountpoint=None):
        return ov.validate_mounted_readonly(
            self.attribution if attribution is None else attribution,
            self.mountpoint if mountpoint is None else mountpoint,
            plistlib.dumps(self.info if info is None else info))

    def test_observed_mount_schema_accepted_and_result_immutable(self):
        result = self.mounted()
        self.assertEqual(result.mode, "readonly_data_mounted")
        self.assertEqual(result.data_uuid, self.attribution.data_uuid)
        self.assertEqual(result.mountpoint, self.mountpoint)
        self.assertEqual(result.main_container_uuid, self.attribution.main_container_uuid)
        main = next(c for c in self.attribution.containers if c.device == result.main_container_device)
        self.assertEqual(result.physical_store_uuid, main.physical_store.uuid)
        with self.assertRaises(FrozenInstanceError):
            result.mountpoint = "/other"
        raw = plistlib.dumps(self.info)
        with mock.patch("builtins.open", side_effect=AssertionError("pure validation only")):
            self.assertEqual(ov.validate_mounted_readonly(self.attribution, self.mountpoint, raw), result)

    def test_all_mounted_required_fields_cannot_be_omitted(self):
        for key in ov._MOUNTED_DATA_INFO:
            with self.subTest(key=key):
                info = copy.deepcopy(self.info)
                del info[key]
                with self.assertRaises(ov.ValidationError):
                    self.mounted(info)

    def test_all_mounted_safety_bools_fail_closed(self):
        fields = ("Writable", "WritableMedia", "WritableVolume", "WholeDisk", "Internal", "OSInternalMedia",
                  "RAIDMaster", "RAIDSlice", "SystemImage", "PartitionMapPartition", "APFSSnapshot",
                  "Encryption", "EncryptionThisVolumeProper", "FileVault", "Locked")
        for field in fields:
            for bad in (True, 0, 1, "false", []):
                with self.subTest(field=field, bad=bad):
                    info = copy.deepcopy(self.info)
                    info[field] = bad
                    with self.assertRaises(ov.ValidationError):
                        self.mounted(info)

    def test_every_mounted_bool_rejects_numbers(self):
        for key, value in self.info.items():
            if type(value) is bool:
                with self.subTest(key=key):
                    info = copy.deepcopy(self.info)
                    info[key] = int(value)
                    with self.assertRaises(ov.ValidationError):
                        self.mounted(info)

    def test_mountpoint_is_canonical_explicit_exact_and_not_name_selected(self):
        for bad in ("", "/", "relative", "//synthetic/data", "/a/../data", "/a//data", "/a/./data",
                    "/a/\ndata", self.mountpoint + "/", self.mountpoint + "-other", self.context.image_path):
            with self.subTest(mountpoint=bad), self.assertRaises(ov.ValidationError):
                self.mounted(mountpoint=bad)
        for bad in ("", self.mountpoint + "/", "/somewhere/else"):
            info = copy.deepcopy(self.info)
            info["MountPoint"] = bad
            with self.assertRaises(ov.ValidationError):
                self.mounted(info)
        self.info["VolumeName"] = "another untrusted display name"
        self.assertEqual(self.mounted().data_uuid, self.attribution.data_uuid)

    def test_mounted_identity_uuid_container_store_and_fs_cross_checks(self):
        bad_fields = {
            "DeviceIdentifier": self.attribution.system_device, "DeviceNode": "/dev/disk0s1",
            "DiskUUID": self.attribution.system_uuid, "VolumeUUID": uid(8000),
            "APFSVolumeGroupID": uid(8001), "APFSContainerReference": "disk0", "ParentWholeDisk": "disk0",
            "Content": "Apple_APFS", "FilesystemType": "hfs", "FilesystemName": "HFS",
            "BusProtocol": "PCI-Express", "Sealed": "Yes", "Size": 1, "TotalSize": 1,
            "IOKitSize": 1, "APFSContainerSize": 1, "DeviceBlockSize": 512,
            "VolumeAllocationBlockSize": 512, "VolumeSize": 1,
            "APFSContainerFree": -1, "CapacityInUse": self.attribution.image_size_bytes,
            "BooterDeviceIdentifier": "disk0s1", "RecoveryDeviceIdentifier": "disk0s2",
        }
        for key, value in bad_fields.items():
            with self.subTest(key=key):
                info = copy.deepcopy(self.info)
                info[key] = value
                with self.assertRaises(ov.ValidationError):
                    self.mounted(info)
        for stores in ([], [{"APFSPhysicalStore": "disk0s1"}], self.info["APFSPhysicalStores"] * 2,
                       [{"APFSPhysicalStore": self.info["APFSPhysicalStores"][0]["APFSPhysicalStore"], "DiskUUID": uid(1)}]):
            info = copy.deepcopy(self.info)
            info["APFSPhysicalStores"] = stores
            with self.assertRaises(ov.ValidationError):
                self.mounted(info)

    def test_unknown_new_field_and_numeric_allocation_block_rejected(self):
        for key, value in (("Mounted", True), ("ReadOnly", True), ("VolumeAllocationBlockSize", True),
                           ("VolumeAllocationBlockSize", "4096"), ("SMARTDeviceSpecificKeysMayVaryNotGuaranteed", {"unknown": 1})):
            with self.subTest(key=key):
                info = copy.deepcopy(self.info)
                info[key] = value
                with self.assertRaises(ov.ValidationError):
                    self.mounted(info)

    def test_unmounted_and_mounted_contracts_remain_separate(self):
        with self.assertRaises(ov.ValidationError):
            self.mounted(locate(self.capture)[2])
        self.capture["volume_info_plists"][self.attribution.data_device] = copy.deepcopy(self.info)
        with self.assertRaises(ov.ValidationError):
            validate(self.context, self.capture)
        self.capture["volume_info_plists"][self.attribution.data_device]["MountPoint"] = ""
        with self.assertRaises(ov.ValidationError):
            validate(self.context, self.capture)  # mounted-only allocation field is still rejected

    def test_wrong_baseline_mode_and_inconsistent_identity_graph_rejected(self):
        wrong = [replace(self.attribution, mode="readwrite_unmounted"),
                 replace(self.attribution, schema="macos-27"),
                 replace(self.attribution, data_device=self.attribution.system_device),
                 replace(self.attribution, data_uuid=uid(8000)),
                 replace(self.attribution, system_uuid=uid(8000)),
                 replace(self.attribution, main_container_uuid=uid(8000)),
                 replace(self.attribution, volume_group_uuid=uid(8000)),
                 replace(self.attribution, containers=()),
                 replace(self.attribution, partitions=()),
                 replace(self.attribution, containers=list(self.attribution.containers))]
        main = next(c for c in self.attribution.containers if c.device == self.attribution.main_container_device)
        for field, value in (("uuid", uid(8000)), ("physical_store_device", "disk0s1"), ("role", [])):
            changed = replace(main.volumes[0], **{field: value})
            updated_main = replace(main, volumes=(changed,) + main.volumes[1:])
            wrong.append(replace(self.attribution, containers=tuple(
                updated_main if c == main else c for c in self.attribution.containers)))
        for attribution in wrong:
            with self.subTest(attribution=attribution), self.assertRaises(ov.ValidationError):
                self.mounted(attribution=attribution)
        for wrong_type in (None, {}, self.context, self.mounted()):
            with self.assertRaises(ov.ValidationError):
                ov.validate_mounted_readonly(wrong_type, self.mountpoint, plistlib.dumps(self.info))

    def test_noowners_metadata_never_implies_writable(self):
        for enabled in (False, True):
            self.info["GlobalPermissionsEnabled"] = enabled
            self.assertEqual(self.mounted().mode, "readonly_data_mounted")
            self.info["WritableVolume"] = True
            with self.assertRaises(ov.ValidationError):
                self.mounted()
            self.info["WritableVolume"] = False

    def test_duplicate_keys_and_oversized_raw_rejected_at_mounted_entrypoint(self):
        raw = plistlib.dumps(self.info)
        duplicate = raw.replace(b"<key>Writable</key>", b"<key>Writable</key><true/><key>Writable</key>")
        for bad in (duplicate, b"x" * (ov.MAX_PLIST_BYTES + 1), b"bplist00"):
            with self.assertRaises(ov.ValidationError):
                ov.validate_mounted_readonly(self.attribution, self.mountpoint, bad)


class MountedWritableTests(unittest.TestCase):
    def setUp(self):
        readonly_context, readonly_capture = synthetic_capture()
        self.readonly = validate(readonly_context, readonly_capture)
        self.context, self.capture = writable_capture()
        self.attribution = ov.validate_writable_unmounted(self.context, self.readonly, **encoded(self.capture))
        self.mountpoint = "/synthetic/private-write-session/data-mount"
        self.info = copy.deepcopy(locate(self.capture)[2])
        self.info.update({"MountPoint": self.mountpoint, "WritableVolume": True, "VolumeAllocationBlockSize": 4096})

    def mounted(self, info=None, attribution=None, mountpoint=None):
        return ov.validate_mounted_writable(
            self.attribution if attribution is None else attribution,
            self.mountpoint if mountpoint is None else mountpoint,
            plistlib.dumps(self.info if info is None else info))

    def test_actual_mounted_writable_schema_distinct_immutable_result(self):
        original = copy.deepcopy(self.info)
        result = self.mounted()
        self.assertIs(type(result), ov.MountedWritableAttribution)
        self.assertNotIsInstance(result, ov.MountedReadonlyAttribution)
        self.assertEqual(result.mode, "writable_data_mounted")
        self.assertEqual(result.data_uuid, self.readonly.data_uuid)
        self.assertEqual(result.main_container_uuid, self.readonly.main_container_uuid)
        self.assertEqual(result.mountpoint, self.mountpoint)
        self.assertEqual(self.info, original)
        main = next(c for c in self.attribution.containers if c.device == result.main_container_device)
        self.assertEqual(result.physical_store_uuid, main.physical_store.uuid)
        with self.assertRaises(FrozenInstanceError):
            result.data_uuid = self.readonly.system_uuid
        with mock.patch("builtins.open", side_effect=AssertionError("no file writes or reads")):
            self.assertEqual(self.mounted(), result)

    def test_all_required_mounted_rw_fields_fail_closed(self):
        for key in ov._MOUNTED_DATA_INFO:
            with self.subTest(key=key):
                info = copy.deepcopy(self.info)
                del info[key]
                with self.assertRaises(ov.ValidationError):
                    self.mounted(info)

    def test_writable_flags_must_all_be_true_booleans_not_just_media(self):
        for key in ("Writable", "WritableMedia", "WritableVolume"):
            for bad in (False, 0, 1, "true", "false", []):
                with self.subTest(key=key, bad=bad):
                    info = copy.deepcopy(self.info)
                    info[key] = bad
                    with self.assertRaises(ov.ValidationError):
                        self.mounted(info)
        with self.assertRaises(ov.ValidationError):
            self.mounted(locate(self.capture)[2])

    def test_encrypted_locked_snapshot_internal_security_flags_still_false(self):
        keys = ("WholeDisk", "Internal", "OSInternalMedia", "RAIDMaster", "RAIDSlice", "SystemImage",
                "PartitionMapPartition", "APFSSnapshot", "Encryption", "EncryptionThisVolumeProper", "FileVault", "Locked")
        for key in keys:
            for bad in (True, 0, 1, "false", []):
                with self.subTest(key=key, bad=bad):
                    info = copy.deepcopy(self.info)
                    info[key] = bad
                    with self.assertRaises(ov.ValidationError):
                        self.mounted(info)

    def test_every_other_bool_also_rejects_numeric_coercion(self):
        for key, value in self.info.items():
            if type(value) is bool:
                with self.subTest(key=key):
                    info = copy.deepcopy(self.info)
                    info[key] = int(value)
                    with self.assertRaises(ov.ValidationError):
                        self.mounted(info)

    def test_exact_data_uuid_group_container_store_and_no_system_substitution(self):
        changes = {
            "DeviceIdentifier": self.attribution.system_device, "DeviceNode": "/dev/disk0s1",
            "DiskUUID": self.attribution.system_uuid, "VolumeUUID": uid(9999), "APFSVolumeGroupID": uid(9998),
            "APFSContainerReference": "disk0", "ParentWholeDisk": "disk0", "Content": "Apple_APFS",
            "FilesystemType": "hfs", "FilesystemName": "HFS", "BusProtocol": "PCI-Express", "Sealed": "Yes",
            "Size": 1, "TotalSize": 1, "IOKitSize": 1, "APFSContainerSize": 1,
            "DeviceBlockSize": 512, "VolumeAllocationBlockSize": 512, "VolumeSize": 1,
            "BooterDeviceIdentifier": "disk0s1", "RecoveryDeviceIdentifier": "disk0s2",
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                info = copy.deepcopy(self.info)
                info[key] = value
                with self.assertRaises(ov.ValidationError):
                    self.mounted(info)
        for stores in ([], [{"APFSPhysicalStore": "disk0s1"}], self.info["APFSPhysicalStores"] * 2):
            info = copy.deepcopy(self.info)
            info["APFSPhysicalStores"] = stores
            with self.assertRaises(ov.ValidationError):
                self.mounted(info)
        system_info = copy.deepcopy(locate(self.capture, "System")[2])
        system_info.update({"MountPoint": self.mountpoint, "WritableVolume": True, "VolumeAllocationBlockSize": 4096})
        with self.assertRaises(ov.ValidationError):
            self.mounted(system_info)

    def test_exact_mountpoint_no_alias_trailing_slash_or_empty(self):
        for point in ("", "/", "relative", "//host/mount", "/a/../mount", "/a//mount", "/a/./mount",
                      self.mountpoint + "/", self.mountpoint + "-other", self.context.image_path):
            with self.subTest(point=point), self.assertRaises(ov.ValidationError):
                self.mounted(mountpoint=point)
        for point in ("", "/synthetic/other", self.mountpoint + "/"):
            info = copy.deepcopy(self.info)
            info["MountPoint"] = point
            with self.assertRaises(ov.ValidationError):
                self.mounted(info)

    def test_apfs_allocation_changes_allowed_but_sizes_and_bounds_pinned(self):
        result = self.mounted()
        self.info["APFSContainerFree"] -= 20480
        self.info["CapacityInUse"] += 16384
        self.assertEqual(self.mounted(), result)
        for key in ("APFSContainerFree", "CapacityInUse"):
            for bad in (-1, self.info["APFSContainerSize"] + 1, True):
                with self.subTest(key=key, bad=bad):
                    info = copy.deepcopy(self.info)
                    info[key] = bad
                    with self.assertRaises(ov.ValidationError):
                        self.mounted(info)

    def test_readonly_and_writable_contracts_cannot_be_mixed_or_mode_spoofed(self):
        for wrong in (self.readonly, replace(self.readonly, mode=ov.WRITABLE_MODE),
                      replace(self.attribution, mode=ov.MODE), self.mounted(), {}, None):
            with self.subTest(kind=type(wrong).__name__), self.assertRaises(ov.ValidationError):
                ov.validate_mounted_writable(wrong, self.mountpoint, plistlib.dumps(self.info))
        with self.assertRaises(ov.ValidationError):
            ov.validate_mounted_readonly(self.readonly, self.mountpoint, plistlib.dumps(self.info))
        with self.assertRaises(ov.ValidationError):
            ov.validate_mounted_readonly(self.attribution, self.mountpoint, plistlib.dumps(self.info))
        info = copy.deepcopy(self.info)
        for key in ("Writable", "WritableMedia", "WritableVolume"):
            info[key] = False
        with self.assertRaises(ov.ValidationError):
            self.mounted(info)

    def test_writable_baseline_entire_identity_graph_is_required(self):
        wrong_baselines = [replace(self.attribution, data_uuid=uid(9999)),
                           replace(self.attribution, main_container_uuid=uid(9999)),
                           replace(self.attribution, volume_group_uuid=uid(9999)),
                           replace(self.attribution, containers=())]
        auxiliary = next(c for c in self.attribution.containers if c.device != self.attribution.main_container_device)
        changed_volume = replace(auxiliary.volumes[0], physical_store_uuid=uid(9000))
        changed = replace(auxiliary, volumes=(changed_volume,) + auxiliary.volumes[1:])
        wrong_baselines.append(replace(self.attribution, containers=tuple(
            changed if c == auxiliary else c for c in self.attribution.containers)))
        for baseline in wrong_baselines:
            with self.assertRaises(ov.ValidationError):
                self.mounted(attribution=baseline)

    def test_unknown_fields_duplicate_keys_and_bad_raw_still_rejected(self):
        for key, value in (("Mounted", True), ("Encrypted", False), ("ReadOnly", False),
                           ("VolumeAllocationBlockSize", True)):
            info = copy.deepcopy(self.info)
            info[key] = value
            with self.assertRaises(ov.ValidationError):
                self.mounted(info)
        raw = plistlib.dumps(self.info)
        duplicate = raw.replace(b"<key>Writable</key>", b"<key>Writable</key><false/><key>Writable</key>")
        for bad in (duplicate, b"x" * (ov.MAX_PLIST_BYTES + 1), b"bplist00"):
            with self.assertRaises(ov.ValidationError):
                ov.validate_mounted_writable(self.attribution, self.mountpoint, bad)


class StrictPlistParserTests(unittest.TestCase):
    @staticmethod
    def xml(body):
        return ('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">' + body + '</plist>').encode()

    def test_standard_apple_dtd_is_accepted_without_resource_access(self):
        raw = plistlib.dumps({"ok": False, "integer": 4, "nested": ["text", {"x": True}]})
        with mock.patch("builtins.open", side_effect=AssertionError("no DTD reads")):
            self.assertEqual(ov.parse_plist(raw)["integer"], 4)

    def test_duplicate_keys_rejected_at_all_depths_before_collapse(self):
        pair = '<key>x</key><false/><key>x</key><true/>'
        for body in ('<dict>' + pair + '</dict>', '<dict><key>nest</key><array><dict>' + pair + '</dict></array></dict>',
                     '<dict><key>Writable</key><false/><key>Writ&#97;ble</key><true/></dict>'):
            with self.subTest(body=body), self.assertRaisesRegex(ov.ValidationError, "duplicate"):
                ov.parse_plist(self.xml(body))

    def test_entities_internal_external_dtd_and_instructions_rejected(self):
        prefix = '<?xml version="1.0"?>'
        cases = [
            '<!DOCTYPE plist [<!ENTITY attack "yes">]>',
            '<!DOCTYPE plist [<!ENTITY attack SYSTEM "file:///synthetic/secret">]>',
            '<!DOCTYPE plist [<!ENTITY % attack SYSTEM "https://example.invalid/evil">%attack;]>',
            '<!DOCTYPE plist SYSTEM "https://example.invalid/evil">',
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" []>',
        ]
        for dtd in cases:
            with self.subTest(dtd=dtd), self.assertRaises(ov.ValidationError):
                ov.parse_plist((prefix + dtd + '<plist version="1.0"><dict/></plist>').encode())
        for body in ('<dict><key>x</key><string>&unknown;</string></dict>', '<?run command?><dict/>'):
            with self.assertRaises(ov.ValidationError):
                ov.parse_plist(self.xml(body))

    def test_malformed_or_unsupported_xml_types_and_scalar_shapes(self):
        cases = [b"", b"bplist00", b"not xml", b"<plist>", plistlib.dumps({"x": 1.5}), plistlib.dumps({"x": b"secret"})]
        bodies = ["<array/>", "<dict/><dict/>", "<dict><key>x</key></dict>",
                  "<dict><string>x</string><false/></dict>", "<dict><key>x</key><key>y</key></dict>",
                  "<dict><key>x</key><true>1</true></dict>", "<dict>unexpected</dict>",
                  "<dict><key>x</key><integer>true</integer></dict>",
                  "<dict><key>x</key><integer>9223372036854775808</integer></dict>",
                  "<dict><key>x</key><integer>01</integer></dict>",
                  "<dict><key>x</key><string><string>nested</string></string></dict>",
                  "<dict><key>x</key><array><key>bad</key></array></dict>",
                  '<dict><key x="y">bad</key><false/></dict>',
                  '<dict><key>x</key><plist version="1.0"><dict/></plist></dict>']
        cases.extend(self.xml(body) for body in bodies)
        cases.append('<?xml version="1.0" encoding="UTF-16"?><plist version="1.0"><dict/></plist>'.encode("utf-16"))
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises(ov.ValidationError):
                ov.parse_plist(raw)

    def test_parser_byte_depth_and_node_limits(self):
        cases = [b" " * (ov.MAX_PLIST_BYTES + 1),
                 self.xml('<dict><key>x</key>' + '<array>' * 60 + '</array>' * 60 + '</dict>'),
                 self.xml('<dict><key>x</key><array>' + '<false/>' * ov.MAX_XML_NODES + '</array></dict>')]
        for raw in cases:
            with self.assertRaises(ov.ValidationError):
                ov.parse_plist(raw)

    def test_numeric_and_string_bools_are_not_coerced_by_parser(self):
        parsed = ov.parse_plist(self.xml('<dict><key>n</key><integer>0</integer><key>b</key><false/><key>s</key><string>false</string></dict>'))
        self.assertIs(type(parsed["n"]), int)
        self.assertIs(type(parsed["b"]), bool)
        self.assertIs(type(parsed["s"]), str)


if __name__ == "__main__":
    unittest.main()
