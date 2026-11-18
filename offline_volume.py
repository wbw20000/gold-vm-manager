"""Pure, fail-closed attribution of the observed macOS 26.6.2 APFS capture.

This module never reads the filesystem, runs commands, mounts, unlocks, writes,
boots, or authorizes any of those actions. Inputs are raw XML plist bytes from
fresh successful captures in each entrypoint's explicit access/mount state.
The trusted caller must resolve and pin the exact new unpublished image's canonical path and file
identity, prove the installer exited and no ordinary boot occurred, hold the
exclusive lifecycle lock, and keep that identity/lock valid throughout capture.
Context flags are assertions by that caller, not proof this module can obtain.

Only the observed three-container layout is supported. Unknown fields, roles
and XML types fail closed. validate_readonly requires readonly media and all
volumes unmounted. validate_mounted_readonly is a separate Data-only follow-up
for the same continuously pinned readonly attachment, not authorization to
mount. validate_writable_unmounted requires its own explicit WritableContext,
a genuine readonly baseline, and a fresh complete writable-media capture with
all filesystems still unmounted; neither readonly result authorizes writes.
validate_mounted_writable separately checks the exact authorized Data mount
reports writable. It performs no write and grants no additional authorization.
A result is metadata evidence, NOT a capability or permission to perform I/O.
Device identifiers expire on detach. The captured GUID whole disk exposes no
DiskUUID; whole_disk_uuid is deliberately None, not a fabricated partition UUID.

Python 3.9+, standard library only. No private image paths or UUIDs are embedded.
"""

from dataclasses import dataclass
import posixpath
import re
from typing import Any, Dict, Mapping, Optional, Tuple
from xml.parsers import expat


SCHEMA = "macos-26.6.2"
MODE = "readonly_unmounted"
WRITABLE_MODE = "writable_unmounted"
MAX_PLIST_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 8 * MAX_PLIST_BYTES
MAX_DOCUMENTS = 64
MAX_XML_NODES = 20000
MAX_XML_DEPTH = 48

GUID = "GUID_partition_scheme"
CONTAINER_HINT = "EF57347C-0000-11AA-AA11-00306543ECAC"
VOLUME_HINT = "41504653-0000-11AA-AA11-00306543ECAC"
PARTITION_HINTS = {
    "Apple_APFS_ISC": "69646961-6700-11AA-AA11-00306543ECAC",
    "Apple_APFS": "7C3457EF-0000-11AA-AA11-00306543ECAC",
    "Apple_APFS_Recovery": "52637672-7900-11AA-AA11-00306543ECAC",
}
ROLE_LAYOUT = {
    "Apple_APFS_ISC": frozenset(("Preboot", "xART", "Hardware", "Recovery")),
    "Apple_APFS": frozenset(("System", "Preboot", "Recovery", "Update", "Data")),
    "Apple_APFS_Recovery": frozenset(("Recovery",)),
}
_DEVICE = re.compile(r"disk(?:0|[1-9][0-9]*)(?:s[1-9][0-9]*)?\Z")
_WHOLE = re.compile(r"disk(?:0|[1-9][0-9]*)\Z")
_UUID = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\Z")


class ValidationError(ValueError):
    """Unsupported, ambiguous, incomplete, or unsafe evidence (no side effects)."""


@dataclass(frozen=True)
class ValidationContext:
    image_path: str
    owner_uid: int
    image_is_new: bool
    unpublished: bool
    never_booted: bool
    lock_held: bool
    installer_exited: bool
    schema: str = SCHEMA
    mode: str = MODE


@dataclass(frozen=True)
class WritableContext:
    """Trusted caller's explicit authorization, scoped to the baseline Data UUID."""
    image_path: str
    owner_uid: int
    image_is_new: bool
    unpublished: bool
    never_booted: bool
    lock_held: bool
    installer_exited: bool
    write_authorized: bool
    schema: str = SCHEMA
    mode: str = WRITABLE_MODE


@dataclass(frozen=True)
class PartitionAttribution:
    device: str
    uuid: str
    content: str
    size: int


@dataclass(frozen=True)
class VolumeAttribution:
    device: str
    uuid: str
    role: str
    container_device: str
    container_uuid: str
    physical_store_device: str
    physical_store_uuid: str
    volume_group_uuid: Optional[str]


@dataclass(frozen=True)
class ContainerAttribution:
    device: str
    uuid: str
    physical_store: PartitionAttribution
    volumes: Tuple[VolumeAttribution, ...]


@dataclass(frozen=True)
class _DiskAttribution:
    """Neutral immutable identity graph; public result types are distinct siblings."""
    schema: str
    mode: str
    image_path: str
    owner_uid: int
    whole_device: str
    whole_disk_uuid: Optional[str]
    image_size_bytes: int
    partitions: Tuple[PartitionAttribution, ...]
    containers: Tuple[ContainerAttribution, ...]
    main_container_device: str
    main_container_uuid: str
    data_device: str
    data_uuid: str
    system_device: str
    system_uuid: str
    volume_group_uuid: str


@dataclass(frozen=True)
class OfflineAttribution(_DiskAttribution):
    """Complete readonly, unmounted capture; not authority for writes."""


@dataclass(frozen=True)
class WritableAttribution(_DiskAttribution):
    """Writable media, all filesystems unmounted; not a mounted-write capability.

    The explicitly authorized target is data_uuid only. This result never
    authorizes writes to System, auxiliary volumes, raw media or security state.
    """


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise ValidationError(message)


def parse_plist(raw: bytes) -> Dict[str, Any]:
    """Parse bounded observed XML types; reject duplicate keys before collapse.

    Apple's standard external DOCTYPE declaration is accepted but NEVER fetched.
    Internal subsets, custom entity declarations/references and other DTDs are
    rejected; normal XML escaping (e.g. &amp;) is supported. Binary plists, data,
    real, date, attributes outside plist version,
    mixed content and processing instructions are deliberately unsupported.
    """
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_PLIST_BYTES,
             "plist must be nonempty bounded bytes")
    parser = expat.ParserCreate("UTF-8")
    stack = []
    roots = []
    nodes = 0

    def start(name, attrs):
        nonlocal nodes
        nodes += 1
        _require(nodes <= MAX_XML_NODES and len(stack) < MAX_XML_DEPTH,
                 "plist complexity limit")
        _require(name in {"plist", "dict", "array", "key", "string", "integer", "true", "false"},
                 "unsupported plist XML type")
        _require(attrs == ({"version": "1.0"} if name == "plist" else {}),
                 "unsupported plist attributes")
        if name == "plist":
            _require(not stack and not roots, "nested plist")
        frame = [name, [], []]
        stack.append(frame)

    def text(value):
        if stack:
            stack[-1][2].append(value)
        else:
            _require(not value.strip(), "text outside plist")

    def end(name):
        frame = stack.pop()
        tag, children, chunks = frame
        value = "".join(chunks)
        _require(name == tag, "mismatched plist tag")
        if tag in {"plist", "dict", "array"}:
            _require(not value.strip(), "mixed plist content")
            if tag == "plist":
                _require(len(children) == 1 and children[0][0] == "dict",
                         "plist root must be one dictionary")
                value = children[0][1]
            elif tag == "array":
                _require(all(t != "key" for t, _ in children), "key in array")
                value = [v for _, v in children]
            else:
                _require(len(children) % 2 == 0, "unpaired dictionary key")
                value = {}
                for index in range(0, len(children), 2):
                    kt, key = children[index]
                    vt, item = children[index + 1]
                    _require(kt == "key" and vt != "key", "invalid dictionary pair")
                    _require(key not in value, "duplicate plist dictionary key")
                    value[key] = item
        else:
            _require(not children, "nested scalar")
            if tag in {"true", "false"}:
                _require(value == "", "nonempty boolean")
                value = tag == "true"
            elif tag == "integer":
                _require(re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", value) is not None,
                         "unsupported plist integer")
                value = int(value)
                _require(-(2 ** 63) <= value < 2 ** 63, "integer out of range")
        pair = (tag, value)
        if stack:
            stack[-1][1].append(pair)
        else:
            roots.append(pair)

    def doctype(name, system_id, public_id, internal):
        _require(name == "plist" and not internal
                 and system_id == "http://www.apple.com/DTDs/PropertyList-1.0.dtd"
                 and public_id == "-//Apple//DTD PLIST 1.0//EN", "unsupported DTD")

    def forbidden(*_):
        raise ValidationError("XML entities/external resources/instructions forbidden")

    def declaration(version, encoding, standalone):
        _require(version == "1.0" and encoding in (None, "UTF-8", "utf-8")
                 and standalone in (-1, 0, 1), "unsupported XML declaration")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.SkippedEntityHandler = forbidden
    parser.ProcessingInstructionHandler = forbidden
    parser.XmlDeclHandler = declaration
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(raw, True)
    except expat.ExpatError as exc:
        raise ValidationError("invalid XML plist") from exc
    _require(len(roots) == 1 and roots[0][0] == "plist", "missing plist root")
    return roots[0][1]


def _fields(kind, names):
    return {name: kind for name in names.split()}


def _record(value, required, optional=None):
    _require(type(value) is dict, "expected plist dictionary")
    fields = dict(required)
    fields.update(optional or {})
    _require(set(required) <= set(value), "missing required schema field")
    _require(set(value) <= set(fields), "unsupported schema field")
    for key, item in value.items():
        _require(type(item) is fields[key], "wrong type for " + key)
    return value


def _eq(value, expected, label):
    _require(type(value) is type(expected) and value == expected, "mismatch: " + label)


def _integer(value, label, minimum=0):
    _require(type(value) is int and minimum <= value < 2 ** 63,
             "invalid integer: " + label)
    return value


def _uuid(value):
    _require(type(value) is str and _UUID.fullmatch(value) is not None
             and value != "00000000-0000-0000-0000-000000000000", "invalid UUID")
    return value


def _device(value, whole=False):
    pattern = _WHOLE if whole else _DEVICE
    _require(type(value) is str and len(value) <= 32 and pattern.fullmatch(value) is not None,
             "invalid exact device identifier")
    return value


def _child(device, parent):
    _device(device)
    _require(re.fullmatch(re.escape(parent) + r"s[1-9][0-9]*", device) is not None,
             "device is not a direct child")


def _unique(items, label):
    _require(len(items) == len(set(items)), "duplicate " + label)


def _singleton(value, label):
    _require(type(value) is list and len(value) == 1, "expected single " + label)
    return value[0]


def _canonical_path(value):
    _require(type(value) is str and value.startswith("/") and not value.startswith("//")
             and len(value) <= 4096 and value != "/"
             and not any(ord(c) < 32 or ord(c) == 127 for c in value)
             and posixpath.normpath(value) == value, "noncanonical absolute image path")


def _context_state(context):
    _canonical_path(context.image_path)
    _integer(context.owner_uid, "owner uid")
    for field in ("image_is_new", "unpublished", "never_booted", "lock_held", "installer_exited"):
        _eq(getattr(context, field), True, "trusted context " + field)
    _eq(context.schema, SCHEMA, "schema")


def _context(context):
    _require(type(context) is ValidationContext, "explicit ValidationContext required")
    _context_state(context)
    _eq(context.mode, MODE, "readonly/unmounted mode")


def _writable_context(context):
    _require(type(context) is WritableContext, "explicit WritableContext required")
    _context_state(context)
    _eq(context.mode, WRITABLE_MODE, "writable/unmounted mode")
    _eq(context.write_authorized, True, "explicit Data write authorization")


_INFO_COMMON = {
    **_fields(str, "DeviceIdentifier DeviceNode ParentWholeDisk Content BusProtocol MountPoint"),
    **_fields(bool, "WholeDisk Internal OSInternalMedia Writable WritableMedia WritableVolume "
                   "RAIDMaster RAIDSlice SystemImage PartitionMapPartition"),
    **_fields(int, "Size TotalSize IOKitSize DeviceBlockSize VolumeSize"),
}
_INFO_METADATA = {
    **_fields(bool, "Bootable CanBeMadeBootable CanBeMadeBootableRequiresDestroy Ejectable "
                   "EjectableMediaAutomaticUnderSoftwareControl EjectableOnly GlobalPermissionsEnabled "
                   "LowLevelFormatSupported OS9DriversInstalled Removable RemovableMedia "
                   "RemovableMediaOrExternalDevice SupportsGlobalPermissionsDisable"),
    **_fields(str, "DeviceTreePath IORegistryEntryName MediaName MediaType SMARTStatus VolumeName"),
    **_fields(int, "FreeSpace"),
    "SMARTDeviceSpecificKeysMayVaryNotGuaranteed": dict,
}
_VOLUME_INFO = {
    **_INFO_COMMON,
    **_fields(str, "APFSContainerReference DiskUUID VolumeUUID FilesystemName FilesystemType Sealed"),
    **_fields(bool, "APFSSnapshot Encryption EncryptionThisVolumeProper FileVault Locked"),
    **_fields(int, "APFSContainerFree APFSContainerSize CapacityInUse"),
    "APFSPhysicalStores": list,
}
_VOLUME_METADATA = {
    **_INFO_METADATA,
    **_fields(str, "APFSVolumeGroupID BooterDeviceIdentifier RecoveryDeviceIdentifier FilesystemUserVisibleName"),
}


def _unmounted_info(info, whole, media_writable):
    # Observed writable *media* does not make an unmounted filesystem writable.
    for key in ("Writable", "WritableMedia"):
        _eq(info[key], media_writable, key)
    for key in ("WritableVolume", "Internal", "RAIDMaster", "RAIDSlice", "SystemImage", "PartitionMapPartition"):
        _eq(info[key], False, key)
    _eq(info["WholeDisk"], whole, "WholeDisk")
    _eq(info["MountPoint"], "", "unmounted")
    _eq(info["BusProtocol"], "Disk Image", "image protocol")
    _eq(info["DeviceNode"], "/dev/" + info["DeviceIdentifier"], "DeviceNode")
    _eq(info["VolumeSize"], 0, "unmounted VolumeSize")
    for key, item in info.items():
        if type(item) is int:
            _integer(item, key)
    if "SMARTDeviceSpecificKeysMayVaryNotGuaranteed" in info:
        _eq(info["SMARTDeviceSpecificKeysMayVaryNotGuaranteed"], {}, "unsupported SMART metadata")


def _entities(value, attach):
    _require(type(value) is list and 0 < len(value) <= 64, "invalid entity inventory")
    result = {}
    for item in value:
        required = _fields(str, "content-hint dev-entry")
        if attach:
            required.update({"potentially-mountable": bool, "unmapped-content-hint": str})
        _record(item, required, {"volume-kind": str} if attach else {})
        path = item["dev-entry"]
        _require(path.startswith("/dev/"), "noncanonical device node")
        device = _device(path[5:])
        _require(device not in result, "duplicate entity device")
        result[device] = item
    return result


def validate_readonly(
    context: ValidationContext, *, attach_plist: bytes, owned_image_plist: bytes,
    disk_list_plist: bytes, whole_info_plist: bytes,
    apfs_plists: Mapping[str, bytes], groups_plists: Mapping[str, bytes],
    volume_info_plists: Mapping[str, bytes],
) -> OfflineAttribution:
    """Attribute every readonly/unmounted volume or raise without I/O.

    Mapping keys are exact bare device identifiers (not paths or volume names).
    Each APFS/groups plist must contain exactly its one requested container.
    owned_image_plist is the single owned image dictionary, not a global hdiutil
    inventory; the trusted collector must also rule out competing attachments.
    No references to mutable input objects are retained in the frozen result.
    There is deliberately no writable-mode switch on this entrypoint.
    """
    _context(context)
    graph = _validate_unmounted(
        context, media_writable=False, attach_plist=attach_plist, owned_image_plist=owned_image_plist,
        disk_list_plist=disk_list_plist, whole_info_plist=whole_info_plist,
        apfs_plists=apfs_plists, groups_plists=groups_plists, volume_info_plists=volume_info_plists)
    return OfflineAttribution(**vars(graph))


def _validate_unmounted(
    context, *, media_writable, attach_plist, owned_image_plist, disk_list_plist,
    whole_info_plist, apfs_plists, groups_plists, volume_info_plists,
):
    """Shared structural validation; inspect actual access flags without rewriting inputs."""
    _require(type(media_writable) is bool, "explicit internal media mode required")
    for mapping in (apfs_plists, groups_plists, volume_info_plists):
        _require(isinstance(mapping, Mapping) and 0 < len(mapping) <= 32,
                 "bounded device-to-bytes mapping required")
        for device in mapping:
            _device(device)
    raws = [attach_plist, owned_image_plist, disk_list_plist, whole_info_plist]
    raws += list(apfs_plists.values()) + list(groups_plists.values()) + list(volume_info_plists.values())
    _require(len(raws) <= MAX_DOCUMENTS and all(type(raw) is bytes for raw in raws),
             "invalid capture bytes/count")
    _require(sum(len(raw) for raw in raws) <= MAX_CAPTURE_BYTES, "capture size limit")
    attach, owned, disks, whole_info = [parse_plist(raw) for raw in raws[:4]]
    apfs = {key: parse_plist(raw) for key, raw in apfs_plists.items()}
    groups = {key: parse_plist(raw) for key, raw in groups_plists.items()}
    infos = {key: parse_plist(raw) for key, raw in volume_info_plists.items()}
    _record(attach, {"system-entities": list})
    _record(owned, {
        **_fields(str, "image-path image-type"),
        **_fields(bool, "writeable autodiskmount image-encrypted"),
        **_fields(int, "owner-uid blockcount blocksize"), "system-entities": list,
    }, {**_fields(str, "icon-path"), **_fields(bool, "diskimages2 removable"),
        **_fields(int, "hdid-pid")})
    _canonical_path(owned["image-path"])
    _eq(owned["image-path"], context.image_path, "exact pinned image ownership")
    _eq(owned["owner-uid"], context.owner_uid, "image owner uid")
    _eq(owned["image-type"], "read/write", "raw image type, not attachment access")
    _eq(owned["writeable"], media_writable, "actual attachment access")
    for key in ("autodiskmount", "image-encrypted"):
        _eq(owned[key], False, key)
    image_size = _integer(owned["blockcount"], "blockcount", 1) * _integer(owned["blocksize"], "blocksize", 1)
    _integer(image_size, "image size", 1)
    if "hdid-pid" in owned:
        _integer(owned["hdid-pid"], "hdid-pid", 1)
    attached_entities = _entities(attach["system-entities"], True)
    owned_entities = _entities(owned["system-entities"], False)
    _eq(set(attached_entities), set(owned_entities), "owned/attached exact entity set")
    wholes = [device for device, item in attached_entities.items() if item["content-hint"] == GUID]
    _require(len(wholes) == 1, "one GUID whole disk required")
    whole = _device(wholes[0], whole=True)

    _record(disks, {"AllDisks": list, "AllDisksAndPartitions": list,
                    "VolumesFromDisks": list, "WholeDisks": list})
    _eq(disks["WholeDisks"], [whole], "disk list whole")
    _eq(disks["VolumesFromDisks"], [], "disk list unmounted")
    listing = _record(_singleton(disks["AllDisksAndPartitions"], "whole disk"),
                      {"Content": str, "DeviceIdentifier": str, "OSInternal": bool,
                       "Partitions": list, "Size": int})
    _eq(listing["Content"], GUID, "GUID disk list")
    _eq(listing["DeviceIdentifier"], whole, "disk list identity")
    _eq(listing["OSInternal"], False, "external image whole")
    _eq(listing["Size"], image_size, "whole disk size")
    partitions = {}
    for part in listing["Partitions"]:
        _record(part, {"Content": str, "DeviceIdentifier": str, "DiskUUID": str, "Size": int})
        device = _device(part["DeviceIdentifier"])
        _child(device, whole)
        _require(device not in partitions, "duplicate partition device")
        _require(part["Content"] in PARTITION_HINTS, "unsupported partition content")
        partitions[device] = PartitionAttribution(device, _uuid(part["DiskUUID"]), part["Content"],
                                                   _integer(part["Size"], "partition size", 1))
    _require(len(partitions) == 3 and {p.content for p in partitions.values()} == set(PARTITION_HINTS),
             "unsupported partition layout")
    _unique([p.uuid for p in partitions.values()], "partition UUID")
    _require(sum(p.size for p in partitions.values()) < image_size, "invalid partition capacities")
    _require(all(type(item) is str for item in disks["AllDisks"]), "invalid AllDisks")
    _unique(disks["AllDisks"], "AllDisks device")
    _eq(set(disks["AllDisks"]), {whole} | set(partitions), "exact disk list inventory")
    _record(whole_info, {**_INFO_COMMON, "VirtualOrPhysical": str}, _INFO_METADATA)
    _unmounted_info(whole_info, True, media_writable)
    for key in ("DeviceIdentifier", "ParentWholeDisk"):
        _eq(whole_info[key], whole, key)
    _eq(whole_info["Content"], GUID, "whole info content")
    _eq(whole_info["OSInternalMedia"], False, "whole internal media")
    _eq(whole_info["VirtualOrPhysical"], "Virtual", "virtual image")
    _eq(whole_info["DeviceBlockSize"], owned["blocksize"], "whole block size")
    for key in ("Size", "TotalSize", "IOKitSize"):
        _eq(whole_info[key], image_size, key)

    # Register each UUID once as an object identity; repeated cross-references
    # below must match. A group UUID is allowed to alias its own Data UUID.
    identity_uuids = {p.uuid for p in partitions.values()}
    expected_entities = {whole: (GUID, GUID, False)}
    expected_entities.update({p.device: (p.content, PARTITION_HINTS[p.content], False)
                              for p in partitions.values()})
    containers = {}
    volumes = {}
    used_stores = set()
    _eq(set(apfs), set(groups), "exact container/group captures")
    for container_device, raw_container in apfs.items():
        _device(container_device, whole=True)
        _require(container_device not in expected_entities, "duplicate whole/container device")
        _record(raw_container, {"Containers": list})
        container = _record(_singleton(raw_container["Containers"], "APFS container"), {
            **_fields(str, "APFSContainerUUID ContainerReference DesignatedPhysicalStore"),
            **_fields(int, "CapacityCeiling CapacityFree"), "PhysicalStores": list, "Volumes": list,
        })
        _eq(container["ContainerReference"], container_device, "container capture key")
        container_uuid = _uuid(container["APFSContainerUUID"])
        _require(container_uuid not in identity_uuids, "duplicate container UUID")
        identity_uuids.add(container_uuid)
        store = _record(_singleton(container["PhysicalStores"], "physical store"),
                        {"DeviceIdentifier": str, "DiskUUID": str, "Size": int})
        store_device = _device(store["DeviceIdentifier"])
        _require(store_device in partitions and store_device not in used_stores, "foreign/duplicate physical store")
        part = partitions[store_device]
        used_stores.add(store_device)
        _eq(container["DesignatedPhysicalStore"], store_device, "designated physical store")
        _eq(_uuid(store["DiskUUID"]), part.uuid, "partition/store UUID")
        _eq(store["Size"], part.size, "partition/store size")
        _eq(container["CapacityCeiling"], part.size, "container capacity")
        _require(_integer(container["CapacityFree"], "container free") <= part.size, "invalid free capacity")
        expected_entities[container_device] = (CONTAINER_HINT, CONTAINER_HINT, False)
        local_volumes = []
        roles = []
        for volume in container["Volumes"]:
            _record(volume, {
                **_fields(str, "APFSVolumeUUID DeviceIdentifier Name"),
                **_fields(int, "CapacityInUse CapacityQuota CapacityReserve"),
                **_fields(bool, "CryptoMigrationOn Encryption FileVault Locked"), "Roles": list,
            })
            volume_device = _device(volume["DeviceIdentifier"])
            _child(volume_device, container_device)
            _require(volume_device not in volumes and volume_device not in expected_entities,
                     "duplicate volume device")
            volume_uuid = _uuid(volume["APFSVolumeUUID"])
            _require(volume_uuid not in identity_uuids, "duplicate volume UUID")
            identity_uuids.add(volume_uuid)
            role = _singleton(volume["Roles"], "volume role")
            _require(type(role) is str and role in ROLE_LAYOUT[part.content], "unsupported volume role/location")
            for key in ("CryptoMigrationOn", "Encryption", "FileVault", "Locked"):
                _eq(volume[key], False, key)
            for key in ("CapacityInUse", "CapacityQuota", "CapacityReserve"):
                _require(_integer(volume[key], key) <= part.size, "volume capacity out of range")
            roles.append(role)
            volumes[volume_device] = (volume, container, part, role)
            local_volumes.append(volume_device)
            expected_entities[volume_device] = (VOLUME_HINT, VOLUME_HINT, True)
        _unique(roles, "role in container")
        _eq(set(roles), set(ROLE_LAYOUT[part.content]), "complete observed role layout")
        containers[container_device] = (container, part, local_volumes)
    _eq(used_stores, set(partitions), "complete physical store coverage")
    _eq(set(infos), set(volumes), "every captured volume info, no extras")
    _eq(set(expected_entities), set(attached_entities), "complete exact attachment inventory")
    for device, (hint, raw_hint, mountable) in expected_entities.items():
        item = attached_entities[device]
        _eq(item["content-hint"], hint, "attach content hint")
        _eq(item["unmapped-content-hint"], raw_hint, "attach unmapped hint")
        _eq(item["potentially-mountable"], mountable, "potentially-mountable")
        _eq(owned_entities[device]["content-hint"], raw_hint, "owned content hint")
        if mountable:
            _eq(item.get("volume-kind"), "apfs", "volume kind")
        else:
            _require("volume-kind" not in item, "volume kind on non-volume")

    group_members = {}
    main_container = None
    group_uuid = None
    for device, (container, part, local_volumes) in containers.items():
        raw_groups = _record(groups[device], {"Containers": list})
        group_container = _record(_singleton(raw_groups["Containers"], "group container"),
                                  {"APFSContainerUUID": str, "ContainerReference": str, "VolumeGroups": list})
        _eq(group_container["ContainerReference"], device, "group container device")
        _eq(_uuid(group_container["APFSContainerUUID"]), container["APFSContainerUUID"], "group container UUID")
        if part.content != "Apple_APFS":
            _eq(group_container["VolumeGroups"], [], "non-main container groups")
            continue
        main_container = device
        group = _record(_singleton(group_container["VolumeGroups"], "main volume group"),
                        {"APFSVolumeGroupUUID": str, "Volumes": list})
        group_uuid = _uuid(group["APFSVolumeGroupUUID"])
        _require(len(group["Volumes"]) == 2, "one System/Data pair required")
        for member in group["Volumes"]:
            _record(member, {"DeviceIdentifier": str, "DiskUUID": str, "NoBrowseRole": bool, "Role": str})
            member_device = _device(member["DeviceIdentifier"])
            _require(member_device in local_volumes and member_device not in group_members,
                     "foreign/duplicate group device")
            volume, _, _, role = volumes[member_device]
            _require(role in {"Data", "System"}, "unsupported group member role")
            _eq(member["Role"], role, "group member role")
            _eq(_uuid(member["DiskUUID"]), volume["APFSVolumeUUID"], "group volume UUID")
            _eq(member["NoBrowseRole"], False, "NoBrowseRole")
            group_members[member_device] = group_uuid
        _eq({volumes[dev][3] for dev in group_members}, {"Data", "System"}, "unique Data/System group")
    _require(main_container is not None and group_uuid is not None, "main group missing")
    data = next(dev for dev in group_members if volumes[dev][3] == "Data")
    system = next(dev for dev in group_members if volumes[dev][3] == "System")
    _require(group_uuid not in identity_uuids or group_uuid == volumes[data][0]["APFSVolumeUUID"],
             "group UUID aliases unrelated identity")

    attributed_volumes = {}
    for device, (volume, container, part, role) in volumes.items():
        info = _record(infos[device], _VOLUME_INFO, _VOLUME_METADATA)
        _unmounted_info(info, False, media_writable)
        _eq(info["DeviceIdentifier"], device, "volume info capture key")
        for key in ("APFSContainerReference", "ParentWholeDisk"):
            _eq(info[key], container["ContainerReference"], key)
        _eq(info["Content"], VOLUME_HINT, "APFS volume hint")
        _eq(info["FilesystemType"], "apfs", "APFS filesystem")
        _eq(info["FilesystemName"], "APFS", "APFS filesystem name")
        for key in ("DiskUUID", "VolumeUUID"):
            _eq(_uuid(info[key]), volume["APFSVolumeUUID"], key)
        for key in ("APFSSnapshot", "Encryption", "EncryptionThisVolumeProper", "FileVault", "Locked"):
            _eq(info[key], False, key)
        _eq(info["Sealed"], "Yes" if role == "System" else "No", "observed seal metadata")
        stores = _record(_singleton(info["APFSPhysicalStores"], "info physical store"), {"APFSPhysicalStore": str})
        _eq(stores["APFSPhysicalStore"], part.device, "volume physical store")
        for key in ("Size", "TotalSize", "IOKitSize", "APFSContainerSize"):
            _eq(info[key], part.size, key)
        _eq(info["APFSContainerFree"], container["CapacityFree"], "container free consistency")
        _eq(info["CapacityInUse"], volume["CapacityInUse"], "volume used consistency")
        _eq(info["DeviceBlockSize"], 4096, "observed APFS block size")
        if device in group_members:
            _eq(info.get("APFSVolumeGroupID"), group_uuid, "info volume group UUID")
        else:
            _require("APFSVolumeGroupID" not in info, "unexpected volume group membership")
        # These are identity references, never a reason to select by name.
        for key, expected_role in (("BooterDeviceIdentifier", "Preboot"), ("RecoveryDeviceIdentifier", "Recovery")):
            if key in info:
                target = info[key]
                _require(target in volumes and volumes[target][1] is container
                         and volumes[target][3] == expected_role, "foreign info device reference")
        attributed_volumes[device] = VolumeAttribution(
            device, volume["APFSVolumeUUID"], role, container["ContainerReference"],
            container["APFSContainerUUID"], part.device, part.uuid, group_members.get(device))
    attributed_containers = tuple(
        ContainerAttribution(device, container["APFSContainerUUID"], part,
                             tuple(attributed_volumes[dev] for dev in sorted(local)))
        for device, (container, part, local) in sorted(containers.items()))
    return _DiskAttribution(
        SCHEMA, WRITABLE_MODE if media_writable else MODE,
        context.image_path, context.owner_uid, whole, None, image_size,
        tuple(partitions[dev] for dev in sorted(partitions)), attributed_containers,
        main_container, containers[main_container][0]["APFSContainerUUID"],
        data, attributed_volumes[data].uuid, system, attributed_volumes[system].uuid, group_uuid)


@dataclass(frozen=True)
class _MountedDataAttribution:
    """Neutral Data mount identity metadata, not an executable I/O capability."""
    schema: str
    mode: str
    image_path: str
    whole_device: str
    main_container_device: str
    main_container_uuid: str
    data_device: str
    data_uuid: str
    volume_group_uuid: str
    physical_store_device: str
    physical_store_uuid: str
    mountpoint: str


@dataclass(frozen=True)
class MountedReadonlyAttribution(_MountedDataAttribution):
    """Readonly Data mount metadata; never a writable capability."""


@dataclass(frozen=True)
class MountedWritableAttribution(_MountedDataAttribution):
    """Explicitly authorized Data mount reports writable; no app/write success claim."""


_MOUNTED_DATA_INFO = {
    **_VOLUME_INFO,
    "APFSVolumeGroupID": str,
    "VolumeAllocationBlockSize": int,
    "GlobalPermissionsEnabled": bool,
}


def _attributed_data(attribution, *, expected_type=OfflineAttribution, expected_mode=MODE):
    """Check the prior result's selected identity graph, never derive it by name."""
    _require(type(attribution) is expected_type, "prior exact attribution type required")
    _eq(attribution.schema, SCHEMA, "prior schema")
    _eq(attribution.mode, expected_mode, "prior unmounted attribution mode")
    _canonical_path(attribution.image_path)
    _device(attribution.whole_device, whole=True)
    _integer(attribution.owner_uid, "prior owner uid")
    _integer(attribution.image_size_bytes, "prior image size", 1)
    _eq(attribution.whole_disk_uuid, None, "observed whole UUID absent")
    _require(type(attribution.containers) is tuple and type(attribution.partitions) is tuple
             and len(attribution.containers) == 3 and len(attribution.partitions) == 3
             and all(type(c) is ContainerAttribution for c in attribution.containers)
             and all(type(p) is PartitionAttribution for p in attribution.partitions),
             "immutable prior attribution graph required")
    candidates = [c for c in attribution.containers if c.device == attribution.main_container_device]
    _require(len(candidates) == 1, "one attributed main container required")
    container = candidates[0]
    _device(container.device, whole=True)
    _require(container.device != attribution.whole_device, "container/whole identity collision")
    _eq(_uuid(container.uuid), _uuid(attribution.main_container_uuid), "prior container UUID")
    part = container.physical_store
    _require(type(part) is PartitionAttribution and part in attribution.partitions,
             "prior main physical store missing")
    _eq(part.content, "Apple_APFS", "main physical store content")
    _child(part.device, attribution.whole_device)
    _uuid(part.uuid)
    _integer(part.size, "prior physical store size", 1)
    _require(part.size < attribution.image_size_bytes, "prior store size exceeds image")
    _require(type(container.volumes) is tuple and len(container.volumes) == 5
             and all(type(v) is VolumeAttribution for v in container.volumes), "immutable prior volumes required")
    _require(all(type(v.device) is str and type(v.uuid) is str and type(v.role) is str
                 for v in container.volumes), "invalid prior volume identity types")
    _unique([v.device for v in container.volumes], "prior volume device")
    _unique([v.uuid for v in container.volumes], "prior volume UUID")
    _unique([v.role for v in container.volumes], "prior main role")
    _eq({v.role for v in container.volumes}, set(ROLE_LAYOUT["Apple_APFS"]), "prior main role layout")
    by_role = {v.role: v for v in container.volumes}
    for volume in container.volumes:
        _child(volume.device, container.device)
        _uuid(volume.uuid)
        _eq(volume.container_device, container.device, "prior volume container")
        _eq(volume.container_uuid, container.uuid, "prior volume container UUID")
        _eq(volume.physical_store_device, part.device, "prior volume store")
        _eq(volume.physical_store_uuid, part.uuid, "prior volume store UUID")
        expected_group = attribution.volume_group_uuid if volume.role in {"Data", "System"} else None
        _eq(volume.volume_group_uuid, expected_group, "prior volume group")
    _uuid(attribution.volume_group_uuid)
    data, system = by_role["Data"], by_role["System"]
    for value, expected, label in ((attribution.data_device, data.device, "Data device"),
                                   (attribution.data_uuid, data.uuid, "Data UUID"),
                                   (attribution.system_device, system.device, "System device"),
                                   (attribution.system_uuid, system.uuid, "System UUID")):
        _eq(value, expected, "prior " + label)
    return container, part, by_role


def validate_mounted_readonly(
    attribution: OfflineAttribution, mountpoint: str, raw_data_info: bytes,
) -> MountedReadonlyAttribution:
    """Validate observed mounted Data info against a live readonly attribution.

    ``attribution`` must be the actual validate_readonly result for this same
    still-attached image, not a serialized/reconstructed result or one from a
    prior attachment. The trusted collector must continuously hold the lifecycle
    lock, pin image identity, recheck complete image ownership, prevent detach or
    another volume mount, and pin the caller-selected private mountpoint without
    symlink/ancestor replacement. Those are external preconditions, not facts
    inferable from a plist. This function performs no filesystem access.

    The observed mounted schema adds required VolumeAllocationBlockSize=4096;
    MountPoint must exactly equal the explicit canonical path. VolumeSize remains
    zero in this Apple output and is NOT used to infer mount success. All three
    Writable flags must still be actual false booleans. GlobalPermissionsEnabled
    is only typed metadata, not evidence that uid/permissions permit writes.

    Container and store UUIDs are absent in diskutil volume info: they remain
    bound to the prior attribution through its exact container/store identifiers
    and Data UUID, conditional on the collector's continuity checks above.
    """
    graph = _validate_mounted_data(attribution, mountpoint, raw_data_info, writable=False)
    return MountedReadonlyAttribution(**vars(graph))


def validate_mounted_writable(
    attribution: WritableAttribution, mountpoint: str, raw_data_info: bytes,
) -> MountedWritableAttribution:
    """Validate fresh Data-only writable mount metadata, never perform a write.

    Requires the actual validate_writable_unmounted result for this continuously
    attached image, obtained with explicit write_authorized=True for baseline
    Data only. A readonly result, reconstructed/stale result, different volume,
    different mountpoint, or readonly/mixed access flags cannot substitute.
    The caller must keep authorization and lifecycle lock valid, pin the image
    identity and private mountpoint, recheck complete image ownership, and ensure
    no detach/reattach or other-volume mount occurred. The plist alone cannot
    establish those facts or eliminate filesystem symlink/TOCTOU hazards.

    Observed Writable/WritableMedia/WritableVolume must all be actual true
    booleans. Identity, encryption/lock/snapshot checks remain unchanged. APFS
    journal/allocation activity may change free/used counts; these must remain
    within the fixed attributed container size, not equal old counts. The actual
    mounted schema still reports VolumeSize=0 and allocation block size 4096.

    Store/container UUIDs are inherited through the exact prior identity graph
    because mounted diskutil info does not report those UUIDs. Data DiskUUID,
    VolumeUUID and group UUID are independently checked against that graph.
    Success reports metadata only: no file was tested writable, no application
    was installed, and no System/security/raw-media mutation is authorized.
    """
    graph = _validate_mounted_data(attribution, mountpoint, raw_data_info, writable=True)
    return MountedWritableAttribution(**vars(graph))


def _validate_mounted_data(attribution, mountpoint, raw_data_info, *, writable):
    """Shared actual-schema checks with explicit access expectation; no raw rewriting."""
    _require(type(writable) is bool, "explicit internal mounted mode required")
    container, part, by_role = _attributed_data(
        attribution, expected_type=WritableAttribution if writable else OfflineAttribution,
        expected_mode=WRITABLE_MODE if writable else MODE)
    _persistent_identity(attribution)
    _canonical_path(mountpoint)
    _require(mountpoint != attribution.image_path, "mountpoint cannot be the image path")
    info = _record(parse_plist(raw_data_info), _MOUNTED_DATA_INFO, _VOLUME_METADATA)
    _eq(info["MountPoint"], mountpoint, "exact mounted Data path")
    _eq(info["DeviceIdentifier"], attribution.data_device, "mounted Data device")
    _eq(info["DeviceNode"], "/dev/" + attribution.data_device, "mounted Data node")
    for key in ("DiskUUID", "VolumeUUID"):
        _eq(_uuid(info[key]), attribution.data_uuid, "mounted " + key)
    _eq(_uuid(info["APFSVolumeGroupID"]), attribution.volume_group_uuid, "mounted Data group UUID")
    for key in ("APFSContainerReference", "ParentWholeDisk"):
        _eq(info[key], container.device, "mounted " + key)
    store = _record(_singleton(info["APFSPhysicalStores"], "mounted physical store"),
                    {"APFSPhysicalStore": str})
    _eq(store["APFSPhysicalStore"], part.device, "mounted physical store")
    for key in ("Writable", "WritableMedia", "WritableVolume"):
        _eq(info[key], writable, "mounted " + key)
    for key in ("WholeDisk", "Internal", "OSInternalMedia", "RAIDMaster", "RAIDSlice", "SystemImage", "PartitionMapPartition",
                "APFSSnapshot", "Encryption", "EncryptionThisVolumeProper", "FileVault", "Locked"):
        _eq(info[key], False, "mounted " + key)
    for key, expected in (("Content", VOLUME_HINT), ("FilesystemType", "apfs"), ("FilesystemName", "APFS"),
                          ("BusProtocol", "Disk Image"), ("Sealed", "No")):
        _eq(info[key], expected, "mounted " + key)
    for key in ("Size", "TotalSize", "IOKitSize", "APFSContainerSize"):
        _eq(info[key], part.size, "mounted " + key)
    for key in ("DeviceBlockSize", "VolumeAllocationBlockSize"):
        _eq(info[key], 4096, "mounted " + key)
    _eq(info["VolumeSize"], 0, "observed mounted VolumeSize")
    for key, value in info.items():
        if type(value) is int:
            _integer(value, "mounted " + key)
    for key in ("APFSContainerFree", "CapacityInUse"):
        _require(info[key] <= part.size, "mounted capacity out of range")
    if "SMARTDeviceSpecificKeysMayVaryNotGuaranteed" in info:
        _eq(info["SMARTDeviceSpecificKeysMayVaryNotGuaranteed"], {}, "unsupported mounted SMART metadata")
    for key, role in (("BooterDeviceIdentifier", "Preboot"), ("RecoveryDeviceIdentifier", "Recovery")):
        if key in info:
            _eq(info[key], by_role[role].device, "mounted " + key)
    return _MountedDataAttribution(
        SCHEMA, "writable_data_mounted" if writable else "readonly_data_mounted",
        attribution.image_path, attribution.whole_device,
        container.device, container.uuid, attribution.data_device, attribution.data_uuid,
        attribution.volume_group_uuid, part.device, part.uuid, mountpoint)


def _persistent_identity(graph):
    """Validate and compare UUID/role/store edges, independent of device numbering."""
    _require(type(graph.partitions) is tuple and len(graph.partitions) == 3
             and type(graph.containers) is tuple and len(graph.containers) == 3,
             "complete immutable identity graph required")
    _canonical_path(graph.image_path)
    _integer(graph.owner_uid, "identity owner uid")
    _integer(graph.image_size_bytes, "identity image size", 1)
    _eq(graph.whole_disk_uuid, None, "identity whole UUID absent")
    devices = [_device(graph.whole_device, whole=True)]
    uuids = []
    partition_rows = []
    for part in graph.partitions:
        _require(type(part) is PartitionAttribution, "invalid identity partition")
        _child(part.device, graph.whole_device)
        _uuid(part.uuid)
        _require(type(part.content) is str and part.content in PARTITION_HINTS, "invalid identity partition type")
        _integer(part.size, "identity partition size", 1)
        devices.append(part.device)
        uuids.append(part.uuid)
        partition_rows.append((part.uuid, part.content, part.size))
    _eq({part.content for part in graph.partitions}, set(PARTITION_HINTS), "identity partition layout")
    _require(sum(part.size for part in graph.partitions) < graph.image_size_bytes, "identity partition capacities")
    store_devices = []
    container_rows = []
    for container in graph.containers:
        _require(type(container) is ContainerAttribution, "invalid identity container")
        _device(container.device, whole=True)
        _uuid(container.uuid)
        devices.append(container.device)
        uuids.append(container.uuid)
        part = container.physical_store
        _require(type(part) is PartitionAttribution and part in graph.partitions, "identity store mismatch")
        store_devices.append(part.device)
        _require(type(container.volumes) is tuple and len(container.volumes) == len(ROLE_LAYOUT[part.content]),
                 "identity volume layout missing")
        volume_rows = []
        roles = []
        for volume in container.volumes:
            _require(type(volume) is VolumeAttribution, "invalid identity volume")
            _child(volume.device, container.device)
            _uuid(volume.uuid)
            _require(type(volume.role) is str and volume.role in ROLE_LAYOUT[part.content], "identity volume role")
            _eq(volume.container_device, container.device, "identity volume container")
            _eq(volume.container_uuid, container.uuid, "identity volume container UUID")
            _eq(volume.physical_store_device, part.device, "identity volume store")
            _eq(volume.physical_store_uuid, part.uuid, "identity volume store UUID")
            expected_group = graph.volume_group_uuid if volume.role in {"System", "Data"} else None
            _eq(volume.volume_group_uuid, expected_group, "identity group membership")
            devices.append(volume.device)
            uuids.append(volume.uuid)
            roles.append(volume.role)
            volume_rows.append((volume.uuid, volume.role, volume.volume_group_uuid or ""))
        _unique(roles, "identity role")
        _eq(set(roles), set(ROLE_LAYOUT[part.content]), "identity complete roles")
        container_rows.append((container.uuid, part.uuid, tuple(sorted(volume_rows))))
    _unique(devices, "identity device")
    _unique(uuids, "identity UUID")
    _unique(store_devices, "identity store")
    _eq(set(store_devices), {p.device for p in graph.partitions}, "identity store coverage")
    return (graph.image_path, graph.owner_uid, graph.image_size_bytes, graph.whole_disk_uuid,
            tuple(sorted(partition_rows)), tuple(sorted(container_rows)), graph.main_container_uuid,
            graph.data_uuid, graph.system_uuid, graph.volume_group_uuid)


def validate_writable_unmounted(
    context: WritableContext, readonly_baseline: OfflineAttribution, *,
    attach_plist: bytes, owned_image_plist: bytes, disk_list_plist: bytes, whole_info_plist: bytes,
    apfs_plists: Mapping[str, bytes], groups_plists: Mapping[str, bytes],
    volume_info_plists: Mapping[str, bytes],
) -> WritableAttribution:
    """Validate a fresh writable-media/nomount capture against a readonly baseline.

    This separate entrypoint requires explicit caller write authorization for
    the exact baseline Data UUID, plus every lifecycle gate. It does not accept
    ValidationContext, mounted evidence, a previous WritableAttribution as the
    baseline, or a flag to weaken validate_readonly. Both complete snapshots
    must originate from the caller's continuously pinned image identity; paths
    and UUIDs cannot detect a cloned/replaced file by themselves. The caller
    retains lock, file identity, freshness, and no-competing-attachment duties.

    The observed schema is writeable=true, Writable=true, WritableMedia=true,
    WritableVolume=false on the whole disk AND all ten volumes. MountPoint must
    be empty everywhere. This is media access evidence, NOT proof a filesystem
    is mounted/writable and NOT permission to alter System/security/raw media.
    Only a separately authorized and validated Data mount can precede installs.
    No commands, mount actions, or executable plans are returned.

    Device numbers may change after reattachment. Every partition/container/
    volume UUID, store relationship, role, group UUID, and image/partition size
    must match the readonly baseline. No input bytes or access flags are edited
    to manufacture readonly evidence.
    """
    _writable_context(context)
    _attributed_data(readonly_baseline)
    baseline_identity = _persistent_identity(readonly_baseline)
    _eq(context.image_path, readonly_baseline.image_path, "authorized baseline image path")
    _eq(context.owner_uid, readonly_baseline.owner_uid, "authorized baseline owner")
    graph = _validate_unmounted(
        context, media_writable=True, attach_plist=attach_plist, owned_image_plist=owned_image_plist,
        disk_list_plist=disk_list_plist, whole_info_plist=whole_info_plist,
        apfs_plists=apfs_plists, groups_plists=groups_plists, volume_info_plists=volume_info_plists)
    _eq(_persistent_identity(graph), baseline_identity, "all persistent baseline identities")
    return WritableAttribution(**vars(graph))
