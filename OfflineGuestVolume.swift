// Safety prerequisite only: never mounts, launches a process, reads a disk, or installs apps.
// Foundation-only, Swift 5, macOS 14+. A private macOS 26.6.2 capture now exists,
// but its different schema has NOT been integrated here: raw output is UNSUPPORTED.
// Synthetic-contract success is not runtime
// compatibility, authorization, an executable mount plan, or a preinstallation receipt.
import Foundation

enum OfflineGuestVolume {
    enum Origin { case unvalidatedSystemOutput, syntheticContractV1 }
    enum Reason: String, Error {
        case unsupportedRealOutputSchema, unsupportedSchema, malformedPlist
        case unsafeContext, invalidDeviceIdentifier, duplicateDevice, ambiguousAttachment
        case foreignPhysicalStore, ambiguousContainer, ambiguousData, invalidVolumeGroup
        case inconsistentVolume, encryptedOrLocked, writableAttachment, unexpectedMount
    }

    // These are explicit CALLER assertions, not checks performed by this pure module.
    // The caller must pin real paths/inodes/owners, hold the lifecycle lock, validate
    // authorization and free space, and ensure the helper has exited before execution.
    struct Context {
        let stageDirectory: String
        let imagePath: String
        let privateEmptyMountpoint: String
        let explicitlyAuthorizedNewDisposableVM: Bool
        let freshAndNeverBooted: Bool
        let installerExited: Bool
        let exclusiveLifecycleLockHeld: Bool
        let canonicalPathsAndOwnershipVerified: Bool
    }

    struct Input {
        let origin: Origin
        let context: Context
        let attachment: Data
        let restrictedDiskList: Data
        let restrictedContainers: [Data]
        let restrictedVolumeGroups: Data
        let dataVolumeInfo: Data
    }

    struct Invocation: Equatable {
        let executable: String
        let arguments: [String]
    }
    enum PlanScope {
        // Description only: after capture, raw output still returns unsupported.
        case initialReadOnlyAttachmentDescription
        // Synthetic devices MUST NOT be substituted into a live operation.
        case syntheticFixtureOnlyDoNotExecute
    }
    struct Plan {
        let scope: PlanScope
        let invocations: [Invocation]
        let requiresExternalAuthorizationAndLifecycleValidation = true
        let provesPreinstallation = false
    }
    struct FixtureAttribution {
        let wholeDevice: String
        let containerDevice: String
        let dataDevice: String
        let dataVolumeUUID: String
        let volumeGroupUUID: String
        let plan: Plan
        let isSyntheticOnly = true
    }
    enum Inspection {
        case unsupported(Reason)
        case rejected(Reason)
        case syntheticFixtureValidated(FixtureAttribution)
    }

    /// Describes only the first read-only attachment. Does not access the path or run it.
    static func initialProbeDescription(_ context: Context) throws -> Plan {
        try validateContext(context)
        return Plan(scope: .initialReadOnlyAttachmentDescription,
                    invocations: [attach(context)])
    }

    static func inspect(_ input: Input) -> Inspection {
        // Do not guess Apple output fields from our synthetic contract, even when
        // the raw bytes happen to match a fixture. No production opt-in exists.
        guard input.origin == .syntheticContractV1 else {
            return .unsupported(.unsupportedRealOutputSchema)
        }
        do { return .syntheticFixtureValidated(try inspectFixture(input)) }
        catch let reason as Reason {
            if reason == .unsupportedSchema { return .unsupported(reason) }
            return .rejected(reason)
        } catch { return .rejected(.malformedPlist) }
    }

    /// Post-mount verification logic for synthetic tests only. Never checks a live mount.
    static func verifyMountedFixture(_ attribution: FixtureAttribution,
                                     context: Context, info: Data) throws {
        try validateContext(context)
        guard attribution.plan.scope == .syntheticFixtureOnlyDoNotExecute else {
            throw Reason.unsupportedSchema
        }
        try validateInfo(try plist(info), dataDevice: try Device(attribution.dataDevice),
                         container: try Device(attribution.containerDevice),
                         volumeUUID: attribution.dataVolumeUUID,
                         groupUUID: attribution.volumeGroupUUID,
                         mountedAt: context.privateEmptyMountpoint)
    }

    // Exact structural identity, NOT startsWith("disk1") or volume-name selection.
    private struct Device: Hashable {
        let disk: UInt32
        let slice: UInt32?
        var identifier: String { "disk\(disk)" + (slice.map { "s\($0)" } ?? "") }
        var node: String { "/dev/" + identifier }
        var whole: Device { Device(disk: disk, slice: nil) }
        private init(disk: UInt32, slice: UInt32?) { self.disk = disk; self.slice = slice }
        init(_ text: String) throws {
            let s = text.hasPrefix("/dev/") ? String(text.dropFirst(5)) : text
            guard s.hasPrefix("disk") else { throw Reason.invalidDeviceIdentifier }
            let components = s.dropFirst(4).split(separator: "s", omittingEmptySubsequences: false)
            guard components.count == 1 || components.count == 2 else { throw Reason.invalidDeviceIdentifier }
            func number(_ value: Substring, zeroAllowed: Bool) throws -> UInt32 {
                guard !value.isEmpty, value.count <= 10,
                      value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                      let n = UInt32(value), String(n) == value,
                      zeroAllowed || n > 0 else { throw Reason.invalidDeviceIdentifier }
                return n
            }
            disk = try number(components[0], zeroAllowed: true)
            slice = components.count == 2 ? try number(components[1], zeroAllowed: false) : nil
            guard text == identifier || text == node else { throw Reason.invalidDeviceIdentifier }
        }
    }
    private struct Partition {
        let device: Device
        let content: String
        let container: Device
    }
    private struct Volume {
        let device: Device
        let uuid: String
        let role: String
        let group: String?
        let container: Device
    }

    private static func inspectFixture(_ input: Input) throws -> FixtureAttribution {
        try validateContext(input.context)
        let attachPlist = try plist(input.attachment)
        try keys(attachPlist, ["system-entities"])
        let entities = try dictionaries(attachPlist, "system-entities")
        guard !entities.isEmpty, entities.count <= 64 else { throw Reason.ambiguousAttachment }
        var attached: [Device: String] = [:]
        for e in entities {
            try keys(e, ["dev-entry", "content-hint"])
            let node = try string(e, "dev-entry")
            guard node.hasPrefix("/dev/") else { throw Reason.invalidDeviceIdentifier }
            let device = try Device(node)
            guard attached[device] == nil else { throw Reason.duplicateDevice }
            let hint = try string(e, "content-hint")
            guard ["GUID_partition_scheme", "Apple_APFS", "Apple_APFS_ISC", "Apple_APFS_Recovery"].contains(hint) else {
                throw Reason.unsupportedSchema
            }
            attached[device] = hint
        }
        let wholes = attached.filter { $0.value == "GUID_partition_scheme" }.map(\.key)
        guard wholes.count == 1, let whole = wholes.first, whole.slice == nil else {
            throw Reason.ambiguousAttachment
        }

        let diskList = try plist(input.restrictedDiskList)
        try keys(diskList, ["AllDisksAndPartitions"])
        let diskEntries = try dictionaries(diskList, "AllDisksAndPartitions")
        guard diskEntries.count == 1, let disk = diskEntries.first else { throw Reason.ambiguousAttachment }
        try keys(disk, ["DeviceIdentifier", "Content", "Partitions"])
        guard try Device(string(disk, "DeviceIdentifier")) == whole,
              try string(disk, "Content") == "GUID_partition_scheme" else { throw Reason.ambiguousAttachment }
        let partitionEntries = try dictionaries(disk, "Partitions")
        guard !partitionEntries.isEmpty, partitionEntries.count <= 16 else { throw Reason.ambiguousContainer }
        var partitions: [Device: Partition] = [:]
        var expectedContainers = Set<Device>()
        for p in partitionEntries {
            try keys(p, ["DeviceIdentifier", "Content", "APFSContainerReference"])
            let device = try Device(string(p, "DeviceIdentifier"))
            let content = try string(p, "Content")
            let container = try Device(string(p, "APFSContainerReference"))
            guard device.slice != nil, device.whole == whole,
                  attached[device] == content,
                  ["Apple_APFS", "Apple_APFS_ISC", "Apple_APFS_Recovery"].contains(content) else {
                throw Reason.foreignPhysicalStore
            }
            guard container.slice == nil, container != whole,
                  attached[container] == "Apple_APFS" else { throw Reason.ambiguousContainer }
            guard partitions[device] == nil, expectedContainers.insert(container).inserted else {
                throw Reason.duplicateDevice
            }
            partitions[device] = Partition(device: device, content: content, container: container)
        }
        let expectedAttached = Set([whole]).union(partitions.keys).union(expectedContainers)
        guard Set(attached.keys) == expectedAttached else { throw Reason.ambiguousAttachment }
        guard input.restrictedContainers.count == expectedContainers.count else { throw Reason.ambiguousContainer }

        var seenContainers = Set<Device>()
        var seenContainerUUIDs = Set<String>()
        var seenVolumeUUIDs = Set<String>()
        var volumes: [Device: Volume] = [:]
        for payload in input.restrictedContainers {
            let root = try plist(payload)
            try keys(root, ["Containers"])
            let entries = try dictionaries(root, "Containers")
            guard entries.count == 1, let c = entries.first else { throw Reason.ambiguousContainer }
            try keys(c, ["ContainerReference", "APFSContainerUUID", "PhysicalStores", "Volumes"])
            let container = try Device(string(c, "ContainerReference"))
            guard expectedContainers.contains(container), seenContainers.insert(container).inserted,
                  seenContainerUUIDs.insert(try uuid(c, "APFSContainerUUID")).inserted else {
                throw Reason.ambiguousContainer
            }
            let stores = try dictionaries(c, "PhysicalStores")
            // Multi-store/Fusion layouts are intentionally unsupported, not guessed.
            guard stores.count == 1, let store = stores.first else { throw Reason.foreignPhysicalStore }
            try keys(store, ["DeviceIdentifier"])
            let physical = try Device(string(store, "DeviceIdentifier"))
            guard let partition = partitions[physical], partition.container == container,
                  physical.whole == whole else { throw Reason.foreignPhysicalStore }
            let volumeEntries = try dictionaries(c, "Volumes")
            guard !volumeEntries.isEmpty, volumeEntries.count <= 32 else { throw Reason.unsupportedSchema }
            for v in volumeEntries {
                try keys(v, ["DeviceIdentifier", "APFSVolumeUUID", "Roles"], optional: ["APFSVolumeGroupUUID"])
                let device = try Device(string(v, "DeviceIdentifier"))
                guard device.slice != nil, device.whole == container, volumes[device] == nil else {
                    throw Reason.inconsistentVolume
                }
                let volumeUUID = try uuid(v, "APFSVolumeUUID")
                guard seenVolumeUUIDs.insert(volumeUUID).inserted else { throw Reason.inconsistentVolume }
                let roles = try strings(v, "Roles")
                guard roles.count == 1, let role = roles.first,
                      ["Data", "System", "Preboot", "Recovery", "VM", "Update", "Hardware", "xART", "iSCPreboot"].contains(role) else {
                    throw Reason.unsupportedSchema
                }
                let group = v["APFSVolumeGroupUUID"] != nil ? try uuid(v, "APFSVolumeGroupUUID") : nil
                guard (role == "Data" || role == "System") == (group != nil) else { throw Reason.invalidVolumeGroup }
                if role == "Data" || role == "System" {
                    guard partition.content == "Apple_APFS" else { throw Reason.inconsistentVolume }
                }
                volumes[device] = Volume(device: device, uuid: volumeUUID, role: role, group: group, container: container)
            }
        }
        guard seenContainers == expectedContainers else { throw Reason.ambiguousContainer }
        let dataVolumes = volumes.values.filter { $0.role == "Data" }
        guard dataVolumes.count == 1, let data = dataVolumes.first, let group = data.group else {
            throw Reason.ambiguousData
        }
        let systemVolumes = volumes.values.filter { $0.role == "System" }
        guard systemVolumes.count == 1, let system = systemVolumes.first,
              system.group == group, system.container == data.container else { throw Reason.invalidVolumeGroup }
        try validateGroups(try plist(input.restrictedVolumeGroups), data: data, system: system)
        try validateInfo(try plist(input.dataVolumeInfo), dataDevice: data.device,
                         container: data.container, volumeUUID: data.uuid,
                         groupUUID: group, mountedAt: nil)

        var commands = [attach(input.context), command("list", "-plist", whole.node)]
        for container in expectedContainers.sorted(by: { $0.identifier < $1.identifier }) {
            commands.append(command("apfs", "list", "-plist", container.node))
        }
        commands += [command("apfs", "listVolumeGroups", "-plist", data.container.node),
                     command("info", "-plist", data.device.node),
                     command("mount", "readOnly", "nobrowse", "-mountOptions", "nodev,nosuid,noexec",
                             "-mountPoint", input.context.privateEmptyMountpoint, data.device.node),
                     command("info", "-plist", data.device.node),
                     command("unmount", data.device.node),
                     Invocation(executable: "/usr/bin/hdiutil", arguments: ["detach", whole.node])]
        return FixtureAttribution(wholeDevice: whole.identifier, containerDevice: data.container.identifier,
                                  dataDevice: data.device.identifier, dataVolumeUUID: data.uuid,
                                  volumeGroupUUID: group,
                                  plan: Plan(scope: .syntheticFixtureOnlyDoNotExecute, invocations: commands))
    }

    private static func validateGroups(_ root: [String: Any], data: Volume, system: Volume) throws {
        try keys(root, ["Containers"])
        let containers = try dictionaries(root, "Containers")
        guard containers.count == 1, let c = containers.first else { throw Reason.invalidVolumeGroup }
        try keys(c, ["ContainerReference", "APFSVolumeGroups"])
        guard try Device(string(c, "ContainerReference")) == data.container else { throw Reason.invalidVolumeGroup }
        let groups = try dictionaries(c, "APFSVolumeGroups")
        guard groups.count == 1, let g = groups.first else { throw Reason.invalidVolumeGroup }
        try keys(g, ["APFSVolumeGroupUUID", "Volumes"])
        guard try uuid(g, "APFSVolumeGroupUUID") == data.group else { throw Reason.invalidVolumeGroup }
        let members = try dictionaries(g, "Volumes")
        guard members.count == 2 else { throw Reason.invalidVolumeGroup }
        let expected = [data.device: data, system.device: system]
        var seen = Set<Device>()
        for member in members {
            try keys(member, ["DeviceIdentifier", "APFSVolumeUUID", "Role"])
            let device = try Device(string(member, "DeviceIdentifier"))
            guard let volume = expected[device], seen.insert(device).inserted,
                  try uuid(member, "APFSVolumeUUID") == volume.uuid,
                  try string(member, "Role") == volume.role else { throw Reason.invalidVolumeGroup }
        }
        guard seen == Set(expected.keys) else { throw Reason.invalidVolumeGroup }
    }

    private static func validateInfo(_ info: [String: Any], dataDevice: Device, container: Device,
                                     volumeUUID: String, groupUUID: String, mountedAt: String?) throws {
        try keys(info, ["DeviceIdentifier", "DeviceNode", "APFSContainerReference", "APFSVolumeUUID",
                        "APFSVolumeGroupUUID", "APFSVolumeRole", "Whole", "ReadOnlyMedia", "ReadOnlyVolume",
                        "Encrypted", "Locked", "FileVault", "Mounted", "MountPoint"])
        guard try Device(string(info, "DeviceIdentifier")) == dataDevice,
              try string(info, "DeviceNode") == dataDevice.node,
              try Device(string(info, "APFSContainerReference")) == container,
              try uuid(info, "APFSVolumeUUID") == volumeUUID,
              try uuid(info, "APFSVolumeGroupUUID") == groupUUID,
              try string(info, "APFSVolumeRole") == "Data", try !boolean(info, "Whole") else {
            throw Reason.inconsistentVolume
        }
        guard try !boolean(info, "Encrypted"), try !boolean(info, "Locked"), try !boolean(info, "FileVault") else {
            throw Reason.encryptedOrLocked
        }
        guard try boolean(info, "ReadOnlyMedia"), try boolean(info, "ReadOnlyVolume") else { throw Reason.writableAttachment }
        guard try boolean(info, "Mounted") == (mountedAt != nil),
              try string(info, "MountPoint") == (mountedAt ?? "") else { throw Reason.unexpectedMount }
    }

    private static func validateContext(_ c: Context) throws {
        func canonicalLexicalPath(_ path: String) -> Bool {
            guard path.hasPrefix("/"), !path.hasSuffix("/"), !path.contains("//"),
                  !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return false }
            let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            return parts.count >= 2 && parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
        }
        guard c.explicitlyAuthorizedNewDisposableVM, c.freshAndNeverBooted, c.installerExited,
              c.exclusiveLifecycleLockHeld, c.canonicalPathsAndOwnershipVerified,
              canonicalLexicalPath(c.stageDirectory), canonicalLexicalPath(c.imagePath),
              canonicalLexicalPath(c.privateEmptyMountpoint),
              c.imagePath == c.stageDirectory + "/disk.img",
              c.privateEmptyMountpoint == c.stageDirectory + "/probe-mount" else { throw Reason.unsafeContext }
    }
    private static func attach(_ c: Context) -> Invocation {
        Invocation(executable: "/usr/bin/hdiutil",
                   arguments: ["attach", "-readonly", "-nomount", "-nobrowse", "-noautoopen", "-imagekey",
                               "diskimage-class=CRawDiskImage", "-plist", c.imagePath])
    }
    private static func command(_ arguments: String...) -> Invocation {
        Invocation(executable: "/usr/sbin/diskutil", arguments: arguments)
    }
    private static func keys(_ object: [String: Any], _ required: Set<String>, optional: Set<String> = []) throws {
        let actual = Set(object.keys)
        guard required.isSubset(of: actual), actual.isSubset(of: required.union(optional)) else { throw Reason.unsupportedSchema }
    }
    private static func string(_ object: [String: Any], _ key: String) throws -> String {
        guard let value = object[key] as? String,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw Reason.unsupportedSchema }
        return value
    }
    private static func uuid(_ object: [String: Any], _ key: String) throws -> String {
        let value = try string(object, key)
        guard let parsed = UUID(uuidString: value), parsed.uuidString == value.uppercased(), value.count == 36 else {
            throw Reason.unsupportedSchema
        }
        return parsed.uuidString
    }
    private static func boolean(_ object: [String: Any], _ key: String) throws -> Bool {
        // The XML validator admits <true/>/<false/> but no numeric elements, so an
        // integer 0/1 cannot be silently bridged into a security decision.
        guard let value = object[key] as? NSNumber, String(cString: value.objCType) == "c" else { throw Reason.unsupportedSchema }
        return value.boolValue
    }
    private static func strings(_ object: [String: Any], _ key: String) throws -> [String] {
        guard let value = object[key] as? [String] else { throw Reason.unsupportedSchema }
        return value
    }
    private static func dictionaries(_ object: [String: Any], _ key: String) throws -> [[String: Any]] {
        guard let value = object[key] as? [[String: Any]] else { throw Reason.unsupportedSchema }
        return value
    }

    private static func plist(_ bytes: Data) throws -> [String: Any] {
        guard !bytes.isEmpty, bytes.count <= 262_144,
              let text = String(data: bytes, encoding: .utf8),
              !text.contains("<!ENTITY"), !text.hasPrefix("bplist") else { throw Reason.malformedPlist }
        // Synthetic V1 is XML only. Check duplicate dictionary keys BEFORE
        // PropertyListSerialization can silently collapse an ambiguous dictionary.
        let validator = FixtureXMLValidator()
        let parser = XMLParser(data: bytes)
        parser.shouldResolveExternalEntities = false
        parser.delegate = validator
        guard parser.parse(), validator.valid else { throw Reason.malformedPlist }
        do {
            guard let root = try PropertyListSerialization.propertyList(from: bytes, options: [], format: nil) as? [String: Any] else {
                throw Reason.unsupportedSchema
            }
            return root
        } catch let reason as Reason { throw reason }
        catch { throw Reason.malformedPlist }
    }

    private final class FixtureXMLValidator: NSObject, XMLParserDelegate {
        var valid = true
        private var stack: [String] = []
        private var dictionaryKeys: [Set<String>] = []
        private var currentKey = ""
        private var nodeCount = 0
        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                    qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
            nodeCount += 1
            guard nodeCount <= 4096, stack.count < 64,
                  ["plist", "dict", "array", "key", "string", "true", "false"].contains(elementName),
                  elementName == "plist" ? attributeDict == ["version": "1.0"] : attributeDict.isEmpty else {
                valid = false; parser.abortParsing(); return
            }
            if elementName == "key" {
                guard stack.last == "dict" else { valid = false; parser.abortParsing(); return }
                currentKey = ""
            }
            if elementName == "dict" { dictionaryKeys.append([]) }
            stack.append(elementName)
        }
        func parser(_ parser: XMLParser, foundCharacters string: String) {
            if stack.last == "key" { currentKey += string }
        }
        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
            guard stack.last == elementName else { valid = false; parser.abortParsing(); return }
            if elementName == "key" {
                guard !dictionaryKeys.isEmpty, dictionaryKeys[dictionaryKeys.count - 1].insert(currentKey).inserted else {
                    valid = false; parser.abortParsing(); return
                }
            }
            if elementName == "dict" { dictionaryKeys.removeLast() }
            stack.removeLast()
        }
    }
}
