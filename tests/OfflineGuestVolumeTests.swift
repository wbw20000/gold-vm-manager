// ALL fixtures below are SYNTHETIC CONTRACT DATA, not captured Apple command output.
// These tests perform no Process/FileManager/disk/VM/network operations. The printed
// result establishes parser behavior only; raw system output remains unsupported.
import Foundation

@main
struct OfflineGuestVolumeTests {
    typealias Module = OfflineGuestVolume
    private static var checks = 0
    private enum TestFailure: Error { case failed(String) }
    private static func expect(_ condition: @autoclosure () -> Bool, _ name: String) throws {
        checks += 1
        if !condition() { throw TestFailure.failed(name) }
    }
    private static func xml(_ object: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
    }
    private static func context(authorized: Bool = true, fresh: Bool = true, exited: Bool = true,
                                locked: Bool = true, paths: Bool = true,
                                stage: String = "/private/synthetic/new-vm",
                                image: String = "/private/synthetic/new-vm/disk.img",
                                mount: String = "/private/synthetic/new-vm/probe-mount") -> Module.Context {
        Module.Context(stageDirectory: stage, imagePath: image, privateEmptyMountpoint: mount,
                       explicitlyAuthorizedNewDisposableVM: authorized, freshAndNeverBooted: fresh,
                       installerExited: exited, exclusiveLifecycleLockHeld: locked,
                       canonicalPathsAndOwnershipVerified: paths)
    }

    private struct Fixture {
        let group = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        let systemUUID = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"
        let dataUUID = "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC"
        var attachmentEntities: [[String: Any]] = [
            ["dev-entry": "/dev/disk40", "content-hint": "GUID_partition_scheme"],
            ["dev-entry": "/dev/disk40s2", "content-hint": "Apple_APFS"],
            ["dev-entry": "/dev/disk41", "content-hint": "Apple_APFS"]
        ]
        var partitions: [[String: Any]] = [
            ["DeviceIdentifier": "disk40s2", "Content": "Apple_APFS", "APFSContainerReference": "disk41"]
        ]
        var physicalStores: [[String: Any]] = [["DeviceIdentifier": "disk40s2"]]
        var volumes: [[String: Any]]
        var groupMembers: [[String: Any]]
        var info: [String: Any]
        var containerReference = "disk41"
        var groupContainerReference = "disk41"
        var groupUUID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        var attachmentOverride: Data?
        var diskListOverride: Data?
        var groupsOverride: Data?
        var extraContainers: [Data] = []
        init() {
            volumes = [
                ["DeviceIdentifier": "disk41s1", "APFSVolumeUUID": systemUUID, "Roles": ["System"], "APFSVolumeGroupUUID": group],
                ["DeviceIdentifier": "disk41s5", "APFSVolumeUUID": dataUUID, "Roles": ["Data"], "APFSVolumeGroupUUID": group]
            ]
            groupMembers = [
                ["DeviceIdentifier": "disk41s1", "APFSVolumeUUID": systemUUID, "Role": "System"],
                ["DeviceIdentifier": "disk41s5", "APFSVolumeUUID": dataUUID, "Role": "Data"]
            ]
            info = ["DeviceIdentifier": "disk41s5", "DeviceNode": "/dev/disk41s5",
                    "APFSContainerReference": "disk41", "APFSVolumeUUID": dataUUID,
                    "APFSVolumeGroupUUID": group, "APFSVolumeRole": "Data", "Whole": false,
                    "ReadOnlyMedia": true, "ReadOnlyVolume": true, "Encrypted": false,
                    "Locked": false, "FileVault": false, "Mounted": false, "MountPoint": ""]
        }
        func containerDocument() throws -> Data {
            try xml(["Containers": [["ContainerReference": containerReference,
                                      "APFSContainerUUID": "DDDDDDDD-DDDD-4DDD-8DDD-DDDDDDDDDDDD",
                                      "PhysicalStores": physicalStores, "Volumes": volumes]]])
        }
        func input(origin: Module.Origin = .syntheticContractV1,
                   c: Module.Context = context()) throws -> Module.Input {
            try Module.Input(origin: origin, context: c,
                             attachment: attachmentOverride ?? xml(["system-entities": attachmentEntities]),
                             restrictedDiskList: diskListOverride ?? xml(["AllDisksAndPartitions": [
                                ["DeviceIdentifier": "disk40", "Content": "GUID_partition_scheme", "Partitions": partitions]
                             ]]),
                             restrictedContainers: [containerDocument()] + extraContainers,
                             restrictedVolumeGroups: groupsOverride ?? xml(["Containers": [
                                ["ContainerReference": groupContainerReference, "APFSVolumeGroups": [
                                    ["APFSVolumeGroupUUID": groupUUID, "Volumes": groupMembers]
                                ]]
                             ]]),
                             dataVolumeInfo: xml(info))
        }
    }

    private static func failure(_ name: String, _ reason: Module.Reason,
                                _ change: (inout Fixture) throws -> Void) throws {
        var fixture = Fixture()
        try change(&fixture)
        switch Module.inspect(try fixture.input()) {
        case .rejected(let actual), .unsupported(let actual): try expect(actual == reason, name)
        case .syntheticFixtureValidated: try expect(false, name)
        }
    }
    private static func fixtureSuccess(_ fixture: Fixture = Fixture()) throws -> Module.FixtureAttribution {
        switch Module.inspect(try fixture.input()) {
        case .syntheticFixtureValidated(let value): return value
        case .rejected(let reason), .unsupported(let reason): throw TestFailure.failed("base synthetic fixture: \(reason.rawValue)")
        }
    }

    static func main() throws {
        let success = try fixtureSuccess()
        var threeContainers = Fixture()
        for (partition, container, role, containerUUID, volumeUUID) in [
            ("disk40s1", "disk42", "iSCPreboot", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"),
            ("disk40s3", "disk43", "Recovery", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444")
        ] {
            let content = role == "Recovery" ? "Apple_APFS_Recovery" : "Apple_APFS_ISC"
            threeContainers.attachmentEntities += [["dev-entry": "/dev/" + partition, "content-hint": content],
                                                   ["dev-entry": "/dev/" + container, "content-hint": "Apple_APFS"]]
            threeContainers.partitions.append(["DeviceIdentifier": partition, "Content": content, "APFSContainerReference": container])
            threeContainers.extraContainers.append(try xml(["Containers": [[
                "ContainerReference": container, "APFSContainerUUID": containerUUID,
                "PhysicalStores": [["DeviceIdentifier": partition]],
                "Volumes": [["DeviceIdentifier": container + "s1", "APFSVolumeUUID": volumeUUID, "Roles": [role]]]
            ]]]))
        }
        let multiple = try fixtureSuccess(threeContainers)
        try expect(multiple.dataDevice == "disk41s5", "Data role attribution across three synthetic containers")
        try expect(multiple.plan.invocations.filter { $0.arguments.prefix(2) == ["apfs", "list"] }.count == 3, "restricted container inventories only")
        var reordered = threeContainers
        reordered.attachmentEntities.reverse()
        reordered.partitions.reverse()
        reordered.extraContainers.reverse()
        let reorderedResult = try fixtureSuccess(reordered)
        try expect(reorderedResult.dataDevice == multiple.dataDevice, "no positional volume inference")
        try expect(success.wholeDevice == "disk40" && success.containerDevice == "disk41" && success.dataDevice == "disk41s5", "exact attribution")
        try expect(success.isSyntheticOnly && !success.plan.provesPreinstallation, "not proof of installation")
        try expect(success.plan.scope == .syntheticFixtureOnlyDoNotExecute, "synthetic plan not executable")
        try expect(success.plan.requiresExternalAuthorizationAndLifecycleValidation, "caller gates remain")
        let initial = try Module.initialProbeDescription(context())
        try expect(initial.invocations.count == 1 && initial.scope == .initialReadOnlyAttachmentDescription, "only initial attach description")
        try expect(initial.invocations[0].arguments.contains("-readonly") && initial.invocations[0].arguments.contains("-nomount"), "read only no automount")
        let mount = success.plan.invocations.filter { $0.arguments.first == "mount" }
        try expect(mount.count == 1 && mount[0].arguments == ["mount", "readOnly", "nobrowse", "-mountOptions", "nodev,nosuid,noexec", "-mountPoint", context().privateEmptyMountpoint, "/dev/disk41s5"], "exact readonly mount description")
        let forbidden = ["unlockVolume", "decryptVolume", "deleteVolume", "eraseDisk", "-force", "force", "enableOwnership", "repairVolume"]
        try expect(success.plan.invocations.allSatisfy { !($0.arguments.contains { forbidden.contains($0) }) }, "no unlock write delete repair force")
        try expect(success.plan.invocations.allSatisfy { ["/usr/bin/hdiutil", "/usr/sbin/diskutil"].contains($0.executable) }, "absolute allowlisted executables")
        try expect(success.plan.invocations.last?.arguments == ["detach", "/dev/disk40"], "exact detach description")

        switch Module.inspect(try Fixture().input(origin: .unvalidatedSystemOutput)) {
        case .unsupported(.unsupportedRealOutputSchema): try expect(true, "real output always unsupported")
        default: try expect(false, "must not promote synthetic schema to production")
        }
        for badContext in [context(authorized: false), context(fresh: false), context(exited: false),
                           context(locked: false), context(paths: false),
                           context(stage: "/private/synthetic/../new-vm"),
                           context(image: "/dev/disk0"), context(mount: "/Applications"),
                           context(stage: "/private//new-vm"),
                           context(stage: "/private/synthetic/new-vm\n") ] {
            switch Module.inspect(try Fixture().input(c: badContext)) {
            case .rejected(.unsafeContext): try expect(true, "unsafe context")
            default: try expect(false, "context bypass")
            }
        }

        try failure("unknown top-level key", .unsupportedSchema) { f in
            f.attachmentOverride = try xml(["system-entities": f.attachmentEntities, "UnknownFutureField": true])
        }
        try failure("duplicate attach device", .duplicateDevice) { f in f.attachmentEntities.append(f.attachmentEntities[1]) }
        try failure("second partition map", .ambiguousAttachment) { f in
            f.attachmentEntities.append(["dev-entry": "/dev/disk400", "content-hint": "GUID_partition_scheme"])
        }
        try failure("extra unowned attachment", .ambiguousAttachment) { f in
            f.attachmentEntities.append(["dev-entry": "/dev/disk99", "content-hint": "Apple_APFS"])
        }
        for badDevice in ["disk040", "disk40s0", "disk40s2s1", "/dev/rdisk40", "/dev/disk40/../disk0", "disk-40", "disk٤٠", "disk4294967296"] {
            try failure("invalid device grammar", .invalidDeviceIdentifier) { f in f.attachmentEntities[0]["dev-entry"] = badDevice }
        }
        try failure("weak prefix cannot attribute store", .foreignPhysicalStore) { f in f.physicalStores[0]["DeviceIdentifier"] = "disk400s2" }
        try failure("different sibling partition", .foreignPhysicalStore) { f in f.physicalStores[0]["DeviceIdentifier"] = "disk40s3" }
        try failure("multi-store unsupported", .foreignPhysicalStore) { f in f.physicalStores.append(["DeviceIdentifier": "disk99s1"]) }
        try failure("unattached container", .ambiguousContainer) { f in f.containerReference = "disk410" }
        try failure("container capture count mismatch", .ambiguousContainer) { f in f.extraContainers.append(try f.containerDocument()) }
        try failure("foreign volume disk number", .inconsistentVolume) { f in f.volumes[1]["DeviceIdentifier"] = "disk410s5" }
        try failure("duplicate volume uuid", .inconsistentVolume) { f in f.volumes[1]["APFSVolumeUUID"] = f.systemUUID }
        try failure("no Data role", .invalidVolumeGroup) { f in f.volumes[1]["Roles"] = ["VM"] }
        try failure("two Data roles", .ambiguousData) { f in f.volumes[0]["Roles"] = ["Data"] }
        try failure("mixed roles unsupported", .unsupportedSchema) { f in f.volumes[1]["Roles"] = ["Data", "System"] }
        try failure("role absent cannot use name", .unsupportedSchema) { f in
            f.volumes[1].removeValue(forKey: "Roles"); f.volumes[1]["VolumeName"] = "Data"
        }
        try failure("missing group", .invalidVolumeGroup) { f in f.volumes[1].removeValue(forKey: "APFSVolumeGroupUUID") }
        try failure("different System group", .invalidVolumeGroup) { f in f.volumes[0]["APFSVolumeGroupUUID"] = "EEEEEEEE-EEEE-4EEE-8EEE-EEEEEEEEEEEE" }
        try failure("different group container", .invalidVolumeGroup) { f in f.groupContainerReference = "disk99" }
        try failure("duplicate group member", .invalidVolumeGroup) { f in f.groupMembers[1] = f.groupMembers[0] }
        try failure("group uuid mismatch", .invalidVolumeGroup) { f in f.groupUUID = "EEEEEEEE-EEEE-4EEE-8EEE-EEEEEEEEEEEE" }
        try failure("foreign group volume", .invalidVolumeGroup) { f in f.groupMembers[1]["DeviceIdentifier"] = "disk99s5" }
        try failure("wrong group role", .invalidVolumeGroup) { f in f.groupMembers[1]["Role"] = "System" }
        try failure("wrong info device", .inconsistentVolume) { f in f.info["DeviceIdentifier"] = "disk99s5" }
        try failure("wrong info node", .inconsistentVolume) { f in f.info["DeviceNode"] = "/dev/disk41s1" }
        try failure("wrong info group", .inconsistentVolume) { f in f.info["APFSVolumeGroupUUID"] = "EEEEEEEE-EEEE-4EEE-8EEE-EEEEEEEEEEEE" }
        for flag in ["Encrypted", "Locked", "FileVault"] {
            try failure("explicit encryption or lock", .encryptedOrLocked) { f in f.info[flag] = true }
            try failure("missing encryption state", .unsupportedSchema) { f in f.info.removeValue(forKey: flag) }
        }
        for flag in ["ReadOnlyMedia", "ReadOnlyVolume"] {
            try failure("writable layer", .writableAttachment) { f in f.info[flag] = false }
        }
        try failure("preexisting mounted volume", .unexpectedMount) { f in f.info["Mounted"] = true; f.info["MountPoint"] = "/Volumes/Data" }
        try failure("string false is not boolean", .unsupportedSchema) { f in f.info["Encrypted"] = "false" }
        try failure("integer false is not boolean", .malformedPlist) { f in f.info["Encrypted"] = 0 }
        try failure("unknown info schema", .unsupportedSchema) { f in f.info["NewSecurityStatus"] = "unknown" }
        try failure("invalid uuid", .unsupportedSchema) { f in f.volumes[1]["APFSVolumeUUID"] = "not-a-uuid" }
        try failure("malformed xml", .malformedPlist) { f in f.attachmentOverride = Data("<plist>".utf8) }
        try failure("oversize xml", .malformedPlist) { f in f.attachmentOverride = Data(repeating: 32, count: 262_145) }
        try failure("duplicate XML key", .malformedPlist) { f in
            f.attachmentOverride = Data("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>system-entities</key><array/><key>system-entities</key><array/></dict></plist>".utf8)
        }
        try failure("entity declarations disallowed", .malformedPlist) { f in
            f.attachmentOverride = Data("<?xml version=\"1.0\"?><!DOCTYPE plist [<!ENTITY x 'system-entities'>]><plist version=\"1.0\"><dict><key>&x;</key><array/></dict></plist>".utf8)
        }
        try failure("binary synthetic schema unsupported", .malformedPlist) { f in
            f.attachmentOverride = try PropertyListSerialization.data(fromPropertyList: ["system-entities": f.attachmentEntities], format: .binary, options: 0)
        }

        var mountedInfo = Fixture().info
        mountedInfo["Mounted"] = true
        mountedInfo["MountPoint"] = context().privateEmptyMountpoint
        try Module.verifyMountedFixture(success, context: context(), info: xml(mountedInfo))
        try expect(true, "postmount identity readonly fixture")
        mountedInfo["ReadOnlyVolume"] = false
        do {
            try Module.verifyMountedFixture(success, context: context(), info: xml(mountedInfo))
            try expect(false, "postmount readonly mandatory")
        } catch Module.Reason.writableAttachment { try expect(true, "postmount readonly mandatory") }
        mountedInfo["ReadOnlyVolume"] = true
        mountedInfo["MountPoint"] = "/Volumes/Data"
        do {
            try Module.verifyMountedFixture(success, context: context(), info: xml(mountedInfo))
            try expect(false, "postmount exact private mountpoint")
        } catch Module.Reason.unexpectedMount { try expect(true, "postmount exact private mountpoint") }
        print("PASS: \(checks) synthetic-contract checks; no commands executed; real output unsupported; preinstallation NOT verified.")
    }
}
