import Foundation
import Darwin
import CryptoKit

// Production is a one-shot ROOT-ONLY metadata operation. The fixture flag removes
// all native discovery and all chown operations; never deploy that build.
enum GuestOwnership {
    #if GOLD_OWNERSHIP_FIXTURE
    static let buildContract = "GOLD_OWNERSHIP_FIXTURE_SIMULATION_ONLY_V2"
    #else
    static let buildContract = "GOLD_OWNERSHIP_PRODUCTION_ROOT_ONLY_V2"
    #endif
    static let apps = ["CCBaga-A.app", "CCBaga-B.app", "Clash Verge.app", "Claude.app"]
    static let base = "Library/Application Support/GoldVMManager"
    static let agent = "Library/LaunchAgents/org.goldvmmanager.first-login.plist"
    static let maxTicket = 64 * 1024 * 1024
    static let maxEntries = 200_000
    static let maxTree: Int64 = 16 * 1024 * 1024 * 1024
    // Stable numeric ABI. Shared POSIX/decoding helpers reject without recording
    // paths or errno; only the semantic caller assigns their category. A nested
    // specific failure (e.g. ACL) always survives its enclosing validation.
    enum Failure: Int32, Error {
        case rejected = 2
        case invocation = 20, ticket = 21, parentLock = 22, stageState = 23
        case disk = 24, paths = 25, bundles = 26, entry = 27, ownership = 28
        case acl = 29, content = 30, receipt = 31, mutation = 32

        func checking<T>(_ body: () throws -> T) throws -> T {
            do { return try body() } catch Failure.rejected { throw self }
        }
    }
    static func need(_ value: Bool, _ failure: Failure = .rejected) throws { if !value { throw failure } }

    struct Identity: Codable, Equatable {
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let mode: UInt32
        let uid: UInt32
        let gid: UInt32
        let sha256: String?
    }
    struct Entry: Codable {
        let path: String
        let kind: String
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let mode: UInt32
        let observed_uid: UInt32
        let observed_gid: UInt32
        let ctime_ns: Int64
        let sha256: String
        let link_target: String
    }
    struct Ticket: Decodable {
        let schema: Int
        let operation_id: String
        let job_id: String
        let name: String
        let state_dir: String
        let tart_home: String
        let caller_pid: Int32
        let image: Identity
        let metadata: [String: Identity]
        let data_uuid: String
        let group_uuid: String
        let apply_mount: String
        let verify_mount: String
        let apply_device: UInt64
        let apply_root_inode: UInt64
        let entries: [Entry]
        var stage: String { tart_home + "/.gold-manager-staging/" + job_id + "/new-environment" }
        var operationDirectory: String { stage + "/.guest-ownership/" + operation_id }
        var helper: String { state_dir + "/ownership-helper/" + (metadata["root_helper"]?.sha256 ?? "") + "/GuestOwnershipHelper" }
    }
    final class FD {
        let value: Int32
        init(_ value: Int32) throws { try need(value >= 0); self.value = value }
        deinit { close(value) }
    }
    struct Owner: Equatable {
        let uid: uid_t
        let gid: gid_t
    }
    struct RawStamp: Equatable {
        let owner: Owner
        let ctime_ns: Int64
    }
    struct LockHolder: Equatable {
        let owner: Owner
        let startSeconds: UInt64
        let startMicroseconds: UInt64
    }
    // Only the APPLY precondition admits APFS's credential-dependent view of
    // the *pair* 99:99. Never project one component, a supplemental group, or
    // a policy-derived guest target. Exact observations need no projection.
    static func applyObservationMatches(_ raw: RawStamp, observed: Owner, ctime_ns: Int64, caller: Owner) -> Bool {
        guard ctime_ns > 0, raw.ctime_ns == ctime_ns else { return false }
        if raw.owner == observed { return true }
        return raw.owner == Owner(uid: 99, gid: 99) && observed == caller &&
            caller.uid >= 501 && caller.uid <= UID_MAX && caller.gid > 0 && caller.gid != 99 && caller.gid <= GID_MAX
    }
    static func rawStampMatches(_ raw: RawStamp, prevalidated: RawStamp) -> Bool { raw == prevalidated }
    static func finalOwnerMatches(_ raw: Owner, desired: Owner) -> Bool { raw == desired }

    struct Context {
        let ticket: Ticket
        let bytes: Data
        let digest: String
        let lockHolder: LockHolder
        var caller: uid_t { lockHolder.owner.uid }
        let directory: FD
        let stage: FD
        let image: FD
        let metadataFiles: [String: FD]
        var lockedConfig: FD { metadataFiles["config"]! } // mandatory private binding in load()
    }
    struct Attribution: Equatable {
        let device: String
        let container: String
        let store: String
        let generation: Int
        let filesystemDevice: UInt64
        let rootInode: UInt64
        let readOnly: Bool
    }

    static func hexadecimal(_ value: String, _ length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func safeText(_ text: String) -> Bool {
        !text.isEmpty && text.utf8.count <= 4096 && !text.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
    }
    static func parts(_ path: String, absolute: Bool) throws -> [String] {
        try need(safeText(path) && path.hasPrefix("/") == absolute && !path.contains("\\"))
        let values = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        let result = absolute ? Array(values.dropFirst()) : values
        try need(!result.isEmpty && result.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255 })
        return result
    }
    static func info(_ fd: Int32) throws -> stat {
        var value = stat(); try need(fstat(fd, &value) == 0); return value
    }
    static func deviceID(_ value: dev_t) -> UInt64 { UInt64(UInt32(bitPattern: value)) }
    static func noACL(_ fd: Int32) throws {
        errno = 0
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else { try need(errno == ENOENT, .acl); return }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?; errno = 0
        let result = acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        try need(result == -1 && errno == EINVAL, .acl)
    }
    static func directory(_ path: String, owner: uid_t? = nil, privateMode: Bool = false) throws -> FD {
        var current = try FD(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
        let names = try parts(path, absolute: true)
        for (index, name) in names.enumerated() {
            current = try FD(openat(current.value, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
            let value = try info(current.value)
            try need(value.st_mode & S_IFMT == S_IFDIR)
            let last = index == names.count - 1
            if last && owner != nil { try need(value.st_uid == owner) }
            if last && privateMode {
                try need(value.st_mode & 0o7777 == 0o700)
                try noACL(current.value)
            }
        }
        return current
    }
    static func openChild(_ parent: FD, _ name: String, directory: Bool = false) throws -> FD {
        try need(!name.contains("/") && name != "." && name != ".." && safeText(name))
        return try FD(openat(parent.value, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (directory ? O_DIRECTORY : 0)))
    }
    static func parentAt(_ root: FD, _ relative: String, device: UInt64) throws -> (FD, String) {
        let names = try parts(relative, absolute: false)
        var current = try FD(dup(root.value))
        for name in names.dropLast() {
            current = try openChild(current, name, directory: true)
            let value = try info(current.value)
            try need(deviceID(value.st_dev) == device && value.st_mode & S_IFMT == S_IFDIR)
        }
        return (current, names.last!)
    }
    static func absent(_ parent: FD, _ name: String) throws {
        var value = stat()
        let result = fstatat(parent.value, name, &value, AT_SYMLINK_NOFOLLOW)
        try need(result == -1 && errno == ENOENT)
    }
    static func read(_ fd: FD, limit: Int) throws -> Data {
        let before = try info(fd.value)
        try need(before.st_mode & S_IFMT == S_IFREG && before.st_nlink == 1 && before.st_size >= 0 && before.st_size <= limit)
        try need(lseek(fd.value, 0, SEEK_SET) == 0)
        var result = Data(); var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let amount = Darwin.read(fd.value, &buffer, buffer.count)
            if amount < 0 && errno == EINTR { continue }
            try need(amount >= 0)
            if amount == 0 { break }
            try need(result.count + amount <= limit)
            result.append(contentsOf: buffer.prefix(amount))
        }
        let after = try info(fd.value)
        try need(before.st_ino == after.st_ino && before.st_size == after.st_size && result.count == before.st_size && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec)
        return result
    }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    static func hashFile(_ fd: FD, size: Int64) throws -> String {
        try need(size >= 0 && size <= maxTree && lseek(fd.value, 0, SEEK_SET) == 0)
        let before = try info(fd.value)
        var hash = SHA256(); var count: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let amount = Darwin.read(fd.value, &buffer, buffer.count)
            if amount < 0 && errno == EINTR { continue }
            try need(amount >= 0)
            if amount == 0 { break }
            count += Int64(amount); try need(count <= size)
            hash.update(data: Data(buffer.prefix(amount)))
        }
        let after = try info(fd.value)
        try need(count == size && before.st_size == after.st_size && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec)
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
    static func checkIdentity(_ fd: FD, _ expected: Identity, caller: uid_t) throws {
        let value = try info(fd.value)
        try need(value.st_mode & S_IFMT == S_IFREG && value.st_nlink == 1 && value.st_uid == caller && value.st_gid == expected.gid && value.st_uid == expected.uid)
        try need(deviceID(value.st_dev) == expected.device && value.st_ino == expected.inode && value.st_size == expected.size && UInt32(value.st_mode & 0o7777) == expected.mode)
        try need(expected.mode == 0o600 || expected.mode == 0o755)
        try noACL(fd.value)
        if let digest = expected.sha256 { try need(hexadecimal(digest, 64) && hashFile(fd, size: expected.size) == digest) }
    }
    static func object(_ bytes: Data) throws -> [String: Any] {
        guard let value = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else { throw Failure.rejected }
        return value
    }
    static func bool(_ value: Any?, _ expected: Bool) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return false }
        return number.boolValue == expected
    }
    static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue == Double(number.int64Value) else { return nil }
        return number.int64Value
    }
    static func privateObject(_ path: String, caller: uid_t) throws -> [String: Any] {
        let names = try parts(path, absolute: true)
        let parent = try directory("/" + names.dropLast().joined(separator: "/"))
        let fd = try openChild(parent, names.last!)
        let value = try info(fd.value)
        try need(value.st_uid == caller && value.st_mode & 0o7777 == 0o600 && value.st_nlink == 1)
        try noACL(fd.value)
        return try object(read(fd, limit: 1024 * 1024))
    }

    static func desired(_ entry: Entry) throws -> (uid_t, gid_t) {
        let names = try Failure.paths.checking { try parts(entry.path, absolute: false) }
        try need(entry.device > 0 && entry.inode > 0, .entry)
        try need(entry.size >= 0, .content)
        try need(entry.mode <= 0o7777, .entry)
        try need(entry.kind == "file" ? hexadecimal(entry.sha256, 64) : entry.sha256.isEmpty, .content)
        try need(entry.kind == "symlink" || entry.link_target.isEmpty, .bundles)
        let fixed: [String: (String, UInt32, UInt32, UInt32)] = [
            base: ("directory", 0, 0, 0o755), base + "/FirstLogin": ("directory", 501, 20, 0o700),
            base + "/FirstLogin/GuestVPNBootstrap": ("file", 0, 0, 0o755),
            base + "/FirstLogin/seed.json": ("file", 501, 20, 0o600), agent: ("file", 0, 0, 0o644)]
        if let rule = fixed[entry.path] {
            try need(entry.kind == rule.0 && entry.mode == rule.3, .entry)
            return (rule.1, rule.2)
        }
        try need(names.count >= 2 && names[0] == "Applications" && apps.contains(names[1]), .paths)
        try need(["directory", "file", "symlink"].contains(entry.kind), .entry)
        if names.count == 2 { try need(entry.kind == "directory" && entry.mode == 0o755, .entry); return (0, 0) }
        if entry.kind == "symlink" {
            try need(entry.mode <= 0o777, .entry)
            try need(safeText(entry.link_target) && !entry.link_target.hasPrefix("/") && !entry.link_target.contains("\\"), .bundles)
            var stack = Array(names.dropLast())
            for part in entry.link_target.split(separator: "/", omittingEmptySubsequences: false).map(String.init) {
                if part == "." || part == "" { continue }
                if part == ".." { try need(stack.count > 2, .bundles); stack.removeLast() } else { stack.append(part) }
            }
        } else { try need(entry.mode & 0o7022 == 0, .entry) }
        return (501, 20)
    }

    static func validName(_ name: String) -> Bool {
        let scalars = name.unicodeScalars
        guard (1...64).contains(scalars.count), !name.hasPrefix("-"), !name.hasPrefix("."), !name.hasSuffix("."),
              !name.hasPrefix(" "), !name.hasSuffix(" "),
              name.utf8.elementsEqual(name.precomposedStringWithCanonicalMapping.utf8) else { return false }
        return scalars.allSatisfy { scalar in
            if [32, 45, 95].contains(scalar.value) { return true }
            switch scalar.properties.generalCategory {
            case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter,
                 .decimalNumber, .letterNumber, .otherNumber: return true
            default: return false
            }
        }
    }

    static func load(_ ticketPath: String) throws -> Context {
        let components = try parts(ticketPath, absolute: true)
        try need(components.count >= 7 && components.last == "ticket.json" && components[components.count - 3] == ".guest-ownership" && components[components.count - 4] == "new-environment")
        let parentPath = "/" + components.dropLast().joined(separator: "/")
        let operationDirectory = try directory(parentPath)
        let file = try openChild(operationDirectory, "ticket.json")
        let fileInfo = try info(file.value)
        let caller = fileInfo.st_uid
        try need(caller >= 501 && fileInfo.st_mode & 0o7777 == 0o600 && fileInfo.st_nlink == 1)
        let parentInfo = try info(operationDirectory.value)
        try need(parentInfo.st_uid == caller && parentInfo.st_mode & 0o7777 == 0o700)
        try noACL(file.value); try noACL(operationDirectory.value)
        let bytes = try read(file, limit: maxTicket)
        let document = try object(bytes)
        try need(Set(document.keys) == ["schema", "operation_id", "job_id", "name", "state_dir", "tart_home", "caller_pid", "image", "metadata", "data_uuid", "group_uuid", "apply_mount", "verify_mount", "apply_device", "apply_root_inode", "entries"])
        // Exact canonical encoding rejects duplicate keys and alternate numeric
        // forms before Codable can silently choose one duplicate value.
        try need(Data(try canonicalJSON(document).utf8) == bytes)
        guard let rawEntries = document["entries"] as? [[String: Any]], rawEntries.count <= maxEntries else { throw Failure.rejected }
        for entry in rawEntries {
            try need(Set(entry.keys) == ["path", "kind", "device", "inode", "size", "mode", "observed_uid", "observed_gid", "ctime_ns", "sha256", "link_target"])
            try need((integer(entry["ctime_ns"]) ?? 0) > 0)
        }
        let ticket: Ticket
        do { ticket = try JSONDecoder().decode(Ticket.self, from: bytes) }
        catch is DecodingError { throw Failure.ticket }
        try need(ticket.schema == 2 && hexadecimal(ticket.job_id, 32) && hexadecimal(ticket.operation_id, 32))
        try need(ticket.operationDirectory + "/ticket.json" == ticketPath && ticket.caller_pid > 1)
        try need(validName(ticket.name))
        try need(UUID(uuidString: ticket.data_uuid) != nil && UUID(uuidString: ticket.group_uuid) != nil)
        let evidence = ticket.state_dir + "/build-jobs/" + ticket.job_id + "/offline-vpn-" + ticket.operation_id
        try need(ticket.apply_mount == evidence + "/write-session/data-mount" && ticket.verify_mount == evidence + "/owner-readonly/data-mount")
        let tartDirectory = try directory(ticket.tart_home, owner: caller)
        try need([0o700, 0o755].contains(try info(tartDirectory.value).st_mode & 0o7777))
        for path in [ticket.state_dir, ticket.tart_home + "/.gold-manager-staging",
                     ticket.tart_home + "/.gold-manager-staging/" + ticket.job_id,
                     ticket.stage, ticket.stage + "/.guest-ownership", ticket.operationDirectory,
                     ticket.state_dir + "/build-jobs", ticket.state_dir + "/build-jobs/" + ticket.job_id, evidence] {
            _ = try directory(path, owner: caller, privateMode: true)
        }
        let operations = try directory(ticket.stage + "/.guest-ownership", owner: caller, privateMode: true)
        try need(Set(try names(operations)) == [ticket.operation_id])
        let stage = try directory(ticket.stage, owner: caller, privateMode: true)
        let image = try openChild(stage, "disk.img")
        try checkIdentity(image, ticket.image, caller: caller)
        try need(ticket.image.mode == 0o600 && ticket.image.size > 0 && ticket.image.sha256 == nil)
        try need(Set(ticket.metadata.keys) == ["request", "restore", "applications", "config", "nvram", "root_helper"])
        let bindings = ["request": ticket.state_dir + "/build-jobs/" + ticket.job_id + "/request.json",
                        "restore": ticket.stage + "/.clean-vm-installer.complete.json", "applications": ticket.stage + "/.offline-preinstall.complete.json",
                        "config": ticket.stage + "/config.json", "nvram": ticket.stage + "/nvram.bin", "root_helper": ticket.helper]
        var metadataFiles = [String: FD]()
        for key in bindings.keys.sorted() {
            let path = bindings[key]!, names = try parts(path, absolute: true)
            let parent = try directory("/" + names.dropLast().joined(separator: "/"))
            let fd = try openChild(parent, names.last!)
            let identity = ticket.metadata[key]!
            try need(identity.sha256 != nil && identity.mode == (key == "root_helper" ? 0o755 : 0o600))
            try checkIdentity(fd, identity, caller: caller)
            metadataFiles[key] = fd
        }
        #if !GOLD_OWNERSHIP_FIXTURE
        try need(CommandLine.arguments[0] == ticket.helper)
        #endif
        // Parent's exact config POSIX write lock must remain held while this
        // synchronous system-authorization operation runs. Do not reacquire it.
        let holder = try lockHolder(metadataFiles["config"]!, ticket.caller_pid, ticketOwner: caller)
        let context = Context(ticket: ticket, bytes: bytes, digest: hash(bytes), lockHolder: holder,
                              directory: operationDirectory, stage: stage, image: image, metadataFiles: metadataFiles)
        try stageState(context)
        return context
    }

    // Query the exact, pinned config descriptor on either side of proc_pidinfo.
    // The ticket PID and file owner are constraints, not credential sources.
    static func lockHolder(_ config: FD, _ callerPID: Int32, ticketOwner: uid_t) throws -> LockHolder {
        try Failure.parentLock.checking {
            func requireLock() throws {
                var lock = flock(l_start: 0, l_len: 0, l_pid: 0, l_type: Int16(F_WRLCK), l_whence: Int16(SEEK_SET))
                try need(fcntl(config.value, F_GETLK, &lock) == 0 && lock.l_type == F_WRLCK &&
                         lock.l_pid == callerPID && lock.l_whence == SEEK_SET && lock.l_start == 0 && lock.l_len == 0)
            }
            try requireLock()
            var bsd = proc_bsdinfo()
            let length = Int32(MemoryLayout<proc_bsdinfo>.size)
            try need(proc_pidinfo(callerPID, PROC_PIDTBSDINFO, 0, &bsd, length) == length && bsd.pbi_pid == UInt32(callerPID))
            try need(bsd.pbi_uid >= 501 && bsd.pbi_uid == ticketOwner && bsd.pbi_ruid == bsd.pbi_uid && bsd.pbi_svuid == bsd.pbi_uid)
            try need(bsd.pbi_rgid == bsd.pbi_gid && bsd.pbi_svgid == bsd.pbi_gid && bsd.pbi_start_tvsec > 0)
            try requireLock()
            return LockHolder(owner: Owner(uid: bsd.pbi_uid, gid: bsd.pbi_gid),
                              startSeconds: bsd.pbi_start_tvsec, startMicroseconds: bsd.pbi_start_tvusec)
        }
    }

    static func recheckLockHolder(_ context: Context) throws {
        try need(try lockHolder(context.lockedConfig, context.ticket.caller_pid, ticketOwner: context.caller) == context.lockHolder, .parentLock)
    }

    static func stageState(_ context: Context) throws {
        try Failure.ticket.checking { try checkIdentity(context.image, context.ticket.image, caller: context.caller) }
        try recheckLockHolder(context)
        try Failure.stageState.checking { try checkStageAndRequest(context) }
        try Failure.ticket.checking { try recheckImmutableBindings(context) }
    }

    static func checkStageAndRequest(_ context: Context) throws {
        let ticket = context.ticket
        let vms = try directory(ticket.tart_home + "/vms", owner: context.caller)
        try need([0o700, 0o755].contains(try info(vms.value).st_mode & 0o7777))
        try absent(vms, ticket.name)
        for name in ["state.vzvmsave", "state.bin", "savedstate"] { try absent(context.stage, name) }
        let current = try privateObject(ticket.state_dir + "/build-current.json", caller: context.caller)
        let request = try privateObject(ticket.state_dir + "/build-jobs/" + ticket.job_id + "/request.json", caller: context.caller)
        for value in [current, request] {
            try need(value["id"] as? String == ticket.job_id && value["name"] as? String == ticket.name && value["mode"] as? String == "preinstall" && value["source_vm"] is NSNull)
        }
        try need(current["stage_path"] as? String == ticket.stage && ["configuring_vpn", "awaiting_system_authorization"].contains(current["phase"] as? String ?? ""))
        for key in ["system_restored", "applications_preinstalled"] { try need(bool(current[key], true)) }
        for key in ["guest_started", "desktop_verified", "published", "host_credentials_copied", "credentials_copied"] { try need(bool(current[key], false)) }
        guard let vpn = current["vpn_configuration"] as? [String: Any] else { throw Failure.rejected }
        try need(vpn["operation_id"] as? String == ticket.operation_id && bool(vpn["active"], true))
        for key in ["acknowledge_preinstall", "acknowledge_network_policy", "acknowledge_guest_autoconfigure"] { try need(bool(request[key], true)) }
        try need(integer(request["disk_gib"]) == ticket.image.size / (1024 * 1024 * 1024) && ticket.image.size % (1024 * 1024 * 1024) == 0)
        let restore = try privateObject(ticket.stage + "/.clean-vm-installer.complete.json", caller: context.caller)
        try need(restore["installer"] as? String == "CleanVMInstaller" && restore["status"] as? String == "complete" && integer(restore["schemaVersion"]) == 1)
        for key in ["networkDeviceCount", "directorySharingDeviceCount", "socketDeviceCount"] { try need(integer(restore[key]) == 0) }
        let apps = try privateObject(ticket.stage + "/.offline-preinstall.complete.json", caller: context.caller)
        try need(apps["job_id"] as? String == ticket.job_id && apps["name"] as? String == ticket.name && apps["stage_path"] as? String == ticket.stage)
        for key in ["applications_preinstalled", "readonly_remount_verified", "final_detach_confirmed"] { try need(bool(apps[key], true)) }
        for key in ["guest_started", "published", "credentials_copied", "desktop_verified"] { try need(bool(apps[key], false)) }
        try need((apps["data_uuid"] as? String)?.uppercased() == ticket.data_uuid && (apps["volume_group_uuid"] as? String)?.uppercased() == ticket.group_uuid)
    }

    static func recheckImmutableBindings(_ context: Context) throws {
        let ticket = context.ticket
        // Recheck immutable receipt/request/config identities, not merely their
        // interpreted success fields. An atomic replacement also fails inode pin.
        for (key, path) in ["request": ticket.state_dir + "/build-jobs/" + ticket.job_id + "/request.json", "restore": ticket.stage + "/.clean-vm-installer.complete.json", "applications": ticket.stage + "/.offline-preinstall.complete.json", "config": ticket.stage + "/config.json", "nvram": ticket.stage + "/nvram.bin"] {
            let names = try parts(path, absolute: true)
            let parent = try directory("/" + names.dropLast().joined(separator: "/"))
            try checkIdentity(openChild(parent, names.last!), ticket.metadata[key]!, caller: context.caller)
        }
    }

    #if !GOLD_OWNERSHIP_FIXTURE
    static func command(_ executable: String, _ arguments: [String]) throws -> Data {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "HOME": "/var/empty"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        process.standardInput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        process.standardOutput = pipe
        do { try process.run() } catch { throw Failure.disk }
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 30)
        timer.setEventHandler { if process.isRunning { process.terminate() } }
        timer.resume(); defer { timer.cancel() }
        var output = Data()
        while true {
            let part = pipe.fileHandleForReading.readData(ofLength: 65536)
            if part.isEmpty { break }
            if output.count + part.count > 8 * 1024 * 1024 { process.terminate(); throw Failure.rejected }
            output.append(part)
        }
        process.waitUntilExit()
        try need(process.terminationStatus == 0)
        return output
    }
    #endif
    static func plist(_ bytes: Data) throws -> [String: Any] {
        guard let value = (try? PropertyListSerialization.propertyList(from: bytes, options: [], format: nil)) as? [String: Any] else { throw Failure.rejected }
        return value
    }
    static func nativeMetadata(_ context: Context, root: FD, verify: Bool) throws -> Attribution {
        let ticket = context.ticket, mount = verify ? ticket.verify_mount : ticket.apply_mount
        let hdi: [String: Any], disk: [String: Any], apfs: [String: Any]
        #if GOLD_OWNERSHIP_FIXTURE
        // These are explicit dummy fixture documents, never trusted in production.
        hdi = try object(read(openChild(context.directory, verify ? "fixture-hdi-verify.json" : "fixture-hdi-apply.json"), limit: 1024 * 1024))
        disk = try object(read(openChild(context.directory, verify ? "fixture-disk-verify.json" : "fixture-disk-apply.json"), limit: 1024 * 1024))
        apfs = try object(read(openChild(context.directory, "fixture-apfs.json"), limit: 1024 * 1024))
        #else
        hdi = try plist(command("/usr/bin/hdiutil", ["info", "-plist"]))
        disk = try plist(command("/usr/sbin/diskutil", ["info", "-plist", mount]))
        apfs = try plist(command("/usr/sbin/diskutil", ["apfs", "list", "-plist"]))
        #endif
        guard let images = hdi["images"] as? [[String: Any]] else { throw Failure.rejected }
        let matches = images.filter { $0["image-path"] as? String == ticket.stage + "/disk.img" }
        try need(matches.count == 1)
        let image = matches[0]
        try need(integer(image["owner-uid"]) == Int64(context.caller) && image["image-type"] as? String == "read/write" && bool(image["writeable"], !verify))
        try need(bool(image["image-encrypted"], false) && bool(image["autodiskmount"], false))
        guard let blocks = integer(image["blockcount"]), let blockSize = integer(image["blocksize"]), blocks > 0, blockSize > 0,
              blocks <= Int64.max / blockSize, blocks * blockSize == ticket.image.size,
              let generation = integer(image["hdid-pid"]), generation > 0,
              let entities = image["system-entities"] as? [[String: Any]], entities.count <= 64 else { throw Failure.rejected }
        guard let device = disk["DeviceIdentifier"] as? String,
              device.range(of: "^disk[0-9]+s[1-9][0-9]*$", options: .regularExpression) != nil,
              let container = disk["APFSContainerReference"] as? String,
              let stores = disk["APFSPhysicalStores"] as? [[String: String]], stores.count == 1,
              let store = stores[0]["APFSPhysicalStore"] else { throw Failure.rejected }
        let entityDevices = entities.compactMap { $0["dev-entry"] as? String }
        try need(entityDevices.count == entities.count && Set(entityDevices).count == entities.count)
        try need([device, container, store].allSatisfy { entityDevices.contains("/dev/" + $0) })
        let mounts = entities.filter { !($0["mount-point"] as? String ?? "").isEmpty }
        try need(mounts.count == 1 && mounts[0]["dev-entry"] as? String == "/dev/" + device && mounts[0]["mount-point"] as? String == mount)
        try need(disk["MountPoint"] as? String == mount && disk["DeviceNode"] as? String == "/dev/" + device && disk["ParentWholeDisk"] as? String == container)
        try need(disk["FilesystemType"] as? String == "apfs" && disk["BusProtocol"] as? String == "Disk Image")
        try need((disk["VolumeUUID"] as? String)?.uppercased() == ticket.data_uuid && (disk["DiskUUID"] as? String)?.uppercased() == ticket.data_uuid && (disk["APFSVolumeGroupID"] as? String)?.uppercased() == ticket.group_uuid)
        for key in ["WholeDisk", "Internal", "OSInternalMedia", "APFSSnapshot", "Encryption", "EncryptionThisVolumeProper", "FileVault", "Locked"] { try need(bool(disk[key], false)) }
        for key in ["Writable", "WritableMedia", "WritableVolume"] { try need(bool(disk[key], !verify)) }
        // Apply needs real observed IDs too: owners-off can synthesize different
        // ownership for the caller and root. Never chown from such a display.
        try need(bool(disk["GlobalPermissionsEnabled"], true))
        if let readOnly = disk["ReadOnly"] { try need(bool(readOnly, verify)) }
        guard let containers = apfs["Containers"] as? [[String: Any]] else { throw Failure.rejected }
        let volumes = containers.flatMap { item -> [[String: Any]] in
            guard item["ContainerReference"] as? String == container,
                  let stores = item["PhysicalStores"] as? [[String: Any]], stores.count == 1,
                  stores[0]["DeviceIdentifier"] as? String == store else { return [] }
            return item["Volumes"] as? [[String: Any]] ?? []
        }.filter { ($0["APFSVolumeUUID"] as? String)?.uppercased() == ticket.data_uuid }
        try need(volumes.count == 1 && volumes[0]["DeviceIdentifier"] as? String == device && volumes[0]["Roles"] as? [String] == ["Data"])
        for key in ["Encryption", "FileVault", "Locked"] { try need(bool(volumes[0][key], false)) }
        let rootInfo = try info(root.value)
        #if !GOLD_OWNERSHIP_FIXTURE
        var filesystem = statfs()
        try need(fstatfs(root.value, &filesystem) == 0)
        let type = withUnsafePointer(to: &filesystem.f_fstypename) { $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) } }
        let from = withUnsafePointer(to: &filesystem.f_mntfromname) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
        let onto = withUnsafePointer(to: &filesystem.f_mntonname) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
        try need(type == "apfs" && from == "/dev/" + device && onto == mount)
        try need((filesystem.f_flags & UInt32(MNT_RDONLY) != 0) == verify)
        try need(filesystem.f_flags & UInt32(MNT_IGNORE_OWNERSHIP) == 0)
        try need(deviceID(rootInfo.st_dev) != deviceID(try info(context.stage.value).st_dev))
        #endif
        if !verify { try need(deviceID(rootInfo.st_dev) == ticket.apply_device && rootInfo.st_ino == ticket.apply_root_inode) }
        return Attribution(device: device, container: container, store: store, generation: Int(generation), filesystemDevice: deviceID(rootInfo.st_dev), rootInode: rootInfo.st_ino, readOnly: verify)
    }

    static func names(_ fd: FD) throws -> [String] {
        let duplicated = dup(fd.value); try need(duplicated >= 0)
        guard let stream = fdopendir(duplicated) else { close(duplicated); throw Failure.rejected }
        defer { closedir(stream) }
        var result = [String]()
        errno = 0
        while let entry = readdir(stream) {
            var value = entry.pointee.d_name
            let name = withUnsafePointer(to: &value) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
            if name != "." && name != ".." { result.append(name); try need(result.count <= maxEntries) }
            errno = 0
        }
        try need(errno == 0)
        return result
    }
    static func linkTarget(_ link: FD) throws -> String {
        var buffer = [CChar](repeating: 0, count: 4097)
        let count = freadlink(link.value, &buffer, 4096)
        try need(count > 0 && count < 4096)
        guard let value = String(bytes: buffer.prefix(count).map { UInt8(bitPattern: $0) }, encoding: .utf8) else { throw Failure.rejected }
        return value
    }
    static func collectPaths(_ root: FD, device: UInt64) throws -> Set<String> {
        var result = Set<String>()
        func visit(_ parent: FD, _ name: String, _ path: String) throws {
            try need(result.insert(path).inserted && result.count <= maxEntries)
            var value = stat(); try need(fstatat(parent.value, name, &value, AT_SYMLINK_NOFOLLOW) == 0 && deviceID(value.st_dev) == device)
            if value.st_mode & S_IFMT == S_IFDIR {
                let fd = try openChild(parent, name, directory: true)
                try need(try info(fd.value).st_ino == value.st_ino)
                for child in try names(fd) { try visit(fd, child, path + "/" + child) }
            }
        }
        let roots = [base, agent] + apps.map { "Applications/" + $0 }
        for path in roots {
            let (parent, name) = try parentAt(root, path, device: device)
            try visit(parent, name, path)
        }
        return result
    }
    static func rawOwner(_ value: stat) -> Owner { Owner(uid: value.st_uid, gid: value.st_gid) }
    static func rawStamp(_ value: stat) throws -> RawStamp {
        let sec = Int64(value.st_ctimespec.tv_sec), nsec = Int64(value.st_ctimespec.tv_nsec)
        try need(sec >= 0 && (0..<1_000_000_000).contains(nsec) && sec <= (Int64.max - nsec) / 1_000_000_000, .ownership)
        return RawStamp(owner: rawOwner(value), ctime_ns: sec * 1_000_000_000 + nsec)
    }
    static func checkShape(_ value: stat, entry: Entry, device: UInt64) throws {
        let expectedKind = entry.kind == "directory" ? S_IFDIR : entry.kind == "file" ? S_IFREG : S_IFLNK
        try need(deviceID(value.st_dev) == device && value.st_ino == entry.inode && UInt32(value.st_mode & 0o7777) == entry.mode, .entry)
        try need(value.st_mode & S_IFMT == expectedKind && (entry.kind == "directory" || value.st_nlink == 1), .entry)
    }
    static func applyMatchesTicket(_ stamp: RawStamp, _ entry: Entry, caller: Owner) -> Bool {
        applyObservationMatches(stamp, observed: Owner(uid: entry.observed_uid, gid: entry.observed_gid),
                                ctime_ns: entry.ctime_ns, caller: caller)
    }
    static func checkEntry(_ entry: Entry, root: FD, device: UInt64, verify: Bool) throws -> (FD, RawStamp) {
        try Failure.entry.checking {
            let target = try desired(entry)
            let (parent, name) = try parentAt(root, entry.path, device: device)
            var value = stat(); try need(fstatat(parent.value, name, &value, AT_SYMLINK_NOFOLLOW) == 0)
            try checkShape(value, entry: entry, device: device)
            // Darwin open(2): O_SYMLINK opens the link itself; adding O_NOFOLLOW
            // would reject it with ELOOP. Never reopen or mutate it by name.
            let fd = entry.kind == "symlink" ? try FD(openat(parent.value, name, O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC)) :
                try openChild(parent, name, directory: entry.kind == "directory")
            let before = try info(fd.value)
            try checkShape(before, entry: entry, device: device)
            try noACL(fd.value)
            if entry.kind == "symlink" {
                try Failure.bundles.checking { try need(try linkTarget(fd) == entry.link_target) }
            } else if entry.kind == "file" {
                try Failure.content.checking {
                    try need(before.st_size == entry.size && hexadecimal(entry.sha256, 64))
                    try need(try hashFile(fd, size: entry.size) == entry.sha256)
                }
            }
            let after = try info(fd.value)
            try checkShape(after, entry: entry, device: device)
            let stamp = try rawStamp(after)
            // Keep more specific content/link/ACL diagnostics above metadata drift.
            try need(try rawStamp(value) == stamp && rawStamp(before) == stamp, .ownership)
            if verify {
                #if !GOLD_OWNERSHIP_FIXTURE
                // A fresh, independent owners-on readonly mount must expose the
                // policy owners literally. Chown changes ctime: no ticket ctime here.
                try need(finalOwnerMatches(stamp.owner, desired: Owner(uid: target.0, gid: target.1)), .ownership)
                #else
                _ = target // Simulation never chowns; it cannot attest final ownership.
                #endif
            }
            return (fd, stamp)
        }
    }

    // Match Python ensure_ascii=True compact JSON used by the existing signed
    // complete-bundle receipt. Paths sort by Unicode scalar values, not locale.
    static func quote(_ value: String) -> String {
        var output = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 34: output += "\\\""
            case 92: output += "\\\\"
            case 8: output += "\\b"
            case 9: output += "\\t"
            case 10: output += "\\n"
            case 12: output += "\\f"
            case 13: output += "\\r"
            case 0...31, 127...65535: output += String(format: "\\u%04x", scalar.value)
            case 65536...0x10ffff:
                let value = scalar.value - 65536
                output += String(format: "\\u%04x\\u%04x", 0xd800 + (value >> 10), 0xdc00 + (value & 1023))
            default: output.unicodeScalars.append(scalar)
            }
        }
        return output + "\""
    }
    static func canonicalJSON(_ value: Any, depth: Int = 0) throws -> String {
        try need(depth <= 32)
        if value is NSNull { return "null" }
        if let text = value as? String { return quote(text) }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
            guard let value = integer(number) else { throw Failure.rejected }
            return String(value)
        }
        if let list = value as? [Any] {
            return "[" + (try list.map { try canonicalJSON($0, depth: depth + 1) }).joined(separator: ",") + "]"
        }
        if let map = value as? [String: Any] {
            let keys = map.keys.sorted { $0.unicodeScalars.map(\.value).lexicographicallyPrecedes($1.unicodeScalars.map(\.value)) }
            return "{" + (try keys.map { quote($0) + ":" + (try canonicalJSON(map[$0]!, depth: depth + 1)) }).joined(separator: ",") + "}"
        }
        throw Failure.rejected
    }

    static func validateLinks(_ entries: [Entry]) throws {
        let byPath = Dictionary(uniqueKeysWithValues: entries.map { ($0.path, $0) })
        for entry in entries where entry.kind == "symlink" {
            let components = try parts(entry.path, absolute: false)
            var resolved = Array(components.prefix(2)), pending = Array(components.dropFirst(2)), hops = 0
            while !pending.isEmpty {
                let part = pending.removeFirst()
                if part == "" || part == "." { continue }
                if part == ".." { try need(resolved.count > 2); resolved.removeLast(); continue }
                resolved.append(part)
                guard let target = byPath[resolved.joined(separator: "/")] else { throw Failure.rejected }
                if target.kind == "symlink" {
                    _ = try desired(target)
                    hops += 1; try need(hops <= 40)
                    resolved.removeLast()
                    pending = target.link_target.split(separator: "/", omittingEmptySubsequences: false).map(String.init) + pending
                } else if !pending.isEmpty { try need(target.kind == "directory") }
            }
            try need(byPath[resolved.joined(separator: "/")] != nil)
        }
    }

    static func verifyAppReceipts(_ context: Context) throws {
        let receipt = try privateObject(context.ticket.stage + "/.offline-preinstall.complete.json", caller: context.caller)
        guard let records = receipt["applications"] as? [[String: Any]], records.count == 4 else { throw Failure.rejected }
        try need(Set(records.compactMap { $0["name"] as? String }) == Set(apps))
        for app in apps {
            let prefix = "Applications/" + app + "/"
            let entries = context.ticket.entries.filter { $0.path.hasPrefix(prefix) }.sorted {
                $0.path.unicodeScalars.map(\.value).lexicographicallyPrecedes($1.path.unicodeScalars.map(\.value))
            }
            try need(!entries.isEmpty)
            var lines = [String](); var total: Int64 = 0
            for entry in entries {
                let path = String(entry.path.dropFirst(prefix.count))
                var values = [quote(path), quote(entry.kind), String(entry.mode)]
                if entry.kind == "file" { values += [String(entry.size), quote(entry.sha256)]; total += entry.size }
                if entry.kind == "symlink" { values.append(quote(entry.link_target)) }
                lines.append("[" + values.joined(separator: ",") + "]")
            }
            let digest = hash(Data(("[" + lines.joined(separator: ",") + "]").utf8))
            let match = records.filter { $0["name"] as? String == app }
            try need(match.count == 1 && match[0]["bundle_tree_sha256"] as? String == digest && integer(match[0]["bundle_bytes"]) == total)
        }
    }

    static func writePrivate(_ parent: FD, _ name: String, bytes: Data, owner: uid_t, group: gid_t) throws {
        let fd = try FD(openat(parent.value, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600))
        try need(bytes.count <= 65536)
        try bytes.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { throw Failure.rejected }
            var offset = 0
            while offset < buffer.count {
                let amount = Darwin.write(fd.value, base.advanced(by: offset), buffer.count - offset)
                if amount < 0 && errno == EINTR { continue }
                try need(amount > 0); offset += amount
            }
        }
        #if !GOLD_OWNERSHIP_FIXTURE
        try need(fchown(fd.value, owner, group) == 0)
        #endif
        try need(fsync(fd.value) == 0 && fsync(parent.value) == 0)
    }
    static func receiptBytes(_ value: [String: Any]) throws -> Data {
        do { return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
        catch { throw Failure.receipt }
    }

    static func execute(_ context: Context, verify: Bool) throws {
        let ticket = context.ticket
        let mount = verify ? ticket.verify_mount : ticket.apply_mount
        let root = try Failure.disk.checking {
            _ = try directory(String(mount.dropLast("/data-mount".count)), owner: context.caller, privateMode: true)
            return try directory(mount)
        }
        let attribution = try Failure.disk.checking { try nativeMetadata(context, root: root, verify: verify) }
        #if GOLD_OWNERSHIP_FIXTURE
        let simulate = true, authorization = "fixture_no_authorization"
        #else
        let simulate = false, authorization = "macos_system_administrator"
        #endif
        let keys = Set(ticket.entries.map(\.path))
        try need(ticket.entries.count >= 9 && ticket.entries.count <= maxEntries && keys.count == ticket.entries.count, .paths)
        try need(Set([base, base + "/FirstLogin", base + "/FirstLogin/seed.json", base + "/FirstLogin/GuestVPNBootstrap", agent] + apps.map { "Applications/" + $0 }).isSubset(of: keys), .paths)
        try need(Set(ticket.entries.map(\.inode)).count == ticket.entries.count, .entry)
        for entry in ticket.entries {
            try need(entry.device == ticket.apply_device && entry.inode > 0, .entry)
            try need(entry.size >= 0 && entry.size <= maxTree, .content)
        }
        try Failure.paths.checking { try need(try collectPaths(root, device: attribution.filesystemDevice) == keys) }
        try Failure.bundles.checking {
            try verifyAppReceipts(context)
            try validateLinks(ticket.entries)
        }
        var bytes: Int64 = 0
        var prevalidated = [UInt64: RawStamp]() // entry inode uniqueness already established above
        var observationsMatch = true
        for entry in ticket.entries {
            let (_, stamp) = try checkEntry(entry, root: root, device: attribution.filesystemDevice, verify: verify)
            if !verify {
                prevalidated[entry.inode] = stamp
                // A changed directory ctime must not mask the more specific
                // identity, ACL or content rejection of a child in this pass.
                if !applyMatchesTicket(stamp, entry, caller: context.lockHolder.owner) { observationsMatch = false }
            }
            if entry.kind == "file" { bytes += entry.size; try need(bytes <= maxTree, .content) }
        }
        try need(observationsMatch, .ownership)
        // Fresh user accounts or Setup Assistant completion disqualify the stage.
        try Failure.stageState.checking {
            let users = try parentAt(root, "Users/Shared", device: attribution.filesystemDevice).0
            try need(Set(try names(users)).isSubset(of: ["Shared", ".localized"]))
            let db = try parentAt(root, "private/var/db/.AppleSetupDone", device: attribution.filesystemDevice).0
            try absent(db, ".AppleSetupDone")
        }
        let operation = verify ? "verify" : "apply"
        try Failure.receipt.checking {
            try absent(context.directory, operation + ".started")
            try absent(context.directory, operation + ".receipt.json")
            if verify {
                let priorFD = try openChild(context.directory, "apply.receipt.json")
                let priorInfo = try info(priorFD.value)
                try need(priorInfo.st_uid == context.caller && priorInfo.st_mode & 0o7777 == 0o600 && priorInfo.st_nlink == 1)
                let prior = try object(read(priorFD, limit: 65536))
                try need(prior["ticket_sha256"] as? String == context.digest && prior["operation_id"] as? String == ticket.operation_id && prior["operation"] as? String == "apply")
                guard let priorGeneration = integer(prior["attachment_generation"]), priorGeneration > 0 else { throw Failure.rejected }
                try need(priorGeneration != Int64(attribution.generation) && integer(prior["schema"]) == 1 && integer(prior["entry_count"]) == Int64(ticket.entries.count))
                try need(bool(prior["fixture_only"], simulate) && bool(prior["metadata_applied"], !simulate)
                         && bool(prior["persistent_ownership_verified"], false) && bool(prior["readonly_owners_on"], false)
                         && prior["helper_contract"] as? String == buildContract)
            }
            // A partial failure consumes this one operation. No retry or rollback.
            try writePrivate(context.directory, operation + ".started", bytes: receiptBytes(["ticket_sha256": context.digest, "operation": operation]), owner: 0, group: 0)
        }
        try stageState(context)
        try Failure.disk.checking { try need(try nativeMetadata(context, root: root, verify: verify) == attribution) }
        if !verify {
            for entry in ticket.entries.sorted(by: { $0.path.count > $1.path.count }) {
                let (fd, checked) = try checkEntry(entry, root: root, device: attribution.filesystemDevice, verify: false)
                try need(applyMatchesTicket(checked, entry, caller: context.lockHolder.owner), .ownership)
                let target = try desired(entry)
                guard let original = prevalidated[entry.inode] else { throw Failure.entry }
                try need(rawStampMatches(checked, prevalidated: original), .ownership)
                try recheckLockHolder(context)
                // No name-based mutation (including symlinks). Re-stat this very
                // descriptor after the second hash/readlink and just before use.
                let latest = try Failure.entry.checking { try info(fd.value) }
                try checkShape(latest, entry: entry, device: attribution.filesystemDevice)
                try need(try rawStampMatches(rawStamp(latest), prevalidated: original), .ownership)
                #if !GOLD_OWNERSHIP_FIXTURE
                try Failure.mutation.checking {
                    try need(fchown(fd.value, target.0, target.1) == 0)
                    try need(try finalOwnerMatches(rawOwner(info(fd.value)), desired: Owner(uid: target.0, gid: target.1)))
                }
                #else
                _ = target // Simulation: no chown symbol; no mutation/verification claim.
                #endif
            }
        }
        try stageState(context)
        try Failure.disk.checking { try need(try nativeMetadata(context, root: root, verify: verify) == attribution) }
        try Failure.paths.checking { try need(try collectPaths(root, device: attribution.filesystemDevice) == keys) }
        let receipt: [String: Any] = ["schema": 1, "operation_id": ticket.operation_id,
            "ticket_sha256": context.digest, "operation": operation,
            "attachment_generation": attribution.generation, "entry_count": ticket.entries.count,
            "fixture_only": simulate, "metadata_applied": !verify && !simulate,
            "persistent_ownership_verified": verify && !simulate,
            "readonly_owners_on": verify, "guest_started": false, "published": false, "helper_contract": buildContract,
            "authorization": authorization]
        try Failure.receipt.checking {
            try writePrivate(context.directory, operation + ".receipt.json", bytes: receiptBytes(receipt), owner: context.caller, group: context.lockHolder.owner.gid)
        }
    }
}

// A separate test main can exercise pure rules without a root invocation or
// providing pretend credentials to this executable. Production always has Main.
#if !(GOLD_OWNERSHIP_FIXTURE && GOLD_OWNERSHIP_PREDICATE_TEST)
@main struct Main {
    static func main() {
        umask(0o077)
        do {
            try GuestOwnership.need(CommandLine.arguments.count == 3 && ["--apply", "--verify"].contains(CommandLine.arguments[2]), .invocation)
            #if GOLD_OWNERSHIP_FIXTURE
            let prefix = "/private/tmp/gold-ownership-tests-"
            try GuestOwnership.need(CommandLine.arguments[1].hasPrefix(prefix), .invocation)
            #else
            try GuestOwnership.need(getuid() == 0 && geteuid() == 0, .invocation)
            #endif
            let context = try GuestOwnership.Failure.ticket.checking { try GuestOwnership.load(CommandLine.arguments[1]) }
            try GuestOwnership.execute(context, verify: CommandLine.arguments[2] == "--verify")
            #if GOLD_OWNERSHIP_FIXTURE
            print("fixture_metadata_simulation_completed")
            #endif
        } catch let failure as GuestOwnership.Failure {
            exit(failure.rawValue)
        } catch {
            // No original errors, paths, credentials or user-controlled text.
            exit(2)
        }
    }
}
#endif
