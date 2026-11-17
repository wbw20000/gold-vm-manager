// Standalone clean-room macOS installer. Never opens an existing VM or invokes Tart.
// Build/run contract: CleanVMInstaller.md. Requires Apple Silicon and macOS 13+.
import Foundation
import Darwin
@preconcurrency import Virtualization

private let gib: UInt64 = 1_073_741_824

// Apple's completion handlers run on arbitrary threads. Restore-image metadata is
// immutable (all public properties are readonly); transfer it once to MainActor.
// No VZVirtualMachine/configuration/installer object crosses this boundary.
private struct RestoreImageTransfer: @unchecked Sendable {
    let value: VZMacOSRestoreImage
}

private struct InstallerError: Error {
    let code: String
    let message: String
    var exitCode: Int32 = 1
}

private func fail(_ code: String, _ message: String) -> InstallerError {
    InstallerError(code: code, message: message)
}

@MainActor
private func emit(_ object: [String: Any]) {
    // Only fixed-schema values reach this writer; no raw errors, URLs, paths or identities in progress.
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
}

private struct Options {
    enum Mode: String { case help, inspect, latest, create }
    let mode: Mode
    var ipsw: String?
    var directory: String?
    var cpu: Int = 2
    var memoryGiB: UInt64 = 4
    var diskGiB: UInt64 = 50

    static func parse(_ args: [String]) throws -> Options {
        guard let first = args.first, let mode = Mode(rawValue: String(first.dropFirst(2))), first.hasPrefix("--") else {
            throw InstallerError(code: "usage", message: "Use --help, --latest, --inspect --ipsw PATH, or --create with all resource arguments.", exitCode: 2)
        }
        if mode == .help || mode == .latest {
            guard args.count == 1 else { throw fail("usage", "This mode accepts no additional arguments.") }
            return Options(mode: mode)
        }
        let allowed: Set<String> = mode == .inspect ? ["--ipsw"] : ["--ipsw", "--directory", "--cpu", "--memory-gib", "--disk-gib"]
        var fields: [String: String] = [:]
        var index = 1
        while index < args.count {
            let key = args[index]
            guard allowed.contains(key), fields[key] == nil, index + 1 < args.count else {
                throw fail("usage", "Unknown, duplicate, or incomplete argument.")
            }
            fields[key] = args[index + 1]
            index += 2
        }
        guard Set(fields.keys) == allowed else { throw fail("usage", "All arguments shown for this mode are required.") }
        var result = Options(mode: mode)
        result.ipsw = fields["--ipsw"]
        if mode == .create {
            func positive(_ key: String) throws -> UInt64 {
                let value = fields[key]!
                guard !value.isEmpty, value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), let number = UInt64(value), number > 0 else {
                    throw fail("usage", "Resource values must be positive decimal integers.")
                }
                return number
            }
            let cpu = try positive("--cpu")
            guard cpu <= UInt64(Int.max) else { throw fail("usage", "CPU count is too large.") }
            result.cpu = Int(cpu)
            result.memoryGiB = try positive("--memory-gib")
            result.diskGiB = try positive("--disk-gib")
            guard result.memoryGiB <= UInt64(Int64.max) / gib, result.diskGiB <= UInt64(Int64.max) / gib else {
                throw fail("usage", "Resource size overflows supported byte counts.")
            }
            result.directory = fields["--directory"]
        }
        return result
    }
}

// Traverse using directory descriptors rather than resolving untrusted symlinks.
private func components(_ path: String) throws -> [String] {
    guard path.hasPrefix("/"), path != "/", !path.contains("\0"), !path.hasSuffix("/") else {
        throw fail("unsafe_path", "Paths must be absolute, non-root, and have no trailing slash or NUL.")
    }
    let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    guard parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
        throw fail("unsafe_path", "Paths must have no empty, dot, or dot-dot components.")
    }
    return parts
}

private func statFD(_ fd: Int32) throws -> stat {
    var value = stat()
    guard fstat(fd, &value) == 0 else { throw fail("filesystem", "Cannot inspect filesystem descriptor.") }
    return value
}

private func sameFile(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
}

private func openDirectory(_ path: String, protected: Bool) throws -> Int32 {
    let parts = try components(path)
    var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard fd >= 0 else { throw fail("filesystem", "Cannot open filesystem root.") }
    do {
        for part in parts {
            let next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw fail("unsafe_path", "Directory missing, inaccessible, or a symlink.") }
            close(fd)
            fd = next
            if protected {
                let info = try statFD(fd)
                guard (info.st_uid == getuid() || info.st_uid == 0), info.st_mode & 0o022 == 0 else {
                    throw fail("unsafe_directory", "Staging ancestors must be root/user owned and not group/world writable.")
                }
            }
        }
        return fd
    } catch {
        close(fd)
        throw error
    }
}

private final class LocalImage {
    let url: URL
    let fd: Int32
    let original: stat
    init(path: String) throws {
        let parts = try components(path)
        let parent = "/" + parts.dropLast().joined(separator: "/")
        let parentFD: Int32
        if parent == "/" { parentFD = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC) }
        else { parentFD = try openDirectory(parent, protected: false) }
        guard parentFD >= 0 else { throw fail("unsafe_ipsw", "Cannot open IPSW parent.") }
        defer { close(parentFD) }
        let opened = openat(parentFD, parts.last!, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard opened >= 0 else { throw fail("unsafe_ipsw", "IPSW must be an accessible local regular file, not a symlink.") }
        do {
            let info = try statFD(opened)
            guard info.st_mode & S_IFMT == S_IFREG, info.st_size > 0, info.st_mode & 0o022 == 0 else {
                throw fail("unsafe_ipsw", "IPSW must be a nonempty regular file, not group/world writable.")
            }
            guard flock(opened, LOCK_SH | LOCK_NB) == 0 else { throw fail("ipsw_busy", "IPSW is exclusively locked.") }
            fd = opened
            original = info
            url = URL(fileURLWithPath: path)
        } catch {
            close(opened)
            throw error
        }
    }
    deinit { close(fd) }
    func verifyUnchanged() throws {
        let reopened = try LocalImage(path: url.path)
        let current = reopened.original
        guard sameFile(original, current), original.st_size == current.st_size,
              original.st_mtimespec.tv_sec == current.st_mtimespec.tv_sec,
              original.st_mtimespec.tv_nsec == current.st_mtimespec.tv_nsec,
              original.st_ctimespec.tv_sec == current.st_ctimespec.tv_sec,
              original.st_ctimespec.tv_nsec == current.st_ctimespec.tv_nsec else {
            throw fail("ipsw_changed", "IPSW changed since inspection; refusing installation.")
        }
    }
}

private final class Stage {
    let path: String
    let fd: Int32
    let original: stat
    private let claimName = ".clean-vm-installer.claim"
    init(path: String) throws {
        let opened = try openDirectory(path, protected: true)
        do {
            let info = try statFD(opened)
            guard info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else {
                throw fail("unsafe_directory", "Staging directory must be owned by the current user with mode 0700.")
            }
            self.path = path
            fd = opened
            original = info
        } catch { close(opened); throw error }
    }
    deinit { close(fd) }
    func verifyPath() throws {
        let current = try openDirectory(path, protected: true)
        defer { close(current) }
        let info = try statFD(current)
        guard sameFile(original, info), info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else {
            throw fail("staging_changed", "Staging directory identity or permissions changed.")
        }
    }
    func entries() throws -> Set<String> {
        // openat(".") obtains a fresh directory stream offset; dup would share offsets.
        let copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard copy >= 0 else { throw fail("filesystem", "Cannot read staging directory.") }
        guard let stream = fdopendir(copy) else { close(copy); throw fail("filesystem", "Cannot enumerate staging directory.") }
        defer { closedir(stream) }
        var names = Set<String>()
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw fail("filesystem", "Directory enumeration failed.") }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { names.insert(name) }
        }
        return names
    }
    func checkEmpty() throws {
        try verifyPath()
        guard try entries().isEmpty else { throw fail("target_not_empty", "Staging directory must be completely empty; no overwrite or resume is supported.") }
    }
    func checkCapacity(diskBytes: UInt64) throws {
        var stats = statvfs()
        guard fstatvfs(fd, &stats) == 0 else { throw fail("filesystem", "Cannot inspect staging filesystem capacity.") }
        let (available, overflow) = UInt64(stats.f_bavail).multipliedReportingOverflow(by: UInt64(stats.f_frsize))
        guard !overflow, available >= diskBytes + 2 * gib else {
            throw fail("insufficient_disk", "Free filesystem space must cover the entire disk plus 2 GiB reserve.")
        }
    }
    func createFile(_ name: String) throws -> Int32 {
        try verifyPath()
        let file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw fail("exclusive_create", "Cannot exclusively create output; existing files are never overwritten.") }
        return file
    }
    func writeNew(_ name: String, _ data: Data) throws {
        let file = try createFile(name)
        defer { close(file) }
        try data.withUnsafeBytes { buffer in
            var count = 0
            while count < buffer.count {
                let result = Darwin.write(file, buffer.baseAddress!.advanced(by: count), buffer.count - count)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { throw fail("filesystem", "Output write failed; leave staging quarantined.") }
                count += result
            }
        }
        guard fsync(file) == 0 else { throw fail("filesystem", "Output sync failed; leave staging quarantined.") }
    }
    func claim() throws {
        try checkEmpty()
        // Persistent O_EXCL claim serializes cooperating invocations, including across crashes.
        try writeNew(claimName, Data("CleanVMInstaller schema 1; do not reuse this staging directory.\n".utf8))
        guard try entries() == [claimName] else { throw fail("staging_changed", "Staging changed during exclusive claim.") }
    }
    func createDisk(bytes: UInt64) throws {
        let disk = try createFile("disk.img")
        defer { close(disk) }
        guard ftruncate(disk, off_t(bytes)) == 0, fsync(disk) == 0 else {
            throw fail("filesystem", "Cannot size/sync new sparse raw disk; leave staging quarantined.")
        }
    }
    func url(_ name: String) -> URL { URL(fileURLWithPath: path, isDirectory: true).appendingPathComponent(name) }
    func verifyRegular(_ name: String) throws {
        try verifyPath()
        var info = stat()
        guard fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1, info.st_uid == getuid() else {
            throw fail("unsafe_output", "Output is not a private, singly linked regular file.")
        }
    }
    func syncDirectory() throws {
        guard fsync(fd) == 0 else { throw fail("filesystem", "Staging directory sync failed.") }
    }
}

@MainActor
private final class ProgressReporter {
    var active = true
    private var lastPercent = -1
    func report(_ fraction: Double) {
        guard active, fraction.isFinite else { return }
        let percent = Int(min(1, max(0, fraction)) * 100)
        guard percent != lastPercent else { return }
        lastPercent = percent
        emit(["event": "progress", "phase": "install", "percent": percent])
    }
}

@MainActor
private func imageJSON(_ image: VZMacOSRestoreImage, event: String) -> [String: Any] {
    let version = image.operatingSystemVersion
    let requirements = image.mostFeaturefulSupportedConfiguration
    var result: [String: Any] = [
        "schemaVersion": 1, "event": event,
        "macOSVersion": "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
        "operatingSystemVersion": ["major": version.majorVersion, "minor": version.minorVersion, "patch": version.patchVersion],
        "buildVersion": image.buildVersion,
        "supported": image.isSupported && requirements?.hardwareModel.isSupported == true,
        "minimumCPUCount": requirements.map { $0.minimumSupportedCPUCount } as Any? ?? NSNull(),
        "minimumMemorySize": requirements.map { $0.minimumSupportedMemorySize } as Any? ?? NSNull(),
        "hardwareModel": requirements.map { $0.hardwareModel.dataRepresentation.base64EncodedString() } as Any? ?? NSNull(),
        "hostLimits": [
            "minimumCPUCount": VZVirtualMachineConfiguration.minimumAllowedCPUCount,
            "maximumCPUCount": VZVirtualMachineConfiguration.maximumAllowedCPUCount,
            "minimumMemorySize": VZVirtualMachineConfiguration.minimumAllowedMemorySize,
            "maximumMemorySize": VZVirtualMachineConfiguration.maximumAllowedMemorySize,
            "activeProcessorCount": ProcessInfo.processInfo.activeProcessorCount,
            "physicalMemory": ProcessInfo.processInfo.physicalMemory
        ]
    ]
    if event == "latest" { result["url"] = image.url.absoluteString }
    return result
}

@MainActor
private func create(_ options: Options, image: VZMacOSRestoreImage, local: LocalImage) async throws {
    guard VZVirtualMachine.isSupported, image.isSupported,
          let requirements = image.mostFeaturefulSupportedConfiguration, requirements.hardwareModel.isSupported else {
        throw fail("unsupported_ipsw", "Restore image has no supported hardware model on this host.")
    }
    let memory = options.memoryGiB * gib
    let disk = options.diskGiB * gib
    let minimumCPU = max(requirements.minimumSupportedCPUCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount)
    let maximumCPU = min(VZVirtualMachineConfiguration.maximumAllowedCPUCount, ProcessInfo.processInfo.activeProcessorCount)
    guard options.cpu >= minimumCPU, options.cpu <= maximumCPU else {
        throw fail("cpu_out_of_range", "Requested CPU count is outside IPSW/host limits; it will not be silently raised.")
    }
    guard memory >= max(requirements.minimumSupportedMemorySize, VZVirtualMachineConfiguration.minimumAllowedMemorySize),
          memory <= min(VZVirtualMachineConfiguration.maximumAllowedMemorySize, ProcessInfo.processInfo.physicalMemory) else {
        throw fail("memory_out_of_range", "Requested memory is outside IPSW/host limits; it will not be silently raised.")
    }
    guard options.diskGiB >= 50 else { throw fail("disk_too_small", "Helper policy requires at least 50 GiB; IPSW does not expose a disk minimum.") }
    let stage = try Stage(path: options.directory!)
    try stage.checkEmpty()
    try stage.checkCapacity(diskBytes: disk)
    try local.verifyUnchanged()
    // All resource/path/media checks above precede the first filesystem write.
    emit(["event": "validated", "cpuCount": options.cpu, "memorySize": memory, "diskSize": disk,
          "networkDeviceCount": 0, "directorySharingDeviceCount": 0, "socketDeviceCount": 0])
    try stage.claim()
    try stage.createDisk(bytes: disk)
    try stage.verifyPath()
    // Do not pass allowOverwrite. Apple refuses an already-existing auxiliary storage file.
    let auxiliary = try VZMacAuxiliaryStorage(creatingStorageAt: stage.url("nvram.bin"), hardwareModel: requirements.hardwareModel, options: [])
    try stage.verifyRegular("nvram.bin")
    let identifier = VZMacMachineIdentifier()
    let mac = VZMACAddress.randomLocallyAdministered()
    let platform = VZMacPlatformConfiguration()
    platform.hardwareModel = requirements.hardwareModel
    platform.machineIdentifier = identifier
    platform.auxiliaryStorage = auxiliary
    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = platform
    configuration.bootLoader = VZMacOSBootLoader()
    configuration.cpuCount = options.cpu
    configuration.memorySize = memory
    let graphics = VZMacGraphicsDeviceConfiguration()
    graphics.displays = [VZMacGraphicsDisplayConfiguration(widthInPixels: 1024, heightInPixels: 768, pixelsPerInch: 72)]
    configuration.graphicsDevices = [graphics]
    configuration.keyboards = [VZUSBKeyboardConfiguration()]
    configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    configuration.networkDevices = []
    configuration.directorySharingDevices = []
    configuration.socketDevices = []
    configuration.serialPorts = []
    configuration.consoleDevices = []
    configuration.audioDevices = []
    try stage.verifyRegular("disk.img")
    let attachment = try VZDiskImageStorageDeviceAttachment(url: stage.url("disk.img"), readOnly: false, cachingMode: .automatic, synchronizationMode: .full)
    configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: attachment)]
    try configuration.validate()
    guard configuration.networkDevices.isEmpty, configuration.directorySharingDevices.isEmpty, configuration.socketDevices.isEmpty else {
        throw fail("isolation", "Installation device isolation invariant failed.")
    }
    try local.verifyUnchanged()
    try stage.verifyPath()
    let machine = VZVirtualMachine(configuration: configuration)
    let installer = VZMacOSInstaller(virtualMachine: machine, restoringFromImageAt: local.url)
    let reporter = ProgressReporter()
    let observation = installer.progress.observe(\.fractionCompleted, options: [.initial, .new]) { progress, _ in
        let fraction = progress.fractionCompleted
        Task { @MainActor in reporter.report(fraction) }
    }
    defer {
        reporter.active = false
        observation.invalidate()
        withExtendedLifetime((machine, installer, local, stage)) {}
    }
    emit(["event": "installing", "networkDeviceCount": 0])
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        installer.install { result in continuation.resume(with: result) }
    }
    reporter.active = false
    // Publication is intentionally not this helper's responsibility. Only successful installs get config/receipt.
    try stage.verifyRegular("disk.img")
    try stage.verifyRegular("nvram.bin")
    let config: [String: Any] = [
        "version": 1, "os": "darwin", "arch": "arm64", "diskFormat": "raw",
        "cpuCountMin": requirements.minimumSupportedCPUCount, "cpuCount": options.cpu,
        "memorySizeMin": requirements.minimumSupportedMemorySize, "memorySize": memory,
        "ecid": identifier.dataRepresentation.base64EncodedString(),
        "hardwareModel": requirements.hardwareModel.dataRepresentation.base64EncodedString(),
        "macAddress": mac.string,
        "display": ["width": 1024, "height": 768, "unit": "px"]
    ]
    try stage.writeNew("config.json", JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys]))
    let version = image.operatingSystemVersion
    let receipt: [String: Any] = [
        "schemaVersion": 1, "status": "complete", "installer": "CleanVMInstaller",
        "macOSVersion": "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
        "buildVersion": image.buildVersion, "networkDeviceCount": 0,
        "directorySharingDeviceCount": 0, "socketDeviceCount": 0
    ]
    try stage.writeNew(".clean-vm-installer.complete.json", JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys]))
    try stage.syncDirectory()
    emit(["event": "complete", "schemaVersion": 1, "networkDeviceCount": 0])
}

@main
private struct CleanVMInstaller {
    @MainActor
    static func main() async {
        // Restrict all newly created files, including files created by Virtualization.framework.
        umask(0o077)
        do {
            let options = try Options.parse(Array(CommandLine.arguments.dropFirst()))
            if options.mode == .help {
                print("""
                CleanVMInstaller — Apple Silicon macOS IPSW clean installer (schema 1)
                --help
                --latest
                --inspect --ipsw /absolute/local/verified.ipsw
                --create --directory /absolute/private/empty-stage --ipsw /absolute/local/verified.ipsw --cpu 2 --memory-gib 4 --disk-gib 50
                --latest fetches Apple metadata only; it does not download an IPSW or create a VM.
                --inspect is read-only and emits one JSON object, including macOS version and requirements.
                --create requires a precreated empty user-owned 0700 directory; no symlinks or overwrite.
                Creation is offline at the guest-device level: zero NICs, shares, sockets or clipboard.
                CPU/memory are strict; sizes are GiB (2^30 bytes). Failed stages are never resumed or removed.
                """)
                return
            }
            if options.mode == .latest {
                let transfer: RestoreImageTransfer = try await withCheckedThrowingContinuation { continuation in
                    VZMacOSRestoreImage.fetchLatestSupported { result in
                        continuation.resume(with: result.map { RestoreImageTransfer(value: $0) })
                    }
                }
                emit(imageJSON(transfer.value, event: "latest"))
                return
            }
            let local = try LocalImage(path: options.ipsw!)
            let transfer: RestoreImageTransfer = try await withCheckedThrowingContinuation { continuation in
                VZMacOSRestoreImage.load(from: local.url) { result in
                    continuation.resume(with: result.map { RestoreImageTransfer(value: $0) })
                }
            }
            let image = transfer.value
            try local.verifyUnchanged()
            if options.mode == .inspect {
                emit(imageJSON(image, event: "inspect"))
                return
            }
            try await create(options, image: image, local: local)
        } catch let error as InstallerError {
            emit(["event": "error", "code": error.code, "message": error.message])
            exit(error.exitCode)
        } catch {
            // Do not print NSError descriptions/userInfo: those may include private local paths or URLs.
            emit(["event": "error", "code": "framework_failure", "message": "Virtualization or system operation failed; any partial staging output must remain quarantined.", "systemCode": (error as NSError).code])
            exit(1)
        }
    }
}
