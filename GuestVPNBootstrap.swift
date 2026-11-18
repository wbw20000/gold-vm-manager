import Foundation
import Darwin
import CryptoKit
import Security
import AppKit
import SystemConfiguration

// Build the production executable WITHOUT GOLD_VPN_BOOTSTRAP_FIXTURE.
// No arbitrary HOME/seed/app/path arguments or environment overrides exist there.
enum GuestVPNBootstrap {
    static let appID = "io.github.clash-verge-rev.clash-verge-rev"
    static let appVersion = "2.5.10"
    static let appTeam = "JPH3Z7PPBB"
    static let seedDirectory = "/Library/Application Support/GoldVMManager/FirstLogin"
    static let statusDirectory = "/Volumes/My Shared Files/gold-status"
    static let appPath = "/Applications/Clash Verge.app"
    static let profileUID = "GoldVMVPN"
    static let profileFile = "gold-vm-vpn.yaml"
    static let markerFile = ".gold-vm-vpn-import.json"
    static let maxBytes = 1_048_576

    enum Failure: String, Error {
        case wrongUser = "wrong_user"
        case unsafePath = "unsafe_path_or_permissions"
        case invalidSeed = "invalid_seed"
        case existingData = "existing_clash_data_manual_recovery_required"
        case partialImport = "partial_import_manual_recovery_required"
        case writeFailed = "private_write_failed"
        case invalidApplication = "signed_application_validation_failed"
    }

    struct Seed: Decodable {
        let schema_version: Int
        let expected_uid: Int
        let seed_id: String
        let app_id: String
        let app_version: String
        let app_team: String
        let receipt_enabled: Bool
        let receipt_token: String
        let documents: [String: String]
    }

    final class Directory {
        let fd: Int32
        init(_ fd: Int32) throws {
            guard fd >= 0 else { throw Failure.unsafePath }
            self.fd = fd
        }
        deinit { close(fd) }
    }

    static func hex(_ value: String, length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    static func attributes(_ fd: Int32) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw Failure.unsafePath }
        return info
    }

    static func noACL(_ fd: Int32) throws {
        errno = 0
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            // On Darwin an existing open file with no extended ACL reports
            // ENOENT. The descriptor was fstat-validated by every caller.
            guard errno == ENOENT else { throw Failure.unsafePath }
            return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        // Darwin returns 0 for an existing ACE (unlike Linux's 1), and -1 /
        // EINVAL when a valid empty ACL has no first entry. Reject every ACE.
        let result = acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        guard result == -1, errno == EINVAL else { throw Failure.unsafePath }
    }

    // The sole production group-write exception is the exact standard system
    // Applications directory. This does not apply to app bundles or user paths.
    static func standardApplicationsException(_ path: String?, _ info: stat) -> Bool {
        path == "/Applications" && info.st_mode & S_IFMT == S_IFDIR &&
            info.st_uid == 0 && info.st_gid == 80 && info.st_mode & 0o7777 == 0o775
    }

    static func checkedDirectory(_ fd: Int32, owner: uid_t?, privateMode: Bool, systemPath: String? = nil) throws -> Directory {
        let directory = try Directory(fd)
        let info = try attributes(fd)
        let standardApplications = owner == 0 && !privateMode && standardApplicationsException(systemPath, info)
        #if GOLD_VPN_BOOTSTRAP_FIXTURE
        let safeParentMode = info.st_mode & 0o022 == 0 || standardApplications || (info.st_uid == 0 && info.st_mode & 0o1777 == 0o1777)
        #else
        let safeParentMode = info.st_mode & 0o022 == 0 || standardApplications
        #endif
        guard info.st_mode & S_IFMT == S_IFDIR, safeParentMode,
              owner == nil || info.st_uid == owner else { throw Failure.unsafePath }
        if privateMode {
            guard info.st_mode & 0o7777 == 0o700 else { throw Failure.unsafePath }
            try noACL(fd)
        }
        return directory
    }

    // Component-by-component O_NOFOLLOW also rejects symlinked ancestors.
    static func openAbsoluteDirectory(_ path: String, owner: uid_t?, privateMode: Bool) throws -> Directory {
        guard path.hasPrefix("/"), !path.contains("\0"), !path.hasSuffix("/"),
              path.split(separator: "/").allSatisfy({ $0 != "." && $0 != ".." }) else { throw Failure.unsafePath }
        var directory = try checkedDirectory(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), owner: 0, privateMode: false)
        let components = path.split(separator: "/").map(String.init)
        for (index, component) in components.enumerated() {
            let last = index == components.count - 1
            let next = openat(directory.fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let systemPath = last && components.count == 1 && path == "/Applications" ? path : nil
            directory = try checkedDirectory(next, owner: last ? owner : nil, privateMode: last && privateMode, systemPath: systemPath)
            let info = try attributes(directory.fd)
            guard info.st_uid == 0 || info.st_uid == getuid() else { throw Failure.unsafePath }
        }
        return directory
    }

    static func childDirectory(_ parent: Directory, _ name: String, create: Bool, owner: uid_t) throws -> Directory {
        if create {
            guard mkdirat(parent.fd, name, 0o700) == 0 else { throw Failure.partialImport }
        }
        return try checkedDirectory(openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), owner: owner, privateMode: true)
    }

    static func userApplicationSupport(_ library: Directory, owner: uid_t) throws -> Directory {
        // Caller opens only the existing trusted user's Library through verified
        // home dirfds. Neither HOME, Library nor arbitrary parents are created.
        let parent = try attributes(library.fd)
        guard parent.st_mode & S_IFMT == S_IFDIR, parent.st_uid == owner,
              parent.st_mode & 0o022 == 0, owner == getuid() else { throw Failure.unsafePath }
        let existing = openat(library.fd, "Application Support", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if existing >= 0 {
            // Preserve the old ownership/mode requirements; never chmod it.
            return try checkedDirectory(existing, owner: owner, privateMode: false)
        }
        guard errno == ENOENT else { throw Failure.unsafePath }
        // EEXIST/races, symlinks and partial failures are refused, not repaired.
        guard mkdirat(library.fd, "Application Support", 0o700) == 0 else { throw Failure.unsafePath }
        let created = try checkedDirectory(openat(library.fd, "Application Support", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), owner: owner, privateMode: true)
        guard fsync(created.fd) == 0, fsync(library.fd) == 0 else { throw Failure.writeFailed }
        return created
    }

    static func readPrivate(_ parent: Directory, _ name: String, owner: uid_t) throws -> Data {
        let fd = openat(parent.fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.unsafePath }
        defer { close(fd) }
        let info = try attributes(fd)
        guard info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o7777 == 0o600,
              info.st_uid == owner, info.st_nlink == 1,
              info.st_size > 0, info.st_size <= maxBytes else { throw Failure.unsafePath }
        try noACL(fd)
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let amount = read(fd, &buffer, buffer.count)
            if amount < 0 {
                if errno == EINTR { continue }
                throw Failure.unsafePath
            }
            if amount == 0 { break }
            guard result.count + amount <= maxBytes else { throw Failure.invalidSeed }
            result.append(contentsOf: buffer.prefix(amount))
        }
        let after = try attributes(fd)
        guard after.st_size == info.st_size, after.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec,
              result.count == Int(info.st_size) else { throw Failure.unsafePath }
        return result
    }

    static func writeExclusive(_ parent: Directory, _ name: String, _ bytes: Data) throws {
        guard !bytes.isEmpty, bytes.count <= maxBytes, !name.contains("/"), name != ".", name != ".." else { throw Failure.writeFailed }
        let fd = openat(parent.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.writeFailed }
        defer { close(fd) }
        let info = try attributes(fd)
        guard info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o7777 == 0o600,
              info.st_uid == getuid(), info.st_nlink == 1 else { throw Failure.unsafePath }
        try noACL(fd)
        try bytes.withUnsafeBytes { raw in
            guard let start = raw.baseAddress else { throw Failure.writeFailed }
            var count = 0
            while count < raw.count {
                let written = write(fd, start.advanced(by: count), raw.count - count)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw Failure.writeFailed }
                count += written
            }
        }
        guard fsync(fd) == 0 else { throw Failure.writeFailed }
    }

    static func json(_ value: Any) throws -> Data {
        guard JSONSerialization.isValidJSONObject(value) else { throw Failure.invalidSeed }
        return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    static func same(_ lhs: Any, _ rhs: Any) throws -> Bool {
        try json(lhs) == json(rhs)
    }

    static func policy() -> [String: Any] {
        ["mixed-port": 7890, "allow-lan": false, "bind-address": "127.0.0.1",
         "mode": "rule", "log-level": "silent", "ipv6": false, "external-controller": "",
         "profile": ["store-selected": false, "store-fake-ip": false],
         "tun": ["enable": true, "stack": "gvisor", "auto-route": true,
                 "strict-route": true, "auto-detect-interface": true,
                 "dns-hijack": ["any:53", "tcp://any:53"], "mtu": 1500],
         "dns": ["enable": true, "listen": "127.0.0.1:1053", "ipv6": false,
                 "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                 "fake-ip-filter": [String](), "use-hosts": false, "use-system-hosts": false,
                 "respect-rules": true, "nameserver": ["https://1.1.1.1/dns-query#PROXY"],
                 "default-nameserver": ["https://1.1.1.1/dns-query#PROXY"],
                 "proxy-server-nameserver": ["https://1.1.1.1/dns-query#PROXY"],
                 "direct-nameserver": [String](), "fallback": [String]()]]
    }

    static func verge() -> [String: Any] {
        ["clash_core": "verge-mihomo", "app_log_level": "silent",
         "enable_tun_mode": true, "enable_system_proxy": true, "enable_dns_settings": false,
         "profile_dns_settings": [profileUID: ["enabled": false]],
         "enable_external_controller": false, "enable_builtin_enhanced": false,
         "enable_auto_launch": false, "enable_silent_start": false,
         "verge_mixed_port": 7897, "verge_socks_enabled": false,
         "verge_http_enabled": false, "verge_redir_enabled": false,
         "proxy_host": "127.0.0.1", "proxy_auto_config": false,
         "enable_proxy_guard": false, "enable_bypass_check": false,
         "use_default_bypass": false, "system_proxy_bypass": "",
         "auto_check_update": false, "enable_auto_delay_detection": false,
         "enable_auto_backup_schedule": false, "auto_backup_on_change": false]
    }

    static func profiles() -> [String: Any] {
        ["current": profileUID, "items": [["uid": profileUID, "type": "local", "name": "Guest VPN",
          "file": profileFile, "updated": 0, "option": ["allow_auto_update": false]]]]
    }

    static func publicIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets = [UInt32]()
        for part in parts {
            guard let value = UInt32(part), value <= 255, String(value) == part else { return false }
            octets.append(value)
        }
        let ip = octets.reduce(UInt32(0)) { ($0 << 8) | $1 }
        let blocked: [(UInt32, UInt32)] = [
            (0x00000000, 0xff000000), (0x0a000000, 0xff000000), (0x64400000, 0xffc00000),
            (0x7f000000, 0xff000000), (0xa9fe0000, 0xffff0000), (0xac100000, 0xfff00000),
            (0xc0000000, 0xffffff00), (0xc0000200, 0xffffff00), (0xc0586300, 0xffffff00),
            (0xc0a80000, 0xffff0000), (0xc6120000, 0xfffe0000), (0xc6336400, 0xffffff00),
            (0xcb007100, 0xffffff00), (0xe0000000, 0xe0000000)]
        return !blocked.contains { ip & $0.1 == $0.0 }
    }

    static func validateNodes(_ nodes: [[String: Any]]) throws {
        guard (1...16).contains(nodes.count) else { throw Failure.invalidSeed }
        let common: Set<String> = ["name", "type", "server", "port", "udp"]
        let tls: Set<String> = ["skip-cert-verify", "alpn", "client-fingerprint"]
        let options: [String: Set<String>] = [
            "tuic": common.union(["uuid", "password", "sni", "disable-sni", "reduce-rtt", "congestion-controller", "udp-relay-mode", "request-timeout", "heartbeat-interval", "max-udp-relay-packet-size", "alpn", "skip-cert-verify"]),
            "vless": common.union(tls).union(["uuid", "tls", "network", "servername", "flow", "reality-opts", "packet-encoding"]),
            "trojan": common.union(tls).union(["password", "sni", "network"]),
            "ss": common.union(["cipher", "password"]),
            "hysteria2": common.union(["password", "sni", "skip-cert-verify", "alpn", "up", "down", "obfs", "obfs-password"])]
        for (index, node) in nodes.enumerated() {
            guard let kind = node["type"] as? String, let allowed = options[kind],
                  Set(node.keys).isSubset(of: allowed), node["name"] as? String == "proxy-\(index + 1)",
                  let server = node["server"] as? String, publicIPv4(server),
                  let port = node["port"] as? NSNumber, CFGetTypeID(port) != CFBooleanGetTypeID(),
                  (1...65535).contains(port.intValue), port.doubleValue == Double(port.intValue), port.intValue != 53,
                  let udp = node["udp"] as? NSNumber, CFGetTypeID(udp) == CFBooleanGetTypeID() else { throw Failure.invalidSeed }
            if kind != "ss" {
                guard try same(["verify": node["skip-cert-verify"] as Any], ["verify": false]) else { throw Failure.invalidSeed }
            } else {
                guard ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"].contains(node["cipher"] as? String ?? "") else { throw Failure.invalidSeed }
            }
            if kind == "vless" {
                guard try same(["tls": node["tls"] as Any], ["tls": true]), node["network"] as? String == "tcp" else { throw Failure.invalidSeed }
                if let reality = node["reality-opts"] {
                    guard let value = reality as? [String: String], Set(value.keys) == ["public-key", "short-id"] else { throw Failure.invalidSeed }
                }
            }
            if kind == "trojan", node["network"] as? String != "tcp" { throw Failure.invalidSeed }
            if kind == "tuic" {
                guard try same(["disabled": node["disable-sni"] as Any], ["disabled": false]) else { throw Failure.invalidSeed }
            }
            // Reject structures hidden under scalar options: no nested directives.
            for (key, value) in node where key != "reality-opts" && key != "alpn" {
                guard value is String || value is NSNumber else { throw Failure.invalidSeed }
            }
            if let alpn = node["alpn"], !(alpn is [String]) { throw Failure.invalidSeed }
        }
    }

    static func parseSeed(_ bytes: Data) throws -> Seed {
        guard bytes.count <= maxBytes,
              let root = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(root.keys) == ["schema_version", "expected_uid", "seed_id", "app_id", "app_version", "app_team", "receipt_enabled", "receipt_token", "documents"] else { throw Failure.invalidSeed }
        let seed = try JSONDecoder().decode(Seed.self, from: bytes)
        guard seed.schema_version == 1, seed.expected_uid == 501,
              seed.app_id == appID, seed.app_version == appVersion, seed.app_team == appTeam,
              hex(seed.seed_id, length: 32), hex(seed.receipt_token, length: 64),
              Set(seed.documents.keys) == ["config.yaml", "verge.yaml", "profiles.yaml", "profiles/" + profileFile] else { throw Failure.invalidSeed }
        var documents = [String: [String: Any]]()
        for (name, text) in seed.documents {
            guard text.utf8.count <= 262144,
                  let value = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { throw Failure.invalidSeed }
            documents[name] = value
        }
        guard var profile = documents["profiles/" + profileFile],
              let nodes = profile.removeValue(forKey: "proxies") as? [[String: Any]],
              let groups = profile.removeValue(forKey: "proxy-groups"),
              let rules = profile.removeValue(forKey: "rules"),
              try same(["rules": rules], ["rules": ["MATCH,PROXY"]]),
              try same(["groups": groups], ["groups": [["name": "PROXY", "type": "select", "proxies": nodes.indices.map { "proxy-\($0 + 1)" }]]]),
              try same(profile, policy()) else { throw Failure.invalidSeed }
        try validateNodes(nodes)
        var expectedOwned = policy()
        expectedOwned["mixed-port"] = 7897
        expectedOwned["external-controller-cors"] = ["allow-origins": [String](), "allow-private-network": false]
        guard var owned = documents["config.yaml"], let secret = owned.removeValue(forKey: "secret") as? String,
              hex(secret, length: 64), try same(owned, expectedOwned),
              try same(documents["verge.yaml"] as Any, verge()),
              try same(documents["profiles.yaml"] as Any, profiles()) else { throw Failure.invalidSeed }
        return seed
    }

    static func seedDigest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func importConfiguration(seed: Seed, digest: String, applicationSupport: Directory, owner: uid_t) throws -> Bool {
        var existing = stat()
        if fstatat(applicationSupport.fd, appID, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFDIR else { throw Failure.existingData }
            let old = try childDirectory(applicationSupport, appID, create: false, owner: owner)
            guard let marker = try JSONSerialization.jsonObject(with: readPrivate(old, markerFile, owner: owner)) as? [String: Any],
                  try same(marker, ["schema_version": 1, "seed_sha256": digest]) else { throw Failure.existingData }
            return false // Same exact seed: no rewrites, relaunch, cleanup or status changes.
        }
        guard errno == ENOENT else { throw Failure.unsafePath }
        let stagingName = ".gold-vpn-import-" + seed.seed_id
        let staging = try childDirectory(applicationSupport, stagingName, create: true, owner: owner)
        // On ANY partial failure retain the private staging directory for manual
        // recovery. Never recursively remove or merge someone else's app data.
        let profilesDirectory = try childDirectory(staging, "profiles", create: true, owner: owner)
        for name in ["config.yaml", "verge.yaml", "profiles.yaml"] {
            guard let text = seed.documents[name] else { throw Failure.invalidSeed }
            try writeExclusive(staging, name, Data(text.utf8))
        }
        guard let profile = seed.documents["profiles/" + profileFile] else { throw Failure.invalidSeed }
        try writeExclusive(profilesDirectory, profileFile, Data(profile.utf8))
        try writeExclusive(staging, markerFile, json(["schema_version": 1, "seed_sha256": digest]))
        guard fsync(profilesDirectory.fd) == 0, fsync(staging.fd) == 0 else { throw Failure.writeFailed }
        guard renameatx_np(applicationSupport.fd, stagingName, applicationSupport.fd, appID, UInt32(RENAME_EXCL)) == 0 else { throw Failure.existingData }
        guard fsync(applicationSupport.fd) == 0 else { throw Failure.writeFailed }
        return true
    }

    static func status(_ importState: String, _ appState: String) -> [String: Any] {
        // No credential, node, seed, token, original error, URL or user metadata.
        ["schema_version": 1, "evidence": "guest_reported", "configuration": importState,
         "application": appState, "system_authorization": "user_action_may_be_required",
         "connection_check": "not_run", "host_independently_verified": false]
    }

    static func writeStatus(_ directory: Directory, name: String, value: [String: Any], replace: Bool) throws {
        var info = stat()
        if fstatat(directory.fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 {
            guard replace, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
                  info.st_mode & 0o7777 == 0o600, info.st_nlink == 1 else { throw Failure.unsafePath }
        } else if errno != ENOENT { throw Failure.unsafePath }
        let temporary = ".status-" + UUID().uuidString.lowercased()
        try writeExclusive(directory, temporary, json(value))
        let result = renameatx_np(directory.fd, temporary, directory.fd, name, replace ? 0 : UInt32(RENAME_EXCL))
        guard result == 0, fsync(directory.fd) == 0 else { throw Failure.writeFailed }
    }

    static func record(_ seed: Seed, seedDirectory: Directory, importState: String, appState: String, fixtureReceipt: Directory? = nil) {
        let value = status(importState, appState)
        try? writeStatus(seedDirectory, name: "status.json", value: value, replace: true)
        guard seed.receipt_enabled else { return }
        // Receipt write is best effort and never widens permissions or creates a
        // shared directory. Parent must provision this one dedicated VM share.
        #if GOLD_VPN_BOOTSTRAP_FIXTURE
        guard let target = fixtureReceipt else { return }
        #else
        guard let target = try? openAbsoluteDirectory(statusDirectory, owner: 501, privateMode: true) else { return }
        #endif
        try? writeStatus(target, name: seed.receipt_token + ".json", value: value, replace: true)
    }

    #if !GOLD_VPN_BOOTSTRAP_FIXTURE
    static func consoleHome() throws -> String {
        guard getuid() == 501, geteuid() == 501 else { throw Failure.wrongUser }
        var consoleUID: uid_t = 0
        var consoleGID: gid_t = 0
        guard let console = SCDynamicStoreCopyConsoleUser(nil, &consoleUID, &consoleGID) as String?,
              consoleUID == 501, console != "loginwindow", console != "_mbsetupuser",
              let entry = getpwuid(501), let homePointer = entry.pointee.pw_dir else { throw Failure.wrongUser }
        let home = String(cString: homePointer)
        let parts = home.split(separator: "/")
        guard parts.count == 2, parts[0] == "Users", parts[1] != "Shared" else { throw Failure.unsafePath }
        return home
    }

    static func validateApplication() throws {
        let applications = try openAbsoluteDirectory("/Applications", owner: 0, privateMode: false)
        let bundleDirectory = try checkedDirectory(openat(applications.fd, "Clash Verge.app", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), owner: 0, privateMode: false)
        _ = bundleDirectory
        let url = URL(fileURLWithPath: appPath, isDirectory: true)
        var code: SecStaticCode?
        var requirement: SecRequirement?
        let rule = "anchor apple generic and identifier \"\(appID)\" and certificate leaf[subject.OU] = \"\(appTeam)\""
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &code) == errSecSuccess,
              SecRequirementCreateWithString(rule as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let code, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode), requirement) == errSecSuccess,
              let bundle = Bundle(url: url), bundle.bundleIdentifier == appID,
              bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == appVersion else { throw Failure.invalidApplication }
    }

    static func openGUI() -> String {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.createsNewApplicationInstance = false
        var finished = false
        var state = "launch_request_pending"
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: appPath), configuration: configuration) { app, error in
            state = app != nil && error == nil ? "opened" : "launch_failed_or_authorization_pending"
            finished = true
        }
        let deadline = Date().addingTimeInterval(30)
        while !finished && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        return state
    }

    static func production() throws {
        guard CommandLine.arguments.count == 1 else { throw Failure.unsafePath }
        let home = try consoleHome()
        let source = try openAbsoluteDirectory(seedDirectory, owner: 501, privateMode: true)
        let bytes = try readPrivate(source, "seed.json", owner: 501)
        let seed = try parseSeed(bytes)
        let homeDirectory = try openAbsoluteDirectory(home, owner: 501, privateMode: false)
        // Existing standard user directories may be 0755, but never writable by
        // another user. They are not chmodded, replaced, or inferred from HOME.
        let library = try checkedDirectory(openat(homeDirectory.fd, "Library", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), owner: 501, privateMode: false)
        let support = try userApplicationSupport(library, owner: 501)
        do {
            let changed = try importConfiguration(seed: seed, digest: seedDigest(bytes), applicationSupport: support, owner: 501)
            guard changed else { return }
            record(seed, seedDirectory: source, importState: "imported", appState: "not_started")
            try validateApplication()
            record(seed, seedDirectory: source, importState: "imported", appState: openGUI())
        } catch {
            // Never log/serialize error descriptions. A marker may prove import
            // succeeded even when signed-app launch validation failed.
            let state = error as? Failure == .invalidApplication ? "imported" : "manual_recovery_required"
            record(seed, seedDirectory: source, importState: state, appState: "not_started")
            throw error
        }
    }
    #else
    static func fixtureApplicationsPolicy() throws {
        // Synthetic stat values only: never inspect/chown/chmod host Applications.
        var info = stat()
        info.st_uid = 0; info.st_gid = 80; info.st_mode = mode_t(S_IFDIR) | 0o775
        guard standardApplicationsException("/Applications", info) else { throw Failure.unsafePath }
        for path in [nil, "/Applications/", "/Applications/Clash Verge.app", "/Users/test/Applications", "/Library/Application Support"] as [String?] {
            guard !standardApplicationsException(path, info) else { throw Failure.unsafePath }
        }
        for owner in [501, 502] as [uid_t] {
            info.st_uid = owner
            guard !standardApplicationsException("/Applications", info) else { throw Failure.unsafePath }
        }
        info.st_uid = 0
        for group in [0, 20, 81] as [gid_t] {
            info.st_gid = group
            guard !standardApplicationsException("/Applications", info) else { throw Failure.unsafePath }
        }
        info.st_gid = 80
        for mode in [0o755, 0o777, 0o757, 0o770, 0o2775, 0o4775] as [mode_t] {
            info.st_mode = mode_t(S_IFDIR) | mode
            guard !standardApplicationsException("/Applications", info) else { throw Failure.unsafePath }
        }
        info.st_mode = mode_t(S_IFLNK) | 0o775
        guard !standardApplicationsException("/Applications", info) else { throw Failure.unsafePath }
        print("fixture_applications_policy_ok")
    }

    static func fixture() throws {
        guard CommandLine.arguments.count == 3,
              ["--fixture", "--fixture-user-library", "--fixture-applications-policy"].contains(CommandLine.arguments[1]) else { throw Failure.unsafePath }
        let root = CommandLine.arguments[2]
        guard root.hasPrefix("/private/tmp/gold-vpn-bootstrap-tests-"),
              root.split(separator: "/").count == 3 else { throw Failure.unsafePath }
        // This override does not exist in production and cannot launch apps or
        // use the real seed, HOME, receipt share, Setup Assistant or the network.
        let source = try openAbsoluteDirectory(root, owner: getuid(), privateMode: true)
        if CommandLine.arguments[1] == "--fixture-applications-policy" {
            try fixtureApplicationsPolicy()
            return
        }
        let bytes = try readPrivate(source, "seed.json", owner: getuid())
        let seed = try parseSeed(bytes)
        let home = try childDirectory(source, "home", create: false, owner: getuid())
        let support: Directory
        if CommandLine.arguments[1] == "--fixture-user-library" {
            let library = try checkedDirectory(openat(home.fd, "Library", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), owner: getuid(), privateMode: false)
            support = try userApplicationSupport(library, owner: getuid())
        } else {
            support = home
        }
        let receipt = try? childDirectory(source, "receipt", create: false, owner: getuid())
        let changed = try importConfiguration(seed: seed, digest: seedDigest(bytes), applicationSupport: support, owner: getuid())
        if changed {
            record(seed, seedDirectory: source, importState: "imported", appState: "not_started_fixture", fixtureReceipt: receipt)
        }
        print(changed ? "fixture_imported" : "fixture_same_seed_noop")
    }
    #endif
}

@main
struct Main {
    static func main() {
        umask(0o077)
        do {
            #if GOLD_VPN_BOOTSTRAP_FIXTURE
            try GuestVPNBootstrap.fixture()
            #else
            try GuestVPNBootstrap.production()
            #endif
        } catch {
            // Production emits only a constant exit status, never raw errors.
            #if GOLD_VPN_BOOTSTRAP_FIXTURE
            print("fixture_failure:" + ((error as? GuestVPNBootstrap.Failure)?.rawValue ?? "invalid_seed"))
            #endif
            exit(2)
        }
    }
}
