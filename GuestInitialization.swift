import AppKit
import ApplicationServices
import ScreenCaptureKit
import Vision
import CoreGraphics

/// Compile into the native AppKit process. Never send Credentials through a web bridge.
/// macOS 14+ APIs only: this does NOT use macOS 27 VZGuestProvisioningOptions.
@MainActor
public final class GuestInitializationDriver {
    public struct Profile: Codable {
        public var version: Int
        public var language: String
        public var country: String
        public var timezone: String
        public var location_services: Bool
        public var skip_migration: Bool
        public var skip_apple_account: Bool
        public var share_analytics: Bool
        public var allow_license_agreement: Bool

        public init(version: Int = 1, language: String = "en-US", country: String,
                    timezone: String, location_services: Bool = false,
                    skip_migration: Bool = true, skip_apple_account: Bool = true,
                    share_analytics: Bool = false, allow_license_agreement: Bool = false) {
            self.version = version; self.language = language; self.country = country
            self.timezone = timezone; self.location_services = location_services
            self.skip_migration = skip_migration; self.skip_apple_account = skip_apple_account
            self.share_analytics = share_analytics
            self.allow_license_agreement = allow_license_agreement
        }
        private enum CodingKeys: String, CodingKey {
            case version, language, country, timezone, location_services, skip_migration
            case skip_apple_account, share_analytics, allow_license_agreement
        }
        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decode(Int.self, forKey: .version)
            language = try c.decode(String.self, forKey: .language)
            country = try c.decode(String.self, forKey: .country)
            timezone = try c.decode(String.self, forKey: .timezone)
            location_services = try c.decode(Bool.self, forKey: .location_services)
            skip_migration = try c.decode(Bool.self, forKey: .skip_migration)
            skip_apple_account = try c.decode(Bool.self, forKey: .skip_apple_account)
            share_analytics = try c.decode(Bool.self, forKey: .share_analytics)
            allow_license_agreement = try c.decodeIfPresent(Bool.self, forKey: .allow_license_agreement) ?? false
        }
    }

    /// Not Codable, not a URL/argument payload, not a logging/description object.
    /// clear() drops this object's references; Swift cannot guarantee forensic RAM erasure.
    public final class Credentials {
        public private(set) var fullname: String
        public private(set) var username: String
        public private(set) var password: String
        public init(fullname: String, username: String, password: String) {
            self.fullname = fullname; self.username = username; self.password = password
        }
        public func clear() { fullname = ""; username = ""; password = "" }
    }

    public enum StopReason: String {
        case busy, invalid_profile, unsupported_language, unsupported_credentials
        case accessibility_permission_required, screen_recording_permission_required
        case target_not_unique, target_not_frontmost, target_changed, target_obscured
        case capture_failed, unknown_page, transition_timeout, operation_timeout
        case existing_login_or_lock_screen, disk_security_requires_user
        case license_consent_required, checkbox_state_requires_user
        case country_not_visible, timezone_requires_manual_selection
        case keyboard_verification_failed, account_form_not_verified, account_readback_failed
        case unsupported_control, input_interrupted
    }
    public enum Result {
        case stopped(StopReason)
        case cancelled
        /// Desktop detected, NOT a configured/ready VM. No timezone/profile claim.
        case desktop_ready_requires_profile_apply
        public var code: String {
            switch self {
            case .stopped(let reason): return reason.rawValue
            case .cancelled: return "cancelled"
            case .desktop_ready_requires_profile_apply: return "desktop_ready_requires_profile_apply"
            }
        }
    }

    private static let tartPath = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/tart.app/Contents/MacOS/tart").path
    private var task: Task<Void, Never>?
    private var credentials: Credentials?
    private var statusCallback: ((String, String) -> Void)?
    private var completionCallback: ((Result) -> Void)?
    private var target: Target?
    private var generation = UUID()
    public init() {}

    public func start(vmName: String, profile: Profile, credentials: Credentials,
                      status: @escaping (String, String) -> Void,
                      completion: @escaping (Result) -> Void) {
        guard task == nil else {
            if self.credentials !== credentials { credentials.clear() }
            completion(.stopped(.busy)); return
        }
        self.credentials = credentials; statusCallback = status; completionCallback = completion
        generation = UUID()
        let token = generation
        task = Task { [weak self] in
            guard let self else { credentials.clear(); return }
            do {
                try self.validate(profile: profile, credentials: credentials)
                guard !vmName.isEmpty, vmName.count <= 200 else { throw StopReason.invalid_profile }
                guard AXIsProcessTrusted() else { throw StopReason.accessibility_permission_required }
                guard CGPreflightScreenCaptureAccess() else { throw StopReason.screen_recording_permission_required }
                self.target = try await self.discover(vmName: vmName)
                self.report("waiting", "bring_exact_vm_window_frontmost")
                try await self.awaitInitialFocus()
                self.report("running", "visible_setup_automation_started")
                try await self.run(profile: profile, credentials: credentials)
                self.finish(.desktop_ready_requires_profile_apply, token: token)
            } catch is CancellationError {
                self.finish(.cancelled, token: token)
            } catch let reason as StopReason {
                self.finish(.stopped(reason), token: token)
            } catch {
                // Never propagate NSError descriptions, OCR, VM names, or credential values.
                self.finish(.stopped(.capture_failed), token: token)
            }
        }
    }

    public func cancel() {
        guard task != nil else { return }
        task?.cancel()
        // Immediate clearing, even if an OS capture call has not yet returned.
        finish(.cancelled, token: generation)
    }

    private func finish(_ result: Result, token: UUID) {
        guard token == generation else { return }
        generation = UUID()
        credentials?.clear(); credentials = nil; target = nil
        let completion = completionCallback
        let status = statusCallback
        completionCallback = nil; statusCallback = nil; task = nil
        status?("finished", result.code)
        completion?(result)
    }
    private func report(_ phase: String, _ code: String) { statusCallback?(phase, code) }
    private func validate(profile: Profile, credentials: Credentials) throws {
        guard profile.version == 1,
              profile.country.count == 2, profile.country == profile.country.uppercased(),
              Locale.Region.isoRegions.contains(where: { $0.identifier == profile.country }),
              TimeZone.knownTimeZoneIdentifiers.contains(profile.timezone),
              !profile.location_services, profile.skip_migration,
              profile.skip_apple_account, !profile.share_analytics else { throw StopReason.invalid_profile }
        // Deliberately not pretending that en-GB / Chinese / other pages are calibrated.
        guard profile.language == "en-US" else { throw StopReason.unsupported_language }
        let ascii: (String) -> Bool = { !$0.isEmpty && $0.utf8.allSatisfy { $0 >= 32 && $0 <= 126 } }
        guard ascii(credentials.fullname), credentials.fullname.count <= 60,
              ascii(credentials.password), (4...128).contains(credentials.password.count),
              (1...32).contains(credentials.username.count),
              credentials.username.first?.isASCII == true,
              credentials.username.first?.isLetter == true,
              credentials.username.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }),
              credentials.fullname == credentials.fullname.trimmingCharacters(in: .whitespaces),
              credentials.password == credentials.password.trimmingCharacters(in: .whitespaces)
        else { throw StopReason.unsupported_credentials }
    }

    private struct Target {
        let pid: pid_t
        let windowID: CGWindowID
        let title: String
        let launchDate: Date
        let initialBounds: CGRect
    }
    private func discover(vmName: String) async throws -> Target {
        let apps = NSWorkspace.shared.runningApplications.filter {
            $0.executableURL?.standardizedFileURL.path == Self.tartPath
        }
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
        let candidates = content.windows.filter { w in
            w.title == vmName && apps.contains(where: { $0.processIdentifier == w.owningApplication?.processID })
        }
        guard candidates.count == 1, let w = candidates.first,
              w.isOnScreen, w.windowLayer == 0, w.frame.width >= 640, w.frame.height >= 480,
              let app = apps.first(where: { $0.processIdentifier == w.owningApplication?.processID }),
              let launched = app.launchDate else { throw StopReason.target_not_unique }
        return Target(pid: app.processIdentifier, windowID: w.windowID, title: vmName,
                      launchDate: launched, initialBounds: w.frame)
    }
    private func awaitInitialFocus() async throws {
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline {
            do { try guardTarget(); return }
            catch StopReason.target_not_frontmost { /* Initial native-sheet handoff only; no input. */ }
            catch StopReason.target_obscured { /* User may bring the exact window forward. */ }
            try await delay(0.25)
        }
        throw StopReason.target_not_frontmost
    }
    private func windowInfo() throws -> [[String: Any]] {
        guard let rows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID)
                as? [[String: Any]] else { throw StopReason.target_changed }
        return rows
    }
    private func bounds(_ row: [String: Any]) -> CGRect? {
        guard let d = row[kCGWindowBounds as String] as? NSDictionary else { return nil }
        return CGRect(dictionaryRepresentation: d)
    }
    private func axValue(_ element: AXUIElement, _ attribute: CFString) -> CFTypeRef? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute, &value) == .success else { return nil }
        return value
    }
    /// Before every individual event, including key-up. No activation and no global post().
    private func guardTarget() throws {
        try Task.checkCancellation()
        guard let t = target,
              let app = NSRunningApplication(processIdentifier: t.pid), !app.isTerminated,
              app.executableURL?.standardizedFileURL.path == Self.tartPath,
              app.launchDate == t.launchDate else { throw StopReason.target_changed }
        guard NSWorkspace.shared.frontmostApplication?.processIdentifier == t.pid,
              !app.isHidden else { throw StopReason.target_not_frontmost }
        var count: UInt32 = 0
        guard CGGetActiveDisplayList(0, nil, &count) == .success, count > 0 else { throw StopReason.target_changed }
        var displays = [CGDirectDisplayID](repeating: 0, count: Int(count))
        guard CGGetActiveDisplayList(count, &displays, &count) == .success,
              displays.contains(where: { CGDisplayBounds($0).contains(t.initialBounds) }) else { throw StopReason.target_obscured }
        let tartPIDs = Set(NSWorkspace.shared.runningApplications.filter {
            $0.executableURL?.standardizedFileURL.path == Self.tartPath
        }.map(\.processIdentifier))
        guard let all = CGWindowListCopyWindowInfo([.optionAll, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]],
              all.filter({ row in
                  guard let pid = row[kCGWindowOwnerPID as String] as? Int32 else { return false }
                  return tartPIDs.contains(pid) && (row[kCGWindowName as String] as? String) == t.title
              }).count == 1 else { throw StopReason.target_not_unique }
        let rows = try windowInfo()
        guard let index = rows.firstIndex(where: { ($0[kCGWindowNumber as String] as? UInt32) == t.windowID }),
              let frame = bounds(rows[index]),
              (rows[index][kCGWindowOwnerPID as String] as? Int32) == t.pid,
              (rows[index][kCGWindowName as String] as? String) == t.title,
              (rows[index][kCGWindowLayer as String] as? Int) == 0,
              frame.equalTo(t.initialBounds),
              (rows[index][kCGWindowAlpha as String] as? Double ?? 1) > 0.99 else { throw StopReason.target_changed }
        // Capture APIs can see obscured windows. Do NOT treat capture success as input safety.
        for row in rows.prefix(index) {
            if let r = bounds(row), r.intersects(frame.insetBy(dx: 2, dy: 2)),
               (row[kCGWindowAlpha as String] as? Double ?? 1) > 0.01 {
                throw StopReason.target_obscured
            }
        }
        let appAX = AXUIElementCreateApplication(t.pid)
        guard let focused = axValue(appAX, kAXFocusedWindowAttribute as CFString),
              CFGetTypeID(focused) == AXUIElementGetTypeID() else { throw StopReason.target_not_frontmost }
        let focusedWindow = unsafeBitCast(focused, to: AXUIElement.self)
        guard axValue(focusedWindow, kAXTitleAttribute as CFString) as? String == t.title,
              let position = axValue(focusedWindow, kAXPositionAttribute as CFString),
              let size = axValue(focusedWindow, kAXSizeAttribute as CFString),
              CFGetTypeID(position) == AXValueGetTypeID(), CFGetTypeID(size) == AXValueGetTypeID()
        else { throw StopReason.target_not_frontmost }
        var p = CGPoint.zero, s = CGSize.zero
        guard AXValueGetValue(unsafeBitCast(position, to: AXValue.self), .cgPoint, &p),
              AXValueGetValue(unsafeBitCast(size, to: AXValue.self), .cgSize, &s),
              abs(p.x - frame.minX) < 2, abs(p.y - frame.minY) < 2,
              abs(s.width - frame.width) < 2, abs(s.height - frame.height) < 2
        else { throw StopReason.target_not_frontmost }
        let flags = CGEventSource.flagsState(.combinedSessionState)
        guard flags.intersection([.maskShift, .maskControl, .maskAlternate, .maskCommand, .maskAlphaShift]).isEmpty
        else { throw StopReason.input_interrupted }
    }

    private struct Text {
        let value: String
        /// ScreenCapture image coordinates: normalized, top-left origin.
        let box: CGRect
    }
    private struct Frame {
        let image: CGImage
        let text: [Text]
        let squares: [CGRect]
        let fields: [CGRect]
        func matches(_ choices: [String]) -> [Text] {
            text.filter { t in choices.contains(where: { Self.normal(t.value) == Self.normal($0) }) }
        }
        func has(_ choices: String...) -> Bool { !matches(choices).isEmpty }
        /// Full allowlisted sentence, optionally wrapped into adjacent OCR lines. Not substring/fuzzy matching.
        func hasBlock(_ choices: String...) -> Bool {
            if !matches(choices).isEmpty { return true }
            let ordered = text.sorted { $0.box.minY < $1.box.minY }
            for start in ordered.indices {
                var value = ordered[start].value
                var last = ordered[start].box
                for end in (start + 1)..<min(start + 5, ordered.count) {
                    let next = ordered[end]
                    guard next.box.minY >= last.minY, next.box.minY - last.maxY < 0.025,
                          abs(next.box.midX - last.midX) < 0.2 else { break }
                    value += " " + next.value
                    if choices.contains(where: { Self.normal(value) == Self.normal($0) }) { return true }
                    last = next.box
                }
            }
            return false
        }
        func one(_ choices: [String]) throws -> Text {
            let rows = matches(choices)
            guard rows.count == 1, let row = rows.first else { throw StopReason.unsupported_control }
            return row
        }
        static func normal(_ s: String) -> String {
            s.trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "’", with: "'")
                .replacingOccurrences(of: "  ", with: " ")
        }
    }
    private func snapshot() async throws -> Frame {
        try guardTarget()
        guard let t = target else { throw StopReason.target_changed }
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        try guardTarget()
        guard let w = content.windows.first(where: { $0.windowID == t.windowID && $0.title == t.title &&
            $0.owningApplication?.processID == t.pid && $0.isOnScreen }) else { throw StopReason.target_changed }
        let configuration = SCStreamConfiguration()
        configuration.width = Int(w.frame.width * 2)
        configuration.height = Int(w.frame.height * 2)
        configuration.showsCursor = false
        if #available(macOS 14.2, *) { configuration.ignoreShadowsSingleWindow = true }
        let image = try await SCScreenshotManager.captureImage(
            contentFilter: SCContentFilter(desktopIndependentWindow: w), configuration: configuration)
        try guardTarget()
        // No file URLs, pasteboard, logging, image uploads, or saved OCR observations.
        let ocr = VNRecognizeTextRequest()
        ocr.recognitionLevel = .accurate
        ocr.recognitionLanguages = ["en-US", "zh-Hans"]
        ocr.usesLanguageCorrection = false
        let rectangles = VNDetectRectanglesRequest()
        rectangles.minimumConfidence = 0.85
        rectangles.minimumAspectRatio = 0.05
        rectangles.maximumAspectRatio = 1
        rectangles.minimumSize = 0.008
        rectangles.maximumObservations = 100
        try VNImageRequestHandler(cgImage: image).perform([ocr, rectangles])
        let text = (ocr.results ?? []).compactMap { observation -> Text? in
            guard let candidate = observation.topCandidates(1).first, candidate.confidence >= 0.88 else { return nil }
            return Text(value: candidate.string, box: Self.topLeft(observation.boundingBox))
        }
        let boxes = (rectangles.results ?? []).map { Self.topLeft($0.boundingBox) }
        let squares = boxes.filter {
            let ratio = $0.width * CGFloat(image.width) / ($0.height * CGFloat(image.height))
            let h = $0.height * w.frame.height
            return (0.8...1.2).contains(ratio) && (10...30).contains(h)
        }
        let fields = boxes.filter {
            let ratio = $0.width * CGFloat(image.width) / ($0.height * CGFloat(image.height))
            let h = $0.height * w.frame.height
            return (3...22).contains(ratio) && (20...55).contains(h) && $0.width > 0.15
        }
        return Frame(image: image, text: text, squares: squares, fields: fields)
    }
    private static func topLeft(_ rect: CGRect) -> CGRect {
        CGRect(x: rect.minX, y: 1 - rect.maxY, width: rect.width, height: rect.height)
    }

    private enum Page: String {
        case language, country, accessibility, dataPrivacy, migration, appleAccount, appleSkipConfirm
        case location, locationConfirm, timeZone, analytics, siri, screenTime, appearance, computerAccount
        case terms, termsConfirm, network, offlineConfirm, keyboard, writtenLanguages, desktop
        case login, diskSecurity, unknown
    }
    private func page(_ f: Frame) -> Page {
        if f.has("FileVault", "FileVault Disk Encryption", "Recovery Key", "Create a Recovery Key", "Store Your Recovery Key", "Disk Encryption", "磁盘加密", "恢复密钥") { return .diskSecurity }
        if f.has("Create a Computer Account", "创建电脑帐户", "创建电脑账户") { return .computerAccount }
        if f.has("Enter Password", "Log In", "Unlock", "Your password is required to log in.", "解锁", "登录") || f.has("Password", "密码") { return .login }
        let menu = f.text.filter { $0.box.midY < 0.14 }.map(\.value)
        if ["Finder", "File", "Edit", "View", "Go", "Window", "Help"].allSatisfy(menu.contains) { return .desktop }
        if f.hasBlock("I have read and agree to the macOS Software License Agreement.") { return .termsConfirm }
        if f.hasBlock("Are you sure you don't want to use Location Services?") && f.has("Don't Use") { return .locationConfirm }
        if f.has("Terms and Conditions", "Software License Agreement", "条款与条件") { return .terms }
        if f.hasBlock("Are you sure you want to skip signing in with an Apple Account?", "Are you sure you want to skip signing in with your Apple ID?") { return .appleSkipConfirm }
        if f.has("Select Your Country or Region", "Choose Your Country or Region", "选择你的国家或地区") { return .country }
        if f.has("Select Your Language", "Choose Your Language", "Language", "语言") && f.has("English") { return .language }
        if f.has("Accessibility", "辅助功能") && f.has("Not Now", "Set Up Later", "Continue") { return .accessibility }
        if f.has("Data & Privacy", "数据与隐私") { return .dataPrivacy }
        if f.has("Transfer Your Information to This Mac", "Migration Assistant", "迁移助理") { return .migration }
        if f.has("Sign In with Your Apple Account", "Sign In with Your Apple ID", "Apple Account", "使用 Apple 账户登录") && f.has("Set Up Later") { return .appleAccount }
        if f.has("Enable Location Services", "Location Services", "启用定位服务") { return .location }
        if f.has("Select Your Time Zone", "Choose Your Time Zone", "选择时区") { return .timeZone }
        if f.has("Analytics", "Share Mac Analytics with Apple", "分析") { return .analytics }
        if f.has("Siri", "Enable Ask Siri", "Ask Siri") { return .siri }
        if f.has("Screen Time", "屏幕使用时间") { return .screenTime }
        if f.has("Choose Your Look", "Choose Your Appearance", "选取外观") { return .appearance }
        if f.has("Select Your Keyboard", "Choose Your Keyboard", "Keyboard Layout") { return .keyboard }
        if f.has("Written and Spoken Languages") { return .writtenLanguages }
        if f.has("Your Mac isn't connected to the Internet.", "Continue without an internet connection?") { return .offlineConfirm }
        if f.has("Select Your Wi-Fi Network", "How Do You Connect?", "Connect to the Internet") { return .network }
        return .unknown
    }

    private func run(profile: Profile, credentials: Credentials) async throws {
        let deadline = Date().addingTimeInterval(20 * 60)
        var transitions = 0
        var accountAttempted = false
        while transitions < 80, Date() < deadline {
            try Task.checkCancellation()
            let f = try await snapshot()
            let p = page(f)
            if p != .language && f.has("创建电脑帐户", "创建电脑账户", "选择你的国家或地区", "辅助功能",
                                       "数据与隐私", "迁移助理", "启用定位服务", "选择时区", "屏幕使用时间", "选取外观", "条款与条件") {
                throw StopReason.unsupported_language
            }
            report("running", p == .unknown ? "inspecting_known_page" : "page_" + p.rawValue)
            switch p {
            case .login: throw StopReason.existing_login_or_lock_screen
            case .diskSecurity: throw StopReason.disk_security_requires_user
            case .unknown: throw StopReason.unknown_page
            case .desktop: return
            case .language:
                try await click(f.one(["English"]).box.center)
                // The first language page can use an unlabeled arrow: Return is allowed only here.
                if f.matches(["Continue"]).count == 1 { try await click(f.one(["Continue"]).box.center) }
                else { try await key(36) }
            case .country:
                try await chooseCountry(profile.country, initial: f)
            case .accessibility, .screenTime:
                try await click(f.one(["Not Now", "Set Up Later"]).box.center)
            case .dataPrivacy, .writtenLanguages:
                try await click(f.one(["Continue"]).box.center)
            case .migration:
                // Explicit modern Setup Assistant skip button only. A radio label is NOT proof
                // that the no-migration radio is selected; older radio-only layouts stop.
                try await click(f.one(["Not Now"]).box.center)
            case .appleAccount:
                try await click(f.one(["Set Up Later"]).box.center)
            case .appleSkipConfirm:
                try await click(f.one(["Skip"]).box.center)
            case .locationConfirm:
                try await click(f.one(["Don't Use"]).box.center)
            case .location:
                if f.matches(["Don't Use", "Not Now"]).count == 1 {
                    try await click(f.one(["Don't Use", "Not Now"]).box.center)
                } else {
                    // User authorized OFF, not a blind toggle: checked must be proven twice,
                    // clicked at most once, then OFF proven twice before any Continue.
                    let off = try await ensureLocationOff(f)
                    try await click(off.one(["Continue"]).box.center)
                }
            case .analytics:
                try requireUnchecked(f, labels: [
                    ["Share Mac Analytics with Apple"],
                    ["Share crash data with app developers", "Share with app developers"]
                ])
                try await click(f.one(["Continue"]).box.center)
            case .siri:
                if f.matches(["Set Up Later", "Not Now"]).count == 1 {
                    try await click(f.one(["Set Up Later", "Not Now"]).box.center)
                } else {
                    try requireUnchecked(f, labels: [["Enable Ask Siri", "Enable Siri"]])
                    try await click(f.one(["Continue"]).box.center)
                }
            case .timeZone:
                // A city label is not proof of a selected IANA zone. Never infer/claim it.
                throw StopReason.timezone_requires_manual_selection
            case .appearance:
                try await click(f.one(["Continue"]).box.center)
            case .keyboard:
                try await click(f.one(["U.S.", "US"]).box.center)
                try await continueOn(.keyboard)
            case .terms, .termsConfirm:
                guard profile.allow_license_agreement else { throw StopReason.license_consent_required }
                try await click(f.one(["Agree"]).box.center)
            case .computerAccount:
                guard !accountAttempted else { throw StopReason.account_readback_failed }
                accountAttempted = true
                try await createAccount(f, credentials: credentials)
            case .network:
                // Only explicit offline options already offered by this known page.
                try await click(f.one(["My computer does not connect to the Internet", "Continue Without Internet", "Set Up Offline"]).box.center)
            case .offlineConfirm:
                try await click(f.one(["Continue", "Continue Without Internet"]).box.center)
            }
            transitions += 1
            try await awaitTransition(from: p, deadline: Date().addingTimeInterval(p == .computerAccount ? 90 : 25))
        }
        throw StopReason.operation_timeout
    }

    private func continueOn(_ expected: Page) async throws {
        try await delay(0.3)
        let f = try await snapshot()
        guard page(f) == expected else { throw StopReason.unknown_page }
        try await click(f.one(["Continue"]).box.center)
    }
    private func awaitTransition(from previous: Page, deadline: Date) async throws {
        var last: Page = previous
        var stable = 0
        while Date() < deadline {
            try await delay(0.6)
            let f = try await snapshot()
            let p = page(f)
            if p == .login { throw StopReason.existing_login_or_lock_screen }
            if p == .diskSecurity { throw StopReason.disk_security_requires_user }
            // Require two consistent known observations before acting on a new page.
            if p != previous && p != .unknown {
                stable = last == p ? stable + 1 : 1
                if stable >= 2 { return }
            } else { stable = 0 }
            last = p
        }
        throw previous == .unknown ? StopReason.unknown_page : StopReason.transition_timeout
    }

    private func chooseCountry(_ code: String, initial: Frame) async throws {
        let english = Locale(identifier: "en_US").localizedString(forRegionCode: code)
        let chinese = Locale(identifier: "zh_Hans").localizedString(forRegionCode: code)
        // Foundation may expand HK/MO to "... SAR China" while Setup uses the short label.
        let setupAliases: [String: [String]] = ["HK": ["Hong Kong"], "MO": ["Macao", "Macau"]]
        let desired = [english, chinese].compactMap { $0 } + (setupAliases[code] ?? [])
        guard !desired.isEmpty else { throw StopReason.invalid_profile }
        let known = Set(Locale.Region.isoRegions.compactMap { Locale(identifier: "en_US").localizedString(forRegionCode: $0.identifier) }
            + setupAliases.values.flatMap { $0 })
        var f = initial
        var previousRows: [String] = []
        var searchingUp = true
        // Scroll only over OCR-confirmed country rows. No offscreen-coordinate guesses.
        // Search up to the top first, then down. Never type into a list with unverified layout.
        for iteration in 0..<90 {
            guard page(f) == .country else { throw StopReason.unknown_page }
            if f.matches(desired).count == 1 {
                try await click(f.one(desired).box.center)
                let selected = try await snapshot()
                guard page(selected) == .country, selected.matches(desired).count == 1,
                      isBlueSelection(selected.image, text: try selected.one(desired).box)
                else { throw StopReason.country_not_visible }
                try await click(selected.one(["Continue"]).box.center)
                return
            }
            let rows = f.text.filter { known.contains($0.value) && $0.box.midY > 0.2 && $0.box.midY < 0.85 }
                .sorted { $0.box.midY < $1.box.midY }
            guard rows.count >= 3 else { throw StopReason.country_not_visible }
            let names = rows.map(\.value)
            if names == previousRows || (searchingUp && iteration >= 44) {
                guard searchingUp else { throw StopReason.country_not_visible }
                searchingUp = false
            }
            previousRows = names
            try await scroll(at: rows[rows.count / 2].box.center, lines: searchingUp ? 5 : -5)
            try await delay(0.45)
            f = try await snapshot()
        }
        throw StopReason.country_not_visible
    }

    private func checkbox(_ frame: Frame, labels: [String]) throws -> CGRect {
        let pairs = frame.matches(labels).flatMap { label in
            frame.squares.filter {
                $0.maxX < label.box.minX && label.box.minX - $0.maxX < 0.055 && abs($0.midY - label.box.midY) < 0.014
            }
        }
        guard pairs.count == 1, let box = pairs.first else { throw StopReason.checkbox_state_requires_user }
        return box
    }
    private func requireUnchecked(_ frame: Frame, labels: [[String]]) throws {
        for choices in labels {
            let box = try checkbox(frame, labels: choices)
            guard isVisiblyEmptyCheckbox(frame.image, box: box) else { throw StopReason.checkbox_state_requires_user }
        }
    }
    /// The ONLY checkbox this driver may change is the user's explicitly authorized Location OFF.
    /// Two checked observations -> ONE click -> two OFF observations. Never retry a toggle.
    private func ensureLocationOff(_ initial: Frame) async throws -> Frame {
        let labels = ["Enable Location Services on this Mac", "Enable Location Services"]
        guard page(initial) == .location else { throw StopReason.unknown_page }
        let original = try checkbox(initial, labels: labels)
        let initiallyOff = isVisiblyEmptyCheckbox(initial.image, box: original)
        guard initiallyOff || isVisiblyCheckedCheckbox(initial.image, box: original)
        else { throw StopReason.checkbox_state_requires_user }

        func sameBox(_ candidate: CGRect) -> Bool {
            abs(candidate.minX - original.minX) < 0.002 && abs(candidate.minY - original.minY) < 0.002 &&
                abs(candidate.width - original.width) < 0.002 && abs(candidate.height - original.height) < 0.002
        }
        try await delay(0.25)
        let before = try await snapshot()
        guard page(before) == .location else { throw StopReason.unknown_page }
        let beforeBox = try checkbox(before, labels: labels)
        guard sameBox(beforeBox) else { throw StopReason.checkbox_state_requires_user }
        if initiallyOff {
            guard isVisiblyEmptyCheckbox(before.image, box: beforeBox) else { throw StopReason.checkbox_state_requires_user }
            return before // Two empty observations; no click at all.
        }
        guard isVisiblyCheckedCheckbox(before.image, box: beforeBox) else { throw StopReason.checkbox_state_requires_user }
        report("running", "disabling_visibly_checked_location_services")
        try await click(beforeBox.center) // Exactly once, on the detected checkbox, not its label.
        var off = before
        for _ in 0..<2 {
            try await delay(0.3)
            off = try await snapshot()
            guard page(off) == .location else { throw StopReason.unknown_page }
            let offBox = try checkbox(off, labels: labels)
            guard sameBox(offBox), isVisiblyEmptyCheckbox(off.image, box: offBox)
            else { throw StopReason.checkbox_state_requires_user }
        }
        return off
    }
    /// Narrow default-blue native checkbox template: blue fill plus a WHITE CHECKMARK,
    /// not merely blue pixels. Unknown accent/theme/shape is unsupported, never guessed.
    private func isVisiblyCheckedCheckbox(_ image: CGImage, box: CGRect) -> Bool {
        guard box.minX >= 0, box.minY >= 0, box.maxX <= 1, box.maxY <= 1,
              box.width * CGFloat(image.width) >= 12, box.height * CGFloat(image.height) >= 12,
              let data = pixels(image) else { return false }
        var blue = 0
        var white: [CGPoint] = []
        let count = 21
        for y in 0..<count { for x in 0..<count {
            let u = 0.12 + CGFloat(x) * 0.76 / CGFloat(count - 1)
            let v = 0.12 + CGFloat(y) * 0.76 / CGFloat(count - 1)
            let px = min(image.width - 1, Int((box.minX + box.width * u) * CGFloat(image.width)))
            let py = min(image.height - 1, Int((box.minY + box.height * v) * CGFloat(image.height)))
            let i = (py * image.width + px) * 4
            let r = Int(data[i]), g = Int(data[i + 1]), b = Int(data[i + 2])
            if b > 150 && b - r > 65 && b - g > 25 { blue += 1 }
            if min(r, g, b) > 225 && max(r, g, b) - min(r, g, b) < 22 {
                white.append(CGPoint(x: u, y: v))
            }
        } }
        let total = count * count
        guard Double(blue) / Double(total) > 0.55,
              (0.055...0.25).contains(Double(white.count) / Double(total)),
              Double(blue + white.count) / Double(total) > 0.85,
              let minX = white.map(\.x).min(), let maxX = white.map(\.x).max(),
              let minY = white.map(\.y).min(), let maxY = white.map(\.y).max(),
              minX < 0.33, maxX > 0.70, maxY - minY > 0.30 else { return false }
        // Top-left image coordinates: short downstroke, then long rising right stroke.
        let a = CGPoint(x: 0.22, y: 0.49), b = CGPoint(x: 0.42, y: 0.70), c = CGPoint(x: 0.79, y: 0.27)
        func distance(_ p: CGPoint, _ start: CGPoint, _ end: CGPoint) -> CGFloat {
            let dx = end.x - start.x, dy = end.y - start.y
            let t = max(0, min(1, ((p.x - start.x) * dx + (p.y - start.y) * dy) / (dx * dx + dy * dy)))
            return hypot(p.x - start.x - t * dx, p.y - start.y - t * dy)
        }
        guard white.filter({ min(distance($0, a, b), distance($0, b, c)) < 0.105 }).count * 10 >= white.count * 9
        else { return false }
        // Both strokes must exist throughout, including the bend; rejects dots/dashes/pluses.
        for segment in [(a, b), (b, c)] {
            for step in 0...5 {
                let t = CGFloat(step) / 5
                let p = CGPoint(x: segment.0.x + t * (segment.1.x - segment.0.x),
                                y: segment.0.y + t * (segment.1.y - segment.0.y))
                guard white.contains(where: { hypot($0.x - p.x, $0.y - p.y) < 0.09 }) else { return false }
            }
        }
        return true
    }
    /// Read back the default blue selected-country row, not merely a still-visible row label.
    /// Nondefault accent/high-contrast rendering is unsupported rather than guessed.
    private func isBlueSelection(_ image: CGImage, text: CGRect) -> Bool {
        guard let data = pixels(image) else { return false }
        var blue = 0
        for x in [text.minX - 0.008, text.maxX + 0.008] {
            for y in [text.minY, text.midY, text.maxY] {
                guard (0..<1).contains(x), (0..<1).contains(y) else { return false }
                let i = (Int(y * CGFloat(image.height)) * image.width + Int(x * CGFloat(image.width))) * 4
                let r = Int(data[i]), g = Int(data[i + 1]), b = Int(data[i + 2])
                if b > 130 && b - r > 45 && b - g > 20 { blue += 1 }
            }
        }
        return blue == 6
    }
    /// Conservative blank-interior + visible neutral outline proof. Not a general UI classifier.
    /// Empty-state test only: checked, colorful or ambiguous controls are never accepted as OFF.
    private func isVisiblyEmptyCheckbox(_ image: CGImage, box: CGRect) -> Bool {
        guard let rgba = pixels(image) else { return false }
        let w = image.width, h = image.height
        func sample(_ nx: CGFloat, _ ny: CGFloat) -> (Double, Double) {
            let x = max(0, min(w - 1, Int(nx * CGFloat(w))))
            let y = max(0, min(h - 1, Int(ny * CGFloat(h))))
            let i = (y * w + x) * 4
            let r = Double(rgba[i]), g = Double(rgba[i + 1]), b = Double(rgba[i + 2])
            return ((r + g + b) / 3, max(r, g, b) - min(r, g, b))
        }
        var interior: [Double] = [], outline: [Double] = [], saturation: [Double] = []
        for y in 3...7 { for x in 3...7 {
            let p = sample(box.minX + box.width * CGFloat(x) / 10, box.minY + box.height * CGFloat(y) / 10)
            interior.append(p.0); saturation.append(p.1)
        } }
        for n in 3...7 {
            for p in [CGPoint(x: 0.05, y: CGFloat(n) / 10), CGPoint(x: 0.95, y: CGFloat(n) / 10),
                      CGPoint(x: CGFloat(n) / 10, y: 0.05), CGPoint(x: CGFloat(n) / 10, y: 0.95)] {
                outline.append(sample(box.minX + box.width * p.x, box.minY + box.height * p.y).0)
            }
        }
        let mean = interior.reduce(0, +) / Double(interior.count)
        let variance = interior.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(interior.count)
        let edge = outline.reduce(0, +) / Double(outline.count)
        return mean > 195 && variance < 12 && saturation.allSatisfy { $0 < 12 } && mean - edge > 22
    }
    private func pixels(_ image: CGImage) -> [UInt8]? {
        var data = [UInt8](repeating: 0, count: image.width * image.height * 4)
        let ok = data.withUnsafeMutableBytes { raw -> Bool in
            guard let context = CGContext(data: raw.baseAddress, width: image.width, height: image.height,
                bitsPerComponent: 8, bytesPerRow: image.width * 4, space: CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue | CGBitmapInfo.byteOrder32Big.rawValue) else { return false }
            // Produce top-left rows to agree with normalized OCR coordinates.
            context.translateBy(x: 0, y: CGFloat(image.height)); context.scaleBy(x: 1, y: -1)
            context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
            return true
        }
        return ok ? data : nil
    }

    private func field(_ f: Frame, labels: [String]) throws -> CGRect {
        let label = try f.one(labels)
        let candidates = f.fields.filter { r in
            r.insetBy(dx: -0.003, dy: -0.003).contains(label.box.center) ||
                (r.minX >= label.box.maxX && r.minX - label.box.maxX < 0.08 && abs(r.midY - label.box.midY) < 0.015)
        }
        guard candidates.count == 1, let r = candidates.first else { throw StopReason.account_form_not_verified }
        return r
    }
    private func createAccount(_ initial: Frame, credentials: Credentials) async throws {
        guard page(initial) == .computerAccount else { throw StopReason.account_form_not_verified }
        let full = try field(initial, labels: ["Full Name", "Full name"])
        let user = try field(initial, labels: ["Account Name", "Account name"])
        let password = try field(initial, labels: ["Password"])
        let verify = try field(initial, labels: ["Verify", "Verify password", "Verify Password"])
        let boxes = [full, user, password, verify]
        for i in boxes.indices { for j in boxes.indices where i != j {
            guard !boxes[i].intersects(boxes[j]) else { throw StopReason.account_form_not_verified }
        } }
        // Prove the physical-key mapping IN THE GUEST, before any secret. Host layout is NOT proof.
        // Fixed public probes cover every printable US ASCII key and both shift states.
        // Small chunks prevent a horizontally-scrolled field from hiding the beginning.
        let alphabet = Array((UInt8(33)...UInt8(126)).map { Character(UnicodeScalar($0)) })
        var probes = ["Aa Zz"]
        for offset in stride(from: 0, to: alphabet.count, by: 6) {
            probes.append("Aa" + String(alphabet[offset..<min(offset + 6, alphabet.count)]) + "Zz")
        }
        report("running", "verifying_guest_us_keyboard")
        for probe in probes {
            try await replaceField(full, text: probe)
            try await delay(0.2)
            let frame = try await snapshot()
            guard page(frame) == .computerAccount, exactReadback(frame, inside: full, expected: probe)
            else { throw StopReason.keyboard_verification_failed }
        }
        // Clear auto-generated short name as well; no account submission on failed verification.
        try await replaceField(full, text: credentials.fullname)
        try await replaceField(user, text: credentials.username)
        try await delay(0.25)
        let readback = try await snapshot()
        guard page(readback) == .computerAccount,
              exactReadback(readback, inside: full, expected: credentials.fullname),
              exactReadback(readback, inside: user, expected: credentials.username)
        else { throw StopReason.account_readback_failed }
        report("running", "entering_native_credentials")
        // NO OCR/screenshot of the password-entry phase. No clipboard or Unicode events.
        try await replaceField(password, text: credentials.password)
        try await replaceField(verify, text: credentials.password)
        try guardTarget()
        // Continue was anchored before secrets; unchanged window geometry is checked per event.
        try await click(initial.one(["Continue"]).box.center)
        credentials.clear()
    }
    private func exactReadback(_ f: Frame, inside box: CGRect, expected: String) -> Bool {
        let values = f.text.filter { box.insetBy(dx: -0.002, dy: -0.002).contains($0.box.center) }
        return values.count == 1 && values.first?.value == expected
    }
    private func replaceField(_ box: CGRect, text: String) async throws {
        try await click(box.center)
        try await chord(0, modifier: 55, flags: .maskCommand) // Cmd-A, field-scoped after anchor click.
        try await key(51) // Delete. Empty field proof is implicit in exact probe/readback.
        try await typeASCII(text)
    }

    // Explicit ANSI US virtual keycodes. VZVirtualMachineView forwards HID keycodes;
    // CGEventKeyboardSetUnicodeString is intentionally never used.
    private static let usKeys: [UInt8: (CGKeyCode, Bool)] = {
        let plain: [(String, CGKeyCode)] = [
            ("a",0),("s",1),("d",2),("f",3),("h",4),("g",5),("z",6),("x",7),("c",8),("v",9),
            ("b",11),("q",12),("w",13),("e",14),("r",15),("y",16),("t",17),
            ("1",18),("2",19),("3",20),("4",21),("6",22),("5",23),("=",24),("9",25),
            ("7",26),("-",27),("8",28),("0",29),("]",30),("o",31),("u",32),("[",33),
            ("i",34),("p",35),("l",37),("j",38),("'",39),("k",40),(";",41),("\\",42),
            (",",43),("/",44),("n",45),("m",46),(".",47),("`",50),(" ",49)
        ]
        var result: [UInt8: (CGKeyCode, Bool)] = [:]
        for (s, k) in plain {
            result[s.utf8.first!] = (k, false)
            if let c = s.utf8.first, (97...122).contains(c) { result[c - 32] = (k, true) }
        }
        let shifted: [(String, String)] = [("!","1"),("@","2"),("#","3"),("$","4"),("%","5"),("^","6"),
            ("&","7"),("*","8"),("(","9"),(")","0"),("_","-"),("+","="),("{","["),("}","]"),
            ("|","\\"),(":",";"),("\"","'"),("<",","),(">","."),("?","/"),("~","`")]
        for (upper, lower) in shifted { if let entry = result[lower.utf8.first!] { result[upper.utf8.first!] = (entry.0, true) } }
        return result
    }()
    private func typeASCII(_ text: String) async throws {
        guard text.utf8.allSatisfy({ Self.usKeys[$0] != nil }) else { throw StopReason.unsupported_credentials }
        for byte in text.utf8 {
            try Task.checkCancellation()
            guard let (code, shifted) = Self.usKeys[byte] else { throw StopReason.unsupported_credentials }
            if shifted { try await chord(code, modifier: 56, flags: .maskShift) }
            else { try await key(code) }
        }
    }
    private func event(_ code: CGKeyCode, down: Bool, flags: CGEventFlags = []) throws {
        try guardTarget()
        guard let t = target, let source = CGEventSource(stateID: .privateState),
              let e = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: down)
        else { throw StopReason.input_interrupted }
        e.flags = flags
        e.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(t.pid))
        e.postToPid(t.pid)
    }
    private func key(_ code: CGKeyCode) async throws {
        try event(code, down: true)
        try event(code, down: false)
        try await delay(0.012)
    }
    private func chord(_ code: CGKeyCode, modifier: CGKeyCode, flags: CGEventFlags) async throws {
        try event(modifier, down: true, flags: flags)
        try event(code, down: true, flags: flags)
        try event(code, down: false, flags: flags)
        try event(modifier, down: false)
        try await delay(0.012)
    }
    private func screenPoint(_ normalized: CGPoint) throws -> CGPoint {
        guard let t = target, (0...1).contains(normalized.x), (0...1).contains(normalized.y) else { throw StopReason.unsupported_control }
        return CGPoint(x: t.initialBounds.minX + normalized.x * t.initialBounds.width,
                       y: t.initialBounds.minY + normalized.y * t.initialBounds.height)
    }
    private func click(_ normalized: CGPoint) async throws {
        let point = try screenPoint(normalized)
        for type in [CGEventType.leftMouseDown, .leftMouseUp] {
            try guardTarget()
            guard let t = target, let source = CGEventSource(stateID: .privateState),
                  let e = CGEvent(mouseEventSource: source, mouseType: type, mouseCursorPosition: point, mouseButton: .left)
            else { throw StopReason.input_interrupted }
            e.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(t.pid))
            e.setIntegerValueField(.mouseEventWindowUnderMousePointer, value: Int64(t.windowID))
            e.setIntegerValueField(.mouseEventWindowUnderMousePointerThatCanHandleThisEvent, value: Int64(t.windowID))
            e.postToPid(t.pid)
        }
        try await delay(0.15)
    }
    private func scroll(at normalized: CGPoint, lines: Int32) async throws {
        try guardTarget()
        guard let t = target, let source = CGEventSource(stateID: .privateState),
              let e = CGEvent(scrollWheelEvent2Source: source, units: .line, wheelCount: 1, wheel1: lines, wheel2: 0, wheel3: 0)
        else { throw StopReason.input_interrupted }
        e.location = try screenPoint(normalized)
        e.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(t.pid))
        e.setIntegerValueField(.mouseEventWindowUnderMousePointer, value: Int64(t.windowID))
        e.setIntegerValueField(.mouseEventWindowUnderMousePointerThatCanHandleThisEvent, value: Int64(t.windowID))
        e.postToPid(t.pid)
    }
    private func delay(_ seconds: Double) async throws {
        try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
        try Task.checkCancellation()
    }
}

extension GuestInitializationDriver.StopReason: Error {}
private extension CGRect {
    var center: CGPoint { CGPoint(x: midX, y: midY) }
}
