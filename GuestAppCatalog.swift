import Foundation

/// Public metadata only. This module does not acquire, execute, install, sign,
/// or approve the licence of any application binary. It is not wired into the UI.
/// All endpoints and filename contracts were reviewed on 2026-11-17; schema
/// changes fail closed and require review rather than a permissive fallback.
enum GuestAppCatalog {
    static let maximumMetadataBytes = 1_048_576
    static let maximumDeclaredArtifactBytes: Int64 = 2_147_483_648
    static let maximumReleaseAssets = 128
    static let maximumClaudeReleases = 256

    enum Product: String, CaseIterable, Encodable {
        case ccbaga
        case clashVergeRev
        case claudeDesktop

        var metadataURL: URL {
            switch self {
            case .ccbaga:
                return URL(string: "https://api.github.com/repos/liseami/CCBaga/releases/latest")!
            case .clashVergeRev:
                return URL(string: "https://api.github.com/repos/clash-verge-rev/clash-verge-rev/releases/latest")!
            case .claudeDesktop:
                return URL(string: "https://downloads.claude.ai/releases/darwin/universal/RELEASES.json")!
            }
        }

        var expectedApplicationNames: [String] {
            switch self {
            case .ccbaga: return ["CCBaga-A.app", "CCBaga-B.app"]
            case .clashVergeRev: return ["Clash Verge.app"]
            case .claudeDesktop: return ["Claude.app"]
            }
        }

        fileprivate var githubRepository: String? {
            switch self {
            case .ccbaga: return "liseami/CCBaga"
            case .clashVergeRev: return "clash-verge-rev/clash-verge-rev"
            case .claudeDesktop: return nil
            }
        }
    }

    /// Errors deliberately contain no server response, URL, arbitrary strings,
    /// filesystem paths, credentials, or underlying networking errors.
    enum CatalogError: String, Error, Equatable, LocalizedError {
        case metadataTooLarge
        case invalidSchema
        case untrustedSource
        case invalidVersion
        case nonStableRelease
        case invalidArtifact
        case duplicateAsset
        case invalidDigest
        case unsupportedSize
        case missingArtifact
        case releaseMismatch
        case invalidTimestamp
        case invalidResponse
        case transportFailure
        case cancelled
        case incompleteCatalog

        var errorDescription: String? {
            switch self {
            case .metadataTooLarge: return "Official application metadata exceeded the safety limit."
            case .invalidSchema: return "Official application metadata has an unsupported schema."
            case .untrustedSource: return "Application metadata came from an unapproved source."
            case .invalidVersion: return "Application metadata contains an unsupported version."
            case .nonStableRelease: return "Only published stable application releases are supported."
            case .invalidArtifact: return "The official application artifact does not match the reviewed contract."
            case .duplicateAsset: return "Application metadata contains duplicate release entries or assets."
            case .invalidDigest: return "The official release checksum is missing or invalid."
            case .unsupportedSize: return "The declared application artifact size is unsupported."
            case .missingArtifact: return "The required complete GUI application artifact was not found."
            case .releaseMismatch: return "Official application release metadata is inconsistent."
            case .invalidTimestamp: return "Application metadata contains an invalid timestamp."
            case .invalidResponse: return "The official metadata endpoint returned an invalid response."
            case .transportFailure: return "Official application metadata could not be retrieved."
            case .cancelled: return "Application metadata retrieval was cancelled."
            case .incompleteCatalog: return "A complete, unique three-application catalog is required."
            }
        }
    }

    struct MetadataDocument {
        let product: Product
        let data: Data
        let finalURL: URL
        let retrievedAt: Date
    }

    enum ChecksumSource: String, Encodable {
        /// A digest explicitly published in the publisher's GitHub release API.
        /// It is not an independent signature or a local binary verification.
        case publisherReleaseAPI
        case absentFromOfficialDesktopFeed
    }

    struct SHA256Evidence: Encodable, Equatable {
        let value: String?
        let firstPartyExplicit: Bool
        let source: ChecksumSource
        let metadataURL: URL
    }

    enum ArtifactFormat: String, Encodable {
        case diskImage
        case applicationZIP
    }

    enum InstallerRequirement: String, Encodable, CaseIterable {
        case obtainUserAuthorizationAndReviewApplicableLicences
        case enforceDownloadSizeLimitAndValidateEveryArtifactRedirect
        case authenticateVendorSignatureAndAssessGatekeeper
        case verifyArchiveLayoutApplicationNamesVersionAndARM64
        case preserveVendorSignaturesQuarantineAndNotarization
        case verifyOrComputeSHA256AndRecordInstallationReceipt
        case obtainSeparateAdministratorAndFeaturePermissionsIfNeeded
    }

    /// Immutable acquisition proposal, NOT proof an artifact is safe/installed.
    /// Missing feed values remain nil; no filename token is used as a checksum.
    struct ArtifactPlan: Encodable, Equatable {
        let product: Product
        let version: String
        let releaseTag: String?
        let releaseID: Int64?
        let assetID: Int64?
        let upstreamReleaseImmutable: Bool?
        let metadataURL: URL
        let releasePageURL: URL?
        let artifactURL: URL
        let artifactName: String
        let format: ArtifactFormat
        let architecture: String
        let declaredSizeBytes: Int64?
        let maximumAcquisitionBytes: Int64
        let sha256: SHA256Evidence
        let publishedAt: Date
        let metadataRetrievedAt: Date
        let expectedApplicationNames: [String]
        let binaryVerificationPerformed: Bool
        let installationPerformed: Bool
        let licenceApprovalGranted: Bool
        let installerRequirements: [InstallerRequirement]
    }

    struct FrozenPlan: Encodable, Equatable {
        let schemaVersion: Int
        let frozenAt: Date
        let artifacts: [ArtifactPlan]
        let binariesDownloaded: Bool
        let applicationsInstalled: Bool

        func encodedJSON() throws -> Data {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            return try encoder.encode(self)
        }
    }

    /// Pure: callers may use fixture bytes or independently retrieved documents.
    /// Unknown API keys are tolerated for additive upstream compatibility, but
    /// every field used for acquisition is validated; no fallback to a CLI/core.
    static func parse(_ document: MetadataDocument) throws -> ArtifactPlan {
        guard document.data.count <= maximumMetadataBytes else { throw CatalogError.metadataTooLarge }
        guard !document.data.isEmpty else { throw CatalogError.invalidSchema }
        try validateMetadataURL(document.finalURL, for: document.product)
        try validateDate(document.retrievedAt)
        switch document.product {
        case .ccbaga, .clashVergeRev: return try parseGitHub(document)
        case .claudeDesktop: return try parseClaude(document)
        }
    }

    /// "Latest" is resolved before this call. The output freezes the selected
    /// metadata snapshot, not an upstream guarantee that URLs cannot change.
    static func freeze(_ documents: [MetadataDocument], at frozenAt: Date) throws -> FrozenPlan {
        try validateDate(frozenAt)
        guard documents.count == Product.allCases.count,
              Set(documents.map { $0.product }).count == Product.allCases.count else {
            throw CatalogError.incompleteCatalog
        }
        var artifacts: [ArtifactPlan] = []
        for product in Product.allCases {
            guard let document = documents.first(where: { $0.product == product }) else {
                throw CatalogError.incompleteCatalog
            }
            guard document.retrievedAt <= frozenAt else { throw CatalogError.invalidTimestamp }
            artifacts.append(try parse(document))
        }
        return FrozenPlan(schemaVersion: 1, frozenAt: frozenAt, artifacts: artifacts,
                          binariesDownloaded: false, applicationsInstalled: false)
    }

    /// Exact fixed metadata URLs: HTTPS, host, path, case, no alternate ports,
    /// credentials, query, fragment, percent-encoding tricks, or mirrors.
    static func validateMetadataURL(_ url: URL, for product: Product) throws {
        guard url.absoluteString == product.metadataURL.absoluteString else {
            throw CatalogError.untrustedSource
        }
    }

    /// Also exposed for offline response-policy tests. A missing length is okay
    /// only because the fetcher independently limits every streamed data chunk.
    static func validateMetadataResponse(_ response: HTTPURLResponse, for product: Product) throws {
        guard let url = response.url else { throw CatalogError.invalidResponse }
        try validateMetadataURL(url, for: product)
        guard response.statusCode == 200 else { throw CatalogError.invalidResponse }
        guard response.expectedContentLength <= Int64(maximumMetadataBytes) else {
            throw CatalogError.metadataTooLarge
        }
    }

    /// Optional acquisition of SMALL JSON ONLY. Not called by the offline tests.
    /// No cookies, credentials, cache, artifact downloads, or redirect following.
    /// Cancellation is available through the returned URLSessionDataTask.
    @discardableResult
    static func fetchMetadata(for product: Product,
                              completion: @escaping (Result<MetadataDocument, CatalogError>) -> Void)
        -> URLSessionDataTask {
        let request = MetadataRequest(product: product, completion: completion)
        return request.start()
    }

    private struct GitHubRelease: Decodable {
        let id: Int64
        let url: String
        let html_url: String
        let tag_name: String
        let draft: Bool
        let prerelease: Bool
        let immutable: Bool
        let published_at: String
        let assets: [GitHubAsset]
    }

    private struct GitHubAsset: Decodable {
        let id: Int64
        let name: String
        let state: String
        let size: Int64
        let digest: String?
        let browser_download_url: String
    }

    private static func parseGitHub(_ document: MetadataDocument) throws -> ArtifactPlan {
        let release: GitHubRelease = try decode(document.data)
        guard let repository = document.product.githubRepository else { throw CatalogError.invalidSchema }
        guard !release.draft, !release.prerelease else { throw CatalogError.nonStableRelease }
        guard release.tag_name.hasPrefix("v") else { throw CatalogError.invalidVersion }
        let version = String(release.tag_name.dropFirst())
        try validateVersion(version)
        guard release.id > 0,
              release.url == "https://api.github.com/repos/\(repository)/releases/\(release.id)",
              release.html_url == "https://github.com/\(repository)/releases/tag/\(release.tag_name)" else {
            throw CatalogError.releaseMismatch
        }
        let publishedAt = try parseTimestamp(release.published_at)
        guard !release.assets.isEmpty, release.assets.count <= maximumReleaseAssets else {
            throw CatalogError.invalidSchema
        }
        var names = Set<String>()
        var ids = Set<Int64>()
        for asset in release.assets {
            guard names.insert(asset.name).inserted, ids.insert(asset.id).inserted else {
                throw CatalogError.duplicateAsset
            }
            guard asset.id > 0, asset.state == "uploaded", asset.name.utf8.count <= 200,
                  matches(asset.name, "[A-Za-z0-9][A-Za-z0-9._-]*"),
                  asset.browser_download_url == "https://github.com/\(repository)/releases/download/\(release.tag_name)/\(asset.name)" else {
                throw CatalogError.invalidArtifact
            }
            guard asset.size > 0, asset.size <= maximumDeclaredArtifactBytes else {
                throw CatalogError.unsupportedSize
            }
        }
        let expectedName: String
        switch document.product {
        case .ccbaga: expectedName = "CCBaga-\(version)-macos-arm64.dmg"
        case .clashVergeRev: expectedName = "Clash.Verge_\(version)_aarch64.dmg"
        case .claudeDesktop: throw CatalogError.invalidSchema
        }
        guard let asset = release.assets.first(where: { $0.name == expectedName }) else {
            throw CatalogError.missingArtifact
        }
        guard let digest = asset.digest, matches(digest, "sha256:[0-9a-f]{64}") else {
            throw CatalogError.invalidDigest
        }
        guard let artifactURL = URL(string: asset.browser_download_url),
              let pageURL = URL(string: release.html_url) else { throw CatalogError.invalidArtifact }
        return makeArtifact(document: document, version: version, releaseTag: release.tag_name,
                            releaseID: release.id, assetID: asset.id, immutable: release.immutable,
                            pageURL: pageURL, artifactURL: artifactURL, artifactName: expectedName,
                            format: .diskImage, architecture: "arm64", size: asset.size,
                            checksum: SHA256Evidence(value: String(digest.dropFirst(7)), firstPartyExplicit: true,
                                                     source: .publisherReleaseAPI, metadataURL: document.product.metadataURL),
                            publishedAt: publishedAt)
    }

    private struct ClaudeFeed: Decodable {
        let currentRelease: String
        let releases: [ClaudeRelease]
    }

    private struct ClaudeRelease: Decodable {
        let version: String
        let updateTo: ClaudeUpdate
    }

    private struct ClaudeUpdate: Decodable {
        let name: String
        let version: String
        let pub_date: String
        let url: String
    }

    private static func parseClaude(_ document: MetadataDocument) throws -> ArtifactPlan {
        let feed: ClaudeFeed = try decode(document.data)
        try validateVersion(feed.currentRelease)
        guard !feed.releases.isEmpty, feed.releases.count <= maximumClaudeReleases else {
            throw CatalogError.invalidSchema
        }
        var versions = Set<String>()
        var selected: (ClaudeRelease, URL, Date)?
        for release in feed.releases {
            try validateVersion(release.version)
            guard versions.insert(release.version).inserted else { throw CatalogError.duplicateAsset }
            guard release.updateTo.version == release.version,
                  release.updateTo.name == "Claude \(release.version)" else { throw CatalogError.releaseMismatch }
            let publishedAt = try parseTimestamp(release.updateTo.pub_date)
            let prefix = "https://downloads.claude.ai/releases/darwin/universal/\(release.version)/"
            guard release.updateTo.url.hasPrefix(prefix) else { throw CatalogError.invalidArtifact }
            let name = String(release.updateTo.url.dropFirst(prefix.count))
            // The 40 hex characters are an opaque filename token, NOT a SHA256.
            guard matches(name, "Claude-[0-9a-f]{40}\\.zip"),
                  let url = URL(string: release.updateTo.url),
                  url.absoluteString == prefix + name else { throw CatalogError.invalidArtifact }
            if release.version == feed.currentRelease { selected = (release, url, publishedAt) }
        }
        guard let (release, url, publishedAt) = selected else { throw CatalogError.missingArtifact }
        return makeArtifact(document: document, version: release.version, releaseTag: nil,
                            releaseID: nil, assetID: nil, immutable: nil, pageURL: nil,
                            artifactURL: url, artifactName: url.lastPathComponent,
                            format: .applicationZIP, architecture: "universal-x64-arm64", size: nil,
                            checksum: SHA256Evidence(value: nil, firstPartyExplicit: false,
                                                     source: .absentFromOfficialDesktopFeed,
                                                     metadataURL: document.product.metadataURL),
                            publishedAt: publishedAt)
    }

    private static func makeArtifact(document: MetadataDocument, version: String, releaseTag: String?,
                                     releaseID: Int64?, assetID: Int64?, immutable: Bool?, pageURL: URL?,
                                     artifactURL: URL, artifactName: String, format: ArtifactFormat,
                                     architecture: String, size: Int64?, checksum: SHA256Evidence,
                                     publishedAt: Date) -> ArtifactPlan {
        ArtifactPlan(product: document.product, version: version, releaseTag: releaseTag,
                     releaseID: releaseID, assetID: assetID, upstreamReleaseImmutable: immutable,
                     metadataURL: document.product.metadataURL, releasePageURL: pageURL,
                     artifactURL: artifactURL, artifactName: artifactName, format: format,
                     architecture: architecture, declaredSizeBytes: size,
                     maximumAcquisitionBytes: maximumDeclaredArtifactBytes, sha256: checksum,
                     publishedAt: publishedAt, metadataRetrievedAt: document.retrievedAt,
                     expectedApplicationNames: document.product.expectedApplicationNames,
                     binaryVerificationPerformed: false, installationPerformed: false,
                     licenceApprovalGranted: false, installerRequirements: InstallerRequirement.allCases)
    }

    private static func decode<T: Decodable>(_ data: Data) throws -> T {
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw CatalogError.invalidSchema }
    }

    private static func validateVersion(_ version: String) throws {
        guard version.utf8.count <= 48,
              matches(version, "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)") else {
            throw CatalogError.invalidVersion
        }
    }

    private static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: "\\A(?:" + pattern + ")\\z", options: .regularExpression) != nil
    }

    private static func validateDate(_ date: Date) throws {
        guard date.timeIntervalSince1970.isFinite, date.timeIntervalSince1970 >= 0 else {
            throw CatalogError.invalidTimestamp
        }
    }

    private static func parseTimestamp(_ value: String) throws -> Date {
        guard value.utf8.count <= 40,
              matches(value, "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z") else {
            throw CatalogError.invalidTimestamp
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = value.contains(".") ? [.withInternetDateTime, .withFractionalSeconds] : [.withInternetDateTime]
        guard let date = formatter.date(from: value) else { throw CatalogError.invalidTimestamp }
        try validateDate(date)
        return date
    }
}

/// URLSession serializes delegate callbacks on its own operation queue. The
/// request is retained by its session until completion, then the cycle is broken.
private final class MetadataRequest: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private let product: GuestAppCatalog.Product
    private let completion: (Result<GuestAppCatalog.MetadataDocument, GuestAppCatalog.CatalogError>) -> Void
    private var session: URLSession?
    private var responseURL: URL?
    private var data = Data()
    private var failure: GuestAppCatalog.CatalogError?
    private var completed = false

    init(product: GuestAppCatalog.Product,
         completion: @escaping (Result<GuestAppCatalog.MetadataDocument, GuestAppCatalog.CatalogError>) -> Void) {
        self.product = product
        self.completion = completion
    }

    func start() -> URLSessionDataTask {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        self.session = session
        var request = URLRequest(url: product.metadataURL)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("GoldVMManager-Metadata/1", forHTTPHeaderField: "User-Agent")
        let task = session.dataTask(with: request)
        task.resume()
        return task
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        do {
            guard let http = response as? HTTPURLResponse else { throw GuestAppCatalog.CatalogError.invalidResponse }
            try GuestAppCatalog.validateMetadataResponse(http, for: product)
            responseURL = http.url
            completionHandler(.allow)
        } catch {
            failure = (error as? GuestAppCatalog.CatalogError) ?? .invalidResponse
            completionHandler(.cancel)
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        guard failure == nil else { return }
        guard chunk.count <= GuestAppCatalog.maximumMetadataBytes - data.count else {
            failure = .metadataTooLarge
            dataTask.cancel()
            return
        }
        data.append(chunk)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        failure = .untrustedSource
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
        } else {
            failure = .untrustedSource
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard !completed else { return }
        completed = true
        let result: Result<GuestAppCatalog.MetadataDocument, GuestAppCatalog.CatalogError>
        if let failure = failure {
            result = .failure(failure)
        } else if let error = error {
            result = .failure((error as NSError).code == NSURLErrorCancelled ? .cancelled : .transportFailure)
        } else if let finalURL = responseURL {
            result = .success(.init(product: product, data: data, finalURL: finalURL, retrievedAt: Date()))
        } else {
            result = .failure(.invalidResponse)
        }
        session.finishTasksAndInvalidate()
        self.session = nil
        completion(result)
    }
}
