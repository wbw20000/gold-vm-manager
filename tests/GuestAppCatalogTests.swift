import Foundation

/// Standalone, offline fixture runner. Compile together with GuestAppCatalog.swift.
/// No fetchMetadata call, URL loading, external fixtures, apps, VM, or credentials.
@main
struct GuestAppCatalogTests {
    typealias Catalog = GuestAppCatalog
    typealias Failure = GuestAppCatalog.CatalogError
    static let retrievedAt = Date(timeIntervalSince1970: 1_794_916_800)
    static var checks = 0

    static func require(_ condition: Bool, _ label: String) {
        checks += 1
        if !condition {
            fputs("FAIL: \(label)\n", stderr)
            exit(1)
        }
    }

    static func rejects(_ expected: Failure, _ label: String, _ operation: () throws -> Void) {
        checks += 1
        do {
            try operation()
            fputs("FAIL: \(label) accepted invalid fixture\n", stderr)
            exit(1)
        } catch let failure as Failure {
            if failure != expected {
                fputs("FAIL: \(label) returned unexpected sanitized error\n", stderr)
                exit(1)
            }
        } catch {
            fputs("FAIL: \(label) leaked an underlying error\n", stderr)
            exit(1)
        }
    }

    static func github(_ product: Catalog.Product) -> [String: Any] {
        let ccbaga = product == .ccbaga
        let repository = ccbaga ? "liseami/CCBaga" : "clash-verge-rev/clash-verge-rev"
        let version = ccbaga ? "0.2.50" : "2.5.10"
        let releaseID = ccbaga ? 426271973 : 432493733
        let assetID = ccbaga ? 683854494 : 705104347
        let name = ccbaga ? "CCBaga-0.2.50-macos-arm64.dmg" : "Clash.Verge_2.5.10_aarch64.dmg"
        let digest = ccbaga ? "0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b" : "40d4a7da4543d75f573a5cfcc31543b0b4bf7e02caa122a9ca50654859585839"
        return [
            "id": releaseID,
            "url": "https://api.github.com/repos/\(repository)/releases/\(releaseID)",
            "html_url": "https://github.com/\(repository)/releases/tag/v\(version)",
            "tag_name": "v\(version)", "draft": false, "prerelease": false, "immutable": false,
            "published_at": ccbaga ? "2026-10-28T04:48:01Z" : "2026-11-03T10:04:21Z",
            "assets": [["id": assetID, "name": name, "state": "uploaded",
                        "size": ccbaga ? 333449374 : 80769307, "digest": "sha256:\(digest)",
                        "browser_download_url": "https://github.com/\(repository)/releases/download/v\(version)/\(name)"]],
            "ignored_upstream_addition": "Additive API fields are not acquisition authority."
        ]
    }

    static func claudeEntry(_ version: String) -> [String: Any] {
        ["version": version, "updateTo": [
            "name": "Claude \(version)", "version": version,
            "pub_date": "2026-11-13T21:03:43.363Z",
            "url": "https://downloads.claude.ai/releases/darwin/universal/\(version)/Claude-1403e2cf44abfb23809c8ae11238d5e9704a41c2.zip",
            "notes": ""
        ]]
    }

    static func claude() -> [String: Any] {
        ["currentRelease": "5.11492.5", "releases": [claudeEntry("5.11492.5")]]
    }

    static func document(_ product: Catalog.Product, _ object: [String: Any],
                         finalURL: URL? = nil, at: Date = retrievedAt) throws -> Catalog.MetadataDocument {
        Catalog.MetadataDocument(product: product,
                                 data: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
                                 finalURL: finalURL ?? product.metadataURL, retrievedAt: at)
    }

    static func alterAsset(_ input: [String: Any], _ mutation: (inout [String: Any]) -> Void) -> [String: Any] {
        var object = input
        var assets = object["assets"] as! [[String: Any]]
        mutation(&assets[0])
        object["assets"] = assets
        return object
    }

    static func alterUpdate(_ input: [String: Any], _ mutation: (inout [String: Any]) -> Void) -> [String: Any] {
        var object = input
        var releases = object["releases"] as! [[String: Any]]
        var update = releases[0]["updateTo"] as! [String: Any]
        mutation(&update)
        releases[0]["updateTo"] = update
        object["releases"] = releases
        return object
    }

    static func parse(_ product: Catalog.Product, _ object: [String: Any]) throws -> Catalog.ArtifactPlan {
        try Catalog.parse(document(product, object))
    }

    static func main() throws {
        let cc = try parse(.ccbaga, github(.ccbaga))
        let clash = try parse(.clashVergeRev, github(.clashVergeRev))
        let desktop = try parse(.claudeDesktop, claude())
        require(cc.version == "0.2.50", "CCBaga stable version")
        require(cc.expectedApplicationNames == ["CCBaga-A.app", "CCBaga-B.app"], "CCBaga requires BOTH GUI apps")
        require(cc.artifactName == "CCBaga-0.2.50-macos-arm64.dmg", "CCBaga full DMG not A-only updater")
        require(cc.declaredSizeBytes == 333449374, "CCBaga explicit size")
        require(cc.sha256.firstPartyExplicit && cc.sha256.source == .publisherReleaseAPI, "CCBaga digest provenance")
        require(cc.sha256.value == "0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b", "CCBaga exact upstream digest")
        require(cc.upstreamReleaseImmutable == false, "mutable upstream release honestly recorded")
        require(clash.version == "2.5.10" && clash.expectedApplicationNames == ["Clash Verge.app"], "full Clash GUI")
        require(clash.artifactName == "Clash.Verge_2.5.10_aarch64.dmg", "Clash ARM64 DMG")
        require(clash.sha256.value == "40d4a7da4543d75f573a5cfcc31543b0b4bf7e02caa122a9ca50654859585839", "Clash exact upstream digest")
        require(desktop.version == "5.11492.5" && desktop.expectedApplicationNames == ["Claude.app"], "official Claude DESKTOP")
        require(desktop.architecture == "universal-x64-arm64" && desktop.format == .applicationZIP, "Claude universal ZIP")
        require(desktop.sha256.value == nil && !desktop.sha256.firstPartyExplicit, "Claude filename token is NOT a checksum")
        require(desktop.sha256.source == .absentFromOfficialDesktopFeed && desktop.declaredSizeBytes == nil, "Claude missing metadata stays unknown")
        for artifact in [cc, clash, desktop] {
            require(!artifact.binaryVerificationPerformed && !artifact.installationPerformed && !artifact.licenceApprovalGranted, "no invented verification installation or licence approval")
            require(artifact.installerRequirements == Catalog.InstallerRequirement.allCases, "installer obligations remain explicit")
        }

        for field in ["draft", "prerelease"] {
            var object = github(.ccbaga); object[field] = true
            rejects(.nonStableRelease, "reject \(field)") { _ = try parse(.ccbaga, object) }
        }
        for tag in ["0.2.50", "v0.2.50-beta.1", "v0.2.50+build", "v00.2.50", "v0.2", "v0.2.50/evil", "v0.2.50\n"] {
            var object = github(.ccbaga); object["tag_name"] = tag
            rejects(.invalidVersion, "invalid GitHub version/tag") { _ = try parse(.ccbaga, object) }
        }
        var wrongOwner = github(.ccbaga)
        wrongOwner["html_url"] = "https://github.com/untrusted/CCBaga/releases/tag/v0.2.50"
        rejects(.releaseMismatch, "wrong repository") { _ = try parse(.ccbaga, wrongOwner) }
        var badReleaseID = github(.ccbaga); badReleaseID["id"] = 0
        rejects(.releaseMismatch, "invalid release id") { _ = try parse(.ccbaga, badReleaseID) }
        var badAPIURL = github(.ccbaga); badAPIURL["url"] = "https://api.github.com/repos/liseami/CCBaga/releases/1"
        rejects(.releaseMismatch, "API release id mismatch") { _ = try parse(.ccbaga, badAPIURL) }

        for digest: Any in ["sha1:" + String(repeating: "a", count: 40), "sha256:" + String(repeating: "a", count: 63),
                            "sha256:" + String(repeating: "A", count: 64), "sha256:" + String(repeating: "g", count: 64), NSNull()] {
            let object = alterAsset(github(.ccbaga)) { $0["digest"] = digest }
            rejects(.invalidDigest, "bad explicit SHA256") { _ = try parse(.ccbaga, object) }
        }
        let missingDigest = alterAsset(github(.ccbaga)) { $0.removeValue(forKey: "digest") }
        rejects(.invalidDigest, "missing required GitHub digest") { _ = try parse(.ccbaga, missingDigest) }
        for size: Any in [0, -1, Int64(2_147_483_649)] {
            let object = alterAsset(github(.ccbaga)) { $0["size"] = size }
            rejects(.unsupportedSize, "bad artifact size") { _ = try parse(.ccbaga, object) }
        }
        for size: Any in [true, "333449374", 1.5, NSNull()] {
            let object = alterAsset(github(.ccbaga)) { $0["size"] = size }
            rejects(.invalidSchema, "wrong size type") { _ = try parse(.ccbaga, object) }
        }
        let sizeUpperBound = alterAsset(github(.ccbaga)) { $0["size"] = Catalog.maximumDeclaredArtifactBytes }
        require(try parse(.ccbaga, sizeUpperBound).declaredSizeBytes == Catalog.maximumDeclaredArtifactBytes, "artifact size upper bound inclusive")

        let goodURL = cc.artifactURL.absoluteString
        for url in [goodURL.replacingOccurrences(of: "https:", with: "http:"),
                    goodURL.replacingOccurrences(of: "github.com/", with: "github.com.evil.invalid/"),
                    goodURL.replacingOccurrences(of: "github.com/", with: "github.com:443/"),
                    goodURL.replacingOccurrences(of: "github.com/", with: "user:password@github.com/"),
                    goodURL.replacingOccurrences(of: "v0.2.50/", with: "v0.2.49/"),
                    goodURL + "?token=private", goodURL + "#fragment",
                    goodURL.replacingOccurrences(of: "CCBaga-", with: "CCBaga%2D")] {
            let object = alterAsset(github(.ccbaga)) { $0["browser_download_url"] = url }
            rejects(.invalidArtifact, "untrusted artifact URL") { _ = try parse(.ccbaga, object) }
        }
        let badState = alterAsset(github(.ccbaga)) { $0["state"] = "open" }
        rejects(.invalidArtifact, "unfinished upload") { _ = try parse(.ccbaga, badState) }
        let badAssetID = alterAsset(github(.ccbaga)) { $0["id"] = -1 }
        rejects(.invalidArtifact, "invalid asset id") { _ = try parse(.ccbaga, badAssetID) }
        let badFilename = alterAsset(github(.ccbaga)) { $0["name"] = "../CCBaga.dmg" }
        rejects(.invalidArtifact, "path traversal asset name") { _ = try parse(.ccbaga, badFilename) }
        for (product, name) in [(Catalog.Product.ccbaga, "CCBaga-0.2.50-macos-arm64.app.tar.gz"),
                                (.ccbaga, "CCBaga-0.2.50-macos-x64.dmg"),
                                (.clashVergeRev, "verge-mihomo"),
                                (.clashVergeRev, "Clash.Verge_2.5.10_x64.dmg")] {
            let object = alterAsset(github(product)) {
                $0["name"] = name
                let old = $0["browser_download_url"] as! String
                $0["browser_download_url"] = String(old.prefix(through: old.lastIndex(of: "/")!)) + name
            }
            rejects(.missingArtifact, "no CLI core updater or wrong architecture substitute") { _ = try parse(product, object) }
        }
        var duplicate = github(.ccbaga)
        let asset = (duplicate["assets"] as! [[String: Any]])[0]
        duplicate["assets"] = [asset, asset]
        rejects(.duplicateAsset, "duplicate asset") { _ = try parse(.ccbaga, duplicate) }
        var duplicateID = asset; duplicateID["name"] = "another.dmg"
        duplicate["assets"] = [asset, duplicateID]
        rejects(.duplicateAsset, "duplicate id different filename") { _ = try parse(.ccbaga, duplicate) }
        var duplicateName = asset; duplicateName["id"] = 123
        duplicate["assets"] = [asset, duplicateName]
        rejects(.duplicateAsset, "duplicate name different id") { _ = try parse(.ccbaga, duplicate) }
        var tooMany = github(.ccbaga); tooMany["assets"] = Array(repeating: asset, count: Catalog.maximumReleaseAssets + 1)
        rejects(.invalidSchema, "bounded asset count") { _ = try parse(.ccbaga, tooMany) }
        var emptyAssets = github(.ccbaga); emptyAssets["assets"] = []
        rejects(.invalidSchema, "empty assets") { _ = try parse(.ccbaga, emptyAssets) }

        for field in ["id", "url", "html_url", "tag_name", "draft", "prerelease", "immutable", "published_at", "assets"] {
            var object = github(.ccbaga); object.removeValue(forKey: field)
            rejects(.invalidSchema, "missing required release field") { _ = try parse(.ccbaga, object) }
        }
        var badBool = github(.ccbaga); badBool["draft"] = 0
        rejects(.invalidSchema, "boolean not number") { _ = try parse(.ccbaga, badBool) }
        for timestamp in ["not-a-date", "2026-99-99T00:00:00Z", "2026-11-13T00:00:00+00:00", "2026-11-13T00:00:00Z\n"] {
            var object = github(.ccbaga); object["published_at"] = timestamp
            rejects(.invalidTimestamp, "invalid publication timestamp") { _ = try parse(.ccbaga, object) }
        }

        var several = claude()
        several["releases"] = [claudeEntry("99.0.0"), claudeEntry("5.11492.5"), claudeEntry("1.0.0")]
        require(try parse(.claudeDesktop, several).version == "5.11492.5", "match currentRelease not highest or first version")
        var absentCurrent = claude(); absentCurrent["currentRelease"] = "5.11492.6"
        rejects(.missingArtifact, "currentRelease must exist") { _ = try parse(.claudeDesktop, absentCurrent) }
        var duplicateClaude = claude(); duplicateClaude["releases"] = [claudeEntry("5.11492.5"), claudeEntry("5.11492.5")]
        rejects(.duplicateAsset, "duplicate Claude versions") { _ = try parse(.claudeDesktop, duplicateClaude) }
        var manyClaude = claude(); manyClaude["releases"] = Array(repeating: claudeEntry("5.11492.5"), count: Catalog.maximumClaudeReleases + 1)
        rejects(.invalidSchema, "bounded Claude releases") { _ = try parse(.claudeDesktop, manyClaude) }
        let mismatch = alterUpdate(claude()) { $0["version"] = "5.11492.6" }
        rejects(.releaseMismatch, "updateTo.version mismatch") { _ = try parse(.claudeDesktop, mismatch) }
        let wrongName = alterUpdate(claude()) { $0["name"] = "Claude Code 5.11492.5" }
        rejects(.releaseMismatch, "Desktop name not CLI") { _ = try parse(.claudeDesktop, wrongName) }
        let desktopURL = desktop.artifactURL.absoluteString
        for url in [desktopURL.replacingOccurrences(of: "https:", with: "http:"),
                    desktopURL.replacingOccurrences(of: "downloads.claude.ai/", with: "downloads.claude.ai.evil.invalid/"),
                    desktopURL.replacingOccurrences(of: "downloads.claude.ai/", with: "downloads.claude.ai:443/"),
                    desktopURL.replacingOccurrences(of: "downloads.claude.ai/", with: "token@downloads.claude.ai/"),
                    desktopURL.replacingOccurrences(of: "universal", with: "x64"),
                    desktopURL.replacingOccurrences(of: "5.11492.5/", with: "5.11492.4/"),
                    desktopURL.replacingOccurrences(of: ".zip", with: ".dmg"),
                    desktopURL.replacingOccurrences(of: "1403e2cf44abfb23809c8ae11238d5e9704a41c2", with: String(repeating: "a", count: 64)),
                    desktopURL + "?credential=secret", desktopURL + "#fragment",
                    "https://downloads.claude.ai/claude-code-releases/5.11492.5/darwin-arm64/claude"] {
            let object = alterUpdate(claude()) { $0["url"] = url }
            rejects(.invalidArtifact, "reject noncontract Claude artifact") { _ = try parse(.claudeDesktop, object) }
        }
        let inventedHash = alterUpdate(claude()) { $0["sha256"] = String(repeating: "a", count: 64); $0["size"] = 123 }
        let ignoredHash = try parse(.claudeDesktop, inventedHash)
        require(ignoredHash.sha256.value == nil && !ignoredHash.sha256.firstPartyExplicit && ignoredHash.declaredSizeBytes == nil,
                "unreviewed feed additions cannot silently establish checksum trust")

        for bytes in [Data(), Data("not JSON".utf8), Data("[]".utf8), Data("{}".utf8)] {
            let doc = Catalog.MetadataDocument(product: .ccbaga, data: bytes, finalURL: Catalog.Product.ccbaga.metadataURL, retrievedAt: retrievedAt)
            rejects(.invalidSchema, "malformed schema") { _ = try Catalog.parse(doc) }
        }
        let oversized = Catalog.MetadataDocument(product: .ccbaga, data: Data(repeating: 32, count: Catalog.maximumMetadataBytes + 1),
                                                 finalURL: Catalog.Product.ccbaga.metadataURL, retrievedAt: retrievedAt)
        rejects(.metadataTooLarge, "bounded JSON bytes") { _ = try Catalog.parse(oversized) }
        var exactlyBounded = try document(.ccbaga, github(.ccbaga)).data
        exactlyBounded.append(Data(repeating: 32, count: Catalog.maximumMetadataBytes - exactlyBounded.count))
        let bounded = Catalog.MetadataDocument(product: .ccbaga, data: exactlyBounded,
                                               finalURL: Catalog.Product.ccbaga.metadataURL, retrievedAt: retrievedAt)
        require(try Catalog.parse(bounded).version == "0.2.50", "metadata byte upper bound inclusive")

        for product in Catalog.Product.allCases {
            try Catalog.validateMetadataURL(product.metadataURL, for: product)
            for url in [product.metadataURL.absoluteString.replacingOccurrences(of: "https:", with: "http:"),
                        product.metadataURL.absoluteString + "?x=1", product.metadataURL.absoluteString + "#fragment",
                        "https://untrusted.invalid/feed.json"] {
                rejects(.untrustedSource, "exact HTTPS metadata endpoint") { try Catalog.validateMetadataURL(URL(string: url)!, for: product) }
            }
            let ok = HTTPURLResponse(url: product.metadataURL, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": "100"])!
            try Catalog.validateMetadataResponse(ok, for: product)
            let noLength = HTTPURLResponse(url: product.metadataURL, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!
            try Catalog.validateMetadataResponse(noLength, for: product)
            for status in [301, 302, 401, 403, 404, 500] {
                let response = HTTPURLResponse(url: product.metadataURL, statusCode: status, httpVersion: "HTTP/1.1", headerFields: [:])!
                rejects(.invalidResponse, "non-200 metadata response") { try Catalog.validateMetadataResponse(response, for: product) }
            }
            let wrong = HTTPURLResponse(url: URL(string: "https://untrusted.invalid/feed.json")!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!
            rejects(.untrustedSource, "final response source") { try Catalog.validateMetadataResponse(wrong, for: product) }
            let huge = HTTPURLResponse(url: product.metadataURL, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": "1048577"])!
            rejects(.metadataTooLarge, "response content length cap") { try Catalog.validateMetadataResponse(huge, for: product) }
        }
        let wrongDocument = try document(.ccbaga, github(.ccbaga), finalURL: Catalog.Product.clashVergeRev.metadataURL)
        rejects(.untrustedSource, "parser rechecks metadata provenance") { _ = try Catalog.parse(wrongDocument) }
        let invalidDate = try document(.ccbaga, github(.ccbaga), at: Date(timeIntervalSince1970: -1))
        rejects(.invalidTimestamp, "invalid retrieval time") { _ = try Catalog.parse(invalidDate) }

        let documents = try [document(.claudeDesktop, claude()), document(.ccbaga, github(.ccbaga)), document(.clashVergeRev, github(.clashVergeRev))]
        let plan = try Catalog.freeze(documents, at: retrievedAt)
        require(plan.artifacts.map { $0.product } == [.ccbaga, .clashVergeRev, .claudeDesktop], "deterministic three-GUI order")
        require(plan == (try Catalog.freeze(Array(documents.reversed()), at: retrievedAt)), "deterministic snapshot irrespective input order")
        require(!plan.binariesDownloaded && !plan.applicationsInstalled, "snapshot not installation evidence")
        rejects(.incompleteCatalog, "missing application") { _ = try Catalog.freeze(Array(documents.prefix(2)), at: retrievedAt) }
        rejects(.incompleteCatalog, "repeated application") { _ = try Catalog.freeze([documents[0], documents[0], documents[1]], at: retrievedAt) }
        rejects(.invalidTimestamp, "freeze before acquisition") { _ = try Catalog.freeze(documents, at: retrievedAt.addingTimeInterval(-1)) }
        let encoded = try plan.encodedJSON()
        require(encoded == (try plan.encodedJSON()), "stable JSON encoding")
        let json = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        let planned = json["artifacts"] as! [[String: Any]]
        let jsonSHA = planned[2]["sha256"] as! [String: Any]
        require(jsonSHA["firstPartyExplicit"] as? Bool == false && jsonSHA["value"] == nil, "JSON preserves absent Claude digest")
        let output = String(data: encoded, encoding: .utf8)!
        for forbidden in ["packet_policy", "proxy", "password", "credential=", "claude-code-releases", "/Users/"] {
            require(!output.contains(forbidden), "no private configuration or CLI references in plan")
        }
        let sanitized = Failure.transportFailure.localizedDescription
        require(!sanitized.contains("secret") && !sanitized.contains("http"), "errors do not expose network payloads")
        print("PASS: \(checks) offline metadata/parser/plan checks; no networking, binaries, installation or VM actions.")
    }
}
