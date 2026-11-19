# Guest GUI artifact acquisition and static verification

Scope: [guest_app_artifacts.py](<guest_app_artifacts.py>) is a Python 3.9 stdlib-only helper. Its [offline fixture tests](<tests/test_guest_app_artifacts.py>) mock all network and subprocess use. It does **not** operate a VM, mount images, extract archives, install/run apps, invoke an installer, read host accounts/configuration, clear quarantine, change Gatekeeper, or re-sign anything. Importing performs no I/O. No real binaries were downloaded or inspected while developing this helper.

## Caller contract

```python
from dataclasses import replace
from guest_app_artifacts import (
    AppExpectation, freeze_manifest, download_artifact, resume_artifact,
    extraction_plan, verify_app_bundles, write_evidence,
)

# Use the frozen catalog's actual release metadata, not these placeholder names.
manifest = freeze_manifest(
    product=product,                  # ccbaga | clashVergeRev | claudeDesktop
    version=version,
    artifact_url=exact_official_url,
    known_sha256=reviewed_sha256_or_none,
    declared_size_bytes=declared_size_or_none,
    maximum_download_bytes=2 * 1024**3,
)
raw = download_artifact(manifest, canonical_private_cache_dir)
# Optional explicit credential-free local CONNECT transport, never ambient env:
# raw = download_artifact(manifest, cache, loopback_proxy='http://127.0.0.1:7897',
#                         deadline_seconds=10800)
# Only AFTER a failed previous attempt has stopped, with a trusted SHA-256 pin:
# raw = resume_artifact(manifest, cache, explicitly_selected_partial_path,
#                       loopback_proxy='http://127.0.0.1:7897', deadline_seconds=10800,
#                       expected_etag=previous_strong_etag_if_known_else_none)
write_evidence(raw, private_evidence_dir / 'raw.json')
plan = extraction_plan(manifest)      # requirements only; no command is executed

# Parent safely mounts readonly / preflights and extracts into exclusive staging.
# Review identities and plist allow-values separately; do not auto-trust observed
# TeamIdentifier, app filename, Info.plist, metadata, or successful codesign -d.
manifest = replace(
    manifest,
    vendor_team_ids=reviewed_team_ids_tuple,
    identity_review_sources=reviewed_public_https_sources_tuple,
    expected_apps=reviewed_app_expectations_tuple,
)
verified = verify_app_bundles(manifest, staging_root, app_paths, raw)
write_evidence(verified, private_evidence_dir / 'verified.json')
# Parent copies complete apps preserving metadata and performs verification again.
```

`AppExpectation` fields are `name`, `bundle_identifiers`, `bundle_names`, `executable_names`, `short_versions`, `bundle_versions`, `required_paths`; all allow-lists must be tuples. The last defaults to `('Contents/Resources',)` and must retain that nonempty GUI resources directory. Supply explicit allowed plist values, including separate `CFBundleVersion` and `CFBundleShortVersionString`. Do not assume Chromium-based CCBaga-B has the product's version. Expected names and order are fixed:

- `ccbaga`: `CCBaga-A.app`, `CCBaga-B.app` — both, never updater-A alone.
- `clashVergeRev`: `Clash Verge.app` — intact GUI, not a core.
- `claudeDesktop`: `Claude.app` — official Desktop, not Code CLI.

The optional manifest limits are `maximum_bundle_bytes` (default/hard ceiling 8 GiB) and `maximum_bundle_entries` (100,000). They apply to the complete selected app set. Smaller explicit limits are supported. The acquisition hard ceiling is 2 GiB.

Missing TeamIDs, identity-review source URLs, or any required plist allow-values cause `PendingReview` before a verification subprocess is invoked. No TeamID is hardcoded by this module. A trusted reviewer may use official artifact digest + Apple certificate-chain validation as a documented signer-bootstrap basis; the helper does not implement or automatically approve that bootstrap. A source URL is a provenance record, not proof that its contents establish the claimed identity.

For Claude, a missing publisher SHA-256 remains `None`. A raw download may compute its hash, but that is not independent authentication. Verifying this case additionally requires explicit `allow_unpinned_sha256=True` **and** reviewed signing identities; alternatively provide an independently reviewed digest and record its actual source in the caller's source manifest. A Homebrew digest must not be mislabeled as Anthropic-published. Changing review fields does not change `artifact_key`; changing acquisition fields does. Full verification receipts bind `manifest_sha256` to all frozen fields.

## Acquisition boundaries

- Initial HTTPS URLs must exactly match the reviewed product/version/asset contracts. No latest redirect, mirror, credentials, alternate port, query, fragment, percent-encoded path, updater archive or executable is accepted as an origin.
- GitHub may redirect only to HTTPS `release-assets.githubusercontent.com/github-production-release-asset/<reviewed-repository-id>/<UUID>`. IDs are `1413898431` for CCBaga and `721767116` for Clash Verge Rev. Subsequent CDN hops must keep the same path. Claude has no reviewed cross-host redirect exception. There are at most four redirect transitions. A new CDN format needs source review rather than a wildcard domain exemption.
- The custom opener has no cookie store, auth manager or ambient proxy settings. Explicit loopback transport accepts only `http://127.0.0.1:<port>` or `http://[::1]:<port>`, with no credentials, path, query or fragment. TLS verification stays enabled; this does not export the proxy into a VM or inspect its settings.
- New downloads require full HTTP 200, identity encoding, with consistent length if supplied. Actual bytes and declared size are checked independently, including when no Content-Length exists. Socket timeout is 30 seconds. The explicit integer `deadline_seconds` defaults to 2700 (45 minutes) for new downloads and 10800 (3 hours) for resume; the hard ceiling is 10800. It is never read from environment/configuration. A blocked socket read may extend beyond a streaming deadline check by its socket timeout. Changing the module does not extend an already running older invocation.
- Explicit cache/evidence roots must be canonical directories, not symlink aliases. Cache/evidence leaf directories must be owned by the current uid and private (0700 or stricter). The cache leaf can be created under an existing parent. On macOS canonicalize a trusted temporary directory explicitly, since `/var` can be a system symlink.
- A failed transfer raises a fixed cause, never exception text: `download-timeout` (no response or data within the 30-second socket timeout), `download-connection-lost`, `download-connect-failed`, `download-dns-failed`, `download-tls-failed`, `download-network-unreachable`, `download-protocol-error` or `host-disk-full`; anything else stays `download-failed` (`resume-failed` for resumes). `download_artifact(..., progress=callable)` reports `(completed_bytes, total_bytes_or_None)` after each chunk; observer exceptions are ignored.
- Files are created 0600 with `O_EXCL|O_NOFOLLOW`. Failed attempts retain random `.partial` files; they are never automatically resumed or reused. Fresh downloads and explicit resumes hold a nonblocking exclusive advisory inode lock through publication. A complete size/hash-checked raw download is published using a no-replace hardlink followed by removal of the checked temporary name. A checksum mismatch never gets a final artifact name. Raw receipt records only the final hostname, not signed CDN query tokens.
- The helper does not set or clear quarantine. Parent must preserve quarantine when present and deliberately implement its download-origin quarantine policy for stdlib downloads, which do not themselves attach browser quarantine metadata. Do not interpret absent quarantine as permission to skip signature/Gatekeeper checks.

### Explicit pinned-hash resume

`resume_artifact(manifest, cache_dir, partial_path, *, loopback_proxy=None, deadline_seconds=10800, expected_etag=None)` is opt-in and never invoked by import, a timeout, or `download_artifact`. The caller must establish that the prior attempt has ended. In particular, older downloads started before the locking implementation do not hold a lock; a new lock cannot prove that an old downloader is inactive. Do not inspect/modify/resume a still-running attempt's partial. Advisory locks also cannot stop an unrelated noncooperating process; the cache must remain exclusive and trusted.

- A non-`None` trusted SHA-256 pin is mandatory, including Claude. An unpinned HTTPS download cannot be resumed through this API merely by allowing unpinned bundle verification.
- Only the explicitly supplied original `32-lowercase-hex.partial` directly under the exact private cache is eligible. No cache scan, filename guessing, directory traversal, symlink, hardlink, foreign ownership, group/other-readable mode, special file or empty prefix is accepted. It opens the existing inode without truncation, checks and locks it, and rechecks identity/size/mtime/ctime after waiting for the response.
- Requests begin again at the frozen publisher URL, with `Range: bytes=<actual-local-length>-`; the same HTTPS and repository-specific CDN rules apply to every hop. Existing bytes are never transmitted. `200` (ignored Range), `416`, multipart, compressed encoding, malformed/duplicate Content-Range, wrong starting offset, unspecified/oversize total, nonfinal end offset, wrong declared size or mismatched Content-Length are rejected before appending. The single `206` response must contain the complete remaining range. Actual received length is separately enforced even without Content-Length.
- If the caller knows a prior **strong** ETag, pass it explicitly; the helper sends `If-Range` and requires the response's single strong ETag to match exactly. Weak/malformed/duplicate ETags are rejected. If no prior ETag is known, the module does not invent continuity from the current ETag. It accepts an absent ETag only because the final whole-file trusted SHA-256 is mandatory. The resumed receipt has an optional `etag` field (default `None` for old/fresh receipts).
- Appended bytes remain in the private partial on failure. On success, the entire actual on-disk prefix plus suffix is rehashed, size and hash must match, and only then is the locked inode published with no overwrite. A corrupt prefix, wrong-version continuation, short response or checksum mismatch never becomes a final artifact. There is no automatic restart, promotion of a complete existing partial without a request, or weakening of signing/Gatekeeper checks. A complete partial rejected as already complete needs a separate deliberate recovery decision, not a `416` success assumption.

## Static verification and receipts

The caller must pass only the expected complete app set below an exclusive, trusted staging root, extracted from the receipt's artifact. Canonical real directories are required; root/standard host Applications roots are refused. The helper does not search host installations. A caller is responsible for not pointing it at a host profile or installed app.

Verification rehashes the actual artifact and rejects a mismatching receipt. It inspects plist identity, name, executable, explicit version values and `APPL` package type; requires a real executable and nonempty GUI resources; checks ARM64 using `/usr/bin/lipo`; runs `/usr/bin/codesign --verify --deep --strict` against a requirement containing `anchor apple generic`, Developer ID certificate OIDs, an externally trusted TeamID, and the allowed bundle identifier; separately records `codesign --display --verbose=4`; and requires successful `/usr/sbin/spctl --assess --type execute --verbose=4` output explicitly reporting `Notarized Developer ID`. A disabled assessor, missing tool, output-format change, rejected/unsigned/ad-hoc app or unavailable trust assessment fails closed. No app or helper executable is run. Only the three fixed Apple inspection tools are invoked, without a shell and with a minimal non-secret environment.

The tree scanner hashes regular files and records directory modes and relative link text. Legal relative Framework symlinks are accepted. Absolute, broken, cyclic and escaping links are refused, including links that leave the bundle and return through an external link. Hardlinked regular files, special files, setuid/setgid entries, case/Unicode-normalization collisions, excess entries and oversized trees are refused. Bundle snapshots are checked before and after tool checks and the whole set is checked again before returning. This does not replace exclusive staging: it is not a general defense against a concurrent attacker controlling the filesystem. Verification/copy must not race another writer.

Evidence contains actual artifact SHA-256/size, full frozen manifest, bundle tree and executable hashes, plist versions/identity, observed architectures and TeamID, and inspection arguments/stdout/stderr. Tool output remains untrusted data, not instructions. Evidence is saved using an explicit `write_evidence` call to an exclusive private file. `installation_performed=False` and `extraction_proven_by_this_module=False` are intentional: static validation cannot prove extraction lineage or first-desktop readiness. Parent must copy from the validated staging tree, preserve all original signatures/links/quarantine, retain the receipt, and reverify the destination.

## Official public sources and unverified identities

Checked 2026-11-17; only public text/API responses were read:

- [CCBaga repository API](https://api.github.com/repos/liseami/CCBaga) confirms repository id `1413898431`; [official latest release API](https://api.github.com/repos/liseami/CCBaga/releases/latest) is the catalog's digest/asset source.
- [CCBaga v0.2.50 release script](https://raw.githubusercontent.com/liseami/CCBaga/v0.2.50/scripts/release-macos.py) obtains `CC_SIGN_IDENTITY` externally and describes signing/notarization/checks for A+B. It does **not** establish a public TeamID or prove actual release-byte verification.
- [CCBaga v0.2.50 browser packaging](https://raw.githubusercontent.com/liseami/CCBaga/v0.2.50/scripts/package-browser.sh) preserves framework links and obtains the browser version from its own plist. A's release version must not be assumed for B.
- [Clash Verge Rev repository API](https://api.github.com/repos/clash-verge-rev/clash-verge-rev) confirms repository id `721767116`; [official latest release API](https://api.github.com/repos/clash-verge-rev/clash-verge-rev/releases/latest) provides the complete GUI DMG selection.
- [Clash v2.5.10 release workflow](https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/.github/workflows/release.yml) references `secrets.APPLE_SIGNING_IDENTITY` and `secrets.APPLE_TEAM_ID`; their actual values are not public in that document.
- [Official Claude Desktop feed](https://downloads.claude.ai/releases/darwin/universal/RELEASES.json) is the catalog's version/ZIP source, not a TeamID assertion. Use the parent's newly frozen current selection, not the older research snapshot's version.
- [Anthropic macOS deployment documentation](https://support.claude.com/en/articles/12611117-deploy-claude-desktop-for-macos) confirms universal Desktop deployment but does not supply a reviewed signing TeamID in the text fetched for this work.

**No current CCBaga, Clash Verge Rev or Claude Desktop signing TeamID was independently established in this helper-development task.** Native web search was unavailable (`ddgs` provider unavailable); the known official URLs above were fetched directly. Public build intent and metadata are not binary verification. The parent may subsequently produce stronger binary/certificate/digest evidence and explicitly review an identity; that is separate work, not an assertion made here.

Run the side-effect-isolated fixtures with:

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_guest_app_artifacts.py -v
```

Runtime validation on 2026-11-17: **62 tests passed on actual system Python 3.9.6**, and the same 62 passed on Python 3.14.7. These were fixture-only executions: all network/subprocess calls were mocked, no running acquisition job or real partial was touched, and no real app/DMG was accessed.
