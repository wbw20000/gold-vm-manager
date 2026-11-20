# Reviewed host materials: download/import only

[Implementation](<host_artifacts.py>) is Python 3.9 stdlib-only and owns **raw material verification**, not host installation or VM control. It does not import/use the three-product guest `ArtifactManifest`.

## Frozen API

```python
from host_artifacts import SPECS, Receipt, Progress, ArtifactError, acquire, import_local

receipt = acquire(
    'podman-installer', private_cache_root,
    loopback_proxy=None,
    progress=lambda event: print(event.phase, event.completed_bytes, event.total_bytes),
    cancelled=lambda: False,
    deadline_seconds=86400,
)
# Explicit caller-selected local file, copied to a NEW private cache inode:
receipt = import_local('ipsw', selected_file, private_cache_root,
                       progress=progress_callback, cancelled=cancel_callback,
                       deadline_seconds=86400)
```

- `SPECS` is a read-only mapping of frozen `Spec` values. Only string keys `podman-installer`, `tart`, and `ipsw` are accepted. There is no URL, custom manifest, mutable registry, or `Spec` parameter in the acquisition API. Small test fixtures replace the module mapping **only inside tests**.
- `Spec` exposes `key`, `version`, `url`, `size_bytes`, `sha256`, `filename`, `hash_provenance`, `review_source`, `redirect_hosts`, and computed `spec_sha256`.
- `Progress` is frozen: `spec_key`, `attempt_id`, `phase`, `completed_bytes`, `total_bytes`. Phases: `download`, `import`, `verify`, `cache-verify`, `accepted`. Counts restart for the separate full-file disk-verification pass. Cache reuse emits `cache-verify`; no transfer is implied. Progress is throttled to about four callbacks per second, except phase boundaries/completion, to avoid flooding the UI during a 20 GB transfer. Callbacks run synchronously and must return promptly.
- `cancelled()` must return an actual boolean. Cancellation/error keeps the attempt's bytes, never deletes them. `ArtifactError.code` is a stable safe code; `.attempt_id` identifies a locally generated attempt when one was created. Error text deliberately excludes URL responses, credentials, private source paths and exception causes. Transfer failures carry a fixed cause code instead of the generic `artifact-io-failed` when one applies (`download-timeout`, `download-connection-lost`, `download-connect-failed`, `download-dns-failed`, `download-tls-failed`, `download-network-unreachable`, `download-protocol-error`, `host-disk-full`).
- The default finite deadline is **24 hours**; maximum **72 hours**, positive integer seconds. Network operations use at most a 30-second socket timeout, plus monotonic deadline/cancellation checks between responses, chunks, hashes and quarantine. `HTTPResponse.read1` avoids waiting for a full megabyte from a slow trickle. These are cooperative limits, not a hard process watchdog: OS DNS/filesystem stalls, synchronous callbacks and native quarantine calls cannot be preempted by this API. The parent should supervise long jobs if a hard wall-clock limit is required.
- `private_cache_root` can be created as a single final directory; its parents must already exist. Pass a trusted canonical path: symlink components (including macOS `/tmp` aliases), `..`, non-owned roots, or modes other than 0700 are refused. Do not resolve an untrusted symlink merely to silence this check.
- `import_local` always validates the specifically supplied source even if accepted cache material already exists. Sources must be caller-owned, single-link regular files with no symlink components. It takes a nonblocking shared flock and checks identity/size/mtime/ctime before and after copying. Source contents, permissions and xattrs are not changed. The source path is not persisted. The new cache copy receives download quarantine independently.

## Reviewed fixed pins

| Key | Version | Exact bytes | SHA-256 provenance |
|---|---|---:|---|
| `podman-installer` | 6.2.0 | 76,730,429 | Publisher GitHub release API digest |
| `tart` | 2.41.1 | 22,959,557 | Publisher GitHub release API digest |
| `ipsw` | 26.6.2 / 25G83 | 19,772,231,540 | Reviewed local SHA of official HTTPS acquisition; **not an independently published Apple hash** |

Public inputs and pins:

- [Podman macOS installer](<https://github.com/podman-container-tools/podman/releases/download/v6.2.0/podman-installer-macos-arm64.pkg>), [review source](<https://api.github.com/repos/podman-container-tools/podman/releases/tags/v6.2.0>): `b4628a29a4c70bbec757a84d0e429882d358cab18956a0017f99df74b37201a7`. Only its gvproxy is used (see below).
- [Tart archive](<https://github.com/openai/tart/releases/download/2.41.1/tart.tar.gz>), [review source](<https://api.github.com/repos/openai/tart/releases/tags/2.41.1>): `e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2`.
- [Apple IPSW](<https://updates.cdn-apple.com/2026SummerFCS/fullrestores/140-75212/A2A24B94-1FC1-45A3-93F7-C51B02AF1F4D/UniversalMac_26.6.2_25G83_Restore.ipsw>): `885503b7f4b06609e9a512f2befd40f59730640a3f1233e3892d60affdd51c95`.

The supplied authorized local IPSW was **stat'ed only** to obtain the exact size above. This implementation session did not hash, mount, execute, or read its contents. No private acquisition path is embedded in source or receipts. Public source/API URLs are provenance notes, never dynamic version discovery; changing `/latest` upstream does not change the pin.

## Transport boundary

Requests start only at a fixed registry URL and use normal certificate-verified HTTPS. There is no ambient cookies/auth/.netrc/proxy consumption and no TLS-relaxation option. `loopback_proxy` is an explicit credential-free HTTP CONNECT endpoint, precisely `http://127.0.0.1:PORT` or `http://[::1]:PORT`, canonical decimal port 1–65535. No `localhost` DNS, SOCKS, credentials, path, query, fragments, or ambient `NO_PROXY` bypass is accepted.

Redirects are manual, maximum four hops. GitHub assets may redirect only to exact host `release-assets.githubusercontent.com` with the strict GitHub numeric-repository/UUID release-asset path grammar; subsequent redirects must keep that exact CDN path. This is a host/path-grammar boundary, **not a separately reviewed repository-ID pin**; the full artifact SHA remains mandatory. Signed CDN queries stay in transient transport only. There is no Apple cross-host or alternate-path redirect allowlist: an unexpected Apple redirect fails closed and requires review, not a broad wildcard fallback.

Responses must be HTTP 200, identity encoding and the exact known total size. Conflicting/duplicate lengths, partial content, 206/416, unexpected encodings and overlong/truncated bodies fail. HTTP errors never trigger automatic retries. The final whole cache file is hashed from disk after fsync; HTTP metadata alone is never acceptance.

## Append-only attempts and acceptance

Each new attempt creates a distinct `<key>-<uuid>` 0700 directory under the caller-owned private root. Artifact/metadata files are exclusively created with `O_EXCL | O_NOFOLLOW`, 0600, caller ownership and single-link checks. Component-wise directory-FD opens reject symlink traversal; pathname/FD identity is rechecked at publication boundaries. Artifact flocks are nonblocking and remain held through receipt and quarantine work.

Within an attempt, the artifact basename alone is **not acceptance**. Files are never renamed, deleted, replaced or chmod'ed executable. Failed artifacts retain the same inode, including zero-byte or partial downloads. Existing failed/receipt-only attempts are not promoted or reused.

Publication order:

1. Create and fsync attempt metadata; stream bounded raw bytes into the new private artifact.
2. Fsync artifact; hash every byte of that on-disk inode; check exact size, SHA and stable identity.
3. Exclusively create/fsync the byte-verification receipt and fsync its containing directory.
4. Call [quarantine policy](<quarantine_policy.py>) `ensure` **only now**. This invokes the existing fixed native xattr policy, adds missing internet-origin quarantine, preserves existing quarantine, and never clears xattrs. Check inode again and fsync.
5. Exclusively create/fsync the separate acceptance record. Only then return the accepted `Receipt`.

`Receipt.receipt_path` names the durable pre-quarantine byte proof (its `quarantine_ensured` is false); `Receipt.acceptance_path` names the post-quarantine record identical to the returned receipt (`quarantine_ensured` true). This deliberate two-record protocol leaves inspectable evidence if quarantine fails. Neither record is a native trust decision. Other fields include `artifact_path`, `spec_key`, `spec_sha256`, `version`, `attempt_id`, `size_bytes`, `sha256`, `source_kind`, canonical public `source_url`, bare `final_host`, `hash_provenance`, device/inode/mtime and schema.

Cache reuse requires both owned private receipts to exactly match the fixed spec, path, inode and metadata, then takes the artifact flock, **freshly hashes every byte**, and re-ensures quarantine. Corrupt accepted entries fail closed rather than silently replacing them. The cache is not a defense against hostile processes with the same UID ignoring locks, nor do returned pathname receipts hold a lifetime lock: parent consumers must keep the private cache exclusive, revalidate identity/hash at their own use boundary, and independently enforce native trust. No filesystem-immutable flag is asserted.

**Resume status: not implemented.** There is no resume API, Range/If-Range request, automatic old-partial discovery, 200/416 fallback or retry of partial attempts. A later resumable protocol must explicitly bind the same owned inode under flock, stored pin/ETag, exact 206 Content-Range and full final digest. For now, a retry starts a new attempt and preserves the old one. Plan roughly 19.8 GB of additional cache space for each IPSW attempt/import, plus any selected source; there is no automatic cleanup or free-space reservation.

## Parent integration gates — still required

Every returned/persisted receipt explicitly has:

```text
digest_verified = true
native_execution_approved = false
binary_verification_performed = false
apple_restore_validation_performed = false
```

- **gvproxy:** the bare upstream release (`gvisor-tap-vsock` v0.9.0, `gvproxy-darwin`) has only a linker ad-hoc signature and no notarization; macOS refused to run it on the host, so it is no longer acquired. Instead the pinned Podman installer is acquired (quarantined like every download) and [host tools](<host_tools.py>) `ensure_gvproxy` checks the package (Developer ID Installer: Red Hat, Inc. (HYSCB8KRL2), notarized, `spctl --assess --type install` accepted), expands it **without installing** it, keeps only `podman/bin/gvproxy` (pinned SHA-256 `45881c33400a14c4c50d4ed7e814b69a60248aa0d78e9b541e879edc05346a85`), propagates the package's quarantine onto that copy, and checks the copy (Developer ID Application: Red Hat, Inc. (HYSCB8KRL2), identifier `gvproxy`, hardened runtime, Gatekeeper's standalone-code assessment `source=Notarized Developer ID`). Its Go build info names the same upstream v0.9.0 tag commit (`6dbb5d4f`) as the bare release. macOS still makes its own decision when the launcher runs it; nothing is re-signed and no quarantine is removed.
- **Tart:** safe archive/package inspection, native signature assessment, exact executable/CLI installation and permissions remain parent tasks. No extraction or binary invocation occurs here.
- **IPSW:** Apple framework signed restore validation, compatibility/support validation and all VM restore/control remain parent tasks. The local reviewed SHA is continuity evidence, not an Apple-published digest or an Apple framework validation result.
- No license acceptance, application launch, helper execution, signing mutation, profile/keychain/credential access, or VM operation is implemented.

## Offline verification

[Tests](<tests/test_host_artifacts.py>) use tiny inert fixture bytes, a test-local registry replacement, mocked HTTP responses/opener, and mocked quarantine. They never download real materials or invoke native tools/VMs.

```sh
/usr/bin/python3 -m unittest discover -s tests -p 'test_host_artifacts.py' -v
```

Verification: Python 3.9.6, 47 tests passing. Covers registry/pins, progress/cancel/deadline, safe proxy behavior, redirects, header and byte bounds, full digest, durable pre-quarantine proof, failure retention, cache corruption/reuse, inode/owner/mode/link/flock checks, and safe local import.
