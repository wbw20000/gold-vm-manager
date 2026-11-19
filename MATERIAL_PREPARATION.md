# Reviewed original application materials

[preinstall_materials.py](<preinstall_materials.py>) prepares **CCBaga A+B, Clash Verge GUI, and Claude Desktop together**, from the exact public original URLs in [guest_app_pins.py](<guest_app_pins.py>). No developer evidence/cache paths, installed host applications, ambient proxies, credentials, latest-version discovery, app execution, or VM operations are used.

## Background-worker API (Python 3.9)

```python
from preinstall_materials import MaterialManager, capability_report

report = capability_report()              # sanitized; no network/mount/VM probes
# Parent creates a dedicated, empty, canonical absolute directory, mode 0700.
# Parent holds its lifecycle lock through preparation AND subsequent installation.
manager = MaterialManager(
    canonical_private_material_root,      # required; never inferred from HOME
    # manifests=None,                     # defaults to reviewed_manifests()
    # loopback_proxy="http://127.0.0.1:19080",  # optional, explicit, no credentials
    cancelled=cancel_event.is_set,
    progress=publish_progress,            # dict: attempt_id, stage, product, resume_supported
                                          # (+ completed_bytes, total_bytes while downloading)
)
try:
    materials = manager.load_reusable()   # this store's newest completed attempt, fully revalidated
except MaterialPreparationError:          # 'material-cache-miss' (or every candidate failed)
    materials = manager.prepare()         # tuple[offline_install.Material, ...], fixed order
attempt_id = manager.last_attempt_id      # save in the parent's lifecycle transaction
public_status = manager.summary(attempt_id)
# Later, using the SAME root and reviewed catalog:
materials = MaterialManager(canonical_private_material_root).load(attempt_id)
```

An explicit `manifests=` override is a **trusted, previously reviewed catalog**, not an auto-trust interface. All three products, complete GUI expectations, pinned SHA-256, signer identities and review sources remain mandatory. A changed catalog cannot load old attempt records.

Only the existing tested tuple `Darwin / arm64 / macOS 26.6.2 / macos-26.6.2` is enabled, with fixed native `hdiutil`, `diskutil`, `ditto`, `xattr`, `lipo`, `codesign`, and `spctl` required. Unknown OS versions, Intel/Rosetta processes and different disk schemas fail closed. Tool presence is not a successful signature or mount assessment: real operations must still pass their existing validators. Extending this allowlist requires separately reviewed native/schema evidence.

## Durable trust boundary

Each `prepare()` exclusively creates a new random attempt with its own cache, staging and evidence. A completed `DownloadReceipt` is fsynced **before** the separate native `quarantine.ensure` step. Controlled DMG/ZIP extraction comes from [offline_payload.py](<offline_payload.py>); full bundle/plist/architecture/Apple-chain/signature/notarization verification comes from [guest_app_artifacts.py](<guest_app_artifacts.py>). Nothing weakens pins, signing checks, archive constraints or quarantine.

The dedicated store binds root identity and authenticated records to exact manifests, original download receipts, raw-file identity/hash, complete source trees, app-root identities, quarantine values and verification evidence. `load(id)` accepts only this store's committed records and repeats raw hashing, filesystem checks and native full-set verification; it does not repair missing quarantine. Internal, contained Framework symlinks remain intact; control/cache path symlinks, escaping links, hardlinked regular files, foreign owners, unsafe permissions, extra/missing applications and reused output directories are rejected. Records are private, exclusive-create and directory-fsynced; outputs are never overwritten or deleted.

`load_reusable()` lets a new job reuse a download that an earlier job already completed and verified, instead of downloading again. Candidates are only this store's attempts whose signed start record matches the store and the **current** reviewed manifests, with a signed completion record and no failure record; failed, cancelled and interrupted attempts are never candidates. The newest candidates (at most three, by completion time) are each rebuilt through `load()`, so every reuse repeats raw hashing plus native signature, notarization and quarantine checks. A candidate that fails is skipped and left exactly as found, never repaired. When none passes it raises `material-cache-miss` and the caller downloads a fresh set. There is still no import of foreign caches or partial downloads.

Authentication detects accidental/foreign record edits, **not a hostile same-UID process able to read the store key**. Keep the entire root exclusive and do not expose it as a shared writable directory. A store lock refuses concurrent operations, but does not replace the parent's lifecycle lock. Returned materials remain source inputs: the existing offline installer must reverify them and validate the new guest disk independently.

## Failures, cancellation and limits

`MaterialPreparationError.code` is a stable sanitized code; `.attempt_id` and `manager.last_attempt_id` identify a retained attempt when one was allocated, and `.product` names the product key that was being processed (`None` before the first or after the last product). A fixed artifact-layer cause is kept as the code (for example `download-timeout`, `download-connection-lost`, `checksum-mismatch`, `verification-tool-rejected`); only causes without a fixed code fall back to `<stage>-failed`. The failure record stores the same `code` and `product`. Byte progress is throttled to about every 2% of a download, plus its end. `summary(id)` returns only public official URLs, fixed product/app names and status; it is **not** current verification or installation success. Raw native evidence is private untrusted diagnostic data, never UI content. Progress observer exceptions are ignored. Neither public summaries nor progress include proxy values, exception bodies, signed CDN redirect URLs or command output.

Cancellation is cooperative **between** bounded download/native stages, not interruption of an in-flight download or DMG mount. The download deadline defaults to the established helper's 2700 seconds and can be explicitly bounded with `deadline_seconds=`. Native operations retain their existing timeouts and controlled cleanup. Do not kill a worker and infer that attachments were cleaned up.

Failures and cancellation report `failed-retained` / `cancelled-retained`; a nonterminal durable attempt reports `interrupted-retained`. None is installable. **Resume is deliberately unsupported:** `resume(id)` raises `resume-unavailable-retained-attempt`. The current downloader chooses a random partial name internally; this module never guesses, scans for, adopts, or retries one. Future resume requires a durable known-stopped attempt plus exact partial inode/pin binding and exclusive ownership. A new explicit `prepare()` downloads a new complete set; old bytes/evidence stay retained. Parent recovery must review possible native attachments after interruption; this module performs no automatic cleanup/adoption.

## Parent responsibilities / tests

No IPSW, Tart or gvproxy acquisition is implemented. The capability report lists the required **unassessed** interfaces: reviewed IPSW restore input, verified Tart runtime, verified gvproxy runtime, exclusive lifecycle lock and fresh-guest-disk lifecycle. Parent owns consent, VM publication, guest installation, VPN/runtime, UI, packaging, cancellation scheduling and retained-output cleanup.

[tests/test_preinstall_materials.py](<tests/test_preinstall_materials.py>) uses real tiny temporary fixtures and mocked native tools/downloads/extraction only; no actual application, network, device, mount or VM operations:

```sh
/usr/bin/python3 -m unittest discover -s tests -p 'test_preinstall_materials.py' -v
```
