# Source installation and reviewed host tools

This is a **local source build**, not a signed/notarized public installer. [Host tooling](<host_tools.py>) never runs Tart, gvproxy, a VM, or a compiled helper. [The installer](<install_app.py>) never launches the new app/server and never replaces an existing application. No host Clash profile, browser session, credential, Keychain inventory or host network settings are harvested or copied.

## Prerequisites — explicit, no bootstrap package installation

The reviewed platform combination is **Apple Silicon / macOS 26.6.2**, with:

- Apple Command Line Tools or an explicitly selected Apple Xcode SDK providing `xcrun`, `swiftc`, `codesign` and `lipo`;
- `/usr/bin/python3` version **3.9 or newer**;
- system Ruby with `Psych.safe_load`;
- the complete project checkout, including the parent-owned one-click module and the restore helper source listed below.

`source_prerequisites()` checks this tuple, CLT selection, system Python, Ruby/Psych and SDK discovery. An unavailable tool or unsupported host fails closed. It does not run `xcode-select --install`, Homebrew, pip, npm, sudo, or any global package installer. Install required Apple developer tools yourself before retrying.

Native tool processes receive a fixed PATH, `LANG/LC_ALL=en_US.UTF-8`, and the legitimate OS account HOME from `pwd.getpwuid(os.getuid()).pw_dir`, not an inherited arbitrary HOME or `/var/empty`. Looking up the account's home path is not reading its profiles. Compiler TMPDIR comes only from `/usr/bin/getconf DARWIN_USER_TEMP_DIR`: its canonical location must be the OS per-user `/private/var/folders/.../T` directory, owned by the current uid at exactly 0700, with safe ancestors. The compiler uses this normal OS scratch area instead of a self-selected temporary directory that triggered Swift startup traps. Module caches, source snapshots, binaries and build diagnostics remain in the explicit private build root. Authentication, proxy, loader, inherited TMPDIR and arbitrary shell environment variables are not retained. Apple native trust/SDK tools may perform their ordinary OS trust/cache work; this module does not enumerate user certificates or use a signing credential.

## Install without replacing anything

Double-click [Install.command](<Install.command>) from the source checkout. It first checks CLT, safely locates its directory even with spaces/Unicode, invokes system Python with a clean environment, and defaults to a **new** application under the invoking user's Applications directory. It does not open the app after building it.

Or invoke the source installer explicitly, with canonical absolute paths:

```sh
/usr/bin/python3 install_app.py \
  --output '/absolute/new/Gold VM Manager.app' \
  --build-root '/absolute/private/build-root'
```

- Output's parent must exist and be a safe canonical non-symlink directory. The exact standard root-owned, `admin`-group `/Applications` directory at 0775 is allowed as a trusted system-administrator ancestor; arbitrary group/world-writable ancestors are not allowed, and this grants no new OS write privilege. Output must be absent, including no symlink at that name. Existing applications are always refused, including the original default `/Applications/Gold VM 管理器.app`; no replacement/update option exists.
- Build root must have an existing safe parent; it can be created as the final directory or already exist as caller-owned **0700**. Each invocation creates fresh unique package/helper attempts. A failed attempt or incomplete app is retained for exact caller review, not deleted, overwritten, resumed, or silently reused.
- Direct Python invocation retains the historic system Applications default if `--output` is omitted. The double-click entrypoint deliberately chooses the user's Applications directory instead. Neither path is privileged automatically.
- No Gatekeeper disabling, quarantine clearing, `spctl --add`, third-party re-signing, license acceptance, app/server launch, VM creation/start or host network change is performed.

A successful package writes its receipt to the explicitly selected build root's **unique** package attempt. There is no dependency on a historical ignored evidence helper or a one-time historical package receipt. The result includes source/artifact SHA values, verified helper entitlements, `signature: local-ad-hoc`, **`notarized: false`**, `developer_id_notarized: false`, and `launched: false`.

## Complete package, not an implicit fallback

[The installer's fixed closure](<install_app.py>) includes all prior manager/lifecycle/share/profile/packet modules plus:

- [VPN parsing](<vpn_config.py>), [VPN storage](<vpn_store.py>), [material preparation](<preinstall_materials.py>), [host acquisition](<host_artifacts.py>), [host tooling](<host_tools.py>), and [v2/v3 runtime preparation](<preinstall_runtime.py>);
- required parent-owned [one-click orchestration](<oneclick.py>) (a missing module is a hard error, never silently omitted);
- the [volume](<offline_volume.py>) and [payload](<offline_payload.py>) modules used to extract the downloaded DMG/ZIP originals, [guest artifacts](<guest_app_artifacts.py>), [reviewed guest pins](<guest_app_pins.py>) and [quarantine policy](<quarantine_policy.py>). The guest disk writers, ownership helper and first-login seed were removed on 2026-11-20;
- the original static files plus [preinstall JavaScript](<static/preinstall.js>) and [preinstall CSS](<static/preinstall.css>), and both [YAML](<examples/vpn/clash.yaml>)/[JSON](<examples/vpn/fields.json>) VPN examples;
- only the fixed three legacy guest setup source files, **not** a broad copy of any locally generated private setup configuration;
- required Swift source/entitlement inputs and the newly built local restore helper.

An AST pass also rejects a local Python import dependency not present in the declared package closure. Tests provide an entirely isolated fixture checkout containing every declared input; they do not omit parent-owned files merely because those files are still being developed.

The existing native wrapper compilation of [NativeApp](<NativeApp.swift>) **and** [GuestInitialization](<GuestInitialization.swift>) is preserved, including its AppKit/WebKit/ScreenCaptureKit/Vision frameworks. Source and packaged copies are hashed. The nested restore helper is signed/verified first; the final wrapper is then locally ad-hoc signed and deep/strict verified; the helper's entitlements are rechecked afterward. Third-party Tart is never included in that re-sign operation.

## Local helper compiler interfaces

```python
(clean_installer,) = compile_helpers(private_build_root)
```

`compile_helpers` returns a one-Path tuple: [CleanVMInstaller source](<CleanVMInstaller.swift>) is built for arm64 with Virtualization, signed locally with exactly the [virtualization entitlement](<CleanVMInstaller.entitlements.plist>), and its resulting signature/entitlements are verified. Nothing is built for, or run in, the guest any more (the first-login bootstrap and the ownership helper were removed on 2026-11-20).

All compiler outputs are new caller-owned executables under private attempts. Local ad-hoc signing uses `--sign - --timestamp=none`; it does not use a signing identity or claim Developer ID/notarization. Helpers are **compiled and statically verified only, never executed**. Per-attempt receipts bind source hashes, output hashes, entitlement checks, production status and no-execution/no-authorization facts. No existing evidence build is reused.

### Resolve installed helpers without runtime Swift compilation

```python
clean_installer = resolve_helpers(resource_root, private_build_root)
```

Use this resolver in one-click orchestration. `resource_root` is the explicit canonical source/resource directory, not a search path.

- Fresh builds emit `helpers.portable.json`. This record contains only fixed source/binary basenames, source/output hashes, exact arm64 build recipes, empty compiler-define lists, expected entitlements and honest local-ad-hoc/no-notarization/no-execution facts. **No development build path, SDK path, inode or temporary directory is embedded in a portable receipt.**
- The installer copies that record alongside the binary **before** signing the outer wrapper, then calls the resolver after signing as an installed-app self-check. An app built by an older installer carries a two-helper receipt that no longer matches; build a new app instead. The outer app's seal protects these resources; it is still only a local ad-hoc integrity seal, not a vendor identity or source-build attestation.
- If any candidate binary or its portable receipt exists, the resolver requires the complete corresponding set. It rejects duplicate JSON keys, unknown/altered build recipes, fixture defines, changed binary hashes, wrong architecture/signatures/entitlements and changed optional source hashes. It verifies a containing local wrapper's deep/strict signature when using its normal Resources/app directory. Binaries/receipt metadata and hashes are checked again across verification.
- A valid binary package needs **no Swift source, SDK lookup, compiler call, build-directory creation or helper execution**. If source files are present, their hashes must match the portable record; their absence does not trigger compilation. Runtime verification uses only static codesign/lipo checks.
- An unreceipted, incomplete or tampered binary set is never adopted, overwritten, or silently repaired by rebuilding. A packaged app missing its helpers is refused even if Swift source happens to be included. Only a source checkout with no candidate binaries/receipts and all required sources may fall back to a fresh private source build.

Native compiler failures retain `HostToolError.code=native-tool-rejected`, the exact numeric `returncode`, and a `diagnostic_path` to bounded raw compiler output in a new 0600 file inside that private build attempt. The public error remains sanitized; no environment values or third-party target diagnostics are dumped. A timeout is reported distinctly. The compiler environment is never replaced with the full inherited environment to get around a failed startup.

## Tart tool interface and independent trust constraints

```python
receipt = ensure_tart(private_tools_root, artifact_receipt=accepted_tart_download)
# OR an explicitly chosen compatible existing app/executable, never a scan:
receipt = ensure_tart(private_tools_root, existing_tart=explicit_app_or_executable)
tart_path = receipt.executable_path
```

Exactly one source is required. `TartReceipt` is frozen and exposes `app_path`, `executable_path`, `receipt_path`, `version`, `team_id`, `executable_sha256`, `bundle_tree_sha256`, `notarized`, `source_kind`, `archive_sha256`, `execution_performed=False`.

### Download/import receipt route

The only downloadable archive accepted is the frozen [host artifact registry](<host_artifacts.py>) Tart **2.41.1** asset:

- [Reviewed release asset](<https://github.com/openai/tart/releases/download/2.41.1/tart.tar.gz>), 22,959,557 bytes;
- SHA-256 `e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2`, from the [public release API](<https://api.github.com/repos/openai/tart/releases/tags/2.41.1>).

`ensure_tart` does not download anything. It requires the exact accepted `host_artifacts.Receipt`, private durable byte-proof and acceptance records, matching spec fingerprint, owner/mode/single-link/inode/size/mtime, **a fresh full compressed-file SHA**, and retained source quarantine. A nonblocking artifact flock stays held through parsing/extraction. Record fabrication without the reviewed bytes cannot satisfy the SHA pin.

The same Python `tarfile` parser instance performs preflight and extraction from that held file descriptor. No system tar/extractall or second parser is used. Only one exact `tart.app` bundle root is accepted. The reviewed upstream archive's top-level `LICENSE` is the only permitted sibling: a non-executable regular file between 1 byte and 128 KiB, retained outside the app. Absolute/dot/dotdot/empty-component paths, duplicate paths, case/Unicode aliases, hardlinks, special/device/FIFO/sparse members, unsafe modes, unsupported PAX metadata and escaping/broken/cyclic symlinks are rejected before writes. Internal framework symlinks are preserved, created only **after** regular files/directories; no file is written through an archive-created link.

Limits are 20,000 entries, 256 MiB per file, 512 MiB expanded file content, 576 MiB expanded tar positioning, bounded parser metadata reads and a cooperative 15-minute parse/extraction budget. The original bundle bytes, signature files, internal links and archive permissions are preserved. A durable extraction record precedes exact source-quarantine propagation. Native verification follows. Failure retains the private attempt and creates no success receipt. There is no automatic fallback to another extractor, another root layout, native trust exception or unsigned binary.

### Native verification, for either route

Requirements are all mandatory:

- signed bundle identifier **`com.github.cirruslabs.tart`**;
- exact version **2.41.1** in the signed plist;
- **arm64** architecture;
- `codesign --verify --deep --strict` with an Apple generic anchor, Developer ID Application chain requirements and team **`9M2P8L4D89`**;
- matching displayed TeamIdentifier/Identifier and the exact `Cirrus Labs, Inc. (9M2P8L4D89)` Developer ID Application authority (the exact no-comma legacy spelling for the same Team is also accepted);
- successful `spctl --assess --type execute` explicitly reporting **Notarized Developer ID**;
- unchanged bounded bundle-tree snapshot before/after static assessment.

The parent supplied the reviewed signing identity after read-only inspection of its installed official Tart. **That local observation alone is not download-source provenance.** Download mode also requires the independently frozen public release digest above. Explicit-existing mode reports `source_kind=explicit-existing-native-verified` and an empty archive digest; it does not pretend the existing bundle came through the public archive acquisition route.

No Tart `--version`, license operation, VM invocation, backend invocation or installation occurs. No third-party signature is changed. Parent must preserve exclusive ownership/revalidate at use boundaries and separately manage any required license, first execution or runtime consent.

## Verification status and remaining gates

Offline tests:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s tests -p 'test_host_tools.py' -v
```

The fixture suite covers hash/receipt continuity, controlled tar extraction, signature and entitlement checks, production compiler flags, source-less portable helper reuse, and refusing to overwrite an app. It does not execute third-party code or start a VM.

The standalone source package has been built on the reviewed Apple Silicon / macOS tuple and checked from an isolated home. Its native wrapper and three helpers are held to local ad-hoc signature and entitlement checks, **not Developer ID notarization**. A clean source checkout does not need any earlier receipts, build tools compiled by a developer, or local diagnostics. Use the installer above to produce new receipts for your build. The [read-only restore-helper tests](<tests/test_CleanVMInstaller.py>) compile their own helper in a temporary directory.

Native validation has accepted the fixed 26.6.2 / 25G83 IPSW for inspection and the exact Tart 2.41.1 archive for restricted extraction and notarization checks. These checks do not prove guest boot or VPN connectivity, nor do they authorize execution of gvproxy or privileged guest provisioning. See [the development handoff](<DEVELOPMENT_HANDOFF.md>) for current integration limits and the outstanding authorization issue.
