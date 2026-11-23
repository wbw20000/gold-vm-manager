# CleanVMInstaller (standalone helper, schema 1)

This helper creates a **new macOS installation from a verified local IPSW**, not a clone, restore of another VM, or Tart `create` invocation. It does not modify manager/UI code, installed applications, existing VM directories, or registration. It does not implement deletion, replacement, publication, downloads, boot-after-install, user provisioning, or network configuration for later Tart runs.

## Build (Apple Silicon, macOS 13+)

```sh
mkdir -p evidence/newbuild
xcrun swiftc -swift-version 6 -parse-as-library -O \
  -target arm64-apple-macos13.0 -framework Virtualization \
  CleanVMInstaller.swift -o evidence/newbuild/CleanVMInstaller
codesign --force --sign - --timestamp=none \
  --entitlements CleanVMInstaller.entitlements.plist \
  evidence/newbuild/CleanVMInstaller
codesign --verify --strict --verbose=2 evidence/newbuild/CleanVMInstaller
```

Only `com.apple.security.virtualization` is entitled. Ad-hoc signing is for local use, not notarized distribution. Packaging must preserve the signed executable/entitlement; this work does not install it into an application. The Swift `@main` async runner keeps the executor alive without blocking the main queue. VM construction, installation, and completion processing run on MainActor; KVO delivers scalar progress back to MainActor. A documented unchecked-Sendable wrapper transfers Apple's **immutable** restore-image metadata from its arbitrary-thread completion handler; no VM/configuration/installer object is transferred this way.

## Invocation

Read-only commands:

```sh
evidence/newbuild/CleanVMInstaller --help
evidence/newbuild/CleanVMInstaller --inspect --ipsw /absolute/local/verified.ipsw
evidence/newbuild/CleanVMInstaller --latest
```

`--latest` asks Apple's `VZMacOSRestoreImage.fetchLatestSupported` API for the latest host-supported restore-image metadata and URL. It accesses the network for metadata but **does not download an IPSW** or create a VM. A separate trusted caller must validate HTTPS/Apple download origin, obtain and verify the local IPSW, then inspect that exact local file. This helper does not authenticate a caller-supplied IPSW against an independent digest. Apple framework parsing is not a substitute for download provenance verification.

Creation syntax (creates new guest storage; do not run without explicit authorization):

```sh
# The caller supplies an already-created, empty, user-owned mode-0700 stage.
evidence/newbuild/CleanVMInstaller --create \
  --directory /absolute/private/empty-stage \
  --ipsw /absolute/local/verified.ipsw \
  --cpu 2 --memory-gib 4 --disk-gib 50
```

All five create arguments are mandatory. No destructive/rebuild mode exists. The parent must separately authorize any eventual old-VM removal and publish the successful stage under its own transaction rules. Prefer keeping the original VM untouched until an entire new installation succeeds. Never point this helper at an existing VM, even if that VM is powered off.

### Preconditions and safeguards

* Absolute paths only; no `..`, `.`, doubled/trailing separators, NULs, or symlink components. Input IPSW must be a nonempty regular local file, not group/world writable; it is opened read-only with a shared nonblocking advisory lock. Its device/inode/size/mtime/ctime are rechecked after inspection and before install.
* Stage must already exist, be wholly empty (including dotfiles), owned by the invoking uid, and exactly mode 0700. Every ancestor must be root/user-owned and not group/world writable; traversal uses `openat` + `O_DIRECTORY|O_NOFOLLOW`. Thus `/tmp/...` and `/var/...` symlink spellings are rejected: supply the actual canonical path instead.
* CPU and RAM must satisfy both IPSW requirements and framework/host bounds. Two CPUs remain **exactly two** if supported; never silently raised to Tart's usual four. RAM cannot exceed host physical RAM, CPU cannot exceed active host processors. All sizes are **binary GiB**, not decimal GB. A 50 GiB disk is 53,687,091,200 bytes.
* No disk minimum is exposed by the IPSW API. This helper accepts whole-number guest disk capacities from 30 to 1024 GiB. The lower bound is project policy, not a claim that every macOS release or future update fits on a 30 GiB disk. Free filesystem capacity must initially cover the entire requested disk plus 2 GiB reserve. Capacity is checked, **not reserved**; host memory pressure and later concurrent disk usage remain risks.
* Resource/path/media checks precede the first stage write. Full `VZVirtualMachineConfiguration.validate()` must happen after the new auxiliary storage/disk exist; later validation or install failure deliberately leaves a quarantined partial stage.
* A persistent, mode-0600 `.clean-vm-installer.claim` is created with `O_EXCL` before disk/NVRAM. Concurrent cooperating invocations cannot both win; a crashed/failed stage cannot be retried. Raw disk and JSON outputs also use exclusive descriptor-relative creation. Auxiliary storage uses Apple's create API with **no allowOverwrite option**. There are no delete, truncate-existing, rename-existing, or cleanup operations.
* Disk is a brand-new sparse raw regular file with the requested logical length. Its initial unwritten bytes are zero. NVRAM is initialized against the inspected hardware model; `VZMacMachineIdentifier()` is new, never copied. MAC uses `VZMACAddress.randomLocallyAdministered()` and is recorded in config only.
* Installation configuration has **zero network devices**, not an unconnected NAT adapter. Also zero shared directories, socket devices, serial ports, console/clipboard devices, and audio devices. The random MAC is **not attached during installation**. Apple host-side installer services may themselves use host networking; zero guest NICs is not a whole-host network firewall.
* Framework URL-based APIs cannot be fully descriptor-anchored. Identity/no-symlink checks are repeated around them, and restrictive stage/ancestor permissions defend against other unprivileged users. They do not constitute a security boundary against root or hostile same-uid processes concurrently changing directories/media, nor do POSIX mode checks exhaust macOS ACL privileges. Use a trusted parent-owned stage hierarchy with no write-granting ACLs and immutable verified media during installation.

## Output contracts

Help is plain text. Every other stdout record is a complete single-line JSON object; progress does not contain identifiers, input paths, tokens, or raw errors. `--inspect` and `--latest` succeed with exactly one JSON object. Failed commands emit `event: "error"` and exit nonzero. Exit 0 and a complete JSON/receipt are required for creation success; absence of completion is failure, including after signals/process termination. No resumable recovery or automatic cleanup is attempted.

### Inspect/latest JSON

```json
{
  "schemaVersion": 1,
  "event": "inspect",
  "macOSVersion": "26.0.0",
  "operatingSystemVersion": {"major": 26, "minor": 0, "patch": 0},
  "buildVersion": "EXAMPLE",
  "supported": true,
  "minimumCPUCount": 2,
  "minimumMemorySize": 4294967296,
  "hardwareModel": "<base64 VZMacHardwareModel.dataRepresentation>",
  "hostLimits": {
    "minimumCPUCount": 1,
    "maximumCPUCount": 8,
    "minimumMemorySize": 1073741824,
    "maximumMemorySize": 17179869184,
    "activeProcessorCount": 8,
    "physicalMemory": 17179869184
  }
}
```

Values above are illustrative, **not observed IPSW requirements**. If there is no host-compatible configuration, `supported` is false and `minimumCPUCount`, `minimumMemorySize`, `hardwareModel` are null. Successful inspection does not authorize creation. The latest record changes `event` to `latest` and adds `url` (Apple download URL); it does not disclose a local input path.

### Create JSONL

* `event: "validated"`: `cpuCount`, `memorySize`, `diskSize` (bytes), `networkDeviceCount: 0`, `directorySharingDeviceCount: 0`, `socketDeviceCount: 0`.
* `event: "installing"`, `networkDeviceCount: 0`.
* `event: "progress"`, `phase: "install"`, `percent` (integer 0–100; change-throttled KVO updates). A progress value of 100 is **not** proof of successful completion.
* `event: "complete"`, `schemaVersion: 1`, `networkDeviceCount: 0` only after successful Apple installation and writing/syncing config and receipt.
* Errors: `event: "error"`, `code` (stable helper category), `message` (sanitized text); unknown framework errors additionally carry integer `systemCode`. Never serialize NSError userInfo/description. Early CLI/path errors and installation failures all return nonzero; consumers must not rely on a particular nonzero integer.

### Successful staged directory and Tart config

Files: `disk.img`, `nvram.bin`, `config.json`, `.clean-vm-installer.claim`, `.clean-vm-installer.complete.json`. Config and receipt are written only **after** Apple's installation completion callback succeeds. The receipt has `schemaVersion: 1`, `status: "complete"`, `installer: "CleanVMInstaller"`, `macOSVersion`, `buildVersion`, and all three zero device counts. Keep the claim; it prevents reusing a stage. Parent publication should validate regular files, receipt, config identity fields, and exit status.

`config.json` schema matches Tart's public `VMConfig`/`Darwin` coders:

```json
{
  "version": 1,
  "os": "darwin",
  "arch": "arm64",
  "diskFormat": "raw",
  "cpuCountMin": "<integer from IPSW>",
  "cpuCount": 2,
  "memorySizeMin": "<integer bytes from IPSW>",
  "memorySize": 4294967296,
  "ecid": "<base64 NEW VZMacMachineIdentifier.dataRepresentation>",
  "hardwareModel": "<base64 inspected VZMacHardwareModel.dataRepresentation>",
  "macAddress": "<random locally administered unicast MAC>",
  "display": {"width": 1024, "height": 768, "unit": "px"}
}
```

Placeholder strings above stand for JSON integers where stated. No OS version is stored in the Tart config because that is not a defined Tart key; use the success receipt. Tart may attach networking/shares/sockets when **later** running this config: installation isolation does not automatically constrain Tart runtime behavior. The MAC and ECID are identifiers, not secrets, but are intentionally omitted from progress logs.

Schema references inspected 2026-11-16: [Tart VMConfig.swift](https://github.com/cirruslabs/tart/blob/main/Sources/tart/VMConfig.swift), [Darwin.swift](https://github.com/cirruslabs/tart/blob/main/Sources/tart/Platform/Darwin.swift), [VM.swift](https://github.com/cirruslabs/tart/blob/main/Sources/tart/VM.swift). These are public upstream source references, not proof of a particular installed Tart binary's behavior. Installed-app compatibility still needs authorized end-to-end validation.

## Historical module tests and current limits

The records in this section describe the helper's initial isolated development phase. Later, authorized real App-panel acceptance completed creation, rebuild, deletion and startup in the developer's configured environment. The earlier absence of live installation below is not the current project-wide status. This does not establish a complete first-boot setup, software install, network acceptance, or cross-host portability result; see [README](<README.md>).

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_CleanVMInstaller.py' -v
```

Tests invoke only `--help` and `--inspect` (including safely generated invalid IPSW bytes), and audit critical source invariants. They **never invoke `--create`**, call Tart, or touch real VM directories. Invalid-media inspection exercises the asynchronous completion/error path without installing a VM. An optional valid, previously verified cached IPSW can be inspected manually; none was found in the searched cache/download locations in this implementation session. After separate explicit authorization, `--latest` was also executed successfully (metadata only): macOS 26.6.2, build 25G83, supported=true, minimum CPU=2, minimum RAM=4 GiB, download host `updates.cdn-apple.com`. No IPSW was downloaded. This validates the asynchronous success/JSON metadata path, not local IPSW loading or installation.

No valid IPSW install, target claim concurrency, resource-rejection create path, sparse disk creation, guest-network observation, finished-VM boot, Tart load, failure recovery, or destructive rebuild has been executed. Those are deliberately deferred until separately authorized. Source inspection/static tests do not prove runtime behavior. macOS 26.6.2 (25G83), Apple Swift 6.4, and the locally selected macOS 27 SDK were observed; the executable deployment target is macOS 13.
