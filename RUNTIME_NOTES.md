# Runtime share integration (scoped handoff)

Historical module-development notes for [runtime_shares.py](<runtime_shares.py>) and [test_runtime_shares.py](<tests/test_runtime_shares.py>). The test statements below describe that isolated development phase, not a fresh-clone or current-release acceptance run. Current project status and external dependencies are documented in [README](<README.md>).

## Parent launcher integration

Copy the module as `share_support.py` into each network controller directory. Under the existing per-VM launcher lock, after reading the Tart inventory's actual VM state and immediately before constructing Popen argv:

```python
from share_support import prepare_vm_shares
plan = prepare_vm_shares(VM_ID, BASE, inventory_entry['State'])
cmd = [TART, 'run', VM_ID, '--net-fd=' + str(vm_sock.fileno())]
cmd.extend(plan.arguments)   # argv only, NEVER a shell or string command
if plan.suspendable:
    cmd.append('--suspendable')
child = subprocess.Popen(cmd, ...)  # existing network-only FD lifecycle
plan.record_launch(child.pid)     # AFTER spawn, before reporting launch success
```

Any exception must abort launch through the existing fail-closed NIC/child cleanup. Never catch validation errors and retry without shares, discard a savedstate, or fall back to bare Tart/NAT. The launcher still owns VM identity, process locking and network lifecycle. `record_launch` records the argv share list passed to the spawned child; it is not a claim that the guest has booted or mounted it successfully.

## Backend exports and semantics

- `CONFIG_PATH`: current user's `~/Library/Application Support/GoldVMManager/config.json`.
- `STATE_DIR = CONFIG_PATH.parent`.
- `ShareValidationError(ValueError)` carries `.code` and safe Chinese text, without raw payloads or paths.
- `validate_shares(raw, *, allow_missing_ids=True) -> list`: returns new normalized dictionaries. Missing ID gets a UUID only for a NEW backend POST; saved config and manifests require IDs. UUID strings normalize to canonical lowercase; other IDs must match an ASCII stable-ID pattern. `read_only` and `enabled` are REQUIRED exact booleans, no silent writable defaults. Names are unique case-insensitively for conservative macOS compatibility. Disabled rows are validated too; maximum16 total rows. Backend retains responsibility for explicit RW acknowledgement.
- `load_desired(vm_id) -> list`: absent file or unconfigured allowed VM =>[]. Invalid file/JSON/schema never becomes empty. A malformed individual other-VM entry is only reported when that VM is read; global malformed schema/unknown VM keys fail closed.
- `read_last_launch(network_base) -> dict`: missing manifest =>{}; otherwise fully validates paths, private file metadata, schema, PID, actual enabled-only shares and fingerprint.
- `shares_fingerprint(shares) -> str`: order-sensitive canonical SHA-256 of normalized share dictionaries; an integrity/reconciliation marker, NOT authentication.
- `prepare_vm_shares(vm_id, network_base, vm_state) -> SharePlan`: exact states stopped/suspended/running only. `.arguments` and `.shares` return defensive lists; `.suspendable` true only with no actual shares; `.pending_changes` compares desired enabled rows against last actual rows for suspended/running. Cold stopped plan applies desired enabled rows immediately and has pending false.

Resume always uses the saved launch's actual shares in the same order/name/path/access mode. Legacy suspended VM with no manifest resumes with no shares, even if newly desired shares exist; those remain pending for next cold boot. Merely planning neither writes manifests nor touches guest/savedstate.

## Manifest

The network directory must exist, be canonical, current-UID-owned, mode0700-style private, and have no symlink components. No directory is auto-created.

`record_launch(pid)` atomically creates/replaces only `network_base/shares.last-start.json`, mode0600. Exact schema:

```json
{"version":1,"vm_id":"gold","pid":12345,"shares":[],"fingerprint":"<64 lowercase hex>","suspendable":true,"started_at":"<UTC ISO string>"}
```

Reads require all these fields and no extra fields. Actual manifest rows must be enabled. JSON files must be private regular current-owner single-link files, not symlinks/FIFOs; duplicate keys, non-finite numbers, oversized/deep/invalid JSON fail closed. A corrupt or foreign-VM manifest is never silently overwritten. Atomic staging uses a private O_EXCL/O_NOFOLLOW file, fsync, dir-fd-relative replacement and verified absolute-path/inode cleanup. A directory swap aborts rather than deleting an unverified staging path.

Both desired AND prior actual paths are validated, including when building a cold plan. If an old active directory disappeared or became forbidden, this intentionally blocks instead of silently discarding potentially saved attachment identity. Repair requires a separate explicit parent operation after independently proving there is no saved/running VM; do not use resume as a repair path.

## Path protections and boundaries

Exact roots `/`, `/Users`, host home, `/Library`, `/System`, `/Applications` are forbidden. Entire system subtrees, `~/.ssh`, `~/.tart`, keychains, Manager state/source/install and all three live network controller directories are protected. Selecting an ANCESTOR of protected data is rejected too, since sharing it would expose that descendant. Dedicated sibling project folders remain allowed; the user's entire project workspace is not declared a protected subtree just because Manager's source is a child.

Configurable constants: `HOST_HOME`, `PROTECTED_ROOTS`, `PROTECTED_SUBTREES`, `STATE_DIR`, `CONFIG_PATH`, `MANAGER_SOURCE_DIR`, `MANAGER_INSTALL_DIR`, `MANAGER_EXTRA_DIRS`, `NETWORK_CONTROLLER_DIRS`. If the parent installs the manager somewhere else, update the corresponding constants consistently in backend and installed helper copies. The source protection root is the directory containing the running module (`__file__`), not a private developer checkout path. When the module is copied into a controller or App, that deployed directory is protected; an unrelated original checkout is not automatically discovered. Keep private development trees and credentials out of deliberately shared folders. Review all install-path constants when adapting the layout; this remains a configured prototype rather than a universal installer.

Selected directories must already exist, be owned by current UID and resolve without any symlink component. Spaces, Unicode, apostrophes, dollar signs and backticks are allowed in directory paths because no shell is involved. Colon, comma and control characters are rejected. `..`, relative and leading-double-slash paths are rejected. Parent must provide the canonical real path for symlink aliases (including macOS `/tmp` vs `/private/tmp`), not ask the module to follow them.

No share contents are inspected; permissions/ownership and path identity do not prove a selected project's contents are harmless. A same-user host process can race filesystem mutations between validation and VZ path open; record_launch revalidates paths and inode identity but cannot pin the eventual VZ attachment with an FD. This is not a sandbox against a malicious same-UID host process. Users should not place secrets, external hardlinks or control files inside deliberately shared project directories.

## Tart source verification

[Official Tart2.41.1 Run.swift DirectoryShare parser](https://github.com/cirruslabs/tart/blob/2.41.1/Sources/tart/Commands/Run.swift): repeated `--dir=name:/absolute/path[:ro]` options use the default `com.apple.virtio-fs.automount` tag. Named shares (even singleton) form VZMultipleDirectoryShare and appear under `/Volumes/My Shared Files/<name>`. No custom tag is emitted.

The parser splits the final colon component by commas and recognizes any `ro` or `tag=` token; a path like `/project,ro` can therefore be misparsed as an option, motivating comma rejection. With any shares, app/launcher conservatively disables pause support and omits `--suspendable`; no live VZ save/restore compatibility test was claimed. Note Tart automatically sets its own suspendable flag when a savedstate exists, so preserving the saved attachment configuration is mandatory regardless of the requested current shares.

## Test command

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest discover -s tests -p test_runtime_shares.py -v
```

Final run: **47 tests passed in 0.196 seconds; exit code0, no failures/errors/skips.** Covers absent/legacy files, RW/RO argv, disabled rows, normal sibling/Unicode/space paths, UUID/stable IDs, duplicate names/IDs, exact booleans,16-item cap, protected roots/ancestors/descendants, symlink/nonowner/file/missing paths, private/owned/single-link JSON, FIFO nonblocking denial, malformed/duplicate/non-finite/oversized/deep JSON, per-VM desired errors, strict VM/state, saved-share resume/pending/remove/reorder behavior, invalid saved paths/fingerprints, defensive plan lists, mode0600 atomic record/PID checks, inode replacement revalidation, and replace/fsync error cleanup without touching unrelated files.

One initial test fixture accidentally generated a valid empty-share manifest while trying to test tampering; its fingerprint was then correctly made inconsistent, and the complete suite reran successfully. This was a fixture correction, not relaxed production validation.

All tests are offline/fixture-only, including fault-injected atomic writes. No network controller or actual user configuration is opened by tests.
