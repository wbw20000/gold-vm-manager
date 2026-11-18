# Explicit guest-ownership authorization

[guest_ownership.py](<guest_ownership.py>) and [GuestOwnershipHelper.swift](<GuestOwnershipHelper.swift>) implement a **separate, real macOS system-administrator authorization step** for ownership metadata on a newly restored, unpublished guest. They do not make an unprivileged `chown` work, and do not treat an `owners off` mount's displayed owner as persisted ownership.

The bridge never collects an administrator password. Each explicitly acknowledged operation invokes `/usr/bin/osascript` with a quoted `do shell script … with administrator privileges` statement on **stdin**. Only macOS presents/handles authorization. macOS may reuse its own authorization or display another genuine dialog for verification; the program does not cache credentials, promise a fixed dialog count, automate approval, or substitute a fake confirmation. Denial/failure retains the unpublished work and never relaxes ownership checks.

## Fixed capability

Production requires both real/effective UID 0. It accepts exactly a private ticket path and `--apply` or `--verify`. It never mounts/detaches, formats a disk, writes guest content, creates guest directories, starts a VM, executes guest binaries/scripts, accesses a network, changes quarantine/Gatekeeper, signs vendor apps, or changes modes. Parent performs content creation and all mount lifecycle operations.

The only ownership targets, derived in the helper rather than supplied as desired IDs, are:

| Guest Data-relative path | Required kind/mode | Desired uid:gid |
| --- | --- | --- |
| `Library/Application Support/GoldVMManager` | directory 0755 | 0:0 |
| `Library/Application Support/GoldVMManager/FirstLogin` | directory 0700 | 501:20 |
| `…/FirstLogin/GuestVPNBootstrap` | regular file 0755 | 0:0 |
| `…/FirstLogin/seed.json` | regular file 0600 | 501:20 |
| `Library/LaunchAgents/org.goldvmmanager.first-login.plist` | regular file 0644 | 0:0 |
| Each of four complete app roots in `Applications` | directory 0755 | 0:0 |
| Each complete app's descendants | pinned original kind/mode | 501:20 |

Four apps are exactly `CCBaga-A.app`, `CCBaga-B.app`, `Clash Verge.app`, and `Claude.app`. Existing `Library`, `Library/Application Support`, `Library/LaunchAgents`, `Applications`, `Users`, and `private/var/db` must already exist as actual same-Data directories. **Missing system parents are unsupported:** the caller must fail and retain, not silently create/chmod them. No `created_parent_paths` expansion is implemented.

Ordinary target files/directories reject set-ID, sticky, group/other-write permissions and extended ACLs. Symlink modes are preserved (Darwin commonly creates 0755 links; 0777 links are also valid), with no special bits. Their ownership is changed only with `fchownat(…, AT_SYMLINK_NOFOLLOW)`; the target is never followed. Internal relative symlink contents remain part of the complete app receipt hash. Link chains are resolved against the complete pinned manifest, without filesystem traversal, with a 40-hop cap; broken/cyclic links and composed escapes fail. Non-directory targets must have link count one. All targets are re-enumerated, bound to pinned inodes, checked against the current mount's device, and opened using no-follow dirfds. Unexpected seed entries, missing app contents, unsafe paths, content changes, and incomplete app tree hashes fail closed.

## Parent API and ordering

1. Obtain a production local helper using `host_tools.resolve_ownership_helper` or `host_tools.compile_ownership_helper`. The ownership module does not compile. Call `deploy_helper(state_dir, binary_path) -> sha256`. It fresh-verifies the portable build receipt, local ad-hoc signature and empty entitlements through `host_tools`, checks the production/fixture contract marker, and EXCL-copies into:
   `state_dir/ownership-helper/<sha256>/GuestOwnershipHelper`.
   An existing version is only fresh-verified and reused; no overwrite/repair. Version directories are 0700 and the executable is 0755, caller-owned, never set-ID. Existing quarantine is propagated to a new copy without clearing attributes. A local ad-hoc signature is **not** Developer ID signing or notarization. Portable receipt verification supports a binary package without Swift source or SDK invocation.
2. Hold the existing stage's POSIX exclusive config-file lock for the entire apply/remount/verify sequence. Keep the returned descriptor alive and pass it as `config_lock_fd` below. **Closing any descriptor for that inode in the same process releases that process's POSIX locks.** The ticket builder therefore hashes it with `pread` on the supplied descriptor, without opening, closing, changing offset, or acquiring another lock. Production root checks `F_GETLK` for the ticket's exact caller PID and write lock, including immediately before the ownership pass.
3. Compute `operation_paths(tart_home, job_id, operation_id, state_dir=state_dir)`. Its mapping contains `directory`, `ticket`, `apply_mount`, `verify_mount`. Both IDs are 32 lowercase hex digits.
   - Ticket directory: `TART_HOME/.gold-manager-staging/<job>/new-environment/.guest-ownership/<op>`.
   - Writable mount: `state_dir/build-jobs/<job>/offline-vpn-<op>/write-session/data-mount`.
   - Fresh owner-verification mount: same operation evidence root, `owner-readonly/data-mount`.
4. Parent creates the ticket directory and its `.guest-ownership` parent privately (0700); the operation directory must be new and empty. Only this operation may exist in the stage's ownership directory. Parent's normal DiskSession creates its own session/evidence directories. **Do not pre-create the future `owner-readonly` session:** the ticket builder only verifies its derived path, not existence.
5. After independent baseline attribution and complete-app verification, parent EXCL-creates all five fixed payload entries with their final modes on its attributed writable Data mount. `collect_entries(apply_mount)` reads/hashes only those fixed seed roots and the four complete apps; returns `tuple[OwnershipEntry]`. This function is not mount attribution and does not authorize writes.
6. Call:

   ```python
   ticket = prepare_ticket(
       state_dir=state_dir, tart_home=tart_home, job_id=job_id, name=name,
       operation_id=operation_id, apply_mount=paths['apply_mount'],
       verify_mount=paths['verify_mount'], data_uuid=data_uuid,
       group_uuid=group_uuid, entries=entries, helper_sha256=helper_sha256,
       config_lock_fd=config_lock_fd,
   )
   ```

   The ticket EXCL file is 0600, unique-inode and caller-owned. It contains only identities, paths, modes, hashes and observed ownership: **no seed bytes, subscriptions, credentials or administrator password**. Config/NVRAM/request/complete restore receipt/complete app receipt/helper are pinned by identity plus SHA256. The raw image is pinned by device/inode/size, not mutable mtime or a whole-image content hash. UI names use the same NFC Unicode alphanumeric/space/underscore/hyphen restrictions as the registry.
7. Set current phase `awaiting_system_authorization` and call:

   ```python
   result = request_authorization(ticket, 'apply', acknowledge_authorization=True)
   ```

   Without literal `True`, it returns `awaiting_system_authorization` and invokes nothing. The flag is the caller's explicit user acknowledgment of the real OS step, **not** administrator approval. Root helper stdout/stderr are discarded; no original error/path/secret is returned. Exit 0 alone never means success: `request_authorization` calls `verify_receipt` internally.
8. A valid apply receipt yields `ownership_applied_awaiting_readonly`, `authorized_helper_completed=True`, and `independent_readonly_acceptance=False`. This only proves the metadata calls completed, **not persistence**. Parent detaches that attachment. It may separately fresh-RO/owners-off verify all bytes/app signatures using its normal verifier, then detach again. Neither that mount nor its visible UID proves persistent ownership.
9. Parent freshly attaches the same raw image read-only with owners enabled, independently attributes it and mounts only its Data volume at the fixed verification path. Call the separately authorized `request_authorization(ticket, 'verify', acknowledge_authorization=True)`. Root re-hashes/opens the private seed even when the host UID differs from guest UID501. It checks actual persisted uid/gid/modes/inodes/content and current APFS attribution. Only this receipt returns `persistent_ownership_verified` with `independent_readonly_acceptance=True`.
10. Parent confirms final detach and any remaining lifecycle requirements. The helper never publishes. This success says nothing about guest boot, desktop, Clash GUI launch, VPN connectivity, or Internet traffic; those require their separate acceptance procedures.

## Independent root guards

- Ticket owner is inferred from its actual stat, never a JSON UID. Caller must be nonroot, UID at least 501. Ticket file/dir reject links, unsafe modes and ACLs.
- State/current operation must still be preinstall, same job/name/stage, no source VM, restored and apps-preinstalled; never guest-started, desktop-verified, credential-copied or published. Phase must be `configuring_vpn` or `awaiting_system_authorization`; current VPN operation ID must match and be active. Required request acknowledgments remain true.
- Complete installer receipt must attest zero networking, sharing and sockets. Immutable complete-app receipt must match the Data/group UUID and all four complete tree hashes/byte counts, with prior RO verification/final detach flags.
- Published-name collision, saved-state markers, existing guest accounts or `.AppleSetupDone` disqualify the stage.
- Native fixed read-only commands independently inspect `hdiutil info -plist`, `diskutil info -plist <derived mount>` and `diskutil apfs list -plist`. They confirm exact private raw image path, host owner, size, encryption/mount policy, attachment generation, owned device set, physical-store/container/Data edges, Data UUID and volume group, and singleton Data role. `diskutil info` alone does **not** supply the Data role.
- `fstatfs` independently requires APFS, exact device/mount names and expected `MNT_RDONLY`; verification also rejects `MNT_IGNORE_OWNERSHIP`. All three real-schema `Writable`, `WritableMedia`, `WritableVolume` fields must be false, and `GlobalPermissionsEnabled` true. Optional `ReadOnly`, if present, must agree; the helper does not invent/require that absent schema field.
- Verification requires a different attachment generation. Current `st_dev` may change on a fresh attachment: each target must match the **current** attributed mount device, while its inode and immutable byte/hash identity remain pinned.
- During apply, observed uid/gid is compared only when native metadata and `statfs` independently agree that owners are enabled. Owners-off can map `stat` ownership to the accessor (host caller versus root), so its display is never treated as persisted ownership. All device/inode/kind/mode/hash/ACL checks still apply, and production still performs real `fchown`. Only the separate owners-on RO verification accepts actual persisted uid/gid.
- Only the existing top-level `TART_HOME` and `TART_HOME/vms` allow 0700 **or** ordinary 0755, caller-owned. Their permissions are never changed. State, staging parent/job/stage, evidence/session parents and ticket containers remain strict 0700.
- Root writes only fixed one-shot `apply.started`/`verify.started` markers and final private `apply.receipt.json`/`verify.receipt.json` in the ticket directory. Started markers are root-owned; final receipts are 0600 and returned to the actual host ticket owner. Markers consume the operation before mutations, preventing automatic retry after partial failure. No rollback, deletion, partial-version repair or failed-stage reuse is implemented.
- Production receipts carry the production contract and genuine system-authorization label; fixture receipts always fail Python acceptance. These local files are not cryptographic defenses against a malicious process already controlling the same host UID. The boundary is uploaded/API content, confused-deputy path targeting, accidental stale stage reuse and unintended host mutation, not a compromised host account.

## Tests and limits

Run the source/fixture-only suite:

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_guest_ownership.py -v
```

[Tests](<tests/test_guest_ownership.py>) compile both variants, **execute only** `-D GOLD_OWNERSHIP_FIXTURE`, and use explicitly owned temporary files plus mocked native metadata. The fixture flag excludes native disk discovery and **all chown calls**, requires a fixed temporary-path prefix, skips actual root/parent-lock/statfs gates and marks every result simulation-only. The production binary is compiled but not executed. Dummy sparse regular files are never formatted or attached. Cleanup is restricted to individually allocated, absolute, no-symlink, owner-checked fixture directories.

These tests can establish strict parsing, identities, scope, hashes, lock preservation, consent/receipt protocol and rejection behavior. They **cannot establish successful native APFS root chown, fresh-remount persistent ownership, actual administrator-dialog UX, or a real guest boot**. Those require separately authorized manual acceptance on a disposable new stage. Any unsupported native schema fails closed; do not fix an integration mismatch by loosening ownership/read-only guards.
