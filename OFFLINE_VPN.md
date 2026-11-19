# Fresh-stage VPN seed and persistent ownership

[offline_vpn.py](<offline_vpn.py>) operates **only after** the complete reviewed CCBaga A+B, Clash Verge GUI and Claude Desktop application transaction has completed on a new, unpublished, never-started `mode=preinstall` stage. It neither publishes nor starts a VM, imports host VPN profiles, repairs disks, changes security policy, or claims network/desktop acceptance.

## Worker API

```python
from offline_vpn import configure_preinstalled_stage

public_receipt = configure_preinstalled_stage(
    state_dir=state, tart_home=tart_home, job_id=job_id, name=new_name,
    private_config=stored_vpn.private_config,
    bootstrap_helper_path=compiled_bootstrap,
    ownership_helper_path=compiled_ownership_helper,
    materials=verified_materials,
    acknowledge_write=True,
    acknowledge_system_authorization=True,
    lifecycle_lock_fd=worker_lock_fd,
)
```

The caller owns validation/consent for the private configuration and trusted compilation of both helpers. The bootstrap must be a caller/root-owned, non-hardlinked, non-writable-by-others executable ARM64 Mach-O. Ownership helper deployment uses `guest_ownership.deploy_helper`; this module never compiles or executes either application or bootstrap. `materials` must be exactly `reviewed_manifests()` in complete fixed order, and fresh source verification remains mandatory.

`load_completed_stage(...)` validates the **real** application-complete sidecar and current/request identities, restore-isolation receipt, image size, original Data/group UUIDs, no saved state and no published VM. It returns the existing `StageTarget`; it never fabricates restore-only state to satisfy `StageTarget.load`. Existing owned, non-group/other-writable Tart roots and `vms` may be 0755; state, stage, job and evidence roots remain private 0700. Existing roots are never chmodded.

The worker lifecycle flock and config POSIX write lock span the entire transaction. `StageTarget.locked` yields its **borrowed** config FD to `prepare_ticket`; neither caller nor ownership bridge closes/reopens config while locked. Opening and closing another FD for that inode would release process-owned POSIX locks. Config/NVRAM, request, restore and app-completion identities remain unchanged throughout.

## Acceptance sequence

1. Fresh readonly `owners off`: attribute the full APFS persistent identity graph, verify the installed four original application trees/signatures/quarantine against fresh reviewed source receipts, and reject existing seed outputs. Confirm detach.
2. Fresh writable `owners off`: independently match the same graph and Data/group UUIDs. Write only `guest_vpn_seed.build_seed(..., receipt_enabled=True).entries` using exclusive creation, no-follow traversal, exact modes, byte checks and fsync. No app contents are rewritten.
3. Request normal macOS administrator authorization for Root helper `--apply`; validate its exact private operation/ticket/count/generation receipt, rejecting fixture-only or incomplete evidence. Confirm detach.
4. Fresh readonly `owners off`: independently reverify original apps and every seed byte/mode/inode. This permits verification even when the host UID is not the future guest UID501. Confirm detach.
5. Fresh readonly `owners on`: separately request Root `--verify`. It verifies real persistent UID/GID plus bytes/modes/layout on a new attachment; a successful apply or `noowners` view is **not** owner acceptance. Validate the private receipt and confirm final detach before completion.

Two explicit authorization requests are made. macOS decides whether to display/reuse authorization; no fixed dialog count or zero-popup behavior is promised. No passwords are read, `sudo` is never used, and the Python module never performs chown or permission escalation.

Only the reviewed existing `Library`, `Library/Application Support` and `Library/LaunchAgents` layout is supported. Missing, aliased, cross-volume or unsafe system parents **fail retained**; this implementation does not create/repair these unlisted ownership targets or change existing parent modes. The newly created GoldVMManager/FirstLogin directories and fixed helper/seed/LaunchAgent files are covered by the Root whitelist.

## Records and recovery

Evidence lives exclusively under `state_dir/build-jobs/<job-id>/offline-vpn-<operation-id>/`; tickets live under the exact stage's `.guest-ownership/<operation-id>/`. Optional `evidence_dir` can only name that job's existing private parent, not an arbitrary output. Outputs are never reused, deleted or overwritten.

Success writes private `.offline-vpn.complete.json` and evidence, then sets `current.vpn_configuration_staged=True` with `phase=awaiting_first_desktop_acceptance`. The returned dictionary is a **sanitized public summary**, with `readonly_payload_verified`, `readonly_remount_verified`, `persistent_ownership_verified` and `final_detach_confirmed`. It retains `guest_started=False`, `published=False`, `desktop_verified=False`, `host_credentials_copied=False` and `vpn_connected=False`.

The private sidecar additionally holds `receipt_token`, seed/helper digests, inode bindings, full persistent volume identity and both authorization receipts. Its private `image_file_stamp` is the exact final detached `[st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns]`; the parent must compare it again under the storage lock immediately before publication. **Never expose that private record or token through API/UI/logs.** Parent code may read the private token only for its per-VM status receipt interface. Runtime preparation/publication, first login, Clash service authorization, Gatekeeper, account login and real connectivity checks remain separate parent/user work.

Any failure after transaction entry retains stage/evidence, sets `phase=failed`, `recovery_required=True`, records the inner `failed_step` and a constant `failure_code` (for example `system-authorization-interaction-not-allowed`, or `internal-error` for unexpected exceptions) in `vpn_configuration` and `vpn-failed.json`, and never promotes partial writes or retries authorization on its own. Recovery does not force-unmount, replace applications, clear security metadata, publish or start a VM. A failure before locks/preflight creates no disk session.

**Paused refused prompt.** When the apply or verify prompt returns `user-cancelled`, `authorization-denied` or `interaction-not-allowed`, and the ticket directory has neither `<operation>.started` nor `<operation>.receipt.json` (so the root helper provably never ran), the workflow keeps the same mounted session and both locks, publishes `authorization_retry` (`operation`, fixed `reason`, `attempt`, `max_attempts` = 3, `expires_at`) and waits up to 15 minutes for the user's explicit choice (`POST /api/preinstall/authorization`). `retry` rechecks the mount and every stage identity, then re-requests the same ticket. `abandon`, no answer, or the third refusal fails as above with the original reason. It never re-prompts on its own. Timeout, helper exit, unknown and preflight failures are never retried.

## Source-only tests

```sh
/usr/bin/python3 -m unittest discover -s tests -p 'test_offline_vpn.py' -v
```

[tests/test_offline_vpn.py](<tests/test_offline_vpn.py>) uses tiny owned temporary files and mocked native sessions, verification and authorization. Fixture-only directory renames preserve inode identity; no disk image is mounted, no device/VM/network is accessed, and no root chown or actual OS authorization occurs. These tests are orchestration/security contracts, **not native acceptance evidence**.
