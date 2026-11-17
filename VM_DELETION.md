# Explicit VM deletion: controller contract and safety boundary

## Implementation and acceptance scope

The module is import-safe and performs no VM work unless `start(...)` is
explicitly called. It does **not** modify legacy controllers or launchers.
The initial implementation was syntax-checked under a UI-only acceptance
restriction; its authored mock tests were not executed in that phase.

Subsequent explicitly authorized front-panel acceptance completed deletion of
one selected development VM, with other listed VMs preserved. The later UI
redesign verified opening and cancelling the confirmation dialog without
performing another deletion. This is not proof of every failure/recovery branch
or compatibility on arbitrary hosts. Do not run destructive acceptance on
someone else's VMs without separate explicit authorization.

## Exact caller API

```python
import vm_deletion

result = vm_deletion.start(
    vm,                       # exact current allowed VM name, str
    confirm_name,             # exact name typed by user, no normalization
    acknowledge_erase,        # literal bool True, not 1 / "true"
    known_names,              # trusted controller-side allowed-name collection
)
# {"ok": True, "job_id": "<32 lowercase hex>", "pid": <int>,
#  "mode": "delete", "message": "..."}

job = vm_deletion.status()     # shared lifecycle status, or None
```

`start` validates synchronously, queues a durable job, spawns a detached dedicated
Python worker, and returns without waiting for deletion. A returned PID is a
handle/diagnostic, **not** a completion assertion or authority to kill unrelated
processes. Do not retry automatically after a timeout or transport failure: first
read status. `ValueError` means a sanitized rejection. Never send raw exception
tracebacks, subprocess output, private configuration, or filesystem paths to the
browser. Fail closed on unreadable state.

The controller must derive `known_names` from its current allowed VM inventory,
not accept it from JSON. The exact VM must also exist in Tart's local inventory
and be `stopped` or `suspended`. The module does not stop a running VM. Linux and
macOS configurations are both eligible; the OS-neutral source snapshot hashes
config bytes without reading proxy credentials or interpreting OS identity.
Names use the existing registry NFC rules, preserving Chinese and spaces. The
worker is spawned with an argv list, never a shell.

## Shared job/status contract

Deletion uses the existing global `STATE/build.lock`, `STATE/build-current.json`,
and `STATE/build-jobs/<job_id>/` namespace. It excludes create/rebuild/delete jobs
with the same inherited `flock`, including after the window/controller exits.
The parent closes its descriptor without `LOCK_UN`. The child writes its PID;
there is an existing queued-with-no-PID grace period before worker startup.

The lifecycle job liveness check must accept the exact current module path of
`vm_deletion.py` as well as `lifecycle.py`, and validate `--worker <job_id>`.
The deletion worker argv is the Python interpreter followed by `-B`, the exact
module path, `--worker`, job id, `--lock-fd`, inherited descriptor. There is no
liveness marker or lifecycle-script impersonation.

All deletion statuses include:

- `mode: "delete"`, `source_vm: vm`, `name: vm`, `id`, `pid`, timestamps;
- `phase`: `queued`, `preflight`, `committing`, then terminal `deleted` or `failed`;
  an unexpectedly exited active process is reported as existing `interrupted`;
- `result: "deleted"`, `old_deleted: true`, `progress: 1` only on completed deletion;
- `recovery_required: true` for an incomplete or unreadable commit journal;
- `retained_private_artifacts`: `private_logs`, `environment_setup`,
  `restore_images`, `staging_caches`.

Add `deleted` to lifecycle's terminal vocabulary. The controller should use
`vm_deletion.status()` for the common job feed: it delegates non-deletion jobs to
`lifecycle.status()` and can recognize a durable deletion completion record if
the worker exited between completing the journal and updating final status.
Reading status does not mutate or retry the transaction.

Block all operations on the related `source_vm`/`name` while active or recovery
is required. Block subsequent create/rebuild/delete jobs for **any** incomplete
journal, even if the process is no longer active. If state is unreadable and the
related name cannot be established, fail closed for all VM operations. Keep the
job visible even after the deleted VM disappears from the inventory.

## Commit ordering and lock discipline

1. Validate exact typed confirmation, literal acknowledgement, trusted known
   names, stopped/suspended inventory, and source root/config owner/device/inode,
   mode, link count, and config SHA-256 snapshot. No directory content is removed
   on validation failure. Parent preflight creates no VM artifacts.
2. The worker holds inherited global build flock for its lifetime. During commit
   it acquires `registry.state_lock`, Tart's storage-directory flock, then the
   existing config inode's POSIX lock. It checks inventory before the storage
   flock so a Tart subprocess does not reacquire that flock.
3. Open and lock the config inode once. Hash via that descriptor. **Never reopen
   and close the same config inode in this process until commit finishes**:
   closing another descriptor could release process-associated POSIX locks.
   Directory walking uses metadata, not additional config file opens.
4. Reject symlinks in paths/tree, mounts, different devices, unknown special
   files, wrong owners, and multiply-linked regular files. A top-level
   `control.sock` is accepted only using the current lifecycle stale-socket
   helper while locked: only a refused connection proves staleness, no protocol
   bytes are sent, and the socket's device/inode is pinned for both tree checks.
5. Validate registry/share configuration before renaming. Prepare the derived
   same-filesystem tombstone parent:
   `TART_HOME/.gold-manager-deletions/<job_id>/old-environment`.
   The client cannot choose any deletion path.
6. Write/fsync private `build-jobs/<job_id>/commit.json` with `before_delete`,
   then rename the source root into the tombstone. Fsync both containing
   directories. Persist `old_tombstoned`.
7. Remove **only** the selected registry VM entry, add its name to `retired`
   (including legacy names), and remove **only** its shared-folder config entry.
   Other VM entries remain unchanged. Write/fsync both configurations and persist
   `configuration_removed`. Host share paths are never resolved, statted, walked,
   or deleted; shares are configuration values only.
8. Fsync state/VM-root/tombstone-parent directories before physical deletion.
   Revalidate the derived absolute tombstone's root identity and entire tree,
   including the previously pinned socket. Only then `rmtree` that exact tree.
   Fsync its parent and persist `committed_old_removed`.
9. Publish terminal `deleted`. The final journal phase intentionally matches the
   existing lifecycle convention; **every other journal phase is incomplete**.

## Recovery and data-retention boundary

There is no rollback/retry/recovery executor in this module. Any interrupted
commit requires manual inspection and explicit human recovery. Incomplete
registry/share writes or partial tree removal are not treated as success. The
worker persists `recovery_required` where possible; lifecycle status independently
recovers that flag from the external durable journal after crashes. Do not remove
or edit `commit.json`, overwrite `build-current.json`, launch another job, or
restart a VM to bypass this interlock. The journal lives outside the target and
survives target deletion. A completed journal is the durable completion authority.

**This is not all-host cleanup.** Only the selected VM root (including disks,
NVRAM, saved suspension state, and its contained files) and the selected VM's
registry/share entries are deleted. Host shared directories are retained.
Private logs, per-environment setup/private materials, restore IPSW downloads,
and earlier staging caches are explicitly retained and reported. Empty deletion
staging directories and job/journal/log records are also retained. Optional
per-environment payload cleanup is not in scope. No attempt is made to traverse
legacy launcher directories or erase proxy credentials outside the VM root.
No secure-erasure claim is made for APFS snapshots, backups, or SSD storage.

Locks and metadata checks protect against cooperating Tart/manager operations
and ordinary stale paths. They are **not a security guarantee against malicious
same-UID processes**, privileged mount manipulation, or a compromised host.

## Authored tests (not executed)

The new `tests/test_vm_deletion.py` covers request validation, source snapshot
OS-neutrality, shared status reconciliation, spawn arguments/global locking,
commit ordering, and failure interlocks through mocks. It is deliberately
unexecuted under the UI-only acceptance restriction. Syntax can be checked with
`ast.parse` without importing modules, creating bytecode, or running tests.

Full front-panel regression acceptance should cover explicit confirmation, running-VM
rejection without auto-stop, persisted job visibility, correct single-row removal,
retained host shares/caches, and clear failure/recovery display. The completed
single-target UI acceptance above does not claim exhaustive coverage of this list. Do not perform
those destructive acceptance actions without the user's separate authorization.
