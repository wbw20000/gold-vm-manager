# Explicit preinstalled-guest runtime, version 2

[Preparation/validation](<preinstall_runtime.py>) and the narrowly extended [protected launcher](<protected_launcher.py>) add a v2 contract without replacing v1. V1 retains its required readonly setup payload, source manifest, VM-root contract, recovery behavior and network filter. Existing environments are not rewritten.

## Preparation API

```python
public = prepare_environment(
    vm_name, staged_vm_config, destination_private_base,
    published_vm_config=explicit_final_vm_config,
    private_config=validated_vpn.private_config,
    endpoints=validated_vpn.endpoints,
    gvproxy_path=reviewed_backend_source,
    tart_path=native_verified_tart_executable,
    preinstall_receipt=private_app_install_receipt_path,
    vpn_seed_receipt=private_guest_seed_receipt_path,
)
```

All inputs are explicit. No host Clash directory, active profile, legacy provisioning discovery, cache auto-selection, default backend installation directory, Mihomo, setup script, DMG or host configuration is consulted. The unchanged [VPN parser](<vpn_config.py>) re-derives the private policy from its explicit normalized nodes, without DNS, and compares both the complete private configuration and exact endpoint set. A `DIRECT` fallback or endpoint disagreement is rejected.

Input contract:

- `vm_name`: current managed-name rules, including NFC normalization.
- `vm_config`: existing private canonical **staged** `config.json`; its complete bytes, MAC, ECID and file device/inode are pinned before publication.
- `published_vm_config`: **mandatory keyword**, explicit canonical future `<Tart home>/vms/<vm_name>/config.json`. Its VM root must already exist; the final config must not exist unless it is exactly the same path as `vm_config` for explicit already-published/static validation. This is the only config path persisted in metadata and used by the launcher. The explicit Tart home is derived from it, never a default host directory.
- Preparation validates the staged config while the published target remains absent. Parent subsequently publishes by **same-filesystem directory rename**, retaining the pinned config inode and SHA; a byte-identical copy with a different inode is rejected. Launch-time validation never accepts a staging override. No VM publication or relocation is performed by this module. **Call prepare before taking the POSIX config publication lock**: this function reads/closes config descriptors and must not accidentally release a lock already held by its caller process. Runtime failure must abort before parent publication.
- `destination_private_base`: **absent** canonical path under an existing owned 0700 parent. Existing directories, including empty ones, are not adopted. Failed partial output is retained, never erased or overwritten.
- `private_config`: unchanged private dictionary from [VPN parsing](<vpn_config.py>), not raw YAML, a profile path, or a host-profile selector. Only its canonical SHA is persisted here; credential-bearing configuration is not redundantly copied to runtime.
- `endpoints`: exact supplied protocol/public-IPv4/port tuples, bounded and duplicate-free. TCP/UDP only; port 53, private/loopback/multicast/reserved IPs and noncanonical literals are refused. Full equality with parsed VPN endpoints is required.
- `gvproxy_path`: explicit regular non-world-writable source: the copy taken by `host_tools.ensure_gvproxy` from Podman's notarized installer. The production SHA is always `45881c33400a14c4c50d4ed7e814b69a60248aa0d78e9b541e879edc05346a85`; both source and destination are checked. Tests substitute only the scoped verification helper with inert bytes, never change the production pin.
- `tart_path`: explicit absolute executable, checked for safe owner/type/mode/link identity and bound by path, inode/device, size and SHA. **Parent must already perform native signing/notarization/version/material validation**; this binding neither substitutes for it nor claims native approval.
- `preinstall_receipt`, `vpn_seed_receipt`: explicit caller-owned private regular JSON object files, bounded to 4 MiB each. Their bytes are copied to private runtime and pinned. These hashes establish continuity only: parent owns semantic validation of actual app installation, readonly acceptance, guest seed placement and native identities. Arbitrary receipt contents cannot confer launch permission.

The sanitized public result contains runtime paths, v2, endpoint count and pending gate flags, never nodes, credentials, IPs, source receipt contents or the guest receipt token. Default status is `awaiting_host_authorization`, `native_execution_approved=false`, `desktop_verified=false`, `network_independently_verified=false`. `backend_requires_executable_permission` reports whether the explicit source lacked owner-execute permission.

Preparation never starts a backend, Tart or VM. Its only native operations are the existing fixed `/usr/bin/xattr` quarantine inspection/preservation policy. Tests mock those operations.

## Owned runtime manifest

A complete fixed manifest covers copied current project launcher, packet policy, share support, managed registry, v2 helper, quarantine helper, pinned gvproxy, policy and both private receipts. The packet-policy source itself remains pinned to the existing reviewed SHA. Copies are exclusive `O_EXCL|O_NOFOLLOW`, bounded, owner/single-link/inode checked, fsynced and rehashed after writing. Directories are 0700; files are 0600 except the launcher and an already-owner-executable backend, which are 0700. Symlink components, group/world writes, set-ID files and special files are refused.

V2 environment metadata additionally binds the config SHA/ECID/MAC, absolute Tart identity, private configuration digest, app/seed receipt digests, backend quarantine digest and status-mailbox directory identity. Its manifest does **not** contain a legacy setup payload. A setup directory in a v2 environment is refused. Source, external bindings, backend pin/quarantine and mailbox are rechecked at startup, and external bindings are checked again before backend/VM launch.

Source quarantine is preserved exactly via [quarantine policy](<quarantine_policy.py>). No xattr is deleted, replaced with a weaker value, or cleared; no signing mutation occurs. A source with no quarantine stays without quarantine on its new raw copy, **but still requires the same explicit execution gate**. The implementation never treats existing host absence of quarantine as native qualification, downloads a replacement to evade quarantine, or adds an execute bit to a previously nonexecutable backend during preparation.

As with v1, private runtime is a trusted same-user control boundary, not a defense against hostile same-UID writers ignoring locks. Parent must retain lifecycle exclusivity and protect prepared source/runtime from concurrent mutation. Source manifests pin the trusted current checkout; they are not signatures from an external publisher.

## First-execution gate: no platform-policy bypass

The backend is gvproxy v0.9.0 from Podman's installer, signed with Red Hat's Developer ID and notarized (`backend_assessment = developer-id-notarized-HYSCB8KRL2`). SHA equality and these checks are still **not** permission to execute it: macOS decides at launch, from the preserved quarantine. Every v2 environment requires:

```text
needs_host_security_authorization = true
native_execution_approved = false
```

V2 launcher defaults to refusal, writes `awaiting_host_authorization`, and does not invoke Tart inventory, backend or VM without the independent explicit CLI flag:

```text
--acknowledge-reviewed-unsigned-backend
```

This flag (its historical name is kept) means **the user explicitly requests normal platform execution of this fixed-SHA reviewed backend**. It does not mean `spctl` passed, notarization exists, macOS permission was granted, or a native-signature policy was disabled. Parent must only add it after the separate backend-warning confirmation UI, never automatically during create or based solely on the general first-boot request. The previously stated approval to first-start `gg1` is not this backend-warning acknowledgement.

After acknowledgement, the launcher still checks all bindings and only calls normal `Popen`. Quarantine remains intact. There is no `spctl --add`, Gatekeeper disabling, re-signing, `xattr -d`, helper wrapping, automatic retry, fallback backend or ordinary NAT. A normal OS execution refusal or early backend exit leaves `awaiting_host_authorization`; no VM is started. This state means authorization/backend startup needs human review, not proof that macOS was specifically the cause. A person may still need the system's **Open Anyway** flow, or a separately reviewed suitable signed/build alternative. A failure is not repaired by this module.

The prepared quarantine value's digest is recorded. Validation requires the attribute to remain present: Gatekeeper may update its flags once it has assessed the notarized backend, so the value itself may change, but a removed attribute fails closed with `backend-quarantine-changed`. The attribute is never cleared.

### Refreshing an older published environment

Environments prepared before 2026-11-19 pinned the unnotarized release binary (`backend_assessment = reviewed-sha256-only-adhoc-no-usable-native-signature`), which macOS refuses to run; macOS's refusal alert can also move the copy to the Trash. `environment_needs_refresh(base)` first validates everything a refresh keeps (`validate_environment_for_refresh`: VM config and Tart bindings, `policy.json`, both private receipts, private-config pin and the status mailbox) and raises if any of it changed; those are never repaired. Only environments with the known legacy assessment and legacy SHA pin qualify; a current signed environment that fails verification is rejected rather than silently rewritten. To migrate the known legacy environment, `refresh_environment(base, gvproxy_path)` writes the current reviewed sources (launcher, packet policy, share support, registry, runtime, quarantine helper) and the signed backend (0600, carrying its source's quarantine) as new files, atomically replaces each, rewrites only `source_sha256`, `backend_assessment` and `backend_quarantine_sha256` in `environment.json`, and fully revalidates. The [controller](<manager.py>) runs this only inside a confirmed, named start of a preinstalled VM, before the launcher; it acquires the Podman installer (about 77 MB, reused from the host-material cache when present) and extracts gvproxy first.

A nonexecutable 0600 source from [host acquisition](<host_artifacts.py>) remains 0600 at preparation. The acknowledgement flag alone still refuses with `backend-not-executable`. The controller passes a second `--enable-reviewed-backend-owner-execute` flag only after the separate exact-name start confirmation. Under the launcher lock, the helper checks bytes, inode, exact private mode and quarantine, then sets only the owner execute bit (0600 → 0700) on the exact private copy. It never changes the source file, removes quarantine, or claims native security approval.

V2 uses its explicitly bound Tart path and canonical Tart home with **only** fixed `HOME`, `TART_HOME`, `PATH`, `LANG`, `PYTHONNOUSERSITE=1`, `PYTHONDONTWRITEBYTECODE=1`, and `TART_NO_AUTO_PRUNE=1`. No arbitrary loader/proxy/authentication variables are inherited. The final config's VM directory name must match `vm_name`. V1 process environment behavior is unchanged. Native material/signature requirements for Tart and guest apps remain parent gates and have not been relaxed.

## Dedicated status share, not arbitrary host access

Preparation exclusively creates the empty 0700 `guest-status` directory directly under its private runtime. Only this exact path and stored device/inode can be the reserved **`gold-status`** RW share. The full runtime, user home and arbitrary host paths are not shared by this mechanism. User share names `setup` and `gold-status` are reserved case-insensitively. All other shares still come from the unchanged [share validator](<runtime_shares.py>), with the existing stopped-VM/configuration/last-launch checks and recording. V2 never creates a setup share or enables suspendable sharing.

The normal v2 command includes the one fenced `--net-fd`, `--no-clipboard`, its status mailbox, and validated user share arguments. Recovery keeps `--recovery --no-clipboard` and the fenced NIC, but exposes no status/setup/user directories. The packet send/receive filtering loop, truncation rejection, backend-failure disconnect behavior and cleanup ordering remain unchanged. No default code path starts a VM during preparation.

`read_guest_status(base, receipt_token)` reads only a caller-supplied 64-lowercase-hex token filename inside the pinned mailbox. It accepts a bounded 0600 single-link regular JSON file containing only the fixed bootstrap status vocabulary. Symlinks, arbitrary names, extra keys, credentials and forged independent-success booleans fail closed. An absent receipt returns `not_observed`. Even an accepted `application=opened` is **untrusted guest self-report**: returned `desktop_verified`, `network_independently_verified` and `host_independently_verified` stay false. The reader does not inspect other mailbox entries. Guest report schema matches the [bootstrap source](<GuestVPNBootstrap.swift>); future vocabulary changes require explicit review.

Parent must still verify real VirtioFS ownership/mode mapping supports the intended guest UID 501 without broadening the host mailbox, independently observe the actual desktop/app state, and independently exercise allowed and denied network paths. No single guest boolean or emitted packet is success evidence for those gates.

## Tests

[Fixture tests](<tests/test_preinstall_runtime.py>) cover explicit inputs, complete manifests, source/copy pins, quarantine preservation, config/Tart identity changes, private receipts, zero default launches, acknowledgement/OS-refusal handling, reserved mailbox commands, recovery and untrusted guest reports. Every process launch is mocked. One integration test exercises the actual relay on native **Unix datagram sockets only**: it checks both directions, denies direct DNS/local-address/wrong-port/unsolicited packets, and proves that backend exit during the readiness wait drops an already queued batch. The relay closes the transport and selector on failure before process cleanup. No host TCP/UDP, DNS, Tart, VM, or proxy service is used by that test. Existing v1 launcher/provisioning and runtime-share suites remain green.

```sh
/usr/bin/python3 -m unittest discover -s tests -p 'test_preinstall_runtime.py'
/usr/bin/python3 -m unittest discover -s tests -p 'test_provisioning.py'
/usr/bin/python3 -m unittest discover -s tests -p 'test_runtime_shares.py'
```

System Python 3.9.6 result: 39 runtime tests (including staged preparation, atomic publication, inode substitution and the native Unix datagram relay) + 17 existing provisioning/launcher tests + 47 share tests pass. No actual backend, Tart or VM was executed; no host-user configuration was inspected.
