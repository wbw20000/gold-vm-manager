# New-VM provisioning contract

This module **prepares files only**. It does not create, start, stop, delete, mount,
restore, install into, or authenticate a VM. It never executes downloaded code.
The parent lifecycle owns explicit user confirmation, fresh VM creation, default
2 CPU / 4 GiB (configurable), unique ECID/MAC validation against inventory, atomic
publication, registry updates and exact-path rollback.

```python
from provisioning import preflight, prepare_environment

# Call before a parent-authorized destructive lifecycle operation.
readiness = preflight()  # only reads local sources and verifies code signing

# After creating a fresh staged VM, before publishing its final name:
result = prepare_environment(
    vm_name,                         # managed_registry.validate_name rules
    staged_vm / 'config.json',       # reads MAC and ECID; never changes them
    private_state / 'environments' / environment_id,
    None,                            # optional existing CCBaga cache; default ~/Downloads
)
```

`destination_private_base` must be absent (or empty/private), with an existing
owned 0700 parent. Symlinked/noncanonical paths and unsafe Tart delimiters are
rejected. Existing environments are never overwritten. An error can leave a
partial private directory; only the lifecycle caller may perform its exact-path
rollback. Do not reuse an old environment when rebuilding a VM.

Return value (safe for API display): `base`, `launcher`, `setup_dir`,
`metadata_path`, `status="awaiting_user_setup"`, `endpoint_count`, `warnings`, and
`software`. It never contains node names, IPs, credentials or controller secrets.
`ProvisioningError` messages contain constant non-secret text; never add parsed
configuration or captured subprocess streams to logs.

`environment.json` is private metadata:
- `version=1`, `vm_name`, final `vm_config` (always `~/.tart/vms/<name>/config.json`,
  never the staging path), `guest_mac`, `ecid`;
- `setup_active=true`, `setup_status="awaiting_user_setup"`;
- `source_sha256` and `setup_sha256` integrity maps.

The base contains the **new independent** launcher, copied reviewed/pinned packet
policy and gvproxy binary, `policy.json`, copied current repository share-support
and registry modules, plus the private setup directory. The original Gold
launcher/policy/backend, installed manager application and existing VMs are not
modified. Active host Clash YAML is parsed in memory using Ruby Psych safe_load
with aliases, object tags and duplicate keys rejected; stderr is discarded.
Only allowlisted TUIC / TLS TCP VLESS Reality node fields are carried over.
Host providers, profile hooks, rules, DNS, selection history, controller secret,
application settings, keychains and account data are not copied.

## Launch contract

Launch `<base>/launcher.py`, never `tart run` without its fence. The launcher checks
all payload hashes/modes, checks the final VM's pinned MAC **and ECID**, requires
stopped state, sets up the gvproxy/socket filter first, then gives Tart only that
filtered `--net-fd`. There is no NAT fallback or exposed management port.

The copied `share_support.prepare_vm_shares` resolves parent-managed user shares.
The launcher independently adds `--dir=setup:<base>/setup:ro`, reserves the `setup`
name, and never adds `--suspendable`. Its user-share launch manifest deliberately
contains only user shares. Consequently **the parent must disable suspend while
setup_active**, rather than relying on the user-share manifest's suspendable bit.
Suspended states are rejected; do not force a resume through another launcher.

## Guest software and verification boundaries

The setup folder appears at `/Volumes/My Shared Files/setup`. The user must finish
macOS first-boot setup/login and explicitly run `Install.command` there. It checks
that it is in a virtualized Apple Silicon guest. System Ruby and the
`kern.hv_vmm_present` indicator are required; missing capabilities fail closed.

- Clash is a **signed pinned Mihomo core service**, not a full Clash Verge GUI.
  The guest explicitly authorizes sudo; no password is captured/stored. New
  loopback controller secret, strict TUN, fake-IP DNS and proxy-only DoH/rules are
  generated. The host fence blocks direct DNS, IPv6, LAN and non-node traffic if
  guest configuration fails. A source TUIC node configured with skip-cert-verify=true retains that setting
  for compatibility with an explicit warning; endpoint isolation does not fix TLS
  authenticity or protect against malicious guest root reusing an allowed tuple.
- CCBaga official **v0.2.50 A+B** DMG is copied from verified local cache; no host
  application data is migrated. SHA-256 matches the official release API. Guest
  mount/copy occurs only after user consent. No Gatekeeper or quarantine bypass.
- Claude Code native binary download is **optional guest confirmation**. It uses
  explicit loopback proxy only, official HTTPS stable/manifest/binary URLs, digest
  validation and Apple code-signature requirement for Anthropic PBC. No remote
  install script is run. GPG manifest signature is not checked (gpg is not shipped
  in a fresh guest). It copies the verified executable into `~/.local/bin/claude`,
  leaves shell settings/accounts untouched and asks the user to authenticate.

If only Claude is missing, retry in guest Terminal:

```bash
/bin/bash "/Volumes/My Shared Files/setup/Install.command" --claude-only
```

That mode still requires the protected setup/guest guards and consent, never
modifies the Clash service/CCBaga, never uses sudo, and refuses an existing Claude
executable. Other partial failures require manual review; there is no destructive
automatic rollback. Private staging (possibly containing node credentials) is
retained and its exact location is displayed for deliberate manual cleanup.

**No guest installation or network success has been verified by these tests.**
The read-only share provides no completion backchannel: the manager must keep
`awaiting_user_setup`, not claim installed/authenticated/verified. An explicit
future guest-validation/detach feature is needed to remove the setup share and
re-enable suspension.

## Reviewed public sources

- [CCBaga v0.2.50 release](https://github.com/liseami/CCBaga/releases/tag/v0.2.50)
  and [official release API](https://api.github.com/repos/liseami/CCBaga/releases/tags/v0.2.50):
  DMG SHA-256 `0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b`.
- [Claude native installation/signing documentation](https://code.claude.com/docs/en/setup.md).
- The current official installer redirects to
  [bootstrap source](https://downloads.claude.ai/claude-code-releases/bootstrap.sh),
  reviewed **as text only**, not executed. It identifies this native binary origin.
- On 2026-11-16, [stable](https://downloads.claude.ai/claude-code-releases/stable)
  returned `2.1.311`; its [manifest](https://downloads.claude.ai/claude-code-releases/2.1.311/manifest.json)
  returned darwin-arm64 SHA-256 `85d8c08707fcfd1e78ffa0204eefbc6ec9e4fe22f375fb2767ef85d957ed3161`.
  Guest download resolves stable again and validates that release at execution;
  this document is not a promise to pin Claude indefinitely.

## Local verification

`python3 -m unittest discover -s tests -p 'test_provisioning.py' -v` exercises
synthetic temporary payloads, secret redaction, Ruby safe YAML parsing, identity
metadata, destination refusal, source/payload hash enforcement, permissions and
always-fenced/read-only/no-suspend argv construction. Test artifact binaries are
inert synthetic bytes and Popen is forbidden in preparation tests. Bash/Ruby syntax
checks and a real **read-only** host preflight additionally pass. No VM lifecycle,
real guest install, DMG mounting, or download execution was used for validation.
