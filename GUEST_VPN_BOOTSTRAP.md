# First-login Clash Verge seed (new guests only)

[Seed builder](<guest_vpn_seed.py>) and [Swift helper](<GuestVPNBootstrap.swift>) prepare **the complete official Clash Verge GUI**, not a replacement bare core. They do not create accounts, skip Setup Assistant, accept licences, clear quarantine, re-sign apps, install privileged services, click authorization prompts, or prove a VPN connection.

## Parent integration contract

```python
from guest_vpn_seed import build_seed
plan = build_seed(validated_vpn_configuration, receipt_enabled=False)
# Also accepts the unchanged VPNConfiguration.private_config dictionary.
# plan.seed_json, plan.launch_agent_plist, plan.entries, plan.receipt_token
```

The pure builder revalidates the **entire** canonical private policy using the fields parser (no Ruby, files or resolver). Results have redacted repr; seed bytes and token are private. `DataEntry` contains `relative_path`, `kind`, `uid`, `gid`, `mode`, and optional private `content` bytes. No directories, disks, users, processes or shares are changed by this API.

| Relative Data-volume entry | Owner | Mode | Kind |
| --- | --- | --- | --- |
| `Library/Application Support/GoldVMManager` | 0:0 | 0755 | directory |
| `Library/Application Support/GoldVMManager/FirstLogin` | 501:20 | 0700 | directory |
| `…/FirstLogin/GuestVPNBootstrap` | 0:0 | 0755 | compiled_helper; caller supplies binary |
| `…/FirstLogin/seed.json` | 501:20 | 0600 | file with private content |
| `Library/LaunchAgents/org.goldvmmanager.first-login.plist` | 0:0 | 0644 | file with plist content |

The parent must perform confined no-follow/exclusive Data-volume installation, verify **persistent numeric ownership** (including after noowners mounts), reject symlinks/unsafe existing targets/ACLs, and perform read-only acceptance before publication. No fallback to 0644 seed or 0755 private directory is allowed. UID501 is intentional: if the actual first local user's UID differs, fail closed and require manual recovery/rebuild. Existing standard ancestors are not a licence to chmod/chown them. Do not publish a fixture-mode binary.

## Production behavior

The root-owned LaunchAgent is `RunAtLoad`, Aqua-only, non-KeepAlive, with umask077 and stdout/stderr to `/dev/null`. It invokes the fixed helper without secrets or path arguments. The helper requires real/effective/console UID501, rejects Setup Assistant's `_mbsetupuser`, and derives a single `/Users/<local-user>` home from `getpwuid`, never environment `HOME`.

Seed loading is fixed-path, size-bounded, `O_NOFOLLOW` for every ancestor, regular-file/nlink/uid/mode/ACL checked. Fixed app identity, document paths, complete owned policy, local profile list and GUI flags are checked again. No arbitrary seed destination, provider, script, custom listener or app-launch path is accepted.

Only when the user's `Library/Application Support` is safe and the Clash app-data directory is absent does the helper build a private sibling stage with EXCL files, fsync, then publish with `renameatx_np(RENAME_EXCL)`. Documents are canonical JSON named `.yaml` (serde_yaml compatible):

- `config.yaml`: owned GUI control-plane/TUN/DNS; mixed port **7897**, no LAN/IPv6, silent core logging.
- `verge.yaml`: system proxy/TUN requested; DNS overrides/builtin enhancements/external TCP controller/updates/backups/auto-launch disabled.
- `profiles.yaml`: one local `GoldVMVPN` profile, no subscription URL or script/provider references.
- `profiles/gold-vm-vpn.yaml`: unchanged validated private parser profile, with DNS `#PROXY`, no DIRECT group entry, final `MATCH,PROXY`.

A private marker binds the import to SHA256 of the exact seed bytes. Same seed plus marker is a **no-op**, even after user edits; it does not rewrite data or relaunch the app. Existing data without the matching marker, existing symlinks or a partial stage are refused. Partial files are retained privately for manual recovery; no destructive cleanup/retry/merge occurs.

After import, the helper verifies the fixed original `/Applications/Clash Verge.app`: bundle ID `io.github.clash-verge-rev.clash-verge-rev`, version **2.5.10**, strict/all-architectures/nested Apple-chain code signature with Team **JPH3Z7PPBB**. It opens that GUI through `NSWorkspace`, leaving Gatekeeper and service/TUN administrator authorization to normal user interaction. Signing checks are not an approval bypass. The helper never invokes mihomo, sudo, osascript or codesign tools.

## Status and honest limitations

Private local status lives beside the seed, mode0600. Stages distinguish `configuration: imported`, GUI `not_started`/`opened`/launch-pending or authorization-pending, and `system_authorization: user_action_may_be_required`. `opened` means only NSWorkspace reported a GUI process, **not** service authorization or a tunnel.

**This implementation does not perform an HTTPS self-check.** `connection_check` is always `not_run`; no fake connection success is emitted. UI/runtime must separately obtain initial user admin consent and verify real egress/isolation. A failed launch after successful import remains a completed import requiring the user to open/recover it; later logins do not replay the seed. GUI auto-launch is not enabled automatically.

Optional `receipt_enabled=True` authorizes only an already-provisioned, VM-specific private RW share at `/Volumes/My Shared Files/gold-status`. The helper never creates a share or searches other shared files. It writes `<random-receipt-token>.json` with only fixed status fields, `evidence: guest_reported`, and `host_independently_verified: false`; never seed contents, endpoints, node names, UUIDs, credentials, raw errors or token in the body. Missing/unsafe share or write failure is best-effort and cannot turn import into proof. Parent must validate filename token and schema, regard receipts as guest assertions, and keep this RW share separate from other host shares.

Real guest UI launch, Setup Assistant/UID behavior, launchd, signing/Gatekeeper authorization, TUN/service, installed-core compatibility and network isolation are **not tested** by these fixtures. The user `Library` must already exist and be trusted; its fixed missing `Application Support` can be created privately. An existing user `Application Support` must be owned by UID501 without group/world write. The fixed system `/Applications` may be root-owned without group/world write or exactly root:admin (0:80) at mode 0775. The app bundle itself must be root-owned with safe mode and a verified signature. Existing system directory permissions are not changed. Extended ACLs on new private targets are rejected rather than weakened. Parent owns binary packaging/signing/quarantine assessment and volume-write acceptance.

## Fixed upstream behavior reviewed

Sources are pinned to official **v2.5.10**, not moving main:

- [dirs.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/utils/dirs.rs>): app-data filenames; GUI creates its own per-user Unix IPC path.
- [clash.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/config/clash.rs>): fills missing defaults and guards controller address; this alone does **not** disable the listener.
- [enhance/mod.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/enhance/mod.rs>): GUI-owned control plane/TUN overrides imported settings; `enable_external_controller=false` explicitly blanks TCP controller; DNS remains profile-owned when GUI DNS override is off.
- [dns.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/config/dns.rs>) and [tun.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/enhance/tun.rs>): explicit per-profile DNS override false; TUN fake-IP normalization preserves nameserver/routing policy.
- [verge.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/config/verge.rs>), [profiles.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/config/profiles.rs>) and [prfitem.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/config/prfitem.rs>): GUI flag/default and local-profile serialization contracts. No imported scripts are created; the missing-chain script fallback in [tmpl.rs](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/src/utils/tmpl.rs>) returns the configuration unchanged.
- [tauri.conf.json](<https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev/v2.5.10/src-tauri/tauri.conf.json>): fixed bundle identifier/version. Runtime still verifies the actual signed application.

The GUI must retain its own **private Unix IPC**, which is distinct from exposing an external TCP controller; this seed does not supply arbitrary IPC paths. Runtime policy must be accepted against the pinned shipped application, not inferred solely from source.

## Compile and fixture tests

Production build (parent chooses a private output/cache directory, and must not execute this on the host):

```sh
/usr/bin/xcrun swiftc -parse-as-library -module-cache-path "$BUILD_ROOT/module-cache" \
  GuestVPNBootstrap.swift -o "$BUILD_ROOT/GuestVPNBootstrap"
```

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_guest_vpn_seed.py -v
```

[Tests](<tests/test_guest_vpn_seed.py>) compile production and `-D GOLD_VPN_BOOTSTRAP_FIXTURE` variants, but execute **only** the fixture variant. Its path override exists only under that compilation flag and is confined to private `/private/tmp/gold-vpn-bootstrap-tests-*` roots; no app launch, real HOME, network or production seed/share is reachable. Every recursive test cleanup first verifies the exact resolved absolute own root and owner. Test compilation writes only within those roots.
