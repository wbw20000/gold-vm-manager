GOLD VM — FIRST-LOGIN SETUP (user-run, NOT unattended)

1. Start this VM ONLY through its generated protected launcher. The host installs
   an endpoint-only Ethernet fence before Tart receives its NIC descriptor. There
   is NO NAT fallback. Until Clash runs in the guest, ordinary networking is
   expected not to work. Finish macOS Setup Assistant and create/login to your own
   guest account. No host settings, keychains, Claude accounts or browser profiles
   are migrated. Fresh ECID/MAC and CPU/RAM are managed by the parent VM workflow.
2. In the guest, open /Volumes/My Shared Files/setup/Install.command. Read the
   installer before consenting. This folder is read-only, but contains PRIVATE
   proxy credentials; read-only does not make them public-safe. Never share it.
3. Type INSTALL when asked. sudo asks for YOUR GUEST admin authorization directly
   in Terminal; no password is stored. The script installs the pinned signed
   Clash/Mihomo core as a root-owned launch daemon (local.goldvm.proxy), with a
   freshly generated loopback controller secret, strict TUN and proxy-only DNS.
   It installs CCBaga-A.app and CCBaga-B.app from the verified official v0.2.50 DMG.
   It does not launch CCBaga or disable Gatekeeper/quarantine checks.
4. Claude is a separate CLAUDE confirmation: the installer downloads the stable
   native darwin-arm64 binary from the official downloads.claude.ai release origin
   THROUGH the local proxy only, verifies the release manifest SHA-256 and Apple's
   signature for Anthropic PBC, then copies it to ~/.local/bin/claude. No remote
   shell script is downloaded or executed. No host credentials are used. A GPG
   manifest signature is not checked (fresh macOS lacks gpg); Apple signing plus
   HTTPS and the manifest digest are required. Signer/format changes fail closed.
   Run ~/.local/bin/claude and authenticate yourself afterward. Shell startup
   files and existing Claude installations are not modified. If ONLY the Claude
   download fails or you skipped it, retry from guest Terminal (no service/app
   overwrites and no sudo in this mode):
   /bin/bash "/Volumes/My Shared Files/setup/Install.command" --claude-only
5. Verify connectivity and open the applications yourself. The manager cannot
   receive completion through a read-only folder and must continue to display
   awaiting_user_setup, NOT 'installed' or 'verified'. Setup sharing also prevents
   suspend/resume; use an ordinary guest shutdown. A future explicit detach flow
   can remove this setup drive, after guest validation.

SECURITY / LIMITATIONS
- Only active local TUIC and TLS/TCP VLESS Reality nodes with global IPv4 literal
  servers are supported. No subscriptions, script/merge hooks, host rules, DNS
  settings or providers are copied. Endpoint addresses are fixed at preparation;
  server rotation requires explicit reprovisioning, never automatic widening.
- A host node's skip-cert-verify setting is retained for compatibility and causes
  an explicit preparation warning. The network fence is endpoint isolation, NOT
  a guarantee of end-to-end TLS authenticity or malicious-guest-root isolation.
- Strict TUN + fake-IP DNS + DoH through PROXY are generated. Host fence rejects
  direct DNS/IPv6/LAN/other Internet traffic even if guest proxy/TUN fails. The
  default DNS bootstrap IP cannot escape the fence. No DIRECT proxy group exists.
- The copied core is version-pinned to a reviewed, signed host binary. App/core
  updates, changed package digests or unsupported profiles require explicit review.
  Guest service logs are discarded so credentials cannot enter diagnostics.
- Guest macOS must provide system Ruby and kern.hv_vmm_present=1. If unavailable,
  the installer refuses rather than guessing; manual reviewed setup is required.
- Fresh-only installer refuses existing target applications/service/Claude binary.
  Installation may be partial on failure. No automatic delete/rollback or VM
  operation occurs. It retains a private temporary directory containing config
  credentials; clean it up manually only after verifying its exact path. It does
  not send receipts, credentials or installation logs back to the manager.
- Official CCBaga release digest pins provenance, not a claim of a security audit.
  Its companion Chromium fork's security backport coverage is not independently
  verified by this feature. Install/open only if you accept that limitation.

SOURCES (reviewed 2026-11-16)
CCBaga A+B v0.2.50 release:
https://github.com/liseami/CCBaga/releases/tag/v0.2.50
Release asset SHA-256 (GitHub release API):
0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b
https://api.github.com/repos/liseami/CCBaga/releases/tags/v0.2.50
Claude official native installation and signing documentation:
https://code.claude.com/docs/en/setup
Official native binary origin (no remote installer executed):
https://downloads.claude.ai/claude-code-releases
Clash/Mihomo core source: installed Clash Verge signed by JPH3Z7PPBB,
SHA-256 94c6fe434317ae5c00c6bc3dd6761fe0734edbd78ae205910108be186b0d968c.
