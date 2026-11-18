"""Reviewed complete GUI releases, frozen 2026-11-18 (Asia/Singapore).

Initial signer bootstrap was NOT an arbitrary observed TeamID: CCBaga/Clash
original archives matched exact publisher GitHub SHA256 metadata, all apps passed
Apple Developer ID chain and notarization assessment, then these identities were
explicitly pinned. Claude came from the exact official HTTPS release feed URL,
matched the independent Homebrew SECONDARY digest, and additionally satisfied an
Apple-anchored certificate subject.O == 'Anthropic PBC' before its TeamID pin.

No latest-version auto-trust, first-launch consent, application execution, host
profile copying or installation is performed by this pure catalog. Updating any
artifact/version/signing identity requires another explicit source review.
"""
from guest_app_artifacts import AppExpectation, freeze_manifest

REVIEWED_AT = '2026-11-18 (Asia/Singapore)'
CLAUDE_DIGEST_SOURCE = 'https://raw.githubusercontent.com/Homebrew/homebrew-cask/master/Casks/c/claude.rb'


def reviewed_manifests():
    ccbaga = freeze_manifest(
        product='ccbaga', version='0.2.50',
        artifact_url='https://github.com/liseami/CCBaga/releases/download/v0.2.50/CCBaga-0.2.50-macos-arm64.dmg',
        known_sha256='0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b',
        declared_size_bytes=333449374, vendor_team_ids=('6UB6WM6VQR',),
        identity_review_sources=(
            'https://api.github.com/repos/liseami/CCBaga/releases/latest',
            'https://github.com/liseami/CCBaga/releases/download/v0.2.50/CCBaga-0.2.50-macos-arm64.dmg'),
        expected_apps=(
            AppExpectation('CCBaga-A.app', bundle_identifiers=('ai.local.requirement-french',),
                bundle_names=('CCBaga-A',), executable_names=('requirement-french',),
                short_versions=('0.2.50',), bundle_versions=('0.2.50',),
                required_paths=('Contents/Resources','Contents/MacOS/requirement-french')),
            AppExpectation('CCBaga-B.app', bundle_identifiers=('ai.local.requirement-french.browser',),
                bundle_names=('CCBaga-B',), executable_names=('CCBrowser',),
                short_versions=('148.0.7778.215',), bundle_versions=('7778.215',),
                required_paths=('Contents/Resources','Contents/MacOS/CCBrowser','Contents/MacOS/Chromium',
                                'Contents/Frameworks/Chromium Framework.framework'))))
    clash = freeze_manifest(
        product='clashVergeRev', version='2.5.10',
        artifact_url='https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.10/Clash.Verge_2.5.10_aarch64.dmg',
        known_sha256='40d4a7da4543d75f573a5cfcc31543b0b4bf7e02caa122a9ca50654859585839',
        declared_size_bytes=80769307, vendor_team_ids=('JPH3Z7PPBB',),
        identity_review_sources=(
            'https://api.github.com/repos/clash-verge-rev/clash-verge-rev/releases/latest',
            'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.10/Clash.Verge_2.5.10_aarch64.dmg'),
        expected_apps=(AppExpectation('Clash Verge.app',
            bundle_identifiers=('io.github.clash-verge-rev.clash-verge-rev',), bundle_names=('Clash Verge',),
            executable_names=('clash-verge',), short_versions=('2.5.10',), bundle_versions=('2.5.10',),
            required_paths=('Contents/Resources','Contents/MacOS/clash-verge','Contents/MacOS/verge-mihomo')),))
    claude = freeze_manifest(
        product='claudeDesktop', version='6.6395.0',
        artifact_url='https://downloads.claude.ai/releases/darwin/universal/6.6395.0/Claude-d71a20056be3b25708751e98bef60759ea1f441b.zip',
        known_sha256='88c7b43039e77529930eda386a21141232bf2acb6762d04e6fbc2d028813847a',
        # Official feed omits size/digest; actual 399131567-byte size is in receipts.
        declared_size_bytes=None, vendor_team_ids=('Q6L2SF6YDW',),
        identity_review_sources=('https://downloads.claude.ai/releases/darwin/universal/RELEASES.json',
            CLAUDE_DIGEST_SOURCE, 'https://support.claude.com/en/articles/12611117-deploy-claude-desktop-for-macos'),
        expected_apps=(AppExpectation('Claude.app', bundle_identifiers=('com.anthropic.claudefordesktop',),
            bundle_names=('Claude',), executable_names=('Claude',), short_versions=('6.6395.0',),
            bundle_versions=('6.6395.0',), required_paths=('Contents/Resources','Contents/Resources/app.asar',
                'Contents/Frameworks/Electron Framework.framework','Contents/MacOS/Claude')),))
    return (ccbaga,clash,claude)
