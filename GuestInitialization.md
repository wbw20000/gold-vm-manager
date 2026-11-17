# Visible first-boot initialization (experimental, paused)

> Status as of 2026-11-17: complete automatic initialization has **not** been delivered and development is paused. The main-panel preview entry is removed. This is retained implementation documentation, not a supported unattended setup workflow. No successful complete credential-entry-to-configured-desktop run is claimed. See [README](<README.md>) for current user-facing scope.

## Capability and honesty boundary

[GuestInitialization.swift](<GuestInitialization.swift>) compiles into the main native AppKit application, not a separately installed helper. It uses **ScreenCaptureKit** (`SCShareableContent`, `SCContentFilter`, `SCScreenshotManager.captureImage`), **local Vision** text/rectangle recognition, Accessibility window inspection, and **PID-targeted physical-key/mouse events**. It does **not** use `VZGuestProvisioningOptions`: that macOS 27 API is unavailable on the specified macOS 26.6.2 host. The source typechecks with Swift 5 mode and a macOS 14 deployment target; the requested host provides the newer single-window shadow-exclusion API (14.2+).

This is conservative, actual GUI action code, **not a claim of a validated unattended macOS 26.6.2 installer**. No VM, screenshot, credential input, GUI test, Tart command, network connection, or installed app was used to develop/validate it. OCR anchors/layout detectors have not been calibrated against a running 26.6.2 Setup Assistant. Ambiguous controls fail closed; that can require manual intervention.

The only desktop outcome is **`desktop_ready_requires_profile_apply`**. This is **not** `ready`, full success, proof of account creation, or proof of persistent language/region/timezone/location settings. It also applies if the driver finds an already-visible desktop. There is no post-desktop Finder/Terminal/sudo helper here. The parent owns subsequent user-authorized guest profile installation/verification. In particular, a caller must not translate the desktop result into “timezone configured.”

## Native API

```swift
@MainActor
let driver = GuestInitializationDriver() // Retain for the run.
let profile = GuestInitializationDriver.Profile(
    version: 1, language: "en-US", country: "US",
    timezone: "America/Los_Angeles",
    location_services: false, skip_migration: true,
    skip_apple_account: true, share_analytics: false,
    allow_license_agreement: false
)
// Obtain these STRINGS exclusively in native controls, including NSSecureTextField.
let credentials = GuestInitializationDriver.Credentials(
    fullname: nativeFullName, username: nativeUsername, password: nativePassword
)
driver.start(vmName: selectedVMName, profile: profile, credentials: credentials,
    status: { phase, code in
        // Constants only; parent may associate its own VM identity with these callbacks.
        // Do not raise the manager window or steal focus from Tart during automation.
    }, completion: { result in
        // result.code is sanitized. Handle .stopped(reason), .cancelled,
        // and .desktop_ready_requires_profile_apply explicitly.
    })
// Main actor; one completion for the active run, immediate reference clearing.
driver.cancel()
```

- All driver operations/callbacks are main-actor isolated. `status` has `(phase: String, code: String)` semantics; it does not include VM names or OCR text. `Result.code` and `StopReason.rawValue` are constant allowlisted status values.
- `Profile` is Codable and contains exactly `version:Int`, `language:String`, `country:String`, `timezone:String`, `location_services:Bool`, `skip_migration:Bool`, `skip_apple_account:Bool`, `share_analytics:Bool`, `allow_license_agreement:Bool`. The last field decodes to **false** when omitted. All other fields are required when decoding. Explicit native consent may set the last field locally; do not silently accept an agreement based on a backend default.
- Profile version must be 1. Country must be an uppercase two-letter ISO region recognized by Foundation, supplied by the parent from the selected VPS country. Country display candidates are derived with English/Chinese Foundation `Locale`, never guessed from an IP. Timezone must be an explicit entry in `TimeZone.knownTimeZoneIdentifiers`; a country alone is never enough for multi-city countries.
- **Only `en-US` is supported.** `en-GB`, `zh-Hans`/`zh-CN`, `zh-Hant`, Japanese, German, French, and any other profile language stop with `unsupported_language` **before any input**. The language chooser can select the exact `English` row; known Chinese headings on subsequent pages stop rather than pretending Chinese automation works. Other unrecognized UI stops. The Chinese recognition language/region-name lookup is not a Chinese-support claim.
- Privacy profile must specify location **false**, migration skip **true**, Apple Account skip **true**, analytics **false**. Other combinations are rejected rather than silently converted.
- `Credentials` is a final reference class with private-set String fields `fullname`, `username`, `password`, its native initializer, and `clear()`. It is **not Codable** and has no custom description/debug-description/logging. It must never enter JSON, HTTP, WebKit/JS, command arguments, environment variables, telemetry, crash messages, or clipboard. Do not inspect it with `dump`/reflection. Keep any native field cleanup in the parent as well.
- Printable ASCII only for **all three** input strings; full name 1–60 characters with no edge spaces; username `[a-z][a-z0-9_]{0,31}`; password 4–128 printable ASCII characters with no edge spaces. These are conservative driver constraints, not a promise of every macOS account-policy constraint. Unsupported characters are rejected before input; there is no Unicode/clipboard fallback.
- `clear()` replaces the object's strings with empty strings on every completion, failure and cancellation. Swift String copies, OS event queues and allocator storage prevent a forensic RAM-wipe guarantee. Do not reuse/share the same credential object across active runs. A second concurrent `start` is rejected as `busy`.

## Host preparation and target fence

1. Parent/user starts the **new** VM independently. This driver has no backend VM API, no VM lifecycle methods, and never invokes Tart/CLI commands.
2. Grant the main native app Accessibility and Screen Recording permissions through normal macOS UI. Missing permissions return constant statuses; the driver does not open permission dialogs or modify TCC.
3. Exactly one window with the **exact** `vmName` title must belong to an already-running executable at:
   `~/Applications/tart.app/Contents/MacOS/tart` under the current user's home directory (resolved to an absolute executable path by the driver).
4. Driver records the PID, process launch date, window ID, title and initial bounds. Initial enumeration includes offscreen windows so a duplicate title is not silently ignored. A matching window must be onscreen, normal-layer and at least 640×480 points.
5. After the native secure sheet closes, status is `waiting / bring_exact_vm_window_frontmost`. There are up to **30 seconds** for the user to focus that exact Tart window. This handoff sends no input and does not activate/raise any application itself. The manager must not keep its sheet in front.
6. Keep the VM window stationary, completely inside one active display, unobscured and foreground. Do not type or hold modifiers/Caps Lock. Closing, minimizing, moving/resizing, duplicate titles, process/PID changes, focus loss, overlapping windows, modifier activity or unexpected AX focus stop the run. There is no automatic focus reacquisition after automation begins.

Every individual event (including releases) rechecks ownership/path/launch date, exact unique title and window ID, bounds/visibility, frontmost application, focused AX window title/geometry, display containment, occlusion and modifiers. Mouse events carry the target window ID. **All events use `postToPid`; there is no global `post`/HID-tap input fallback.** Local capture success alone does not authorize input to an obscured window. Like all GUI automation, OS scheduling allows a tiny check-to-delivery race; PID targeting remains in place even then. If the user changes focus between a modifier-down/up pair the driver stops instead of releasing into a different application; the user may need to tap/release that key in the VM.

## Known pages and fail-closed behavior

Only exact normalized allowlisted OCR anchors are recognized, not fuzzy “AI” interpretations. Normalization only handles surrounding whitespace, duplicate spaces and apostrophe style. A few exact dialog sentences can be reconstructed from adjacent wrapped OCR lines. Clicking uses recognized text bounds or detected input-field rectangles bound to exact form labels, **not hard-coded screen coordinates**. Mouse scrolling is anchored to OCR-confirmed country-list rows.

| Page | Action / boundary |
| --- | --- |
| Language | Exact `English`, then exact `Continue` or physical Return on this known initial page only. |
| Country/region | Exact Foundation display name, bounded upward/downward scrolling. A default-blue selection highlight must be read back before Continue; nondefault/ambiguous rendering stops. |
| Accessibility | Explicit `Not Now` / `Set Up Later` only. |
| Data & Privacy / Written and Spoken Languages | Exact Continue; not a claim that all persistent language/input-source preferences were configured. |
| Migration | Exact modern `Not Now` skip button. Older radio-only layouts stop; a clicked label alone is not proof of no-migration selection. |
| Apple Account | Exact Set Up Later; only the exact recognized skip-confirmation dialog may click Skip. |
| Location | Explicit Don't Use / Not Now, or an exact-label, uniquely detected checkbox. **Two stable empty/OFF observations** permit Continue without a toggle. **Two stable checked observations** (default-blue fill plus white-checkmark shape) permit **one** checkbox-center click, then **two stable empty/OFF readbacks** are mandatory before Continue. Unknown state, changed geometry/page, or failed OFF readback stops with `checkbox_state_requires_user` / `unknown_page`; there is never a second-toggle retry. Recognized Don't Use confirmation is handled. |
| Time zone | `timezone_requires_manual_selection`. A visible city label is not proof of the chosen IANA zone. This source does not configure or claim a timezone. |
| Analytics | Both known analytics-sharing checkboxes must be confidently visually empty before Continue. Unknown/checked state stops; never blind toggles. |
| Siri | Explicit Set Up Later / Not Now, or proven empty enable checkbox before Continue. |
| Screen Time | Explicit Not Now / Set Up Later only. |
| Appearance | Exact Continue, preserving the displayed default. |
| Keyboard | Exact U.S./US option when this known page is offered. Physical mapping is still independently verified before secrets. |
| Computer account | The guarded procedure below; only exact `Create a Computer Account` permits account entry. |
| Terms | `license_consent_required` unless native opt-in `allow_license_agreement == true`; only exact Agree on recognized terms/confirmation pages. |
| Network | Only already-offered explicit offline choices. No network changes, hidden shortcuts, downloads or fence widening. Other network layouts stop. |
| Finder desktop | Requires exact Finder menu anchors near the top of the captured VM window. Returns the partial desktop result only. |
| Login / lock screen | STOP. No password guessing, unlock or credential attempt. |
| FileVault / disk security / recovery key | STOP for user. No encryption disablement, erasure, recovery-key reading, or sensitive-database edits. |
| Unknown page/control | STOP with constant status, never raw OCR/UI strings. |

Empty-checkbox proof requires a detected square immediately beside the allowlisted label, a neutral, uniform bright interior, and a visible contrasting outline. Location alone may also recognize the opposite state: a default-blue filled square with a white checkmark, both its short descending and long rising strokes, sufficient blue background, and most white pixels close to the expected checkmark polyline. Blue color alone, dots, dashes and plus signs are not enough. The square and exact location page/label must remain stable across both pre-click frames and both post-click OFF frames. The click is on the detected square, not an arbitrary point or the text label. Analytics/Siri behavior is unchanged: checked or ambiguous still stops.

These are intentionally restrictive local raster heuristics, **not** a general state model or live-VM-calibrated detector. Dark/high-contrast/nonblue/animated/unrecognized controls may require manual handling. Only an observed checked-to-OFF change is authorized, never an unknown-to-toggle change; there are no location-database edits. As with any GUI automation, check/click cannot be made atomic against concurrent user/guest input: do not interact with the guest during this operation. A failed OFF readback stops without another click or Continue. Setup choices are not post-desktop audits of global guest services.

There are at most 80 recognized page actions and a 20-minute outer deadline. Transitions require two consecutive recognized new-page captures, normally within 25 seconds (90 seconds after account submission). Transient unknown frames during a transition are never acted on; timeout stops. Country search and keyboard probes also have finite bounds. A failure does not blindly retry an account submission.

## Physical keyboard and account safety

`VZVirtualMachineView` forwards HID keycodes. **`CGEventKeyboardSetUnicodeString` is not a valid guest-text solution and is not used.** The source explicitly maps every printable ASCII character to ANSI US physical keycodes and real Shift down/up events; it uses no clipboard. Host keyboard layout alone is not trusted as proof of the guest layout.

Before any credential text:

1. Require the exact Computer Account page and unique nonoverlapping detected rectangles tied to Full Name, Account Name, Password, Verify labels.
2. In the Full Name field, type a sequence of **fixed public ASCII probes**, covering every printable character, shifted and unshifted keys, letters, digits and space. Replace each short probe using field-scoped Cmd-A/Delete.
3. Locally OCR that visible field and demand **exact** readback for every probe. OCR ambiguity, wrong keyboard layout, unfocused fields, text truncation or mapping disagreement stops as `keyboard_verification_failed`. No secret is entered on probe failure.
4. Replace public probes with full name and username; locally read both back exactly. No inference from a click alone.
5. Only then type password and verification through the private local physical-key path. No screenshot/OCR is requested inside this password-entry phase; no password is read back, logged, serialized or passed to another model. Click the already-recognized Continue in the unchanged fenced window, then clear credential references.
6. Require a recognized new page/desktop rather than claiming that clicking Continue succeeded. Account errors are not repeated as guesses.

The required exact OCR probes are deliberately strict: typography/rectangle detection may make a legitimate layout fail. That is safer than silently typing a different password. The parent should explain the stop, not bypass verification or switch to Unicode events. A stopped/cancelled operation does not erase guest UI fields or roll back a partially completed account; doing so after focus loss would violate the input fence. Resume must be deliberate, with the user handling any existing account/login screen manually.

## Compile-only validation

Executed successfully without running code or interacting with a VM:

```sh
xcrun swiftc -swift-version 5 -target arm64-apple-macosx14.0 \
  -warnings-as-errors -typecheck GuestInitialization.swift
```

The source-only Location-OFF followup also passed that same strict typecheck; no screenshot, VM action, classifier runtime test or credential input was performed for that followup.

The initial driver was also successfully compiled and linked with a temporary, empty `@main` Swift entry point using the same Swift-5/macOS-14 flags plus `-parse-as-library`. The temporary source and binary were removed after verifying their resolved temporary paths. **The binary was never executed.**

The parent must compile this source alongside its refactored `@main` native app, linked against standard Apple AppKit/ApplicationServices/ScreenCaptureKit/Vision frameworks as Swift imports require. Existing top-level native-app entry code must not be combined with an additional `@main` without the parent's refactor. No signed standalone helper, install step, production binary replacement, test VM input or credential test is provided by these files.
