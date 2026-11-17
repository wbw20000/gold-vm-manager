import AppKit
import Foundation
let fm = FileManager.default
let home = fm.homeDirectoryForCurrentUser
let app = home.appendingPathComponent("Applications/Gold VM Manager.app", isDirectory: true)
let entry = home.appendingPathComponent("Desktop/Gold VM 管理器")
guard fm.fileExists(atPath: app.appendingPathComponent("Contents/MacOS/GoldVMManager").path),
      !fm.fileExists(atPath: entry.path) else { exit(2) }
let data = try app.bookmarkData(options: .suitableForBookmarkFile, includingResourceValuesForKeys: nil, relativeTo: nil)
try URL.writeBookmarkData(data, to: entry)
let resolved = try URL(resolvingAliasFileAt: entry, options: [.withoutUI])
guard resolved.resolvingSymlinksInPath().path == app.resolvingSymlinksInPath().path else { exit(3) }
let icon = app.appendingPathComponent("Contents/Resources/AppIcon.icns")
if let image = NSImage(contentsOf: icon) { _ = NSWorkspace.shared.setIcon(image, forFile: entry.path, options: []) }
let values = try entry.resourceValues(forKeys: [.isAliasFileKey])
print("Desktop entry created; resolves to native app:", resolved.path)
print("Finder alias:", values.isAliasFile == true)
