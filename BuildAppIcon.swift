import AppKit
import Foundation
let out = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)
func render(_ pixels: Int) throws -> Data {
    let size = NSSize(width: 1024, height: 1024)
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
        let context = NSGraphicsContext(bitmapImageRep: bitmap) else { throw NSError(domain: "Icon", code: 1) }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    context.cgContext.scaleBy(x: CGFloat(pixels) / size.width, y: CGFloat(pixels) / size.height)
    let background = NSBezierPath(roundedRect: NSRect(x: 32, y: 32, width: 960, height: 960), xRadius: 218, yRadius: 218)
    let gradient = NSGradient(starting: NSColor(calibratedRed: 0.08, green: 0.19, blue: 0.16, alpha: 1),
                              ending: NSColor(calibratedRed: 0.17, green: 0.38, blue: 0.29, alpha: 1))!
    gradient.draw(in: background, angle: 50)
    for index in (0...2).reversed() {
        let offset = CGFloat(index) * 30
        let panel = NSBezierPath(roundedRect: NSRect(x: 258 + offset, y: 246 + offset, width: 450, height: 450), xRadius: 76, yRadius: 76)
        NSColor(calibratedRed: 0.75, green: 0.84, blue: 0.69, alpha: index == 0 ? 0.10 : 0.035).setFill()
        panel.fill()
        NSColor(calibratedRed: 0.83, green: 0.76, blue: 0.54, alpha: index == 0 ? 0.75 : 0.32).setStroke()
        panel.lineWidth = index == 0 ? 5 : 3
        panel.stroke()
    }
    let gold = NSColor(calibratedRed: 0.91, green: 0.81, blue: 0.56, alpha: 1)
    let font = NSFont(name: "Georgia-Bold", size: 480) ?? NSFont.boldSystemFont(ofSize: 480)
    let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: gold]
    let text = "g" as NSString
    let dimensions = text.size(withAttributes: attrs)
    text.draw(at: NSPoint(x: (1024 - dimensions.width) / 2 - 15, y: 270), withAttributes: attrs)
    for x in [440, 512, 584] {
        let circle = NSBezierPath(ovalIn: NSRect(x: CGFloat(x) - 10, y: 155, width: 20, height: 20))
        gold.withAlphaComponent(x == 512 ? 1 : 0.42).setFill()
        circle.fill()
    }
    NSGraphicsContext.restoreGraphicsState()
    guard let data = bitmap.representation(using: .png, properties: [:]) else { throw NSError(domain: "Icon", code: 2) }
    return data
}
for (name, pixels) in [("icon_16x16.png",16),("icon_16x16@2x.png",32),("icon_32x32.png",32),("icon_32x32@2x.png",64),("icon_128x128.png",128),("icon_128x128@2x.png",256),("icon_256x256.png",256),("icon_256x256@2x.png",512),("icon_512x512.png",512),("icon_512x512@2x.png",1024)] {
    try render(pixels).write(to: out.appendingPathComponent(name), options: .withoutOverwriting)
}
print("Created native-resolution app icon assets")
