import SwiftUI
import CoreImage
import CoreImage.CIFilterBuiltins
import UIKit
import StarRadarCore

/**
 二维码渲染。

 ## 为什么用 CoreImage 而不是移植 Android 端的手写编码器

 Android 端的 `Qr.kt` 是自研的（GF(256) RS + 8 掩码 + SVG），那是为了
 不引第三方库又能逐字节验证。iOS 有系统级实现 `CIQRCodeGenerator`，
 它是苹果自己的编码器、长期被系统和 App 使用 —— 用它比移植 486 行
 位运算更可靠，也省掉一处只有真机才能发现的错误。

 内容本身（deep link / socks5:// 链接）仍然由 `ShareLinks` 生成，
 那部分才需要与 PC 端逐字节一致，并且有交叉验证向量兜底。

 ## 静区必须自己补

 `CIQRCodeGenerator` 的输出**不带** 4 模块的白色边距。缺了它，很多扫码器
 在深色背景或紧贴边框时会识别失败。这里统一补 4 模块。
 */
enum QrRenderer {

    /// 每模块像素数。取 8 是画质与内存的折中（41×41 的码约 392×392 px）。
    static let pixelsPerModule: CGFloat = 8
    /// 静区（模块数）。
    static let quietZoneModules = 4

    static func image(_ text: String) -> UIImage? {
        if text.isEmpty { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        // 与 Android 端一致的纠错级别 M（约 15%）
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }

        let modules = Int(output.extent.width.rounded())
        if modules <= 0 { return nil }
        let scale = pixelsPerModule
        let side = CGFloat(modules) * scale + scale * CGFloat(quietZoneModules) * 2
        let sidePixels = Int(side)

        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: sidePixels,
                                      height: sidePixels, bitsPerComponent: 8,
                                      bytesPerRow: 0, space: colorSpace,
                                      bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)
        else { return nil }

        // 白底
        context.setFillColor(red: 1, green: 1, blue: 1, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: side, height: side))
        context.interpolationQuality = .none

        let ciContext = CIContext(options: nil)
        guard let modulesImage = ciContext.createCGImage(output,
                                                        from: output.extent) else {
            return nil
        }
        let offset = scale * CGFloat(quietZoneModules)
        context.draw(modulesImage, in: CGRect(x: offset, y: offset,
                                              width: CGFloat(modules) * scale,
                                              height: CGFloat(modules) * scale))
        guard let composed = context.makeImage() else { return nil }
        return UIImage(cgImage: composed)
    }
}

struct QrImage: View {
    let text: String
    var side: CGFloat = 200

    var body: some View {
        Group {
            if let image = QrRenderer.image(text) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: side, height: side)
            } else {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Sr.surface2)
                    Text("二维码生成失败")
                        .font(.system(size: 12))
                        .foregroundColor(Sr.err)
                }
                .frame(width: side, height: side)
            }
        }
    }
}
