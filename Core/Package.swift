// swift-tools-version:5.7
import PackageDescription

/**
 协议核心 —— 与 Android/PC 端逐字节同协议的那一层。

 单独做成 SwiftPM 包的原因：这些代码只依赖 Foundation / CryptoKit，
 可以在 macOS 上用 `swift test` 跑真机同一份实现，用同一批
 交叉验证向量（来自 PC 的 Python 实现）比对。UI 与网络监听留在 App
  target 里，那部分必须上真机才能验。
 */
let package = Package(
    name: "StarRadarCore",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "StarRadarCore", targets: ["StarRadarCore"]),
    ],
    targets: [
        .target(
            name: "StarRadarCore",
            path: "Sources/StarRadarCore"
        ),
        .testTarget(
            name: "StarRadarCoreTests",
            dependencies: ["StarRadarCore"],
            path: "Tests/StarRadarCoreTests",
            resources: [.copy("Vectors")]
        ),
    ]
)
