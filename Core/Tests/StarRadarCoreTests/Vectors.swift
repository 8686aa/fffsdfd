import Foundation
import XCTest
@testable import StarRadarCore

/// 交叉验证向量的读取入口。
///
/// 这批 JSON 是 **PC 端 Python 实现生成的**（`starradar-android/tools/gen_*.py`），
/// 安卓端已经用它们逐字节对齐过。iOS 端直接复用同一批文件，等于三个平台
/// 拿同一把尺子量 —— 任何一处偏移/填充/编码写错都会在这里红。
enum Vectors {

    static func load(_ name: String) -> JSON {
        guard let url = Bundle.module.url(forResource: name,
                                         withExtension: "json",
                                         subdirectory: "Vectors"),
              let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8),
              let json = Json.parse(text) else {
            fatalError("读不到向量文件：\(name).json")
        }
        return json
    }

    static func bytes(_ value: String?) -> [UInt8] {
        guard let value else { return [] }
        return Hex.decode(value) ?? []
    }
}
