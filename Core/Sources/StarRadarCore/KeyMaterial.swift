import Foundation

/// 一份对局密钥候选 —— 与 `KeyMaterial.kt` 的字段一一对应。
///
/// PC 版还带 `source_context`（母料前后各 2KB 的上下文，用于离线复核），
/// 移动端**不带**：那是额外的内存与落盘开销，复核本来就在节点侧做。
public struct KeyMaterial {
    public let material: [UInt8]
    public let session: String
    public let upstream: (host: String, port: Int)
    public let sha256: String
    public let command: Int
    public let sequence: UInt32
    public let layer: String
    public let offset: Int
    public let observedMs: Int64

    public init(material: [UInt8], session: String,
                upstream: (host: String, port: Int), sha256: String,
                command: Int, sequence: UInt32, layer: String = "plain",
                offset: Int = 0,
                observedMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) {
        precondition(material.count == Tgcp.materialSize,
                     "母料必须是 128 字节，实际 \(material.count)")
        self.material = material
        self.session = session
        self.upstream = upstream
        self.sha256 = sha256
        self.command = command
        self.sequence = sequence
        self.layer = layer
        self.offset = offset
        self.observedMs = observedMs
    }

    /// 上报端用的 key_id：取指纹前 16 位，够区分且不解密就别想反推。
    public var id: String { String(sha256.prefix(16)) }

    public var materialB64: String {
        Data(material).base64EncodedString()
    }
}
