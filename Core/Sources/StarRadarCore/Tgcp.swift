import Foundation

/**
 TGCP 协议层 —— 与 PC 版 `core/tgcp.py`、Android 版 `Tgcp.kt` 逐字节一致。

 ## 帧结构（21 字节固定头 + 扩展 + body）

 ```
   偏移  长度  含义
   0     2     magic "3f"
   2     4     保留
   6     2     command（大端）
   8     1     gate / dir_flags（高 4 位加密标记、低 4 位方向）
   9     4     sequence（大端）
   13    4     header_len（含扩展头，大端）
   17    4     body_len（大端）
   21    ...   扩展头（DH 公钥就在这里）
 ```

 这一层必须 1:1：任何一处偏移算错，现象都是「握手看着成功、几秒后断开」，
 日志里看不出所以然。所以每个常量都标注了它在 Python 版里的对应表达式。
 */
public enum Tgcp {

    public static let magic: [UInt8] = [0x33, 0x66]        // '3' 'f'
    public static let fixedHeader = 21

    /// AES-CBC 固定 IV —— 协议里就是 `bytes(range(16))`。
    public static let nativeIV: [UInt8] = (0..<16).map { UInt8($0) }

    /// 填充块尾部 5 字节标记（`tsf4g`），pad 值单独在最后一字节。
    public static let trailerMarker: [UInt8] = Array("tsf4g".utf8)

    // 命令字
    public static let cmdClientHello: Int = 0x1001
    public static let cmdServerHello: Int = 0x1002
    public static let cmdBattleS2C: Int = 0x4013

    public static let maxHeader = 65536
    public static let maxFrame = 4194304
    public static let maxInspect = 524288
    public static let lz4Limit = 4194304
    public static let contextRadius = 2048

    /// 母料 128 字节。base64 后 172 字符且必带 '='。
    public static let materialSize = 128

    // ── 数值编解码 ─────────────────────────────────────────────

    /// 最小大端表示。0 单独编码成一个 `0x00`（Python 版同样特判）。
    public static func minimalBe(_ value: BigUInt) -> [UInt8] {
        value.bytes
    }

    /// 定长左补零大端。
    public static func fixedBe(_ value: BigUInt, size: Int = 64) -> [UInt8] {
        value.fixedBytes(size)
    }

    /// 共享秘密 → AES 密钥：`MD5(最小大端表示)`。
    public static func md5Key(_ shared: BigUInt) -> [UInt8] {
        Crypto.md5(minimalBe(shared))
    }

    public static func publicIsValid(_ value: BigUInt) -> Bool {
        value > BigUInt(1) && value < (TgcpConstants.p - BigUInt(1))
    }

    // ── DH ────────────────────────────────────────────────────

    public final class DhSide {
        public let privateKey: BigUInt
        public let publicKey: BigUInt

        init(privateKey: BigUInt) {
            self.privateKey = privateKey
            self.publicKey = TgcpConstants.g.modPow(privateKey, TgcpConstants.p)
        }

        public var publicBytes: [UInt8] {
            fixedBe(publicKey)
        }

        /// 派生共享密钥；对端公钥越界直接抛（Python 版同样行为）。
        public func deriveKey(peerPublic: BigUInt) throws -> [UInt8] {
            guard publicIsValid(peerPublic) else {
                throw ProxyError("peer DH public value is outside the accepted range")
            }
            let shared = peerPublic.modPow(privateKey, TgcpConstants.p)
            return md5Key(shared)
        }

        /// 随机私钥，范围 `[2, P-2]`（等价于 Python 的 `randbelow(P-3)+2`）。
        public static func create() -> DhSide {
            let byteCount = (TgcpConstants.p.bitCount + 7) / 8
            let upper = TgcpConstants.p - BigUInt(2)
            let two = BigUInt(2)
            for _ in 0..<64 {
                var bytes = Crypto.randomBytes(byteCount)
                // 清掉超出模数位宽的高位，减少反复重试
                let excess = byteCount * 8 - TgcpConstants.p.bitCount
                if excess > 0 {
                    bytes[0] &= UInt8(0xFF >> excess)
                }
                let candidate = BigUInt(bytes: bytes)
                if candidate >= two && candidate < upper {
                    return DhSide(privateKey: candidate)
                }
            }
            // 理论上到不了这里；退而求其次用一个固定小数（仍然合法）
            return DhSide(privateKey: BigUInt(0x1234_5678))
        }

        /// 测试用：固定私钥，保证可复现。
        public static func of(privateKey: BigUInt) -> DhSide {
            DhSide(privateKey: privateKey)
        }
    }

    // ── 帧 ────────────────────────────────────────────────────

    public struct Frame {
        public let rawHeader: [UInt8]
        public let body: [UInt8]
        public let offset: Int
        public let command: Int
        public let gate: Int
        public let sequence: UInt32

        public init(rawHeader: [UInt8], body: [UInt8], offset: Int = 0) {
            self.rawHeader = rawHeader
            self.body = body
            self.offset = offset
            self.command = Bytes.u16(rawHeader, 6)
            self.gate = Int(rawHeader[8])
            self.sequence = Bytes.u32(rawHeader, 9)
        }

        private init(rawHeader: [UInt8], body: [UInt8], offset: Int,
                     command: Int, gate: Int, sequence: UInt32) {
            self.rawHeader = rawHeader
            self.body = body
            self.offset = offset
            self.command = command
            self.gate = gate
            self.sequence = sequence
        }

        public var headerLen: Int { Int(Bytes.u32(rawHeader, 13)) }
        public var bodyLen: Int { Int(Bytes.u32(rawHeader, 17)) }

        public var ext: [UInt8] {
            rawHeader.count > fixedHeader
                ? Array(rawHeader[fixedHeader...]) : []
        }

        public func withBody(_ newBody: [UInt8]) -> Frame {
            Frame(rawHeader: rawHeader, body: newBody, offset: offset,
                  command: command, gate: gate, sequence: sequence)
        }

        public func withHeader(_ newHeader: [UInt8]) -> Frame {
            Frame(rawHeader: newHeader, body: body, offset: offset)
        }

        public func withParts(newHeader: [UInt8]? = nil,
                              newBody: [UInt8]? = nil) -> Frame {
            Frame(rawHeader: newHeader ?? rawHeader,
                  body: newBody ?? body, offset: offset)
        }

        /// 回填 header_len / body_len 两个字段并拼起来。
        public func pack() -> [UInt8] {
            let head = rawHeader
            var out = [UInt8](repeating: 0, count: head.count + body.count)
            out.replaceSubrange(0..<13, with: head[0..<13])
            Bytes.putU32(&out, 13, UInt32(head.count))
            Bytes.putU32(&out, 17, UInt32(body.count))
            if head.count > fixedHeader {
                out.replaceSubrange(fixedHeader..<head.count,
                                    with: head[fixedHeader..<head.count])
            }
            out.replaceSubrange(head.count..<(head.count + body.count), with: body)
            return out
        }

        public var commandName: String {
            String(format: "0x%04x", command)
        }
    }

    /**
     按 header_len/body_len 切帧。

     长度字段不合法时**直接抛**，不做「尽量恢复」：magic 已经对上了却切不出
     合法的帧，说明流已经错位，继续往后猜只会把垃圾当帧喂给上层。
     */
    public final class Framer {
        private var buffer: [UInt8] = []
        private var position = 0
        public private(set) var streamOffset = 0

        public init() {}

        public func feed(_ data: [UInt8]) throws -> [Frame] {
            append(data)
            var frames: [Frame] = []
            while true {
                if buffer.count - position < fixedHeader { break }
                if buffer[position] != magic[0] || buffer[position + 1] != magic[1] {
                    throw ProxyError("TGCP magic mismatch at stream offset \(streamOffset)")
                }
                let headerLen = Int(Bytes.u32(buffer, position + 13))
                let bodyLen = Int(Bytes.u32(buffer, position + 17))
                if headerLen < fixedHeader || headerLen > maxHeader {
                    throw ProxyError("invalid TGCP header length \(headerLen)")
                }
                let total = headerLen + bodyLen
                if total > maxFrame || total < 0 {
                    throw ProxyError("invalid TGCP frame length \(total)")
                }
                if buffer.count - position < total { break }
                let raw = Array(buffer[position..<(position + total)])
                frames.append(Frame(rawHeader: Array(raw[0..<headerLen]),
                                    body: Array(raw[headerLen..<total]),
                                    offset: streamOffset))
                streamOffset += total
                position += total
            }
            compact()
            return frames
        }

        private func append(_ data: [UInt8]) {
            if data.isEmpty { return }
            let keep = buffer.count - position
            var merged = [UInt8]()
            merged.reserveCapacity(keep + data.count)
            if keep > 0 { merged.append(contentsOf: buffer[position...]) }
            merged.append(contentsOf: data)
            buffer = merged
            position = 0
        }

        /// 把已消费的前缀丢掉，避免长连接上 buffer 无限长。
        private func compact() {
            if position == 0 { return }
            if position >= buffer.count {
                buffer = []
                position = 0
                return
            }
            if position > 8192 {
                buffer = Array(buffer[position...])
                position = 0
            }
        }
    }

    // ── DH 扩展头 ──────────────────────────────────────────────

    public struct DhPublic {
        public let value: BigUInt
        public let begin: Int
        public let end: Int
    }

    /// 解析扩展头里的对端公钥：`type(1)=3 | len(2) | public(len)`。
    public static func parseDhPublic(_ header: [UInt8]) throws -> DhPublic {
        let extLen = header.count - fixedHeader
        if extLen < 3 {
            throw ProxyError("DH header extension is shorter than 3 bytes")
        }
        let kind = Int(header[fixedHeader])
        let publicLen = Bytes.u16(header, fixedHeader + 1)
        if kind != 3 {
            throw ProxyError("unexpected DH type \(kind); expected type 3")
        }
        if publicLen < 1 || publicLen > TgcpConstants.dhPublicBytes {
            throw ProxyError("unexpected DH public length \(publicLen)")
        }
        let begin = fixedHeader + 3
        let end = begin + publicLen
        if end > header.count {
            throw ProxyError("DH public value exceeds header")
        }
        return DhPublic(value: BigUInt(bytes: Array(header[begin..<end])),
                        begin: begin, end: end)
    }

    /// 把扩展头里的公钥换成本端生成的，并回填 header_len。
    public static func replaceDhPublic(_ header: [UInt8],
                                       _ replacement: [UInt8]) throws -> [UInt8] {
        let parsed = try parseDhPublic(header)
        if replacement.isEmpty || replacement.count > TgcpConstants.dhPublicBytes {
            throw ProxyError("replacement DH public length is invalid")
        }
        var out = header
        Bytes.putU16(&out, fixedHeader + 1, replacement.count)
        // 新公钥长度可能与旧的不同：长度字段已改，后面的字节要整体挪。
        let tail = Array(out[parsed.end...])
        var rebuilt = [UInt8]()
        rebuilt.reserveCapacity(parsed.begin + replacement.count + tail.count)
        rebuilt.append(contentsOf: out[0..<parsed.begin])
        rebuilt.append(contentsOf: replacement)
        rebuilt.append(contentsOf: tail)
        Bytes.putU32(&rebuilt, 13, UInt32(rebuilt.count))
        return rebuilt
    }

    // ── native 填充 / AES-CBC 翻译 ─────────────────────────────

    /**
     明文按 16 对齐时补的字节数。

     `rem <= 10` → 补到 16；否则补到 32。因为尾部固定要塞 6 字节
     （`tsf4g` + pad 值），「明文 + 6」还得能装进一个块里。

     推论：`nativePadLen(0) == 16` —— 空 body 也会加密成一个整块。
     */
    public static func nativePadLen(_ size: Int) -> Int {
        let remainder = size & 15
        return remainder <= 10 ? 16 - remainder : 32 - remainder
    }

    /**
     从解密后的填充块里剥出明文。

     ⚠️ `size == 0` 是**合法**的：空 body 加密后是一个 16 字节块，解开是
     `[16 字节填充][tsf4g][pad=16]`，`size = 0`。曾经把 `<= 0` 都当非法，
     结果 server hello 的空加密 body 永远解不开，被当明文透传 —— 手机用
     服务器密钥解不开自己的 hello，2~11 秒后 EOF。
     */
    public static func stripNativeBody(_ plain: [UInt8]) throws -> [UInt8] {
        if plain.count < 16 {
            throw ProxyError("decrypted body is too short")
        }
        let markerAt = plain.count - 6
        for index in 0..<trailerMarker.count {
            if plain[markerAt + index] != trailerMarker[index] {
                throw ProxyError("native trailer marker mismatch")
            }
        }
        let pad = Int(plain[plain.count - 1])
        let size = plain.count - pad
        if size < 0 {
            throw ProxyError("native trailer produced negative body size")
        }
        if nativePadLen(size) != pad {
            throw ProxyError("native trailer pad byte mismatch")
        }
        return Array(plain[0..<size])
    }

    public struct Translated {
        public let cipher: [UInt8]
        public let plain: [UInt8]
    }

    /**
     源腿解开 → 目标腿重新加密。填充原样搬过去（不重新生成），
     这样字节长度和填充位与原始端完全一致。
     */
    public static func translateBody(sourceKey: [UInt8], destKey: [UInt8],
                                     body: [UInt8]) throws -> Translated {
        if body.isEmpty || body.count % 16 != 0 {
            throw ProxyError("encrypted body is not a nonempty multiple of 16 bytes")
        }
        let padded = AES.cbcDecrypt(key: sourceKey, iv: nativeIV, data: body)
        let plain = try stripNativeBody(padded)
        return Translated(cipher: AES.cbcEncrypt(key: destKey, iv: nativeIV,
                                                 data: padded),
                          plain: plain)
    }
}
