import Foundation

/**
 上报通道的双向加密（StarRadarSecureWS v1）—— 与 `core/secure_ws.py`、
 `SecureWs.kt` 逐字节一致。

 ## 握手三条消息

 ```
  C → S  {"type":"secure_hello","v":1,"api_key":"<32hex>","nonce":"<64hex>"}
  S → C  {"type":"secure_challenge","v":1,"nonce":"<64hex>","proof":"<64hex>"}
  C → S  {"type":"secure_finish","v":1,"proof":"<64hex>"}   ← 这条已加密
 ```

 之后所有消息都是 `{"type":"enc","v":1,"seq":N,"d":"base64(密文)"}`。

 ## 密钥派生

 ```
  keys = HKDF-SHA256(ikm = api_key 的 ASCII 字节, salt = clientNonce‖serverNonce,
                     info = "StarRadarSecureWS/v1", len = 104)
  → c2sKey(32) ‖ s2cKey(32) ‖ c2sIv(4) ‖ s2cIv(4) ‖ proofKey(32)
 ```

 ## 容易写错的三处

 1. `ikm` 是 **api_key 的 ASCII 字节**（32 个字符），不是 hex 解码值。
 2. GCM 的 iv = 4 字节固定前缀 ‖ 8 字节大端 seq —— 不是随机 iv。
 3. AAD 是 `"SRW1" ‖ version ‖ direction ‖ seq(>Q)`，direction 与 seq 都必须
    用**本条消息自己的**，写错方向会得到「帧认证失败」。
 */
public enum SecureWs {

    public static let version = 1

    public static let dirC2S = 1
    public static let dirS2C = 2

    public static let helloType = "secure_hello"
    public static let challengeType = "secure_challenge"
    public static let finishType = "secure_finish"
    public static let okType = "secure_ok"
    public static let errorType = "error"
    public static let envelopeType = "enc"

    static let hkdfInfo: [UInt8] = Array("StarRadarSecureWS/v1".utf8)
    static let roomIdPrefix: [UInt8] = Array("StarRadarRoomKeyV1\u{0}".utf8)
    static let transcriptPrefix = "StarRadarSecureWS1"
    static let frameMagic: [UInt8] = Array("SRW1".utf8)

    public static let nonceBytes = 32
    public static let tagSize = 16
    public static let apiKeyChars = 32
    public static let maxPlaintext = 4 * 1024 * 1024

    public struct SessionKeys {
        public let c2sKey: [UInt8]
        public let s2cKey: [UInt8]
        public let c2sIv: [UInt8]
        public let s2cIv: [UInt8]
        public let proofKey: [UInt8]
    }

    /// 房间 Key 必须是 32 位十六进制。统一转小写，避免大小写派生出不同密钥。
    public static func normalizeApiKey(_ apiKey: String?) throws -> String {
        let key = (apiKey ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard key.count == apiKeyChars,
              key.allSatisfy({ $0.hexDigitValue != nil }) else {
            throw SecureError("房间 Key 需为 32 位十六进制")
        }
        return key
    }

    public static func roomId(_ apiKey: String?) -> String {
        let key = (apiKey ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        var data = roomIdPrefix
        data.append(contentsOf: Array(key.utf8))
        return Hex.encode(Crypto.sha256(data))
    }

    public static func deriveKeys(_ apiKey: String?, clientNonce: [UInt8],
                                  serverNonce: [UInt8]) throws -> SessionKeys {
        let key = try normalizeApiKey(apiKey)
        guard clientNonce.count == nonceBytes,
              serverNonce.count == nonceBytes else {
            throw SecureError("握手 nonce 必须各 32 字节")
        }
        let salt = clientNonce + serverNonce
        let material = Crypto.hkdfSha256(ikm: Array(key.utf8), salt: salt,
                                         info: hkdfInfo, length: 104)
        return SessionKeys(
            c2sKey: Array(material[0..<32]),
            s2cKey: Array(material[32..<64]),
            c2sIv: Array(material[64..<68]),
            s2cIv: Array(material[68..<72]),
            proofKey: Array(material[72..<104])
        )
    }

    public static func buildTranscript(room: String, clientNonce: [UInt8],
                                       serverNonce: [UInt8]) -> String {
        "\(transcriptPrefix)|\(room)|\(Hex.encode(clientNonce))|\(Hex.encode(serverNonce))"
    }

    public static func buildProof(keys: SessionKeys, transcript: String,
                                  side: String) -> String {
        precondition(side == "client" || side == "server", "proof 侧别非法")
        var message = Array(side.utf8)
        message.append(UInt8(ascii: "|"))
        message.append(contentsOf: Array(transcript.utf8))
        return Hex.encode(Crypto.hmacSha256(key: keys.proofKey, data: message))
    }

    public static func decodeNonce(_ value: String?,
                                   _ name: String = "nonce") throws -> [UInt8] {
        guard let value, value.count == nonceBytes * 2,
              let bytes = Hex.decode(value) else {
            throw SecureError("\(name) 需为 64 位 hex")
        }
        return bytes
    }

    // ── 信封 ───────────────────────────────────────────────────

    /**
     一个方向的加密通道。收方向的 seq 与发方向各自独立计数。

     seq 严格连续：收到不连续的直接拒。跳号意味着有帧丢了或被重放了，
     继续用同一把 iv 加密反而危险。
     */
    public final class Channel {
        private let keys: SessionKeys
        private let outboundDir: Int
        private let inboundDir: Int
        private var sendSeq: Int64 = 0
        private var recvSeq: Int64 = 0

        public init(keys: SessionKeys, outboundDir: Int) {
            self.keys = keys
            self.outboundDir = outboundDir
            self.inboundDir = outboundDir == SecureWs.dirC2S
                ? SecureWs.dirS2C : SecureWs.dirC2S
        }

        private func material(_ direction: Int) -> ([UInt8], [UInt8]) {
            direction == SecureWs.dirC2S
                ? (keys.c2sKey, keys.c2sIv) : (keys.s2cKey, keys.s2cIv)
        }

        private func aad(_ direction: Int, _ seq: Int64) -> [UInt8] {
            var out = SecureWs.frameMagic
            out.append(UInt8(SecureWs.version))
            out.append(UInt8(direction))
            // 先把 seq 的 8 个字节位置占出来，否则 putU64 会写越界
            out.append(contentsOf: [UInt8](repeating: 0, count: 8))
            Bytes.putU64(&out, 6, UInt64(seq))
            return out
        }

        private func buildIv(_ base: [UInt8], _ seq: Int64) -> [UInt8] {
            var iv = base
            iv.append(contentsOf: [UInt8](repeating: 0, count: 8))
            Bytes.putU64(&iv, base.count, UInt64(seq))
            return iv
        }

        public func encrypt(_ plaintext: [UInt8]) throws -> String {
            if plaintext.count > SecureWs.maxPlaintext {
                throw SecureError("单帧明文过大")
            }
            let seq = sendSeq + 1
            let (key, base) = material(outboundDir)
            let sealed = try Crypto.gcmSeal(key: key, iv: buildIv(base, seq),
                                            plaintext: plaintext,
                                            aad: aad(outboundDir, seq))
            sendSeq = seq
            return Json.build(
                ("type", .string(SecureWs.envelopeType)),
                ("v", .number(Double(SecureWs.version))),
                ("seq", .number(Double(seq))),
                ("d", .string(Data(sealed).base64EncodedString()))
            )
        }

        public func encryptJson(_ json: String) throws -> String {
            try encrypt(Array(json.utf8))
        }

        public func decrypt(_ envelope: String) throws -> [UInt8] {
            guard let doc = Json.parse(envelope) else {
                throw SecureError("信封不是 JSON 对象")
            }
            if doc["type"]?.stringValue != SecureWs.envelopeType {
                throw SecureError("不是加密信封（type=\(doc["type"]?.stringValue ?? "?")）")
            }
            if doc["v"]?.intValue != SecureWs.version {
                throw SecureError("协议版本不一致")
            }
            guard let seq = doc["seq"]?.int64Value else {
                throw SecureError("seq 非法")
            }
            if seq <= 0 {
                throw SecureError("seq 非法")
            }
            if seq != recvSeq + 1 {
                throw SecureError("seq 不连续（期望 \(recvSeq + 1)，收到 \(seq)）")
            }
            guard let encoded = doc["d"]?.stringValue,
                  let sealed = Data(base64Encoded: encoded) else {
                throw SecureError("密文 base64 非法")
            }
            if sealed.count < SecureWs.tagSize {
                throw SecureError("密文过短")
            }
            let (key, base) = material(inboundDir)
            let data: [UInt8]
            do {
                data = try Crypto.gcmOpen(key: key, iv: buildIv(base, seq),
                                          sealed: [UInt8](sealed),
                                          aad: aad(inboundDir, seq))
            } catch {
                throw SecureError("帧认证失败")
            }
            recvSeq = seq
            return data
        }

        public var sentSeq: Int64 { sendSeq }
        public var receivedSeq: Int64 { recvSeq }
    }

    // ── 客户端握手 ─────────────────────────────────────────────

    public final class ClientHandshake {
        private let key: String
        private let nonce: [UInt8]
        private var done = false

        public init(apiKey: String?, clientNonce: [UInt8]? = nil) throws {
            key = try SecureWs.normalizeApiKey(apiKey)
            nonce = clientNonce ?? Crypto.randomBytes(SecureWs.nonceBytes)
            if nonce.count != SecureWs.nonceBytes {
                throw SecureError("客户端 nonce 必须 32 字节")
            }
        }

        public var clientNonce: [UInt8] { nonce }

        public func hello() -> String {
            Json.build(
                ("type", .string(SecureWs.helloType)),
                ("v", .number(Double(SecureWs.version))),
                ("api_key", .string(key)),
                ("nonce", .string(Hex.encode(nonce)))
            )
        }

        public struct Accepted {
            public let channel: Channel
            public let finish: String
        }

        public func acceptChallenge(_ text: String) throws -> Accepted {
            if done { throw SecureError("握手已完成") }
            guard let doc = Json.parse(text) else {
                throw SecureError("secure_challenge 不是合法 JSON")
            }
            if doc["type"]?.stringValue != SecureWs.challengeType {
                throw SecureError("不是 secure_challenge")
            }
            if doc["v"]?.intValue != SecureWs.version {
                throw SecureError("协议版本不一致")
            }
            let serverNonce = try SecureWs.decodeNonce(
                doc["nonce"]?.stringValue, "server nonce")

            let keys = try SecureWs.deriveKeys(key, clientNonce: nonce,
                                              serverNonce: serverNonce)
            let transcript = SecureWs.buildTranscript(
                room: SecureWs.roomId(key), clientNonce: nonce,
                serverNonce: serverNonce)
            let supplied = doc["proof"]?.stringValue?.lowercased()
            let expected = SecureWs.buildProof(keys: keys, transcript: transcript,
                                               side: "server")
            guard let supplied,
                  Crypto.secureEquals(Array(supplied.utf8),
                                      Array(expected.utf8)) else {
                throw SecureError("服务端握手证明不通过")
            }

            done = true
            let finish = Json.build(
                ("type", .string(SecureWs.finishType)),
                ("v", .number(Double(SecureWs.version))),
                ("proof", .string(SecureWs.buildProof(
                    keys: keys, transcript: transcript, side: "client")))
            )
            return Accepted(channel: Channel(keys: keys, outboundDir: SecureWs.dirC2S),
                            finish: finish)
        }
    }
}
