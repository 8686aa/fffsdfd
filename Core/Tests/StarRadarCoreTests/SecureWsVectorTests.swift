import XCTest
@testable import StarRadarCore

/// 上报通道加密层与 PC/Android 的逐字节对照。
final class SecureWsVectorTests: XCTestCase {

    private let vectors = Vectors.load("vectors")

    private func session() -> (SecureWs.SessionKeys, JSON) {
        let vector = vectors["secure_ws"]!
        let apiKey = vector["apiKey"]!.stringValue!
        let clientNonce = Vectors.bytes(vector["clientNonce_hex"]?.stringValue)
        let serverNonce = Vectors.bytes(vector["serverNonce_hex"]?.stringValue)
        let keys = try! SecureWs.deriveKeys(apiKey, clientNonce: clientNonce,
                                           serverNonce: serverNonce)
        return (keys, vector)
    }

    func testHkdfDerivesIdenticalSessionKeys() {
        let (keys, vector) = session()
        XCTAssertEqual(Hex.encode(keys.c2sKey), vector["c2sKey_hex"]?.stringValue)
        XCTAssertEqual(Hex.encode(keys.s2cKey), vector["s2cKey_hex"]?.stringValue)
        XCTAssertEqual(Hex.encode(keys.c2sIv), vector["c2sIv_hex"]?.stringValue)
        XCTAssertEqual(Hex.encode(keys.s2cIv), vector["s2cIv_hex"]?.stringValue)
        XCTAssertEqual(Hex.encode(keys.proofKey), vector["proofKey_hex"]?.stringValue)
    }

    func testRoomIdAndTranscriptMatchPython() {
        let (_, vector) = session()
        let apiKey = vector["apiKey"]!.stringValue!
        let clientNonce = Vectors.bytes(vector["clientNonce_hex"]?.stringValue)
        let serverNonce = Vectors.bytes(vector["serverNonce_hex"]?.stringValue)

        let room = SecureWs.roomId(apiKey)
        XCTAssertEqual(room, vector["roomId"]?.stringValue)

        let transcript = SecureWs.buildTranscript(room: room,
                                                  clientNonce: clientNonce,
                                                  serverNonce: serverNonce)
        XCTAssertEqual(transcript, vector["transcript"]?.stringValue)
    }

    func testProofsMatchPython() {
        let (keys, vector) = session()
        let transcript = vector["transcript"]!.stringValue!
        XCTAssertEqual(SecureWs.buildProof(keys: keys, transcript: transcript,
                                           side: "client"),
                       vector["proofClient"]?.stringValue)
        XCTAssertEqual(SecureWs.buildProof(keys: keys, transcript: transcript,
                                           side: "server"),
                       vector["proofServer"]?.stringValue)
    }

    func testHelloJsonMatchesPython() throws {
        let vector = vectors["secure_ws"]!
        let apiKey = vector["apiKey"]!.stringValue!
        let nonce = Vectors.bytes(vector["clientNonce_hex"]?.stringValue)
        let expected = vector["helloJson"]!
        let handshake = try SecureWs.ClientHandshake(apiKey: apiKey,
                                                     clientNonce: nonce)
        let text = handshake.hello()
        let doc = Json.parse(text)!

        XCTAssertEqual(doc["type"]?.stringValue, expected["type"]?.stringValue)
        XCTAssertEqual(doc["v"]?.intValue, expected["v"]?.intValue)
        XCTAssertEqual(doc["api_key"]?.stringValue, expected["api_key"]?.stringValue)
        XCTAssertEqual(doc["nonce"]?.stringValue, expected["nonce"]?.stringValue)

        // 键顺序也要对：节点侧对 hello 是按字符串比对的
        let order = ["\"type\"", "\"v\"", "\"api_key\"", "\"nonce\""]
        var cursor = text.startIndex
        for key in order {
            guard let range = text.range(of: key, range: cursor..<text.endIndex) else {
                return XCTFail("hello 报文缺少字段或顺序不对：\(text)")
            }
            cursor = range.upperBound
        }
    }

    func testEnvelopeCiphertextIsByteIdentical() throws {
        let (keys, _) = session()
        let envelope = vectors["envelope"]!

        // ⚠️ `firstPlaintext_utf8` 是与 `first` **同级**的字段，不是 first 的子字段。
        // 之前写成 `first["firstPlaintext_utf8"]` 于是在 CI 上强制解包 nil 崩掉
        // （编译期看不出来，只有跑测试才炸）。
        let first = envelope["first"]!
        guard let plaintext = envelope["firstPlaintext_utf8"]?.stringValue else {
            return XCTFail("向量缺 firstPlaintext_utf8")
        }

        let channel = SecureWs.Channel(keys: keys, outboundDir: SecureWs.dirC2S)
        let text = try channel.encrypt(Array(plaintext.utf8))
        let doc = Json.parse(text)!
        XCTAssertEqual(doc["seq"]?.intValue, first["seq"]?.intValue)
        XCTAssertEqual(doc["d"]?.stringValue, first["d"]?.stringValue,
                       "同一 key/iv/seq 下 GCM 密文应当逐字节相同")

        // 第二条只断言 seq 自增。
        //
        // 不能拿 first 的明文再加密一次去比 `second.d`：向量里 second 的
        // 明文只有 6 字节（密文 22 字节 − 16 字节 tag），与 first 的 31 字节
        // 不同 —— 那是生成向量时用的一段独立测试串，内容没写进 JSON。
        let second = envelope["second"]!
        let secondText = try channel.encrypt(Array(plaintext.utf8))
        let secondDoc = Json.parse(secondText)!
        XCTAssertEqual(secondDoc["seq"]?.intValue, second["seq"]?.intValue,
                       "seq 必须自增到 2")
        XCTAssertFalse(second["d"]?.stringValue.isEmpty ?? true,
                       "向量里的 second.d 不该为空")
    }

    func testDecryptsServerFrameFromPython() throws {
        let (keys, _) = session()
        let frame = vectors["envelope"]!["serverFrame"]!
        let envelopeText = Json.build(
            ("type", .string(frame["type"]!.stringValue!)),
            ("v", .number(Double(frame["v"]!.intValue!))),
            ("seq", .number(Double(frame["seq"]!.intValue!))),
            ("d", .string(frame["d"]!.stringValue!))
        )
        let channel = SecureWs.Channel(keys: keys, outboundDir: SecureWs.dirC2S)
        let plain = try channel.decrypt(envelopeText)
        XCTAssertFalse(plain.isEmpty, "解出来的明文不该是空")
        // 再解一次同样的 seq 必须被拒（严格连续）
        XCTAssertThrowsError(try channel.decrypt(envelopeText))
    }

    func testRejectsTamperedEnvelope() throws {
        let (keys, _) = session()
        let first = vectors["envelope"]!["first"]!
        var data = first["d"]!.stringValue!
        // 改动 base64 的最后一个字符（落在 tag 上）
        let last = data.removeLast()
        data.append(last == "A" ? "B" : "A")
        let envelopeText = Json.build(
            ("type", .string("enc")),
            ("v", .number(1)),
            ("seq", .number(1)),
            ("d", .string(data))
        )
        let channel = SecureWs.Channel(keys: keys, outboundDir: SecureWs.dirC2S)
        XCTAssertThrowsError(try channel.decrypt(envelopeText))
    }

    func testBatchPayloadMatchesPythonByteForByte() {
        let batch = vectors["batch"]!
        let items = batch["items"]!.arrayValue!
        let pending = items.enumerated().map { index, item in
            Uploader.Pending(data: item["data"]!.stringValue!,
                             keyId: item["key_id"]?.stringValue ?? "",
                             seq: Int64(index + 1))
        }
        let built = Uploader(node: "", apiKey: "").buildBatchPayload(pending)
        XCTAssertEqual(built, batch["payload"]?.stringValue,
                       "批量报文必须逐字节一致（字段顺序与转义）")
    }

    func testNormalizeApiKeyRejectsBadInput() {
        XCTAssertThrowsError(try SecureWs.normalizeApiKey("短"))
        XCTAssertThrowsError(try SecureWs.normalizeApiKey(
            String(repeating: "z", count: 32)))
        // 大小写不影响派生
        let upper = try? SecureWs.normalizeApiKey(
            String(repeating: "AB", count: 16))
        XCTAssertEqual(upper, String(repeating: "ab", count: 16))
    }

    func testShareSiteEndpointUrlIsNodeBased() {
        // 最终跳转地址固定是 节点IP:666/share/<code>
        XCTAssertEqual(
            ShareSite.normalizeUrl("http://127.0.0.1:1666/share/FSF3-9K9A",
                                   nodeHost: "106.52.86.244", code: "FSF3-9K9A"),
            "http://106.52.86.244:666/share/FSF3-9K9A")
        XCTAssertEqual(
            ShareSite.normalizeUrl("http://localhost:1666/share/A?t=1",
                                   nodeHost: "106.52.86.244", code: "A"),
            "http://106.52.86.244:666/share/A?t=1")
        XCTAssertEqual(
            ShareSite.normalizeUrl("", nodeHost: "106.52.86.244", code: "A"),
            "http://106.52.86.244:666/share/A")
        XCTAssertEqual(
            ShareSite.normalizeUrl("file:///etc/passwd",
                                   nodeHost: "106.52.86.244", code: ""),
            "")
    }
}
