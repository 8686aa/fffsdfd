import XCTest
@testable import StarRadarCore

/// TGCP 协议层与 PC/Android 的逐字节对照。
final class TgcpVectorTests: XCTestCase {

    private let vectors = Vectors.load("vectors")

    // ── 数值编码 ──────────────────────────────────────────────

    func testMinimalBigEndianMatchesPython() {
        guard let items = vectors["minimal_be"]?.arrayValue else {
            return XCTFail("缺 minimal_be")
        }
        for item in items {
            let hex = item["hex"]!.stringValue!
            let value = BigUInt(hex: hex) ?? BigUInt(0)
            XCTAssertEqual(Hex.encode(Tgcp.minimalBe(value)), hex,
                           "最小大端表示不一致（输入 \(hex)）")
        }
    }

    // ── DH（同时验证自写的大数与 Montgomery 模幂）────────────

    func testDhPublicAndSharedKeyMatchPython() {
        guard let dh = vectors["dh"] else { return XCTFail("缺 dh") }
        guard let privateA = BigUInt(decimal: dh["privateA"]!.stringValue!),
              let privateB = BigUInt(decimal: dh["privateB"]!.stringValue!),
              let publicA = dh["publicA_hex"]?.stringValue,
              let publicB = dh["publicB_hex"]?.stringValue,
              let keyA = dh["keyA_hex"]?.stringValue,
              let keyB = dh["keyB_hex"]?.stringValue else {
            return XCTFail("dh 向量字段不全")
        }

        let sideA = Tgcp.DhSide.of(privateKey: privateA)
        let sideB = Tgcp.DhSide.of(privateKey: privateB)

        XCTAssertEqual(Hex.encode(sideA.publicBytes), publicA, "A 的公钥不一致")
        XCTAssertEqual(Hex.encode(sideB.publicBytes), publicB, "B 的公钥不一致")

        let sharedA = try! sideA.deriveKey(peerPublic: BigUInt(hex: publicB)!)
        let sharedB = try! sideB.deriveKey(peerPublic: BigUInt(hex: publicA)!)
        XCTAssertEqual(Hex.encode(sharedA), keyA, "A 派生的会话密钥不一致")
        XCTAssertEqual(Hex.encode(sharedB), keyB, "B 派生的会话密钥不一致")
        XCTAssertEqual(keyA, keyB, "两端的密钥应当相同")
    }

    func testDhRejectsOutOfRangePublic() {
        XCTAssertThrowsError(try Tgcp.DhSide.create()
            .deriveKey(peerPublic: BigUInt(1)))
        XCTAssertThrowsError(try Tgcp.DhSide.create()
            .deriveKey(peerPublic: TgcpConstants.p))
    }

    // ── native 填充 ──────────────────────────────────────────

    func testNativePadLengthMatchesPython() {
        guard let table = vectors["pad_len"] else { return XCTFail("缺 pad_len") }
        for index in 0..<65 {
            guard let expected = table["\(index)"]?.intValue else { continue }
            XCTAssertEqual(Tgcp.nativePadLen(index), expected,
                           "nativePadLen(\(index)) 不一致")
        }
        // 空 body 也会加密成一个整块
        XCTAssertEqual(Tgcp.nativePadLen(0), 16)
    }

    func testStripNativeBodyMatchesPython() {
        guard let items = vectors["strip"]?.arrayValue else {
            return XCTFail("缺 strip")
        }
        for item in items {
            let block = Vectors.bytes(item["block_hex"]?.stringValue)
            let expected = Vectors.bytes(item["decoded_hex"]?.stringValue)
            do {
                let plain = try Tgcp.stripNativeBody(block)
                XCTAssertEqual(Hex.encode(plain), Hex.encode(expected),
                               "剥离填充结果不一致")
            } catch {
                XCTFail("strip 失败：\(error)")
            }
        }
    }

    // ── body 翻译（AES-CBC + 填充搬运）───────────────────────

    func testTranslateBodyMatchesPython() {
        guard let items = vectors["translate"]?.arrayValue else {
            return XCTFail("缺 translate")
        }
        for item in items {
            let keySrc = Vectors.bytes(item["keySrc_hex"]?.stringValue)
            let keyDst = Vectors.bytes(item["keyDst_hex"]?.stringValue)
            let cipher = Vectors.bytes(item["inCipher_hex"]?.stringValue)
            let expectedCipher = item["outCipher_hex"]?.stringValue
            let expectedPlain = item["decodedPlain_hex"]?.stringValue
            do {
                let result = try Tgcp.translateBody(sourceKey: keySrc,
                                                    destKey: keyDst,
                                                    body: cipher)
                XCTAssertEqual(Hex.encode(result.cipher), expectedCipher,
                               "目标腿密文不一致")
                XCTAssertEqual(Hex.encode(result.plain), expectedPlain,
                               "解出的明文不一致")
            } catch {
                XCTFail("translateBody 失败：\(error)")
            }
        }
    }

    // ── 帧打包 / 分帧 ────────────────────────────────────────

    func testPackMatchesPython() {
        guard let items = vectors["pack"]?.arrayValue else { return XCTFail("缺 pack") }
        for item in items {
            let header = Vectors.bytes(item["header_hex"]?.stringValue)
            let body = Vectors.bytes(item["body_hex"]?.stringValue)
            let packed = Tgcp.Frame(rawHeader: header, body: body).pack()
            XCTAssertEqual(Hex.encode(packed), item["packed_hex"]?.stringValue,
                           "帧打包不一致（header_len/body_len 回填）")
        }
    }

    func testFramerMatchesPython() throws {
        guard let framer = vectors["framer"] else { return XCTFail("缺 framer") }
        let stream = Vectors.bytes(framer["stream_hex"]?.stringValue)
        let expected = framer["frames"]?.arrayValue?.count ?? 0
        let frames = try Tgcp.Framer().feed(stream)
        XCTAssertEqual(frames.count, expected, "切出的帧数不一致")
    }

    func testFramerHandlesPartialThenComplete() throws {
        guard let partial = vectors["framer_partial"] else {
            return XCTFail("缺 framer_partial")
        }
        let packed = Vectors.bytes(partial["packed_hex"]?.stringValue)
        let bounds = partial["bounds"]?.arrayValue?.compactMap { $0.intValue } ?? []
        let expected = partial["counts"]?.arrayValue?.compactMap { $0.intValue } ?? []

        // ⚠️ bounds 是「分段点」，第一个元素是起点（0），**没有**对应的计数；
        // counts[i] 对应的是喂到 bounds[i+1] 之后的累计帧数。
        // 之前直接用 enumerated() 的 index 去查 counts，整体错位一位 ——
        // 结果在最后一段上断言 total==1 却拿到 counts[4] 的语义，稳定失败。
        XCTAssertEqual(bounds.first ?? 0, 0, "bounds 应以 0 起始")
        let framer = Tgcp.Framer()
        var total = 0
        var previous = 0
        for (index, bound) in bounds.dropFirst().enumerated() {
            let upper = min(bound, packed.count)
            if upper <= previous { continue }
            total += try framer.feed(Array(packed[previous..<upper])).count
            previous = upper
            if index < expected.count {
                XCTAssertEqual(total, expected[index],
                               "喂到第 \(index + 1) 段（累计 \(upper) 字节）后帧数不一致")
            }
        }
        // 整段喂完必须切出 1 帧（53 字节 = 21 字节头 + 32 字节 body）
        XCTAssertEqual(total, 1, "完整喂完后应切出 1 帧")
        XCTAssertEqual(previous, packed.count, "应把全部字节都喂进去")
    }

    // ── DH 扩展头替换 ────────────────────────────────────────

    func testReplaceDhPublicMatchesPython() throws {
        guard let item = vectors["replace_dh"] else { return XCTFail("缺 replace_dh") }
        let header = Vectors.bytes(item["header_hex"]?.stringValue)
        let newPublic = Vectors.bytes(item["new_pub_hex"]?.stringValue)
        let parsed = try Tgcp.parseDhPublic(header)
        XCTAssertEqual(parsed.begin, item["parsed_begin"]?.intValue)
        XCTAssertEqual(parsed.end, item["parsed_end"]?.intValue)

        let replaced = try Tgcp.replaceDhPublic(header, newPublic)
        XCTAssertEqual(Hex.encode(replaced), item["result_hex"]?.stringValue,
                       "替换公钥后的头不一致（长度字段要同步改）")
    }

    // ── AES 已知答案（FIPS-197）─────────────────────────────

    func testAesKnownAnswer() {
        // FIPS-197 附录 C.1：AES-128
        let key = Hex.decode("000102030405060708090a0b0c0d0e0f")!
        let plain = Hex.decode("00112233445566778899aabbccddeeff")!
        let expected = "69c4e0d86a7b0430d8cdb78070b4c55a"
        let cipher = AES.cbcEncrypt(key: key, iv: [UInt8](repeating: 0, count: 16),
                                   data: plain)
        XCTAssertEqual(Hex.encode(cipher), expected, "AES-128 单块结果不符合 FIPS-197")

        let back = AES.cbcDecrypt(key: key, iv: [UInt8](repeating: 0, count: 16),
                                  data: cipher)
        XCTAssertEqual(Hex.encode(back), Hex.encode(plain), "AES 解密不可逆")
    }

    func testAesSboxSanity() {
        // 手写 S-box 容易错一个字节，这里钉两个公开的已知值
        XCTAssertEqual(AES.sbox[0x00], 0x63)
        XCTAssertEqual(AES.sbox[0x53], 0xED)
        XCTAssertEqual(AES.invSbox[0x63], 0x00)
        XCTAssertEqual(AES.invSbox[0xED], 0x53)
    }
}
