import XCTest
@testable import StarRadarCore

/**
 LZ4 解压的逐字节交叉验证。

 ## 为什么这个测试必须存在（而不是「跑一次看看能不能解」）

 LZ4 的错误不会明显崩：它安静地解出一段**错位的字节**。而母料扫描拿不到
 东西时的现象，和「这一帧本来就没母料」完全一样 —— 界面上都是「参数没更新」，
 用户看到的都是「第二盘不上报」。所以只靠真机试是分不出对错的。

 向量由 `tools/gen_lz4_vectors.py` 用 PC 参考实现（`starradar-pc/core/lz4.py`）
 生成，覆盖 LZ4 block 格式的每一处分支：空输入、长短 literal（含 0xFF 连续
 扩展）、普通回溯、offset=1 的 RLE、offset < matchLen 的重叠、长 match 扩展、
 以及真实形状（172 字符 base64 母料 + 前后控制字节）。三条非法输入要求抛错。
 */
final class Lz4Tests: XCTestCase {

    private let doc = Vectors.load("lz4_vectors")

    private var cases: [JSON] {
        doc["cases"]?.arrayValue ?? []
    }

    func testVectorFileHasEveryBranch() {
        // 向量文件被误删/漏生成时，下面的循环会零次执行、测试假通过 ——
        // 这是「测试全绿但其实什么也没测」最典型的形态，所以先钉条数。
        XCTAssertGreaterThanOrEqual(cases.count, 12, "向量条数不对，check gen_lz4_vectors.py")
        let names = cases.compactMap { $0["name"]?.stringValue }
        for required in ["empty", "literal_short", "literal_long",
                         "literal_escape_chain", "literal_plus_match",
                         "rle_offset_one", "overlap_partial",
                         "long_match_escape", "material_base64_literal",
                         "material_then_match"] {
            XCTAssertTrue(names.contains(required), "缺少用例：\(required)")
        }
    }

    func testMatchesReferenceImplementation() throws {
        for item in cases {
            let name = item["name"]?.stringValue ?? "?"
            let block = Vectors.bytes(item["block_hex"]?.stringValue)
            let expectError = item["expectError"]?.boolValue ?? false

            if expectError {
                XCTAssertThrowsError(try Lz4.decompress(block),
                                     "用例 \(name) 应当报错") { error in
                    XCTAssertTrue(error is Lz4.Lz4Error,
                                  "用例 \(name) 抛了非 Lz4Error：\(error)")
                }
                continue
            }

            let plain = try Lz4.decompress(block)
            let expectLen = item["plainLen"]?.intValue ?? -1
            XCTAssertEqual(plain.count, expectLen, "用例 \(name) 长度不符")

            if let hex = item["plain_hex"]?.stringValue {
                XCTAssertEqual(Hex.encode(plain), hex, "用例 \(name) 内容不符")
            } else if let sha = item["plainSha256"]?.stringValue {
                XCTAssertEqual(Hex.encode(Crypto.sha256(plain)), sha,
                               "用例 \(name) 摘要不符")
            }
        }
    }

    func testTryDecompressReturnsNilOnBadInput() {
        // 调用方（母料扫描）依赖「失败返回 nil 而不是抛异常」：
        // 大部分帧本来就没压缩，抛出去会把整条连接判成故障。
        XCTAssertNil(Lz4.tryDecompress([0x14, 0x61, 0x62, 0x63, 0x64, 0x00, 0x00]))
        XCTAssertNotNil(Lz4.tryDecompress([0x40, 0x61, 0x62, 0x63, 0x64]))
    }

    func testOutputLimitIsEnforced() {
        // 压缩炸弹：几字节输入解出几百 MB。手机上不拦就是被系统直接杀掉
        // （jetsam 不看是谁的错），所以上限必须真的生效。
        //
        // 构造：1 字节 literal + offset=1 的 RLE（matchLen = 1040，总输出 1041）。
        //   token 0x1F = literal 1 / match nibble 15
        //   matchLen = 15 + 4 + (255*4 + 1) = 1040
        let bomb: [UInt8] = [0x1F, 0x41, 0x01, 0x00,
                             0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        XCTAssertThrowsError(try Lz4.decompress(bomb, maxOutput: 1024)) { error in
            XCTAssertTrue(error is Lz4.Lz4Error)
        }
        XCTAssertNil(Lz4.tryDecompress(bomb, maxOutput: 1024))
        // 上限足够时同一段数据要能正常解出来（否则上面的断言可能只是
        // 因为「本来就解不开」而假通过）
        let expanded = try? Lz4.decompress(bomb, maxOutput: 4096)
        XCTAssertEqual(expanded?.count, 1041)
        XCTAssertEqual(expanded, [UInt8](repeating: 0x41, count: 1041))
    }

    /// 空输入必须是「空输出」而不是错误 —— 空 body 的帧很常见。
    func testEmptyInput() throws {
        XCTAssertEqual(try Lz4.decompress([]), [])
    }
}
