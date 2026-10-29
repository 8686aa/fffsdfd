import XCTest
@testable import StarRadarCore

/**
 入局帧判定与压缩位识别的回归测试。

 ## 为什么这两件事要单独钉

 它们都**只影响「能不能采到母料」**，不影响连接是否正常 ——
 错了不会崩、不会报错，只是那一局不上报。这种 bug 最贵：用户只看到
 「第二盘没数据」，而日志里一切正常。

 - `joinMessages` 里的两个消息名必须与 PC 的 `core/tgcp.py` 逐字节一致。
   改一个字（比如把 Ntf 写成 NTF）就等于再也没有无条件扫描。
 - 压缩位读错位置，就会拿一段压缩字节当明文扫，母料永远采不到。
 */
final class TgcpJoinTests: XCTestCase {

    func testJoinMessageNamesAreExact() {
        // 这不是「随便挑两个字符串」：它们是服务端真实下发过的消息名，
        // PC 版靠这两个名字把「第二盘不上报」修好了。改动等于回退。
        let names = Tgcp.joinMessages.map { String(decoding: $0, as: UTF8.self) }
        XCTAssertEqual(names, ["CSPlayerJoinMatchNtf", "CSMatchRoomReconnectRes"])
    }

    func testMentionsJoinFindsSubstring() {
        let payload = Array("\u{0}\u{1}\u{10}CSPlayerJoinMatchNtf\u{0}".utf8)
        XCTAssertTrue(Tgcp.mentionsJoin(payload))
        // 重连帧也算入局
        XCTAssertTrue(Tgcp.mentionsJoin(Array("xxCSMatchRoomReconnectRes".utf8)))
        // 不相干的帧不能被误判（否则每帧都全扫，进游戏会卡）
        XCTAssertFalse(Tgcp.mentionsJoin(Array("CSPlayerLeaveMatchNtf".utf8)))
        XCTAssertFalse(Tgcp.mentionsJoin([]))
        XCTAssertFalse(Tgcp.mentionsJoin(Array("CSPlayer".utf8)))
    }

    func testMentionsJoinHandlesNameAtBothEnds() {
        let name = Array("CSPlayerJoinMatchNtf".utf8)
        XCTAssertTrue(Tgcp.mentionsJoin(name), "整段就是消息名")
        XCTAssertTrue(Tgcp.mentionsJoin([0x00] + name), "消息名在末尾")
        XCTAssertTrue(Tgcp.mentionsJoin(name + [0x00]), "消息名在开头")
    }

    func testCompressionMethodReadsFirstExtByte() {
        // 没有扩展头 → 0（不能默认「没压缩」再去试一次 LZ4，那要扫一遍字节）
        XCTAssertEqual(Tgcp.compressionMethod([UInt8](repeating: 0, count: 21)), 0)
        // 有扩展头，第一个字节 = 压缩方法
        var header = [UInt8](repeating: 0, count: 21)
        header.append(1)
        XCTAssertEqual(Tgcp.compressionMethod(header), 1)
        header[21] = 2
        XCTAssertEqual(Tgcp.compressionMethod(header), 2)
        // 太短的 header 不能崩
        XCTAssertEqual(Tgcp.compressionMethod([]), 0)
        XCTAssertEqual(Tgcp.compressionMethod([1, 2, 3]), 0)
    }

    func testMaybeDecompressLz4RejectsNonLz4() {
        // 普通明文（没压缩）解压失败必须返回 nil，而不是抛错 ——
        // 母料扫描把「这一帧没压缩」当成最常见的正常情况。
        XCTAssertNil(Tgcp.maybeDecompressLz4(Array("hello world".utf8)))
        XCTAssertNil(Tgcp.maybeDecompressLz4([]))
        // 合法的「纯 literal」块要能解出来
        XCTAssertEqual(Tgcp.maybeDecompressLz4([0x40, 0x61, 0x62, 0x63, 0x64]),
                       Array("abcd".utf8))
        // 解出来和输入完全一样 → 视为「没有新增信息」，返回 nil
        // （调用方据此避免把同一帧扫两遍）
        let selfIdentity: [UInt8] = [0x10, 0x31]
        XCTAssertEqual(Tgcp.maybeDecompressLz4(selfIdentity), Array("1".utf8))
    }
}
