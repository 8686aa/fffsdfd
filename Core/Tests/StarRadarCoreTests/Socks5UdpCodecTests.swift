import XCTest
@testable import StarRadarCore

/**
 SOCKS5 UDP 数据报编解码的边界测试。

 ## 为什么单独一个文件

 UDP relay 是「另一台设备断网」这类问题的必经之路 —— **DNS 也走它**。
 而它的失败方式全是静默的：解析返回 nil、调用方 continue，日志里什么都没有。

 这里把三种地址形态（IPv4 / 域名 / IPv6）和几种畸形输入逐条钉住，
 免得以后改解析逻辑时把某一种悄悄弄坏（现场表现会是「只有某类目标不通」，
 极难从日志看出来）。

 真实向量（`share_vectors.json` 的 `udp` 段）由 PC 版 Python 生成，
 已在 ShareVectorTests 里逐字节比对；这个文件专注边界与往返一致性。
 */
final class Socks5UdpCodecTests: XCTestCase {

    private func payload(_ count: Int) -> [UInt8] {
        (0..<count).map { UInt8($0 & 0xFF) }
    }

    // ── 往返 ──────────────────────────────────────────────────

    /// IPv4 目标：编出来再解回去，字段必须完全一致。
    func testIPv4RoundTrip() {
        let data = payload(24)
        let packet = Socks5Proto.buildUdp("10.1.2.3", 53, data)
        guard let parsed = Socks5Proto.parseUdp(packet) else {
            return XCTFail("自己编的包解不开")
        }
        XCTAssertEqual(parsed.host, "10.1.2.3")
        XCTAssertEqual(parsed.port, 53)
        XCTAssertEqual(parsed.payload, data)
        // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
        XCTAssertEqual(parsed.headerLen, 10)
        XCTAssertEqual(packet.count, 10 + data.count)
    }

    /// 域名目标：长度由一字节给出，后面接端口与数据。
    func testDomainRoundTrip() {
        var raw: [UInt8] = [0, 0, 0, Socks5Proto.atypDomain, 11]
        raw.append(contentsOf: Array("dns.qq.com".utf8))     // 恰好 10 字节？
        raw[4] = UInt8(raw.count - 5)
        raw.append(contentsOf: [0x01, 0xBB])                  // 443
        let data = payload(8)
        raw.append(contentsOf: data)

        guard let parsed = Socks5Proto.parseUdp(raw) else {
            return XCTFail("域名格式解析失败")
        }
        XCTAssertEqual(parsed.host, "dns.qq.com")
        XCTAssertEqual(parsed.port, 443)
        XCTAssertEqual(parsed.payload, data)
    }

    /// IPv6 目标：16 字节地址，文本形式要能还原。
    func testIPv6RoundTrip() {
        var raw: [UInt8] = [0, 0, 0, Socks5Proto.atypIPv6]
        // 2001:db8::1
        raw.append(contentsOf: [0x20, 0x01, 0x0d, 0xb8,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01])
        raw.append(contentsOf: [0x00, 0x35])                  // 53
        let data = payload(12)
        raw.append(contentsOf: data)

        guard let parsed = Socks5Proto.parseUdp(raw) else {
            return XCTFail("IPv6 格式解析失败")
        }
        XCTAssertEqual(parsed.host, "2001:db8::1")
        XCTAssertEqual(parsed.port, 53)
        XCTAssertEqual(parsed.payload, data)
        XCTAssertEqual(parsed.headerLen, 4 + 16 + 2)
    }

    /// 空载荷是合法的（有些客户端用它做保活）。
    func testEmptyPayloadIsValid() {
        let packet = Socks5Proto.buildUdp("1.1.1.1", 53, [])
        guard let parsed = Socks5Proto.parseUdp(packet) else {
            return XCTFail("空载荷不该被拒")
        }
        XCTAssertEqual(parsed.payload, [])
        XCTAssertEqual(parsed.port, 53)
    }

    // ── 畸形输入 ──────────────────────────────────────────────

    /// 各种截断/非法输入必须返回 nil，而不是崩或产生错误字段。
    func testMalformedInputsAreRejected() {
        // 太短
        XCTAssertNil(Socks5Proto.parseUdp([]))
        XCTAssertNil(Socks5Proto.parseUdp([0, 0, 0]))
        // RSV 非 0
        XCTAssertNil(Socks5Proto.parseUdp([1, 0, 0, 1, 1, 2, 3, 4, 0, 53]))
        XCTAssertNil(Socks5Proto.parseUdp([0, 1, 0, 1, 1, 2, 3, 4, 0, 53]))
        // FRAG 非 0（RFC 1928 允许不实现分片）
        XCTAssertNil(Socks5Proto.parseUdp([0, 0, 1, 1, 1, 2, 3, 4, 0, 53]))
        // 未知 ATYP
        XCTAssertNil(Socks5Proto.parseUdp([0, 0, 0, 9, 1, 2, 3, 4, 0, 53]))
        // IPv4 但缺端口
        XCTAssertNil(Socks5Proto.parseUdp([0, 0, 0, 1, 1, 2, 3, 4, 0]))
        // 域名长度越界
        XCTAssertNil(Socks5Proto.parseUdp([0, 0, 0, 3, 200, 65, 66]))
    }

    // ── 常量 ──────────────────────────────────────────────────

    /// 地址类型与命令字必须与 PC 版一致（写错了整条链路都不通）。
    func testProtocolConstants() {
        XCTAssertEqual(Socks5Proto.version, 0x05)
        XCTAssertEqual(Socks5Proto.atypIPv4, 0x01)
        XCTAssertEqual(Socks5Proto.atypDomain, 0x03)
        XCTAssertEqual(Socks5Proto.atypIPv6, 0x04)
        XCTAssertEqual(Socks5Proto.cmdConnect, 0x01)
        XCTAssertEqual(Socks5Proto.cmdUdpAssociate, 0x03)
        XCTAssertEqual(Socks5Proto.repOK, 0x00)
        // UDP 缓冲区要能装下最大的 UDP 载荷 + SOCKS5 头
        XCTAssertGreaterThanOrEqual(Socks5Proto.maxUdpPacket, 65535)
    }

    /// `encodeAddr` 对非 IPv4 输入退化成 0.0.0.0，而不是产生长度错误的包。
    ///
    /// 这一点在 UDP ASSOCIATE 的回复里很重要：回复报文长度错了，客户端
    /// 会当成协议错误直接断开 —— 表现就是「关联建不起来」。
    func testEncodeAddrFallsBackToZeroForBadInput() {
        let encoded = Socks5Proto.encodeAddr("not-an-ip", 1080)
        XCTAssertEqual(encoded.count, 7, "ATYP + 4 字节地址 + 2 字节端口")
        XCTAssertEqual(encoded[0], Socks5Proto.atypIPv4)
        XCTAssertEqual(Array(encoded[1...4]), [0, 0, 0, 0])
        XCTAssertEqual(Int(encoded[5]) << 8 | Int(encoded[6]), 1080)
    }

    /// 回复报文长度固定 10 字节（VER REP RSV ATYP ADDR PORT）。
    ///
    /// 少了或多了，客户端会解析错位 —— 而这是「UDP 关联看似建立、
    /// 实际客户端一直重试」的一个隐蔽原因。
    func testReplyLengthIsStable() {
        let ok = Socks5Proto.reply(Socks5Proto.repOK, host: "192.168.1.5", port: 57638)
        XCTAssertEqual(ok.count, 10)
        XCTAssertEqual(ok[0], Socks5Proto.version)
        XCTAssertEqual(ok[1], Socks5Proto.repOK)
        XCTAssertEqual(ok[2], 0)
        XCTAssertEqual(ok[3], Socks5Proto.atypIPv4)
        XCTAssertEqual(Int(ok[8]) << 8 | Int(ok[9]), 57638)
    }
}
