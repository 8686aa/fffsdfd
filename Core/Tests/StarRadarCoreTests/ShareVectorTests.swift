import XCTest
@testable import StarRadarCore

/// 扫码链接 / 订阅 / UDP 封装的逐字节对照。
final class ShareVectorTests: XCTestCase {

    private let vectors = Vectors.load("share_vectors")

    func testPercentEncodingMatchesPythonQuote() {
        guard let cases = vectors["percent"]?.arrayValue else {
            return XCTFail("缺 percent")
        }
        for item in cases {
            let text = item["text"]!.stringValue!
            XCTAssertEqual(ShareLinks.percentEncode(text),
                           item["encoded"]?.stringValue,
                           "percentEncode(\(text)) 不一致")
        }
    }

    func testShareLinksMatchPython() {
        guard let links = vectors["links"], case .object(let cases) = links else {
            return XCTFail("缺 links")
        }
        for (flavor, value) in cases {
            let host = value["host"]!.stringValue!
            let port = value["port"]!.intValue!
            let user = value["user"]?.stringValue ?? ""
            let pass = value["pass"]?.stringValue ?? ""
            let target = ShareLinks.Target(host: host, port: port,
                                           user: user, pass: pass)

            XCTAssertEqual(ShareLinks.socks5Uri(target),
                           value["socks5_uri"]?.stringValue,
                           "[\(flavor)] socks5:// 不一致")
            XCTAssertEqual(ShareLinks.socksUri(target),
                           value["socks_uri"]?.stringValue,
                           "[\(flavor)] socks:// 不一致")
            XCTAssertEqual(ShareLinks.socksUriFull(target),
                           value["socks_uri_full"]?.stringValue,
                           "[\(flavor)] socks:// full 不一致")
            XCTAssertEqual(ShareLinks.subscriptionBody(target, flavor: "shadowrocket"),
                           value["sub_shadowrocket"]?.stringValue,
                           "[\(flavor)] Shadowrocket 订阅不一致")
            XCTAssertEqual(ShareLinks.subscriptionBody(target, flavor: "mixed"),
                           value["sub_mixed"]?.stringValue,
                           "[\(flavor)] 混合订阅不一致")
            XCTAssertEqual(ShareLinks.subscriptionPlain(target, flavor: "shadowrocket"),
                           value["sub_plain_shadowrocket"]?.stringValue,
                           "[\(flavor)] 明文订阅不一致")
            XCTAssertEqual(ShareLinks.subscriptionPlain(target, flavor: "mixed"),
                           value["sub_plain_mixed"]?.stringValue,
                           "[\(flavor)] 混合明文订阅不一致")
            XCTAssertEqual(ShareLinks.shadowrocketConf(target),
                           value["conf"]?.stringValue,
                           "[\(flavor)] .conf 不一致")
        }
    }

    func testSocks5UriHasNoGroupSuffix() {
        // 扫码出现两个配置的根因：URI 尾部带了 `#备注` 被当成分组名
        let target = ShareLinks.Target(host: "192.168.1.23", port: 1083)
        XCTAssertFalse(ShareLinks.socks5Uri(target).contains("#"))
    }

    func testUdpDatagramRoundTripMatchesPython() {
        guard let cases = vectors["udp"]?.arrayValue else { return XCTFail("缺 udp") }
        for item in cases {
            let packetHex = item["packet_hex"]!.stringValue!
            let payloadHex = item["payload_hex"]?.stringValue ?? ""
            let host = item["host"]!.stringValue!
            let port = item["port"]!.intValue!

            let raw = Hex.decode(packetHex)!
            guard let parsed = Socks5Proto.parseUdp(raw) else {
                XCTFail("解析失败：\(packetHex)")
                continue
            }
            XCTAssertEqual(parsed.host, host)
            XCTAssertEqual(parsed.port, port)
            XCTAssertEqual(Hex.encode(parsed.payload), payloadHex)
            XCTAssertEqual(parsed.headerLen, item["header_len"]?.intValue)

            let rebuilt = Socks5Proto.buildUdp(parsed.host, parsed.port,
                                               parsed.payload)
            XCTAssertEqual(Hex.encode(rebuilt), packetHex,
                           "封回去的字节必须与 Python 一致")
        }
    }

    func testSingboxLinkEncodesUrlAsWhole() {
        let link = ShareLinks.singboxLink("http://192.168.1.23:8088/share/singbox")
        XCTAssertTrue(link.hasPrefix("sing-box://import-remote-profile?url="))
        // 冒号与斜杠都必须被编码，否则 App 侧切 query 会把参数截断
        XCTAssertTrue(link.contains("%3A"))
        XCTAssertTrue(link.contains("%2F"))
    }

    func testUdpDirectionIsNormalized() {
        // 下行包：src=服务器 dst=客户端。规范化后 client/server 不能反。
        let down = UdpReport.normalize(srcIp: "1.2.3.4", srcPort: 10001,
                                       dstIp: "192.168.1.5", dstPort: 5000,
                                       up: false)
        XCTAssertEqual(down.clientIp, "192.168.1.5")
        XCTAssertEqual(down.serverIp, "1.2.3.4")
        XCTAssertFalse(down.up)

        // 拼出来的 IP 报文里，源地址必须是服务器（真实方向）
        let packet = UdpReport.packet(down, [1, 2, 3])!
        XCTAssertEqual(Array(packet[12..<16]), [1, 2, 3, 4])
        XCTAssertEqual(Array(packet[16..<20]), [192, 168, 1, 5])
    }
}
