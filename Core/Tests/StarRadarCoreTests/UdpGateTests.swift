import XCTest
@testable import StarRadarCore

/// UDP 过滤器 —— 纯逻辑，不依赖网络。
final class UdpGateTests: XCTestCase {

    private func datagram(port: Int, up: Bool, size: Int = 32,
                          serverIp: String = "1.2.3.4") -> UdpGate.Datagram {
        UdpGate.Datagram(clientIp: "192.168.1.5", clientPort: 5000,
                         serverIp: serverIp, serverPort: port, up: up,
                         payload: [UInt8](repeating: 0xAB, count: size))
    }

    func testSystemPortsAreDropped() {
        let gate = UdpGate(mode: UdpGate.modeBalance)
        // DNS / mDNS / SSDP：无论如何都不该上报
        for port in [53, 5353, 1900] {
            let out = gate.handle(datagram(port: port, up: true), now: 1_000)
            XCTAssertTrue(out.isEmpty, "系统端口 \(port) 不该放行")
        }
        let snapshot = gate.snapshot()
        XCTAssertGreaterThan(snapshot.dropped, 0)
    }

    func testMediaPortsAreDroppedWhenEnabled() {
        let gate = UdpGate(mode: UdpGate.modeBalance, blockMedia: true)
        XCTAssertTrue(gate.handle(datagram(port: 443, up: true), now: 1_000).isEmpty)
        // 关掉媒体过滤后，443 交给流级判定（新流先 HOLD → 不放行）
        let open = UdpGate(mode: UdpGate.modeBalance, blockMedia: false)
        XCTAssertTrue(open.handle(datagram(port: 443, up: true), now: 1_000).isEmpty)
        XCTAssertEqual(open.snapshot().holding, 1, "应当进入 HOLD 而不是被丢")
    }

    func testMatureFlowReleasesBacklog() {
        let gate = UdpGate(mode: UdpGate.modeBalance)
        var now: Int64 = 1_000_000
        var released = 0
        // 8 个包、间隔 300ms、双向 → 满足「≥6 包 + ≥2s + 双向」
        for index in 0..<8 {
            let out = gate.handle(datagram(port: 10001, up: index % 2 == 0),
                                  now: now)
            released += out.count
            now += 300
        }
        XCTAssertEqual(released, 8, "判据成立时应当把缓冲一起放行")
        XCTAssertGreaterThanOrEqual(gate.snapshot().passed, 8)
    }

    func testOneWayFlowIsNeverReleased() {
        let gate = UdpGate(mode: UdpGate.modeBalance)
        var now: Int64 = 1_000_000
        var released = 0
        // 全是上行：包数和时长都够，但没有回包 —— 典型探测特征
        for _ in 0..<8 {
            released += gate.handle(datagram(port: 10001, up: true), now: now).count
            now += 300
        }
        XCTAssertEqual(released, 0, "单向流不该放行")
        gate.settle()
        XCTAssertGreaterThan(gate.snapshot().dropped, 0, "结算时应当计入丢弃")
    }

    func testLargeFlowIsReleasedNotDropped() {
        let gate = UdpGate(mode: UdpGate.modeBalance)
        var now: Int64 = 1_000_000
        var released = 0
        // 大包快发：还没到 minSpan，但字节数已经超过 HOLD_MAX_BYTES。
        // PC 版踩过「把字节上限当判死」的坑 —— 长流会被整条丢掉。
        for _ in 0..<6 {
            released += gate.handle(datagram(port: 10001, up: true, size: 24_000),
                                    now: now).count
            now += 50
        }
        XCTAssertGreaterThan(released, 0, "字节超限应当放行，而不是判死")
    }

    func testNonPublicServerIsIgnored() {
        let gate = UdpGate(mode: UdpGate.modeOff)
        let out = gate.handle(datagram(port: 10001, up: true,
                                       serverIp: "192.168.1.9"), now: 1_000)
        XCTAssertTrue(out.isEmpty)
        XCTAssertEqual(gate.snapshot().droppedNonPublic, 1)
    }

    func testStrictModeDropsUnlistedPorts() {
        let gate = UdpGate(mode: UdpGate.modeStrict, ports: [10001])
        XCTAssertFalse(gate.handle(datagram(port: 10001, up: true),
                                   now: 1_000).isEmpty)
        XCTAssertTrue(gate.handle(datagram(port: 10002, up: true),
                                  now: 1_000).isEmpty)
    }

    func testOffModePassesEverythingPublic() {
        let gate = UdpGate(mode: UdpGate.modeOff)
        XCTAssertEqual(gate.handle(datagram(port: 10001, up: true),
                                   now: 1_000).count, 1)
        // 但系统端口仍然要挡（off 只是「不做流级判定」）
        XCTAssertTrue(gate.handle(datagram(port: 53, up: true), now: 1_000).isEmpty)
    }
}
