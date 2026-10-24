import Foundation

/**
 上报过滤 —— 与 `pc/collect/udpfilter.py`、`UdpGate.kt` 一致。

 ## 目的只有一个：别把没用的包也传上去

 UDP 流量的大头是 DNS、QUIC、mDNS、SSDP、选服探测。这些对节点毫无价值，
 但一条一条 base64 上传会实打实消耗流量和电量。PC 版实测：一份 425 个包的
 抓包里**全部是选服探测**，真实对局流 0 条。

 ## 判据为什么是「时长 + 包数 + 双向」而不是端口

 对局 UDP 的端口是服务器**每局下发**的（见过的有 10001/10119/50976/8011/
 10391/55103/10229/10328）。写死端口必然在某次更新后全线漏报。真正稳定的
 特征是持续时间：探测几十毫秒打完就没，对局是每秒几十包、持续几分钟。

 ## HOLD 状态：判据成立前的包不能丢

 新流先进缓冲，判据成立时**连缓冲一起放行**（时间戳用原始的），否则节点侧
 会缺第一帧，整局数据作废。
 */
public final class UdpGate {

    public static let modeOff = "off"
    public static let modeLoose = "loose"
    public static let modeBalance = "balance"
    public static let modeStrict = "strict"
    public static let modes = [modeOff, modeLoose, modeBalance, modeStrict]

    /// 对局实测 20~40 pps，1.5 秒就是 30~60 个包。阈值故意宽松：
    /// 多报几条垃圾只是费点流量，漏一条对局是整局没数据。
    public static let minPackets = 6
    public static let minSpanMs: Int64 = 2000

    public static let holdMaxPackets = 256
    public static let holdMaxBytes = 128 * 1024
    public static let holdMaxMs: Int64 = 30_000
    public static let holdMaxFlows = 128

    public static let flowIdleMs: Int64 = 60_000
    public static let maxFlows = 512

    /// 系统端口：DNS / DHCP / NTP / NetBIOS / SSDP / mDNS / LLMNR。
    public static let systemPorts: Set<Int> = [
        53, 67, 68, 69, 123, 137, 138, 139, 1900, 3702, 5353, 5355, 546, 547,
    ]

    /// 媒体与隧道端口：QUIC / STUN / TURN / IPsec / OpenVPN / WireGuard。
    public static let mediaPorts: Set<Int> = [
        80, 443, 3478, 3479, 5349, 500, 4500, 1194, 51820, 1701,
    ]

    private enum State {
        case hold, pass, drop
    }

    private final class Flow {
        let clientIp: String
        let clientPort: Int
        let serverIp: String
        let serverPort: Int
        var state = State.hold
        var first: Int64
        var last: Int64
        var packets = 0
        var bytes = 0
        var up = 0
        var down = 0
        var buffer: [Datagram] = []
        var bufferBytes = 0
        var why = ""

        init(_ datagram: Datagram, _ now: Int64) {
            clientIp = datagram.clientIp
            clientPort = datagram.clientPort
            serverIp = datagram.serverIp
            serverPort = datagram.serverPort
            first = now
            last = now
        }

        var span: Int64 { last - first }
    }

    /// 进入过滤器的数据报。
    public struct Datagram {
        public let clientIp: String
        public let clientPort: Int
        public let serverIp: String
        public let serverPort: Int
        public let up: Bool
        public let payload: [UInt8]

        public init(clientIp: String, clientPort: Int, serverIp: String,
                    serverPort: Int, up: Bool, payload: [UInt8]) {
            self.clientIp = clientIp
            self.clientPort = clientPort
            self.serverIp = serverIp
            self.serverPort = serverPort
            self.up = up
            self.payload = payload
        }

        public var size: Int { payload.count }
    }

    public struct BlockedEntry {
        public let port: Int
        public let packets: Int
        public let bytes: Int
        public let spanMs: Int64
        public let why: String
    }

    public struct Snapshot {
        public let mode: String
        public let passed: Int64
        public let dropped: Int64
        public let droppedNonPublic: Int64
        public let passedBytes: Int64
        public let droppedBytes: Int64
        public let flows: Int
        public let holding: Int
        public let opened: Int
        public let blocked: [BlockedEntry]
        /// 「省了多少」按剔除内网/组播之后的口径算。
        public let savedPct: Double
    }

    public var mode: String
    public var ports: Set<Int>
    public var blockMedia: Bool
    public var minPacketThreshold: Int
    public var minSpanThreshold: Int64

    private let lock = NSLock()
    private var flows: [String: Flow] = [:]
    private var blockedList: [BlockedEntry] = []

    public private(set) var passed: Int64 = 0
    public private(set) var dropped: Int64 = 0
    public private(set) var passedBytes: Int64 = 0
    public private(set) var droppedBytes: Int64 = 0
    public private(set) var openFlows: Int64 = 0
    public private(set) var blockedFlows: Int64 = 0
    public private(set) var droppedNonPublic: Int64 = 0

    public init(mode: String = UdpGate.modeBalance, ports: Set<Int> = [],
                blockMedia: Bool = true,
                minPackets: Int = UdpGate.minPackets,
                minSpanMs: Int64 = UdpGate.minSpanMs) {
        self.mode = mode
        self.ports = ports
        self.blockMedia = blockMedia
        self.minPacketThreshold = minPackets
        self.minSpanThreshold = minSpanMs
    }

    private func flowKey(_ datagram: Datagram) -> String {
        "\(datagram.clientIp):\(datagram.clientPort)|\(datagram.serverIp):\(datagram.serverPort)"
    }

    /**
     判定一个数据报。

     返回**该放行的全部数据报**：流刚达到判据时里面是之前缓存的一批
     （含当前这个）；已在放行状态的流只有当前这个；被挡则空。

     ⚠️ 调用方**不要**自己再发一次当前包 —— 会重复上报。
     */
    public func handle(_ datagram: Datagram,
                       now: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> [Datagram] {
        // 内网/保留地址一律不上报（防御性判断）
        if isNonPublic(datagram.serverIp) {
            lock.lock()
            dropped += 1
            droppedBytes += Int64(datagram.size)
            droppedNonPublic += 1
            lock.unlock()
            return []
        }

        switch portVerdict(datagram.serverPort) {
        case .pass:
            lock.lock()
            passed += 1
            passedBytes += Int64(datagram.size)
            lock.unlock()
            return [datagram]
        case .drop:
            lock.lock()
            dropped += 1
            droppedBytes += Int64(datagram.size)
            noteBlocked(datagram.serverPort, 1, datagram.size, 0, "端口")
            lock.unlock()
            return []
        case nil:
            break
        }

        lock.lock()
        defer { lock.unlock() }

        if flows.count >= UdpGate.maxFlows { evictLocked(now) }
        let key = flowKey(datagram)
        var flow: Flow
        if let existing = flows[key] {
            flow = existing
        } else {
            let holding = flows.values.filter { $0.state == .hold }.count
            if holding >= UdpGate.holdMaxFlows {
                dropped += 1
                droppedBytes += Int64(datagram.size)
                return []
            }
            flow = Flow(datagram, now)
            flows[key] = flow
        }
        flow.last = now
        flow.packets += 1
        flow.bytes += datagram.size
        if datagram.up { flow.up += 1 } else { flow.down += 1 }

        if flow.state == .pass {
            passed += 1
            passedBytes += Int64(datagram.size)
            return [datagram]
        }
        if flow.state == .drop {
            dropped += 1
            droppedBytes += Int64(datagram.size)
            return []
        }

        // HOLD：先攒着
        flow.buffer.append(datagram)
        flow.bufferBytes += datagram.size

        if isMature(flow) {
            return release(flow)
        }

        // 攒到上限还没达标 —— 这里 PC 版踩过一个坑：
        // **字节上限不能当「判死」**。一条 3.5MB 的长时间流会在第 87 个下行
        // 大包处被整条丢掉。达到一定量本身就说明它不是垃圾（DNS/探测都是
        // 小包小量），所以「超字节上限」应当判**放行**。
        if flow.bufferBytes >= UdpGate.holdMaxBytes {
            return release(flow)
        }
        if flow.buffer.count >= UdpGate.holdMaxPackets ||
            flow.span >= UdpGate.holdMaxMs {
            flow.state = .drop
            blockedFlows += 1
            let lost = flow.buffer
            let bytes = flow.bufferBytes
            flow.buffer = []
            flow.bufferBytes = 0
            dropped += Int64(lost.count)
            droppedBytes += Int64(bytes)
            flow.why = (flow.up == 0 || flow.down == 0) ? "单向" : "判据未达"
            noteBlocked(datagram.serverPort, flow.packets, flow.bytes,
                        flow.span, flow.why)
            return []
        }
        return []
    }

    private func release(_ flow: Flow) -> [Datagram] {
        flow.state = .pass
        openFlows += 1
        let backlog = flow.buffer
        let bytes = flow.bufferBytes
        flow.buffer = []
        flow.bufferBytes = 0
        passed += Int64(backlog.count)
        passedBytes += Int64(bytes)
        return backlog
    }

    /// 判据：包数够 + 时长够 + **双向**。
    private func isMature(_ flow: Flow) -> Bool {
        flow.packets >= minPacketThreshold &&
            flow.span >= minSpanThreshold &&
            flow.up > 0 && flow.down > 0
    }

    private func portVerdict(_ port: Int) -> State? {
        if ports.contains(port) { return .pass }        // 人工白名单最优先
        if UdpGate.systemPorts.contains(port) { return .drop }
        if blockMedia && UdpGate.mediaPorts.contains(port) { return .drop }
        switch mode {
        case UdpGate.modeOff, UdpGate.modeLoose: return .pass
        case UdpGate.modeStrict: return .drop           // 严格：白名单外全丢
        default: return nil                             // balance：交给流级判定
        }
    }

    private func isNonPublic(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count != 4 { return true }
        guard let a = Int(parts[0]), let b = Int(parts[1]) else { return true }
        if a == 10 { return true }
        if a == 127 { return true }
        if a == 0 { return true }
        if a == 169 && b == 254 { return true }
        if a == 172 && (16...31).contains(b) { return true }
        if a == 192 && b == 168 { return true }
        if a >= 224 { return true }                     // 组播/保留
        return false
    }

    private func noteBlocked(_ port: Int, _ packets: Int, _ bytes: Int,
                             _ spanMs: Int64, _ why: String) {
        // 只留端口与计数，**不带地址**（快照会进状态页/日志）
        blockedList.append(BlockedEntry(port: port, packets: packets,
                                        bytes: bytes, spanMs: spanMs, why: why))
        while blockedList.count > 16 { blockedList.removeFirst() }
    }

    private func evictLocked(_ now: Int64) {
        let cutoff = now - UdpGate.flowIdleMs
        let dead = flows.filter { $0.value.last < cutoff }.map { $0.key }
        for key in dead {
            guard let flow = flows.removeValue(forKey: key) else { continue }
            if flow.state == .hold && !flow.buffer.isEmpty {
                dropped += Int64(flow.buffer.count)
                droppedBytes += Int64(flow.bufferBytes)
                noteBlocked(flow.serverPort, flow.packets, flow.bytes,
                            flow.span, "流提前结束")
            }
        }
    }

    /// 停机时结算还挂在缓冲里的流（否则统计会凭空少一批）。
    public func settle() {
        lock.lock()
        defer { lock.unlock() }
        for flow in flows.values {
            if flow.state == .hold && !flow.buffer.isEmpty {
                dropped += Int64(flow.buffer.count)
                droppedBytes += Int64(flow.bufferBytes)
                noteBlocked(flow.serverPort, flow.packets, flow.bytes,
                            flow.span, "流提前结束")
                flow.buffer = []
                flow.bufferBytes = 0
            }
        }
        flows.removeAll()
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        flows.removeAll()
        blockedList.removeAll()
        passed = 0; dropped = 0
        passedBytes = 0; droppedBytes = 0
        openFlows = 0; blockedFlows = 0
        droppedNonPublic = 0
    }

    public func snapshot() -> Snapshot {
        lock.lock()
        let holding = flows.values.filter { $0.state == .hold }.count
        let opened = flows.values.filter { $0.state == .pass }.count
        let flowCount = flows.count
        let entries = blockedList
        let passedB = passedBytes
        let droppedB = droppedBytes - max(droppedNonPublic, 0)
        let passedValue = passed
        let droppedValue = dropped
        let nonPublic = droppedNonPublic
        lock.unlock()

        let total = passedB + droppedB
        let savedPct = total > 0
            ? (Double(droppedB) * 1000.0 / Double(total)).rounded() / 10.0
            : 0.0

        return Snapshot(mode: mode, passed: passedValue, dropped: droppedValue,
                        droppedNonPublic: nonPublic, passedBytes: passedB,
                        droppedBytes: droppedB, flows: flowCount,
                        holding: holding, opened: opened,
                        blocked: entries, savedPct: savedPct)
    }
}
