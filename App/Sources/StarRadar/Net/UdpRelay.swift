import Foundation
import Darwin
import StarRadarCore

/**
 SOCKS5 的 UDP relay —— 与 `Socks5UdpRelay.kt` 等价。

 ```
   另一台设备 ──UDP(SOCKS5 封装)──▶ 本 relay ──UDP──▶ 真实目标
                 ▲                    │
                 └──── 封回去 ─────────┘
                                      └──▶ 上报（过滤后）
 ```

 sing-box / NekoBox / Shadowrocket 的 TUN 模式都会把 UDP（含 DNS、QUIC）
 交给 SOCKS5 的 UDP ASSOCIATE。**DNS 也走这里** —— 所以这一层不通，表现
 不是「某个游戏连不上」，而是整台设备解析不了域名 = 完全断网。

 ## 这一层出问题时最难的地方：看不见

 之前的实现里，任何一步失败都是 `continue` 静默丢弃：包没到、解析失败、
 目标解析不了、发送失败 —— 日志全都一样（什么都没有），而客户端只知道
 「查询超时」，于是每 3 秒重开一个 UDP 关联重试。现场看到的就是
 **一堆「UDP 关联已建立」而没有任何结论**。

 现在每个失败分支都有独立计数，并在下列时机落日志：
 - 第一次收到包（附源地址、目标、长度）—— 证明「包确实到了」
 - 每种失败第一次发生（附具体原因）
 - 关联关闭时的完整汇总
 - **关联建立 5 秒还没收到任何包** → 明确告警「客户端 UDP 没到达本机」，
   这条能一次性区分「收不到」和「转不出去」两类完全不同的原因。

 ## 安全：只服务申请者

 只接受「申请这个 relay 的那个客户端 IP」发来的包。否则任何能连到这台
 手机 UDP 端口的人都能拿它当开放中继（放大攻击的跳板）。某些客户端会用
 不同的源端口，所以只校验 IP、不校验端口。被丢弃的源地址会记日志 ——
 这既保留了安全性，又不会让「源地址不匹配」这种情况继续隐形。
 */
public final class UdpRelay {

    public static let idleTimeoutMs: Int64 = 60_000
    public static let maxUpstreams = 128
    public static let recvTimeoutMs = 500
    /// 关联建立后多久检查一次「有没有收到过任何包」。
    public static let probeAfterMs: Int64 = 5000
    /// 每种异常最多打几条日志，避免刷屏。
    static let logLimitPerKind = 3

    private final class Upstream {
        let fd: Int32
        let label: String
        let targetIp: String
        let targetPort: Int
        /// IPv6 目标单独标记：上报链路只支持 IPv4，这类包只转发不上报。
        let isIPv6: Bool
        var thread: Thread?
        var lastActive: Int64
        var sent = 0
        var received = 0

        init(fd: Int32, label: String, targetIp: String, targetPort: Int,
             isIPv6: Bool, lastActive: Int64) {
            self.fd = fd
            self.label = label
            self.targetIp = targetIp
            self.targetPort = targetPort
            self.isIPv6 = isIPv6
            self.lastActive = lastActive
        }
    }

    private let clientIp: String
    private let onUdp: (String, Int, String, Int, [UInt8], Bool) -> Void
    private let log: (String) -> Void

    private var fd: Int32 = -1
    private var thread: Thread?
    private var running = false
    private let lock = NSLock()

    private var upstreams: [String: Upstream] = [:]
    private var dnsCache: [String: String] = [:]

    /// 客户端最后从哪里发来（回包发给它）。
    private var clientAddress: sockaddr_in?

    public private(set) var port = 0
    /// socket 上**原始**收到的 UDP 包数（源地址过滤之前）。
    ///
    /// 它和 `packetsIn` 分开是有意义的：
    ///   raw == 0          → 包根本没到本机（广告地址/局域网问题）
    ///   raw > 0, in == 0  → 到了但源地址不是申请者（被安全过滤挡掉）
    /// 这两种原因的修法完全不同，不能混成一个数。
    public private(set) var packetsRaw = 0
    /// 通过源校验、真正进入转发流程的包数。
    public private(set) var packetsIn = 0
    public private(set) var packetsOut = 0
    /// 已经打过日志的「异常种类」（每种只打前几条）。
    private var loggedKinds: [String: Int] = [:]
    private var firstPacketLogged = false

    // 失败分类计数（关掉时一次性汇总）
    private var droppedWrongSource = 0
    private var droppedParse = 0
    private var droppedPortZero = 0
    private var droppedResolve = 0
    private var sendFails = 0
    private var replyFails = 0

    public var isRunning: Bool { running }

    public init(clientIp: String,
                onUdp: @escaping (String, Int, String, Int, [UInt8], Bool) -> Void,
                log: @escaping (String) -> Void = { _ in }) {
        self.clientIp = clientIp
        self.onUdp = onUdp
        self.log = log
    }

    // ── 生命周期 ──────────────────────────────────────────────

    /// 建 socket。失败返回 false（端口耗尽之类）。
    public func open() -> Bool {
        let handle = socket(AF_INET, SOCK_DGRAM, 0)
        if handle < 0 {
            log("[udp] relay 起不来：socket() errno \(errno)")
            return false
        }
        var reuse: Int32 = 1
        setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(handle, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bound != 0 {
            log("[udp] relay 绑定失败（errno \(errno)）")
            Darwin.close(handle)
            return false
        }
        var timeout = timeval(tv_sec: 0,
                              tv_usec: Int32(UdpRelay.recvTimeoutMs * 1000))
        setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))

        var local = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &local) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(handle, $0, &length)
            }
        }
        fd = handle
        port = Int(UInt16(bigEndian: local.sin_port))
        return true
    }

    public func start() {
        if fd < 0 { return }
        running = true
        let thread = Thread { [weak self] in self?.loop() }
        thread.name = "s5-udp-\(port)"
        thread.stackSize = 512 * 1024
        self.thread = thread
        thread.start()
    }

    // ── 客户端 → 目标 ────────────────────────────────────────

    private func loop() {
        var buffer = [UInt8](repeating: 0, count: Socks5Proto.maxUdpPacket)
        while running {
            var from = sockaddr_in()
            var fromLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            // 容量必须在闭包外取：闭包内读 buffer.count 会与
            // withUnsafeMutableBytes 的可变借用重叠（Swift 独占访问检查）。
            let capacity = buffer.count
            let received = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return withUnsafeMutablePointer(to: &from) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        recvfrom(fd, base, capacity, 0, $0, &fromLength)
                    }
                }
            }
            if received <= 0 {
                if received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    sweepIdle()
                    continue
                }
                if received < 0 && errno == EINTR { continue }
                if running { log("[udp] 接收结束（errno \(errno)）") }
                break
            }

            let fromIp = Self.text(from.sin_addr)
            let fromPort = Int(UInt16(bigEndian: from.sin_port))
            lock.lock(); packetsRaw += 1; lock.unlock()

            // 只服务申请者。被别的源打过标记 —— 这条以前是静默丢弃，
            // 于是「源 IP 对不上」和「根本没收到包」在日志里无法区分。
            if !clientIp.isEmpty && fromIp != clientIp {
                lock.lock(); droppedWrongSource += 1; lock.unlock()
                note("已丢弃来自其它主机的 UDP（\(fromIp):\(fromPort)→本机 \(port)，"
                     + "只服务 \(clientIp)）", kind: "wrong-source")
                continue
            }

            lock.lock(); packetsIn += 1; lock.unlock()

            let data = Array(buffer[0..<received])
            guard let parsed = Socks5Proto.parseUdp(data), parsed.port != 0 else {
                lock.lock()
                if parsed == nil { droppedParse += 1 } else { droppedPortZero += 1 }
                lock.unlock()
                note("UDP 报文解析失败（\(received) 字节，首 4 字节 "
                     + "\(data.prefix(4).map { String(format: "%02x", $0) }.joined(separator: " "))）",
                     kind: "parse")
                continue
            }

            lock.lock(); clientAddress = from; lock.unlock()

            guard let targetIp = resolve(parsed.host) else {
                lock.lock(); droppedResolve += 1; lock.unlock()
                note("目标无法解析成 IPv4：\(parsed.host)（该包已丢弃）", kind: "resolve")
                continue
            }

            if !firstPacketLogged {
                firstPacketLogged = true
                log("[udp] 收到第一包：\(fromIp):\(fromPort) → "
                    + "\(targetIp):\(parsed.port) · \(parsed.payload.count) 字节")
            }

            report(fromIp, fromPort, targetIp, parsed.port, parsed.payload, true)
            forward(targetIp, parsed.port,
                    isIPv6: parsed.host.contains(":"), parsed.payload)
        }
    }

    private func forward(_ targetIp: String, _ port: Int, isIPv6: Bool,
                         _ payload: [UInt8]) {
        let key = "\(targetIp):\(port)"
        lock.lock()
        if let existing = upstreams[key] {
            existing.lastActive = Self.nowMs()
            existing.sent += 1
            let handle = existing.fd
            lock.unlock()
            // ⚠️ 用 send 而不是 sendto：这个 socket 已经 connect 到目标，
            // 在 Darwin 上对已连接 socket 调 sendto 并再传一次地址，
            // 行为依实现而定（部分版本直接返回 EISCONN）。send 没有歧义。
            let sent = payload.withUnsafeBytes { raw in
                Darwin.send(handle, raw.baseAddress, payload.count, 0)
            }
            if sent < 0 {
                lock.lock(); sendFails += 1; lock.unlock()
                note("发往 \(key) 失败（errno \(errno)）", kind: "send-fail")
            }
            return
        }
        if upstreams.count >= UdpRelay.maxUpstreams {
            // 满了：关掉最老的一个。对局换服时新目标才是重要的那个。
            if let oldest = upstreams.min(by: { $0.value.lastActive < $1.value.lastActive }) {
                upstreams.removeValue(forKey: oldest.key)
                Darwin.close(oldest.value.fd)
                note("上游目标已达上限，淘汰最老的 \(oldest.key)", kind: "upstream-evict")
            }
        }
        lock.unlock()
        openUpstream(key, targetIp, port, isIPv6: isIPv6, payload)
    }

    private func openUpstream(_ key: String, _ targetIp: String, _ port: Int,
                              isIPv6: Bool, _ first: [UInt8]) {
        let family = isIPv6 ? AF_INET6 : AF_INET
        let handle = socket(family, SOCK_DGRAM, 0)
        if handle < 0 {
            log("[udp] 建上游 socket 失败（errno \(errno)）")
            return
        }
        let connected: Int32
        if isIPv6 {
            var address = Self.address6(targetIp, port)
            connected = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(handle, $0,
                                   socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        } else {
            var address = Self.address(targetIp, port)
            connected = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(handle, $0,
                                   socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if connected != 0 {
            let code = errno
            Darwin.close(handle)
            lock.lock(); sendFails += 1; lock.unlock()
            note("连不上 UDP 目标 \(key)（errno \(code)）", kind: "upstream-connect")
            return
        }
        var timeout = timeval(tv_sec: 0,
                              tv_usec: Int32(UdpRelay.recvTimeoutMs * 1000))
        setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))

        let sent = first.withUnsafeBytes { raw in
            Darwin.send(handle, raw.baseAddress, first.count, 0)
        }
        if sent < 0 {
            let code = errno
            Darwin.close(handle)
            lock.lock(); sendFails += 1; lock.unlock()
            note("首包发往 \(key) 失败（errno \(code)）", kind: "send-fail")
            return
        }

        let entry = Upstream(fd: handle, label: key, targetIp: targetIp,
                             targetPort: port, isIPv6: isIPv6,
                             lastActive: Self.nowMs())
        entry.sent = 1
        let thread = Thread { [weak self] in
            self?.upstreamLoop(entry)
        }
        thread.name = "s5-udp-up-\(port)"
        thread.stackSize = 512 * 1024
        entry.thread = thread

        lock.lock()
        upstreams[key] = entry
        lock.unlock()
        thread.start()
    }

    // ── 目标 → 客户端 ────────────────────────────────────────

    private func upstreamLoop(_ entry: Upstream) {
        var buffer = [UInt8](repeating: 0, count: Socks5Proto.maxUdpPacket)
        let capacity = buffer.count
        while running {
            let received = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.recv(entry.fd, base, capacity, 0)
            }
            if received <= 0 {
                if received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    lock.lock()
                    let idle = Self.nowMs() - entry.lastActive
                    lock.unlock()
                    if idle > UdpRelay.idleTimeoutMs {
                        closeUpstream(entry.label)
                        return
                    }
                    continue
                }
                if received < 0 && errno == EINTR { continue }
                return
            }
            let data = Array(buffer[0..<received])

            lock.lock()
            entry.lastActive = Self.nowMs()
            entry.received += 1
            packetsOut += 1
            let destination = clientAddress
            lock.unlock()

            guard let destination else {
                note("收到 \(entry.label) 的回包，但不知道发给谁"
                     + "（客户端还没发过包）", kind: "no-client-addr")
                continue
            }
            let clientPort = Int(UInt16(bigEndian: destination.sin_port))
            let clientText = Self.text(destination.sin_addr)

            // IPv6 目标只转发、不上报：上报用的是 IPv4 数据报，
            // 构造不出对应的五元组。这样 DNS over IPv6 仍然能用。
            if !entry.isIPv6 {
                report(entry.targetIp, entry.targetPort,
                       clientText.isEmpty ? clientIp : clientText,
                       clientPort, data, false)
            }

            sendToClient(entry.targetIp, entry.targetPort, data, destination)
        }
    }

    private func sendToClient(_ targetIp: String, _ targetPort: Int,
                              _ payload: [UInt8], _ destination: sockaddr_in) {
        if fd < 0 { return }
        let framed = Socks5Proto.buildUdp(targetIp, targetPort, payload)
        var address = destination
        let sent = framed.withUnsafeBytes { raw in
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, raw.baseAddress, framed.count, 0, $0,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if sent < 0 {
            lock.lock(); replyFails += 1; lock.unlock()
            note("回包发给客户端失败（errno \(errno)）", kind: "reply-fail")
        }
    }

    // ── 上报 ────────────────────────────────────────────────

    private func report(_ srcIp: String, _ srcPort: Int, _ dstIp: String,
                        _ dstPort: Int, _ payload: [UInt8], _ up: Bool) {
        // 上报失败不影响转发
        onUdp(srcIp, srcPort, dstIp, dstPort, payload, up)
    }

    // ── 域名解析（带缓存）────────────────────────────────────

    /// 目标 → IPv4。
    ///
    /// 已经是 IPv4 字面量就直接用；IPv6 字面量返回它自己（由调用方按
    /// IPv6 建 socket）；域名只解析 A 记录。
    private func resolve(_ host: String) -> String? {
        if host.isEmpty { return nil }
        if IpDatagram.isIpv4(host) { return host }
        if host.contains(":") { return host }        // IPv6 字面量，交给上层
        lock.lock()
        if let cached = dnsCache[host] {
            lock.unlock()
            return cached
        }
        lock.unlock()
        // HostResolver.ipv4 返回 String?，`try?` 会把它 flatten 成 String?，
        // 所以只需要解一层。
        guard let value = try? HostResolver.ipv4(host), let ip = value else {
            return nil
        }
        lock.lock()
        if dnsCache.count > 128 { dnsCache.removeAll() }
        dnsCache[host] = ip
        lock.unlock()
        return ip
    }

    // ── 回收 ────────────────────────────────────────────────

    private func sweepIdle() {
        let now = Self.nowMs()
        lock.lock()
        let dead = upstreams.filter { now - $0.value.lastActive > UdpRelay.idleTimeoutMs }
            .map { $0.key }
        lock.unlock()
        for key in dead { closeUpstream(key) }
    }

    private func closeUpstream(_ key: String) {
        lock.lock()
        let entry = upstreams.removeValue(forKey: key)
        lock.unlock()
        if let entry { Darwin.close(entry.fd) }
    }

    public func close() {
        running = false
        lock.lock()
        let all = upstreams
        upstreams.removeAll()
        lock.unlock()
        for (_, entry) in all { Darwin.close(entry.fd) }
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
        thread = nil
    }

    public var upstreamCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return upstreams.count
    }

    /// 一条汇总。关闭时打到日志里 —— 有它就能直接判断「是没收到包」
    /// 还是「收到了但出不去」。
    public func summaryLine() -> String {
        lock.lock()
        defer { lock.unlock() }
        var parts = ["原始 \(packetsRaw) 包", "进入转发 \(packetsIn) 包",
                     "回包 \(packetsOut)", "目标 \(upstreams.count) 个"]
        if droppedWrongSource > 0 { parts.append("源不符 \(droppedWrongSource)") }
        if droppedParse > 0 { parts.append("解析失败 \(droppedParse)") }
        if droppedPortZero > 0 { parts.append("端口为 0 \(droppedPortZero)") }
        if droppedResolve > 0 { parts.append("解析目标失败 \(droppedResolve)") }
        if sendFails > 0 { parts.append("发送失败 \(sendFails)") }
        if replyFails > 0 { parts.append("回包失败 \(replyFails)") }
        return parts.joined(separator: " · ")
    }

    public func snapshot() -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        return [
            "port": port,
            "raw": packetsRaw,
            "in": packetsIn,
            "out": packetsOut,
            "upstreams": upstreams.count,
            "wrongSource": droppedWrongSource,
            "parseFails": droppedParse,
            "resolveFails": droppedResolve,
            "sendFails": sendFails,
            "replyFails": replyFails,
        ]
    }

    // ── 诊断日志 ────────────────────────────────────────────

    /// 同类异常只打前几条，之后静默计数（关闭时汇总）。
    private func note(_ text: String, kind: String) {
        lock.lock()
        let count = loggedKinds[kind, default: 0]
        let allow = count < UdpRelay.logLimitPerKind
        loggedKinds[kind] = count + 1
        let total = loggedKinds[kind] ?? 0
        lock.unlock()
        guard allow else { return }
        if total == UdpRelay.logLimitPerKind {
            log("[udp] \(text)（同类后续只计数，关闭时汇总）")
        } else {
            log("[udp] \(text)")
        }
    }

    // ── 小工具 ──────────────────────────────────────────────

    static func nowMs() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    static func address(_ ip: String, _ port: Int) -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        inet_pton(AF_INET, ip, &address.sin_addr)
        return address
    }

    static func address6(_ ip: String, _ port: Int) -> sockaddr_in6 {
        var address = sockaddr_in6()
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = in_port_t(UInt16(port).bigEndian)
        inet_pton(AF_INET6, ip, &address.sin6_addr)
        return address
    }

    static func text(_ address: in_addr) -> String {
        var raw = address
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &raw, &buffer, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buffer)
    }
}
