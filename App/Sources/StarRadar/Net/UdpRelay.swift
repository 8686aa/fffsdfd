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

 sing-box / NekoBox / Shadowrocket 的 TUN 模式都会把 UDP（含对局流、DNS、
 QUIC）交给 SOCKS5 的 UDP ASSOCIATE。所以这里是**唯一**能看到对局 UDP 的
 地方 —— 上报链路能不能拿到数据，全看这一层对不对。

 ## 安全：只服务申请者

 只接受「申请这个 relay 的那个客户端 IP」发来的包。否则任何能连到这台
 手机 UDP 端口的人都能拿它当开放中继（放大攻击的跳板）。某些客户端会用
 不同的源端口，所以只校验 IP、不校验端口。

 ## 每个目标一个 socket

 一个 UDP socket 只能配一个远端地址。对局同时会连好几个目标（选服、
 心跳、战斗服），所以按 (ip, port) 各开一个 —— 代价是 fd 多几个，
 换来的是「回包不会串台」。
 */
public final class UdpRelay {

    public static let idleTimeoutMs: Int64 = 60_000
    public static let maxUpstreams = 128
    public static let recvTimeoutMs = 500

    private final class Upstream {
        let fd: Int32
        var thread: Thread?
        var lastActive: Int64

        init(fd: Int32, lastActive: Int64) {
            self.fd = fd
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

    public private(set) var udpIn: Int64 = 0
    public private(set) var udpOut: Int64 = 0
    public private(set) var bytesIn: Int64 = 0
    public private(set) var bytesOut: Int64 = 0

    public init(clientIp: String,
                onUdp: @escaping (String, Int, String, Int, [UInt8], Bool) -> Void,
                log: @escaping (String) -> Void = { _ in }) {
        self.clientIp = clientIp
        self.onUdp = onUdp
        self.log = log
    }

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
        thread.stackSize = 256 * 1024
        self.thread = thread
        thread.start()
    }

    // ── 客户端 → 目标 ────────────────────────────────────────

    private func loop() {
        var buffer = [UInt8](repeating: 0, count: Socks5Proto.maxUdpPacket)
        while running {
            var from = sockaddr_in()
            var fromLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let received = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return withUnsafeMutablePointer(to: &from) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        recvfrom(fd, base, buffer.count, 0, $0, &fromLength)
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
            // 只服务申请者
            if !clientIp.isEmpty && fromIp != clientIp { continue }

            let data = Array(buffer[0..<received])
            guard let parsed = Socks5Proto.parseUdp(data), parsed.port != 0 else {
                continue
            }
            clientAddress = from

            guard let targetIp = resolve(parsed.host) else { continue }

            lock.lock()
            udpIn += 1
            bytesIn += Int64(parsed.payload.count)
            lock.unlock()

            report(fromIp, Int(UInt16(bigEndian: from.sin_port)),
                   targetIp, parsed.port, parsed.payload, true)
            forward(targetIp, parsed.port, parsed.payload)
        }
    }

    private func forward(_ targetIp: String, _ port: Int, _ payload: [UInt8]) {
        let key = "\(targetIp):\(port)"
        lock.lock()
        if let existing = upstreams[key] {
            existing.lastActive = Self.nowMs()
            let handle = existing.fd
            lock.unlock()
            var address = Self.address(targetIp, port)
            _ = payload.withUnsafeBytes { raw in
                withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(handle, raw.baseAddress, payload.count, 0, $0,
                               socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            return
        }
        if upstreams.count >= UdpRelay.maxUpstreams {
            // 满了：关掉最老的一个，不要拒绝新目标 —— 对局换服时新目标
            // 才是重要的那个。
            if let oldest = upstreams.min(by: { $0.value.lastActive < $1.value.lastActive }) {
                upstreams.removeValue(forKey: oldest.key)
                Darwin.close(oldest.value.fd)
            }
        }
        lock.unlock()
        openUpstream(key, targetIp, port, payload)
    }

    private func openUpstream(_ key: String, _ targetIp: String, _ port: Int,
                              _ first: [UInt8]) {
        let handle = socket(AF_INET, SOCK_DGRAM, 0)
        if handle < 0 {
            log("[udp] 建上游 socket 失败（errno \(errno)）")
            return
        }
        // 「已连接」的 UDP socket：回包只会来自这个目标，不需要自己比对地址
        var address = Self.address(targetIp, port)
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(handle, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if connected != 0 {
            log("[udp] 连不上 \(key)（errno \(errno)）")
            Darwin.close(handle)
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
            log("[udp] 发往 \(key) 失败（errno \(errno)）")
            Darwin.close(handle)
            return
        }

        let entry = Upstream(fd: handle, lastActive: Self.nowMs())
        let thread = Thread { [weak self] in
            self?.upstreamLoop(key, handle)
        }
        thread.name = "s5-udp-up-\(port)"
        thread.stackSize = 256 * 1024
        entry.thread = thread

        lock.lock()
        upstreams[key] = entry
        lock.unlock()
        thread.start()
    }

    // ── 目标 → 客户端 ────────────────────────────────────────

    private func upstreamLoop(_ key: String, _ handle: Int32) {
        var buffer = [UInt8](repeating: 0, count: Socks5Proto.maxUdpPacket)
        let parts = key.split(separator: ":")
        guard parts.count == 2, let targetPort = Int(parts[1]) else { return }
        let targetIp = String(parts[0])

        while running {
            let received = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.recv(handle, base, buffer.count, 0)
            }
            if received <= 0 {
                if received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    lock.lock()
                    let idle = upstreams[key].map {
                        Self.nowMs() - $0.lastActive
                    } ?? 0
                    lock.unlock()
                    if idle > UdpRelay.idleTimeoutMs {
                        closeUpstream(key)
                        return
                    }
                    continue
                }
                if received < 0 && errno == EINTR { continue }
                return
            }
            let data = Array(buffer[0..<received])
            lock.lock()
            upstreams[key]?.lastActive = Self.nowMs()
            udpOut += 1
            bytesOut += Int64(data.count)
            let destination = clientAddress
            lock.unlock()

            guard let destination else { continue }
            let clientPort = Int(UInt16(bigEndian: destination.sin_port))
            let clientText = Self.text(destination.sin_addr)

            // 下行也必须上报：解码端是按「请求/回包成对」解流的，只送上行
            // 会一直停在「等配对」上 —— 页面上看着正常，节点侧读不出内容。
            report(targetIp, targetPort, clientText.isEmpty ? clientIp : clientText,
                   clientPort, data, false)

            sendToClient(targetIp, targetPort, data, destination)
        }
    }

    private func sendToClient(_ targetIp: String, _ targetPort: Int,
                              _ payload: [UInt8], _ destination: sockaddr_in) {
        if fd < 0 { return }
        let framed = Socks5Proto.buildUdp(targetIp, targetPort, payload)
        var address = destination
        _ = framed.withUnsafeBytes { raw in
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, raw.baseAddress, framed.count, 0, $0,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    // ── 上报 ────────────────────────────────────────────────

    private func report(_ srcIp: String, _ srcPort: Int, _ dstIp: String,
                        _ dstPort: Int, _ payload: [UInt8], _ up: Bool) {
        // 上报失败不影响转发
        onUdp(srcIp, srcPort, dstIp, dstPort, payload, up)
    }

    // ── 域名解析（带缓存）────────────────────────────────────

    private func resolve(_ host: String) -> String? {
        if host.isEmpty { return nil }
        if IpDatagram.isIpv4(host) { return host }
        lock.lock()
        if let cached = dnsCache[host] {
            lock.unlock()
            return cached
        }
        lock.unlock()
        // HostResolver.ipv4 返回 String?，`try?` 会把它 flatten 成 String?，
        // 所以只需要解一层。写成 `guard let ip = try?, let value = ip` 会因为
        // ip 已经是 String 而报 "must have Optional type"。
        guard let value = try? HostResolver.ipv4(host) else { return nil }
        lock.lock()
        if dnsCache.count > 128 { dnsCache.removeAll() }
        dnsCache[host] = value
        lock.unlock()
        return value
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

    public func snapshot() -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        return [
            "port": port,
            "in": udpIn,
            "out": udpOut,
            "bytesIn": bytesIn,
            "bytesOut": bytesOut,
            "upstreams": upstreams.count,
        ]
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

    static func text(_ address: in_addr) -> String {
        var raw = address
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &raw, &buffer, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buffer)
    }
}
