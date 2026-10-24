import Foundation
import Darwin
import StarRadarCore

/**
 局域网 SOCKS5 服务端 —— 与 `Socks5Server.kt` 等价。

 ## 它解决的是哪件事

 ```
   另一台设备（PC / 另一台手机）          本机（这台 iPhone）
   ┌──────────────────────┐              ┌───────────────────────┐
   │ sing-box / SR / Neko │──SOCKS5────▶ │ 本服务                │
   │ 把全局流量交给代理    │              │  ├ 65010 → MITM 抓母料 │
   └──────────────────────┘              │  ├ 其它端口 → 直连转发 │
                                          │  └ UDP → 过滤后上报    │
                                          └───────────────────────┘
 ```

 ## 为什么 CONNECT 要按端口分流

 只有对局端口（默认 65010）的字节流是 TGCP 帧、可以翻译。其余端口
 （443 / 80 / CDN / 系统更新）走的是完全不同的协议 —— 把它们的载荷塞进
 TGCP 分帧器会立刻抛错并断连。而另一台设备开着 TUN 模式时，**绝大多数
 流量都是这些非对局连接**，不分流就等于「代理一开就断网」。

 ## 为什么一条连接一个线程

 Android 端在这里踩过一个致命 bug：连接池用了**无界队列**，而
 `ThreadPoolExecutor` 只在「队列满了」才扩容 —— 无界队列永远不会满，
 于是全程只有 2 个工作线程，第二条之后的连接连握手都收不到响应，而 TCP
 三次握手是内核完成的，客户端看起来是「连上了、但没网络」。

 iOS 这边直接用「一条连接一个 Thread」，从结构上不存在这个问题；
 `workerStats()` 仍然保留，供界面显示连接数与线程数是否匹配。
 */
public final class Socks5Server {

    public static let handshakeTimeoutMs = 12_000
    public static let connectTimeoutMs = 10_000
    /// 同时在处理的连接上限。超了直接拒（而不是排队 —— 排队会让客户端一直等）。
    public static let maxConnections = 256
    public static let halfCloseGraceMs = 3000

    /// 同时存在的 UDP 关联上限。
    ///
    /// 客户端在 UDP 不通时会不停地重开关联，而**旧的往往不关**（现场见过
    /// 40 秒内 18 个）。每个关联占 1 个控制连接 + 1 个 relay socket + 1 个
    /// 线程，不设上限就是稳定泄漏，最后连 TCP 都开不出来。
    /// 超过上限时关掉最老的那个 —— 新的那个才是客户端现在在用的。
    public static let maxRelays = 32

    public let port: Int
    public let targetPorts: Set<Int>

    private let onUdp: (String, Int, String, Int, [UInt8], Bool) -> Void
    private let onKey: (KeyMaterial) -> Void
    private let advertiseIp: () -> String
    private let user: String
    private let password: String
    private let log: (String) -> Void

    private var listener: NetSocket?
    private var acceptThread: Thread?
    private var running = false
    private let lock = NSLock()

    private var clients: [Int32: NetSocket] = [:]
    private var relays: [UdpRelay] = []

    public private(set) var connects: Int64 = 0
    public private(set) var channelTcp: Int64 = 0
    public private(set) var plainTcp: Int64 = 0
    public private(set) var udpAssoc: Int64 = 0
    public private(set) var rejected: Int64 = 0
    public private(set) var active: Int64 = 0
    public private(set) var udpIn: Int64 = 0
    public private(set) var udpOut: Int64 = 0
    public private(set) var bytesIn: Int64 = 0
    public private(set) var bytesOut: Int64 = 0
    public private(set) var error = ""

    /// 实际绑定到的端口（传入 0 时由系统分配，测试要用）。
    public private(set) var boundPort = 0

    public init(port: Int, targetPorts: Set<Int>,
                onUdp: @escaping (String, Int, String, Int, [UInt8], Bool) -> Void,
                onKey: @escaping (KeyMaterial) -> Void,
                advertiseIp: @escaping () -> String,
                user: String = "", password: String = "",
                log: @escaping (String) -> Void = { _ in }) {
        self.port = port
        self.targetPorts = targetPorts
        self.onUdp = onUdp
        self.onKey = onKey
        self.advertiseIp = advertiseIp
        self.user = user
        self.password = password
        self.log = log
    }

    // ── 生命周期 ──────────────────────────────────────────────

    public func start() -> Bool {
        do {
            let socket = try NetSocket.listen(port: port)
            listener = socket
            boundPort = socket.localPort()
            running = true
            let thread = Thread { [weak self] in self?.acceptLoop(socket) }
            thread.name = "s5-accept"
            thread.stackSize = 256 * 1024
            acceptThread = thread
            thread.start()
            log("[s5] 已就绪（0.0.0.0:\(boundPort)）")
            return true
        } catch {
            // 端口被占是最常见的失败。要把端口号说出来，否则用户只看到
            // 「启动失败」，完全不知道该改哪里。
            let message = (error as? ProxyError)?.message ?? "未知错误"
            self.error = "监听 0.0.0.0:\(port) 失败：\(message)"
            log("[s5] \(self.error)")
            return false
        }
    }

    public func stop() {
        running = false
        listener?.close()
        listener = nil
        acceptThread = nil

        lock.lock()
        let allRelays = relays
        relays.removeAll()
        let allClients = clients
        clients.removeAll()
        lock.unlock()

        for relay in allRelays { relay.close() }
        for (_, socket) in allClients { socket.close() }
    }

    private func acceptLoop(_ socket: NetSocket) {
        while running {
            let accepted: (NetSocket, String)
            do {
                accepted = try socket.accept()
            } catch {
                if running {
                    log("[s5] accept 结束：\((error as? ProxyError)?.message ?? "未知")")
                }
                break
            }
            let (client, peer) = accepted
            lock.lock()
            if clients.count >= Socks5Server.maxConnections {
                lock.unlock()
                rejected += 1
                log("[s5] 连接数已满（\(Socks5Server.maxConnections)），拒绝新连接")
                client.close()
                continue
            }
            clients[client.fd] = client
            lock.unlock()

            let thread = Thread { [weak self] in
                self?.serveClient(client, peer)
            }
            thread.name = "s5-conn"
            thread.stackSize = 256 * 1024
            thread.start()
        }
    }

    // ── 单条连接 ──────────────────────────────────────────────

    private func serveClient(_ client: NetSocket, _ peer: String) {
        active += 1
        // fd 要在关闭**之前**记下来：隧道/转发内部会先 close，
        // 之后 client.fd 变成 -1，用 -1 去 remove 就找不到原条目（字典泄漏）。
        let fdKey = client.fd
        defer {
            active -= 1
            lock.lock()
            clients.removeValue(forKey: fdKey)
            lock.unlock()
            client.close()
        }
        do {
            client.setNoDelay()
            client.setRecvTimeout(ms: Socks5Server.handshakeTimeoutMs)

            let negotiated = try negotiate(client)
            guard negotiated else { return }
            guard let request = try readRequest(client) else { return }

            switch request.command {
            case Socks5Proto.cmdConnect:
                try doConnect(client, peer, request.host, request.port)
            case Socks5Proto.cmdUdpAssociate:
                try doUdpAssociate(client, peer)
            default:
                try reply(client, Socks5Proto.repCmdUnsupported)
                log("[s5] 不支持的命令 \(Socks5Proto.commandName(request.command))")
            }
        } catch {
            // 客户端断开 / 超时：正常现象，不刷日志
        }
    }

    // ── 方法协商 ──────────────────────────────────────────────

    /// 配置了用户名密码就**只接受** 0x02，否则只接受 0x00 ——
    /// 「配置了密码却也放行无认证」等于密码没设。
    private func negotiate(_ client: NetSocket) throws -> Bool {
        let head = try client.readFully(2)
        let version = head[0]
        let count = Int(head[1])
        if version != Socks5Proto.version {
            // 不是 SOCKS5，可能是 HTTP 之类误连。直接断，不回任何东西
            // （回 0x05 会让某些客户端反复重试）。
            return false
        }
        if count == 0 { return false }
        let methods = try client.readFully(count)

        let want = user.isEmpty ? Socks5Proto.methodNoAuth : Socks5Proto.methodUserPass
        if !methods.contains(want) {
            try client.write([Socks5Proto.version, Socks5Proto.methodNone])
            rejected += 1
            return false
        }
        try client.write([Socks5Proto.version, want])

        if want == Socks5Proto.methodUserPass {
            let passed = try checkUserPass(client)
            if !passed {
                rejected += 1
                return false
            }
        }
        return true
    }

    /// RFC 1929：`VER(1) ULEN UNAME PLEN PASSWD` → `VER(1) STATUS`。
    private func checkUserPass(_ client: NetSocket) throws -> Bool {
        let head = try client.readFully(2)
        if head[0] != 1 { return false }
        let nameLength = Int(head[1])
        let name = try client.readFully(nameLength)
        let passLength = Int(try client.readFully(1)[0])
        let pass = try client.readFully(passLength)

        let ok = String(decoding: name, as: UTF8.self) == user &&
            String(decoding: pass, as: UTF8.self) == password
        try client.write([1, ok ? 0 : 1])
        return ok
    }

    // ── 请求行 ────────────────────────────────────────────────

    private func readRequest(_ client: NetSocket) throws -> Socks5Proto.Request? {
        let head = try client.readFully(4)
        let version = head[0]
        let command = head[1]
        let atyp = head[3]
        if version != Socks5Proto.version { return nil }

        let host: String
        switch atyp {
        case Socks5Proto.atypIPv4:
            let raw = try client.readFully(4)
            host = "\(raw[0]).\(raw[1]).\(raw[2]).\(raw[3])"
        case Socks5Proto.atypIPv6:
            let raw = try client.readFully(16)
            host = Socks5Proto.ipv6Text(raw)
        case Socks5Proto.atypDomain:
            let length = Int(try client.readFully(1)[0])
            let raw = try client.readFully(length)
            host = String(decoding: raw, as: UTF8.self)
        default:
            try reply(client, Socks5Proto.repAtypUnsupported)
            return nil
        }
        let portBytes = try client.readFully(2)
        let port = (Int(portBytes[0]) << 8) | Int(portBytes[1])
        return Socks5Proto.Request(command: command, host: host, port: port)
    }

    private func reply(_ client: NetSocket, _ code: UInt8,
                       _ host: String = "0.0.0.0", _ port: Int = 0) throws {
        try client.write(Socks5Proto.reply(code, host: host, port: port))
    }

    // ── CONNECT ───────────────────────────────────────────────

    private func doConnect(_ client: NetSocket, _ peer: String,
                           _ rawHost: String, _ dstPort: Int) throws {
        // 第一条连接记一条：这是「另一台设备真的连进来了」的唯一直接证据。
        if connects == 0 && channelTcp == 0 && plainTcp == 0 {
            log("[s5] 收到第一条连接（目标端口 \(dstPort)）")
        }
        guard let dstIp = try HostResolver.ipv4(rawHost) else {
            try reply(client, Socks5Proto.repHostUnreach)
            log("[s5] 域名解析失败（目标端口 \(dstPort)）")
            return
        }

        // 对局端口交给帧翻译通道；其余端口普通转发。
        let isTarget = targetPorts.contains(dstPort)
        let upstream: NetSocket
        do {
            upstream = try NetSocket.connect(host: dstIp, port: dstPort,
                                             timeoutMs: Socks5Server.connectTimeoutMs)
        } catch {
            let message = (error as? ProxyError)?.message ?? "连接失败"
            let refused = message.contains("拒绝")
            try? reply(client, refused ? Socks5Proto.repRefused
                       : Socks5Proto.repNetUnreach)
            // 失败必须留痕。只记端口与原因 —— 目标 IP 属于敏感信息，不进日志。
            log("[s5] 连不上目标端口 \(dstPort)（\(message)）")
            return
        }

        // 上游通了才回成功 —— 先回成功再连的话，客户端会以为通了，
        // 于是一路往里写数据，最终表现成「连上了但没反应」。
        try reply(client, Socks5Proto.repOK, upstream.localIPv4(),
                  upstream.localPort())

        connects += 1
        if isTarget { log("[s5] 对局通道已建立（:\(dstPort)）") }

        defer { upstream.close() }
        client.setRecvTimeout(ms: 0)          // 长连接不再有握手超时

        if isTarget {
            channelTcp += 1
            SocketTunnel(client: client, upstream: upstream,
                         sessionInfo: { (dstIp, dstPort) },
                         onKey: onKey, log: log).run()
        } else {
            plainTcp += 1
            plainPipe(client, upstream, dstPort)
        }
    }

    /**
     普通 TCP 转发（不碰载荷）。

     与帧翻译路径的关键差别：**任何一端半关闭都要传给另一端**，而不是立刻
     把两边都关掉。HTTP 的 chunked、以及大部分长连接都会「发完就关写端、
     继续读」，砍掉另一头会让客户端拿到残缺响应。
     */
    private func plainPipe(_ client: NetSocket, _ upstream: NetSocket,
                           _ dstPort: Int) {
        let started = Date()
        let upExit = ExitSignal(tag: "c2s")
        let downExit = ExitSignal(tag: "s2c")

        let a = Thread { [weak self] in
            self?.pipe(client, upstream, true, upExit)
        }
        a.name = "s5-htp-c2s"
        a.stackSize = 512 * 1024
        let b = Thread { [weak self] in
            self?.pipe(upstream, client, false, downExit)
        }
        b.name = "s5-htp-s2c"
        b.stackSize = 512 * 1024
        a.start()
        b.start()

        // ⚠️ 这里的语义是「不限时等某个方向结束，再给另一个 3 秒收尾」。
        // 曾经写成「最多等 3 秒就无条件关」—— 那等于给每条转发连接设了
        // 3 秒寿命，另一台设备的网页、API 全部打不开（表现为整个断网，
        // 而不只是某个游戏掉线）。
        let outcome = ThreadJoin.either(upExit, downExit,
                                        graceMs: Socks5Server.halfCloseGraceMs) {
            // 只有「一方结束后另一方仍卡着」才会走到这里。
            // 先 shutdown 再 close：close 唤不醒另一个线程里阻塞的 read。
            client.shutdownBoth()
            upstream.shutdownBoth()
        }
        client.close()
        upstream.close()

        // 普通转发是最常见的连接（网页/API/HTTPS 全是），所以这里只在
        // 「非正常结束」时打日志：正常 EOF 不刷屏，异常才留痕。
        let abnormal = outcome.forced || outcome.firstReason.contains("读失败")
        if abnormal {
            let seconds = String(format: "%.1f", Date().timeIntervalSince(started))
            log("[s5] 转发异常结束（:\(dstPort) · 持续 \(seconds)s · "
                + "先退出：\(outcome.firstExit)（\(outcome.firstReason)）"
                + (outcome.forced ? " · 另一方向被强制断开" : "") + "）")
        }
    }

    /// 单向泵：读 from 写 to，EOF 时把 EOF 传给 to。
    private func pipe(_ from: NetSocket, _ to: NetSocket, _ isUp: Bool,
                      _ exit: ExitSignal) {
        var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = from.read(&buffer)
            if count < 0 {
                let code = errno
                if code == EINTR { continue }
                // 读超时不能当连接结束（见 SocketTunnel.pump 的同类注释）
                if code == EAGAIN || code == EWOULDBLOCK { continue }
                exit.fire("读失败 errno \(code)")
                return
            }
            if count == 0 {
                exit.fire("对端 EOF")
                break
            }
            do {
                try to.write(Array(buffer[0..<count]))
            } catch {
                exit.fire("写对端失败")
                break
            }
            if isUp { bytesIn += Int64(count) } else { bytesOut += Int64(count) }
        }
        to.shutdownWrite()
    }

    // ── UDP ASSOCIATE ─────────────────────────────────────────

    private func doUdpAssociate(_ client: NetSocket, _ peer: String) throws {
        let relay = UdpRelay(clientIp: peer,
                             onUdp: { [weak self] srcIp, srcPort, dstIp, dstPort, payload, up in
            self?.relayNote(up, payload.count)
            self?.onUdp(srcIp, srcPort, dstIp, dstPort, payload, up)
        }, log: log)
        guard relay.open() else {
            try reply(client, Socks5Proto.repFailure)
            return
        }
        let bindIp = advertiseIp()
        try reply(client, Socks5Proto.repOK, bindIp, relay.port)
        udpAssoc += 1

        lock.lock()
        relays.append(relay)
        var evicted: UdpRelay?
        if relays.count > Socks5Server.maxRelays {
            evicted = relays.removeFirst()
        }
        lock.unlock()
        if let evicted {
            log("[s5] UDP 关联数超过 \(Socks5Server.maxRelays)，关闭最老的一个"
                + "（\(evicted.summaryLine())）")
            evicted.close()
        }

        relay.start()
        log("[s5] UDP 关联已建立（\(bindIp):\(relay.port) · 对端 \(peer)）")

        // 5 秒后如果这个关联一个包都没收到，就明确告警。
        //
        // 这一条是整个 UDP 排查的分水岭：
        //   · 有告警 → 客户端的 UDP 根本没到达本机（广告地址不对 / 局域网
        //     不放行 UDP / 客户端把它发给了别的地址）
        //   · 没告警但客户端仍不通 → 包到了但转不出去，看 relay 内部的
        //     「解析失败 / 发送失败」那几行
        // 以前这两种情况在日志里长得一模一样（什么都没有）。
        DispatchQueue.global().asyncAfter(
            deadline: .now() + .milliseconds(Int(UdpRelay.probeAfterMs))
        ) { [weak relay] in
            guard let relay, relay.isRunning else { return }
            let seconds = UdpRelay.probeAfterMs / 1000
            if relay.packetsRaw == 0 {
                self.log("[s5] ⚠️ UDP 关联 \(bindIp):\(relay.port) 建立 "
                         + "\(seconds) 秒仍未收到任何 UDP 包（对端 \(peer)）")
                self.log("[s5]    包的层面就没到：确认客户端把 UDP 发到了 "
                         + "\(bindIp):\(relay.port)，且局域网放行 UDP")
            } else if relay.packetsIn == 0 {
                // 到了却被源地址校验挡掉 —— 这条以前完全看不见
                self.log("[s5] ⚠️ UDP 关联 \(bindIp):\(relay.port) 收到 "
                         + "\(relay.packetsRaw) 个包但全部被源地址校验挡掉"
                         + "（申请者 \(peer)）")
            }
        }

        defer {
            lock.lock()
            relays.removeAll { $0 === relay }
            lock.unlock()
            log("[s5] UDP 关联已关闭（\(relay.summaryLine())）")
            relay.close()
        }

        // 这条 TCP 连接的生命周期就是 UDP 关联的生命周期（RFC 1928）：
        // 客户端断开 → relay 关闭。所以这里要把控制连接读到 EOF。
        client.setRecvTimeout(ms: 0)
        var scratch = [UInt8](repeating: 0, count: 512)
        while true {
            let count = client.read(&scratch)
            if count <= 0 {
                if count < 0 && errno == EINTR { continue }
                break
            }
        }
    }

    private func relayNote(_ up: Bool, _ size: Int) {
        if up {
            udpIn += 1
            bytesIn += Int64(size)
        } else {
            udpOut += 1
            bytesOut += Int64(size)
        }
    }

    // ── 诊断 ─────────────────────────────────────────────────

    /// 清掉所有已建立的连接，让客户端重新连。
    ///
    /// 用在「App 曾被系统挂起」之后：挂起期间没有人读这些 socket，客户端那边
    /// 看到的是一条**还活着但没有任何响应**的连接 —— 它不会立刻重连，而是要
    /// 等 TCP 重传超时（几分钟）。主动 shutdown 能让客户端立刻收到 RST、
    /// 马上重新发起 CONNECT，体感上是「卡一下就好了」而不是「一直没网」。
    ///
    /// 用 shutdown 而不是 close：阻塞在 read 上的隧道线程要靠 SHUT_RDWR
    /// 才能立刻返回，光 close 不保证唤醒。
    @discardableResult
    public func dropStaleClients(reason: String) -> Int {
        lock.lock()
        let all = clients
        clients.removeAll()
        let allRelays = relays
        relays.removeAll()
        lock.unlock()

        for (_, socket) in all { socket.shutdownBoth() }
        for relay in allRelays { relay.close() }

        if !all.isEmpty {
            log("[s5] 已断开 \(all.count) 条僵死连接（\(reason)），等客户端重连")
        }
        return all.count
    }

    /// (当前连接数, 排队数)。iOS 是一条连接一个线程，队列恒为 0；
    /// 保留这个形状是为了与 Android 端界面一致，便于对照排查。
    public func workerStats() -> (Int, Int) {
        lock.lock()
        defer { lock.unlock() }
        return (clients.count, 0)
    }

    public func snapshot() -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        return [
            "listening": running,
            "port": boundPort,
            "workers": clients.count,
            "queuedTasks": 0,
            "connects": connects,
            "channelTcp": channelTcp,
            "plainTcp": plainTcp,
            "udpAssoc": udpAssoc,
            "rejected": rejected,
            "active": active,
            "udpIn": udpIn,
            "udpOut": udpOut,
            "bytesIn": bytesIn,
            "bytesOut": bytesOut,
            "relays": relays.count,
            "error": error,
        ]
    }
}
