import Foundation
import StarRadarCore

/**
 一条被翻译的 SOCKS5 连接 —— 两端都是系统 socket。

 ```
   另一台设备 ──SOCKS5 CONNECT──▶ 本机 socket ──▶ TgcpEngine c2s ──▶ 真服务器
   另一台设备 ◀──本机 socket ────── TgcpEngine s2c ◀── 真服务器
 ```

 ## 写操作为什么要各自加锁

 每个方向的 socket 可能被**两个**线程写：一帧的直接发送在读取线程上，而
 「握手前缓存的帧补发」发生在另一个方向解析到 hello 的那个线程上。不锁的话
 两个 TGCP 帧会交错，对端分帧立刻错位 —— 现象是「握手成功、之后全是垃圾」。

 ## 半关闭

 客户端发完请求就关写端是合法行为，服务器此时还在回包。所以客户端 EOF 不能
 直接 close —— 要把 EOF 传给上游，给它一段宽限把剩下的数据回完。

 ## 退出诊断

 每条连接结束时会打一行完整结论：持续时长、两方向帧数、谁先退出、退出原因、
 最后几帧的轨迹。排「连上就断」这类问题时，这一行基本就能定位：
 是服务器关的、是我们分帧失败的、还是客户端走了。
 */
public final class SocketTunnel {

    /// 客户端关写端之后，等服务器把剩下的回完的宽限。
    public static let halfCloseGraceMs = 3000

    /// 帧轨迹保留条数。够看清退出前发生了什么，又不会吃内存。
    public static let traceKeep = 12

    private let client: NetSocket
    private let upstream: NetSocket
    private let sessionInfo: () -> (String, Int)
    private let onKey: (KeyMaterial) -> Void
    private let log: (String) -> Void

    private let clientLock = NSLock()
    private let upstreamLock = NSLock()

    public init(client: NetSocket, upstream: NetSocket,
                sessionInfo: @escaping () -> (String, Int),
                onKey: @escaping (KeyMaterial) -> Void,
                log: @escaping (String) -> Void = { _ in }) {
        self.client = client
        self.upstream = upstream
        self.sessionInfo = sessionInfo
        self.onKey = onKey
        self.log = log
    }

    private final class SinkImpl: TgcpEngine.Sink {
        /// **强引用** owner。
        ///
        /// 这里踩过一个很危险的坑，值得写下来：`TgcpEngine.sink` 是 `weak`，
        /// 所以 sink 必须由调用方强持有。曾经把赋值写成
        /// `engine.sink = SinkImpl(owner: self)`（临时对象）—— 赋值完临时对象
        /// 立刻释放，`engine.sink` 当场变成 nil，于是**所有翻译后的数据都被
        /// 静默丢弃**：socket 两端都开着、对端收不到任何回包、最后超时断开，
        /// 而现场日志里连一个错误都没有。
        ///
        /// 所以：sink 由 `run()` 的局部变量强持有，sink 自己强引用 owner。
        /// 这样既不会提前释放，也不会因为 owner 释放而崩溃（owner 由 run()
        /// 的栈帧保证存活，退出时 sink 随之释放）。
        let owner: SocketTunnel

        init(owner: SocketTunnel) {
            self.owner = owner
        }

        func toClient(_ data: [UInt8]) {
            owner.writeClient(data)
        }

        func toUpstream(_ data: [UInt8]) {
            owner.writeUpstream(data)
        }
    }

    private func writeClient(_ data: [UInt8]) {
        clientLock.lock()
        defer { clientLock.unlock() }
        do {
            try client.write(data)
        } catch {
            log("[tun] 写客户端失败：\((error as? ProxyError)?.message ?? "未知")")
        }
    }

    private func writeUpstream(_ data: [UInt8]) {
        upstreamLock.lock()
        defer { upstreamLock.unlock() }
        do {
            try upstream.write(data)
        } catch {
            log("[tun] 写上游失败：\((error as? ProxyError)?.message ?? "未知")")
        }
    }

    public func run() {
        let engine = TgcpEngine(onKey: onKey, sessionInfo: sessionInfo, log: log)
        // ⚠️ 必须用局部变量持有 sink：`engine.sink` 是 weak，写成
        // `engine.sink = SinkImpl(owner: self)` 会让它在下一行就变 nil。
        let sink = SinkImpl(owner: self)
        engine.sink = sink

        let started = Date()
        let c2sExit = ExitSignal(tag: "c2s")
        let s2cExit = ExitSignal(tag: "s2c")

        let c2s = Thread { [weak self] in
            guard let self else {
                c2sExit.fire("tunnel 已释放")
                return
            }
            self.pump(self.client, "客户端→服务器", "c2s", c2sExit,
                      onData: { engine.feedC2s($0) },
                      onEnd: { self.upstream.shutdownWrite() })
        }
        c2s.name = "tun-c2s"
        c2s.stackSize = 512 * 1024

        let s2c = Thread { [weak self] in
            guard let self else {
                s2cExit.fire("tunnel 已释放")
                return
            }
            self.pump(self.upstream, "服务器→客户端", "s2c", s2cExit,
                      onData: { engine.feedS2c($0) },
                      onEnd: { self.client.shutdownWrite() })
        }
        s2c.name = "tun-s2c"
        s2c.stackSize = 512 * 1024

        c2s.start()
        s2c.start()

        // 等**任一方向**结束，不能只等 c2s：服务器主动关连接很常见
        // （HTTP 短连接、游戏踢人、目标端口不存在时的 RST），那种情况下
        // c2s 还在安静地等客户端，而客户端可能永远不发也不关。
        //
        // ⚠️ 语义是「不限时等结束，再给另一方 3 秒收尾」。曾经写成
        // 「最多等 3 秒就无条件收尾」，等于给每条连接设了 3 秒寿命。
        let result = ThreadJoin.either(c2sExit, s2cExit,
                                       graceMs: SocketTunnel.halfCloseGraceMs) {
            // 只有「一方结束后另一方仍卡着」才会走到这里。先 shutdown 再
            // close：close 唤不醒另一个线程里阻塞的 read。
            self.client.shutdownBoth()
            self.upstream.shutdownBoth()
        }
        client.close()
        upstream.close()

        logEnd(engine: engine, started: started, outcome: result)
    }

    private func logEnd(engine: TgcpEngine, started: Date,
                        outcome: ThreadJoin.Outcome) {
        let stats = engine.snapshot()
        let seconds = String(format: "%.1f", Date().timeIntervalSince(started))
        let frames = "\(stats["framesC2s"] ?? 0)/\(stats["framesS2c"] ?? 0) 帧"
        let bytes = "\(stats["bytesC2s"] ?? 0)/\(stats["bytesS2c"] ?? 0) B"

        var line = "[tun] 连接结束（\(frames) · \(bytes) · 持续 \(seconds)s）"
        line += " · 先退出：\(outcome.firstExit.isEmpty ? "无" : outcome.firstExit)"
        if !outcome.firstReason.isEmpty {
            line += "（\(outcome.firstReason)）"
        }
        if outcome.forced {
            line += " · 另一方向宽限到期被强制断开"
        }
        log(line)

        // 引擎自己的失败原因单独打一遍：它通常是「连接为什么结束」的答案
        let engineError = (stats["error"] as? String) ?? ""
        if !engineError.isEmpty {
            log("[tun] 引擎错误：\(engineError)")
        }

        // 最后几帧的轨迹。分帧错位、命令异常这类问题看这一行序列就够。
        if let trace = stats["trace"] as? [String], !trace.isEmpty {
            log("[tun] 最后 \(trace.count) 帧：")
            for item in trace { log("[tun]   \(item)") }
        }
    }

    /// 读一侧的字节并喂给引擎。
    ///
    /// 每个退出路径都会 `exit.fire(reason)`，原因会进结束日志。这一点很关键：
    /// 之前只有一句「连接结束」，无法区分「服务器关的」「我们分帧失败的」
    /// 和「客户端走了」，排查只能靠猜。
    private func pump(_ socket: NetSocket, _ name: String, _ tag: String,
                      _ exit: ExitSignal,
                      onData: ([UInt8]) -> Bool,
                      onEnd: () -> Void) {
        var buffer = [UInt8](repeating: 0, count: 16384)
        var total = 0
        while true {
            let count = socket.read(&buffer)
            if count < 0 {
                // errno 必须在 read 返回后立刻取：后面任何一次系统调用或
                // 内存分配都可能把它覆盖掉。NetSocket.read 内部已保证
                // 返回前不再有别的系统调用。
                let code = errno
                if code == EINTR { continue }
                if code == EAGAIN || code == EWOULDBLOCK {
                    // 读超时不该被当成 EOF 把连接判死。隧道 socket 设的是
                    // 「不超时」，走到这里说明某条路径漏了设置 —— 继续等。
                    continue
                }
                log("[tun] \(name) 读失败（errno \(code)，已读 \(total) 字节）")
                exit.fire("读失败 errno \(code)")
                return
            }
            if count == 0 {
                log("[tun] \(name) 方向 EOF（已读 \(total) 字节）")
                exit.fire("对端 EOF")
                onEnd()
                return
            }
            total += count
            if !onData(Array(buffer[0..<count])) {
                // 引擎判定这条流不能再用（分帧错位 / 翻译失败）。
                // 具体原因引擎自己已经记在 lastError 里并被 logEnd 打出。
                exit.fire("引擎拒绝（流错位）")
                return
            }
        }
    }
}
