import Foundation
import StarRadarCore

/**
 一条被翻译的 SOCKS5 连接 —— 两端都是系统 socket。

 ```
   另一台设备 ──SOCKS5 CONNECT──▶ 本机 socket ──▶ TgcpEngine c2s ──▶ 真服务器
   另一台设备 ◀──本机 socket ────── TgcpEngine s2c ◀── 真服务器
 ```

 ## 写操作为什么要各自加锁

 每个方向的 socket 可能被**两个**线程写：一帧的直接发送在读取线程上，
 而「握手前缓存的帧补发」发生在另一个方向解析到 hello 的那个线程上。
 不锁的话两个 TGCP 帧会交错，对端分帧立刻错位 —— 现象是「握手成功、
 之后全是垃圾」。

 ## 半关闭

 客户端发完请求就关写端是合法行为，服务器此时还在回包。所以客户端 EOF
 不能直接 close —— 要把 EOF 传给上游，给它一段宽限把剩下的数据回完。
 */
public final class SocketTunnel {

    /// 客户端关写端之后，等服务器把剩下的回完的宽限。
    public static let halfCloseGraceMs = 3000

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
        weak var owner: SocketTunnel?

        func toClient(_ data: [UInt8]) {
            owner?.writeClient(data)
        }

        func toUpstream(_ data: [UInt8]) {
            owner?.writeUpstream(data)
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
        let sink = SinkImpl()
        sink.owner = self
        engine.sink = sink

        let c2s = Thread { [weak self] in
            guard let self else { return }
            self.pump(self.client, "client",
                      onData: { engine.feedC2s($0) },
                      onEnd: { self.upstream.shutdownWrite() })
        }
        c2s.name = "tun-c2s"
        c2s.stackSize = 256 * 1024

        let s2c = Thread { [weak self] in
            guard let self else { return }
            self.pump(self.upstream, "server",
                      onData: { engine.feedS2c($0) },
                      onEnd: { self.client.shutdownWrite() })
        }
        s2c.name = "tun-s2c"
        s2c.stackSize = 256 * 1024

        c2s.start()
        s2c.start()

        // 等**任一方向**结束，不能只等 c2s：服务器主动关连接很常见
        // （HTTP 短连接、游戏踢人、目标端口不存在时的 RST），那种情况下
        // c2s 还在安静地等客户端，而客户端可能永远不发也不关。
        ThreadJoin.either(c2s, s2c, graceMs: SocketTunnel.halfCloseGraceMs) {
            self.client.close()
            self.upstream.close()
        }
        client.close()
        upstream.close()

        let stats = engine.snapshot()
        log("[tun] 连接结束（\(stats["framesC2s"] ?? 0)/\(stats["framesS2c"] ?? 0) 帧）")
    }

    /// 读一侧的字节并喂给引擎。`onData` 返回 false 表示流已错位，立刻停。
    private func pump(_ socket: NetSocket, _ name: String,
                      onData: ([UInt8]) -> Bool,
                      onEnd: () -> Void) {
        var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = socket.read(&buffer)
            if count < 0 {
                if errno == EINTR { continue }
                break
            }
            if count == 0 {
                log("[tun] \(name) 方向 EOF")
                onEnd()
                break
            }
            if !onData(Array(buffer[0..<count])) { break }
        }
    }
}
