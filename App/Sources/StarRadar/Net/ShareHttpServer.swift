import Foundation

/**
 极小的 HTTP 服务 —— 只为了让 sing-box 拉到配置。

 ## 为什么必须有它

 sing-box 的扫码入口是 `sing-box://import-remote-profile?url=...`，它扫完会
 **主动去拉**那个 url。没有 HTTP 服务，那张码扫了也是白屏。

 只实现 GET + 三个路径，不实现 keep-alive（客户端拉一次就走）：
 ```
   /                      纯文本首页（浏览器打开时能看懂这是什么）
   /share/singbox         完整 profile JSON
   /share/shadowrocket    base64 订阅（只放 socks5:// 明文）
   /share/nekobox         base64 订阅（混合风味）
   /share/shadowrocket.conf  Shadowrocket 配置文件
 ```
 */
public final class ShareHttpServer {

    private let preferredPort: Int
    private let target: () -> ShareLinks.Target
    private let title: String
    private let log: (String) -> Void

    private var listener: NetSocket?
    private var thread: Thread?
    private var running = false
    private let lock = NSLock()

    public private(set) var boundPort = 0
    public private(set) var requests: Int64 = 0
    public private(set) var error = ""

    public init(preferredPort: Int, target: @escaping () -> ShareLinks.Target,
                title: String = "", log: @escaping (String) -> Void = { _ in }) {
        self.preferredPort = preferredPort
        self.target = target
        self.title = title
        self.log = log
    }

    /// 起服务。端口被占时**顺延**几个（另一台设备要连的地址里带端口，
    /// 所以顺延后要把实际端口显示出来，不能还用配置值）。
    @discardableResult
    public func start() -> Bool {
        var chosen = 0
        var socket: NetSocket?
        for offset in 0..<8 {
            let candidate = preferredPort + offset
            do {
                socket = try NetSocket.listen(port: candidate)
                chosen = candidate
                break
            } catch {
                continue
            }
        }
        guard let listener = socket else {
            error = "监听 \(preferredPort) 失败（连续 8 个端口都被占用）"
            log("[http] \(error)")
            return false
        }
        self.listener = listener
        boundPort = listener.localPort()
        running = true
        let thread = Thread { [weak self] in self?.acceptLoop(listener) }
        thread.name = "share-http"
        thread.stackSize = 256 * 1024
        self.thread = thread
        thread.start()
        log("[http] 配置服务已就绪（0.0.0.0:\(boundPort)）")
        _ = chosen
        return true
    }

    public func stop() {
        running = false
        listener?.close()
        listener = nil
        thread = nil
    }

    private func acceptLoop(_ socket: NetSocket) {
        while running {
            guard let (client, _) = try? socket.accept() else {
                if running { log("[http] accept 结束") }
                break
            }
            let thread = Thread { [weak self] in self?.serve(client) }
            thread.name = "share-http-conn"
            thread.stackSize = 128 * 1024
            thread.start()
        }
    }

    private func serve(_ client: NetSocket) {
        defer { client.close() }
        client.setRecvTimeout(ms: 5000)

        // 只读请求头：GET 没有 body，读到 \r\n\r\n 就够
        var head: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 1024)
        while head.count < 8192 {
            let count = client.read(&buffer)
            if count <= 0 { break }
            head.append(contentsOf: buffer[0..<count])
            if head.count >= 4 {
                let tail = Array(head[(head.count - 4)...])
                if tail == [13, 10, 13, 10] { break }
            }
        }
        let text = String(decoding: head, as: UTF8.self)
        guard let firstLine = text.components(separatedBy: "\r\n").first else {
            return
        }
        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2 else { return }
        let path = String(parts[1]).components(separatedBy: "?").first ?? "/"

        requests += 1
        let current = target()
        switch path {
        case "/", "/index.html":
            respond(client, 200, "text/plain; charset=utf-8",
                    indexText(current))
        case "/share/singbox":
            respond(client, 200, "application/json; charset=utf-8",
                    ShareLinks.singboxConfigJson(current))
        case "/share/shadowrocket.conf":
            respond(client, 200, "text/plain; charset=utf-8",
                    ShareLinks.shadowrocketConf(current))
        case "/share/shadowrocket":
            respond(client, 200, "text/plain; charset=utf-8",
                    ShareLinks.subscriptionBody(current, flavor: "shadowrocket"))
        case "/share/nekobox":
            respond(client, 200, "text/plain; charset=utf-8",
                    ShareLinks.nekoboxBody(current))
        default:
            respond(client, 404, "text/plain; charset=utf-8", "not found\n")
        }
    }

    private func respond(_ client: NetSocket, _ status: Int, _ type: String,
                         _ body: String) {
        let data = Array(body.utf8)
        var head = "HTTP/1.1 \(status) \(status == 200 ? "OK" : "Not Found")\r\n"
        head += "Content-Type: \(type)\r\n"
        head += "Content-Length: \(data.count)\r\n"
        head += "Cache-Control: no-store\r\n"
        head += "Connection: close\r\n\r\n"
        var out = Array(head.utf8)
        out.append(contentsOf: data)
        try? client.write(out)
    }

    private func indexText(_ target: ShareLinks.Target) -> String {
        let name = title.isEmpty ? "配置服务" : "\(title) 配置服务"
        return """
        \(name)

        这个服务只为本机生成给 sing-box / Shadowrocket / NekoBox 用的配置。
        SOCKS5 地址：\(target.host):\(target.port)

        /share/singbox            完整 profile JSON
        /share/shadowrocket       base64 订阅
        /share/nekobox            base64 订阅（混合）
        /share/shadowrocket.conf  配置文件

        """
    }
}
