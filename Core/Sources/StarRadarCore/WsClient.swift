import Foundation

/**
 最小 WebSocket 客户端 —— 用系统的 `URLSessionWebSocketTask`。

 ## 为什么不再手写 RFC 6455

 Android 端手写是因为要精确控制发送时序（逐包上报不能有额外缓冲）。
 iOS 这边 `URLSessionWebSocketTask` 已经满足了全部需求：文本帧、ping、
 关闭握手、自动分片重组，而且是系统实现 —— 少一份自己维护的帧解析，
 就少一处「客户端掩码算错」这类只有真机才暴露的坑。

 ## 但有一处行为必须自己补：**关闭要能立刻唤醒等待方**

 Android 端踩过：读线程结束时只调 `onClose`、不通知消息队列，于是握手
 代码白等满 8 秒超时，报成「鉴权超时」—— 真实原因是节点已经关了连接。
 这里同样处理：读线程退出前必须往队列塞 [closedMarker]。
 */
public final class WsClient: NSObject, URLSessionWebSocketDelegate {

    /// 连接关闭的信号。用零宽字符做标记，不可能是真实报文。
    public static let closedMarker = "\u{0}closed"

    private let url: URL
    private let log: (String) -> Void
    private let onText: (String) -> Void
    private let onClose: (String) -> Void

    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private var running = false
    private var reader: Thread?

    private let openSignal = DispatchSemaphore(value: 0)
    private var openFailure: String?
    private let writeLock = NSLock()

    /// 文本帧队列。读线程只管往里塞；用的人决定是阻塞取（握手）
    /// 还是轮询取（业务）。
    private let queue = MessageQueue()

    public init(url: String, onText: @escaping (String) -> Void = { _ in },
                onClose: @escaping (String) -> Void = { _ in },
                log: @escaping (String) -> Void = { _ in }) throws {
        guard let parsed = URL(string: url),
              let scheme = parsed.scheme?.lowercased(),
              scheme == "ws" || scheme == "wss" else {
            throw ProxyError("节点地址不是 ws/wss：\(url)")
        }
        self.url = parsed
        self.onText = onText
        self.onClose = onClose
        self.log = log
        super.init()
    }

    /// 建连（含 WebSocket 升级）。升级失败直接抛。
    public func connect(timeoutMs: Int = 8000) throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = Double(timeoutMs) / 1000.0
        configuration.timeoutIntervalForResource = 3600
        configuration.waitsForConnectivity = false
        let session = URLSession(configuration: configuration, delegate: self,
                                 delegateQueue: nil)
        self.session = session
        let task = session.webSocketTask(with: url)
        self.task = task
        task.resume()

        // 等 didOpen / didClose。没有这一步，握手失败会晚到第一次 receive
        // 才表现出来，而那时已经把 hello 发出去了 —— 日志会指向错误的方向。
        let deadline = DispatchTime.now() + .milliseconds(timeoutMs)
        if openSignal.wait(timeout: deadline) == .timedOut {
            task.cancel(with: .goingAway, reason: nil)
            throw ProxyError("WebSocket 升级超时（\(timeoutMs / 1000) 秒）")
        }
        if let failure = openFailure {
            task.cancel(with: .goingAway, reason: nil)
            throw ProxyError("WebSocket 升级被拒：\(failure)")
        }
        running = true
    }

    /// 起读线程。回调在**这个线程**上执行，调用方不要在里面阻塞太久。
    public func startReader() {
        let thread = Thread { [weak self] in
            guard let self else { return }
            var reason = ""
            while self.running {
                guard let task = self.task else { break }
                let semaphore = DispatchSemaphore(value: 0)
                var payload: String?
                var failure: Error?
                task.receive { result in
                    switch result {
                    case .success(let message):
                        switch message {
                        case .string(let text): payload = text
                        case .data(let data):
                            payload = String(decoding: data, as: UTF8.self)
                        @unknown default: break
                        }
                    case .failure(let error):
                        failure = error
                    }
                    semaphore.signal()
                }
                semaphore.wait()
                if let failure {
                    reason = failure.localizedDescription
                    break
                }
                if let payload {
                    self.queue.push(payload)
                    self.onText(payload)
                }
            }
            self.running = false
            // ⚠️ 必须通知队列：连接已经没了，等消息的人应当**立刻**拿到
            // 「已关闭」而不是干等满超时。
            self.queue.push(WsClient.closedMarker)
            if reason.isEmpty { reason = "服务端关闭了连接" }
            self.onClose(reason)
        }
        thread.name = "ws-reader"
        thread.stackSize = 256 * 1024
        reader = thread
        thread.start()
    }

    /// 阻塞取一条文本消息；超时返回 nil。
    public func nextMessage(_ timeoutMs: Int) -> String? {
        queue.pop(timeoutMs: timeoutMs)
    }

    /// 非阻塞取。
    public func pollMessage() -> String? {
        queue.pop(timeoutMs: 0)
    }

    /// 发一条文本帧。失败直接抛（与 Android 的 `sendText` 一致）。
    public func sendText(_ text: String) throws {
        guard let task else { throw ProxyError("连接已关闭") }
        writeLock.lock()
        defer { writeLock.unlock() }
        let semaphore = DispatchSemaphore(value: 0)
        var failure: Error?
        task.send(.string(text)) { error in
            failure = error
            semaphore.signal()
        }
        if semaphore.wait(timeout: .now() + 8) == .timedOut {
            throw ProxyError("发送超时")
        }
        if let failure {
            throw ProxyError("发送失败：\(failure.localizedDescription)")
        }
    }

    public func sendPing() {
        task?.sendPing { _ in }
    }

    public var isOpen: Bool {
        running && task != nil
    }

    public func close() {
        if !running {
            hardClose()
            return
        }
        running = false
        // 正常关闭：发 close 帧（1000 = normal），服务端据此清理会话
        task?.cancel(with: .normalClosure, reason: nil)
        hardClose()
    }

    private func hardClose() {
        queue.push(WsClient.closedMarker)
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        session?.invalidateAndCancel()
        session = nil
    }

    // ── URLSessionWebSocketDelegate ───────────────────────────

    public func urlSession(_ session: URLSession,
                           webSocketTask: URLSessionWebSocketTask,
                           didOpenWithProtocol proto: String?) {
        openSignal.signal()
    }

    public func urlSession(_ session: URLSession,
                           webSocketTask: URLSessionWebSocketTask,
                           didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
                           reason: Data?) {
        let text = reason.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        openFailure = "服务端关闭（\(closeCode.rawValue)\(text.isEmpty ? "" : "：\(text)")）"
        openSignal.signal()
        running = false
        queue.push(WsClient.closedMarker)
    }
}

/// 带超时的简单消息队列。
final class MessageQueue {
    private let condition = NSCondition()
    private var items: [String] = []

    func push(_ text: String) {
        condition.lock()
        items.append(text)
        condition.broadcast()
        condition.unlock()
    }

    func pop(timeoutMs: Int) -> String? {
        condition.lock()
        defer { condition.unlock() }
        if items.isEmpty {
            if timeoutMs <= 0 { return nil }
            let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
            while items.isEmpty {
                if !condition.wait(until: deadline) { return nil }
            }
        }
        return items.removeFirst()
    }
}
