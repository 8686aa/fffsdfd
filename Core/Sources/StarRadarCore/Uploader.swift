import Foundation

/**
 上报端 —— 与 `core/uploader.py` 的 `WsReporter`、`Uploader.kt` 一致。

 ## 一份连接干三件事

 ```
  1. 鉴权：secure_hello → challenge → finish（加密）→ secure_ok（加密）
  2. 下发密钥：{"type":"battle_key", ...}（加密信封里）
  3. 上送报文：{"batch":[{"data":"<base64 整包>","k":"<key_id>"}, ...]}
 ```

 ## 队列语义（都是被线上问题逼出来的）

 - 只有**写成功**才出队。写失败整批留队，重连后补发 —— 宁可重复也不能丢，
   因为对局数据「缺一帧这一局就废」，重复只是节点侧多算一次。
 - 队列上限 20000，超了丢**最旧**的。最新的帧才对应当前对局。
 - 一批最多 40 条。再大节点侧单帧上限会顶到，且一条失败整批重发。

 ## 状态机

 `stopped → connecting → connected → reconnecting → connecting …`

 「connecting」和「reconnecting」要分开：页面上的「节点未连接」如果连
 「正在连」也算进去，重建链路的几秒里会红一下，看着像出错。
 */
public final class Uploader {

    public static let batchMax = 40
    public static let queueLimit = 20000
    public static let reconnectMinMs: Int = 1000
    public static let reconnectMaxMs: Int = 5000
    public static let pingIntervalMs: Int = 5000

    public static let stateStopped = "stopped"
    public static let stateConnecting = "connecting"
    public static let stateConnected = "connected"
    public static let stateReconnecting = "reconnecting"

    public struct BattleKey {
        public let id: String
        public let sha256: String
        public let materialB64: String
        public let room: Int
        public let session: String
        public let generation: String
        public let server: String
        public let upstream: (host: String, port: Int)?
        public let observedMs: Int64
        public let verified: Bool

        public init(id: String, sha256: String, materialB64: String, room: Int,
                    session: String, generation: String, server: String,
                    upstream: (host: String, port: Int)?, observedMs: Int64,
                    verified: Bool = false) {
            self.id = id
            self.sha256 = sha256
            self.materialB64 = materialB64
            self.room = room
            self.session = session
            self.generation = generation
            self.server = server
            self.upstream = upstream
            self.observedMs = observedMs
            self.verified = verified
        }

        public init(material: KeyMaterial, room: Int, generation: String,
                    server: String) {
            self.init(id: material.id, sha256: material.sha256,
                      materialB64: material.materialB64, room: room,
                      session: material.session, generation: generation,
                      server: server, upstream: material.upstream,
                      observedMs: material.observedMs)
        }
    }

    public struct Pending {
        public let data: String
        public let keyId: String
        public let seq: Int64
    }

    // 回调（对应 Kotlin 的 Listener）
    public var onState: ((String, String) -> Void)?
    public var onAuthFailed: ((String) -> Void)?
    public var onKeyAcked: (() -> Void)?
    public var onLog: ((String, String) -> Void)?

    public let url: String
    private let apiKey: String

    private let lock = NSLock()
    private var queue: [Pending] = []
    private var pendingSeq: Int64 = 0

    private var running = false
    private var thread: Thread?
    private var client: WsClient?
    private var channel: SecureWs.Channel?

    public private(set) var state = Uploader.stateStopped
    public private(set) var lastError = ""
    public private(set) var connected = false

    public private(set) var enqueued: Int64 = 0
    public private(set) var sent: Int64 = 0
    public private(set) var dropped: Int64 = 0
    public private(set) var resent: Int64 = 0
    public private(set) var reconnects: Int64 = 0
    public private(set) var keySent: Int64 = 0
    public private(set) var lastKeyId = ""

    private var pendingKey: BattleKey?
    private var keyDirty = false
    private let startLock = NSLock()

    public init(node: String, apiKey: String) {
        url = NodeURL.normalize(node)
        self.apiKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // ── 生命周期 ──────────────────────────────────────────────

    public func start() {
        startLock.lock()
        if running {
            startLock.unlock()
            return
        }
        running = true
        state = Uploader.stateConnecting
        startLock.unlock()

        let thread = Thread { [weak self] in self?.runLoop() }
        thread.name = "sr-upload"
        thread.stackSize = 512 * 1024
        self.thread = thread
        thread.start()
    }

    public func stop() {
        running = false
        client?.close()
        client = nil
        state = Uploader.stateStopped
        connected = false
        thread = nil
    }

    /// 抓包侧调用：把整包入队。`packet` 是完整的 IPv4+UDP 报文。
    public func enqueue(_ packet: [UInt8]) {
        if packet.isEmpty { return }
        lock.lock()
        pendingSeq += 1
        queue.append(Pending(data: Data(packet).base64EncodedString(),
                             keyId: lastKeyId, seq: pendingSeq))
        enqueued += 1
        while queue.count > Uploader.queueLimit {
            queue.removeFirst()
            dropped += 1
        }
        lock.unlock()
    }

    /// 下发一份密钥。写成功之前不会清掉，断线重连会再发一遍。
    public func setKey(_ key: BattleKey?) {
        guard let key else { return }
        lock.lock()
        pendingKey = key
        keyDirty = true
        lock.unlock()
    }

    public var queued: Int {
        lock.lock()
        defer { lock.unlock() }
        return queue.count
    }

    // ── 主循环 ────────────────────────────────────────────────

    private func runLoop() {
        var backoff = Uploader.reconnectMinMs
        var first = true
        while running {
            state = first ? Uploader.stateConnecting : Uploader.stateReconnecting
            first = false
            do {
                try connectAndServe()
                backoff = Uploader.reconnectMinMs
            } catch {
                let message = (error as? SecureError)?.message
                    ?? (error as? ProxyError)?.message
                    ?? error.localizedDescription
                lastError = message
                onLog?("warn", "[ws] 连接异常: \(message)")
                connected = false
                if state == Uploader.stateConnected {
                    state = Uploader.stateReconnecting
                    onState?(state, lastError)
                }
            }
            client?.close()
            client = nil
            if !running { break }
            reconnects += 1
            onLog?("warn", "[ws] 已断开，\(backoff / 1000) 秒后重连")
            Thread.sleep(forTimeInterval: Double(backoff) / 1000.0)
            backoff = min(backoff * 2, Uploader.reconnectMaxMs)
        }
        state = Uploader.stateStopped
        connected = false
    }

    private func connectAndServe() throws {
        let node = url
        if node.isEmpty { throw SecureError("没填节点 IP") }

        let ws = try WsClient(url: node,
                              onClose: { [weak self] reason in
                                  if !reason.isEmpty { self?.lastError = reason }
                              },
                              log: { [weak self] text in
                                  self?.onLog?("info", text)
                              })
        client = ws

        // 先起读线程再握手：读线程只负责把文本帧塞进队列，握手代码用
        // nextMessage() 按序取，顺序仍然是我们控制的。
        try ws.connect()
        ws.startReader()

        let handshake = try SecureWs.ClientHandshake(apiKey: apiKey)
        try ws.sendText(handshake.hello())
        onLog?("info", "[ws] 已发送 secure_hello（等 challenge）")

        let challenge = try nextOrThrow(ws, 8000, "secure_challenge")
        let accepted = try handshake.acceptChallenge(challenge)
        let chan = accepted.channel
        channel = chan
        onLog?("ok", "[ws] 收到 challenge 并验证通过（对端身份已确认）")

        // ⚠️ finish **必须加密后发送**。
        //
        // 协议文档写得很清楚：`C → S {"type":"secure_finish",...} ← 这条已加密`。
        // 但 Android 端曾经一直发明文，于是节点按信封解析失败，立刻关闭
        // TCP 且**不给任何错误帧**。现象是「节点在等 secure_ok 时关闭了
        // 连接」，看着像口令问题，实际跟口令无关。
        try ws.sendText(try chan.encrypt(Array(accepted.finish.utf8)))
        onLog?("info", "[ws] 已发送 secure_finish（加密，等 secure_ok）")

        let okText = try nextOrThrow(ws, 8000, "secure_ok")
        // 明文 error 是节点在握手阶段拒绝时的形态（key 无效、房间满等）
        if let doc = Json.parse(okText),
           doc["type"]?.stringValue == SecureWs.errorType {
            let message = doc["msg"]?.stringValue ?? "invalid api_key"
            lastError = "鉴权失败：\(message)"
            onAuthFailed?(message)
            throw SecureError(lastError)
        }
        let inner: String
        do {
            inner = String(decoding: try chan.decrypt(okText), as: UTF8.self)
        } catch {
            throw SecureError("鉴权回执解不开：\((error as? SecureError)?.message ?? "未知")")
        }
        guard let okDoc = Json.parse(inner),
              okDoc["type"]?.stringValue == SecureWs.okType else {
            let message = Json.parse(inner)?["msg"]?.stringValue
                ?? String(inner.prefix(120))
            lastError = "鉴权被拒：\(message)"
            onAuthFailed?(message)
            throw SecureError(lastError)
        }
        connected = true
        state = Uploader.stateConnected
        onState?(state, "")
        onLog?("ok", "[ws] 鉴权通过，开始逐包上送")

        var lastPing = Date()
        while running && ws.isOpen {
            try drainIncoming(ws)
            flushKey(ws)
            try flushQueue(ws)
            if Date().timeIntervalSince(lastPing) >=
                Double(Uploader.pingIntervalMs) / 1000.0 {
                ws.sendPing()
                lastPing = Date()
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        if running { throw SecureError("连接已关闭") }
    }

    /**
     取一条消息；拿到关闭标记或超时都抛，让外层决定重连。

     ⚠️ 必须识别 error 消息：key 错时节点不发 challenge，而是直接回
     `{"type":"error","msg":"invalid api_key"}` 然后断开。只按「预期顺序」
     取的话，这条 error 会被当成"不是 secure_challenge" → 报一个含糊的
     协议错误，`onAuthFailed` 一次都不触发。

     ## 超时与「被关闭」必须分开报

     这两种情况的原因完全不同：
      · **被关闭**：节点收下 finish 但拒绝继续（实测真节点不发任何错误帧
        直接关 TCP）。最常见的原因是口令无效、或该口令已有一端在线。
      · **真超时**：8 秒一个字节都没回来。这时候要怀疑网络/端口被拦。
     */
    private func nextOrThrow(_ ws: WsClient, _ timeoutMs: Int,
                             _ what: String) throws -> String {
        guard let text = ws.nextMessage(timeoutMs) else {
            throw SecureError("握手超时：等 \(what) 超过 \(timeoutMs / 1000) 秒，" +
                "节点没有任何响应。多为网络阻断（检查 1082 端口是否可达）")
        }
        if text == WsClient.closedMarker {
            throw SecureError("节点在等 \(what) 时关闭了连接（未给出错误码）。" +
                "常见原因：房间口令与该节点上的房间不一致，或该口令已有采集端在线")
        }
        if let doc = Json.parse(text),
           doc["type"]?.stringValue == SecureWs.errorType {
            let message = doc["msg"]?.stringValue ?? "invalid api_key"
            // lastError 要在这里就设好，不能等外层 catch —— 否则
            // onAuthFailed 已经回调了、UI 读 lastError 却还是空串。
            lastError = "鉴权失败：\(message)"
            onAuthFailed?(message)
            throw SecureError(lastError)
        }
        return text
    }

    private func drainIncoming(_ ws: WsClient) throws {
        while true {
            guard let text = ws.pollMessage() else { return }
            if text == WsClient.closedMarker {
                throw SecureError("连接已关闭")
            }
            handleMessage(text)
        }
    }

    private func handleMessage(_ text: String) {
        guard let doc = Json.parse(text) else { return }
        switch doc["type"]?.stringValue {
        case SecureWs.errorType:
            lastError = doc["msg"]?.stringValue ?? "节点返回错误"
            onLog?("err", "[ws] \(lastError)")
        case SecureWs.envelopeType:
            guard let channel, let plain = try? channel.decrypt(text),
                  let inner = Json.parse(String(decoding: plain, as: UTF8.self))
            else { return }
            switch inner["type"]?.stringValue {
            case "battle_key_ack":
                onKeyAcked?()
            case SecureWs.errorType:
                lastError = inner["msg"]?.stringValue ?? "节点返回错误"
                onLog?("err", "[ws] \(lastError)")
            default:
                break
            }
        case "battle_key_ack":
            onKeyAcked?()
        default:
            break
        }
    }

    private func flushKey(_ ws: WsClient) {
        lock.lock()
        let dirty = keyDirty
        let key = pendingKey
        lock.unlock()
        guard dirty, let key, let chan = channel else { return }

        let payload = buildKeyPayload(key)
        do {
            try ws.sendText(try chan.encrypt(Array(payload.utf8)))
            lock.lock()
            keyDirty = false
            lastKeyId = key.id
            lock.unlock()
            keySent += 1
            onLog?("ok", "[ch] 参数已下发")
        } catch {
            // 发失败就留着，下一轮再试
            onLog?("warn", "[ws] 密钥下发失败：\(error.localizedDescription)")
        }
    }

    private func flushQueue(_ ws: WsClient) throws {
        lock.lock()
        if queue.isEmpty {
            lock.unlock()
            return
        }
        let take = min(Uploader.batchMax, queue.count)
        let batch = Array(queue[0..<take])
        queue.removeFirst(take)
        lock.unlock()

        let text = buildBatchPayload(batch)
        guard let chan = channel else {
            // 没有通道就把这批放回队首，等下一轮
            lock.lock()
            queue.insert(contentsOf: batch, at: 0)
            lock.unlock()
            return
        }
        do {
            try ws.sendText(try chan.encrypt(Array(text.utf8)))
            sent += Int64(batch.count)
        } catch {
            // 写失败：**整批放回队首**，不能丢，顺序也要保持
            lock.lock()
            queue.insert(contentsOf: batch, at: 0)
            lock.unlock()
            resent += Int64(batch.count)
            throw error
        }
    }

    // ── 报文拼装（与 Python 逐字节一致）───────────────────────

    public func buildBatchPayload(_ items: [Pending]) -> String {
        var out = "{\"batch\":["
        for (index, item) in items.enumerated() {
            if index > 0 { out += "," }
            out += "{\"data\":\"" + item.data + "\""
            if !item.keyId.isEmpty {
                out += ",\"k\":\"" + Json.escape(item.keyId) + "\""
            }
            out += "}"
        }
        out += "]}"
        return out
    }

    public func buildKeyPayload(_ key: BattleKey) -> String {
        var out = "{\"type\":\"battle_key\""
        out += ",\"key_id\":\"" + Json.escape(key.id) + "\""
        out += ",\"sha256\":\"" + Json.escape(key.sha256) + "\""
        out += ",\"material\":\"" + Json.escape(key.materialB64) + "\""
        out += ",\"room\":" + String(key.room)
        out += ",\"session\":\"" + Json.escape(key.session) + "\""
        out += ",\"generation\":\"" + Json.escape(key.generation) + "\""
        out += ",\"server\":\"" + Json.escape(key.server) + "\""
        if let upstream = key.upstream {
            out += ",\"upstream\":[" + Json.quote(upstream.host) + ","
            out += String(upstream.port) + "]"
        }
        out += ",\"observed_ms\":" + String(key.observedMs)
        out += ",\"verified\":" + (key.verified ? "true" : "false")
        out += ",\"ts\":" + String(Int64(Date().timeIntervalSince1970 * 1000))
        out += "}"
        return out
    }
}
