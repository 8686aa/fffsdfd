import Foundation
import StarRadarCore

/**
 TGCP 帧翻译引擎 —— 与 `TgcpEngine.kt` 等价的传输无关部分。

 ```
   另一台设备 ──SOCKS5──▶ Socket ──┐
                                   ├─▶ 本引擎 ──▶ 真服务器
   真服务器 ────────────── Socket ──┘
 ```

 翻译本身（换 DH 公钥、换加密 body、抓母料）跟「连接来自用户态 TCP 栈还是
 系统 socket」毫无关系。iOS 只有 SOCKS5 这一种入口（iOS 不允许第三方 App
 接管全局 TUN，除非用 NetworkExtension），但引擎仍然独立，方便以后加别的入口。

 ## 三条不能改的规则（PC 版用线上问题换来的）

 1. **握手前到达的应用帧要缓存**，不能当错误断掉。客户端不等响应就
    pipeline 发下一帧是合法 TCP 行为。
 2. **不要用 header 的标志位判断「这帧加不加密」**：byte[8] 是 dir_flags，
    c2s 的低 4 位恒为 0，拿它当「明文」在 c2s 上恒成立 —— 结果 c2s 密文
    被当明文送出，服务器解不开直接断，每个会话都卡在 4 帧。正确做法是
    **直接试解，解不开就当明文透传**。
 3. **server hello 的 body 解不开也要原样带过去**，不能丢 —— 手机用服务器
    密钥解不开自己的 hello，2~11 秒后 EOF。
 */
public final class TgcpEngine {

    public enum Direction {
        case c2s, s2c
    }

    public protocol Sink: AnyObject {
        /// 服务器 → 客户端方向。
        func toClient(_ data: [UInt8])
        /// 客户端 → 服务器方向。
        func toUpstream(_ data: [UInt8])
    }

    public static let pendingMaxFrames = 64
    public static let pendingMaxBytes = 256 * 1024

    /// 已采到母料后，业务帧的抽样间隔（每 N 帧才全文扫一次）。
    ///
    /// PC 版是 200，iOS 用 16 —— 手机 CPU 比路由器强得多，而漏一帧的代价
    /// 是整局没钥。两边都还有「入局帧无条件扫」兜底，所以这个值只影响
    /// 「同一局内新出现的母料」这条少见路径。
    public static let rescanEvery = 16

    /// 还没采到任何母料时的扫描预算（业务帧计数）。超了就停扫 ——
    /// 只在「连接活着但永远没有母料」时生效，避免白烧 CPU。
    public static let scanBudget = 200_000

    private struct Emit {
        let direction: Direction
        let data: [UInt8]
    }

    public weak var sink: Sink?

    private let onKey: (KeyMaterial) -> Void
    private let sessionInfo: () -> (String, Int)
    private let log: (String) -> Void

    private let lock = NSRecursiveLock()

    private var clientKey: [UInt8]?
    private var serverKey: [UInt8]?
    private var keysReady: Bool {
        clientKey != nil && serverKey != nil
    }

    private let clientSide = Tgcp.DhSide.create()
    private let serverSide = Tgcp.DhSide.create()

    private var clientPublic: BigUInt?
    private var serverPublic: BigUInt?

    private var pending: [(Direction, Tgcp.Frame)] = []
    private var pendingBytes = 0

    private var seenMaterials = Set<String>()
    private var scanFrames = 0
    /// 解压成功 / 失败的业务帧数。状态页要能看出「这台机器上的帧到底压没压」——
    /// 采不到母料时第一个要排除的就是「压缩位没认出来」。
    private var lz4Frames = 0
    private var lz4Failed = 0
    /// 最后一份母料来自哪一层（"plain" / "lz4"）。
    private var lastMaterialLayer = ""

    /// 最近的帧轨迹（环形，最多 `traceKeep` 条）。
    ///
    /// 排查「连上就断」时这是最有用的一件东西：能直接看出退出前那几帧
    /// 是什么命令、多大 body、被怎么处理的。没有它，现场只有一句
    /// 「连接结束」，无法区分「服务器关的」和「我们自己分帧失败的」。
    private var trace: [String] = []
    public static let traceKeep = 24

    private let c2sFramer = Tgcp.Framer()
    private let s2cFramer = Tgcp.Framer()

    // 统计（页面上要显示）
    public private(set) var framesC2s: Int64 = 0
    public private(set) var framesS2c: Int64 = 0
    public private(set) var bytesC2s: Int64 = 0
    public private(set) var bytesS2c: Int64 = 0
    public private(set) var translatedBody: Int64 = 0
    public private(set) var handshakeDone = false
    public private(set) var materials = 0
    public private(set) var lastError = ""

    public init(onKey: @escaping (KeyMaterial) -> Void,
                sessionInfo: @escaping () -> (String, Int),
                log: @escaping (String) -> Void = { _ in }) {
        self.onKey = onKey
        self.sessionInfo = sessionInfo
        self.log = log
    }

    // ── 喂数据 ────────────────────────────────────────────────

    /// 客户端方向。返回 false 表示这条流不能再用了。
    @discardableResult
    public func feedC2s(_ data: [UInt8]) -> Bool {
        if data.isEmpty { return true }
        lock.lock()
        bytesC2s += Int64(data.count)
        lock.unlock()

        let frames: [Tgcp.Frame]
        do {
            frames = try c2sFramer.feed(data)
        } catch {
            let message = (error as? ProxyError)?.message ?? "分帧失败"
            lock.lock(); lastError = "c2s 分帧失败：\(message)"; lock.unlock()
            log("[ch] c2s 分帧失败：\(message)")
            return false
        }

        for frame in frames {
            var emits: [Emit] = []
            lock.lock()
            do {
                emits = try translateLocked(.c2s, frame)
            } catch {
                let message = (error as? ProxyError)?.message ?? "翻译失败"
                lastError = "c2s 翻译失败：\(message)"
                lock.unlock()
                log("[ch] c2s 翻译失败：\(message)")
                return false
            }
            lock.unlock()
            emitAll(emits)
        }
        return true
    }

    /// 服务器方向。返回 false 表示这条流不能再用了。
    @discardableResult
    public func feedS2c(_ data: [UInt8]) -> Bool {
        if data.isEmpty { return true }
        lock.lock()
        bytesS2c += Int64(data.count)
        lock.unlock()

        let frames: [Tgcp.Frame]
        do {
            frames = try s2cFramer.feed(data)
        } catch {
            let message = (error as? ProxyError)?.message ?? "分帧失败"
            lock.lock(); lastError = "s2c 分帧失败：\(message)"; lock.unlock()
            log("[ch] s2c 分帧失败：\(message)")
            return false
        }

        for frame in frames {
            var emits: [Emit] = []
            lock.lock()
            do {
                emits = try translateLocked(.s2c, frame)
            } catch {
                let message = (error as? ProxyError)?.message ?? "翻译失败"
                lastError = "s2c 翻译失败：\(message)"
                lock.unlock()
                log("[ch] s2c 翻译失败：\(message)")
                return false
            }
            lock.unlock()
            emitAll(emits)
        }
        return true
    }

    private func note(_ direction: Direction, _ frame: Tgcp.Frame,
                      _ action: String) {
        let tag = direction == .c2s ? "c2s" : "s2c"
        let line = String(format: "%@ %@ b=%d h=%d %@",
                          tag, frame.commandName, frame.body.count,
                          frame.rawHeader.count, action)
        trace.append(line)
        if trace.count > TgcpEngine.traceKeep {
            trace.removeFirst(trace.count - TgcpEngine.traceKeep)
        }
    }

    private func emitAll(_ emits: [Emit]) {
        guard let sink else {
            // 静默丢数据是最难查的一类故障：socket 两端都开着，对端只是
            // 「没反应」，最后超时断开，而日志里什么都没有。
            if !emits.isEmpty {
                lock.lock()
                if lastError.isEmpty {
                    lastError = "输出通道已失效，丢弃 \(emits.count) 段数据"
                }
                lock.unlock()
            }
            return
        }
        for item in emits {
            switch item.direction {
            case .c2s: sink.toUpstream(item.data)
            case .s2c: sink.toClient(item.data)
            }
        }
    }

    // ── 翻译（核心）──────────────────────────────────────────

    private func translateLocked(_ direction: Direction,
                                 _ frame: Tgcp.Frame) throws -> [Emit] {
        switch direction {
        case .c2s:
            framesC2s += 1
            if frame.command == Tgcp.cmdClientHello {
                return try handleClientHello(frame)
            }
        case .s2c:
            framesS2c += 1
            if frame.command == Tgcp.cmdServerHello {
                return try handleServerHello(frame)
            }
        }

        if !keysReady {
            // 握手没完成就来了应用帧：缓存，等握手完成补发。
            //
            // ⚠️ 溢出**必须报错断开**，不能静默丢帧。
            // 曾经写成「超了就跳过」—— 丢掉一帧等于丢掉一段字节，整条
            // TGCP 流立刻错位，对端解不开；而现象是「连接还在、但什么都不
            // 通」，日志里连个错误都看不到。PC 版这里一直是 raise。
            if pending.count >= TgcpEngine.pendingMaxFrames ||
                pendingBytes >= TgcpEngine.pendingMaxBytes {
                let message = "应用帧等不到握手完成（已攒 \(pending.count) 帧 / "
                    + "\(pendingBytes) 字节）"
                lastError = message
                note(direction, frame, "pending-overflow")
                log("[ch] \(message)")
                throw ProxyError(message)
            }
            pending.append((direction, frame))
            pendingBytes += frame.body.count
            note(direction, frame, "pending")
            log("[ch] 握手未完成，缓存一帧（\(frame.commandName)）")
            return []
        }
        let data = translateApplicationBody(direction, frame)
        return [Emit(direction: direction, data: data)]
    }

    private func handleClientHello(_ frame: Tgcp.Frame) throws -> [Emit] {
        if clientPublic != nil || serverPublic != nil || !frame.body.isEmpty {
            throw ProxyError("unexpected or repeated client hello")
        }
        let parsed = try Tgcp.parseDhPublic(frame.rawHeader)
        clientPublic = parsed.value
        clientKey = try clientSide.deriveKey(peerPublic: parsed.value)
        let header = try Tgcp.replaceDhPublic(frame.rawHeader,
                                             serverSide.publicBytes)
        note(.c2s, frame, "rewrite-client-hello")
        log("[ch] c2s hello（client_key 就绪，header \(frame.rawHeader.count) B）")
        var emits = [Emit(direction: .c2s,
                          data: frame.withHeader(header).pack())]
        emits.append(contentsOf: flushPendingLocked())
        return emits
    }

    private func handleServerHello(_ frame: Tgcp.Frame) throws -> [Emit] {
        if clientPublic == nil || serverPublic != nil {
            throw ProxyError("server hello is out of order")
        }
        let parsed = try Tgcp.parseDhPublic(frame.rawHeader)
        serverPublic = parsed.value
        serverKey = try serverSide.deriveKey(peerPublic: parsed.value)
        let header = try Tgcp.replaceDhPublic(frame.rawHeader,
                                             clientSide.publicBytes)

        // body 可能是明文参数块：试着翻译，解不开就原样带过去
        var body = frame.body
        var translated = false
        if !body.isEmpty, let serverKey, let clientKey {
            if let result = try? Tgcp.translateBody(sourceKey: serverKey,
                                                    destKey: clientKey,
                                                    body: body) {
                body = result.cipher
                translated = true
            }
        }
        handshakeDone = true
        note(.s2c, frame, translated ? "rewrite-server-hello" : "hello-body-plain")
        log("[ch] s2c hello（server_key 就绪，body 翻译=\(translated ? "是" : "否")）")
        if !body.isEmpty && !translated {
            // 这条很关键：server hello 的 body 如果是密文而我们没翻成功，
            // 客户端用 client_key 解不开，2~11 秒后就会 EOF ——
            // 现象和「服务器踢人」一模一样，极易误判。
            log("[ch] ⚠️ server hello 的 body 未能翻译，原样透传（客户端可能解不开）")
        }

        var emits = [Emit(direction: .s2c,
                          data: frame.withParts(newHeader: header,
                                                newBody: body).pack())]
        emits.append(contentsOf: flushPendingLocked())
        return emits
    }

    private func translateApplicationBody(_ direction: Direction,
                                          _ frame: Tgcp.Frame) -> [UInt8] {
        if frame.body.isEmpty {
            note(direction, frame, "pass-empty")
            return frame.pack()
        }
        guard let clientKey, let serverKey else { return frame.pack() }

        let sourceKey = direction == .c2s ? clientKey : serverKey
        let destKey = direction == .c2s ? serverKey : clientKey

        // ⚠️ 直接试解，解不开当明文透传（判据见类注释第 2 条）
        if let result = try? Tgcp.translateBody(sourceKey: sourceKey,
                                                destKey: destKey,
                                                body: frame.body) {
            translatedBody += 1
            note(direction, frame, "translate")
            inspectPlain(direction, frame, result.plain)
            return frame.withBody(result.cipher).pack()
        }
        // 解不开 → 当明文原样透传。这是正确行为（有些帧本来就是明文），
        // 但要在轨迹里留痕，否则「一直透传」和「一直翻译」看起来一样。
        note(direction, frame, "pass-plain")
        inspectPlain(direction, frame, frame.body)
        return frame.withBody(frame.body).pack()
    }

    /// 握手完成后补发缓存帧。
    private func flushPendingLocked() -> [Emit] {
        if !keysReady || pending.isEmpty { return [] }
        let backlog = pending
        pending = []
        pendingBytes = 0
        log("[ch] 补发握手前缓存的 \(backlog.count) 帧")
        var emits: [Emit] = []
        for (direction, frame) in backlog {
            emits.append(Emit(direction: direction,
                              data: translateApplicationBody(direction, frame)))
        }
        return emits
    }

    // ── 母料扫描 ─────────────────────────────────────────────

    private func inspectPlain(_ direction: Direction, _ frame: Tgcp.Frame,
                              _ plain: [UInt8]) {
        if direction != .s2c || frame.command != Tgcp.cmdBattleS2C { return }

        // 0x4013 是**常规业务帧**（实测一局出现 679 次），不是只在登录时
        // 下发一次。所以这里每一步都要能省则省，否则每帧几毫秒地累，
        // 进游戏就是明显卡顿。
        scanFrames += 1

        // ── 明文层 + 可选的 LZ4 层 ─────────────────────────────
        //
        // 压缩位在扩展头第一个字节：非 0 表示 body 是整块 LZ4。
        // 只在真的标了压缩时才试 —— 解压要扫一遍字节，而绝大多数帧没压。
        var layers: [(data: [UInt8], name: String)] = [(data: plain, name: "plain")]
        if Tgcp.compressionMethod(frame.rawHeader) != 0 {
            if let expanded = Tgcp.maybeDecompressLz4(plain) {
                layers.append((data: expanded, name: "lz4"))
                lz4Frames += 1
            } else {
                lz4Failed += 1
            }
        }

        // ── 入局帧无条件扫，不受抽样 / 预算限制 ────────────────
        //
        // 见 `Tgcp.joinMessages` 的说明：游戏不在局间重连，一个连接跨好几局，
        // 母料却逐局都换。旧逻辑按索引抽样，第二盘的入局帧被跳过 → 那一局
        // 母料永远丢失，用户看到「第二盘不上报」。
        var joined = false
        for layer in layers where Tgcp.mentionsJoin(layer.data) {
            joined = true
            break
        }

        if !joined {
            if !seenMaterials.isEmpty {
                // 已经捞到过母料：同一连接里密钥通常不会变，只抽查。
                // （保留抽样是为了「一帧里有多个母料」和「局内换钥」这两种
                //  少见但出现过的情况 —— 入局帧那条路已经兜住了。）
                if scanFrames % TgcpEngine.rescanEvery != 0 { return }
            } else if scanFrames > TgcpEngine.scanBudget {
                // 还没捞到就超预算：停扫。这一条只在「连接活着但永远没有
                // 母料」时生效（比如连的是别的服），避免白烧 CPU。
                return
            }
        } else {
            log("[ch] 入局帧（第 \(scanFrames) 个业务帧），这一帧必扫")
        }

        for layer in layers {
            scanLayer(direction, frame, layer.data, layer.name)
        }
    }

    /// 在一层数据里找 128 字节母料。抽出来是因为现在有 plain / lz4 两层。
    private func scanLayer(_ direction: Direction, _ frame: Tgcp.Frame,
                           _ data: [UInt8], _ layer: String) {
        // 母料 128 字节 base64 后必带 '='。没有 '=' 的明文不可能命中，
        // 直接跳过全文扫描 —— 这条能省掉 99% 的成本。
        if !data.contains(UInt8(ascii: "=")) { return }

        var index = 0
        while index < data.count {
            guard let run = findBase64Run(data, index) else { break }
            index = run.end
            let token = Array(data[run.start..<run.end])
            guard let decoded = Data(base64Encoded: Data(token)) else { continue }
            if decoded.count != Tgcp.materialSize { continue }
            let bytes = [UInt8](decoded)
            let sha = Hex.encode(Crypto.sha256(bytes))
            if seenMaterials.contains(sha) { continue }

            seenMaterials.insert(sha)
            materials = seenMaterials.count
            log("[ch] 参数已更新")
            let upstream = sessionInfo()
            lastMaterialLayer = layer
            onKey(KeyMaterial(material: bytes, session: upstream.0,
                              upstream: upstream, sha256: sha,
                              command: frame.command,
                              sequence: frame.sequence))
        }
    }

    private struct Run {
        let start: Int
        let end: Int
    }

    /**
     找一段长度 160~220 的 base64 连续区（`[A-Za-z0-9+/]`，尾部最多 2 个 `=`）。

     边界条件与 PC 版的正则一致：
     `(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{160,220}={0,2})(?![A-Za-z0-9+/=])`
     */
    private func findBase64Run(_ data: [UInt8], _ from: Int) -> Run? {
        var index = from
        while index < data.count {
            if !isBase64Char(data[index]) {
                index += 1
                continue
            }
            // 左边界：前一个字符不能是 base64
            if index > 0 && isBase64Char(data[index - 1]) {
                while index < data.count && isBase64Char(data[index]) { index += 1 }
                continue
            }
            var end = index
            while end < data.count && isBase64Char(data[end]) { end += 1 }
            var pad = 0
            while end + pad < data.count && data[end + pad] == UInt8(ascii: "=")
                    && pad < 2 {
                pad += 1
            }
            let coreLen = end - index
            let rightOk = (end + pad >= data.count) || !isBase64Char(data[end + pad])
            if (160...220).contains(coreLen) && rightOk {
                return Run(start: index, end: end + pad)
            }
            index = max(end, index + 1)
        }
        return nil
    }

    private func isBase64Char(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A) ||       // A-Z
            (byte >= 0x61 && byte <= 0x7A) ||   // a-z
            (byte >= 0x30 && byte <= 0x39) ||   // 0-9
            byte == 0x2B || byte == 0x2F        // + /
    }

    public func snapshot() -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        return [
            "handshake": handshakeDone,
            "framesC2s": framesC2s,
            "framesS2c": framesS2c,
            "bytesC2s": bytesC2s,
            "bytesS2c": bytesS2c,
            "translated": translatedBody,
            "materials": materials,
            "scanFrames": scanFrames,
            "lz4Frames": lz4Frames,
            "lz4Failed": lz4Failed,
            "materialLayer": lastMaterialLayer,
            "pending": pending.count,
            "error": lastError,
            "trace": trace,
        ]
    }
}
