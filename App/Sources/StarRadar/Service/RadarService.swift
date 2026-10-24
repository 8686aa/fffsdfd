import Foundation
import UIKit
// ObservableObject / @Published 来自 Combine；UIKit 不会替你带进来
import Combine
import StarRadarCore

/**
 采集总控 —— 与 Android 端 `RadarService` 的职责一致。

 ```
   另一台设备 ──SOCKS5──▶ Socks5Server
                            ├─ 65010 ──▶ SocketTunnel（TGCP 翻译）──▶ 真服务器
                            │              └─ 母料 ──▶ Uploader（battle_key）
                            ├─ 其它端口 ─▶ 直连转发
                            └─ UDP ASSOCIATE ─▶ UdpGate ─▶ IpDatagram ─▶ Uploader
   本机 ──HTTP:8088──▶ ShareHttpServer（/share/{singbox,shadowrocket,nekobox}）
 ```

 iOS 没有 VpnService / NetworkExtension，所以**只有这一种入口**：
 本机开 SOCKS5 服务，让同一局域网的另一台设备接入。功能与 PC/Android
 的 socks5 模式完全等价（同一份协议实现、同一套过滤与上报）。
 */
final class RadarService: ObservableObject {

    // 配置（与 Settings 双向同步）
    @Published var node: String = ""
    @Published var apiKey: String = ""
    @Published var filterMode: String = UdpGate.modeBalance
    @Published var socksPort: Int = 1083
    @Published var httpPort: Int = 8088
    @Published var authUser: String = ""
    @Published var authPassword: String = ""
    @Published var backgroundAudio: Bool = true

    // 状态
    @Published var running = false
    @Published var lanIp = ""
    @Published var lanLabel = ""
    @Published var boundSocksPort = 0
    @Published var boundHttpPort = 0

    // 统计
    @Published var connects: Int64 = 0
    @Published var active: Int64 = 0
    @Published var udpUp: Int64 = 0
    @Published var udpDown: Int64 = 0
    @Published var keysFound = 0
    @Published var workers = 0
    @Published var queuedTasks = 0

    // 上报
    @Published var uplinkState = Uploader.stateStopped
    @Published var uplinkQueued = 0
    @Published var uplinkSent: Int64 = 0

    // 后台/挂起状态。iOS 断网的现场判据全在这几个字段里：
    //   · inBackground       —— 现在是不是在后台（后台靠静音音频吊着）
    //   · suspendedSeconds   —— 上次被系统挂起了多久（>0 表示保活失效过）
    //   · lowPowerMode       —— 低电量模式下系统更激进地挂起后台 App
    @Published var inBackground = false
    @Published var suspendedSeconds = 0
    @Published var lowPowerMode = ProcessInfo.processInfo.isLowPowerModeEnabled

    // 诊断
    @Published var keepAliveSummary = ""
    @Published var egressLevel = ""
    @Published var egressSummary = ""
    @Published var egressDetail = ""
    @Published var filterSummary = ""
    @Published var problems: [String] = []
    @Published var errorText = ""

    // 扫码接入
    @Published var entries: [ShareLinks.Entry] = []

    /**
     是否显示调试日志。

     默认关：`[s5] UDP 关联已建立`、`[tun] 连接结束（63/65 帧）`、
     `[ch] 缓存一帧` 这类东西在正常使用时纯属噪音，而用户看日志是为了
     回答「现在到底通不通」。排查问题时在日志卡里打开这个开关。

     注意：**日志本身一直全量记录**（`logs` 不过滤），只是显示时过滤。
     所以打开开关能立刻看到之前发生的事，不会因为「当时没开」而丢线索。
     */
    @Published var showDebugLogs: Bool = false

    @Published var logs: [String] = []

    private let settings = Settings()
    private var server: Socks5Server?
    private var http: ShareHttpServer?
    private var uploader: Uploader?
    private var keepAlive: KeepAlive?
    private let gate = UdpGate()

    // UDP 包计数先攒在普通变量里，由 0.5s 的刷新定时器一次取走。
    //
    // 之前是「每个 UDP 包一次 DispatchQueue.main.async」—— 对局期间 UDP
    // 每秒几百上千个（含 QUIC / DNS），主线程会被这些 block 淹没，
    // 表现为界面卡死、日志延迟，连带刷新定时器都跑不动。
    // 计数器不是业务数据（精确到 0.5 秒足够看趋势），没必要每包都上主线程。
    private let statLock = NSLock()
    private var pendingUdpUp: Int64 = 0
    private var pendingUdpDown: Int64 = 0

    private var refreshTimer: Timer?
    private var logSeq = 0

    private var observers: [NSObjectProtocol] = []

    init() {
        loadSettings()
        observeAppLifecycle()
    }

    /// 观察前后台切换与低电量模式。
    ///
    /// 这两件事直接决定「另一台设备会不会断网」，所以要在界面上有可见状态：
    /// 用户报「切后台就断」时，第一句话该问的是「界面上保活那一行写的是什么」。
    private func observeAppLifecycle() {
        let center = NotificationCenter.default
        observers.append(center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            self?.inBackground = true
        })
        observers.append(center.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            self?.inBackground = false
        })
        observers.append(center.addObserver(
            forName: .NSProcessInfoPowerStateDidChange,
            object: nil, queue: .main
        ) { [weak self] _ in
            self?.lowPowerMode = ProcessInfo.processInfo.isLowPowerModeEnabled
        })
    }

    // ── 配置 ──────────────────────────────────────────────────

    func loadSettings() {
        node = settings.node
        apiKey = settings.apiKey
        filterMode = settings.filterMode
        socksPort = settings.socksPort
        httpPort = settings.httpPort
        authUser = settings.user
        authPassword = settings.password
        backgroundAudio = settings.backgroundAudio
        showDebugLogs = settings.debugLogs
        problems = settings.problems()
    }

    func saveSettings() {
        settings.node = node.trimmingCharacters(in: .whitespacesAndNewlines)
        settings.apiKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        settings.filterMode = filterMode
        settings.socksPort = socksPort
        settings.httpPort = httpPort
        settings.user = authUser
        settings.password = authPassword
        settings.backgroundAudio = backgroundAudio
        settings.debugLogs = showDebugLogs
        settings.save()
        apiKey = settings.apiKey
        problems = settings.problems()
    }

    var configured: Bool { settings.configured }

    /// 另一台设备要连的地址。
    var address: String {
        lanIp.isEmpty ? "—" : "\(lanIp):\(boundSocksPort > 0 ? boundSocksPort : socksPort)"
    }

    var shareTarget: ShareLinks.Target {
        ShareLinks.Target(host: lanIp.isEmpty ? "127.0.0.1" : lanIp,
                          port: boundSocksPort > 0 ? boundSocksPort : socksPort,
                          user: authUser, pass: authPassword)
    }

    // ── 启停 ──────────────────────────────────────────────────

    func toggle() {
        running ? stop() : start()
    }

    func start() {
        if running { return }
        saveSettings()
        problems = settings.problems()
        if !problems.isEmpty {
            errorText = "先修配置：" + problems.joined(separator: "；")
            appendLog("[cfg] \(errorText)")
            return
        }
        errorText = ""

        // 局域网地址：另一台设备要连的那个。Wi-Fi 优先、热点次之。
        let candidate = LanAddress.best()
        lanIp = candidate?.ip ?? ""
        lanLabel = candidate?.label ?? ""
        if lanIp.isEmpty {
            errorText = "没找到局域网地址：先让本机连上 Wi-Fi，或开热点让另一台设备连过来"
            appendLog("[net] \(errorText)")
            return
        }

        // 出站指纹自检：确认连游戏服务器走的是本机原生栈（没被 VPN 接管）。
        let egress = EgressCheck.check(ourVpnRunning: false)
        egressLevel = egress.level.rawValue
        egressSummary = egress.summary
        egressDetail = egress.detail

        // 过滤参数
        gate.mode = filterMode
        gate.ports = []
        gate.blockMedia = true
        gate.reset()

        // 保活（先拿锁再对外「已开始」，否则头几秒仍会被挂起）
        let keeper = KeepAlive(audioEnabled: backgroundAudio)
        keeper.onLog = { [weak self] text in self?.appendLog(text) }
        // 系统真的挂起过 → 把已经没人读的旧连接清掉。
        //
        // 这一步是「切后台后回来」体感的关键：挂起期间监听 socket 由内核
        // 维持，但已建立的客户端连接上没有任何人在读，客户端会对着一条
        // 静默连接干等 TCP 超时（几分钟）。主动断开让它立刻重连。
        keeper.onSuspended = { [weak self] seconds in
            guard let self else { return }
            self.suspendedSeconds = seconds
            // 短暂挂起**不能**断连接。
            //
            // 挂起期间内核仍然持有这些 socket，收到的数据会缓存在接收缓冲里，
            // 恢复后照样能读出来 —— 一条活着的 TCP 连接撑几十秒没问题。
            // 只有挂得足够久、客户端大概率已经超时重连了，清掉才是有益的
            // （让它立刻收到 RST 去重连，而不是干等几分钟）。
            let reason = "系统挂起 \(seconds)s"
            if seconds >= RadarService.staleAfterSuspendedSeconds {
                let dropped = self.server?.dropStaleClients(reason: reason) ?? 0
                self.appendLog("[ka] 挂起 \(seconds) 秒，已断开 \(dropped) 条旧连接等客户端重连")
            } else {
                self.appendLog("[ka] 挂起 \(seconds) 秒后恢复，连接保留")
            }
        }
        keepAliveSummary = keeper.acquire()
        keepAlive = keeper

        // 上报
        let reporter = Uploader(node: node, apiKey: apiKey)
        reporter.onLog = { [weak self] level, text in
            self?.appendLog("[\(level)] \(text)")
        }
        reporter.onState = { [weak self] state, detail in
            DispatchQueue.main.async {
                self?.uplinkState = state
                if !detail.isEmpty { self?.errorText = detail }
                self?.refreshStats()
            }
        }
        reporter.onAuthFailed = { [weak self] message in
            self?.appendLog("[err] 鉴权失败：\(message)")
        }
        reporter.onKeyAcked = { [weak self] in
            self?.appendLog("[ok] 节点已确认参数")
        }
        reporter.start()
        uploader = reporter

        // SOCKS5 服务端
        let socks = Socks5Server(
            port: socksPort,
            targetPorts: [65010],
            onUdp: { [weak self] srcIp, srcPort, dstIp, dstPort, payload, up in
                self?.handleUdp(srcIp, srcPort, dstIp, dstPort, payload, up)
            },
            onKey: { [weak self] material in
                self?.handleKey(material)
            },
            advertiseIp: { [weak self] in self?.lanIp ?? "0.0.0.0" },
            user: authUser, password: authPassword,
            log: { [weak self] text in self?.appendLog(text) }
        )
        guard socks.start() else {
            errorText = socks.error
            appendLog("[s5] \(socks.error)")
            reporter.stop()
            uploader = nil
            keeper.release()
            keepAlive = nil
            return
        }
        server = socks
        boundSocksPort = socks.boundPort

        // 配置服务（供 sing-box 拉 profile）。起不来不影响另外两个客户端。
        let share = ShareHttpServer(preferredPort: httpPort,
                                    target: { [weak self] in
                                        self?.shareTarget
                                            ?? ShareLinks.Target(host: "127.0.0.1", port: 1083)
                                    },
                                    title: "APP",
                                    log: { [weak self] text in self?.appendLog(text) })
        if share.start() {
            http = share
            boundHttpPort = share.boundPort
        } else {
            http = nil
            boundHttpPort = 0
            errorText = share.error
        }

        running = true
        appendLog("[s5] 已开始：\(address) · 另一台设备连同一个局域网后扫码接入")
        updateEntries()
        startRefreshTimer()
        refreshStats()
    }

    func stop() {
        refreshTimer?.invalidate()
        refreshTimer = nil
        server?.stop()
        server = nil
        http?.stop()
        http = nil
        uploader?.stop()
        uploader = nil
        gate.settle()
        keepAlive?.release()
        keepAlive = nil
        keepAliveSummary = ""
        suspendedSeconds = 0
        running = false
        boundSocksPort = 0
        boundHttpPort = 0
        uplinkState = Uploader.stateStopped
        egressLevel = ""
        egressSummary = ""
        egressDetail = ""
        filterSummary = ""
        entries = []
        appendLog("[s5] 已停止")
    }

    // ── 数据回填 ──────────────────────────────────────────────

    private func handleUdp(_ srcIp: String, _ srcPort: Int, _ dstIp: String,
                           _ dstPort: Int, _ payload: [UInt8], _ up: Bool) {
        // 必须先规范化方向：下行包的 src 是服务器、dst 是客户端内网地址，
        // 直接塞进过滤器会让 serverIp 变成私网地址，被 isNonPublic 整条丢掉，
        // 结果只有上行、「双向」判据永不成立 —— 一局一个包都上不去。
        let flow = UdpReport.normalize(srcIp: srcIp, srcPort: srcPort,
                                       dstIp: dstIp, dstPort: dstPort, up: up)
        let ready = gate.handle(UdpGate.Datagram(
            clientIp: flow.clientIp, clientPort: flow.clientPort,
            serverIp: flow.serverIp, serverPort: flow.serverPort,
            up: flow.up, payload: payload))
        if ready.isEmpty { return }

        statLock.lock()
        if up {
            pendingUdpUp += Int64(ready.count)
        } else {
            pendingUdpDown += Int64(ready.count)
        }
        statLock.unlock()

        for item in ready {
            let reported = UdpReport.Flow(clientIp: item.clientIp,
                                          clientPort: item.clientPort,
                                          serverIp: item.serverIp,
                                          serverPort: item.serverPort,
                                          up: item.up)
            guard let packet = UdpReport.packet(reported, item.payload) else {
                continue
            }
            uploader?.enqueue(packet)
        }
    }

    private func handleKey(_ material: KeyMaterial) {
        DispatchQueue.main.async { [weak self] in
            self?.keysFound += 1
        }
        let key = Uploader.BattleKey(
            id: material.id,
            sha256: material.sha256,
            materialB64: material.materialB64,
            room: 1,
            session: material.session,
            generation: RadarService.deviceTag(),
            server: material.upstream.host,
            upstream: material.upstream,
            observedMs: material.observedMs
        )
        uploader?.setKey(key)
        appendLog("[ch] 已获取对局参数（\(material.id)）")
    }

    /// 挂起超过这个秒数才清理旧连接。低于它认为连接还活着（内核在挂起期间
    /// 仍会缓冲收到的数据，恢复后可以继续读）。
    static let staleAfterSuspendedSeconds = 60

    /// 上报用的「设备代次」，取机型标识前 16 位（与 Android 取 fingerprint
    /// 前 16 位等价）。节点侧用它区分同一口令下的不同采集端。
    static func deviceTag() -> String {
        var info = utsname()
        uname(&info)
        let machine = withUnsafePointer(to: &info.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        return String(machine.prefix(16))
    }

    // ── 定时刷新 ──────────────────────────────────────────────

    private func startRefreshTimer() {
        refreshTimer?.invalidate()
        let timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) {
            [weak self] _ in
            self?.refreshStats()
        }
        refreshTimer = timer
    }

    func refreshStats() {
        guard let server else { return }

        statLock.lock()
        let up = pendingUdpUp
        let down = pendingUdpDown
        pendingUdpUp = 0
        pendingUdpDown = 0
        statLock.unlock()
        if up > 0 { udpUp += up }
        if down > 0 { udpDown += down }

        connects = server.connects
        active = server.active
        let (threads, queued) = server.workerStats()
        workers = threads
        queuedTasks = queued
        if let reporter = uploader {
            uplinkState = reporter.state
            uplinkQueued = reporter.queued
            uplinkSent = reporter.sent
        }
        if let keeper = keepAlive {
            keepAliveSummary = keeper.summary
        }
        let filter = gate.snapshot()
        if filter.passed + filter.dropped > 0 {
            filterSummary = "UDP 过滤：放行 \(filter.passed) 包 / 挡下 \(filter.dropped) 包" +
                "（省 \(String(format: "%.1f", filter.savedPct))%）"
        }
    }

    // ── 扫码接入 ──────────────────────────────────────────────

    func updateEntries() {
        guard !lanIp.isEmpty else {
            entries = []
            return
        }
        let target = shareTarget
        let port = boundHttpPort
        let all = ShareLinks.entries(target) { app in
            "http://\(self.lanIp):\(port)/share/\(app)"
        }
        // 配置服务没起来时**不显示 sing-box**：它的扫码入口是「去这个 URL
        // 拉配置」，服务不在，那张码扫了只会一直转圈。
        entries = port > 0 ? all : all.filter { $0.id != ShareLinks.appSingbox }
    }

    // ── 日志 ──────────────────────────────────────────────────

    // ── 日志分级 ──────────────────────────────────────────────

    /// 纯流程日志的标签。带这些标签的行默认不显示。
    private static let debugTags = [
        "[s5]", "[udp]", "[tun]", "[ch]", "[ka]", "[ws]", "[net]", "[cfg]",
    ]

    /**
     这些词一旦出现，即使带调试标签也**保留显示**。

     区别在于「流程」和「结果」：
       · `[s5] UDP 关联已建立`        → 流程，正常时天天有，隐藏
       · `[s5] 连不上目标端口 63861`  → 结果，出事了，必须看得见

     否则关掉调试日志后，真正的问题也一起消失了 —— 那比噪音更糟。
     */
    private static let keepWords = [
        // 出了问题
        "⚠️", "失败", "错误", "连不上", "打不开", "拒绝", "异常", "超时", "不匹配",
        // 代理的开关状态。这两条虽然也挂在 [s5] 上，但它们是用户最想确认的
        // 事实（代理到底开没开），绝不能因为「带调试标签」被藏掉。
        // 注意别加「已就绪」：那条是 `[s5] 已就绪（0.0.0.0:1083）`（监听成功）
        // 和 `[ka] 静音音频已就绪`（保活流程），都属于纯流程日志。
        "已开始", "已停止", "没找到",
    ]

    /// 这一行是不是「纯调试」日志。
    static func isDebugLine(_ line: String) -> Bool {
        // 上报状态（[ok] / [err]）是用户能直接感知的状态变化，一律保留
        if line.contains("[ok]") || line.contains("[err]") { return false }
        // 出事的信息保留
        if keepWords.contains(where: { line.contains($0) }) { return false }
        // 剩下带流程标签的才算调试
        return debugTags.contains(where: { line.contains($0) })
    }

    /// 界面要显示的日志（已按开关过滤）。
    ///
    /// @param limit 只取最后几条 —— 日志卡高度有限，滚动成本高于信息量。
    func visibleLogs(limit: Int) -> [String] {
        let source = showDebugLogs
            ? logs
            : logs.filter { !RadarService.isDebugLine($0) }
        return Array(source.suffix(limit))
    }

    /// 当前被隐藏的调试日志条数（用来在开关旁提示「还有 N 条」）。
    var hiddenLogCount: Int {
        guard !showDebugLogs else { return 0 }
        return logs.reduce(into: 0) { count, line in
            if RadarService.isDebugLine(line) { count += 1 }
        }
    }

    func appendLog(_ text: String) {
        let stamp = RadarService.clock()
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.logSeq += 1
            self.logs.append("\(stamp) \(text)")
            // 上限放宽到 400：调试日志也全量留着，打开开关时能回看，
            // 但又不至于无限增长。400 条短字符串的内存可忽略。
            if self.logs.count > 400 {
                self.logs.removeFirst(self.logs.count - 400)
            }
        }
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    static func clock() -> String {
        formatter.string(from: Date())
    }

    // ── 节点自检 / 内置网页 ───────────────────────────────────

    /// 自检跑在后台线程（最坏十几秒，放主线程会卡界面）。
    func runProbe(completion: @escaping (NodeProbeReport) -> Void) {
        let currentNode = node
        let currentKey = apiKey
        appendLog("开始节点自检（\(currentNode)）")
        DispatchQueue.global(qos: .userInitiated).async {
            let report = NodeProbe.run(node: currentNode, apiKey: currentKey)
            self.appendLog("自检完成：\(report.summary())")
            DispatchQueue.main.async { completion(report) }
        }
    }

    /// 取内置网页地址（后台线程），回调在主线程。
    func resolveShareSite(completion: @escaping (ShareSite.Result) -> Void) {
        let currentNode = node
        let currentKey = apiKey
        DispatchQueue.global(qos: .userInitiated).async {
            let result = ShareSite.resolve(node: currentNode, apiKey: currentKey)
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// 内置网页是否可用：**代理已开 且 上报 WS 已连上**。
    ///
    /// 节点侧要靠上报通道确认「这个口令有一端在线」，否则 /api/share/by_key
    /// 多半返回空。所以不看「配了 IP」就放行 —— 那只会让用户点进去看白屏。
    var webReady: Bool {
        running && uplinkState == Uploader.stateConnected
    }

    deinit {
        let center = NotificationCenter.default
        for token in observers { center.removeObserver(token) }
    }
}
