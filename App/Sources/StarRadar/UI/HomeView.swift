import SwiftUI
import UIKit
import StarRadarCore

/// 主界面 —— 与 Android 端「采集卡 + 地址卡 + 扫码」的结构一致。
struct HomeView: View {

    @ObservedObject var service: RadarService

    @State private var showQr = false
    @State private var showConfig = false
    @State private var showWeb = false
    @State private var webUrl = ""
    @State private var probeReport: NodeProbeReport?
    @State private var probing = false
    @State private var toast = ""
    @State private var toastTimer: Timer?

    var body: some View {
        ZStack(alignment: .bottom) {
            ScrollView {
                VStack(spacing: 12) {
                    header
                    startButton
                    addressCard
                    statsCard
                    configCard
                    logCard
                }
                .padding(.horizontal, 14)
                .padding(.top, 10)
                .padding(.bottom, 28)
            }
            .background(Sr.bg)

            if !toast.isEmpty {
                Text(toast)
                    .font(.system(size: 12.5))
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    .background(Color.black.opacity(0.78))
                    .cornerRadius(9)
                    .padding(.bottom, 24)
                    .transition(.opacity)
            }
        }
        .sheet(isPresented: $showQr) {
            QrSheet(entries: service.entries, address: service.address) { text in
                copy(text, note: "已复制")
            }
        }
        .sheet(isPresented: $showConfig) {
            ConfigView(service: service)
        }
        .fullScreenCover(isPresented: $showWeb) {
            if let url = URL(string: webUrl) {
                BuiltinWebScreen(url: url)
            } else {
                VStack(spacing: 10) {
                    Text("地址无效").foregroundColor(Sr.err)
                    Text(webUrl).font(.system(size: 12)).foregroundColor(Sr.dim)
                }
            }
        }
        .onAppear { service.refreshStats() }
    }

    // ── 顶部 ──────────────────────────────────────────────────

    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 2) {
                Text("APP")
                    .font(.system(size: 21, weight: .bold))
                    .foregroundColor(Sr.fg)
                Text("局域网 SOCKS5 采集")
                    .font(.system(size: 11))
                    .foregroundColor(Sr.dim)
            }
            Spacer()
            statusPill
        }
        .padding(.vertical, 4)
    }

    private var statusPill: some View {
        let (text, color) = statusInfo
        return Text(text)
            .font(.system(size: 11.5, weight: .medium))
            .foregroundColor(color)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(color.opacity(0.10))
            .cornerRadius(999)
    }

    private var statusInfo: (String, Color) {
        if !service.running { return ("未启动", Sr.dim) }
        switch service.uplinkState {
        case Uploader.stateConnected: return ("采集中", Sr.ok)
        case Uploader.stateConnecting: return ("连接中", Sr.warn)
        case Uploader.stateReconnecting: return ("重连中", Sr.warn)
        default: return ("已启动", Sr.accent)
        }
    }

    private var startButton: some View {
        PrimaryButton(title: service.running ? "停止代理" : "开始代理",
                      enabled: service.running || service.problems.isEmpty) {
            service.toggle()
            if !service.errorText.isEmpty { showToast(service.errorText) }
        }
    }

    // ── 地址 + 入口 ───────────────────────────────────────────

    private var addressCard: some View {
        SrCard {
            HStack {
                CardTitle(text: "接入地址", tag: "另一台设备要连这个")
                Spacer()
                Text("复制")
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundColor(Sr.accentDark)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .onTapGesture { copy(service.address, note: "地址已复制") }
            }

            HStack(spacing: 10) {
                Mono(service.address, size: 17, color: Sr.accentDark)
                Text("SOCKS5")
                    .font(.system(size: 10.5))
                    .foregroundColor(Sr.accentDark)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Sr.accentLine)
                    .cornerRadius(999)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 11)
            .background(Sr.accentSoft)
            .cornerRadius(8)
            .padding(.top, 8)

            if !service.lanIp.isEmpty {
                Hint("本机 \(service.lanLabel) 地址 · 另一台设备要连同一个局域网" +
                     (service.boundHttpPort > 0
                      ? " · 配置服务 :\(service.boundHttpPort)" : ""))
                    .padding(.top, 6)
            }

            HStack(spacing: 10) {
                SecondaryButton(title: "生成二维码",
                                enabled: !service.entries.isEmpty) {
                    showQr = true
                }
                SecondaryButton(title: probing ? "自检中…" : "节点自检",
                                enabled: !probing && service.problems.isEmpty) {
                    runProbe()
                }
            }
            .padding(.top, 12)

            // 内置网页要点开节点上的页面，节点只认「已连上上报」的口令，
            // 所以这里必须等上报真的 connected。
            Button {
                openWeb()
            } label: {
                Text(service.webReady ? "打开内置网页" : "内置网页（需先连上报）")
                    .font(.system(size: 14,
                                  weight: service.webReady ? .semibold : .regular))
                    .foregroundColor(service.webReady ? .white : Sr.line2)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(service.webReady ? Sr.accent : Sr.surface2)
                    .cornerRadius(9)
            }
            .disabled(!service.webReady)
            .padding(.top, 8)

            if service.entries.isEmpty && service.lanIp.isEmpty && service.running {
                Hint("还没找到局域网地址：先让本机连上 Wi-Fi，或开热点让另一台设备连过来。",
                     tone: .warn)
                    .padding(.top, 8)
            }
            if let report = probeReport {
                probeResult(report).padding(.top, 10)
            }
        }
    }

    private func probeResult(_ report: NodeProbeReport) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(Array(report.steps.enumerated()), id: \.offset) { _, step in
                HStack(alignment: .top, spacing: 6) {
                    Text(step.ok ? "✓" : "✗")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(step.ok ? Sr.ok : Sr.err)
                        .frame(width: 14, alignment: .leading)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(step.name)
                            .font(.system(size: 12,
                                          weight: step.ok ? .regular : .medium))
                            .foregroundColor(step.ok ? Sr.fg : Sr.err)
                        if !step.ok || step.name.contains("解密") ||
                            step.name.contains("WebSocket") {
                            Text(step.detail)
                                .font(.system(size: 11))
                                .foregroundColor(Sr.dim)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer(minLength: 0)
                }
            }
            Hint(report.summary(), tone: report.ok ? .ok : .warn)
                .padding(.top, 4)
        }
        .padding(10)
        .background(Sr.surface2)
        .cornerRadius(8)
    }

    // ── 统计 ──────────────────────────────────────────────────

    private var statsCard: some View {
        SrCard {
            CardTitle(text: "采集", tag: service.running ? "运行中" : "未启动")
            HStack {
                StatView(label: "连接", value: "\(service.connects)")
                StatView(label: "活跃", value: "\(service.active)")
                StatView(label: "对局参数", value: "\(service.keysFound)")
            }
            .padding(.top, 10)

            HStack {
                StatView(label: "上行 UDP", value: "\(service.udpUp)")
                StatView(label: "下行 UDP", value: "\(service.udpDown)")
                StatView(label: "上报队列", value: "\(service.uplinkQueued)")
            }
            .padding(.top, 6)

            if service.running {
                Hint("工作线程 \(service.workers) · 排队 \(service.queuedTasks)",
                     tone: service.queuedTasks > 2 ? .warn : .normal)
                    .padding(.top, 8)
            }
            if !service.egressSummary.isEmpty {
                Hint(service.egressSummary,
                     tone: service.egressLevel == "OK" ? .ok
                        : (service.egressLevel == "BAD" ? .error : .warn))
                    .padding(.top, 6)
                if service.egressLevel != "OK" && !service.egressDetail.isEmpty {
                    Hint(service.egressDetail).padding(.top, 2)
                }
            }
            if !service.keepAliveSummary.isEmpty {
                Hint(service.keepAliveSummary,
                     tone: service.keepAliveSummary.contains("已启用") ? .ok : .warn)
                    .padding(.top, 6)
            }
            // 后台/挂起状态。iOS 上「另一台设备断网」几乎总是这两件事之一：
            //   ① 静音音频被打断后没恢复 → 系统挂起 App
            //   ② 已经在后台且处于低电量模式 → 系统更激进地回收
            // 所以这里把它们摆到明面上，用户报问题时一眼能看到原因。
            if service.running && service.inBackground {
                Hint("App 在后台：正在用静音音频保持运行。"
                     + "若另一台设备断网，回到前台即可恢复", tone: .normal)
                    .padding(.top, 6)
            }
            if service.running && service.lowPowerMode {
                Hint("低电量模式已开启：系统会更积极地挂起后台 App，"
                     + "建议关掉它再开代理", tone: .warn)
                    .padding(.top, 6)
            }
            if service.suspendedSeconds > 0 {
                Hint("曾检测到系统挂起 App 约 \(service.suspendedSeconds) 秒，"
                     + "已自动清理僵死连接并恢复音频", tone: .warn)
                    .padding(.top, 6)
            }
            if !service.filterSummary.isEmpty {
                Hint(service.filterSummary, tone: .ok).padding(.top, 6)
            }
            if !service.errorText.isEmpty {
                Hint(service.errorText, tone: .error).padding(.top, 6)
            }
        }
    }

    // ── 配置 ──────────────────────────────────────────────────

    private var configCard: some View {
        SrCard {
            HStack {
                CardTitle(text: "配置")
                Spacer()
                Text("修改")
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundColor(Sr.accentDark)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .onTapGesture { showConfig = true }
            }
            VStack(alignment: .leading, spacing: 5) {
                row("节点", service.node)
                row("口令", maskKey(service.apiKey))
                row("过滤", Settings.filterModeLabel(service.filterMode))
                row("端口", "SOCKS5 \(service.socksPort) · 配置服务 \(service.httpPort)")
            }
            .padding(.top, 8)

            if !service.problems.isEmpty {
                Hint("先修：" + service.problems.joined(separator: "；"), tone: .warn)
                    .padding(.top, 8)
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(spacing: 8) {
            Text(label)
                .font(.system(size: 11.5))
                .foregroundColor(Sr.dim)
                .frame(width: 46, alignment: .leading)
            Text(value.isEmpty ? "—" : value)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(Sr.fg)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 0)
        }
    }

    private func maskKey(_ key: String) -> String {
        guard key.count > 8 else { return key }
        return "\(key.prefix(6))……\(key.suffix(4))"
    }

    // ── 日志 ──────────────────────────────────────────────────

    /// 版本号 + 构建号。
    ///
    /// 侧载安装后「手机上装的是哪个包」本来无从确认 —— 而排查「改了为什么
    /// 没效果」时，这是必须先排除的一项（拿错包、装的是上一版，很容易发生）。
    /// 所以把它摆在页面上，让用户能直接截图对照。
    private var versionLine: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "版本 \(version)（build \(build)）"
    }

    private var logCard: some View {
        SrCard {
            HStack {
                CardTitle(text: "日志")
                Spacer()
                Text("清空")
                    .font(.system(size: 12))
                    .foregroundColor(Sr.dim)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .onTapGesture { service.logs.removeAll() }
            }
            Hint(versionLine).padding(.top, 2)
            let lines = Array(service.logs.suffix(18))
            if lines.isEmpty {
                Hint("还没有日志").padding(.top, 6)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 10.5, design: .monospaced))
                            .foregroundColor(Sr.dim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.top, 6)
            }
        }
    }

    // ── 动作 ──────────────────────────────────────────────────

    private func runProbe() {
        probing = true
        probeReport = nil
        service.runProbe { report in
            probing = false
            probeReport = report
        }
    }

    private func openWeb() {
        service.resolveShareSite { result in
            if result.ok {
                webUrl = result.url
                showWeb = true
                service.appendLog("内置网页已打开\(result.code.isEmpty ? "" : "（\(result.code)）")")
            } else {
                showToast(result.error)
            }
        }
    }

    private func copy(_ text: String, note: String) {
        UIPasteboard.general.string = text
        showToast(note)
    }

    private func showToast(_ text: String) {
        toast = text
        toastTimer?.invalidate()
        toastTimer = Timer.scheduledTimer(withTimeInterval: 2.4, repeats: false) { _ in
            toast = ""
        }
    }
}

// ── 扫码弹窗 ─────────────────────────────────────────────────

/// 三个客户端**一次列全**。
///
/// 之前试过「选一个 App 只显示一张」，问题是用户不知道到底有几项、
/// 也看不到另外两个是什么。三张码内容本来不同（不能合成一张），
/// 那就不该藏起来。
struct QrSheet: View {

    let entries: [ShareLinks.Entry]
    let address: String
    let onCopy: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("扫码接入")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(Sr.fg)
                Text("共 \(entries.count) 项")
                    .font(.system(size: 10.5))
                    .foregroundColor(Sr.dim)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Sr.surface2)
                    .cornerRadius(999)
                Spacer()
                Text("关闭")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(Sr.accentDark)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .onTapGesture { dismiss() }
            }
            .padding(.horizontal, 16)
            .padding(.top, 14)

            Hint("另一台设备装的是哪一个就扫哪一张 · SOCKS5 \(address)")
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 8)

            ScrollView {
                VStack(spacing: 12) {
                    if entries.isEmpty {
                        Hint("还没有可用的接入地址：先让本机连上 Wi-Fi 并开始代理",
                             tone: .warn)
                            .padding(.top, 40)
                    }
                    ForEach(Array(entries.enumerated()), id: \.offset) { index, entry in
                        entryCard(entry, index + 1)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 20)
            }
        }
        .background(Sr.bg)
    }

    private func entryCard(_ entry: ShareLinks.Entry, _ index: Int) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 7) {
                Text("\(index)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.white)
                    .frame(width: 18, height: 18)
                    .background(Sr.accent)
                    .clipShape(Circle())
                Text(entry.label)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(Sr.fg)
                Text(entry.qrKind)
                    .font(.system(size: 10))
                    .foregroundColor(Sr.dim)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(Sr.surface2)
                    .cornerRadius(999)
                Spacer()
            }
            QrImage(text: entry.qrText, side: 196)
                .frame(maxWidth: .infinity, alignment: .center)
            Hint(entry.hint)
            HStack(spacing: 4) {
                Text("复制链接")
                    .font(.system(size: 11.5))
                    .foregroundColor(Sr.accentDark)
                Mono(entry.manual, size: 10.5, color: Sr.dim)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .contentShape(Rectangle())
            .onTapGesture { onCopy(entry.qrText) }
        }
        .padding(10)
        .background(Sr.surface)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Sr.line, lineWidth: 1))
        .cornerRadius(10)
    }
}

// ── 配置页 ───────────────────────────────────────────────────

struct ConfigView: View {

    @ObservedObject var service: RadarService
    @Environment(\.dismiss) private var dismiss

    @State private var node = ""
    @State private var apiKey = ""
    @State private var filterMode = UdpGate.modeBalance
    @State private var socksPort = "1083"
    @State private var httpPort = "8088"
    @State private var authUser = ""
    @State private var authPassword = ""
    @State private var backgroundAudio = true

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("节点")) {
                    TextField("节点 IP（只填 IP 即可，端口固定 1082）",
                              text: $node)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("房间口令（32 位十六进制）", text: $apiKey)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
                Section(header: Text("过滤")) {
                    Picker("UDP 过滤", selection: $filterMode) {
                        ForEach(UdpGate.modes, id: \.self) { mode in
                            Text(Settings.filterModeLabel(mode)).tag(mode)
                        }
                    }
                }
                Section(header: Text("端口")) {
                    TextField("SOCKS5 端口", text: $socksPort)
                        .keyboardType(.numberPad)
                    TextField("配置服务端口", text: $httpPort)
                        .keyboardType(.numberPad)
                }
                Section(header: Text("接入认证（可留空）"),
                        footer: Text("填了账号密码后，另一台设备必须填同样的；不填就是无认证。")) {
                    TextField("用户名", text: $authUser)
                        .autocapitalization(.none)
                    TextField("密码", text: $authPassword)
                        .autocapitalization(.none)
                }
                Section(header: Text("后台"),
                        footer: Text("iOS 进后台约 30 秒会被系统挂起，只有静音音频能常驻。" +
                                     "关掉更省电，但切后台就会断。")) {
                    Toggle("静音音频保活", isOn: $backgroundAudio)
                }
            }
            .navigationTitle("配置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { save() }
                        .foregroundColor(Sr.accentDark)
                }
            }
        }
        .onAppear(perform: fill)
    }

    private func fill() {
        node = service.node
        apiKey = service.apiKey
        filterMode = service.filterMode
        socksPort = "\(service.socksPort)"
        httpPort = "\(service.httpPort)"
        authUser = service.authUser
        authPassword = service.authPassword
        backgroundAudio = service.backgroundAudio
    }

    private func save() {
        service.node = node.trimmingCharacters(in: .whitespacesAndNewlines)
        service.apiKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        service.filterMode = filterMode
        service.socksPort = Int(socksPort) ?? 1083
        service.httpPort = Int(httpPort) ?? 8088
        service.authUser = authUser
        service.authPassword = authPassword
        service.backgroundAudio = backgroundAudio
        service.saveSettings()
        service.updateEntries()
        dismiss()
    }
}
