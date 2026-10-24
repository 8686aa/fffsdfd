import Foundation
import StarRadarCore

/// 配置持久化（UserDefaults）—— 与 Android 端 `Settings.kt` 的字段一致。
final class Settings {

    private enum Key {
        static let node = "sr.node"
        static let apiKey = "sr.apiKey"
        static let filterMode = "sr.filterMode"
        static let socksPort = "sr.socksPort"
        static let httpPort = "sr.httpPort"
        static let user = "sr.user"
        static let password = "sr.password"
        static let backgroundAudio = "sr.backgroundAudio"
    }

    private let defaults: UserDefaults

    var node: String
    var apiKey: String
    var filterMode: String
    var socksPort: Int
    var httpPort: Int
    var user: String
    var password: String
    /// 用静音音频换后台常驻。关掉更省电，但切后台会被系统挂起（iOS 限制）。
    var backgroundAudio: Bool

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        node = defaults.string(forKey: Key.node) ?? "106.52.86.244"
        apiKey = defaults.string(forKey: Key.apiKey) ?? ""
        filterMode = defaults.string(forKey: Key.filterMode) ?? UdpGate.modeBalance
        let storedSocks = defaults.integer(forKey: Key.socksPort)
        socksPort = storedSocks > 0 ? storedSocks : 1083
        let storedHttp = defaults.integer(forKey: Key.httpPort)
        httpPort = storedHttp > 0 ? storedHttp : 8088
        user = defaults.string(forKey: Key.user) ?? ""
        password = defaults.string(forKey: Key.password) ?? ""
        backgroundAudio = defaults.object(forKey: Key.backgroundAudio) as? Bool ?? true
    }

    var configured: Bool {
        !node.trimmingCharacters(in: .whitespaces).isEmpty &&
            apiKey.count == 32 && apiKey.allSatisfy { $0.hexDigitValue != nil }
    }

    /// 配置里的问题（界面直接显示，不让用户点了开始才发现）。
    func problems() -> [String] {
        var issues: [String] = []
        if node.trimmingCharacters(in: .whitespaces).isEmpty {
            issues.append("没填节点 IP")
        }
        let key = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if key.isEmpty {
            issues.append("没填房间口令")
        } else if key.count != 32 || !key.allSatisfy({ $0.hexDigitValue != nil }) {
            issues.append("房间口令需为 32 位十六进制")
        }
        if socksPort < 1024 || socksPort > 65535 {
            issues.append("SOCKS5 端口要在 1024~65535（iOS 不允许绑定特权端口）")
        }
        if httpPort < 1024 || httpPort > 65535 {
            issues.append("配置服务端口要在 1024~65535")
        }
        if !UdpGate.modes.contains(filterMode) {
            issues.append("过滤模式非法：\(filterMode)")
        }
        return issues
    }

    func save() {
        defaults.set(node, forKey: Key.node)
        defaults.set(apiKey, forKey: Key.apiKey)
        defaults.set(filterMode, forKey: Key.filterMode)
        defaults.set(socksPort, forKey: Key.socksPort)
        defaults.set(httpPort, forKey: Key.httpPort)
        defaults.set(user, forKey: Key.user)
        defaults.set(password, forKey: Key.password)
        defaults.set(backgroundAudio, forKey: Key.backgroundAudio)
    }

    /// 过滤模式的显示名。
    static func filterModeLabel(_ mode: String) -> String {
        switch mode {
        case UdpGate.modeOff: return "不过滤（全上报）"
        case UdpGate.modeLoose: return "宽松（只挡系统端口）"
        case UdpGate.modeBalance: return "平衡（默认）"
        case UdpGate.modeStrict: return "严格（只放白名单）"
        default: return mode
        }
    }
}
