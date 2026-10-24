import Foundation

/**
 扫码接入的链接与订阅内容 —— 与 `pc/share.py`、`ShareLinks.kt` 一致。

 ## 为什么这段要逐字对齐 PC 版

 二维码里的字符串是**给别人家 App 解析**的：多一个 `#备注` 会多出一个分组、
 少一层 base64 就是「不能获取订阅节点」、sing-box 的 deep link 少一层
 百分号编码就拉不到配置。这些坑 PC 版都踩过并修好了，这里直接照抄
 已验证的规则。

 | 客户端 | 扫码用的是什么 | 注意 |
 |---|---|---|
 | sing-box | `sing-box://import-remote-profile?url=…` | url 要整体百分号编码 |
 | Shadowrocket | 明文 `socks5://host:port` | **不能带 `#备注`**，否则多一个分组 |
 | NekoBox | 明文 `socks5://host:port` | 同上 |
 */
public enum ShareLinks {

    public static let appSingbox = "singbox"
    public static let appShadowrocket = "shadowrocket"
    public static let appNekobox = "nekobox"

    public struct Target {
        public let host: String
        public let port: Int
        public let user: String
        public let pass: String

        public init(host: String, port: Int, user: String = "", pass: String = "") {
            self.host = host
            self.port = port
            self.user = user
            self.pass = pass
        }

        public var auth: Bool { !user.isEmpty }
    }

    public struct Entry {
        public let id: String
        public let label: String
        /// 二维码内容。
        public let qrText: String
        public let qrKind: String
        public let hint: String
        public let manual: String
        /// (说明, URL)：.conf / 订阅这类「需要点开」的地址。
        public let files: [(String, String)]
    }

    // ── 编码工具 ────────────────────────────────────────────────

    /// 等价于 Python 的 `urllib.parse.quote(s, safe='')`：
    /// 只保留 `A-Za-z0-9-_.~`，其余一律 `%XX`（大写）。
    ///
    /// 手写而不是用 `addingPercentEncoding`：后者对 `-_.~` 的处理与
    /// `allowedCharacters` 的具体表有关，不同系统版本会有细微差别，
    /// 而且它不编码 `/` 这类字符的行为需要额外断言 —— 协议要求逐字节一致。
    public static func percentEncode(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.utf8.count * 3)
        for byte in Array(text.utf8) {
            let keep = (byte >= 0x41 && byte <= 0x5A) ||        // A-Z
                (byte >= 0x61 && byte <= 0x7A) ||               // a-z
                (byte >= 0x30 && byte <= 0x39) ||               // 0-9
                byte == 0x2D || byte == 0x5F ||                 // - _
                byte == 0x2E || byte == 0x7E                    // . ~
            if keep {
                out.unicodeScalars.append(Unicode.Scalar(byte))
            } else {
                out += String(format: "%%%02X", Int(byte))
            }
        }
        return out
    }

    /// 标准 base64（带填充）。
    public static func base64(_ text: String) -> String {
        Data(Array(text.utf8)).base64EncodedString()
    }

    // ── 节点链接 ────────────────────────────────────────────────

    /// `socks://base64(...)`（NekoBox / v2rayN 系）。
    public static func socksUri(_ target: Target,
                                label: String = "StarRadar") -> String {
        let body = target.auth
            ? "\(target.user):\(target.pass)@\(target.host):\(target.port)"
            : "\(target.host):\(target.port)"
        var uri = "socks://" + base64(body)
        if !label.isEmpty { uri += "#" + percentEncode(label) }
        return uri
    }

    /// `socks://base64("socks5:user:pass@host:port")`。
    ///
    /// 没有认证时退回基本形态 —— 写成 `socks5::@host:port` 会让部分解析器
    /// 把空串当用户名。
    public static func socksUriFull(_ target: Target,
                                    label: String = "StarRadar") -> String {
        if !target.auth { return socksUri(target, label: label) }
        let body = "socks5:\(target.user):\(target.pass)@\(target.host):\(target.port)"
        var uri = "socks://" + base64(body)
        if !label.isEmpty { uri += "#" + percentEncode(label) }
        return uri
    }

    /// `socks5://` 明文 URI（扫码导入的唯一形态）。
    ///
    /// ⚠️ 默认**不带 `#备注`**：NekoBox / Shadowrocket 会把 URI 尾部的 `#xxx`
    /// 当成**分组名**，于是列表里出现「分组 + 节点」两条记录。
    public static func socks5Uri(_ target: Target, label: String = "") -> String {
        let auth = target.auth
            ? "\(percentEncode(target.user)):\(percentEncode(target.pass))@"
            : ""
        var uri = "socks5://\(auth)\(target.host):\(target.port)"
        if !label.isEmpty { uri += "#" + percentEncode(label) }
        return uri
    }

    // ── sing-box ────────────────────────────────────────────────

    /// 完整配置（TUN 入站 + SOCKS5 出站）。
    public static func singboxConfigJson(_ target: Target) -> String {
        var lines: [String] = []
        lines.append("{")
        lines.append("  \"log\": {")
        lines.append("    \"level\": \"warn\",")
        lines.append("    \"timestamp\": true")
        lines.append("  },")
        lines.append("  \"inbounds\": [")
        lines.append("    {")
        lines.append("      \"type\": \"tun\",")
        lines.append("      \"tag\": \"tun-in\",")
        lines.append("      \"address\": [")
        lines.append("        \"172.19.0.1/30\"")
        lines.append("      ],")
        lines.append("      \"mtu\": 9000,")
        lines.append("      \"auto_route\": true,")
        lines.append("      \"strict_route\": false,")
        lines.append("      \"stack\": \"mixed\"")
        lines.append("    }")
        lines.append("  ],")
        lines.append("  \"outbounds\": [")
        lines.append("    {")
        lines.append("      \"type\": \"socks\",")
        lines.append("      \"tag\": \"proxy\",")
        lines.append("      \"server\": \(jsonString(target.host)),")
        lines.append("      \"server_port\": \(target.port),")
        var proxyTail = "      \"version\": \"5\""
        if target.auth {
            proxyTail += ",\n"
            proxyTail += "      \"username\": \(jsonString(target.user)),\n"
            proxyTail += "      \"password\": \(jsonString(target.pass))"
        }
        lines.append(proxyTail)
        lines.append("    },")
        lines.append("    {")
        lines.append("      \"type\": \"direct\",")
        lines.append("      \"tag\": \"direct\"")
        lines.append("    }")
        lines.append("  ],")
        lines.append("  \"route\": {")
        lines.append("    \"final\": \"proxy\",")
        lines.append("    \"auto_detect_interface\": true")
        lines.append("  }")
        lines.append("}")
        return lines.joined(separator: "\n")
    }

    /// `sing-box://import-remote-profile?url=<encoded>`，url 必须整体百分号编码。
    public static func singboxLink(_ configUrl: String) -> String {
        "sing-box://import-remote-profile?url=" + percentEncode(configUrl)
    }

    // ── Shadowrocket ────────────────────────────────────────────

    public static func shadowrocketConf(_ target: Target) -> String {
        let proxyLine = target.auth
            ? "StarRadar = socks5, \(target.host), \(target.port), \(target.user), \(target.pass)"
            : "StarRadar = socks5, \(target.host), \(target.port)"
        return [
            "[General]",
            "bypass-system = true",
            "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, " +
                "172.16.0.0/12, 169.254.0.0/16, localhost, *.local",
            "bypass-tun = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12",
            "dns-server = 223.5.5.5, 119.29.29.29",
            "",
            "[Proxy]",
            proxyLine,
            "",
            "[Rule]",
            "FINAL,StarRadar",
            "",
        ].joined(separator: "\n")
    }

    public static func shadowrocketConfWithProxy(_ target: Target) -> String {
        shadowrocketConf(target)
            .replacingOccurrences(of: "[Rule]",
                                  with: "[Proxy Group]\nPROXY = select, StarRadar\n\n[Rule]")
            .replacingOccurrences(of: "FINAL,StarRadar", with: "FINAL,PROXY")
    }

    // ── 订阅内容 ────────────────────────────────────────────────

    /// 订阅里要放的链接。
    ///
    /// 踩过的真问题：订阅里只放 `socks://base64(...)`，Shadowrocket 扫码后
    /// 提示「不能获取订阅节点」—— 它拉到了内容，但一行都解析不出来。
    /// 所以按客户端分风味：
    ///  - `shadowrocket` 只放 `socks5://` 明文；
    ///  - `mixed` 明文 + 两种 `socks://`，给 NekoBox 系。
    public static func subLinks(_ target: Target,
                                flavor: String = "mixed") -> [String] {
        var links: [String] = []
        if flavor == "shadowrocket" || flavor == "mixed" || flavor == "plain" {
            links.append(socks5Uri(target))
        }
        if flavor == "mixed" || flavor == "plain" {
            links.append(socksUri(target))
            links.append(socksUriFull(target))
        }
        var out: [String] = []
        for link in links where !link.isEmpty && !out.contains(link) {
            out.append(link)
        }
        return out
    }

    public static func subscriptionBody(_ target: Target,
                                        flavor: String = "mixed") -> String {
        base64(subLinks(target, flavor: flavor).joined(separator: "\n"))
    }

    public static func subscriptionPlain(_ target: Target,
                                         flavor: String = "plain") -> String {
        subLinks(target, flavor: flavor).joined(separator: "\n")
    }

    public static func nekoboxBody(_ target: Target) -> String {
        subscriptionBody(target, flavor: "mixed")
    }

    // ── 汇总（给界面用）────────────────────────────────────────

    public static func entries(_ target: Target,
                               configUrl: (String) -> String) -> [Entry] {
        let host = target.host
        let port = target.port
        let manualAuth = target.auth
            ? "，用户名 \(target.user) / 密码 \(target.pass)"
            : "，不填账号"

        return [
            Entry(
                id: appSingbox,
                label: "sing-box",
                qrText: singboxLink(configUrl(appSingbox)),
                qrKind: "官方 deep link",
                hint: "扫完 App 会自己拉配置；首次会请求 VPN 权限，允许即可",
                manual: "sing-box → 配置文件 → 从剪贴板导入，或手动添加 " +
                    "SOCKS 出站（\(host):\(port)）",
                files: [("配置文件 JSON", configUrl(appSingbox))]
            ),
            Entry(
                id: appShadowrocket,
                label: "Shadowrocket",
                qrText: socks5Uri(target),
                qrKind: "节点链接 socks5://",
                hint: "扫码后自动添加节点；下方链接可给整份配置或订阅",
                manual: "Shadowrocket → 添加节点 → 类型 SOCKS5，服务器 \(host)，端口 \(port)\(manualAuth)",
                files: [
                    ("配置文件 .conf", configUrl(appShadowrocket + ".conf")),
                    ("订阅（base64 列表）", configUrl(appShadowrocket)),
                ]
            ),
            Entry(
                id: appNekobox,
                label: "NekoBox",
                qrText: socks5Uri(target),
                qrKind: "节点链接 socks5://",
                hint: "NekoBox 与 sing-box 内核同源，TUN 模式一样能接管全局",
                manual: "NekoBox → 新建配置 → 类型 SOCKS，服务器 \(host)，端口 \(port)\(manualAuth)",
                files: [("订阅内容（base64）", configUrl(appNekobox))]
            ),
        ]
    }

    static func jsonString(_ text: String) -> String {
        Json.quote(text)
    }
}
