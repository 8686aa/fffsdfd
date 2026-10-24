import Foundation

/**
 节点地址规整：把「只填 IP」补成 ws 地址，端口固定 1082。

 与 `Uploader.normalizeNodeUrl` / PC 版 `normalize_node_url` 一致。
 */
public enum NodeURL {

    public static let defaultPort = 1082

    public static func normalize(_ node: String) -> String {
        let text = node.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return "" }
        var withScheme = text
        if !text.contains("://") { withScheme = "ws://" + text }
        guard let schemeEnd = withScheme.range(of: "://") else { return withScheme }
        let scheme = String(withScheme[..<schemeEnd.lowerBound])
        let rest = String(withScheme[schemeEnd.upperBound...])
        // 已经有端口就不动；但要小心 IPv6 的冒号，只在方括号外用
        let lastColon = rest.lastIndex(of: ":")
        let lastBracket = rest.lastIndex(of: "]")
        let hasPort: Bool
        if let lastColon {
            if let lastBracket {
                hasPort = lastColon > lastBracket
            } else {
                hasPort = true
            }
        } else {
            hasPort = false
        }
        return hasPort ? withScheme : "\(scheme)://\(rest):\(defaultPort)"
    }
}
