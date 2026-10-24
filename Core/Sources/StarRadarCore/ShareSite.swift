import Foundation

/**
 内置网页的入口链接解析 —— 与 `ShareSite.kt` 一致。

 ```
   GET http://<节点IP>:666/api/share/by_key?key=<房间口令>
   →  {"ok": true, "username": "admin", "code": "FSF3-9K9A",
       "url": "http://<节点IP>:666/share/FSF3-9K9A"}
 ```

 ## 最终跳转地址固定是 `http://<节点IP>:666/share/<code>`

 不能直接用节点返回的 url：节点常在反向代理 / 容器后面，自报的地址是
 内部的（`http://127.0.0.1:1666/share/xxx`）。手机上 `127.0.0.1` 指向手机
 自己、`1666` 是容器内端口 —— 永远打不开，而且白屏看不出原因。

 所以只保留 raw 的 path + query，authority 一律重建为「用户填的节点 IP + 666」。

 ## 失败必须说人话

 失败点不少（没开代理、口令错、节点没起服务、端口被拦），用户看到的
 只是"打不开"。所以每个分支都给一句具体原因。
 */
public enum ShareSite {

    /// 节点提供分享页的端口（与 PC 端约定一致：666）。
    public static let sharePort = 666
    public static let apiByKey = "/api/share/by_key"
    public static let connectTimeoutMs = 8000

    public struct Result {
        public let url: String
        public let code: String
        public let username: String
        public let error: String

        public init(url: String = "", code: String = "",
                    username: String = "", error: String = "") {
            self.url = url
            self.code = code
            self.username = username
            self.error = error
        }

        public var ok: Bool { !url.isEmpty }
    }

    /**
     按口令取页面地址。

     - Parameters:
       - node: 节点地址，可以带端口或 scheme
       - apiKey: 32 位十六进制房间口令
       - sharePort: **只有测试会传非默认值**；生产固定 666
     */
    public static func resolve(node: String, apiKey: String,
                               timeoutMs: Int = ShareSite.connectTimeoutMs,
                               sharePort: Int = ShareSite.sharePort) -> Result {
        let host = hostOf(node)
        if host.isEmpty { return Result(error: "没填节点 IP") }
        let key = apiKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if key.count != 32 {
            return Result(error: "房间口令需为 32 位十六进制")
        }

        let api = "http://\(host):\(sharePort)\(apiByKey)?key=\(key)"
        let body: String
        do {
            body = try httpGet(api, timeoutMs)
        } catch {
            return Result(error: describe(error))
        }

        guard let doc = Json.parse(body) else {
            return Result(error: "节点返回的不是 JSON（可能是别的东西占用了 \(sharePort) 端口）")
        }
        if doc["ok"]?.boolValue != true {
            let message = doc["msg"]?.stringValue ?? doc["error"]?.stringValue
            return Result(error: "节点拒绝了请求：" + (message ?? "口令无效或没有对应房间"))
        }
        let raw = (doc["url"]?.stringValue ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let code = (doc["code"]?.stringValue ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty && code.isEmpty {
            return Result(error: "节点没返回页面地址（ok=true 但缺 url 与 code）")
        }
        if !raw.isEmpty && !isSafeUrl(raw) {
            return Result(error: "节点返回的地址不是 http/https：\(String(raw.prefix(40)))")
        }
        let url = normalizeUrl(raw, nodeHost: host, code: code, sharePort: sharePort)
        if url.isEmpty {
            return Result(error: "拼不出可用地址（url=\(String(raw.prefix(60))), code=\(code)）")
        }
        return Result(url: url, code: code,
                      username: doc["username"]?.stringValue ?? "")
    }

    /// 归一化成 `http://<节点IP>:666/share/<code>[?原query]`。
    public static func normalizeUrl(_ raw: String, nodeHost: String,
                                    code: String,
                                    sharePort: Int = ShareSite.sharePort) -> String {
        let host = nodeHost.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.isEmpty { return "" }

        var path = ""
        var query = ""
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        if text.isEmpty {
            if code.isEmpty { return "" }
            path = "/share/\(code)"
        } else if isSafeUrl(text) {
            // 完整 URL：只取 path 与 query，authority 一律丢弃后重建
            if let components = URLComponents(string: text) {
                path = components.percentEncodedPath
                query = components.percentEncodedQuery ?? ""
            }
            if path.isEmpty {
                let afterScheme = text.components(separatedBy: "://").last ?? ""
                if let slash = afterScheme.firstIndex(of: "/") {
                    let rest = String(afterScheme[slash...])
                    path = rest.components(separatedBy: "?").first ?? ""
                    if let mark = rest.firstIndex(of: "?") {
                        query = String(rest[rest.index(after: mark)...])
                    }
                }
            }
        } else {
            // 相对路径形态：`/share/xxx` 或 `share/xxx`
            path = text.components(separatedBy: "?").first ?? ""
            if let mark = text.firstIndex(of: "?") {
                query = String(text[text.index(after: mark)...])
            }
            if !path.isEmpty && !path.hasPrefix("/") { path = "/" + path }
        }

        if !path.contains("/share/") {
            if code.isEmpty { return "" }
            path = "/share/\(code)"
        }

        var out = "http://\(host):\(sharePort)\(path)"
        if !query.isEmpty { out += "?" + query }
        return out
    }

    /// 从用户填的节点串里取主机名（允许带端口、允许带 scheme）。
    public static func hostOf(_ node: String) -> String {
        var text = node.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return "" }
        if let range = text.range(of: "://") {
            text = String(text[range.upperBound...])
        }
        if let slash = text.firstIndex(of: "/") {
            text = String(text[..<slash])
        }
        if text.filter({ $0 == ":" }).count == 1,
           let colon = text.firstIndex(of: ":") {
            text = String(text[..<colon])
        }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// 只放行 http / https。
    ///
    /// `javascript:` 会执行脚本；`file://` 能读应用私有目录（配置里有口令）；
    /// `intent://` 能拉起任意组件（iOS 上是自定义 scheme）。这些都不该由
    /// 「节点返回的字符串」决定。
    public static func isSafeUrl(_ url: String) -> Bool {
        let lower = url.lowercased()
        return (lower.hasPrefix("http://") && lower.count > 7) ||
            (lower.hasPrefix("https://") && lower.count > 8)
    }

    // ── HTTP ──────────────────────────────────────────────────

    /// 同步 GET。Core 里刻意不用 async/await：这条链路在调用方那儿就是
    /// 「点一下等结果」的同步操作，用信号量同步反而少一层状态机。
    static func httpGet(_ url: String, _ timeoutMs: Int) throws -> String {
        guard let parsed = URL(string: url) else {
            throw ProxyError("地址非法")
        }
        var request = URLRequest(url: parsed)
        request.httpMethod = "GET"
        request.timeoutInterval = Double(timeoutMs) / 1000.0
        request.setValue("StarRadar-iOS/1.0", forHTTPHeaderField: "User-Agent")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = Double(timeoutMs) / 1000.0
        configuration.timeoutIntervalForResource = Double(timeoutMs) / 1000.0
        configuration.waitsForConnectivity = false
        let session = URLSession(configuration: configuration)

        let semaphore = DispatchSemaphore(value: 0)
        var resultData: Data?
        var status = 0
        var failure: Error?
        let task = session.dataTask(with: request) { data, response, error in
            resultData = data
            status = (response as? HTTPURLResponse)?.statusCode ?? 0
            failure = error
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + .milliseconds(timeoutMs + 1500))
            == .timedOut {
            task.cancel()
            session.invalidateAndCancel()
            throw ProxyError("连接节点超时（\(timeoutMs / 1000) 秒）：网络不通或被拦")
        }
        session.finishTasksAndInvalidate()

        if let failure {
            throw failure
        }
        let text = String(decoding: resultData ?? Data(), as: UTF8.self)
        if !(200...299).contains(status) {
            let detail = text.isEmpty ? "" : "：\(String(text.prefix(80)))"
            throw ProxyError("HTTP \(status)\(detail)")
        }
        return text
    }

    /// 把网络异常翻成用户能行动的一句话。
    static func describe(_ error: Error) -> String {
        let message = error.localizedDescription
        let nsError = error as NSError
        if message.contains("HTTP 40") {
            return "节点说找不到这个口令对应的页面（\(message)）"
        }
        if message.contains("HTTP 50") {
            return "节点内部错误（\(message)），稍后再试或找节点管理员"
        }
        switch nsError.code {
        case NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed:
            return "解析不到节点地址：检查填的 IP 是否正确"
        case NSURLErrorCannotConnectToHost:
            return "连不上节点的 \(sharePort) 端口：节点可能没开分享页服务"
        case NSURLErrorTimedOut:
            return "连接节点超时（\(connectTimeoutMs / 1000) 秒）：网络不通或被拦"
        case NSURLErrorAppTransportSecurityRequiresSecureConnection:
            return "系统拦了明文 HTTP：需要允许任意加载（Info.plist 的 ATS 配置）"
        case NSURLErrorNotConnectedToInternet:
            return "本机没有网络"
        default:
            return message.isEmpty ? "取页面地址失败：\(nsError.code)" : "取页面地址失败：\(message)"
        }
    }
}
