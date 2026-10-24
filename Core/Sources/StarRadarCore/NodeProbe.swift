import Foundation

/**
 节点自检 —— 把「连不上」拆成可观测的 6 步。

 ## 为什么需要它

 「鉴权超时（没收到 secure_ok）」这一句话同时对应四种完全不同的原因：
 网络阻断 / 端口不对 / 口令无效 / 同一口令已有采集端在线。用户照着
 「超时」去查网络，方向完全错了。

 自检把每一步单独打点，失败的那一步直接给排查方向。

 ## 绝不抛异常

 这是「诊断工具」，自身崩掉就失去意义了。所有错误都转成一条
 `Step(name, ok: false, detail)`。
 */
public struct NodeProbeReport {

    public struct Step {
        public let name: String
        public let ok: Bool
        public let detail: String

        public init(_ name: String, _ ok: Bool, _ detail: String) {
            self.name = name
            self.ok = ok
            self.detail = detail
        }
    }

    public let steps: [Step]

    public init(_ steps: [Step]) {
        self.steps = steps
    }

    public var ok: Bool { steps.allSatisfy { $0.ok } }

    public var failed: Step? { steps.first { !$0.ok } }

    /// 一句话结论。失败时给**下一步动作**，而不是复述错误。
    public func summary() -> String {
        guard let failed else {
            return "全部通过：节点可达、口令有效、会话密钥一致"
        }
        switch failed.name {
        case "检查配置":
            return "先修配置：\(failed.detail)"
        case "WebSocket 升级":
            return "连不上节点的 WebSocket：检查 IP、1082 端口是否可达（防火墙/运营商拦截也常见）"
        case "发送 hello 并等 challenge":
            if failed.detail.contains("关闭") {
                return "节点收下 hello 后直接断开：多半是端口上跑的不是本协议服务，或节点正在重启"
            }
            return "节点 8 秒内没回 challenge：网络被拦，或该端口不是转发服务"
        case "校验 challenge":
            return "服务端握手证明不通过：房间口令与该节点上的房间不一致"
        case "发送 finish 并等 secure_ok":
            if failed.detail.contains("关闭") {
                return "卡在「发送 finish 并等 secure_ok」：多半是房间口令无效，" +
                    "或同一口令已有另一台采集端在线"
            }
            return "节点在等 secure_ok 时超时：网络抖动，或节点负载过高"
        case "解密回执":
            return "回执解不开：双方会话密钥不一致（口令大小写/全半角最好重新粘贴一次）"
        default:
            return "自检没跑完：\(failed.detail)"
        }
    }
}

public enum NodeProbe {

    public static func run(node: String, apiKey: String,
                           timeoutMs: Int = 6000) -> NodeProbeReport {
        var steps: [NodeProbeReport.Step] = []
        let raw = node.trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty {
            return NodeProbeReport([.init("检查配置", false, "没填节点 IP")])
        }
        let url = NodeURL.normalize(raw)
        let key: String
        do {
            key = try SecureWs.normalizeApiKey(apiKey)
        } catch {
            let message = (error as? SecureError)?.message ?? "房间口令格式不对"
            return NodeProbeReport([.init("检查配置", false, message)])
        }
        steps.append(.init("检查配置", true,
                           "\(url) · 口令 \(key.prefix(4))…\(key.suffix(4))"))

        var client: WsClient?
        defer { client?.close() }

        do {
            let started = Date()
            let ws = try WsClient(url: url, log: { _ in })
            client = ws
            do {
                try ws.connect(timeoutMs: timeoutMs)
            } catch {
                let message = (error as? ProxyError)?.message ?? error.localizedDescription
                steps.append(.init("WebSocket 升级", false, message))
                return NodeProbeReport(steps)
            }
            let elapsed = Int(Date().timeIntervalSince(started) * 1000)
            steps.append(.init("WebSocket 升级", true, "耗时 \(elapsed)ms"))
            ws.startReader()

            let handshake = try SecureWs.ClientHandshake(apiKey: key)
            do {
                try ws.sendText(handshake.hello())
            } catch {
                steps.append(.init("发送 hello 并等 challenge", false,
                                   "发送失败：\(error.localizedDescription)"))
                return NodeProbeReport(steps)
            }

            guard let challenge = ws.nextMessage(timeoutMs) else {
                steps.append(.init("发送 hello 并等 challenge", false,
                                   "\(timeoutMs / 1000) 秒内没有响应"))
                return NodeProbeReport(steps)
            }
            if challenge == WsClient.closedMarker {
                steps.append(.init("发送 hello 并等 challenge", false,
                                   "节点直接关闭了连接"))
                return NodeProbeReport(steps)
            }
            steps.append(.init("发送 hello 并等 challenge", true, "已收到"))

            let accepted: SecureWs.ClientHandshake.Accepted
            do {
                accepted = try handshake.acceptChallenge(challenge)
            } catch {
                let message = (error as? SecureError)?.message ?? "验证失败"
                steps.append(.init("校验 challenge", false, message))
                return NodeProbeReport(steps)
            }
            steps.append(.init("校验 challenge", true, "对端证明通过"))

            // finish 必须加密发送（与节点真实行为一致，见 Uploader 里的说明）
            do {
                try ws.sendText(try accepted.channel.encrypt(
                    Array(accepted.finish.utf8)))
            } catch {
                steps.append(.init("发送 finish 并等 secure_ok", false,
                                   "发送失败：\(error.localizedDescription)"))
                return NodeProbeReport(steps)
            }

            guard let okText = ws.nextMessage(timeoutMs) else {
                steps.append(.init("发送 finish 并等 secure_ok", false,
                                   "\(timeoutMs / 1000) 秒内没有响应"))
                return NodeProbeReport(steps)
            }
            if okText == WsClient.closedMarker {
                steps.append(.init("发送 finish 并等 secure_ok", false,
                                   "节点关闭了连接且没有给出错误码"))
                return NodeProbeReport(steps)
            }
            if let doc = Json.parse(okText),
               doc["type"]?.stringValue == SecureWs.errorType {
                let message = doc["msg"]?.stringValue ?? "invalid api_key"
                steps.append(.init("发送 finish 并等 secure_ok", false,
                                   "节点报错：\(message)"))
                return NodeProbeReport(steps)
            }
            steps.append(.init("发送 finish 并等 secure_ok", true, "鉴权完成"))

            let inner: String
            do {
                inner = String(decoding: try accepted.channel.decrypt(okText),
                               as: UTF8.self)
            } catch {
                let message = (error as? SecureError)?.message ?? "解密失败"
                steps.append(.init("解密回执", false, message))
                return NodeProbeReport(steps)
            }
            guard let doc = Json.parse(inner),
                  doc["type"]?.stringValue == SecureWs.okType else {
                steps.append(.init("解密回执", false,
                                   "回执内容不是 secure_ok：\(String(inner.prefix(120)))"))
                return NodeProbeReport(steps)
            }
            steps.append(.init("解密回执", true, "双方会话密钥一致（secure_ok）"))
            return NodeProbeReport(steps)
        } catch {
            let message = (error as? ProxyError)?.message
                ?? (error as? SecureError)?.message
                ?? error.localizedDescription
            steps.append(.init("自检异常", false, message))
            return NodeProbeReport(steps)
        }
    }
}
