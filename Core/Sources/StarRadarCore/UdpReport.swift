import Foundation

/**
 把「一条 UDP 数据报」整理成过滤器与上报要的形状。

 ## 这件事为什么值得单独抽出来

 采集层交上来的永远是「源 → 目的」，而过滤器需要的是
 「客户端（设备）↔ 服务器（对端）」这个**与方向无关**的规范形状：

 ```
   上行：src=客户端  dst=服务器   →  client=src, server=dst
   下行：src=服务器  dst=客户端   →  client=dst, server=src   ← 这里容易搞反
 ```

 搞反的后果不是「少报一个字段」，而是**所有下行包被整条丢掉**：
 `UdpGate` 第一步就判 `isNonPublic(serverIp)`，反转之后 serverIp 变成客户端的
 私网地址 —— 于是每条流都只剩上行，「双向」判据永远不成立，一局游戏一个包
 都上不去。现象是页面上「上行 UDP」在涨、「下行 UDP」是 0。
 */
public enum UdpReport {

    /// 规范形状：客户端一侧固定放 client*，对端固定放 server*。
    public struct Flow {
        public let clientIp: String
        public let clientPort: Int
        public let serverIp: String
        public let serverPort: Int
        public let up: Bool

        public init(clientIp: String, clientPort: Int, serverIp: String,
                    serverPort: Int, up: Bool) {
            self.clientIp = clientIp
            self.clientPort = clientPort
            self.serverIp = serverIp
            self.serverPort = serverPort
            self.up = up
        }
    }

    public static func normalize(srcIp: String, srcPort: Int, dstIp: String,
                                 dstPort: Int, up: Bool) -> Flow {
        if up {
            return Flow(clientIp: srcIp, clientPort: srcPort,
                        serverIp: dstIp, serverPort: dstPort, up: true)
        }
        return Flow(clientIp: dstIp, clientPort: dstPort,
                    serverIp: srcIp, serverPort: srcPort, up: false)
    }

    /// 按真实方向拼 IPv4+UDP 报文。非 IPv4 时返回 nil（跳过这一包）。
    public static func packet(_ flow: Flow, _ payload: [UInt8],
                              ttl: UInt8 = 64) -> [UInt8]? {
        do {
            if flow.up {
                return try IpDatagram.udp(srcIp: flow.clientIp, dstIp: flow.serverIp,
                                          srcPort: flow.clientPort,
                                          dstPort: flow.serverPort,
                                          payload: payload, ttl: ttl)
            }
            return try IpDatagram.udp(srcIp: flow.serverIp, dstIp: flow.clientIp,
                                      srcPort: flow.serverPort,
                                      dstPort: flow.clientPort,
                                      payload: payload, ttl: ttl)
        } catch {
            return nil
        }
    }
}
