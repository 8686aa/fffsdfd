import Foundation

/**
 SOCKS5 报文编解码 —— 与 `pc/collect/socks5.py`、`Socks5Proto.kt` 一致。

 这一层全是纯函数，可以拿固定字节做单测；网络部分在 App 的 `Socks5Server`。
 报文形状错了，现象是「客户端连上来就断」或「UDP 一个包都发不出去」，
 而双方都不报错 —— 所以「怎么切字节」必须能独立验证。

 ## 协议要点（RFC 1928 / 1929）

 协商：
 ```
   客户端 → VER(5) NMETHODS METHODS...
   服务端 → VER(5) METHOD          ; 0x00 无认证 / 0x02 用户名密码 / 0xFF 拒绝
 ```
 请求：
 ```
   客户端 → VER(5) CMD RSV(0) ATYP DST.ADDR DST.PORT
   服务端 → VER(5) REP RSV(0) ATYP BND.ADDR BND.PORT
 ```
 UDP 数据报：
 ```
   RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA
 ```
 */
public enum Socks5Proto {

    public static let version: UInt8 = 5

    public static let methodNoAuth: UInt8 = 0x00
    public static let methodUserPass: UInt8 = 0x02
    public static let methodNone: UInt8 = 0xFF

    public static let cmdConnect: UInt8 = 0x01
    public static let cmdBind: UInt8 = 0x02
    public static let cmdUdpAssociate: UInt8 = 0x03

    public static let atypIPv4: UInt8 = 0x01
    public static let atypDomain: UInt8 = 0x03
    public static let atypIPv6: UInt8 = 0x04

    public static let repOK: UInt8 = 0x00
    public static let repFailure: UInt8 = 0x01
    public static let repNotAllowed: UInt8 = 0x02
    public static let repNetUnreach: UInt8 = 0x03
    public static let repHostUnreach: UInt8 = 0x04
    public static let repRefused: UInt8 = 0x05
    public static let repTTLExpired: UInt8 = 0x06
    public static let repCmdUnsupported: UInt8 = 0x07
    public static let repAtypUnsupported: UInt8 = 0x08

    public static let maxUdpPacket = 65535

    public struct Request {
        public let command: UInt8
        public let host: String
        public let port: Int

        public init(command: UInt8, host: String, port: Int) {
            self.command = command
            self.host = host
            self.port = port
        }
    }

    public struct UdpPacket {
        public let host: String
        public let port: Int
        public let payload: [UInt8]
        public let headerLen: Int

        public init(host: String, port: Int, payload: [UInt8], headerLen: Int) {
            self.host = host
            self.port = port
            self.payload = payload
            self.headerLen = headerLen
        }
    }

    // ── 地址编码 ────────────────────────────────────────────────

    /**
     把 IPv4 地址编成 `ATYP+ADDR+PORT`。

     不是合法 IPv4 时退化成 `0.0.0.0`（与 Python 版一致）：回复报文里这个
     字段只是参考信息，多数客户端不用它；为了它把整条回复改成错误码反而
     更难排查。
     */
    public static func encodeAddr(_ ip: String, _ port: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 1 + 4 + 2)
        out[0] = atypIPv4
        let parts = ip.split(separator: ".", omittingEmptySubsequences: false)
        var valid = parts.count == 4
        if valid {
            for index in 0..<4 {
                guard let value = Int(parts[index]), (0...255).contains(value) else {
                    valid = false
                    break
                }
                out[1 + index] = UInt8(value)
            }
        }
        if !valid {
            for index in 1...4 { out[index] = 0 }
        }
        out[5] = UInt8((port >> 8) & 0xFF)
        out[6] = UInt8(port & 0xFF)
        return out
    }

    /// 构造一条回复：`VER REP RSV ATYP BND.ADDR BND.PORT`。
    public static func reply(_ code: UInt8, host: String = "0.0.0.0",
                             port: Int = 0) -> [UInt8] {
        let addr = encodeAddr(host, port)
        var out = [UInt8](repeating: 0, count: 3 + addr.count)
        out[0] = version
        out[1] = code
        out[2] = 0
        out.replaceSubrange(3..<(3 + addr.count), with: addr)
        return out
    }

    /**
     解析一个 SOCKS5 UDP 请求数据报。

     `FRAG != 0` 直接丢弃 —— RFC 1928 明确允许不实现分片，而游戏 UDP
     不会用 SOCKS5 层的分片。
     */
    public static func parseUdp(_ data: [UInt8]) -> UdpPacket? {
        if data.count < 4 { return nil }
        if data[0] != 0 || data[1] != 0 { return nil }
        if data[2] != 0 { return nil }
        let atyp = data[3]
        var offset = 4
        var host = ""
        switch atyp {
        case atypIPv4:
            if data.count < offset + 4 + 2 { return nil }
            host = "\(data[offset]).\(data[offset + 1]).\(data[offset + 2]).\(data[offset + 3])"
            offset += 4
        case atypIPv6:
            if data.count < offset + 16 + 2 { return nil }
            host = ipv6Text(Array(data[offset..<(offset + 16)]))
            offset += 16
        case atypDomain:
            if data.count < offset + 1 { return nil }
            let length = Int(data[offset])
            offset += 1
            if data.count < offset + length + 2 { return nil }
            host = String(decoding: data[offset..<(offset + length)], as: UTF8.self)
            offset += length
        default:
            return nil
        }
        let port = (Int(data[offset]) << 8) | Int(data[offset + 1])
        offset += 2
        return UdpPacket(host: host, port: port,
                         payload: Array(data[offset...]), headerLen: offset)
    }

    /// 反向：把要回给客户端的数据封成 SOCKS5 UDP 格式。
    public static func buildUdp(_ host: String, _ port: Int,
                                _ payload: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 3)
        out[0] = 0
        out[1] = 0
        out[2] = 0
        out.append(contentsOf: encodeAddr(host, port))
        out.append(contentsOf: payload)
        return out
    }

    /// IPv6 文本（RFC 5952 的常规压缩写法）。
    public static func ipv6Text(_ raw: [UInt8]) -> String {
        guard raw.count >= 16 else { return "" }
        var groups = [Int](repeating: 0, count: 8)
        for index in 0..<8 {
            groups[index] = (Int(raw[index * 2]) << 8) | Int(raw[index * 2 + 1])
        }
        // 找最长的一段连续 0，用 :: 压缩
        var bestStart = -1
        var bestLen = 0
        var index = 0
        while index < 8 {
            if groups[index] == 0 {
                var next = index
                while next < 8 && groups[next] == 0 { next += 1 }
                if next - index > bestLen {
                    bestLen = next - index
                    bestStart = index
                }
                index = next
            } else {
                index += 1
            }
        }
        let hex = { (value: Int) in String(value, radix: 16) }
        if bestLen < 2 {
            return (0..<8).map { hex(groups[$0]) }.joined(separator: ":")
        }
        let head = (0..<bestStart).map { hex(groups[$0]) }.joined(separator: ":")
        let tail = ((bestStart + bestLen)..<8).map { hex(groups[$0]) }
            .joined(separator: ":")
        return head + "::" + tail
    }

    public static func commandName(_ command: UInt8) -> String {
        switch command {
        case cmdConnect: return "CONNECT"
        case cmdBind: return "BIND"
        case cmdUdpAssociate: return "UDP ASSOCIATE"
        default: return String(format: "0x%02x", command)
        }
    }

    public static func replyName(_ code: UInt8) -> String {
        switch code {
        case repOK: return "succeeded"
        case repFailure: return "general failure"
        case repNotAllowed: return "not allowed"
        case repNetUnreach: return "network unreachable"
        case repHostUnreach: return "host unreachable"
        case repRefused: return "connection refused"
        case repTTLExpired: return "TTL expired"
        case repCmdUnsupported: return "command not supported"
        case repAtypUnsupported: return "address type not supported"
        default: return String(format: "0x%02x", code)
        }
    }
}
