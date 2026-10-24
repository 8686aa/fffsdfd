import Foundation

/**
 构造一个完整的 IPv4 + UDP 报文 —— 与 `core/dumper.py` 的 `ip_datagram` 一致。

 ## 为什么要自己拼，而不是把收到的包原样送上去

 上报内容是**整包 IP 报文**（节点侧按 IP 头解析五元组）。SOCKS5 的 UDP
 ASSOCIATE 交给我们的是裸载荷，没有 IP 头；而且我们要对齐手机真实出网的
 样子（TTL 64 / IP ID 0），所以统一重建。

 校验和一定要算对：节点侧只要校验，一个错的 checksum 会让整批包被丢，
 而现象是「上报成功但读不出内容」。
 */
public enum IpDatagram {

    public static func udp(srcIp: String, dstIp: String, srcPort: Int,
                           dstPort: Int, payload: [UInt8],
                           ttl: UInt8 = 64) throws -> [UInt8] {
        let src = try ipv4Bytes(srcIp)
        let dst = try ipv4Bytes(dstIp)

        let udpLen = 8 + payload.count
        var udp = [UInt8](repeating: 0, count: udpLen)
        Bytes.putU16(&udp, 0, srcPort)
        Bytes.putU16(&udp, 2, dstPort)
        Bytes.putU16(&udp, 4, udpLen)
        Bytes.putU16(&udp, 6, 0)              // 校验和先占位
        udp.replaceSubrange(8..<udpLen, with: payload)

        // UDP 校验和用伪头：src(4) dst(4) 0(1) proto(1) udp_len(2)
        var pseudo = src + dst
        pseudo.append(0)
        pseudo.append(17)                     // UDP
        // UDP 长度字段占 2 字节：先占位再回填，避免越界写
        pseudo.append(contentsOf: [0, 0])
        Bytes.putU16(&pseudo, 10, udpLen)
        pseudo.append(contentsOf: udp)
        Bytes.putU16(&udp, 6, checksum(pseudo))

        let total = 20 + udpLen
        var header = [UInt8](repeating: 0, count: 20)
        header[0] = 0x45                      // IPv4, IHL=5
        header[1] = 0
        Bytes.putU16(&header, 2, total)
        Bytes.putU16(&header, 4, 0)           // IP ID = 0（与手机一致）
        Bytes.putU16(&header, 6, 0)           // flags/frag = 0
        header[8] = ttl
        header[9] = 17                        // UDP
        Bytes.putU16(&header, 10, 0)
        header.replaceSubrange(12..<16, with: src)
        header.replaceSubrange(16..<20, with: dst)
        Bytes.putU16(&header, 10, checksum(header))

        return header + udp
    }

    /// 标准 Internet 校验和（RFC 1071）。
    public static func checksum(_ data: [UInt8]) -> Int {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < data.count {
            sum += (UInt32(data[index]) << 8) | UInt32(data[index + 1])
            index += 2
        }
        if index < data.count {
            sum += UInt32(data[index]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return Int((~sum) & 0xFFFF)
    }

    /// "1.2.3.4" → 4 字节；不是合法 IPv4 抛错（只支持 IPv4）。
    public static func ipv4Bytes(_ text: String) throws -> [UInt8] {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            throw ProxyError("只支持 IPv4：\(text)")
        }
        var out = [UInt8]()
        for part in parts {
            guard let value = Int(part), (0...255).contains(value) else {
                throw ProxyError("只支持 IPv4：\(text)")
            }
            out.append(UInt8(value))
        }
        return out
    }

    public static func isIpv4(_ text: String) -> Bool {
        (try? ipv4Bytes(text)) != nil
    }
}
