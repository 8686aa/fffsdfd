import Foundation
import Darwin
import StarRadarCore

/**
 局域网地址发现 —— 与 `LanAddress.kt` 等价。

 另一台设备要连的是「这台手机在局域网里的地址」，不是 127.0.0.1。
 多个候选时按可用性排序：Wi-Fi（en0）优先，其次热点（bridge/pdp_ip 系）。
 */
public enum LanAddress {

    public struct Candidate {
        public let ip: String
        public let label: String
        public let score: Int

        public init(ip: String, label: String, score: Int) {
            self.ip = ip
            self.label = label
            self.score = score
        }
    }

    /// 取最可能被另一台设备访问到的那个地址。
    public static func best() -> Candidate? {
        all().first
    }

    public static func all() -> [Candidate] {
        var candidates: [Candidate] = []
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return [] }
        defer { freeifaddrs(pointer) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let address = entry.pointee.ifa_addr else { continue }
            let family = address.pointee.sa_family
            if family != UInt8(AF_INET) { continue }
            let flags = Int32(entry.pointee.ifa_flags)
            if flags & IFF_UP == 0 || flags & IFF_LOOPBACK != 0 { continue }

            let name = String(cString: entry.pointee.ifa_name)
            var host = [CChar](repeating: 0, count: Int(NET_ADDRSTRLEN))
            address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer in
                var raw = pointer.pointee.sin_addr
                inet_ntop(AF_INET, &raw, &host, socklen_t(NET_ADDRSTRLEN))
            }
            let ip = String(cString: host)
            if ip.isEmpty || ip.hasPrefix("169.254.") { continue }   // 自分配地址

            let (label, score) = classify(name)
            candidates.append(Candidate(ip: ip, label: label, score: score))
        }
        return candidates.sorted {
            if $0.score != $1.score { return $0.score > $1.score }
            return $0.ip < $1.ip
        }
    }

    /// 接口名 → (给用户看的名字, 排序分)。
    ///
    /// iOS 的接口名与 Android 不同：Wi-Fi 是 `en0`，个人热点共享出去的
    /// 网段通常也是 `en0` 或 `bridge100`，蜂窝是 `pdp_ip0`。
    private static func classify(_ name: String) -> (String, Int) {
        if name == "en0" { return ("Wi-Fi", 100) }
        if name.hasPrefix("bridge") { return ("热点", 90) }
        if name.hasPrefix("en") { return ("网络 \(name)", 80) }
        if name.hasPrefix("pdp_ip") { return ("蜂窝", 40) }
        if name.hasPrefix("utun") || name.hasPrefix("ipsec") {
            return ("VPN \(name)", 10)
        }
        return (name, 20)
    }
}
