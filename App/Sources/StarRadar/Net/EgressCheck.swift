import Foundation
import Darwin

/**
 出站指纹自检 —— 与 `EgressCheck.kt` 同思路。

 ## 为什么 iOS 端也要查这一项

 这套代理**不做**任何 TCP 指纹伪装，因为上游连接是 iOS 内核自己发的：
 TTL 64、TCP options 顺序、ISN、IP ID 全部是本机原生的，本来就与「一台
 iPhone 该有的样子」一致。PC 版需要伪装成手机，是因为它用 Windows 内核
 重连；iOS 端没有这个问题。

 **唯一会破坏这个前提的**是：出站被第三方 VPN / 加速器接管。那时真正的
 TCP 栈变成隧道服务器的，若其出口是 Windows，PC 版那个「应用层 iPhone +
 网络层 Windows」的跨层矛盾就被重新造出来了。

 所以这里只检查、不改动 —— 原生值本来就是对的，硬改反而有风险。
 */
public enum EgressCheck {

    public enum Level: String {
        case ok = "OK"
        case warn = "WARN"
        case bad = "BAD"
    }

    public struct Verdict {
        public let level: Level
        public let summary: String
        public let detail: String

        public init(_ level: Level, _ summary: String, _ detail: String) {
            self.level = level
            self.summary = summary
            self.detail = detail
        }
    }

    public static func check(ourVpnRunning: Bool = false) -> Verdict {
        var hasVpn = false
        var transport = ""
        var mtu = 0
        var addressCount = 0

        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else {
            return Verdict(.warn, "读不到网络状态",
                           "系统没返回网卡列表，这次无法确认出站是否被 VPN 接管")
        }
        defer { freeifaddrs(pointer) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0 else { continue }
            let name = String(cString: entry.pointee.ifa_name)

            if name.hasPrefix("utun") || name.hasPrefix("ipsec") ||
                name.hasPrefix("ppp") {
                hasVpn = true
            }
            guard let address = entry.pointee.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET) else { continue }
            if flags & IFF_LOOPBACK != 0 { continue }

            addressCount += 1
            if transport.isEmpty {
                if name == "en0" {
                    transport = "Wi-Fi"
                } else if name.hasPrefix("pdp_ip") {
                    transport = "蜂窝"
                } else if name.hasPrefix("bridge") {
                    transport = "热点"
                } else {
                    transport = name
                }
            }
            if mtu == 0, let data = entry.pointee.ifa_data {
                let info = data.assumingMemoryBound(to: if_data.self).pointee
                mtu = Int(info.ifi_mtu)
            }
        }

        if addressCount == 0 {
            return Verdict(.warn, "当前没有 IPv4 网络",
                           "连不上节点，也接不了另一台设备：先连 Wi-Fi 或开热点")
        }
        // 自己的 VPN 模式不存在于 iOS 端（没有 NetworkExtension），
        // 所以这里的 VPN 一律视为第三方接管。
        if hasVpn && !ourVpnRunning {
            return Verdict(.bad, "出站可能被 VPN 接管",
                           "检测到 utun/ipsec 接口：先关掉那个 VPN / 加速器再开始代理。" +
                           "否则连游戏服务器的 TCP 栈会变成隧道服务器的，" +
                           "服务器能看出「应用层是 iPhone、网络层是别的系统」")
        }
        if mtu > 0 && (mtu < 1400 || mtu > 1500) {
            return Verdict(.warn, "出站分段可能异常（MTU \(mtu)）",
                           "隧道或蜂窝的 MTU 偏离常见值，包会被切得更碎；" +
                           "不改变 TCP 栈身份，但收发节奏会与典型客户端不同")
        }
        return Verdict(.ok, "出站指纹正常（\(transport)\(mtu > 0 ? " · MTU \(mtu)" : "")）",
                       "上游连接由 iOS 内核直接发起，TTL/选项顺序都是本机原生")
    }
}
