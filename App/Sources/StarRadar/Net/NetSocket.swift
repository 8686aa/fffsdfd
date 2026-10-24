import Foundation
import Darwin
import StarRadarCore

/**
 一层薄薄的 BSD socket 封装。

 ## 为什么 iOS 端不用 Network.framework

 这套代理的行为细节全部围绕「字节流」：握手要逐字节读（不能预读，否则
 CONNECT 后紧跟的载荷会被吞掉）、半关闭要把 EOF 透传给对端、超时要能
 精确设到某一步。BSD socket 的 `read` / `shutdown` / `SO_RCVTIMEO`
 正好一一对应，移植时几乎不需要重新推理；而 `NWConnection` 是消息式的
 回调模型，得自己再拼一层缓冲，反而多出一处可能出错的地方。

 iOS 上普通 App 可以监听 >1024 的端口，不需要任何特权 —— 需要的是
 Info.plist 里的 `NSLocalNetworkUsageDescription`（首次访问局域网时
 系统会弹一次授权）。
 */
public final class NetSocket {

    public private(set) var fd: Int32

    public init(fd: Int32) {
        self.fd = fd
    }

    deinit {
        close()
    }

    // ── 建连 ──────────────────────────────────────────────────

    /// 主动连接。失败抛错，错误里带上 errno 的语义分类。
    public static func connect(host: String, port: Int,
                               timeoutMs: Int = 10_000) throws -> NetSocket {
        guard let ip = try HostResolver.ipv4(host) else {
            throw ProxyError("解析不到 \(host) 的 IPv4 地址")
        }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 { throw ProxyError("socket() 失败：\(errno)") }

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        if inet_pton(AF_INET, ip, &address.sin_addr) != 1 {
            Darwin.close(fd)
            throw ProxyError("地址非法：\(ip)")
        }

        // 非阻塞 connect + poll：阻塞式 connect 在不可达时可能挂几十秒，
        // 而我们要的是「10 秒内给客户端一个明确的失败码」。
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result != 0 {
            if errno != EINPROGRESS {
                let code = errno
                Darwin.close(fd)
                throw ProxyError(code == ECONNREFUSED
                                 ? "连接被拒绝（errno \(code)）"
                                 : "连接失败（errno \(code)）")
            }
            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&descriptor, 1, Int32(timeoutMs))
            if ready <= 0 {
                Darwin.close(fd)
                throw ProxyError("连接超时（\(timeoutMs / 1000) 秒）")
            }
            var socketError: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &length)
            if socketError != 0 {
                Darwin.close(fd)
                throw ProxyError(socketError == ECONNREFUSED
                                 ? "连接被拒绝（errno \(socketError)）"
                                 : "连接失败（errno \(socketError)）")
            }
        }
        _ = fcntl(fd, F_SETFL, flags)          // 恢复阻塞模式
        let socket = NetSocket(fd: fd)
        socket.setNoDelay()
        return socket
    }

    /// 监听 `0.0.0.0:port`。port 传 0 由系统分配（测试用）。
    public static func listen(port: Int) throws -> NetSocket {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 { throw ProxyError("socket() 失败：\(errno)") }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        address.sin_addr.s_addr = INADDR_ANY

        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bound != 0 {
            let code = errno
            Darwin.close(fd)
            throw ProxyError("监听 0.0.0.0:\(port) 失败（errno \(code)，端口被占用？）")
        }
        if Darwin.listen(fd, 64) != 0 {
            let code = errno
            Darwin.close(fd)
            throw ProxyError("listen() 失败（errno \(code)）")
        }
        return NetSocket(fd: fd)
    }

    /// 接受一条连接。返回新 socket 与对端 IP。
    public func accept() throws -> (NetSocket, String) {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let client = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.accept(fd, $0, &length)
            }
        }
        if client < 0 {
            throw ProxyError("accept() 失败（errno \(errno)）")
        }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN))
        let peer = String(cString: buffer)
        return (NetSocket(fd: client), peer)
    }

    // ── 读写 ──────────────────────────────────────────────────

    /// 读一次。返回 0 表示 EOF（与 POSIX 的 -0 区分：这里用 -1 表示错误）。
    public func read(_ buffer: inout [UInt8], maxLength: Int? = nil) -> Int {
        let size = maxLength ?? buffer.count
        return buffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return -1 }
            return Darwin.read(fd, base, size)
        }
    }

    /// 读满 n 字节。EOF 或出错抛错。
    ///
    /// ⚠️ 握手必须用这个而不是「一次 read」：客户端可能把 CONNECT 和后续
    /// 载荷一起发来，一次 read 会多拿，多出来的字节在交给隧道后就丢了
    /// —— 现象是「连上了，但客户端说协议错」。
    public func readFully(_ count: Int) throws -> [UInt8] {
        if count == 0 { return [] }
        var out = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let got = out.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.read(fd, base.advanced(by: offset), count - offset)
            }
            if got <= 0 {
                if got == 0 { throw ProxyError("连接在读完之前关闭") }
                if errno == EINTR { continue }
                throw ProxyError("读失败（errno \(errno)）")
            }
            offset += got
        }
        return out
    }

    public func write(_ data: [UInt8]) throws {
        if data.isEmpty { return }
        var offset = 0
        while offset < data.count {
            let sent = data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.send(fd, base.advanced(by: offset), data.count - offset,
                                   0)
            }
            if sent <= 0 {
                if errno == EINTR { continue }
                throw ProxyError("写失败（errno \(errno)）")
            }
            offset += sent
        }
    }

    public func shutdownWrite() {
        _ = Darwin.shutdown(fd, SHUT_WR)
    }

    public func close() {
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }

    // ── 选项 ──────────────────────────────────────────────────

    public func setNoDelay() {
        var value: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value,
                   socklen_t(MemoryLayout<Int32>.size))
    }

    /// 读超时。`ms <= 0` 表示不超时（长连接用）。
    public func setRecvTimeout(ms: Int) {
        var timeout = timeval(tv_sec: ms / 1000, tv_usec: Int32((ms % 1000) * 1000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))
    }

    public func localPort() -> Int {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &length)
            }
        }
        if result != 0 { return 0 }
        return Int(UInt16(bigEndian: address.sin_port))
    }

    public func localIPv4() -> String {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &length)
            }
        }
        if result != 0 { return "0.0.0.0" }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN))
        let text = String(cString: buffer)
        return text == "0.0.0.0" ? "0.0.0.0" : text
    }
}

/// 域名 → IPv4。只支持 IPv4：上报链路发的是 IPv4 数据报，构造不出 IPv6 五元组。
public enum HostResolver {

    private static let cacheLock = NSLock()
    private static var cache: [String: String] = [:]

    public static func ipv4(_ host: String) throws -> String? {
        if host.isEmpty { return nil }
        if IpDatagram.isIpv4(host) { return host }
        if host.contains(":") { return nil }            // IPv6 目标：不支持

        cacheLock.lock()
        if let cached = cache[host] {
            cacheLock.unlock()
            return cached
        }
        cacheLock.unlock()

        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET,
                             ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil,
                             ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        defer { if result != nil { freeaddrinfo(result) } }
        guard status == 0, let info = result else { return nil }
        guard let address = info.pointee.ai_addr else { return nil }
        var ip = ""
        address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer in
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &pointer.pointee.sin_addr, &buffer,
                      socklen_t(INET_ADDRSTRLEN))
            ip = String(cString: buffer)
        }
        if ip.isEmpty { return nil }
        cacheLock.lock()
        if cache.count > 256 { cache.removeAll() }
        cache[host] = ip
        cacheLock.unlock()
        return ip
    }
}
