import Foundation

/**
 双向转发的收尾：等任一方向结束，再给另一个方向一段宽限。

 ## 正确语义（两阶段，缺一不可）

 ```
   第一阶段：不限时，等任一方向结束        ← 正常的长连接会一直停在这里
   第二阶段：再给另一个方向 graceMs 收尾
   两个都结束了        → 直接返回，不碰 socket
   过了 grace 还有残留 → 调 onTimeout（shutdown socket，把阻塞的 read 逼出来）
 ```

 ## ⚠️ 曾经的两种错误写法

 **错误一：把 grace 当成连接寿命。**

 ```swift
 let deadline = Date() + graceMs
 while Date() < deadline { if 任一结束 break }
 onTimeout()                      // ← 无条件调用
 ```

 这等于给每条连接设了 3 秒硬性寿命：时间一到就把两端 socket 全关掉，不管数据
 有没有传完。线上表现是另一台设备「连上了但一会儿就断」，日志里帧数永远停在
 60 上下（3 秒的心跳量）。而普通端口转发（网页/API）走同一段代码，于是整台
 设备表现为**完全断网**。

 **错误二：用 `Thread.isFinished` 判断方向是否结束。**

 `isFinished` 依赖 Foundation 内部的线程状态更新。对于 `Thread(block:)` 创建的
 线程，这个状态在**异常路径**上不一定及时更新；一旦它提前变 true，第一阶段
 立刻退出、第二阶段干等满 grace 后强制关连接 —— 症状和错误一模一样。

 现在改成**显式退出信号** `ExitSignal`：pump 函数在真正要退出的那一刻自己置位，
 不猜、不依赖框架状态。置位时还会带上原因（EOF / 读错误 errno / 引擎拒绝），
 结束日志因此能直接说明「是哪一侧、因为什么先退的」。

 ## 为什么收尾要用 `shutdown` 而不是 `close`

 POSIX 规定一个 fd 正被别的线程 `read` 时 `close` 的行为**未定义**；macOS 上常见
 的结果是那个 `read` 永久不返回（内核还持有 file description 的引用），线程就
 泄漏了。`shutdown(fd, SHUT_RDWR)` 则保证阻塞中的 `read` 立刻返回 0。
 所以两处调用点的 `onTimeout` 都是「先 shutdown 两端，再 close」。
 */
public enum ThreadJoin {

    /// 轮询步长。20ms 足够及时，锁检查的开销可忽略。
    public static let stepMs = 20

    /// 收尾结果。日志里要能说清「谁先退出、是不是被强制断的」。
    public struct Outcome {
        /// 先退出的方向标签（如 `"c2s"`）。两边都没退出却超时则为空串。
        public let firstExit: String
        /// 先退出的原因（EOF / 读错误 errno N / 引擎拒绝：…）。
        public let firstReason: String
        /// 是否因宽限到期而强制断开。
        public let forced: Bool
    }

    /**
     等任一方向结束后收尾。

     - Parameters:
       - first/second: 两个方向的退出信号。
       - graceMs: 先结束的一方退出后，给另一方多少毫秒把残数据传完。
       - onTimeout: 过了 grace 仍有方向存活时调用。**必须**在里面 shutdown
         两端 socket（光 close 唤不醒别的线程里阻塞的 read）。
     */
    @discardableResult
    public static func either(_ first: ExitSignal, _ second: ExitSignal,
                              graceMs: Int,
                              onTimeout: () -> Void) -> Outcome {
        // 第一阶段：不限时。这条循环是「正常长连接」的常态 ——
        // 游戏连接可以几十分钟都停在这里，这是对的。
        while !first.isFired && !second.isFired {
            Thread.sleep(forTimeInterval: Double(stepMs) / 1000.0)
        }

        let leader = first.isFired ? first : second
        let leaderTag = first.isFired ? first.tag : second.tag
        let leaderReason = leader.reason

        // 第二阶段：一方已经结束，给另一方 graceMs。
        let deadline = Date().addingTimeInterval(Double(graceMs) / 1000.0)
        while Date() < deadline {
            if first.isFired && second.isFired {
                return Outcome(firstExit: leaderTag, firstReason: leaderReason,
                               forced: false)
            }
            Thread.sleep(forTimeInterval: Double(stepMs) / 1000.0)
        }

        // 到这儿说明有方向还卡着（半关闭后对端不再发也不再关）。
        onTimeout()
        return Outcome(firstExit: leaderTag, firstReason: leaderReason,
                       forced: true)
    }
}

/**
 一个方向「我结束了」的显式信号。

 用它替代 `Thread.isFinished`：pump 在真正退出前自己调用 `fire(_:)`，
 带上可读原因。这样「谁先退出、为什么」不再靠猜。
 */
public final class ExitSignal {

    private let lock = NSLock()
    private var fired = false
    private var reasonText = ""

    /// 方向标签（`c2s` / `s2c` / `client→server` …），只用于日志。
    public let tag: String

    public init(tag: String) {
        self.tag = tag
    }

    /// 置位。只有第一次调用会记住原因（后续调用不会覆盖真正的首因）。
    public func fire(_ reason: String) {
        lock.lock()
        if !fired {
            fired = true
            reasonText = reason
        }
        lock.unlock()
    }

    public var isFired: Bool {
        lock.lock()
        defer { lock.unlock() }
        return fired
    }

    public var reason: String {
        lock.lock()
        defer { lock.unlock() }
        return reasonText
    }
}
