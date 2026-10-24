import Foundation

/**
 双向转发的收尾：等任一方向结束，再给另一个方向一段宽限。

 ## 为什么不能用 `a.join()` 然后 `b.join(grace)`

 一条双向连接有两个方向线程。**服务器先关是常态**：HTTP 短连接回完就断、
 游戏服踢人、目标端口不存在时回 RST。那种情况下「服务器 → 客户端」那一侧
 立刻读到 EOF 结束，而「客户端 → 服务器」还在安静地等客户端发数据 ——
 客户端可能既不发也不关。

 于是 `a.join()` 永久阻塞：这条连接的线程再也不释放。跑一段时间线程/连接号
 就耗光了，表现为「用着用着就连不上了」，而现场看每条连接都「正常建立过」。

 ## 正确语义（两阶段，缺一不可）

 ```
   第一阶段：不限时，等任一方向结束        ← 正常的长连接会一直停在这里
   第二阶段：再给另一个方向 graceMs 收尾
   两个都结束了        → 直接返回，不碰 socket
   过了 grace 还有残留 → 调 onTimeout（关 socket，把阻塞的 read 逼出来）
 ```

 ## ⚠️ 曾经把这里写成「最多等 graceMs，然后无条件 onTimeout」

 那等于**给每条连接设了 3 秒的硬性寿命**：时间一到就把两端 socket 全关掉，
 不管数据有没有传完、也不管对端还想不想继续。

 iOS 端线上表现就是这样：另一台设备「连上了但一会儿就断」，日志里
 `[tun] 连接结束（63/65 帧）` —— 60 多帧正好是 3 秒内游戏的心跳量。
 而普通端口转发（网页、API）走的是同一个 `either()`，于是整台设备表现为
 **完全断网**，不只是某个游戏断线。

 这个 bug 极其安静：不崩溃、不报错、帧数看着还挺正常，只是连接短命。
 单测在 `ThreadJoinTests.swift` 里锁住了「长连接不会被 grace 提前掐断」。
 */
public enum ThreadJoin {

    /// 轮询步长。50ms 足够及时，又不会把 CPU 烧起来。
    public static let stepMs = 50

    /**
     等任一方向结束后收尾。

     - Parameters:
       - first/second: 两个方向线程（**必须已经 start**，否则会一直等）。
       - graceMs: 先结束的一方退出后，给另一方多少毫秒把残数据传完。
       - onTimeout: 过了 grace 仍有线程存活时调用。通常是 `shutdown` 两端
         socket —— 光 `close` 不保证能唤醒另一个线程里阻塞着的 `read`。
     */
    public static func either(_ first: Thread, _ second: Thread,
                              graceMs: Int,
                              onTimeout: () -> Void) {
        let step = Double(stepMs) / 1000.0

        // 第一阶段：不限时。这条循环是「正常连接」的常态 —— 游戏长连接可以
        // 跑几十分钟都停在这里，这是对的。
        while !first.isFinished && !second.isFinished {
            Thread.sleep(forTimeInterval: step)
        }

        // 第二阶段：一方已经结束，给另一方 graceMs。
        let deadline = Date().addingTimeInterval(Double(graceMs) / 1000.0)
        while Date() < deadline {
            if first.isFinished && second.isFinished { return }
            Thread.sleep(forTimeInterval: step)
        }

        // 到这儿说明有线程还卡着（半关闭后对端不再发也不再关）。
        // 关 socket 让它的 read 立刻返回，线程才能退出。
        onTimeout()
    }
}
