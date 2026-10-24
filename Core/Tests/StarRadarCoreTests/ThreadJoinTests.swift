import XCTest
@testable import StarRadarCore

/**
 `ThreadJoin.either` 的语义测试。

 ## 为什么这个文件必须有

 这个工具曾经把「等任一方向结束」错写成「最多等 graceMs，然后无条件关连接」。
 后果不是崩溃、不是报错，而是**给每条连接设了 3 秒硬性寿命**：

 - 帧翻译通道：`[tun] 连接结束（63/65 帧）`，正好是 3 秒的心跳量
 - 普通端口转发：网页/API 全在 3 秒后断 → 整台设备「连上了但没网络」

 这种「安静地把功能做废」的错误，靠人看代码很难发现（代码读起来还挺合理），
 只能靠测试锁住「长连接不会被 grace 提前掐断」这条性质。
 */
final class ThreadJoinTests: XCTestCase {

    /// 线程安全的小开关，用来让「永不结束」的线程能正常退出。
    private final class Flag {
        private let lock = NSLock()
        private var value = false
        var isSet: Bool {
            lock.lock(); defer { lock.unlock() }
            return value
        }
        func set() {
            lock.lock(); value = true; lock.unlock()
        }
    }

    /// 一个「活 durationMs 之后自己退出」的线程；durationMs = 0 表示立刻退出。
    private func worker(_ name: String, _ durationMs: Int) -> Thread {
        let thread = Thread {
            if durationMs > 0 {
                Thread.sleep(forTimeInterval: Double(durationMs) / 1000.0)
            }
        }
        thread.name = name
        return thread
    }

    /// 一个「只有置位 flag 才会退出」的线程 —— 模拟半关闭后卡住的读。
    private func stuckWorker(_ flag: Flag) -> Thread {
        let thread = Thread {
            while !flag.isSet {
                Thread.sleep(forTimeInterval: 0.02)
            }
        }
        thread.name = "stuck"
        return thread
    }

    // ── 核心回归：长连接不能被 grace 提前掐断 ────────────────

    /// 两个方向都活跃超过 graceMs：不该调 onTimeout，也不该在 grace 处返回。
    ///
    /// 旧实现（`while Date() < graceDeadline { ... }; onTimeout()`）会在这里
    /// 立刻失败：200ms 就返回、而且还调了 onTimeout。
    func testLongLivedPairIsNotCutByGrace() {
        let a = worker("a", 800)
        let b = worker("b", 850)
        a.start()
        b.start()

        var timedOut = false
        let started = Date()
        ThreadJoin.either(a, b, graceMs: 200) { timedOut = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertFalse(timedOut,
                       "两个方向都在 grace 之后才结束，不该被迫断开")
        XCTAssertGreaterThan(elapsed, 0.75,
                             "either() 只用了 \(elapsed)s 就返回 —— 说明它在等 grace，"
                             + "而不是在等「某个方向结束」。这正是线上「连上 3 秒就断」的根因。")
    }

    /// 线上真实参数（3000ms）的复现：连接活到 3.5 秒，不能被 3 秒的 grace 杀掉。
    ///
    /// 这条用例直接对应日志 `[tun] 连接结束（63/65 帧）`：3 秒 × 约 20 帧/秒。
    func testThreeSecondGraceDoesNotKillLongConnection() {
        let a = worker("a", 3500)
        let b = worker("b", 3550)
        a.start()
        b.start()

        var timedOut = false
        let started = Date()
        ThreadJoin.either(a, b, graceMs: 3000) { timedOut = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertFalse(timedOut, "活过 3 秒的长连接不该被关掉")
        XCTAssertGreaterThan(elapsed, 3.4,
                             "只等了 \(elapsed)s —— grace 被当成了连接寿命")
    }

    // ── 另一半语义：该关的时候必须关 ────────────────────────

    /// 一方结束、另一方卡住（客户端半关闭后既不发也不关）：
    /// 必须在 grace 之后强制断开，否则线程永远不释放。
    func testStuckDirectionIsClosedAfterGrace() {
        let flag = Flag()
        let a = worker("a", 100)
        let b = stuckWorker(flag)
        a.start()
        b.start()
        defer { flag.set() }

        var timedOut = false
        let started = Date()
        ThreadJoin.either(a, b, graceMs: 300) { timedOut = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertTrue(timedOut, "另一方卡住时必须调 onTimeout，否则线程泄漏")
        XCTAssertGreaterThan(elapsed, 0.35,
                             "还没等满 grace 就断了，可能把残数据截断")
        XCTAssertLessThan(elapsed, 2.0,
                          "拖了 \(elapsed)s 才收尾，宽限期没生效")
    }

    /// 两个方向都干净结束：不能被误判成「需要强制关闭」。
    func testBothFinishedDoesNotTriggerForcedClose() {
        let a = worker("a", 0)
        let b = worker("b", 80)
        a.start()
        b.start()

        var timedOut = false
        let started = Date()
        ThreadJoin.either(a, b, graceMs: 2000) { timedOut = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertFalse(timedOut, "两个方向都正常结束，不该再关一次 socket")
        XCTAssertLessThan(elapsed, 1.0,
                          "都结束了还在等，说明第二阶段没提前 return")
    }

    /// graceMs 要真的被用上，不能被写死。
    ///
    /// 同一个「卡住」场景，grace 长短不同 → 总耗时应随之变化。
    func testGraceValueIsHonored() {
        let shortFlag = Flag()
        let shortA = worker("a", 50)
        let shortB = stuckWorker(shortFlag)
        shortA.start()
        shortB.start()
        let shortStart = Date()
        ThreadJoin.either(shortA, shortB, graceMs: 150) { }
        let shortElapsed = Date().timeIntervalSince(shortStart)
        shortFlag.set()

        let longFlag = Flag()
        let longA = worker("a", 50)
        let longB = stuckWorker(longFlag)
        longA.start()
        longB.start()
        let longStart = Date()
        ThreadJoin.either(longA, longB, graceMs: 600) { }
        let longElapsed = Date().timeIntervalSince(longStart)
        longFlag.set()

        XCTAssertGreaterThan(longElapsed - shortElapsed, 0.3,
                             "grace 600ms 与 150ms 的耗时应当差 0.45s 左右，"
                             + "实际差 \(longElapsed - shortElapsed)s —— grace 没生效")
    }
}
