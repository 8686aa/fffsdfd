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

 另外这里还锁住了「用显式 ExitSignal 而不是 Thread.isFinished」这个决定：
 后者在线程异常退出时可能不更新，会让第一阶段误判为「已完成」。
 */
final class ThreadJoinTests: XCTestCase {

    /// 过 `durationMs` 之后自己置位的信号 —— 模拟「某方向正常结束」。
    private func fireAfter(_ signal: ExitSignal, _ durationMs: Int,
                           _ reason: String) -> Thread {
        let thread = Thread {
            if durationMs > 0 {
                Thread.sleep(forTimeInterval: Double(durationMs) / 1000.0)
            }
            signal.fire(reason)
        }
        thread.name = "fire-\(signal.tag)"
        return thread
    }

    // ── 核心回归：长连接不能被 grace 提前掐断 ────────────────

    /// 两个方向都活跃超过 graceMs：不该强制断开，也不该在 grace 处返回。
    ///
    /// 旧实现（`while Date() < graceDeadline { ... }; onTimeout()`）会在这里
    /// 立刻失败：200ms 就返回、而且还调了 onTimeout。
    func testLongLivedPairIsNotCutByGrace() {
        let a = ExitSignal(tag: "a")
        let b = ExitSignal(tag: "b")
        fireAfter(a, 800, "a 正常结束").start()
        fireAfter(b, 850, "b 正常结束").start()

        var forced = false
        let started = Date()
        let outcome = ThreadJoin.either(a, b, graceMs: 200) { forced = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertFalse(forced, "两个方向都在 grace 之后才结束，不该被迫断开")
        XCTAssertFalse(outcome.forced)
        XCTAssertGreaterThan(elapsed, 0.75,
                             "either() 只用了 \(elapsed)s 就返回 —— 说明它在等 grace，"
                             + "而不是在等「某个方向结束」。这正是线上「连上 3 秒就断」的根因。")
        XCTAssertEqual(outcome.firstExit, "a", "应当报出先退出的那一侧")
        XCTAssertEqual(outcome.firstReason, "a 正常结束", "退出原因要能带出来")
    }

    /// 线上真实参数（3000ms）的复现：连接活到 3.5 秒，不能被 3 秒的 grace 杀掉。
    ///
    /// 这条用例直接对应日志 `[tun] 连接结束（63/65 帧）`：3 秒 × 约 20 帧/秒。
    func testThreeSecondGraceDoesNotKillLongConnection() {
        let a = ExitSignal(tag: "c2s")
        let b = ExitSignal(tag: "s2c")
        fireAfter(a, 3500, "对端 EOF").start()
        fireAfter(b, 3550, "对端 EOF").start()

        var forced = false
        let started = Date()
        ThreadJoin.either(a, b, graceMs: 3000) { forced = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertFalse(forced, "活过 3 秒的长连接不该被关掉")
        XCTAssertGreaterThan(elapsed, 3.4,
                             "只等了 \(elapsed)s —— grace 被当成了连接寿命")
    }

    // ── 另一半语义：该关的时候必须关 ────────────────────────

    /// 一方结束、另一方卡住（客户端半关闭后既不发也不关）：
    /// 必须在 grace 之后强制断开，否则线程永远不释放。
    func testStuckDirectionIsClosedAfterGrace() {
        let a = ExitSignal(tag: "c2s")
        let b = ExitSignal(tag: "stuck")        // 永不置位
        fireAfter(a, 100, "对端 EOF").start()

        var forced = false
        let started = Date()
        let outcome = ThreadJoin.either(a, b, graceMs: 300) { forced = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertTrue(forced, "另一方卡住时必须调 onTimeout，否则线程泄漏")
        XCTAssertTrue(outcome.forced)
        XCTAssertGreaterThan(elapsed, 0.35, "还没等满 grace 就断了，可能把残数据截断")
        XCTAssertLessThan(elapsed, 2.0, "拖了 \(elapsed)s 才收尾，宽限期没生效")
        XCTAssertEqual(outcome.firstReason, "对端 EOF")
    }

    /// 两个方向都干净结束：不能被误判成「需要强制关闭」。
    func testBothFinishedDoesNotTriggerForcedClose() {
        let a = ExitSignal(tag: "a")
        let b = ExitSignal(tag: "b")
        fireAfter(a, 0, "EOF").start()
        fireAfter(b, 80, "EOF").start()

        var forced = false
        let started = Date()
        ThreadJoin.either(a, b, graceMs: 2000) { forced = true }
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertFalse(forced, "两个方向都正常结束，不该再关一次 socket")
        XCTAssertLessThan(elapsed, 1.0, "都结束了还在等，说明第二阶段没提前 return")
    }

    /// graceMs 要真的被用上，不能被写死。
    func testGraceValueIsHonored() {
        func measure(_ graceMs: Int) -> Double {
            let a = ExitSignal(tag: "a")
            let b = ExitSignal(tag: "stuck")
            fireAfter(a, 50, "EOF").start()
            let started = Date()
            ThreadJoin.either(a, b, graceMs: graceMs) { }
            return Date().timeIntervalSince(started)
        }
        let short = measure(150)
        let long = measure(600)
        XCTAssertGreaterThan(long - short, 0.3,
                             "grace 600ms 与 150ms 的耗时应当差 0.45s 左右，"
                             + "实际差 \(long - short)s —— grace 没生效")
    }

    // ── 信号本身 ──────────────────────────────────────────────

    /// 只有第一次 fire 生效：后到的原因不能覆盖真正的首因。
    func testExitSignalKeepsFirstReason() {
        let signal = ExitSignal(tag: "c2s")
        XCTAssertFalse(signal.isFired)
        signal.fire("对端 EOF")
        signal.fire("读失败 errno 54")
        XCTAssertTrue(signal.isFired)
        XCTAssertEqual(signal.reason, "对端 EOF", "首因不能被后来的覆盖")
    }

    /// 并发 fire 不能崩，也不能让 isFired 出现「假」的中间态。
    func testExitSignalIsThreadSafe() {
        let signal = ExitSignal(tag: "race")
        let group = DispatchGroup()
        for index in 0..<32 {
            DispatchQueue.global().async(group: group) {
                signal.fire("第 \(index) 个线程")
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(signal.isFired)
        XCTAssertFalse(signal.reason.isEmpty, "并发置位后原因不能是空")
    }
}
