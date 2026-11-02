import Foundation

/// 换钥总闸 —— 与 PC 版 `core/proxy.py`、安卓版 `RekeyGate.kt` 同一套语义。
///
/// ## 为什么要它
///
/// 把 65010 的字节流翻译成明文、从而拿到母料，代价是**换掉了 DH 公钥**。
/// 服务器只要做一次公钥一致性校验就知道有中间人（PC 版实测：换过一次就够，
/// 之后约 13 秒被要求重连）。所以「换多少次」本身就是要控的资源。
///
/// 三条结论照搬：
///
/// 1. **总闸**（`armed`）：默认关。只有用户点「重新采集」才打开；
///    采到母料立刻关掉 —— 这一局剩下的时间零换钥、零暴露。
/// 2. **最小间隔**（`minGapMs`）：挡掉大厅那种 5 秒一条的短连接。
/// 3. **风暴冷却**：窗口内连接过密就暂停一段，防止被反复踢时连环换钥。
///
/// 外加一条 **对局放行**：UDP 对局流速起来后的几十秒内强制放行。
/// 母料是「入局那一刻」下发的，而那时客户端不一定重建连接 —— 如果那条
/// 连接正好被最小间隔挡掉，整盘就采不到（PC 版实测差 3 秒错过一整局）。
///
/// ## 线程安全
///
/// 调用发生在 SOCKS5 的 accept 线程、UDP 上报线程、UI 主线程三处，
/// 所有状态用一把 `NSLock` 保护；决策函数本身不做 IO，不会卡住连接。
public final class RekeyGate {

    public struct Decision {
        public let allowed: Bool
        public let reason: String
    }

    // MARK: - 可调参数

    /// 两次换钥之间的最小间隔（毫秒）。
    public var minGapMs: Int64
    /// 风暴统计窗口（毫秒）。
    public var stormWindowMs: Int64
    /// 窗口内连接数达到这个值就算「过密」。
    public var stormMinConns: Int
    /// 冷却时长（毫秒）。0 = 不启用。
    public var stormCooldownMs: Int64
    /// 采到母料后是否自动撤防。
    public var disarmOnMaterial: Bool
    /// 「对局刚起来」的放行窗口（毫秒）。
    public var battleWindowMs: Int64

    // MARK: - 状态（全部受 lock 保护）

    private let lock = NSLock()
    private var _armed: Bool
    private var lastRekeyAt: Int64 = 0
    private var recentConns: [Int64] = []
    private var cooldownUntil: Int64 = 0
    private var cooldownHits = 0
    private var _battleSeenAt: Int64 = 0
    private var _opened = 0
    private var _skipped = 0
    private var _skipReason = ""

    /// 总闸：true = 允许换钥（采集窗口开着）。
    public var armed: Bool {
        lock.lock(); defer { lock.unlock() }
        return _armed
    }

    /// 已换钥次数。
    public var opened: Int {
        lock.lock(); defer { lock.unlock() }
        return _opened
    }

    /// 被闸门跳过的次数。
    public var skipped: Int {
        lock.lock(); defer { lock.unlock() }
        return _skipped
    }

    /// 最近一次跳过原因，给界面/日志看。
    public var skipReason: String {
        lock.lock(); defer { lock.unlock() }
        return _skipReason
    }

    public init(armed: Bool = false,
                minGapMs: Int64 = 15_000,
                stormWindowMs: Int64 = 60_000,
                stormMinConns: Int = 8,
                stormCooldownMs: Int64 = 60_000,
                disarmOnMaterial: Bool = true,
                battleWindowMs: Int64 = 30_000) {
        self._armed = armed
        self.minGapMs = minGapMs
        self.stormWindowMs = stormWindowMs
        self.stormMinConns = stormMinConns
        self.stormCooldownMs = stormCooldownMs
        self.disarmOnMaterial = disarmOnMaterial
        self.battleWindowMs = battleWindowMs
    }

    // MARK: - 决策

    /// 这条连接要不要换钥。
    ///
    /// - Parameter now: 当前毫秒时间戳（注入是为了单测能推进时间）。
    public func allow(now: Int64 = RekeyGate.nowMs()) -> Decision {
        lock.lock(); defer { lock.unlock() }

        guard _armed else {
            _skipReason = "disarmed"
            _skipped += 1
            return Decision(allowed: false, reason: "disarmed")
        }

        // 每次新连接都记一笔，风暴统计靠它
        recentConns.append(now)
        while let first = recentConns.first, now - first > stormWindowMs {
            recentConns.removeFirst()
        }
        if recentConns.count > 4096 {
            recentConns.removeFirst(recentConns.count - 4096)
        }

        if now < cooldownUntil {
            _skipReason = "cool"
            _skipped += 1
            return Decision(allowed: false, reason: "cool")
        }

        // ★ 对局刚起来：强制放行。
        //
        // 只在这几十秒内有效（母料就是这段时间下发的）。它**不看**最小
        // 间隔与冷却 —— 那两道闸的本意是省暴露，而这里放行一次换来的
        // 是一整局能解开。
        if _battleSeenAt > 0, now - _battleSeenAt <= battleWindowMs {
            lastRekeyAt = now
            _opened += 1
            _skipReason = ""
            return Decision(allowed: true, reason: "battle")
        }

        // 风暴：窗口内过密 → 冷却。见过母料之后才启用（见类注释）
        if stormCooldownMs > 0, lastRekeyAt > 0,
           recentConns.count >= stormMinConns {
            cooldownUntil = now + stormCooldownMs
            cooldownHits += 1
            recentConns.removeAll()
            _skipReason = "cool"
            _skipped += 1
            return Decision(allowed: false, reason: "cool")
        }

        if minGapMs > 0, lastRekeyAt > 0, now - lastRekeyAt < minGapMs {
            _skipReason = "gap"
            _skipped += 1
            return Decision(allowed: false, reason: "gap")
        }

        lastRekeyAt = now
        _opened += 1
        _skipReason = ""
        return Decision(allowed: true, reason: "")
    }

    // MARK: - 状态变更

    /// 某条连接交付了母料：撤防（之后一律纯转发，直到用户重新采集）。
    public func noteMaterial() {
        guard disarmOnMaterial else { return }
        lock.lock(); defer { lock.unlock() }
        if _armed {
            _armed = false
            _skipReason = "disarmed"
        }
    }

    /// 采集层看到「对局 UDP 真的在跑」时喂进来。
    ///
    /// 为什么需要这个信号（PC 版踩过的死锁）：判断「入局」原来只能靠解出
    /// 明文里的入局通知，而解出明文要先换钥 —— 于是「跳过换钥 → 看不到
    /// 入局 → 永远不放行」形成自锁。UDP 流速不需要解密就能看见。
    ///
    /// ## ⚠ 窗口只从「第一次看到对局」开始算
    ///
    /// 原来每次都无条件刷新 `battleSeenAt`。而对局期间 UDP 是持续活跃的
    /// （采集层每 2 秒喂一次），于是窗口永远是开的 ——「入局放行一次」
    /// 变成「对局期间每条连接都换钥」（PC 版实测一局 7 次）。
    ///
    /// 现在只在窗口过期后才重新计时：放行窗口 = 对局开始后的 30 秒，
    /// 之后回到正常闸门（`minGapMs` 生效）。
    public func noteBattleActive(now: Int64 = RekeyGate.nowMs()) {
        lock.lock(); defer { lock.unlock() }
        if _battleSeenAt > 0, now - _battleSeenAt <= battleWindowMs { return }
        _battleSeenAt = now
    }

    /// 「重新采集」：重新武装 + 把节流状态清零。
    ///
    /// 效果等价于 PC 版的 `reset_rekey_state` —— 下一条连接必然换钥。
    public func reset() {
        lock.lock(); defer { lock.unlock() }
        _armed = true
        lastRekeyAt = 0
        cooldownUntil = 0
        recentConns.removeAll()
        _skipReason = ""
    }

    public func setArmed(_ value: Bool) {
        lock.lock(); defer { lock.unlock() }
        _armed = value
        if value {
            lastRekeyAt = 0
            cooldownUntil = 0
            recentConns.removeAll()
            _skipReason = ""
        } else {
            _skipReason = "disarmed"
        }
    }

    // MARK: - 阶段

    /// 当前阶段：`battle` 对局中 / `lobby` 大厅等待 / `idle` 未连接。
    ///
    /// 判据与 PC 版 `_phase` 一致：先看 UDP 对局流速，再看有没有活跃连接。
    /// **不能**拿「见过入局通知」当判据 —— 那个一旦为真就不复位。
    public func phase(hasActiveConnection: Bool,
                      now: Int64 = RekeyGate.nowMs()) -> String {
        lock.lock()
        let seen = _battleSeenAt
        lock.unlock()
        if seen > 0, now - seen <= battleWindowMs { return "battle" }
        return hasActiveConnection ? "lobby" : "idle"
    }

    /// 给日志/状态页用的一行摘要。
    public func snapshot() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        return [
            "armed": _armed,
            "opened": _opened,
            "skipped": _skipped,
            "skipReason": _skipReason,
            "cooldownHits": cooldownHits,
        ]
    }

    public static func nowMs() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }
}
