import Foundation
import StarRadarCore

/// 等「任一方向结束」的收尾工具。
///
/// 只等 c2s 的话，服务器先关（HTTP 短连接、目标回 RST）时 c2s 会一直等
/// 客户端，线程永不释放 —— 跑一段时间后连接号就耗光了（现象是「用着用着
/// 就连不上了」）。
public enum ThreadJoin {

    public static func either(_ first: Thread, _ second: Thread,
                              graceMs: Int,
                              onTimeout: () -> Void) {
        let deadline = Date().addingTimeInterval(Double(graceMs) / 1000.0)
        while Date() < deadline {
            // 任一方向已经结束（isFinished）就算「先结束」
            if first.isFinished || second.isFinished { break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        onTimeout()
    }
}
