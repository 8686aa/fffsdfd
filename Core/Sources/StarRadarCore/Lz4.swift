import Foundation

/**
 纯 Swift 的 LZ4 block 解压。

 ## 为什么 iOS 版必须有这个

 服务器下发给客户端的 `0x4013` 应用帧，明文**经常是整块 LZ4 压缩的**
 （扩展头第一个字节 = 压缩方法，非 0 即压缩）。而那条 128 字节的母料
 就挂在解压后的明文里。

 ### 未解压时到底能不能捞到？—— 不稳定，等于没有

 128 字节随机母料在 LZ4 里找不到可回溯的匹配，必然被原样存成 literal，
 所以压缩数据里**确实还留着母料原文**。但扫描的判据是
 `(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{160,220}={0,2})(?![A-Za-z0-9+/=])`：

  · LZ4 的控制字节（literal 长度扩展位、offset 低/高字节）**紧跟母料**，
    只要值落在 base64 字符集里，run 就会被算长、或被负向断言挡住，
    长度对不上 → 判为非法候选 → 母料丢失；
  · `'=' not in data` 这个快速排除，会让一部分没带 `=` 的压缩帧整帧跳过。

 也就是说「有时能、有时不能」，取决于压缩流的控制字节 —— 这种「概率性
 可用」比彻底不可用更危险：测试可能过、真机上换个长度就丢。

 实测佐证：PC 版 evidence 里所有 `ch-*.bin` 的 `layer` 字段都是 `lz4`，
 **没有一条**来自 plain 层。所以解压不是「多一条路」，是唯一稳的那条。

 ## 为什么不用现成库

 LZ4 block 格式本身极简单（`[token][literal 长度][literals][offset]
 [match 长度]` 循环），几百字节到几 KB 的解压纯 Swift 完全够快 ——
 这条路径只在 s2c 的 `0x4013` 上跑，一局几百次。
 引一个 SwiftPM 依赖要多一份供应链风险，还要为它维护 iOS/macOS 两套
 编译条件，不值得。

 与 Python 版 `starradar-pc/core/lz4.py`、Kotlin 版 `Lz4.kt` 逐行对应
 （Python 是唯一算法源头，改算法请同步三边）。
 交叉验证向量在 `Tests/StarRadarCoreTests/Vectors/lz4_vectors.json`，
 由 PC 的参考实现生成，`Lz4Tests` 逐条比对。

 ## 为什么不用 `[UInt8]` 直接 append

 这是热路径（每帧都跑）。Swift 数组每次 `append` 都可能触发扩容 + 拷贝，
 一帧几 KB 就是几千次边界检查；这里用一个自己扩缩的连续缓冲区，
 按 2 倍增长，最后 `Array(...)` 精确裁掉尾部 —— 与 Kotlin 版同样的理由。

 格式参考：https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
 */
public enum Lz4 {

    /// 每个 token 的 literal/match 长度上限：到 15 就进入「继续累加」模式。
    private static let maxNibble = 15

    /// LZ4 的最小匹配长度，编码时已减掉，解码要加回来。
    private static let minMatch = 4

    public struct Lz4Error: Error, CustomStringConvertible {
        public let message: String
        public init(_ message: String) { self.message = message }
        public var description: String { message }
    }

    /**
     把一段 LZ4 block 解成原始字节。

     - Parameter maxOutput: 输出上限。压缩炸弹的常见形态是「几 KB 解出
       几百 MB」，必须有上限，否则一条异常报文就能把 App 内存吃光被系统
       杀掉（iOS 的 jetsam 不看是谁的错）。
     */
    public static func decompress(_ data: [UInt8],
                                  maxOutput: Int = Tgcp.lz4Limit) throws -> [UInt8] {
        let size = data.count
        if size == 0 { return [] }

        // 初值别按 size * 4 直接分配：maxOutput 可能是 4 MB，而一帧通常只有
        // 几 KB，一次就分配几 MB 在手机上等同于制造内存压力。
        // 起步 1 KB 起（或输入大小），按需翻倍。
        var capacity = min(maxOutput, max(1024, size))
        var out = [UInt8](repeating: 0, count: capacity)
        var outLen = 0
        var pos = 0

        /// 确保还能再写 `need` 个字节，不够就按 2 倍扩。
        func ensure(_ need: Int) throws {
            let want = outLen + need
            if want <= capacity { return }
            if need < 0 || want > maxOutput {
                throw Lz4Error("解压结果过大")
            }
            var cap = capacity
            while cap < want {
                cap = min(maxOutput, cap * 2)
            }
            if cap < want { throw Lz4Error("解压结果过大") }
            out.append(contentsOf:
                        [UInt8](repeating: 0, count: cap - capacity))
            capacity = cap
        }

        while pos < size {
            let token = Int(data[pos])
            pos += 1

            // ── literal 段 ──────────────────────────────────────
            var literalLen = token >> 4
            if literalLen == maxNibble {
                while true {
                    if pos >= size { throw Lz4Error("literal 长度越界") }
                    let extra = Int(data[pos])
                    pos += 1
                    literalLen += extra
                    if extra != 0xFF { break }
                }
            }
            if literalLen > 0 {
                let end = pos + literalLen
                if end > size { throw Lz4Error("literal 数据越界") }
                try ensure(literalLen)
                // 逐段拷到 out 的尾部
                out.replaceSubrange(outLen..<(outLen + literalLen),
                                    with: data[pos..<end])
                outLen += literalLen
                pos = end
            }

            // 到末尾就是最后一个 block 的收尾（只有 literal，没有 match）
            if pos >= size { break }

            // ── 回溯段 ──────────────────────────────────────────
            if pos + 2 > size { throw Lz4Error("offset 字段不完整") }
            let offset = Int(data[pos]) | (Int(data[pos + 1]) << 8)
            pos += 2
            if offset == 0 || offset > outLen {
                throw Lz4Error("offset 非法（\(offset)，已输出 \(outLen)）")
            }

            var matchLen = token & 0x0F
            if matchLen == maxNibble {
                while true {
                    if pos >= size { throw Lz4Error("match 长度越界") }
                    let extra = Int(data[pos])
                    pos += 1
                    matchLen += extra
                    if extra != 0xFF { break }
                }
            }
            matchLen += minMatch
            try ensure(matchLen)

            // ⚠️ 逐字节复制：offset < matchLen 时源区间与目标区间**重叠**，
            // 必须一个字节一个字节来 —— 这正是 LZ4 表示连续重复数据的技巧，
            // 整段拷贝会读到还没生成的数据（后段是垃圾）。
            var src = outLen - offset
            for _ in 0..<matchLen {
                out[outLen] = out[src]
                outLen += 1
                src += 1
            }
        }

        if outLen == capacity { return out }
        return Array(out[0..<outLen])
    }

    /**
     试着解压，失败返回 nil。

     给「不确定这一帧到底压没压」的场景用：真实数据里压缩位偶尔为 0，
     但内容其实是 LZ4 块。调用方拿到 nil 就当没压过。
     */
    public static func tryDecompress(_ data: [UInt8],
                                     maxOutput: Int = Tgcp.lz4Limit) -> [UInt8]? {
        do {
            return try decompress(data, maxOutput: maxOutput)
        } catch {
            return nil
        }
    }
}
