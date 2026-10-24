import Foundation

/**
 无符号大整数 + Montgomery 模幂。

 ## 为什么不用 BigInt 包

 TGCP 握手要在 512 位模数上做两次模幂（生成密钥对 + 派生共享密钥）。
 引第三方包（attaswift/BigInt）当然更省事，但 iOS 端只为一个运算法引入
 依赖，等于给构建链路多加一个可能失败的点 —— 而这条链路本来就要靠
 macOS CI 才能编译。自己实现 Montgomery 乘法大约 200 行，且能用
 PC 端 Python 生成的 DH 向量逐字节验证（见 TgcpVectorTests），
 正确性是可证的。

 ## 表示

 little-endian 的 32 位 limb 数组，尾部不留 0（归一化）。
 与 JVM 的 `BigInteger` 只在 **值** 上等价，不共享内部表示。
 */
public struct BigUInt: Comparable {
    /// little-endian limbs，高位不带尾随 0。
    public private(set) var limbs: [UInt32]

    public init(limbs: [UInt32]) {
        var trimmed = limbs
        while let last = trimmed.last, last == 0 { trimmed.removeLast() }
        self.limbs = trimmed
    }

    public init(_ value: UInt64) {
        if value == 0 {
            self.limbs = []
        } else {
            self.limbs = [UInt32(value & 0xFFFF_FFFF), UInt32(value >> 32)]
            while let last = self.limbs.last, last == 0 { self.limbs.removeLast() }
        }
    }

    /// 大端字节（无符号）。空数组表示 0。
    public init(bytes: [UInt8]) {
        var limbs = [UInt32]()
        var index = bytes.count
        while index > 0 {
            let start = max(0, index - 4)
            var word: UInt32 = 0
            for offset in start..<index {
                word = (word << 8) | UInt32(bytes[offset])
            }
            limbs.append(word)
            index = start
        }
        self.init(limbs: limbs)
    }

    /// 十六进制（大小写不敏感）。
    public init?(hex: String) {
        guard let bytes = Hex.decode(hex) else { return nil }
        self.init(bytes: bytes)
    }

    /// 十进制（只用于读测试向量：PC 端的 Python 把私钥写成十进制）。
    public init?(decimal: String) {
        let digits = Array(decimal.trimmingCharacters(in: .whitespaces))
        guard !digits.isEmpty else { return nil }
        var value = BigUInt(0)
        let ten = BigUInt(10)
        for character in digits {
            guard let digit = character.hexDigitValue, digit < 10 else { return nil }
            value = value * ten + BigUInt(UInt64(digit))
        }
        self = value
    }

    public var isZero: Bool { limbs.isEmpty }

    /// 最小大端表示。0 单独编码成一个 `0x00`（与 Python 的 `int.to_bytes` 习惯不同，
    /// 但与 Kotlin 版 `minimalBe` 一致 —— 协议要求就是这个）。
    public var bytes: [UInt8] {
        if limbs.isEmpty { return [0] }
        var out = [UInt8]()
        out.reserveCapacity(limbs.count * 4)
        for (position, limb) in limbs.enumerated().reversed() {
            let shift: UInt32 = 24
            out.append(UInt8((limb >> shift) & 0xFF))
            out.append(UInt8((limb >> 16) & 0xFF))
            out.append(UInt8((limb >> 8) & 0xFF))
            out.append(UInt8(limb & 0xFF))
            _ = position
        }
        // 去掉前导 0（第一个非零字节之前）
        var begin = 0
        while begin < out.count - 1 && out[begin] == 0 { begin += 1 }
        return Array(out[begin...])
    }

    /// 定长左补零大端（DH 公钥 64 字节）。
    public func fixedBytes(_ size: Int) -> [UInt8] {
        let raw = bytes
        if raw.count >= size { return Array(raw[(raw.count - size)...]) }
        return [UInt8](repeating: 0, count: size - raw.count) + raw
    }

    public var bitCount: Int {
        guard let top = limbs.last else { return 0 }
        var bits = (limbs.count - 1) * 32
        var value = top
        while value > 0 {
            bits += 1
            value >>= 1
        }
        return bits
    }

    public func bit(_ index: Int) -> Bool {
        let limbIndex = index / 32
        if limbIndex >= limbs.count { return false }
        return (limbs[limbIndex] >> UInt32(index % 32)) & 1 == 1
    }

    public var hex: String { Hex.encode(bytes) }

    // ── 比较 ───────────────────────────────────────────────────

    public static func < (lhs: BigUInt, rhs: BigUInt) -> Bool {
        compare(lhs, rhs) < 0
    }

    public static func > (lhs: BigUInt, rhs: BigUInt) -> Bool {
        compare(lhs, rhs) > 0
    }

    public static func == (lhs: BigUInt, rhs: BigUInt) -> Bool {
        compare(lhs, rhs) == 0
    }

    public static func compare(_ lhs: BigUInt, _ rhs: BigUInt) -> Int {
        if lhs.limbs.count != rhs.limbs.count {
            return lhs.limbs.count < rhs.limbs.count ? -1 : 1
        }
        var index = lhs.limbs.count - 1
        while index >= 0 {
            if lhs.limbs[index] != rhs.limbs[index] {
                return lhs.limbs[index] < rhs.limbs[index] ? -1 : 1
            }
            index -= 1
        }
        return 0
    }

    // ── 加减 ───────────────────────────────────────────────────

    public static func + (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        let size = max(lhs.limbs.count, rhs.limbs.count)
        var out = [UInt32](repeating: 0, count: size + 1)
        var carry: UInt64 = 0
        for index in 0..<size {
            let a = index < lhs.limbs.count ? UInt64(lhs.limbs[index]) : 0
            let b = index < rhs.limbs.count ? UInt64(rhs.limbs[index]) : 0
            let sum = a + b + carry
            out[index] = UInt32(sum & 0xFFFF_FFFF)
            carry = sum >> 32
        }
        out[size] = UInt32(carry)
        return BigUInt(limbs: out)
    }

    /// `lhs - rhs`，要求 lhs >= rhs（协议里只在已比较过的场合调用）。
    public static func - (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        var out = [UInt32](repeating: 0, count: lhs.limbs.count)
        var borrow: Int64 = 0
        for index in 0..<lhs.limbs.count {
            let a = Int64(lhs.limbs[index])
            let b = index < rhs.limbs.count ? Int64(rhs.limbs[index]) : 0
            var value = a - b - borrow
            if value < 0 {
                value += 1 << 32
                borrow = 1
            } else {
                borrow = 0
            }
            out[index] = UInt32(value)
        }
        return BigUInt(limbs: out)
    }

    /// 学校式乘法。只用于十进制解析与测试，热路径走 Montgomery。
    public static func * (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        if lhs.isZero || rhs.isZero { return BigUInt(0) }
        // 多留一格：最高位的进位可能要多一个 limb
        var out = [UInt32](repeating: 0,
                           count: lhs.limbs.count + rhs.limbs.count + 1)
        for i in 0..<lhs.limbs.count {
            var carry: UInt64 = 0
            let a = UInt64(lhs.limbs[i])
            for j in 0..<rhs.limbs.count {
                let index = i + j
                let acc = UInt64(out[index]) + a * UInt64(rhs.limbs[j]) + carry
                out[index] = UInt32(acc & 0xFFFF_FFFF)
                carry = acc >> 32
            }
            var index = i + rhs.limbs.count
            while carry > 0 && index < out.count {
                let acc = UInt64(out[index]) + carry
                out[index] = UInt32(acc & 0xFFFF_FFFF)
                carry = acc >> 32
                index += 1
            }
        }
        return BigUInt(limbs: out)
    }

    // ── 模幂（Montgomery）─────────────────────────────────────

    /// `self^exponent mod modulus`。
    ///
    /// 只支持**奇数**模数 —— TGCP 的 P 是素数，恒满足。偶数模数下
    /// Montgomery 不成立，这里直接 precondition 失败，而不是悄悄算错：
    /// 曾经写过一条「偶数时退回二进制方法」的兜底路径，结果那条路径里
    /// 用加法当乘方（`addMod(result, result)` 算的是 2·result 而不是
    /// result²），只因为 P 是奇数才一直没被触发。留着这种分支比删掉更危险。
    public func modPow(_ exponent: BigUInt, _ modulus: BigUInt) -> BigUInt {
        if modulus.limbs.isEmpty { return BigUInt(0) }
        precondition(modulus.limbs[0] & 1 == 1,
                     "modPow 只支持奇数模数（TGCP 的 P 是素数，恒满足）")
        let context = Montgomery(modulus: modulus)
        return context.modPow(base: self, exponent: exponent)
    }

}

/// Montgomery 上下文：把「乘 + 取模」变成移位与加法。
struct Montgomery {
    private let modulus: [UInt32]
    private let size: Int
    /// `-n⁻¹ mod 2³²`
    private let n0inv: UInt32
    /// `R² mod n`，R = 2^(32·size)
    private let r2: [UInt32]

    init(modulus: BigUInt) {
        var limbs = modulus.limbs
        while let last = limbs.last, last == 0 { limbs.removeLast() }
        self.modulus = limbs
        self.size = limbs.count
        self.n0inv = Self.inverse32(limbs[0])

        // R² 用「反复翻倍」算两次，避免引入除法：
        //   1 → 翻倍 32·size 次得到 R = 2^(32·size) mod n
        //   R → 再翻倍 32·size 次得到 R² = 2^(64·size) mod n
        // double() 里对进位溢出的处理与 multiply 的最终归约是同一个道理。
        var value = [UInt32](repeating: 0, count: size)
        value[0] = 1
        for _ in 0..<(32 * size) { value = Self.double(value, limbs) }
        for _ in 0..<(32 * size) { value = Self.double(value, limbs) }
        self.r2 = value
    }

    /// `n0⁻¹ mod 2³²` 的 Newton 迭代（5 轮收敛到 32 位）。
    private static func inverse32(_ n0: UInt32) -> UInt32 {
        var inverse: UInt32 = 1
        for _ in 0..<5 {
            inverse = inverse &* (2 &- n0 &* inverse)
        }
        return 0 &- inverse                    // -n⁻¹
    }

    /// `2·value mod n`（value < n）。
    private static func double(_ value: [UInt32], _ n: [UInt32]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: value.count)
        var carry: UInt32 = 0
        for index in 0..<value.count {
            let next = value[index] << 1
            out[index] = next | carry
            carry = value[index] >> 31
        }
        if carry == 1 || Self.compare(out, n) >= 0 {
            out = Self.subtract(out, n)
        }
        return out
    }

    private static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        let size = max(a.count, b.count)
        var index = size - 1
        while index >= 0 {
            let x = index < a.count ? a[index] : 0
            let y = index < b.count ? b[index] : 0
            if x != y { return x < y ? -1 : 1 }
            index -= 1
        }
        return 0
    }

    private static func subtract(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = a
        var borrow: Int64 = 0
        for index in 0..<out.count {
            let y = index < b.count ? Int64(b[index]) : 0
            var value = Int64(out[index]) - y - borrow
            if value < 0 {
                value += 1 << 32
                borrow = 1
            } else {
                borrow = 0
            }
            out[index] = UInt32(value)
        }
        return out
    }

    /// CIOS：`a·b·R⁻¹ mod n`。a、b 均为 size 个 limb 且 < n。
    private func multiply(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var t = [UInt32](repeating: 0, count: size + 2)
        for i in 0..<size {
            var carry: UInt64 = 0
            let multiplier = UInt64(b[i])
            for j in 0..<size {
                let acc = UInt64(t[j]) + UInt64(a[j]) * multiplier + carry
                t[j] = UInt32(acc & 0xFFFF_FFFF)
                carry = acc >> 32
            }
            var top = UInt64(t[size]) + carry
            t[size] = UInt32(top & 0xFFFF_FFFF)
            t[size + 1] = UInt32(top >> 32)

            let m = (t[0] &* n0inv)
            var borrow: UInt64 = 0
            let first = UInt64(t[0]) + UInt64(m) * UInt64(modulus[0])
            borrow = first >> 32
            for j in 1..<size {
                let acc = UInt64(t[j]) + UInt64(m) * UInt64(modulus[j]) + borrow
                t[j - 1] = UInt32(acc & 0xFFFF_FFFF)
                borrow = acc >> 32
            }
            let last = UInt64(t[size]) + borrow
            t[size - 1] = UInt32(last & 0xFFFF_FFFF)
            t[size] = t[size + 1] &+ UInt32(last >> 32)
            t[size + 1] = 0
        }

        // ★ 归约必须看 t[size]。
        //
        // CIOS 结束时结果的真实值是 `t[size]·2^(32·size) + 低 size 位`，
        // 可能落在 [n, 2n)。只比较低 size 位是不够的：t[size] == 1 时
        // 真实值必然 ≥ 2^(32·size) > n，必须减一次 n，而减去时产生的
        // 借位正好抵消掉那个 2^(32·size)。
        //
        // 漏掉这一条不会在 P（512 位素数）上必现 —— 某些中间值恰好
        // 让 t[size] 保持 0，于是「大部分正确、偶发算错」。实测在 16~512 位
        // 的随机奇数模数上有 9/24 算错，而 P 恰好通过，属于最难查的一类。
        var result = Array(t[0..<size])
        if t[size] != 0 || Self.compare(result, modulus) >= 0 {
            result = Self.subtract(result, modulus)
        }
        return result
    }

    /// 转出 Montgomery 域：`value·R⁻¹ mod n`。
    private func fromDomain(_ value: [UInt32]) -> BigUInt {
        var one = [UInt32](repeating: 0, count: size)
        one[0] = 1
        return BigUInt(limbs: multiply(value, one))
    }

    func modPow(base: BigUInt, exponent: BigUInt) -> BigUInt {
        var baseLimbs = base.limbs
        while baseLimbs.count < size { baseLimbs.append(0) }
        if baseLimbs.count > size { baseLimbs = Array(baseLimbs[0..<size]) }
        let baseDomain = multiply(baseLimbs, r2)

        var one = [UInt32](repeating: 0, count: size)
        one[0] = 1
        var result = multiply(one, r2)

        var bitIndex = exponent.bitCount - 1
        while bitIndex >= 0 {
            result = multiply(result, result)
            if exponent.bit(bitIndex) {
                result = multiply(result, baseDomain)
            }
            bitIndex -= 1
        }
        return fromDomain(result)
    }
}
