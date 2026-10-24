import Foundation

/**
 AES 分组加密 + CBC（NoPadding）。

 ## 为什么自己实现，而不是用系统库

 CryptoKit 只提供 AES-GCM 与 ChaChaPoly，**没有 CBC**。TGCP 的 body 翻译
 用的正是 AES-CBC-128/NoPadding（填充由协议自己管：`tsf4g` + pad 值）。

 CommonCrypto 的 `CCCrypt` 能做，但它在 Swift 里要过一层 C 指针，
 且 `kCCOptionECBMode` 的开关语义容易被误读成"CBC 也是这个标志"。
 手写一份反而更可控：字节级行为完全可测（`AesTests` 用 FIPS-197 的
 已知答案向量核对），而且不依赖桥接头。

 ## S-box 为什么在运行时算

 256 字节的表手抄一遍，只要错一个字节，现象是"绝大多数包正常、偶发
 某条连接解不开"—— 极难定位。这里用 GF(2⁸) 的乘法逆 + 仿射变换
 现场生成，正确性只依赖两行数学定义，并且有已知答案测试兜底。
 */
public enum AES {

    public static let blockSize = 16

    // ── GF(2⁸) ────────────────────────────────────────────────

    /// 乘法（模多项式 0x11B）。
    static func multiply(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var x = a
        var y = b
        var result: UInt8 = 0
        for _ in 0..<8 {
            if y & 1 != 0 { result ^= x }
            let high = x & 0x80
            x <<= 1
            if high != 0 { x ^= 0x1B }
            y >>= 1
        }
        return result
    }

    /// 乘法逆：`x²⁵⁴`（x = 0 时定义为 0）。
    static func inverse(_ value: UInt8) -> UInt8 {
        if value == 0 { return 0 }
        var result: UInt8 = 1
        var base = value
        var exponent: UInt8 = 254
        while exponent > 0 {
            if exponent & 1 != 0 { result = multiply(result, base) }
            base = multiply(base, base)
            exponent >>= 1
        }
        return result
    }

    static func rotateLeft(_ value: UInt8, _ count: UInt8) -> UInt8 {
        (value << count) | (value >> (8 - count))
    }

    /// 仿射变换：`b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63`。
    static func affine(_ value: UInt8) -> UInt8 {
        value ^ rotateLeft(value, 1) ^ rotateLeft(value, 2) ^
            rotateLeft(value, 3) ^ rotateLeft(value, 4) ^ 0x63
    }

    /// 前向 S-box（懒加载一次）。
    static let sbox: [UInt8] = (0..<256).map { affine(inverse(UInt8($0))) }

    /// 逆向 S-box：由前向表反查，避免再写一份定义。
    static let invSbox: [UInt8] = {
        var table = [UInt8](repeating: 0, count: 256)
        for index in 0..<256 where true {
            table[Int(sbox[index])] = UInt8(index)
        }
        return table
    }()

    private static func xtime(_ value: UInt8) -> UInt8 {
        let high = value & 0x80
        var out = value << 1
        if high != 0 { out ^= 0x1B }
        return out
    }

    // ── 密钥扩展 ──────────────────────────────────────────────

    /// 扩展成 `4·(Nr+1)` 字节的轮密钥。
    static func expandKey(_ key: [UInt8]) -> [UInt8] {
        let nk = key.count / 4
        let rounds = nk + 6
        var words = [[UInt8]]()
        words.reserveCapacity(4 * (rounds + 1))
        for index in 0..<nk {
            words.append(Array(key[(index * 4)..<(index * 4 + 4)]))
        }
        var rcon: UInt8 = 1
        var index = nk
        while index < 4 * (rounds + 1) {
            var temp = words[index - 1]
            if index % nk == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]]
                for position in 0..<4 {
                    temp[position] = sbox[Int(temp[position])]
                }
                temp[0] ^= rcon
                rcon = xtime(rcon)
            } else if nk > 6 && index % nk == 4 {
                for position in 0..<4 {
                    temp[position] = sbox[Int(temp[position])]
                }
            }
            let previous = words[index - nk]
            var next = [UInt8](repeating: 0, count: 4)
            for position in 0..<4 {
                next[position] = previous[position] ^ temp[position]
            }
            words.append(next)
            index += 1
        }
        return words.flatMap { $0 }
    }

    // ── 单块 ──────────────────────────────────────────────────

    private static func addRoundKey(_ state: inout [UInt8], _ schedule: [UInt8],
                                    _ round: Int) {
        let offset = round * 16
        for index in 0..<16 {
            state[index] ^= schedule[offset + index]
        }
    }

    private static func subBytes(_ state: inout [UInt8], _ table: [UInt8]) {
        for index in 0..<16 {
            state[index] = table[Int(state[index])]
        }
    }

    private static func shiftRows(_ state: inout [UInt8]) {
        // 列优先布局：state[r + 4c]
        for row in 1..<4 {
            let a = state[row]
            let b = state[row + 4]
            let c = state[row + 8]
            let d = state[row + 12]
            switch row {
            case 1:
                state[row] = b; state[row + 4] = c
                state[row + 8] = d; state[row + 12] = a
            case 2:
                state[row] = c; state[row + 4] = d
                state[row + 8] = a; state[row + 12] = b
            default:
                state[row] = d; state[row + 4] = a
                state[row + 8] = b; state[row + 12] = c
            }
        }
    }

    private static func invShiftRows(_ state: inout [UInt8]) {
        for row in 1..<4 {
            let a = state[row]
            let b = state[row + 4]
            let c = state[row + 8]
            let d = state[row + 12]
            switch row {
            case 1:
                state[row] = d; state[row + 4] = a
                state[row + 8] = b; state[row + 12] = c
            case 2:
                state[row] = c; state[row + 4] = d
                state[row + 8] = a; state[row + 12] = b
            default:
                state[row] = b; state[row + 4] = c
                state[row + 8] = d; state[row + 12] = a
            }
        }
    }

    private static func mixColumns(_ state: inout [UInt8]) {
        for column in 0..<4 {
            let base = column * 4
            let a0 = state[base]
            let a1 = state[base + 1]
            let a2 = state[base + 2]
            let a3 = state[base + 3]
            state[base] = multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3
            state[base + 1] = a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3
            state[base + 2] = a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3)
            state[base + 3] = multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2)
        }
    }

    private static func invMixColumns(_ state: inout [UInt8]) {
        for column in 0..<4 {
            let base = column * 4
            let a0 = state[base]
            let a1 = state[base + 1]
            let a2 = state[base + 2]
            let a3 = state[base + 3]
            state[base] = multiply(a0, 14) ^ multiply(a1, 11) ^
                multiply(a2, 13) ^ multiply(a3, 9)
            state[base + 1] = multiply(a0, 9) ^ multiply(a1, 14) ^
                multiply(a2, 11) ^ multiply(a3, 13)
            state[base + 2] = multiply(a0, 13) ^ multiply(a1, 9) ^
                multiply(a2, 14) ^ multiply(a3, 11)
            state[base + 3] = multiply(a0, 11) ^ multiply(a1, 13) ^
                multiply(a2, 9) ^ multiply(a3, 14)
        }
    }

    public static func encryptBlock(_ input: [UInt8], _ schedule: [UInt8],
                                    _ rounds: Int) -> [UInt8] {
        var state = input
        addRoundKey(&state, schedule, 0)
        for round in 1..<rounds {
            subBytes(&state, sbox)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, schedule, round)
        }
        subBytes(&state, sbox)
        shiftRows(&state)
        addRoundKey(&state, schedule, rounds)
        return state
    }

    public static func decryptBlock(_ input: [UInt8], _ schedule: [UInt8],
                                    _ rounds: Int) -> [UInt8] {
        var state = input
        addRoundKey(&state, schedule, rounds)
        for round in stride(from: rounds - 1, through: 1, by: -1) {
            invShiftRows(&state)
            subBytes(&state, invSbox)
            addRoundKey(&state, schedule, round)
            invMixColumns(&state)
        }
        invShiftRows(&state)
        subBytes(&state, invSbox)
        addRoundKey(&state, schedule, 0)
        return state
    }

    // ── CBC ───────────────────────────────────────────────────

    /// AES-CBC 加密，无填充。要求明文是 16 的整数倍。
    public static func cbcEncrypt(key: [UInt8], iv: [UInt8],
                                  data: [UInt8]) -> [UInt8] {
        precondition(data.count % blockSize == 0, "CBC 明文必须是 16 的倍数")
        precondition(iv.count == blockSize, "IV 必须是 16 字节")
        let schedule = expandKey(key)
        let rounds = key.count / 4 + 6
        var previous = iv
        var out = [UInt8]()
        out.reserveCapacity(data.count)
        var offset = 0
        while offset < data.count {
            var block = Array(data[offset..<(offset + blockSize)])
            for index in 0..<blockSize { block[index] ^= previous[index] }
            let encrypted = encryptBlock(block, schedule, rounds)
            out.append(contentsOf: encrypted)
            previous = encrypted
            offset += blockSize
        }
        return out
    }

    /// AES-CBC 解密，无填充。
    public static func cbcDecrypt(key: [UInt8], iv: [UInt8],
                                  data: [UInt8]) -> [UInt8] {
        precondition(data.count % blockSize == 0, "CBC 密文必须是 16 的倍数")
        precondition(iv.count == blockSize, "IV 必须是 16 字节")
        let schedule = expandKey(key)
        let rounds = key.count / 4 + 6
        var previous = iv
        var out = [UInt8]()
        out.reserveCapacity(data.count)
        var offset = 0
        while offset < data.count {
            let block = Array(data[offset..<(offset + blockSize)])
            var plain = decryptBlock(block, schedule, rounds)
            for index in 0..<blockSize { plain[index] ^= previous[index] }
            out.append(contentsOf: plain)
            previous = block
            offset += blockSize
        }
        return out
    }
}
