import Foundation
import CryptoKit

/**
 哈希 / HMAC / HKDF / AES-GCM —— 全部走 CryptoKit。

 Android 端用 JCE（`MessageDigest` / `Mac` / `Cipher`），这里换成苹果的
 等价实现。**唯一要小心的是输出拼接顺序**：

  · JCE 的 `AES/GCM` 输出是 `密文 ‖ 16 字节 tag`
  · CryptoKit 的 `SealedBox` 把两者分开存
 所以 seal 之后要手工拼、open 之前要手工切 —— 拼错了就是「帧认证失败」，
 而这种现象看起来很像密钥派生错了。
 */
public enum Crypto {

    public static func sha256(_ data: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(data)))
    }

    public static func sha1(_ data: [UInt8]) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: Data(data)))
    }

    public static func md5(_ data: [UInt8]) -> [UInt8] {
        Array(Insecure.MD5.hash(data: Data(data)))
    }

    public static func hmacSha256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(data),
                                                  using: SymmetricKey(data: key))
        return Array(mac)
    }

    /// HKDF-SHA256（extract + expand）。
    ///
    /// 与 Android 端手写的那份等价：`PRK = HMAC(salt, ikm)`，
    /// 之后 `T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)`。
    public static func hkdfSha256(ikm: [UInt8], salt: [UInt8], info: [UInt8],
                                  length: Int) -> [UInt8] {
        let prk = hmacSha256(key: salt, data: ikm)
        var out = [UInt8]()
        out.reserveCapacity(length)
        var block = [UInt8]()
        var counter: UInt8 = 1
        while out.count < length {
            var input = block
            input.append(contentsOf: info)
            input.append(counter)
            block = hmacSha256(key: prk, data: input)
            let take = min(block.count, length - out.count)
            out.append(contentsOf: block[0..<take])
            counter += 1
        }
        return out
    }

    // ── AES-256-GCM ───────────────────────────────────────────

    /// 返回 `密文 ‖ tag`（与 JCE 的输出形态一致）。
    public static func gcmSeal(key: [UInt8], iv: [UInt8], plaintext: [UInt8],
                               aad: [UInt8]) throws -> [UInt8] {
        let symmetric = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: Data(iv))
        let sealed = try AES.GCM.seal(Data(plaintext), using: symmetric,
                                      nonce: nonce, authenticating: Data(aad))
        return Array(sealed.ciphertext) + Array(sealed.tag)
    }

    public static func gcmOpen(key: [UInt8], iv: [UInt8], sealed: [UInt8],
                               aad: [UInt8]) throws -> [UInt8] {
        guard sealed.count >= 16 else {
            throw SecureError("密文过短")
        }
        let body = Array(sealed[0..<(sealed.count - 16)])
        let tag = Array(sealed[(sealed.count - 16)...])
        let symmetric = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: Data(iv))
        let box = try AES.GCM.SealedBox(nonce: nonce,
                                        ciphertext: Data(body),
                                        tag: Data(tag))
        return Array(try AES.GCM.open(box, using: symmetric,
                                      authenticating: Data(aad)))
    }

    /// 定长比较。普通 `==` 会在第一个不同字节处提前返回，给了侧信道；
    /// 这里与 Kotlin 的 `MessageDigest.isEqual` 行为对齐。
    public static func secureEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        if lhs.count != rhs.count { return false }
        var diff: UInt8 = 0
        for index in 0..<lhs.count {
            diff |= lhs[index] ^ rhs[index]
        }
        return diff == 0
    }

    public static func secureEquals(_ lhs: String, _ rhs: String) -> Bool {
        secureEquals(Array(lhs.utf8), Array(rhs.utf8))
    }

    /// 密码学安全随机数。
    public static func randomBytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        if SecRandomCopyBytes(kSecRandomDefault, count, &bytes) != errSecSuccess {
            // 兜底：系统随机源不可用时用 SystemRandomNumberGenerator
            var generator = SystemRandomNumberGenerator()
            for index in 0..<count {
                bytes[index] = UInt8(truncatingIfNeeded: generator.next() as UInt64)
            }
        }
        return bytes
    }
}
