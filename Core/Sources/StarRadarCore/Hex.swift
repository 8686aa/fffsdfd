import Foundation

/// 十六进制编解码。
///
/// 与 Android 端的 `toHex()` / `hexToBytes()` 等价：小写输出、奇数长度返回 nil。
public enum Hex {

    private static let digits: [Character] =
        Array("0123456789abcdef")

    public static func encode(_ bytes: [UInt8]) -> String {
        var out = String()
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return out
    }

    public static func decode(_ text: String) -> [UInt8]? {
        let chars = Array(text)
        if chars.count % 2 != 0 { return nil }
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var index = 0
        while index < chars.count {
            guard let hi = chars[index].hexDigitValue,
                  let lo = chars[index + 1].hexDigitValue else {
                return nil
            }
            out.append(UInt8((hi << 4) | lo))
            index += 2
        }
        return out
    }
}

extension Character {
    /// `Character.digit(c, 16)` 的等价物。
    var hexDigitValue: Int? {
        guard let scalar = unicodeScalars.first, unicodeScalars.count == 1 else {
            return nil
        }
        switch scalar {
        case "0"..."9": return Int(scalar.value - 48)
        case "a"..."f": return Int(scalar.value - 87)
        case "A"..."F": return Int(scalar.value - 55)
        default: return nil
        }
    }
}

/// 32 位大端读写。与 Kotlin 的 `u32` / `putU32` 一一对应。
public enum Bytes {

    public static func u16(_ buffer: [UInt8], _ offset: Int) -> Int {
        (Int(buffer[offset]) << 8) | Int(buffer[offset + 1])
    }

    public static func u32(_ buffer: [UInt8], _ offset: Int) -> UInt32 {
        (UInt32(buffer[offset]) << 24) |
            (UInt32(buffer[offset + 1]) << 16) |
            (UInt32(buffer[offset + 2]) << 8) |
            UInt32(buffer[offset + 3])
    }

    public static func putU16(_ buffer: inout [UInt8], _ offset: Int, _ value: Int) {
        buffer[offset] = UInt8((value >> 8) & 0xFF)
        buffer[offset + 1] = UInt8(value & 0xFF)
    }

    public static func putU32(_ buffer: inout [UInt8], _ offset: Int, _ value: UInt32) {
        buffer[offset] = UInt8((value >> 24) & 0xFF)
        buffer[offset + 1] = UInt8((value >> 16) & 0xFF)
        buffer[offset + 2] = UInt8((value >> 8) & 0xFF)
        buffer[offset + 3] = UInt8(value & 0xFF)
    }

    /// 8 字节大端（GCM 的 seq 与 iv 后缀用）。
    public static func putU64(_ buffer: inout [UInt8], _ offset: Int, _ value: UInt64) {
        for index in 0..<8 {
            buffer[offset + index] =
                UInt8((value >> UInt64((7 - index) * 8)) & 0xFF)
        }
    }
}

/// 协议不符 / 连接不可继续。调用方按「断开这一条」处理。
public struct ProxyError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

public struct SecureError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}
