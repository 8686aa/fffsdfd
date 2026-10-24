import Foundation

/**
 最小 JSON 工具。

 ## 为什么解析和编码用两套做法

 **解析**用自己写的递归下降：节点回来的 `secure_challenge` 可能带额外字段，
 自己写解析器要能容忍未知键；同时不引第三方依赖（iOS 上多一个包就多一处
 版本风险）。

 **编码**手拼：上报报文（`{"batch":[...]}`、`{"type":"battle_key",...}`）
 是转发器按**字符串**比对的，字段顺序、转义方式都必须与 PC 版一致。
 走 `JSONEncoder` 的话键顺序不保证、`/` 的转义也不同 —— 那就不是
 「逐字节一致」了，而这一点正是协议要求。

 所以这里给出一个**保序**的 JSON 值类型：`.object([(String, JSON)])`。
 */
public indirect enum JSON {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSON])
    case object([(String, JSON)])

    public subscript(key: String) -> JSON? {
        guard case .object(let pairs) = self else { return nil }
        for (name, value) in pairs where name == key { return value }
        return nil
    }

    public var stringValue: String? {
        if case .string(let text) = self { return text }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let flag) = self { return flag }
        return nil
    }

    public var intValue: Int? {
        if case .number(let value) = self { return Int(value) }
        return nil
    }

    public var int64Value: Int64? {
        if case .number(let value) = self { return Int64(value) }
        return nil
    }

    public var doubleValue: Double? {
        if case .number(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSON]? {
        if case .array(let items) = self { return items }
        return nil
    }

    public var isObject: Bool {
        if case .object = self { return true }
        return false
    }

    /// `.number` 的整数形态（seq 这类字段用）。
    public var numericText: String {
        switch self {
        case .number(let value):
            if value == value.rounded(), abs(value) < 1e15 {
                return String(Int64(value))
            }
            return String(value)
        case .bool(let flag): return flag ? "true" : "false"
        case .null: return "null"
        case .string(let text): return text
        default: return ""
        }
    }
}

public enum Json {

    // ── 编码 ───────────────────────────────────────────────────

    /// 拼成紧凑 JSON（无空格），顺序按传入的列表来。
    public static func build(_ fields: [(String, JSON)]) -> String {
        var out = "{"
        for (index, field) in fields.enumerated() {
            if index > 0 { out += "," }
            out += "\"" + escape(field.0) + "\":"
            out += render(field.1)
        }
        out += "}"
        return out
    }

    public static func build(_ fields: (String, JSON)...) -> String {
        build(fields)
    }

    public static func quote(_ value: String) -> String {
        "\"" + escape(value) + "\""
    }

    public static func escape(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count + 8)
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }

    public static func render(_ value: JSON) -> String {
        switch value {
        case .null: return "null"
        case .bool(let flag): return flag ? "true" : "false"
        case .number(let number):
            // 整数收敛成整型写法，避免 seq 被写成 1.0（节点侧按整数读会失败）
            if number == number.rounded(), abs(number) < 1e15 {
                return String(Int64(number))
            }
            return String(number)
        case .string(let text): return quote(text)
        case .array(let items):
            return "[" + items.map(render).joined(separator: ",") + "]"
        case .object(let pairs):
            return build(pairs)
        }
    }

    // ── 解析 ───────────────────────────────────────────────────

    /// 解析成对象；顶层不是对象时返回 nil（与 Kotlin 的 `parse` 一致）。
    public static func parse(_ text: String) -> JSON? {
        var parser = Parser(text)
        guard let value = parser.parseValue(), value.isObject else { return nil }
        return value
    }

    private struct Parser {
        private let scalars: [Unicode.Scalar]
        private var index = 0

        init(_ text: String) {
            scalars = Array(text.unicodeScalars)
        }

        private var current: Unicode.Scalar? {
            index < scalars.count ? scalars[index] : nil
        }

        private mutating func skipWhitespace() {
            while let scalar = current, scalar == " " || scalar == "\n" ||
                    scalar == "\r" || scalar == "\t" {
                index += 1
            }
        }

        mutating func parseValue() -> JSON? {
            skipWhitespace()
            guard let scalar = current else { return nil }
            switch scalar {
            case "{": return parseObject()
            case "[": return parseArray()
            case "\"": return parseString().map(JSON.string)
            case "t":
                return match("true") ? .bool(true) : nil
            case "f":
                return match("false") ? .bool(false) : nil
            case "n":
                return match("null") ? .null : nil
            default:
                return parseNumber()
            }
        }

        private mutating func match(_ literal: String) -> Bool {
            let items = Array(literal.unicodeScalars)
            guard index + items.count <= scalars.count else { return false }
            for offset in 0..<items.count where scalars[index + offset] != items[offset] {
                return false
            }
            index += items.count
            return true
        }

        private mutating func parseObject() -> JSON? {
            index += 1                        // '{'
            var pairs: [(String, JSON)] = []
            skipWhitespace()
            if current == "}" { index += 1; return .object(pairs) }
            while true {
                skipWhitespace()
                guard let key = parseString() else { return nil }
                skipWhitespace()
                guard current == ":" else { return nil }
                index += 1
                guard let value = parseValue() else { return nil }
                pairs.append((key, value))
                skipWhitespace()
                if current == "," { index += 1; continue }
                if current == "}" { index += 1; return .object(pairs) }
                return nil
            }
        }

        private mutating func parseArray() -> JSON? {
            index += 1                        // '['
            var items: [JSON] = []
            skipWhitespace()
            if current == "]" { index += 1; return .array(items) }
            while true {
                guard let value = parseValue() else { return nil }
                items.append(value)
                skipWhitespace()
                if current == "," { index += 1; continue }
                if current == "]" { index += 1; return .array(items) }
                return nil
            }
        }

        private mutating func parseString() -> String? {
            guard current == "\"" else { return nil }
            index += 1
            var out = String()
            while let scalar = current {
                index += 1
                if scalar == "\"" { return out }
                if scalar != "\\" {
                    out.unicodeScalars.append(scalar)
                    continue
                }
                guard let escape = current else { return nil }
                index += 1
                switch escape {
                case "\"": out += "\""
                case "\\": out += "\\"
                case "/": out += "/"
                case "b": out += "\u{08}"
                case "f": out += "\u{0C}"
                case "n": out += "\n"
                case "r": out += "\r"
                case "t": out += "\t"
                case "u":
                    guard index + 4 <= scalars.count else { return nil }
                    var code: UInt32 = 0
                    for _ in 0..<4 {
                        guard let digit = Character(scalars[index]).hexDigitValue else {
                            return nil
                        }
                        code = (code << 4) | UInt32(digit)
                        index += 1
                    }
                    if let unicode = Unicode.Scalar(code) {
                        out.unicodeScalars.append(unicode)
                    }
                default:
                    return nil
                }
            }
            return nil
        }

        private mutating func parseNumber() -> JSON? {
            let start = index
            if current == "-" { index += 1 }
            while let scalar = current,
                  (scalar >= "0" && scalar <= "9") || scalar == "." ||
                    scalar == "e" || scalar == "E" || scalar == "+" || scalar == "-" {
                index += 1
            }
            guard index > start else { return nil }
            let text = String(String.UnicodeScalarView(scalars[start..<index]))
            guard let value = Double(text) else { return nil }
            return .number(value)
        }
    }
}
