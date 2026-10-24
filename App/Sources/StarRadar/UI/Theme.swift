import SwiftUI

/// 配色与 PC / Android 端一致：白底 + 橙。
enum Sr {

    static let bg = Color(hex: 0xFFFFFF)
    static let surface = Color(hex: 0xFFFFFF)
    static let surface2 = Color(hex: 0xF6F7F9)
    static let line = Color(hex: 0xE5E7EB)
    static let line2 = Color(hex: 0x9CA3AF)
    static let fg = Color(hex: 0x111827)
    static let dim = Color(hex: 0x6B7280)
    static let accent = Color(hex: 0xEA580C)
    static let accentDark = Color(hex: 0xC2410C)
    static let accentSoft = Color(hex: 0xFFF7ED)
    static let accentLine = Color(hex: 0xFED7AA)
    static let ok = Color(hex: 0x16A34A)
    static let err = Color(hex: 0xDC2626)
    static let warn = Color(hex: 0xD97706)
}

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255.0,
            green: Double((hex >> 8) & 0xFF) / 255.0,
            blue: Double(hex & 0xFF) / 255.0,
            opacity: 1.0
        )
    }
}

/// 白底卡片。
struct SrCard<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Sr.surface)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(Sr.line, lineWidth: 1)
            )
            .cornerRadius(12)
    }
}

struct CardTitle: View {
    let text: String
    var tag: String = ""

    var body: some View {
        HStack(spacing: 6) {
            Text(text)
                .font(.system(size: 13.5, weight: .semibold))
                .foregroundColor(Sr.fg)
            if !tag.isEmpty {
                Text(tag)
                    .font(.system(size: 10.5))
                    .foregroundColor(Sr.dim)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(Sr.surface2)
                    .cornerRadius(999)
            }
        }
    }
}

enum HintTone {
    case normal, ok, warn, error
}

struct Hint: View {
    let text: String
    var tone: HintTone = .normal

    init(_ text: String, tone: HintTone = .normal) {
        self.text = text
        self.tone = tone
    }

    private var color: Color {
        switch tone {
        case .normal: return Sr.dim
        case .ok: return Sr.ok
        case .warn: return Sr.warn
        case .error: return Sr.err
        }
    }

    var body: some View {
        Text(text)
            .font(.system(size: 11.5))
            .foregroundColor(color)
            .fixedSize(horizontal: false, vertical: true)
    }
}

struct Mono: View {
    let text: String
    var size: CGFloat = 13
    var color: Color = Sr.fg

    init(_ text: String, size: CGFloat = 13, color: Color = Sr.fg) {
        self.text = text
        self.size = size
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.system(size: size, design: .monospaced))
            .foregroundColor(color)
    }
}

struct StatView: View {
    let label: String
    let value: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(size: 17, weight: .semibold))
                .foregroundColor(Sr.fg)
            Text(label)
                .font(.system(size: 10.5))
                .foregroundColor(Sr.dim)
        }
        .frame(maxWidth: .infinity)
    }
}

struct PrimaryButton: View {
    let title: String
    var enabled: Bool = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 14.5, weight: .semibold))
                .foregroundColor(enabled ? .white : Sr.line2)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 11)
                .background(enabled ? Sr.accent : Sr.surface2)
                .cornerRadius(9)
        }
        .disabled(!enabled)
    }
}

struct SecondaryButton: View {
    let title: String
    var enabled: Bool = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 13.5))
                .foregroundColor(enabled ? Sr.fg : Sr.line2)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 9)
                .background(Sr.surface2)
                .cornerRadius(9)
        }
        .disabled(!enabled)
    }
}
