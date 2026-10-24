import Foundation

/**
 TGCP 常量。

 ⚠️ **这个文件由 `tools/gen_swift_constants.py` 从 `starradar-pc/core/tgcp.py`
 生成**，不要手改。P 是 512 位素数，手抄 128 个十六进制字符只要错一位，
 握手就会稳定失败而错误信息只会说"公钥越界"。
 */
public enum TgcpConstants {

    /// 与 PC 版 `P_HEX` 完全一致。
    public static let pHex = "97981e0aade0de72e29cd2789193562547bad2591fb7e59c523923dddecebccae49bdcd4b8ec39022b0bd95d4af8fd3cd600919393255c1084c2fd5abb2fede3"

    public static let p = BigUInt(hex: pHex)!

    public static let g = BigUInt(2)

    /// DH 公钥定长 64 字节（左补零）。
    public static let dhPublicBytes = 64
}
