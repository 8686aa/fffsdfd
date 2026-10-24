#!/usr/bin/env python3
"""从 PC 端的 `core/tgcp.py` 生成 `TgcpConstants.swift`。

为什么不让模型/人手抄：P 是 512 位素数，128 个十六进制字符里错一位，
握手就会稳定失败，而错误信息只会说「公钥越界」—— 排查成本极高。
这里直接读源码、拼成一整串、校验长度与字符集，再写进 Swift。
"""
from __future__ import annotations

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PC_SOURCE = os.path.join(os.path.dirname(ROOT), 'starradar-pc', 'core', 'tgcp.py')
OUTPUT = os.path.join(ROOT, 'Core', 'Sources', 'StarRadarCore', 'TgcpConstants.swift')

TEMPLATE = '''import Foundation

/**
 TGCP 常量。

 ⚠️ **这个文件由 `tools/gen_swift_constants.py` 从 `starradar-pc/core/tgcp.py`
 生成**，不要手改。P 是 512 位素数，手抄 128 个十六进制字符只要错一位，
 握手就会稳定失败而错误信息只会说"公钥越界"。
 */
public enum TgcpConstants {

    /// 与 PC 版 `P_HEX` 完全一致。
    public static let pHex = "{p_hex}"

    public static let p = BigUInt(hex: pHex)!

    public static let g = BigUInt(2)

    /// DH 公钥定长 64 字节（左补零）。
    public static let dhPublicBytes = 64
}
'''


def main() -> int:
    if not os.path.exists(PC_SOURCE):
        print('找不到 PC 端源码：%s' % PC_SOURCE, file=sys.stderr)
        return 1
    text = io.open(PC_SOURCE, encoding='utf-8').read()
    match = re.search(r"P_HEX\s*=\s*\(\s*'([0-9a-fA-F]+)'\s*'([0-9a-fA-F]+)'\s*\)", text)
    if not match:
        print('没找到 P_HEX 定义', file=sys.stderr)
        return 1
    p_hex = match.group(1) + match.group(2)
    if len(p_hex) != 128:
        print('P 长度异常：%d（期望 128）' % len(p_hex), file=sys.stderr)
        return 1
    if any(character not in '0123456789abcdefABCDEF' for character in p_hex):
        print('P 含非十六进制字符', file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    io.open(OUTPUT, 'w', encoding='utf-8', newline='\n').write(
        TEMPLATE.format(p_hex=p_hex))
    print('已生成 %s（%d 位）' % (OUTPUT, len(p_hex) * 4))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
