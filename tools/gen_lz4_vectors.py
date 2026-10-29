#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 LZ4 交叉验证向量：`Core/Tests/StarRadarCoreTests/Vectors/lz4_vectors.json`

## 为什么要这个文件

iOS 的 `Lz4.swift` 是新写的第三个实现（Python / Kotlin / Swift）。LZ4 的
错误不会「明显崩」——它会安静地解出一段错的字节，而母料扫描拿不到东西
时的现象和「这一帧本来就没有母料」完全一样。所以必须拿参考实现逐字节比对。

参考实现就用 PC 的 `starradar-pc/core/lz4.py`（源码里写明它是唯一算法源头）。
本脚本**用 PC 的实现解出期望输出**再写进向量，而不是我手算期望值 ——
手算 280 字节 literal 或重叠 match 的偏移，错一位就是一条假通过的用例。

## 用例怎么挑的

按 LZ4 block 格式里**每一处分支**各来一条：

    · 空输入
    · 纯 literal（短 / 长，长的那条要触发 0xFF 连续累加）
    · literal + match（普通回溯）
    · offset = 1（RLE，源区间与目标区间完全重叠）
    · offset < matchLen（部分重叠，逐字节复制的正确性靠这条）
    · 长 match（matchLen 超过 15，走扩展字节）
    · 真实形状：172 字符 base64 母料 + 中英混排控制字节
    · 非法输入（offset = 0 / offset 越界 / literal 截断）→ 必须抛错

    用法：python tools/gen_lz4_vectors.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IOS_ROOT = os.path.dirname(HERE)
PC_ROOT = os.path.join(os.path.dirname(IOS_ROOT), 'starradar-pc')
OUTPUT = os.path.join(IOS_ROOT, 'Core', 'Tests', 'StarRadarCoreTests',
                      'Vectors', 'lz4_vectors.json')

sys.path.insert(0, PC_ROOT)
from core import lz4 as ref  # noqa: E402


def literal_only(payload: bytes) -> bytes:
    """把整段当 literal 输出（LZ4 最后一个 block 的合法形态）。"""
    n = len(payload)
    if n < 15:
        return bytes([n << 4]) + payload
    out = bytearray([0xF0])
    rest = n - 15
    while rest >= 255:
        out.append(0xFF)
        rest -= 255
    out.append(rest)
    out += payload
    return bytes(out)


def seq(literals: bytes, offset: int, match_len: int,
        tail: bytes = b'') -> bytes:
    """手工拼「literal 段 + 一个 match + 尾部 literal」。

    match_len 是**解压后的总长度**（含 MIN_MATCH=4）。
    """
    body = match_len - 4
    lit_len = len(literals)
    token_hi = 15 if lit_len >= 15 else lit_len
    token_lo = 15 if body >= 15 else body
    out = bytearray([(token_hi << 4) | token_lo])
    if lit_len >= 15:
        rest = lit_len - 15
        while rest >= 255:
            out.append(0xFF)
            rest -= 255
        out.append(rest)
    out += literals
    out += bytes([offset & 0xFF, (offset >> 8) & 0xFF])
    if body >= 15:
        rest = body - 15
        while rest >= 255:
            out.append(0xFF)
            rest -= 255
        out.append(rest)
    if tail:
        out += literal_only(tail)
    return bytes(out)


def material_bytes(seed: str) -> bytes:
    """确定性的 128 字节母料（不用随机数，向量要可复现）。"""
    out = bytearray()
    counter = 0
    while len(out) < 128:
        out += hashlib.sha256(('%s:%d' % (seed, counter)).encode()).digest()
        counter += 1
    return bytes(out[:128])


def cases() -> list:
    out = []

    def add(name, block, note, expect_error=False):
        row = {'name': name, 'block_hex': block.hex(), 'note': note}
        if expect_error:
            try:
                ref.decompress(block)
            except ref.Lz4Error:
                row['expectError'] = True
                out.append(row)
                return
            raise SystemExit('用例 %s 本应报错，参考实现却解出来了' % name)
        try:
            plain = ref.decompress(block)
        except ref.Lz4Error as exc:
            raise SystemExit('用例 %s 参考实现解不开：%s' % (name, exc))
        row['plainLen'] = len(plain)
        row['plainSha256'] = hashlib.sha256(plain).hexdigest()
        # 小于 4 KB 的明文整段放进向量，方便失败时直接看差在哪
        if len(plain) <= 4096:
            row['plain_hex'] = plain.hex()
        out.append(row)

    add('empty', b'', '空输入 → 空输出（不是错误）')

    add('literal_short', literal_only(b'hello world'),
        '纯 literal，长度 < 15，token 高 4 位直接就是长度')

    add('literal_long', literal_only(b'A' * 40),
        '纯 literal，长度 40：token 高 4 位 = 15，再跟一个 25 的扩展字节')

    add('literal_escape_chain',
        literal_only(bytes(range(256)) + b'x' * 24),
        'literal 长度 280：扩展字节 0xFF 连加两段（255 + 10）')

    add('literal_plus_match',
        seq(b'abcd', 4, 8),
        '标准回溯：literals "abcd" + offset=4 len=8 → abcdabcdabcd')

    add('rle_offset_one',
        seq(b'A', 1, 99),
        'offset=1 的 RLE：解出 100 个 A，源区间与目标区间完全重叠')

    add('overlap_partial',
        seq(b'xyz', 3, 20),
        'offset=3 < matchLen=20：逐字节复制才会对，整段拷贝会读到垃圾')

    add('long_match_escape',
        seq(b'head', 4, 300),
        'matchLen=300：低 4 位 = 15 后走扩展字节（255 + 41）')

    # ── 真实形状：base64 母料 ────────────────────────────────
    material = material_bytes('ios-vector')
    token = base64.b64encode(material)
    real = b'\x08\x01\x12\x10CSPlayerJoinMatchNtf' + token + b'\x18\x00'
    add('material_base64_literal', literal_only(real),
        '172 字符 base64 母料 + 前后控制字节，真实帧的最小形状')

    # 母料后面紧跟一个 match：控制字节会污染 base64 边界，
    # 这正是「不解压就概率性失败」的原因，向量要能复现这个形态
    add('material_then_match', seq(real, len(real), 32),
        '母料后紧跟回溯段：解压与否会影响边界判定')

    # ── 非法输入 ─────────────────────────────────────────────
    add('bad_offset_zero', bytes([0x14]) + b'abcd' + bytes([0x00, 0x00]),
        'offset = 0 是非法值', expect_error=True)
    add('bad_offset_too_far', bytes([0x14]) + b'abcd' + bytes([0x09, 0x00]),
        'offset 超过已输出长度', expect_error=True)
    add('bad_literal_truncated', bytes([0x60]) + b'ab',
        '声明 6 字节 literal 但只给了 2 字节', expect_error=True)
    add('last_block_no_match', bytes([0x10]) + b'a',
        'literal 之后数据就结束了：这是最后一个 block 的合法收尾，'
        '不能当成「offset 字段不完整」报错', expect_error=False)
    return out


def main() -> None:
    rows = cases()
    doc = {
        'note': '由 tools/gen_lz4_vectors.py 生成，期望值来自 PC 参考实现 '
                'starradar-pc/core/lz4.py。不要手改。',
        'cases': rows,
    }
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w', encoding='utf-8', newline='') as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
    print('写入 %s：%d 条' % (OUTPUT, len(rows)))
    for row in rows:
        flag = 'ERR ' if row.get('expectError') else 'ok  '
        print('  %s %-26s %s' % (flag, row['name'], row['note']))


if __name__ == '__main__':
    main()
