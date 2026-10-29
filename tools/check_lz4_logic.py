# -*- coding: utf-8 -*-
"""按 Swift 版 Lz4.decompress 的**扩容逻辑**逐行复刻，跑一遍向量。

为什么要单独复刻：PC 的 core/lz4.py 用 `bytearray.append`，不需要自己管容量；
Swift 版为了避开数组重复扩容，写的是「预分配 capacity + ensure 翻倍 +
replaceSubrange 定长覆盖」。这段容量逻辑是本机唯一没法编译验证的部分，
只能靠等价复刻来查边界（比如 capacity 与实际长度脱节、ensure 少算一位）。

用法：python tools/check_lz4_logic.py（Windows/Linux 上也能跑，不需要 Swift）
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IOS = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(os.path.dirname(IOS), 'starradar-pc'))
from core import lz4 as ref  # noqa: E402

VECTORS = os.path.join(IOS, 'Core', 'Tests', 'StarRadarCoreTests',
                       'Vectors', 'lz4_vectors.json')
MAX_NIBBLE = 15
MIN_MATCH = 4


class Lz4Error(Exception):
    pass


def decompress(data: bytes, max_output: int = 4194304) -> bytes:
    """逐行对应 Swift 实现（capacity / ensure / replaceSubrange / 逐字节 match）。"""
    size = len(data)
    if size == 0:
        return b''
    capacity = min(max_output, max(1024, size))
    out = bytearray(capacity)          # [UInt8](repeating: 0, count: capacity)
    out_len = 0
    pos = 0

    def ensure(need: int) -> None:
        nonlocal capacity, out
        want = out_len + need
        if want <= capacity:
            return
        if need < 0 or want > max_output:
            raise Lz4Error('解压结果过大')
        cap = capacity
        while cap < want:
            cap = min(max_output, cap * 2)
        if cap < want:
            raise Lz4Error('解压结果过大')
        out += bytes(cap - capacity)   # append(contentsOf: [UInt8](repeating:0,...))
        capacity = cap

    while pos < size:
        token = data[pos]
        pos += 1

        literal_len = token >> 4
        if literal_len == MAX_NIBBLE:
            while True:
                if pos >= size:
                    raise Lz4Error('literal 长度越界')
                extra = data[pos]
                pos += 1
                literal_len += extra
                if extra != 0xFF:
                    break
        if literal_len > 0:
            end = pos + literal_len
            if end > size:
                raise Lz4Error('literal 数据越界')
            ensure(literal_len)
            # out.replaceSubrange(outLen..<(outLen+literalLen), with: data[pos..<end])
            out[out_len:out_len + literal_len] = data[pos:end]
            out_len += literal_len
            pos = end

        if pos >= size:
            break

        if pos + 2 > size:
            raise Lz4Error('offset 字段不完整')
        offset = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if offset == 0 or offset > out_len:
            raise Lz4Error('offset 非法（%d，已输出 %d）' % (offset, out_len))

        match_len = token & 0x0F
        if match_len == MAX_NIBBLE:
            while True:
                if pos >= size:
                    raise Lz4Error('match 长度越界')
                extra = data[pos]
                pos += 1
                match_len += extra
                if extra != 0xFF:
                    break
        match_len += MIN_MATCH
        ensure(match_len)

        src = out_len - offset
        for _ in range(match_len):
            out[out_len] = out[src]
            out_len += 1
            src += 1

    if out_len == capacity:
        return bytes(out[:out_len])
    return bytes(out[:out_len])


def main() -> None:
    doc = json.load(open(VECTORS, encoding='utf-8'))
    ok = bad = 0
    for case in doc['cases']:
        name = case['name']
        block = bytes.fromhex(case['block_hex'])
        if case.get('expectError'):
            try:
                decompress(block)
                print('FAIL %-26s 本应报错' % name)
                bad += 1
            except Lz4Error:
                ok += 1
            continue
        try:
            plain = decompress(block)
        except Lz4Error as exc:
            print('FAIL %-26s 意外报错：%s' % (name, exc))
            bad += 1
            continue
        if plain.hex() != case['plain_hex'] if 'plain_hex' in case else \
                len(plain) != case['plainLen']:
            print('FAIL %-26s 内容/长度不符' % name)
            bad += 1
            continue
        # 与参考实现再对一次（双保险）
        expect = ref.decompress(block)
        if plain != expect:
            print('FAIL %-26s 与参考实现不一致' % name)
            bad += 1
            continue
        ok += 1
    print('复刻版：%d 通过，%d 失败' % (ok, bad))
    # 额外：大输入触发扩容路径（capacity 从 1024 翻倍成长）
    import hashlib
    big = (b'lorem ipsum dolor sit amet ' * 400)
    block = bytes([0xF0]) + _ext(len(big) - 15) + big
    assert decompress(block) == ref.decompress(block) == big
    print('扩容路径：%d 字节 OK（%s）'
          % (len(big), hashlib.sha256(big).hexdigest()[:12]))
    return 0 if bad == 0 else 1


def _ext(rest: int) -> bytes:
    out = bytearray()
    while rest >= 255:
        out.append(0xFF)
        rest -= 255
    out.append(rest)
    return bytes(out)


if __name__ == '__main__':
    sys.exit(main())
