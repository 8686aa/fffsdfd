#!/usr/bin/env python3
"""校验打出来的无签名 ipa。

    python3 tools/verify_ipa.py <path/to/StarRadar-unsigned.ipa>

检查项：
  1. zip 结构必须是 `Payload/StarRadar.app/` 一层（直接 zip 整个目录会多一层，
     装的时候直接失败）
  2. Info.plist 的关键字段（显示名、bundle id、后台模式、局域网描述、ATS）
  3. Mach-O 是 arm64 + iOS 平台，且最低版本符合预期
  4. 确实没有签名材料（无签名包才允许侧载改造）

## 为什么不用 `codesign` / `plutil` 验

那两个只在 macOS 上有。这个脚本要能在 Windows 上跑（产物是在 CI 上出的，
本地没有 Xcode），所以 plist 用 plistlib、Mach-O 手工解析 load commands。

## 一个曾经的坑：字节序

Mach-O 的 magic 是 0xFEEDFACF，但文件里按**小端**存成 `cf fa ed fe`。
用 `<I` 读得 0xfeedfacf，用 `>I` 读得 0xcffaedfe —— 后者看上去像个
陌生 magic，容易误判成「格式未知」。
"""
from __future__ import annotations

import plistlib
import struct
import sys
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
CPU_TYPE_ARM = 12
CPU_ARCH_ABI64 = 0x01000000
LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION = 0x32
PLATFORM_IOS = 2
PLATFORM_IOSSIMULATOR = 7

APP_PATH = 'Payload/StarRadar.app/'


class Report:
    def __init__(self) -> None:
        self.ok = 0
        self.bad = 0

    def check(self, name: str, condition: bool, detail: str = '') -> bool:
        mark = 'PASS' if condition else 'FAIL'
        print('[%s] %s%s' % (mark, name, ('  → ' + detail) if detail else ''))
        if condition:
            self.ok += 1
        else:
            self.bad += 1
        return condition


def version_text(value: int) -> str:
    return '%d.%d.%d' % (value >> 16, (value >> 8) & 0xFF, value & 0xFF)


def scan_macho(data: bytes) -> dict:
    header = struct.unpack('<6I', data[4:28])
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = header
    out = {
        'cputype': cputype,
        'ncmds': ncmds,
        'min_os': None,
        'sdk': None,
        'platform': None,
    }
    offset = 32
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd, size = struct.unpack('<2I', data[offset:offset + 8])
        if cmd == LC_BUILD_VERSION and offset + 24 <= len(data):
            platform, minos, sdk = struct.unpack('<3I', data[offset + 8:offset + 20])
            out['platform'] = platform
            out['min_os'] = version_text(minos)
            out['sdk'] = version_text(sdk)
        elif cmd == LC_VERSION_MIN_IPHONEOS and offset + 16 <= len(data):
            minos, sdk = struct.unpack('<2I', data[offset + 8:offset + 16])
            out['min_os'] = version_text(minos)
            out['sdk'] = version_text(sdk)
        if size == 0:
            break
        offset += size
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print('用法：python3 tools/verify_ipa.py <ipa 路径>')
        return 2
    path = sys.argv[1]
    report = Report()

    archive = zipfile.ZipFile(path)
    names = archive.namelist()
    print('ipa: %s（%d 个条目）\n' % (path, len(names)))

    # ── 1. 结构 ───────────────────────────────────────────
    print('=== 结构 ===')
    report.check('顶层有 Payload/', any(n == 'Payload/' or n.startswith('Payload/')
                                        for n in names))
    app_dirs = {n.split('/')[1] for n in names
                if n.startswith('Payload/') and len(n.split('/')) > 1
                and n.split('/')[1]}
    report.check('Payload 下只有一个 .app', len(app_dirs) == 1,
                 str(sorted(app_dirs)))
    app_name = sorted(app_dirs)[0] if app_dirs else ''
    report.check('app 名是 StarRadar.app', app_name == 'StarRadar.app', app_name)
    report.check('没有多套一层目录',
                 not any(n.startswith('Payload/Payload') for n in names))

    base = 'Payload/%s/' % app_name if app_name else APP_PATH

    # ── 2. Info.plist ─────────────────────────────────────
    print('\n=== Info.plist ===')
    plist_key = base + 'Info.plist'
    if plist_key not in names:
        report.check('Info.plist 存在', False)
        return 1
    raw = archive.read(plist_key)
    info = plistlib.loads(raw)
    report.check('plist 可解析（二进制或 XML 均可）', bool(info),
                 'binary' if raw[:6] == b'bplist' else 'xml')

    report.check('显示名是 APP',
                 info.get('CFBundleDisplayName') == 'APP',
                 str(info.get('CFBundleDisplayName')))
    bundle_id = info.get('CFBundleIdentifier', '')
    report.check('bundle id 已展开（不是 $(...)）',
                 bool(bundle_id) and '$(' not in bundle_id, bundle_id)
    report.check('CFBundleExecutable 已展开',
                 '$(' not in str(info.get('CFBundleExecutable', '')),
                 str(info.get('CFBundleExecutable')))
    report.check('版本号已展开',
                 '$(' not in str(info.get('CFBundleShortVersionString', '')),
                 str(info.get('CFBundleShortVersionString')))

    background = info.get('UIBackgroundModes') or []
    report.check('声明了 audio 后台模式', 'audio' in background, str(background))
    report.check('有局域网用途描述（iOS 14+ 必需）',
                 bool(info.get('NSLocalNetworkUsageDescription')))
    ats = info.get('NSAppTransportSecurity') or {}
    report.check('允许明文 HTTP（节点接口是 http）',
                 ats.get('NSAllowsArbitraryLoads') is True)
    report.check('有 UILaunchScreen（否则界面被压成 1/4 屏）',
                 'UILaunchScreen' in info)

    # ── 3. Mach-O ─────────────────────────────────────────
    print('\n=== 可执行文件 ===')
    exe_key = base + str(info.get('CFBundleExecutable', 'StarRadar'))
    if exe_key not in names:
        report.check('可执行文件存在', False, exe_key)
        return 1
    exe = archive.read(exe_key)
    print('  大小 %.2f MB' % (len(exe) / 1024 / 1024))

    little = struct.unpack('<I', exe[:4])[0]
    big = struct.unpack('>I', exe[:4])[0]
    report.check('是 64 位 Mach-O（小端读 magic）', little == MH_MAGIC_64,
                 exe[:4].hex())
    report.check('不是 FAT 多架构包（大端读不是 FAT_MAGIC）', big != FAT_MAGIC)
    if little != MH_MAGIC_64:
        return 1

    macho = scan_macho(exe)
    arm64 = CPU_ARCH_ABI64 | CPU_TYPE_ARM
    report.check('架构是 arm64（真机可装）',
                 macho['cputype'] == arm64, hex(macho['cputype']))
    report.check('架构不是 32 位 armv7', macho['cputype'] != CPU_TYPE_ARM)
    platform = macho['platform']
    if platform is not None:
        report.check('平台是 iOS（不是模拟器）', platform == PLATFORM_IOS,
                     'platform=%s' % platform)
    report.check('声明了最低 iOS 版本',
                 macho['min_os'] is not None,
                 '%s（SDK %s）' % (macho['min_os'], macho['sdk']))

    plist_min = info.get('MinimumOSVersion')
    report.check('plist 与 Mach-O 的最低版本一致',
                 plist_min is not None and
                 macho['min_os'] is not None and
                 str(plist_min).startswith(macho['min_os'].rsplit('.', 1)[0]),
                 'plist=%s macho=%s' % (plist_min, macho['min_os']))

    # ── 4. 签名 ───────────────────────────────────────────
    print('\n=== 签名状态 ===')
    signed = any('_CodeSignature' in n for n in names)
    provision = any(n.endswith('embedded.mobileprovision') for n in names)
    report.check('没有 _CodeSignature（无签名包）', not signed)
    report.check('没有 embedded.mobileprovision', not provision)
    if signed:
        print('  注意：带签名材料，侧载工具可能要求先剥离')

    print('\n%d 项通过，%d 项失败' % (report.ok, report.bad))
    if report.bad == 0:
        print('\n结论：这个 ipa 结构完整、arm64、无签名，可用 AltStore /')
        print('      Sideloadly / TrollStore 等工具侧载安装。')
        print('      注意 iOS 会校验签名，侧载工具需要用它自己的证书重签一次。')
    return 0 if report.bad == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
