#!/usr/bin/env bash
#
# 在 macOS 上本地打无签名 ipa。
#
#   ./scripts/build_ipa.sh
#
# 需要：Xcode（命令行工具齐全）、xcodegen（brew install xcodegen）
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v xcodegen >/dev/null 2>&1; then
    echo "缺 xcodegen：brew install xcodegen"
    exit 1
fi

echo "==> 1/4 跑协议层向量测试"
(cd Core && swift test)

echo "==> 2/4 生成 Xcode 工程"
xcodegen generate

echo "==> 3/4 构建 Release（无签名）"
xcodebuild \
    -project StarRadar.xcodeproj \
    -scheme StarRadar \
    -configuration Release \
    -sdk iphoneos \
    -derivedDataPath build \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" \
    build

echo "==> 4/4 打包 Payload"
APP="build/Build/Products/Release-iphoneos/StarRadar.app"
if [ ! -d "$APP" ]; then
    echo "找不到 $APP"
    exit 1
fi
rm -rf Payload StarRadar-unsigned.ipa
mkdir -p Payload
cp -R "$APP" Payload/
zip -qry StarRadar-unsigned.ipa Payload

echo
echo "产物：$(pwd)/StarRadar-unsigned.ipa"
ls -lh StarRadar-unsigned.ipa
echo
echo "安装方式（无签名）：AltStore / Sideloadly / TrollStore 等侧载工具。"
