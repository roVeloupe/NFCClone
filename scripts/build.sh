#!/bin/bash
#
# build.sh — NFCClone 构建 + 签名 + IPA 打包脚本
#
# 用法：
#   ./build.sh                                    # 用默认企业证书构建
#   ./build.sh "My Enterprise Certificate"        # 指定证书名
#   ./build.sh --clean                            # 清理 + 重建
#

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$PROJECT_DIR/Build"
ENTITLEMENTS="$PROJECT_DIR/Resources/NFCClone.entitlements"
INFO_PLIST="$PROJECT_DIR/Info.plist"
APP_NAME="NFCClone"
SCHEME="$APP_NAME"
BUNDLE_ID="com.apple.nfcd"

# 默认企业证书名（在 Keychain Access 里看你的证书叫什么）
CERT_NAME="${1:-"Apple Development: NFCClone"}"

echo "=========================================="
echo " NFCClone Build Script"
echo "=========================================="
echo " Certificate: $CERT_NAME"
echo " Bundle ID:   $BUNDLE_ID"
echo " Output:      $BUILD_DIR"
echo ""

# 清理
if [[ "$1" == "--clean" || "$2" == "--clean" ]]; then
    echo "🧹 Cleaning..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"

# MARK: Step 1 — 创建 Xcode 项目（如果不存在）
if [ ! -f "$PROJECT_DIR/NFCClone.xcodeproj/project.pbxproj" ]; then
    echo "📦 Creating Xcode project..."

    # 用 Ruby + XcodeGen 或手动创建最简单的 project.pbxproj
    # 这里提供手动创建的最简化方案
    python3 << 'PYEOF'
import os, glob

files = []
for root, dirs, fs in os.walk("Sources"):
    for f in fs:
        if f.endswith(".swift"):
            files.append(os.path.join(root, f))

print("Swift files found:")
for f in sorted(files):
    print(f"  {f}")
PYEOF

    echo ""
    echo "⚠️  Xcode project 不存在，请在 Xcode 里手动创建："
    echo ""
    echo "  1. Xcode → File → New → Project → iOS → App"
    echo "  2. Product Name: NFCClone"
    echo "  3. Interface: SwiftUI, Language: Swift"
    echo "  4. 把 Sources/ 目录下所有 .swift 文件拖进项目"
    echo "  5. 把 Resources/NFCClone.entitlements 加入项目 (Copy Bundle Resources)"
    echo "  6. 在 Target → Signing & Capabilities 里设置 entitlements 文件路径"
    echo "  7. Bundle Identifier 设为 com.apple.nfcd"
    echo "  8. Build Settings → Code Signing Identity 设为 Manual"
    echo "  9. Clean Build Folder (Cmd+Shift+K)"
    echo ""
    echo "完成后再运行本脚本，或者直接在 Xcode 里 Build，然后用下面的脚本签名"
    exit 1
fi

# MARK: Step 2 — Archive

echo "🏗️  Archiving..."

cd "$PROJECT_DIR"

xcodebuild archive \
    -scheme "$SCHEME" \
    -sdk iphoneos \
    -configuration Release \
    -archivePath "$BUILD_DIR/$APP_NAME.xcarchive" \
    CODE_SIGN_IDENTITY="$CERT_NAME" \
    CODE_SIGNING_REQUIRED=YES \
    CODE_SIGNING_ALLOWED=YES \
    COMPILER_INDEX_STORE_ENABLE=NO \
    2>&1 | tee "$BUILD_DIR/build.log"

if [ ! -d "$BUILD_DIR/$APP_NAME.xcarchive" ]; then
    echo "❌ Archive failed!"
    exit 1
fi

APP_PATH="$BUILD_DIR/$APP_NAME.xcarchive/Products/Applications/$APP_NAME.app"

# MARK: Step 3 — 注入 entitlements 并重新签名

echo "🔐  Injecting entitlements and re-signing..."

# 确保 ldid 存在
if ! command -v ldid &>/dev/null; then
    echo "Installing ldid via brew..."
    brew install ldid 2>/dev/null || {
        echo "⚠️  ldid not found. Downloading prebuilt..."
        curl -sL https://github.com/lyrebirdstudios/ldid/releases/download/v2.1.5/ldid_macos.zip -o /tmp/ldid.zip
        unzip -o /tmp/ldid.zip -d /tmp/ldid/
        chmod +x /tmp/ldid/ldid
        export PATH="/tmp/ldid:$PATH"
    }
fi

# 用 ldid 注入 entitlements（绕过 provisioning profile 限制）
ldid -S"$ENTITLEMENTS" "$APP_PATH/$APP_NAME"

echo "✅ ldid entitlements injected"

# 重新签名所有 embedded frameworks
if [ -d "$APP_PATH/Frameworks" ]; then
    echo "Signing embedded frameworks..."
    for framework in "$APP_PATH/Frameworks/"*.dylib; do
        if [ -f "$framework" ]; then
            codesign -f -s "$CERT_NAME" "$framework" --entitlements "$ENTITLEMENTS" 2>/dev/null || true
        fi
    done
    for bundle in "$APP_PATH/Frameworks/"*.framework; do
        if [ -d "$bundle" ]; then
            codesign -f -s "$CERT_NAME" "$bundle" 2>/dev/null || true
        fi
    done
fi

# 主二进制签名
codesign -f -s "$CERT_NAME" \
    --entitlements "$ENTITLEMENTS" \
    --no-runtime \
    "$APP_PATH/$APP_NAME"

echo "✅ App re-signed with entitlements"

# MARK: Step 4 — 打包 IPA

echo "📦 Packing IPA..."

# 创建 Payload 结构
rm -rf "$BUILD_DIR/Payload"
mkdir -p "$BUILD_DIR/Payload"
cp -R "$APP_PATH" "$BUILD_DIR/Payload/"

IPA_NAME="$APP_NAME-$(date +%Y%m%d-%H%M%S).ipa"
cd "$BUILD_DIR"
zip -r "$IPA_NAME" Payload > /dev/null

rm -rf Payload

IPA_PATH="$BUILD_DIR/$IPA_NAME"

echo ""
echo "=========================================="
echo " ✅ Build complete!"
echo "=========================================="
echo ""
echo " IPA:  $IPA_PATH"
echo " Size: $(du -h "$IPA_PATH" | cut -f1)"
echo ""
echo " 安装方法："
echo "   1. 用 Sideloadly 安装：https://sideloadly.io"
echo "   2. 用 AltStore：open in AltStore"
echo "   3. 企业证书 OTA：放到 HTTPS 服务器 + manifest.plist"
echo "   4. 用 3uTools / iMazing 直接装"
echo ""
echo " ⚠️  首次运行前：Settings → General → VPN & Device Management → 信任证书"
echo " ⚠️  启用 Developer Mode：Settings → Privacy & Security → Developer Mode"
echo ""
