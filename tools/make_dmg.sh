#!/usr/bin/env bash
# make_dmg.sh — macOS .app bundle ve DMG paketi oluşturur
# Kullanım: ./tools/make_dmg.sh [build_dir]
set -euo pipefail

BUILD_DIR="${1:-build}"
APP_PATH="$BUILD_DIR/imshark.app"
DMG_NAME="imshark-macos.dmg"

if [ ! -d "$APP_PATH" ]; then
    echo "Hata: $APP_PATH bulunamadı. Önce cmake --build $BUILD_DIR çalıştırın." >&2
    echo "macOS .app bundle için CMake'e -DCMAKE_BUILD_TYPE=Release verin." >&2
    exit 1
fi

if command -v create-dmg &>/dev/null; then
    create-dmg \
        --volname "ImShark" \
        --window-pos 200 120 \
        --window-size 600 300 \
        --icon-size 100 \
        --app-drop-link 425 120 \
        "$DMG_NAME" \
        "$APP_PATH"
else
    # Fallback: hdiutil
    hdiutil create -volname "ImShark" -srcfolder "$APP_PATH" \
        -ov -format UDZO "$DMG_NAME"
fi

echo "Oluşturuldu: $DMG_NAME"
