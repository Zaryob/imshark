#!/usr/bin/env bash
# make_appimage.sh — linuxdeploy ile AppImage oluşturma scripti
# Kullanım: ./tools/make_appimage.sh [build_dir]
set -euo pipefail

BUILD_DIR="${1:-build}"
APP_DIR="AppDir"

if [ ! -f "$BUILD_DIR/imshark" ]; then
    echo "Hata: $BUILD_DIR/imshark bulunamadı. Önce cmake --build $BUILD_DIR çalıştırın." >&2
    exit 1
fi

if ! command -v linuxdeploy-x86_64.AppImage &>/dev/null; then
    echo "linuxdeploy-x86_64.AppImage bulunamadı, indiriliyor..."
    wget -c -nv "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
    chmod +x linuxdeploy-x86_64.AppImage
    LINUXDEPLOY="./linuxdeploy-x86_64.AppImage"
else
    LINUXDEPLOY="linuxdeploy-x86_64.AppImage"
fi

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/usr/bin"
mkdir -p "$APP_DIR/usr/share/applications"
mkdir -p "$APP_DIR/usr/share/icons/hicolor/256x256/apps"

cp "$BUILD_DIR/imshark" "$APP_DIR/usr/bin/"

cat > "$APP_DIR/usr/share/applications/imshark.desktop" <<EOF
[Desktop Entry]
Name=ImShark
Exec=imshark
Icon=imshark
Type=Application
Categories=Network;
EOF

touch "$APP_DIR/usr/share/icons/hicolor/256x256/apps/imshark.png"

$LINUXDEPLOY --appdir "$APP_DIR" --output appimage -d "$APP_DIR/usr/share/applications/imshark.desktop" -i "$APP_DIR/usr/share/icons/hicolor/256x256/apps/imshark.png"

echo "Oluşturuldu: ImShark-*.AppImage"
