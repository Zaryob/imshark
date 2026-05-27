#!/usr/bin/env bash
# make_appimage.sh - builds an AppImage with linuxdeploy. Not part of CPack. The release workflow
# (.github/workflows/release.yml) calls it on the Linux runner after the build; you can also run it by hand on a
# Linux machine after building. Set VERSION to put the version in the file name (ImShark-<VERSION>-x86_64.AppImage).
#
# Usage: LINUXDEPLOY=/path/to/linuxdeploy-x86_64.AppImage ./tools/make_appimage.sh [build_dir] [icon.png]
#
# linuxdeploy is not downloaded by this script: the release workflow fetches a pinned release, and by hand you obtain
# it yourself, check its signature or checksum, and point LINUXDEPLOY at it. The icon is
# optional; without one a plain placeholder PNG is generated (the project has no icon artwork yet).
set -euo pipefail

BUILD_DIR="${1:-build}"
ICON_SRC="${2:-}"
APP_DIR="AppDir"
LINUXDEPLOY="${LINUXDEPLOY:-linuxdeploy-x86_64.AppImage}"

if [ ! -f "$BUILD_DIR/imshark" ]; then
    echo "Error: $BUILD_DIR/imshark not found. Run cmake --build $BUILD_DIR first." >&2
    exit 1
fi
if ! command -v "$LINUXDEPLOY" &>/dev/null; then
    echo "Error: linuxdeploy not found ('$LINUXDEPLOY'). Set LINUXDEPLOY to its path." >&2
    exit 1
fi

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/usr/bin" "$APP_DIR/usr/share/applications" "$APP_DIR/usr/share/icons/hicolor/256x256/apps"
ICON="$APP_DIR/usr/share/icons/hicolor/256x256/apps/imshark.png"

cp "$BUILD_DIR/imshark" "$APP_DIR/usr/bin/"

cat > "$APP_DIR/usr/share/applications/imshark.desktop" <<DESKTOP
[Desktop Entry]
Name=ImShark
Exec=imshark
Icon=imshark
Type=Application
Categories=Network;
DESKTOP

if [ -n "$ICON_SRC" ]; then
    cp "$ICON_SRC" "$ICON"
else
    # placeholder: a valid 256x256 single colour PNG (a 0-byte file makes linuxdeploy fail)
    python3 - "$ICON" <<'PY'
import struct, sys, zlib
def chunk(t, d):
    c = struct.pack(">I", len(d)) + t + d
    return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
row = b"\x00" + bytes([0x2E, 0x5E, 0x8C]) * 256
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 256, 256, 8, 2, 0, 0, 0)) \
    + chunk(b"IDAT", zlib.compress(row * 256)) + chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
PY
fi

"$LINUXDEPLOY" --appdir "$APP_DIR" --output appimage \
    -d "$APP_DIR/usr/share/applications/imshark.desktop" -i "$ICON"

echo "Created: ImShark-*.AppImage"
