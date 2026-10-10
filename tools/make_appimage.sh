#!/usr/bin/env bash
# make_appimage.sh - builds an AppImage with linuxdeploy. Not part of CPack. The release workflow
# (.github/workflows/release.yml) calls it on the Linux runner after the build; you can also run it by hand on a
# Linux machine after building. Set VERSION to put the version in the file name (ImShark-<VERSION>-x86_64.AppImage).
#
# Usage: LINUXDEPLOY=/path/to/linuxdeploy-x86_64.AppImage ./tools/make_appimage.sh [build_dir] [icon.png]
#
# linuxdeploy is not downloaded by this script: the release workflow fetches a pinned release, and by hand you obtain
# it yourself, check its signature or checksum, and point LINUXDEPLOY at it. `--output appimage` also needs the
# executable linuxdeploy-plugin-appimage on PATH. The optional icon argument overrides the bundled ImShark logo.
set -euo pipefail

BUILD_DIR="${1:-build}"
ICON_SRC="${2:-$(cd "$(dirname "$0")/.." && pwd)/resources/imshark.png}"
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

# Use the install rules so the AppImage includes dependency copyright notices and future resources.
DESTDIR="$(pwd)/$APP_DIR" cmake --install "$BUILD_DIR" --prefix /usr

cp "$ICON_SRC" "$ICON"

"$LINUXDEPLOY" --appdir "$APP_DIR" --output appimage \
    -d "$APP_DIR/usr/share/applications/imshark.desktop" -i "$ICON"

echo "Created: ImShark-*.AppImage"
