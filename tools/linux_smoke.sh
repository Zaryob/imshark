#!/usr/bin/env bash
# Exercise the real GLFW/OpenGL application with a checked-in capture. No GPU,
# display server, network, capture privileges, or optional corpus is required.
set -euo pipefail

REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${1:-"$REPO_DIR/build"}
CAPTURE=${2:-"$REPO_DIR/tests/data/sample.pcap"}
SMOKE_ARTIFACT_DIR=${SMOKE_ARTIFACT_DIR:-}

for tool in xvfb-run glxinfo openbox xdotool wmctrl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing Linux smoke-test tool: $tool (see docs/BUILDING.md)." >&2
        exit 1
    fi
done
if [[ -n "$SMOKE_ARTIFACT_DIR" ]] && ! command -v import >/dev/null 2>&1; then
    echo 'Screenshot output requires ImageMagick (the import command).' >&2
    exit 1
fi
if [[ ! -x "$BUILD_DIR/imshark" || ! -f "$CAPTURE" ]]; then
    echo "Expected an imshark executable in $BUILD_DIR and capture at $CAPTURE." >&2
    exit 1
fi

export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe
export IMSHARK_SMOKE_APP="$BUILD_DIR/imshark" IMSHARK_SMOKE_CAPTURE="$CAPTURE"
export SMOKE_ARTIFACT_DIR
xvfb-run --auto-servernum --server-args='-screen 0 1600x1000x24 -nolisten tcp' bash <<'SMOKE'
set -euo pipefail
smoke_dir=$(mktemp -d)
app_pid=
wm_pid=
cleanup() {
    if [[ -n "$SMOKE_ARTIFACT_DIR" ]]; then
        mkdir -p "$SMOKE_ARTIFACT_DIR"
        for log in opengl imshark openbox; do
            [[ ! -f "$smoke_dir/$log.log" ]] || cp "$smoke_dir/$log.log" "$SMOKE_ARTIFACT_DIR/$log.log"
        done
    fi
    [[ -z "$app_pid" ]] || kill "$app_pid" 2>/dev/null || true
    [[ -z "$wm_pid" ]] || kill "$wm_pid" 2>/dev/null || true
    rm -rf "$smoke_dir"
}
trap cleanup EXIT
glxinfo -B | tee "$smoke_dir/opengl.log"
if ! grep -qi 'OpenGL renderer string: llvmpipe' "$smoke_dir/opengl.log"; then
    echo 'Expected Mesa llvmpipe software rendering.' >&2
    exit 1
fi
# Isolate settings so CI never reads or writes a developer's preferences.
export XDG_CONFIG_HOME="$smoke_dir/config"
mkdir -p "$XDG_CONFIG_HOME"
openbox >"$smoke_dir/openbox.log" 2>&1 &
wm_pid=$!
# Wait for the window manager to own the display before GLFW maps its window.
for ((attempt = 0; attempt < 100; ++attempt)); do
    if wmctrl -m >/dev/null 2>&1; then break; fi
    if ! kill -0 "$wm_pid" 2>/dev/null; then
        cat "$smoke_dir/openbox.log" >&2
        exit 1
    fi
    sleep 0.1
done
if ! wmctrl -m >/dev/null 2>&1; then
    echo 'Openbox did not initialize within 10 seconds.' >&2
    exit 1
fi
"$IMSHARK_SMOKE_APP" -- "$IMSHARK_SMOKE_CAPTURE" >"$smoke_dir/imshark.log" 2>&1 &
app_pid=$!
window_id=
for ((attempt = 0; attempt < 100; ++attempt)); do
    if ! kill -0 "$app_pid" 2>/dev/null; then
        cat "$smoke_dir/imshark.log" >&2
        echo 'ImShark exited before creating its window.' >&2
        exit 1
    fi
    window_id=$(xdotool search --onlyvisible --pid "$app_pid" --name 'ImShark$' 2>/dev/null | head -n 1 || true)
    [[ -z "$window_id" ]] || break
    sleep 0.1
done
if [[ -z "$window_id" ]]; then
    cat "$smoke_dir/imshark.log" >&2
    echo 'ImShark did not create a visible window within 10 seconds.' >&2
    exit 1
fi
# The title changes only after the loader publishes a nonempty capture.
capture_name=$(basename -- "$IMSHARK_SMOKE_CAPTURE")
capture_loaded=false
for ((attempt = 0; attempt < 100; ++attempt)); do
    if ! kill -0 "$app_pid" 2>/dev/null; then
        cat "$smoke_dir/imshark.log" >&2
        echo 'ImShark exited while loading the capture.' >&2
        exit 1
    fi
    title=$(xdotool getwindowname "$window_id")
    if [[ "$title" == "$capture_name ("*") - ImShark" && "$title" =~ \([1-9][0-9]*\ packets\) ]]; then
        capture_loaded=true
        echo "Loaded capture: $title"
        break
    fi
    sleep 0.1
done
if [[ "$capture_loaded" != true ]]; then
    cat "$smoke_dir/imshark.log" >&2
    echo 'ImShark did not publish a nonempty capture within 10 seconds.' >&2
    exit 1
fi
# Let several complete frames render before taking visual evidence.
xdotool windowfocus "$window_id"
xdotool key --clearmodifiers --window "$window_id" Home
sleep 1
if [[ -n "$SMOKE_ARTIFACT_DIR" ]]; then
    mkdir -p "$SMOKE_ARTIFACT_DIR"
    import -window "$window_id" "$SMOKE_ARTIFACT_DIR/imshark-linux.png"
fi
# A window manager delivers WM_DELETE_WINDOW, exercising normal app shutdown.
printf -v window_hex '0x%x' "$window_id"
wmctrl -ic "$window_hex"
for ((attempt = 0; attempt < 100; ++attempt)); do
    if ! kill -0 "$app_pid" 2>/dev/null; then
        wait "$app_pid"
        app_pid=
        echo 'Linux GUI smoke passed: fixture opened, OpenGL rendered, window closed cleanly.'
        exit 0
    fi
    sleep 0.1
done
cat "$smoke_dir/imshark.log" >&2
echo 'ImShark did not exit cleanly after its window was closed.' >&2
exit 1
SMOKE
