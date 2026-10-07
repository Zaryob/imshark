#!/usr/bin/env bash
# Run inside the verification image, including with --network none.
set -euo pipefail
REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_DIR"
ctest --preset default --parallel 1 --output-on-failure
bash tools/linux_smoke.sh /opt/imshark/bin
