#!/bin/bash
# Source based code coverage of the unit tests (clang + llvm-cov).
#   tools/coverage.sh            -> summary table per file
#   tools/coverage.sh --html     -> also writes build-cov/coverage-html/index.html
set -euo pipefail
cd "$(dirname "$0")/.."

LLVM_COV=${LLVM_COV:-$(xcrun --find llvm-cov 2>/dev/null || command -v llvm-cov)}
LLVM_PROFDATA=${LLVM_PROFDATA:-$(xcrun --find llvm-profdata 2>/dev/null || command -v llvm-profdata)}

cmake -S . -B build-cov -DCMAKE_BUILD_TYPE=Debug -DIMSHARK_COVERAGE=ON -DCMAKE_CXX_COMPILER="${CXX:-clang++}" > /dev/null
cmake --build build-cov -j8 --target imshark_tests > /dev/null

rm -f build-cov/*.profraw build-cov/tests.profdata
LLVM_PROFILE_FILE="build-cov/tests-%p.profraw" ./build-cov/tests/imshark_tests > /dev/null
"$LLVM_PROFDATA" merge -sparse build-cov/tests-*.profraw -o build-cov/tests.profdata

# only our own sources: not tests, ImGui, GoogleTest or system headers
IGNORE='(third_party|/tests/|/usr/|/opt/|Xcode)'
"$LLVM_COV" report ./build-cov/tests/imshark_tests -instr-profile=build-cov/tests.profdata \
    -ignore-filename-regex="$IGNORE" -use-color=false

if [ "${1:-}" = "--html" ]; then
    "$LLVM_COV" show ./build-cov/tests/imshark_tests -instr-profile=build-cov/tests.profdata \
        -ignore-filename-regex="$IGNORE" -format=html -output-dir=build-cov/coverage-html > /dev/null
    echo "HTML report: build-cov/coverage-html/index.html"
fi
