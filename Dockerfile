# Build dependencies are managed by vcpkg. apt supplies the compiler, platform
# headers, and display tools needed to exercise the desktop application.
FROM mirror.gcr.io/library/ubuntu:24.04 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive \
    VCPKG_ROOT=/opt/vcpkg \
    VCPKG_DISABLE_METRICS=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf autoconf-archive automake bison build-essential ca-certificates cmake curl flex git \
    imagemagick libgl1-mesa-dev libglu1-mesa-dev libltdl-dev libtool \
    libwayland-dev libx11-dev libxcursor-dev libxi-dev libxinerama-dev \
    libxrandr-dev mesa-utils ninja-build openbox pkg-config python3 \
    tar unzip wayland-protocols wmctrl xauth xdotool xvfb zip \
    && rm -rf /var/lib/apt/lists/*

# The manifest is the single source of truth for the registry checkout as well
# as dependency versions. A newer vcpkg executable is never silently substituted.
COPY vcpkg.json /tmp/imshark-vcpkg.json
RUN baseline=$(python3 -c 'import json; print(json.load(open("/tmp/imshark-vcpkg.json"))["builtin-baseline"])') \
    && git init "$VCPKG_ROOT" \
    && git -C "$VCPKG_ROOT" remote add origin https://github.com/microsoft/vcpkg.git \
    && git -C "$VCPKG_ROOT" fetch --depth 1 origin "$baseline" \
    && git -C "$VCPKG_ROOT" checkout --detach FETCH_HEAD \
    && "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics

FROM toolchain AS build
WORKDIR /workspace
ARG BUILD_JOBS=2

# Keep dependency compilation cached while application sources change.
COPY vcpkg.json vcpkg-configuration.json ./
COPY vcpkg-ports/ ./vcpkg-ports/
RUN --mount=type=cache,target=/root/.cache/vcpkg/archives \
    --mount=type=cache,target=/opt/vcpkg/downloads \
    "$VCPKG_ROOT/vcpkg" install --x-install-root=/workspace/vcpkg_installed \
    --x-buildtrees-root=/tmp/vcpkg-buildtrees --x-packages-root=/tmp/vcpkg-packages \
    && rm -rf /tmp/vcpkg-buildtrees /tmp/vcpkg-packages

COPY CMakeLists.txt CMakePresets.json LICENSE ./
COPY cmake/ ./cmake/
COPY core/ ./core/
COPY src/ ./src/
COPY tests/ ./tests/
COPY tools/ ./tools/
RUN cmake --preset default -DVCPKG_INSTALLED_DIR=/workspace/vcpkg_installed \
    && cmake --build --preset default --parallel "$BUILD_JOBS"
COPY docs/ ./docs/
RUN ctest --preset default --parallel 1 --output-on-failure
RUN cmake --install build --prefix /opt/imshark \
    && /opt/imshark/bin/imshark --version \
    && cd build && cpack -G TGZ && cpack -G DEB

# Validate the DEB in a fresh OS with no compiler, vcpkg checkout or build tree.
FROM mirror.gcr.io/library/ubuntu:24.04 AS package-verify
ENV DEBIAN_FRONTEND=noninteractive LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe
COPY --from=build /workspace/build/*.deb /tmp/
RUN apt-get update && apt-get install -y --no-install-recommends \
    /tmp/imshark-*.deb imagemagick mesa-utils openbox wmctrl xauth xdotool xvfb \
    && rm -rf /var/lib/apt/lists/* /tmp/*.deb \
    && imshark --version
WORKDIR /workspace
COPY tools/linux_smoke.sh ./tools/
COPY tests/data/sample.pcap ./tests/data/sample.pcap
CMD ["bash", "tools/linux_smoke.sh", "/usr/bin"]

# docker run --rm --network none imshark-linux-verify
# Optional: mount an output directory at /artifacts and set SMOKE_ARTIFACT_DIR.
FROM build AS verify
ENV LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe
CMD ["bash", "tools/verify_linux.sh"]
