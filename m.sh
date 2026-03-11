#!/bin/sh
# m.sh: in-tree build script for convenience
cd "$(dirname "$0")"
set -ex

case "$1" in
"c")
    # clean artifacts
    rm -rf build compile_commands.json
    ;;
"x")
    # cross compiling, environment vars need to be set
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSROOT="${SYSROOT}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DCMAKE_SKIP_RPATH=ON \
        ..
    cmake --build . -t multiplexd
    ls -lh bin/multiplexd
    ;;
"posix")
    # rebuild for strict POSIX compliance
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DFORCE_POSIX=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -t multiplexd
    ls -lh bin/multiplexd
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build . -t multiplexd
    (cd bin && llvm-objdump -drwS multiplexd >multiplexd.S)
    ls -lh bin/multiplexd
    ;;
"min")
    # rebuild for minimized size
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build . -t multiplexd
    ls -lh bin/multiplexd
    ;;
"p")
    # rebuild for profiling
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DENABLE_THREADS=ON \
        ..
    cmake --build . -t multiplexd
    (cd bin && objdump -drwS multiplexd >multiplexd.S)
    ls -lh bin/multiplexd
    ;;
"r")
    # rebuild for release
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DENABLE_THREADS=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -t multiplexd
    ls -lh bin/multiplexd
    ;;
"d")
    # rebuild for debug
    if command -v clang-format >/dev/null; then
        find src -type f -regex '.*\.[hc]' -exec clang-format -i {} +
    fi
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        -DENABLE_THREADS=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    ;;
*)
    # default: incremental build
    mkdir -p build
    cd build
    if [ ! -f Makefile ]; then
        cmake ..
    fi
    cmake --build .
    ls -lh bin/multiplexd
    ;;
esac
