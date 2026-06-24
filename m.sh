#!/bin/sh
# m.sh: in-tree build script for convenience
cd "$(dirname "$0")"
set -ex

gen_schema() {
    # conf: parsed once at startup — optimize for binary size
    python3 scripts/gen_schema.py --prefix json_ --optimize size src/conf_schema.json
    # proto: parsed on every mux frame — optimize for speed
    python3 scripts/gen_schema.py --prefix json_ --optimize fast src/mux/proto_schema.json
}

case "$1" in
"gen")
    # generate code from schemas
    gen_schema
    ;;
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
"vanilla")
    # rebuild without tls
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DUSE_TLS_LIBRARY="none" \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
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
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
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
"msys2")
    # rebuild with MSYS 2
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        ..
    cmake --build . -t multiplexd
    HOST="$(cc -dumpmachine)"
    zip -9j "multiplexd-win32.${HOST}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "/usr/bin/msys-crypto-3.dll" \
        "/usr/bin/msys-ssl-3.dll" \
        "bin/multiplexd.exe"
    ls -lh "multiplexd-win32.${HOST}.zip"
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
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    (cd bin && objdump -drwS multiplexd >multiplexd.S)
    ls -lh bin/multiplexd
    ;;
"r")
    # rebuild for release
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DENABLE_THREADS=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    ls -lh bin/multiplexd
    ;;
"d")
    # rebuild for debug
    gen_schema
    if command -v clang-format >/dev/null; then
        find src -type f -regex '.*\.[hc]' -not -regex '.*\.gen\.[hc]' -exec clang-format -i {} +
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
