#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harnesses and the known-answer test runner.
#
# Emscripten is a wasm toolchain whose own tests need emcc + LLVM + node, none of which exist in this
# air-gapped image. What compiles natively with clang is the C/C++ source shipped inside the repo that is
# emscripten's own: the emmalloc allocator (system/lib/emmalloc.c), the mmap layer
# (system/lib/libc/emscripten_mmap.c plus musl's mmap/munmap/msync front ends), and the host-side
# websocket_to_posix_proxy tool (frame parser and POSIX-socket message dispatcher). The wasm-targeted C is
# built for the host by compile-time substitution only (mayhem/shim, -D renames); no emscripten file is edited.
# Everything is built from tracked source; nothing is fetched.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/test"

# Benign UBSan patterns, relaxed per source file (never via an ignorelist):
#  * websocket proxy: uint32_t loads/stores through byte pointers (alignment) and `d[-1-i]` base64 padding (pointer-overflow);
#  * emmalloc.c: `__builtin_clzll(0)` at the free-bucket lookup is guarded by the caller and defined on wasm (builtin).
NO_WS_BENIGN="-fno-sanitize=alignment,pointer-overflow"
NO_ALIGN="-fno-sanitize=alignment"
NO_CLZ0="-fno-sanitize=builtin"

WS_DIR="$SRC/tools/websocket_to_posix_proxy/src"
WS_INC="-I$SRC -I$WS_DIR"

# Host stand-ins for wasm-only pieces (see mayhem/shim and mayhem/fuzz_emmalloc/host_heap.[ch]).
SHIM="-include mayhem/shim/emscripten_native.h -Imayhem/shim"
EMM_RENAME="-DEMMALLOC_NO_STD_EXPORTS -Dfree=emmalloc_free"
HEAP_INC="-Imayhem/fuzz_emmalloc"
MUSL="system/lib/libc/musl"
# emscripten_mmap.c and the musl mmap/munmap/msync it sits behind: musl's internal headers, the emscripten
# syscall numbers (mayhem/shim/mmap_native.h), and the allocator calls pointed at emmalloc.
MMAP_FLAGS="$SHIM -include mayhem/shim/mmap_native.h -D__EMSCRIPTEN__=1 -Dhidden= -I$MUSL/src/internal -idirafter $MUSL/arch/emscripten -idirafter $MUSL/arch/generic -Isystem/lib/libc -Isystem/include -Wno-macro-redefined -Demscripten_builtin_memalign=emmalloc_memalign -Demscripten_builtin_malloc=emmalloc_malloc -Demscripten_builtin_free=emmalloc_free"
# The proxy's libc socket calls, replaced at compile time by the stand-ins in the posix-socket harness.
SOCK_MOCKS="-Dsocket=mock_socket -Dsocketpair=mock_socketpair -Dshutdown=mock_shutdown -Dclose=mock_close -Dbind=mock_bind -Dconnect=mock_connect -Dlisten=mock_listen -Daccept=mock_accept -Dgetsockname=mock_getsockname -Dgetpeername=mock_getpeername -Dsend=mock_send -Drecv=mock_recv -Dsendto=mock_sendto -Drecvfrom=mock_recvfrom -Dgetsockopt=mock_getsockopt -Dsetsockopt=mock_setsockopt -Dgetaddrinfo=mock_getaddrinfo -Dfreeaddrinfo=mock_freeaddrinfo"

# compile_all <dir> <flags> : every project object, for the fuzz build (sanitized) or the test build (normal flags)
compile_all() {
  local d="$1" f="$2" cc="$3" cxx="$4"
  $cc  $f $SHIM $NO_CLZ0 $EMM_RENAME -c system/lib/emmalloc.c -o "$d/emmalloc.o"
  $cc  $f $HEAP_INC -c mayhem/fuzz_emmalloc/host_heap.c -o "$d/host_heap.o"
  $cc  $f $HEAP_INC -c mayhem/fuzz_emscripten_mmap/host_js.c -o "$d/host_js.o"
  $cc  $f $MMAP_FLAGS -c system/lib/libc/emscripten_mmap.c -o "$d/emscripten_mmap.o"
  $cc  $f $MMAP_FLAGS -Dmmap=em_mmap_alias -Demscripten_builtin_mmap=em_builtin_mmap_alias -c $MUSL/src/mman/mmap.c -o "$d/musl_mmap.o"
  $cc  $f $MMAP_FLAGS -Dmunmap=em_munmap_alias -Demscripten_builtin_munmap=em_builtin_munmap_alias -c $MUSL/src/mman/munmap.c -o "$d/musl_munmap.o"
  $cc  $f $MMAP_FLAGS -Dmsync=em_msync -c $MUSL/src/mman/msync.c -o "$d/musl_msync.o"
  $cc  $f $MMAP_FLAGS -c $MUSL/src/internal/syscall_ret.c -o "$d/syscall_ret.o"
  $cxx $f $NO_ALIGN -c "$WS_DIR/sha1.cpp" -o "$d/sha1.o"
  $cxx $f -c "$WS_DIR/socket_registry.cpp" -o "$d/socket_registry.o"
  $cc  $f $NO_ALIGN -c "$WS_DIR/websocket_to_posix_proxy.c" -o "$d/websocket_to_posix_proxy.o"
}

# ---- 1) sanitized + coverage-instrumented project objects (fuzz build) -------------------------------------
FZ="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
compile_all "$B/fuzz" "$FZ" "$CC" "$CXX"
# the socket-mock variants of the proxy objects (only fuzz_posix_socket_proxy links these)
$CC  $FZ $NO_ALIGN $SOCK_MOCKS -I"$WS_DIR" -c "$WS_DIR/websocket_to_posix_proxy.c" -o "$B/fuzz/websocket_to_posix_proxy_mock.o"
$CXX $FZ $SOCK_MOCKS -I"$WS_DIR" -c "$WS_DIR/socket_registry.cpp" -o "$B/fuzz/socket_registry_mock.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -c mayhem/lsan_off.cc -o "$B/fuzz/lsan_off.o"
$CC  $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"

WS_OBJS="$B/fuzz/sha1.o $B/fuzz/socket_registry.o $B/fuzz/websocket_to_posix_proxy.o"
EMM_OBJS="$B/fuzz/emmalloc.o $B/fuzz/host_heap.o"
MMAP_OBJS="$B/fuzz/emscripten_mmap.o $B/fuzz/musl_mmap.o $B/fuzz/musl_munmap.o $B/fuzz/musl_msync.o $B/fuzz/syscall_ret.o $B/fuzz/host_js.o $EMM_OBJS"
SOCK_OBJS="$B/fuzz/websocket_to_posix_proxy_mock.o $B/fuzz/socket_registry_mock.o"

# link <name> <harness.cc> <extra cxx flags> <objects...>   (fuzzer + standalone reproducer)
link() {
  local name="$1" src="$2" flags="$3"; shift 3
  $CXX $FZ $flags "$src" "$@" "$B/fuzz/lsan_off.o" $LIB_FUZZING_ENGINE -pthread -o "$SRC/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $flags "$src" "$@" "$B/fuzz/lsan_off.o" "$B/fuzz/standalone_main.o" -pthread -o "$SRC/$name-standalone"
}

link fuzz_websocket_frames mayhem/fuzz_websocket_frames/fuzz_websocket_frames.cc "$WS_INC -Imayhem/fuzz_websocket_frames $NO_WS_BENIGN" $WS_OBJS
link fuzz_posix_socket_proxy mayhem/fuzz_posix_socket_proxy/fuzz_posix_socket_proxy.cc "" $SOCK_OBJS
link fuzz_emmalloc mayhem/fuzz_emmalloc/fuzz_emmalloc.cc "$HEAP_INC" $EMM_OBJS
link fuzz_emscripten_mmap mayhem/fuzz_emscripten_mmap/fuzz_emscripten_mmap.cc "$HEAP_INC" $MMAP_OBJS

# ---- 2) known-answer test runner: the same project sources with the project's NORMAL flags ------------------
TF="-O1 $COVERAGE_FLAGS"
compile_all "$B/test" "$TF" "$CC" "$CXX"
T="$B/test"
$CXX $TF $WS_INC $HEAP_INC -Imayhem/fuzz_websocket_frames mayhem/tests/known_answer.cc \
  "$T/sha1.o" "$T/socket_registry.o" "$T/websocket_to_posix_proxy.o" \
  "$T/emscripten_mmap.o" "$T/musl_mmap.o" "$T/musl_munmap.o" "$T/musl_msync.o" "$T/syscall_ret.o" "$T/host_js.o" \
  "$T/emmalloc.o" "$T/host_heap.o" -pthread -o "$B/known_answer"
