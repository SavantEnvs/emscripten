// Force-included (after emscripten_native.h) when musl's mmap/munmap/msync and emscripten_mmap.c are
// built for the host: points musl's SYS_* numbers at emscripten's __syscall_* entry points, as the
// wasm build does via arch/emscripten/bits/syscall.h.
#include <sys/syscall.h>
#undef SYS_mmap
#undef SYS_munmap
#undef SYS_msync
#undef SYS_mmap2
#define SYS_mmap2 __syscall_mmap2
#define SYS_munmap __syscall_munmap
#define SYS_msync __syscall_msync
#define weak_alias(old, new) extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))
