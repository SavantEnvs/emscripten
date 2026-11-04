// Force-included when emscripten's wasm-targeted C sources are compiled for the build host.
// It only supplies what the host toolchain lacks (wasm32's 8-byte max_align_t, EM_ASM/EM_JS hooks);
// no emscripten source file is edited.
#include <stddef.h>
typedef struct { long long a; double b; } emscripten_native_max_align_t;
#define max_align_t emscripten_native_max_align_t
#define EM_JS_DEPS(...)
#define MAIN_THREAD_ASYNC_EM_ASM(...) ((void)0)
#define EM_ASM(...) ((void)0)
void* emscripten_builtin_memalign(size_t alignment, size_t size);
void* emscripten_builtin_malloc(size_t size);
void emscripten_builtin_free(void* ptr);
