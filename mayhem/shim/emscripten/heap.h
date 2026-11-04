// Host stand-in for <emscripten/heap.h>: only what system/lib/emmalloc.c and emscripten_mmap.c use.
#pragma once
#include <stddef.h>
#define WASM_PAGE_SIZE 65536
size_t emscripten_get_heap_size(void);
size_t emscripten_get_heap_max(void);
