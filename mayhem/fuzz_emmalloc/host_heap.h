// A fake wasm linear memory for building system/lib/emmalloc.c on the host: an sbrk() arena that is
// zeroed, capped and rewound between fuzz inputs so every run starts from the same heap.
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
void host_heap_reset(size_t cap);

// emscripten's own entry points, supplied here because the host has no wasm runtime.
void* _sbrk64(int64_t numBytes);
size_t emscripten_get_heap_size(void);
size_t emscripten_get_heap_max(void);

// emmalloc API (system/lib/emmalloc.c; see system/include/emscripten/emmalloc.h).
void* emmalloc_malloc(size_t size);
void* emmalloc_memalign(size_t alignment, size_t size);
void* emmalloc_calloc(size_t num, size_t size);
void* emmalloc_realloc(void* ptr, size_t size);
void* emmalloc_realloc_try(void* ptr, size_t size);
void* emmalloc_realloc_uninitialized(void* ptr, size_t size);
void* emmalloc_aligned_realloc(void* ptr, size_t alignment, size_t size);
void* emmalloc_aligned_realloc_uninitialized(void* ptr, size_t alignment, size_t size);
int emmalloc_posix_memalign(void** memptr, size_t alignment, size_t size);
void emmalloc_free(void* ptr);
size_t emmalloc_usable_size(void* ptr);
int emmalloc_trim(size_t pad);
int emmalloc_validate_memory_regions(void);
void emmalloc_blank_slate_from_orbit(void);
size_t emmalloc_dynamic_heap_size(void);
size_t emmalloc_free_dynamic_memory(void);
size_t emmalloc_compute_free_dynamic_memory_fragmentation_map(size_t freeMemorySizeMap[32]);
size_t emmalloc_unclaimed_heap_memory(void);
#ifdef __cplusplus
}
#endif
