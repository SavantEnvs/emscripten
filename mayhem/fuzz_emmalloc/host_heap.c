#include "host_heap.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define ARENA_SIZE (16u << 20)

static uint8_t arena[ARENA_SIZE] __attribute__((aligned(16)));
static size_t brk_off, high_water, cap = ARENA_SIZE;

void host_heap_reset(size_t new_cap) {
  memset(arena, 0, high_water);
  brk_off = high_water = 0;
  cap = new_cap > ARENA_SIZE ? ARENA_SIZE : new_cap;
}

void* _sbrk64(int64_t numBytes) {
  uint8_t* old = arena + brk_off;
  if (numBytes < 0) {
    if ((uint64_t)-numBytes > brk_off) {
      errno = ENOMEM;
      return (void*)-1;
    }
    brk_off -= (size_t)-numBytes;
  } else {
    if ((uint64_t)numBytes > cap - brk_off) {
      errno = ENOMEM;
      return (void*)-1;
    }
    brk_off += (size_t)numBytes;
    if (brk_off > high_water) high_water = brk_off;
  }
  return old;
}

size_t emscripten_get_heap_size(void) { return cap; }
size_t emscripten_get_heap_max(void) { return cap; }
void emscripten_errf(const char* fmt, ...) { (void)fmt; }
