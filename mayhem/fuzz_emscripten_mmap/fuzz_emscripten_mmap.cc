// Fuzz harness for emscripten's mmap() layer: musl's mmap/munmap/msync front ends plus
// system/lib/libc/emscripten_mmap.c (__syscall_mmap2/munmap/msync), which keeps the mapping list and
// carves anonymous mappings out of the malloc heap (here emmalloc on a capped host arena).
// The input is a program of mmap/munmap/msync calls and heap allocations. The harness checks what
// the C API promises: anonymous memory is zeroed and writable, a partial munmap is refused and leaves
// the mapping intact, a double munmap fails, and the allocator's own heap check stays clean.
#include "host_heap.h"

#include <errno.h>
#include <sys/mman.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
extern uint8_t host_file_backing[];  // what fd 4 "maps" without copying (host_js.c)
void* __mmap(void* start, size_t len, int prot, int flags, int fd, off_t off);
int __munmap(void* start, size_t len);
int em_msync(void* start, size_t len, int flags);
}

namespace {

constexpr int kSlots = 12;

struct Map {
  uint8_t* addr;
  size_t len;
  bool anon;
};
Map maps[kSlots];
void* heap_blocks[kSlots];

struct Reader {
  const uint8_t* p;
  const uint8_t* end;
  bool done() const { return p >= end; }
  uint8_t u8() { return p < end ? *p++ : 0; }
  uint32_t u16() { uint32_t lo = u8(); return lo | (uint32_t)u8() << 8; }
};

[[noreturn]] void broken(const char* what) {
  fprintf(stderr, "mmap contract violated: %s\n", what);
  abort();
}

size_t pick_len(Reader& r) {
  uint8_t b = r.u8();
  switch (b >> 6) {
    case 0: return b & 0x3f;
    case 1: return (size_t)(b & 0x3f) * 4096 + r.u8();
    case 2: return (size_t)r.u16() * 16 + (b & 15);
    default: return (size_t)r.u16() << (b & 15);
  }
}

}  // namespace

namespace {

void check_heap() {
  if (emmalloc_validate_memory_regions() != 0) broken("emmalloc_validate_memory_regions() reports a corrupt heap");
}

bool view_live() {
  for (const Map& m : maps)
    if (m.addr == host_file_backing) return true;
  return false;
}

void touch(const Map& m) {
  if (m.len == 0) return;
  volatile uint8_t* p = m.addr;
  p[0] = 0xa5;
  p[m.len - 1] = 0xa5;
  p[m.len / 2] = 0xa5;
}

void run(Reader& r) {
  host_heap_reset(((size_t)r.u8() + 1) * 65536);
  memset(maps, 0, sizeof maps);
  memset(heap_blocks, 0, sizeof heap_blocks);
  emmalloc_blank_slate_from_orbit();

  for (int step = 0; step < 200 && !r.done(); step++) {
    uint8_t op = r.u8() % 8;
    int i = r.u8() % kSlots;
    switch (op) {
      case 0: case 1: case 2: {  // anonymous mapping
        size_t len = pick_len(r);
        int flags = (r.u8() & 1 ? MAP_PRIVATE : MAP_SHARED) | MAP_ANONYMOUS;
        // mmap(len 0) must fail with EINVAL (POSIX); emscripten_mmap.c returns a mapping that munmap() then
        // refuses forever, a leak (known-findings/zero-length-mmap), so it is not generated.
        if (maps[i].addr || len == 0) break;
        void* p = __mmap(nullptr, len, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (p == MAP_FAILED) break;
        maps[i] = Map{(uint8_t*)p, len, true};
        for (size_t k = 0; k < len && k < 256; k++)
          if (maps[i].addr[k]) broken("anonymous mapping is not zero-filled");
        if (len && maps[i].addr[len - 1]) broken("anonymous mapping is not zero-filled");
        touch(maps[i]);
        break;
      }
      case 3: {  // file-backed mapping
        size_t len = pick_len(r);
        int fd = 3 + r.u8() % 4;
        off_t off = (off_t)r.u8() * 4096;
        if (!(r.u8() & 1)) off += r.u8() % 4096;
        int flags = r.u8() & 1 ? MAP_PRIVATE : MAP_SHARED;
        if (maps[i].addr || len == 0) break;
        // Two mappings of the same in-heap file share an address and munmap() then matches the wrong
        // one (known-findings/shared-address-mappings), so only one fd-4 mapping is kept alive.
        if (fd == 4 && view_live()) break;
        void* p = __mmap(nullptr, len, PROT_READ | PROT_WRITE, flags, fd, off);
        if (p == MAP_FAILED) break;
        maps[i] = Map{(uint8_t*)p, len, false};
        if (fd == 3) touch(maps[i]);
        break;
      }
      case 4: {  // munmap with the right length
        if (!maps[i].addr) break;
        if (__munmap(maps[i].addr, maps[i].len) != 0) broken("munmap of a live mapping failed");
        if (__munmap(maps[i].addr, maps[i].len) == 0) broken("second munmap of the same mapping succeeded");
        maps[i] = Map{};
        break;
      }
      case 5: {  // munmap with another length: must be refused, mapping must survive
        size_t other = pick_len(r);
        if (!maps[i].addr || other == maps[i].len) break;
        if (__munmap(maps[i].addr, other) == 0) broken("partial munmap succeeded");
        touch(maps[i]);
        break;
      }
      case 6: {
        size_t len = pick_len(r);
        int flags = (r.u8() & 1) ? MS_SYNC : MS_ASYNC;
        if (maps[i].addr) {
          if (em_msync(maps[i].addr, len, flags) != 0) broken("msync of a live mapping failed");
        } else {
          em_msync(maps[i].addr, len, flags);
        }
        break;
      }
      case 7: {  // other users of the same heap
        if (heap_blocks[i]) {
          emmalloc_free(heap_blocks[i]);
          heap_blocks[i] = nullptr;
        } else {
          heap_blocks[i] = emmalloc_malloc(pick_len(r));
        }
        break;
      }
    }
    check_heap();
    for (int a = 0; a < kSlots; a++) {
      if (!maps[a].addr) continue;
      for (int b = a + 1; b < kSlots; b++) {
        if (!maps[b].addr || !maps[a].anon || !maps[b].anon) continue;
        if (maps[a].addr < maps[b].addr + maps[b].len && maps[b].addr < maps[a].addr + maps[a].len) broken("two live anonymous mappings overlap");
      }
    }
  }
}

// emscripten_mmap.c keeps its mapping list in a static, so every mapping is unmapped before the heap is rewound.
void release_all() {
  for (int i = 0; i < kSlots; i++)
    if (maps[i].addr && __munmap(maps[i].addr, maps[i].len) != 0) broken("cleanup munmap failed");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4 || size > 4096) return -1;
  Reader r{data, data + size};
  run(r);
  release_all();
  return 0;
}
