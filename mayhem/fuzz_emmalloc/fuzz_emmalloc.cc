// Fuzz harness for system/lib/emmalloc.c, emscripten's small sbrk()-based malloc.
// The input is a program of allocator calls (malloc, memalign, calloc, the realloc family,
// posix_memalign, free, trim, stats, a foreign sbrk()). After every call the harness checks what
// the C API promises (alignment, usable size, no overlap, contents preserved by realloc, calloc
// zeroing) and runs emmalloc's own heap checker, emmalloc_validate_memory_regions().
#include "host_heap.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

constexpr int kSlots = 24;
constexpr size_t kCheckBytes = 512;

struct Slot {
  uint8_t* ptr;
  size_t size;      // bytes the program asked for
  size_t align;     // alignment it asked for
  uint8_t pattern;  // byte the payload was filled with
};

Slot slots[kSlots];

struct Reader {
  const uint8_t* p;
  const uint8_t* end;
  bool done() const { return p >= end; }
  uint8_t u8() { return p < end ? *p++ : 0; }
  uint32_t u16() { uint32_t lo = u8(); return lo | (uint32_t)u8() << 8; }
};

[[noreturn]] void broken(const char* what) {
  fprintf(stderr, "emmalloc contract violated: %s\n", what);
  abort();
}

// Small sizes most of the time, with a tail of large ones so buckets, sbrk growth and OOM are all reached.
size_t pick_size(Reader& r) {
  uint8_t b = r.u8();
  switch (b >> 6) {
    case 0: return b & 0x3f;
    case 1: return (size_t)(b & 0x3f) * 16 + r.u8();
    case 2: return (size_t)r.u16() * 4 + (b & 3);
    default: return (size_t)r.u16() << (b & 15);
  }
}

size_t pick_align(Reader& r) { return (size_t)1 << (r.u8() % 14); }

void fill(Slot& s, uint8_t pattern) {
  s.pattern = pattern;
  size_t n = s.size < kCheckBytes ? s.size : kCheckBytes;
  memset(s.ptr, pattern, n);
  if (s.size > kCheckBytes) memset(s.ptr + s.size - kCheckBytes, pattern, kCheckBytes);
}

// Checks the bytes fill() wrote (head and tail of a `written`-byte payload) that lie below `keep`.
bool intact(const uint8_t* ptr, size_t written, size_t keep, uint8_t pattern) {
  size_t head = written < kCheckBytes ? written : kCheckBytes;
  if (head > keep) head = keep;
  for (size_t i = 0; i < head; i++)
    if (ptr[i] != pattern) return false;
  if (written > kCheckBytes) {
    size_t end = keep < written ? keep : written;
    for (size_t i = written - kCheckBytes; i < end; i++)
      if (ptr[i] != pattern) return false;
  }
  return true;
}

void check_heap() {
  if (emmalloc_validate_memory_regions() != 0) broken("emmalloc_validate_memory_regions() reports a corrupt heap");
  for (int i = 0; i < kSlots; i++) {
    const Slot& a = slots[i];
    if (!a.ptr) continue;
    size_t usable = emmalloc_usable_size(a.ptr);
    if (usable < a.size) broken("usable size smaller than the requested size");
    if (((uintptr_t)a.ptr & (a.align - 1)) != 0) broken("pointer is not aligned as requested");
    if (!intact(a.ptr, a.size, a.size, a.pattern)) broken("payload bytes changed behind the owner's back");
    for (int j = i + 1; j < kSlots; j++) {
      const Slot& b = slots[j];
      if (!b.ptr) continue;
      if (a.ptr < b.ptr + emmalloc_usable_size(b.ptr) && b.ptr < a.ptr + usable) broken("two live allocations overlap");
    }
  }
}

// Record a successful allocation in slot `i`, releasing whatever the slot held before.
void install(int i, void* p, size_t size, size_t align, uint8_t pattern, bool zeroed) {
  if (slots[i].ptr) emmalloc_free(slots[i].ptr);
  slots[i] = Slot{(uint8_t*)p, size, align, pattern};
  if (!p) {
    slots[i] = Slot{};
    return;
  }
  if (zeroed)
    for (size_t k = 0; k < size && k < kCheckBytes; k++)
      if (slots[i].ptr[k]) broken("calloc returned non-zero memory");
  fill(slots[i], pattern);
}

void run(Reader& r) {
  host_heap_reset(((size_t)r.u8() + 1) * 65536);
  memset(slots, 0, sizeof slots);
  emmalloc_blank_slate_from_orbit();
  check_heap();

  for (int step = 0; step < 400 && !r.done(); step++) {
    uint8_t op = r.u8() % 16;
    int i = r.u8() % kSlots;
    Slot& s = slots[i];
    uint8_t pattern = (uint8_t)(0x30 + step);
    switch (op) {
      case 0: case 1: {
        size_t n = pick_size(r);
        install(i, emmalloc_malloc(n), n, 8, pattern, false);
        break;
      }
      case 2: case 3: {
        size_t a = pick_align(r), n = pick_size(r);
        install(i, emmalloc_memalign(a, n), n, a, pattern, false);
        break;
      }
      case 4: {
        size_t num = (size_t)r.u8() * 4, sz = r.u8() & 63;
        install(i, emmalloc_calloc(num, sz), num * sz, 8, pattern, true);
        break;
      }
      case 5: case 6: {  // realloc keeps min(old, new) bytes
        size_t n = pick_size(r);
        if (!s.ptr) break;
        uint8_t old = s.pattern;
        size_t keep = s.size < n ? s.size : n;
        uint8_t* p = (uint8_t*)emmalloc_realloc(s.ptr, n);
        if (n == 0) { s = Slot{}; break; }
        if (!p) break;
        Slot moved{p, n, 8, old};
        if (!intact(p, s.size, keep, old)) broken("realloc lost the old contents");
        s = moved;
        fill(s, pattern);
        break;
      }
      case 7: {  // aligned_realloc keeps the pointer's own alignment
        size_t n = pick_size(r);
        if (!s.ptr) break;
        uint8_t old = s.pattern;
        size_t keep = s.size < n ? s.size : n, a = s.align;
        uint8_t* p = (uint8_t*)emmalloc_aligned_realloc(s.ptr, a, n);
        if (n == 0) { s = Slot{}; break; }
        if (!p) break;
        Slot moved{p, n, a, old};
        if (!intact(p, s.size, keep, old)) broken("aligned_realloc lost the old contents");
        s = moved;
        fill(s, pattern);
        break;
      }
      case 8: {  // realloc_try: either resizes in place or leaves the block untouched
        size_t n = pick_size(r);
        if (!s.ptr) break;
        uint8_t old = s.pattern;
        size_t keep = s.size < n ? s.size : n;
        uint8_t* p = (uint8_t*)emmalloc_realloc_try(s.ptr, n);
        if (n == 0) { s = Slot{}; break; }
        if (!p) break;
        if (p != s.ptr) broken("realloc_try moved the block");
        Slot resized{p, n, s.align, old};
        if (!intact(p, s.size, keep, old)) broken("realloc_try lost the old contents");
        s = resized;
        fill(s, pattern);
        break;
      }
      case 9: case 10: {  // the two "contents undefined" variants
        size_t n = pick_size(r);
        if (!s.ptr) break;
        size_t a = s.align;
        uint8_t* p = (op == 9) ? (uint8_t*)emmalloc_realloc_uninitialized(s.ptr, n)
                               : (uint8_t*)emmalloc_aligned_realloc_uninitialized(s.ptr, a, n);
        if (op == 9) a = 8;
        if (n == 0) { s = Slot{}; break; }
        if (!p) { s = Slot{}; break; }  // may have freed the old block before failing
        s = Slot{p, n, a, 0};
        fill(s, pattern);
        break;
      }
      case 11: {
        if (s.ptr) {
          emmalloc_free(s.ptr);
          s = Slot{};
        }
        break;
      }
      case 12: {
        size_t a = (size_t)8 << (r.u8() % 8), n = pick_size(r);
        void* p = nullptr;
        int rc = emmalloc_posix_memalign(&p, a, n);
        if (rc == 0) install(i, p, n, a, pattern, false);
        break;
      }
      case 13: emmalloc_trim((size_t)r.u16()); break;
      case 14: {
        size_t map[32];
        if (s.ptr) {
          size_t u = emmalloc_usable_size(s.ptr);
          if (u < s.size) broken("usable size smaller than the requested size");
        }
        emmalloc_compute_free_dynamic_memory_fragmentation_map(map);
        volatile size_t sink = emmalloc_dynamic_heap_size() + emmalloc_free_dynamic_memory() + emmalloc_unclaimed_heap_memory();
        (void)sink;
        break;
      }
      case 15: {  // another sbrk() user, so emmalloc has to cope with a discontiguous heap
        _sbrk64((int64_t)(r.u16() & ~15u));
        break;
      }
    }
    check_heap();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4 || size > 4096) return -1;
  Reader r{data, data + size};
  run(r);
  return 0;
}
