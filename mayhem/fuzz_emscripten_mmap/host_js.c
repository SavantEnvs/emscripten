// Host stand-ins for what emscripten_mmap.c gets from the JS runtime (src/lib/libsyscall.js: _mmap_js,
// _munmap_js, FS.mmap) and from musl (__lock/__unlock). A file-backed mapping is either a malloc'd copy of
// the file (allocated = 1; fd 3) or a view into memory that already exists (allocated = 0; fd 4).
// Anything else fails like a bad descriptor does.
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "host_heap.h"

#define HOST_FILE_BYTES (1u << 20)
uint8_t host_file_backing[HOST_FILE_BYTES];

void __lock(volatile int* l) { (void)l; }
void __unlock(volatile int* l) { (void)l; }

int _mmap_js(size_t length, int prot, int flags, int fd, off_t offset, int* allocated, void** addr) {
  (void)prot; (void)flags; (void)offset;
  switch (fd) {
    case 3: {
      if (length == 0) return -EINVAL;
      void* p = emmalloc_memalign(65536, length);
      if (!p) return -ENOMEM;
      memset(p, 0x5a, length < 4096 ? length : 4096);
      *allocated = 1;
      *addr = p;
      return 0;
    }
    case 4:
      if (length == 0) return -EINVAL;
      if (length > HOST_FILE_BYTES) return -ENOMEM;
      *allocated = 0;
      *addr = host_file_backing;
      return 0;
    case 5: return -ENODEV;
    default: return -EBADF;
  }
}
int _munmap_js(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  (void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset;
  return 0;
}
int _msync_js(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  (void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset;
  return 0;
}
