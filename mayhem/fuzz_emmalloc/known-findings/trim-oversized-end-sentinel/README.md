# emmalloc_trim leaves an oversized end sentinel, the next heap growth corrupts the region list

`system/lib/emmalloc.c`, `trim_dynamic_heap_reservation()` (~l.1328-1339): when the trim discards the last free region and
fewer than `sizeof(Region)` bytes are left, the end-of-heap sentinel is written with a size that `emmalloc_validate_memory_regions()`
and the growth path (`l.489`, `l.1203`) assume cannot happen. The next `emmalloc_malloc()` that grows the heap then builds on it.

Reproduce: `/mayhem/fuzz_emmalloc-standalone repro.bin` (arena cap byte `0x91`, then `trim(0)`)
-> "emmalloc contract violated: emmalloc_validate_memory_regions() reports a corrupt heap".
Plain API sequence: `emmalloc_blank_slate_from_orbit(); emmalloc_trim(0); emmalloc_malloc(8); emmalloc_validate_memory_regions() == 1`.
Impact: heap metadata corruption after a trim, the call malloc-using programs make to give memory back.
Not in `testsuite/`: seeds must not crash.
