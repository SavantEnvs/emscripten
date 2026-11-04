# emmalloc_trim assumes it owns the end of the sbrk heap

`system/lib/emmalloc.c:1254`, `trim_dynamic_heap_reservation()`: `assert(sbrkAddr == previousSbrkEndAddress)`. If anything else
called `sbrk()` since emmalloc last grew (the harness does `_sbrk64(32)`), the assertion fires; with `NDEBUG` the trim goes on to
shrink the heap over memory emmalloc does not own.

Reproduce: `/mayhem/fuzz_emmalloc-standalone repro.bin` (foreign `_sbrk64(32)`, then `trim`) -> `Assertion 'sbrkAddr == previousSbrkEndAddress' failed`.
Impact: abort (or foreign-memory corruption in release builds) for a program that mixes emmalloc with another sbrk user.
Not in `testsuite/`: seeds must not crash.
