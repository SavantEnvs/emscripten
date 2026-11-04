# 64-bit payload length 0xffffffffffffffff is not validated

Same frame parser: a 127-length frame with an all-ones 64-bit payload length (after the early return documented in
`../hasfullheader-overread`) makes `FullMessageSize` wrap, and the proxy indexes the buffer with the wrapped value ->
ASan heap-buffer-overflow.

Reproduce: `/mayhem/fuzz_websocket_frames-standalone repro.bin`.
Fix: reject payload lengths larger than the receive buffer before computing the full message size.
Not in `testsuite/`: seeds must not crash.
