# WebSocketHasFullHeader returns early on payloadLength 126

`tools/websocket_to_posix_proxy/src/main.cpp`, `WebSocketHasFullHeader`: `case 126` / `case 127` use
`return expectedNumBytes += N`, which returns a truthy value without comparing against `numBytesInBuffer`.
`WebSocketFullMessageSize` / `PayloadLength` then read past the received bytes.

Reproduce: `/mayhem/fuzz_websocket_frames-standalone repro.bin` (the first byte is the chunk size; the frame is `$~`,
a 2-byte header announcing a 16-bit length) -> ASan heap-buffer-overflow read.
Impact: a remote websocket client can make the proxy read beyond its receive buffer.
Fix: `return numBytesInBuffer >= expectedNumBytes + N;`.
Not in `testsuite/`: seeds must not crash.
