# POSIX-socket dispatcher reads fixed-size request fields without checking the message length

`tools/websocket_to_posix_proxy/src/websocket_to_posix_proxy.c`, `ProcessWebSocketMessage()` only checks
`numBytes >= sizeof(SocketCallHeader)` (8 bytes). `Socket()`, `Bind()`, `Getsockname()`, `Setsockopt()` and the other handlers then read
their `MSG` fields (`domain`, `type`, `address_len`, ...) beyond the end of the received websocket payload.

Reproduce: `PROXY_RAW_MESSAGES=1 /mayhem/fuzz_posix_socket_proxy-standalone repro.bin` (one 8-byte SOCKET request: call id 1, function 1, nothing else)
-> ASan heap-buffer-overflow read in `Socket()`.
Related, same cause: `Send()` computes `(int)numBytes - sizeof(MSG)` unsigned, `Sendto()` copies into a fixed 256-byte `dest_addr`.
The fuzz target zero-extends each message to its handler's request size (the env var turns that off), so this bug does not
re-trigger through every handler; the same applies to a `Bind` `address_len` or `Sendto` `length` that exceeds the message.
Impact: a remote websocket client can make the proxy read (and in `Send`/`Sendto` write or send) memory outside its message buffer.
Not in `testsuite/`: seeds must not crash.
