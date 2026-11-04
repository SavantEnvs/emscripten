# Client-supplied output lengths are used as copy and allocation sizes without clamping to the proxy's buffers

`tools/websocket_to_posix_proxy/src/websocket_to_posix_proxy.c`: `Getsockname()`, `Getpeername()`, `Recvfrom()` and `Getsockopt()` take
`address_len` / `option_len` straight from the request and use them as the input size for the kernel call and as the length of the reply
copy (`actualAddressLen = MIN(addressLen, d->address_len)`, `memcpy(r->address, address, actualAddressLen)`), although the local buffers are
`address[MAX_SOCKADDR_SIZE]` (256 bytes) and `option_value[MAX_OPTIONVALUE_SIZE]` (16 bytes). When the kernel call fails (it leaves the length
alone) or reports a larger real length, the reply copies up to 4 GiB out of those stack buffers, and `Recv()`/`Recvfrom()` `malloc(d->length)`
with a client-chosen 32-bit size. `Accept()` clamps (`MIN(d->address_len, MAX_SOCKADDR_SIZE)`); the others do not.

`Recvfrom()` also never frees its `malloc(d->length)` receive buffer (a leak that grows with the client-chosen length; `Recv()` frees it).
`Getaddrinfo()` likewise hands the request's `node[2048]` and `service[128]` to `getaddrinfo()` without checking that they are NUL-terminated.

Reproduce: `PROXY_RAW_MESSAGES=1 /mayhem/fuzz_posix_socket_proxy-standalone repro.bin` (SOCKET, then GETPEERNAME with `address_len = 0x20000`, the mock
kernel's getpeername failing with ENOTCONN) -> ASan stack-buffer-overflow read in `Getpeername()`.
The fuzz target clamps these fields to the proxy's buffer sizes and NUL-terminates the getaddrinfo strings (the env var turns that off), so this one bug does not re-trigger through every handler.
Impact: a remote websocket client can make the proxy leak stack memory back over the websocket, crash it, or force a huge allocation.
Not in `testsuite/`: seeds must not crash.
