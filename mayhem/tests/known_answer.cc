// Known-answer tests for the emscripten sources that mayhem/build.sh fuzzes natively: the emmalloc allocator,
// the mmap layer (emscripten_mmap.c behind musl's mmap/munmap/msync) and the websocket_to_posix_proxy
// (handshake/framing code and the POSIX-socket message dispatcher).
// Built with the project's normal flags (no sanitizers) and run by mayhem/test.sh.
#define main websocket_proxy_main
#include "tools/websocket_to_posix_proxy/src/main.cpp"
#undef main

#include "ws_stream.h"
#include "host_heap.h"

#include <cerrno>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>

extern "C" {
void* __mmap(void* start, size_t len, int prot, int flags, int fd, off_t off);
int __munmap(void* start, size_t len);
int em_msync(void* start, size_t len, int flags);
}

static int gTotal = 0, gPassed = 0;
static void check(bool ok, const char* name) {
  gTotal++;
  if (ok) gPassed++;
  fprintf(stderr, "%s %s\n", ok ? "PASS" : "FAIL", name);
}


static void testEmmalloc() {
  host_heap_reset(4u << 20);
  emmalloc_blank_slate_from_orbit();
  check(emmalloc_validate_memory_regions() == 0, "emmalloc: fresh heap validates");

  void* a = emmalloc_malloc(100);
  check(a && ((uintptr_t)a & 7) == 0 && emmalloc_usable_size(a) >= 100, "emmalloc: malloc(100) is 8-aligned with >= 100 usable bytes");
  memset(a, 0xab, 100);
  void* m = emmalloc_memalign(256, 100);
  check(m && ((uintptr_t)m & 255) == 0, "emmalloc: memalign(256, 100) is 256-aligned");
  uint8_t* z = (uint8_t*)emmalloc_calloc(10, 10);
  bool zero = z != nullptr;
  for (int i = 0; z && i < 100; i++) zero = zero && z[i] == 0;
  check(zero, "emmalloc: calloc(10, 10) returns zeroed memory");

  uint8_t* r = (uint8_t*)emmalloc_realloc(a, 5000);
  bool kept = r != nullptr;
  for (int i = 0; r && i < 100; i++) kept = kept && r[i] == 0xab;
  check(kept && emmalloc_usable_size(r) >= 5000, "emmalloc: realloc grows and keeps the old 100 bytes");
  check(emmalloc_validate_memory_regions() == 0, "emmalloc: heap validates with live blocks");

  void* pm = nullptr;
  check(emmalloc_posix_memalign(&pm, 3, 16) == EINVAL, "emmalloc: posix_memalign with alignment 3 is EINVAL");
  check(emmalloc_posix_memalign(&pm, 64, 16) == 0 && pm && ((uintptr_t)pm & 63) == 0, "emmalloc: posix_memalign(64) succeeds, aligned");
  emmalloc_free(pm);
  emmalloc_free(r);
  emmalloc_free(m);
  emmalloc_free(z);
  check(emmalloc_validate_memory_regions() == 0, "emmalloc: heap validates after freeing everything");

  // Coalescing: three adjacent blocks freed (middle first) must merge into one region big enough for their sum,
  // so allocating that sum again must not grow the heap.
  emmalloc_blank_slate_from_orbit();
  void* x = emmalloc_malloc(1000);
  void* y = emmalloc_malloc(1000);
  void* w = emmalloc_malloc(1000);
  void* guard = emmalloc_malloc(64);
  size_t grown = emmalloc_dynamic_heap_size();
  emmalloc_free(y);
  emmalloc_free(x);
  emmalloc_free(w);
  void* big = emmalloc_malloc(2900);
  check(big != nullptr && big == x && emmalloc_dynamic_heap_size() == grown, "emmalloc: freed neighbours coalesce, reused without growing the heap");
  emmalloc_free(big);
  emmalloc_free(guard);

  host_heap_reset(64u << 10);
  emmalloc_blank_slate_from_orbit();
  check(emmalloc_malloc((size_t)1 << 20) == nullptr, "emmalloc: request beyond the arena fails with NULL");
  check(emmalloc_validate_memory_regions() == 0, "emmalloc: heap validates after a failed allocation");
}

static void testMmap() {
  host_heap_reset(8u << 20);
  emmalloc_blank_slate_from_orbit();

  uint8_t* p = (uint8_t*)__mmap(nullptr, 100, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(p != (uint8_t*)MAP_FAILED && ((uintptr_t)p & 65535) == 0, "mmap: anonymous mapping is 64 KiB-aligned");
  bool zero = p != (uint8_t*)MAP_FAILED;
  for (int i = 0; zero && i < 100; i++) zero = p[i] == 0;
  check(zero, "mmap: anonymous memory is zero-filled");
  if (p != (uint8_t*)MAP_FAILED) memset(p, 0x7e, 100);
  check(p != (uint8_t*)MAP_FAILED && __munmap(p, 50) == -1 && errno == EINVAL, "munmap: a partial unmap is refused with EINVAL");
  check(p != (uint8_t*)MAP_FAILED && p[99] == 0x7e, "munmap: refused partial unmap leaves the mapping intact");
  check(__munmap(p, 100) == 0, "munmap: exact unmap succeeds");
  check(__munmap(p, 100) == -1, "munmap: second unmap of the same range fails");

  uint8_t* f = (uint8_t*)__mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, 3, 0);
  check(f != (uint8_t*)MAP_FAILED && f[0] == 0x5a && f[4095] == 0x5a, "mmap: file-backed mapping carries the file contents");
  check(f != (uint8_t*)MAP_FAILED && __munmap(f, 4096) == 0, "munmap: file-backed mapping unmaps");

  errno = 0;
  check(__mmap(nullptr, 100, PROT_READ, MAP_PRIVATE, 99, 0) == MAP_FAILED && errno == EBADF, "mmap: bad file descriptor gives EBADF");
  errno = 0;
  check(__mmap(nullptr, 100, PROT_READ, MAP_PRIVATE, 3, 1) == MAP_FAILED && errno == EINVAL, "mmap: unaligned file offset gives EINVAL");
  errno = 0;
  check(__mmap(nullptr, (size_t)-1 >> 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == ENOMEM, "mmap: length >= PTRDIFF_MAX gives ENOMEM");

  void* q = __mmap(nullptr, 64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(q != MAP_FAILED && em_msync(q, 64, MS_SYNC) == 0, "msync: anonymous mapping syncs");
  if (q != MAP_FAILED) __munmap(q, 64);
  check(emmalloc_validate_memory_regions() == 0, "mmap: allocator heap validates after the mapping calls");
}

// Run one proxy request on the host's real sockets and return the reply frame's payload.
static std::vector<uint8_t> call(int clientFd, int peerFd, std::vector<int> words, const std::vector<uint8_t>& tail = {}) {
  std::vector<uint8_t> msg(words.size() * 4 + tail.size());
  memcpy(msg.data(), words.data(), words.size() * 4);
  if (!tail.empty()) memcpy(msg.data() + words.size() * 4, tail.data(), tail.size());
  uint8_t* heap = (uint8_t*)malloc(msg.size());
  memcpy(heap, msg.data(), msg.size());
  ProcessWebSocketMessage(clientFd, heap, msg.size());
  free(heap);
  uint8_t frame[512];
  ssize_t n = recv(peerFd, frame, sizeof frame, MSG_DONTWAIT);
  if (n < 2 || (frame[0] & 0x0f) != 2 || frame[1] >= 126 || (size_t)n < 2u + frame[1]) return {};
  return std::vector<uint8_t>(frame + 2, frame + 2 + frame[1]);
}

static int word(const std::vector<uint8_t>& r, int i) {
  int v = 0;
  if (r.size() >= (size_t)(i + 1) * 4) memcpy(&v, r.data() + i * 4, 4);
  return v;
}

static void testProxyDispatcher() {
  InitWebSocketRegistry();
  int sv[2];
  check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "proxy: client socketpair");

  auto sock = call(sv[0], sv[1], {11, 1, 2, 1, 0});  // socket(AF_INET, SOCK_STREAM, 0) in musl numbering
  int fd = word(sock, 1);
  check(sock.size() == 12 && word(sock, 0) == 11 && fd >= 0 && word(sock, 2) == 0, "proxy: SOCKET returns the call id, a descriptor and errno 0");

  auto set = call(sv[0], sv[1], {12, 17, fd, 1, 2, 4}, {1, 0, 0, 0});  // setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
  check(set.size() == 12 && word(set, 0) == 12 && word(set, 1) == 0, "proxy: SETSOCKOPT SO_REUSEADDR succeeds");
  auto get = call(sv[0], sv[1], {13, 16, fd, 1, 2, 4});  // getsockopt(SOL_SOCKET, SO_REUSEADDR)
  check(get.size() == 20 && word(get, 1) == 0 && word(get, 3) == 4 && word(get, 4) != 0, "proxy: GETSOCKOPT reads back SO_REUSEADDR set");

  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = 0;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  std::vector<uint8_t> addr((uint8_t*)&sa, (uint8_t*)&sa + sizeof sa);
  auto bind = call(sv[0], sv[1], {14, 4, fd, (int)sizeof sa}, addr);
  check(bind.size() == 12 && word(bind, 0) == 14 && word(bind, 1) == 0, "proxy: BIND to 127.0.0.1:0 succeeds");
  auto name = call(sv[0], sv[1], {15, 8, fd, 128});
  sockaddr_in got{};
  if (name.size() >= 16 + sizeof got) memcpy(&got, name.data() + 16, sizeof got);
  check(name.size() == 32 && word(name, 1) == 0 && word(name, 3) == 16 && got.sin_family == AF_INET && got.sin_port != 0 &&
            got.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
        "proxy: GETSOCKNAME reports the AF_INET loopback address with the port the kernel assigned");

  auto lis = call(sv[0], sv[1], {16, 6, fd, 1});
  check(lis.size() == 12 && word(lis, 0) == 16 && word(lis, 1) == 0, "proxy: LISTEN succeeds on the bound socket");
  auto foreign = call(sv[0], sv[1], {17, 8, 9999, 128});
  check(foreign.size() >= 12 && word(foreign, 0) == 17 && word(foreign, 1) == -1, "proxy: a descriptor this connection did not create is refused");

  CloseAllSocketsByConnection(sv[0]);
  check(!IsSocketPartOfConnection(sv[0], fd), "proxy: closing the connection releases its sockets");
  close(sv[0]);
  close(sv[1]);
}

static void testWebsocket() {
  // SHA-1 known answer (FIPS 180 "abc") through the proxy's own SHA1 helper.
  char digest[21];
  SHA1(digest, (char*)"abc", 3);
  static const unsigned char expect[20] = {0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d};
  check(memcmp(digest, expect, 20) == 0, "sha1(abc)");

  // RFC 6455 section 1.3 handshake example, over a socketpair.
  int sv[2];
  check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
  SendHandshake(sv[0], "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
  char resp[512] = {0};
  recv(sv[1], resp, sizeof resp - 1, 0);
  check(strstr(resp, "HTTP/1.1 101 Switching Protocols") != nullptr, "handshake: 101 status line");
  check(strstr(resp, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != nullptr, "handshake: RFC 6455 accept key");

  // RFC 6455 section 5.7: a single-frame masked text message containing "Hello".
  uint8_t hello[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
  check(WebSocketHasFullHeader(hello, sizeof hello), "frame: full header");
  check(WebSocketFullMessageSize(hello, sizeof hello) == sizeof hello, "frame: full size 11");
  check(WebSocketMessagePayloadLength(hello, sizeof hello) == 5, "frame: payload length 5");
  check(WebSocketMessageMaskingKey(hello, sizeof hello) == 0x3d21fa37u, "frame: masking key");
  uint8_t* payload = WebSocketMessageData(hello, sizeof hello);
  WebSocketMessageUnmaskPayload(payload, 5, WebSocketMessageMaskingKey(hello, sizeof hello));
  check(memcmp(payload, "Hello", 5) == 0, "frame: unmasked payload is Hello");

  // 16-bit extended length: 300-byte unmasked binary frame.
  std::vector<uint8_t> big = {0x82, 126, 0x01, 0x2c};
  for (int i = 0; i < 300; i++) big.push_back((uint8_t)(i * 7));
  check(WebSocketFullMessageSize(big.data(), big.size()) == 304, "frame: 16-bit length size 304");
  check(WebSocketMessagePayloadLength(big.data(), big.size()) == 300, "frame: 16-bit payload length");
  check(WebSocketMessageData(big.data(), big.size()) == big.data() + 4, "frame: 16-bit payload offset");
  check(ntoh64(0x0102030405060708ull) == 0x0807060504030201ull, "ntoh64 byte swap");

  // Stream of two binary frames (one masked), delivered whole and in 5-byte chunks.
  std::vector<uint8_t> stream = {0x82, 0x03, 'a', 'b', 'c'};
  uint8_t key[4] = {1, 2, 3, 4};
  const char* msg = "xyzzy";
  stream.insert(stream.end(), {0x82, 0x85, key[0], key[1], key[2], key[3]});
  for (int i = 0; i < 5; i++) stream.push_back((uint8_t)msg[i] ^ key[i % 4]);
  for (size_t chunk : {stream.size(), (size_t)5}) {
    std::vector<std::string> got;
    FeedStream(stream.data(), stream.size(), chunk,
               [&](unsigned, uint8_t* p, uint64_t len) { got.emplace_back((const char*)p, (size_t)len); });
    check(got.size() == 2 && got[0] == "abc" && got[1] == "xyzzy", chunk == 5 ? "stream: chunked delivery" : "stream: whole delivery");
  }
  std::vector<uint8_t> closing = {0x88, 0x00, 0x82, 0x01, 'z'};
  int delivered = 0;
  FeedStream(closing.data(), closing.size(), 2, [&](unsigned, uint8_t*, uint64_t) { delivered++; });
  check(delivered == 0, "stream: close frame stops later chunks being read");
}

int main() {
  testEmmalloc();
  testMmap();
  testWebsocket();
  testProxyDispatcher();
  printf("KNOWN_ANSWER total=%d passed=%d failed=%d\n", gTotal, gPassed, gTotal - gPassed);
  return gPassed == gTotal ? 0 : 1;
}
