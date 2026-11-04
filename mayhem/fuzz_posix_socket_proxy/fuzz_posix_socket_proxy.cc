// Fuzz harness for the message dispatcher of tools/websocket_to_posix_proxy (websocket_to_posix_proxy.c):
// the code that turns the binary POSIX-socket messages a browser page sends over the WebSocket into
// socket(), bind(), connect(), send(), recv(), getsockopt(), getaddrinfo() ... calls and serialises the
// replies. The libc socket calls are replaced at compile time (-Dsocket=mock_socket, ...) by the host
// kernel stand-ins below, which behave like the kernel does (fd ownership, copy sizes, EINVAL for oversized
// addresses) but touch no real descriptor. Every message is delivered in an exactly sized heap block,
// as the receive loop in main.cpp does, so a handler that reads past the message end is caught.
//
// Input: three bytes of mock-kernel behaviour, then messages, each a 16-bit length and that many bytes.
// Each message is made well-formed first, so the handlers' common unchecked-length bugs (two known findings) are
// not re-found through every function: a message shorter than its request struct (plus the bytes a length field
// inside it declares) is zero-extended (known-findings/short-message-overread), and a client-supplied output
// length is clamped to the proxy's own buffer for it and the getaddrinfo strings are NUL-terminated
// (known-findings/unclamped-output-length). Set
// PROXY_RAW_MESSAGES=1 to deliver messages exactly as received and reproduce them.
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

extern "C" {
void InitWebSocketRegistry();
void CloseAllSocketsByConnection(int proxyConnection);
void ProcessWebSocketMessage(int client_fd, uint8_t* payload, uint64_t numBytes);
void ProcessWebSocketMessageSynchronouslyInCurrentThread(int client_fd, uint8_t* payload, uint64_t numBytes);
}

namespace {

constexpr int kClientFd = 7;     // the WebSocket connection itself
constexpr int kFirstSocket = 100;  // the mock kernel hands out descriptors from here
constexpr size_t kMaxIo = 4096;
constexpr socklen_t kSockaddrSize = 16;  // every mock endpoint is an AF_INET address
constexpr uint32_t kSockaddrMax = 128;     // the largest address the mock kernel accepts

bool well_formed = true;
int next_fd;
unsigned fail_bits, io_bits, calls;
uint8_t sink;

// Bytes of the fixed request struct of POSIX_SOCKET_MSG_<function> (websocket_to_posix_proxy.c), header included.
// `m` is the message zero-extended to at least 24 bytes, so the fields read here are the ones the handler will see.
size_t request_size(const uint8_t* m) {
  auto u32 = [&](size_t off) { uint32_t v; memcpy(&v, m + off, 4); return v; };
  int function = (int)u32(4);
  switch (function) {
    case 1: case 2: return 20;                       // socket, socketpair
    case 3: case 6: case 7: case 8: case 9: return 16;  // shutdown, listen, accept, getsockname, getpeername
    case 4: case 5: {                                // bind, connect: + address[address_len]
      uint32_t n = u32(12);
      return 16 + (n <= kSockaddrMax ? n : 0);
    }
    case 10: case 11: return 20;                     // send, recv
    case 12: {                                       // sendto: dest_addr[256] + message[length]
      uint32_t n = u32(12);
      return 280 + (n <= kMaxIo ? n : 0);
    }
    case 13: return 24;                              // recvfrom
    case 16: case 17: return 24;                     // getsockopt, setsockopt
    case 18: return 2204;                            // getaddrinfo: node[2048], service[128], hints
    default: return 8;
  }
}

// Clamp the client-supplied output sizes that Getsockname/Getpeername/Recvfrom/Getsockopt/Recv trust: address_len
// to the proxy's address[256], option_len to its option_value[16], a Recv length to 64 KiB; and NUL-terminate
// the Getaddrinfo strings. m holds the full request.
void clamp_output_lengths(uint8_t* m) {
  auto clamp = [&](size_t off, uint32_t cap) {
    uint32_t v;
    memcpy(&v, m + off, 4);
    if (v > cap) { v = cap; memcpy(m + off, &v, 4); }
  };
  int function;
  memcpy(&function, m + 4, 4);
  switch (function) {
    case 8: case 9: clamp(12, 256); break;
    case 11: clamp(12, 65536); break;
    case 13: clamp(12, 64); clamp(20, 256); break;  // Recvfrom() leaks its receive buffer: keep that small
    case 16: clamp(20, 16); break;
    case 18: m[8 + 2048 - 1] = 0; m[8 + 2048 + 128 - 1] = 0; break;  // node[], service[] are C strings
  }
}

bool fails() { return (fail_bits >> (calls++ & 15)) & 1; }
bool owned(int fd) { return fd >= kFirstSocket && fd < next_fd; }

// A kernel reads exactly `len` bytes the caller points it at.
void consume(const void* p, size_t len) {
  const volatile uint8_t* b = (const volatile uint8_t*)p;
  uint8_t acc = 0;
  for (size_t i = 0; i < len; i++) acc ^= b[i];
  sink ^= acc;
}

// copy_to_user() of a sockaddr: at most what the caller offered, then report the real size.
void put_sockaddr(void* addr, socklen_t* len) {
  if (!addr || !len) return;
  socklen_t n = *len < kSockaddrSize ? *len : kSockaddrSize;
  memset(addr, 0x41, n);
  *len = kSockaddrSize;
}

int bad_fd(int fd) {
  if (owned(fd)) return 0;
  errno = EBADF;
  return -1;
}

struct addrinfo* make_addrinfo(int count) {
  struct addrinfo* head = nullptr;
  for (int i = count - 1; i >= 0; i--) {
    struct addrinfo* ai = (struct addrinfo*)calloc(1, sizeof(struct addrinfo));
    ai->ai_family = AF_INET;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_addrlen = kSockaddrSize;
    ai->ai_addr = (struct sockaddr*)calloc(1, kSockaddrSize);
    ai->ai_addr->sa_family = AF_INET;
    ai->ai_next = head;
    if (i == 0 && (io_bits & 4)) ai->ai_canonname = strdup("example.invalid");
    head = ai;
  }
  return head;
}

}  // namespace

extern "C" {

void lock_websocket_send_lock() {}
void unlock_websocket_send_lock() {}

int mock_socket(int, int, int) {
  if (fails()) { errno = EMFILE; return -1; }
  return next_fd++;
}
int mock_socketpair(int, int, int, int sv[2]) {
  if (fails()) { errno = EMFILE; return -1; }
  sv[0] = next_fd++;
  sv[1] = next_fd++;
  return 0;
}
int mock_shutdown(int fd, int) {
  if (bad_fd(fd)) return -1;
  return fails() ? (errno = ENOTCONN, -1) : 0;
}
int mock_close(int fd) {
  if (!owned(fd)) { fprintf(stderr, "closed descriptor %d that the mock kernel never handed out\n", fd); abort(); }
  return 0;
}
int mock_bind(int fd, const struct sockaddr* addr, socklen_t len) {
  if (bad_fd(fd)) return -1;
  if (len > kSockaddrMax) { errno = EINVAL; return -1; }
  consume(addr, len);
  return fails() ? (errno = EADDRINUSE, -1) : 0;
}
int mock_connect(int fd, const struct sockaddr* addr, socklen_t len) {
  if (bad_fd(fd)) return -1;
  if (len > 128) { errno = EINVAL; return -1; }
  consume(addr, len);
  return fails() ? (errno = ECONNREFUSED, -1) : 0;
}
int mock_listen(int fd, int) {
  if (bad_fd(fd)) return -1;
  return fails() ? (errno = EOPNOTSUPP, -1) : 0;
}
int mock_accept(int fd, struct sockaddr* addr, socklen_t* len) {
  if (bad_fd(fd)) return -1;
  if (fails()) { errno = EAGAIN; return -1; }
  put_sockaddr(addr, len);
  return next_fd++;
}
int mock_getsockname(int fd, struct sockaddr* addr, socklen_t* len) {
  if (bad_fd(fd)) return -1;
  put_sockaddr(addr, len);
  return 0;
}
int mock_getpeername(int fd, struct sockaddr* addr, socklen_t* len) {
  if (bad_fd(fd)) return -1;
  if (fails()) { errno = ENOTCONN; return -1; }
  put_sockaddr(addr, len);
  return 0;
}
ssize_t mock_send(int fd, const void* buf, size_t len, int) {
  if (fd != kClientFd && bad_fd(fd)) return -1;
  consume(buf, len);
  if (fd != kClientFd && fails()) { errno = EPIPE; return -1; }
  return (ssize_t)len;
}
ssize_t mock_recv(int fd, void* buf, size_t len, int) {
  if (bad_fd(fd)) return -1;
  if (!buf) { errno = EFAULT; return -1; }
  size_t n = len < (io_bits & 3) * 100u ? len : (io_bits & 3) * 100u;
  if (n > kMaxIo) n = kMaxIo;
  memset(buf, 0x52, n);
  return (ssize_t)n;
}
ssize_t mock_sendto(int fd, const void* buf, size_t len, int, const struct sockaddr* addr, socklen_t alen) {
  if (bad_fd(fd)) return -1;
  if (alen > kSockaddrMax || len > kMaxIo) { errno = EINVAL; return -1; }
  consume(addr, alen);
  consume(buf, len);
  return (ssize_t)len;
}
ssize_t mock_recvfrom(int fd, void* buf, size_t len, int, struct sockaddr* addr, socklen_t* alen) {
  ssize_t n = mock_recv(fd, buf, len, 0);
  if (n >= 0) put_sockaddr(addr, alen);
  return n;
}
int mock_getsockopt(int fd, int, int, void* val, socklen_t* len) {
  if (bad_fd(fd)) return -1;
  if (!val || !len) { errno = EFAULT; return -1; }
  socklen_t n = *len < 4 ? *len : 4;
  memset(val, 0x01, n);
  *len = 4;
  return 0;
}
int mock_setsockopt(int fd, int, int, const void* val, socklen_t len) {
  if (bad_fd(fd)) return -1;
  if ((int)len < 0 || len > kMaxIo) { errno = EINVAL; return -1; }
  consume(val, len);
  return 0;
}
int mock_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
  if (node) consume(node, strlen(node));
  if (service) consume(service, strlen(service));
  if (hints) consume(hints, sizeof *hints);
  if (fails()) { *res = nullptr; return EAI_NONAME; }
  *res = make_addrinfo((io_bits >> 4) & 3);
  return 0;
}
void mock_freeaddrinfo(struct addrinfo* ai) {
  while (ai) {
    struct addrinfo* next = ai->ai_next;
    free(ai->ai_addr);
    free(ai->ai_canonname);
    free(ai);
    ai = next;
  }
}

int LLVMFuzzerInitialize(int*, char***) {
  well_formed = !getenv("PROXY_RAW_MESSAGES");
  InitWebSocketRegistry();
  freopen("/dev/null", "w", stdout);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4 || size > 8192) return -1;
  fail_bits = data[0] | (unsigned)data[1] << 8;
  io_bits = data[2];
  next_fd = kFirstSocket;
  calls = 0;
  const uint8_t* p = data + 3;
  const uint8_t* end = data + size;

  for (int msg = 0; msg < 24 && end - p >= 2; msg++) {
    size_t len = (size_t)p[0] | (size_t)p[1] << 8;
    p += 2;
    if (len > (size_t)(end - p)) len = (size_t)(end - p);
    uint8_t head[24] = {};
    memcpy(head, p, len < sizeof head ? len : sizeof head);
    size_t size_needed = well_formed && len >= 8 ? request_size(head) : len;
    size_t block = size_needed > len ? size_needed : len;
    uint8_t* payload = (uint8_t*)calloc(block ? block : 1, 1);
    memcpy(payload, p, len);
    p += len;
    len = block;
    if (well_formed && len >= 8) clamp_output_lengths(payload);

    // recv/recvfrom/recvmsg/connect/accept are handed to a detached thread by ProcessWebSocketMessage();
    // the handler itself is run on this thread instead, after the same size check.
    int function = len >= 8 ? ((int*)payload)[1] : 0;
    bool offloaded = function == 5 || function == 7 || function == 11 || function == 13 || function == 15;
    if (offloaded && len >= 8)
      ProcessWebSocketMessageSynchronouslyInCurrentThread(kClientFd, payload, len);
    else
      ProcessWebSocketMessage(kClientFd, payload, len);
    free(payload);
  }
  CloseAllSocketsByConnection(kClientFd);
  return 0;
}

}  // extern "C"
