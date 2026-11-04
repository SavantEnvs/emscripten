// Fuzz harness for the websocket_to_posix_proxy receive path: the HTTP upgrade handshake
// (SendHandshake: header scan, SHA-1, base64) and the WebSocket frame parser/unmasker.
// Input starting with "GET " is a handshake request; anything else is a byte stream of frames.
// main.cpp is included with main() renamed so its static helpers can be called directly.
#define main websocket_proxy_main
#include "tools/websocket_to_posix_proxy/src/main.cpp"
#undef main

#include "ws_stream.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>

static int gSock[2] = {-1, -1};

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  // SendHandshake prints and sends; keep stdout quiet and give it a socket that never fills.
  freopen("/dev/null", "w", stdout);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, gSock) != 0) abort();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2 || size > (1u << 16)) return -1;
  if (size >= 4 && memcmp(data, "GET ", 4) == 0) {
    std::vector<char> request(data, data + size);
    request.push_back('\0');
    SendHandshake(gSock[0], request.data());
    char sink[512];
    while (recv(gSock[1], sink, sizeof sink, MSG_DONTWAIT) > 0) {
    }
    return 0;
  }
  // First byte picks how the stream is split into recv()-sized chunks, the rest is the stream.
  size_t chunk = (size_t)data[0] + 1;
  std::vector<uint8_t> stream(data + 1, data + size);
  volatile uint64_t seen = 0;
  FeedStream(stream.data(), stream.size(), chunk,
             [&](unsigned, uint8_t* payload, uint64_t len) { for (uint64_t i = 0; i < len; i++) seen = seen + payload[i]; });
  return 0;
}
