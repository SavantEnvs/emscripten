// The WebSocket receive path of tools/websocket_to_posix_proxy, driven from memory instead of a
// socket. FeedStream mirrors the inner framing loop of connection_thread() in main.cpp (same
// helpers, same order) and hands each complete binary payload to a callback instead of
// ProcessWebSocketMessage(), which performs real socket/connect/send calls.
#pragma once
#include <functional>
#include <vector>

// main.cpp (included first by the user of this header) provides the framing helpers.
static void FeedStream(const uint8_t* data, size_t size, size_t chunk,
                       const std::function<void(unsigned opcode, uint8_t* payload, uint64_t len)>& onMessage) {
  std::vector<uint8_t> fragmentData;
  if (chunk == 0) chunk = 1;
  bool connectionAlive = true;
  for (size_t off = 0; connectionAlive && off < size; off += chunk) {
    size_t n = size - off < chunk ? size - off : chunk;
    fragmentData.insert(fragmentData.end(), data + off, data + off + n);
    while (!fragmentData.empty()) {
      bool hasFullHeader = WebSocketHasFullHeader(&fragmentData[0], fragmentData.size());
      if (!hasFullHeader) break;
      uint64_t neededBytes = WebSocketFullMessageSize(&fragmentData[0], fragmentData.size());
      if (fragmentData.size() < neededBytes) break;

      WebSocketMessageHeader* header = (WebSocketMessageHeader*)&fragmentData[0];
      uint64_t payloadLength = WebSocketMessagePayloadLength(&fragmentData[0], neededBytes);
      uint8_t* payload = WebSocketMessageData(&fragmentData[0], neededBytes);
      if (header->mask)
        WebSocketMessageUnmaskPayload(payload, payloadLength, WebSocketMessageMaskingKey(&fragmentData[0], neededBytes));
      switch (header->opcode) {
      case 0x02: onMessage(header->opcode, payload, payloadLength); break;
      case 0x08: connectionAlive = false; break;
      default: connectionAlive = false; break;
      }
      fragmentData.erase(fragmentData.begin(), fragmentData.begin() + (ptrdiff_t)neededBytes);
    }
  }
}
