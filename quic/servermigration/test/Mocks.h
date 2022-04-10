#pragma once

#include <folly/portability/GMock.h>
#include <quic/servermigration/management/Callbacks.h>

namespace quic {

class MockClientStateUpdateCallback : public ClientStateUpdateCallback {
 public:
  ~MockClientStateUpdateCallback() = default;

  MOCK_METHOD(
      void,
      onHandshakeFinished,
      (folly::SocketAddress address,
       ConnectionId serverConnectionId,
       folly::Optional<std::unordered_set<ServerMigrationProtocol>>
           negotiatedProtocols),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onMigrationDetected,
      (ConnectionId serverConnectionId, folly::SocketAddress newAddress),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onConnectionClose,
      (ConnectionId serverConnectionId),
      (noexcept, override));
};

} // namespace quic
