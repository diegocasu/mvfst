#pragma once

#include <folly/portability/GMock.h>
#include <quic/servermigration/Callbacks.h>
#include <quic/servermigration/PoolMigrationAddressSchedulerFactory.h>

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
      onClientMigrationDetected,
      (ConnectionId serverConnectionId, folly::SocketAddress newAddress),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onConnectionClose,
      (ConnectionId serverConnectionId),
      (noexcept, override));
};

class MockServerMigrationEventCallback : public ServerMigrationEventCallback {
 public:
  ~MockServerMigrationEventCallback() = default;

  MOCK_METHOD(
      void,
      onPoolMigrationAddressReceived,
      (PoolMigrationAddressFrame frame),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onPoolMigrationAddressAckReceived,
      (ConnectionId serverConnectionId, PoolMigrationAddressFrame frame),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onServerMigrationReceived,
      (ServerMigrationFrame frame),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onServerMigrationAckReceived,
      (ConnectionId serverConnectionId, ServerMigrationFrame frame),
      (noexcept, override));

  MOCK_METHOD(void, onServerMigratedReceived, (), (noexcept, override));

  MOCK_METHOD(
      void,
      onServerMigratedAckReceived,
      (ConnectionId serverConnectionId),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onServerMigrationProbingStarted,
      (ServerMigrationProtocol protocol, folly::SocketAddress probingAddress),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onServerMigrationFailed,
      (ConnectionId serverConnectionId, ServerMigrationError error),
      (noexcept, override));

  MOCK_METHOD(
      void,
      onServerMigrationReady,
      (ConnectionId serverConnectionId),
      (noexcept, override));

  MOCK_METHOD(void, onServerMigrationCompleted, (), (noexcept, override));

  MOCK_METHOD(
      void,
      onServerMigrationCompleted,
      (ConnectionId serverConnectionId),
      (noexcept, override));
};

class MockPoolMigrationAddressSchedulerFactory
    : public PoolMigrationAddressSchedulerFactory {
 public:
  ~MockPoolMigrationAddressSchedulerFactory() = default;

  MOCK_METHOD(
      std::shared_ptr<PoolMigrationAddressScheduler>,
      make,
      (),
      (override));
};

} // namespace quic
