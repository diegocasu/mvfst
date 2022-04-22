#include <quic/servermigration/ServerMigrationFrameFunctions.h>

namespace quic {

void sendServerMigrationFrame(
    QuicServerConnectionState& connectionState,
    QuicServerMigrationFrame frame) {
  connectionState.pendingEvents.frames.emplace_back(std::move(frame));
}

void updateServerMigrationFrameOnPacketReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame) {
  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      if (connectionState.serverMigrationState.serverMigrationEventCallback) {
        connectionState.serverMigrationState.serverMigrationEventCallback
            ->onPoolMigrationAddressReceived(
                std::move(*frame.asPoolMigrationAddressFrame()));
      }
      throw QuicTransportException(
          "Server received a POOL_MIGRATION_ADDRESS frame",
          TransportErrorCode::PROTOCOL_VIOLATION);
  }
  folly::assume_unreachable();
}

void updateServerMigrationFrameOnPacketReceived(
    QuicClientConnectionState& connectionState,
    const QuicServerMigrationFrame& frame) {
  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      auto& poolMigrationAddressFrame = *frame.asPoolMigrationAddressFrame();

      if (connectionState.serverMigrationState.serverMigrationEventCallback) {
        connectionState.serverMigrationState.serverMigrationEventCallback
            ->onPoolMigrationAddressReceived(poolMigrationAddressFrame);
      }

      if (connectionState.serverMigrationState.protocolState) {
        if (connectionState.serverMigrationState.protocolState->type() !=
            QuicServerMigrationProtocolClientState::Type::
                PoolOfAddressesClientState) {
          throw QuicTransportException(
              "Client received a POOL_MIGRATION_ADDRESS frame, but another server migration protocol is in use",
              TransportErrorCode::PROTOCOL_VIOLATION);
        }
        connectionState.serverMigrationState.protocolState
            ->asPoolOfAddressesClientState()
            ->migrationAddresses.insert(poolMigrationAddressFrame.address);
        return;
      }

      PoolOfAddressesClientState protocolState;
      protocolState.migrationAddresses.insert(
          poolMigrationAddressFrame.address);
      connectionState.serverMigrationState.protocolState =
          std::move(protocolState);
      return;
  }
  folly::assume_unreachable();
}

} // namespace quic
