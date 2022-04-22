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

} // namespace quic
