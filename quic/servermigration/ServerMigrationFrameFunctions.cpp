#include <quic/servermigration/ServerMigrationFrameFunctions.h>

namespace quic {

void sendServerMigrationFrame(
    QuicServerConnectionState& connectionState,
    QuicServerMigrationFrame frame) {
  connectionState.pendingEvents.frames.emplace_back(std::move(frame));
}

void updateServerMigrationFrameOnPacketReceived(
    QuicServerConnectionState& /*connectionState*/,
    const QuicServerMigrationFrame& frame) {
  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
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

void updateServerMigrationFrameOnPacketAckReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame) {
  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      auto& poolMigrationAddressFrame = *frame.asPoolMigrationAddressFrame();

      if (connectionState.serverMigrationState.serverMigrationEventCallback) {
        connectionState.serverMigrationState.serverMigrationEventCallback
            ->onPoolMigrationAddressAckReceived(
                connectionState.serverConnectionId.value(),
                poolMigrationAddressFrame);
      }

      if (!connectionState.serverMigrationState.protocolState) {
        throw QuicTransportException(
            "Server received an ack for a POOL_MIGRATION_ADDRESS frame, but no server migration state is present",
            TransportErrorCode::INTERNAL_ERROR);
      }
      if (connectionState.serverMigrationState.protocolState->type() !=
          QuicServerMigrationProtocolServerState::Type::
              PoolOfAddressesServerState) {
        throw QuicTransportException(
            "Server received an ack for a POOL_MIGRATION_ADDRESS frame, but another server migration protocol is in use",
            TransportErrorCode::INTERNAL_ERROR);
      }

      auto protocolState = connectionState.serverMigrationState.protocolState
                               ->asPoolOfAddressesServerState();
      auto it = protocolState->migrationAddresses.find(
          poolMigrationAddressFrame.address);
      if (it == protocolState->migrationAddresses.end()) {
        throw QuicTransportException(
            "Server received an acknowledgement for a POOL_MIGRATION_ADDRESS frame that was never sent",
            TransportErrorCode::INTERNAL_ERROR);
      }
      if (!it->second) {
        // The migration address has got an acknowledgement for the first time.
        it->second = true;
        protocolState->numberOfReceivedAcks += 1;
        return;
      }
      // Duplicate acknowledgements are ignored.
      return;
  }
  folly::assume_unreachable();
}

} // namespace quic
