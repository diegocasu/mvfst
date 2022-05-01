#include <quic/servermigration/ServerMigrationFrameFunctions.h>

namespace {

/**
 * Throws a QuicTransportException if the server migration is not enabled,
 * namely if one of the following conditions is true:
 * 1) the negotiator is not initialized;
 * 2) the negotiation did not happen;
 * 3) the negotiation ended with no protocols in common between the endpoints.
 * @tparam T               either QuicServerConnectionState or
 *                         QuicClientConnectionState.
 * @param connectionState  the connection state of the client or the server.
 * @param errorMsg         the error message of the exception.
 * @param errorCode        the error code of the exception.
 */
template <class T>
void throwIfMigrationIsNotEnabled(
    const T& connectionState,
    const std::string& errorMsg,
    const quic::TransportErrorCode errorCode) {
  static_assert(
      std::is_same<T, quic::QuicServerConnectionState>::value ||
          std::is_same<T, quic::QuicClientConnectionState>::value,
      "Template type parameter must be either QuicServerConnectionState or QuicClientConnectionState");

  if (!connectionState.serverMigrationState.negotiator ||
      !connectionState.serverMigrationState.negotiator
           ->getNegotiatedProtocols() ||
      connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
          ->empty()) {
    throw quic::QuicTransportException(errorMsg, errorCode);
  }
}

/**
 * Throws a QuicTransportException if the given frame type does not belong to
 * one of the negotiated server migration protocols.
 * The function assumes that the server migration is enabled, i.e. that
 * a call to throwIfServerMigrationIsNotEnabled() does not cause an exception.
 * @tparam T               either QuicServerConnectionState or
 *                         QuicClientConnectionState.
 * @param connectionState  the connection state of the client or the server.
 * @param frame            the server migration frame.
 * @param errorMsg         the error message of the exception.
 * @param errorCode        the error code of the exception.
 */
template <class T>
void throwIfProtocolWasNotNegotiated(
    const T& connectionState,
    const quic::QuicServerMigrationFrame& frame,
    const std::string& errorMsg,
    const quic::TransportErrorCode errorCode) {
  static_assert(
      std::is_same<T, quic::QuicServerConnectionState>::value ||
          std::is_same<T, quic::QuicClientConnectionState>::value,
      "Template type parameter must be either QuicServerConnectionState or QuicClientConnectionState");

  auto& negotiatedProtocols =
      connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
          .value();
  switch (frame.type()) {
    case quic::QuicServerMigrationFrame::Type::ServerMigrationFrame: {
      auto isAllZero = frame.asServerMigrationFrame()->address.isAllZero();
      if ((!isAllZero &&
           !negotiatedProtocols.count(
               quic::ServerMigrationProtocol::EXPLICIT)) ||
          (isAllZero &&
           !negotiatedProtocols.count(
               quic::ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC))) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
      return;
    }
    case quic::QuicServerMigrationFrame::Type::ServerMigratedFrame:
      if (!negotiatedProtocols.count(
              quic::ServerMigrationProtocol::SYMMETRIC) &&
          !negotiatedProtocols.count(
              quic::ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC)) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
      return;
    case quic::QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      if (!negotiatedProtocols.count(
              quic::ServerMigrationProtocol::POOL_OF_ADDRESSES)) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
      return;
  }
  folly::assume_unreachable();
}

/**
 * Throws a QuicTransportException if the migration protocol state saved
 * in the client connection state does not match the type of the given frame.
 * If the protocol state has not already been created, no exception is raised.
 * @param connectionState  the connection state of the client.
 * @param frame            the server migration frame.
 * @param errorMsg         the error message of the exception.
 * @param errorCode        the error code of the exception.
 */
void throwIfProtocolStateNotMatching(
    const quic::QuicClientConnectionState& connectionState,
    const quic::QuicServerMigrationFrame& frame,
    const std::string& errorMsg,
    const quic::TransportErrorCode errorCode) {
  if (!connectionState.serverMigrationState.protocolState) {
    return;
  }

  auto protocolStateType =
      connectionState.serverMigrationState.protocolState->type();
  switch ((frame.type())) {
    case quic::QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      if (protocolStateType !=
          quic::QuicServerMigrationProtocolClientState::Type::
              PoolOfAddressesClientState) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
      return;
  }
  folly::assume_unreachable();
}

/**
 * Throws a QuicTransportException if the migration protocol state saved
 * in the server connection state does not match the type of the given frame.
 * If the protocol state has not already been created, an exception is raised.
 * @param connectionState  the connection state of the server.
 * @param frame            the server migration frame.
 * @param errorMsg         the error message of the exception.
 * @param errorCode        the error code of the exception.
 */
void throwIfProtocolStateNotMatching(
    const quic::QuicServerConnectionState& connectionState,
    const quic::QuicServerMigrationFrame& frame,
    const std::string& errorMsg,
    const quic::TransportErrorCode errorCode) {
  if (!connectionState.serverMigrationState.protocolState) {
    throw quic::QuicTransportException(errorMsg, errorCode);
  }

  auto protocolStateType =
      connectionState.serverMigrationState.protocolState->type();
  switch ((frame.type())) {
    case quic::QuicServerMigrationFrame::Type::ServerMigrationFrame: {
      auto isAllZero = frame.asServerMigrationFrame()->address.isAllZero();
      if ((!isAllZero &&
           protocolStateType !=
               quic::QuicServerMigrationProtocolServerState::Type::
                   ExplicitServerState) ||
          (isAllZero &&
           protocolStateType !=
               quic::QuicServerMigrationProtocolServerState::Type::
                   SynchronizedSymmetricServerState)) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
    }
    case quic::QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      if (protocolStateType !=
          quic::QuicServerMigrationProtocolServerState::Type::
              PoolOfAddressesServerState) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
      return;
    case quic::QuicServerMigrationFrame::Type::ServerMigratedFrame:
      if (protocolStateType !=
              quic::QuicServerMigrationProtocolServerState::Type::
                  SymmetricServerState &&
          protocolStateType !=
              quic::QuicServerMigrationProtocolServerState::Type::
                  SynchronizedSymmetricServerState) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
      if (protocolStateType ==
              quic::QuicServerMigrationProtocolServerState::Type::
                  SynchronizedSymmetricServerState &&
          !connectionState.serverMigrationState.protocolState
               ->asSynchronizedSymmetricServerState()
               ->migrationAcknowledged) {
        throw quic::QuicTransportException(errorMsg, errorCode);
      }
      return;
  }
  folly::assume_unreachable();
}

void handleClientReceptionOfPoolMigrationAddress(
    quic::QuicClientConnectionState& connectionState,
    const quic::QuicServerMigrationFrame& frame) {
  auto& poolMigrationAddressFrame = *frame.asPoolMigrationAddressFrame();

  // Do not process duplicates.
  if (connectionState.serverMigrationState.protocolState &&
      connectionState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.count(poolMigrationAddressFrame.address)) {
    return;
  }

  // The pool cannot change during a migration or after at least one migration
  // has been completed successfully. Moreover, it is up to the server to wait
  // for all the addresses to be acknowledged before attempting a migration.
  if (connectionState.serverMigrationState.migrationInProgress ||
      connectionState.serverMigrationState.numberOfMigrations > 0) {
    throw quic::QuicTransportException(
        "Client cannot receive a POOL_MIGRATION_ADDRESS frame during or after a migration",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }

  // The information given by the peer address guarantees to identify
  // the correct address family used by the socket stored in the client
  // transport (if Happy Eyeballs is enabled, at this point of the
  // execution it must have finished).
  if ((connectionState.peerAddress.getIPAddress().isV4() &&
       !poolMigrationAddressFrame.address.hasIPv4Field()) ||
      (connectionState.peerAddress.getIPAddress().isV6() &&
       !poolMigrationAddressFrame.address.hasIPv6Field())) {
    throw quic::QuicTransportException(
        "Client received a POOL_MIGRATION_ADDRESS frame not carrying an address of a supported family",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }

  if (connectionState.serverMigrationState.serverMigrationEventCallback) {
    connectionState.serverMigrationState.serverMigrationEventCallback
        ->onPoolMigrationAddressReceived(poolMigrationAddressFrame);
  }

  if (connectionState.serverMigrationState.protocolState) {
    connectionState.serverMigrationState.protocolState
        ->asPoolOfAddressesClientState()
        ->migrationAddresses.insert(poolMigrationAddressFrame.address);
    return;
  }

  quic::PoolOfAddressesClientState protocolState;
  protocolState.migrationAddresses.insert(poolMigrationAddressFrame.address);
  connectionState.serverMigrationState.protocolState = std::move(protocolState);
}

void handleServerReceptionOfPoolMigrationAddressAck(
    quic::QuicServerConnectionState& connectionState,
    const quic::QuicServerMigrationFrame& frame) {
  auto& poolMigrationAddressFrame = *frame.asPoolMigrationAddressFrame();
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asPoolOfAddressesServerState();
  auto it =
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address);

  if (it == protocolState->migrationAddresses.end()) {
    throw quic::QuicTransportException(
        "Server received an acknowledgement for a POOL_MIGRATION_ADDRESS frame that was never sent",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
  if (!it->second) {
    // The migration address has got an acknowledgement for the first time.
    it->second = true;
    protocolState->numberOfReceivedAcks += 1;
    if (connectionState.serverMigrationState.serverMigrationEventCallback) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onPoolMigrationAddressAckReceived(
              connectionState.serverConnectionId.value(),
              poolMigrationAddressFrame);
    }
    return;
  }
  // Duplicate acknowledgements are ignored.
}

} // namespace

namespace quic {

void sendServerMigrationFrame(
    QuicServerConnectionState& connectionState,
    QuicServerMigrationFrame frame) {
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Attempting to send a server migration frame with server migration disabled",
      TransportErrorCode::INTERNAL_ERROR);
  throwIfProtocolWasNotNegotiated(
      connectionState,
      frame,
      "Attempting to send a server migration frame belonging to a not negotiated protocol",
      TransportErrorCode::INTERNAL_ERROR);
  connectionState.pendingEvents.frames.emplace_back(std::move(frame));
}

void updateServerMigrationFrameOnPacketReceived(
    QuicServerConnectionState& /*connectionState*/,
    const QuicServerMigrationFrame& frame) {
  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::ServerMigrationFrame:
      throw QuicTransportException(
          "Server received a SERVER_MIGRATION frame",
          TransportErrorCode::PROTOCOL_VIOLATION);
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      throw QuicTransportException(
          "Server received a POOL_MIGRATION_ADDRESS frame",
          TransportErrorCode::PROTOCOL_VIOLATION);
    case QuicServerMigrationFrame::Type::ServerMigratedFrame:
      throw QuicTransportException(
          "Server received a SERVER_MIGRATED frame",
          TransportErrorCode::PROTOCOL_VIOLATION);
  }
  folly::assume_unreachable();
}

void updateServerMigrationFrameOnPacketReceived(
    QuicClientConnectionState& connectionState,
    const QuicServerMigrationFrame& frame) {
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Client received a server migration frame, but the server migration is disabled",
      TransportErrorCode::PROTOCOL_VIOLATION);
  throwIfProtocolWasNotNegotiated(
      connectionState,
      frame,
      "Client received a server migration frame belonging to a not negotiated protocol",
      TransportErrorCode::PROTOCOL_VIOLATION);
  throwIfProtocolStateNotMatching(
      connectionState,
      frame,
      "Client received a server migration frame not matching the protocol in use",
      TransportErrorCode::PROTOCOL_VIOLATION);

  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      handleClientReceptionOfPoolMigrationAddress(connectionState, frame);
      return;
  }
  folly::assume_unreachable();
}

void updateServerMigrationFrameOnPacketAckReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame) {
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Server received a server migration frame acknowledgement, but the server migration is disabled",
      TransportErrorCode::INTERNAL_ERROR);
  throwIfProtocolWasNotNegotiated(
      connectionState,
      frame,
      "Server received a server migration frame acknowledgement belonging to a not negotiated protocol",
      TransportErrorCode::INTERNAL_ERROR);
  throwIfProtocolStateNotMatching(
      connectionState,
      frame,
      "Server received a server migration frame acknowledgement not matching the protocol in use",
      TransportErrorCode::INTERNAL_ERROR);

  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      handleServerReceptionOfPoolMigrationAddressAck(connectionState, frame);
      return;
  }
  folly::assume_unreachable();
}

void updateServerMigrationFrameOnPacketSent(
    QuicConnectionStateBase& connectionState,
    const QuicServerMigrationFrame& frame) {
  auto& frames = connectionState.pendingEvents.frames;
  auto it = std::find(frames.begin(), frames.end(), frame);
  if (it != frames.end()) {
    frames.erase(it);
  }
}

folly::Optional<QuicSimpleFrame> updateServerMigrationFrameOnPacketClone(
    QuicConnectionStateBase& /*connectionState*/,
    const QuicServerMigrationFrame& frame) {
  return QuicSimpleFrame(QuicServerMigrationFrame(frame));
}

void updateServerMigrationFrameOnPacketLoss(
    QuicConnectionStateBase& connectionState,
    const QuicServerMigrationFrame& frame) {
  // Retransmit frame.
  connectionState.pendingEvents.frames.push_back(frame);
}

} // namespace quic
