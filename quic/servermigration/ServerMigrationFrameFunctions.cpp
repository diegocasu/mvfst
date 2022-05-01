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

void throwIfUnexpectedPoolMigrationAddressFrame(
    const quic::QuicServerConnectionState& connectionState) {
  if (!connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
           ->count(quic::ServerMigrationProtocol::POOL_OF_ADDRESSES)) {
    throw quic::QuicTransportException(
        "Pool of Addresses protocol not negotiated",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
  if (!connectionState.serverMigrationState.protocolState) {
    throw quic::QuicTransportException(
        "Pool of Addresses protocol state not initialized",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
  if (connectionState.serverMigrationState.protocolState->type() !=
      quic::QuicServerMigrationProtocolServerState::Type::
          PoolOfAddressesServerState) {
    throw quic::QuicTransportException(
        "Pool of Addresses protocol took the place of another protocol",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
}

void throwIfUnexpectedPoolMigrationAddressFrame(
    const quic::QuicClientConnectionState& connectionState) {
  if (!connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
           ->count(quic::ServerMigrationProtocol::POOL_OF_ADDRESSES)) {
    throw quic::QuicTransportException(
        "Pool of Addresses protocol not negotiated",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!connectionState.serverMigrationState.protocolState) {
    return;
  }
  if (connectionState.serverMigrationState.protocolState->type() !=
      quic::QuicServerMigrationProtocolClientState::Type::
          PoolOfAddressesClientState) {
    throw quic::QuicTransportException(
        "Pool of Addresses protocol took the place of another protocol",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }
}

void throwIfUnexpectedServerMigrationFrame(
    const quic::QuicServerConnectionState& connectionState,
    const quic::ServerMigrationFrame& frame) {
  auto& negotiatedProtocols =
      connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
          .value();

  if (!frame.address.isAllZero()) {
    // Explicit protocol.
    if (!negotiatedProtocols.count(quic::ServerMigrationProtocol::EXPLICIT)) {
      throw quic::QuicTransportException(
          "Explicit protocol not negotiated",
          quic::TransportErrorCode::INTERNAL_ERROR);
    }
    if (!connectionState.serverMigrationState.protocolState) {
      throw quic::QuicTransportException(
          "Explicit protocol state not initialized",
          quic::TransportErrorCode::INTERNAL_ERROR);
    }
    if (connectionState.serverMigrationState.protocolState->type() !=
        quic::QuicServerMigrationProtocolServerState::Type::
            ExplicitServerState) {
      throw quic::QuicTransportException(
          "Explicit protocol took the place of another protocol",
          quic::TransportErrorCode::INTERNAL_ERROR);
    }
    return;
  }

  // Synchronized symmetric protocol.
  if (!negotiatedProtocols.count(
          quic::ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC)) {
    throw quic::QuicTransportException(
        "Synchronized Symmetric protocol not negotiated",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
  if (!connectionState.serverMigrationState.protocolState) {
    throw quic::QuicTransportException(
        "Synchronized Symmetric protocol state not initialized",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
  if (connectionState.serverMigrationState.protocolState->type() !=
      quic::QuicServerMigrationProtocolServerState::Type::
          SynchronizedSymmetricServerState) {
    throw quic::QuicTransportException(
        "Synchronized Symmetric protocol took the place of another protocol",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
}

void throwIfUnexpectedServerMigrationFrame(
    const quic::QuicClientConnectionState& connectionState,
    const quic::ServerMigrationFrame& frame) {
  auto& negotiatedProtocols =
      connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
          .value();

  if (!frame.address.isAllZero()) {
    // Explicit protocol.
    if (!negotiatedProtocols.count(quic::ServerMigrationProtocol::EXPLICIT)) {
      throw quic::QuicTransportException(
          "Explicit protocol not negotiated",
          quic::TransportErrorCode::PROTOCOL_VIOLATION);
    }
    if (!connectionState.serverMigrationState.protocolState) {
      return;
    }
    if (connectionState.serverMigrationState.protocolState->type() !=
        quic::QuicServerMigrationProtocolClientState::Type::
            ExplicitClientState) {
      throw quic::QuicTransportException(
          "Explicit protocol took the place of another protocol",
          quic::TransportErrorCode::PROTOCOL_VIOLATION);
    }
    return;
  }

  // Synchronized symmetric protocol.
  if (!negotiatedProtocols.count(
          quic::ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC)) {
    throw quic::QuicTransportException(
        "Synchronized Symmetric protocol not negotiated",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!connectionState.serverMigrationState.protocolState) {
    return;
  }
  if (connectionState.serverMigrationState.protocolState->type() !=
      quic::QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState) {
    throw quic::QuicTransportException(
        "Synchronized Symmetric protocol took the place of another protocol",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }
}

void throwIfUnexpectedServerMigratedFrame(
    const quic::QuicServerConnectionState& connectionState) {
  auto& negotiatedProtocols =
      connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
          .value();

  if (!connectionState.serverMigrationState.protocolState) {
    throw quic::QuicTransportException(
        "Symmetric or Synchronized Symmetric protocol state not initialized",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }

  if (connectionState.serverMigrationState.protocolState->type() ==
      quic::QuicServerMigrationProtocolServerState::Type::
          SymmetricServerState) {
    if (!negotiatedProtocols.count(quic::ServerMigrationProtocol::SYMMETRIC)) {
      throw quic::QuicTransportException(
          "Symmetric protocol not negotiated",
          quic::TransportErrorCode::INTERNAL_ERROR);
    }
    return;
  }

  if (connectionState.serverMigrationState.protocolState->type() ==
      quic::QuicServerMigrationProtocolServerState::Type::
          SynchronizedSymmetricServerState) {
    if (!negotiatedProtocols.count(
            quic::ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC)) {
      throw quic::QuicTransportException(
          "Synchronized Symmetric protocol not negotiated",
          quic::TransportErrorCode::INTERNAL_ERROR);
    }
    if (!connectionState.serverMigrationState.protocolState
             ->asSynchronizedSymmetricServerState()
             ->migrationAcknowledged) {
      throw quic::QuicTransportException(
          "Synchronized Symmetric protocol sent a SERVER_MIGRATED frame before "
          "the reception of an acknowledgement for a SERVER_MIGRATION frame",
          quic::TransportErrorCode::INTERNAL_ERROR);
    }
    return;
  }

  throw quic::QuicTransportException(
      "Symmetric or Synchronized Symmetric protocol took the place of another protocol",
      quic::TransportErrorCode::INTERNAL_ERROR);
}

void throwIfUnexpectedServerMigratedFrame(
    const quic::QuicClientConnectionState& connectionState) {
  auto& negotiatedProtocols =
      connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
          .value();

  if (!connectionState.serverMigrationState.protocolState ||
      connectionState.serverMigrationState.protocolState->type() ==
          quic::QuicServerMigrationProtocolClientState::Type::
              SymmetricClientState) {
    // Symmetric protocol.
    if (!negotiatedProtocols.count(quic::ServerMigrationProtocol::SYMMETRIC)) {
      throw quic::QuicTransportException(
          "Symmetric protocol not negotiated",
          quic::TransportErrorCode::PROTOCOL_VIOLATION);
    }
    return;
  }

  if (connectionState.serverMigrationState.protocolState->type() ==
      quic::QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState) {
    if (!negotiatedProtocols.count(
            quic::ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC)) {
      throw quic::QuicTransportException(
          "Synchronized Symmetric protocol not negotiated",
          quic::TransportErrorCode::PROTOCOL_VIOLATION);
    }
  }

  throw quic::QuicTransportException(
      "Symmetric or Synchronized Symmetric protocol took the place of another protocol",
      quic::TransportErrorCode::PROTOCOL_VIOLATION);
}

bool ignoreOldFrame(
    const quic::QuicClientConnectionState& connectionState,
    const quic::QuicServerMigrationFrame& frame,
    const quic::PacketNum& packetNumber) {
  // Ignore frames carried in old packets, if fresher ones have already been
  // processed. Note that the check exploiting the packet number involves only
  // the frame types that are expected to be found once inside a packet.
  // POOL_MIGRATION_ADDRESS frames are excluded because:
  // 1) multiple frames can be carried by the same packet.
  // If largestProcessedPacketNumber is updated when the first frame is
  // processed by this function, the others would be ignored in the next
  // invocations (could be solved by moving the update outside this function,
  // but there is no need at the moment);
  // 2) multiple frames can be spread over multiple packets, and the condition
  // would cause the drop of addresses carried by out-of-order packets.
  return connectionState.serverMigrationState.largestProcessedPacketNumber &&
      packetNumber <= connectionState.serverMigrationState
                          .largestProcessedPacketNumber.value() &&
      frame.type() !=
      quic::QuicServerMigrationFrame::Type::PoolMigrationAddressFrame;
}

void updateLargestProcessedPacketNumber(
    quic::QuicClientConnectionState& connectionState,
    const quic::PacketNum& packetNumber) {
  if (!connectionState.serverMigrationState.largestProcessedPacketNumber ||
      packetNumber > connectionState.serverMigrationState
                         .largestProcessedPacketNumber.value()) {
    connectionState.serverMigrationState.largestProcessedPacketNumber =
        packetNumber;
  }
}

void handlePoolMigrationAddressFrame(
    quic::QuicClientConnectionState& connectionState,
    const quic::PoolMigrationAddressFrame& frame) {
  // Do not process duplicates.
  if (connectionState.serverMigrationState.protocolState &&
      connectionState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.count(frame.address)) {
    return;
  }

  // The pool cannot change during a migration or after at least one migration
  // has been completed successfully. Moreover, it is up to the server to wait
  // for all the addresses to be acknowledged before attempting a migration.
  if (connectionState.serverMigrationState.migrationInProgress ||
      connectionState.serverMigrationState.numberOfMigrations > 0) {
    throw quic::QuicTransportException(
        "Received a POOL_MIGRATION_ADDRESS frame during or after a migration",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }

  // The information given by the peer address guarantees to identify
  // the correct address family used by the socket stored in the client
  // transport (if Happy Eyeballs is enabled, at this point of the
  // execution it must have finished).
  if ((connectionState.peerAddress.getIPAddress().isV4() &&
       !frame.address.hasIPv4Field()) ||
      (connectionState.peerAddress.getIPAddress().isV6() &&
       !frame.address.hasIPv6Field())) {
    throw quic::QuicTransportException(
        "Received a POOL_MIGRATION_ADDRESS frame not carrying an address of a supported family",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }

  if (connectionState.serverMigrationState.serverMigrationEventCallback) {
    connectionState.serverMigrationState.serverMigrationEventCallback
        ->onPoolMigrationAddressReceived(frame);
  }

  if (connectionState.serverMigrationState.protocolState) {
    connectionState.serverMigrationState.protocolState
        ->asPoolOfAddressesClientState()
        ->migrationAddresses.insert(frame.address);
    return;
  }

  quic::PoolOfAddressesClientState protocolState;
  protocolState.migrationAddresses.insert(frame.address);
  connectionState.serverMigrationState.protocolState = std::move(protocolState);
}

void handlePoolMigrationAddressAck(
    quic::QuicServerConnectionState& connectionState,
    const quic::PoolMigrationAddressFrame& frame) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asPoolOfAddressesServerState();
  auto it = protocolState->migrationAddresses.find(frame.address);

  if (it == protocolState->migrationAddresses.end()) {
    throw quic::QuicTransportException(
        "Received an acknowledgement for a POOL_MIGRATION_ADDRESS frame that was never sent",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
  if (!it->second) {
    // The migration address has got an acknowledgement for the first time.
    it->second = true;
    protocolState->numberOfReceivedAcks += 1;
    if (connectionState.serverMigrationState.serverMigrationEventCallback) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onPoolMigrationAddressAckReceived(
              connectionState.serverConnectionId.value(), frame);
    }
  }
}

} // namespace

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
    case QuicServerMigrationFrame::Type::ServerMigrationFrame:
      throw QuicTransportException(
          "Received a SERVER_MIGRATION frame",
          TransportErrorCode::PROTOCOL_VIOLATION);
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      throw QuicTransportException(
          "Received a POOL_MIGRATION_ADDRESS frame",
          TransportErrorCode::PROTOCOL_VIOLATION);
    case QuicServerMigrationFrame::Type::ServerMigratedFrame:
      throw QuicTransportException(
          "Received a SERVER_MIGRATED frame",
          TransportErrorCode::PROTOCOL_VIOLATION);
  }
  folly::assume_unreachable();
}

void updateServerMigrationFrameOnPacketReceived(
    QuicClientConnectionState& connectionState,
    const QuicServerMigrationFrame& frame,
    const PacketNum& packetNumber) {
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Server migration is disabled",
      TransportErrorCode::PROTOCOL_VIOLATION);

  if (ignoreOldFrame(connectionState, frame, packetNumber)) {
    return;
  }
  updateLargestProcessedPacketNumber(connectionState, packetNumber);

  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::ServerMigrationFrame:
      throwIfUnexpectedServerMigrationFrame(
          connectionState, *frame.asServerMigrationFrame());
      return;
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      throwIfUnexpectedPoolMigrationAddressFrame(connectionState);
      handlePoolMigrationAddressFrame(
          connectionState, *frame.asPoolMigrationAddressFrame());
      return;
    case QuicServerMigrationFrame::Type::ServerMigratedFrame:
      throwIfUnexpectedServerMigratedFrame(connectionState);
      return;
  }
  folly::assume_unreachable();
}

void updateServerMigrationFrameOnPacketAckReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame) {
  // The various checks (server migration enabled, protocol negotiated,
  // consistent state, etc.) are performed here when the ack is received,
  // not when the corresponding frame is sent. They are not strictly necessary
  // if the functions calling sendServerMigrationFrame() are correct, but
  // can help in spotting bugs or wrong operations during the migration.
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Server migration is disabled",
      TransportErrorCode::INTERNAL_ERROR);

  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::ServerMigrationFrame:
      throwIfUnexpectedServerMigrationFrame(
          connectionState, *frame.asServerMigrationFrame());
      return;
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      throwIfUnexpectedPoolMigrationAddressFrame(connectionState);
      handlePoolMigrationAddressAck(
          connectionState, *frame.asPoolMigrationAddressFrame());
      return;
    case QuicServerMigrationFrame::Type::ServerMigratedFrame:
      throwIfUnexpectedServerMigratedFrame(connectionState);
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
