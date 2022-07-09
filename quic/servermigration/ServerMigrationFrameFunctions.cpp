#include <quic/servermigration/DefaultPoolMigrationAddressSchedulerFactory.h>
#include <quic/servermigration/ServerMigrationFrameFunctions.h>

namespace {

using namespace std::chrono_literals;

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
    const quic::QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress) {
  auto& negotiatedProtocols =
      connectionState.serverMigrationState.negotiator->getNegotiatedProtocols()
          .value();
  if (peerAddress == connectionState.peerAddress) {
    throw quic::QuicTransportException(
        "Received a SERVER_MIGRATED frame from the current peer address",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if (!connectionState.serverMigrationState.protocolState) {
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
              SymmetricClientState ||
      connectionState.serverMigrationState.protocolState->type() ==
          quic::QuicServerMigrationProtocolClientState::Type::
              SynchronizedSymmetricClientState) {
    return;
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

bool ignoreOldAck(
    const quic::QuicServerConnectionState& connectionState,
    const quic::QuicServerMigrationFrame& frame,
    const quic::PacketNum& packetNumber) {
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

void updateLargestProcessedPacketNumber(
    quic::QuicServerConnectionState& connectionState,
    const quic::PacketNum& packetNumber) {
  if (!connectionState.serverMigrationState.largestProcessedPacketNumber ||
      packetNumber > connectionState.serverMigrationState
                         .largestProcessedPacketNumber.value()) {
    connectionState.serverMigrationState.largestProcessedPacketNumber =
        packetNumber;
  }
}

quic::CongestionAndRttState moveCurrentCongestionAndRttState(
    quic::QuicConnectionStateBase& connectionState) {
  quic::CongestionAndRttState state;
  state.peerAddress = connectionState.peerAddress;
  state.recordTime = quic::Clock::now();
  state.congestionController = std::move(connectionState.congestionController);
  state.srtt = connectionState.lossState.srtt;
  state.lrtt = connectionState.lossState.lrtt;
  state.rttvar = connectionState.lossState.rttvar;
  state.mrtt = connectionState.lossState.mrtt;
  return state;
}

void resetCongestionAndRttState(
    quic::QuicConnectionStateBase& connectionState) {
  if (connectionState.congestionControllerFactory) {
    connectionState.congestionController =
        connectionState.congestionControllerFactory->makeCongestionController(
            connectionState,
            connectionState.transportSettings.defaultCongestionController);
  } else {
    quic::DefaultCongestionControllerFactory congestionControllerFactory;
    connectionState.congestionController =
        congestionControllerFactory.makeCongestionController(
            connectionState,
            connectionState.transportSettings.defaultCongestionController);
  }
  connectionState.lossState.srtt = 0us;
  connectionState.lossState.lrtt = 0us;
  connectionState.lossState.rttvar = 0us;
  connectionState.lossState.mrtt = quic::kDefaultMinRtt;
}

void restoreCongestionAndRttState(
    quic::QuicConnectionStateBase& connectionState,
    quic::CongestionAndRttState state) {
  connectionState.congestionController = std::move(state.congestionController);
  connectionState.lossState.srtt = state.srtt;
  connectionState.lossState.lrtt = state.lrtt;
  connectionState.lossState.rttvar = state.rttvar;
  connectionState.lossState.mrtt = state.mrtt;
}

void handlePoolMigrationAddressFrame(
    quic::QuicClientConnectionState& connectionState,
    const quic::PoolMigrationAddressFrame& frame) {
  VLOG(3) << "Received a POOL_MIGRATION_ADDRESS frame carrying the address "
          << quicIPAddressToString(frame.address);

  // Do not process duplicates.
  if (connectionState.serverMigrationState.protocolState &&
      connectionState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(frame.address)) {
    VLOG(3) << "Ignoring a duplicate pool migration address";
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
        "Received a POOL_MIGRATION_ADDRESS frame not carrying an address "
        "of a supported family",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }

  if (connectionState.serverMigrationState.serverMigrationEventCallback) {
    connectionState.serverMigrationState.serverMigrationEventCallback
        ->onPoolMigrationAddressReceived(frame);
  }

  if (connectionState.serverMigrationState.protocolState) {
    connectionState.serverMigrationState.protocolState
        ->asPoolOfAddressesClientState()
        ->addressScheduler->insert(frame.address);
    return;
  }

  if (!connectionState.serverMigrationState
           .poolMigrationAddressSchedulerFactory) {
    connectionState.serverMigrationState.poolMigrationAddressSchedulerFactory =
        std::make_unique<quic::DefaultPoolMigrationAddressSchedulerFactory>();
  }

  quic::PoolOfAddressesClientState protocolState(
      connectionState.serverMigrationState.poolMigrationAddressSchedulerFactory
          ->make());
  protocolState.addressScheduler->insert(frame.address);
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
        "Received an acknowledgement for a POOL_MIGRATION_ADDRESS frame"
        " that was never sent",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }
  if (!it->second) {
    // The migration address has got an acknowledgement for the first time.
    it->second = true;
    protocolState->numberOfReceivedAcks += 1;
    if (connectionState.serverMigrationState.serverMigrationEventCallback) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onPoolMigrationAddressAckReceived(
              connectionState.serverMigrationState.originalConnectionId.value(),
              frame);
    }
  }
}

void handleExplicitServerMigrationFrame(
    quic::QuicClientConnectionState& connectionState,
    const quic::ServerMigrationFrame& frame) {
  VLOG(3) << "Received a SERVER_MIGRATION frame carrying the address "
          << quicIPAddressToString(frame.address);

  if ((connectionState.peerAddress.getIPAddress().isV4() &&
       !frame.address.hasIPv4Field()) ||
      (connectionState.peerAddress.getIPAddress().isV6() &&
       !frame.address.hasIPv6Field())) {
    throw quic::QuicTransportException(
        "Received a SERVER_MIGRATION frame not carrying an address "
        "of a supported family",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }
  if ((connectionState.peerAddress.getIPAddress().isV4() &&
       frame.address.getIPv4AddressAsSocketAddress() ==
           connectionState.peerAddress) ||
      (connectionState.peerAddress.getIPAddress().isV6() &&
       frame.address.getIPv6AddressAsSocketAddress() ==
           connectionState.peerAddress)) {
    throw quic::QuicTransportException(
        "Received a SERVER_MIGRATION frame carrying the current "
        "address of the peer",
        quic::TransportErrorCode::PROTOCOL_VIOLATION);
  }

  if (!connectionState.serverMigrationState.protocolState) {
    connectionState.serverMigrationState.protocolState =
        quic::ExplicitClientState(frame.address);
    connectionState.serverMigrationState.migrationInProgress = true;
    if (connectionState.serverMigrationState.serverMigrationEventCallback) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigrationReceived(frame);
    }
    return;
  }

  // Ignore duplicates.
  if (connectionState.serverMigrationState.protocolState
          ->asExplicitClientState()
          ->migrationAddress == frame.address) {
    VLOG(3) << "Ignoring a duplicate server migration address";
    return;
  }

  throw quic::QuicTransportException(
      "Received multiple SERVER_MIGRATION frames with different addresses",
      quic::TransportErrorCode::PROTOCOL_VIOLATION);
}

void handleExplicitServerMigrationFrameAck(
    quic::QuicServerConnectionState& connectionState,
    const quic::ServerMigrationFrame& frame) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asExplicitServerState();

  if (protocolState->migrationAddress != frame.address) {
    throw quic::QuicTransportException(
        "Received an acknowledgement for an unexpected SERVER_MIGRATION frame",
        quic::TransportErrorCode::INTERNAL_ERROR);
  }

  if (!protocolState->migrationAcknowledged) {
    protocolState->migrationAcknowledged = true;
    if (connectionState.serverMigrationState.serverMigrationEventCallback) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigrationAckReceived(
              connectionState.serverMigrationState.originalConnectionId.value(),
              frame);
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigrationReady(connectionState.serverMigrationState
                                       .originalConnectionId.value());
    }
  }
}

void handleSynchronizedSymmetricServerMigrationFrame(
    quic::QuicClientConnectionState& connectionState,
    const quic::ServerMigrationFrame& frame) {
  VLOG(3) << "Received a SERVER_MIGRATION frame carrying the address "
          << quicIPAddressToString(frame.address);
  if (!connectionState.serverMigrationState.protocolState) {
    connectionState.serverMigrationState.protocolState =
        quic::SynchronizedSymmetricClientState();
    connectionState.serverMigrationState.migrationInProgress = true;
    if (connectionState.serverMigrationState.serverMigrationEventCallback) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigrationReceived(frame);
    }
  }
}

void handleSynchronizedSymmetricServerMigrationFrameAck(
    quic::QuicServerConnectionState& connectionState,
    const quic::ServerMigrationFrame& frame) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  if (!protocolState->migrationAcknowledged) {
    protocolState->migrationAcknowledged = true;
    if (connectionState.serverMigrationState.serverMigrationEventCallback) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigrationAckReceived(
              connectionState.serverMigrationState.originalConnectionId.value(),
              frame);
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigrationReady(connectionState.serverMigrationState
                                       .originalConnectionId.value());
    }
  }
}

void handleServerMigratedFrame(
    quic::QuicClientConnectionState& connectionState) {
  // Only handle the callbacks for both the Symmetric and Synchronized
  // Symmetric protocols. The update of the state is handled directly in
  // maybeDetectSymmetricMigration().
  VLOG(3) << "Received a SERVER_MIGRATED frame";
  if (!connectionState.serverMigrationState.protocolState) {
    connectionState.serverMigrationState.protocolState =
        quic::SymmetricClientState();
  }
  if (connectionState.serverMigrationState.protocolState->type() ==
      quic::QuicServerMigrationProtocolClientState::Type::
          SymmetricClientState) {
    auto protocolState = connectionState.serverMigrationState.protocolState
                             ->asSymmetricClientState();
    if (connectionState.serverMigrationState.serverMigrationEventCallback &&
        !protocolState->onServerMigratedReceivedNotified) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigratedReceived();
      protocolState->onServerMigratedReceivedNotified = true;
    }
    return;
  }
  if (connectionState.serverMigrationState.protocolState->type() ==
      quic::QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState) {
    auto protocolState = connectionState.serverMigrationState.protocolState
                             ->asSynchronizedSymmetricClientState();
    if (connectionState.serverMigrationState.serverMigrationEventCallback &&
        !protocolState->onServerMigratedReceivedNotified) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigratedReceived();
      protocolState->onServerMigratedReceivedNotified = true;
    }
  }
}

void handleServerMigratedFrameAck(
    quic::QuicServerConnectionState& connectionState) {
  if (connectionState.serverMigrationState.protocolState->type() ==
      quic::QuicServerMigrationProtocolServerState::Type::
          SymmetricServerState) {
    auto protocolState = connectionState.serverMigrationState.protocolState
                             ->asSymmetricServerState();
    if (connectionState.serverMigrationState.serverMigrationEventCallback &&
        !protocolState->onServerMigratedAckReceivedNotified) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigratedAckReceived(connectionState.serverMigrationState
                                            .originalConnectionId.value());
      protocolState->onServerMigratedAckReceivedNotified = true;
    }
    return;
  }
  if (connectionState.serverMigrationState.protocolState->type() ==
      quic::QuicServerMigrationProtocolServerState::Type::
          SynchronizedSymmetricServerState) {
    auto protocolState = connectionState.serverMigrationState.protocolState
                             ->asSynchronizedSymmetricServerState();
    if (connectionState.serverMigrationState.serverMigrationEventCallback &&
        !protocolState->onServerMigratedAckReceivedNotified) {
      connectionState.serverMigrationState.serverMigrationEventCallback
          ->onServerMigratedAckReceived(connectionState.serverMigrationState
                                            .originalConnectionId.value());
      protocolState->onServerMigratedAckReceivedNotified = true;
    }
  }
}

void maybeUpdateExplicitServerMigrationProbing(
    quic::QuicClientConnectionState& connectionState) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asExplicitClientState();
  if (protocolState->probingFinished || protocolState->probingInProgress) {
    // If the probing has finished, there is nothing to do. If the probing
    // is in progress, the scheduling of the next probe is done directly by
    // the loss functions, so there is nothing to do as well.
    return;
  }

  // A probe timeout has been triggered after sending an acknowledgement for
  // a SERVER_MIGRATION frame. Then, start probing the new server address.
  auto congestionRttState = moveCurrentCongestionAndRttState(connectionState);
  connectionState.serverMigrationState.previousCongestionAndRttStates
      .emplace_back(std::move(congestionRttState));
  resetCongestionAndRttState(connectionState);

  protocolState->serverAddressBeforeProbing = connectionState.peerAddress;
  connectionState.peerAddress =
      connectionState.peerAddress.getIPAddress().isV4()
      ? protocolState->migrationAddress.getIPv4AddressAsSocketAddress()
      : protocolState->migrationAddress.getIPv6AddressAsSocketAddress();
  protocolState->probingInProgress = true;

  if (connectionState.serverMigrationState.serverMigrationEventCallback &&
      !protocolState->onServerMigrationProbingStartedNotified) {
    protocolState->onServerMigrationProbingStartedNotified = true;
    connectionState.serverMigrationState.serverMigrationEventCallback
        ->onServerMigrationProbingStarted(
            quic::ServerMigrationProtocol::EXPLICIT,
            connectionState.peerAddress);
  }
  VLOG(3) << "Server migration detected: sending probes to the address "
          << connectionState.peerAddress.describe();
}

void maybeEndExplicitServerMigrationProbing(
    quic::QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asExplicitClientState();
  auto expectedPeerAddress = connectionState.peerAddress.getIPAddress().isV4()
      ? protocolState->migrationAddress.getIPv4AddressAsSocketAddress()
      : protocolState->migrationAddress.getIPv6AddressAsSocketAddress();

  if (protocolState->probingFinished || !protocolState->probingInProgress) {
    return;
  }
  if (peerAddress == protocolState->serverAddressBeforeProbing) {
    // The highest-numbered non-probing packet arrived from the old server
    // address, most likely due to the loss of the SERVER_MIGRATION
    // acknowledgement. Then, stop the probing and roll back to the
    // pre-probing state: the migration probing will restart at the next PTO.
    // Note that the callback state is not reset, meaning that the callback
    // will not be invoked again at the next PTO. This is not needed, because
    // the next PTO will restart the same migration probing that was
    // previously notified.
    VLOG(3) << "Stopping server migration probing: received the highest-"
               "numbered non-probing packet from the old server address "
            << peerAddress.describe() << ". Rolling back to the previous state";
    connectionState.peerAddress = protocolState->serverAddressBeforeProbing;
    protocolState->serverAddressBeforeProbing = folly::SocketAddress();
    protocolState->probingInProgress = false;
    protocolState->probingFinished = false;
    restoreCongestionAndRttState(
        connectionState,
        std::move(connectionState.serverMigrationState
                      .previousCongestionAndRttStates.back()));
    connectionState.serverMigrationState.previousCongestionAndRttStates
        .pop_back();
    return;
  }
  if (peerAddress == expectedPeerAddress) {
    // Stop the probing.
    VLOG(3) << "Stopping server migration probing: received the highest-"
               "numbered non-probing packet from the new server address "
            << peerAddress.describe();
    protocolState->probingInProgress = false;
    protocolState->probingFinished = true;

    // Start path validation. The retransmission of PATH_CHALLENGE frames
    // is done automatically when a packet is marked as lost.
    uint64_t pathData;
    folly::Random::secureRandom(&pathData, sizeof(pathData));
    connectionState.pendingEvents.pathChallenge =
        quic::PathChallengeFrame(pathData);

    // Set the anti-amplification limit for the non-validated path.
    // This limit is automatically ignored after a path validation succeeds.
    connectionState.pathValidationLimiter =
        std::make_unique<quic::PendingPathRateLimiter>(
            connectionState.udpSendPacketLen);
  }
}

void maybeUpdatePoolOfAddressesServerMigrationProbing(
    quic::QuicClientConnectionState& connectionState) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  if (protocolState->probingFinished) {
    return;
  }
  if (!protocolState->probingInProgress) {
    // First probe, so initialize the probing state.
    auto congestionRttState = moveCurrentCongestionAndRttState(connectionState);
    connectionState.serverMigrationState.previousCongestionAndRttStates
        .emplace_back(std::move(congestionRttState));
    protocolState->serverAddressBeforeProbing = connectionState.peerAddress;
    protocolState->addressScheduler->setCurrentServerAddress(
        quic::QuicIPAddress(connectionState.peerAddress));
    protocolState->probingInProgress = true;
  }

  resetCongestionAndRttState(connectionState);
  auto nextProbingAddress = protocolState->addressScheduler->next();
  connectionState.peerAddress =
      connectionState.peerAddress.getIPAddress().isV4()
      ? nextProbingAddress.getIPv4AddressAsSocketAddress()
      : nextProbingAddress.getIPv6AddressAsSocketAddress();

  if (connectionState.serverMigrationState.serverMigrationEventCallback) {
    connectionState.serverMigrationState.serverMigrationEventCallback
        ->onServerMigrationProbingStarted(
            quic::ServerMigrationProtocol::POOL_OF_ADDRESSES,
            connectionState.peerAddress);
  }
  VLOG(3) << "Server migration detected: sending probes to the address "
          << connectionState.peerAddress.describe();
}

void maybeEndPoolOfAddressesServerMigrationProbing(
    quic::QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  if (protocolState->probingFinished || !protocolState->probingInProgress) {
    return;
  }
  if (peerAddress == protocolState->serverAddressBeforeProbing) {
    // The PTO was due to a packet loss, not a server migration.
    // Stop the probing and restore the congestion controller state.
    VLOG(3) << "Stopping server migration probing: received the highest-"
               "numbered non-probing packet from the old server address "
            << peerAddress.describe() << ". Rolling back to the previous state";
    connectionState.peerAddress = protocolState->serverAddressBeforeProbing;
    protocolState->serverAddressBeforeProbing = folly::SocketAddress();
    protocolState->probingInProgress = false;
    protocolState->probingFinished = false;
    protocolState->addressScheduler->restart();
    protocolState->addressScheduler->setCurrentServerAddress(
        quic::QuicIPAddress());
    restoreCongestionAndRttState(
        connectionState,
        std::move(connectionState.serverMigrationState
                      .previousCongestionAndRttStates.back()));
    connectionState.serverMigrationState.previousCongestionAndRttStates
        .pop_back();
    return;
  }
  if (protocolState->addressScheduler->contains(peerAddress)) {
    VLOG(3) << "Stopping server migration probing: received the highest-"
               "numbered non-probing packet from the new server address "
            << peerAddress.describe();

    // Due to congestion/latency/loss, the packet could have been sent by an
    // address already cycled by the scheduler, so update the peer address.
    connectionState.peerAddress = peerAddress;
    protocolState->serverAddressBeforeProbing = folly::SocketAddress();

    // Set the migrationInProgress flag only after the new server address has
    // been found, to avoid that POOL_MIGRATION_ADDRESS frames arriving during
    // a false alarm, i.e. after a PTO not caused by migration, are mistaken
    // for a protocol violation.
    connectionState.serverMigrationState.migrationInProgress = true;

    // Stop the probing.
    protocolState->probingInProgress = false;
    protocolState->probingFinished = true;
    protocolState->addressScheduler->restart();
    protocolState->addressScheduler->setCurrentServerAddress(
        quic::QuicIPAddress());

    // Start path validation. The retransmission of PATH_CHALLENGE frames
    // is done automatically when a packet is marked as lost.
    uint64_t pathData;
    folly::Random::secureRandom(&pathData, sizeof(pathData));
    connectionState.pendingEvents.pathChallenge =
        quic::PathChallengeFrame(pathData);

    // Set the anti-amplification limit for the non-validated path.
    // This limit is automatically ignored after a path validation succeeds.
    connectionState.pathValidationLimiter =
        std::make_unique<quic::PendingPathRateLimiter>(
            connectionState.udpSendPacketLen);
  }
}

void handleSymmetricMigration(
    quic::QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress) {
  if (!connectionState.serverMigrationState.protocolState) {
    // A SERVER_MIGRATED frame was not carried in the packet causing
    // the migration, so create the state here.
    connectionState.serverMigrationState.protocolState =
        quic::SymmetricClientState();
  }

  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asSymmetricClientState();
  if (protocolState->pathValidationStarted) {
    return;
  }

  // Change the peer address.
  connectionState.peerAddress = peerAddress;
  connectionState.serverMigrationState.migrationInProgress = true;

  // Reset congestion controller.
  auto congestionRttState = moveCurrentCongestionAndRttState(connectionState);
  connectionState.serverMigrationState.previousCongestionAndRttStates
      .emplace_back(std::move(congestionRttState));
  resetCongestionAndRttState(connectionState);

  // Start path validation. The retransmission of PATH_CHALLENGE frames
  // is done automatically when a packet is marked as lost.
  uint64_t pathData;
  folly::Random::secureRandom(&pathData, sizeof(pathData));
  connectionState.pendingEvents.pathChallenge =
      quic::PathChallengeFrame(pathData);
  protocolState->pathValidationStarted = true;

  // Set the anti-amplification limit for the non-validated path.
  // This limit is automatically ignored after a path validation succeeds.
  connectionState.pathValidationLimiter =
      std::make_unique<quic::PendingPathRateLimiter>(
          connectionState.udpSendPacketLen);
}

void handleSynchronizedSymmetricMigration(
    quic::QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress) {
  auto protocolState = connectionState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  if (protocolState->pathValidationStarted) {
    return;
  }

  // Change the peer address.
  connectionState.peerAddress = peerAddress;

  // Reset congestion controller.
  auto congestionRttState = moveCurrentCongestionAndRttState(connectionState);
  connectionState.serverMigrationState.previousCongestionAndRttStates
      .emplace_back(std::move(congestionRttState));
  resetCongestionAndRttState(connectionState);

  // Start path validation. The retransmission of PATH_CHALLENGE frames
  // is done automatically when a packet is marked as lost.
  uint64_t pathData;
  folly::Random::secureRandom(&pathData, sizeof(pathData));
  connectionState.pendingEvents.pathChallenge =
      quic::PathChallengeFrame(pathData);
  protocolState->pathValidationStarted = true;

  // Set the anti-amplification limit for the non-validated path.
  // This limit is automatically ignored after a path validation succeeds.
  connectionState.pathValidationLimiter =
      std::make_unique<quic::PendingPathRateLimiter>(
          connectionState.udpSendPacketLen);
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
    const PacketNum& packetNumber,
    const folly::SocketAddress& peerAddress) {
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Server migration is disabled",
      TransportErrorCode::PROTOCOL_VIOLATION);

  if (ignoreOldFrame(connectionState, frame, packetNumber)) {
    VLOG(3)
        << "Ignoring old QuicServerMigrationFrame. Largest processed packet number="
        << connectionState.serverMigrationState.largestProcessedPacketNumber
               .value()
        << ", received packet number=" << packetNumber;
    return;
  }
  updateLargestProcessedPacketNumber(connectionState, packetNumber);

  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::ServerMigrationFrame: {
      auto& serverMigrationFrame = *frame.asServerMigrationFrame();
      throwIfUnexpectedServerMigrationFrame(
          connectionState, serverMigrationFrame);
      if (serverMigrationFrame.address.isAllZero()) {
        handleSynchronizedSymmetricServerMigrationFrame(
            connectionState, serverMigrationFrame);
      } else {
        handleExplicitServerMigrationFrame(
            connectionState, serverMigrationFrame);
      }
      return;
    }
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      throwIfUnexpectedPoolMigrationAddressFrame(connectionState);
      handlePoolMigrationAddressFrame(
          connectionState, *frame.asPoolMigrationAddressFrame());
      return;
    case QuicServerMigrationFrame::Type::ServerMigratedFrame:
      if (peerAddress == connectionState.peerAddress) {
        return;
      }
      throwIfUnexpectedServerMigratedFrame(connectionState, peerAddress);
      handleServerMigratedFrame(connectionState);
      return;
  }
  folly::assume_unreachable();
}

void updateServerMigrationFrameOnPacketAckReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame,
    const PacketNum& packetNumber) {
  // The various checks (server migration enabled, protocol negotiated,
  // consistent state, etc.) are performed here when the ack is received,
  // not when the corresponding frame is sent. This is done because:
  // 1) if there is an error, the client should recognize it and eventually
  // close the connection due to a protocol violation;
  // 2) lazily evaluating the correctness of the state allows making
  // sendServerMigrationFrame() simpler. Moreover, it allows putting the frame
  // in the output queue without the need to perform the initialization of the
  // protocol state before calling sendServerMigrationFrame().
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Server migration is disabled",
      TransportErrorCode::INTERNAL_ERROR);

  if (ignoreOldAck(connectionState, frame, packetNumber)) {
    VLOG(3) << "Ignoring old packet carrying a QuicServerMigrationFrame ack. "
               "Largest processed packet number="
            << connectionState.serverMigrationState.largestProcessedPacketNumber
                   .value()
            << ", received packet number=" << packetNumber;
    return;
  }
  updateLargestProcessedPacketNumber(connectionState, packetNumber);

  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::ServerMigrationFrame: {
      auto& serverMigrationFrame = *frame.asServerMigrationFrame();
      throwIfUnexpectedServerMigrationFrame(
          connectionState, serverMigrationFrame);
      if (serverMigrationFrame.address.isAllZero()) {
        handleSynchronizedSymmetricServerMigrationFrameAck(
            connectionState, serverMigrationFrame);
      } else {
        handleExplicitServerMigrationFrameAck(
            connectionState, serverMigrationFrame);
      }
      return;
    }
    case QuicServerMigrationFrame::Type::PoolMigrationAddressFrame:
      throwIfUnexpectedPoolMigrationAddressFrame(connectionState);
      handlePoolMigrationAddressAck(
          connectionState, *frame.asPoolMigrationAddressFrame());
      return;
    case QuicServerMigrationFrame::Type::ServerMigratedFrame:
      throwIfUnexpectedServerMigratedFrame(connectionState);
      handleServerMigratedFrameAck(connectionState);
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
  switch (frame.type()) {
    case QuicServerMigrationFrame::Type::ServerMigratedFrame:
      // Do not retransmit a SERVER_MIGRATED to avoid a protocol violation
      // caused by the frame arriving when the client already detected a
      // migration and updated the peer address.
      // Note that the client detects the server migration when the first
      // non-probing packet from the new address arrives, so there is no need
      // to enforce a retransmission.
      VLOG(3) << "Skipping retransmission of a SERVER_MIGRATED frame";
      break;
    default:
      // Retransmit the frame.
      connectionState.pendingEvents.frames.push_back(frame);
  }
}

void maybeUpdateServerMigrationProbing(
    QuicClientConnectionState& connectionState) {
  CHECK(connectionState.serverMigrationState.protocolState);

  switch (connectionState.serverMigrationState.protocolState->type()) {
    case QuicServerMigrationProtocolClientState::Type::ExplicitClientState:
      maybeUpdateExplicitServerMigrationProbing(connectionState);
      return;
    case QuicServerMigrationProtocolClientState::Type::
        PoolOfAddressesClientState:
      maybeUpdatePoolOfAddressesServerMigrationProbing(connectionState);
      return;
    case QuicServerMigrationProtocolClientState::Type::SymmetricClientState:
    case QuicServerMigrationProtocolClientState::Type::
        SynchronizedSymmetricClientState:
      return;
  }
  folly::assume_unreachable();
}

void maybeEndServerMigrationProbing(
    QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress) {
  CHECK(connectionState.serverMigrationState.protocolState);

  switch (connectionState.serverMigrationState.protocolState->type()) {
    case QuicServerMigrationProtocolClientState::Type::ExplicitClientState:
      maybeEndExplicitServerMigrationProbing(connectionState, peerAddress);
      return;
    case QuicServerMigrationProtocolClientState::Type::
        PoolOfAddressesClientState:
      maybeEndPoolOfAddressesServerMigrationProbing(
          connectionState, peerAddress);
      return;
    case QuicServerMigrationProtocolClientState::Type::SymmetricClientState:
    case QuicServerMigrationProtocolClientState::Type::
        SynchronizedSymmetricClientState:
      return;
  }
  folly::assume_unreachable();
}

void maybeDetectSymmetricMigration(
    QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress,
    const PacketNum& packetNumber) {
  if (peerAddress == connectionState.peerAddress) {
    return;
  }
  throwIfMigrationIsNotEnabled(
      connectionState,
      "Server migration is disabled",
      TransportErrorCode::PROTOCOL_VIOLATION);

  if (!connectionState.serverMigrationState.protocolState) {
    // If the execution flow arrives here, it means that this is an attempt for
    // a Symmetric migration, but a SERVER_MIGRATED frame was not carried in the
    // first packet received from the new server address. Then, perform here the
    // same checks done when a SERVER_MIGRATED frame is received.
    VLOG(3) << "Detected a Symmetric migration without receiving "
               "a SERVER_MIGRATED frame";
    throwIfUnexpectedServerMigratedFrame(connectionState, peerAddress);
    // Here and in the following switch cases, the largest processed packet
    // number must be updated, as happens with the reception of SERVER_MIGRATED.
    // This ensures that the reception of an out-of-order SERVER_MIGRATED does
    // not cause a protocol violation when invoking
    // updateServerMigrationFrameOnPacketReceived().
    updateLargestProcessedPacketNumber(connectionState, packetNumber);
    handleSymmetricMigration(connectionState, peerAddress);
    return;
  }

  switch (connectionState.serverMigrationState.protocolState->type()) {
    case QuicServerMigrationProtocolClientState::Type::ExplicitClientState:
    case QuicServerMigrationProtocolClientState::Type::
        PoolOfAddressesClientState:
      return;
    case QuicServerMigrationProtocolClientState::Type::SymmetricClientState:
      VLOG(3) << "Detected a Symmetric migration";
      updateLargestProcessedPacketNumber(connectionState, packetNumber);
      handleSymmetricMigration(connectionState, peerAddress);
      return;
    case QuicServerMigrationProtocolClientState::Type::
        SynchronizedSymmetricClientState:
      VLOG(3) << "Detected a Synchronized Symmetric migration";
      updateLargestProcessedPacketNumber(connectionState, packetNumber);
      handleSynchronizedSymmetricMigration(connectionState, peerAddress);
      return;
  }
  folly::assume_unreachable();
}

void endServerMigration(
    QuicClientConnectionState& connectionState,
    const PacketNum& packetNumber) {
  CHECK(connectionState.serverMigrationState.protocolState);
  VLOG(3) << "Ending server migration";
  connectionState.serverMigrationState.migrationInProgress = false;
  connectionState.serverMigrationState.numberOfMigrations += 1;

  // Clear the protocol state, so that future migrations are possible. The only
  // exception is when Pool of Addresses is used, since the pool must be
  // preserved across migrations.
  auto poolOfAddressesProtocolState =
      connectionState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState();
  if (poolOfAddressesProtocolState) {
    poolOfAddressesProtocolState->probingFinished = false;
  } else {
    connectionState.serverMigrationState.protocolState.clear();
  }

  // Removing the path limiter is not strictly necessary, since it is
  // ignored once the validation succeeded, but do it for clarity.
  connectionState.pathValidationLimiter.reset();

  // Update the largest processed server migration packet to
  // record the one that ended the migration.
  updateLargestProcessedPacketNumber(connectionState, packetNumber);

  if (connectionState.serverMigrationState.serverMigrationEventCallback) {
    connectionState.serverMigrationState.serverMigrationEventCallback
        ->onServerMigrationCompleted();
  }
}

void endServerMigration(
    QuicServerConnectionState& connectionState,
    const PacketNum& packetNumber) {
  CHECK(connectionState.serverMigrationState.protocolState);
  VLOG(3) << "Ending server migration";
  connectionState.serverMigrationState.migrationInProgress = false;

  // Clear the protocol state, so that future migrations are possible. The only
  // exception is when Pool of Addresses is used, since the pool must be
  // preserved across migrations.
  if (!connectionState.serverMigrationState.protocolState
           ->asPoolOfAddressesServerState()) {
    connectionState.serverMigrationState.protocolState.clear();
  }

  // Update the largest processed server migration acknowledgement to
  // record the one that ended the migration.
  updateLargestProcessedPacketNumber(connectionState, packetNumber);

  if (connectionState.serverMigrationState.serverMigrationEventCallback) {
    connectionState.serverMigrationState.serverMigrationEventCallback
        ->onServerMigrationCompleted(
            connectionState.serverMigrationState.originalConnectionId.value());
  }
}

} // namespace quic
