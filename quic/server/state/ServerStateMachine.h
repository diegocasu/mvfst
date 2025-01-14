/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <glog/logging.h>
#include <memory>
#include <vector>

#include <quic/QuicException.h>
#include <quic/codec/Types.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>

#include <quic/loss/QuicLossFunctions.h>
#include <quic/server/handshake/ServerHandshake.h>
#include <quic/server/handshake/ServerHandshakeFactory.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/servermigration/Callbacks.h>
#include <quic/servermigration/QuicServerMigrationNegotiatorServer.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/StateData.h>

#ifdef CCP_ENABLED
#include <ccp/ccp.h>
#endif

#include <folly/ExceptionWrapper.h>
#include <folly/IPAddress.h>
#include <folly/Overload.h>
#include <folly/Random.h>
#include <folly/io/async/AsyncSocketException.h>

namespace quic {

enum ServerState {
  Open,
  Closed,
};

struct ServerEvents {
  struct ReadData {
    folly::SocketAddress peer;
    NetworkDataSingle networkData;
  };

  struct Close {};
};

struct ConnectionMigrationState {
  uint32_t numMigrations{0};

  // Previous validated peer addresses, not containing current peer address
  std::vector<folly::SocketAddress> previousPeerAddresses;

  // Congestion state and rtt stats of last validated peer
  folly::Optional<CongestionAndRttState> lastCongestionAndRtt;
};

struct PoolOfAddressesServerState {
  using Pool = std::unordered_map<QuicIPAddress, bool, QuicIPAddressHash>;

  // Set of possible migration addresses. Each address is characterized by a
  // boolean telling if the associated frame has been acknowledged or not.
  Pool migrationAddresses;
  unsigned int numberOfReceivedAcks{0};

  bool operator==(const PoolOfAddressesServerState& rhs) const {
    return migrationAddresses == rhs.migrationAddresses &&
        numberOfReceivedAcks == rhs.numberOfReceivedAcks;
  }

  bool operator!=(const PoolOfAddressesServerState& rhs) const {
    return !(rhs == *this);
  }
};

struct ExplicitServerState {
  QuicIPAddress migrationAddress;
  bool migrationAcknowledged{false};

  ExplicitServerState(QuicIPAddress migrationAddress)
      : migrationAddress(std::move(migrationAddress)) {}

  bool operator==(const ExplicitServerState& rhs) const {
    return migrationAddress == rhs.migrationAddress &&
        migrationAcknowledged == rhs.migrationAcknowledged;
  }

  bool operator!=(const ExplicitServerState& rhs) const {
    return !(rhs == *this);
  }
};

struct SymmetricServerState {
  bool onServerMigratedAckReceivedNotified{false};

  bool operator==(const SymmetricServerState& rhs) const {
    return onServerMigratedAckReceivedNotified ==
        rhs.onServerMigratedAckReceivedNotified;
  }

  bool operator!=(const SymmetricServerState& rhs) const {
    return !(rhs == *this);
  }
};

struct SynchronizedSymmetricServerState {
  bool migrationAcknowledged{false};
  bool onServerMigratedAckReceivedNotified{false};

  bool operator==(const SynchronizedSymmetricServerState& rhs) const {
    return migrationAcknowledged == rhs.migrationAcknowledged &&
        onServerMigratedAckReceivedNotified ==
        rhs.onServerMigratedAckReceivedNotified;
  }

  bool operator!=(const SynchronizedSymmetricServerState& rhs) const {
    return !(rhs == *this);
  }
};

#define QUIC_SERVER_MIGRATION_PROTOCOL_SERVER_STATE(F, ...) \
  F(PoolOfAddressesServerState, __VA_ARGS__)                \
  F(ExplicitServerState, __VA_ARGS__)                       \
  F(SymmetricServerState, __VA_ARGS__)                      \
  F(SynchronizedSymmetricServerState, __VA_ARGS__)

DECLARE_VARIANT_TYPE(
    QuicServerMigrationProtocolServerState,
    QUIC_SERVER_MIGRATION_PROTOCOL_SERVER_STATE)

struct QuicServerConnectionState : public QuicConnectionStateBase {
  ~QuicServerConnectionState() override = default;

  ServerState state;

  // Data which we cannot read yet, because the handshake has not completed.
  // Zero rtt protected packets
  std::unique_ptr<std::vector<ServerEvents::ReadData>> pendingZeroRttData;
  // One rtt protected packets
  std::unique_ptr<std::vector<ServerEvents::ReadData>> pendingOneRttData;

  // Current state of connection migration
  ConnectionMigrationState migrationState;

  struct ServerMigrationState {
    // The original connection ID derived by the transport and used to finalize
    // the handshake. It is useful to identify the transport when an imminent
    // migration is notified. It must be initialized as soon as the handshake
    // is done and must never change, neither if a NEW_CONNECTION_ID frame is
    // issued, nor if a RETIRE_CONNECTION_ID frame is received.
    folly::Optional<ConnectionId> originalConnectionId;

    // Server migration protocol negotiator.
    std::shared_ptr<QuicServerMigrationNegotiatorServer> negotiator;

    // Protocol state.
    folly::Optional<PoolOfAddressesServerState::Pool>
        pendingPoolMigrationAddresses;
    folly::Optional<QuicServerMigrationProtocolServerState> protocolState;

    // Largest packet number processed by the server migration layer.
    // This number refers only to packets containing acknowledgements
    // for server migration frames, not to all the packets. The only exception
    // is represented by packets containing acknowledgements for PATH_RESPONSE
    // frames, which are included in this count to record a migration end.
    folly::Optional<PacketNum> largestProcessedPacketNumber;

    // Flag telling whether the transport is currently involved in a
    // server migration. The flag is reset after a server migration is
    // completed successfully.
    bool migrationInProgress{false};

    // Callbacks and flags denoting if a particular
    // callback has been invoked or not.
    std::shared_ptr<ClientStateUpdateCallback> clientStateUpdateCallback;
    bool notifiedHandshakeDone{false};
    std::shared_ptr<ServerMigrationEventCallback> serverMigrationEventCallback;
  };

  ServerMigrationState serverMigrationState;

  // Parameters to generate server chosen connection id
  folly::Optional<ServerConnectionIdParams> serverConnIdParams;

  // ConnectionIdAlgo implementation to encode and decode ConnectionId with
  // various info, such as routing related info.
  ConnectionIdAlgo* connIdAlgo{nullptr};

  // ServerConnectionIdRejector can reject a ConnectionId from ConnectionIdAlgo
  ServerConnectionIdRejector* connIdRejector{nullptr};

  // Source address token that can be saved to client via PSK.
  // Address with higher index is more recently used.
  std::vector<folly::IPAddress> tokenSourceAddresses;

  ServerHandshake* serverHandshakeLayer;

  // Whether transport parameters from psk match current server parameters.
  // A false value indicates 0-rtt is rejected.
  folly::Optional<bool> transportParamsMatching;

  // Whether source address token matches client ip.
  // A false value indicates either 0-rtt is rejected or inflight bytes are
  // limited until CFIN depending on matching policy.
  folly::Optional<bool> sourceTokenMatching;

  // Server address of VIP. Currently used as input for stateless reset token.
  folly::SocketAddress serverAddr;

  // Whether we've sent the handshake done signal yet.
  bool sentHandshakeDone{false};

  // Whether we've sent the new_token frame yet.
  bool sentNewTokenFrame{false};

  // Number of bytes the server has written during the handshake.
  uint64_t numHandshakeBytesSent{0};

#ifdef CCP_ENABLED
  // Pointer to struct that maintains state needed for interacting with libccp.
  // Once instance of this struct is created for each instance of
  // QuicServerWorker (but lives in the worker's corresponding CCPReader). We
  // need to store a pointer to it here, because it needs to be accessible by
  // the QuicCCP congestion control algorithm, which only has access to the
  // connection's QuicConnectionStateBase.
  struct ccp_datapath* ccpDatapath;
#endif

  folly::Optional<ConnectionIdData> createAndAddNewSelfConnId() override;

  QuicServerConnectionState(
      std::shared_ptr<ServerHandshakeFactory> handshakeFactory)
      : QuicConnectionStateBase(QuicNodeType::Server) {
    state = ServerState::Open;
    // Create the crypto stream.
    cryptoState = std::make_unique<QuicCryptoState>();
    congestionController = std::make_unique<Cubic>(*this);
    connectionTime = Clock::now();
    supportedVersions = std::vector<QuicVersion>{
        {QuicVersion::MVFST,
         QuicVersion::MVFST_EXPERIMENTAL,
         QuicVersion::MVFST_ALIAS,
         QuicVersion::QUIC_V1,
         QuicVersion::QUIC_DRAFT}};
    originalVersion = QuicVersion::MVFST;
    DCHECK(handshakeFactory);
    auto tmpServerHandshake =
        std::move(*handshakeFactory).makeServerHandshake(this);
    serverHandshakeLayer = tmpServerHandshake.get();
    handshakeLayer = std::move(tmpServerHandshake);
    // We shouldn't normally need to set this until we're starting the
    // transport, however writing unit tests is much easier if we set this here.
    updateFlowControlStateWithSettings(flowControlState, transportSettings);
    pendingZeroRttData =
        std::make_unique<std::vector<ServerEvents::ReadData>>();
    pendingOneRttData = std::make_unique<std::vector<ServerEvents::ReadData>>();
    streamManager = std::make_unique<QuicStreamManager>(
        *this, this->nodeType, transportSettings);
  }
};

// Transition to error state on invalid state transition.
void ServerInvalidStateHandler(QuicServerConnectionState& state);

void onServerReadData(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData);

void onServerReadDataFromOpen(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData);

void onServerReadDataFromClosed(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData);

void onServerClose(QuicServerConnectionState& conn);

void onServerCloseOpenState(QuicServerConnectionState& conn);

void processClientInitialParams(
    QuicServerConnectionState& conn,
    const ClientTransportParameters& clientParams);

void updateHandshakeState(QuicServerConnectionState& conn);

bool validateAndUpdateSourceToken(
    QuicServerConnectionState& conn,
    std::vector<folly::IPAddress> sourceAddresses);

void updateWritableByteLimitOnRecvPacket(QuicServerConnectionState& conn);

void updateTransportParamsFromTicket(
    QuicServerConnectionState& conn,
    uint64_t idleTimeout,
    uint64_t maxRecvPacketSize,
    uint64_t initialMaxData,
    uint64_t initialMaxStreamDataBidiLocal,
    uint64_t initialMaxStreamDataBidiRemote,
    uint64_t initialMaxStreamDataUni,
    uint64_t initialMaxStreamsBidi,
    uint64_t initialMaxStreamsUni);

void onConnectionMigration(
    QuicServerConnectionState& conn,
    const folly::SocketAddress& newPeerAddress,
    bool isIntentional = false);

std::vector<TransportParameter> setSupportedExtensionTransportParameters(
    QuicServerConnectionState& conn);

} // namespace quic
