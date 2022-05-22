/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/client/test/Mocks.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/TransportParameters.h>

using namespace ::testing;
namespace quic::test {

namespace {
// Use non-default values to test for nops
constexpr auto idleTimeout = kDefaultIdleTimeout + 1s;
constexpr auto maxRecvPacketSize = 1420;
constexpr auto initialMaxData = kDefaultConnectionWindowSize + 2;
constexpr auto initialMaxStreamDataBidiLocal = kDefaultStreamWindowSize + 3;
constexpr auto initialMaxStreamDataBidiRemote = kDefaultStreamWindowSize + 4;
constexpr auto initialMaxStreamDataUni = kDefaultStreamWindowSize + 5;
constexpr auto initialMaxStreamsBidi = kDefaultMaxStreamsBidirectional + 6;
constexpr auto initialMaxStreamsUni = kDefaultMaxStreamsUnidirectional + 7;
const CachedServerTransportParameters kParams{
    std::chrono::milliseconds(idleTimeout).count(),
    maxRecvPacketSize,
    initialMaxData,
    initialMaxStreamDataBidiLocal,
    initialMaxStreamDataBidiRemote,
    initialMaxStreamDataUni,
    initialMaxStreamsBidi,
    initialMaxStreamsUni};
} // namespace

class ClientStateMachineTest : public Test {
 public:
  void SetUp() override {
    mockFactory_ = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory_, _makeClientHandshake(_))
        .WillRepeatedly(Invoke(
            [&](QuicClientConnectionState* conn)
                -> std::unique_ptr<quic::ClientHandshake> {
              auto handshake = std::make_unique<MockClientHandshake>(conn);
              mockHandshake_ = handshake.get();
              return handshake;
            }));
    client_ = std::make_unique<QuicClientConnectionState>(mockFactory_);
  }

  std::shared_ptr<MockClientHandshakeFactory> mockFactory_;
  MockClientHandshake* mockHandshake_;
  std::unique_ptr<QuicClientConnectionState> client_;
};

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsNotIgnorePathMTU) {
  updateTransportParamsFromCachedEarlyParams(*client_, kParams);
  EXPECT_EQ(client_->udpSendPacketLen, kDefaultUDPSendPacketLen);
}

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsFromCachedEarlyParams) {
  client_->transportSettings.canIgnorePathMTU = true;

  updateTransportParamsFromCachedEarlyParams(*client_, kParams);
  EXPECT_EQ(client_->peerIdleTimeout, idleTimeout);
  EXPECT_NE(client_->udpSendPacketLen, maxRecvPacketSize);
  EXPECT_EQ(client_->flowControlState.peerAdvertisedMaxOffset, initialMaxData);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
      initialMaxStreamDataBidiLocal);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote,
      initialMaxStreamDataBidiRemote);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
      initialMaxStreamDataUni);

  for (unsigned long i = 0; i < initialMaxStreamsBidi; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextBidirectionalStream().hasValue());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextBidirectionalStream().hasError());
  for (unsigned long i = 0; i < initialMaxStreamsUni; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextUnidirectionalStream().hasValue());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextUnidirectionalStream().hasError());
}

TEST_F(ClientStateMachineTest, PreserveHappyeyabllsDuringUndo) {
  folly::EventBase evb;
  client_->clientConnectionId = ConnectionId::createRandom(8);
  client_->happyEyeballsState.finished = true;
  client_->happyEyeballsState.secondSocket =
      std::make_unique<folly::AsyncUDPSocket>(&evb);
  auto newConn = undoAllClientStateForRetry(std::move(client_));
  EXPECT_TRUE(newConn->happyEyeballsState.finished);
  EXPECT_NE(nullptr, newConn->happyEyeballsState.secondSocket);
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeBelowMin) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead - 1));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  try {
    processServerInitialParams(clientConn, serverTransportParams, 0);
    FAIL()
        << "Expect transport exception due to max datagram frame size too small";
  } catch (QuicTransportException& e) {
    EXPECT_EQ(e.errorCode(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeZeroOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(
      encodeIntegerParameter(TransportParameterId::max_datagram_frame_size, 0));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_EQ(clientConn.datagramState.maxWriteFrameSize, 0);
}

TEST_F(ClientStateMachineTest, TestProcessMaxDatagramSizeOk) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  std::vector<TransportParameter> transportParams;
  transportParams.push_back(encodeIntegerParameter(
      TransportParameterId::max_datagram_frame_size,
      kMaxDatagramPacketOverhead + 1));
  ServerTransportParameters serverTransportParams = {
      std::move(transportParams)};
  processServerInitialParams(clientConn, serverTransportParams, 0);
  EXPECT_EQ(
      clientConn.datagramState.maxWriteFrameSize,
      kMaxDatagramPacketOverhead + 1);
}

TEST_F(ClientStateMachineTest, TestProcessServerMigrationSuite) {
  QuicClientConnectionState clientConnection(
      FizzClientQuicHandshakeContext::Builder().build());
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);

  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);
  clientConnection.serverMigrationState.negotiator = std::move(negotiator);

  QuicServerMigrationNegotiatorClient fakePeerNegotiator(supportedProtocols);
  std::vector<TransportParameter> transportParameters;
  transportParameters.push_back(
      fakePeerNegotiator.onTransportParametersEncoding());
  ServerTransportParameters serverTransportParams = {
      std::move(transportParameters)};

  EXPECT_NO_THROW(
      processServerInitialParams(clientConnection, serverTransportParams, 0));
  EXPECT_TRUE(
      clientConnection.serverMigrationState.negotiator->getNegotiatedProtocols()
          .has_value());
}

TEST_F(ClientStateMachineTest, TestReceptionOfServerMigrationSuiteWithMigrationDisabled) {
  QuicClientConnectionState clientConnection(
      FizzClientQuicHandshakeContext::Builder().build());
  ASSERT_TRUE(!clientConnection.serverMigrationState.negotiator);

  std::unordered_set<ServerMigrationProtocol> peerSupportedProtocols;
  peerSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorClient fakePeerNegotiator(
      peerSupportedProtocols);
  std::vector<TransportParameter> transportParameters;
  transportParameters.push_back(
      fakePeerNegotiator.onTransportParametersEncoding());
  ServerTransportParameters serverTransportParams = {
      std::move(transportParameters)};

  EXPECT_THROW(
      processServerInitialParams(clientConnection, serverTransportParams, 0),
      QuicTransportException);
}

TEST_F(ClientStateMachineTest, TestNoReceptionOfServerMigrationSuite) {
  QuicClientConnectionState clientConnection(
      FizzClientQuicHandshakeContext::Builder().build());
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);

  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);
  clientConnection.serverMigrationState.negotiator = std::move(negotiator);

  std::vector<TransportParameter> transportParameters;
  ServerTransportParameters serverTransportParams = {
      std::move(transportParameters)};

  EXPECT_NO_THROW(
      processServerInitialParams(clientConnection, serverTransportParams, 0));
  EXPECT_FALSE(
      clientConnection.serverMigrationState.negotiator->getNegotiatedProtocols()
          .has_value());
}

} // namespace quic::test
