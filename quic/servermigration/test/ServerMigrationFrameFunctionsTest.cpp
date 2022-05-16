#include <folly/portability/GTest.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/servermigration/ServerMigrationFrameFunctions.h>
#include <quic/servermigration/test/Mocks.h>
#include <quic/servermigration/DefaultPoolMigrationAddressScheduler.h>

using namespace testing;

namespace quic {
namespace test {

class QuicServerMigrationFrameFunctionsTest : public Test {
 public:
  QuicServerConnectionState serverState{
      FizzServerQuicHandshakeContext::Builder().build()};
  QuicClientConnectionState clientState{
      FizzClientQuicHandshakeContext::Builder().build()};
  std::unordered_set<ServerMigrationProtocol> serverSupportedProtocols;
  std::unordered_set<ServerMigrationProtocol> clientSupportedProtocols;
  DefaultCongestionControllerFactory congestionControllerFactory;
  std::shared_ptr<DefaultPoolMigrationAddressScheduler>
      poolMigrationAddressScheduler;

  void SetUp() override {
    serverState.serverConnectionId = ConnectionId::createRandom(8);
    serverState.serverMigrationState.originalConnectionId =
        serverState.serverConnectionId;
    clientState.peerAddress = folly::SocketAddress("1.2.3.4", 1234);
    serverState.peerAddress = folly::SocketAddress("5.6.7.8", 5678);
    clientState.congestionController =
        congestionControllerFactory.makeCongestionController(
            clientState,
            clientState.transportSettings.defaultCongestionController);
    serverState.congestionController =
        congestionControllerFactory.makeCongestionController(
            serverState,
            serverState.transportSettings.defaultCongestionController);
    poolMigrationAddressScheduler =
        std::make_shared<DefaultPoolMigrationAddressScheduler>();
  }

  void enableServerMigrationServerSide() {
    serverState.serverMigrationState.negotiator =
        std::make_shared<QuicServerMigrationNegotiatorServer>(
            serverSupportedProtocols);
  }

  void enableServerMigrationClientSide() {
    clientState.serverMigrationState.negotiator =
        QuicServerMigrationNegotiatorClient(clientSupportedProtocols);
  }

  void doNegotiation() {
    CHECK(
        serverState.serverMigrationState.negotiator &&
        clientState.serverMigrationState.negotiator);
    auto clientParameter = clientState.serverMigrationState.negotiator.value()
                               .onTransportParametersEncoding();
    serverState.serverMigrationState.negotiator->onMigrationSuiteReceived(
        clientParameter);
    auto serverParameter = serverState.serverMigrationState.negotiator
                               ->onTransportParametersEncoding();
    clientState.serverMigrationState.negotiator->onMigrationSuiteReceived(
        serverParameter);
  }
};

TEST_F(QuicServerMigrationFrameFunctionsTest, TestSendServerMigrationFrame) {
  ASSERT_TRUE(serverState.pendingEvents.frames.empty());
  ServerMigratedFrame frame;
  sendServerMigrationFrame(serverState, frame);
  EXPECT_FALSE(serverState.pendingEvents.frames.empty());
  EXPECT_EQ(serverState.pendingEvents.frames.size(), 1);
  EXPECT_EQ(
      *serverState.pendingEvents.frames.at(0)
           .asQuicServerMigrationFrame()
           ->asServerMigratedFrame(),
      frame);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfFrame) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, poolMigrationAddressFrame),
      QuicTransportException);

  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5001));
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, serverMigrationFrame),
      QuicTransportException);

  ServerMigratedFrame serverMigratedFrame;
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, serverMigratedFrame),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExpectedPoolMigrationAddress) {
  PoolMigrationAddressFrame poolMigrationAddressFrame1(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PoolMigrationAddressFrame poolMigrationAddressFrame2(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5001));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived)
      .Times(Exactly(2))
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame1);
      })
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame2);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(!clientState.serverMigrationState.protocolState);
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, poolMigrationAddressFrame1, 0, clientState.peerAddress));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(poolMigrationAddressFrame1.address));

  // Test reception of a duplicate.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, poolMigrationAddressFrame1, 0, clientState.peerAddress));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(poolMigrationAddressFrame1.address));

  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, poolMigrationAddressFrame2, 0, clientState.peerAddress));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(poolMigrationAddressFrame2.address));
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedPoolMigrationAddress) {
  PoolMigrationAddressFrame poolMigrationAddressFrameV4(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PoolMigrationAddressFrame poolMigrationAddressFrameV6(
      QuicIPAddress(folly::IPAddressV6("::1"), 5001));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0, clientState.peerAddress),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0, clientState.peerAddress),
      QuicTransportException);

  // Simulate successful negotiation.
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Test with protocol state not matching the frame type.
  clientState.serverMigrationState.protocolState = SymmetricClientState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0, clientState.peerAddress),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();

  // Test with a frame carrying an address of a different family wrt
  // the one used in the transport socket.
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV6, 0, clientState.peerAddress),
      QuicTransportException);

  clientState.peerAddress = folly::SocketAddress("::1", 1234);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0, clientState.peerAddress),
      QuicTransportException);
  clientState.peerAddress = folly::SocketAddress("1.2.3.4", 1234);

  // Test with a migration in progress.
  clientState.serverMigrationState.migrationInProgress = true;
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0, clientState.peerAddress),
      QuicTransportException);

  // Test with at least one migration completed.
  clientState.serverMigrationState.migrationInProgress = false;
  clientState.serverMigrationState.numberOfMigrations = 1;
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0, clientState.peerAddress),
      QuicTransportException);
  clientState.serverMigrationState.numberOfMigrations = 0;
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExpectedPoolMigrationAddressAck) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived)
      .Times(Exactly(1))
      .WillRepeatedly([&](Unused, PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame);
      });

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();

  // Test reception of a correct acknowledgement.
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asPoolOfAddressesServerState();
  protocolState->migrationAddresses.insert(
      {poolMigrationAddressFrame.address, false});
  ASSERT_EQ(protocolState->numberOfReceivedAcks, 0);
  ASSERT_NE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address),
      protocolState->migrationAddresses.end());
  ASSERT_FALSE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address)
          ->second);

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, poolMigrationAddressFrame, 0);
  EXPECT_EQ(protocolState->numberOfReceivedAcks, 1);
  EXPECT_TRUE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address)
          ->second);

  // Test reception of an acknowledgement for a duplicate.
  updateServerMigrationFrameOnPacketAckReceived(
      serverState, poolMigrationAddressFrame, 1);
  EXPECT_EQ(protocolState->numberOfReceivedAcks, 1);
  EXPECT_TRUE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address)
          ->second);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfUnexpectedPoolMigrationAddressAck) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, 0),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, 1),
      QuicTransportException);

  // Test reception without a protocol state.
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState.clear();
  ASSERT_TRUE(!serverState.serverMigrationState.protocolState);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, 2),
      QuicTransportException);

  // Test reception when there is a protocol state, but the address is unknown.
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, 3),
      QuicTransportException);

  // Test with protocol state not matching the frame type.
  serverState.serverMigrationState.protocolState = SymmetricServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, 4),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdateServerMigrationFrameOnPacketSent) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(serverState.pendingEvents.frames.empty());
  ServerMigratedFrame frame;
  sendServerMigrationFrame(serverState, frame);
  ASSERT_EQ(serverState.pendingEvents.frames.size(), 1);
  ASSERT_EQ(
      *serverState.pendingEvents.frames.at(0)
           .asQuicServerMigrationFrame()
           ->asServerMigratedFrame(),
      frame);

  updateServerMigrationFrameOnPacketSent(serverState, frame);
  EXPECT_TRUE(serverState.pendingEvents.frames.empty());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExpectedExplicitServerMigration) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrame);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(!clientState.serverMigrationState.protocolState);
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 0, clientState.peerAddress));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::ExplicitClientState);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  EXPECT_EQ(protocolState->migrationAddress, serverMigrationFrame.address);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);

  // Test reception of a duplicate.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 1, clientState.peerAddress));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::ExplicitClientState);
  protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  EXPECT_EQ(protocolState->migrationAddress, serverMigrationFrame.address);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedExplicitServerMigration) {
  ServerMigrationFrame serverMigrationFrameV4(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  ServerMigrationFrame serverMigrationFrameV6(
      QuicIPAddress(folly::IPAddressV6("::1"), 5001));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV4, 1, clientState.peerAddress),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV4, 2, clientState.peerAddress),
      QuicTransportException);

  // Simulate successful negotiation.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Test with protocol state not matching the frame type.
  clientState.serverMigrationState.protocolState = SymmetricClientState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV4, 3, clientState.peerAddress),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();

  // Test with a frame carrying an address of a different family wrt
  // the one used in the transport socket.
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV6, 4, clientState.peerAddress),
      QuicTransportException);

  clientState.peerAddress = folly::SocketAddress("::1", 1234);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV4, 5, clientState.peerAddress),
      QuicTransportException);
  clientState.peerAddress = folly::SocketAddress("1.2.3.4", 1234);

  // Test with a frame carrying the current address of the server.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          ServerMigrationFrame(QuicIPAddress(clientState.peerAddress)),
          6,
          clientState.peerAddress),
      QuicTransportException);
  Mock::VerifyAndClearExpectations(callback.get());

  // Test reception of multiple frames with different addresses.
  EXPECT_CALL(*callback, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrameV4);
      });
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrameV4, 7, clientState.peerAddress));
  EXPECT_TRUE(clientState.serverMigrationState.protocolState);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          ServerMigrationFrame(
              QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 6000)),
          8,
          clientState.peerAddress),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExpectedExplicitServerMigrationAck) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce([&](Unused, ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrame);
      });
  EXPECT_CALL(*callback, onServerMigrationReady).Times(Exactly(1));

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState =
      ExplicitServerState(serverMigrationFrame.address);

  // Test reception of a correct acknowledgement.
  auto protocolState =
      serverState.serverMigrationState.protocolState->asExplicitServerState();
  ASSERT_FALSE(protocolState->migrationAcknowledged);
  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, 0);
  EXPECT_TRUE(protocolState->migrationAcknowledged);

  // Test reception of an acknowledgement for a duplicate.
  ASSERT_TRUE(protocolState->migrationAcknowledged);
  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, 1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfUnexpectedExplicitServerMigrationAck) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverState.serverMigrationState.protocolState =
      ExplicitServerState(serverMigrationFrame.address);

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 0),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 1),
      QuicTransportException);

  // Test reception without a protocol state.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState.clear();
  ASSERT_TRUE(!serverState.serverMigrationState.protocolState);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 2),
      QuicTransportException);

  // Test reception when there is a protocol state, but the address does not
  // match.
  serverState.serverMigrationState.protocolState =
      ExplicitServerState(QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 5050));
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 3),
      QuicTransportException);

  // Test with protocol state not matching the frame type.
  serverState.serverMigrationState.protocolState = SymmetricServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 4),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExpectedSynchronizedSymmetricServerMigration) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrame);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(!clientState.serverMigrationState.protocolState);
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 0, clientState.peerAddress));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);

  // Test reception of a duplicate.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 1, clientState.peerAddress));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedSynchronizedSymmetricServerMigration) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrame, 1, clientState.peerAddress),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrame, 2, clientState.peerAddress),
      QuicTransportException);

  // Simulate successful negotiation.
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Test with protocol state not matching the frame type.
  clientState.serverMigrationState.protocolState = SymmetricClientState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrame, 3, clientState.peerAddress),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExpectedSynchronizedSymmetricServerMigrationAck) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce([&](Unused, ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrame);
      });
  EXPECT_CALL(*callback, onServerMigrationReady).Times(Exactly(1));

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState =
      SynchronizedSymmetricServerState();

  // Test reception of a correct acknowledgement.
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  ASSERT_FALSE(protocolState->migrationAcknowledged);
  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, 0);
  EXPECT_TRUE(protocolState->migrationAcknowledged);

  // Test reception of an acknowledgement for a duplicate.
  ASSERT_TRUE(protocolState->migrationAcknowledged);
  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, 1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfUnexpectedSynchronizedSymmetricServerMigrationAck) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverState.serverMigrationState.protocolState =
      SynchronizedSymmetricServerState();

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 0),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 1),
      QuicTransportException);

  // Test reception without a protocol state.
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState.clear();
  ASSERT_TRUE(!serverState.serverMigrationState.protocolState);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 2),
      QuicTransportException);

  // Test with protocol state not matching the frame type.
  serverState.serverMigrationState.protocolState = SymmetricServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, 3),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedSymmetricServerMigrated) {
  ServerMigratedFrame serverMigratedFrame;
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ASSERT_NE(serverNewAddress, clientState.peerAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, 1, serverNewAddress),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, 2, serverNewAddress),
      QuicTransportException);

  // Simulate successful negotiation.
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Test with protocol state not matching the frame type.
  clientState.serverMigrationState.protocolState =
      ExplicitClientState(QuicIPAddress(serverNewAddress));
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, 3, serverNewAddress),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();

  // Test reception from the current peer address.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, 4, clientState.peerAddress),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExpectedSymmetricServerMigrated) {
  ServerMigratedFrame serverMigratedFrame;
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ASSERT_NE(serverNewAddress, clientState.peerAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(Exactly(1));
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Test when no protocol state is present.
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, 0, serverNewAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState);
  ASSERT_TRUE(
      clientState.serverMigrationState.protocolState->asSymmetricClientState());
  auto protocolState =
      clientState.serverMigrationState.protocolState->asSymmetricClientState();
  EXPECT_TRUE(protocolState->callbackNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);

  // Test when state is already present and callback already notified.
  ASSERT_TRUE(protocolState->callbackNotified);
  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, 1, serverNewAddress);
  EXPECT_TRUE(protocolState->callbackNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
  Mock::VerifyAndClearExpectations(callback.get());

  // Test when state is present, but the callback has not been notified yet.
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(Exactly(1));
  protocolState->callbackNotified = false;
  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, 2, serverNewAddress);
  EXPECT_TRUE(protocolState->callbackNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedSynchronizedSymmetricServerMigrated) {
  ServerMigratedFrame serverMigratedFrame;
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ASSERT_NE(serverNewAddress, clientState.peerAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, 1, serverNewAddress),
      QuicTransportException);

  // Simulate successful negotiation.
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Test with protocol state not matching the frame type.
  clientState.serverMigrationState.protocolState =
      ExplicitClientState(QuicIPAddress(serverNewAddress));
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, 2, serverNewAddress),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();

  // Test reception from the current peer address.
  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, 3, clientState.peerAddress),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExpectedSynchronizedSymmetricServerMigrated) {
  ServerMigratedFrame serverMigratedFrame;
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ASSERT_NE(serverNewAddress, clientState.peerAddress);

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(Exactly(1));
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Test when state is present, but the callback has not been notified yet.
  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  ASSERT_FALSE(protocolState->callbackNotified);
  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, 0, serverNewAddress);
  EXPECT_TRUE(protocolState->callbackNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);

  // Test when state is already present and callback already notified.
  ASSERT_TRUE(protocolState->callbackNotified);
  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, 1, serverNewAddress);
  EXPECT_TRUE(protocolState->callbackNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfUnexpectedSymmetricServerMigratedAck) {
  ServerMigratedFrame serverMigratedFrame;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 0),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverState.serverMigrationState.protocolState = SymmetricServerState();
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 1),
      QuicTransportException);

  // Test reception without a protocol state.
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState.clear();
  ASSERT_TRUE(!serverState.serverMigrationState.protocolState);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 2),
      QuicTransportException);

  // Test with protocol state not matching the frame type.
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 3),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfUnexpectedSynchronizedSymmetricServerMigratedAck) {
  ServerMigratedFrame serverMigratedFrame;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 0),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverState.serverMigrationState.protocolState =
      SynchronizedSymmetricServerState();
  serverState.serverMigrationState.protocolState
      ->asSynchronizedSymmetricServerState()
      ->migrationAcknowledged = true;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 1),
      QuicTransportException);

  // Test with SERVER_MIGRATION not acknowledged.
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState
      ->asSynchronizedSymmetricServerState()
      ->migrationAcknowledged = false;
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 2),
      QuicTransportException);

  // Test reception without a protocol state.
  serverState.serverMigrationState.protocolState.clear();
  ASSERT_TRUE(!serverState.serverMigrationState.protocolState);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 3),
      QuicTransportException);

  // Test with protocol state not matching the frame type.
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, 4),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdateExplicitServerMigrationProbing) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::EXPLICIT);
        EXPECT_EQ(
            probingAddress, migrationAddress.getIPv4AddressAsSocketAddress());
      });

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();

  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      clientState.peerAddress);
  ASSERT_FALSE(protocolState->probingInProgress);
  ASSERT_FALSE(protocolState->probingFinished);
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  // Test when the probing is finished.
  protocolState->probingFinished = true;
  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_NE(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());
  protocolState->probingFinished = false;

  // Test start of the probing.
  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 0us);
  EXPECT_EQ(clientState.lossState.lrtt, 0us);
  EXPECT_EQ(clientState.lossState.rttvar, 0us);
  EXPECT_EQ(clientState.lossState.mrtt, kDefaultMinRtt);

  // Test with probing already in progress.
  ASSERT_TRUE(protocolState->probingInProgress);
  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndExplicitServerMigrationProbing) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = true;

  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      clientState.peerAddress);
  ASSERT_FALSE(protocolState->probingFinished);
  ASSERT_TRUE(protocolState->probingInProgress);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);

  // Test end probing with peer address not matching the expected one.
  folly::SocketAddress badPeerAddress("127.1.1.10", 12345);
  ASSERT_NE(badPeerAddress, migrationAddress.getIPv4AddressAsSocketAddress());
  maybeEndServerMigrationProbing(clientState, badPeerAddress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);

  // Test attempt to end probing when probing is already finished.
  protocolState->probingInProgress = false;
  protocolState->probingFinished = true;
  maybeEndServerMigrationProbing(
      clientState, migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);
  protocolState->probingInProgress = true;
  protocolState->probingFinished = false;

  // Test correct probing ending.
  maybeEndServerMigrationProbing(
      clientState, migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdatePoolOfAddressesServerMigrationProbing) {
  QuicIPAddress poolAddress(folly::IPAddressV4("1.1.1.1"), 1111);
  auto currentServerAddress = clientState.peerAddress;
  poolMigrationAddressScheduler->insert(poolAddress);
  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationProbingStarted)
      .Times(Exactly(2))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::POOL_OF_ADDRESSES);
        EXPECT_EQ(probingAddress, currentServerAddress);
      })
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::POOL_OF_ADDRESSES);
        EXPECT_EQ(probingAddress, poolAddress.getIPv4AddressAsSocketAddress());
      });
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  ASSERT_TRUE(
      poolMigrationAddressScheduler->getCurrentServerAddress().isAllZero());
  ASSERT_NE(
      clientState.peerAddress, poolAddress.getIPv4AddressAsSocketAddress());
  ASSERT_FALSE(protocolState->probingInProgress);
  ASSERT_FALSE(protocolState->probingFinished);
  ASSERT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  // Test when the probing is finished.
  protocolState->probingFinished = true;
  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_TRUE(
      poolMigrationAddressScheduler->getCurrentServerAddress().isAllZero());
  EXPECT_EQ(clientState.peerAddress, currentServerAddress);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  EXPECT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());
  protocolState->probingFinished = false;

  // Test start of the probing.
  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_EQ(
      poolMigrationAddressScheduler->getCurrentServerAddress(),
      QuicIPAddress(currentServerAddress));
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, currentServerAddress);
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_EQ(clientState.peerAddress, currentServerAddress);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 0us);
  EXPECT_EQ(clientState.lossState.lrtt, 0us);
  EXPECT_EQ(clientState.lossState.rttvar, 0us);
  EXPECT_EQ(clientState.lossState.mrtt, kDefaultMinRtt);
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 10us;
  clientState.lossState.rttvar = 10us;
  clientState.lossState.mrtt = kDefaultInitialRtt;

  // Test with probing already in progress.
  ASSERT_TRUE(protocolState->probingInProgress);
  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_EQ(
      poolMigrationAddressScheduler->getCurrentServerAddress(),
      QuicIPAddress(currentServerAddress));
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, currentServerAddress);
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_EQ(
      clientState.peerAddress, poolAddress.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 0us);
  EXPECT_EQ(clientState.lossState.lrtt, 0us);
  EXPECT_EQ(clientState.lossState.rttvar, 0us);
  EXPECT_EQ(clientState.lossState.mrtt, kDefaultMinRtt);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndPoolOfAddressesProbingWhenNoProbingInProgress) {
  QuicIPAddress poolAddress1(folly::IPAddressV4("1.1.1.1"), 1111);
  QuicIPAddress poolAddress2(folly::IPAddressV4("2.2.2.2"), 2222);
  QuicIPAddress poolAddress3(folly::IPAddressV4("3.3.3.3"), 3333);
  auto currentServerAddress = clientState.peerAddress;
  poolMigrationAddressScheduler->setCurrentServerAddress(
      QuicIPAddress(currentServerAddress));
  poolMigrationAddressScheduler->insert(poolAddress1);
  poolMigrationAddressScheduler->insert(poolAddress2);
  poolMigrationAddressScheduler->insert(poolAddress3);
  poolMigrationAddressScheduler->next(); // Returns currentServerAddress
  poolMigrationAddressScheduler->next(); // Returns poolAddress1
  clientState.peerAddress =
      poolMigrationAddressScheduler->next()
          .getIPv4AddressAsSocketAddress(); // Returns poolAddress2
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());
  clientState.serverMigrationState.migrationInProgress = false;
  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = currentServerAddress;
  ASSERT_NE(currentServerAddress, poolAddress1.getIPv4AddressAsSocketAddress());
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);

  protocolState->probingFinished = true;
  protocolState->probingInProgress = true;
  maybeEndServerMigrationProbing(
      clientState, poolAddress1.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      clientState.peerAddress, poolAddress2.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, currentServerAddress);
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_EQ(
      poolMigrationAddressScheduler->getCurrentServerAddress(),
      QuicIPAddress(currentServerAddress));
  EXPECT_EQ(poolMigrationAddressScheduler->next(), poolAddress3);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);

  protocolState->probingFinished = false;
  protocolState->probingInProgress = false;
  maybeEndServerMigrationProbing(
      clientState, poolAddress1.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      clientState.peerAddress, poolAddress2.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, currentServerAddress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_EQ(
      poolMigrationAddressScheduler->getCurrentServerAddress(),
      QuicIPAddress(currentServerAddress));
  EXPECT_EQ(
      poolMigrationAddressScheduler->next(),
      QuicIPAddress(currentServerAddress));
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndPoolOfAddressesProbingWithCurrentServerAddress) {
  QuicIPAddress poolAddress1(folly::IPAddressV4("1.1.1.1"), 1111);
  QuicIPAddress poolAddress2(folly::IPAddressV4("2.2.2.2"), 2222);
  QuicIPAddress poolAddress3(folly::IPAddressV4("3.3.3.3"), 3333);
  auto currentServerAddress = clientState.peerAddress;
  poolMigrationAddressScheduler->setCurrentServerAddress(
      QuicIPAddress(currentServerAddress));
  poolMigrationAddressScheduler->insert(poolAddress1);
  poolMigrationAddressScheduler->insert(poolAddress2);
  poolMigrationAddressScheduler->insert(poolAddress3);
  poolMigrationAddressScheduler->next(); // Returns currentServerAddress
  poolMigrationAddressScheduler->next(); // Returns poolAddress1
  clientState.peerAddress =
      poolMigrationAddressScheduler->next()
          .getIPv4AddressAsSocketAddress(); // Returns poolAddress2
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());
  clientState.serverMigrationState.migrationInProgress = false;
  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = currentServerAddress;
  protocolState->probingFinished = false;
  protocolState->probingInProgress = true;

  ASSERT_NE(clientState.peerAddress, currentServerAddress);
  maybeEndServerMigrationProbing(clientState, currentServerAddress);
  EXPECT_EQ(clientState.peerAddress, currentServerAddress);
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(
      poolMigrationAddressScheduler->getCurrentServerAddress().isAllZero());
  EXPECT_EQ(poolMigrationAddressScheduler->next(), poolAddress1);
  EXPECT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndPoolOfAddressesProbingWithNewServerAddress) {
  QuicIPAddress poolAddress1(folly::IPAddressV4("1.1.1.1"), 1111);
  QuicIPAddress poolAddress2(folly::IPAddressV4("2.2.2.2"), 2222);
  QuicIPAddress poolAddress3(folly::IPAddressV4("3.3.3.3"), 3333);
  auto currentServerAddress = clientState.peerAddress;
  poolMigrationAddressScheduler->setCurrentServerAddress(
      QuicIPAddress(currentServerAddress));
  poolMigrationAddressScheduler->insert(poolAddress1);
  poolMigrationAddressScheduler->insert(poolAddress2);
  poolMigrationAddressScheduler->insert(poolAddress3);
  poolMigrationAddressScheduler->next(); // Returns currentServerAddress
  poolMigrationAddressScheduler->next(); // Returns poolAddress1
  clientState.peerAddress =
      poolMigrationAddressScheduler->next()
          .getIPv4AddressAsSocketAddress(); // Returns poolAddress2
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());
  clientState.serverMigrationState.migrationInProgress = false;
  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = currentServerAddress;
  protocolState->probingFinished = false;
  protocolState->probingInProgress = true;

  ASSERT_NE(
      clientState.peerAddress, poolAddress1.getIPv4AddressAsSocketAddress());
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  maybeEndServerMigrationProbing(
      clientState, poolAddress1.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      clientState.peerAddress, poolAddress1.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(
      poolMigrationAddressScheduler->getCurrentServerAddress().isAllZero());
  EXPECT_EQ(poolMigrationAddressScheduler->next(), poolAddress1);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndServerMigrationClientSide) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  clientState.serverMigrationState.migrationInProgress = true;
  clientState.pathValidationLimiter =
      std::make_unique<quic::PendingPathRateLimiter>(
          clientState.udpSendPacketLen);
  clientState.serverMigrationState.largestProcessedPacketNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationCompleted()).Times(Exactly(1));
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  ASSERT_TRUE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState);
  ASSERT_TRUE(clientState.pathValidationLimiter);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_EQ(clientState.serverMigrationState.largestProcessedPacketNumber, 0);

  endServerMigration(clientState, 1);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.pathValidationLimiter);
  EXPECT_EQ(clientState.serverMigrationState.numberOfMigrations, 1);
  EXPECT_EQ(clientState.serverMigrationState.largestProcessedPacketNumber, 1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndServerMigrationServerSide) {
  serverState.serverMigrationState.protocolState = SymmetricServerState();
  serverState.serverMigrationState.migrationInProgress = true;
  serverState.serverMigrationState.largestProcessedPacketNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationCompleted(_)).Times(Exactly(1));
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  ASSERT_TRUE(serverState.serverMigrationState.migrationInProgress);
  ASSERT_TRUE(serverState.serverMigrationState.protocolState);
  ASSERT_EQ(serverState.serverMigrationState.largestProcessedPacketNumber, 0);

  endServerMigration(serverState, 1);
  EXPECT_FALSE(serverState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(serverState.serverMigrationState.protocolState);
  EXPECT_EQ(serverState.serverMigrationState.largestProcessedPacketNumber, 1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndServerMigrationDoesNotClearPoolOfAddressesState) {
  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  clientState.serverMigrationState.largestProcessedPacketNumber = 0;
  endServerMigration(clientState, 1);
  EXPECT_TRUE(clientState.serverMigrationState.protocolState);
  EXPECT_TRUE(clientState.serverMigrationState.protocolState
                  ->asPoolOfAddressesClientState());

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  serverState.serverMigrationState.largestProcessedPacketNumber = 0;
  endServerMigration(serverState, 1);
  EXPECT_TRUE(serverState.serverMigrationState.protocolState);
  EXPECT_TRUE(serverState.serverMigrationState.protocolState
                  ->asPoolOfAddressesServerState());
}

} // namespace test
} // namespace quic
