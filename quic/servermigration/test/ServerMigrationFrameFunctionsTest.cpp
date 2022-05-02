#include <folly/portability/GTest.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/servermigration/ServerMigrationFrameFunctions.h>
#include <quic/servermigration/test/Mocks.h>

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

  void SetUp() override {
    serverState.serverConnectionId = ConnectionId::createRandom(8);
    clientState.peerAddress = folly::SocketAddress("1.2.3.4", 1234);
    serverState.peerAddress = folly::SocketAddress("5.6.7.8", 5678);
  }

  void enableServerMigrationServerSide() {
    serverState.serverMigrationState.negotiator =
        QuicServerMigrationNegotiatorServer(serverSupportedProtocols);
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

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onPoolMigrationAddressReceived)
      .Times(Exactly(2))
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame1);
      })
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame2);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = &callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(!clientState.serverMigrationState.protocolState);
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, poolMigrationAddressFrame1, 0));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.size(),
      1);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.count(poolMigrationAddressFrame1.address));

  // Test reception of a duplicate.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, poolMigrationAddressFrame1, 0));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.size(),
      1);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.count(poolMigrationAddressFrame1.address));

  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, poolMigrationAddressFrame2, 0));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.size(),
      2);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->migrationAddresses.count(poolMigrationAddressFrame2.address));
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedPoolMigrationAddress) {
  PoolMigrationAddressFrame poolMigrationAddressFrameV4(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PoolMigrationAddressFrame poolMigrationAddressFrameV6(
      QuicIPAddress(folly::IPAddressV6("::1"), 5001));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = &callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0),
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
          clientState, poolMigrationAddressFrameV4, 0),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();

  // Test with a frame carrying an address of a different family wrt
  // the one used in the transport socket.
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV6, 0),
      QuicTransportException);

  clientState.peerAddress = folly::SocketAddress("::1", 1234);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0),
      QuicTransportException);
  clientState.peerAddress = folly::SocketAddress("1.2.3.4", 1234);

  // Test with a migration in progress.
  clientState.serverMigrationState.migrationInProgress = true;
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0),
      QuicTransportException);

  // Test with at least one migration completed.
  clientState.serverMigrationState.migrationInProgress = false;
  clientState.serverMigrationState.numberOfMigrations = 1;
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrameV4, 0),
      QuicTransportException);
  clientState.serverMigrationState.numberOfMigrations = 0;
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExpectedPoolMigrationAddressAck) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onPoolMigrationAddressAckReceived)
      .Times(Exactly(1))
      .WillRepeatedly([&](Unused, PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame);
      });

  serverState.serverMigrationState.serverMigrationEventCallback = &callback;
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
      serverState, poolMigrationAddressFrame);
  EXPECT_EQ(protocolState->numberOfReceivedAcks, 1);
  EXPECT_TRUE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address)
          ->second);

  // Simulate reception of a duplicate acknowledgement.
  updateServerMigrationFrameOnPacketAckReceived(
      serverState, poolMigrationAddressFrame);
  EXPECT_EQ(protocolState->numberOfReceivedAcks, 1);
  EXPECT_TRUE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address)
          ->second);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfUnexpectedPoolMigrationAddressAck) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onPoolMigrationAddressReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = &callback;
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, poolMigrationAddressFrame),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, poolMigrationAddressFrame),
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
          serverState, poolMigrationAddressFrame),
      QuicTransportException);

  // Test reception when there is a protocol state, but the address is unknown.
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame),
      QuicTransportException);

  // Test with protocol state not matching the frame type.
  serverState.serverMigrationState.protocolState = SymmetricServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame),
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

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrame);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = &callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(!clientState.serverMigrationState.protocolState);
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 0));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::ExplicitClientState);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState->asExplicitClientState()
          ->migrationAddress,
      serverMigrationFrame.address);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);

  // Test reception of a duplicate.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 1));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::ExplicitClientState);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState->asExplicitClientState()
          ->migrationAddress,
      serverMigrationFrame.address);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedExplicitServerMigration)   {
  ServerMigrationFrame serverMigrationFrameV4(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  ServerMigrationFrame serverMigrationFrameV6(
      QuicIPAddress(folly::IPAddressV6("::1"), 5001));

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV4, 1),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV4, 2),
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
          clientState, serverMigrationFrameV4, 3),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();

  // Test with a frame carrying an address of a different family wrt
  // the one used in the transport socket.
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV6, 4),
      QuicTransportException);

  clientState.peerAddress = folly::SocketAddress("::1", 1234);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrameV4, 5),
      QuicTransportException);
  clientState.peerAddress = folly::SocketAddress("1.2.3.4", 1234);

  // Test reception of multiple frames with different addresses.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrameV4, 6));
  EXPECT_TRUE(clientState.serverMigrationState.protocolState);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          ServerMigrationFrame(
              QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 6000)),
          7),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExpectedExplicitServerMigrationAck) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce([&](Unused, ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrame);
      });
  EXPECT_CALL(callback, onServerMigrationReady).Times(Exactly(1));

  serverState.serverMigrationState.serverMigrationEventCallback = &callback;
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
      serverState, serverMigrationFrame);
  EXPECT_TRUE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfUnexpectedExplicitServerMigrationAck) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onServerMigrationAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = &callback;
  serverState.serverMigrationState.protocolState =
      ExplicitServerState(serverMigrationFrame.address);

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, serverMigrationFrame),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, serverMigrationFrame),
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
          serverState, serverMigrationFrame),
      QuicTransportException);

  // Test reception when there is a protocol state, but the address does not
  // match.
  serverState.serverMigrationState.protocolState =
      ExplicitServerState(QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 5050));
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame),
      QuicTransportException);

  // Test with protocol state not matching the frame type.
  serverState.serverMigrationState.protocolState = SymmetricServerState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExpectedSynchronizedSymmetricServerMigration) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_TRUE(frame == serverMigrationFrame);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = &callback;
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(!clientState.serverMigrationState.protocolState);
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 0));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);

  // Test reception of a duplicate.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, 1));
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfUnexpectedSynchronizedSymmetricServerMigration)   {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrame, 1),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigrationFrame, 2),
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
          clientState, serverMigrationFrame, 3),
      QuicTransportException);
  clientState.serverMigrationState.protocolState.clear();
}

} // namespace test
} // namespace quic
