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

TEST_F(QuicServerMigrationFrameFunctionsTest, TestExpectedSendServerMigrationFrame) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

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

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUnexpectedSendServerMigrationFrame) {
  ASSERT_TRUE(serverState.pendingEvents.frames.empty());

  // Test with server migration not enabled.
  ServerMigratedFrame frame;
  EXPECT_THROW(
      sendServerMigrationFrame(serverState, frame), QuicTransportException);
  EXPECT_TRUE(serverState.pendingEvents.frames.empty());

  // Test with negotiated protocol not matching the frame type.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      sendServerMigrationFrame(serverState, frame), QuicTransportException);
  EXPECT_TRUE(serverState.pendingEvents.frames.empty());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfFrame) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, poolMigrationAddressFrame),
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
      clientState, poolMigrationAddressFrame1));
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
      clientState, poolMigrationAddressFrame2));
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
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = &callback;

  // Test with server migration disabled.
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrame),
      QuicTransportException);

  // Test with frame type belonging to a not negotiated protocol.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, poolMigrationAddressFrame),
      QuicTransportException);

  // TODO add test with protocol state not matching frame type, so where
  // clientState.serverMigrationState.protocolState !=
  // QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExpectedPoolMigrationAddressAck) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onPoolMigrationAddressAckReceived)
      .Times(Exactly(2))
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

  // TODO add test with protocol state not matching frame type, so where
  // serverState.serverMigrationState.protocolState !=
  // QuicServerMigrationProtocolServerState::Type::PoolOfAddressesServerState
}

} // namespace test
} // namespace quic
