#include <folly/portability/GTest.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/servermigration/DefaultPoolMigrationAddressScheduler.h>
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
  EXPECT_EQ(serverState.pendingEvents.frames.size(), 1);
  EXPECT_EQ(
      *serverState.pendingEvents.frames.at(0)
           .asQuicServerMigrationFrame()
           ->asServerMigratedFrame(),
      frame);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfMigrationFrame) {
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

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddresses) {
  PoolMigrationAddressFrame firstPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PoolMigrationAddressFrame secondPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5001));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived)
      .Times(Exactly(2))
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == firstPoolMigrationAddressFrame);
      })
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == secondPoolMigrationAddressFrame);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  updateServerMigrationFrameOnPacketReceived(
      clientState,
      firstPoolMigrationAddressFrame,
      packetNumber,
      clientState.peerAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(firstPoolMigrationAddressFrame.address));
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);

  updateServerMigrationFrameOnPacketReceived(
      clientState,
      secondPoolMigrationAddressFrame,
      packetNumber,
      clientState.peerAddress);
  EXPECT_TRUE(clientState.serverMigrationState.protocolState
                  ->asPoolOfAddressesClientState()
                  ->addressScheduler->contains(
                      secondPoolMigrationAddressFrame.address));
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddressesSpanningMultiplePackets) {
  PoolMigrationAddressFrame firstPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum firstPacketNumber = 1;

  PoolMigrationAddressFrame secondPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5001));
  PacketNum secondPacketNumber = 2;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived)
      .Times(Exactly(2))
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == firstPoolMigrationAddressFrame);
      })
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == secondPoolMigrationAddressFrame);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  updateServerMigrationFrameOnPacketReceived(
      clientState,
      firstPoolMigrationAddressFrame,
      firstPacketNumber,
      clientState.peerAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(firstPoolMigrationAddressFrame.address));
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      firstPacketNumber);

  updateServerMigrationFrameOnPacketReceived(
      clientState,
      secondPoolMigrationAddressFrame,
      secondPacketNumber,
      clientState.peerAddress);
  EXPECT_TRUE(clientState.serverMigrationState.protocolState
                  ->asPoolOfAddressesClientState()
                  ->addressScheduler->contains(
                      secondPoolMigrationAddressFrame.address));
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      secondPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddressesSpanningMultipleOutOfOrderPackets) {
  PoolMigrationAddressFrame firstPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum firstPacketNumber = 1;

  PoolMigrationAddressFrame secondPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5001));
  PacketNum secondPacketNumber = 2;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived)
      .Times(Exactly(2))
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == secondPoolMigrationAddressFrame);
      })
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == firstPoolMigrationAddressFrame);
      });

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  // Out of order reception: first whe receive the packet marked by
  // "secondPacketNumber", then the packet marked by "firstPacketNumber".
  updateServerMigrationFrameOnPacketReceived(
      clientState,
      secondPoolMigrationAddressFrame,
      secondPacketNumber,
      clientState.peerAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  EXPECT_TRUE(clientState.serverMigrationState.protocolState
                  ->asPoolOfAddressesClientState()
                  ->addressScheduler->contains(
                      secondPoolMigrationAddressFrame.address));
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      secondPacketNumber);

  updateServerMigrationFrameOnPacketReceived(
      clientState,
      firstPoolMigrationAddressFrame,
      firstPacketNumber,
      clientState.peerAddress);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(firstPoolMigrationAddressFrame.address));
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      secondPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfDuplicatePoolMigrationAddress) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  clientState.serverMigrationState.protocolState->asPoolOfAddressesClientState()
      ->addressScheduler->insert(poolMigrationAddressFrame.address);
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  updateServerMigrationFrameOnPacketReceived(
      clientState,
      poolMigrationAddressFrame,
      packetNumber,
      clientState.peerAddress);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState
          ->asPoolOfAddressesClientState()
          ->addressScheduler->contains(poolMigrationAddressFrame.address));
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddressWithServerMigrationDisabled) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  ASSERT_FALSE(clientState.serverMigrationState.negotiator);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          poolMigrationAddressFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddressWithPoolOfAddressesNotNegotiated) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          poolMigrationAddressFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddressWhenAnotherProtocolIsInUse) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  clientState.serverMigrationState.protocolState = SymmetricClientState();
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          poolMigrationAddressFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::SymmetricClientState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddressWithUnexpectedIPFamily) {
  PoolMigrationAddressFrame poolMigrationAddressFrameV4(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PoolMigrationAddressFrame poolMigrationAddressFrameV6(
      QuicIPAddress(folly::IPAddressV6("::1"), 5001));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);

  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          poolMigrationAddressFrameV6,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);

  clientState.peerAddress = folly::SocketAddress("::1", 1234);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV6());
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          poolMigrationAddressFrameV4,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddressDuringOrAfterAMigration) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());

  // Test with a migration in progress.
  clientState.serverMigrationState.migrationInProgress = true;
  ASSERT_EQ(clientState.serverMigrationState.numberOfMigrations, 0);
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          poolMigrationAddressFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);

  // Test with at least one migration completed.
  clientState.serverMigrationState.migrationInProgress = false;
  clientState.serverMigrationState.numberOfMigrations = 1;
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          poolMigrationAddressFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfPoolMigrationAddressAck) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived)
      .Times(Exactly(1))
      .WillOnce([&](Unused, PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame);
      });

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asPoolOfAddressesServerState();
  protocolState->migrationAddresses.insert(
      {poolMigrationAddressFrame.address, false});

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_EQ(protocolState->numberOfReceivedAcks, 0);

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, poolMigrationAddressFrame, packetNumber);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_EQ(protocolState->numberOfReceivedAcks, 1);
  EXPECT_TRUE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address)
          ->second);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfDuplicatePoolMigrationAddressAck) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asPoolOfAddressesServerState();
  protocolState->migrationAddresses.insert(
      {poolMigrationAddressFrame.address, true});
  protocolState->numberOfReceivedAcks = 1;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, poolMigrationAddressFrame, packetNumber);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_EQ(protocolState->numberOfReceivedAcks, 1);
  EXPECT_TRUE(
      protocolState->migrationAddresses.find(poolMigrationAddressFrame.address)
          ->second);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfPoolMigrationAddressAckWithServerMigrationDisabled) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  serverState.serverMigrationState.protocolState->asPoolOfAddressesServerState()
      ->migrationAddresses.insert({poolMigrationAddressFrame.address, false});

  ASSERT_FALSE(serverState.serverMigrationState.negotiator);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, packetNumber),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfPoolMigrationAddressAckWithPoolOfAddressesNotNegotiated) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  serverState.serverMigrationState.protocolState->asPoolOfAddressesServerState()
      ->migrationAddresses.insert({poolMigrationAddressFrame.address, false});
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, packetNumber),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfPoolMigrationAddressAckWithoutProtocolState) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(serverState.serverMigrationState.protocolState);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, packetNumber),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfPoolMigrationAddressAckWhenAnotherProtocolIsInUse) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = SymmetricServerState();
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, packetNumber),
      QuicTransportException);
  EXPECT_EQ(
      serverState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolServerState::Type::SymmetricServerState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfPoolMigrationAddressAckForUnkownAddress) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, poolMigrationAddressFrame, packetNumber),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdateServerMigrationFrameOnPacketSent) {
  ServerMigratedFrame frame;
  serverState.pendingEvents.frames.push_back(QuicServerMigrationFrame(frame));
  ASSERT_EQ(serverState.pendingEvents.frames.size(), 1);
  updateServerMigrationFrameOnPacketSent(serverState, frame);
  EXPECT_TRUE(serverState.pendingEvents.frames.empty());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExplicitServerMigration) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

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

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  ASSERT_NE(
      clientState.peerAddress,
      serverMigrationFrame.address.getIPv4AddressAsSocketAddress());

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, packetNumber, clientState.peerAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::ExplicitClientState);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  EXPECT_EQ(protocolState->migrationAddress, serverMigrationFrame.address);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfDuplicateExplicitServerMigration) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(serverMigrationFrame.address);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = false;
  protocolState->probingFinished = false;
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;
  clientState.serverMigrationState.migrationInProgress = true;

  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  ASSERT_NE(
      clientState.peerAddress,
      serverMigrationFrame.address.getIPv4AddressAsSocketAddress());

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, packetNumber, clientState.peerAddress);
  EXPECT_EQ(protocolState->migrationAddress, serverMigrationFrame.address);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExplicitServerMigrationWithMigrationDisabled) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  ASSERT_FALSE(clientState.serverMigrationState.negotiator);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  ASSERT_NE(
      clientState.peerAddress,
      serverMigrationFrame.address.getIPv4AddressAsSocketAddress());

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExplicitServerMigrationWithExplicitNotNegotiated) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  ASSERT_NE(
      clientState.peerAddress,
      serverMigrationFrame.address.getIPv4AddressAsSocketAddress());

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExplicitServerMigrationWhenAnotherProtocolIsInUse) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  clientState.serverMigrationState.protocolState = SymmetricClientState();

  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  ASSERT_NE(
      clientState.peerAddress,
      serverMigrationFrame.address.getIPv4AddressAsSocketAddress());

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::SymmetricClientState);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExplicitServerMigrationWithUnexpectedIPFamily) {
  ServerMigrationFrame serverMigrationFrameV6(
      QuicIPAddress(folly::IPAddressV6("::1"), 5001));
  PacketNum packetNumberV6 = 1;

  ServerMigrationFrame serverMigrationFrameV4(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumberV4 = 2;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  ASSERT_NE(
      clientState.peerAddress,
      serverMigrationFrameV4.address.getIPv4AddressAsSocketAddress());

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrameV6,
          packetNumberV6,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);

  clientState.peerAddress = folly::SocketAddress("::1", 1234);
  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV6());
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrameV4,
          packetNumberV4,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfExplicitServerMigrationCarryingCurrentAddressOfTheServer) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(clientState.peerAddress));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfMultipleExplicitServerMigrationCarryingDifferentAddresses) {
  ServerMigrationFrame firstServerMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  ServerMigrationFrame secondServerMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5000));
  PacketNum secondPacketNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_TRUE(clientState.peerAddress.getIPAddress().isV4());
  ASSERT_NE(
      clientState.peerAddress,
      firstServerMigrationFrame.address.getIPv4AddressAsSocketAddress());
  ASSERT_NE(
      clientState.peerAddress,
      secondServerMigrationFrame.address.getIPv4AddressAsSocketAddress());

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(firstServerMigrationFrame.address);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = false;
  protocolState->probingFinished = false;
  clientState.serverMigrationState.largestProcessedPacketNumber =
      secondPacketNumber - 1;
  clientState.serverMigrationState.migrationInProgress = true;

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          secondServerMigrationFrame,
          secondPacketNumber,
          clientState.peerAddress),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExplicitServerMigrationAck) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

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
  auto protocolState =
      serverState.serverMigrationState.protocolState->asExplicitServerState();
  ASSERT_FALSE(protocolState->migrationAcknowledged);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, packetNumber);
  EXPECT_TRUE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfDuplicateExplicitServerMigrationAck) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState =
      ExplicitServerState(serverMigrationFrame.address);
  auto protocolState =
      serverState.serverMigrationState.protocolState->asExplicitServerState();
  protocolState->migrationAcknowledged = true;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, packetNumber);
  EXPECT_TRUE(protocolState->migrationAcknowledged);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExplicitServerMigrationAckWithMigrationDisabled) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverState.serverMigrationState.protocolState =
      ExplicitServerState(serverMigrationFrame.address);
  auto protocolState =
      serverState.serverMigrationState.protocolState->asExplicitServerState();

  ASSERT_FALSE(serverState.serverMigrationState.negotiator);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->migrationAcknowledged);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExplicitServerMigrationAckWithExplicitNotNegotiated) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState =
      ExplicitServerState(serverMigrationFrame.address);
  auto protocolState =
      serverState.serverMigrationState.protocolState->asExplicitServerState();

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->migrationAcknowledged);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExplicitServerMigrationAckWithoutProtocolState) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(serverState.serverMigrationState.protocolState);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(serverState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExplicitServerMigrationAckWhenAnotherProtocolIsInUse) {
  ServerMigrationFrame serverMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = SymmetricServerState();
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_EQ(
      serverState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolServerState::Type::SymmetricServerState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfExplicitServerMigrationAckForWrongAddress) {
  ServerMigrationFrame originalServerMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  ServerMigrationFrame wrongServerMigrationFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5001));
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState =
      ExplicitServerState(originalServerMigrationFrame.address);
  auto protocolState =
      serverState.serverMigrationState.protocolState->asExplicitServerState();

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->migrationAcknowledged);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, wrongServerMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigration) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

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

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, packetNumber, clientState.peerAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState.has_value());
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::
          SynchronizedSymmetricClientState);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  EXPECT_FALSE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfDuplicateSynchronizedSymmetricServerMigration) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);

  clientState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  protocolState->onServerMigratedReceivedNotified = false;
  protocolState->pathValidationStarted = false;
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;
  clientState.serverMigrationState.migrationInProgress = true;

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigrationFrame, packetNumber, clientState.peerAddress);
  EXPECT_FALSE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigrationWithMigrationDisabled) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  ASSERT_FALSE(clientState.serverMigrationState.negotiator);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigrationWithSynchronizedSymmetricNotNegotiated) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigrationWhenAnotherProtocolIsInUse) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState = SymmetricClientState();
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigrationFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigrationAck) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

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
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  ASSERT_FALSE(protocolState->migrationAcknowledged);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, packetNumber);
  EXPECT_TRUE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfDuplicateSynchronizedSymmetricServerMigrationAck) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

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
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  protocolState->migrationAcknowledged = true;
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigrationFrame, packetNumber);
  EXPECT_TRUE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigrationAckWithMigrationDisabled) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverState.serverMigrationState.protocolState =
      SynchronizedSymmetricServerState();
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();

  ASSERT_FALSE(serverState.serverMigrationState.negotiator);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->migrationAcknowledged);
  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->migrationAcknowledged);
  EXPECT_FALSE(protocolState->onServerMigratedAckReceivedNotified);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigrationAckWithSynchronizedSymmetricNotNegotiated) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState =
      SynchronizedSymmetricServerState();
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->migrationAcknowledged);
  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->migrationAcknowledged);
  EXPECT_FALSE(protocolState->onServerMigratedAckReceivedNotified);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigrationAckWithoutProtocolState) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(serverState.serverMigrationState.protocolState);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(serverState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigrationAckWhenAnotherProtocolIsInUse) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationAckReceived).Times(0);
  EXPECT_CALL(*callback, onServerMigrationReady).Times(0);

  serverState.serverMigrationState.serverMigrationEventCallback = callback;
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  serverState.serverMigrationState.protocolState = SymmetricServerState();

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigrationFrame, packetNumber),
      QuicTransportException);
  EXPECT_EQ(
      serverState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolServerState::Type::SymmetricServerState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSymmetricServerMigrated) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(Exactly(1));
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, packetNumber, serverNewAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState);
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::SymmetricClientState);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asSymmetricClientState();
  EXPECT_TRUE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfDuplicateSymmetricServerMigrated) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState = SymmetricClientState();
  auto protocolState =
      clientState.serverMigrationState.protocolState->asSymmetricClientState();
  protocolState->onServerMigratedReceivedNotified = true;
  protocolState->pathValidationStarted = false;
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_NE(serverNewAddress, clientState.peerAddress);

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, packetNumber, serverNewAddress);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_TRUE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSymmetricServerMigratedWithMigrationDisabled) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.negotiator);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, packetNumber, serverNewAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSymmetricServerMigratedWithSymmetricNotNegotiated) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, packetNumber, serverNewAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSymmetricServerMigratedWhenAnotherProtocolIsInUse) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();
  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, packetNumber, serverNewAddress),
      QuicTransportException);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSymmetricServerMigratedFromCurrentPeerAddress) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigratedFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigrated) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

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

  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(protocolState->onServerMigratedReceivedNotified);
  ASSERT_FALSE(protocolState->pathValidationStarted);

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, packetNumber, serverNewAddress);
  EXPECT_TRUE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfDuplicateSynchronizedSymmetricServerMigrated) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 2;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  protocolState->onServerMigratedReceivedNotified = true;
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(protocolState->pathValidationStarted);

  updateServerMigrationFrameOnPacketReceived(
      clientState, serverMigratedFrame, packetNumber, serverNewAddress);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_TRUE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigratedWithMigrationDisabled) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.negotiator);
  ASSERT_FALSE(protocolState->onServerMigratedReceivedNotified);
  ASSERT_FALSE(protocolState->pathValidationStarted);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, packetNumber, serverNewAddress),
      QuicTransportException);
  EXPECT_FALSE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigratedWhenAnotherProtocolIsInUse) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(QuicIPAddress(serverNewAddress));

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState, serverMigratedFrame, packetNumber, serverNewAddress),
      QuicTransportException);
  EXPECT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::ExplicitClientState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfSynchronizedSymmetricServerMigratedFromCurrentPeerAddress) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_FALSE(protocolState->onServerMigratedReceivedNotified);
  ASSERT_FALSE(protocolState->pathValidationStarted);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          clientState,
          serverMigratedFrame,
          packetNumber,
          clientState.peerAddress),
      QuicTransportException);
  EXPECT_FALSE(protocolState->onServerMigratedReceivedNotified);
  EXPECT_FALSE(protocolState->pathValidationStarted);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSymmetricServerMigratedAck) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(Exactly(1));
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = SymmetricServerState();
  auto protocolState =
      serverState.serverMigrationState.protocolState->asSymmetricServerState();

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigratedFrame, packetNumber);
  EXPECT_TRUE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfDuplicateSymmetricServerMigratedAck) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = SymmetricServerState();
  auto protocolState =
      serverState.serverMigrationState.protocolState->asSymmetricServerState();
  protocolState->onServerMigratedAckReceivedNotified = true;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigratedFrame, packetNumber);
  EXPECT_TRUE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSymmetricServerMigratedAckWithMigrationDisabled) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverState.serverMigrationState.protocolState = SymmetricServerState();
  auto protocolState =
      serverState.serverMigrationState.protocolState->asSymmetricServerState();

  ASSERT_FALSE(serverState.serverMigrationState.negotiator);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSymmetricServerMigratedAckWithSymmetricNotNegotiated) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = SymmetricServerState();
  auto protocolState =
      serverState.serverMigrationState.protocolState->asSymmetricServerState();

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->onServerMigratedAckReceivedNotified);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSymmetricServerMigratedAckWithoutProtocolState) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  ASSERT_FALSE(serverState.serverMigrationState.protocolState);
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(serverState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSymmetricServerMigratedAckWhenAnotherProtocolIsInUse) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 0;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_EQ(
      serverState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolServerState::Type::PoolOfAddressesServerState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigratedAck) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(Exactly(1));
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
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  protocolState->migrationAcknowledged = true;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigratedFrame, packetNumber);
  EXPECT_TRUE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfDuplicateSynchronizedSymmetricServerMigratedAck) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 2;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
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
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  protocolState->migrationAcknowledged = true;
  protocolState->onServerMigratedAckReceivedNotified = true;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  updateServerMigrationFrameOnPacketAckReceived(
      serverState, serverMigratedFrame, packetNumber);
  EXPECT_TRUE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigratedAckWithMigrationDisabled) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverState.serverMigrationState.protocolState =
      SynchronizedSymmetricServerState();
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  protocolState->migrationAcknowledged = true;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_FALSE(serverState.serverMigrationState.negotiator);
  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_TRUE(protocolState->migrationAcknowledged);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber - 1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigratedAckWithSynchronizedSymmetricNotNegotiated) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState =
      SynchronizedSymmetricServerState();
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  protocolState->migrationAcknowledged = true;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_TRUE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigratedAckWithoutProtocolState) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;
  ASSERT_FALSE(serverState.serverMigrationState.protocolState);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(serverState.serverMigrationState.protocolState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigratedAckWhenAnotherProtocolIsInUse) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  serverState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_EQ(
      serverState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolServerState::Type::PoolOfAddressesServerState);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfSynchronizedSymmetricServerMigratedAckWhenMigrationNotAcknowledged) {
  ServerMigratedFrame serverMigratedFrame;
  PacketNum packetNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedAckReceived).Times(0);
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
  auto protocolState = serverState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricServerState();
  protocolState->migrationAcknowledged = false;

  ASSERT_FALSE(serverState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(protocolState->onServerMigratedAckReceivedNotified);

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketAckReceived(
          serverState, serverMigratedFrame, packetNumber),
      QuicTransportException);
  EXPECT_FALSE(protocolState->onServerMigratedAckReceivedNotified);
  EXPECT_FALSE(protocolState->migrationAcknowledged);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestStartExplicitServerMigrationProbing) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto peerAddressBeforeProbing = clientState.peerAddress;

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

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();

  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      clientState.peerAddress);
  ASSERT_FALSE(protocolState->probingInProgress);
  ASSERT_FALSE(protocolState->probingFinished);
  ASSERT_FALSE(protocolState->onServerMigrationProbingStartedNotified);
  ASSERT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->onServerMigrationProbingStartedNotified);
  EXPECT_EQ(
      protocolState->serverAddressBeforeProbing, peerAddressBeforeProbing);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 0us);
  EXPECT_EQ(clientState.lossState.lrtt, 0us);
  EXPECT_EQ(clientState.lossState.rttvar, 0us);
  EXPECT_EQ(clientState.lossState.mrtt, kDefaultMinRtt);
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdateExplicitServerMigrationProbingWhenProbingInProgress) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto peerAddressBeforeProbing = clientState.peerAddress;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationProbingStarted).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = true;
  protocolState->onServerMigrationProbingStartedNotified = true;
  protocolState->probingFinished = false;
  protocolState->serverAddressBeforeProbing = peerAddressBeforeProbing;
  clientState.peerAddress = migrationAddress.getIPv4AddressAsSocketAddress();
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      peerAddressBeforeProbing);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());

  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->onServerMigrationProbingStartedNotified);
  EXPECT_EQ(
      protocolState->serverAddressBeforeProbing, peerAddressBeforeProbing);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 100us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdateExplicitServerMigrationProbingWhenProbingAlreadyFinished) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto peerAddressBeforeProbing = clientState.peerAddress;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationProbingStarted).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = false;
  protocolState->onServerMigrationProbingStartedNotified = true;
  protocolState->probingFinished = true;
  protocolState->serverAddressBeforeProbing = peerAddressBeforeProbing;
  clientState.peerAddress = migrationAddress.getIPv4AddressAsSocketAddress();
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  uint64_t pathData;
  folly::Random::secureRandom(&pathData, sizeof(pathData));
  clientState.pendingEvents.pathChallenge = quic::PathChallengeFrame(pathData);
  clientState.pathValidationLimiter =
      std::make_unique<quic::PendingPathRateLimiter>(
          clientState.udpSendPacketLen);

  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      peerAddressBeforeProbing);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());

  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->onServerMigrationProbingStartedNotified);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      protocolState->serverAddressBeforeProbing, peerAddressBeforeProbing);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 100us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndExplicitServerMigrationProbingReceivingFrameFromServerAddressBeforeProbing) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto peerAddressBeforeProbing = clientState.peerAddress;
  CongestionAndRttState previousCongestionAndRttState;
  previousCongestionAndRttState.congestionController =
      congestionControllerFactory.makeCongestionController(
          clientState,
          clientState.transportSettings.defaultCongestionController);
  previousCongestionAndRttState.srtt = 1us;
  previousCongestionAndRttState.lrtt = 2us;
  previousCongestionAndRttState.rttvar = 3us;
  previousCongestionAndRttState.mrtt = 4us;

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = true;
  protocolState->probingFinished = false;
  protocolState->onServerMigrationProbingStartedNotified = true;
  protocolState->serverAddressBeforeProbing = peerAddressBeforeProbing;
  clientState.peerAddress = migrationAddress.getIPv4AddressAsSocketAddress();
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      peerAddressBeforeProbing);
  ASSERT_FALSE(
      previousCongestionAndRttState.congestionController->isAppLimited());
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      std::move(previousCongestionAndRttState));

  maybeEndServerMigrationProbing(
      clientState, protocolState->serverAddressBeforeProbing);
  EXPECT_EQ(clientState.peerAddress, peerAddressBeforeProbing);
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->onServerMigrationProbingStartedNotified);
  EXPECT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());
  EXPECT_EQ(clientState.lossState.srtt, 1us);
  EXPECT_EQ(clientState.lossState.lrtt, 2us);
  EXPECT_EQ(clientState.lossState.rttvar, 3us);
  EXPECT_EQ(clientState.lossState.mrtt, 4us);
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndExplicitServerMigrationProbingReceivingFrameFromNewServerAddress) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto peerAddressBeforeProbing = clientState.peerAddress;

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = true;
  protocolState->probingFinished = false;
  protocolState->onServerMigrationProbingStartedNotified = true;
  protocolState->serverAddressBeforeProbing = peerAddressBeforeProbing;
  clientState.peerAddress = migrationAddress.getIPv4AddressAsSocketAddress();
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());

  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      peerAddressBeforeProbing);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);

  maybeEndServerMigrationProbing(
      clientState, migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->onServerMigrationProbingStartedNotified);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      protocolState->serverAddressBeforeProbing, peerAddressBeforeProbing);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 100us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndExplicitServerMigrationProbingReceivingFrameFromUnkownServerAddress) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto peerAddressBeforeProbing = clientState.peerAddress;
  folly::SocketAddress unknownPeerAddress("127.1.1.10", 12345);

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = true;
  protocolState->probingFinished = false;
  protocolState->onServerMigrationProbingStartedNotified = true;
  protocolState->serverAddressBeforeProbing = peerAddressBeforeProbing;
  clientState.peerAddress = migrationAddress.getIPv4AddressAsSocketAddress();
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());

  ASSERT_NE(
      unknownPeerAddress, migrationAddress.getIPv4AddressAsSocketAddress());
  ASSERT_NE(unknownPeerAddress, peerAddressBeforeProbing);
  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      peerAddressBeforeProbing);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);

  maybeEndServerMigrationProbing(clientState, unknownPeerAddress);
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->onServerMigrationProbingStartedNotified);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      protocolState->serverAddressBeforeProbing, peerAddressBeforeProbing);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 100us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestAttemptToEndExplicitServerMigrationProbingWhenProbingAlreadyFinished) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  auto peerAddressBeforeProbing = clientState.peerAddress;

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  auto protocolState =
      clientState.serverMigrationState.protocolState->asExplicitClientState();
  protocolState->probingInProgress = false;
  protocolState->probingFinished = true;
  protocolState->onServerMigrationProbingStartedNotified = true;
  protocolState->serverAddressBeforeProbing = peerAddressBeforeProbing;
  clientState.peerAddress = migrationAddress.getIPv4AddressAsSocketAddress();
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());

  uint64_t pathData;
  folly::Random::secureRandom(&pathData, sizeof(pathData));
  clientState.pendingEvents.pathChallenge = quic::PathChallengeFrame(pathData);
  clientState.pathValidationLimiter =
      std::make_unique<quic::PendingPathRateLimiter>(
          clientState.udpSendPacketLen);

  ASSERT_NE(
      migrationAddress.getIPv4AddressAsSocketAddress(),
      peerAddressBeforeProbing);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());

  maybeEndServerMigrationProbing(
      clientState, migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_TRUE(protocolState->onServerMigrationProbingStartedNotified);
  EXPECT_EQ(
      clientState.peerAddress,
      migrationAddress.getIPv4AddressAsSocketAddress());
  EXPECT_EQ(
      protocolState->serverAddressBeforeProbing, peerAddressBeforeProbing);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 100us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestStartPoolOfAddressesServerMigrationProbing) {
  QuicIPAddress poolAddress(folly::IPAddressV4("1.1.1.1"), 1111);
  auto currentServerAddress = clientState.peerAddress;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::POOL_OF_ADDRESSES);
        EXPECT_EQ(probingAddress, currentServerAddress);
      });
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  poolMigrationAddressScheduler->insert(poolAddress);
  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(
      clientState.peerAddress, poolAddress.getIPv4AddressAsSocketAddress());
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_TRUE(
      poolMigrationAddressScheduler->getCurrentServerAddress().isAllZero());
  ASSERT_FALSE(protocolState->probingInProgress);
  ASSERT_FALSE(protocolState->probingFinished);
  ASSERT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

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
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdatePoolOfAddressesServerMigrationProbing) {
  QuicIPAddress poolAddress(folly::IPAddressV4("1.1.1.1"), 1111);
  auto currentServerAddress = clientState.peerAddress;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::POOL_OF_ADDRESSES);
        EXPECT_EQ(probingAddress, poolAddress.getIPv4AddressAsSocketAddress());
      });
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  poolMigrationAddressScheduler->setCurrentServerAddress(
      QuicIPAddress(currentServerAddress));
  poolMigrationAddressScheduler->insert(poolAddress);

  // Simulate one address already cycled (the original one of the server).
  poolMigrationAddressScheduler->next();
  clientState.peerAddress = currentServerAddress;
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());

  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = currentServerAddress;
  protocolState->probingInProgress = true;
  protocolState->probingFinished = false;

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(currentServerAddress, poolAddress.getIPv4AddressAsSocketAddress());
  ASSERT_TRUE(clientState.congestionController->isAppLimited());

  maybeUpdateServerMigrationProbing(clientState);
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
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestUpdatePoolOfAddressesServerMigrationProbingWhenProbingAlreadyFinished) {
  QuicIPAddress poolAddress(folly::IPAddressV4("1.1.1.1"), 1111);
  auto currentServerAddress = clientState.peerAddress;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationProbingStarted).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  clientState.peerAddress = poolAddress.getIPv4AddressAsSocketAddress();
  clientState.serverMigrationState.migrationInProgress = true;

  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = folly::SocketAddress();
  protocolState->probingInProgress = false;
  protocolState->probingFinished = true;
  protocolState->addressScheduler->insert(poolAddress);
  protocolState->addressScheduler->setCurrentServerAddress(
      quic::QuicIPAddress());
  protocolState->addressScheduler->restart();

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());

  uint64_t pathData;
  folly::Random::secureRandom(&pathData, sizeof(pathData));
  clientState.pendingEvents.pathChallenge = quic::PathChallengeFrame(pathData);
  clientState.pathValidationLimiter =
      std::make_unique<quic::PendingPathRateLimiter>(
          clientState.udpSendPacketLen);

  ASSERT_TRUE(clientState.congestionController->isAppLimited());

  maybeUpdateServerMigrationProbing(clientState);
  EXPECT_EQ(
      clientState.peerAddress, poolAddress.getIPv4AddressAsSocketAddress());
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(protocolState->probingInProgress);
  EXPECT_TRUE(protocolState->probingFinished);
  EXPECT_EQ(protocolState->serverAddressBeforeProbing, folly::SocketAddress());
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 40us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestReceivePoolMigrationAddressDuringServerMigrationProbing) {
  PoolMigrationAddressFrame firstPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));
  PacketNum firstPacketNumber = 0;

  PoolMigrationAddressFrame secondPoolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.2"), 5001));
  PacketNum secondPacketNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onPoolMigrationAddressReceived)
      .Times(Exactly(2))
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == firstPoolMigrationAddressFrame);
      })
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == secondPoolMigrationAddressFrame);
      });
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  // Simulate reception of first pool migration address.
  updateServerMigrationFrameOnPacketReceived(
      clientState,
      firstPoolMigrationAddressFrame,
      firstPacketNumber,
      clientState.peerAddress);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState);
  ASSERT_EQ(
      clientState.serverMigrationState.protocolState->type(),
      QuicServerMigrationProtocolClientState::Type::PoolOfAddressesClientState);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  ASSERT_TRUE(protocolState->addressScheduler->contains(
      firstPoolMigrationAddressFrame.address));
  ASSERT_FALSE(protocolState->probingInProgress);
  ASSERT_FALSE(protocolState->probingFinished);

  // Simulate beginning of the migration probing.
  maybeUpdateServerMigrationProbing(clientState);
  ASSERT_TRUE(protocolState->probingInProgress);
  ASSERT_FALSE(protocolState->probingFinished);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);

  // Reception of the second pool migration address.
  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState,
      secondPoolMigrationAddressFrame,
      secondPacketNumber,
      clientState.peerAddress));
  EXPECT_TRUE(protocolState->addressScheduler->contains(
      secondPoolMigrationAddressFrame.address));
  EXPECT_TRUE(protocolState->probingInProgress);
  EXPECT_FALSE(protocolState->probingFinished);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestAttemptToEndPoolOfAddressesProbingWhenProbingAlreadyFinished) {
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

  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = currentServerAddress;
  protocolState->probingFinished = true;
  protocolState->probingInProgress = true;

  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());
  clientState.serverMigrationState.migrationInProgress = false;

  ASSERT_NE(currentServerAddress, poolAddress1.getIPv4AddressAsSocketAddress());
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);

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
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestAttemptToEndPoolOfAddressesProbingWhenNoProbingInProgress) {
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

  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = currentServerAddress;
  protocolState->probingFinished = false;
  protocolState->probingInProgress = false;

  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());
  clientState.serverMigrationState.migrationInProgress = false;

  ASSERT_NE(currentServerAddress, poolAddress1.getIPv4AddressAsSocketAddress());
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);

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
  EXPECT_EQ(poolMigrationAddressScheduler->next(), poolAddress3);
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

  CongestionAndRttState previousCongestionAndRttState;
  previousCongestionAndRttState.congestionController =
      congestionControllerFactory.makeCongestionController(
          clientState,
          clientState.transportSettings.defaultCongestionController);
  previousCongestionAndRttState.srtt = 1us;
  previousCongestionAndRttState.lrtt = 2us;
  previousCongestionAndRttState.rttvar = 3us;
  previousCongestionAndRttState.mrtt = 4us;

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

  clientState.serverMigrationState.protocolState =
      PoolOfAddressesClientState(poolMigrationAddressScheduler);
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asPoolOfAddressesClientState();
  protocolState->serverAddressBeforeProbing = currentServerAddress;
  protocolState->probingFinished = false;
  protocolState->probingInProgress = true;

  clientState.serverMigrationState.migrationInProgress = false;
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 100us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_FALSE(
      previousCongestionAndRttState.congestionController->isAppLimited());
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_NE(clientState.peerAddress, currentServerAddress);
  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      std::move(previousCongestionAndRttState));

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
  EXPECT_EQ(clientState.lossState.srtt, 1us);
  EXPECT_EQ(clientState.lossState.lrtt, 2us);
  EXPECT_EQ(clientState.lossState.rttvar, 3us);
  EXPECT_EQ(clientState.lossState.mrtt, 4us);
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
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

TEST_F(QuicServerMigrationFrameFunctionsTest, TestDetectSymmetricMigrationWithMigrationDisabled) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  PacketNum packetNumber = 0;

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.negotiator);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  EXPECT_THROW(
      maybeDetectSymmetricMigration(
          clientState, serverNewAddress, packetNumber),
      QuicTransportException);
  EXPECT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 40us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestDetectSymmetricMigrationWithPathValidationAlreadyStarted) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  PacketNum packetNumber = 1;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;
  clientState.serverMigrationState.protocolState = SymmetricClientState();
  auto protocolState =
      clientState.serverMigrationState.protocolState->asSymmetricClientState();
  protocolState->pathValidationStarted = true;

  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);

  maybeDetectSymmetricMigration(clientState, serverNewAddress, packetNumber);
  EXPECT_NE(serverNewAddress, clientState.peerAddress);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);
  EXPECT_TRUE(protocolState->pathValidationStarted);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 40us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestDetectSymmetricMigrationWithoutProtocolState) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  PacketNum packetNumber = 0;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.largestProcessedPacketNumber);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState);
  ASSERT_FALSE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  maybeDetectSymmetricMigration(clientState, serverNewAddress, packetNumber);
  ASSERT_TRUE(
      clientState.serverMigrationState.protocolState->asSymmetricClientState());
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState->asSymmetricClientState()
          ->pathValidationStarted);
  EXPECT_EQ(clientState.peerAddress, serverNewAddress);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 0us);
  EXPECT_EQ(clientState.lossState.lrtt, 0us);
  EXPECT_EQ(clientState.lossState.rttvar, 0us);
  EXPECT_EQ(clientState.lossState.mrtt, kDefaultMinRtt);
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestDetectSymmetricMigrationWithProtocolStateAlreadyPresent) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  PacketNum packetNumber = 0;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.protocolState = SymmetricClientState();
  clientState.serverMigrationState.migrationInProgress = false;
  clientState.serverMigrationState.largestProcessedPacketNumber = packetNumber;

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  maybeDetectSymmetricMigration(clientState, serverNewAddress, packetNumber);
  EXPECT_EQ(clientState.peerAddress, serverNewAddress);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState->asSymmetricClientState()
          ->pathValidationStarted);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 0us);
  EXPECT_EQ(clientState.lossState.lrtt, 0us);
  EXPECT_EQ(clientState.lossState.rttvar, 0us);
  EXPECT_EQ(clientState.lossState.mrtt, kDefaultMinRtt);
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestReceiveOutOfOrderServerMigratedAfterSymmetricMigrationDetected) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ASSERT_NE(serverNewAddress, clientState.peerAddress);

  PacketNum packetNumberServerMigrated = 1;
  PacketNum packetNumberMigration = 2;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  maybeDetectSymmetricMigration(
      clientState, serverNewAddress, packetNumberMigration);
  ASSERT_EQ(clientState.peerAddress, serverNewAddress);
  ASSERT_TRUE(clientState.serverMigrationState.migrationInProgress);
  ASSERT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumberMigration);
  ASSERT_TRUE(
      clientState.serverMigrationState.protocolState->asSymmetricClientState());
  ASSERT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());
  ASSERT_TRUE(clientState.congestionController->isAppLimited());

  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState,
      ServerMigratedFrame(),
      packetNumberServerMigrated,
      serverNewAddress));
  EXPECT_EQ(clientState.peerAddress, serverNewAddress);
  EXPECT_TRUE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_TRUE(clientState.serverMigrationState.largestProcessedPacketNumber);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumberMigration);
  EXPECT_TRUE(
      clientState.serverMigrationState.protocolState->asSymmetricClientState());
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 40us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestDetectSynchronizedSymmetricMigrationWithMigrationDisabled) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  PacketNum packetNumber = 1;

  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;
  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.serverMigrationState.negotiator);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  EXPECT_THROW(
      maybeDetectSymmetricMigration(
          clientState, serverNewAddress, packetNumber),
      QuicTransportException);
  EXPECT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 40us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestDetectSynchronizedSymmetricMigrationWithPathValidationAlreadyStarted) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  PacketNum packetNumber = 1;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;
  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();
  auto protocolState = clientState.serverMigrationState.protocolState
                           ->asSynchronizedSymmetricClientState();
  protocolState->pathValidationStarted = true;

  clientState.serverMigrationState.previousCongestionAndRttStates.emplace_back(
      CongestionAndRttState());
  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);

  maybeDetectSymmetricMigration(clientState, serverNewAddress, packetNumber);
  EXPECT_NE(serverNewAddress, clientState.peerAddress);
  EXPECT_FALSE(clientState.pendingEvents.pathChallenge);
  EXPECT_FALSE(clientState.pathValidationLimiter);
  EXPECT_TRUE(protocolState->pathValidationStarted);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 40us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestDetectSynchronizedSymmetricMigration) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  PacketNum packetNumber = 1;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumber - 1;
  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());

  ASSERT_NE(serverNewAddress, clientState.peerAddress);
  ASSERT_FALSE(clientState.pendingEvents.pathChallenge);
  ASSERT_FALSE(clientState.pathValidationLimiter);
  ASSERT_FALSE(clientState.serverMigrationState.protocolState
                   ->asSynchronizedSymmetricClientState()
                   ->pathValidationStarted);
  ASSERT_TRUE(clientState.congestionController->isAppLimited());
  ASSERT_TRUE(
      clientState.serverMigrationState.previousCongestionAndRttStates.empty());

  maybeDetectSymmetricMigration(clientState, serverNewAddress, packetNumber);
  EXPECT_EQ(clientState.peerAddress, serverNewAddress);
  EXPECT_TRUE(clientState.pendingEvents.pathChallenge);
  EXPECT_TRUE(clientState.pathValidationLimiter);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumber);
  EXPECT_TRUE(clientState.serverMigrationState.protocolState
                  ->asSynchronizedSymmetricClientState()
                  ->pathValidationStarted);
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
  EXPECT_EQ(clientState.lossState.srtt, 0us);
  EXPECT_EQ(clientState.lossState.lrtt, 0us);
  EXPECT_EQ(clientState.lossState.rttvar, 0us);
  EXPECT_EQ(clientState.lossState.mrtt, kDefaultMinRtt);
  EXPECT_FALSE(clientState.congestionController->isAppLimited());
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestReceiveOutOfOrderServerMigratedAfterSynchronizedSymmetricMigrationDetected) {
  folly::SocketAddress serverNewAddress("127.0.0.1", 5000);
  ASSERT_NE(serverNewAddress, clientState.peerAddress);

  PacketNum packetNumberServerMigrated = 1;
  PacketNum packetNumberMigration = 2;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigratedReceived).Times(0);
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  enableServerMigrationServerSide();
  enableServerMigrationClientSide();
  doNegotiation();

  clientState.serverMigrationState.largestProcessedPacketNumber =
      packetNumberServerMigrated - 1;
  clientState.serverMigrationState.protocolState =
      SynchronizedSymmetricClientState();

  maybeDetectSymmetricMigration(
      clientState, serverNewAddress, packetNumberMigration);
  ASSERT_EQ(clientState.peerAddress, serverNewAddress);
  ASSERT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumberMigration);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState
                  ->asSynchronizedSymmetricClientState());
  ASSERT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);

  clientState.lossState.srtt = 10us;
  clientState.lossState.lrtt = 20us;
  clientState.lossState.rttvar = 30us;
  clientState.lossState.mrtt = 40us;
  clientState.congestionController->setAppIdle(true, TimePoint::clock::now());
  ASSERT_TRUE(clientState.congestionController->isAppLimited());

  EXPECT_NO_THROW(updateServerMigrationFrameOnPacketReceived(
      clientState,
      ServerMigratedFrame(),
      packetNumberServerMigrated,
      serverNewAddress));
  EXPECT_EQ(clientState.peerAddress, serverNewAddress);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      packetNumberMigration);
  EXPECT_TRUE(clientState.serverMigrationState.protocolState
                  ->asSynchronizedSymmetricClientState());
  EXPECT_EQ(clientState.lossState.srtt, 10us);
  EXPECT_EQ(clientState.lossState.lrtt, 20us);
  EXPECT_EQ(clientState.lossState.rttvar, 30us);
  EXPECT_EQ(clientState.lossState.mrtt, 40us);
  EXPECT_TRUE(clientState.congestionController->isAppLimited());
  EXPECT_EQ(
      clientState.serverMigrationState.previousCongestionAndRttStates.size(),
      1);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndServerMigrationClientSide) {
  QuicIPAddress migrationAddress(folly::IPAddressV4("127.0.0.1"), 5000);
  PacketNum endMigrationPacketNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationCompleted()).Times(Exactly(1));
  clientState.serverMigrationState.serverMigrationEventCallback = callback;

  clientState.serverMigrationState.protocolState =
      ExplicitClientState(migrationAddress);
  clientState.serverMigrationState.migrationInProgress = true;
  clientState.pathValidationLimiter =
      std::make_unique<quic::PendingPathRateLimiter>(
          clientState.udpSendPacketLen);
  clientState.serverMigrationState.largestProcessedPacketNumber =
      endMigrationPacketNumber - 1;
  clientState.serverMigrationState.numberOfMigrations = 0;

  endServerMigration(clientState, endMigrationPacketNumber);
  EXPECT_FALSE(clientState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(clientState.serverMigrationState.protocolState);
  EXPECT_FALSE(clientState.pathValidationLimiter);
  EXPECT_EQ(clientState.serverMigrationState.numberOfMigrations, 1);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      endMigrationPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndServerMigrationServerSide) {
  PacketNum endMigrationPacketNumber = 1;

  auto callback = std::make_shared<MockServerMigrationEventCallback>();
  EXPECT_CALL(*callback, onServerMigrationCompleted(_)).Times(Exactly(1));
  serverState.serverMigrationState.serverMigrationEventCallback = callback;

  serverState.serverMigrationState.protocolState = SymmetricServerState();
  serverState.serverMigrationState.migrationInProgress = true;
  serverState.serverMigrationState.largestProcessedPacketNumber =
      endMigrationPacketNumber - 1;

  endServerMigration(serverState, endMigrationPacketNumber);
  EXPECT_FALSE(serverState.serverMigrationState.migrationInProgress);
  EXPECT_FALSE(serverState.serverMigrationState.protocolState);
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      endMigrationPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndServerMigrationDoesNotClearServerPoolOfAddressesState) {
  PacketNum endMigrationPacketNumber = 1;
  serverState.serverMigrationState.protocolState = PoolOfAddressesServerState();
  serverState.serverMigrationState.largestProcessedPacketNumber =
      endMigrationPacketNumber - 1;

  endServerMigration(serverState, endMigrationPacketNumber);
  EXPECT_TRUE(serverState.serverMigrationState.protocolState);
  EXPECT_TRUE(serverState.serverMigrationState.protocolState
                  ->asPoolOfAddressesServerState());
  EXPECT_EQ(
      serverState.serverMigrationState.largestProcessedPacketNumber.value(),
      endMigrationPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestEndServerMigrationDoesNotClearClientPoolOfAddressesState) {
  PacketNum endMigrationPacketNumber = 1;
  PoolOfAddressesClientState protocolState(poolMigrationAddressScheduler);
  protocolState.probingInProgress = false;
  protocolState.probingFinished = true;
  clientState.serverMigrationState.protocolState = std::move(protocolState);
  clientState.serverMigrationState.largestProcessedPacketNumber =
      endMigrationPacketNumber - 1;

  endServerMigration(clientState, endMigrationPacketNumber);
  ASSERT_TRUE(clientState.serverMigrationState.protocolState
                  ->asPoolOfAddressesClientState());
  auto newProtocolState = clientState.serverMigrationState.protocolState
                              ->asPoolOfAddressesClientState();
  EXPECT_FALSE(newProtocolState->probingInProgress);
  EXPECT_FALSE(newProtocolState->probingFinished);
  EXPECT_EQ(
      clientState.serverMigrationState.largestProcessedPacketNumber.value(),
      endMigrationPacketNumber);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestRetransmissionOnPacketLoss) {
  QuicIPAddress emptyAddress;
  ServerMigrationFrame serverMigrationFrame(emptyAddress);
  ASSERT_TRUE(serverState.pendingEvents.frames.empty());
  updateServerMigrationFrameOnPacketLoss(serverState, serverMigrationFrame);
  EXPECT_EQ(serverState.pendingEvents.frames.size(), 1);
  EXPECT_EQ(
      *serverState.pendingEvents.frames.at(0)
           .asQuicServerMigrationFrame()
           ->asServerMigrationFrame(),
      serverMigrationFrame);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerMigratedNotRetransmittedOnPacketLoss) {
  ServerMigratedFrame serverMigratedFrame;
  ASSERT_TRUE(serverState.pendingEvents.frames.empty());
  updateServerMigrationFrameOnPacketLoss(serverState, serverMigratedFrame);
  EXPECT_TRUE(serverState.pendingEvents.frames.empty());
}

} // namespace test
} // namespace quic
