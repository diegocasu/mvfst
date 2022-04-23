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
};

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfFrame) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, poolMigrationAddressFrame),
      QuicTransportException);
}

TEST_F(QuicServerMigrationFrameFunctionsTest, TestClientReceptionOfPoolMigrationAddress) {
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

  // TODO add test where clientState.serverMigrationState.protocolState !=
  // QuicServerMigrationProtocolStateClient::Type::PoolOfAddressesStateClient
}

} // namespace test
} // namespace quic
