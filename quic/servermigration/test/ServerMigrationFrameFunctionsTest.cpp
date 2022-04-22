#include <folly/portability/GTest.h>
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
};

TEST_F(QuicServerMigrationFrameFunctionsTest, TestServerReceptionOfFrame) {
  PoolMigrationAddressFrame poolMigrationAddressFrame(
      QuicIPAddress(folly::IPAddressV4("127.0.0.1"), 5000));

  MockServerMigrationEventCallback callback;
  EXPECT_CALL(callback, onPoolMigrationAddressReceived)
      .Times(Exactly(1))
      .WillOnce([&](PoolMigrationAddressFrame frame) {
        EXPECT_TRUE(frame == poolMigrationAddressFrame);
      });

  serverState.serverMigrationState.serverMigrationEventCallback = &callback;
  EXPECT_THROW(
      updateServerMigrationFrameOnPacketReceived(
          serverState, poolMigrationAddressFrame),
      QuicTransportException);
}

} // namespace test
} // namespace quic
