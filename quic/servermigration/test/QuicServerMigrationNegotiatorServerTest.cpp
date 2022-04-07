#include <folly/portability/GTest.h>
#include <quic/servermigration/QuicServerMigrationNegotiatorServer.h>

namespace quic {
namespace test {

TEST(QuicServerMigrationNegotiatorServerTest, TestEmptySupportedProtocols) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  ASSERT_TRUE(supportedProtocols.empty());

  ASSERT_THROW(
      QuicServerMigrationNegotiatorServer negotiator(supportedProtocols),
      QuicInternalException);
}

TEST(QuicServerMigrationNegotiatorServerTest, TestWrongParametersPassedOrReceived) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorServer negotiator(supportedProtocols);

  CustomIntegralTransportParameter wrongParameter(
      static_cast<uint64_t>(TransportParameterId::disable_migration), 0xFF);

  ASSERT_THROW(
      negotiator.onMigrationSuiteReceived(wrongParameter.encode()),
      QuicTransportException);
  ASSERT_TRUE(!negotiator.getNegotiatedProtocols());

  CustomStringTransportParameter wronglyEncodedParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite), "");

  // Check that the raw data in wronglyEncodedParameter
  // is not accidentally a quic integer.
  auto wronglyEncodedRaw = wronglyEncodedParameter.encode();
  auto cursor = folly::io::Cursor(wronglyEncodedRaw.value.get());
  auto quicInteger = decodeQuicInteger(cursor);
  ASSERT_TRUE(!quicInteger);

  ASSERT_THROW(
      negotiator.onMigrationSuiteReceived(wronglyEncodedParameter.encode()),
      QuicTransportException);
  ASSERT_TRUE(!negotiator.getNegotiatedProtocols());

  CustomIntegralTransportParameter noProtocolsEncodedParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite), 0);

  ASSERT_THROW(
      negotiator.onMigrationSuiteReceived(noProtocolsEncodedParameter.encode()),
      QuicTransportException);
  ASSERT_TRUE(!negotiator.getNegotiatedProtocols());
}

TEST(QuicServerMigrationNegotiatorServerTest, TestEncodingBeforeSuiteReceived) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorServer negotiator(supportedProtocols);

  ASSERT_THROW(
      negotiator.onTransportParametersEncoding(), QuicTransportException);
  ASSERT_TRUE(!negotiator.getNegotiatedProtocols());

  CustomIntegralTransportParameter peerParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      static_cast<uint64_t>(ServerMigrationProtocol::SYMMETRIC));

  ASSERT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter.encode()));
  ASSERT_TRUE(negotiator.getNegotiatedProtocols().has_value());
  ASSERT_NO_THROW(negotiator.onTransportParametersEncoding());
}

TEST(QuicServerMigrationNegotiatorServerTest, TestTransportParameterEncoding) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  supportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  supportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorServer negotiator(supportedProtocols);

  auto expectedParameterId = TransportParameterId::server_migration_suite;
  uint64_t expectedParameterValue = 0x7; // 00..00111 in binary representation

  CustomIntegralTransportParameter peerParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      static_cast<uint64_t>(ServerMigrationProtocol::EXPLICIT) |
          static_cast<uint64_t>(ServerMigrationProtocol::POOL_OF_ADDRESSES) |
          static_cast<uint64_t>(ServerMigrationProtocol::SYMMETRIC));

  ASSERT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter.encode()));

  EXPECT_TRUE(
      negotiator.getNegotiatedProtocols().has_value() &&
      negotiator.getNegotiatedProtocols()->size() == 3);

  ASSERT_NO_THROW(negotiator.onTransportParametersEncoding());
  auto encodedParameter = negotiator.onTransportParametersEncoding();

  auto cursor = folly::io::Cursor(encodedParameter.value.get());
  auto decodedValue = decodeQuicInteger(cursor).value().first;

  EXPECT_TRUE(encodedParameter.parameter == expectedParameterId);
  EXPECT_TRUE(decodedValue == expectedParameterValue);
}

TEST(QuicServerMigrationNegotiatorServerTest, TestSuccessfulNegotiationWithSingleProtocol) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  supportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  supportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorServer negotiator(supportedProtocols);

  CustomIntegralTransportParameter peerParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      static_cast<uint64_t>(ServerMigrationProtocol::SYMMETRIC));

  ASSERT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter.encode()));
  auto negotiatedProtocols = negotiator.getNegotiatedProtocols();
  ASSERT_TRUE(negotiatedProtocols.hasValue());

  ASSERT_TRUE(
      negotiatedProtocols->size() == 1 &&
      negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));

  ASSERT_NO_THROW(negotiator.onTransportParametersEncoding());
}

TEST(QuicServerMigrationNegotiatorServerTest, TestSuccessfulNegotiationWithMultipleProtocols) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  supportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  supportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorServer negotiator(supportedProtocols);

  CustomIntegralTransportParameter peerParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      static_cast<uint64_t>(ServerMigrationProtocol::POOL_OF_ADDRESSES) |
          static_cast<uint64_t>(ServerMigrationProtocol::SYMMETRIC));

  ASSERT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter.encode()));
  auto negotiatedProtocols = negotiator.getNegotiatedProtocols();
  ASSERT_TRUE(negotiatedProtocols.hasValue());

  ASSERT_TRUE(
      negotiatedProtocols->size() == 2 &&
      negotiatedProtocols->count(ServerMigrationProtocol::POOL_OF_ADDRESSES) &&
      negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));

  ASSERT_NO_THROW(negotiator.onTransportParametersEncoding());
}

TEST(QuicServerMigrationNegotiatorServerTest, TestUnsuccessfulNegotiation) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorServer negotiator(supportedProtocols);

  CustomIntegralTransportParameter peerParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      static_cast<uint64_t>(ServerMigrationProtocol::POOL_OF_ADDRESSES));

  ASSERT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter.encode()));
  auto negotiatedProtocols = negotiator.getNegotiatedProtocols();
  ASSERT_TRUE(negotiatedProtocols.hasValue());
  ASSERT_TRUE(negotiatedProtocols->empty());

  ASSERT_NO_THROW(negotiator.onTransportParametersEncoding());
  auto encodedParameter = negotiator.onTransportParametersEncoding();

  auto cursor = folly::io::Cursor(encodedParameter.value.get());
  auto decodedValue = decodeQuicInteger(cursor).value().first;

  auto expectedParameterId = TransportParameterId::server_migration_suite;
  uint64_t expectedParameterValue = 0;

  EXPECT_TRUE(encodedParameter.parameter == expectedParameterId);
  EXPECT_TRUE(decodedValue == expectedParameterValue);
}

} // namespace test
} // namespace quic
